//! Engine — orchestrates the DNS loop and the route lifecycle.
//!
//! Threads (see `docs/design.md` §4):
//! - `dns-listener`: receives client queries, forwards them upstream
//! - `dns-upstream`: receives upstream responses, returns them to clients,
//!   and adds routes for redirect-list domains
//! - `route-cleanup`: wakes every [`ROUTE_TTL`], removes expired routes
//!
//! Shutdown happens when [`EngineHandle`] is dropped: threads are joined
//! and all remaining routes are removed.

use std::collections::BTreeSet;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::core::dns::server;
use crate::core::etw::{PortOwners, ProcessTracker};
use crate::core::forwarder;
use crate::core::redirect::RedirectList;
use crate::core::router::cidr::Cidr;
use crate::core::router::windows::{WindowsRouter, discover_peer, discover_tunnel_peer};
use crate::core::router::{RouteRegistry, registry_path};
use crate::core::settings::Settings;

/// How often the cleanup loop runs: expire dead routes and re-pin
/// near-expiry domains. Independent of any TTL — the loop is a heartbeat.
pub(crate) const CLEANUP_INTERVAL: Duration = Duration::from_secs(60);

/// How far ahead of expiry a redirect-list domain is re-queried so its
/// routes stay pinned without waiting for a client to ask again.
pub(crate) const REPIN_LEAD: Duration = Duration::from_secs(30);

/// Socket poll interval — how often the receive loops check the shutdown
/// flag.
pub(crate) const POLL_INTERVAL: Duration = Duration::from_millis(250);

/// Largest DNS message we accept over UDP (EDNS0 max).
pub(crate) const MAX_DNS_UDP: usize = 4096;

/// Minimum gap between upstream queries — paces dnscache's query bursts so
/// protective resolvers (e.g. Pi-Hole with burst limits) don't ICMP-reject
/// the app as an abusive client.
pub(crate) const MIN_UPSTREAM_SEND_INTERVAL: Duration = Duration::from_millis(15);

/// Things the engine reports to the UI.
#[derive(Debug, Clone)]
pub enum Event {
    /// The engine started listening.
    Started {
        /// Where the engine listens for client queries.
        listen: SocketAddr,
        /// The VPN gateway IPs are routed through.
        gateway: Ipv4Addr,
    },
    /// The engine stopped and removed all routes it added.
    Stopped,
    /// A client query was forwarded upstream.
    QueryForwarded {
        /// The queried domain.
        domain: String,
        /// Process that requested the query, when attribution is available.
        process: Option<String>,
        /// Whether or not the domain in redirect list of the engine.
        in_redirect_list: bool,
    },
    /// A route was added for an IP (refreshes are silent).
    RouteAdded {
        /// The routed IP.
        ip: Ipv4Addr,
    },
    /// A route was removed (expiry or shutdown cleanup).
    RouteRemoved {
        /// The unrouted IP.
        ip: Ipv4Addr,
    },
    /// A non-fatal problem.
    Error(String),
    /// A warning — not fatal, but something to act on.
    Warning(String),
    /// An informational notice.
    Info(String),
}

/// Commands the UI can send to a running engine.
pub(crate) enum Command {
    /// Replace the redirect list (applied on save while running).
    SetRedirectList(Vec<String>),
    /// Replace the static CIDR list (applied on save while running).
    SetCidrList(Vec<String>),
    /// Re-query these domains so their routes stay pinned before the DNS
    /// TTL elapses. Emitted by the cleanup loop; handled by the listener.
    RepinDomains(Vec<String>),
}

/// Handle to a running engine.
///
/// Dropping the handle stops the engine: threads are joined and every route
/// added by this run is removed.
pub struct EngineHandle {
    shutdown: Arc<AtomicBool>,
    threads: Vec<JoinHandle<()>>,
    registry: Arc<Mutex<RouteRegistry>>,
    registry_path: PathBuf,
    events: mpsc::Sender<Event>,
    commands: mpsc::Sender<Command>,
}

impl EngineHandle {
    /// Replaces the redirect list in the running engine — no restart needed.
    pub fn set_redirect_list(&self, domains: Vec<String>) {
        let _ = self.commands.send(Command::SetRedirectList(domains));
    }

    /// Replaces the static CIDR list in the running engine — no restart
    /// needed.
    pub fn set_cidr_list(&self, cidrs: Vec<String>) {
        let _ = self.commands.send(Command::SetCidrList(cidrs));
    }
}

impl Drop for EngineHandle {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        for thread in &self.threads {
            thread.thread().unpark();
        }
        for thread in self.threads.drain(..) {
            let _ = thread.join();
        }
        let (removed, errors) = lock_ok(&self.registry).delete_all();
        for ip in removed {
            let _ = self.events.send(Event::RouteRemoved { ip });
        }
        for error in errors {
            let _ = self.events.send(Event::Error(error));
        }
        let _ = lock_ok(&self.registry).save(&self.registry_path);
        let _ = self.events.send(Event::Stopped);
    }
}

/// The engine itself — construction only, no state.
pub struct Engine;

impl Engine {
    /// Validates `settings`, cleans up leftover routes from a previous
    /// (crashed) run, and starts the engine threads.
    ///
    /// # Errors
    ///
    /// Returns an error if a setting does not parse, a socket cannot be
    /// bound/connected, or the route registry file is corrupt.
    pub fn start(settings: &Settings, events: mpsc::Sender<Event>) -> io::Result<EngineHandle> {
        let listen: SocketAddr = settings.listen_addr.parse().map_err(|_| {
            io::Error::other(format!("invalid listen address `{}`", settings.listen_addr))
        })?;
        let upstream_addr: SocketAddr = settings.dns_server.parse().map_err(|_| {
            io::Error::other(format!(
                "invalid DNS server address `{}`",
                settings.dns_server
            ))
        })?;
        let next_hop = resolve_next_hop(&settings.vpn_interface, &settings.vpn_gateway)?;
        let timeout = Duration::from_millis(settings.timeout_ms.max(1));
        if !WindowsRouter::is_elevated() {
            let _ = events.send(Event::Warning(
                "process is not elevated — route add/delete will fail; \
                 run the app as administrator"
                    .to_owned(),
            ));
        }
        let registry_path = registry_path().ok_or_else(|| {
            io::Error::other("APPDATA is not set — cannot persist the route registry")
        })?;

        // Crash cleanup: remove routes left by a previous run that did not
        // shut down cleanly, then start with a fresh registry.
        let (mut registry, existed) =
            RouteRegistry::load(&registry_path, Box::new(WindowsRouter), next_hop)?;
        if existed {
            let (removed, errors) = registry.delete_all();
            for ip in removed {
                let _ = events.send(Event::RouteRemoved { ip });
            }
            for error in errors {
                let _ = events.send(Event::Error(error));
            }
            registry = RouteRegistry::new(next_hop, Box::new(WindowsRouter));
        }

        // Static networks are pinned for the engine's whole lifetime.
        let cidrs: BTreeSet<Cidr> = settings
            .cidr_list
            .iter()
            .filter_map(|entry| Cidr::parse(entry).ok())
            .collect();
        let (_, added, errors) = registry.set_nets(cidrs.clone());
        for cidr in added {
            let _ = events.send(Event::Info(format!("static route + {cidr}")));
        }
        for error in errors {
            let _ = events.send(Event::Error(error));
        }

        // Per-app attribution: optional — the engine works without it.
        let (tracker, ports) = start_attribution(&events);

        let listener = UdpSocket::bind(listen).map_err(|e| {
            io::Error::other(format!(
                "failed to bind DNS listener on {listen}: {e} — \
                 on Windows error 10013 usually means another process owns the \
                 port (mDNS holds 5353) or it is excluded by Windows; pick \
                 another port in Settings"
            ))
        })?;
        listener.set_read_timeout(Some(POLL_INTERVAL))?;
        // The upstream socket is deliberately NOT connected: Windows treats
        // connected UDP sockets specially (ICMP poisoning, firewall flow
        // quirks) and a wedged one silently eats replies. Unconnected +
        // send_to/recv_from with a source check is the robust pattern.
        let upstream_socket = UdpSocket::bind("0.0.0.0:0")?;
        upstream_socket.set_read_timeout(Some(POLL_INTERVAL))?;
        // Client answers go out from the LISTENER socket (the one bound to
        // the configured listen address), never the upstream socket. UDP
        // clients — including the Windows resolver and `nslookup` — match
        // replies by source IP:port; a reply sent from an ephemeral
        // socket is silently dropped by the client and looks like a
        // timeout. The upstream socket stays dedicated to talking to the
        // real resolver.

        let (command_tx, command_rx) = mpsc::channel();
        let runtime = Runtime {
            listener: Arc::new(listener),
            upstream: Arc::new(RwLock::new(upstream_socket)),
            upstream_addr,
            pending: server::PendingMap::default(),
            redirect: Arc::new(RwLock::new(RedirectList::new(
                settings.redirect_list.clone(),
            ))),
            id_counter: Arc::new(AtomicU16::new(0)),
            registry: Arc::new(Mutex::new(registry)),
            registry_path,
            timeout,
            events: events.clone(),
            shutdown: Arc::new(AtomicBool::new(false)),
            vpn_interface: settings.vpn_interface.clone(),
            vpn_gateway: settings.vpn_gateway.clone(),
            cidrs,
            tracker,
            ports,
            commands: command_tx.clone(),
        };
        let threads = spawn_threads(&runtime, command_rx)?;

        let _ = events.send(Event::Started {
            listen,
            gateway: next_hop,
        });
        Ok(EngineHandle {
            shutdown: Arc::clone(&runtime.shutdown),
            threads,
            registry: Arc::clone(&runtime.registry),
            registry_path: runtime.registry_path.clone(),
            events,
            commands: command_tx,
        })
    }
}

/// Shared state for the engine threads.
struct Runtime {
    listener: Arc<UdpSocket>,
    upstream: Arc<RwLock<UdpSocket>>,
    upstream_addr: SocketAddr,
    pending: server::PendingMap,
    redirect: Arc<RwLock<RedirectList>>,
    id_counter: Arc<AtomicU16>,
    registry: Arc<Mutex<RouteRegistry>>,
    registry_path: PathBuf,
    timeout: Duration,
    events: mpsc::Sender<Event>,
    shutdown: Arc<AtomicBool>,
    vpn_interface: String,
    vpn_gateway: String,
    cidrs: BTreeSet<Cidr>,
    tracker: Option<Arc<ProcessTracker>>,
    ports: Arc<PortOwners>,
    /// Sender side of the command channel — cloned into the cleanup loop
    /// so it can request re-pins without going through the UI.
    commands: mpsc::Sender<Command>,
}

/// Spawns the three engine threads and returns their join handles.
///
/// # Errors
///
/// Returns an error if a thread cannot be spawned.
fn spawn_threads(
    runtime: &Runtime,
    commands: mpsc::Receiver<Command>,
) -> io::Result<Vec<JoinHandle<()>>> {
    let mut threads = Vec::new();
    threads.push(
        thread::Builder::new()
            .name("dns-listener".to_owned())
            .spawn({
                let listener = Arc::clone(&runtime.listener);
                let ctx = server::ListenerCtx {
                    upstream: Arc::clone(&runtime.upstream),
                    upstream_addr: runtime.upstream_addr,
                    pending: Arc::clone(&runtime.pending),
                    redirect: Arc::clone(&runtime.redirect),
                    registry: Arc::clone(&runtime.registry),
                    tracker: runtime.tracker.clone(),
                    ports: Arc::clone(&runtime.ports),
                    commands,
                    id_counter: Arc::clone(&runtime.id_counter),
                    timeout: runtime.timeout,
                    events: runtime.events.clone(),
                    shutdown: Arc::clone(&runtime.shutdown),
                };
                move || server::run(listener, ctx)
            })?,
    );
    threads.push(
        thread::Builder::new()
            .name("dns-upstream".to_owned())
            .spawn({
                let listener = Arc::clone(&runtime.listener);
                let upstream = Arc::clone(&runtime.upstream);
                let upstream_addr = runtime.upstream_addr;
                let pending = Arc::clone(&runtime.pending);
                let registry = Arc::clone(&runtime.registry);
                let events = runtime.events.clone();
                let shutdown = Arc::clone(&runtime.shutdown);
                move || {
                    forwarder::run(
                        listener,
                        upstream,
                        upstream_addr,
                        pending,
                        registry,
                        events,
                        shutdown,
                    );
                }
            })?,
    );
    threads.push(
        thread::Builder::new()
            .name("route-cleanup".to_owned())
            .spawn({
                let registry = Arc::clone(&runtime.registry);
                let registry_path = runtime.registry_path.clone();
                let events = runtime.events.clone();
                let commands = runtime.commands.clone();
                let shutdown = Arc::clone(&runtime.shutdown);
                let vpn_interface = runtime.vpn_interface.clone();
                let vpn_gateway = runtime.vpn_gateway.clone();
                let cidrs = runtime.cidrs.clone();
                move || {
                    cleanup_loop(
                        registry,
                        registry_path,
                        events,
                        commands,
                        shutdown,
                        vpn_interface,
                        vpn_gateway,
                        cidrs,
                    );
                }
            })?,
    );
    Ok(threads)
}

/// Starts the attribution services (ETW tracker + port-ownership
/// snapshots). Failures degrade gracefully — attribution is optional.
fn start_attribution(
    events: &mpsc::Sender<Event>,
) -> (Option<Arc<ProcessTracker>>, Arc<PortOwners>) {
    let tracker = match ProcessTracker::start() {
        Ok(tracker) => Some(Arc::new(tracker)),
        Err(e) => {
            let _ = events.send(Event::Warning(format!(
                "per-app attribution unavailable: {e}"
            )));
            None
        }
    };
    (tracker, Arc::new(PortOwners::start()))
}

/// Resolves the route next hop from settings: auto-detect the tunnel
/// adapter when `vpn_interface` is empty, otherwise query the explicit
/// interface; fall back to the static `vpn_gateway` when discovery fails.
///
/// # Errors
///
/// Returns an error if discovery fails and no valid gateway is configured.
fn resolve_next_hop(vpn_interface: &str, vpn_gateway: &str) -> io::Result<Ipv4Addr> {
    let discovered = if vpn_interface.trim().is_empty() {
        discover_tunnel_peer()
    } else {
        discover_peer(vpn_interface.trim())
    };
    match discovered {
        Ok(peer) => Ok(peer),
        Err(discovery_error) => {
            if vpn_gateway.trim().is_empty() {
                Err(discovery_error)
            } else {
                vpn_gateway.trim().parse().map_err(|_| {
                    io::Error::other(format!(
                        "{discovery_error}; `{vpn_gateway}` is not a valid IPv4 gateway"
                    ))
                })
            }
        }
    }
}

/// The cleanup cycle: expires dead routes, re-pins domains whose routes
/// are near expiry, and re-discovers the tunnel peer after VPN reconnects.
///
/// Thread entry point: takes ownership because the caller hands the values
/// to a new thread.
#[allow(clippy::needless_pass_by_value)]
fn cleanup_loop(
    registry: Arc<Mutex<RouteRegistry>>,
    registry_path: PathBuf,
    events: mpsc::Sender<Event>,
    commands: mpsc::Sender<Command>,
    shutdown: Arc<AtomicBool>,
    vpn_interface: String,
    vpn_gateway: String,
    cidrs: BTreeSet<Cidr>,
) {
    let mut next = Instant::now() + CLEANUP_INTERVAL;
    loop {
        if shutdown.load(Ordering::Relaxed) {
            return;
        }
        let now = Instant::now();
        if now >= next {
            // Resolve BEFORE taking the registry lock — spawning PowerShell
            // under the lock would stall every response that needs routing.
            let peer = resolve_next_hop(&vpn_interface, &vpn_gateway);
            let mut registry = lock_ok(&registry);
            // A VPN reconnect flips the point-to-point peer; stale next hops
            // would silently drop traffic. Re-resolve each cycle and re-pin
            // on change.
            match peer {
                Ok(peer) if peer != registry.next_hop() => {
                    let (removed, errors) = registry.delete_all();
                    for ip in removed {
                        let _ = events.send(Event::RouteRemoved { ip });
                    }
                    for error in errors {
                        let _ = events.send(Event::Error(error));
                    }
                    registry.set_next_hop(peer);
                    // Static networks re-pin immediately — they have no DNS
                    // resolution to wait for.
                    let (_, added, errors) = registry.set_nets(cidrs.clone());
                    for cidr in added {
                        let _ = events.send(Event::Info(format!("static route + {cidr}")));
                    }
                    for error in errors {
                        let _ = events.send(Event::Error(error));
                    }
                    let _ = events.send(Event::Warning(format!(
                        "VPN peer changed — routes will re-pin via {peer} on the next resolution"
                    )));
                }
                Err(e) => {
                    let _ = events.send(Event::Error(format!("failed to resolve VPN peer: {e}")));
                }
                Ok(_) => {}
            }
            // Routes whose own DNS TTL has elapsed.
            let (removed, errors) = registry.expire(now);
            for ip in removed {
                let _ = events.send(Event::RouteRemoved { ip });
            }
            for error in errors {
                let _ = events.send(Event::Error(error));
            }
            // Domains whose routes are near expiry. Collected under the
            // lock, dispatched after — the listener's command handler
            // re-locks the redirect list, and holding the registry lock
            // while it does so risks cross-lock contention.
            let expiring = registry.expiring_domains(REPIN_LEAD, now);
            if let Err(e) = registry.save(&registry_path) {
                let _ = events.send(Event::Error(format!(
                    "failed to persist route registry: {e}"
                )));
            }
            drop(registry);
            if !expiring.is_empty() {
                let _ = commands.send(Command::RepinDomains(expiring));
            }
            next = now + CLEANUP_INTERVAL;
            continue;
        }
        thread::park_timeout(next.saturating_duration_since(now));
    }
}

/// Locks a mutex, recovering from poisoning (a panicked thread) instead of
/// panicking itself.
pub(crate) fn lock_ok<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Locks an `RwLock` for reading, recovering from poisoning.
pub(crate) fn read_ok<T>(rw: &RwLock<T>) -> RwLockReadGuard<'_, T> {
    rw.read().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Locks an `RwLock` for writing, recovering from poisoning.
pub(crate) fn write_ok<T>(rw: &RwLock<T>) -> RwLockWriteGuard<'_, T> {
    rw.write()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Whether an I/O error is a socket timeout (not a real failure).
pub(crate) fn is_timeout(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    )
}
