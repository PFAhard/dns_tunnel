//! UDP listener: receives client queries, forwards them upstream, and
//! tracks pending queries by our own ID (see `docs/design.md` §5).

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use crate::core::dns::message::{TYPE_A, encode_query, parse_questions};
use crate::core::engine::{
    Command, Event, MAX_DNS_UDP, MIN_UPSTREAM_SEND_INTERVAL, POLL_INTERVAL, is_timeout, lock_ok,
    read_ok, write_ok,
};
use crate::core::etw::{PortOwners, ProcessTracker};
use crate::core::redirect::RedirectList;
use crate::core::router::RouteRegistry;
use crate::core::router::cidr::Cidr;

/// A query forwarded upstream, awaiting its response.
#[derive(Debug)]
pub(crate) struct Pending {
    /// Client that asked — `None` for the engine's own pre-pin queries.
    pub client: Option<SocketAddr>,
    /// The client's original query ID — restored before answering.
    pub orig_id: u16,
    /// Whether the queried domain matched the redirect list.
    pub needs_routing: bool,
    /// When to give up on the upstream response.
    pub deadline: Instant,
}

/// Pending queries, keyed by our own query ID.
pub(crate) type PendingMap = Arc<Mutex<HashMap<u16, Pending>>>;

/// How long a forwarded query waits before its log event is emitted —
/// gives the ETW attribution (batched, seconds late under load) time to
/// land before the port-ownership fallback sticks.
const ATTRIBUTION_DELAY: Duration = Duration::from_secs(3);

/// Shared state for the listener thread.
///
/// Fields are owned — the thread entry point receives them by value and
/// uses them for its whole lifetime.
pub(crate) struct ListenerCtx {
    /// Upstream socket (shared with the forwarder thread, which may replace
    /// it on receive errors).
    pub upstream: Arc<RwLock<UdpSocket>>,
    /// Address of the real resolver — queries are sent here explicitly.
    pub upstream_addr: SocketAddr,
    /// Pending queries keyed by our ID.
    pub pending: PendingMap,
    /// Redirect-list matcher — shared with the UI, replaced on save.
    pub redirect: Arc<RwLock<RedirectList>>,
    /// Route registry — static network updates from the UI land here.
    pub registry: Arc<Mutex<RouteRegistry>>,
    /// Per-app attribution tracker (`None` when ETW is unavailable).
    pub tracker: Option<Arc<ProcessTracker>>,
    /// Port-ownership snapshots for direct clients (browser resolvers).
    pub ports: Arc<PortOwners>,
    /// Commands from the UI (e.g. redirect-list updates).
    pub commands: mpsc::Receiver<Command>,
    /// Counter for our query IDs.
    pub id_counter: Arc<AtomicU16>,
    /// How long to wait for an upstream response.
    pub timeout: Duration,
    /// Event sink.
    pub events: mpsc::Sender<Event>,
    /// Shutdown flag.
    pub shutdown: Arc<AtomicBool>,
}

/// Receives queries and forwards them upstream until shutdown.
///
/// Thread entry point: takes ownership because the caller hands the values
/// to a new thread.
#[allow(clippy::needless_pass_by_value)]
pub(crate) fn run(listener: Arc<UdpSocket>, ctx: ListenerCtx) {
    // Pin the whole redirect list up front: clients may hold cached IPs and
    // won't re-query for a while after a restart.
    let mut last_send = Instant::now();
    let initial: Vec<String> = read_ok(&ctx.redirect).domains().to_vec();
    pin_domains(initial, &ctx, &mut last_send);

    let mut buf = vec![0u8; MAX_DNS_UDP];
    let mut deferred: VecDeque<(String, Option<u16>, Instant)> = VecDeque::new();
    loop {
        if ctx.shutdown.load(Ordering::Relaxed) {
            return;
        }
        while deferred
            .front()
            .is_some_and(|(_, _, due)| *due <= Instant::now())
        {
            if let Some((domain, source_port, _)) = deferred.pop_front() {
                let process = ctx
                    .tracker
                    .as_ref()
                    .and_then(|tracker| tracker.process_for(&domain))
                    .or_else(|| {
                        let port = source_port?;
                        let pid = ctx.ports.owner_of(port)?;
                        (pid != 0 && pid != 4).then(|| ctx.ports.name_of(pid))
                    });

                let in_redirect_list = read_ok(&ctx.redirect).matches(&domain);

                let _ = ctx.events.send(Event::QueryForwarded { domain, process, in_redirect_list });
            }
        }
        while let Ok(command) = ctx.commands.try_recv() {
            match command {
                Command::SetRedirectList(domains) => {
                    let old: Vec<String> = read_ok(&ctx.redirect).domains().to_vec();
                    let new = RedirectList::new(domains);
                    let added: Vec<String> = new
                        .domains()
                        .iter()
                        .filter(|domain| !old.iter().any(|known| known == *domain))
                        .cloned()
                        .collect();
                    let count = new.len();
                    *write_ok(&ctx.redirect) = new;
                    let _ = ctx.events.send(Event::Info(format!(
                        "redirect list updated: {count} domain(s)"
                    )));
                    // Pre-resolve newly added domains so their routes exist
                    // before clients with cached IPs reconnect.
                    pin_domains(added, &ctx, &mut last_send);
                }
                Command::SetCidrList(cidrs) => {
                    let nets: BTreeSet<Cidr> = cidrs
                        .iter()
                        .filter_map(|cidr| Cidr::parse(cidr).ok())
                        .collect();
                    let (removed, added, errors) = lock_ok(&ctx.registry).set_nets(nets);
                    for cidr in removed {
                        let _ = ctx
                            .events
                            .send(Event::Info(format!("static route - {cidr}")));
                    }
                    for cidr in added {
                        let _ = ctx
                            .events
                            .send(Event::Info(format!("static route + {cidr}")));
                    }
                    for error in errors {
                        let _ = ctx.events.send(Event::Error(error));
                    }
                }
            }
        }
        match listener.recv_from(&mut buf) {
            Ok((len, client)) => {
                handle_query(&mut buf, len, client, &ctx, &mut last_send, &mut deferred);
            }
            Err(e) if is_timeout(&e) => {}
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {
                // A previous reply to a since-closed client port made the
                // local stack send an ICMP port-unreachable, which Windows
                // surfaces as WSAECONNRESET on the next recv. Harmless —
                // just keep receiving.
            }
            Err(e) => {
                // Transient receive errors must not kill the engine.
                let _ = ctx
                    .events
                    .send(Event::Error(format!("listener receive failed: {e}")));
                std::thread::sleep(POLL_INTERVAL);
            }
        }
    }
}

fn handle_query(
    buf: &mut [u8],
    len: usize,
    client: SocketAddr,
    ctx: &ListenerCtx,
    last_send: &mut Instant,
    deferred: &mut VecDeque<(String, Option<u16>, Instant)>,
) {
    let bytes = &buf[..len];
    let (header, questions, _) = match parse_questions(bytes) {
        Ok(parsed) => parsed,
        Err(e) => {
            let _ = ctx
                .events
                .send(Event::Error(format!("unparsable query from {client}: {e}")));
            return;
        }
    };
    let Some(question) = questions.first() else {
        return; // nothing to forward
    };

    // Replace the client's ID with one of ours so response correlation
    // never collides between clients.
    let id = next_free_id(&ctx.id_counter, &ctx.pending);
    let mut fwd = bytes.to_vec();
    if let Some(head) = fwd.get_mut(0..2) {
        head.copy_from_slice(&id.to_be_bytes());
    }
    let deadline = Instant::now() + ctx.timeout;
    lock_ok(&ctx.pending).insert(
        id,
        Pending {
            client: Some(client),
            orig_id: header.id,
            needs_routing: read_ok(&ctx.redirect).matches(&question.name),
            deadline,
        },
    );
    throttle(last_send);
    if read_ok(&ctx.upstream)
        .send_to(&fwd, ctx.upstream_addr)
        .is_err()
    {
        lock_ok(&ctx.pending).remove(&id);
        let _ = ctx.events.send(Event::Error(
            "failed to forward query to upstream".to_owned(),
        ));
        return;
    }
    if let Some(tracker) = &ctx.tracker {
        tracker.note_query(&question.name);
    }
    // The source port is only meaningful for local clients (loopback) —
    // LAN devices cannot be attributed.
    let source_port = client.ip().is_loopback().then(|| client.port());
    deferred.push_back((
        question.name.clone(),
        source_port,
        Instant::now() + ATTRIBUTION_DELAY,
    ));
}

/// Sleeps until [`MIN_UPSTREAM_SEND_INTERVAL`] has passed since the last
/// upstream send, so protective resolvers don't see query bursts.
fn throttle(last_send: &mut Instant) {
    if let Some(remaining) = MIN_UPSTREAM_SEND_INTERVAL.checked_sub(last_send.elapsed()) {
        std::thread::sleep(remaining);
    }
    *last_send = Instant::now();
}

/// Returns an ID that is not currently used in the pending table.
///
/// Bounded to one full sweep of the u16 space. Every slot being taken
/// means the forwarder is stuck; overwriting a stale entry is preferable
/// to hanging the listener thread forever.
fn next_free_id(counter: &AtomicU16, pending: &PendingMap) -> u16 {
    let mut id = 0u16;
    for _ in 0..=u16::MAX {
        id = counter.fetch_add(1, Ordering::Relaxed);
        if !lock_ok(pending).contains_key(&id) {
            return id;
        }
    }
    id
}

/// Pre-resolves `domains` upstream so their IPs get routed immediately —
/// covers clients that hold cached IPs and won't re-query for a while.
///
/// Synthetic queries: nobody is waiting for the answer (`client: None`), but
/// the routing side of the response handling still pins the routes.
fn pin_domains(domains: Vec<String>, ctx: &ListenerCtx, last_send: &mut Instant) {
    for domain in domains {
        let id = next_free_id(&ctx.id_counter, &ctx.pending);
        let Ok(query) = encode_query(id, &domain, TYPE_A) else {
            continue; // list entries are pre-validated; defensive only
        };
        lock_ok(&ctx.pending).insert(
            id,
            Pending {
                client: None,
                orig_id: id,
                needs_routing: true,
                deadline: Instant::now() + ctx.timeout,
            },
        );
        throttle(last_send);
        if read_ok(&ctx.upstream)
            .send_to(&query, ctx.upstream_addr)
            .is_err()
        {
            lock_ok(&ctx.pending).remove(&id);
            let _ = ctx.events.send(Event::Error(format!(
                "failed to pre-pin {domain}: upstream unreachable"
            )));
        }
    }
}
