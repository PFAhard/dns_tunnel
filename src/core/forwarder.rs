//! Upstream client: receives DNS responses, returns them to the client that
//! asked, and adds routes for redirect-list domains (see `docs/design.md` §5).

use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;

use crate::core::dns::message::{collect_a_records, parse_questions};
use crate::core::dns::server::PendingMap;
use crate::core::engine::{
    Event, MAX_DNS_UDP, POLL_INTERVAL, is_timeout, lock_ok, read_ok, write_ok,
};
use crate::core::router::RouteRegistry;

/// Receives upstream responses until `shutdown` is set.
///
/// The upstream socket is shared with the listener thread (sends) and is
/// recreated here when a receive error poisons it.
///
/// Thread entry point: takes ownership because the caller hands the values
/// to a new thread.
#[allow(clippy::needless_pass_by_value)]
pub(crate) fn run(
    listener: Arc<UdpSocket>,
    upstream: Arc<RwLock<UdpSocket>>,
    upstream_addr: SocketAddr,
    pending: PendingMap,
    registry: Arc<Mutex<RouteRegistry>>,
    events: mpsc::Sender<Event>,
    shutdown: Arc<AtomicBool>,
) {
    let mut buf = vec![0u8; MAX_DNS_UDP];
    loop {
        if shutdown.load(Ordering::Relaxed) {
            return;
        }
        // Bind the receive result to a local first: a read-lock guard as a
        // match-scrutinee temporary lives through the arms, and the error
        // arm takes the WRITE lock to recreate the socket — self-deadlock.
        let received = read_ok(&upstream).recv_from(&mut buf);
        match received {
            Ok((len, source)) if source == upstream_addr => {
                // Drop pending queries whose deadline passed — the client
                // will time out on its own.
                lock_ok(&pending).retain(|_, entry| entry.deadline > Instant::now());
                handle_response(&mut buf, len, &listener, &pending, &registry, &events);
            }
            Ok((len, source)) => {
                let _ = events.send(Event::Warning(format!(
                    "ignored datagram from unexpected source {source} ({len} bytes)"
                )));
            }
            Err(e) if is_timeout(&e) => {}
            Err(e) => {
                // A transient error can kill a UDP socket; rebuild instead
                // of dying — the listener keeps sending through the shared
                // socket either way.
                let _ = events.send(Event::Warning(format!(
                    "upstream receive failed ({e}) — recreating the upstream socket"
                )));
                match recreate_upstream(&upstream) {
                    Ok(()) => {
                        // In-flight queries died with the old socket; drop
                        // them so clients retry against the new one.
                        let dropped = {
                            let mut pending = lock_ok(&pending);
                            let count = pending.len();
                            pending.clear();
                            count
                        };
                        if dropped > 0 {
                            let _ = events.send(Event::Info(format!(
                                "dropped {dropped} pending quer(ies) after socket reset — clients will retry"
                            )));
                        }
                    }
                    Err(recreate_error) => {
                        let _ = events.send(Event::Error(format!(
                            "failed to recreate upstream socket: {recreate_error}"
                        )));
                        std::thread::sleep(POLL_INTERVAL);
                    }
                }
            }
        }
    }
}

/// Binds a fresh upstream socket and swaps it in for the shared one.
fn recreate_upstream(upstream: &RwLock<UdpSocket>) -> std::io::Result<()> {
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.set_read_timeout(Some(POLL_INTERVAL))?;
    *write_ok(upstream) = socket;
    Ok(())
}

fn handle_response(
    buf: &mut [u8],
    len: usize,
    listener: &UdpSocket,
    pending: &PendingMap,
    registry: &Mutex<RouteRegistry>,
    events: &mpsc::Sender<Event>,
) {
    let bytes = &buf[..len];
    let Ok((header, _, cursor)) = parse_questions(bytes) else {
        let _ = events.send(Event::Warning(format!(
            "unparsable upstream response ({len} bytes) — dropped"
        )));
        return;
    };
    let Some(entry) = lock_ok(pending).remove(&header.id) else {
        let _ = events.send(Event::Warning(format!(
            "no pending query for upstream id {} — dropped",
            header.id
        )));
        return;
    };

    let mut out = bytes.to_vec();
    if let Some(head) = out.get_mut(0..2) {
        head.copy_from_slice(&entry.orig_id.to_be_bytes());
    }

    if entry.needs_routing
        && let Ok(addresses) = collect_a_records(bytes, &header, cursor)
    {
        let mut registry = lock_ok(registry);
        for ip in addresses {
            match registry.register(ip, Instant::now()) {
                Ok(true) => {
                    let _ = events.send(Event::RouteAdded { ip });
                }
                Ok(false) => {} // refresh — silent
                Err(e) => {
                    let _ = events.send(Event::Error(format!("failed to add route for {ip}: {e}")));
                }
            }
        }
    }

    // Answers go out from the listener socket — bound to the address the
    // client sent its query to. Sending from an ephemeral socket (the
    // previous design) breaks UDP clients, which match replies by source
    // IP:port and silently drop a reply from the wrong port.
    if let Some(client) = entry.client
        && let Err(e) = listener.send_to(&out, client)
    {
        let _ = events.send(Event::Error(format!(
            "failed to return response to {client}: {e}"
        )));
    }
}
