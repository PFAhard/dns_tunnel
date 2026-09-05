//! Per-app DNS attribution on Windows, in two complementary mechanisms.
//!
//! 1. **ETW** (`ProcessTracker`): apps using the OS resolver emit
//!    DNS-Client ETW events *from their own process* (header PID = the
//!    requester — verified empirically). Matching is two-phase: the
//!    listener notes every forwarded query into a pending queue, and the
//!    ETW callback (whose events arrive in ~1-second batches, *after* the
//!    proxy has seen the query) joins them by domain within a short window.
//! 2. **Port ownership** (`PortOwners`): browsers run their own resolvers
//!    and query the proxy directly from their own sockets — they never
//!    emit ETW events. Their PID is recovered from a periodic snapshot of
//!    the OS UDP port table instead.
//!
//! See `docs/design.md` §5 for the dependency justification.

use std::collections::{HashMap, VecDeque};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use ferrisetw::EventRecord;
use ferrisetw::parser::Parser;
use ferrisetw::provider::{Provider, TraceFlags};
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::trace::UserTrace;

use crate::core::engine::{lock_ok, read_ok, write_ok};
use crate::core::redirect::normalize_domain;
use crate::core::router::windows::hidden;

/// DNS-Client provider GUID.
const DNS_CLIENT_PROVIDER: &str = "1c95126e-7eea-49a9-a3fe-a378b03ddb4d";

/// How long a noted query waits for its ETW event (ETW batches can lag by
/// seconds under load).
const ATTRIBUTION_WINDOW: Duration = Duration::from_secs(5);

/// How long an attribution stays answerable after it was made.
const ATTRIBUTION_HOLDOFF: Duration = Duration::from_secs(6);

/// Upper bound for the pending queue — browsers flood queries far faster
/// than the window; entries evicted before their event lands lose their
/// attribution. Memory is trivial (a few strings × 2k).
const PENDING_CAPACITY: usize = 2048;

/// State shared between the ETW callback thread and the listener.
#[derive(Default)]
struct State {
    /// Queries noted by the listener, awaiting their ETW event:
    /// (domain, noted-at).
    pending: VecDeque<(String, Instant)>,
    /// Resolved attributions: domain → (process name, attributed-at).
    attrs: HashMap<String, (String, Instant)>,
    /// Resolved names per PID.
    names: HashMap<u32, String>,
}

impl State {
    /// Notes a forwarded query for later attribution.
    fn note_query(&mut self, domain: String, now: Instant) {
        self.pending.push_back((domain, now));
        if self.pending.len() > PENDING_CAPACITY {
            self.pending.pop_front();
        }
    }

    /// Joins an ETW event against the pending queries.
    fn on_event(&mut self, domain: &str, pid: u32, name: &str, now: Instant) {
        self.names.entry(pid).or_insert_with(|| name.to_owned());
        let mut attributed = false;
        self.pending.retain(|(queued, queued_at)| {
            if now.duration_since(*queued_at) > ATTRIBUTION_WINDOW {
                return false; // expired — no event ever came
            }
            if !attributed && *queued == domain {
                attributed = true;
                self.attrs.insert(domain.to_owned(), (name.to_owned(), now));
                return false;
            }
            true
        });
    }

    /// Returns the process name attributed to `domain`, if still fresh.
    fn attribute(&self, domain: &str, now: Instant) -> Option<String> {
        let (name, attributed_at) = self.attrs.get(domain)?;
        if now.duration_since(*attributed_at) > ATTRIBUTION_HOLDOFF {
            return None;
        }
        Some(name.clone())
    }
}

/// Tracks which process asked for which domain, in real time.
///
/// Dropping it stops the ETW session.
pub struct ProcessTracker {
    state: Arc<Mutex<State>>,
    /// Held to keep the trace session alive.
    _trace: UserTrace,
}

impl ProcessTracker {
    /// Starts the ETW subscription.
    ///
    /// # Errors
    ///
    /// Returns an error if the trace session cannot be started.
    pub fn start() -> Result<Self, String> {
        let state = Arc::new(Mutex::new(State::default()));
        let callback_state = Arc::clone(&state);
        let provider = Provider::by_guid(DNS_CLIENT_PROVIDER)
            .add_callback(move |record, locator| on_event(record, locator, &callback_state))
            .trace_flags(TraceFlags::EVENT_ENABLE_PROPERTY_PROCESS_START_KEY)
            .build();
        let trace = UserTrace::new()
            .enable(provider)
            .start_and_process()
            .map_err(|error| format!("failed to start ETW trace: {error:?}"))?;
        Ok(Self {
            state,
            _trace: trace,
        })
    }

    /// Notes a forwarded query, to be attributed when its ETW event lands.
    pub fn note_query(&self, domain: &str) {
        let domain = normalize_domain(domain);
        lock_ok(&self.state).note_query(domain, Instant::now());
    }

    /// Returns the process name attributed to `domain`, if any is fresh.
    #[must_use]
    pub fn process_for(&self, domain: &str) -> Option<String> {
        let domain = normalize_domain(domain);
        let state = lock_ok(&self.state);
        state.attribute(&domain, Instant::now())
    }
}

/// Callback invoked by ferrisetw on its processing thread.
fn on_event(record: &EventRecord, locator: &SchemaLocator, state: &Mutex<State>) {
    let Ok(schema) = locator.event_schema(record) else {
        return;
    };
    let parser = Parser::create(record, &schema);
    let Ok(domain) = parser.try_parse::<String>("QueryName") else {
        return;
    };
    if domain.is_empty() {
        return;
    }
    let pid = record.process_id();
    let name = {
        let mut s = lock_ok(state);
        if let Some(cached) = s.names.get(&pid) {
            cached.clone()
        } else {
            let resolved = process_name(pid);
            s.names.insert(pid, resolved.clone());
            resolved
        }
    };
    // dnscache emits its own events for every relayed query; joining on
    // them would mislabel app queries as svchost. Genuine service queries
    // are still covered by the port-ownership fallback.
    if name.eq_ignore_ascii_case("svchost.exe") {
        return;
    }
    lock_ok(state).on_event(&normalize_domain(&domain), pid, &name, Instant::now());
}

/// UDP local-port → owning-PID snapshot, refreshed in the background.
///
/// Direct clients (browsers with built-in resolvers) query the proxy from
/// their own sockets; the OS port table names the owner.
pub struct PortOwners {
    map: Arc<RwLock<HashMap<u16, u32>>>,
    names: Mutex<HashMap<u32, String>>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl PortOwners {
    /// Starts the snapshot refresher (once per second).
    #[must_use]
    pub fn start() -> Self {
        let map = Arc::new(RwLock::new(HashMap::new()));
        let thread_map = Arc::clone(&map);
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let thread = std::thread::Builder::new()
            .name("port-owners".to_owned())
            .spawn(move || {
                while !thread_stop.load(Ordering::Relaxed) {
                    if let Some(snapshot) = snapshot_ports() {
                        *write_ok(&thread_map) = snapshot;
                    }
                    std::thread::sleep(Duration::from_secs(1));
                }
            })
            .ok();
        Self {
            map,
            names: Mutex::new(HashMap::new()),
            stop,
            thread,
        }
    }

    /// Returns the PID owning `port` at the last snapshot.
    #[must_use]
    pub fn owner_of(&self, port: u16) -> Option<u32> {
        read_ok(&self.map).get(&port).copied()
    }

    /// Resolves a PID to its process name, cached.
    #[must_use]
    pub fn name_of(&self, pid: u32) -> String {
        let mut names = lock_ok(&self.names);
        names
            .entry(pid)
            .or_insert_with(|| process_name(pid))
            .clone()
    }
}

impl Drop for PortOwners {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Parses `netstat -ano -p UDP` output into a port → PID map.
fn parse_netstat(text: &str) -> HashMap<u16, u32> {
    let mut map = HashMap::new();
    for line in text.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 4 || fields[0] != "UDP" {
            continue;
        }
        let Some(port) = fields[1]
            .rsplit(':')
            .next()
            .and_then(|p| p.parse::<u16>().ok())
        else {
            continue;
        };
        if let Ok(pid) = fields[3].parse::<u32>() {
            map.insert(port, pid);
        }
    }
    map
}

/// Takes a fresh port-ownership snapshot.
fn snapshot_ports() -> Option<HashMap<u16, u32>> {
    let output = hidden(Command::new("netstat"))
        .args(["-ano", "-p", "UDP"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    Some(parse_netstat(&String::from_utf8_lossy(&output.stdout)))
}

/// Resolves a PID to its process name via `tasklist`.
fn process_name(pid: u32) -> String {
    let Ok(output) = hidden(Command::new("tasklist"))
        .args(["/FI", &format!("PID eq {pid}"), "/FO", "CSV", "/NH"])
        .output()
    else {
        return pid.to_string();
    };
    if !output.status.success() {
        return pid.to_string();
    }
    let text = String::from_utf8_lossy(&output.stdout);
    text.split(',')
        .next()
        .map(|name| name.trim().trim_matches('"').to_owned())
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| pid.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t0() -> Instant {
        Instant::now()
    }

    #[test]
    fn attributes_when_event_lands_after_query() {
        let mut state = State::default();
        let start = t0();
        state.note_query("example.com".to_owned(), start);
        state.on_event(
            "example.com",
            100,
            "chrome.exe",
            start + Duration::from_millis(500),
        );
        assert_eq!(
            state
                .attribute("example.com", start + Duration::from_secs(1))
                .as_deref(),
            Some("chrome.exe")
        );
    }

    #[test]
    fn no_attribution_without_event() {
        let mut state = State::default();
        let start = t0();
        state.note_query("example.com".to_owned(), start);
        assert_eq!(
            state.attribute("example.com", start + Duration::from_secs(1)),
            None
        );
    }

    #[test]
    fn event_arriving_after_window_does_not_join() {
        let mut state = State::default();
        let start = t0();
        state.note_query("example.com".to_owned(), start);
        state.on_event(
            "example.com",
            100,
            "chrome.exe",
            start + ATTRIBUTION_WINDOW + Duration::from_secs(1),
        );
        assert_eq!(
            state.attribute(
                "example.com",
                start + ATTRIBUTION_WINDOW + Duration::from_secs(2)
            ),
            None
        );
    }

    #[test]
    fn attribution_expires_after_holdoff() {
        let mut state = State::default();
        let start = t0();
        state.note_query("example.com".to_owned(), start);
        state.on_event(
            "example.com",
            100,
            "chrome.exe",
            start + Duration::from_millis(500),
        );
        assert_eq!(
            state.attribute(
                "example.com",
                start + ATTRIBUTION_HOLDOFF + Duration::from_secs(1)
            ),
            None
        );
    }

    #[test]
    fn first_pending_match_wins_per_event() {
        let mut state = State::default();
        let start = t0();
        state.note_query("example.com".to_owned(), start);
        state.note_query("example.com".to_owned(), start + Duration::from_millis(100));
        state.on_event(
            "example.com",
            200,
            "firefox.exe",
            start + Duration::from_millis(500),
        );
        // The remaining pending entry has no event — attribution reflects
        // only the joined (first) query.
        assert_eq!(
            state
                .attribute("example.com", start + Duration::from_secs(1))
                .as_deref(),
            Some("firefox.exe")
        );
    }

    #[test]
    fn falls_back_to_pid_when_name_missing() {
        let mut state = State::default();
        let start = t0();
        state.note_query("example.com".to_owned(), start);
        // Directly seed an attribution without a name cache entry.
        state
            .attrs
            .insert("example.com".to_owned(), ("42".to_owned(), start));
        assert_eq!(state.attribute("example.com", start).as_deref(), Some("42"));
    }

    #[test]
    fn parses_netstat_port_ownership() {
        let text = "  UDP    127.0.0.1:54321           *:*                                    3040\r\n\
                    UDP    0.0.0.0:5353             *:*                                    1234\r\n\
                    UDP    [::1]:53000              *:*                                    5678\r\n\
                    not a udp line";
        let map = parse_netstat(text);
        assert_eq!(map.get(&54321), Some(&3040));
        assert_eq!(map.get(&5353), Some(&1234));
        assert_eq!(map.get(&53000), Some(&5678));
    }
}
