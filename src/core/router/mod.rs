//! Route registry: tracks which IPs are pinned to the VPN gateway, expires
//! them, and persists them for crash cleanup.
//!
//! OS-specific route commands live in [`windows`]; [`RouteOps`] is the seam
//! that keeps this module testable and future ports cheap.

pub mod cidr;
pub mod windows;

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::core::router::cidr::Cidr;

/// OS-level route manipulation (implemented by [`windows::WindowsRouter`]).
pub trait RouteOps: Send + Sync {
    /// Adds a host route for `ip` via `gateway`.
    ///
    /// # Errors
    ///
    /// Returns an error if the OS command fails.
    fn add_route(&self, ip: Ipv4Addr, gateway: Ipv4Addr) -> io::Result<()>;
    /// Removes the host route for `ip` via `gateway`.
    ///
    /// # Errors
    ///
    /// Returns an error if the OS command fails.
    fn delete_route(&self, ip: Ipv4Addr, gateway: Ipv4Addr) -> io::Result<()>;
    /// Adds a network route for `cidr` via `gateway`.
    ///
    /// # Errors
    ///
    /// Returns an error if the OS command fails.
    fn add_net_route(&self, cidr: Cidr, gateway: Ipv4Addr) -> io::Result<()>;
    /// Removes the network route for `cidr` via `gateway`.
    ///
    /// # Errors
    ///
    /// Returns an error if the OS command fails.
    fn delete_net_route(&self, cidr: Cidr, gateway: Ipv4Addr) -> io::Result<()>;
}

/// Floor for a route's lifetime: a DNS TTL below this is still pinned for
/// at least this long, so a client hammering a short-TTL name does not
/// cause add/remove churn.
pub(crate) const MIN_ROUTE_TTL: Duration = Duration::from_secs(30);

/// Ceiling for a route's lifetime: a DNS answer with an unusually large
/// TTL is not pinned indefinitely. The cleanup loop re-queries near
/// expiry anyway, so this only matters if the cleanup loop stops running.
pub(crate) const MAX_ROUTE_TTL: Duration = Duration::from_secs(3600);

/// A registered host route.
#[derive(Debug, Clone)]
struct Entry {
    /// When this route should be removed unless refreshed.
    expires_at: Instant,
    /// The redirect-list domain whose A records produced this route.
    /// Used by [`RouteRegistry::expiring_domains`] to schedule re-pins.
    /// Empty for entries loaded from disk (crash cleanup deletes those
    /// before the engine starts).
    domain: String,
}

/// Path of the persisted registry: `%APPDATA%\dns_tunnel\routes.ron`.
#[must_use]
pub fn registry_path() -> Option<PathBuf> {
    std::env::var_os("APPDATA")
        .map(|base| PathBuf::from(base).join("dns_tunnel").join("routes.ron"))
}

/// Whether `ip` is a valid route destination — a routable unicast address.
///
/// Rejects the reserved ranges that make no sense as a tunnel host route:
/// `0.0.0.0/8` (source-only; resolvers return `0.0.0.0` for blocked
/// domains), `127.0.0.0/8` (loopback), `224.0.0.0/4` (multicast), and
/// `240.0.0.0/4` (reserved, including the broadcast address). Private,
/// link-local, and shared-address ranges are accepted — the VPN can
/// legitimately route them.
#[must_use]
pub fn is_routable(ip: Ipv4Addr) -> bool {
    let first = ip.octets()[0];
    first != 0 && first != 127 && first < 224
}

/// On-disk shape of the registry.
///
/// The field is named `gateway` for compatibility with existing registry
/// files; the value is the route next hop.
#[derive(Serialize, Deserialize)]
struct RegistryFile {
    gateway: String,
    routes: Vec<String>,
    #[serde(default)]
    nets: Vec<String>,
}

/// The set of host routes currently pinned to the VPN tunnel.
pub struct RouteRegistry {
    next_hop: Ipv4Addr,
    entries: BTreeMap<Ipv4Addr, Entry>,
    nets: BTreeSet<Cidr>,
    ops: Box<dyn RouteOps>,
}

impl RouteRegistry {
    /// Creates an empty registry that routes via `next_hop` (the tunnel's
    /// point-to-point peer or the configured gateway).
    #[must_use]
    pub fn new(next_hop: Ipv4Addr, ops: Box<dyn RouteOps>) -> Self {
        Self {
            next_hop,
            entries: BTreeMap::new(),
            nets: BTreeSet::new(),
            ops,
        }
    }

    /// Loads the registry from `path`.
    ///
    /// Returns the loaded registry and whether the file existed. A missing
    /// file yields an empty registry using `fallback_next_hop`.
    ///
    /// # Errors
    ///
    /// Returns an error if the file exists but cannot be read or parsed.
    pub fn load(
        path: &Path,
        ops: Box<dyn RouteOps>,
        fallback_next_hop: Ipv4Addr,
    ) -> io::Result<(Self, bool)> {
        let Ok(raw) = std::fs::read_to_string(path) else {
            return Ok((Self::new(fallback_next_hop, ops), false));
        };
        let parsed: RegistryFile = ron::from_str(&raw).map_err(|e| {
            io::Error::other(format!(
                "corrupt route registry `{}`: {e} (delete the file to reset)",
                path.display()
            ))
        })?;
        let next_hop: Ipv4Addr = parsed
            .gateway
            .parse()
            .map_err(|_| io::Error::other(format!("corrupt gateway in `{}`", path.display())))?;
        let mut entries = BTreeMap::new();
        for route in parsed.routes {
            let ip: Ipv4Addr = route.parse().map_err(|_| {
                io::Error::other(format!("corrupt route entry in `{}`", path.display()))
            })?;
            // Loaded entries are immediately expired (crash cleanup deletes
            // them before the engine starts), and have no domain
            // attribution — both only matter while the engine runs.
            entries.insert(
                ip,
                Entry {
                    expires_at: Instant::now(),
                    domain: String::new(),
                },
            );
        }
        let mut nets = BTreeSet::new();
        for net in parsed.nets {
            let cidr = Cidr::parse(&net).map_err(|e| {
                io::Error::other(format!(
                    "corrupt network entry `{net}` in `{}`: {e}",
                    path.display()
                ))
            })?;
            nets.insert(cidr);
        }
        Ok((
            Self {
                next_hop,
                entries,
                nets,
                ops,
            },
            true,
        ))
    }

    /// Writes the registry to `path` (ron format).
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be written.
    pub fn save(&self, path: &Path) -> io::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = RegistryFile {
            gateway: self.next_hop.to_string(),
            routes: self.entries.keys().map(ToString::to_string).collect(),
            nets: self.nets.iter().map(ToString::to_string).collect(),
        };
        let raw = ron::to_string(&file)
            .map_err(|e| io::Error::other(format!("serializing route registry: {e}")))?;
        std::fs::write(path, raw)
    }

    /// The next hop used for route commands.
    #[must_use]
    pub fn next_hop(&self) -> Ipv4Addr {
        self.next_hop
    }

    /// Replaces the next hop (e.g. after a VPN reconnect flipped the
    /// point-to-point peer). Call [`Self::delete_all`] first when entries
    /// still reference the old next hop.
    pub fn set_next_hop(&mut self, next_hop: Ipv4Addr) {
        self.next_hop = next_hop;
    }

    /// Registers a host route for `ip`, valid for `ttl` (from the DNS
    /// answer, clamped to `[MIN_ROUTE_TTL, MAX_ROUTE_TTL]`).
    ///
    /// If the IP is already routed, its expiry and domain attribution are
    /// refreshed (last observed wins). Returns `Ok(true)` when a new OS
    /// route was added.
    ///
    /// Non-routable addresses ([`is_routable`]) are silently skipped and
    /// reported as `Ok(false)` — resolvers return `0.0.0.0` for blocked
    /// domains, and a route for it (or for loopback / multicast /
    /// reserved) is meaningless and would only add noise to the log.
    ///
    /// # Errors
    ///
    /// Returns an error if the OS refuses the route (e.g. unreachable
    /// next hop). Persistence is best-effort — a failed save is ignored;
    /// reboot-clearance and manual cleanup remain as safety nets.
    pub fn register(
        &mut self,
        ip: Ipv4Addr,
        ttl: Duration,
        domain: &str,
        now: Instant,
    ) -> io::Result<bool> {
        if !is_routable(ip) {
            return Ok(false);
        }
        let expires_at = now + ttl.clamp(MIN_ROUTE_TTL, MAX_ROUTE_TTL);
        if let Some(entry) = self.entries.get_mut(&ip) {
            entry.expires_at = expires_at;
            entry.domain = domain.to_owned();
            return Ok(false);
        }
        self.ops.add_route(ip, self.next_hop)?;
        self.entries.insert(
            ip,
            Entry {
                expires_at,
                domain: domain.to_owned(),
            },
        );
        Ok(true)
    }

    /// Removes entries whose own expiry has passed.
    ///
    /// Returns the removed IPs and error messages for deletions that failed
    /// (those entries are kept and retried on the next cycle).
    #[must_use]
    pub fn expire(&mut self, now: Instant) -> (Vec<Ipv4Addr>, Vec<String>) {
        let mut removed = Vec::new();
        let mut errors = Vec::new();
        self.entries.retain(|ip, entry| {
            if entry.expires_at > now {
                return true;
            }
            match self.ops.delete_route(*ip, self.next_hop) {
                Ok(()) => {
                    removed.push(*ip);
                    false
                }
                Err(e) => {
                    errors.push(format!("failed to remove route for {ip}: {e}"));
                    true
                }
            }
        });
        (removed, errors)
    }

    /// Returns the distinct domains whose routes expire within `within`
    /// of `now` — the ones worth re-querying so their routes stay pinned.
    /// Entries loaded from disk have no domain and are skipped.
    #[must_use]
    pub fn expiring_domains(&self, within: Duration, now: Instant) -> Vec<String> {
        let mut seen = BTreeSet::new();
        for entry in self.entries.values() {
            if entry.domain.is_empty() {
                continue;
            }
            if entry.expires_at.saturating_duration_since(now) <= within {
                seen.insert(entry.domain.clone());
            }
        }
        seen.into_iter().collect()
    }

    /// Deletes every registered route, including the static networks.
    ///
    /// Returns the removed host IPs and error messages for deletions that
    /// failed.
    #[must_use]
    pub fn delete_all(&mut self) -> (Vec<Ipv4Addr>, Vec<String>) {
        let mut removed = Vec::new();
        let mut errors = Vec::new();
        for (ip, _) in std::mem::take(&mut self.entries) {
            match self.ops.delete_route(ip, self.next_hop) {
                Ok(()) => removed.push(ip),
                Err(e) => errors.push(format!("failed to remove route for {ip}: {e}")),
            }
        }
        for cidr in std::mem::take(&mut self.nets) {
            if let Err(e) = self.ops.delete_net_route(cidr, self.next_hop) {
                errors.push(format!("failed to remove static route {cidr}: {e}"));
            }
        }
        (removed, errors)
    }

    /// Replaces the static network routes: removes configured ones that are
    /// gone, adds new ones. Returns the removed and added CIDRs plus error
    /// messages. A failed add is retried on the next peer-rebind cycle.
    #[must_use]
    pub fn set_nets(&mut self, nets: BTreeSet<Cidr>) -> (Vec<Cidr>, Vec<Cidr>, Vec<String>) {
        let mut removed = Vec::new();
        let mut added = Vec::new();
        let mut errors = Vec::new();
        for cidr in self.nets.difference(&nets) {
            match self.ops.delete_net_route(*cidr, self.next_hop) {
                Ok(()) => removed.push(*cidr),
                Err(e) => errors.push(format!("failed to remove static route {cidr}: {e}")),
            }
        }
        for cidr in nets.difference(&self.nets) {
            match self.ops.add_net_route(*cidr, self.next_hop) {
                Ok(()) => added.push(*cidr),
                Err(e) => errors.push(format!("failed to add static route {cidr}: {e}")),
            }
        }
        self.nets = nets;
        (removed, added, errors)
    }

    /// Number of registered routes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether no routes are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;

    #[derive(Default)]
    struct FakeState {
        added: Mutex<Vec<Ipv4Addr>>,
        deleted: Mutex<Vec<Ipv4Addr>>,
        added_nets: Mutex<Vec<Cidr>>,
        deleted_nets: Mutex<Vec<Cidr>>,
    }

    #[derive(Clone)]
    struct FakeOps(Arc<FakeState>);

    impl FakeOps {
        fn new() -> Self {
            Self(Arc::new(FakeState::default()))
        }

        fn added(&self) -> Vec<Ipv4Addr> {
            self.0.added.lock().unwrap().clone()
        }

        fn deleted(&self) -> Vec<Ipv4Addr> {
            self.0.deleted.lock().unwrap().clone()
        }

        fn added_nets(&self) -> Vec<Cidr> {
            self.0.added_nets.lock().unwrap().clone()
        }

        fn deleted_nets(&self) -> Vec<Cidr> {
            self.0.deleted_nets.lock().unwrap().clone()
        }
    }

    impl RouteOps for FakeOps {
        fn add_route(&self, ip: Ipv4Addr, _gateway: Ipv4Addr) -> io::Result<()> {
            self.0.added.lock().unwrap().push(ip);
            Ok(())
        }

        fn delete_route(&self, ip: Ipv4Addr, _gateway: Ipv4Addr) -> io::Result<()> {
            self.0.deleted.lock().unwrap().push(ip);
            Ok(())
        }

        fn add_net_route(&self, cidr: Cidr, _gateway: Ipv4Addr) -> io::Result<()> {
            self.0.added_nets.lock().unwrap().push(cidr);
            Ok(())
        }

        fn delete_net_route(&self, cidr: Cidr, _gateway: Ipv4Addr) -> io::Result<()> {
            self.0.deleted_nets.lock().unwrap().push(cidr);
            Ok(())
        }
    }

    fn gateway() -> Ipv4Addr {
        "10.0.0.1".parse().unwrap()
    }

    fn ip(octet: u8) -> Ipv4Addr {
        Ipv4Addr::new(1, 2, 3, octet)
    }

    fn temp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "dns_tunnel_registry_{}_{}.ron",
            std::process::id(),
            name
        ))
    }

    #[test]
    fn register_skips_non_routable_ips() {
        let ops = FakeOps::new();
        let mut registry = RouteRegistry::new(gateway(), Box::new(ops.clone()));
        let now = Instant::now();
        for ip in [
            Ipv4Addr::new(0, 0, 0, 0),
            Ipv4Addr::new(0, 0, 0, 1),
            Ipv4Addr::new(0, 255, 255, 255),
            Ipv4Addr::new(127, 0, 0, 1),
            Ipv4Addr::new(127, 255, 255, 255),
            Ipv4Addr::new(224, 0, 0, 1),
            Ipv4Addr::new(239, 255, 255, 255),
            Ipv4Addr::new(240, 0, 0, 1),
            Ipv4Addr::new(255, 255, 255, 255),
        ] {
            assert!(
                !registry
                    .register(ip, Duration::from_secs(300), "example.com", now)
                    .unwrap(),
                "{ip} should not be routed"
            );
        }
        assert!(ops.added().is_empty());
        assert!(registry.is_empty());
    }

    #[test]
    fn register_accepts_private_and_public_ips() {
        let ops = FakeOps::new();
        let mut registry = RouteRegistry::new(gateway(), Box::new(ops.clone()));
        let now = Instant::now();
        for ip in [
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(172, 16, 0, 1),
            Ipv4Addr::new(169, 254, 1, 1),
            Ipv4Addr::new(100, 64, 0, 1),
            Ipv4Addr::new(8, 8, 8, 8),
            Ipv4Addr::new(1, 1, 1, 1),
        ] {
            assert!(
                registry
                    .register(ip, Duration::from_secs(300), "example.com", now)
                    .unwrap(),
                "{ip} should be routed"
            );
        }
    }

    #[test]
    fn register_adds_os_route_once_then_refreshes() {
        let ops = FakeOps::new();
        let mut registry = RouteRegistry::new(gateway(), Box::new(ops.clone()));
        let now = Instant::now();
        assert!(
            registry
                .register(ip(4), Duration::from_secs(300), "example.com", now)
                .unwrap()
        );
        assert!(
            !registry
                .register(
                    ip(4),
                    Duration::from_secs(300),
                    "example.com",
                    now + Duration::from_mins(1)
                )
                .unwrap()
        );
        assert_eq!(ops.added(), vec![ip(4)]);
        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn save_load_roundtrip() {
        let path = temp_path("roundtrip");
        let ops = FakeOps::new();
        {
            let mut registry = RouteRegistry::new(gateway(), Box::new(ops.clone()));
            registry
                .register(ip(5), Duration::from_secs(300), "example.com", Instant::now())
                .unwrap();
            registry.save(&path).unwrap();
        }
        let (loaded, existed) = RouteRegistry::load(&path, Box::new(ops), gateway()).unwrap();
        assert!(existed);
        assert_eq!(loaded.len(), 1);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn load_missing_file_is_empty() {
        let ops = FakeOps::new();
        let (registry, existed) =
            RouteRegistry::load(&temp_path("missing"), Box::new(ops), gateway()).unwrap();
        assert!(!existed);
        assert!(registry.is_empty());
    }

    #[test]
    fn load_corrupt_file_fails() {
        let path = temp_path("corrupt");
        std::fs::write(&path, "this is not ron").unwrap();
        let ops = FakeOps::new();
        assert!(RouteRegistry::load(&path, Box::new(ops), gateway()).is_err());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn expire_removes_old_keeps_fresh() {
        let ops = FakeOps::new();
        let mut registry = RouteRegistry::new(gateway(), Box::new(ops.clone()));
        let now = Instant::now();
        // Registered long ago with a short TTL → already expired.
        registry
            .register(
                ip(1),
                Duration::from_secs(60),
                "a.example",
                now.checked_sub(Duration::from_secs(2_000)).unwrap(),
            )
            .unwrap();
        // Registered 30 s ago with a 300 s TTL → still fresh.
        registry
            .register(
                ip(2),
                Duration::from_secs(300),
                "b.example",
                now.checked_sub(Duration::from_secs(30)).unwrap(),
            )
            .unwrap();
        let (removed, errors) = registry.expire(now);
        assert_eq!(errors, Vec::<String>::new());
        assert_eq!(removed, vec![ip(1)]);
        assert_eq!(ops.deleted(), vec![ip(1)]);
        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn register_clamps_ttl_to_bounds() {
        let ops = FakeOps::new();
        let mut registry = RouteRegistry::new(gateway(), Box::new(ops.clone()));
        let now = Instant::now();
        // TTL below the floor is lifted to MIN_ROUTE_TTL.
        registry
            .register(ip(1), Duration::from_secs(1), "a.example", now)
            .unwrap();
        assert!(
            registry
                .expire(now + MIN_ROUTE_TTL - Duration::from_secs(1))
                .0
                .is_empty()
        );
        // TTL above the ceiling is cut to MAX_ROUTE_TTL.
        registry
            .register(ip(2), Duration::from_secs(10_000_000), "b.example", now)
            .unwrap();
        assert!(
            registry
                .expire(now + MAX_ROUTE_TTL - Duration::from_secs(1))
                .0
                .is_empty()
        );
    }

    #[test]
    fn expiring_domains_returns_unique_near_expiry() {
        let ops = FakeOps::new();
        let mut registry = RouteRegistry::new(gateway(), Box::new(ops.clone()));
        let now = Instant::now();
        // Two IPs for the same domain, both near expiry: deduped to one.
        registry
            .register(ip(1), Duration::from_secs(40), "a.example", now)
            .unwrap();
        registry
            .register(ip(2), Duration::from_secs(40), "a.example", now)
            .unwrap();
        // One far from expiry: not included.
        registry
            .register(ip(3), Duration::from_secs(3600), "b.example", now)
            .unwrap();
        let expiring = registry.expiring_domains(Duration::from_secs(30), now);
        assert_eq!(expiring, vec!["a.example".to_owned()]);
    }

    #[test]
    fn delete_all_removes_everything() {
        let ops = FakeOps::new();
        let mut registry = RouteRegistry::new(gateway(), Box::new(ops.clone()));
        registry
            .register(ip(1), Duration::from_secs(300), "a.example", Instant::now())
            .unwrap();
        registry
            .register(ip(2), Duration::from_secs(300), "b.example", Instant::now())
            .unwrap();
        let (removed, errors) = registry.delete_all();
        assert_eq!(errors, Vec::<String>::new());
        assert_eq!(removed, vec![ip(1), ip(2)]);
        assert!(registry.is_empty());
    }

    #[test]
    fn set_nets_diffs_and_persists() {
        let ops = FakeOps::new();
        let path = temp_path("nets");
        let mut registry = RouteRegistry::new(gateway(), Box::new(ops.clone()));
        let (removed, added, errors) = registry.set_nets(BTreeSet::from([
            Cidr::parse("91.108.0.0/16").unwrap(),
            Cidr::parse("149.154.160.0/20").unwrap(),
        ]));
        assert_eq!(removed, Vec::<Cidr>::new());
        assert_eq!(added.len(), 2);
        assert_eq!(errors, Vec::<String>::new());
        assert_eq!(ops.added_nets().len(), 2);
        registry.save(&path).unwrap();

        let (mut loaded, _) = RouteRegistry::load(&path, Box::new(ops.clone()), gateway()).unwrap();
        let (removed, added, errors) = loaded.set_nets(BTreeSet::from([
            Cidr::parse("91.108.0.0/16").unwrap(),
            Cidr::parse("10.0.0.0/8").unwrap(),
        ]));
        assert_eq!(removed, vec![Cidr::parse("149.154.160.0/20").unwrap()]);
        assert_eq!(added, vec![Cidr::parse("10.0.0.0/8").unwrap()]);
        assert_eq!(errors, Vec::<String>::new());
        assert_eq!(
            ops.deleted_nets(),
            vec![Cidr::parse("149.154.160.0/20").unwrap()]
        );
        let _ = std::fs::remove_file(&path);
    }

}
