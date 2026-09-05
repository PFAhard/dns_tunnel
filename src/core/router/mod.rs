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

/// Path of the persisted registry: `%APPDATA%\dns_tunnel\routes.ron`.
#[must_use]
pub fn registry_path() -> Option<PathBuf> {
    std::env::var_os("APPDATA")
        .map(|base| PathBuf::from(base).join("dns_tunnel").join("routes.ron"))
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
    entries: BTreeMap<Ipv4Addr, Instant>,
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
            // Age is irrelevant: leftovers are deleted on load.
            entries.insert(ip, Instant::now());
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

    /// Registers a host route for `ip`.
    ///
    /// If the IP is already routed, only its timestamp is refreshed.
    /// Returns `Ok(true)` when a new OS route was added.
    ///
    /// # Errors
    ///
    /// Returns an error if the OS refuses the route (e.g. unreachable
    /// next hop). Persistence is best-effort — a failed save is ignored;
    /// reboot-clearance and manual cleanup remain as safety nets.
    pub fn register(&mut self, ip: Ipv4Addr, now: Instant) -> io::Result<bool> {
        if let Some(added) = self.entries.get_mut(&ip) {
            *added = now;
            return Ok(false);
        }
        self.ops.add_route(ip, self.next_hop)?;
        self.entries.insert(ip, now);
        Ok(true)
    }

    /// Removes entries at least `ttl` old.
    ///
    /// Returns the removed IPs and error messages for deletions that failed
    /// (those entries are kept and retried on the next cycle).
    #[must_use]
    pub fn expire(&mut self, now: Instant, ttl: Duration) -> (Vec<Ipv4Addr>, Vec<String>) {
        let mut removed = Vec::new();
        let mut errors = Vec::new();
        self.entries.retain(|ip, added| {
            if now.duration_since(*added) < ttl {
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
    fn register_adds_os_route_once_then_refreshes() {
        let ops = FakeOps::new();
        let mut registry = RouteRegistry::new(gateway(), Box::new(ops.clone()));
        let now = Instant::now();
        assert!(registry.register(ip(4), now).unwrap());
        assert!(
            !registry
                .register(ip(4), now + Duration::from_mins(1))
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
            registry.register(ip(5), Instant::now()).unwrap();
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
        registry
            .register(ip(1), now.checked_sub(Duration::from_secs(2_000)).unwrap())
            .unwrap();
        registry
            .register(ip(2), now.checked_sub(Duration::from_mins(1)).unwrap())
            .unwrap();
        let (removed, errors) = registry.expire(now, Duration::from_mins(15));
        assert_eq!(errors, Vec::<String>::new());
        assert_eq!(removed, vec![ip(1)]);
        assert_eq!(ops.deleted(), vec![ip(1)]);
        assert_eq!(registry.len(), 1);
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

    #[test]
    fn delete_all_removes_everything() {
        let ops = FakeOps::new();
        let mut registry = RouteRegistry::new(gateway(), Box::new(ops.clone()));
        registry.register(ip(1), Instant::now()).unwrap();
        registry.register(ip(2), Instant::now()).unwrap();
        let (removed, errors) = registry.delete_all();
        assert_eq!(errors, Vec::<String>::new());
        assert_eq!(removed, vec![ip(1), ip(2)]);
        assert!(registry.is_empty());
    }
}
