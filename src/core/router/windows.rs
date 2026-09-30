//! Windows route manipulation via `route.exe` (IPv4 host routes).

use std::io;
use std::net::Ipv4Addr;
use std::os::windows::process::CommandExt;
use std::process::Command;

use crate::core::router::RouteOps;
use crate::core::router::cidr::Cidr;

/// `CREATE_NO_WINDOW` — console children must not flash a console window,
/// especially when the app itself runs as a GUI-subsystem binary.
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// Marks a command as window-less.
pub(crate) fn hidden(mut command: Command) -> Command {
    command.creation_flags(CREATE_NO_WINDOW);
    command
}

/// Windows implementation of [`RouteOps`] using `route.exe`.
///
/// Requires an elevated process (routing-table changes are admin-only).
#[derive(Default)]
pub struct WindowsRouter;

impl WindowsRouter {
    /// Whether the current process runs elevated.
    ///
    /// `fltmc` (Filter Manager control) requires an elevated token on every
    /// Vista+ system and returns a zero exit code when run as admin — that
    /// is the primary signal. `net session` is kept only as a fallback for
    /// the rare machine where `fltmc.exe` is missing: it depends on the
    /// Server (LanmanServer) service, which is commonly disabled on tweaked
    /// systems and would then report a false negative for an elevated
    /// process, so it is not trusted as the primary check.
    #[must_use]
    pub fn is_elevated() -> bool {
        if hidden(Command::new("fltmc"))
            .output()
            .is_ok_and(|output| output.status.success())
        {
            return true;
        }
        hidden(Command::new("net"))
            .args(["session"])
            .output()
            .is_ok_and(|output| output.status.success())
    }
}

impl RouteOps for WindowsRouter {
    fn add_route(&self, ip: Ipv4Addr, gateway: Ipv4Addr) -> io::Result<()> {
        match run_route(&[
            "add",
            &ip.to_string(),
            "mask",
            "255.255.255.255",
            &gateway.to_string(),
        ]) {
            // An equivalent route already being present is not an error.
            Err(e)
                if e.to_string()
                    .to_lowercase()
                    .contains("object already exists") =>
            {
                Ok(())
            }
            other => other,
        }
    }

    fn delete_route(&self, ip: Ipv4Addr, gateway: Ipv4Addr) -> io::Result<()> {
        match run_route(&[
            "delete",
            &ip.to_string(),
            "mask",
            "255.255.255.255",
            &gateway.to_string(),
        ]) {
            // Deleting an absent route means our goal (route gone) is met.
            Err(e) if e.to_string().to_lowercase().contains("element not found") => Ok(()),
            other => other,
        }
    }

    fn add_net_route(&self, cidr: Cidr, gateway: Ipv4Addr) -> io::Result<()> {
        match run_route(&[
            "add",
            &cidr.network.to_string(),
            "mask",
            &cidr.mask().to_string(),
            &gateway.to_string(),
        ]) {
            Err(e)
                if e.to_string()
                    .to_lowercase()
                    .contains("object already exists") =>
            {
                Ok(())
            }
            other => other,
        }
    }

    fn delete_net_route(&self, cidr: Cidr, gateway: Ipv4Addr) -> io::Result<()> {
        match run_route(&[
            "delete",
            &cidr.network.to_string(),
            "mask",
            &cidr.mask().to_string(),
            &gateway.to_string(),
        ]) {
            Err(e) if e.to_string().to_lowercase().contains("element not found") => Ok(()),
            other => other,
        }
    }
}

/// Discovers the point-to-point peer of the VPN tunnel adapter — whichever
/// TAP/DCO/wintun adapter currently has an IPv4 address.
///
/// Interface indices change across reboots, so this matches by driver
/// description instead of any hardcoded ID or IP.
///
/// # Errors
///
/// Returns an error if no tunnel adapter has an IPv4 address (VPN not
/// connected) or the address is not `/30`.
pub fn discover_tunnel_peer() -> io::Result<Ipv4Addr> {
    let command = "Get-NetAdapter | \
        Where-Object { $_.InterfaceDescription -like '*TAP*' -or \
                       $_.InterfaceDescription -like '*OpenVPN*' -or \
                       $_.InterfaceDescription -like '*wintun*' } | \
        ForEach-Object { $adapter = $_; \
            Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 \
                -ErrorAction SilentlyContinue | \
            ForEach-Object { $_.IPAddress.ToString() + '/' + $_.PrefixLength } }";
    let output = hidden(Command::new("powershell"))
        .args(["-NoProfile", "-NonInteractive", "-Command", command])
        .output()?;
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "failed to enumerate network adapters: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let Some(line) = stdout.lines().map(str::trim).find(|l| l.contains('/')) else {
        return Err(io::Error::other(
            "no IPv4 address on any VPN tunnel adapter (TAP/DCO/wintun) — \
             is the VPN connected?",
        ));
    };
    peer_from_line(line, "tunnel adapter")
}

/// Discovers the point-to-point peer of a specific `interface` — an
/// interface index (e.g. `15`) or an adapter alias (e.g. `Local Area
/// Connection`). Explicit override for unusual setups; indices are unstable
/// across reboots, so prefer the alias or the default auto-detection.
///
/// # Errors
///
/// Returns an error if the interface cannot be queried, has no IPv4
/// address, or does not use a `/30` prefix.
pub fn discover_peer(interface: &str) -> io::Result<Ipv4Addr> {
    let command = if let Ok(index) = interface.parse::<u32>() {
        format!(
            "Get-NetIPAddress -InterfaceIndex {index} -AddressFamily IPv4 | \
             ForEach-Object {{ $_.IPAddress.ToString() + '/' + $_.PrefixLength }}"
        )
    } else {
        if interface.contains('\'') {
            return Err(io::Error::other("interface alias must not contain quotes"));
        }
        format!(
            "Get-NetIPAddress -InterfaceAlias '{interface}' -AddressFamily IPv4 | \
             ForEach-Object {{ $_.IPAddress.ToString() + '/' + $_.PrefixLength }}"
        )
    };
    let output = hidden(Command::new("powershell"))
        .args(["-NoProfile", "-NonInteractive", "-Command", &command])
        .output()?;
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "failed to query interface {interface}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let line = stdout
        .lines()
        .map(str::trim)
        .find(|line| line.contains('/'))
        .ok_or_else(|| io::Error::other(format!("interface {interface} has no IPv4 address")))?;
    peer_from_line(line, &format!("interface {interface}"))
}

/// Parses `ip/prefix` output and computes the `/30` peer.
fn peer_from_line(line: &str, what: &str) -> io::Result<Ipv4Addr> {
    let (ip, prefix) = line
        .split_once('/')
        .ok_or_else(|| io::Error::other(format!("unparsable address `{line}` ({what})")))?;
    let ip: Ipv4Addr = ip
        .parse()
        .map_err(|_| io::Error::other(format!("unparsable address `{line}` ({what})")))?;
    let prefix: u8 = prefix
        .parse()
        .map_err(|_| io::Error::other(format!("unparsable address `{line}` ({what})")))?;
    peer_of(ip, prefix).map_err(|e| io::Error::other(format!("{what}: {e}")))
}

/// Computes the point-to-point peer for a `/30` tunnel: the other host
/// address in the subnet.
fn peer_of(ip: Ipv4Addr, prefix: u8) -> io::Result<Ipv4Addr> {
    if prefix != 30 {
        return Err(io::Error::other(format!(
            "unsupported prefix /{prefix} — only /30 point-to-point is \
             auto-detected; configure vpn_gateway explicitly"
        )));
    }
    let host = u32::from(ip) & 3;
    if host == 0 || host == 3 {
        return Err(io::Error::other(format!(
            "{ip} is not a host address in its /30 subnet"
        )));
    }
    // The /30 holds exactly two hosts; the peer is the other one.
    Ok(Ipv4Addr::from((u32::from(ip) & !3) | (3 - host)))
}

/// Runs `route.exe` with argument arrays only (no shell string building) and
/// turns a failed invocation into an `io::Error` carrying its output.
///
/// The exit code alone is not reliable — `route.exe` can exit 0 even when
/// the operation failed (e.g. unreachable gateway). The `"OK!"`
/// acknowledgement is treated as the only success signal. (English systems
/// only; on a localized Windows this marker would need revisiting.)
fn run_route(args: &[&str]) -> io::Result<()> {
    let output = hidden(Command::new("route")).args(args).output()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    if output.status.success() && stdout.trim() == "OK!" {
        Ok(())
    } else {
        // route.exe prints failures to stdout, not stderr — include both.
        let detail = [stdout.trim(), stderr.trim()]
            .into_iter()
            .filter(|part| !part.is_empty())
            .collect::<Vec<_>>()
            .join(" ");
        Err(io::Error::other(format!(
            "route {} {} failed: {detail}",
            args[0], args[1]
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_of_flips_the_last_bit() {
        assert_eq!(
            peer_of("10.8.0.14".parse().unwrap(), 30).unwrap(),
            "10.8.0.13".parse::<Ipv4Addr>().unwrap()
        );
        assert_eq!(
            peer_of("10.8.0.13".parse().unwrap(), 30).unwrap(),
            "10.8.0.14".parse::<Ipv4Addr>().unwrap()
        );
    }

    #[test]
    fn peer_of_rejects_other_prefixes() {
        assert!(peer_of("10.8.0.14".parse().unwrap(), 24).is_err());
        assert!(peer_of("10.8.0.14".parse().unwrap(), 32).is_err());
    }

    #[test]
    fn peer_of_rejects_non_host_addresses() {
        assert!(peer_of("10.8.0.12".parse().unwrap(), 30).is_err());
        assert!(peer_of("10.8.0.15".parse().unwrap(), 30).is_err());
    }
}
