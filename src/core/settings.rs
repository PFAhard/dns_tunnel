//! Persistent application settings.
//!
//! The data model and validation live here (headlessly testable); the UI and
//! persistence glue live in [`crate::app`]. Fields track `docs/design.md` §7.

use serde::{Deserialize, Serialize};

use crate::core::redirect::is_valid_domain;

/// User-configurable application settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Settings {
    /// Local host:port the DNS listener binds to.
    pub listen_addr: String,
    /// host:port of the upstream DNS server carrying tunnel traffic.
    pub dns_server: String,
    /// VPN gateway (IPv4) — fallback next hop when tunnel discovery fails.
    ///
    /// Empty means "not configured"; routing then relies on auto-detection
    /// finding the tunnel's peer.
    pub vpn_gateway: String,
    /// VPN interface override (ifIndex or adapter alias). Empty = auto-
    /// detect the tunnel adapter by driver description — indices change
    /// across reboots, so leave this empty unless an override is needed.
    pub vpn_interface: String,
    /// Domains whose resolved IPs are routed through the VPN.
    ///
    /// Matching is exact + subdomains (see [`crate::core::redirect`]).
    pub redirect_list: Vec<String>,
    /// Static networks always routed through the VPN while the engine runs
    /// (no TTL) — for services that connect by raw IP without DNS
    /// (e.g. Telegram).
    pub cidr_list: Vec<String>,
    /// Request timeout in milliseconds.
    pub timeout_ms: u64,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            // 53: the engine is the machine's main resolver. The port must
            // be free (ICS holds 0.0.0.0:53 on Win10/11); 5353 is avoided
            // because mDNS owns it.
            listen_addr: "127.0.0.1:53".to_owned(),
            dns_server: "8.8.8.8:53".to_owned(),
            vpn_gateway: String::new(),
            vpn_interface: String::new(),
            redirect_list: Vec::new(),
            cidr_list: Vec::new(),
            timeout_ms: 5_000,
        }
    }
}

impl Settings {
    /// Returns human-readable problems with the current values.
    ///
    /// Empty redirect-list entries are ignored (they are dropped by
    /// [`Self::normalized`]). An empty result means the settings are valid.
    #[must_use]
    pub fn errors(&self) -> Vec<String> {
        let mut errors = Vec::new();
        if self.listen_addr.parse::<std::net::SocketAddr>().is_err() {
            errors.push(format!(
                "`{}` is not a valid listen address (host:port)",
                self.listen_addr
            ));
        }
        if self.dns_server.parse::<std::net::SocketAddr>().is_err() {
            errors.push(format!(
                "`{}` is not a valid DNS server address (host:port)",
                self.dns_server
            ));
        }
        if self.vpn_interface.contains('\'') {
            errors.push("VPN interface must not contain quotes".to_owned());
        }
        if !self.vpn_gateway.trim().is_empty()
            && self
                .vpn_gateway
                .trim()
                .parse::<std::net::Ipv4Addr>()
                .is_err()
        {
            errors.push(format!(
                "`{}` is not a valid IPv4 gateway address",
                self.vpn_gateway
            ));
        }
        if self.timeout_ms == 0 {
            errors.push("timeout must be at least 1 ms".to_owned());
        }
        for domain in &self.redirect_list {
            if !domain.trim().is_empty() && !is_valid_domain(domain) {
                errors.push(format!("`{domain}` is not a valid domain name"));
            }
        }
        for cidr in &self.cidr_list {
            if !cidr.trim().is_empty()
                && let Err(e) = crate::core::router::cidr::Cidr::parse(cidr)
            {
                errors.push(e);
            }
        }
        errors
    }

    /// Returns a normalized copy: strings trimmed, domains lowercased,
    /// empty redirect-list entries dropped, duplicates removed.
    #[must_use]
    pub fn normalized(&self) -> Self {
        let mut seen = std::collections::HashSet::new();
        let redirect_list = self
            .redirect_list
            .iter()
            .map(|domain| crate::core::redirect::normalize_domain(domain))
            .filter(|domain| !domain.is_empty() && seen.insert(domain.clone()))
            .collect();
        let mut seen_nets = std::collections::HashSet::new();
        let cidr_list = self
            .cidr_list
            .iter()
            .map(|cidr| cidr.trim().to_owned())
            .filter(|cidr| !cidr.is_empty() && seen_nets.insert(cidr.clone()))
            .collect();
        Self {
            listen_addr: self.listen_addr.trim().to_owned(),
            dns_server: self.dns_server.trim().to_owned(),
            vpn_gateway: self.vpn_gateway.trim().to_owned(),
            vpn_interface: self.vpn_interface.trim().to_owned(),
            redirect_list,
            cidr_list,
            timeout_ms: self.timeout_ms,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_valid() {
        assert_eq!(Settings::default().errors(), Vec::<String>::new());
    }

    #[test]
    fn rejects_malformed_listen_addr() {
        let settings = Settings {
            listen_addr: "not an address".to_owned(),
            ..Settings::default()
        };
        assert_eq!(settings.errors().len(), 1);
    }

    #[test]
    fn rejects_zero_timeout() {
        let settings = Settings {
            timeout_ms: 0,
            ..Settings::default()
        };
        assert_eq!(settings.errors().len(), 1);
    }

    #[test]
    fn accepts_ipv6_addresses() {
        let settings = Settings {
            listen_addr: "[::1]:5353".to_owned(),
            dns_server: "[2001:4860:4860::8888]:53".to_owned(),
            ..Settings::default()
        };
        assert_eq!(settings.errors(), Vec::<String>::new());
    }

    #[test]
    fn rejects_ipv6_gateway() {
        let settings = Settings {
            vpn_gateway: "fe80::1".to_owned(),
            ..Settings::default()
        };
        let errors = settings.errors();
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("IPv4"));
    }

    #[test]
    fn rejects_quote_in_interface() {
        let settings = Settings {
            vpn_interface: "a'b".to_owned(),
            ..Settings::default()
        };
        let errors = settings.errors();
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("quotes"));
    }

    #[test]
    fn accepts_valid_cidrs() {
        let settings = Settings {
            cidr_list: vec!["91.108.0.0/16".to_owned(), "149.154.160.0/20".to_owned()],
            ..Settings::default()
        };
        assert_eq!(settings.errors(), Vec::<String>::new());
    }

    #[test]
    fn rejects_invalid_cidr() {
        let settings = Settings {
            cidr_list: vec!["0.0.0.0/0".to_owned()],
            ..Settings::default()
        };
        let errors = settings.errors();
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("prefix"));
    }

    #[test]
    fn normalized_trims_and_dedups_cidrs() {
        let settings = Settings {
            cidr_list: vec![
                " 91.108.0.0/16 ".to_owned(),
                "91.108.0.0/16".to_owned(),
                String::new(),
            ],
            ..Settings::default()
        };
        assert_eq!(
            settings.normalized().cidr_list,
            vec!["91.108.0.0/16".to_owned()]
        );
    }

    #[test]
    fn rejects_invalid_redirect_domain() {
        let settings = Settings {
            redirect_list: vec!["exa mple.com".to_owned()],
            ..Settings::default()
        };
        assert_eq!(settings.errors().len(), 1);
    }

    #[test]
    fn normalized_trims_lowercases_and_dedups() {
        let settings = Settings {
            vpn_gateway: " 10.0.0.1 ".to_owned(),
            redirect_list: vec![
                "Example.COM".to_owned(),
                " example.com. ".to_owned(),
                String::new(),
                "www.example.com".to_owned(),
            ],
            ..Settings::default()
        };
        let normalized = settings.normalized();
        assert_eq!(normalized.vpn_gateway, "10.0.0.1");
        assert_eq!(
            normalized.redirect_list,
            vec!["example.com".to_owned(), "www.example.com".to_owned()]
        );
    }
}
