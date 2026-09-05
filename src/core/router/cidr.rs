//! IPv4 CIDR notation — hand-rolled like the DNS wire format.

use std::net::Ipv4Addr;

/// An IPv4 network in CIDR notation (e.g. `91.108.0.0/16`).
///
/// The prefix must be in 1..=32 — `/0` is rejected because a static route
/// for it would capture the default route.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Cidr {
    /// Network address (host bits masked out).
    pub network: Ipv4Addr,
    /// Prefix length.
    pub prefix: u8,
}

impl Cidr {
    /// Parses CIDR notation.
    ///
    /// # Errors
    ///
    /// Returns a human-readable message if the text is not a valid CIDR,
    /// has an invalid prefix, or names a `/0` network.
    pub fn parse(text: &str) -> Result<Self, String> {
        let text = text.trim();
        let Some((ip, prefix)) = text.split_once('/') else {
            return Err(format!("`{text}` is not a CIDR (expected host/prefix)"));
        };
        let network: Ipv4Addr = ip
            .parse()
            .map_err(|_| format!("`{text}` has an invalid address"))?;
        let prefix: u8 = prefix
            .parse()
            .map_err(|_| format!("`{text}` has an invalid prefix"))?;
        if prefix == 0 || prefix > 32 {
            return Err(format!(
                "`{text}`: prefix must be in 1..=32 (a /0 would capture the default route)"
            ));
        }
        let mask = u32::MAX << (32 - u32::from(prefix));
        Ok(Self {
            network: Ipv4Addr::from(u32::from(network) & mask),
            prefix,
        })
    }

    /// The subnet mask as an IPv4 address (e.g. `/16` → `255.255.0.0`).
    #[must_use]
    pub fn mask(self) -> Ipv4Addr {
        Ipv4Addr::from(u32::MAX << (32 - u32::from(self.prefix)))
    }
}

impl std::fmt::Display for Cidr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.network, self.prefix)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_cidr_and_masks_host_bits() {
        let cidr = Cidr::parse("91.108.5.7/16").unwrap();
        assert_eq!(cidr.network, "91.108.0.0".parse::<Ipv4Addr>().unwrap());
        assert_eq!(cidr.prefix, 16);
        assert_eq!(cidr.to_string(), "91.108.0.0/16");
    }

    #[test]
    fn rejects_zero_and_oversized_prefixes() {
        assert!(Cidr::parse("0.0.0.0/0").is_err());
        assert!(Cidr::parse("10.0.0.0/33").is_err());
        assert!(Cidr::parse("10.0.0.0/99").is_err());
    }

    #[test]
    fn rejects_garbage() {
        for text in ["", "nope", "10.0.0.0", "10.0.0.0/", "10.0.0.0/x", "/24"] {
            assert!(Cidr::parse(text).is_err(), "{text} should be invalid");
        }
    }

    #[test]
    fn mask_matches_prefix() {
        assert_eq!(
            Cidr::parse("10.0.0.0/8").unwrap().mask(),
            "255.0.0.0".parse::<Ipv4Addr>().unwrap()
        );
        assert_eq!(
            Cidr::parse("10.0.0.0/24").unwrap().mask(),
            "255.255.255.0".parse::<Ipv4Addr>().unwrap()
        );
        assert_eq!(
            Cidr::parse("10.0.0.1/32").unwrap().mask(),
            "255.255.255.255".parse::<Ipv4Addr>().unwrap()
        );
    }
}
