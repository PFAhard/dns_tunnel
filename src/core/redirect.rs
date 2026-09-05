//! Redirect-list domain matching (exact + subdomains).
//!
//! Matching is case-insensitive and label-boundary aware: `example.com`
//! matches `example.com` and `www.example.com`, but not `badexample.com`.

/// Normalizes a domain for comparison: trimmed, lowercased, trailing dots
/// removed.
#[must_use]
pub fn normalize_domain(domain: &str) -> String {
    domain.trim().trim_end_matches('.').to_lowercase()
}

/// Returns `true` if `domain` is a syntactically valid DNS name:
/// ASCII letters, digits, hyphens; labels of 1–63 bytes; at most 253 bytes
/// in total; labels must not start or end with `-`.
#[must_use]
pub fn is_valid_domain(domain: &str) -> bool {
    let domain = domain.trim().trim_end_matches('.');
    if domain.is_empty() || domain.len() > 253 {
        return false;
    }
    domain.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            && !label.starts_with('-')
            && !label.ends_with('-')
    })
}

/// Compares two domains by reversed label order — TLD first, then the
/// parent label, and so on — so related domains group together in
/// listings (`example.com` next to `www.example.com`, before `a.org`).
#[must_use]
pub fn compare_tld_first(a: &str, b: &str) -> std::cmp::Ordering {
    let a: Vec<&str> = a.split('.').rev().collect();
    let b: Vec<&str> = b.split('.').rev().collect();
    a.cmp(&b)
}

/// Extracts the registrable part of `domain` using the public suffix list
/// (Mozilla's list, embedded at build time by the `psl` crate) — exact for
/// every real TLD, including new gTLDs (`.gram`, `.biz`) and private
/// suffixes (`foo.blogspot.com` → `foo.blogspot.com`).
#[must_use]
pub fn registrable_domain(domain: &str) -> &str {
    psl::domain_str(domain).unwrap_or(domain)
}

/// Domains whose resolved IPs should be routed through the VPN.
///
/// Entries are stored normalized; edits happen in
/// [`crate::core::settings::Settings`], which normalizes on save.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RedirectList {
    domains: Vec<String>,
}

impl RedirectList {
    /// Builds a list from raw domain strings (normalized, empties dropped,
    /// duplicates removed).
    #[must_use]
    pub fn new(domains: impl IntoIterator<Item = String>) -> Self {
        let mut domains: Vec<String> = domains
            .into_iter()
            .map(|domain| normalize_domain(&domain))
            .filter(|domain| !domain.is_empty())
            .collect();
        domains.sort_unstable();
        domains.dedup();
        Self { domains }
    }

    /// Returns `true` if `domain` equals an entry or is a subdomain of one.
    #[must_use]
    pub fn matches(&self, domain: &str) -> bool {
        let domain = normalize_domain(domain);
        self.domains.iter().any(|entry| {
            domain == *entry
                || domain
                    .strip_suffix(entry.as_str())
                    .is_some_and(|rest| rest.ends_with('.'))
        })
    }

    /// The normalized domain entries.
    #[must_use]
    pub fn domains(&self) -> &[String] {
        &self.domains
    }

    /// Number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.domains.len()
    }

    /// Whether the list is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.domains.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list(entries: &[&str]) -> RedirectList {
        RedirectList::new(entries.iter().map(|d| (*d).to_owned()))
    }

    #[test]
    fn matches_exact() {
        assert!(list(&["example.com"]).matches("example.com"));
    }

    #[test]
    fn matches_subdomains() {
        assert!(list(&["example.com"]).matches("www.example.com"));
        assert!(list(&["example.com"]).matches("a.b.example.com"));
    }

    #[test]
    fn does_not_match_label_prefixes() {
        assert!(!list(&["example.com"]).matches("badexample.com"));
    }

    #[test]
    fn matching_is_case_insensitive() {
        assert!(list(&["EXAMPLE.com"]).matches("WWW.Example.COM"));
    }

    #[test]
    fn trailing_dot_in_query_is_ignored() {
        assert!(list(&["example.com"]).matches("example.com."));
    }

    #[test]
    fn registrable_domain_extraction() {
        // `cloudfront.net` is itself a public suffix: every distribution is
        // its own registrable domain per the PSL.
        assert_eq!(
            registrable_domain("d2nvs31859zcd8.cloudfront.net"),
            "d2nvs31859zcd8.cloudfront.net"
        );
        assert_eq!(registrable_domain("www.google.com"), "google.com");
        assert_eq!(registrable_domain("example.co.uk"), "example.co.uk");
        assert_eq!(registrable_domain("a.b.example.co.uk"), "example.co.uk");
        assert_eq!(registrable_domain("www.example.de"), "example.de");
        // `github.io` is a public suffix (GitHub Pages): each user/org is
        // its own registrable domain.
        assert_eq!(registrable_domain("x.y.github.io"), "y.github.io");
        assert_eq!(registrable_domain("localhost"), "localhost");
        assert_eq!(registrable_domain("github.io"), "github.io");
        // New-style gTLDs.
        assert_eq!(registrable_domain("www.example.biz"), "example.biz");
        assert_eq!(registrable_domain("www.example.gram"), "example.gram");
        // Private suffixes are modeled exactly.
        assert_eq!(registrable_domain("foo.blogspot.com"), "foo.blogspot.com");
        assert_eq!(registrable_domain("co.uk"), "co.uk");
    }

    #[test]
    fn tld_first_ordering_groups_by_tld_then_parent() {
        use std::cmp::Ordering;
        // Same domain chain: shorter (parent) before deeper (subdomain).
        assert_eq!(
            compare_tld_first("example.com", "www.example.com"),
            Ordering::Less
        );
        // TLD decides before the second-level label.
        assert_eq!(compare_tld_first("a.com", "b.org"), Ordering::Less);
        assert_eq!(
            compare_tld_first("example.org", "example.com"),
            Ordering::Greater
        );
        // Related domains land next to each other.
        let mut domains = vec!["www.example.com", "example.com", "a.org"];
        domains.sort_by(|a, b| compare_tld_first(a, b));
        assert_eq!(domains, vec!["example.com", "www.example.com", "a.org"]);
    }

    #[test]
    fn empty_list_never_matches() {
        assert!(!list(&[]).matches("example.com"));
    }

    #[test]
    fn new_normalizes_and_dedups() {
        let list = list(&["Example.COM", "example.com.", "", "www.example.com"]);
        assert_eq!(list.len(), 2);
        assert!(list.matches("example.com"));
        assert!(list.matches("www.example.com"));
    }

    #[test]
    fn valid_domains() {
        for domain in [
            "example.com",
            "example.com.",
            "a-b.example.com",
            "x.io",
            "localhost",
        ] {
            assert!(is_valid_domain(domain), "{domain} should be valid");
        }
    }

    #[test]
    fn invalid_domains() {
        for domain in [
            "",
            ".",
            "exa mple.com",
            "exämple.com",
            "-bad.com",
            "bad-.com",
            "example..com",
            "under_score.com",
        ] {
            assert!(!is_valid_domain(domain), "{domain} should be invalid");
        }
        let long = format!("{}.com", "a".repeat(64));
        assert!(!is_valid_domain(&long), "63+ label should be invalid");
    }
}
