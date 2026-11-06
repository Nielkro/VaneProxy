//! Domain clustering, apex extraction, and SAN consolidation.

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet, HashMap};

use crate::caddyfile::model::SiteBlock;

/// Precomputed hostname -> site index lookup.
///
/// Exact hostnames take precedence over a single-level `*.suffix` wildcard,
/// matching both SNI routing and per-request `Host` resolution.
#[derive(Debug, Default)]
pub struct SiteIndex {
    exact: HashMap<String, usize>,
    wildcards: HashMap<String, usize>,
}

impl SiteIndex {
    /// Builds the index from site blocks. First occurrence wins on duplicates.
    pub fn build(sites: &[SiteBlock]) -> Self {
        let mut exact = HashMap::new();
        let mut wildcards = HashMap::new();

        for (idx, site) in sites.iter().enumerate() {
            for addr in &site.addresses {
                let name = addr.trim().trim_end_matches('.');
                if name.is_empty() {
                    continue;
                }
                if let Some(suffix) = name.strip_prefix("*.") {
                    wildcards
                        .entry(suffix.to_ascii_lowercase())
                        .or_insert(idx);
                } else {
                    exact.entry(name.to_ascii_lowercase()).or_insert(idx);
                }
            }
        }

        Self { exact, wildcards }
    }

    /// Looks up a hostname (optionally with port) and returns the site index.
    #[inline]
    pub fn lookup(&self, host: &str) -> Option<usize> {
        let host = host.split(':').next().unwrap_or(host).trim();
        let host = host.trim_end_matches('.');
        if host.is_empty() {
            return None;
        }

        let host: Cow<'_, str> = if host.bytes().any(|b| b.is_ascii_uppercase()) {
            Cow::Owned(host.to_ascii_lowercase())
        } else {
            Cow::Borrowed(host)
        };

        if let Some(idx) = self.exact.get(host.as_ref()) {
            return Some(*idx);
        }

        if let Some(dot) = host.find('.') {
            if let Some(idx) = self.wildcards.get(&host[dot + 1..]) {
                return Some(*idx);
            }
        }

        None
    }
}

/// Extracts the apex (registrable) domain from a fully-qualified domain name
/// using the Mozilla Public Suffix List (via `addr`), with fallback for multi-label domains.
pub fn extract_apex_domain(domain: &str) -> String {
    let clean = domain.trim().trim_start_matches("*.").trim_end_matches('.');
    if let Ok(parsed) = addr::parse_domain_name(clean) {
        if let Some(root) = parsed.root() {
            return root.to_lowercase();
        }
    }

    let parts: Vec<&str> = clean.split('.').collect();
    if parts.len() <= 2 {
        return clean.to_lowercase();
    }

    // Fallback: check for well-known two-part suffixes
    let len = parts.len();
    let last_two = format!("{}.{}", parts[len - 2], parts[len - 1]).to_lowercase();
    let is_two_part_tld = matches!(
        last_two.as_str(),
        "co.uk"
            | "org.uk"
            | "me.uk"
            | "com.ru"
            | "net.ru"
            | "org.ru"
            | "msk.ru"
            | "spb.ru"
            | "com.ua"
            | "co.za"
            | "eu.cc"
    );

    if is_two_part_tld && len >= 3 {
        format!("{}.{}", parts[len - 3], last_two)
    } else {
        format!("{}.{}", parts[len - 2], parts[len - 1]).to_lowercase()
    }
}

/// Consolidates a collection of domain names and wildcards across sites
/// into an optimized, unified list of Subject Alternative Names (SANs).
///
/// For managed apexes (or all apexes if `managed_apexes` is None):
/// - Adds apex domain (`domain.com`)
/// - If subdomains or explicit wildcard exist, adds `*.domain.com` (and nested sub-wildcards)
/// - Deduplicates exact domains covered by wildcards.
///
/// For unmanaged apexes (not present in `managed_apexes`):
/// - Only exact domains explicitly declared in `domains` are included (without synthetic apex or wildcard).
pub fn consolidate_sans(domains: &[String]) -> Vec<String> {
    consolidate_sans_with_managed_apexes(domains, None)
}

/// Consolidates SANs, expanding apex/wildcard only for apex domains present in `managed_apexes`.
pub fn consolidate_sans_with_managed_apexes(
    domains: &[String],
    managed_apexes: Option<&BTreeSet<String>>,
) -> Vec<String> {
    let mut apex_groups: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();

    for d in domains {
        let trimmed = d.trim().to_lowercase();
        if trimmed.is_empty() {
            continue;
        }
        let apex = extract_apex_domain(&trimmed);
        apex_groups.entry(apex).or_default().insert(trimmed);
    }

    let mut consolidated = BTreeSet::new();

    for (apex, group) in apex_groups {
        let is_managed = managed_apexes.map(|set| set.contains(&apex)).unwrap_or(true);

        if is_managed {
            let has_wildcard_or_subdomain = group.iter().any(|d| d.starts_with("*.") || d != &apex);

            // Always include the apex domain itself
            consolidated.insert(apex.clone());

            // If subdomains or explicit wildcard exist, include *.apex
            if has_wildcard_or_subdomain {
                consolidated.insert(format!("*.{}", apex));
            }

            // RFC 6125 §6.4.3: Wildcards (*.domain.com) only match a single level.
            // For nested subdomains (e.g. met.sub.example.com), *.example.com DOES NOT MATCH.
            // Include the sub-wildcard (*.sub.example.com).
            for domain in group {
                let clean = domain.trim_start_matches("*.");
                if clean != apex {
                    if let Some(parent) = clean.split_once('.').map(|(_, rest)| rest) {
                        if parent != apex && parent.ends_with(&apex) {
                            // Multi-level: add *.parent wildcard
                            consolidated.insert(format!("*.{}", parent));
                        }
                    }
                    if !domain.starts_with("*.") {
                        consolidated.insert(domain.clone());
                    }
                }
            }
        } else {
            // Unmanaged apex: only keep exact domains explicitly configured (no synthetic apex or wildcard)
            for domain in group {
                if !domain.starts_with("*.") {
                    consolidated.insert(domain);
                }
            }
        }
    }

    // Deduplicate exact domains covered by a wildcard in the same order.
    // Let's Encrypt rejects orders with malformed error if an exact domain is redundant
    // with a wildcard in the same certificate request (e.g. groups.chat.example.com with *.chat.example.com).
    let wildcards: BTreeSet<String> = consolidated
        .iter()
        .filter_map(|d| d.strip_prefix("*.").map(|s| s.to_string()))
        .collect();

    consolidated.retain(|d| {
        if d.starts_with("*.") {
            return true;
        }
        // Match wildcard coverage: *.parent covers label.parent (single level).
        // Apex domains (e.g. example.com) have parent 'com' which is not in wildcards, so they are kept.
        if let Some((_label, parent)) = d.split_once('.') {
            if wildcards.contains(parent) {
                return false;
            }
        }
        true
    });

    consolidated.into_iter().collect()
}

/// Checks whether an incoming TLS SNI matches a configured site pattern.
///
/// Supports exact matching (case-insensitive) and standard single-level
/// wildcard matching (`*.example.com` matches `foo.example.com`, but not
/// `example.com` or `bar.foo.example.com`).
pub fn matches_site_address(pattern: &str, sni: &str) -> bool {
    let pat = pattern.trim().as_bytes();
    let s = sni.trim().as_bytes();

    // Fast path: exact match, allocation-free ASCII case fold.
    if pat.eq_ignore_ascii_case(s) {
        return true;
    }

    // Wildcard: `*.example.com` matches exactly one leading label.
    if let Some(suffix) = pat.strip_prefix(b"*.") {
        if s.len() > suffix.len() && s[s.len() - suffix.len()..].eq_ignore_ascii_case(suffix) {
            let prefix = &s[..s.len() - suffix.len()];
            if prefix.ends_with(b".") {
                let label = &prefix[..prefix.len() - 1];
                if !label.is_empty() && !label.contains(&b'.') {
                    return true;
                }
            }
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn site(addresses: &[&str]) -> SiteBlock {
        SiteBlock {
            addresses: addresses.iter().map(|a| a.to_string()).collect(),
            directives: Vec::new(),
            source_file: None,
            line: 0,
        }
    }

    #[test]
    fn site_index_prefers_exact_over_wildcard() {
        let sites = vec![site(&["*.penik.ru"]), site(&["vpn.penik.ru"])];
        let index = SiteIndex::build(&sites);

        assert_eq!(index.lookup("vpn.penik.ru"), Some(1));
        assert_eq!(index.lookup("VPN.PENIK.RU:443"), Some(1));
        assert_eq!(index.lookup("other.penik.ru"), Some(0));
        assert_eq!(index.lookup("deep.other.penik.ru"), None);
        assert_eq!(index.lookup("penik.ru"), None);
        assert_eq!(index.lookup(""), None);
    }
}
