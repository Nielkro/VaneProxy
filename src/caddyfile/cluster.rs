//! Domain clustering, apex extraction, and SAN consolidation.

use std::collections::{BTreeMap, BTreeSet};

/// Extracts the apex (registrable) domain from a fully-qualified domain name.
///
/// Handles common two-part public suffixes (e.g., `.home.kg`, `.co.uk`)
/// and standard single-part TLDs (e.g., `.ru`, `.com`, `.org`).
pub fn extract_apex_domain(domain: &str) -> String {
    let clean = domain.trim().trim_start_matches("*.").trim_end_matches('.');
    let parts: Vec<&str> = clean.split('.').collect();

    if parts.len() <= 2 {
        return clean.to_lowercase();
    }

    // Check for well-known two-part suffixes (e.g., .home.kg, .co.uk, .com.ru)
    let len = parts.len();
    let last_two = format!("{}.{}", parts[len - 2], parts[len - 1]).to_lowercase();
    let is_two_part_tld = matches!(
        last_two.as_str(),
        "home.kg"
            | "co.uk"
            | "org.uk"
            | "me.uk"
            | "com.ru"
            | "net.ru"
            | "org.ru"
            | "msk.ru"
            | "spb.ru"
            | "com.ua"
            | "co.za"
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
/// If any subdomain exists under an apex domain, both the apex (`domain.com`)
/// and the wildcard (`*.domain.com`) are included in the consolidated SAN list.
pub fn consolidate_sans(domains: &[String]) -> Vec<String> {
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
        let has_wildcard_or_subdomain = group.iter().any(|d| d.starts_with("*.") || d != &apex);

        // Always include the apex domain itself
        consolidated.insert(apex.clone());

        // If subdomains or explicit wildcard exist, include *.apex
        if has_wildcard_or_subdomain {
            consolidated.insert(format!("*.{}", apex));
        }
    }

    consolidated.into_iter().collect()
}

/// Checks whether an incoming TLS SNI matches a configured site pattern.
///
/// Supports exact matching (case-insensitive) and standard single-level
/// wildcard matching (`*.example.com` matches `foo.example.com`, but not
/// `example.com` or `bar.foo.example.com`).
pub fn matches_site_address(pattern: &str, sni: &str) -> bool {
    let pat = pattern.trim().to_lowercase();
    let s = sni.trim().to_lowercase();

    if pat == s {
        return true;
    }

    if let Some(suffix) = pat.strip_prefix("*.") {
        if let Some(prefix) = s.strip_suffix(suffix) {
            if prefix.ends_with('.') && !prefix[..prefix.len() - 1].contains('.') && !prefix[..prefix.len() - 1].is_empty() {
                return true;
            }
        }
    }

    false
}
