//! Pure routing decision: given a parsed ClientHello, pick what to do next.

use std::collections::HashMap;

use crate::caddyfile::cluster::SiteIndex;

/// Outcome of route resolution. Contains no I/O and can be unit-tested.
#[derive(Debug, PartialEq, Eq)]
pub enum RouteDecision<'a> {
    /// Handle an ACME TLS-ALPN-01 challenge probe.
    AcmeAlpn,
    /// Explicit L4 passthrough route from `config.toml`.
    L4(&'a str),
    /// Terminate TLS for the L7 site at this index.
    L7(usize),
    /// No route matched: use `default_backend`.
    Default,
}

/// Resolves the routing decision.
///
/// Precedence mirrors the connection handler:
/// 1. ACME TLS-ALPN-01 probe (needs a registered challenge and TLS acceptor).
/// 2. Exact L4 route from `config.toml`.
/// 3. L7 site by SNI (exact then single-level wildcard) when TLS termination is available.
/// 4. Default backend.
pub fn decide<'a>(
    sni: Option<&str>,
    is_acme_alpn: bool,
    alpn_challenge_present: bool,
    has_tls_acceptor: bool,
    routes: &'a HashMap<String, String>,
    site_index: &SiteIndex,
) -> RouteDecision<'a> {
    if is_acme_alpn && sni.is_some() && alpn_challenge_present && has_tls_acceptor {
        return RouteDecision::AcmeAlpn;
    }

    if let Some(sni) = sni {
        if let Some(backend) = routes.get(sni) {
            return RouteDecision::L4(backend);
        }
        if has_tls_acceptor {
            if let Some(idx) = site_index.lookup(sni) {
                return RouteDecision::L7(idx);
            }
        }
    }

    RouteDecision::Default
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::caddyfile::model::SiteBlock;

    fn site(addresses: &[&str]) -> SiteBlock {
        SiteBlock {
            addresses: addresses.iter().map(|a| a.to_string()).collect(),
            directives: Vec::new(),
            source_file: None,
            line: 0,
        }
    }

    fn routes(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn l4_exact_beats_l7() {
        let sites = vec![site(&["vpn.penik.ru"])];
        let index = SiteIndex::build(&sites);
        let r = routes(&[("vpn.penik.ru", "xray")]);

        assert_eq!(
            decide(Some("vpn.penik.ru"), false, false, true, &r, &index),
            RouteDecision::L4("xray")
        );
    }

    #[test]
    fn l7_exact_beats_wildcard() {
        let sites = vec![site(&["*.penik.ru"]), site(&["vpn.penik.ru"])];
        let index = SiteIndex::build(&sites);
        let r = routes(&[]);

        assert_eq!(
            decide(Some("vpn.penik.ru"), false, false, true, &r, &index),
            RouteDecision::L7(1)
        );
        assert_eq!(
            decide(Some("other.penik.ru"), false, false, true, &r, &index),
            RouteDecision::L7(0)
        );
    }

    #[test]
    fn acme_requires_registered_challenge_and_acceptor() {
        let sites = vec![site(&["vpn.penik.ru"])];
        let index = SiteIndex::build(&sites);
        let r = routes(&[]);

        assert_eq!(
            decide(Some("vpn.penik.ru"), true, true, true, &r, &index),
            RouteDecision::AcmeAlpn
        );
        // No acceptor: fall through to the normal L7 route.
        assert_eq!(
            decide(Some("vpn.penik.ru"), true, true, false, &r, &index),
            RouteDecision::Default
        );
        // No registered challenge: normal routing.
        assert_eq!(
            decide(Some("vpn.penik.ru"), true, false, true, &r, &index),
            RouteDecision::L7(0)
        );
    }

    #[test]
    fn unknown_host_falls_back() {
        let sites = vec![site(&["penik.ru"])];
        let index = SiteIndex::build(&sites);
        let r = routes(&[]);

        assert_eq!(
            decide(Some("unknown.example"), false, false, true, &r, &index),
            RouteDecision::Default
        );
        assert_eq!(
            decide(None, false, false, true, &r, &index),
            RouteDecision::Default
        );
    }
}
