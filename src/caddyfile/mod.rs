//! Caddyfile parser, AST models, and domain clustering.

pub mod cluster;
pub mod lexer;
pub mod model;
pub mod parser;
pub mod placeholders;

use std::fs;
use std::path::Path;
use thiserror::Error;

pub use cluster::{consolidate_sans, extract_apex_domain, matches_site_address};
pub use model::{
    Directive, FileServerConfig, HandleBlock, HandlePathBlock, HeaderOp, MatcherDef, MatcherRule,
    RedirConfig, RespondConfig, ResponseHeaderConfig, ReverseProxyConfig, RewriteConfig,
    SiteBlock, TlsUpstream, Upstream,
};
pub use parser::{parse_caddyfile, ParserError};
pub use placeholders::{replace_placeholders, validate_placeholders, PlaceholderContext};

/// Error loading site configuration files from directory.
#[derive(Debug, Error)]
pub enum SiteLoadError {
    #[error("failed to read sites directory '{path}': {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },

    #[error("syntax error in '{path}': {source}")]
    Parse {
        path: String,
        source: ParserError,
    },
}

/// Loads and parses all `.caddy` and `.conf` files from the specified directory.
pub fn load_sites_dir(dir: &Path) -> Result<Vec<SiteBlock>, SiteLoadError> {
    if !dir.exists() {
        return Ok(Vec::new());
    }

    let entries = fs::read_dir(dir).map_err(|e| SiteLoadError::Io {
        path: dir.display().to_string(),
        source: e,
    })?;

    let mut sites = Vec::new();
    let mut files: Vec<_> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|p| {
            if let Some(ext) = p.extension().and_then(|s| s.to_str()) {
                ext == "caddy" || ext == "conf"
            } else {
                false
            }
        })
        .collect();

    files.sort();

    for file_path in files {
        let content = match fs::read_to_string(&file_path) {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(path = %file_path.display(), error = %e, "failed to read site configuration file; skipping");
                continue;
            }
        };

        match parse_caddyfile(&content, Some(&file_path)) {
            Ok(parsed) => {
                sites.extend(parsed);
            }
            Err(e) => {
                tracing::error!(path = %file_path.display(), error = %e, "syntax error in site configuration; skipping invalid site file");
            }
        }
    }

    Ok(sites)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_single_reverse_proxy() {
        let input = r#"
            ad1.example.org {
                reverse_proxy 127.0.0.1:3001
            }
        "#;
        let sites = parse_caddyfile(input, None).expect("should parse");
        assert_eq!(sites.len(), 1);
        assert_eq!(sites[0].addresses, vec!["ad1.example.org"]);
        match &sites[0].directives[0] {
            Directive::ReverseProxy(cfg) => {
                assert_eq!(cfg.upstreams, vec![Upstream::Tcp("127.0.0.1:3001".to_string())]);
            }
            other => panic!("expected ReverseProxy, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_unix_socket_upstream() {
        let input = r#"
            chat.example.com {
                reverse_proxy unix//run/chat.sock
            }
        "#;
        let sites = parse_caddyfile(input, None).expect("should parse");
        match &sites[0].directives[0] {
            Directive::ReverseProxy(cfg) => {
                assert_eq!(cfg.upstreams, vec![Upstream::Unix(std::path::PathBuf::from("/run/chat.sock"))]);
            }
            other => panic!("expected ReverseProxy with unix socket, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_multi_domain_and_comments() {
        let input = r#"
            # Global comment
            example.org, *.example.org {
                // Inline comment
                root * /var/www/example
                file_server
            }
        "#;
        let sites = parse_caddyfile(input, None).expect("should parse");
        assert_eq!(sites[0].addresses, vec!["example.org", "*.example.org"]);
        assert_eq!(sites[0].directives.len(), 2);
        assert_eq!(sites[0].directives[0], Directive::Root("/var/www/example".to_string()));
        assert_eq!(sites[0].directives[1], Directive::FileServer(FileServerConfig { browse: false, hide: Vec::new() }));
    }

    #[test]
    fn test_parse_fail_fast_on_unknown_directive() {
        let input = r#"
            example.com {
                unsupported_directive foo bar
            }
        "#;
        let err = parse_caddyfile(input, None).expect_err("should fail");
        match err {
            ParserError::UnknownDirective { directive, line, .. } => {
                assert_eq!(directive, "unsupported_directive");
                assert_eq!(line, 3);
            }
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[test]
    fn test_domain_clustering_and_consolidation() {
        let domains = vec![
            "ad1.example.org".to_string(),
            "ad2.example.org".to_string(),
            "example.org".to_string(),
            "ad1.example.com".to_string(),
            "met.sub.example.org".to_string(),
        ];
        let sans = consolidate_sans(&domains);
        assert_eq!(
            sans,
            vec![
                "*.example.com",
                "*.example.org",
                "*.sub.example.org",
                "example.com",
                "example.org"
            ]
        );
    }

    #[test]
    fn test_consolidate_sans_omits_exact_covered_by_wildcard() {
        let domains = vec![
            "example.com".to_string(),
            "api.example.com".to_string(),
            "chat.example.com".to_string(),
            "groups.chat.example.com".to_string(),
            "share.chat.example.com".to_string(),
            "sub2.pnc.example.com".to_string(),
        ];
        let sans = consolidate_sans(&domains);
        assert_eq!(
            sans,
            vec![
                "*.chat.example.com",
                "*.example.com",
                "*.pnc.example.com",
                "example.com",
            ]
        );
    }

    #[test]
    fn test_wildcard_matching() {
        assert!(matches_site_address("*.example.org", "ad1.example.org"));
        assert!(matches_site_address("*.example.org", "chat.example.org"));
        // Does not match root domain
        assert!(!matches_site_address("*.example.org", "example.org"));
        // Does not match multi-level subdomain
        assert!(!matches_site_address("*.example.org", "deep.sub.example.org"));
        // Exact match
        assert!(matches_site_address("example.org", "example.org"));
        assert!(matches_site_address("example.org", "EXAMPLE.ORG"));
    }

    #[test]
    fn test_phase3_parse_directives_and_matchers() {
        let input = r#"
            chat.example.com {
                reverse_proxy https://127.0.0.1:8082 {
                    transport http {
                        tls_insecure_skip_verify
                    }
                    header_up Host {host}
                    header_up X-Real-IP {client_ip}
                    header_down +X-Served-By "Vane-Proxy"
                }
            }

            api.example.com {
                @options method OPTIONS
                respond @options 204

                handle_path /prefix/* {
                    rewrite * /new-prefix
                    respond "OK" 200
                }

                header Access-Control-Allow-Origin *
                request_body {
                    max_size 250MB
                }
            }
        "#;

        let sites = parse_caddyfile(input, None).expect("should parse successfully");
        assert_eq!(sites.len(), 2);

        // Site 1: TLS upstream with transport insecure
        let chat = &sites[0];
        assert_eq!(chat.addresses, vec!["chat.example.com"]);
        match &chat.directives[0] {
            Directive::ReverseProxy(cfg) => {
                assert!(cfg.insecure_tls);
                assert_eq!(cfg.upstreams.len(), 1);
                match &cfg.upstreams[0] {
                    Upstream::Tls(tls) => {
                        assert_eq!(tls.addr, "127.0.0.1:8082");
                        assert_eq!(tls.sni, "127.0.0.1");
                        assert!(tls.insecure);
                    }
                    _ => panic!("expected TLS upstream"),
                }
            }
            _ => panic!("expected ReverseProxy directive"),
        }

        // Site 2: Matcher, respond, handle_path, header, request_body
        let api = &sites[1];
        assert_eq!(api.addresses, vec!["api.example.com"]);
        assert!(api.directives.iter().any(|d| matches!(d, Directive::Matcher(_))));
        assert!(api.directives.iter().any(|d| matches!(d, Directive::Respond(_))));
        assert!(api.directives.iter().any(|d| matches!(d, Directive::HandlePath(_))));
        assert!(api.directives.iter().any(|d| matches!(d, Directive::ResponseHeader(_))));
        assert!(api.directives.iter().any(|d| matches!(d, Directive::RequestBodyLimit(262144000))));
    }

    #[test]
    fn test_phase3_insecure_tls_guard_rejects_external_hosts() {
        let input = r#"
            evil.com {
                reverse_proxy https://8.8.8.8:443 {
                    transport http {
                        tls_insecure_skip_verify
                    }
                }
            }
        "#;
        let err = parse_caddyfile(input, None).expect_err("should reject external insecure TLS");
        match err {
            ParserError::InsecureTlsNotLoopback { addr, .. } => {
                assert_eq!(addr, "8.8.8.8:443");
            }
            other => panic!("expected InsecureTlsNotLoopback error, got: {:?}", other),
        }
    }

    #[test]
    fn test_handle_errors_with_named_matchers() {
        let input = r#"
            call.example.org {
                handle_errors {
                    root * /var/www/error
                    @404 expression {http.error.status_code} == 404
                    rewrite @404 /404.html
                    @5xx expression {http.error.status_code} >= 500 && {http.error.status_code} < 600
                    rewrite @5xx /error.html
                }
            }
        "#;
        let sites = parse_caddyfile(input, None).expect("should parse handle_errors with named matchers");
        assert_eq!(sites.len(), 1);
        let site = &sites[0];
        assert_eq!(site.addresses, vec!["call.example.org"]);
        match &site.directives[0] {
            Directive::HandleErrors(dirs) => {
                assert_eq!(dirs.len(), 5);
                assert!(matches!(&dirs[0], Directive::Root(p) if p == "/var/www/error"));
                assert!(matches!(&dirs[1], Directive::Matcher(m) if m.name == "404"));
                assert!(matches!(&dirs[2], Directive::Rewrite(r) if r.matcher.as_deref() == Some("@404") && r.target == "/404.html"));
                assert!(matches!(&dirs[3], Directive::Matcher(m) if m.name == "5xx"));
                assert!(matches!(&dirs[4], Directive::Rewrite(r) if r.matcher.as_deref() == Some("@5xx") && r.target == "/error.html"));
            }
            other => panic!("expected HandleErrors directive, got: {:?}", other),
        }
    }
}
