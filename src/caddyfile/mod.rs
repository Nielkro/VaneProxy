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
        let content = fs::read_to_string(&file_path).map_err(|e| SiteLoadError::Io {
            path: file_path.display().to_string(),
            source: e,
        })?;

        let parsed =
            parse_caddyfile(&content, Some(&file_path)).map_err(|e| SiteLoadError::Parse {
                path: file_path.display().to_string(),
                source: e,
            })?;

        sites.extend(parsed);
    }

    Ok(sites)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_single_reverse_proxy() {
        let input = r#"
            ad1.slavchat.ru {
                reverse_proxy 127.0.0.1:3001
            }
        "#;
        let sites = parse_caddyfile(input, None).expect("should parse");
        assert_eq!(sites.len(), 1);
        assert_eq!(sites[0].addresses, vec!["ad1.slavchat.ru"]);
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
            chat.penik.ru {
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
            slavchat.ru, *.slavchat.ru {
                // Inline comment
                root * /var/www/slavchat
                file_server
            }
        "#;
        let sites = parse_caddyfile(input, None).expect("should parse");
        assert_eq!(sites[0].addresses, vec!["slavchat.ru", "*.slavchat.ru"]);
        assert_eq!(sites[0].directives.len(), 2);
        assert_eq!(sites[0].directives[0], Directive::Root("/var/www/slavchat".to_string()));
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
            "ad1.slavchat.ru".to_string(),
            "ad2.slavchat.ru".to_string(),
            "slavchat.ru".to_string(),
            "ad1.penik.ru".to_string(),
            "met.home.slavchat.ru".to_string(),
        ];
        let sans = consolidate_sans(&domains);
        assert_eq!(
            sans,
            vec![
                "*.home.slavchat.ru",
                "*.penik.ru",
                "*.slavchat.ru",
                "ad1.penik.ru",
                "ad1.slavchat.ru",
                "ad2.slavchat.ru",
                "met.home.slavchat.ru",
                "penik.ru",
                "slavchat.ru"
            ]
        );
    }

    #[test]
    fn test_wildcard_matching() {
        assert!(matches_site_address("*.slavchat.ru", "ad1.slavchat.ru"));
        assert!(matches_site_address("*.slavchat.ru", "chat.slavchat.ru"));
        // Does not match root domain
        assert!(!matches_site_address("*.slavchat.ru", "slavchat.ru"));
        // Does not match multi-level subdomain
        assert!(!matches_site_address("*.slavchat.ru", "deep.sub.slavchat.ru"));
        // Exact match
        assert!(matches_site_address("slavchat.ru", "slavchat.ru"));
        assert!(matches_site_address("slavchat.ru", "SLAVCHAT.RU"));
    }

    #[test]
    fn test_phase3_parse_directives_and_matchers() {
        let input = r#"
            snikket.penik.ru {
                reverse_proxy https://127.0.0.1:8082 {
                    transport http {
                        tls_insecure_skip_verify
                    }
                    header_up Host {host}
                    header_up X-Real-IP {client_ip}
                    header_down +X-Served-By "Vane-Proxy"
                }
            }

            api.penik.ru {
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
        let snikket = &sites[0];
        assert_eq!(snikket.addresses, vec!["snikket.penik.ru"]);
        match &snikket.directives[0] {
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
        assert_eq!(api.addresses, vec!["api.penik.ru"]);
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
}
