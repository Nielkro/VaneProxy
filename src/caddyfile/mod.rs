//! Caddyfile parser, AST models, and domain clustering.

pub mod cluster;
pub mod lexer;
pub mod model;
pub mod parser;

use std::fs;
use std::path::Path;
use thiserror::Error;

pub use cluster::{consolidate_sans, extract_apex_domain, matches_site_address};
pub use model::{
    Directive, FileServerConfig, HandleBlock, HeaderOp, RedirConfig, ReverseProxyConfig,
    RewriteConfig, SiteBlock, Upstream,
};
pub use parser::{parse_caddyfile, ParserError};

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
        assert_eq!(sites[0].directives[1], Directive::FileServer(FileServerConfig { browse: false }));
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
        ];
        let sans = consolidate_sans(&domains);
        assert_eq!(
            sans,
            vec![
                "*.penik.ru",
                "*.slavchat.ru",
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
}
