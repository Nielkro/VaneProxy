//! Configuration loading and validation (TOML).

use std::collections::{HashMap, HashSet};
use std::fs;
use std::net::SocketAddr;
use std::path::Path;

use serde::Deserialize;
use thiserror::Error;

use crate::sni::normalize_sni;

/// Raw file layout.
#[derive(Debug, Deserialize)]
struct FileConfig {
    #[serde(default = "default_listen")]
    listen: Vec<String>,
    #[serde(default = "default_true")]
    strict_listen: bool,
    #[serde(default = "default_hello_timeout")]
    client_hello_timeout_ms: u64,
    #[serde(default = "default_backend_timeout")]
    backend_connect_timeout_ms: u64,
    #[serde(default = "default_max_hello")]
    max_client_hello_bytes: usize,
    #[serde(default)]
    log_level: Option<String>,
    #[serde(default)]
    access_log: bool,
    backends: HashMap<String, BackendConf>,
    default_backend: String,
    #[serde(default)]
    routes: Vec<RouteConf>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BackendConf {
    pub addr: String,
    #[serde(default)]
    pub send_proxy_protocol: bool,
}

#[derive(Debug, Clone, Deserialize)]
struct RouteConf {
    sni: String,
    backend: String,
}

fn default_listen() -> Vec<String> {
    vec!["0.0.0.0:443".to_string(), "[::]:443".to_string()]
}

fn default_true() -> bool {
    true
}

fn default_hello_timeout() -> u64 {
    5000
}

fn default_backend_timeout() -> u64 {
    3000
}

fn default_max_hello() -> usize {
    16389
}

/// Validated runtime configuration.
#[derive(Debug, Clone)]
pub struct Config {
    pub listen: Vec<SocketAddr>,
    pub strict_listen: bool,
    pub client_hello_timeout_ms: u64,
    pub backend_connect_timeout_ms: u64,
    pub max_client_hello_bytes: usize,
    pub log_level: String,
    pub access_log: bool,
    pub backends: HashMap<String, Backend>,
    pub default_backend: String,
    /// Normalized SNI -> backend name.
    pub routes: HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct Backend {
    pub addr: SocketAddr,
    pub send_proxy_protocol: bool,
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("cannot read config: {0}")]
    Io(#[from] std::io::Error),
    #[error("cannot parse config: {0}")]
    Parse(String),
    #[error("invalid config: {0}")]
    Invalid(String),
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = fs::read_to_string(path)?;
        Self::parse(&text)
    }

    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        let file: FileConfig =
            toml::from_str(text).map_err(|e| ConfigError::Parse(e.to_string()))?;

        if file.listen.is_empty() {
            return Err(ConfigError::Invalid("listen must not be empty".into()));
        }
        let mut listen = Vec::with_capacity(file.listen.len());
        let mut seen_listen = HashSet::new();
        for raw in &file.listen {
            let addr: SocketAddr = raw
                .parse()
                .map_err(|_| ConfigError::Invalid(format!("bad listen addr: {raw}")))?;
            if !seen_listen.insert(addr) {
                return Err(ConfigError::Invalid(format!(
                    "duplicate listen addr: {raw}"
                )));
            }
            listen.push(addr);
        }

        if file.backends.is_empty() {
            return Err(ConfigError::Invalid("no backends defined".into()));
        }
        let mut backends = HashMap::with_capacity(file.backends.len());
        for (name, b) in &file.backends {
            let addr: SocketAddr = b.addr.parse().map_err(|_| {
                ConfigError::Invalid(format!("bad addr for backend '{name}': {}", b.addr))
            })?;
            backends.insert(
                name.clone(),
                Backend {
                    addr,
                    send_proxy_protocol: b.send_proxy_protocol,
                },
            );
        }

        if !backends.contains_key(&file.default_backend) {
            return Err(ConfigError::Invalid(format!(
                "unknown default_backend: {}",
                file.default_backend
            )));
        }

        let mut routes = HashMap::with_capacity(file.routes.len());
        for r in &file.routes {
            if !backends.contains_key(&r.backend) {
                return Err(ConfigError::Invalid(format!(
                    "route '{}' points at unknown backend '{}'",
                    r.sni, r.backend
                )));
            }
            let normalized = normalize_sni(r.sni.trim().as_bytes())
                .ok_or_else(|| ConfigError::Invalid(format!("bad route sni: '{}'", r.sni)))?;
            if routes.contains_key(&normalized) {
                return Err(ConfigError::Invalid(format!(
                    "duplicate route sni: '{}'",
                    r.sni
                )));
            }
            routes.insert(normalized, r.backend.clone());
        }

        Ok(Self {
            listen,
            strict_listen: file.strict_listen,
            client_hello_timeout_ms: file.client_hello_timeout_ms,
            backend_connect_timeout_ms: file.backend_connect_timeout_ms,
            max_client_hello_bytes: file.max_client_hello_bytes.max(64),
            log_level: file.log_level.unwrap_or_else(|| "error".to_string()),
            access_log: file.access_log,
            backends,
            default_backend: file.default_backend,
            routes,
        })
    }

    /// Look up the backend name for an SNI (exact match, fallback to default).
    pub fn route(&self, sni: Option<&str>) -> &str {
        match sni {
            Some(name) => self.routes.get(name).map_or(&self.default_backend, |v| v),
            None => &self.default_backend,
        }
    }

    pub fn backend(&self, name: &str) -> &Backend {
        &self.backends[name]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = r#"
listen = ["0.0.0.0:443"]
default_backend = "caddy"

[backends.xray]
addr = "127.0.0.1:8443"
send_proxy_protocol = false

[backends.caddy]
addr = "127.0.0.1:8444"
send_proxy_protocol = true

[[routes]]
sni = "studio.iuharin.ru"
backend = "xray"
"#;

    #[test]
    fn parses_minimal() {
        let cfg = Config::parse(BASE).unwrap();
        assert_eq!(cfg.route(Some("studio.iuharin.ru")), "xray");
        assert_eq!(cfg.route(Some("unknown.example.com")), "caddy");
        assert_eq!(cfg.route(None), "caddy");
        assert!(cfg.backend("caddy").send_proxy_protocol);
        assert!(!cfg.backend("xray").send_proxy_protocol);
    }

    #[test]
    fn rejects_duplicate_sni_after_fold() {
        let text =
            format!("{BASE}\n[[routes]]\nsni = \"STUDIO.iuharin.ru.\"\nbackend = \"xray\"\n");
        assert!(Config::parse(&text).is_err());
    }

    #[test]
    fn rejects_unknown_backend() {
        let text = BASE.replace("backend = \"xray\"", "backend = \"nope\"");
        assert!(Config::parse(&text).is_err());
    }

    #[test]
    fn rejects_empty_listen() {
        let text = BASE.replace("listen = [\"0.0.0.0:443\"]", "listen = []");
        assert!(Config::parse(&text).is_err());
    }
}
