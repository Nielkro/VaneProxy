//! PenikProxy: SNI-based TCP router & hybrid reverse proxy.
//!
//! Listens on :443, sniffs the TLS ClientHello SNI and ALPN without terminating TLS for L4 routes,
//! terminates TLS for configured L7 sites (with Auto-SSL, reverse proxying, WebSockets and static files),
//! and falls back to default_backend (with PROXY protocol v2).

pub mod acme;
pub mod caddyfile;
mod config;
pub mod l7;
mod logging;
mod proxy_proto;
mod relay;
mod sni;
pub mod tls;
pub mod watcher;

use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use tokio::net::{TcpListener, TcpStream};
use tracing::error;

use crate::config::Config;

/// SNI router & hybrid reverse proxy: :443 -> Xray / L7 / Caddy.
#[derive(Debug, Parser)]
#[command(name = "penik-proxy", version)]
struct Args {
    /// Path to the TOML config file.
    #[arg(
        long,
        env = "PENIK_CONFIG",
        default_value = "/etc/penik-proxy/config.toml"
    )]
    config: PathBuf,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    let cfg = match Config::load(&args.config) {
        Ok(c) => Arc::new(c),
        Err(e) => {
            eprintln!("config error ({}): {e}", args.config.display());
            std::process::exit(1);
        }
    };

    // Install process-wide default CryptoProvider for Rustls (ring)
    let _ = rustls::crypto::ring::default_provider().install_default();

    logging::init(&cfg.log_level, cfg.access_log);

    // Load initial sites from sites_dir if configured
    let sites = if let Some(dir) = &cfg.sites_dir {
        match caddyfile::load_sites_dir(dir) {
            Ok(s) => s,
            Err(e) => {
                error!(error = %e, "failed to load sites directory");
                Vec::new()
            }
        }
    } else {
        Vec::new()
    };

    let alpn_registry = Arc::new(acme::AlpnChallengeRegistry::new());

    // Initialize TLS and certificate store if configured
    let mut cert_resolver = None;
    let mut tls_acceptor = None;
    let mut acme_mgr = None;

    if let Some(tls_cfg) = &cfg.tls {
        let storage_dir = tls_cfg
            .storage_dir
            .clone()
            .unwrap_or_else(|| PathBuf::from("/var/lib/penik-proxy/certs"));
        let store = match acme::CertStore::new(&storage_dir) {
            Ok(s) => Some(s),
            Err(e) => {
                error!(error = %e, "failed to initialize certificate store");
                None
            }
        };

        if let Some(store) = store {
            let resolver = Arc::new(tls::DynamicCertResolver::with_alpn_registry(
                None,
                alpn_registry.clone(),
            ));

            // Load all existing certificates from disk
            if let Ok(all_certs) = store.load_all_certificates() {
                let mut cert_domains = Vec::new();
                for s in &sites {
                    cert_domains.extend(s.addresses.clone());
                }
                resolver.register_loaded_certs(&cert_domains, &all_certs);
            }

            if let Ok(server_config) = tls::create_server_config(resolver.clone()) {
                tls_acceptor = Some(tokio_rustls::TlsAcceptor::from(Arc::new(server_config)));
                cert_resolver = Some(resolver);
            }

            // Setup ACME manager if email is configured
            if let Some(email) = &tls_cfg.email {
                let acme_config = acme::AcmeConfig {
                    email: email.clone(),
                    staging: tls_cfg.staging,
                    storage_dir,
                    cloudflare_credentials: tls_cfg.cloudflare_credentials.clone(),
                    cloudflare_token: tls_cfg.cloudflare_token.clone(),
                    directory_url: tls_cfg.directory_url.clone(),
                    root_ca: tls_cfg.root_ca.clone(),
                    propagation_secs: tls_cfg.cloudflare_propagation_seconds.unwrap_or(60),
                };
                if let Ok(mgr) = acme::AcmeManager::new(acme_config, (*alpn_registry).clone()) {
                    let mgr_arc = Arc::new(mgr);
                    acme_mgr = Some(mgr_arc.clone());

                    // Collect domains and run certificate order in background
                    let mut site_domains = Vec::new();
                    for s in &sites {
                        site_domains.extend(s.addresses.clone());
                    }
                    if !site_domains.is_empty() {
                        let mgr_task = mgr_arc.clone();
                        let resolver_opt = cert_resolver.clone();
                        let domains_copy = site_domains.clone();
                        tokio::spawn(async move {
                            if let Ok(()) = mgr_task.ensure_certificates(&site_domains).await {
                                if let Ok(all_certs) = mgr_task.store().load_all_certificates() {
                                    if let Some(res) = &resolver_opt {
                                        res.register_loaded_certs(&domains_copy, &all_certs);
                                    }
                                }
                            }
                        });
                    }
                }
            }
        }
    }

    let state = Arc::new(relay::RuntimeState::new(
        cfg.clone(),
        Arc::new(sites),
        alpn_registry,
        tls_acceptor,
    ));

    // Spawn zero-downtime hot reload coordinator
    watcher::spawn_reload_watcher(
        state.clone(),
        args.config.clone(),
        cfg.sites_dir.clone(),
        acme_mgr,
        cert_resolver,
    );

    // Optional HTTP redirect listener
    if let Some(http_addr) = cfg.http_listen {
        tokio::spawn(async move {
            if let Ok(lis) = TcpListener::bind(http_addr).await {
                while let Ok((mut stream, _)) = lis.accept().await {
                    tokio::spawn(async move {
                        use tokio::io::{AsyncReadExt, AsyncWriteExt};
                        let mut buf = [0u8; 2048];
                        if let Ok(n) = stream.read(&mut buf).await {
                            if n > 0 {
                                let req_str = String::from_utf8_lossy(&buf[..n]);
                                let mut lines = req_str.lines();
                                let first_line = lines.next().unwrap_or("");
                                let path = first_line.split_whitespace().nth(1).unwrap_or("/");

                                let mut host = "";
                                for line in lines {
                                    if let Some(h) = line.strip_prefix("Host:") {
                                        host = h.trim();
                                        break;
                                    } else if let Some(h) = line.strip_prefix("host:") {
                                        host = h.trim();
                                        break;
                                    }
                                }

                                let clean_host = host.split(':').next().unwrap_or(host);
                                let location = if clean_host.is_empty() {
                                    format!("https://{}", path)
                                } else {
                                    format!("https://{}{}", clean_host, path)
                                };

                                let resp = format!(
                                    "HTTP/1.1 301 Moved Permanently\r\nLocation: {}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
                                    location
                                );
                                let _ = stream.write_all(resp.as_bytes()).await;
                            }
                        }
                    });
                }
            }
        });
    }

    let listeners = match bind_all(&cfg).await {
        Ok(l) if !l.is_empty() => l,
        Ok(_) => {
            error!("no listen sockets bound, exiting");
            std::process::exit(1);
        }
        Err(e) => {
            error!(error = %e, "bind failed");
            std::process::exit(1);
        }
    };

    eprintln!("penik-proxy started on {:?}", cfg.listen);

    let mut tasks = Vec::new();
    for lis in listeners {
        let state = state.clone();
        tasks.push(tokio::spawn(async move {
            loop {
                match lis.accept().await {
                    Ok((stream, _)) => {
                        let _ = stream.set_nodelay(true);
                        let state = state.clone();
                        tokio::spawn(async move {
                            relay::handle_conn(stream, state).await;
                        });
                    }
                    Err(e) => {
                        error!(error = %e, "accept failed");
                        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    }
                }
            }
        }));
    }

    let _ = tokio::signal::ctrl_c().await;
    eprintln!("penik-proxy: shutdown signal, exiting");
    for t in tasks {
        t.abort();
    }
}

/// Bind every address from `listen`.
async fn bind_all(cfg: &Config) -> std::io::Result<Vec<TcpListener>> {
    let mut out = Vec::new();
    for addr in &cfg.listen {
        match bind_one(*addr) {
            Ok(l) => out.push(l),
            Err(e) if !cfg.strict_listen => {
                error!(listen = %addr, error = %e, "bind failed, skipping (strict_listen=false)");
            }
            Err(e) => {
                return Err(e);
            }
        }
    }
    Ok(out)
}

fn bind_one(addr: std::net::SocketAddr) -> std::io::Result<TcpListener> {
    use socket2::{Domain, Protocol, Socket, Type};

    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let sock = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    sock.set_reuse_address(true)?;
    if addr.is_ipv6() {
        sock.set_only_v6(true)?;
    }
    sock.bind(&addr.into())?;
    sock.listen(4096)?;
    sock.set_nonblocking(true)?;
    let std_lis: std::net::TcpListener = sock.into();
    TcpListener::from_std(std_lis)
}

/// Re-export for integration tests.
#[allow(dead_code)]
fn _assert_stream(_: TcpStream) {}
