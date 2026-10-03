//! PenikProxy: SNI-based TCP router.
//!
//! Listens on :443, sniffs the TLS ClientHello SNI without terminating TLS,
//! and splices the stream to Xray (raw) or Caddy (with PROXY protocol v2).

mod config;
mod logging;
mod proxy_proto;
mod relay;
mod sni;

use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use tokio::net::{TcpListener, TcpStream};
use tracing::error;

use crate::config::Config;

/// SNI router: :443 -> Xray / Caddy.
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

    logging::init(&cfg.log_level, cfg.access_log);

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

    tracing::error!(listen = ?cfg.listen, "penik-proxy started");

    // Accept loop per socket, with graceful shutdown on Ctrl-C / SIGTERM.
    let mut tasks = Vec::new();
    for lis in listeners {
        let cfg = cfg.clone();
        tasks.push(tokio::spawn(async move {
            loop {
                match lis.accept().await {
                    Ok((stream, _)) => {
                        let _ = stream.set_nodelay(true);
                        let cfg = cfg.clone();
                        tokio::spawn(async move {
                            relay::handle_conn(stream, cfg).await;
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
    tracing::error!("shutdown signal, exiting");
    for t in tasks {
        t.abort();
    }
}

/// Bind every address from `listen`.
///
/// IPv6 sockets get `IPV6_V6ONLY=true` explicitly: on Linux the default
/// `net.ipv6.bindv6only=0` would otherwise make `[::]:443` swallow IPv4
/// and the `0.0.0.0:443` bind would fail with `EADDRINUSE`.
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
    sock.listen(1024)?;
    sock.set_nonblocking(true)?;
    let std_lis: std::net::TcpListener = sock.into();
    TcpListener::from_std(std_lis)
}

/// Re-export for integration tests.
#[allow(dead_code)]
fn _assert_stream(_: TcpStream) {}
