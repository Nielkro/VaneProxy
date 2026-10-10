//! Zero-downtime hot reload coordinator with SIGHUP and debounced filesystem watcher.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use notify::{Event, RecursiveMode, Watcher};
use tokio::sync::mpsc;
use tracing::{error, info, warn};

use crate::acme::manager::AcmeManager;
use crate::caddyfile::load_sites_dir;
use crate::config::Config;
use crate::relay::RuntimeState;

/// Spawns the hot-reload coordinator background task.
pub fn spawn_reload_watcher(
    state: Arc<RuntimeState>,
    config_path: PathBuf,
    sites_dir: Option<PathBuf>,
    acme_mgr: Option<Arc<AcmeManager>>,
) {
    tokio::spawn(async move {
        let (tx, mut rx) = mpsc::channel(16);

        // 1. Setup filesystem watcher
        let tx_fs = tx.clone();
        let mut watcher = match notify::recommended_watcher(move |res: Result<Event, notify::Error>| {
            if let Ok(event) = res {
                if event.kind.is_modify() || event.kind.is_create() || event.kind.is_remove() {
                    let _ = tx_fs.try_send(());
                }
            }
        }) {
            Ok(w) => Some(w),
            Err(e) => {
                warn!(error = %e, "failed to initialize filesystem watcher");
                None
            }
        };

        if let Some(w) = &mut watcher {
            let _ = w.watch(&config_path, RecursiveMode::NonRecursive);
            if let Some(dir) = &sites_dir {
                if dir.exists() {
                    let _ = w.watch(dir, RecursiveMode::Recursive);
                }
            }
        }

        // 2. Setup SIGHUP listener (Unix)
        #[cfg(unix)]
        let mut sighup = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()) {
            Ok(s) => Some(s),
            Err(e) => {
                warn!(error = %e, "failed to register SIGHUP listener");
                None
            }
        };

        info!("hot reload watcher active (SIGHUP + inotify with 500ms debounce)");

        loop {
            tokio::select! {
                Some(()) = rx.recv() => {
                    // Debounce: wait 500ms to coalesce burst events from editors
                    tokio::time::sleep(Duration::from_millis(500)).await;
                    while rx.try_recv().is_ok() {}
                    reload_all(&state, &config_path, &sites_dir, &acme_mgr).await;
                }
                _ = async {
                    #[cfg(unix)]
                    if let Some(hup) = &mut sighup {
                        hup.recv().await;
                        return;
                    }
                    std::future::pending::<()>().await;
                } => {
                    info!("received SIGHUP signal, triggering reload");
                    reload_all(&state, &config_path, &sites_dir, &acme_mgr).await;
                }
            }
        }
    });
}

async fn reload_all(
    state: &Arc<RuntimeState>,
    config_path: &Path,
    sites_dir: &Option<PathBuf>,
    acme_mgr: &Option<Arc<AcmeManager>>,
) {
    info!("compiling draft configuration for atomic reload...");

    // 1. Reload and validate config.toml
    let new_cfg = match Config::load(config_path) {
        Ok(c) => Arc::new(c),
        Err(e) => {
            error!(error = %e, "reload rejected: invalid config.toml, keeping current config");
            return;
        }
    };

    // 2. Reload and validate sites-enabled
    let target_sites_dir = new_cfg.sites_dir.as_ref().or(sites_dir.as_ref());
    let new_sites = match target_sites_dir {
        Some(dir) => match load_sites_dir(dir) {
            Ok(s) => Arc::new(s),
            Err(e) => {
                error!(error = %e, "reload rejected: invalid site configuration, keeping current sites");
                return;
            }
        },
        None => Arc::new(Vec::new()),
    };

    // 3. Atomically update runtime state
    state.update_config(new_cfg.clone());
    state.update_sites(new_sites.clone());

    info!(
        routes = new_cfg.routes.len(),
        sites = new_sites.len(),
        "configuration atomically reloaded without downtime"
    );

    // 4. Update certificates if new domains exist
    if let Some(mgr) = acme_mgr {
        let mut domains = Vec::new();
        for site in new_sites.iter() {
            domains.extend(site.addresses.clone());
        }
        if !domains.is_empty() {
            let mgr_clone = Arc::clone(mgr);
            tokio::spawn(async move {
                let _ = mgr_clone.ensure_certificates(&domains).await;
            });
        }
    }
}
