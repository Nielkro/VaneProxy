//! Logging setup: quiet by default, access log only when enabled.

use tracing_subscriber::EnvFilter;

/// Initialize global tracing.
///
/// `level` is the base directive (e.g. "error"). When `access_log` is true
/// and the level would silence `info!`, it is lifted to `info` so the
/// per-connection lines are visible.
pub fn init(level: &str, access_log: bool) {
    let directive = if access_log && matches!(level, "error" | "warn") {
        "info"
    } else {
        level
    };
    let filter = EnvFilter::try_new(format!("penik_proxy={directive}"))
        .unwrap_or_else(|_| EnvFilter::new("error"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .try_init();
}
