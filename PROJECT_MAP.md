# Project Map

Map of core source files for the PenikProxy project. Paths are relative to the project root; cache, logs, vendor code, and auto-generated build artifacts are excluded.

## Core

### Rust proxy

- `src/main.rs` — Binary entry point: parses CLI (`--config` / `PENIK_CONFIG`), loads config, inits logging, binds dual-stack listeners via `socket2` (`IPV6_V6ONLY`), and runs accept loops with graceful shutdown.
- `src/config.rs` — Loads and validates TOML configuration: listen sockets, timeouts, log flags, named backends (`addr` + `send_proxy_protocol`), `default_backend`, and normalized `SNI -> backend` routes.
- `src/sni.rs` — TLS ClientHello SNI parser: extracts first `host_name` from extension `0x0000` without terminating TLS; ASCII case-folds, trims trailing dot, rejects malformed input with `None`.
- `src/proxy_proto.rs` — PROXY protocol v2 encoder: builds `PROXY` headers for IPv4/IPv6 (with `to_canonical()` for mapped addresses) and `LOCAL` fallback for mixed families.
- `src/relay.rs` — Per-connection handler: read-loop sniffs first record (fast-path for non-TLS), routes by SNI, connects to backend, writes optional PPv2 header plus buffered bytes, then splices via `copy_bidirectional`.
- `src/logging.rs` — Tracing setup: quiet `error` default, lifts to `info` when `access_log` is enabled so per-connection lines are visible.
- `src/caddyfile/mod.rs` — Caddyfile module root, directory loader, and integration tests.
- `src/caddyfile/model.rs` — AST data structures for Caddyfile site blocks, directives, upstreams, and matchers.
- `src/caddyfile/lexer.rs` — Caddyfile tokenizer with exact line/column tracking and comment handling.
- `src/caddyfile/parser.rs` — Fail-fast recursive descent parser for Caddyfile syntax.
- `src/caddyfile/cluster.rs` — Apex domain extraction, wildcard consolidation, and SNI site matching.
- `src/acme/mod.rs` — ACME module root and lifecycle integration tests.
- `src/acme/dns_cloudflare.rs` — Cloudflare DNS-01 API client for TXT challenge records.
- `src/acme/alpn_challenge.rs` — Ephemeral TLS-ALPN-01 challenge certificate manager (RFC 8737).
- `src/acme/store.rs` — Certificate persistence with 0600 file permissions, X.509 notAfter expiration parsing, SAN domain coverage validation, and apex loading.
- `src/acme/manager.rs` — High-level ACME order manager with unified multi-SAN and partitioning fallback.
- `src/l7/mod.rs` — Layer-7 reverse proxy and static asset HTTP server engine.
- `src/l7/proxy.rs` — Upstream HTTP reverse proxy forwarder with WebSocket upgrade support.
- `src/l7/service.rs` — Request dispatcher handling static files, reverse proxy, rewrites, and redirects.
- `src/l7/static_files.rs` — Static file server with traversal protection and MIME detection.
- `src/tls/mod.rs` — TLS server configuration and PEM parsing utilities.
- `src/tls/resolver.rs` — Dynamic SNI-based TLS certificate resolver with apex domain grouping and hot-reloading support.
- `src/watcher.rs` — Zero-downtime hot reload coordinator with configurable periodic renewal interval, SIGHUP, and 500ms debounce.
- `Cargo.toml` — Package manifest: `vane` binary, `tokio` / `socket2` / `clap` / `serde` / `toml` / `tracing` / `thiserror` dependencies.
- `Cargo.lock` — Pinned dependency tree for reproducible builds.
- `vane.service` — Hardened systemd service unit with `CAP_NET_BIND_SERVICE` running as unprivileged `vane` user.
- `vane_yandere.py` — Parody single-file Python port of Vane L4 core in YandereDev style: giant if/elif chains, globals, magic strings, duplicated PPv2 encoders, Update() polling loop.
- `assets/vane-logo.svg` — Aerodynamic neon SVG vector logo for Vane.
- `README.md` — Project documentation, architecture diagrams, and quickstart guide.
- `LICENSE` — MIT open-source license.
- `config.example.toml` — Example configuration: dual-stack listen, Xray (raw) and Caddy (PPv2) backends, default route to Caddy, SNI routes for messenger and site domains.
- `config.production.toml` — Production configuration template with strict security, DNS-01/ALPN, and L4/L7 routing.
- `tests/e2e/test_vane.py` — Standalone Python E2E integration test suite testing L4 SNI routing, PROXY protocol v2, default fallback, HTTP redirect, SIGHUP hot reload, and TLS termination with X.509 certificate verification.
- `tests/e2e/config.ci.toml` — Isolated CI/E2E configuration file for Vane test runners supporting local Pebble ACME server and custom root CA.
- `tests/e2e/pebble/pebble.minica.pem` — Pebble Root CA certificate for local ACME testing.
- `.github/workflows/e2e.yml` — GitHub Actions CI pipeline running unit tests, binary build, Pebble ACME service container, and zero-dependency Python E2E integration suite.

## Docs

### Project rules

- `AGENTS.md` — Agent working rules: Russian communication, English code/commits, `PROJECT_MAP.md` navigation, auto-commit style, subagent policy.

### Design

- `plan/00-overview.md` — Goal and confirmed decisions: SNI routing on `:443`, fallback to Caddy, PPv2 only for Caddy, systemd deploy, error-only logs by default.
- `plan/01-architecture.md` — Connection flow, record vs handshake lengths, PPv2 layout, dual-stack sockets, `copy_bidirectional` over `splice` rationale, timeouts.
- `plan/02-config.md` — Config format reference: unified backend entity, match rules, startup validation, no hot-reload in MVP.
- `plan/03-implementation.md` — Crate layout, dependency choices, `handle_conn` pseudocode, development steps.
- `plan/04-deploy.md` — systemd unit with `CAP_NET_BIND_SERVICE`, Caddy `:8444` with per-port `proxy_protocol` wrapper (`xcaddy`), Xray untouched, cutover order.
- `plan/05-testing-risks.md` — Unit/integration/manual test matrix, ECH and fragmentation risks, out-of-MVP scope (metrics, QUIC, TLS termination).
- `plan/06-reverse-proxy-auto-ssl.md` — Hybrid L4/L7 architecture, Caddyfile parser, unified multi-domain SAN Auto-SSL (DNS-01 / TLS-ALPN-01), reverse proxy, static file server, and hot-reload.
