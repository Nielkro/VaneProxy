//! AST models for the supported Caddyfile subset.

use std::path::PathBuf;

/// A parsed Caddyfile site block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SiteBlock {
    /// List of hostnames or addresses this site serves (e.g., `["slavchat.ru", "*.slavchat.ru"]`).
    pub addresses: Vec<String>,
    /// Block directives.
    pub directives: Vec<Directive>,
    /// Source file path, if known.
    pub source_file: Option<PathBuf>,
    /// Line number where the block started.
    pub line: usize,
}

/// Upstream target for reverse proxying.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Upstream {
    /// TCP host:port, e.g., `127.0.0.1:3000` or `backend.internal:8080`.
    Tcp(String),
    /// Unix domain socket path, e.g., `/run/app.sock`.
    Unix(PathBuf),
}

/// Reverse proxy directive configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReverseProxyConfig {
    /// Destination upstream addresses.
    pub upstreams: Vec<Upstream>,
    /// Header operations applied to requests before sending upstream.
    pub header_up: Vec<HeaderOp>,
    /// Header operations applied to responses before returning downstream.
    pub header_down: Vec<HeaderOp>,
}

/// Header modification operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeaderOp {
    /// Set or replace header: `header_up Header-Name value`.
    Set(String, String),
    /// Add header value: `header_up +Header-Name value`.
    Add(String, String),
    /// Remove header: `header_up -Header-Name`.
    Delete(String),
}

/// Static file server configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileServerConfig {
    /// Whether directory browsing is enabled.
    pub browse: bool,
}

/// HTTP redirect configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedirConfig {
    /// Optional request matcher (e.g., `/old-path`).
    pub matcher: Option<String>,
    /// Target URI or path.
    pub target: String,
    /// HTTP status code (default 302, or 301/307/308).
    pub code: u16,
}

/// URL rewrite configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RewriteConfig {
    /// Optional request matcher.
    pub matcher: Option<String>,
    /// New internal path.
    pub target: String,
}

/// Mutually exclusive handling block (`handle [<matcher>] { ... }`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandleBlock {
    /// Optional matcher identifier (e.g., `@static` or `/api/*`).
    pub matcher: Option<String>,
    /// Nested directives.
    pub directives: Vec<Directive>,
}

/// Directives supported by PenikProxy's Caddyfile parser.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Directive {
    /// `reverse_proxy <upstreams...>`
    ReverseProxy(ReverseProxyConfig),
    /// `root [<matcher>] <path>`
    Root(String),
    /// `file_server [browse]`
    FileServer(FileServerConfig),
    /// `try_files <files...>`
    TryFiles(Vec<String>),
    /// `redir [<matcher>] <target> [code]`
    Redir(RedirConfig),
    /// `rewrite [<matcher>] <target>`
    Rewrite(RewriteConfig),
    /// `handle [<matcher>] { ... }`
    Handle(HandleBlock),
}
