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
    /// HTTPS upstream, e.g., `https://backend.internal:8443`.
    Tls(TlsUpstream),
}

/// TLS upstream target configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsUpstream {
    /// Destination host:port for TCP connection (e.g. `127.0.0.1:8082` or `sub.pnc.penik.ru:8082`).
    pub addr: String,
    /// Hostname used for SNI handshake and default Host header (without port).
    pub sni: String,
    /// Whether to disable TLS certificate verification (`tls_insecure_skip_verify`).
    /// Strictly guarded: only permitted for loopback destinations.
    pub insecure: bool,
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
    /// Whether transport block requested tls_insecure_skip_verify.
    pub insecure_tls: bool,
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

/// Response header configuration: `header [@matcher] [+|-]Header-Name [value]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseHeaderConfig {
    pub matcher: Option<String>,
    pub op: HeaderOp,
}

/// Static file server configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileServerConfig {
    /// Whether directory browsing is enabled.
    pub browse: bool,
    /// List of file patterns to hide from serving / browsing.
    pub hide: Vec<String>,
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

/// Respond directive configuration: `respond [@matcher] [body] [status_code]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RespondConfig {
    pub matcher: Option<String>,
    pub body: Option<String>,
    pub status: u16,
}

/// Named matcher declaration: `@name { ... }` or `@name <matcher-inline>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatcherDef {
    pub name: String,
    pub matchers: Vec<MatcherRule>,
}

/// Individual matcher rule within a MatcherDef or inline directive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MatcherRule {
    /// `path /prefix/*` or `path /exact`
    Path(Vec<String>),
    /// `path_regexp [name] <regex>`
    PathRegexp(String),
    /// `method GET POST OPTIONS`
    Method(Vec<String>),
    /// `header [!]Header-Name [value]`
    Header {
        name: String,
        value: Option<String>,
        negated: bool,
    },
    /// `file` check (exists on disk)
    File,
    /// `{http.error.status_code} == 404` expression
    StatusExpr(StatusCond),
}

/// Simplified status comparison condition for handle_errors expressions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusCond {
    pub op: StatusOp,
    pub code: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusOp {
    Eq,
    Neq,
    Gte,
    Lte,
    Gt,
    Lt,
}

/// Mutually exclusive handling block (`handle [<matcher>] { ... }`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandleBlock {
    /// Optional matcher identifier (e.g., `@static` or `/api/*`).
    pub matcher: Option<String>,
    /// Nested directives.
    pub directives: Vec<Directive>,
}

/// Handle path block (`handle_path <prefix> { ... }`) which strips the prefix first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandlePathBlock {
    pub prefix: String,
    pub directives: Vec<Directive>,
}

/// Directives supported by Vane's Caddyfile parser.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Directive {
    /// Named matcher definition: `@name { ... }`
    Matcher(MatcherDef),
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
    /// `respond [<matcher>] [body] [status_code]`
    Respond(RespondConfig),
    /// `header [<matcher>] [+|-]<name> [value]`
    ResponseHeader(ResponseHeaderConfig),
    /// `uri strip_prefix <prefix>`
    UriStripPrefix(String),
    /// `handle [<matcher>] { ... }`
    Handle(HandleBlock),
    /// `handle_path <prefix> { ... }`
    HandlePath(HandlePathBlock),
    /// `handle_errors { ... }`
    HandleErrors(Vec<Directive>),
    /// `request_body { max_size <bytes> }` or `request_body max_size <bytes>`
    RequestBodyLimit(u64),
    /// `header_up [+|-]<name> [value]`
    HeaderUp(HeaderOp),
    /// `header_down [+|-]<name> [value]`
    HeaderDown(HeaderOp),
}
