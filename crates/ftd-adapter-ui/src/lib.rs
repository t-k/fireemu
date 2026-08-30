//! Emulator UI: the embedded single-page app under `/ui` and its API under `/ui/api`.
//!
//! The API is a same-origin, privileged front to the runtime's own surfaces: Firestore
//! requests go through the REST layer as `Bearer owner`, Auth requests through the Identity
//! Toolkit admin routes, Storage through the JSON API, control-plane requests through the
//! control API, so no logic is duplicated and every existing check (validation, budgets,
//! the admission barrier, fault plans) applies. Two server-sent event streams push Firestore
//! commits and function logs.
//!
//! ```text
//! GET  /ui, /ui/*                      the app (SPA fallback; index.html carries window.__FTD__)
//! GET  /ui/api/config                  what this runtime is (project, edition, ports, sessions)
//! ANY  /ui/api/firestore/v1/...        Firestore REST, as owner
//! GET  /ui/api/firestore/watch         SSE: commits (project / database filters)
//! ANY  /ui/api/auth/...                Identity Toolkit admin + emulator routes, as owner
//! GET  /ui/api/storage/buckets         the buckets of every session project
//! ANY  /ui/api/storage/...             Storage JSON API, as owner
//! GET  /ui/api/functions               manifest, status, history, dead letters
//! GET  /ui/api/functions/logs          SSE: runner log lines and invocation outcomes
//! GET  /ui/api/appcheck/config         App Check: apps and baseline modes (no digest, no secret)
//! ANY  /ui/api/appcheck/projects/...   App Check debug-token management, as the control token
//! ANY  /ui/api/control/v1/...          the control API
//! ```
//!
//! Browser policy: a request carrying an `Origin` must come from a loopback origin and, for
//! the API, present the control token (`Authorization: Bearer <token>` or `?token=`); a
//! `Host` naming anything but this machine is refused (DNS rebinding). Requests without an
//! `Origin` (curl, scripts) are trusted like the control API trusts them.

pub mod api;
pub mod assets;
pub mod server;
pub mod sse;

use std::collections::BTreeMap;
use std::sync::Arc;

use ftd_adapter_functions::runtime::FunctionsRuntime;
use ftd_adapter_grpc::local::LocalBackend;
use ftd_adapter_grpc::rest::RestState;
use ftd_adapter_http::control::ControlState;
use ftd_adapter_http::identity_toolkit::AuthState;
use ftd_adapter_http::storage::StorageState;
use serde_json::{json, Value};

/// Maximum accepted body of a JSON route.
pub const MAX_JSON_BODY_BYTES: usize = 256 * 1024;

/// Header a response carries when the fault plan's `dropConnection` fired behind this
/// front: the listener closes the connection instead of sending it.
pub const DROP_CONNECTION_HEADER: &str = "x-ftd-drop-connection";

/// What the UI shows about App Check (fixed at start). The mutable part of the surface --
/// the registered apps, their dynamic debug tokens and the observations -- is read from the
/// registry on every request instead, so the page never shows a stale registration.
#[derive(Debug, Clone, Default)]
pub struct AppCheckInfo {
    /// The `kid` of this instance's App Check signing key (public: it names the JWKS entry).
    pub kid: String,
    /// The effective baseline mode of each service (`--only` applied), in a stable order.
    pub modes: Vec<(String, String)>,
}

/// What the UI shows about this runtime (fixed at start).
#[derive(Debug, Clone, Default)]
pub struct RuntimeInfo {
    /// Crate version.
    pub version: String,
    /// Default project.
    pub project: String,
    /// `standard` / `enterprise`.
    pub edition: String,
    /// Firestore listener (gRPC + REST).
    pub firestore_addr: String,
    /// Auth + control listener.
    pub http_addr: String,
    /// Storage listener.
    pub storage_addr: String,
    /// Functions listener, when a codebase is loaded.
    pub functions_addr: Option<String>,
    /// Functions source directory.
    pub functions_source: Option<String>,
    /// This listener.
    pub ui_addr: String,
    /// Whether Security Rules are enforced (config `rules.enforced`).
    pub rules_enforced: bool,
    /// Whether the clock start was pinned by `daemon.clockStart`.
    pub clock_pinned: bool,
    /// App Check, when the runtime enabled it.
    pub app_check: Option<AppCheckInfo>,
}

/// Shared state of the UI surface.
pub struct UiState {
    /// The control token browser pages must present.
    pub control_token: String,
    /// Runtime description.
    pub info: RuntimeInfo,
    /// Firestore REST layer.
    pub rest: Arc<RestState>,
    /// Firestore backend (commit subscriptions).
    pub backend: Arc<LocalBackend>,
    /// Identity Toolkit.
    pub auth: Arc<AuthState>,
    /// Storage.
    pub storage: Arc<StorageState>,
    /// Control API.
    pub control: Arc<ControlState>,
    /// Functions runtime, when configured.
    pub functions: Option<Arc<FunctionsRuntime>>,
    /// App Check, when the runtime enabled it: the UI fronts its privileged debug-token
    /// management and reads its registry for the configuration summary. The state carries the
    /// control token and the secret source, so it never leaves this crate's own routes.
    pub app_check: Option<Arc<ftd_adapter_http::app_check::AppCheckState>>,
}

/// One request of the UI surface.
#[derive(Debug, Clone, Default)]
pub struct UiRequest {
    /// Method.
    pub method: String,
    /// Path (not decoded, no query string).
    pub path: String,
    /// Raw query string.
    pub query: String,
    /// Headers (lowercase names).
    pub headers: BTreeMap<String, String>,
    /// Body.
    pub body: Vec<u8>,
}

impl UiRequest {
    /// A header by lowercase name.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).map(String::as_str)
    }

    /// The first value of a query parameter (percent-decoded).
    #[must_use]
    pub fn param(&self, name: &str) -> Option<String> {
        self.query
            .split('&')
            .filter(|s| !s.is_empty())
            .map(|kv| kv.split_once('=').unwrap_or((kv, "")))
            .find(|(k, _)| *k == name)
            .map(|(_, v)| percent_decode(v))
    }
}

/// Response body: bytes, or a server-sent event stream.
#[derive(Debug)]
pub enum UiBody {
    /// A complete body.
    Full(Vec<u8>),
    /// Chunks produced by a task until the client goes away.
    Stream(tokio::sync::mpsc::Receiver<bytes::Bytes>),
}

/// One response.
#[derive(Debug)]
pub struct UiResponse {
    /// Status.
    pub status: u16,
    /// Headers.
    pub headers: Vec<(String, String)>,
    /// Body.
    pub body: UiBody,
}

impl UiResponse {
    /// A JSON response.
    #[must_use]
    pub fn json(status: u16, body: &Value) -> Self {
        Self {
            status,
            headers: vec![
                (
                    "content-type".to_owned(),
                    "application/json; charset=utf-8".to_owned(),
                ),
                ("x-content-type-options".to_owned(), "nosniff".to_owned()),
            ],
            body: UiBody::Full(serde_json::to_vec(body).unwrap_or_default()),
        }
    }

    /// An error in the control API's shape.
    #[must_use]
    pub fn error(status: u16, message: &str) -> Self {
        Self::json(
            status,
            &json!({"error": {"code": status, "message": message}}),
        )
    }

    /// The JSON body when the response is one.
    #[must_use]
    pub fn body_json(&self) -> Option<Value> {
        match &self.body {
            UiBody::Full(bytes) => serde_json::from_slice(bytes).ok(),
            UiBody::Stream(_) => None,
        }
    }
}

/// Percent-decoding (`+` stays a plus; the UI encodes spaces as `%20`).
#[must_use]
pub fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Some(b) = s
                .get(i + 1..i + 3)
                .and_then(|h| u8::from_str_radix(h, 16).ok())
            {
                out.push(b);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Whether a `Host` header names this machine (loopback), with or without a port.
#[must_use]
pub fn host_is_local(host: &str) -> bool {
    let host = host.trim();
    let name = if let Some(rest) = host.strip_prefix('[') {
        rest.split(']').next().unwrap_or("")
    } else {
        host.rsplit_once(':').map_or(host, |(h, _)| h)
    };
    matches!(name, "localhost" | "127.0.0.1" | "::1")
}

/// Whether `s` contains a NUL or another control character (refused at the boundary).
#[must_use]
pub fn has_control_chars(s: &str) -> bool {
    s.bytes().any(|b| b < 0x20 || b == 0x7f)
}

/// The browser policy (see the module documentation). `None` admits the request.
#[must_use]
pub fn guard(state: &UiState, req: &UiRequest) -> Option<UiResponse> {
    // A request without a Host is not one a browser on this machine sent to this port.
    if !req.header("host").is_some_and(host_is_local) {
        return Some(UiResponse::error(
            403,
            "FORBIDDEN_HOST : the UI answers only to localhost / 127.0.0.1 / [::1]",
        ));
    }
    if has_control_chars(&req.path) || has_control_chars(&req.query) {
        return Some(UiResponse::error(
            400,
            "INVALID_ARGUMENT : control characters in the request target",
        ));
    }
    if !req.path.starts_with("/ui/api/") && req.path != "/ui/api" {
        return None;
    }
    if let Some(origin) = req.header("origin") {
        if !ftd_adapter_http::identity_toolkit::origin_is_local(origin) {
            return Some(UiResponse::error(403, "FORBIDDEN_ORIGIN"));
        }
    }
    // Every API request presents the token in the header, whether or not it carries an
    // `Origin`: browsers omit `Origin` on navigations and sub-resource loads (`<iframe>`,
    // `<script src>`, `<img>`), which would otherwise read this privileged surface from a
    // page on another site. The page the daemon serves always sends it; a query
    // parameter is not accepted (it would land in histories and logs).
    let presented = req
        .header("authorization")
        .and_then(|a| a.strip_prefix("Bearer "))
        .map(str::trim);
    if !ftd_adapter_http::control::token_matches(presented, &state.control_token) {
        return Some(UiResponse::error(
            403,
            "CONTROL_TOKEN_REQUIRED : requests to the UI API need Authorization: Bearer <control token>",
        ));
    }
    None
}

/// The nonce of the configuration script the page carries (stable for the daemon's
/// lifetime, unguessable without the token it derives from).
fn script_nonce(state: &UiState) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in state
        .control_token
        .bytes()
        .chain(b"ftd-ui-nonce".iter().copied())
    {
        h = (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3);
    }
    format!("{h:016x}")
}

/// The configuration the page receives (`window.__FTD__`) and `GET /ui/api/config` returns.
#[must_use]
pub fn config_json(state: &UiState) -> Value {
    let info = &state.info;
    let sessions = state.control.sessions.lock().map_or_else(
        |_| Vec::new(),
        |s| {
            s.iter()
                .map(|(name, project)| json!({"name": name, "project": project}))
                .collect::<Vec<_>>()
        },
    );
    json!({
        "version": info.version,
        "project": info.project,
        "edition": info.edition,
        "firestoreAddr": info.firestore_addr,
        "httpAddr": info.http_addr,
        "storageAddr": info.storage_addr,
        "functionsAddr": info.functions_addr,
        "functionsSource": info.functions_source,
        "uiAddr": info.ui_addr,
        "rulesEnforced": info.rules_enforced,
        "clockPinned": info.clock_pinned,
        "functionsConfigured": state.functions.is_some(),
        "appCheckEnabled": state.app_check.is_some(),
        "uiBundled": assets::bundled(),
        "sessions": sessions,
        "controlToken": state.control_token,
    })
}

/// Routes one request. Streams are produced by tasks spawned on the current runtime.
pub async fn handle(state: &Arc<UiState>, req: &UiRequest) -> UiResponse {
    if let Some(refusal) = guard(state, req) {
        return refusal;
    }
    let path = req.path.as_str();
    if path == "/ui/api/config" {
        return match req.method.as_str() {
            "GET" => UiResponse::json(200, &config_json(state)),
            _ => UiResponse::error(405, "METHOD_NOT_ALLOWED"),
        };
    }
    if let Some(rest) = path.strip_prefix("/ui/api/") {
        return api::route(state, rest, req).await;
    }
    if path == "/ui" || path.starts_with("/ui/") {
        if req.method != "GET" && req.method != "HEAD" {
            return UiResponse::error(405, "METHOD_NOT_ALLOWED");
        }
        let rel = path.strip_prefix("/ui").unwrap_or("");
        let nonce = script_nonce(state);
        return match assets::resolve(rel, &config_json(state), &nonce) {
            Some(asset) => UiResponse {
                status: 200,
                headers: vec![
                    ("content-type".to_owned(), asset.content_type.to_owned()),
                    ("cache-control".to_owned(), asset.cache_control.to_owned()),
                    ("x-content-type-options".to_owned(), "nosniff".to_owned()),
                    // The app never runs inside another site's frame, loads nothing from
                    // elsewhere, and only its own bundle plus the nonced configuration
                    // script may run.
                    ("x-frame-options".to_owned(), "DENY".to_owned()),
                    ("referrer-policy".to_owned(), "no-referrer".to_owned()),
                    (
                        "content-security-policy".to_owned(),
                        format!(
                            "default-src 'self'; script-src 'self' 'nonce-{nonce}'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data: blob:; font-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
                        ),
                    ),
                ],
                body: UiBody::Full(asset.body),
            },
            None => UiResponse::error(404, "NOT_FOUND"),
        };
    }
    UiResponse::error(404, "NOT_FOUND")
}
