//! The REST API.
use fireemu_core_database::{Limits, Path, Tree};

/// An HTTP request as the REST layer sees it.
#[derive(Debug, Clone, Default)]
pub struct HttpRequest {
    /// The method.
    pub method: String,
    /// The path and query (`/a/b.json?ns=x`).
    pub target: String,
    /// The headers, `Host` included.
    pub headers: Vec<(String, String)>,
    /// The body.
    pub body: Vec<u8>,
}

/// An HTTP response.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HttpResponse {
    /// The status code.
    pub status: u16,
    /// The headers.
    pub headers: Vec<(String, String)>,
    /// The body.
    pub body: Vec<u8>,
}

/// One server-sent event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SseEvent {
    /// The event name (`put`, `patch`, `keep-alive`).
    pub event: String,
    /// The data line.
    pub data: String,
}

/// What a request produced.
#[derive(Debug)]
pub enum Handled {
    /// A complete response, and the events it caused on open streams.
    Response {
        /// The response.
        response: HttpResponse,
        /// Events for open streams, by subscription id.
        events: Vec<(u64, SseEvent)>,
    },
    /// A new event stream.
    Stream {
        /// The subscription id.
        id: u64,
        /// The response head.
        response: HttpResponse,
        /// The first event.
        initial: SseEvent,
    },
}

/// How requests are authorized while no rules are loaded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RulesMode {
    /// Everything is allowed (emulator and strict, ledger 1471 Q4).
    #[default]
    AllowAll,
    /// Everything but the owner credential is denied (productionExact).
    DenyAll,
}

/// Options of the REST layer.
#[derive(Debug, Clone)]
pub struct RestOptions {
    /// The namespace of requests that name none.
    pub default_namespace: String,
    /// Authorization without rules.
    pub rules: RulesMode,
    /// Write limits.
    pub limits: Limits,
}

impl Default for RestOptions {
    fn default() -> Self {
        Self {
            default_namespace: "fake-server".to_owned(),
            rules: RulesMode::AllowAll,
            limits: Limits::default(),
        }
    }
}

/// Every namespace of one emulator.
#[derive(Debug)]
pub struct Database;

impl Database {
    /// An empty database; push ids draw their randomness from `seed`.
    pub fn new(options: RestOptions, seed: u64) -> Self {
        let _ = (options, seed);
        todo!()
    }

    /// The tree of `namespace`, if it was ever written.
    pub fn tree(&self, namespace: &str) -> Option<&Tree> {
        let _ = namespace;
        todo!()
    }

    /// Declares the index `.indexOn: spec` at `path` of `namespace`.
    pub fn declare_index(&mut self, namespace: &str, path: &Path, spec: &str) {
        let _ = (namespace, path, spec);
        todo!()
    }

    /// Handles one request at the server time `now_millis`.
    pub fn handle(&mut self, request: &HttpRequest, now_millis: i64) -> Handled {
        let _ = (request, now_millis);
        todo!()
    }
}
