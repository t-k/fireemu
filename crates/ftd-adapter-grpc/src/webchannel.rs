//! `WebChannel` transport for the `Listen` and `Write` streams, as used by the Firebase web SDK
//! in browsers (`/google.firestore.v1.Firestore/{Listen,Write}/channel`).
//!
//! Protocol (closure `WebChannelBase`, version 8, `sendRawJson`, `encodeInitMessageHeaders`):
//!
//! - handshake: `POST ...?database=...&VER=8&RID=<n>&CVER=22&X-HTTP-Session-Id=gsessionid`
//!   with body `headers=<url-encoded "Name:Value\r\n">&count=1&ofs=0&req0___data__=<json>`;
//!   the response carries `X-HTTP-Session-Id` and the chunk `[[0,["c","<sid>","",8,12,30000]]]`;
//! - forward channel: `POST ...?SID=<sid>&RID=<n>&AID=<acked>` with more `reqN___data__`
//!   maps; the response is `[<backchannel present>,<last array id>,0]`;
//! - back channel: `GET ...?SID=<sid>&RID=rpc&AID=<acked>&CI=0&TYPE=xmlhttp` streams
//!   `<len>\n[[<array id>,[<message json>]]]` chunks until the client reconnects;
//!   `CI=1` (long polling) closes the response after the first batch;
//! - `TYPE=terminate` ends the session.
//!
//! Every chunk is the decimal byte length, a newline and the JSON text. Stream errors are
//! delivered as `[{"error": {...}}]` payloads (the shape the SDK unwraps).

// `tonic::Status` is the error type shared with the gRPC surface.
#![allow(clippy::result_large_err)]

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ftd_proto_firestore::google::firestore::v1 as pb;
use serde_json::{json, Value};
use tokio::sync::{mpsc, Notify};
use tokio_stream::wrappers::ReceiverStream;
use tonic::Status;

use crate::rest::json::{
    listen_request_from_json, listen_response_to_json, write_request_from_json,
    write_response_to_json, JsonError,
};
use crate::rest::{error_response, RestState};
use crate::streams::{listen_stream, write_stream, StreamContext};

/// Sessions idle (no request) longer than this are dropped.
const SESSION_IDLE_TTL: Duration = Duration::from_secs(120);
/// Long-polling back channels return after this long without data.
const LONG_POLL_WAIT: Duration = Duration::from_secs(30);
/// Maximum accepted form body.
pub const MAX_FORM_BYTES: usize = 10 * 1024 * 1024;

static NEXT_SID: AtomicU64 = AtomicU64::new(1);

fn trace_enabled() -> bool {
    static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ENABLED.get_or_init(|| std::env::var_os("FTD_TRACE_WEBCHANNEL").is_some())
}

fn trace(what: &str, detail: &str) {
    if trace_enabled() {
        eprintln!("[webchannel] {what}: {detail}");
    }
}

/// Which gRPC stream a session carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamKind {
    /// `Listen`.
    Listen,
    /// `Write`.
    Write,
}

/// What a `WebChannel` HTTP handler returns.
pub enum ChannelResponse {
    /// A complete JSON/text body.
    Full {
        /// HTTP status.
        status: u16,
        /// Extra headers.
        headers: Vec<(&'static str, String)>,
        /// Body.
        body: String,
    },
    /// A streamed body (back channel).
    Stream {
        /// Extra headers.
        headers: Vec<(&'static str, String)>,
        /// Chunks.
        body: ReceiverStream<Result<bytes::Bytes, Status>>,
    },
}

struct Session {
    sid: String,
    kind: StreamKind,
    inbound: mpsc::Sender<Result<Value, Status>>,
    /// Arrays produced by the stream, not yet acknowledged: `(array id, json text)`.
    outbound: Mutex<VecDeque<(u64, String)>>,
    next_aid: AtomicU64,
    /// Bumped whenever a back channel attaches; older back channels stop.
    backchannel_generation: AtomicU64,
    notify: Notify,
    last_seen: Mutex<Instant>,
    /// Next expected forward-channel map id (duplicates from retries are skipped).
    next_map_id: Mutex<u64>,
    /// The stream ended (error already queued).
    closed: Mutex<bool>,
}

impl Session {
    fn push(&self, payload: &Value) -> u64 {
        let aid = self.next_aid.fetch_add(1, Ordering::SeqCst) + 1;
        let text = json!([aid, payload]).to_string();
        trace("array", &format!("{} {text}", self.sid));
        if let Ok(mut q) = self.outbound.lock() {
            q.push_back((aid, text));
        }
        // `notify_one` keeps a permit when no back channel is waiting yet (no lost wakeups).
        self.notify.notify_one();
        aid
    }

    fn acknowledge(&self, aid: u64) {
        if let Ok(mut q) = self.outbound.lock() {
            while q.front().is_some_and(|(id, _)| *id <= aid) {
                q.pop_front();
            }
        }
    }

    /// Unacknowledged arrays after `aid`, with their ids.
    fn pending_after(&self, aid: u64) -> Vec<(u64, String)> {
        self.outbound.lock().map_or_else(
            |_| Vec::new(),
            |q| q.iter().filter(|(id, _)| *id > aid).cloned().collect(),
        )
    }

    fn last_aid(&self) -> u64 {
        self.next_aid.load(Ordering::SeqCst)
    }

    fn touch(&self) {
        if let Ok(mut t) = self.last_seen.lock() {
            *t = Instant::now();
        }
    }
}

/// Session registry shared by every connection.
pub struct Hub {
    state: Arc<RestState>,
    sessions: Mutex<HashMap<String, Arc<Session>>>,
}

/// One parsed `WebChannel` HTTP request.
pub struct ChannelRequest {
    /// `Listen` or `Write`.
    pub kind: StreamKind,
    /// HTTP method.
    pub method: String,
    /// Query parameters.
    pub params: BTreeMap<String, String>,
    /// `Authorization` header (a browser cannot always set it; the handshake body may carry
    /// it instead).
    pub authorization: Option<String>,
    /// Raw form body.
    pub body: String,
}

fn chunk(text: &str) -> String {
    format!("{}\n{}", text.len(), text)
}

/// Percent-decodes a form value (`+` is a space).
#[must_use]
pub fn form_decode(s: &str) -> String {
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
        out.push(if bytes[i] == b'+' { b' ' } else { bytes[i] });
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Parses `k=v&k=v` (query string or form body).
#[must_use]
pub fn parse_form(text: &str) -> BTreeMap<String, String> {
    text.split('&')
        .filter(|kv| !kv.is_empty())
        .map(|kv| {
            let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
            (form_decode(k), form_decode(v))
        })
        .collect()
}

/// Header block `Name:Value\r\n...` (the `headers=` / `$httpHeaders` encoding).
fn parse_header_block(block: &str) -> BTreeMap<String, String> {
    block
        .split("\r\n")
        .filter_map(|line| line.split_once(':'))
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_owned()))
        .collect()
}

impl Hub {
    /// Creates the hub over the shared local state.
    #[must_use]
    pub fn new(state: Arc<RestState>) -> Self {
        Self {
            state,
            sessions: Mutex::new(HashMap::new()),
        }
    }

    fn purge_idle(&self) {
        if let Ok(mut sessions) = self.sessions.lock() {
            sessions.retain(|_, s| {
                s.last_seen
                    .lock()
                    .is_ok_and(|t| t.elapsed() < SESSION_IDLE_TTL)
            });
        }
    }

    fn session(&self, sid: &str) -> Option<Arc<Session>> {
        let s = self.sessions.lock().ok()?.get(sid).cloned()?;
        s.touch();
        Some(s)
    }

    /// Handles one HTTP request of the channel endpoint.
    pub fn handle(&self, req: &ChannelRequest) -> ChannelResponse {
        self.purge_idle();
        trace(
            "request",
            &format!(
                "{:?} {} {:?} body={}",
                req.kind, req.method, req.params, req.body
            ),
        );
        let sid = req
            .params
            .get("SID")
            .cloned()
            .filter(|s| !s.is_empty() && s != "null");
        match (req.method.as_str(), sid) {
            ("POST", None) => self.handshake(req),
            ("POST", Some(sid)) => self.forward(req, &sid),
            ("GET", Some(sid)) => self.backchannel(req, &sid),
            _ => bad_request("unsupported channel request"),
        }
    }

    fn handshake(&self, req: &ChannelRequest) -> ChannelResponse {
        let form = parse_form(&req.body);
        // Init headers travel in the body (`headers=`) or the query (`$httpHeaders`).
        let mut headers = BTreeMap::new();
        if let Some(block) = form.get("headers") {
            headers.extend(parse_header_block(block));
        }
        if let Some(block) = req.params.get("$httpHeaders") {
            headers.extend(parse_header_block(block));
        }
        let authorization = headers
            .get("authorization")
            .cloned()
            .or_else(|| req.authorization.clone());
        let principal = match &self.state.rules {
            Some(r) => match r.principal_from_authorization(authorization.as_deref()) {
                Ok(p) => p,
                Err(e) => return error_chunk(&e),
            },
            None => crate::rules::Principal::Owner,
        };
        let sid = format!("ftd{:016x}", NEXT_SID.fetch_add(1, Ordering::Relaxed));
        let (inbound_tx, inbound_rx) = mpsc::channel::<Result<Value, Status>>(64);
        let session = Arc::new(Session {
            sid: sid.clone(),
            kind: req.kind,
            inbound: inbound_tx,
            outbound: Mutex::new(VecDeque::new()),
            next_aid: AtomicU64::new(0),
            backchannel_generation: AtomicU64::new(0),
            notify: Notify::new(),
            last_seen: Mutex::new(Instant::now()),
            next_map_id: Mutex::new(0),
            closed: Mutex::new(false),
        });
        if let Ok(mut sessions) = self.sessions.lock() {
            sessions.insert(sid.clone(), session.clone());
        }
        let ctx = StreamContext {
            local: self.state.local.clone(),
            gateway: self.state.gateway.clone(),
            rules: self.state.rules.clone(),
            principal,
            authorization,
            epoch: self.state.local.epoch(),
        };
        spawn_stream(&session, ctx, inbound_rx);
        // The first message rides along with the handshake.
        if let Err(e) = session_deliver(&session, &form) {
            return error_chunk(&e);
        }
        let handshake = json!([[0, ["c", sid, "", 8, 12, 30_000]]]).to_string();
        ChannelResponse::Full {
            status: 200,
            headers: vec![
                ("x-http-session-id", session.sid.clone()),
                ("content-type", "text/plain; charset=utf-8".to_owned()),
            ],
            body: chunk(&handshake),
        }
    }

    fn forward(&self, req: &ChannelRequest, sid: &str) -> ChannelResponse {
        let Some(session) = self.session(sid) else {
            return unknown_session();
        };
        if let Some(aid) = req.params.get("AID").and_then(|a| a.parse::<u64>().ok()) {
            session.acknowledge(aid);
        }
        if req.params.get("TYPE").map(String::as_str) == Some("terminate") {
            if let Ok(mut sessions) = self.sessions.lock() {
                sessions.remove(sid);
            }
            return ChannelResponse::Full {
                status: 200,
                headers: vec![("content-type", "text/plain; charset=utf-8".to_owned())],
                body: String::new(),
            };
        }
        let form = parse_form(&req.body);
        if let Err(e) = session_deliver(&session, &form) {
            return error_chunk(&e);
        }
        let attached = u64::from(session.backchannel_generation.load(Ordering::SeqCst) > 0);
        let text = json!([attached, session.last_aid(), 0]).to_string();
        ChannelResponse::Full {
            status: 200,
            headers: vec![("content-type", "text/plain; charset=utf-8".to_owned())],
            body: chunk(&text),
        }
    }

    fn backchannel(&self, req: &ChannelRequest, sid: &str) -> ChannelResponse {
        let Some(session) = self.session(sid) else {
            return unknown_session();
        };
        let acked = req
            .params
            .get("AID")
            .and_then(|a| a.parse::<u64>().ok())
            .unwrap_or(0);
        session.acknowledge(acked);
        let long_poll = req.params.get("CI").map(String::as_str) == Some("1");
        let generation = session
            .backchannel_generation
            .fetch_add(1, Ordering::SeqCst)
            + 1;
        let (tx, rx) = mpsc::channel::<Result<bytes::Bytes, Status>>(64);
        tokio::spawn(async move {
            let mut cursor = acked;
            loop {
                let pending = session.pending_after(cursor);
                if let Some((last, _)) = pending.last() {
                    let texts: Vec<&str> = pending.iter().map(|(_, t)| t.as_str()).collect();
                    let text = format!("[{}]", texts.join(","));
                    trace(
                        "backchannel send",
                        &format!("{} gen={generation} {text}", session.sid),
                    );
                    if tx.send(Ok(bytes::Bytes::from(chunk(&text)))).await.is_err() {
                        trace("backchannel", "receiver gone");
                        return;
                    }
                    // The cursor is the last id actually sent; arrays pushed meanwhile are
                    // picked up by the next iteration.
                    cursor = *last;
                    if long_poll {
                        return;
                    }
                }
                if session.closed.lock().is_ok_and(|c| *c) && pending.is_empty() {
                    return;
                }
                let waited = tokio::time::timeout(LONG_POLL_WAIT, session.notify.notified()).await;
                trace(
                    "backchannel wake",
                    &format!(
                        "{} gen={generation} timeout={}",
                        session.sid,
                        waited.is_err()
                    ),
                );
                if session.backchannel_generation.load(Ordering::SeqCst) != generation {
                    trace("backchannel", "superseded");
                    return;
                }
                if waited.is_err() {
                    if long_poll {
                        return;
                    }
                    // Keep-alive on a streaming back channel.
                    let noop = json!([[session.last_aid(), ["noop"]]]).to_string();
                    if tx.send(Ok(bytes::Bytes::from(chunk(&noop)))).await.is_err() {
                        return;
                    }
                }
            }
        });
        ChannelResponse::Stream {
            headers: vec![("content-type", "text/plain; charset=utf-8".to_owned())],
            body: ReceiverStream::new(rx),
        }
    }
}

/// Delivers the `reqN___data__` maps of a form body to the session's stream, in map order.
fn session_deliver(session: &Session, form: &BTreeMap<String, String>) -> Result<(), Status> {
    let count: u64 = form.get("count").and_then(|c| c.parse().ok()).unwrap_or(0);
    let ofs: u64 = form.get("ofs").and_then(|c| c.parse().ok()).unwrap_or(0);
    for n in 0..count {
        let map_id = ofs + n;
        let Some(raw) = form.get(&format!("req{n}___data__")) else {
            continue;
        };
        let mut next = session
            .next_map_id
            .lock()
            .map_err(|_| Status::internal("session lock poisoned"))?;
        if map_id < *next {
            continue; // retried map
        }
        *next = map_id + 1;
        drop(next);
        let value: Value = serde_json::from_str(raw)
            .map_err(|e| Status::invalid_argument(format!("invalid message JSON: {e}")))?;
        session
            .inbound
            .try_send(Ok(value))
            .map_err(|_| Status::unavailable("stream is not accepting messages"))?;
    }
    Ok(())
}

fn spawn_stream(
    session: &Arc<Session>,
    ctx: StreamContext,
    inbound_rx: mpsc::Receiver<Result<Value, Status>>,
) {
    let (out_tx, mut out_rx) = mpsc::channel::<Result<Value, Status>>(256);
    let kind = session.kind;
    // Pump: stream output → numbered arrays on the session.
    let pump_session = session.clone();
    tokio::spawn(async move {
        while let Some(item) = out_rx.recv().await {
            match item {
                Ok(v) => {
                    pump_session.push(&json!([v]));
                }
                Err(e) => {
                    let envelope = error_response(&e).body;
                    pump_session.push(&json!([envelope]));
                    break;
                }
            }
        }
        if let Ok(mut c) = pump_session.closed.lock() {
            *c = true;
        }
        pump_session.notify.notify_one();
    });
    match kind {
        StreamKind::Listen => {
            let inbound = ReceiverStream::new(inbound_rx).map_items(|r: Result<Value, Status>| {
                r.and_then(|v| listen_request_from_json(&v).map_err(|e| bad_json(&e)))
            });
            let (tx, mut rx) = mpsc::channel::<Result<pb::ListenResponse, Status>>(256);
            tokio::spawn(async move {
                while let Some(item) = rx.recv().await {
                    let forwarded = item.map(|r| listen_response_to_json(&r));
                    if out_tx.send(forwarded).await.is_err() {
                        break;
                    }
                }
            });
            tokio::spawn(listen_stream(ctx, inbound, tx));
        }
        StreamKind::Write => {
            let inbound = ReceiverStream::new(inbound_rx).map_items(|r: Result<Value, Status>| {
                r.and_then(|v| write_request_from_json(&v).map_err(|e| bad_json(&e)))
            });
            let (tx, mut rx) = mpsc::channel::<Result<pb::WriteResponse, Status>>(256);
            tokio::spawn(async move {
                while let Some(item) = rx.recv().await {
                    let forwarded = item.map(|r| write_response_to_json(&r));
                    if out_tx.send(forwarded).await.is_err() {
                        break;
                    }
                }
            });
            tokio::spawn(write_stream(ctx, inbound, tx));
        }
    }
}

fn bad_json(e: &JsonError) -> Status {
    Status::invalid_argument(e.to_string())
}

fn bad_request(message: &str) -> ChannelResponse {
    ChannelResponse::Full {
        status: 400,
        headers: vec![("content-type", "text/plain; charset=utf-8".to_owned())],
        body: message.to_owned(),
    }
}

fn unknown_session() -> ChannelResponse {
    // The client re-handshakes on 400 with an unknown SID.
    ChannelResponse::Full {
        status: 400,
        headers: vec![("content-type", "text/plain; charset=utf-8".to_owned())],
        body: "Unknown SID".to_owned(),
    }
}

fn error_chunk(e: &Status) -> ChannelResponse {
    let envelope = error_response(e);
    ChannelResponse::Full {
        status: envelope.status,
        headers: vec![("content-type", "application/json; charset=utf-8".to_owned())],
        body: envelope.body.to_string(),
    }
}

/// Small adapter: map the items of a `ReceiverStream`.
trait MapItems: Sized {
    fn map_items<F, U>(self, f: F) -> MappedStream<Self, F>
    where
        F: FnMut(Result<Value, Status>) -> U;
}

impl MapItems for ReceiverStream<Result<Value, Status>> {
    fn map_items<F, U>(self, f: F) -> MappedStream<Self, F>
    where
        F: FnMut(Result<Value, Status>) -> U,
    {
        MappedStream { inner: self, f }
    }
}

/// A `ReceiverStream` with a mapping function (kept local to avoid a `futures` dependency).
pub struct MappedStream<S, F> {
    inner: S,
    f: F,
}

impl<S, F, U> tokio_stream::Stream for MappedStream<S, F>
where
    S: tokio_stream::Stream<Item = Result<Value, Status>> + Unpin,
    F: FnMut(Result<Value, Status>) -> U + Unpin,
{
    type Item = U;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        let this = &mut *self;
        match std::pin::Pin::new(&mut this.inner).poll_next(cx) {
            std::task::Poll::Ready(Some(item)) => std::task::Poll::Ready(Some((this.f)(item))),
            std::task::Poll::Ready(None) => std::task::Poll::Ready(None),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}
