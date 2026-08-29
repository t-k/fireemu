//! `WebChannel` transport for the `Listen` and `Write` streams, as used by the Firebase web SDK
//! in browsers (`/google.firestore.v1.Firestore/{Listen,Write}/channel`).
//!
//! Protocol (closure `WebChannelBase`, version 8, `sendRawJson`, `encodeInitMessageHeaders`):
//!
//! - handshake: `POST ...?database=...&VER=8&RID=<n>&CVER=22&X-HTTP-Session-Id=gsessionid`
//!   with body `headers=<url-encoded "Name:Value\r\n">&count=1&ofs=0&req0___data__=<json>`;
//!   the response carries `X-HTTP-Session-Id` and the chunk `[[0,["c","<sid>","",8,12,30000]]]`;
//! - forward channel: `POST ...?SID=<sid>&RID=<n>&AID=<acked>` with more `reqN___data__`
//!   maps (delivered in map-id order, retries and reordering tolerated); the response is
//!   `[<backchannel present>,<last array id>,0]`;
//! - back channel: `GET ...?SID=<sid>&RID=rpc&AID=<acked>&CI=0&TYPE=xmlhttp` streams
//!   `<len>\n[[<array id>,[<message json>]]]` chunks until the client reconnects;
//!   `CI=1` (long polling, `TO` ms) closes the response after the first batch or a `noop`;
//! - `TYPE=terminate` ends the session.
//!
//! Chunk lengths count UTF-16 code units (the browser slices JavaScript strings). Stream
//! errors are delivered as `[{"error": {...}}]` payloads (the shape the SDK unwraps).
//!
//! Sessions are bound to the origin and stream kind they were opened with, identified by
//! 128 random bits, capped in number and queue size, and closed (tasks ended) on terminate,
//! idle purge or overflow. Only loopback origins may open a channel: the endpoint carries
//! credentials (init headers) and must not be reachable from arbitrary web pages.

// `tonic::Status` is the error type shared with the gRPC surface.
#![allow(clippy::result_large_err)]

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::hash::{BuildHasher, Hasher};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
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

/// Sessions without an attached back channel and without requests longer than this are
/// closed.
const SESSION_IDLE_TTL: Duration = Duration::from_secs(120);
/// Default long-polling wait (`TO` overrides it, bounded).
const LONG_POLL_WAIT: Duration = Duration::from_secs(30);
/// Upper bound on `TO`.
const LONG_POLL_MAX: Duration = Duration::from_secs(60);
/// Streaming back channels send a keep-alive after this much silence.
const KEEPALIVE: Duration = Duration::from_secs(30);
/// Maximum accepted form body.
pub const MAX_FORM_BYTES: usize = 10 * 1024 * 1024;
/// Maximum concurrent sessions.
pub const MAX_SESSIONS: usize = 256;
/// Maximum unacknowledged arrays per session before it is closed.
pub const MAX_QUEUED_ARRAYS: usize = 4096;
/// Maximum maps per forward request and maximum gap of buffered map ids.
const MAX_MAPS_PER_REQUEST: u64 = 1000;

fn trace_enabled() -> bool {
    static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ENABLED.get_or_init(|| std::env::var_os("FTD_TRACE_WEBCHANNEL").is_some())
}

/// Redacted tracing: identifiers, counts and sizes only (never headers or message bodies).
fn trace(what: &str, detail: &str) {
    if trace_enabled() {
        eprintln!("[webchannel] {what}: {detail}");
    }
}

/// 128 random bits (system-keyed hashing of a counter; not derived from the deterministic
/// runtime seed, so session ids are not guessable across runs).
fn random_sid() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(1);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let state = std::collections::hash_map::RandomState::new();
    let mut a = state.build_hasher();
    a.write_u64(n);
    a.write_u64(0xA5A5);
    let mut b = state.build_hasher();
    b.write_u64(n ^ 0x5A5A_5A5A);
    b.write_u64(u64::from(std::process::id()));
    format!("{:016x}{:016x}", a.finish(), b.finish())
}

/// Whether a browser `Origin` names this machine (loopback).
#[must_use]
pub fn origin_is_local(origin: &str) -> bool {
    let rest = origin
        .strip_prefix("http://")
        .or_else(|| origin.strip_prefix("https://"));
    let Some(rest) = rest else { return false };
    let host = rest.strip_prefix('[').map_or_else(
        || rest.split(':').next().unwrap_or(""),
        |v6| v6.split(']').next().unwrap_or(""),
    );
    matches!(host, "localhost" | "127.0.0.1" | "::1")
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
    /// Origin the session was opened from (`None` for non-browser clients).
    origin: Option<String>,
    /// Inbound side of the stream; taken (dropped) when the session closes so the stream
    /// task ends.
    inbound: Mutex<Option<mpsc::Sender<Result<Value, Status>>>>,
    /// Arrays produced by the stream, not yet acknowledged: `(array id, json text)`.
    outbound: Mutex<VecDeque<(u64, String)>>,
    next_aid: AtomicU64,
    /// Bumped whenever a back channel attaches; older back channels stop.
    backchannel_generation: AtomicU64,
    backchannel_attached: AtomicBool,
    /// Data arrived (permit-keeping wakeup) / channel replaced (broadcast wakeup).
    notify: Notify,
    last_seen: Mutex<Instant>,
    /// Forward-channel maps: next expected id and out-of-order buffer.
    maps: Mutex<(u64, BTreeMap<u64, String>)>,
    /// The stream ended (error already queued) or the session was closed.
    closed: AtomicBool,
}

impl Session {
    fn push(&self, payload: &Value) -> Result<u64, ()> {
        let aid = self.next_aid.fetch_add(1, Ordering::SeqCst) + 1;
        let text = json!([aid, payload]).to_string();
        trace(
            "array",
            &format!("{} aid={aid} bytes={}", self.sid, text.len()),
        );
        let overflow = match self.outbound.lock() {
            Ok(mut q) => {
                q.push_back((aid, text));
                q.len() > MAX_QUEUED_ARRAYS
            }
            Err(_) => true,
        };
        self.touch();
        // `notify_one` keeps a permit when no back channel is waiting yet (no lost wakeups).
        self.notify.notify_one();
        if overflow {
            return Err(());
        }
        Ok(aid)
    }

    fn acknowledge(&self, aid: u64) -> Result<(), Status> {
        if aid > self.last_aid() {
            return Err(Status::invalid_argument(
                "AID acknowledges an array that was never sent",
            ));
        }
        if let Ok(mut q) = self.outbound.lock() {
            while q.front().is_some_and(|(id, _)| *id <= aid) {
                q.pop_front();
            }
        }
        Ok(())
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

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    /// Ends the session: the stream task sees EOF, waiters wake up and exit.
    fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        if let Ok(mut inbound) = self.inbound.lock() {
            inbound.take();
        }
        self.backchannel_generation.fetch_add(1, Ordering::SeqCst);
        self.notify.notify_waiters();
        self.notify.notify_one();
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
    /// `Origin` header.
    pub origin: Option<String>,
    /// Raw form body.
    pub body: String,
}

/// `<length>\n<text>` where the length counts UTF-16 code units (what the browser's string
/// slicing sees).
fn chunk(text: &str) -> String {
    format!("{}\n{}", text.encode_utf16().count(), text)
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

fn text_response(status: u16, body: String) -> ChannelResponse {
    ChannelResponse::Full {
        status,
        headers: vec![("content-type", "text/plain; charset=utf-8".to_owned())],
        body,
    }
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

    /// Closes and forgets sessions that are idle without a live back channel.
    fn purge_idle(&self) {
        let Ok(mut sessions) = self.sessions.lock() else {
            return;
        };
        let mut gone = Vec::new();
        sessions.retain(|sid, s| {
            let idle = s
                .last_seen
                .lock()
                .is_ok_and(|t| t.elapsed() >= SESSION_IDLE_TTL);
            let live = s.backchannel_attached.load(Ordering::SeqCst);
            let keep = (!idle || live) && !s.is_closed();
            if !keep {
                gone.push((sid.clone(), s.clone()));
            }
            keep
        });
        for (sid, s) in gone {
            trace("purge", &sid);
            s.close();
        }
    }

    fn session(&self, req: &ChannelRequest, sid: &str) -> Result<Arc<Session>, ChannelResponse> {
        let s = self
            .sessions
            .lock()
            .ok()
            .and_then(|m| m.get(sid).cloned())
            .filter(|s| !s.is_closed())
            .ok_or_else(unknown_session)?;
        // A session answers only the origin and stream kind that opened it.
        if s.kind != req.kind || s.origin != req.origin {
            return Err(unknown_session());
        }
        s.touch();
        Ok(s)
    }

    fn remove(&self, sid: &str) {
        let removed = self.sessions.lock().ok().and_then(|mut m| m.remove(sid));
        if let Some(s) = removed {
            s.close();
        }
    }

    /// Handles one HTTP request of the channel endpoint.
    pub fn handle(&self, req: &ChannelRequest) -> ChannelResponse {
        self.purge_idle();
        trace(
            "request",
            &format!(
                "{:?} {} params={:?} body_bytes={}",
                req.kind,
                req.method,
                req.params.keys().collect::<Vec<_>>(),
                req.body.len()
            ),
        );
        if let Some(origin) = &req.origin {
            if !origin_is_local(origin) {
                return text_response(403, "Forbidden origin".to_owned());
            }
        }
        let sid = req
            .params
            .get("SID")
            .cloned()
            .filter(|s| !s.is_empty() && s != "null");
        if req.params.get("TYPE").map(String::as_str) == Some("terminate") {
            // Sent as POST, or as a GET image request when the page unloads.
            if let Some(sid) = sid {
                if self.session(req, &sid).is_ok() {
                    self.remove(&sid);
                }
            }
            return text_response(200, String::new());
        }
        match (req.method.as_str(), sid) {
            ("POST", None) => self.handshake(req),
            ("POST", Some(sid)) => self.forward(req, &sid),
            ("GET", Some(sid)) => self.backchannel(req, &sid),
            _ => text_response(400, "unsupported channel request".to_owned()),
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
        let sid = random_sid();
        let (inbound_tx, inbound_rx) = mpsc::channel::<Result<Value, Status>>(64);
        let session = Arc::new(Session {
            sid: sid.clone(),
            kind: req.kind,
            origin: req.origin.clone(),
            inbound: Mutex::new(Some(inbound_tx)),
            outbound: Mutex::new(VecDeque::new()),
            next_aid: AtomicU64::new(0),
            backchannel_generation: AtomicU64::new(0),
            backchannel_attached: AtomicBool::new(false),
            notify: Notify::new(),
            last_seen: Mutex::new(Instant::now()),
            maps: Mutex::new((0, BTreeMap::new())),
            closed: AtomicBool::new(false),
        });
        {
            let Ok(mut sessions) = self.sessions.lock() else {
                return text_response(500, "session registry poisoned".to_owned());
            };
            if sessions.len() >= MAX_SESSIONS {
                return text_response(503, "too many channel sessions".to_owned());
            }
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
            self.remove(&sid);
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
        let session = match self.session(req, sid) {
            Ok(s) => s,
            Err(r) => return r,
        };
        if let Some(aid) = req.params.get("AID").and_then(|a| a.parse::<u64>().ok()) {
            if let Err(e) = session.acknowledge(aid) {
                return error_chunk(&e);
            }
        }
        let form = parse_form(&req.body);
        if let Err(e) = session_deliver(&session, &form) {
            return error_chunk(&e);
        }
        let attached = u64::from(session.backchannel_attached.load(Ordering::SeqCst));
        let text = json!([attached, session.last_aid(), 0]).to_string();
        text_response(200, chunk(&text))
    }

    fn backchannel(&self, req: &ChannelRequest, sid: &str) -> ChannelResponse {
        let session = match self.session(req, sid) {
            Ok(s) => s,
            Err(r) => return r,
        };
        let acked = req
            .params
            .get("AID")
            .and_then(|a| a.parse::<u64>().ok())
            .unwrap_or(0);
        if let Err(e) = session.acknowledge(acked) {
            return error_chunk(&e);
        }
        let long_poll = req.params.get("CI").map(String::as_str) == Some("1");
        let wait = req
            .params
            .get("TO")
            .and_then(|t| t.parse::<u64>().ok())
            .map_or(LONG_POLL_WAIT, Duration::from_millis)
            .clamp(Duration::from_secs(1), LONG_POLL_MAX);
        let generation = session
            .backchannel_generation
            .fetch_add(1, Ordering::SeqCst)
            + 1;
        session.backchannel_attached.store(true, Ordering::SeqCst);
        // Wake a previous back channel so it notices it was replaced.
        session.notify.notify_waiters();
        let (tx, rx) = mpsc::channel::<Result<bytes::Bytes, Status>>(64);
        tokio::spawn(async move {
            let mut cursor = acked;
            let outcome =
                backchannel_loop(&session, generation, long_poll, wait, &tx, &mut cursor).await;
            if session.backchannel_generation.load(Ordering::SeqCst) == generation {
                session.backchannel_attached.store(false, Ordering::SeqCst);
                session.touch();
            }
            trace(
                "backchannel end",
                &format!("{} gen={generation} {outcome}", session.sid),
            );
        });
        ChannelResponse::Stream {
            headers: vec![("content-type", "text/plain; charset=utf-8".to_owned())],
            body: ReceiverStream::new(rx),
        }
    }
}

/// Serves one back channel until the client goes away, the session closes, a newer back
/// channel takes over, or (long polling) one batch was delivered.
async fn backchannel_loop(
    session: &Session,
    generation: u64,
    long_poll: bool,
    wait: Duration,
    tx: &mpsc::Sender<Result<bytes::Bytes, Status>>,
    cursor: &mut u64,
) -> &'static str {
    loop {
        let pending = session.pending_after(*cursor);
        if let Some((last, _)) = pending.last() {
            let texts: Vec<&str> = pending.iter().map(|(_, t)| t.as_str()).collect();
            let text = format!("[{}]", texts.join(","));
            trace(
                "backchannel send",
                &format!("{} gen={generation} arrays={}", session.sid, pending.len()),
            );
            if tx.send(Ok(bytes::Bytes::from(chunk(&text)))).await.is_err() {
                return "receiver gone";
            }
            // The cursor is the last id actually sent; arrays pushed meanwhile are picked
            // up by the next iteration.
            *cursor = *last;
            if long_poll {
                return "long poll batch";
            }
        }
        if session.is_closed() && pending.is_empty() {
            return "session closed";
        }
        let idle = if long_poll { wait } else { KEEPALIVE };
        let waited = tokio::time::timeout(idle, session.notify.notified()).await;
        if session.backchannel_generation.load(Ordering::SeqCst) != generation {
            // Hand a possibly consumed data permit to the newer back channel.
            session.notify.notify_one();
            return "superseded";
        }
        if waited.is_err() {
            // Silence: a framed keep-alive (a completed request with no bytes would be
            // treated as an error by the client).
            let noop = json!([[session.last_aid(), ["noop"]]]).to_string();
            if tx.send(Ok(bytes::Bytes::from(chunk(&noop)))).await.is_err() {
                return "receiver gone";
            }
            if long_poll {
                return "long poll timeout";
            }
        }
    }
}

/// Delivers the `reqN___data__` maps of a form body to the session's stream in map-id
/// order: retries are ignored, out-of-order maps are buffered, and the cursor advances only
/// after a map was parsed and enqueued.
fn session_deliver(session: &Session, form: &BTreeMap<String, String>) -> Result<(), Status> {
    let count: u64 = form.get("count").and_then(|c| c.parse().ok()).unwrap_or(0);
    let ofs: u64 = form.get("ofs").and_then(|c| c.parse().ok()).unwrap_or(0);
    if count > MAX_MAPS_PER_REQUEST {
        return Err(Status::invalid_argument("too many maps in one request"));
    }
    let mut maps = session
        .maps
        .lock()
        .map_err(|_| Status::internal("session lock poisoned"))?;
    for n in 0..count {
        let map_id = ofs.saturating_add(n);
        let Some(raw) = form.get(&format!("req{n}___data__")) else {
            continue;
        };
        if map_id < maps.0 || maps.1.contains_key(&map_id) {
            continue; // retried map
        }
        if map_id.saturating_sub(maps.0) > MAX_MAPS_PER_REQUEST {
            return Err(Status::invalid_argument(
                "forward channel map id too far ahead",
            ));
        }
        maps.1.insert(map_id, raw.clone());
    }
    // Drain the contiguous prefix.
    while let Some(raw) = maps.1.get(&maps.0).cloned() {
        let value: Value = serde_json::from_str(&raw)
            .map_err(|e| Status::invalid_argument(format!("invalid message JSON: {e}")))?;
        let inbound = session
            .inbound
            .lock()
            .map_err(|_| Status::internal("session lock poisoned"))?;
        let Some(sender) = inbound.as_ref() else {
            return Err(Status::unavailable("the stream has ended"));
        };
        sender
            .try_send(Ok(value))
            .map_err(|_| Status::unavailable("stream is not accepting messages"))?;
        drop(inbound);
        let done = maps.0;
        maps.1.remove(&done);
        maps.0 = done + 1;
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
            let pushed = match item {
                Ok(v) => pump_session.push(&json!([v])),
                Err(e) => {
                    let envelope = error_response(&e).body;
                    let _ = pump_session.push(&json!([envelope]));
                    break;
                }
            };
            if pushed.is_err() {
                trace("overflow", &pump_session.sid);
                break;
            }
        }
        pump_session.close();
    });
    match kind {
        StreamKind::Listen => {
            let inbound = MappedStream {
                inner: ReceiverStream::new(inbound_rx),
                f: |r: Result<Value, Status>| {
                    r.and_then(|v| listen_request_from_json(&v).map_err(|e| bad_json(&e)))
                },
            };
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
            let inbound = MappedStream {
                inner: ReceiverStream::new(inbound_rx),
                f: |r: Result<Value, Status>| {
                    r.and_then(|v| write_request_from_json(&v).map_err(|e| bad_json(&e)))
                },
            };
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

fn unknown_session() -> ChannelResponse {
    // The client classifies this body as an unknown session and re-handshakes.
    text_response(400, "Error: Unknown SID".to_owned())
}

fn error_chunk(e: &Status) -> ChannelResponse {
    let envelope = error_response(e);
    ChannelResponse::Full {
        status: envelope.status,
        headers: vec![("content-type", "application/json; charset=utf-8".to_owned())],
        body: envelope.body.to_string(),
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
