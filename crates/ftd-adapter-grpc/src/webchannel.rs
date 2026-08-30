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
    /// Target project named by the opening request, for classifying a replacement token.
    project: String,
    /// The app this channel was admitted for (specification section 13.1). `None` when
    /// nothing binds it: the service is `off` or `unenforced`, or the opening request
    /// presented a privileged credential instead of an App Check token.
    app_check: Option<ChannelApp>,
    /// The stream ended (error already queued) or the session was closed.
    closed: AtomicBool,
}

/// What a `WebChannel` is bound to once it has been admitted.
///
/// The channel outlives its opening request, and later envelopes may present a replacement
/// token, so the admitted app and the session epoch of that admission are kept for the
/// channel's life. A replacement for another app — or one minted under another epoch —
/// closes the channel instead of taking it over.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ChannelApp {
    app_id: String,
    epoch: ftd_core_app_check::registry::ProjectEpoch,
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

    /// Ends the session: the stream task sees EOF; the attached back channel delivers what
    /// is still queued (a stream error, typically) and then exits.
    fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        if let Ok(mut inbound) = self.inbound.lock() {
            inbound.take();
        }
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
    /// Every real `X-Firebase-AppCheck` HTTP field instance, in wire order. A browser sends
    /// the token in the init header block instead; both sources are collected so that
    /// presenting it twice stays ambiguous rather than becoming a value someone chooses.
    pub app_check: Vec<String>,
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

/// Header block `Name:Value\r\n...` (the `headers=` / `$httpHeaders` encoding), in wire
/// order with duplicates kept: the App Check contract of section 7.3 must be able to refuse
/// two instances, which a map would silently collapse into one.
fn parse_header_block(block: &str) -> Vec<(String, String)> {
    block
        .split("\r\n")
        .filter_map(|line| line.split_once(':'))
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_owned()))
        .collect()
}

/// The init header block of one channel request: the handshake carries it in the `headers=`
/// form field, later requests in the `$httpHeaders` query parameter.
fn init_headers(req: &ChannelRequest, form: &BTreeMap<String, String>) -> Vec<(String, String)> {
    let mut fields = Vec::new();
    if let Some(block) = form.get("headers") {
        fields.extend(parse_header_block(block));
    }
    if let Some(block) = req.params.get("$httpHeaders") {
        fields.extend(parse_header_block(block));
    }
    fields
}

/// The last value of a field of the init block (the browser sends each at most once).
fn init_header<'a>(fields: &'a [(String, String)], name: &str) -> Option<&'a str> {
    fields
        .iter()
        .rev()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
}

/// Every App Check field value a channel request presented, from both sources, in wire order.
fn app_check_values(req: &ChannelRequest, fields: &[(String, String)]) -> Vec<String> {
    let mut values: Vec<String> = fields
        .iter()
        .filter(|(k, _)| ftd_core_app_check::header::is_app_check_header(k))
        .map(|(_, v)| v.clone())
        .collect();
    values.extend(req.app_check.iter().cloned());
    values
}

/// The privileged credential a channel request presented, if any (specification section 12.2).
///
/// As on unary Firestore, the owner credential is verified here rather than read off the
/// principal, because the principal is `Owner` for everyone while Security Rules are disabled.
fn channel_bypass(authorization: Option<&str>) -> ftd_core_app_check::admission::PrivilegedBypass {
    if crate::rules::is_owner_credential(authorization) {
        ftd_core_app_check::admission::PrivilegedBypass::FirestoreOwner
    } else {
        ftd_core_app_check::admission::PrivilegedBypass::None
    }
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

    /// Admits an opening channel request and returns what the channel is bound to.
    ///
    /// A denial answers with the channel's error chunk, which is how the browser SDK learns
    /// that the channel will not open (specification section 17: HTTP 403 with the Google JSON
    /// `PERMISSION_DENIED` envelope). Only an `enforced` policy binds: under `unenforced` no
    /// request is ever denied, so binding would enforce by the back door.
    fn admit_channel(
        &self,
        project: &str,
        values: &[String],
        authorization: Option<&str>,
    ) -> Result<Option<ChannelApp>, ChannelResponse> {
        let Some(policy) = &self.state.app_check else {
            return Ok(None);
        };
        let header = ftd_core_app_check::header::classify_app_check_header(values);
        let (decision, epoch) =
            policy.admit_bound(&ftd_core_app_check::admission::AdmissionRequest {
                project_id: project,
                transport: "webchannel",
                operation: "channel.open",
                bypass: channel_bypass(authorization),
                header: &header,
                now: self.state.local.now(),
            });
        if let Some(reason) = decision.reason {
            return Err(error_chunk(&crate::service::app_check_denied(reason)));
        }
        Ok(match (decision.mode, decision.identity(), epoch) {
            (ftd_core_app_check::verify::BaselineMode::Enforced, Some(identity), Some(epoch)) => {
                Some(ChannelApp {
                    app_id: identity.app_id.clone(),
                    epoch,
                })
            }
            _ => None,
        })
    }

    /// Checks a replacement token presented on a later envelope of a bound channel.
    ///
    /// Later envelopes may omit the field entirely and keep the channel's admission — the
    /// token's expiry does not end an admitted channel. A presented replacement, though, must
    /// be valid for the same app and the current session epoch; a different app or an invalid
    /// replacement closes the channel rather than taking it over (section 13.1).
    fn check_replacement(
        &self,
        req: &ChannelRequest,
        session: &Arc<Session>,
        form: &BTreeMap<String, String>,
    ) -> Result<(), ChannelResponse> {
        let (Some(policy), Some(bound)) = (&self.state.app_check, session.app_check.as_ref())
        else {
            return Ok(());
        };
        let values = app_check_values(req, &init_headers(req, form));
        if values.is_empty() {
            return Ok(());
        }
        let header = ftd_core_app_check::header::classify_app_check_header(&values);
        let (decision, epoch) =
            policy.admit_bound(&ftd_core_app_check::admission::AdmissionRequest {
                project_id: &session.project,
                transport: "webchannel",
                operation: "channel.replacement",
                bypass: ftd_core_app_check::admission::PrivilegedBypass::None,
                header: &header,
                now: self.state.local.now(),
            });
        let replacement = decision.identity().map(|identity| ChannelApp {
            app_id: identity.app_id.clone(),
            epoch: epoch.unwrap_or(bound.epoch),
        });
        if replacement.as_ref() == Some(bound) {
            return Ok(());
        }
        let reason = decision
            .reason
            .unwrap_or(ftd_core_app_check::verify::PUBLIC_DENIAL_REASON);
        self.remove(&session.sid);
        Err(error_chunk(&crate::service::app_check_denied(reason)))
    }

    fn handshake(&self, req: &ChannelRequest) -> ChannelResponse {
        let form = parse_form(&req.body);
        // Init headers travel in the body (`headers=`) or the query (`$httpHeaders`).
        let headers = init_headers(req, &form);
        let authorization = init_header(&headers, "authorization")
            .map(str::to_owned)
            .or_else(|| req.authorization.clone());
        // App Check classifies the opening request once, before the Firebase Auth credential
        // and before any stream task exists (specification sections 7.4 and 13.1). The
        // project comes from the `database` parameter of the opening request; the stream
        // itself is admitted again against the database its first message names, so a channel
        // opened under one project cannot drive another.
        let values = app_check_values(req, &headers);
        let project = crate::service::project_of_resource(
            req.params.get("database").map_or("", String::as_str),
        )
        .to_owned();
        let bound = match self.admit_channel(&project, &values, authorization.as_deref()) {
            Ok(bound) => bound,
            Err(response) => return response,
        };
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
            project: project.clone(),
            app_check: bound,
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
            authorization: authorization.clone(),
            epoch: self.state.local.epoch(),
            app_check: self.state.app_check.as_ref().map(|policy| {
                crate::streams::StreamAdmission::new(
                    policy.clone(),
                    &values,
                    channel_bypass(authorization.as_deref()),
                    "webchannel",
                )
            }),
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
        let form = parse_form(&req.body);
        if let Err(response) = self.check_replacement(req, &session, &form) {
            return response;
        }
        if let Some(aid) = req.params.get("AID").and_then(|a| a.parse::<u64>().ok()) {
            if let Err(e) = session.acknowledge(aid) {
                return error_chunk(&e);
            }
        }
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
        // The back channel is a GET: its init headers ride in `$httpHeaders`, so a
        // replacement token can arrive here too.
        if let Err(response) = self.check_replacement(req, &session, &BTreeMap::new()) {
            return response;
        }
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
