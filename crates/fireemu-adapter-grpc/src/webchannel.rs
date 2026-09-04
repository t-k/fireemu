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
use std::io::Write as _;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{sync_channel, SyncSender, TrySendError};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

pub use fireemu_core_session::loopback::origin_is_local;
use fireemu_proto_firestore::google::firestore::v1 as pb;
use serde_json::{json, Value};
use tokio::sync::{mpsc, oneshot, Notify};
use tokio_stream::wrappers::ReceiverStream;
use tonic::Status;

use crate::rest::json::{
    listen_request_from_json, listen_response_to_json, write_request_from_json,
    write_response_to_json, JsonError,
};
use crate::rest::{error_response, RestState};
use crate::streams::{listen_stream_observed, write_stream, ListenObserver, StreamContext};

/// Sessions without an attached back channel and without requests longer than this are
/// closed.
const SESSION_IDLE_TTL: Duration = Duration::from_secs(120);
/// A terminal array cannot retain an abandoned session indefinitely.
const TERMINAL_DELIVERY_TTL: Duration = Duration::from_secs(120);
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
/// Maximum completed target lifetimes retained solely for diagnostics.
const MAX_TRACE_COMPLETED_TARGETS: usize = 256;
/// Maximum diagnostic events emitted by one admitted channel session.
const MAX_TRACE_EVENTS_PER_SESSION: u64 = 4096;
/// Diagnostic messages wait in a bounded queue and are dropped rather than blocking protocol work.
const TRACE_QUEUE_CAPACITY: usize = 1024;
/// Process-wide trace budget for each fixed one-second interval. Crossing an interval boundary
/// can burst at most twice this count; the bounded sink still drops excess queued events.
const MAX_TRACE_EVENTS_PER_SECOND: u64 = 2048;

fn trace_enabled() -> bool {
    static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ENABLED.get_or_init(|| std::env::var_os("FIREEMU_TRACE_WEBCHANNEL").is_some())
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TraceEvent {
    RequestReceived {
        session: u64,
        kind: StreamKind,
        method: &'static str,
        rid: TraceRid,
        aid: Option<u64>,
        ci: Option<u64>,
        body_bytes: usize,
    },
    SessionOpened {
        session: u64,
        kind: StreamKind,
    },
    SessionPurged {
        session: u64,
    },
    ArrayGenerated {
        session: u64,
        aid: u64,
        bytes: usize,
        queued_first: Option<u64>,
        queued_last: Option<u64>,
        queued_count: usize,
    },
    ArrayAcknowledged {
        session: u64,
        aid: u64,
        queued_first: Option<u64>,
        queued_last: Option<u64>,
        queued_count: usize,
    },
    BackchannelStarted {
        session: u64,
        generation: u64,
        rid: TraceRid,
        client_aid: u64,
        long_poll: bool,
    },
    BackchannelQueued {
        session: u64,
        generation: u64,
        first_aid: u64,
        last_aid: u64,
        count: usize,
    },
    BackchannelCommitted {
        session: u64,
        generation: u64,
        last_aid: u64,
    },
    BackchannelEnded {
        session: u64,
        generation: u64,
        outcome: &'static str,
    },
    ForwardMaps {
        session: u64,
        offset: u64,
        declared: u64,
        accepted: usize,
        duplicates: usize,
        buffered: usize,
        next_expected: u64,
    },
    Overflow {
        session: u64,
    },
    SessionTraceLimitReached {
        session: u64,
    },
    ListenRequest {
        session: u64,
        action: &'static str,
        target: i32,
        lifetime: Option<u64>,
    },
    ListenResponse {
        session: u64,
        kind: &'static str,
        targets: Vec<(i32, Option<u64>)>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TraceRid {
    Missing,
    Rpc,
    Numeric(u64),
    Other,
}

fn format_optional_range(first: Option<u64>, last: Option<u64>) -> String {
    match (first, last) {
        (Some(first), Some(last)) => format!("{first}..{last}"),
        _ => "none".to_owned(),
    }
}

fn format_rid(rid: TraceRid) -> String {
    match rid {
        TraceRid::Missing => "missing".to_owned(),
        TraceRid::Rpc => "rpc".to_owned(),
        TraceRid::Numeric(value) => value.to_string(),
        TraceRid::Other => "other".to_owned(),
    }
}

fn format_targets(targets: &[(i32, Option<u64>)]) -> String {
    if targets.is_empty() {
        return "all".to_owned();
    }
    targets
        .iter()
        .map(|(target, lifetime)| match lifetime {
            Some(lifetime) => format!("{target}@{lifetime}"),
            None => format!("{target}@unknown"),
        })
        .collect::<Vec<_>>()
        .join(",")
}

#[allow(clippy::too_many_lines)]
fn format_trace_event(event: &TraceEvent) -> String {
    match event {
        TraceEvent::RequestReceived {
            session,
            kind,
            method,
            rid,
            aid,
            ci,
            body_bytes,
        } => format!(
            "session={session} request kind={kind:?} method={method} rid={} aid={} ci={} body_bytes={body_bytes}",
            format_rid(*rid),
            aid.map_or_else(|| "missing".to_owned(), |value| value.to_string()),
            ci.map_or_else(|| "missing".to_owned(), |value| value.to_string())
        ),
        TraceEvent::SessionOpened { session, kind } => {
            format!("session={session} opened kind={kind:?}")
        }
        TraceEvent::SessionPurged { session } => format!("session={session} purged"),
        TraceEvent::ArrayGenerated {
            session,
            aid,
            bytes,
            queued_first,
            queued_last,
            queued_count,
        } => format!(
            "session={session} array=generated aid={aid} bytes={bytes} queued={} queued_count={queued_count}",
            format_optional_range(*queued_first, *queued_last)
        ),
        TraceEvent::ArrayAcknowledged {
            session,
            aid,
            queued_first,
            queued_last,
            queued_count,
        } => format!(
            "session={session} array=acknowledged aid={aid} queued={} queued_count={queued_count}",
            format_optional_range(*queued_first, *queued_last)
        ),
        TraceEvent::BackchannelStarted {
            session,
            generation,
            rid,
            client_aid,
            long_poll,
        } => format!(
            "session={session} backchannel=started generation={generation} rid={} client_aid={client_aid} long_poll={long_poll}",
            format_rid(*rid)
        ),
        TraceEvent::BackchannelQueued {
            session,
            generation,
            first_aid,
            last_aid,
            count,
        } => format!(
            "session={session} backchannel=queued generation={generation} arrays={first_aid}..{last_aid} count={count}"
        ),
        TraceEvent::BackchannelCommitted {
            session,
            generation,
            last_aid,
        } => format!(
            "session={session} backchannel=committed generation={generation} last_aid={last_aid}"
        ),
        TraceEvent::BackchannelEnded {
            session,
            generation,
            outcome,
        } => format!(
            "session={session} backchannel=ended generation={generation} outcome={outcome}"
        ),
        TraceEvent::ForwardMaps {
            session,
            offset,
            declared,
            accepted,
            duplicates,
            buffered,
            next_expected,
        } => format!(
            "session={session} maps offset={offset} declared={declared} accepted={accepted} duplicates={duplicates} buffered={buffered} next_expected={next_expected}"
        ),
        TraceEvent::Overflow { session } => format!("session={session} overflow"),
        TraceEvent::SessionTraceLimitReached { session } => {
            format!("session={session} trace=limit-reached")
        }
        TraceEvent::ListenRequest {
            session,
            action,
            target,
            lifetime,
        } => format!(
            "session={session} listen=request action={action} target={target}@{}",
            lifetime.map_or_else(|| "unknown".to_owned(), |value| value.to_string())
        ),
        TraceEvent::ListenResponse {
            session,
            kind,
            targets,
        } => format!(
            "session={session} listen=response kind={kind} targets={}",
            format_targets(targets)
        ),
    }
}

fn trace_sender() -> Option<&'static SyncSender<String>> {
    static SENDER: OnceLock<SyncSender<String>> = OnceLock::new();
    if !trace_enabled() {
        return None;
    }
    Some(SENDER.get_or_init(|| {
        let (sender, receiver) = sync_channel::<String>(TRACE_QUEUE_CAPACITY);
        let _ = std::thread::Builder::new()
            .name("webchannel-trace".to_owned())
            .spawn(move || {
                while let Ok(line) = receiver.recv() {
                    let stderr = std::io::stderr();
                    let mut stderr = stderr.lock();
                    let _ = writeln!(stderr, "[webchannel] {line}");
                }
            });
        sender
    }))
}

struct TraceRateLimiter {
    window_started: Instant,
    emitted: u64,
}

impl TraceRateLimiter {
    fn allow(&mut self, now: Instant) -> bool {
        if now.duration_since(self.window_started) >= Duration::from_secs(1) {
            self.window_started = now;
            self.emitted = 0;
        }
        if self.emitted >= MAX_TRACE_EVENTS_PER_SECOND {
            return false;
        }
        self.emitted += 1;
        true
    }
}

fn claim_global_trace_slot() -> bool {
    static LIMITER: OnceLock<Mutex<TraceRateLimiter>> = OnceLock::new();
    let limiter = LIMITER.get_or_init(|| {
        Mutex::new(TraceRateLimiter {
            window_started: Instant::now(),
            emitted: 0,
        })
    });
    limiter
        .try_lock()
        .is_ok_and(|mut limiter| limiter.allow(Instant::now()))
}

/// Redacted tracing: generated numeric identifiers, counts and sizes only. Formatting happens
/// after protocol locks are released, and a full or disconnected sink drops the event.
fn trace(event: &TraceEvent) {
    let Some(sender) = trace_sender() else { return };
    if !claim_global_trace_slot() {
        return;
    }
    match sender.try_send(format_trace_event(event)) {
        Ok(()) | Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => {}
    }
}

fn trace_rid(params: &BTreeMap<String, String>) -> TraceRid {
    match params.get("RID").map(String::as_str) {
        None => TraceRid::Missing,
        Some("rpc") => TraceRid::Rpc,
        Some(value) => value
            .parse::<u64>()
            .map_or(TraceRid::Other, TraceRid::Numeric),
    }
}

fn trace_request(session: &Session, request: &ChannelRequest) {
    let method = match request.method.as_str() {
        "GET" => "GET",
        "POST" => "POST",
        _ => "OTHER",
    };
    session.trace_event(&TraceEvent::RequestReceived {
        session: session.trace_id,
        kind: request.kind,
        method,
        rid: trace_rid(&request.params),
        aid: request
            .params
            .get("AID")
            .and_then(|value| value.parse().ok()),
        ci: request
            .params
            .get("CI")
            .and_then(|value| value.parse().ok()),
        body_bytes: request.body.len(),
    });
}

#[derive(Default)]
struct ListenTraceState {
    next_lifetime: u64,
    active: BTreeMap<i32, u64>,
    completed: BTreeMap<i32, u64>,
    completed_order: VecDeque<i32>,
}

impl ListenTraceState {
    fn request_add(&mut self, target: i32) -> u64 {
        self.next_lifetime = self.next_lifetime.saturating_add(1);
        let lifetime = self.next_lifetime;
        self.completed.remove(&target);
        self.completed_order
            .retain(|completed| *completed != target);
        self.active.insert(target, lifetime);
        lifetime
    }

    fn request_remove(&mut self, target: i32) -> Option<u64> {
        let lifetime = self.active.remove(&target)?;
        self.remember_completed(target, lifetime);
        Some(lifetime)
    }

    fn remember_completed(&mut self, target: i32, lifetime: u64) {
        self.completed.remove(&target);
        self.completed_order
            .retain(|completed| *completed != target);
        self.completed.insert(target, lifetime);
        self.completed_order.push_back(target);
        while self.completed_order.len() > MAX_TRACE_COMPLETED_TARGETS {
            if let Some(evicted) = self.completed_order.pop_front() {
                self.completed.remove(&evicted);
            }
        }
    }

    fn active_lifetime(&self, target: i32) -> Option<u64> {
        self.active.get(&target).copied()
    }

    fn latest_lifetime(&self, target: i32) -> Option<u64> {
        self.active_lifetime(target)
            .or_else(|| self.completed.get(&target).copied())
    }

    fn response_event(&mut self, session: u64, response: &pb::ListenResponse) -> TraceEvent {
        use pb::listen_response::ResponseType as Response;
        let (kind, mut target_ids) = match response.response_type.as_ref() {
            Some(Response::TargetChange(change)) => {
                let kind = pb::target_change::TargetChangeType::try_from(change.target_change_type)
                    .map_or("target_change_unknown", |kind| match kind {
                        pb::target_change::TargetChangeType::NoChange => "no_change",
                        pb::target_change::TargetChangeType::Add => "target_add",
                        pb::target_change::TargetChangeType::Remove => "target_remove",
                        pb::target_change::TargetChangeType::Current => "current",
                        pb::target_change::TargetChangeType::Reset => "reset",
                    });
                (kind, change.target_ids.clone())
            }
            Some(Response::DocumentChange(change)) => {
                let mut ids = change.target_ids.clone();
                ids.extend(change.removed_target_ids.iter().copied());
                ("document_change", ids)
            }
            Some(Response::DocumentDelete(change)) => {
                ("document_delete", change.removed_target_ids.clone())
            }
            Some(Response::DocumentRemove(change)) => {
                ("document_remove", change.removed_target_ids.clone())
            }
            Some(Response::Filter(filter)) => ("filter", vec![filter.target_id]),
            None => ("empty", Vec::new()),
        };
        target_ids.sort_unstable();
        target_ids.dedup();
        let targets = target_ids
            .iter()
            .map(|target| (*target, self.latest_lifetime(*target)))
            .collect();
        if kind == "target_remove" {
            for target in target_ids {
                let _ = self.request_remove(target);
            }
        }
        TraceEvent::ListenResponse {
            session,
            kind,
            targets,
        }
    }

    fn exchange_events(
        &mut self,
        session: u64,
        request: Option<&pb::ListenRequest>,
        responses: &[pb::ListenResponse],
        event_limit: usize,
    ) -> Vec<TraceEvent> {
        let mut events = Vec::with_capacity(responses.len().saturating_add(1).min(event_limit));
        if let Some(request) = request {
            match request.target_change.as_ref() {
                Some(pb::listen_request::TargetChange::AddTarget(target)) => {
                    let accepted = responses.iter().any(|response| {
                        matches!(
                            response.response_type.as_ref(),
                            Some(pb::listen_response::ResponseType::TargetChange(change))
                                if change.target_change_type
                                    == pb::target_change::TargetChangeType::Add as i32
                                    && change.target_ids.contains(&target.target_id)
                        )
                    });
                    let lifetime = accepted.then(|| self.request_add(target.target_id));
                    if events.len() < event_limit {
                        events.push(TraceEvent::ListenRequest {
                            session,
                            action: "add",
                            target: target.target_id,
                            lifetime,
                        });
                    }
                }
                Some(pb::listen_request::TargetChange::RemoveTarget(target)) => {
                    let lifetime = self.request_remove(*target);
                    if events.len() < event_limit {
                        events.push(TraceEvent::ListenRequest {
                            session,
                            action: "remove",
                            target: *target,
                            lifetime,
                        });
                    }
                }
                None => {}
            }
        }
        for response in responses {
            let event = self.response_event(session, response);
            if events.len() < event_limit {
                events.push(event);
            }
        }
        events
    }
}

struct WebchannelListenObserver {
    session: Arc<Session>,
    state: Mutex<ListenTraceState>,
}

impl ListenObserver for WebchannelListenObserver {
    fn exchange(&self, request: Option<&pb::ListenRequest>, responses: &[pb::ListenResponse]) {
        let event_limit = self.session.trace_event_capacity();
        if event_limit == 0 {
            return;
        }
        let events = match self.state.lock() {
            Ok(mut state) => {
                state.exchange_events(self.session.trace_id, request, responses, event_limit)
            }
            Err(_) => return,
        };
        for event in events {
            self.session.trace_event(&event);
        }
    }
}

/// 128 bits from the operating system CSPRNG.
///
/// A channel id was always unguessable-by-construction, but since App Check admits a channel
/// once and later envelopes ride on that admission (specification section 13.1), knowing one
/// *is* the capability to use an admitted channel. It is drawn from the same source as the
/// control token, the runner secret and the project epochs rather than from keyed hashing of a
/// counter. A failed draw falls back to that keyed hashing rather than to anything predictable:
/// refusing to open channels because `/dev/urandom` is unreadable would be worse, and the
/// fallback is exactly the previous behaviour.
fn random_sid() -> String {
    use std::fmt::Write as _;
    use std::io::Read as _;
    let mut bytes = [0u8; 16];
    if std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut bytes))
        .is_ok()
    {
        let mut out = String::with_capacity(32);
        for byte in bytes {
            let _ = write!(out, "{byte:02x}");
        }
        return out;
    }
    keyed_sid()
}

/// The fallback of [`random_sid`]: system-keyed hashing of a counter, not derived from the
/// deterministic runtime seed.
fn keyed_sid() -> String {
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

fn next_trace_session_id() -> u64 {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
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
        /// Chunks and the ownership lease for this HTTP response.
        body: BackchannelBody,
    },
}

type SessionRegistry = Mutex<HashMap<String, Arc<Session>>>;

struct Session {
    sid: String,
    /// Process-local diagnostic identifier. Unlike `sid`, this is not a channel capability.
    trace_id: u64,
    /// Per-session diagnostic budget. Protocol work continues after this counter is exhausted.
    trace_events: AtomicU64,
    kind: StreamKind,
    /// Origin the session was opened from (`None` for non-browser clients).
    origin: Option<String>,
    /// Inbound side of the stream; taken (dropped) when the session closes so the stream
    /// task ends.
    inbound: Mutex<Option<mpsc::Sender<Result<Value, Status>>>>,
    /// Arrays produced by the stream, not yet acknowledged: `(array id, json text)`.
    delivery: Mutex<DeliveryState>,
    /// The response allowed to commit the next chunk. Replacement and the final generation
    /// check before enqueue share this lock, so a superseded response cannot win between a
    /// generation check and delivery.
    backchannel_owner: Mutex<BackchannelOwner>,
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
    /// Weak access lets the terminal deadline remove only this exact session registration.
    registry: std::sync::Weak<SessionRegistry>,
    /// The transport is no longer available for any request.
    terminated: AtomicBool,
}

#[derive(Debug, Clone, Copy)]
struct StreamEnd {
    ended_at: Instant,
    terminal_aid: u64,
}

#[derive(Debug, Default)]
struct DeliveryState {
    outbound: VecDeque<(u64, String)>,
    next_aid: u64,
    committed_aid: u64,
    acknowledged_aid: u64,
    stream_end: Option<StreamEnd>,
    terminal_expiry_cancel: Option<oneshot::Sender<()>>,
    terminal_expiry_tasks: Arc<AtomicUsize>,
}

struct BackchannelOwner {
    generation: u64,
    cancel: Option<oneshot::Sender<()>>,
}

/// A back-channel HTTP body that retains ownership until the response reaches EOF or is dropped.
pub struct BackchannelBody {
    inner: ReceiverStream<Result<bytes::Bytes, Status>>,
    session: Arc<Session>,
    generation: u64,
    released: bool,
}

impl BackchannelBody {
    fn new(
        receiver: mpsc::Receiver<Result<bytes::Bytes, Status>>,
        session: Arc<Session>,
        generation: u64,
    ) -> Self {
        Self {
            inner: ReceiverStream::new(receiver),
            session,
            generation,
            released: false,
        }
    }

    fn release(&mut self) {
        if self.released {
            return;
        }
        self.released = true;
        if self.session.finish_backchannel(self.generation) {
            self.session.touch();
        }
    }
}

impl tokio_stream::Stream for BackchannelBody {
    type Item = Result<bytes::Bytes, Status>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        let next = std::pin::Pin::new(&mut self.inner).poll_next(cx);
        if matches!(&next, std::task::Poll::Ready(None)) {
            self.release();
        }
        next
    }
}

impl Drop for BackchannelBody {
    fn drop(&mut self) {
        self.release();
    }
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
    epoch: fireemu_core_app_check::registry::ProjectEpoch,
}

impl Session {
    fn trace_event_capacity(&self) -> usize {
        let emitted = self.trace_events.load(Ordering::Relaxed);
        let capacity = MAX_TRACE_EVENTS_PER_SESSION
            .saturating_sub(emitted)
            .saturating_add(u64::from(emitted <= MAX_TRACE_EVENTS_PER_SESSION));
        usize::try_from(capacity).unwrap_or(usize::MAX)
    }

    fn trace_event(&self, event: &TraceEvent) {
        if !trace_enabled() {
            return;
        }
        let slot =
            self.trace_events
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |emitted| {
                    (emitted <= MAX_TRACE_EVENTS_PER_SESSION).then_some(emitted + 1)
                });
        match slot {
            Ok(emitted) if emitted < MAX_TRACE_EVENTS_PER_SESSION => trace(event),
            Ok(_) => trace(&TraceEvent::SessionTraceLimitReached {
                session: self.trace_id,
            }),
            Err(_) => {}
        }
    }

    fn replace_backchannel(&self, cancel: oneshot::Sender<()>) -> Result<u64, ()> {
        let mut owner = self.backchannel_owner.lock().map_err(|_| ())?;
        if self.terminated.load(Ordering::SeqCst) {
            return Err(());
        }
        owner.generation = owner.generation.checked_add(1).ok_or(())?;
        if let Some(previous) = owner.cancel.replace(cancel) {
            let _ = previous.send(());
        }
        Ok(owner.generation)
    }

    fn finish_backchannel(&self, generation: u64) -> bool {
        let Ok(mut owner) = self.backchannel_owner.lock() else {
            return false;
        };
        if owner.generation != generation {
            return false;
        }
        owner.cancel.take();
        true
    }

    fn backchannel_attached(&self) -> bool {
        self.backchannel_owner
            .lock()
            .is_ok_and(|owner| owner.cancel.is_some())
    }

    fn push(&self, payload: &Value) -> Result<u64, ()> {
        let (aid, bytes, overflow, queued_first, queued_last, queued_count) = {
            let Ok(mut delivery) = self.delivery.lock() else {
                return Err(());
            };
            delivery.next_aid = delivery.next_aid.checked_add(1).ok_or(())?;
            let aid = delivery.next_aid;
            let text = json!([aid, payload]).to_string();
            let bytes = text.len();
            delivery.outbound.push_back((aid, text));
            (
                aid,
                bytes,
                delivery.outbound.len() > MAX_QUEUED_ARRAYS,
                delivery.outbound.front().map(|(id, _)| *id),
                delivery.outbound.back().map(|(id, _)| *id),
                delivery.outbound.len(),
            )
        };
        self.trace_event(&TraceEvent::ArrayGenerated {
            session: self.trace_id,
            aid,
            bytes,
            queued_first,
            queued_last,
            queued_count,
        });
        self.touch();
        // `notify_one` keeps a permit when no back channel is waiting yet (no lost wakeups).
        self.notify.notify_one();
        if overflow {
            return Err(());
        }
        Ok(aid)
    }

    fn acknowledge(&self, aid: u64) -> Result<(), Status> {
        let (
            queued_first,
            queued_last,
            queued_count,
            terminal_acknowledged,
            backchannel_cancelled,
            expiry_cancelled,
        ) = {
            let mut owner = self
                .backchannel_owner
                .lock()
                .map_err(|_| Status::internal("session lock poisoned"))?;
            let mut delivery = self
                .delivery
                .lock()
                .map_err(|_| Status::internal("session lock poisoned"))?;
            if aid > delivery.committed_aid {
                return Err(Status::invalid_argument(
                    "AID acknowledges an array that was not committed",
                ));
            }
            while delivery.outbound.front().is_some_and(|(id, _)| *id <= aid) {
                delivery.outbound.pop_front();
            }
            delivery.acknowledged_aid = delivery.acknowledged_aid.max(aid);
            let terminal_acknowledged = delivery
                .stream_end
                .is_some_and(|ended| delivery.acknowledged_aid >= ended.terminal_aid);
            let (backchannel_cancelled, expiry_cancelled) = if terminal_acknowledged {
                owner.generation = owner.generation.saturating_add(1);
                self.terminated.store(true, Ordering::SeqCst);
                delivery.outbound.clear();
                (owner.cancel.take(), delivery.terminal_expiry_cancel.take())
            } else {
                (None, None)
            };
            (
                delivery.outbound.front().map(|(id, _)| *id),
                delivery.outbound.back().map(|(id, _)| *id),
                delivery.outbound.len(),
                terminal_acknowledged,
                backchannel_cancelled,
                expiry_cancelled,
            )
        };
        self.trace_event(&TraceEvent::ArrayAcknowledged {
            session: self.trace_id,
            aid,
            queued_first,
            queued_last,
            queued_count,
        });
        if terminal_acknowledged {
            if let Some(cancel) = backchannel_cancelled {
                let _ = cancel.send(());
            }
            if let Some(cancel) = expiry_cancelled {
                let _ = cancel.send(());
            }
            if let Ok(mut inbound) = self.inbound.lock() {
                inbound.take();
            }
            if let Ok(mut maps) = self.maps.lock() {
                maps.1.clear();
            }
            self.notify.notify_waiters();
            self.notify.notify_one();
        }
        Ok(())
    }

    /// Serializes unacknowledged arrays after `aid` without cloning the retained strings.
    fn pending_chunk_after(&self, aid: u64) -> Option<(u64, usize, String)> {
        let delivery = self.delivery.lock().ok()?;
        let pending = delivery.outbound.iter().skip_while(|(id, _)| *id <= aid);
        let mut body = String::new();
        body.push('[');
        let mut last = None;
        let mut count = 0;
        for (id, text) in pending {
            if count != 0 {
                body.push(',');
            }
            body.push_str(text);
            last = Some(*id);
            count += 1;
        }
        body.push(']');
        last.map(|last| (last, count, body))
    }

    fn last_aid(&self) -> u64 {
        self.delivery.lock().map_or(0, |delivery| delivery.next_aid)
    }

    fn touch(&self) {
        if let Ok(mut t) = self.last_seen.lock() {
            *t = Instant::now();
        }
    }

    fn is_stream_ended(&self) -> bool {
        self.delivery
            .lock()
            .is_ok_and(|delivery| delivery.stream_end.is_some())
    }

    fn is_terminated(&self) -> bool {
        self.terminated.load(Ordering::SeqCst)
    }

    fn terminal_delivery_expired(&self) -> bool {
        self.delivery.lock().map_or(true, |delivery| {
            delivery
                .stream_end
                .is_some_and(|ended| ended.ended_at.elapsed() >= TERMINAL_DELIVERY_TTL)
        })
    }

    fn terminal_acknowledged(&self) -> bool {
        self.delivery.lock().is_ok_and(|delivery| {
            delivery
                .stream_end
                .is_some_and(|ended| delivery.acknowledged_aid >= ended.terminal_aid)
        })
    }

    #[cfg(test)]
    fn terminal_expiry_task_count(&self) -> usize {
        self.delivery.lock().map_or(0, |delivery| {
            delivery.terminal_expiry_tasks.load(Ordering::SeqCst)
        })
    }

    /// Ends the application stream while preserving its final numbered array for delivery.
    fn end_stream(self: &Arc<Self>) {
        let _terminal_acknowledged = self.backchannel_owner.lock().ok().and_then(|mut owner| {
            let mut delivery = self.delivery.lock().ok()?;
            let terminal_aid = delivery.next_aid;
            delivery.stream_end.get_or_insert(StreamEnd {
                ended_at: Instant::now(),
                terminal_aid,
            });
            let acknowledged = delivery
                .stream_end
                .is_some_and(|ended| delivery.acknowledged_aid >= ended.terminal_aid);
            if acknowledged && owner.cancel.is_none() {
                owner.generation = owner.generation.saturating_add(1);
                self.terminated.store(true, Ordering::SeqCst);
                delivery.outbound.clear();
            }
            Some(acknowledged)
        });
        if let Ok(mut inbound) = self.inbound.lock() {
            inbound.take();
        }
        if let Ok(mut maps) = self.maps.lock() {
            maps.1.clear();
        }
        if !self.is_terminated() {
            schedule_terminal_expiry(self, TERMINAL_DELIVERY_TTL);
        }
        self.notify.notify_waiters();
        self.notify.notify_one();
    }

    /// Permanently ends both the application stream and the `WebChannel` transport.
    fn terminate(&self) {
        if let Ok(mut owner) = self.backchannel_owner.lock() {
            owner.generation = owner.generation.saturating_add(1);
            self.terminated.store(true, Ordering::SeqCst);
            if let Some(cancel) = owner.cancel.take() {
                let _ = cancel.send(());
            }
        } else {
            self.terminated.store(true, Ordering::SeqCst);
        }
        if let Ok(mut inbound) = self.inbound.lock() {
            inbound.take();
        }
        if let Ok(mut delivery) = self.delivery.lock() {
            delivery.outbound.clear();
            if let Some(cancel) = delivery.terminal_expiry_cancel.take() {
                let _ = cancel.send(());
            }
        }
        if let Ok(mut maps) = self.maps.lock() {
            maps.1.clear();
        }
        self.notify.notify_waiters();
        self.notify.notify_one();
    }
}

struct TerminalExpiryTask {
    active: Arc<AtomicUsize>,
}

impl Drop for TerminalExpiryTask {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::SeqCst);
    }
}

fn schedule_terminal_expiry(session: &Arc<Session>, delay: Duration) {
    let (cancel, mut cancelled) = oneshot::channel();
    let active = {
        let Ok(mut delivery) = session.delivery.lock() else {
            return;
        };
        if delivery.terminal_expiry_cancel.is_some() || session.is_terminated() {
            return;
        }
        delivery.terminal_expiry_cancel = Some(cancel);
        delivery
            .terminal_expiry_tasks
            .fetch_add(1, Ordering::SeqCst);
        delivery.terminal_expiry_tasks.clone()
    };
    let session = Arc::downgrade(session);
    tokio::spawn(async move {
        let _task = TerminalExpiryTask { active };
        let expired = tokio::select! {
            () = tokio::time::sleep(delay) => true,
            _ = &mut cancelled => false,
        };
        if !expired {
            return;
        }
        if let Some(session) = session.upgrade() {
            if session.terminal_delivery_expired() {
                session.terminate();
                if let Some(registry) = session.registry.upgrade() {
                    if let Ok(mut sessions) = registry.lock() {
                        let registered = sessions
                            .get(&session.sid)
                            .is_some_and(|candidate| Arc::ptr_eq(candidate, &session));
                        if registered {
                            sessions.remove(&session.sid);
                        }
                    }
                }
            }
        }
    });
}

/// Session registry shared by every connection.
pub struct Hub {
    state: Arc<RestState>,
    sessions: Arc<SessionRegistry>,
}

fn terminate_registered_sessions(sessions: &SessionRegistry) {
    let sessions = sessions
        .lock()
        .map(|mut sessions| sessions.drain().map(|(_, session)| session).collect())
        .unwrap_or_else(|_| Vec::new());
    for session in sessions {
        session.terminate();
    }
}

impl Drop for Hub {
    fn drop(&mut self) {
        terminate_registered_sessions(&self.sessions);
    }
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
        .filter(|(k, _)| fireemu_core_app_check::header::is_app_check_header(k))
        .map(|(_, v)| v.clone())
        .collect();
    values.extend(req.app_check.iter().cloned());
    values
}

/// The privileged credential a channel request presented, if any (specification section 12.2).
///
/// As on unary Firestore, the owner credential is verified here rather than read off the
/// principal, because the principal is `Owner` for everyone while Security Rules are disabled.
fn channel_bypass(
    authorization: Option<&str>,
) -> fireemu_core_app_check::admission::PrivilegedBypass {
    if crate::rules::is_owner_credential(authorization) {
        fireemu_core_app_check::admission::PrivilegedBypass::FirestoreOwner
    } else {
        fireemu_core_app_check::admission::PrivilegedBypass::None
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
            sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Closes and forgets sessions that are idle without a live back channel.
    fn purge_idle(&self) {
        let gone = {
            let Ok(mut sessions) = self.sessions.lock() else {
                return;
            };
            let mut gone = Vec::new();
            sessions.retain(|sid, s| {
                let idle = s
                    .last_seen
                    .lock()
                    .is_ok_and(|t| t.elapsed() >= SESSION_IDLE_TTL);
                let live = s.backchannel_attached();
                let keep = !s.is_terminated()
                    && if s.is_stream_ended() {
                        !s.terminal_delivery_expired()
                    } else {
                        !idle || live
                    };
                if !keep {
                    gone.push((sid.clone(), s.clone()));
                }
                keep
            });
            gone
        };
        for (_sid, s) in gone {
            s.trace_event(&TraceEvent::SessionPurged {
                session: s.trace_id,
            });
            s.terminate();
        }
    }

    fn session(&self, req: &ChannelRequest, sid: &str) -> Result<Arc<Session>, ChannelResponse> {
        let s = self
            .sessions
            .lock()
            .ok()
            .and_then(|m| m.get(sid).cloned())
            .filter(|s| !s.is_terminated())
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
            s.terminate();
        }
    }

    /// Handles one HTTP request of the channel endpoint.
    pub fn handle(&self, req: &ChannelRequest) -> ChannelResponse {
        self.purge_idle();
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
        let header = fireemu_core_app_check::header::classify_app_check_header(values);
        let (decision, epoch) =
            policy.admit_bound(&fireemu_core_app_check::admission::AdmissionRequest {
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
            (
                fireemu_core_app_check::verify::BaselineMode::Enforced,
                Some(identity),
                Some(epoch),
            ) => Some(ChannelApp {
                app_id: identity.app_id.clone(),
                epoch,
            }),
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
        let header = fireemu_core_app_check::header::classify_app_check_header(&values);
        let (decision, epoch) =
            policy.admit_bound(&fireemu_core_app_check::admission::AdmissionRequest {
                project_id: &session.project,
                transport: "webchannel",
                operation: "channel.replacement",
                bypass: fireemu_core_app_check::admission::PrivilegedBypass::None,
                header: &header,
                now: self.state.local.now(),
            });
        // A verified identity always comes with a known epoch — verification checks the token
        // against it — but the pair is required explicitly rather than defaulted, so a future
        // change that separates them fails closed instead of comparing against the channel's
        // own epoch and matching itself.
        let replacement = match (decision.identity(), epoch) {
            (Some(identity), Some(epoch)) => Some(ChannelApp {
                app_id: identity.app_id.clone(),
                epoch,
            }),
            _ => None,
        };
        if replacement.as_ref() == Some(bound) {
            return Ok(());
        }
        let reason = decision
            .reason
            .unwrap_or(fireemu_core_app_check::verify::PUBLIC_DENIAL_REASON);
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
            Some(r) => match r
                .principal_from_authorization_for_project(authorization.as_deref(), &project)
            {
                Ok(p) => p,
                Err(e) => return error_chunk(&e),
            },
            None => crate::rules::Principal::Owner,
        };
        let sid = random_sid();
        let (inbound_tx, inbound_rx) = mpsc::channel::<Result<Value, Status>>(64);
        let session = Arc::new(Session {
            sid: sid.clone(),
            trace_id: next_trace_session_id(),
            trace_events: AtomicU64::new(0),
            kind: req.kind,
            origin: req.origin.clone(),
            inbound: Mutex::new(Some(inbound_tx)),
            delivery: Mutex::new(DeliveryState::default()),
            backchannel_owner: Mutex::new(BackchannelOwner {
                generation: 0,
                cancel: None,
            }),
            notify: Notify::new(),
            last_seen: Mutex::new(Instant::now()),
            maps: Mutex::new((0, BTreeMap::new())),
            project: project.clone(),
            app_check: bound,
            registry: Arc::downgrade(&self.sessions),
            terminated: AtomicBool::new(false),
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
        session.trace_event(&TraceEvent::SessionOpened {
            session: session.trace_id,
            kind: session.kind,
        });
        trace_request(&session, req);
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
        trace_request(&session, req);
        if let Some(aid) = req.params.get("AID").and_then(|a| a.parse::<u64>().ok()) {
            if let Err(e) = session.acknowledge(aid) {
                return error_chunk(&e);
            }
        }
        if !session.is_stream_ended() {
            if let Err(e) = session_deliver(&session, &form) {
                return error_chunk(&e);
            }
        }
        let attached = u64::from(session.backchannel_attached());
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
        trace_request(&session, req);
        let acked = req
            .params
            .get("AID")
            .and_then(|a| a.parse::<u64>().ok())
            .unwrap_or(0);
        if let Err(e) = session.acknowledge(acked) {
            return error_chunk(&e);
        }
        if session.is_terminated() {
            let noop = json!([[session.last_aid(), ["noop"]]]).to_string();
            return text_response(200, chunk(&noop));
        }
        let long_poll = req.params.get("CI").map(String::as_str) == Some("1");
        let wait = req
            .params
            .get("TO")
            .and_then(|t| t.parse::<u64>().ok())
            .map_or(LONG_POLL_WAIT, Duration::from_millis)
            .clamp(Duration::from_secs(1), LONG_POLL_MAX);
        let (cancel_tx, mut cancelled) = oneshot::channel();
        let Ok(generation) = session.replace_backchannel(cancel_tx) else {
            if session.is_terminated() {
                let noop = json!([[session.last_aid(), ["noop"]]]).to_string();
                return text_response(200, chunk(&noop));
            }
            return text_response(500, "session lock poisoned".to_owned());
        };
        session.trace_event(&TraceEvent::BackchannelStarted {
            session: session.trace_id,
            generation,
            rid: trace_rid(&req.params),
            client_aid: acked,
            long_poll,
        });
        // Wake a previous back channel so it notices it was replaced.
        session.notify.notify_waiters();
        let (tx, rx) = mpsc::channel::<Result<bytes::Bytes, Status>>(64);
        let response_session = session.clone();
        tokio::spawn(async move {
            let mut cursor = acked;
            let outcome = backchannel_loop(
                &session,
                generation,
                long_poll,
                wait,
                &tx,
                &mut cursor,
                &mut cancelled,
            )
            .await;
            session.trace_event(&TraceEvent::BackchannelEnded {
                session: session.trace_id,
                generation,
                outcome,
            });
        });
        ChannelResponse::Stream {
            headers: vec![("content-type", "text/plain; charset=utf-8".to_owned())],
            body: BackchannelBody::new(rx, response_session, generation),
        }
    }
}

/// Commits a reserved response slot only if this response still owns the session.
///
/// The permit makes enqueue synchronous. Holding the ownership lock across the generation
/// check and `send` gives replacement one linearization point without holding a lock across
/// an await.
fn commit_backchannel_chunk(
    session: &Session,
    generation: u64,
    last_aid: u64,
    permit: mpsc::Permit<'_, Result<bytes::Bytes, Status>>,
    body: bytes::Bytes,
) -> bool {
    let committed = {
        let Ok(owner) = session.backchannel_owner.lock() else {
            return false;
        };
        if owner.generation != generation || session.is_terminated() {
            return false;
        }
        let Ok(mut delivery) = session.delivery.lock() else {
            return false;
        };
        if last_aid > delivery.next_aid {
            return false;
        }
        permit.send(Ok(body));
        delivery.committed_aid = delivery.committed_aid.max(last_aid);
        true
    };
    if !committed {
        return false;
    }
    session.trace_event(&TraceEvent::BackchannelCommitted {
        session: session.trace_id,
        generation,
        last_aid,
    });
    true
}

async fn send_backchannel_chunk(
    session: &Session,
    generation: u64,
    last_aid: u64,
    tx: &mpsc::Sender<Result<bytes::Bytes, Status>>,
    cancelled: &mut oneshot::Receiver<()>,
    body: bytes::Bytes,
) -> Result<(), &'static str> {
    let permit = tokio::select! {
        biased;
        _ = &mut *cancelled => return Err("superseded"),
        permit = tx.reserve() => permit.map_err(|_| "receiver gone")?,
    };
    if commit_backchannel_chunk(session, generation, last_aid, permit, body) {
        Ok(())
    } else {
        Err("superseded")
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
    cancelled: &mut oneshot::Receiver<()>,
) -> &'static str {
    loop {
        if session
            .backchannel_owner
            .lock()
            .map_or(true, |owner| owner.generation != generation)
        {
            return "superseded";
        }
        let pending = session.pending_chunk_after(*cursor);
        if let Some((last, count, text)) = &pending {
            let first = last.saturating_sub(*count as u64).saturating_add(1);
            session.trace_event(&TraceEvent::BackchannelQueued {
                session: session.trace_id,
                generation,
                first_aid: first,
                last_aid: *last,
                count: *count,
            });
            if let Err(outcome) = send_backchannel_chunk(
                session,
                generation,
                *last,
                tx,
                cancelled,
                bytes::Bytes::from(chunk(text)),
            )
            .await
            {
                return outcome;
            }
            // The cursor is the last id actually sent; arrays pushed meanwhile are picked
            // up by the next iteration.
            *cursor = *last;
            if long_poll {
                return "long poll batch";
            }
        }
        if session.is_stream_ended()
            && session.terminal_acknowledged()
            && !session.is_terminated()
            && pending.is_none()
        {
            let noop = json!([[session.last_aid(), ["noop"]]]).to_string();
            if let Err(outcome) = send_backchannel_chunk(
                session,
                generation,
                session.last_aid(),
                tx,
                cancelled,
                bytes::Bytes::from(chunk(&noop)),
            )
            .await
            {
                return outcome;
            }
            session.terminate();
            return "session ended";
        }
        if session.is_terminated() && pending.is_none() {
            return "session ended";
        }
        let idle = if long_poll { wait } else { KEEPALIVE };
        let waited = tokio::select! {
            biased;
            _ = &mut *cancelled => return "superseded",
            () = tx.closed() => return "receiver gone",
            waited = tokio::time::timeout(idle, session.notify.notified()) => waited,
        };
        if session
            .backchannel_owner
            .lock()
            .map_or(true, |owner| owner.generation != generation)
        {
            // Hand a possibly consumed data permit to the newer back channel.
            session.notify.notify_one();
            return "superseded";
        }
        if waited.is_err() {
            // Silence: a framed keep-alive (a completed request with no bytes would be
            // treated as an error by the client).
            let noop = json!([[session.last_aid(), ["noop"]]]).to_string();
            if let Err(outcome) = send_backchannel_chunk(
                session,
                generation,
                session.last_aid(),
                tx,
                cancelled,
                bytes::Bytes::from(chunk(&noop)),
            )
            .await
            {
                return outcome;
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
fn session_deliver(session: &Session, form: &BTreeMap<String, String>) -> Result<bool, Status> {
    let count: u64 = form.get("count").and_then(|c| c.parse().ok()).unwrap_or(0);
    let ofs: u64 = form.get("ofs").and_then(|c| c.parse().ok()).unwrap_or(0);
    if count > MAX_MAPS_PER_REQUEST {
        return Err(Status::invalid_argument("too many maps in one request"));
    }
    let mut maps = session
        .maps
        .lock()
        .map_err(|_| Status::internal("session lock poisoned"))?;
    let mut accepted = 0;
    let mut duplicates = 0;
    for n in 0..count {
        let map_id = ofs.saturating_add(n);
        let Some(raw) = form.get(&format!("req{n}___data__")) else {
            continue;
        };
        if map_id < maps.0 || maps.1.contains_key(&map_id) {
            duplicates += 1;
            continue; // retried map
        }
        if map_id.saturating_sub(maps.0) > MAX_MAPS_PER_REQUEST {
            return Err(Status::invalid_argument(
                "forward channel map id too far ahead",
            ));
        }
        maps.1.insert(map_id, raw.clone());
        accepted += 1;
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
            maps.1.clear();
            return Ok(false);
        };
        match sender.try_send(Ok(value)) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Closed(_)) => {
                drop(inbound);
                maps.1.clear();
                return Ok(false);
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                return Err(Status::unavailable("stream is not accepting messages"));
            }
        }
        drop(inbound);
        let done = maps.0;
        maps.1.remove(&done);
        maps.0 = done + 1;
    }
    let event = TraceEvent::ForwardMaps {
        session: session.trace_id,
        offset: ofs,
        declared: count,
        accepted,
        duplicates,
        buffered: maps.1.len(),
        next_expected: maps.0,
    };
    drop(maps);
    session.trace_event(&event);
    Ok(true)
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
                pump_session.trace_event(&TraceEvent::Overflow {
                    session: pump_session.trace_id,
                });
                break;
            }
        }
        pump_session.end_stream();
    });
    match kind {
        StreamKind::Listen => {
            let inbound = MappedStream {
                inner: ReceiverStream::new(inbound_rx),
                f: move |r: Result<Value, Status>| {
                    r.and_then(|v| listen_request_from_json(&v).map_err(|e| bad_json(&e)))
                },
            };
            let (tx, mut rx) = mpsc::channel::<Result<pb::ListenResponse, Status>>(256);
            tokio::spawn(async move {
                while let Some(item) = rx.recv().await {
                    let forwarded = item.map(|response| listen_response_to_json(&response));
                    if out_tx.send(forwarded).await.is_err() {
                        break;
                    }
                }
            });
            let observer = trace_enabled().then(|| {
                Arc::new(WebchannelListenObserver {
                    session: session.clone(),
                    state: Mutex::new(ListenTraceState::default()),
                }) as Arc<dyn ListenObserver>
            });
            tokio::spawn(listen_stream_observed(ctx, inbound, tx, observer));
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

#[cfg(test)]
mod tests {
    use super::*;

    fn terminal_session(
        sid: &str,
        registry: &Arc<SessionRegistry>,
        ended_at: Instant,
    ) -> Arc<Session> {
        let (inbound, _inbound_rx) = mpsc::channel(1);
        Arc::new(Session {
            sid: sid.to_owned(),
            trace_id: next_trace_session_id(),
            trace_events: AtomicU64::new(0),
            kind: StreamKind::Write,
            origin: None,
            inbound: Mutex::new(Some(inbound)),
            delivery: Mutex::new(DeliveryState {
                outbound: VecDeque::from([(1, "[1,[{\"error\":{}}]]".to_owned())]),
                next_aid: 1,
                committed_aid: 1,
                stream_end: Some(StreamEnd {
                    ended_at,
                    terminal_aid: 1,
                }),
                ..DeliveryState::default()
            }),
            backchannel_owner: Mutex::new(BackchannelOwner {
                generation: 0,
                cancel: None,
            }),
            notify: Notify::new(),
            last_seen: Mutex::new(Instant::now()),
            maps: Mutex::new((1, BTreeMap::new())),
            project: "demo-app".to_owned(),
            app_check: None,
            registry: Arc::downgrade(registry),
            terminated: AtomicBool::new(false),
        })
    }

    async fn wait_for_no_expiry_tasks(sessions: &[Arc<Session>]) {
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if sessions
                    .iter()
                    .all(|session| session.terminal_expiry_task_count() == 0)
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("cancelled terminal expiry tasks must finish promptly");
    }

    #[test]
    fn trace_events_cannot_render_channel_capabilities_or_payloads() {
        let rendered = format_trace_event(&TraceEvent::ArrayGenerated {
            session: 7,
            aid: 4,
            bytes: 128,
            queued_first: Some(2),
            queued_last: Some(4),
            queued_count: 3,
        });

        assert_eq!(
            rendered,
            "session=7 array=generated aid=4 bytes=128 queued=2..4 queued_count=3"
        );
        for secret in [
            "session-capability-secret",
            "projects/private-project",
            "Bearer private-token",
            "private-document-field",
        ] {
            assert!(!rendered.contains(secret));
        }
    }

    #[test]
    fn trace_rate_limiter_resets_after_its_bounded_window() {
        let started = Instant::now();
        let mut limiter = TraceRateLimiter {
            window_started: started,
            emitted: 0,
        };

        for _ in 0..MAX_TRACE_EVENTS_PER_SECOND {
            assert!(limiter.allow(started));
        }
        assert!(!limiter.allow(started));
        assert!(limiter.allow(started + Duration::from_secs(1)));
    }

    #[test]
    fn listen_trace_assigns_a_new_lifetime_when_a_target_id_is_reused() {
        let mut trace = ListenTraceState::default();

        assert_eq!(trace.request_add(5), 1);
        assert_eq!(trace.active_lifetime(5), Some(1));
        assert_eq!(trace.request_remove(5), Some(1));
        assert_eq!(trace.active_lifetime(5), None);
        assert_eq!(trace.request_add(5), 2);
        assert_eq!(trace.active_lifetime(5), Some(2));
    }

    #[test]
    fn listen_trace_bounds_completed_target_history() {
        let mut trace = ListenTraceState::default();
        let newest = i32::try_from(MAX_TRACE_COMPLETED_TARGETS).expect("small trace cap") + 17;
        for target in 1..=newest {
            let lifetime = trace.request_add(target);
            assert_eq!(trace.request_remove(target), Some(lifetime));
        }

        assert!(trace.completed.len() <= MAX_TRACE_COMPLETED_TARGETS);
        assert_eq!(trace.latest_lifetime(1), None);
        assert!(trace.latest_lifetime(newest).is_some());
    }

    #[test]
    fn listen_trace_records_only_accepted_adds_and_keeps_pipelined_lifetimes_distinct() {
        let add = |target_id| pb::ListenRequest {
            target_change: Some(pb::listen_request::TargetChange::AddTarget(pb::Target {
                target_id,
                ..Default::default()
            })),
            ..Default::default()
        };
        let remove = |target_id| pb::ListenRequest {
            target_change: Some(pb::listen_request::TargetChange::RemoveTarget(target_id)),
            ..Default::default()
        };
        let response = |kind, target_id| pb::ListenResponse {
            response_type: Some(pb::listen_response::ResponseType::TargetChange(
                pb::TargetChange {
                    target_change_type: kind as i32,
                    target_ids: vec![target_id],
                    ..Default::default()
                },
            )),
        };
        let mut trace = ListenTraceState::default();

        let rejected = trace.exchange_events(
            1,
            Some(&add(7)),
            &[response(pb::target_change::TargetChangeType::Remove, 7)],
            usize::MAX,
        );
        assert_eq!(trace.latest_lifetime(7), None);
        assert!(format_trace_event(&rejected[0]).ends_with("target=7@unknown"));

        let first = trace.exchange_events(
            1,
            Some(&add(9)),
            &[response(pb::target_change::TargetChangeType::Add, 9)],
            usize::MAX,
        );
        let removed = trace.exchange_events(
            1,
            Some(&remove(9)),
            &[response(pb::target_change::TargetChangeType::Remove, 9)],
            usize::MAX,
        );
        let replacement = trace.exchange_events(
            1,
            Some(&add(9)),
            &[response(pb::target_change::TargetChangeType::Add, 9)],
            usize::MAX,
        );

        assert!(format_trace_event(&first[0]).ends_with("target=9@1"));
        assert!(format_trace_event(&removed[0]).ends_with("target=9@1"));
        assert!(format_trace_event(&replacement[0]).ends_with("target=9@2"));

        let bounded = trace.exchange_events(
            1,
            None,
            &[
                response(pb::target_change::TargetChangeType::NoChange, 9),
                response(pb::target_change::TargetChangeType::Current, 9),
                response(pb::target_change::TargetChangeType::Reset, 9),
            ],
            2,
        );
        assert_eq!(bounded.len(), 2);
    }

    #[test]
    fn listen_response_trace_contains_only_response_shape_and_target_lifetimes() {
        let mut trace = ListenTraceState::default();
        let lifetime = trace.request_add(9);
        let response = pb::ListenResponse {
            response_type: Some(pb::listen_response::ResponseType::DocumentChange(
                pb::DocumentChange {
                    document: Some(pb::Document {
                        name: "projects/private-project/databases/(default)/documents/users/private-user"
                            .to_owned(),
                        ..Default::default()
                    }),
                    target_ids: vec![9],
                    removed_target_ids: vec![],
                },
            )),
        };

        let event = trace.response_event(3, &response);
        let rendered = format_trace_event(&event);

        assert_eq!(lifetime, 1);
        assert_eq!(
            rendered,
            "session=3 listen=response kind=document_change targets=9@1"
        );
        assert!(!rendered.contains("private-project"));
        assert!(!rendered.contains("private-user"));
    }

    #[test]
    fn pending_chunk_starts_after_the_backchannel_cursor() {
        let (inbound, _inbound_rx) = mpsc::channel(1);
        let session = Session {
            sid: "session-one".to_owned(),
            trace_id: 1,
            trace_events: AtomicU64::new(0),
            kind: StreamKind::Listen,
            origin: None,
            inbound: Mutex::new(Some(inbound)),
            delivery: Mutex::new(DeliveryState {
                outbound: VecDeque::from([
                    (1, "[1,[\"first\"]]".to_owned()),
                    (2, "[2,[\"second\"]]".to_owned()),
                    (3, "[3,[\"third\"]]".to_owned()),
                ]),
                next_aid: 3,
                committed_aid: 3,
                ..DeliveryState::default()
            }),
            backchannel_owner: Mutex::new(BackchannelOwner {
                generation: 0,
                cancel: None,
            }),
            notify: Notify::new(),
            last_seen: Mutex::new(Instant::now()),
            maps: Mutex::new((0, BTreeMap::new())),
            project: "demo-app".to_owned(),
            app_check: None,
            registry: std::sync::Weak::new(),
            terminated: AtomicBool::new(false),
        };

        assert_eq!(
            session.pending_chunk_after(1),
            Some((3, 2, "[[2,[\"second\"]],[3,[\"third\"]]]".to_owned()))
        );
        assert_eq!(session.pending_chunk_after(3), None);
    }

    #[tokio::test]
    async fn terminal_delivery_deadline_is_independent_of_request_activity() {
        let (inbound, _inbound_rx) = mpsc::channel(1);
        let registry = Arc::new(Mutex::new(HashMap::new()));
        let session = Arc::new(Session {
            sid: "terminal-session".to_owned(),
            trace_id: 1,
            trace_events: AtomicU64::new(0),
            kind: StreamKind::Write,
            origin: None,
            inbound: Mutex::new(Some(inbound)),
            delivery: Mutex::new(DeliveryState {
                outbound: VecDeque::from([(2, "[2,[{\"error\":{}}]]".to_owned())]),
                next_aid: 2,
                committed_aid: 2,
                acknowledged_aid: 0,
                stream_end: Some(StreamEnd {
                    ended_at: Instant::now()
                        .checked_sub(TERMINAL_DELIVERY_TTL)
                        .expect("test instant must support the terminal TTL"),
                    terminal_aid: 2,
                }),
                ..DeliveryState::default()
            }),
            backchannel_owner: Mutex::new(BackchannelOwner {
                generation: 0,
                cancel: None,
            }),
            notify: Notify::new(),
            last_seen: Mutex::new(Instant::now()),
            maps: Mutex::new((2, BTreeMap::new())),
            project: "demo-app".to_owned(),
            app_check: None,
            registry: Arc::downgrade(&registry),
            terminated: AtomicBool::new(false),
        });
        registry
            .lock()
            .unwrap()
            .insert(session.sid.clone(), session.clone());

        session.touch();
        assert!(session.terminal_delivery_expired());
        assert!(!session.is_terminated());
        schedule_terminal_expiry(&session, Duration::ZERO);
        tokio::time::timeout(Duration::from_secs(1), async {
            while !session.is_terminated() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the deadline task must terminate an abandoned session");
        assert!(session.delivery.lock().unwrap().outbound.is_empty());
        assert!(!registry.lock().unwrap().contains_key(&session.sid));
    }

    #[tokio::test]
    async fn terminal_acknowledgement_and_termination_cancel_all_expiry_work() {
        let registry = Arc::new(Mutex::new(HashMap::new()));
        let sessions = (0..64)
            .map(|index| {
                let session =
                    terminal_session(&format!("terminal-{index}"), &registry, Instant::now());
                registry
                    .lock()
                    .unwrap()
                    .insert(session.sid.clone(), session.clone());
                schedule_terminal_expiry(&session, Duration::from_secs(60));
                session
            })
            .collect::<Vec<_>>();
        assert!(sessions
            .iter()
            .all(|session| session.terminal_expiry_task_count() == 1));

        for (index, session) in sessions.iter().enumerate() {
            if index % 2 == 0 {
                session.acknowledge(1).unwrap();
            } else {
                session.terminate();
            }
        }

        wait_for_no_expiry_tasks(&sessions).await;
    }

    #[tokio::test]
    async fn cancelling_an_old_expiry_cannot_remove_a_replacement_sid() {
        let registry = Arc::new(Mutex::new(HashMap::new()));
        let old = terminal_session("reused", &registry, Instant::now());
        registry
            .lock()
            .unwrap()
            .insert(old.sid.clone(), old.clone());
        schedule_terminal_expiry(&old, Duration::from_secs(60));

        let replacement = terminal_session("reused", &registry, Instant::now());
        registry
            .lock()
            .unwrap()
            .insert(replacement.sid.clone(), replacement.clone());
        old.terminate();
        wait_for_no_expiry_tasks(std::slice::from_ref(&old)).await;

        let registered = registry.lock().unwrap().get("reused").cloned().unwrap();
        assert!(Arc::ptr_eq(&registered, &replacement));
        assert!(!replacement.is_terminated());
    }

    #[tokio::test]
    async fn hub_shutdown_cancels_every_registered_expiry() {
        let registry = Arc::new(Mutex::new(HashMap::new()));
        let sessions = (0..16)
            .map(|index| {
                let session =
                    terminal_session(&format!("hub-terminal-{index}"), &registry, Instant::now());
                registry
                    .lock()
                    .unwrap()
                    .insert(session.sid.clone(), session.clone());
                schedule_terminal_expiry(&session, Duration::from_secs(60));
                session
            })
            .collect::<Vec<_>>();

        terminate_registered_sessions(&registry);

        assert!(registry.lock().unwrap().is_empty());
        wait_for_no_expiry_tasks(&sessions).await;
        assert!(sessions.iter().all(|session| session.is_terminated()));
    }

    #[test]
    fn stream_end_observes_an_acknowledgement_that_won_the_race() {
        let (inbound, _inbound_rx) = mpsc::channel(1);
        let session = Arc::new(Session {
            sid: "ack-first-session".to_owned(),
            trace_id: 1,
            trace_events: AtomicU64::new(0),
            kind: StreamKind::Write,
            origin: None,
            inbound: Mutex::new(Some(inbound)),
            delivery: Mutex::new(DeliveryState {
                outbound: VecDeque::from([(2, "[2,[{\"error\":{}}]]".to_owned())]),
                next_aid: 2,
                committed_aid: 2,
                ..DeliveryState::default()
            }),
            backchannel_owner: Mutex::new(BackchannelOwner {
                generation: 0,
                cancel: None,
            }),
            notify: Notify::new(),
            last_seen: Mutex::new(Instant::now()),
            maps: Mutex::new((2, BTreeMap::new())),
            project: "demo-app".to_owned(),
            app_check: None,
            registry: std::sync::Weak::new(),
            terminated: AtomicBool::new(false),
        });

        session.acknowledge(2).unwrap();
        assert!(!session.is_terminated());
        session.end_stream();
        assert!(session.is_terminated());
        assert!(session.delivery.lock().unwrap().outbound.is_empty());
    }

    #[tokio::test]
    async fn acknowledged_stream_end_frames_the_attached_backchannel_before_termination() {
        let (inbound, _inbound_rx) = mpsc::channel(1);
        let session = Arc::new(Session {
            sid: "ack-owner-end-session".to_owned(),
            trace_id: 1,
            trace_events: AtomicU64::new(0),
            kind: StreamKind::Write,
            origin: None,
            inbound: Mutex::new(Some(inbound)),
            delivery: Mutex::new(DeliveryState {
                outbound: VecDeque::from([(2, "[2,[{\"error\":{}}]]".to_owned())]),
                next_aid: 2,
                committed_aid: 2,
                ..DeliveryState::default()
            }),
            backchannel_owner: Mutex::new(BackchannelOwner {
                generation: 0,
                cancel: None,
            }),
            notify: Notify::new(),
            last_seen: Mutex::new(Instant::now()),
            maps: Mutex::new((2, BTreeMap::new())),
            project: "demo-app".to_owned(),
            app_check: None,
            registry: std::sync::Weak::new(),
            terminated: AtomicBool::new(false),
        });

        session.acknowledge(2).unwrap();
        let (cancel, mut cancelled) = oneshot::channel();
        let generation = session.replace_backchannel(cancel).unwrap();
        session.end_stream();
        assert!(!session.is_terminated());

        let (tx, mut rx) = mpsc::channel(1);
        let mut cursor = 2;
        let outcome = backchannel_loop(
            &session,
            generation,
            true,
            Duration::from_secs(1),
            &tx,
            &mut cursor,
            &mut cancelled,
        )
        .await;

        assert_eq!(outcome, "session ended");
        assert_eq!(
            rx.recv().await.unwrap().unwrap(),
            bytes::Bytes::from_static(b"14\n[[2,[\"noop\"]]]")
        );
        assert!(session.is_terminated());
        assert!(!session.backchannel_attached());
    }

    #[tokio::test]
    async fn unacknowledged_streaming_terminal_array_replays_after_response_loss() {
        let (inbound, _inbound_rx) = mpsc::channel(1);
        let terminal = "[1,[{\"error\":{\"status\":\"PERMISSION_DENIED\"}}]]";
        let session = Arc::new(Session {
            sid: "unacknowledged-stream-end".to_owned(),
            trace_id: 1,
            trace_events: AtomicU64::new(0),
            kind: StreamKind::Write,
            origin: None,
            inbound: Mutex::new(Some(inbound)),
            delivery: Mutex::new(DeliveryState {
                outbound: VecDeque::from([(1, terminal.to_owned())]),
                next_aid: 1,
                stream_end: Some(StreamEnd {
                    ended_at: Instant::now(),
                    terminal_aid: 1,
                }),
                ..DeliveryState::default()
            }),
            backchannel_owner: Mutex::new(BackchannelOwner {
                generation: 1,
                cancel: None,
            }),
            notify: Notify::new(),
            last_seen: Mutex::new(Instant::now()),
            maps: Mutex::new((1, BTreeMap::new())),
            project: "demo-app".to_owned(),
            app_check: None,
            registry: std::sync::Weak::new(),
            terminated: AtomicBool::new(false),
        });
        let (tx, mut rx) = mpsc::channel(1);
        let (_cancel, mut cancelled) = oneshot::channel();
        let first_session = session.clone();
        let first = tokio::spawn(async move {
            let mut cursor = 0;
            backchannel_loop(
                &first_session,
                1,
                false,
                Duration::from_secs(1),
                &tx,
                &mut cursor,
                &mut cancelled,
            )
            .await
        });

        let committed = rx.recv().await.unwrap().unwrap();
        drop(rx);
        assert_eq!(first.await.unwrap(), "receiver gone");
        assert!(!session.is_terminated());
        assert!(!session.terminal_acknowledged());
        assert!(session.delivery.lock().unwrap().outbound.len() == 1);

        let (cancel, mut cancelled) = oneshot::channel();
        let generation = session.replace_backchannel(cancel).unwrap();
        let (replay_tx, mut replay_rx) = mpsc::channel(1);
        let mut replay_cursor = 0;
        assert_eq!(
            backchannel_loop(
                &session,
                generation,
                true,
                Duration::from_secs(1),
                &replay_tx,
                &mut replay_cursor,
                &mut cancelled,
            )
            .await,
            "long poll batch"
        );
        assert_eq!(replay_rx.recv().await.unwrap().unwrap(), committed);
        assert!(!session.is_terminated());
    }

    #[test]
    fn acknowledgement_cannot_remove_an_uncommitted_array() {
        let (inbound, _inbound_rx) = mpsc::channel(1);
        let session = Session {
            sid: "uncommitted-session".to_owned(),
            trace_id: 1,
            trace_events: AtomicU64::new(0),
            kind: StreamKind::Write,
            origin: None,
            inbound: Mutex::new(Some(inbound)),
            delivery: Mutex::new(DeliveryState {
                outbound: VecDeque::from([(2, "[2,[{\"error\":{}}]]".to_owned())]),
                next_aid: 2,
                committed_aid: 1,
                ..DeliveryState::default()
            }),
            backchannel_owner: Mutex::new(BackchannelOwner {
                generation: 0,
                cancel: None,
            }),
            notify: Notify::new(),
            last_seen: Mutex::new(Instant::now()),
            maps: Mutex::new((2, BTreeMap::new())),
            project: "demo-app".to_owned(),
            app_check: None,
            registry: std::sync::Weak::new(),
            terminated: AtomicBool::new(false),
        };

        assert_eq!(
            session.acknowledge(2).unwrap_err().code(),
            tonic::Code::InvalidArgument
        );
        assert_eq!(session.delivery.lock().unwrap().outbound.len(), 1);
    }

    #[test]
    fn a_terminated_session_cannot_acquire_a_new_backchannel_owner() {
        let (inbound, _inbound_rx) = mpsc::channel(1);
        let session = Session {
            sid: "terminated-session".to_owned(),
            trace_id: 1,
            trace_events: AtomicU64::new(0),
            kind: StreamKind::Write,
            origin: None,
            inbound: Mutex::new(Some(inbound)),
            delivery: Mutex::new(DeliveryState::default()),
            backchannel_owner: Mutex::new(BackchannelOwner {
                generation: 0,
                cancel: None,
            }),
            notify: Notify::new(),
            last_seen: Mutex::new(Instant::now()),
            maps: Mutex::new((0, BTreeMap::new())),
            project: "demo-app".to_owned(),
            app_check: None,
            registry: std::sync::Weak::new(),
            terminated: AtomicBool::new(false),
        };
        session.terminate();
        let (cancel, _cancelled) = oneshot::channel();

        assert!(session.replace_backchannel(cancel).is_err());
        assert!(!session.backchannel_attached());
    }

    #[test]
    fn a_closed_inbound_stream_absorbs_late_maps_without_buffering_them() {
        let (inbound, inbound_rx) = mpsc::channel(1);
        drop(inbound_rx);
        let session = Session {
            sid: "closed-inbound-session".to_owned(),
            trace_id: 1,
            trace_events: AtomicU64::new(0),
            kind: StreamKind::Write,
            origin: None,
            inbound: Mutex::new(Some(inbound)),
            delivery: Mutex::new(DeliveryState::default()),
            backchannel_owner: Mutex::new(BackchannelOwner {
                generation: 0,
                cancel: None,
            }),
            notify: Notify::new(),
            last_seen: Mutex::new(Instant::now()),
            maps: Mutex::new((0, BTreeMap::new())),
            project: "demo-app".to_owned(),
            app_check: None,
            registry: std::sync::Weak::new(),
            terminated: AtomicBool::new(false),
        };
        let body = BTreeMap::from([
            ("count".to_owned(), "1".to_owned()),
            ("ofs".to_owned(), "0".to_owned()),
            (
                "req0___data__".to_owned(),
                json!({"database": "projects/demo-app/databases/(default)"}).to_string(),
            ),
        ]);

        assert!(!session_deliver(&session, &body).unwrap());
        assert!(session.maps.lock().unwrap().1.is_empty());
    }

    #[tokio::test]
    async fn a_superseded_backchannel_cannot_send_queued_arrays() {
        let (inbound, _inbound_rx) = mpsc::channel(1);
        let session = Session {
            sid: "session-one".to_owned(),
            trace_id: 1,
            trace_events: AtomicU64::new(0),
            kind: StreamKind::Listen,
            origin: None,
            inbound: Mutex::new(Some(inbound)),
            delivery: Mutex::new(DeliveryState {
                outbound: VecDeque::from([(1, "[1,[{\"current\":true}]]".to_owned())]),
                next_aid: 1,
                ..DeliveryState::default()
            }),
            backchannel_owner: Mutex::new(BackchannelOwner {
                generation: 2,
                cancel: None,
            }),
            notify: Notify::new(),
            last_seen: Mutex::new(Instant::now()),
            maps: Mutex::new((0, BTreeMap::new())),
            project: "demo-app".to_owned(),
            app_check: None,
            registry: std::sync::Weak::new(),
            terminated: AtomicBool::new(false),
        };
        let (tx, mut rx) = mpsc::channel(1);
        let (_cancel_tx, mut cancelled) = oneshot::channel();
        let mut cursor = 0;

        let outcome = backchannel_loop(
            &session,
            1,
            true,
            Duration::from_secs(1),
            &tx,
            &mut cursor,
            &mut cancelled,
        )
        .await;

        assert_eq!(outcome, "superseded");
        assert_eq!(cursor, 0);
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn termination_invalidates_a_reserved_backchannel_commit() {
        let (inbound, _inbound_rx) = mpsc::channel(1);
        let session = Session {
            sid: "terminating-session".to_owned(),
            trace_id: 1,
            trace_events: AtomicU64::new(0),
            kind: StreamKind::Write,
            origin: None,
            inbound: Mutex::new(Some(inbound)),
            delivery: Mutex::new(DeliveryState {
                outbound: VecDeque::from([(1, "[1,[{\"error\":{}}]]".to_owned())]),
                next_aid: 1,
                ..DeliveryState::default()
            }),
            backchannel_owner: Mutex::new(BackchannelOwner {
                generation: 1,
                cancel: None,
            }),
            notify: Notify::new(),
            last_seen: Mutex::new(Instant::now()),
            maps: Mutex::new((1, BTreeMap::new())),
            project: "demo-app".to_owned(),
            app_check: None,
            registry: std::sync::Weak::new(),
            terminated: AtomicBool::new(false),
        };
        let (tx, mut rx) = mpsc::channel(1);
        let permit = tx.reserve().await.unwrap();

        session.terminate();

        assert!(!commit_backchannel_chunk(
            &session,
            1,
            1,
            permit,
            bytes::Bytes::from_static(b"terminal"),
        ));
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn replacement_and_delivery_commit_have_one_linearization_point() {
        let (inbound, _inbound_rx) = mpsc::channel(1);
        let session = Session {
            sid: "session-one".to_owned(),
            trace_id: 1,
            trace_events: AtomicU64::new(0),
            kind: StreamKind::Listen,
            origin: None,
            inbound: Mutex::new(Some(inbound)),
            delivery: Mutex::new(DeliveryState {
                next_aid: 1,
                ..DeliveryState::default()
            }),
            backchannel_owner: Mutex::new(BackchannelOwner {
                generation: 1,
                cancel: None,
            }),
            notify: Notify::new(),
            last_seen: Mutex::new(Instant::now()),
            maps: Mutex::new((0, BTreeMap::new())),
            project: "demo-app".to_owned(),
            app_check: None,
            registry: std::sync::Weak::new(),
            terminated: AtomicBool::new(false),
        };
        let (tx, mut rx) = mpsc::channel(1);
        let old_permit = tx.reserve().await.unwrap();
        let (replacement_cancel, _replacement_cancelled) = oneshot::channel();

        let replacement_generation = session.replace_backchannel(replacement_cancel).unwrap();
        assert_eq!(replacement_generation, 2);
        assert!(session.backchannel_attached());
        assert!(!session.finish_backchannel(1));
        assert!(session.backchannel_attached());
        assert!(!commit_backchannel_chunk(
            &session,
            1,
            1,
            old_permit,
            bytes::Bytes::from_static(b"old"),
        ));
        assert!(rx.try_recv().is_err());

        let replacement_permit = tx.reserve().await.unwrap();
        assert!(commit_backchannel_chunk(
            &session,
            replacement_generation,
            1,
            replacement_permit,
            bytes::Bytes::from_static(b"new"),
        ));
        assert_eq!(
            rx.recv().await.unwrap().unwrap(),
            bytes::Bytes::from_static(b"new")
        );
        assert!(rx.try_recv().is_err());
        assert!(session.finish_backchannel(replacement_generation));
        assert!(!session.backchannel_attached());
    }
}
