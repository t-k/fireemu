//! Streaming RPCs of the local backend: `Write` (handshake + sequential atomic commits) and
//! `Listen` (initial snapshot, then a diff after every commit on the database).
//!
//! `Listen` keeps one target registry per stream. Whenever the backend publishes a commit
//! on the database (or a target is added), every active target is refreshed against one
//! database snapshot; the diff against its last known `(path, version)` set becomes
//! `DocumentChange` / `DocumentDelete` / `DocumentRemove` messages, followed by one global
//! `NO_CHANGE` boundary carrying the snapshot read time and a resume token derived from
//! the snapshot version; a target made current in that snapshot gets its token with
//! `CURRENT` instead of a `NO_CHANGE` of its own. A target added with a resume token (or a
//! read time) replays only what changed since that version: a global boundary with the resume
//! point's token comes first, then the target's state at the token is recomputed from the
//! retained history and diffed against the current snapshot, with no existence filter
//! (production's framing, AUTH-FS-CROSS stage 2).
//!
//! A token is only honoured while the store can still reproduce its version exactly
//! (`FirestoreState::is_retained`: not compacted away by the one-hour retention window, not
//! ahead of this database). A future or expired token falls back to `RESET`; strict removes non-empty undecodable tokens and the emulator resets them,
//! so a token is never resumed against unrelated history; the client drops its cache and
//! replays from scratch. Security Rules are re-checked on every refresh; a denial removes
//! the target with a `PERMISSION_DENIED` cause.

// `tonic::Status` is the error type dictated by the generated trait.
#![allow(clippy::result_large_err)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use fireemu_core_firestore::path::DocumentPath;
use fireemu_core_firestore::query::Query;
use fireemu_core_firestore::store::{CommitVersion, Document, Write};
use fireemu_core_types::time::LogicalInstant;
use fireemu_proto_firestore::google::firestore::v1 as pb;
use tokio::sync::mpsc;
use tokio_stream::StreamExt;
use tonic::Status;

use crate::decode::{parse_parent, Parent};
use crate::encode::{decode_instant, decode_write, encode_document, encode_instant};
use crate::gateway::Gateway;
use crate::local::{CommitNotification, LocalBackend};
use crate::rules::{write_guard, Principal, RulesEnforcer};

/// The App Check credential a stream opened with (specification section 13.1).
///
/// The opening metadata — the gRPC headers, or the `WebChannel` init header block — is
/// classified exactly once, here. The decision it produces is taken once more, when the first
/// request finally names the database, because that is the earliest moment the target project
/// is known; from then on the stream is admitted for its whole life. Neither the token's
/// expiry nor a later policy change ends an admitted stream: a client that needs a fresh
/// decision reconnects, and the new stream is admitted on its own opening credential.
pub struct StreamAdmission {
    policy: Arc<fireemu_core_app_check::admission::ServiceAdmission>,
    header: fireemu_core_app_check::header::HeaderClassification,
    bypass: fireemu_core_app_check::admission::PrivilegedBypass,
    transport: &'static str,
}

impl StreamAdmission {
    /// The classification of one stream's opening App Check field values.
    #[must_use]
    pub fn new(
        policy: Arc<fireemu_core_app_check::admission::ServiceAdmission>,
        values: &[String],
        bypass: fireemu_core_app_check::admission::PrivilegedBypass,
        transport: &'static str,
    ) -> Self {
        Self {
            policy,
            header: fireemu_core_app_check::header::classify_app_check_header(values),
            bypass,
            transport,
        }
    }
}

/// Shared pieces every stream task needs.
pub struct StreamContext {
    /// Local backend.
    pub local: Arc<LocalBackend>,
    /// Strict gateway (kept for parity with the service; queries are validated through the
    /// backend).
    pub gateway: Arc<Gateway>,
    /// Rules enforcement, if configured.
    pub rules: Option<Arc<RulesEnforcer>>,
    /// Caller as resolved when the stream opened.
    pub principal: Principal,
    /// Raw `Authorization` value: re-verified on every write / refresh so revocation,
    /// disablement and expiry end the stream instead of living on in it.
    pub authorization: Option<String>,
    /// Backend reset epoch when the stream opened; a reset ends the stream.
    pub epoch: u64,
    /// App Check for this stream, or `None` when the service's baseline mode is `off`.
    pub app_check: Option<StreamAdmission>,
}

impl StreamContext {
    /// Re-resolves the caller and checks the session epoch before serving anything.
    fn refresh_principal(&self, project: &str) -> Result<Principal, Status> {
        if self.local.epoch() != self.epoch {
            return Err(Status::aborted(
                "the session was reset; streams opened before the reset are closed",
            ));
        }
        match &self.rules {
            Some(r) => {
                r.principal_from_authorization_for_project(self.authorization.as_deref(), project)
            }
            None => Ok(self.principal.clone()),
        }
    }

    /// Admits the stream once, against the database its first request named.
    ///
    /// Called from exactly one place per stream — where the parent is resolved — and never
    /// again. Unlike [`Self::refresh_principal`], which re-verifies the Auth credential on
    /// every message so revocation ends the stream, App Check is a stream-lifetime decision.
    fn admit_app_check(&self, parent: &Parent, operation: &'static str) -> Result<(), Status> {
        let Some(app_check) = &self.app_check else {
            return Ok(());
        };
        let decision =
            app_check
                .policy
                .admit(&fireemu_core_app_check::admission::AdmissionRequest {
                    project_id: parent.project.as_str(),
                    transport: app_check.transport,
                    operation,
                    bypass: app_check.bypass,
                    header: &app_check.header,
                    now: self.local.now(),
                });
        match decision.reason {
            None => Ok(()),
            Some(reason) => Err(crate::service::app_check_denied(reason)),
        }
    }
}

fn status(e: crate::decode::DecodeError) -> Status {
    crate::gateway::Rejection::Decode(e).to_status()
}

fn database_parent(database: &str) -> Result<Parent, Status> {
    parse_parent(&format!("{database}/documents")).map_err(status)
}

static NEXT_STREAM_ID: AtomicU64 = AtomicU64::new(1);

// ---------------------------------------------------------------------------------------
// Write stream
// ---------------------------------------------------------------------------------------

struct WriteStreamState {
    parent: Option<Parent>,
    stream_id: String,
    /// Tokens are issued 1, 2, 3, ...; a request may acknowledge any issued token not
    /// older than the highest acknowledgement seen (clients pipeline several batches
    /// against the last token they saw).
    issued: u64,
    acknowledged: u64,
    token_prefix: u64,
}

/// Runs the `Write` stream: the first message (no writes) is the handshake; every later
/// message commits its writes atomically and answers with results and a fresh token.
pub async fn write_stream(
    ctx: StreamContext,
    mut inbound: impl tokio_stream::Stream<Item = Result<pb::WriteRequest, Status>> + Unpin + Send,
    tx: mpsc::Sender<Result<pb::WriteResponse, Status>>,
) {
    let stream_number = NEXT_STREAM_ID.fetch_add(1, Ordering::Relaxed);
    let mut state = WriteStreamState {
        parent: None,
        stream_id: format!("fireemu-{stream_number}"),
        issued: 0,
        acknowledged: 0,
        token_prefix: stream_number,
    };
    while let Some(next) = inbound.next().await {
        let req = match next {
            Ok(r) => r,
            Err(e) => {
                let _ = tx.send(Err(e)).await;
                break;
            }
        };
        // Production evaluates an empty write after anything the client already sent: a client
        // that half-closed right behind it gets a stream that ends OK (trailing-metadata),
        // one still waiting for the answer gets `empty write operation`
        // (response-before-half-close). Look once, without waiting.
        if state.parent.is_some()
            && req.writes.iter().any(|write| write.operation.is_none())
            && already_half_closed(&mut inbound)
        {
            break;
        }
        // Production refuses a first message carrying a token (ABORTED) while the client keeps
        // sending, but ends the stream OK when the client half-closes right behind it
        // (coordinator decision D5, 2026-09-27). A large message can finish arriving just
        // before its half-close does, so only this refusal waits, briefly, for the half-close.
        // The grace approximates production's processing time; it is not observed.
        if state.parent.is_none()
            && !req.stream_token.is_empty()
            && req.stream_id.is_empty()
            && req.writes.is_empty()
            && half_closes_before(
                &mut inbound,
                tokio::time::sleep(FIRST_TOKEN_HALF_CLOSE_GRACE),
            )
            .await
        {
            break;
        }
        let outcome = handle_write_request(&ctx, &mut state, &req);
        let stop = outcome.is_err();
        if tx.send(outcome).await.is_err() || stop {
            break;
        }
    }
}

/// How long a refused first-message token waits for the client's half-close (decision D5).
const FIRST_TOKEN_HALF_CLOSE_GRACE: std::time::Duration = std::time::Duration::from_millis(100);

/// Whether the client ends its side before `deadline` does. The end wins a tie; a message or
/// the deadline means the client is still sending.
async fn half_closes_before<S, D>(inbound: &mut S, deadline: D) -> bool
where
    S: tokio_stream::Stream + Unpin,
    D: std::future::Future<Output = ()>,
{
    tokio::select! {
        biased;
        next = inbound.next() => next.is_none(),
        () = deadline => false,
    }
}

/// Whether the client side of a stream has already ended, without waiting for it.
fn already_half_closed<S: tokio_stream::Stream + Unpin>(inbound: &mut S) -> bool {
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    matches!(
        std::pin::Pin::new(inbound).poll_next(&mut cx),
        std::task::Poll::Ready(None)
    )
}

fn token_bytes(prefix: u64, n: u64) -> Vec<u8> {
    let mut token = Vec::with_capacity(16);
    token.extend_from_slice(&prefix.to_be_bytes());
    token.extend_from_slice(&n.to_be_bytes());
    token
}

fn handle_write_request(
    ctx: &StreamContext,
    state: &mut WriteStreamState,
    req: &pb::WriteRequest,
) -> Result<pb::WriteResponse, Status> {
    let first = state.parent.is_none();
    if first {
        if req.database.is_empty() {
            return Err(Status::invalid_argument(
                "the first Write request must name the database",
            ));
        }
        if !req.stream_id.is_empty() {
            return Err(Status::failed_precondition(
                "write stream resumption is not supported; start a new stream",
            ));
        }
        if !req.stream_token.is_empty() {
            return Err(Status::aborted("resuming a stream not supported"));
        }
        if !req.writes.is_empty() {
            return Err(Status::invalid_argument(
                "the first Write request is the handshake and must carry no writes",
            ));
        }
        let parent = database_parent(&req.database)?;
        if parent.document.is_some() {
            return Err(Status::invalid_argument(
                "the first Write request must name the database root",
            ));
        }
        // The route and the target database are resolved; App Check decides before the
        // Firebase Auth credential, Security Rules and every mutation (section 7.4).
        ctx.admit_app_check(&parent, "Write")?;
        // Only then is the stream opened against a database that exists. A request refused
        // for two reasons answers with the same one here as on the unary paths, which
        // classify App Check before they touch any database.
        ctx.local.database_handle(&parent)?;
        state.parent = Some(parent);
    } else if !req.stream_id.is_empty() || !req.database.is_empty() {
        return Err(Status::invalid_argument(
            "stream_id / database are only valid on the first Write request",
        ));
    }
    let Some(parent) = state.parent.as_ref() else {
        return Err(Status::internal("write stream without database"));
    };
    if !req.stream_token.is_empty() {
        let acknowledged = req
            .stream_token
            .as_slice()
            .try_into()
            .ok()
            .and_then(|bytes: [u8; 16]| {
                let (prefix, sequence) = bytes.split_at(8);
                let prefix = u64::from_be_bytes(prefix.try_into().ok()?);
                let sequence = u64::from_be_bytes(sequence.try_into().ok()?);
                (prefix == state.token_prefix).then_some(sequence)
            })
            .unwrap_or(0);
        if acknowledged == 0 || acknowledged > state.issued || acknowledged < state.acknowledged {
            return Err(Status::failed_precondition("unknown write stream token"));
        }
        state.acknowledged = acknowledged;
    }
    state.issued += 1;
    let stream_id = if first {
        state.stream_id.clone()
    } else {
        String::new()
    };
    if req.writes.is_empty() {
        return Ok(pb::WriteResponse {
            stream_id,
            stream_token: token_bytes(state.token_prefix, state.issued),
            write_results: Vec::new(),
            commit_time: None,
        });
    }
    let writes = req
        .writes
        .iter()
        .map(decode_write)
        .collect::<Result<Vec<Write>, _>>()
        .map_err(status)?;
    for w in &writes {
        LocalBackend::check_database(parent, &w.op.path().resource_name())?;
    }
    let principal = ctx.refresh_principal(parent.project.as_str())?;
    let guard = write_guard(ctx.rules.as_ref(), &principal);
    // The epoch is re-checked inside the commit critical section: a reset that starts
    // after the check above cannot be raced by this write.
    let epoch = ctx.epoch;
    let local = ctx.local.clone();
    let actor = crate::local::Actor::from_principal(&principal);
    let guarded = move |db: &fireemu_core_firestore::store::FirestoreState,
                        writes: &[Write],
                        now: fireemu_core_types::time::LogicalInstant|
          -> Result<(), Status> {
        if local.epoch() != epoch {
            return Err(Status::aborted("the session was reset"));
        }
        local.set_actor(actor.clone());
        guard(db, writes, now)
    };
    let result = ctx.local.commit_writes(parent, &writes, &guarded)?;
    Ok(pb::WriteResponse {
        stream_id,
        stream_token: token_bytes(state.token_prefix, state.issued),
        write_results: result.write_results,
        commit_time: result.commit_time,
    })
}

// ---------------------------------------------------------------------------------------
// Listen stream
// ---------------------------------------------------------------------------------------

#[derive(Debug)]
enum TargetKind {
    Documents(Vec<DocumentPath>),
    Query(Box<Query>),
}

/// Where a re-added target resumes from.
enum Resume {
    /// A version the stream handed out earlier (or a read time).
    Version(CommitVersion),
    /// A read time: the version current at that instant, while it is still retained.
    ReadTime(fireemu_core_types::time::LogicalInstant),
    /// Not a token this daemon issued, or one whose version was compacted away: full replay
    /// after a `RESET`.
    Invalid,
}

// The flags are independent facts of one target (once, server-assigned id, current).
#[allow(clippy::struct_excessive_bools)]
struct TargetState {
    kind: TargetKind,
    target_hash: u64,
    parent: Parent,
    known: BTreeMap<DocumentPath, CommitVersion>,
    /// Pending resume, resolved on the first refresh (it needs the snapshot).
    resume: Option<Resume>,
    once: bool,
    /// The server picked this target's id (the request said 0).
    assigned: bool,
    /// How a strict resume of a query target is answered (see `ResumeAnswer`).
    resume_answer: ResumeAnswer,
    /// Reached its first consistent snapshot (`CURRENT` was sent).
    current: bool,
    /// Responses produced by the last refresh, drained by the caller.
    pending: Vec<pb::ListenResponse>,
}

#[derive(Debug, Clone)]
enum RefreshInput {
    Full,
    Delta {
        through: CommitVersion,
        paths: BTreeSet<DocumentPath>,
    },
}

#[derive(Debug, Clone, Copy)]
struct DatabaseHashCache {
    generation: u64,
    hash: u64,
}

/// Maximum targets one `Listen` stream may hold (spec 10.6: queue length caps are explicit,
/// never a silent drop); the web SDK multiplexes every listener of a client over one stream.
pub const MAX_LISTEN_TARGETS: usize = 1000;

/// Optional observer used by transports that need lifecycle diagnostics at the exact point
/// where one request has been applied and its response batch has been constructed.
pub(crate) trait ListenObserver: Send + Sync {
    fn exchange(&self, request: Option<&pb::ListenRequest>, responses: &[pb::ListenResponse]);
}

/// Runs the `Listen` stream.
///
/// Back-pressure: responses go out through a bounded channel and the loop awaits it, so a
/// slow client stalls the loop instead of growing a queue. Commits that land meanwhile
/// accumulate in the broadcast channel and are coalesced into one refresh (the diff
/// against the last known state covers every intervening commit), and a lagged broadcast
/// is the same one refresh.
pub async fn listen_stream(
    ctx: StreamContext,
    inbound: impl tokio_stream::Stream<Item = Result<pb::ListenRequest, Status>> + Unpin + Send,
    tx: mpsc::Sender<Result<pb::ListenResponse, Status>>,
) {
    listen_stream_observed(ctx, inbound, tx, None, ListenTransport::Grpc).await;
}

/// Which transport carries a `Listen` stream. Production's one-hour close was observed on native
/// gRPC streams only (AUTH-FS-CROSS stage 2), so only they take it; a `WebChannel` keeps its
/// stream as before.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ListenTransport {
    /// A native gRPC `Listen`.
    Grpc,
    /// A `Listen` over `WebChannel`.
    WebChannel,
}

/// Runs `Listen` with an optional transport observer. The observer sees a completed response
/// batch before the next inbound request can be processed, preventing pipelined target-ID reuse
/// from relabeling an earlier response.
#[allow(clippy::too_many_lines)]
pub(crate) async fn listen_stream_observed(
    ctx: StreamContext,
    mut inbound: impl tokio_stream::Stream<Item = Result<pb::ListenRequest, Status>> + Unpin + Send,
    tx: mpsc::Sender<Result<pb::ListenResponse, Status>>,
    observer: Option<Arc<dyn ListenObserver>>,
    transport: ListenTransport,
) {
    let mut parent: Option<Parent> = None;
    let mut targets: BTreeMap<i32, TargetState> = BTreeMap::new();
    let mut database_hash_cache = None;
    let mut last_snapshot_version = None;
    let mut events = ctx.local.subscribe();
    let stream_deadline = ctx
        .rules
        .as_ref()
        .filter(|_| transport == ListenTransport::Grpc)
        .and_then(|rules| rules.listen_stream_deadline(&ctx.principal));
    loop {
        let mut out: Vec<pb::ListenResponse> = Vec::new();
        let mut request = None;
        let until_deadline = until_stream_deadline(&ctx, stream_deadline);
        if until_deadline == Some(Duration::ZERO) {
            let _ = tx.send(Err(lifetime_reached())).await;
            return;
        }
        // At most a second at a time: a pinned clock moved past the deadline is noticed without
        // waiting for a commit, as the wall is.
        let deadline = async {
            match until_deadline {
                Some(wait) => tokio::time::sleep(wait.min(DEADLINE_CHECK)).await,
                None => std::future::pending().await,
            }
        };
        let outcome: Result<bool, Status> = tokio::select! {
            () = tx.closed() => Ok(false),
            // Woken at the deadline or to look again: the loop's head decides.
            () = deadline => Ok(true),
            msg = inbound.next() => match msg {
                None => Ok(false),
                Some(Err(e)) => Err(e),
                Some(Ok(_)) if deadline_reached(&ctx, stream_deadline) => Err(lifetime_reached()),
                Some(Ok(req)) => {
                    let result = handle_listen_request(
                        &ctx,
                        &mut parent,
                        &mut targets,
                        &req,
                        &mut database_hash_cache,
                        &mut last_snapshot_version,
                        &mut out,
                    ).map(|()| true);
                    request = Some(req);
                    result
                },
            },
            // A commit met after the deadline (a pinned clock moved past it) ends the stream
            // as the deadline does.
            ev = events.recv() => if deadline_reached(&ctx, stream_deadline) {
                Err(lifetime_reached())
            } else { match ev {
                Ok(first) => {
                    // Coalesce: every commit already queued behind this one is covered by
                    // the single refresh below.
                    let mut input = refresh_input_for_event(
                        parent.as_ref(),
                        last_snapshot_version,
                        &first,
                    );
                    let mut closed = false;
                    loop {
                        match events.try_recv() {
                            Ok(ev) => merge_refresh_event(
                                &mut input,
                                parent.as_ref(),
                                last_snapshot_version,
                                &ev,
                            ),
                            Err(tokio::sync::broadcast::error::TryRecvError::Lagged(_)) => {
                                input = Some(RefreshInput::Full);
                            }
                            Err(tokio::sync::broadcast::error::TryRecvError::Closed) => {
                                closed = true;
                                break;
                            }
                            Err(tokio::sync::broadcast::error::TryRecvError::Empty) => break,
                        }
                    }
                    if closed {
                        Ok(false)
                    } else if let Some(input) = input {
                        refresh_all(
                            &ctx,
                            parent.as_ref(),
                            &mut targets,
                            input,
                            &mut database_hash_cache,
                            &mut last_snapshot_version,
                            &mut out,
                        ).map(|()| true)
                    } else {
                        Ok(true)
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                    refresh_all(
                        &ctx,
                        parent.as_ref(),
                        &mut targets,
                        RefreshInput::Full,
                        &mut database_hash_cache,
                        &mut last_snapshot_version,
                        &mut out,
                    ).map(|()| true)
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => Ok(false),
            }},
        };
        if let Some(observer) = observer.as_ref() {
            observer.exchange(request.as_ref(), &out);
        }
        for r in out {
            if tx.send(Ok(r)).await.is_err() {
                return;
            }
        }
        match outcome {
            Ok(true) => {}
            Ok(false) => return,
            Err(e) => {
                let _ = tx.send(Err(e)).await;
                return;
            }
        }
    }
}

/// Whether a commit concerns the stream's database.
fn is_relevant(parent: Option<&Parent>, ev: &CommitNotification) -> bool {
    parent.is_some_and(|p| p.project.as_str() == ev.project && p.database.as_str() == ev.database)
}

fn refresh_input_for_event(
    parent: Option<&Parent>,
    last_snapshot_version: Option<CommitVersion>,
    event: &CommitNotification,
) -> Option<RefreshInput> {
    if !is_relevant(parent, event) {
        return None;
    }
    let Some(last) = last_snapshot_version else {
        return Some(RefreshInput::Full);
    };
    if event.reset {
        return Some(RefreshInput::Full);
    }
    let version = CommitVersion::from_value(event.version);
    if version <= last {
        return None;
    }
    if version.value() != last.value().saturating_add(1) {
        return Some(RefreshInput::Full);
    }
    Some(RefreshInput::Delta {
        through: version,
        paths: event
            .changes
            .iter()
            .map(|change| change.path.clone())
            .collect(),
    })
}

fn merge_refresh_event(
    input: &mut Option<RefreshInput>,
    parent: Option<&Parent>,
    last_snapshot_version: Option<CommitVersion>,
    event: &CommitNotification,
) {
    if !is_relevant(parent, event) {
        return;
    }
    if event.reset {
        *input = Some(RefreshInput::Full);
        return;
    }
    let Some(last) = last_snapshot_version else {
        *input = Some(RefreshInput::Full);
        return;
    };
    let version = CommitVersion::from_value(event.version);
    if version <= last {
        return;
    }
    match input {
        Some(RefreshInput::Delta { through, paths }) => {
            if version <= *through {
                return;
            }
            if version.value() != through.value().saturating_add(1) {
                *input = Some(RefreshInput::Full);
                return;
            }
            *through = version;
            paths.extend(event.changes.iter().map(|change| change.path.clone()));
        }
        None => {
            *input = refresh_input_for_event(parent, Some(last), event);
        }
        Some(RefreshInput::Full) => {}
    }
}

fn handle_listen_request(
    ctx: &StreamContext,
    parent: &mut Option<Parent>,
    targets: &mut BTreeMap<i32, TargetState>,
    req: &pb::ListenRequest,
    database_hash_cache: &mut Option<DatabaseHashCache>,
    last_snapshot_version: &mut Option<CommitVersion>,
    out: &mut Vec<pb::ListenResponse>,
) -> Result<(), Status> {
    if parent.is_none() {
        if req.database.is_empty() {
            return Err(Status::invalid_argument(
                "the first Listen request must name the database",
            ));
        }
        let resolved = database_parent(&req.database)?;
        // As on the Write stream: one decision, taken as soon as the database is known.
        ctx.admit_app_check(&resolved, "Listen")?;
        *parent = Some(resolved);
    }
    let Some(parent) = parent.as_ref() else {
        return Err(Status::internal("listen stream without database"));
    };
    match &req.target_change {
        Some(pb::listen_request::TargetChange::AddTarget(target)) => {
            let (id, assigned) = listen_target_id(ctx, target, targets)?;
            if targets.contains_key(&id) {
                // Production removes the new target and keeps the stream (and the first target)
                // listening: `native/target-protocol/duplicate-id`.
                out.push(removed_with_cause(
                    id,
                    &Status::already_exists(format!("Target ID already exists: {id}")),
                ));
                return Ok(());
            }
            if targets.len() >= MAX_LISTEN_TARGETS {
                return Err(Status::resource_exhausted(format!(
                    "this Listen stream already holds {MAX_LISTEN_TARGETS} targets"
                )));
            }
            // Decoding and validating the query is per-target work: the strict gateway can
            // refuse this one target (a missing composite index, a name outside the stream
            // database, a malformed query) while every other target on the stream is
            // unaffected. Production answers such a refusal with `REMOVE[id]` carrying the
            // cause and keeps the stream open, so a stream-level error is reserved for
            // session-wide or database-wide failures. Ending the stream here instead makes
            // the browser SDK read a transport failure and report `unavailable` rather than
            // the actionable cause.
            let kind = match decode_target(ctx, parent, target) {
                Ok(kind) => kind,
                Err(e) => {
                    out.extend(decode_refusal(id, &e));
                    return Ok(());
                }
            };
            if let Some(refusal) = malformed_token_refusal(ctx, parent, target, &kind, id) {
                out.push(refusal);
                return Ok(());
            }
            let target_hash = target_hash(&kind);
            let database_hash = synchronize_database_generation(
                parent,
                &ctx.local,
                database_hash_cache,
                targets,
                out,
            );
            out.push(target_change(
                pb::target_change::TargetChangeType::Add,
                vec![id],
                None,
                None,
            ));
            // A token is honoured only for the epoch, database and target it was issued
            // for: after a reset (or on another database / target) the version numbers
            // start over and would silently line up with unrelated history.
            let binding = TokenBinding {
                epoch: ctx.local.epoch(),
                strict: ctx.gateway.production_refusals(),
                database: database_hash,
                target: target_hash,
            };
            let resume = resume_of(target, &binding);
            let resume_answer = resume_answer_of(ctx, target, &kind);
            targets.insert(
                id,
                TargetState {
                    kind,
                    target_hash,
                    parent: parent.clone(),
                    known: BTreeMap::new(),
                    resume,
                    once: target.once,
                    assigned,
                    resume_answer,
                    current: false,
                    pending: Vec::new(),
                },
            );
            // Every target is brought to the same snapshot before one global boundary.
            refresh_all(
                ctx,
                Some(parent),
                targets,
                RefreshInput::Full,
                database_hash_cache,
                last_snapshot_version,
                out,
            )?;
        }
        Some(pb::listen_request::TargetChange::RemoveTarget(id)) => {
            if targets.remove(id).is_some() {
                out.push(target_change(
                    pb::target_change::TargetChangeType::Remove,
                    vec![*id],
                    None,
                    None,
                ));
            }
        }
        None => {}
    }
    Ok(())
}

/// The id a target is added under, and whether the server picked it.
///
/// Production assigns the smallest free positive id to a target sent with id 0 (FS-LISTEN-SDK L1,
/// `native/target-protocol/server-assigned-id` and `second-zero-id`), as the API documents and
/// the official emulator does. A negative id ends the stream with `INVALID_ARGUMENT` in production
/// (`negative-id`) and in the official emulator. Production also ends the stream when an explicit
/// id follows a server-assigned one (`id-after-assigned`); the official emulator accepts it, so
/// only strict refuses.
fn listen_target_id(
    ctx: &StreamContext,
    target: &pb::Target,
    targets: &BTreeMap<i32, TargetState>,
) -> Result<(i32, bool), Status> {
    choose_target_id(
        target.target_id,
        &targets.keys().copied().collect(),
        targets.values().any(|t| t.assigned),
        ctx.gateway.production_refusals(),
    )
    .map_err(Status::invalid_argument)
}

/// The decision of `listen_target_id`, without the stream: `requested` is the id on the wire,
/// `used` the ids active on the stream, `assigned_before` whether one of them was server-assigned
/// and `strict` whether production's refusals apply.
fn choose_target_id(
    requested: i32,
    used: &BTreeSet<i32>,
    assigned_before: bool,
    strict: bool,
) -> Result<(i32, bool), &'static str> {
    match requested {
        id if id < 0 => Err("target_id must not be negative"),
        0 => Ok((first_free_target_id(used), true)),
        _ if strict && assigned_before => {
            Err("an explicit target_id cannot follow a server-assigned one on this stream")
        }
        id => Ok((id, false)),
    }
}

/// Where an added target resumes from, if it names a token or a read time.
fn resume_of(target: &pb::Target, binding: &TokenBinding) -> Option<Resume> {
    match &target.resume_type {
        None => None,
        Some(pb::target::ResumeType::ResumeToken(bytes)) => {
            Some(parse_resume_token(bytes, binding))
        }
        Some(pb::target::ResumeType::ReadTime(t)) => Some(Resume::ReadTime(decode_instant(t))),
    }
}

/// The answer to a target that cannot be decoded. A refused index is acknowledged first and
/// removed after, as production does (`native/target-protocol/missing-index`: ADD[1], then
/// REMOVE[1] with code 9); any other refusal is a removal alone.
fn decode_refusal(id: i32, error: &Status) -> Vec<pb::ListenResponse> {
    let mut out = Vec::new();
    if error.code() == tonic::Code::FailedPrecondition {
        out.push(target_change(
            pb::target_change::TargetChangeType::Add,
            vec![id],
            None,
            None,
        ));
    }
    out.push(removed_with_cause(id, error));
    out
}

/// Bytes that are not a token at all: production removes the target with `INVALID_ARGUMENT` and
/// sends no ADD (`native/resume-token/invalid`, recorded with 11 bytes). The official emulator
/// ignores the token and replays everything, so only strict refuses; the emulator profile resets.
/// An empty token is not the recorded shape (production probably reads it as no token), so it is
/// not refused and keeps the reset.
fn malformed_token_refusal(
    ctx: &StreamContext,
    parent: &Parent,
    target: &pb::Target,
    kind: &TargetKind,
    id: i32,
) -> Option<pb::ListenResponse> {
    let binding = TokenBinding {
        epoch: ctx.local.epoch(),
        strict: ctx.gateway.production_refusals(),
        database: database_hash(parent, ctx.local.database_generation(parent)),
        target: target_hash(kind),
    };
    let malformed = matches!(
        &target.resume_type,
        Some(pb::target::ResumeType::ResumeToken(bytes))
            if !bytes.is_empty() && matches!(parse_resume_token(bytes, &binding), Resume::Invalid)
    );
    (ctx.gateway.production_refusals() && malformed)
        .then(|| removed_with_cause(id, &Status::invalid_argument("bad resume token")))
}

/// Whether `bytes` have the shape of an emulator-profile token (32 bytes).
fn is_token_shaped(bytes: &[u8]) -> bool {
    <[u8; 32]>::try_from(bytes).is_ok()
}

/// The smallest positive id not in `used`: what the server assigns to a target sent with id 0.
fn first_free_target_id(used: &BTreeSet<i32>) -> i32 {
    (1..=i32::MAX)
        .find(|id| !used.contains(id))
        .unwrap_or(i32::MAX)
}

fn decode_target(
    ctx: &StreamContext,
    parent: &Parent,
    target: &pb::Target,
) -> Result<TargetKind, Status> {
    match &target.target_type {
        Some(pb::target::TargetType::Documents(d)) => {
            let mut paths = Vec::with_capacity(d.documents.len());
            for name in &d.documents {
                let path = LocalBackend::check_database(parent, name)?;
                // A name listed twice is one document (one change, one in the count).
                if !paths.contains(&path) {
                    paths.push(path);
                }
            }
            Ok(TargetKind::Documents(paths))
        }
        Some(pb::target::TargetType::Query(q)) => {
            let query_parent = parse_parent(&q.parent).map_err(status)?;
            if query_parent.project != parent.project || query_parent.database != parent.database {
                return Err(Status::invalid_argument(
                    "query parent does not belong to the stream database",
                ));
            }
            let Some(pb::target::query_target::QueryType::StructuredQuery(sq)) = &q.query_type
            else {
                return Err(Status::invalid_argument(
                    "query target requires a structured_query",
                ));
            };
            if sq.find_nearest.is_some() {
                return Err(Status::unimplemented(
                    "Listen does not support findNearest targets",
                ));
            }
            let accepted = ctx.local.accepted_query(&query_parent, sq)?;
            Ok(TargetKind::Query(Box::new(accepted.query)))
        }
        None => Err(Status::invalid_argument("target without target_type")),
    }
}

/// The longest a held stream waits before it looks at its deadline again.
const DEADLINE_CHECK: Duration = Duration::from_secs(1);

/// How long until the stream's deadline on the session clock: zero once it has passed, `None`
/// when the stream has none. A clock that cannot be read counts as passed.
fn until_stream_deadline(
    ctx: &StreamContext,
    deadline: Option<LogicalInstant>,
) -> Option<Duration> {
    let deadline = deadline?;
    let Some(now) = ctx
        .rules
        .as_ref()
        .and_then(|rules| rules.session_now().ok())
    else {
        return Some(Duration::ZERO);
    };
    // The difference is signed: a deadline already passed is no wait at all.
    Some(
        deadline
            .checked_duration_since(now)
            .filter(|left| left.is_positive())
            .map_or(Duration::ZERO, |left| {
                Duration::from_nanos(u64::try_from(left.as_nanos()).unwrap_or(u64::MAX))
            }),
    )
}

fn deadline_reached(ctx: &StreamContext, deadline: Option<LogicalInstant>) -> bool {
    until_stream_deadline(ctx, deadline) == Some(Duration::ZERO)
}

/// How a held stream ends at its deadline. Production's front end resets the HTTP/2 stream
/// (`RST_STREAM`, `INTERNAL_ERROR`), which gRPC clients report as `INTERNAL` with their own text.
fn lifetime_reached() -> Status {
    Status::internal("the stream reached its one-hour lifetime")
}

/// Refreshes every target against one snapshot, then emits the global boundary. Targets
/// whose rules now deny are removed with a cause; `once` targets are removed after their
/// first consistent snapshot.
#[allow(clippy::too_many_lines)]
fn refresh_all(
    ctx: &StreamContext,
    parent: Option<&Parent>,
    targets: &mut BTreeMap<i32, TargetState>,
    mut input: RefreshInput,
    database_hash_cache: &mut Option<DatabaseHashCache>,
    last_snapshot_version: &mut Option<CommitVersion>,
    out: &mut Vec<pb::ListenResponse>,
) -> Result<(), Status> {
    let Some(parent) = parent else { return Ok(()) };
    // Authentication / reset failures end the stream (every target is removed with the
    // cause first, so the client learns why).
    let principal = match ctx.refresh_principal(parent.project.as_str()) {
        Ok(p) => p,
        Err(e) => {
            for id in targets.keys() {
                out.push(removed_with_cause(*id, &e));
            }
            targets.clear();
            return Err(e);
        }
    };
    // A refresh is a read: the fault plan has its say like for any other read.
    if let Err(e) = ctx
        .local
        .consult_faults(parent.project.as_str(), "firestore.read")
    {
        for id in targets.keys() {
            out.push(removed_with_cause(*id, &e));
        }
        targets.clear();
        return Err(e);
    }
    // One critical section: every target sees the same version, read time and documents.
    let expected_epoch = ctx.epoch;
    let local = ctx.local.clone();
    let snapshot = ctx
        .local
        .with_snapshot(parent, |db, version, read_at, generation| {
            let (database_hash, generation_changed) =
                cached_database_hash_at(parent, generation, database_hash_cache);
            if generation_changed {
                input = RefreshInput::Full;
                invalidate_targets(targets, out);
            }
            if local.epoch() != expected_epoch {
                return Err(Status::aborted("the session was reset"));
            }
            let read_time = encode_instant(read_at);
            let binding = TokenBinding {
                epoch: local.epoch(),
                strict: ctx.gateway.production_refusals(),
                database: database_hash,
                target: 0,
            };
            let token = resume_token(version, &binding);
            let delta_paths = complete_delta_paths(&input, version);
            let mut removed = Vec::new();
            for (id, state) in targets.iter_mut() {
                let refreshed = authorize_target(ctx, &principal, db, state).and_then(|()| {
                    if state.current && state.resume.is_none() {
                        if let Some(paths) = delta_paths {
                            if refresh_target_delta(db, *id, state, read_time, paths)?.is_some() {
                                return Ok(());
                            }
                        }
                    }
                    refresh_target_full(db, *id, state, read_time, &binding, version)
                });
                match refreshed {
                    Ok(()) => {
                        out.append(&mut state.pending);
                        if !state.current {
                            state.current = true;
                            let bound = TokenBinding {
                                target: state.target_hash,
                                ..binding
                            };
                            out.push(target_change(
                                pb::target_change::TargetChangeType::Current,
                                vec![*id],
                                Some(resume_token(version, &bound)),
                                Some(read_time),
                            ));
                        }
                    }
                    Err(e) => {
                        state.pending.clear();
                        out.push(removed_with_cause(*id, &e));
                        removed.push(*id);
                    }
                }
            }
            Ok((read_time, token, removed, version))
        });
    let (read_time, token, removed, version) = match snapshot.and_then(|r| r) {
        Ok(s) => s,
        Err(e) => {
            for id in targets.keys() {
                out.push(removed_with_cause(*id, &e));
            }
            targets.clear();
            return Err(e);
        }
    };
    *last_snapshot_version = Some(version);
    for id in removed {
        targets.remove(&id);
    }
    if targets.is_empty() {
        return Ok(());
    }
    // One global boundary closes the snapshot. The token it carries applies to every target
    // (production and the official emulator send no per-target NO_CHANGE after a change:
    // FS-LISTEN-SDK L1, `native/target-lifecycle/update` and `delete`); a target that became
    // current in this snapshot got its own token with CURRENT.
    out.push(target_change(
        pb::target_change::TargetChangeType::NoChange,
        vec![],
        Some(token),
        Some(read_time),
    ));
    let once: Vec<i32> = targets
        .iter()
        .filter(|(_, t)| t.once)
        .map(|(id, _)| *id)
        .collect();
    for id in once {
        targets.remove(&id);
        out.push(target_change(
            pb::target_change::TargetChangeType::Remove,
            vec![id],
            None,
            None,
        ));
    }
    Ok(())
}

fn authorize_target(
    ctx: &StreamContext,
    principal: &Principal,
    db: &fireemu_core_firestore::store::FirestoreState,
    state: &TargetState,
) -> Result<(), Status> {
    match &state.kind {
        TargetKind::Documents(paths) => {
            if let Some(rules) = &ctx.rules {
                let items = paths
                    .iter()
                    .map(|path| (path.clone(), db.get(path).cloned()))
                    .collect::<Vec<_>>();
                let reader = crate::rules::StateReader {
                    db,
                    parent: &state.parent,
                    version: None,
                };
                rules.authorize_gets(principal, &items, &reader)?;
            }
        }
        TargetKind::Query(query) => {
            if let Some(rules) = &ctx.rules {
                let reader = crate::rules::StateReader {
                    db,
                    parent: &state.parent,
                    version: None,
                };
                rules.authorize_query(principal, &state.parent, query, &reader)?;
            }
        }
    }
    Ok(())
}

/// Recomputes one target and appends the diff against its last known state.
///
/// A resumed target starts with a global boundary, as production answers a resume
/// (AUTH-FS-CROSS stage 2, packet v7): its token is `boundary`'s for the resume point, so a
/// stream that drops before the diff resumes from there again. Strict uses the resume
/// point's read time (D7(a)); the emulator uses the new snapshot's read time. If the commit
/// time is unavailable, both keep the snapshot's read time. The client raises its snapshot
/// from its cache there, not current, until `CURRENT`.
fn refresh_target_full(
    db: &fireemu_core_firestore::store::FirestoreState,
    id: i32,
    state: &mut TargetState,
    read_time: prost_types::Timestamp,
    boundary: &TokenBinding,
    snapshot_version: CommitVersion,
) -> Result<(), Status> {
    let resumed = resolve_resume(db, id, state)?;
    if let Some((from, resume_time)) = resumed {
        let echo_time = if boundary.strict {
            resume_time.map_or(read_time, encode_instant)
        } else {
            read_time
        };
        state.pending.push(target_change(
            pb::target_change::TargetChangeType::NoChange,
            vec![],
            Some(resume_token(from, boundary)),
            Some(echo_time),
        ));
    }
    // How production answers this resume: see `ResumeAnswer`.
    let answer = if resumed.is_some() {
        state.resume_answer
    } else {
        ResumeAnswer::Exact
    };
    let current: Vec<Document> = match &state.kind {
        TargetKind::Documents(paths) => paths
            .iter()
            .filter_map(|path| db.get(path).cloned())
            .collect(),
        TargetKind::Query(query) => db
            .run_query(query, None)
            .map_err(|error| crate::encode::status_from_error(&error))?,
    };
    let mut next_known: BTreeMap<DocumentPath, CommitVersion> = BTreeMap::new();
    let mut changed = 0_usize;
    for doc in &current {
        next_known.insert(doc.path.clone(), doc.version);
        if state.known.get(&doc.path) != Some(&doc.version) {
            changed += 1;
            out_change(doc, id, &mut state.pending);
        }
    }
    let departed: Vec<&DocumentPath> = state
        .known
        .keys()
        .filter(|path| !next_known.contains_key(*path))
        .collect();
    // Exactly one commit since the token, and what it did is one departure: production replayed
    // it, a boundary after the removal message and no filter (`native/resume-kinds/leave` and
    // `delete`, both L1b runs).
    let one_commit_departure = answer == ResumeAnswer::CountOnly
        && changed == 0
        && departed.len() == 1
        && resumed
            .is_some_and(|(from, _)| from.value().checked_add(1) == Some(snapshot_version.value()));
    match answer {
        ResumeAnswer::CountOnly if one_commit_departure => {
            out_removal(db, departed[0], id, read_time, &mut state.pending);
            state.pending.push(target_change(
                pb::target_change::TargetChangeType::NoChange,
                vec![],
                Some(resume_token(snapshot_version, boundary)),
                Some(read_time),
            ));
        }
        ResumeAnswer::CountOnly => {
            // With the count filter the client finds the removals by the count, as production
            // leaves them to it (`native/existence-filter/without-expected-count`, both runs).
            state.pending.push(count_only_filter(id, current.len()));
        }
        ResumeAnswer::BloomWhenUnchanged | ResumeAnswer::Exact => {
            for path in &departed {
                out_removal(db, path, id, read_time, &mut state.pending);
            }
            // A client that gave an expected count and lost no document is answered with the bloom
            // filter of the documents the target matches, whatever its count was (`resume-grid-*`
            // k1-expected, k2-expected, k2-wrong, both L1b runs).
            if answer == ResumeAnswer::BloomWhenUnchanged && departed.is_empty() {
                let names: Vec<String> =
                    current.iter().map(|doc| doc.path.resource_name()).collect();
                if let Some(bloom) = crate::bloom::Bloom::for_documents(&names) {
                    state.pending.push(existence_filter(
                        id,
                        current.len(),
                        Some(bloom.into_proto()),
                    ));
                }
            }
        }
    }
    state.known = next_known;
    Ok(())
}

/// How a strict resume by token of a query target is answered. Production answered a resume with
/// an exact replay of the changes, and, depending on the request, with an existence filter.
///
/// - `CountOnly`: no expected count. The replay ends with a count-only existence filter and the
///   removals are left to the count, in four L1 rows (`native/resume-token/older`, `other-query`,
///   `native/existence-filter/without-expected-count`, `native/resume-token-expired/expired`) and
///   most L1b rows; the one-commit departure is the exception (`refresh_target_full`). Some
///   one-commit modifications were replayed instead, in some runs and not in others (the L1b
///   reading): this answer is one of the two production gave, so strict keeps it.
///   "One commit" is database-wide (the token's version + 1 is the snapshot version): an unrelated
///   commit in between makes a departure fall back to this answer, narrower than one commit on the
///   target and enough for the recorded shape.
/// - `BloomWhenUnchanged`: an expected count. The diff ends with a bloom filter of the documents
///   the target matches (see `bloom`) when no document left; a departure keeps the removal
///   messages and no filter (L1's `with-expected-count`).
/// - `Exact`: the diff and nothing else: a profile that follows the official emulator, a target
///   that is not a resumed query, and what production's rows do not decide.
///
/// The official emulator never sends an existence filter (it resets the target on a resume), so
/// the emulator profile is always `Exact`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResumeAnswer {
    Exact,
    CountOnly,
    BloomWhenUnchanged,
}

/// The `ResumeAnswer` of a target. Only strict (production's refusals), only a query target
/// resumed by a token of this daemon's shape; whether the request gave an expected count decides
/// between the two answers. An SDK always gives one.
fn resume_answer_of(ctx: &StreamContext, target: &pb::Target, kind: &TargetKind) -> ResumeAnswer {
    let resumed_query = ctx.gateway.production_refusals()
        && matches!(kind, TargetKind::Query(_))
        && matches!(
            &target.resume_type,
            Some(pb::target::ResumeType::ResumeToken(bytes)) if bytes.len() == 11
        );
    match (resumed_query, target.expected_count.is_some()) {
        (false, _) => ResumeAnswer::Exact,
        (true, false) => ResumeAnswer::CountOnly,
        (true, true) => ResumeAnswer::BloomWhenUnchanged,
    }
}

/// The recorded count-only existence filter: the target, the number of documents it matches and
/// an empty bloom filter (hash count 0, no bitmap, no padding), as production sent it in the rows
/// above.
fn count_only_filter(id: i32, count: usize) -> pb::ListenResponse {
    existence_filter(
        id,
        count,
        Some(pb::BloomFilter {
            bits: Some(pb::BitSequence {
                bitmap: Vec::new(),
                padding: 0,
            }),
            hash_count: 0,
        }),
    )
}

fn existence_filter(
    id: i32,
    count: usize,
    unchanged: Option<pb::BloomFilter>,
) -> pb::ListenResponse {
    pb::ListenResponse {
        response_type: Some(pb::listen_response::ResponseType::Filter(
            pb::ExistenceFilter {
                target_id: id,
                count: i32::try_from(count).unwrap_or(i32::MAX),
                unchanged_names: unchanged,
            },
        )),
    }
}

/// Applies one complete changed-path set to a target. Returns `false` when the query shape
/// has nonlocal membership and requires a full refresh.
fn refresh_target_delta(
    db: &fireemu_core_firestore::store::FirestoreState,
    id: i32,
    state: &mut TargetState,
    read_time: prost_types::Timestamp,
    changed_paths: &BTreeSet<DocumentPath>,
) -> Result<Option<usize>, Status> {
    let mut examined = 0;
    match &state.kind {
        TargetKind::Documents(paths) => {
            for path in paths.iter().filter(|path| changed_paths.contains(*path)) {
                examined += 1;
                match db.get(path) {
                    Some(document) => {
                        if state.known.get(path) != Some(&document.version) {
                            out_change(document, id, &mut state.pending);
                            state.known.insert(path.clone(), document.version);
                        }
                    }
                    None => {
                        if state.known.remove(path).is_some() {
                            out_removal(db, path, id, read_time, &mut state.pending);
                        }
                    }
                }
            }
        }
        TargetKind::Query(query) => {
            let changed_documents = changed_paths
                .iter()
                .filter_map(|path| db.get(path))
                .collect::<Vec<_>>();
            let Some(matched) = db
                .run_incremental_query(query, changed_documents)
                .map_err(|error| crate::encode::status_from_error(&error))?
            else {
                return Ok(None);
            };
            examined = changed_paths.len();
            let matched_paths = matched
                .iter()
                .map(|document| document.path.clone())
                .collect::<BTreeSet<_>>();
            for document in &matched {
                if state.known.get(&document.path) != Some(&document.version) {
                    out_change(document, id, &mut state.pending);
                    state.known.insert(document.path.clone(), document.version);
                }
            }
            for path in changed_paths {
                if !matched_paths.contains(path) && state.known.remove(path).is_some() {
                    out_removal(db, path, id, read_time, &mut state.pending);
                }
            }
        }
    }
    Ok(Some(examined))
}

fn complete_delta_paths(
    input: &RefreshInput,
    snapshot_version: CommitVersion,
) -> Option<&BTreeSet<DocumentPath>> {
    match input {
        RefreshInput::Delta { through, paths } if *through == snapshot_version => Some(paths),
        RefreshInput::Full | RefreshInput::Delta { .. } => None,
    }
}

/// A document that left the target. One that still exists (it stopped matching) goes as a
/// document change that names the target in `removed_target_ids`, as production sends it
/// (`native/existence-filter/with-expected-count`: a change with removed ids and no target ids);
/// a deleted one goes as a `DocumentDelete`.
fn out_removal(
    db: &fireemu_core_firestore::store::FirestoreState,
    path: &DocumentPath,
    id: i32,
    read_time: prost_types::Timestamp,
    out: &mut Vec<pb::ListenResponse>,
) {
    let response_type = if let Some(document) = db.get(path) {
        pb::listen_response::ResponseType::DocumentChange(pb::DocumentChange {
            document: Some(encode_document(document)),
            target_ids: vec![],
            removed_target_ids: vec![id],
        })
    } else {
        pb::listen_response::ResponseType::DocumentDelete(pb::DocumentDelete {
            document: path.resource_name(),
            removed_target_ids: vec![id],
            read_time: Some(read_time),
        })
    };
    out.push(pb::ListenResponse {
        response_type: Some(response_type),
    });
}

/// Resume: the target's state at the token becomes the known state, so the diff carries
/// exactly what changed since; a token this daemon cannot honour resets the target.
/// Returns the resumed version and its read time, when available.
///
/// "Cannot honour" includes a version the store compacted away: history older than the
/// retention window is gone, and replaying a target against a version the store can no
/// longer describe would produce a diff against unrelated history. Such a token is refused
/// like an unknown one -- `RESET`, then a full replay.
fn resolve_resume(
    db: &fireemu_core_firestore::store::FirestoreState,
    id: i32,
    state: &mut TargetState,
) -> Result<Option<(CommitVersion, Option<LogicalInstant>)>, Status> {
    let Some(resume) = state.resume.take() else {
        return Ok(None);
    };
    let (version, read_time) = match resume {
        Resume::Version(v) => (Some(v), db.commit_time_of(v)),
        Resume::ReadTime(t) => (db.version_at_retained(t), Some(t)),
        Resume::Invalid => (None, None),
    };
    let version = version.filter(|v| db.is_retained(*v));
    if let Some(v) = version {
        state.known = known_at(db, &state.kind, v)?;
        return Ok(Some((v, read_time)));
    }
    state.pending.push(target_change(
        pb::target_change::TargetChangeType::Reset,
        vec![id],
        None,
        None,
    ));
    Ok(None)
}

/// What a resume token is bound to besides its version.
#[derive(Debug, Clone, Copy)]
struct TokenBinding {
    /// Strict uses the recorded 11-byte length; the emulator keeps 32 bytes.
    strict: bool,
    /// Backend reset epoch.
    epoch: u64,
    /// Hash of the project / database.
    database: u64,
    /// Hash of the target definition; `0` in the global boundary that applies to every
    /// target.
    target: u64,
}

/// FNV-1a over `text`.
fn fnv(text: &str) -> u64 {
    text.bytes().fold(0xcbf2_9ce4_8422_2325_u64, |h, b| {
        (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3)
    })
}

fn database_hash(parent: &Parent, generation: u64) -> u64 {
    fnv(&format!(
        "{}/{}#{generation}",
        parent.project.as_str(),
        parent.database.as_str()
    ))
}

fn cached_database_hash(
    parent: &Parent,
    local: &LocalBackend,
    cache: &mut Option<DatabaseHashCache>,
) -> (u64, bool) {
    let generation = local.database_generation(parent);
    cached_database_hash_at(parent, generation, cache)
}

fn cached_database_hash_at(
    parent: &Parent,
    generation: u64,
    cache: &mut Option<DatabaseHashCache>,
) -> (u64, bool) {
    if let Some(cached) = cache {
        if cached.generation == generation {
            return (cached.hash, false);
        }
    }
    let generation_changed = cache.is_some();
    let hash = database_hash(parent, generation);
    *cache = Some(DatabaseHashCache { generation, hash });
    (hash, generation_changed)
}

fn synchronize_database_generation(
    parent: &Parent,
    local: &LocalBackend,
    cache: &mut Option<DatabaseHashCache>,
    targets: &mut BTreeMap<i32, TargetState>,
    out: &mut Vec<pb::ListenResponse>,
) -> u64 {
    let (hash, generation_changed) = cached_database_hash(parent, local, cache);
    if generation_changed {
        invalidate_targets(targets, out);
    }
    hash
}

fn invalidate_targets(targets: &mut BTreeMap<i32, TargetState>, out: &mut Vec<pb::ListenResponse>) {
    for (id, state) in targets {
        state.known.clear();
        state.resume = None;
        state.current = false;
        state.pending.clear();
        out.push(target_change(
            pb::target_change::TargetChangeType::Reset,
            vec![*id],
            None,
            None,
        ));
    }
}

fn target_hash(kind: &TargetKind) -> u64 {
    fnv(&format!("{kind:?}"))
}

/// Strict: 8-byte big-endian version and a 3-byte binding check. Emulator: four 8-byte words.
/// The truncated check can collide; it is an opaque binding check, not authentication.
fn resume_token(version: CommitVersion, binding: &TokenBinding) -> Vec<u8> {
    let mut out = Vec::with_capacity(32);
    out.extend_from_slice(&version.value().to_be_bytes());
    if binding.strict {
        let check = fnv(&format!(
            "{}/{}/{}",
            binding.epoch, binding.database, binding.target
        ));
        out.extend_from_slice(&check.to_be_bytes()[5..]);
        return out;
    }
    out.extend_from_slice(&binding.epoch.to_be_bytes());
    out.extend_from_slice(&binding.database.to_be_bytes());
    out.extend_from_slice(&binding.target.to_be_bytes());
    out
}

/// A token this daemon issued for this epoch, database and target (or for every target).
fn parse_resume_token(bytes: &[u8], binding: &TokenBinding) -> Resume {
    if binding.strict {
        let Ok(raw) = <[u8; 11]>::try_from(bytes) else {
            return Resume::Invalid;
        };
        let version =
            CommitVersion::from_value(u64::from_be_bytes(raw[..8].try_into().unwrap_or([0; 8])));
        let global = TokenBinding {
            target: 0,
            ..*binding
        };
        if raw[8..] != resume_token(version, binding)[8..]
            && raw[8..] != resume_token(version, &global)[8..]
        {
            return Resume::Invalid;
        }
        return Resume::Version(version);
    }
    if !is_token_shaped(bytes) {
        return Resume::Invalid;
    }
    let Ok(raw) = <[u8; 32]>::try_from(bytes) else {
        return Resume::Invalid;
    };
    let word = |i: usize| u64::from_be_bytes(raw[i * 8..i * 8 + 8].try_into().unwrap_or([0; 8]));
    let (version, epoch, database, target) = (word(0), word(1), word(2), word(3));
    if epoch != binding.epoch
        || database != binding.database
        || (target != 0 && target != binding.target)
    {
        return Resume::Invalid;
    }
    Resume::Version(CommitVersion::from_value(version))
}

/// The `(path, version)` set of a target as of `version`.
fn known_at(
    db: &fireemu_core_firestore::store::FirestoreState,
    kind: &TargetKind,
    version: CommitVersion,
) -> Result<BTreeMap<DocumentPath, CommitVersion>, Status> {
    let docs: Vec<Document> = match kind {
        TargetKind::Documents(paths) => paths
            .iter()
            .filter_map(|p| db.get_at(p, version).cloned())
            .collect(),
        TargetKind::Query(query) => db
            .run_query(query, Some(version))
            .map_err(|e| crate::encode::status_from_error(&e))?,
    };
    Ok(docs.into_iter().map(|d| (d.path, d.version)).collect())
}

fn out_change(doc: &Document, id: i32, out: &mut Vec<pb::ListenResponse>) {
    out.push(pb::ListenResponse {
        response_type: Some(pb::listen_response::ResponseType::DocumentChange(
            pb::DocumentChange {
                document: Some(encode_document(doc)),
                target_ids: vec![id],
                removed_target_ids: vec![],
            },
        )),
    });
}

fn target_change(
    kind: pb::target_change::TargetChangeType,
    target_ids: Vec<i32>,
    resume_token: Option<Vec<u8>>,
    read_time: Option<prost_types::Timestamp>,
) -> pb::ListenResponse {
    pb::ListenResponse {
        response_type: Some(pb::listen_response::ResponseType::TargetChange(
            pb::TargetChange {
                target_change_type: kind as i32,
                target_ids,
                cause: None,
                resume_token: resume_token.unwrap_or_default(),
                read_time,
            },
        )),
    }
}

fn removed_with_cause(id: i32, e: &Status) -> pb::ListenResponse {
    pb::ListenResponse {
        response_type: Some(pb::listen_response::ResponseType::TargetChange(
            pb::TargetChange {
                target_change_type: pb::target_change::TargetChangeType::Remove as i32,
                target_ids: vec![id],
                cause: Some(fireemu_proto_firestore::google::rpc::Status {
                    code: i32::from(e.code()),
                    message: e.message().to_owned(),
                    details: Vec::new(),
                }),
                resume_token: Vec::new(),
                read_time: None,
            },
        )),
    }
}

/// Commit result in wire form (shared by the write stream).
pub struct WireCommit {
    /// Per-write results.
    pub write_results: Vec<pb::WriteResult>,
    /// Commit time.
    pub commit_time: Option<prost_types::Timestamp>,
}

impl WireCommit {
    /// Converts a core commit result.
    #[must_use]
    pub fn from_result(result: &fireemu_core_firestore::store::CommitResult) -> Self {
        let encoded = crate::local::encode_commit(result);
        Self {
            write_results: encoded.write_results,
            commit_time: encoded.commit_time,
        }
    }
}

#[cfg(test)]
mod refresh_tests {
    use super::*;
    use crate::local::{CommitChangeKind, CommitPathChange, FirestoreSnapshot};
    use fireemu_core_firestore::field_path::FieldPath;
    use fireemu_core_firestore::index::{
        IndexDefinition, IndexField, IndexFieldMode, IndexQueryScope, IndexSet,
        IndexValidationPolicy, PlanningContext,
    };
    use fireemu_core_firestore::store::{FirestoreState, WriteOp};
    use fireemu_core_firestore::value::Value;
    use fireemu_core_session::clock::VirtualClock;
    use fireemu_core_session::tenancy::Scope;
    use fireemu_core_types::edition::{FirestoreApiMode, FirestoreEdition};
    use fireemu_core_types::ids::CollectionId;
    use fireemu_core_types::time::LogicalInstant;

    fn path(relative: &str) -> DocumentPath {
        crate::encode::decode_document_name(&format!(
            "projects/demo-app/databases/{}/documents/{relative}",
            fireemu_core_types::ids::DatabaseId::DEFAULT,
        ))
        .unwrap()
    }

    fn set(relative: &str) -> Write {
        Write {
            op: WriteOp::Set {
                path: path(relative),
                fields: BTreeMap::new(),
                update_mask: None,
            },
            precondition: None,
            transforms: Vec::new(),
        }
    }

    fn notification(version: u64, relative: &str) -> CommitNotification {
        CommitNotification {
            project: "demo-app".to_owned(),
            database: fireemu_core_types::ids::DatabaseId::DEFAULT.to_owned(),
            version,
            reset: false,
            changes: Arc::from([CommitPathChange {
                path: path(relative),
                kind: CommitChangeKind::Updated,
            }]),
        }
    }

    fn state_with_value(value: &str) -> FirestoreState {
        let mut state = FirestoreState::new();
        let mut write = set("restored/a");
        let WriteOp::Set { fields, .. } = &mut write.op else {
            unreachable!();
        };
        fields.insert("v".to_owned(), Value::String(value.to_owned()));
        state
            .commit(&[write], None, LogicalInstant::UNIX_EPOCH)
            .unwrap();
        state
    }

    fn query_request(id: i32, collection: &str) -> pb::ListenRequest {
        pb::ListenRequest {
            database: "projects/demo-app/databases/(default)".to_owned(),
            target_change: Some(pb::listen_request::TargetChange::AddTarget(pb::Target {
                target_id: id,
                target_type: Some(pb::target::TargetType::Query(pb::target::QueryTarget {
                    parent: "projects/demo-app/databases/(default)/documents".to_owned(),
                    query_type: Some(pb::target::query_target::QueryType::StructuredQuery(
                        pb::StructuredQuery {
                            from: vec![pb::structured_query::CollectionSelector {
                                collection_id: collection.to_owned(),
                                all_descendants: false,
                            }],
                            ..Default::default()
                        },
                    )),
                })),
                ..Default::default()
            })),
            ..Default::default()
        }
    }

    #[test]
    fn listen_decoder_refuses_find_nearest_targets() {
        let fixture = generation_fixture();
        let parent = fixture.parent.as_ref().unwrap();
        let mut request = query_request(1, "restored");
        let Some(pb::listen_request::TargetChange::AddTarget(target)) = &mut request.target_change
        else {
            unreachable!();
        };
        let Some(pb::target::TargetType::Query(query)) = &mut target.target_type else {
            unreachable!();
        };
        let Some(pb::target::query_target::QueryType::StructuredQuery(structured)) =
            &mut query.query_type
        else {
            unreachable!();
        };
        structured.find_nearest = Some(pb::structured_query::FindNearest {
            vector_field: Some(pb::structured_query::FieldReference {
                field_path: "embedding".to_owned(),
            }),
            query_vector: Some(pb::Value {
                value_type: Some(pb::value::ValueType::MapValue(pb::MapValue {
                    fields: [
                        (
                            "__type__".to_owned(),
                            pb::Value {
                                value_type: Some(pb::value::ValueType::StringValue(
                                    "__vector__".to_owned(),
                                )),
                            },
                        ),
                        (
                            "value".to_owned(),
                            pb::Value {
                                value_type: Some(pb::value::ValueType::ArrayValue(
                                    pb::ArrayValue {
                                        values: vec![pb::Value {
                                            value_type: Some(pb::value::ValueType::DoubleValue(
                                                1.0,
                                            )),
                                        }],
                                    },
                                )),
                            },
                        ),
                    ]
                    .into_iter()
                    .collect(),
                })),
            }),
            distance_measure: pb::structured_query::find_nearest::DistanceMeasure::Euclidean as i32,
            limit: Some(1),
            ..Default::default()
        });
        let Some(pb::listen_request::TargetChange::AddTarget(target)) = request.target_change
        else {
            unreachable!();
        };
        let error = decode_target(&fixture.context, parent, &target).unwrap_err();
        assert_eq!(error.code(), tonic::Code::Unimplemented);
        assert!(error.message().contains("findNearest"));
    }

    struct GenerationFixture {
        context: StreamContext,
        scope: Scope,
        parent: Option<Parent>,
        cache: Option<DatabaseHashCache>,
        targets: BTreeMap<i32, TargetState>,
        last_snapshot_version: Option<CommitVersion>,
    }

    fn generation_fixture() -> GenerationFixture {
        let gateway = Gateway {
            enforce_limits: true,
            ctx: PlanningContext {
                edition: FirestoreEdition::Standard,
                api_mode: FirestoreApiMode::Native,
                policy: IndexValidationPolicy::Production,
            },
            indexes: {
                let mut indexes = IndexSet::default();
                indexes.add_composite(IndexDefinition {
                    collection_group: CollectionId::try_new("restored").unwrap(),
                    query_scope: IndexQueryScope::Collection,
                    fields: vec![IndexField {
                        path: FieldPath::parse("embedding").unwrap(),
                        mode: IndexFieldMode::Vector { dimension: 1 },
                    }],
                });
                indexes
            },
        };
        let clock = Arc::new(std::sync::Mutex::new(VirtualClock::new(
            LogicalInstant::UNIX_EPOCH,
        )));
        let local = Arc::new(LocalBackend::new(gateway.clone(), clock, 7));
        let scope = Scope::Project("demo-app".to_owned());
        local
            .restore_scope(&scope, &restored_snapshot("before"))
            .unwrap();
        let parent = database_parent("projects/demo-app/databases/(default)").unwrap();
        let generation = local.database_generation(&parent);
        let query = Query::new(fireemu_core_firestore::query::QueryScope::collection(
            None,
            CollectionId::try_new("restored").unwrap(),
        ));
        let targets = BTreeMap::from([(
            1,
            TargetState {
                target_hash: target_hash(&TargetKind::Query(Box::new(query.clone()))),
                kind: TargetKind::Query(Box::new(query)),
                parent: parent.clone(),
                known: BTreeMap::from([(path("restored/a"), CommitVersion::from_value(1))]),
                resume: None,
                once: false,
                assigned: false,
                resume_answer: ResumeAnswer::Exact,
                current: true,
                pending: Vec::new(),
            },
        )]);
        GenerationFixture {
            context: StreamContext {
                local: local.clone(),
                gateway: Arc::new(gateway),
                rules: None,
                principal: Principal::Owner,
                authorization: None,
                epoch: local.epoch(),
                app_check: None,
            },
            scope,
            parent: Some(parent.clone()),
            cache: Some(DatabaseHashCache {
                generation,
                hash: database_hash(&parent, generation),
            }),
            targets,
            last_snapshot_version: Some(CommitVersion::from_value(1)),
        }
    }

    fn restored_snapshot(value: &str) -> FirestoreSnapshot {
        FirestoreSnapshot {
            databases: BTreeMap::from([(
                (
                    "demo-app".to_owned(),
                    fireemu_core_types::ids::DatabaseId::DEFAULT.to_owned(),
                ),
                state_with_value(value),
            )]),
            ids: None,
        }
    }

    fn assert_reset_replay(out: &[pb::ListenResponse], value: &str) {
        assert!(out.iter().any(|response| matches!(
            &response.response_type,
            Some(pb::listen_response::ResponseType::TargetChange(change))
                if change.target_change_type == pb::target_change::TargetChangeType::Reset as i32
                    && change.target_ids == [1]
        )));
        let replay = out
            .iter()
            .find_map(|response| match &response.response_type {
                Some(pb::listen_response::ResponseType::DocumentChange(change))
                    if change.target_ids == [1] =>
                {
                    change
                        .document
                        .as_ref()?
                        .fields
                        .get("v")?
                        .value_type
                        .as_ref()
                }
                _ => None,
            });
        assert_eq!(
            replay,
            Some(&pb::value::ValueType::StringValue(value.to_owned()))
        );
    }

    #[test]
    fn add_target_cannot_consume_a_restore_generation_before_existing_targets_reset() {
        let mut fixture = generation_fixture();
        fixture
            .context
            .local
            .restore_scope(&fixture.scope, &restored_snapshot("after"))
            .unwrap();
        let mut out = Vec::new();

        handle_listen_request(
            &fixture.context,
            &mut fixture.parent,
            &mut fixture.targets,
            &query_request(2, "second"),
            &mut fixture.cache,
            &mut fixture.last_snapshot_version,
            &mut out,
        )
        .unwrap();
        assert_reset_replay(&out, "after");

        out.clear();
        let current_hash = synchronize_database_generation(
            fixture.parent.as_ref().unwrap(),
            &fixture.context.local,
            &mut fixture.cache,
            &mut fixture.targets,
            &mut out,
        );
        assert!(out.is_empty());
        fixture
            .context
            .local
            .restore_scope(&fixture.scope, &restored_snapshot("after-precheck"))
            .unwrap();
        refresh_all(
            &fixture.context,
            fixture.parent.as_ref(),
            &mut fixture.targets,
            RefreshInput::Full,
            &mut fixture.cache,
            &mut fixture.last_snapshot_version,
            &mut out,
        )
        .unwrap();
        assert_ne!(
            current_hash,
            fixture
                .cache
                .expect("snapshot refresh caches the restored generation")
                .hash
        );
        assert_reset_replay(&out, "after-precheck");
    }

    #[test]
    fn adjacent_notifications_coalesce_paths_and_gaps_force_a_full_refresh() {
        let parent = database_parent("projects/demo-app/databases/(default)").unwrap();
        let last = Some(CommitVersion::from_value(1));
        let mut input = refresh_input_for_event(Some(&parent), last, &notification(2, "items/a"));
        merge_refresh_event(&mut input, Some(&parent), last, &notification(3, "items/b"));
        let Some(RefreshInput::Delta { through, paths }) = input else {
            panic!("adjacent notifications must remain incremental");
        };
        assert_eq!(through, CommitVersion::from_value(3));
        assert_eq!(paths, BTreeSet::from([path("items/a"), path("items/b")]));

        let mut input = Some(RefreshInput::Delta { through, paths });
        merge_refresh_event(&mut input, Some(&parent), last, &notification(5, "items/c"));
        assert!(matches!(input, Some(RefreshInput::Full)));

        merge_refresh_event(&mut input, Some(&parent), last, &notification(6, "items/d"));
        assert!(matches!(input, Some(RefreshInput::Full)));
    }

    #[test]
    fn resume_echo_without_a_commit_time_keeps_the_snapshot_read_time() {
        let mut fixture = generation_fixture();
        let mut target = fixture.targets.remove(&1).unwrap();
        let database = FirestoreState::new();
        let version = database.current_version();
        let read_time = encode_instant(LogicalInstant::from_unix_seconds(10));
        let binding = TokenBinding {
            strict: true,
            epoch: 0,
            database: 0,
            target: 0,
        };
        target.resume = Some(Resume::Version(version));
        refresh_target_full(&database, 1, &mut target, read_time, &binding, version).unwrap();
        let Some(pb::listen_response::ResponseType::TargetChange(echo)) =
            &target.pending[0].response_type
        else {
            panic!("expected resume echo")
        };
        assert_eq!(echo.read_time, Some(read_time));
        assert_eq!(echo.resume_token, resume_token(version, &binding));
    }

    #[test]
    fn document_delta_counts_only_intersecting_paths_and_suppresses_unchanged_versions() {
        let mut database = FirestoreState::new();
        let mut updated = set("target/a");
        let WriteOp::Set { fields, .. } = &mut updated.op else {
            unreachable!();
        };
        fields.insert("revision".to_owned(), Value::Integer(2));
        database
            .commit(&[updated], None, LogicalInstant::UNIX_EPOCH)
            .unwrap();
        let document = database.get(&path("target/a")).unwrap();
        let parent = database_parent("projects/demo-app/databases/(default)").unwrap();
        let mut target = TargetState {
            target_hash: 1,
            kind: TargetKind::Documents(vec![path("target/a")]),
            parent,
            known: BTreeMap::from([(document.path.clone(), document.version)]),
            resume: None,
            once: false,
            assigned: false,
            resume_answer: ResumeAnswer::Exact,
            current: true,
            pending: Vec::new(),
        };
        let changed = BTreeSet::from([path("target/a"), path("unrelated/b")]);
        let examined = refresh_target_delta(
            &database,
            1,
            &mut target,
            prost_types::Timestamp::default(),
            &changed,
        )
        .unwrap();
        assert_eq!(examined, Some(1));
        assert!(target.pending.is_empty());

        let examined = refresh_target_delta(
            &database,
            1,
            &mut target,
            prost_types::Timestamp::default(),
            &BTreeSet::from([path("unrelated/b")]),
        )
        .unwrap();
        assert_eq!(examined, Some(0));
        assert!(target.pending.is_empty());

        database
            .commit(&[set("target/a")], None, LogicalInstant::UNIX_EPOCH)
            .unwrap();
        let examined = refresh_target_delta(
            &database,
            1,
            &mut target,
            prost_types::Timestamp::default(),
            &changed,
        )
        .unwrap();
        assert_eq!(examined, Some(1));
        assert_eq!(target.pending.len(), 1);
    }

    #[test]
    fn snapshot_version_mismatch_forces_full_refresh() {
        let paths = BTreeSet::from([path("items/a")]);
        let input = RefreshInput::Delta {
            through: CommitVersion::from_value(1),
            paths,
        };
        assert!(complete_delta_paths(&input, CommitVersion::from_value(1)).is_some());
        assert!(complete_delta_paths(&input, CommitVersion::from_value(2)).is_none());
        assert!(complete_delta_paths(&RefreshInput::Full, CommitVersion::from_value(1)).is_none());
    }

    #[test]
    #[ignore = "large release-mode acceptance check"]
    fn fifty_targets_examine_one_changed_document_fifty_times() {
        let mut database = FirestoreState::new();
        for start in (0..100_000).step_by(500) {
            let writes = (start..start + 500)
                .map(|index| set(&format!("unrelated/d{index:06}")))
                .collect::<Vec<_>>();
            database
                .commit(&writes, None, LogicalInstant::UNIX_EPOCH)
                .unwrap();
        }
        database
            .commit(&[set("target/a")], None, LogicalInstant::UNIX_EPOCH)
            .unwrap();
        let changed = BTreeSet::from([path("target/a")]);
        let parent = database_parent("projects/demo-app/databases/(default)").unwrap();
        let query = Query::new(fireemu_core_firestore::query::QueryScope::collection(
            None,
            CollectionId::try_new("target").unwrap(),
        ));
        let read_time = prost_types::Timestamp::default();
        let mut examined = 0;
        for target_id in 1..=50 {
            let mut target = TargetState {
                target_hash: target_hash(&TargetKind::Query(Box::new(query.clone()))),
                kind: TargetKind::Query(Box::new(query.clone())),
                parent: parent.clone(),
                known: BTreeMap::new(),
                resume: None,
                once: false,
                assigned: false,
                resume_answer: ResumeAnswer::Exact,
                current: true,
                pending: Vec::new(),
            };
            examined +=
                refresh_target_delta(&database, target_id, &mut target, read_time, &changed)
                    .unwrap()
                    .expect("unbounded query stays incremental");
        }
        assert_eq!(examined, 50);
    }
}

#[cfg(test)]
mod empty_write_tests {
    use super::*;
    use fireemu_core_firestore::index::{IndexSet, IndexValidationPolicy, PlanningContext};
    use fireemu_core_session::clock::VirtualClock;
    use fireemu_core_types::edition::{FirestoreApiMode, FirestoreEdition};
    use fireemu_core_types::time::LogicalInstant;

    fn context() -> StreamContext {
        let gateway = Gateway {
            enforce_limits: true,
            ctx: PlanningContext {
                edition: FirestoreEdition::Standard,
                api_mode: FirestoreApiMode::Native,
                policy: IndexValidationPolicy::Production,
            },
            indexes: IndexSet::default(),
        };
        let clock = Arc::new(std::sync::Mutex::new(VirtualClock::new(
            LogicalInstant::UNIX_EPOCH,
        )));
        let local = Arc::new(LocalBackend::new(gateway.clone(), clock, 7));
        StreamContext {
            local: local.clone(),
            gateway: Arc::new(gateway),
            rules: None,
            principal: Principal::Owner,
            authorization: None,
            epoch: local.epoch(),
            app_check: None,
        }
    }

    /// Runs a stream over `requests`; `half_closed` drops the client side before the server
    /// reads, as when a client half-closes right after its last message.
    async fn run(half_closed: bool) -> Vec<Result<pb::WriteResponse, Status>> {
        let (client, inbound) = mpsc::channel(4);
        client
            .send(Ok(pb::WriteRequest {
                database: "projects/demo-app/databases/(default)".to_owned(),
                ..Default::default()
            }))
            .await
            .unwrap();
        client
            .send(Ok(pb::WriteRequest {
                writes: vec![pb::Write::default()],
                ..Default::default()
            }))
            .await
            .unwrap();
        let open = (!half_closed).then_some(client);
        let (tx, mut rx) = mpsc::channel(4);
        write_stream(
            context(),
            tokio_stream::wrappers::ReceiverStream::new(inbound),
            tx,
        )
        .await;
        drop(open);
        let mut out = Vec::new();
        while let Some(item) = rx.recv().await {
            out.push(item);
        }
        out
    }

    /// `writes/write-stream-terminal/response-before-half-close` (recorded twice on
    /// 2026-09-25): a client still waiting for the answer gets `empty write operation`.
    /// `writes/write-stream-terminal/trailing-metadata`: a client that half-closed right after
    /// the empty write gets a stream that ends OK. Production evaluates the empty write after
    /// it has seen the half-close; which one it sees first depends on arrival order.
    #[tokio::test]
    async fn an_empty_write_is_refused_only_while_the_client_is_still_sending() {
        let open = run(false).await;
        assert_eq!(open.len(), 2, "{open:?}");
        assert!(open[0].is_ok());
        let refused = open[1].as_ref().unwrap_err();
        assert_eq!(refused.code(), tonic::Code::InvalidArgument);
        assert_eq!(refused.message(), "empty write operation");

        let closed = run(true).await;
        assert_eq!(closed.len(), 1, "{closed:?}");
        assert!(
            closed[0].is_ok(),
            "only the handshake answer, then an OK end"
        );
    }

    /// The half-close race that decides a first-message token, without time: the client's end
    /// wins over a deadline that is ready at the same moment.
    #[tokio::test]
    async fn the_first_token_grace_is_decided_by_what_arrives_first() {
        use std::future::{pending, ready};
        let closed = || tokio_stream::iter(Vec::<u8>::new());
        let open = || tokio_stream::pending::<u8>();
        assert!(half_closes_before(&mut closed(), pending::<()>()).await);
        assert!(
            half_closes_before(&mut closed(), ready(())).await,
            "the end wins a tie"
        );
        assert!(
            !half_closes_before(&mut open(), ready(())).await,
            "the deadline passed"
        );
        assert!(
            !half_closes_before(&mut tokio_stream::iter(vec![1_u8]), pending::<()>()).await,
            "another message means the client is still sending"
        );
    }

    /// Production's D5 probe refused an unknown first token while the sender stayed open,
    /// whereas both 10 MiB request-byte recordings ended OK after an immediate half-close.
    #[tokio::test]
    async fn an_unknown_first_token_depends_on_client_half_close() {
        async fn run(half_closed: bool) -> Vec<Result<pb::WriteResponse, Status>> {
            let (client, inbound) = mpsc::channel(2);
            client
                .send(Ok(pb::WriteRequest {
                    database: "projects/demo-app/databases/(default)".to_owned(),
                    stream_token: vec![7; 16],
                    ..Default::default()
                }))
                .await
                .unwrap();
            let open = (!half_closed).then_some(client);
            let (tx, mut rx) = mpsc::channel(2);
            write_stream(
                context(),
                tokio_stream::wrappers::ReceiverStream::new(inbound),
                tx,
            )
            .await;
            drop(open);
            let mut out = Vec::new();
            while let Some(item) = rx.recv().await {
                out.push(item);
            }
            out
        }

        let open = run(false).await;
        assert_eq!(open.len(), 1, "{open:?}");
        let refused = open[0].as_ref().unwrap_err();
        assert_eq!(refused.code(), tonic::Code::Aborted);
        assert_eq!(refused.message(), "resuming a stream not supported");

        let closed = run(true).await;
        assert!(closed.is_empty(), "{closed:?}");
    }
}

#[cfg(test)]
mod assigned_target_id_tests {
    use super::{choose_target_id, first_free_target_id, is_token_shaped};
    use proptest::prelude::*;
    use std::collections::BTreeSet;

    #[test]
    fn the_decision_table_of_a_requested_id() {
        let used = BTreeSet::from([1, 2]);
        assert_eq!(choose_target_id(0, &used, false, true), Ok((3, true)));
        assert_eq!(choose_target_id(0, &used, true, true), Ok((3, true)));
        assert_eq!(choose_target_id(7, &used, false, true), Ok((7, false)));
        assert!(choose_target_id(7, &used, true, true).is_err());
        assert_eq!(choose_target_id(7, &used, true, false), Ok((7, false)));
        assert!(choose_target_id(-1, &used, false, false).is_err());
        assert!(choose_target_id(-1, &used, false, true).is_err());
        assert!(choose_target_id(i32::MIN, &used, false, true).is_err());
    }

    #[test]
    fn a_token_has_the_shape_of_exactly_thirty_two_bytes() {
        assert!(is_token_shaped(&[0; 32]));
        assert!(!is_token_shaped(&[0; 31]));
        assert!(!is_token_shaped(&[0; 33]));
        assert!(!is_token_shaped(&[]));
    }

    #[test]
    fn the_first_id_is_one_and_a_gap_is_filled_before_the_end() {
        assert_eq!(first_free_target_id(&BTreeSet::new()), 1);
        assert_eq!(first_free_target_id(&BTreeSet::from([1])), 2);
        assert_eq!(first_free_target_id(&BTreeSet::from([2, 3])), 1);
        assert_eq!(first_free_target_id(&BTreeSet::from([1, 3])), 2);
        // Ids at or below zero never count: they do not occupy a positive id.
        assert_eq!(first_free_target_id(&BTreeSet::from([-1, 0])), 1);
        assert_eq!(first_free_target_id(&BTreeSet::from([i32::MAX])), 1);
    }

    proptest! {
        #[test]
        fn the_assigned_id_is_the_smallest_free_positive_one(
            used in proptest::collection::btree_set(-3_i32..40, 0..30)
        ) {
            let id = first_free_target_id(&used);
            prop_assert!(id >= 1);
            prop_assert!(!used.contains(&id));
            for smaller in 1..id {
                prop_assert!(used.contains(&smaller));
            }
        }

        #[test]
        fn a_requested_id_is_decided_by_sign_and_by_what_the_stream_holds(
            requested in -5_i32..50,
            used in proptest::collection::btree_set(-3_i32..40, 0..30),
            assigned_before in any::<bool>(),
            strict in any::<bool>(),
        ) {
            let decided = choose_target_id(requested, &used, assigned_before, strict);
            if requested < 0 {
                prop_assert!(decided.is_err());
            } else if requested == 0 {
                let (id, assigned) = decided.unwrap();
                prop_assert!(assigned);
                prop_assert_eq!(id, first_free_target_id(&used));
            } else if strict && assigned_before {
                prop_assert!(decided.is_err());
            } else {
                prop_assert_eq!(decided, Ok((requested, false)));
            }
        }

        #[test]
        fn only_thirty_two_bytes_are_token_shaped(len in 0_usize..70) {
            prop_assert_eq!(is_token_shaped(&vec![7; len]), len == 32);
        }
    }
}
