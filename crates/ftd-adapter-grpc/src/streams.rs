//! Streaming RPCs of the local backend: `Write` (handshake + sequential atomic commits) and
//! `Listen` (initial snapshot, then a diff after every commit on the database).
//!
//! `Listen` keeps one target registry per stream. Whenever the backend publishes a commit
//! on the database (or a target is added), every active target is refreshed against one
//! database snapshot; the diff against its last known `(path, version)` set becomes
//! `DocumentChange` / `DocumentDelete` / `DocumentRemove` messages, followed by one global
//! `NO_CHANGE` boundary carrying the snapshot read time and a resume token derived from
//! the snapshot version. A target added with a resume token (or a read time) replays only
//! what changed since that version: the target's state at the token is recomputed from the
//! retained history and diffed against the current snapshot, followed by an
//! `ExistenceFilter` with the current count (production's post-resume check).
//!
//! A token is only honoured while the store can still reproduce its version exactly
//! (`FirestoreState::is_retained`: not compacted away by the one-hour retention window, not
//! ahead of this database). An undecodable, future or expired token falls back to `RESET`,
//! so a token is never resumed against unrelated history; the client drops its cache and
//! replays from scratch. Security Rules are re-checked on every refresh; a denial removes
//! the target with a `PERMISSION_DENIED` cause.

// `tonic::Status` is the error type dictated by the generated trait.
#![allow(clippy::result_large_err)]

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use ftd_core_firestore::path::DocumentPath;
use ftd_core_firestore::query::Query;
use ftd_core_firestore::store::{CommitVersion, Document, Write};
use ftd_proto_firestore::google::firestore::v1 as pb;
use tokio::sync::mpsc;
use tokio_stream::StreamExt;
use tonic::Status;

use crate::decode::{parse_parent, Parent};
use crate::encode::{decode_instant, decode_write, encode_document, encode_instant};
use crate::gateway::Gateway;
use crate::local::{CommitEvent, LocalBackend};
use crate::rules::{write_guard, Principal, RulesEnforcer};

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
}

impl StreamContext {
    /// Re-resolves the caller and checks the session epoch before serving anything.
    fn refresh_principal(&self) -> Result<Principal, Status> {
        if self.local.epoch() != self.epoch {
            return Err(Status::aborted(
                "the session was reset; streams opened before the reset are closed",
            ));
        }
        match &self.rules {
            Some(r) => r.principal_from_authorization(self.authorization.as_deref()),
            None => Ok(self.principal.clone()),
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
}

/// Runs the `Write` stream: the first message (no writes) is the handshake; every later
/// message commits its writes atomically and answers with results and a fresh token.
pub async fn write_stream(
    ctx: StreamContext,
    mut inbound: impl tokio_stream::Stream<Item = Result<pb::WriteRequest, Status>> + Unpin + Send,
    tx: mpsc::Sender<Result<pb::WriteResponse, Status>>,
) {
    let mut state = WriteStreamState {
        parent: None,
        stream_id: format!("ftd-{}", NEXT_STREAM_ID.fetch_add(1, Ordering::Relaxed)),
        issued: 0,
        acknowledged: 0,
    };
    while let Some(next) = inbound.next().await {
        let req = match next {
            Ok(r) => r,
            Err(e) => {
                let _ = tx.send(Err(e)).await;
                break;
            }
        };
        let outcome = handle_write_request(&ctx, &mut state, &req);
        let stop = outcome.is_err();
        if tx.send(outcome).await.is_err() || stop {
            break;
        }
    }
}

fn token_bytes(n: u64) -> Vec<u8> {
    n.to_be_bytes().to_vec()
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
        if !req.stream_id.is_empty() || !req.stream_token.is_empty() {
            return Err(Status::failed_precondition(
                "write stream resumption is not supported; start a new stream",
            ));
        }
        if !req.writes.is_empty() {
            return Err(Status::invalid_argument(
                "the first Write request is the handshake and must carry no writes",
            ));
        }
        state.parent = Some(database_parent(&req.database)?);
    } else if !req.stream_id.is_empty() || !req.database.is_empty() {
        return Err(Status::invalid_argument(
            "stream_id / database are only valid on the first Write request",
        ));
    }
    let Some(parent) = state.parent.as_ref() else {
        return Err(Status::internal("write stream without database"));
    };
    if !req.stream_token.is_empty() {
        let acknowledged: Option<[u8; 8]> = req.stream_token.as_slice().try_into().ok();
        let acknowledged = acknowledged.map_or(0, u64::from_be_bytes);
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
            stream_token: token_bytes(state.issued),
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
    let principal = ctx.refresh_principal()?;
    let guard = write_guard(ctx.rules.as_ref(), &principal);
    // The epoch is re-checked inside the commit critical section: a reset that starts
    // after the check above cannot be raced by this write.
    let epoch = ctx.epoch;
    let local = ctx.local.clone();
    let actor = crate::local::Actor::from_principal(&principal);
    let guarded = move |db: &ftd_core_firestore::store::FirestoreState,
                        writes: &[Write],
                        now: ftd_core_types::time::LogicalInstant|
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
        stream_token: token_bytes(state.issued),
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
    ReadTime(ftd_core_types::time::LogicalInstant),
    /// Not a token this daemon issued, or one whose version was compacted away: full replay
    /// after a `RESET`.
    Invalid,
}

struct TargetState {
    kind: TargetKind,
    parent: Parent,
    known: BTreeMap<DocumentPath, CommitVersion>,
    /// Pending resume, resolved on the first refresh (it needs the snapshot).
    resume: Option<Resume>,
    once: bool,
    /// Reached its first consistent snapshot (`CURRENT` was sent).
    current: bool,
    /// Responses produced by the last refresh, drained by the caller.
    pending: Vec<pb::ListenResponse>,
}

/// Maximum targets one `Listen` stream may hold (spec 10.6: queue length caps are explicit,
/// never a silent drop); the web SDK multiplexes every listener of a client over one stream.
pub const MAX_LISTEN_TARGETS: usize = 1000;

/// Runs the `Listen` stream.
///
/// Back-pressure: responses go out through a bounded channel and the loop awaits it, so a
/// slow client stalls the loop instead of growing a queue. Commits that land meanwhile
/// accumulate in the broadcast channel and are coalesced into one refresh (the diff
/// against the last known state covers every intervening commit), and a lagged broadcast
/// is the same one refresh.
pub async fn listen_stream(
    ctx: StreamContext,
    mut inbound: impl tokio_stream::Stream<Item = Result<pb::ListenRequest, Status>> + Unpin + Send,
    tx: mpsc::Sender<Result<pb::ListenResponse, Status>>,
) {
    let mut parent: Option<Parent> = None;
    let mut targets: BTreeMap<i32, TargetState> = BTreeMap::new();
    let mut events = ctx.local.subscribe();
    loop {
        let mut out: Vec<pb::ListenResponse> = Vec::new();
        let outcome: Result<bool, Status> = tokio::select! {
            () = tx.closed() => Ok(false),
            msg = inbound.next() => match msg {
                None => Ok(false),
                Some(Err(e)) => Err(e),
                Some(Ok(req)) => handle_listen_request(&ctx, &mut parent, &mut targets, &req, &mut out).map(|()| true),
            },
            ev = events.recv() => match ev {
                Ok(first) => {
                    // Coalesce: every commit already queued behind this one is covered by
                    // the single refresh below.
                    let mut relevant = is_relevant(parent.as_ref(), &first);
                    let mut closed = false;
                    loop {
                        match events.try_recv() {
                            Ok(ev) => relevant |= is_relevant(parent.as_ref(), &ev),
                            Err(tokio::sync::broadcast::error::TryRecvError::Lagged(_)) => {
                                relevant = true;
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
                    } else if relevant {
                        refresh_all(&ctx, parent.as_ref(), &mut targets, &mut out).map(|()| true)
                    } else {
                        Ok(true)
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                    refresh_all(&ctx, parent.as_ref(), &mut targets, &mut out).map(|()| true)
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => Ok(false),
            },
        };
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
fn is_relevant(parent: Option<&Parent>, ev: &CommitEvent) -> bool {
    parent.is_some_and(|p| p.project.as_str() == ev.project && p.database.as_str() == ev.database)
}

fn handle_listen_request(
    ctx: &StreamContext,
    parent: &mut Option<Parent>,
    targets: &mut BTreeMap<i32, TargetState>,
    req: &pb::ListenRequest,
    out: &mut Vec<pb::ListenResponse>,
) -> Result<(), Status> {
    if parent.is_none() {
        if req.database.is_empty() {
            return Err(Status::invalid_argument(
                "the first Listen request must name the database",
            ));
        }
        *parent = Some(database_parent(&req.database)?);
    }
    let Some(parent) = parent.as_ref() else {
        return Err(Status::internal("listen stream without database"));
    };
    match &req.target_change {
        Some(pb::listen_request::TargetChange::AddTarget(target)) => {
            let id = target.target_id;
            if id == 0 {
                return Err(Status::invalid_argument("target_id must be non-zero"));
            }
            if targets.contains_key(&id) {
                return Err(Status::invalid_argument(format!(
                    "target {id} is already active on this stream"
                )));
            }
            if targets.len() >= MAX_LISTEN_TARGETS {
                return Err(Status::resource_exhausted(format!(
                    "this Listen stream already holds {MAX_LISTEN_TARGETS} targets"
                )));
            }
            let kind = decode_target(ctx, parent, target)?;
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
                database: database_hash(parent, ctx.local.database_generation(parent)),
                target: target_hash(&kind),
            };
            let resume = match &target.resume_type {
                None => None,
                Some(pb::target::ResumeType::ResumeToken(bytes)) => {
                    Some(parse_resume_token(bytes, &binding))
                }
                Some(pb::target::ResumeType::ReadTime(t)) => {
                    Some(Resume::ReadTime(decode_instant(t)))
                }
            };
            targets.insert(
                id,
                TargetState {
                    kind,
                    parent: parent.clone(),
                    known: BTreeMap::new(),
                    resume,
                    once: target.once,
                    current: false,
                    pending: Vec::new(),
                },
            );
            // Every target is brought to the same snapshot before one global boundary.
            refresh_all(ctx, Some(parent), targets, out)?;
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
            let accepted = ctx.local.accepted_query(&query_parent, sq)?;
            Ok(TargetKind::Query(Box::new(accepted.query)))
        }
        None => Err(Status::invalid_argument("target without target_type")),
    }
}

/// Refreshes every target against one snapshot, then emits the global boundary. Targets
/// whose rules now deny are removed with a cause; `once` targets are removed after their
/// first consistent snapshot.
#[allow(clippy::too_many_lines)]
fn refresh_all(
    ctx: &StreamContext,
    parent: Option<&Parent>,
    targets: &mut BTreeMap<i32, TargetState>,
    out: &mut Vec<pb::ListenResponse>,
) -> Result<(), Status> {
    let Some(parent) = parent else { return Ok(()) };
    // Authentication / reset failures end the stream (every target is removed with the
    // cause first, so the client learns why).
    let principal = match ctx.refresh_principal() {
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
    let snapshot = ctx.local.with_snapshot(parent, |db, version, read_at| {
        if local.epoch() != expected_epoch {
            return Err(Status::aborted("the session was reset"));
        }
        let read_time = encode_instant(read_at);
        let binding = TokenBinding {
            epoch: local.epoch(),
            database: database_hash(parent, local.database_generation(parent)),
            target: 0,
        };
        let token = resume_token(version, &binding);
        let mut removed = Vec::new();
        for (id, state) in targets.iter_mut() {
            match refresh_target(ctx, &principal, db, *id, state, read_time) {
                Ok(()) => {
                    out.append(&mut state.pending);
                    if !state.current {
                        state.current = true;
                        let bound = TokenBinding {
                            target: target_hash(&state.kind),
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
        Ok((read_time, token, removed, version, binding))
    });
    let (read_time, token, removed, version, binding) = match snapshot.and_then(|r| r) {
        Ok(s) => s,
        Err(e) => {
            for id in targets.keys() {
                out.push(removed_with_cause(*id, &e));
            }
            targets.clear();
            return Err(e);
        }
    };
    for id in removed {
        targets.remove(&id);
    }
    if targets.is_empty() {
        return Ok(());
    }
    for (id, state) in &*targets {
        let bound = TokenBinding {
            target: target_hash(&state.kind),
            ..binding
        };
        out.push(target_change(
            pb::target_change::TargetChangeType::NoChange,
            vec![*id],
            Some(resume_token(version, &bound)),
            Some(read_time),
        ));
    }
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

/// Recomputes one target and appends the diff against its last known state.
fn refresh_target(
    ctx: &StreamContext,
    principal: &Principal,
    db: &ftd_core_firestore::store::FirestoreState,
    id: i32,
    state: &mut TargetState,
    read_time: prost_types::Timestamp,
) -> Result<(), Status> {
    let resumed = resolve_resume(db, id, state)?;
    let current: Vec<Document> = match &state.kind {
        TargetKind::Documents(paths) => {
            let mut docs = Vec::new();
            for path in paths {
                let doc = db.get(path).cloned();
                if let Some(rules) = &ctx.rules {
                    let reader = crate::rules::StateReader {
                        db,
                        parent: &state.parent,
                        version: None,
                    };
                    rules.authorize_get(principal, path, doc.as_ref(), &reader)?;
                }
                if let Some(d) = doc {
                    docs.push(d);
                }
            }
            docs
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
            db.run_query(query, None)
                .map_err(|e| crate::encode::status_from_error(&e))?
        }
    };
    let mut next_known: BTreeMap<DocumentPath, CommitVersion> = BTreeMap::new();
    for doc in &current {
        next_known.insert(doc.path.clone(), doc.version);
        if state.known.get(&doc.path) != Some(&doc.version) {
            out_change(doc, id, &mut state.pending);
        }
    }
    for path in state.known.keys() {
        if next_known.contains_key(path) {
            continue;
        }
        let name = path.resource_name();
        let still_exists = db.get(path).is_some();
        let response_type = if still_exists {
            pb::listen_response::ResponseType::DocumentRemove(pb::DocumentRemove {
                document: name,
                removed_target_ids: vec![id],
                read_time: Some(read_time),
            })
        } else {
            pb::listen_response::ResponseType::DocumentDelete(pb::DocumentDelete {
                document: name,
                removed_target_ids: vec![id],
                read_time: Some(read_time),
            })
        };
        state.pending.push(pb::ListenResponse {
            response_type: Some(response_type),
        });
    }
    state.known = next_known;
    if resumed {
        // Production follows a resume with the current count so the client can verify its
        // cache; the diff above already made it exact.
        state.pending.push(pb::ListenResponse {
            response_type: Some(pb::listen_response::ResponseType::Filter(
                pb::ExistenceFilter {
                    target_id: id,
                    count: i32::try_from(current.len()).unwrap_or(i32::MAX),
                    unchanged_names: None,
                },
            )),
        });
    }
    Ok(())
}

/// Resume: the target's state at the token becomes the known state, so the diff carries
/// exactly what changed since; a token this daemon cannot honour resets the target.
/// Returns whether the target resumed.
///
/// "Cannot honour" includes a version the store compacted away: history older than the
/// retention window is gone, and replaying a target against a version the store can no
/// longer describe would produce a diff against unrelated history. Such a token is refused
/// like an unknown one -- `RESET`, then a full replay.
fn resolve_resume(
    db: &ftd_core_firestore::store::FirestoreState,
    id: i32,
    state: &mut TargetState,
) -> Result<bool, Status> {
    let Some(resume) = state.resume.take() else {
        return Ok(false);
    };
    let version = match resume {
        Resume::Version(v) => Some(v),
        Resume::ReadTime(t) => db.version_at_retained(t),
        Resume::Invalid => None,
    }
    .filter(|v| db.is_retained(*v));
    if let Some(v) = version {
        state.known = known_at(db, &state.kind, v)?;
        return Ok(true);
    }
    state.pending.push(target_change(
        pb::target_change::TargetChangeType::Reset,
        vec![id],
        None,
        None,
    ));
    Ok(false)
}

/// What a resume token is bound to besides its version.
#[derive(Debug, Clone, Copy)]
struct TokenBinding {
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

fn target_hash(kind: &TargetKind) -> u64 {
    fnv(&format!("{kind:?}"))
}

/// 32 bytes: version, epoch, database hash, target hash (big-endian).
fn resume_token(version: CommitVersion, binding: &TokenBinding) -> Vec<u8> {
    let mut out = Vec::with_capacity(32);
    out.extend_from_slice(&version.value().to_be_bytes());
    out.extend_from_slice(&binding.epoch.to_be_bytes());
    out.extend_from_slice(&binding.database.to_be_bytes());
    out.extend_from_slice(&binding.target.to_be_bytes());
    out
}

/// A token this daemon issued for this epoch, database and target (or for every target).
fn parse_resume_token(bytes: &[u8], binding: &TokenBinding) -> Resume {
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
    db: &ftd_core_firestore::store::FirestoreState,
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
                cause: Some(ftd_proto_firestore::google::rpc::Status {
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
    pub fn from_result(result: &ftd_core_firestore::store::CommitResult) -> Self {
        let encoded = crate::local::encode_commit(result);
        Self {
            write_results: encoded.write_results,
            commit_time: encoded.commit_time,
        }
    }
}
