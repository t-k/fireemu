//! Streaming RPCs of the local backend: `Write` (handshake + sequential atomic commits) and
//! `Listen` (initial snapshot, then a diff after every commit on the database).
//!
//! `Listen` keeps one target registry per stream. Whenever the backend publishes a commit
//! on the database (or a target is added), every active target is refreshed against one
//! database snapshot; the diff against its last known `(path, version)` set becomes
//! `DocumentChange` / `DocumentDelete` / `DocumentRemove` messages, followed by one global
//! `NO_CHANGE` boundary carrying the snapshot read time and a resume token derived from
//! the snapshot version. A target added with a resume token is `RESET` before its replay
//! (resume history is not kept). Security Rules are re-checked on every refresh; a denial
//! removes the target with a `PERMISSION_DENIED` cause.

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
use crate::encode::{decode_write, encode_document, encode_instant};
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
    let guarded = move |db: &ftd_core_firestore::store::FirestoreState,
                        writes: &[Write],
                        now: ftd_core_types::time::LogicalInstant|
          -> Result<(), Status> {
        if local.epoch() != epoch {
            return Err(Status::aborted("the session was reset"));
        }
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

enum TargetKind {
    Documents(Vec<DocumentPath>),
    Query(Box<Query>),
}

struct TargetState {
    kind: TargetKind,
    parent: Parent,
    known: BTreeMap<DocumentPath, CommitVersion>,
    once: bool,
    /// Reached its first consistent snapshot (`CURRENT` was sent).
    current: bool,
    /// Responses produced by the last refresh, drained by the caller.
    pending: Vec<pb::ListenResponse>,
}

/// Runs the `Listen` stream.
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
                Ok(CommitEvent { project, database, .. }) => {
                    let relevant = parent.as_ref().is_some_and(|p| {
                        p.project.as_str() == project && p.database.as_str() == database
                    });
                    if relevant {
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
            let kind = decode_target(ctx, parent, target)?;
            out.push(target_change(
                pb::target_change::TargetChangeType::Add,
                vec![id],
                None,
                None,
            ));
            if target.resume_type.is_some() {
                // No resume history is kept: the client drops its cache and replays.
                out.push(target_change(
                    pb::target_change::TargetChangeType::Reset,
                    vec![id],
                    None,
                    None,
                ));
            }
            targets.insert(
                id,
                TargetState {
                    kind,
                    parent: parent.clone(),
                    known: BTreeMap::new(),
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
                paths.push(LocalBackend::check_database(parent, name)?);
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
    // One critical section: every target sees the same version, read time and documents.
    let expected_epoch = ctx.epoch;
    let local = ctx.local.clone();
    let snapshot = ctx.local.with_snapshot(parent, |db, version, read_at| {
        if local.epoch() != expected_epoch {
            return Err(Status::aborted("the session was reset"));
        }
        let read_time = encode_instant(read_at);
        let token = version.value().to_be_bytes().to_vec();
        let mut removed = Vec::new();
        for (id, state) in targets.iter_mut() {
            match refresh_target(ctx, &principal, db, *id, state, read_time) {
                Ok(()) => {
                    out.append(&mut state.pending);
                    if !state.current {
                        state.current = true;
                        out.push(target_change(
                            pb::target_change::TargetChangeType::Current,
                            vec![*id],
                            Some(token.clone()),
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
        Ok((read_time, token, removed))
    });
    let (read_time, token, removed) = match snapshot.and_then(|r| r) {
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
    for id in targets.keys() {
        out.push(target_change(
            pb::target_change::TargetChangeType::NoChange,
            vec![*id],
            Some(token.clone()),
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
    Ok(())
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
