//! Streaming RPCs of the local backend: `Write` (handshake + sequential atomic commits) and
//! `Listen` (initial snapshot, then a diff after every commit on the database).
//!
//! `Listen` keeps one target registry per stream. A target is refreshed whenever the
//! backend publishes a commit on its database; the diff against the last known
//! `(path, version)` set becomes `DocumentChange` / `DocumentDelete` / `DocumentRemove`
//! messages, followed by a `CURRENT`/`NO_CHANGE` boundary carrying the read time. Security
//! Rules are re-checked on every refresh; a denial removes the target with a
//! `PERMISSION_DENIED` cause, exactly as the service does for one-shot reads.

// `tonic::Status` is the error type dictated by the generated trait.
#![allow(clippy::result_large_err)]

use std::collections::BTreeMap;
use std::sync::Arc;

use ftd_core_firestore::path::DocumentPath;
use ftd_core_firestore::query::Query;
use ftd_core_firestore::store::{CommitVersion, Document, Write};
use ftd_proto_firestore::google::firestore::v1 as pb;
use tokio::sync::mpsc;
use tokio_stream::StreamExt;
use tonic::{Status, Streaming};

use crate::decode::{decode_structured_query, parse_parent, Parent};
use crate::encode::{decode_write, encode_document, encode_instant};
use crate::gateway::{Gateway, Rejection};
use crate::local::{CommitEvent, LocalBackend};
use crate::rules::{Principal, RulesEnforcer};

/// Shared pieces every stream task needs.
pub struct StreamContext {
    /// Local backend.
    pub local: Arc<LocalBackend>,
    /// Strict gateway (query validation).
    pub gateway: Arc<Gateway>,
    /// Rules enforcement, if configured.
    pub rules: Option<Arc<RulesEnforcer>>,
    /// Caller.
    pub principal: Principal,
}

fn status(e: crate::decode::DecodeError) -> Status {
    Rejection::Decode(e).to_status()
}

fn database_parent(database: &str) -> Result<Parent, Status> {
    parse_parent(&format!("{database}/documents")).map_err(status)
}

// ---------------------------------------------------------------------------------------
// Write stream
// ---------------------------------------------------------------------------------------

/// Runs the `Write` stream: the first message (no writes) is the handshake; every later
/// message commits its writes atomically and answers with results and a fresh token.
pub async fn write_stream(
    ctx: StreamContext,
    mut inbound: Streaming<pb::WriteRequest>,
    tx: mpsc::Sender<Result<pb::WriteResponse, Status>>,
) {
    let mut parent: Option<Parent> = None;
    let mut token: u64 = 0;
    let stream_id = "ftd-write-stream".to_owned();
    while let Some(next) = inbound.next().await {
        let Ok(req) = next else { break };
        let outcome = handle_write_request(&ctx, &mut parent, &mut token, &stream_id, &req);
        let stop = outcome.is_err();
        if tx.send(outcome).await.is_err() || stop {
            break;
        }
    }
}

fn handle_write_request(
    ctx: &StreamContext,
    parent: &mut Option<Parent>,
    token: &mut u64,
    stream_id: &str,
    req: &pb::WriteRequest,
) -> Result<pb::WriteResponse, Status> {
    if parent.is_none() {
        if req.database.is_empty() {
            return Err(Status::invalid_argument(
                "the first Write request must name the database",
            ));
        }
        *parent = Some(database_parent(&req.database)?);
    }
    let Some(parent) = parent.as_ref() else {
        return Err(Status::internal("write stream without database"));
    };
    if !req.stream_token.is_empty() && req.stream_token != token.to_be_bytes() {
        return Err(Status::failed_precondition("unknown write stream token"));
    }
    *token += 1;
    if req.writes.is_empty() {
        return Ok(pb::WriteResponse {
            stream_id: stream_id.to_owned(),
            stream_token: token.to_be_bytes().to_vec(),
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
    if let Some(rules) = &ctx.rules {
        for w in &writes {
            rules.authorize_write(&ctx.principal, &ctx.local, parent, w)?;
        }
    }
    let result = ctx.local.commit_writes(parent, &writes)?;
    Ok(pb::WriteResponse {
        stream_id: stream_id.to_owned(),
        stream_token: token.to_be_bytes().to_vec(),
        write_results: result.write_results,
        commit_time: result.commit_time,
    })
}

// ---------------------------------------------------------------------------------------
// Listen stream
// ---------------------------------------------------------------------------------------

enum TargetKind {
    Documents(Vec<DocumentPath>),
    Query(Box<QueryTargetState>),
}

struct QueryTargetState {
    query: Query,
    collection_id: String,
}

struct TargetState {
    kind: TargetKind,
    known: BTreeMap<DocumentPath, CommitVersion>,
    once: bool,
    current: bool,
}

/// Runs the `Listen` stream.
pub async fn listen_stream(
    ctx: StreamContext,
    mut inbound: Streaming<pb::ListenRequest>,
    tx: mpsc::Sender<Result<pb::ListenResponse, Status>>,
) {
    let mut parent: Option<Parent> = None;
    let mut targets: BTreeMap<i32, TargetState> = BTreeMap::new();
    let mut events = ctx.local.subscribe();
    loop {
        let mut out: Vec<pb::ListenResponse> = Vec::new();
        let outcome: Result<bool, Status> = tokio::select! {
            msg = inbound.next() => match msg {
                None | Some(Err(_)) => Ok(false),
                Some(Ok(req)) => handle_listen_request(&ctx, &mut parent, &mut targets, &req, &mut out).map(|()| true),
            },
            ev = events.recv() => match ev {
                Ok(CommitEvent { project, database, .. }) => {
                    let relevant = parent.as_ref().is_some_and(|p| {
                        p.project.as_str() == project && p.database.as_str() == database
                    });
                    if relevant {
                        refresh_all(&ctx, parent.as_ref(), &mut targets, &mut out);
                    }
                    Ok(true)
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                    refresh_all(&ctx, parent.as_ref(), &mut targets, &mut out);
                    Ok(true)
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
            let mut state = TargetState {
                kind,
                known: BTreeMap::new(),
                once: target.once,
                current: false,
            };
            out.push(target_change(
                pb::target_change::TargetChangeType::Add,
                vec![id],
                None,
                None,
            ));
            let read_time = encode_instant(ctx.local.now());
            match refresh_target(ctx, parent, id, &mut state, out) {
                Ok(()) => {
                    state.current = true;
                    out.push(target_change(
                        pb::target_change::TargetChangeType::Current,
                        vec![id],
                        Some(resume_token(ctx)),
                        Some(read_time),
                    ));
                    out.push(target_change(
                        pb::target_change::TargetChangeType::NoChange,
                        vec![],
                        None,
                        Some(read_time),
                    ));
                    if !state.once {
                        targets.insert(id, state);
                    }
                }
                Err(e) => out.push(removed_with_cause(id, &e)),
            }
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
                paths.push(path);
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
            let query = decode_structured_query(&query_parent, sq).map_err(status)?;
            let accepted = ctx
                .gateway
                .validate_query(&query)
                .map_err(|r| r.to_status())?;
            Ok(TargetKind::Query(Box::new(QueryTargetState {
                query: accepted.query,
                collection_id: sq
                    .from
                    .first()
                    .map(|f| f.collection_id.clone())
                    .unwrap_or_default(),
            })))
        }
        None => Err(Status::invalid_argument("target without target_type")),
    }
}

fn refresh_all(
    ctx: &StreamContext,
    parent: Option<&Parent>,
    targets: &mut BTreeMap<i32, TargetState>,
    out: &mut Vec<pb::ListenResponse>,
) {
    let Some(parent) = parent else { return };
    let read_time = encode_instant(ctx.local.now());
    let mut removed = Vec::new();
    for (id, state) in targets.iter_mut() {
        if let Err(e) = refresh_target(ctx, parent, *id, state, out) {
            out.push(removed_with_cause(*id, &e));
            removed.push(*id);
        }
    }
    for id in removed {
        targets.remove(&id);
    }
    if targets.is_empty() {
        return;
    }
    for id in targets.keys() {
        out.push(target_change(
            pb::target_change::TargetChangeType::NoChange,
            vec![*id],
            Some(resume_token(ctx)),
            Some(read_time),
        ));
    }
    out.push(target_change(
        pb::target_change::TargetChangeType::NoChange,
        vec![],
        None,
        Some(read_time),
    ));
}

/// Recomputes one target and appends the diff against its last known state.
fn refresh_target(
    ctx: &StreamContext,
    parent: &Parent,
    id: i32,
    state: &mut TargetState,
    out: &mut Vec<pb::ListenResponse>,
) -> Result<(), Status> {
    let current: Vec<Document> = match &state.kind {
        TargetKind::Documents(paths) => {
            let mut docs = Vec::new();
            for path in paths {
                if let Some(rules) = &ctx.rules {
                    rules.authorize_get(&ctx.principal, &ctx.local, parent, path)?;
                }
                if let Some(d) = ctx.local.current_document(parent, path)? {
                    docs.push(d);
                }
            }
            docs
        }
        TargetKind::Query(q) => {
            let docs = ctx.local.run_query_latest(parent, &q.query)?;
            if let Some(rules) = &ctx.rules {
                let paths: Vec<DocumentPath> = docs.iter().map(|d| d.path.clone()).collect();
                let placeholder = placeholder_for(parent, &q.collection_id)?;
                rules.authorize_list(&ctx.principal, &ctx.local, parent, &paths, &placeholder)?;
            }
            docs
        }
    };
    let read_time = Some(encode_instant(ctx.local.now()));
    let mut next_known = BTreeMap::new();
    for doc in &current {
        next_known.insert(doc.path.clone(), doc.version);
        if state.known.get(&doc.path) != Some(&doc.version) {
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
    }
    for path in state.known.keys() {
        if next_known.contains_key(path) {
            continue;
        }
        let name = path.resource_name();
        let still_exists = ctx.local.current_document(parent, path)?.is_some();
        let response_type = if still_exists {
            pb::listen_response::ResponseType::DocumentRemove(pb::DocumentRemove {
                document: name,
                removed_target_ids: vec![id],
                read_time,
            })
        } else {
            pb::listen_response::ResponseType::DocumentDelete(pb::DocumentDelete {
                document: name,
                removed_target_ids: vec![id],
                read_time,
            })
        };
        out.push(pb::ListenResponse {
            response_type: Some(response_type),
        });
    }
    state.known = next_known;
    Ok(())
}

fn placeholder_for(parent: &Parent, collection_id: &str) -> Result<DocumentPath, Status> {
    let relative = match &parent.document {
        Some(p) => format!("{}/{collection_id}/ftd-placeholder", p.relative()),
        None => format!("{collection_id}/ftd-placeholder"),
    };
    DocumentPath::parse(&parent.project, &parent.database, &relative)
        .map_err(|e| Status::invalid_argument(e.to_string()))
}

fn resume_token(ctx: &StreamContext) -> Vec<u8> {
    ctx.local.now().as_nanos().to_be_bytes().to_vec()
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
