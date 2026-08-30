//! Local execution backend: one `FirestoreState` per (project, database) behind a mutex, a
//! shared virtual clock, strict gateway validation before every query.

// `tonic::Status` is the error type dictated by the generated service trait.
#![allow(clippy::result_large_err)]

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

use ftd_core_firestore::field_path::FieldPath;
use ftd_core_firestore::path::DocumentPath;
use ftd_core_firestore::query::Query;
use ftd_core_firestore::store::{
    Aggregation, CommitResult, CommitVersion, Document, DocumentChange, FirestoreState,
    Precondition, TransactionId, Write, WriteOp,
};
use ftd_core_session::barrier::AdmissionBarrier;
use ftd_core_session::clock::VirtualClock;
use ftd_core_types::determinism::{Clock, DeterministicRng, SplitMix64};
use ftd_core_types::ids::{CollectionId, DocumentId};
use ftd_proto_firestore::google::firestore::v1 as pb;
use tonic::Status;

use crate::decode::{decode_structured_query, parse_parent, DecodeError, Parent};
use crate::encode::{
    decode_document_name, decode_fields, decode_mask, decode_precondition, decode_transaction,
    decode_write, encode_document, encode_instant, encode_transaction, encode_value,
    status_from_error,
};
use crate::gateway::{AcceptedQuery, Gateway, Rejection};
use crate::rules::{allow_all, ReadCheck, ReadGuard, WriteGuard};

/// `ListDocuments` page size when the request leaves it unset (the service default).
pub const DEFAULT_LIST_PAGE_SIZE: usize = 100;
/// How far back a `read_time` selector may reach (Firestore: one hour without PITR).
pub const READ_TIME_RETENTION_SECONDS: i64 = 3600;

/// Local backend state.
pub struct LocalBackend {
    gateway: Gateway,
    clock: Arc<Mutex<VirtualClock>>,
    databases: Mutex<BTreeMap<(String, String), FirestoreState>>,
    /// The actor of the commit in progress, staged by the write guard inside the critical
    /// section and consumed by `publish` (same critical section, so never another's).
    pending_actor: Mutex<Option<Actor>>,
    /// The sessions' fault plans (looked up by project), when shared.
    faults: Mutex<Option<ftd_core_session::fault::SharedFaultRegistry>>,
    /// Told after a fault plan moved the virtual clock (the functions runtime re-reads
    /// its schedules and retries).
    clock_observer: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
    /// Per-database generation, bumped by every wipe of that database (resume tokens are
    /// bound to it, so a project reset invalidates that project's tokens only).
    generations: Mutex<BTreeMap<(String, String), u64>>,
    ids: Mutex<SplitMix64>,
    commits: tokio::sync::broadcast::Sender<CommitEvent>,
    /// Bumped by every reset; long-lived streams compare it to refuse stale sessions.
    epoch: std::sync::atomic::AtomicU64,
    /// Session-wide admission barrier shared with the other surfaces (reset holds it
    /// exclusively).
    barrier: Arc<AdmissionBarrier>,
    /// Called for every commit inside the database critical section, in commit order and
    /// before the commit's response is returned (event triggers): nothing is lost or
    /// reordered, and `await-idle` sees the event as soon as the write returns.
    change_sink: Mutex<Option<ChangeSink>>,
}

/// Synchronous observer of commits (see [`LocalBackend::set_change_sink`]).
pub type ChangeSink = Arc<dyn Fn(&CommitEvent) + Send + Sync>;

/// Metadata key a `dropConnection` fault sets on its status: the server closes the
/// connection (or resets the stream) instead of delivering the response.
pub const DROP_CONNECTION_KEY: &str = "ftd-drop-connection";

/// A session's Firestore snapshot: its databases, and the auto-ID generator when the
/// session owns it (the default one).
#[derive(Debug, Clone)]
pub struct FirestoreSnapshot {
    /// Databases by `(project, database)`.
    pub databases: BTreeMap<(String, String), FirestoreState>,
    /// The auto-ID generator state.
    pub ids: Option<SplitMix64>,
}

/// Published after every successful commit (drives `Listen` streams).
#[derive(Debug, Clone, PartialEq)]
pub struct CommitEvent {
    /// Who made the commit (`withAuthContext` triggers).
    pub actor: Actor,
    /// Project.
    pub project: String,
    /// Database.
    pub database: String,
    /// Version after the commit.
    pub version: u64,
    /// Commit time (`None` for a reset).
    pub commit_time: Option<ftd_core_types::time::LogicalInstant>,
    /// Documents the commit changed (before / after), shared with every subscriber.
    pub changes: Arc<Vec<DocumentChange>>,
}

fn status(e: DecodeError) -> Status {
    Rejection::Decode(e).to_status()
}

/// The principal behind a commit, in Eventarc's `authtype` / `authid` terms.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Actor {
    /// `app_user`, `service_account`, `unauthenticated`, `system`.
    pub auth_type: String,
    /// The user ID (`app_user`) or the service account (`service_account`).
    pub auth_id: Option<String>,
}

impl Actor {
    /// The runtime itself (resets, internal writes).
    #[must_use]
    pub fn system() -> Self {
        Self {
            auth_type: "system".to_owned(),
            auth_id: None,
        }
    }

    /// The actor behind a request principal.
    #[must_use]
    pub fn from_principal(principal: &crate::rules::Principal) -> Self {
        match principal {
            crate::rules::Principal::Owner => Self {
                auth_type: "service_account".to_owned(),
                auth_id: Some("owner".to_owned()),
            },
            crate::rules::Principal::User(a) => Self {
                auth_type: "app_user".to_owned(),
                auth_id: Some(a.uid.clone()),
            },
            crate::rules::Principal::Anonymous => Self {
                auth_type: "unauthenticated".to_owned(),
                auth_id: None,
            },
        }
    }
}

fn lock_poisoned() -> Status {
    Status::internal("backend state lock poisoned")
}

/// One item of a batch get (core snapshot; encoded after authorization).
#[derive(Debug, Clone)]
pub enum BatchGetItem {
    /// Found document.
    Found(Document),
    /// Missing document name.
    Missing(String),
}

impl BatchGetItem {
    /// Path of the item.
    pub fn path(&self) -> Result<DocumentPath, Status> {
        match self {
            Self::Found(d) => Ok(d.path.clone()),
            Self::Missing(name) => decode_document_name(name).map_err(status),
        }
    }

    /// Snapshot document, if found.
    #[must_use]
    pub const fn document(&self) -> Option<&Document> {
        match self {
            Self::Found(d) => Some(d),
            Self::Missing(_) => None,
        }
    }

    /// Wire form with the response mask applied.
    #[must_use]
    pub fn encode(&self, mask: Option<&[FieldPath]>) -> pb::batch_get_documents_response::Result {
        match self {
            Self::Found(d) => {
                pb::batch_get_documents_response::Result::Found(encode_masked(d, mask))
            }
            Self::Missing(n) => pb::batch_get_documents_response::Result::Missing(n.clone()),
        }
    }
}

/// Result of a batch get: snapshots, the transaction to report and the read time.
#[derive(Debug, Clone)]
pub struct BatchGetOutcome {
    /// Items in request order.
    pub items: Vec<BatchGetItem>,
    /// New transaction token (empty unless `new_transaction` was requested).
    pub transaction: Vec<u8>,
    /// Snapshot time.
    pub read_time: ftd_core_types::time::LogicalInstant,
    /// Response mask.
    pub mask: Option<Vec<FieldPath>>,
}

/// A single-document read: the exact snapshot the response is built from.
#[derive(Debug, Clone)]
pub struct DocumentSnapshot {
    /// Path.
    pub path: DocumentPath,
    /// Snapshot (`None` = missing).
    pub document: Option<Document>,
    /// Response mask.
    pub mask: Option<Vec<FieldPath>>,
}

impl DocumentSnapshot {
    /// Wire form (`NOT_FOUND` when missing).
    pub fn into_response(self) -> Result<pb::Document, Status> {
        match self.document {
            Some(d) => Ok(encode_masked(&d, self.mask.as_deref())),
            None => Err(Status::not_found(format!(
                "Document not found: {}",
                self.path.resource_name()
            ))),
        }
    }
}

impl LocalBackend {
    /// Creates a backend with the strict gateway and a shared clock.
    #[must_use]
    pub fn new(gateway: Gateway, clock: Arc<Mutex<VirtualClock>>, seed: u64) -> Self {
        Self {
            gateway,
            clock,
            databases: Mutex::new(BTreeMap::new()),
            pending_actor: Mutex::new(None),
            faults: Mutex::new(None),
            clock_observer: Mutex::new(None),
            generations: Mutex::new(BTreeMap::new()),
            ids: Mutex::new(SplitMix64::new(seed)),
            commits: tokio::sync::broadcast::channel(1024).0,
            epoch: std::sync::atomic::AtomicU64::new(0),
            change_sink: Mutex::new(None),
            barrier: Arc::new(AdmissionBarrier::new()),
        }
    }

    /// The session's admission barrier (share it with every other mutable surface).
    #[must_use]
    pub fn barrier(&self) -> Arc<AdmissionBarrier> {
        self.barrier.clone()
    }

    /// Installs the synchronous commit observer (at most one). Contract: the sink runs
    /// inside the database critical section, so it must not call back into this backend
    /// (self-deadlock) and must not panic (poisoned lock); it should only hand the event to
    /// its own queue.
    pub fn set_change_sink(&self, sink: ChangeSink) {
        if let Ok(mut slot) = self.change_sink.lock() {
            *slot = Some(sink);
        }
    }

    /// Current reset epoch.
    pub fn epoch(&self) -> u64 {
        self.epoch.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// The wipe generation of a database (see `generations`).
    #[must_use]
    pub fn database_generation(&self, parent: &Parent) -> u64 {
        self.generations
            .lock()
            .ok()
            .and_then(|g| {
                g.get(&(
                    parent.project.as_str().to_owned(),
                    parent.database.as_str().to_owned(),
                ))
                .copied()
            })
            .unwrap_or(0)
    }

    fn bump_generations(&self, keys: &[(String, String)]) {
        if let Ok(mut g) = self.generations.lock() {
            for k in keys {
                *g.entry(k.clone()).or_insert(0) += 1;
            }
        }
    }

    /// Drops every database of one project (a session reset of that project): other
    /// projects' streams and epoch are untouched; the project's streams observe the wipe.
    pub fn reset_project(&self, project: &str) {
        self.reset_scope(&ftd_core_session::tenancy::Scope::Project(
            project.to_owned(),
        ));
    }

    /// Drops every database `scope` owns. The default session's scope also starts a new
    /// epoch (streams opened before it end like on a full reset); a project scope only
    /// bumps the generations of the databases it wiped.
    pub fn reset_scope(&self, scope: &ftd_core_session::tenancy::Scope) {
        if scope.is_default() {
            // Streams opened before the reset see the epoch change before any data is
            // dropped.
            self.epoch.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
        let cleared: Vec<(String, String)> = match self.databases.lock() {
            Ok(mut dbs) => {
                let keys: Vec<(String, String)> = dbs
                    .keys()
                    .filter(|(p, _)| scope.owns_project(p))
                    .cloned()
                    .collect();
                for k in &keys {
                    dbs.remove(k);
                }
                keys
            }
            Err(_) => Vec::new(),
        };
        self.bump_generations(&cleared);
        self.announce_wipe(cleared);
    }

    fn announce_wipe(&self, databases: Vec<(String, String)>) {
        for (project, database) in databases {
            let _ = self.commits.send(CommitEvent {
                actor: Actor::system(),
                project,
                database,
                version: 0,
                commit_time: None,
                changes: Arc::new(Vec::new()),
            });
        }
    }

    /// A copy of every database (the default session's snapshot).
    #[must_use]
    pub fn snapshot_databases(&self) -> BTreeMap<(String, String), FirestoreState> {
        self.databases
            .lock()
            .map(|dbs| dbs.clone())
            .unwrap_or_default()
    }

    /// The databases `scope` owns, plus the auto-ID generator for the default scope (it
    /// is shared by every project, so only the default session snapshots it).
    #[must_use]
    pub fn snapshot_scope(&self, scope: &ftd_core_session::tenancy::Scope) -> FirestoreSnapshot {
        let databases = self
            .databases
            .lock()
            .map(|dbs| {
                dbs.iter()
                    .filter(|((p, _), _)| scope.owns_project(p))
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect()
            })
            .unwrap_or_default();
        let ids = scope
            .is_default()
            .then(|| self.ids.lock().map(|r| r.clone()).ok())
            .flatten();
        FirestoreSnapshot { databases, ids }
    }

    /// Replaces every database with `databases` (the default session's restore): a new
    /// epoch, and the streams opened before it end like on a reset.
    pub fn restore_databases(&self, databases: BTreeMap<(String, String), FirestoreState>) {
        self.restore_scope(
            &ftd_core_session::tenancy::Scope::AllExcept(std::collections::BTreeSet::new()),
            &FirestoreSnapshot {
                databases,
                ids: None,
            },
        );
    }

    /// Replaces the databases `scope` owns with the snapshot's (the others stay). The
    /// default scope starts a new epoch and puts the auto-ID generator back; a project
    /// scope bumps the generations of the databases it replaced.
    pub fn restore_scope(
        &self,
        scope: &ftd_core_session::tenancy::Scope,
        snapshot: &FirestoreSnapshot,
    ) {
        if scope.is_default() {
            self.epoch.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
        let touched: Vec<(String, String)> = match self.databases.lock() {
            Ok(mut dbs) => {
                let mut keys: Vec<(String, String)> = dbs
                    .keys()
                    .filter(|(p, _)| scope.owns_project(p))
                    .cloned()
                    .collect();
                for k in &keys {
                    dbs.remove(k);
                }
                for (k, v) in &snapshot.databases {
                    if scope.owns_project(&k.0) {
                        if !keys.contains(k) {
                            keys.push(k.clone());
                        }
                        dbs.insert(k.clone(), v.clone());
                    }
                }
                keys
            }
            Err(_) => Vec::new(),
        };
        if let Some(ids) = &snapshot.ids {
            if let Ok(mut rng) = self.ids.lock() {
                *rng = ids.clone();
            }
        }
        self.bump_generations(&touched);
        self.announce_wipe(touched);
    }

    /// Drops every database (session reset). Listen streams observe the wipe as deletes.
    pub fn reset(&self) {
        self.reset_scope(&ftd_core_session::tenancy::Scope::AllExcept(
            std::collections::BTreeSet::new(),
        ));
    }

    /// Subscribes to commit events.
    #[must_use]
    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<CommitEvent> {
        self.commits.subscribe()
    }

    /// Publishes a commit: the change sink first (synchronously, inside the database
    /// critical section the caller holds), then the `Listen` broadcast.
    /// Shares the session's fault plan with this backend.
    pub fn set_faults(&self, faults: ftd_core_session::fault::SharedFaultRegistry) {
        if let Ok(mut slot) = self.faults.lock() {
            *slot = Some(faults);
        }
    }

    /// Installs the observer told after a fault plan moved the virtual clock.
    pub fn set_clock_observer(&self, observer: Arc<dyn Fn() + Send + Sync>) {
        if let Ok(mut slot) = self.clock_observer.lock() {
            *slot = Some(observer);
        }
    }

    fn clock_moved(&self) {
        let observer = self.clock_observer.lock().ok().and_then(|o| o.clone());
        if let Some(observer) = observer {
            observer();
        }
    }

    /// Applies `project`'s fault plan to `operation` (spec 18): an error action fails the
    /// request here, a delay moves the virtual clock before it runs.
    fn fault(&self, project: &str, operation: &str) -> Result<(), Status> {
        use ftd_core_session::fault::FaultAction;
        let faults = self.faults.lock().ok().and_then(|f| f.clone());
        for action in
            ftd_core_session::fault::decide_for(faults.as_ref(), project, operation, None, None)
        {
            match action {
                FaultAction::ReturnError { code } => {
                    return Err(Status::new(
                        grpc_code(&code),
                        format!("fault plan: {operation} returns {code}"),
                    ))
                }
                FaultAction::TransactionConflict => {
                    return Err(Status::aborted(format!(
                        "fault plan: {operation} conflicts (ABORTED)"
                    )))
                }
                FaultAction::Timeout => {
                    return Err(Status::deadline_exceeded(format!(
                        "fault plan: {operation} timed out"
                    )))
                }
                FaultAction::DropConnection => {
                    // The transport layer closes the connection instead of answering
                    // (see `DROP_CONNECTION_KEY`); the status is what a client that
                    // still gets an answer (WebChannel) sees.
                    let mut status = Status::unavailable(format!(
                        "fault plan: connection dropped during {operation}"
                    ));
                    if let Ok(v) = "1".parse() {
                        status.metadata_mut().insert(DROP_CONNECTION_KEY, v);
                    }
                    return Err(status);
                }
                FaultAction::Delay { seconds } => {
                    if let Ok(mut clock) = self.clock.lock() {
                        let _ = clock.advance(ftd_core_types::time::LogicalDuration::from_seconds(
                            seconds.max(0),
                        ));
                    }
                    self.clock_moved();
                }
                FaultAction::Duplicate { .. }
                | FaultAction::CrashRunner
                | FaultAction::DeadLetter => {}
            }
        }
        Ok(())
    }

    /// Stages the actor of the commit about to be published (called by write guards inside
    /// the database critical section).
    pub fn set_actor(&self, actor: Actor) {
        if let Ok(mut slot) = self.pending_actor.lock() {
            *slot = Some(actor);
        }
    }

    fn publish(&self, parent: &Parent, result: &CommitResult) {
        let actor = self
            .pending_actor
            .lock()
            .ok()
            .and_then(|mut a| a.take())
            .unwrap_or_else(Actor::system);
        let event = CommitEvent {
            actor,
            project: parent.project.as_str().to_owned(),
            database: parent.database.as_str().to_owned(),
            version: result.version.value(),
            commit_time: Some(result.commit_time),
            changes: Arc::new(result.changes.clone()),
        };
        if let Some(sink) = self.change_sink.lock().ok().and_then(|s| s.clone()) {
            sink(&event);
        }
        let _ = self.commits.send(event);
    }

    /// Commits `writes` outside a transaction (used by the `Write` stream).
    pub fn commit_writes(
        &self,
        parent: &Parent,
        writes: &[Write],
        guard: WriteGuard<'_>,
    ) -> Result<crate::streams::WireCommit, Status> {
        self.fault(parent.project.as_str(), "firestore.commit")?;
        let now = self.now();
        let result = self.with_db(parent, |db| {
            guard(db, writes, now)?;
            let result = db
                .commit(writes, None, now)
                .map_err(|e| status_from_error(&e))?;
            self.publish(parent, &result);
            Ok(result)
        })?;
        Ok(crate::streams::WireCommit::from_result(&result))
    }

    /// Current version and read time of a database (Listen boundaries, resume tokens).
    pub fn snapshot(
        &self,
        parent: &Parent,
    ) -> Result<(CommitVersion, ftd_core_types::time::LogicalInstant), Status> {
        let now = self.now();
        self.with_db(parent, |db| Ok((db.current_version(), db.read_time(now))))
    }

    /// Runs `f` against one consistent database snapshot (version, read time, lookups and
    /// queries all see the same state). `Listen` refreshes use it.
    pub fn with_snapshot<T>(
        &self,
        parent: &Parent,
        f: impl FnOnce(&FirestoreState, CommitVersion, ftd_core_types::time::LogicalInstant) -> T,
    ) -> Result<T, Status> {
        let now = self.now();
        self.with_db(parent, |db| {
            Ok(f(db, db.current_version(), db.read_time(now)))
        })
    }

    /// Decodes and validates a structured query through the strict gateway.
    pub fn accepted_query(
        &self,
        parent: &Parent,
        sq: &pb::StructuredQuery,
    ) -> Result<AcceptedQuery, Status> {
        let query = decode_structured_query(parent, sq).map_err(status)?;
        self.gateway
            .validate_query(&query)
            .map_err(|r| r.to_status())
    }

    /// Runs an accepted query at the latest version and returns core documents.
    pub fn run_query_latest(
        &self,
        parent: &Parent,
        query: &Query,
    ) -> Result<Vec<Document>, Status> {
        self.with_db(parent, |db| {
            db.run_query(query, None).map_err(|e| status_from_error(&e))
        })
    }

    /// `PartitionQuery`: cursor points that split a collection-group query (ordered by
    /// `__name__`, without filters, other orderings, limits or cursors) into up to
    /// `partition_count + 1` ranges of similar size, paged by `page_size` / `page_token`.
    /// The cuts are computed at one version (the `read_time` selector's, else the version
    /// current at the first page) that the page token carries, so later pages see the same
    /// partitioning whatever was written in between; the token is bound to the query.
    #[allow(clippy::too_many_lines)]
    pub fn partition_query(
        &self,
        req: &pb::PartitionQueryRequest,
    ) -> Result<pb::PartitionQueryResponse, Status> {
        let parent = parse_parent(&req.parent).map_err(status)?;
        if parent.document.is_some() {
            return Err(Status::invalid_argument(
                "PartitionQuery parent must be the database (projects/{p}/databases/{d}/documents)",
            ));
        }
        let Some(pb::partition_query_request::QueryType::StructuredQuery(sq)) = &req.query_type
        else {
            return Err(Status::invalid_argument(
                "PartitionQuery requires a structured_query",
            ));
        };
        let query = self.accepted_query(&parent, sq)?.query;
        let name_ascending_only = query.order_by.iter().all(|o| {
            o.field.is_document_name()
                && o.direction == ftd_core_firestore::query::Direction::Ascending
        });
        if !query.scope.all_descendants
            || query.filter.is_some()
            || !name_ascending_only
            || query.limit.is_some()
            || query.offset != 0
            || query.start_at.is_some()
            || query.end_at.is_some()
        {
            return Err(Status::invalid_argument(
                "PartitionQuery requires a collection group query ordered by __name__ only (no filters, order bys, limits, offsets or cursors)",
            ));
        }
        let partition_count = usize::try_from(req.partition_count)
            .ok()
            .filter(|n| *n > 0)
            .ok_or_else(|| Status::invalid_argument("partition_count must be positive"))?;
        if req.page_size < 0 {
            return Err(Status::invalid_argument("page_size must not be negative"));
        }
        let read_time = req.consistency_selector.as_ref().map(
            |pb::partition_query_request::ConsistencySelector::ReadTime(t)| {
                crate::encode::decode_instant(t)
            },
        );
        // Fingerprint of everything a page token must agree with, including the reset
        // epoch and the database generation: a token from before a reset or restore is
        // refused instead of resuming against unrelated history at the same version.
        let fingerprint = {
            let text = format!(
                "{}|{}|{}|{:?}|{}|{}",
                req.parent,
                query.scope.collection_id.as_str(),
                partition_count,
                read_time.map(ftd_core_types::time::LogicalInstant::as_nanos),
                self.epoch(),
                self.database_generation(&parent)
            );
            text.bytes().fold(0xcbf2_9ce4_8422_2325_u64, |h, b| {
                (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3)
            })
        };
        // The page token: `<version>:<fingerprint>:<index>`.
        let (token_version, start) = if req.page_token.is_empty() {
            (None, 0usize)
        } else {
            let parts: Vec<&str> = req.page_token.split(':').collect();
            let parsed = match parts.as_slice() {
                [v, f, i] => v
                    .parse::<u64>()
                    .ok()
                    .zip(f.parse::<u64>().ok())
                    .zip(i.parse::<usize>().ok())
                    .filter(|((_, f), _)| *f == fingerprint)
                    .map(|((v, _), i)| (v, i)),
                _ => None,
            };
            let (v, i) = parsed.ok_or_else(|| {
                Status::invalid_argument(
                    "invalid page_token (not issued for this query, count and read time, or the session was reset)",
                )
            })?;
            (Some(CommitVersion::from_value(v)), i)
        };
        let (names, version): (Vec<String>, CommitVersion) = self.with_db(&parent, |db| {
            let version = match (token_version, read_time) {
                (Some(v), _) => v,
                (None, Some(t)) => db.version_at(t),
                (None, None) => db.current_version(),
            };
            if version > db.current_version() {
                return Err(Status::invalid_argument("invalid page_token"));
            }
            db.run_query(&query, Some(version))
                .map(|docs| {
                    (
                        docs.iter().map(|d| d.path.resource_name()).collect(),
                        version,
                    )
                })
                .map_err(|e| status_from_error(&e))
        })?;
        // k cut points split n documents into k + 1 ranges; never more than n - 1 cuts.
        let cuts = partition_count.min(names.len().saturating_sub(1));
        let cursors: Vec<pb::Cursor> = (1..=cuts)
            .map(|i| pb::Cursor {
                values: vec![pb::Value {
                    value_type: Some(pb::value::ValueType::ReferenceValue(
                        names[names.len() * i / (cuts + 1)].clone(),
                    )),
                }],
                before: true,
            })
            .collect();
        if start > cursors.len() {
            return Err(Status::invalid_argument("invalid page_token"));
        }
        let page = usize::try_from(req.page_size)
            .ok()
            .filter(|n| *n > 0)
            .unwrap_or(cursors.len().max(1));
        let end = (start + page).min(cursors.len());
        Ok(pb::PartitionQueryResponse {
            partitions: cursors[start..end].to_vec(),
            next_page_token: if end < cursors.len() {
                format!("{}:{fingerprint}:{end}", version.value())
            } else {
                String::new()
            },
        })
    }

    /// Current logical time of the backend clock.
    pub fn now(&self) -> ftd_core_types::time::LogicalInstant {
        self.clock
            .lock()
            .map(|c| c.now())
            .unwrap_or(ftd_core_types::time::LogicalInstant::UNIX_EPOCH)
    }

    /// Reads a database without taking a session admission: for callers that already
    /// hold one (a Storage request evaluating `firestore.get()` in its rules). `None` when
    /// the database does not exist yet or the lock is poisoned.
    pub fn read_unadmitted<T>(
        &self,
        parent: &Parent,
        f: impl FnOnce(&FirestoreState) -> T,
    ) -> Option<T> {
        let dbs = self.databases.lock().ok()?;
        dbs.get(&(
            parent.project.as_str().to_owned(),
            parent.database.as_str().to_owned(),
        ))
        .map(f)
    }

    fn with_db<T>(
        &self,
        parent: &Parent,
        f: impl FnOnce(&mut FirestoreState) -> Result<T, Status>,
    ) -> Result<T, Status> {
        // Admitted for the whole critical section: a reset waits for it and nothing runs
        // against a half-reset session.
        let _admitted = self.barrier.admit();
        let mut dbs = self.databases.lock().map_err(|_| lock_poisoned())?;
        // An actor staged by a guard whose commit then failed must not be attributed to
        // this critical section's commit.
        if let Ok(mut actor) = self.pending_actor.lock() {
            actor.take();
        }
        let db = dbs
            .entry((
                parent.project.as_str().to_owned(),
                parent.database.as_str().to_owned(),
            ))
            .or_default();
        f(db)
    }

    fn auto_id(&self) -> String {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        let mut rng = match self.ids.lock() {
            Ok(r) => r,
            Err(p) => p.into_inner(),
        };
        (0..20)
            .map(|_| {
                let index = usize::try_from(rng.next_below(ALPHABET.len() as u64)).unwrap_or(0);
                ALPHABET[index] as char
            })
            .collect()
    }

    /// Wire token for a transaction: the handle plus a tag binding it to its database, so a
    /// token issued by one database is rejected by another.
    fn token(parent: &Parent, id: &TransactionId) -> Vec<u8> {
        let mut bytes = encode_transaction(id);
        bytes.extend_from_slice(&database_tag(parent).to_be_bytes());
        bytes
    }

    fn txn(parent: &Parent, bytes: &[u8]) -> Result<Option<TransactionId>, Status> {
        if bytes.is_empty() {
            return Ok(None);
        }
        let (handle, tag) = bytes.split_at(bytes.len().saturating_sub(8));
        let tag: Option<[u8; 8]> = tag.try_into().ok();
        if tag.map(u64::from_be_bytes) != Some(database_tag(parent)) {
            return Err(Status::invalid_argument(
                "transaction token does not belong to this database",
            ));
        }
        decode_transaction(handle).map(Some).map_err(status)
    }

    fn required_txn(parent: &Parent, bytes: &[u8]) -> Result<TransactionId, Status> {
        Self::txn(parent, bytes)?.ok_or_else(|| Status::invalid_argument("missing transaction"))
    }

    /// Rejects document names outside the request's database.
    pub fn check_database(parent: &Parent, name: &str) -> Result<DocumentPath, Status> {
        let path = decode_document_name(name).map_err(status)?;
        if path.project() != &parent.project || path.database() != &parent.database {
            return Err(Status::invalid_argument(format!(
                "document {name} does not belong to database projects/{}/databases/{}",
                parent.project.as_str(),
                parent.database.as_str()
            )));
        }
        Ok(path)
    }

    /// Validates a `read_time` selector: a well-formed, microsecond-precision timestamp that
    /// is not in the future and lies within the retention window
    /// ([`READ_TIME_RETENTION_SECONDS`]).
    fn read_time_selector(
        ts: &prost_types::Timestamp,
        now: ftd_core_types::time::LogicalInstant,
    ) -> Result<ftd_core_types::time::LogicalInstant, Status> {
        if !(0..1_000_000_000).contains(&ts.nanos) {
            return Err(Status::invalid_argument("read_time: nanos out of range"));
        }
        if ts.nanos % 1000 != 0 {
            return Err(Status::invalid_argument(
                "read_time must be a microsecond precision timestamp",
            ));
        }
        let at = crate::encode::decode_instant(ts);
        if at.as_nanos() > now.as_nanos() {
            return Err(Status::invalid_argument(
                "read_time must not be in the future",
            ));
        }
        let oldest = now.as_nanos() - i128::from(READ_TIME_RETENTION_SECONDS) * 1_000_000_000;
        if at.as_nanos() < oldest {
            return Err(Status::invalid_argument(format!(
                "read_time must be within the past {READ_TIME_RETENTION_SECONDS} seconds"
            )));
        }
        Ok(at)
    }

    /// Starts the transaction described by `new_transaction` options: read-only unless a
    /// read-write mode is given (Firestore's default for `new_transaction`), at the
    /// `read_time` snapshot when one is requested.
    fn new_transaction(
        db: &mut FirestoreState,
        opts: &pb::TransactionOptions,
        now: ftd_core_types::time::LogicalInstant,
    ) -> Result<TransactionId, Status> {
        match &opts.mode {
            Some(pb::transaction_options::Mode::ReadWrite(_)) => db.begin_transaction(false, now),
            Some(pb::transaction_options::Mode::ReadOnly(ro)) => match &ro.consistency_selector {
                Some(pb::transaction_options::read_only::ConsistencySelector::ReadTime(ts)) => {
                    let at = Self::read_time_selector(ts, now)?;
                    db.begin_transaction_at(at, now)
                }
                None => db.begin_transaction(true, now),
            },
            None => db.begin_transaction(true, now),
        }
        .map_err(|e| status_from_error(&e))
    }

    /// `GetDocument` as a snapshot, authorized by `guard` inside the critical section that
    /// reads it (then [`DocumentSnapshot::into_response`]).
    pub fn get_document_snapshot(
        &self,
        req: &pb::GetDocumentRequest,
        guard: ReadGuard<'_>,
    ) -> Result<DocumentSnapshot, Status> {
        let path = decode_document_name(&req.name).map_err(status)?;
        let parent = parse_parent(&req.name).map_err(status)?;
        self.fault(parent.project.as_str(), "firestore.read")?;
        let now = self.now();
        let (txn, read_at) = match &req.consistency_selector {
            Some(pb::get_document_request::ConsistencySelector::Transaction(t)) => {
                (Some(Self::required_txn(&parent, t)?), None)
            }
            Some(pb::get_document_request::ConsistencySelector::ReadTime(ts)) => {
                (None, Some(Self::read_time_selector(ts, now)?))
            }
            None => (None, None),
        };
        let mask = decode_mask(req.mask.as_ref()).map_err(status)?;
        let document = self.with_db(&parent, |db| {
            let (document, version) = match (&txn, read_at) {
                (Some(t), _) => {
                    db.touch_transaction(t, now)
                        .map_err(|e| status_from_error(&e))?;
                    let version = db
                        .transaction_read_version(t)
                        .map_err(|e| status_from_error(&e))?;
                    (db.get_at(&path, version).cloned(), Some(version))
                }
                (None, Some(at)) => {
                    let version = db.version_at(at);
                    (db.get_at(&path, version).cloned(), Some(version))
                }
                (None, None) => (db.get(&path).cloned(), None),
            };
            guard(
                db,
                version,
                ReadCheck::Document {
                    path: &path,
                    snapshot: document.as_ref(),
                },
            )?;
            // The read joins the transaction's read set only once it is authorized.
            if let Some(t) = &txn {
                db.record_transaction_read(t, &path, document.as_ref())
                    .map_err(|e| status_from_error(&e))?;
            }
            Ok(document)
        })?;
        Ok(DocumentSnapshot {
            path,
            document,
            mask,
        })
    }

    /// `GetDocument`.
    pub fn get_document(
        &self,
        req: &pb::GetDocumentRequest,
        guard: ReadGuard<'_>,
    ) -> Result<pb::Document, Status> {
        self.get_document_snapshot(req, guard)?.into_response()
    }

    /// `BatchGetDocuments`: returns the items and the transaction to report (new or given);
    /// every item is authorized by `guard` against the snapshot it is read from.
    pub fn batch_get_documents(
        &self,
        req: &pb::BatchGetDocumentsRequest,
        guard: ReadGuard<'_>,
    ) -> Result<BatchGetOutcome, Status> {
        let parent = parse_parent(&format!("{}/documents", req.database)).map_err(status)?;
        self.fault(parent.project.as_str(), "firestore.read")?;
        let now = self.now();
        let mask = decode_mask(req.mask.as_ref()).map_err(status)?;
        let paths = req
            .documents
            .iter()
            .map(|name| Self::check_database(&parent, name))
            .collect::<Result<Vec<_>, _>>()?;
        let read_at = match &req.consistency_selector {
            Some(pb::batch_get_documents_request::ConsistencySelector::ReadTime(ts)) => {
                Some(Self::read_time_selector(ts, now)?)
            }
            _ => None,
        };
        self.with_db(&parent, |db| {
            let (txn, report) = match &req.consistency_selector {
                Some(pb::batch_get_documents_request::ConsistencySelector::Transaction(t)) => {
                    let t = Self::required_txn(&parent, t)?;
                    db.touch_transaction(&t, now)
                        .map_err(|e| status_from_error(&e))?;
                    (Some(t), Vec::new())
                }
                Some(pb::batch_get_documents_request::ConsistencySelector::NewTransaction(
                    opts,
                )) => {
                    let id = Self::new_transaction(db, opts, now)?;
                    let bytes = Self::token(&parent, &id);
                    (Some(id), bytes)
                }
                Some(pb::batch_get_documents_request::ConsistencySelector::ReadTime(_)) | None => {
                    (None, Vec::new())
                }
            };
            let run = |db: &mut FirestoreState| -> Result<BatchGetOutcome, Status> {
                let read_time = match (&txn, read_at) {
                    (Some(t), _) => db
                        .transaction_read_time(t)
                        .map_err(|e| status_from_error(&e))?,
                    (None, Some(at)) => at,
                    (None, None) => db.read_time(now),
                };
                let version = match (&txn, read_at) {
                    (Some(t), _) => Some(
                        db.transaction_read_version(t)
                            .map_err(|e| status_from_error(&e))?,
                    ),
                    (None, Some(at)) => Some(db.version_at(at)),
                    (None, None) => None,
                };
                // Every document is read from the snapshot first, then the whole batch is
                // authorized, and only then do the reads join the transaction's read set.
                let reads: Vec<(DocumentPath, Option<Document>)> = paths
                    .iter()
                    .map(|path| {
                        let doc = match version {
                            Some(v) => db.get_at(path, v).cloned(),
                            None => db.get(path).cloned(),
                        };
                        (path.clone(), doc)
                    })
                    .collect();
                guard(db, version, ReadCheck::Documents(&reads))?;
                if let Some(t) = &txn {
                    for (path, doc) in &reads {
                        db.record_transaction_read(t, path, doc.as_ref())
                            .map_err(|e| status_from_error(&e))?;
                    }
                }
                let items = req
                    .documents
                    .iter()
                    .zip(reads)
                    .map(|(name, (_, doc))| match doc {
                        Some(d) => BatchGetItem::Found(d),
                        None => BatchGetItem::Missing(name.clone()),
                    })
                    .collect();
                Ok(BatchGetOutcome {
                    items,
                    transaction: report.clone(),
                    read_time,
                    mask: mask.clone(),
                })
            };
            let outcome = run(db);
            if outcome.is_err() && !report.is_empty() {
                // A refused read must not leave a transaction the client never learned of.
                if let Some(id) = &txn {
                    db.abandon_transaction(id);
                }
            }
            outcome
        })
    }

    /// Current document (latest version) without any transaction bookkeeping.
    pub fn current_document(
        &self,
        parent: &Parent,
        path: &DocumentPath,
    ) -> Result<Option<Document>, Status> {
        self.with_db(parent, |db| Ok(db.get(path).cloned()))
    }

    /// Result of `write` against the current state without publishing it.
    pub fn preview_write(
        &self,
        parent: &Parent,
        write: &Write,
    ) -> Result<Option<Document>, Status> {
        let now = self.now();
        self.with_db(parent, |db| {
            db.preview_write(write, now)
                .map_err(|e| status_from_error(&e))
        })
    }

    /// Decodes a `CreateDocument` request into its write (the document ID is fixed here, so
    /// that authorization and execution see the same path).
    pub fn plan_create(&self, req: &pb::CreateDocumentRequest) -> Result<(Parent, Write), Status> {
        let parent = parse_parent(&req.parent).map_err(status)?;
        let collection = CollectionId::try_new(req.collection_id.as_str())
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        let document_id = if req.document_id.is_empty() {
            self.auto_id()
        } else {
            req.document_id.clone()
        };
        DocumentId::try_new(document_id.as_str())
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        let relative = match &parent.document {
            Some(p) => format!("{}/{}/{}", p.relative(), collection.as_str(), document_id),
            None => format!("{}/{}", collection.as_str(), document_id),
        };
        let path = DocumentPath::parse(&parent.project, &parent.database, &relative)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        let fields = decode_fields(
            &req.document
                .as_ref()
                .map(|d| d.fields.clone())
                .unwrap_or_default(),
        )
        .map_err(status)?;
        let write = Write {
            op: WriteOp::Set {
                path,
                fields,
                update_mask: None,
            },
            precondition: Some(Precondition::Exists(false)),
            transforms: vec![],
        };
        Ok((parent, write))
    }

    /// `CreateDocument`.
    pub fn create_document(&self, req: &pb::CreateDocumentRequest) -> Result<pb::Document, Status> {
        let (parent, write) = self.plan_create(req)?;
        self.execute_planned(&parent, write, req.mask.as_ref())
    }

    /// Executes a single planned write and returns the resulting document.
    pub fn execute_planned(
        &self,
        parent: &Parent,
        write: Write,
        mask: Option<&pb::DocumentMask>,
    ) -> Result<pb::Document, Status> {
        self.execute_planned_with(parent, write, mask, &allow_all)
    }

    /// Executes a single planned write; `guard` runs inside the database critical section
    /// (Security Rules) right before the commit.
    pub fn execute_planned_with(
        &self,
        parent: &Parent,
        write: Write,
        mask: Option<&pb::DocumentMask>,
        guard: WriteGuard<'_>,
    ) -> Result<pb::Document, Status> {
        self.fault(parent.project.as_str(), "firestore.commit")?;
        let mask = decode_mask(mask).map_err(status)?;
        let path = write.op.path().clone();
        let now = self.now();
        let doc = self.with_db(parent, |db| {
            guard(db, std::slice::from_ref(&write), now)?;
            let result = db
                .commit(&[write], None, now)
                .map_err(|e| status_from_error(&e))?;
            let doc = db
                .get(&path)
                .map(|d| encode_masked(d, mask.as_deref()))
                .ok_or_else(|| Status::internal("document vanished after commit"))?;
            self.publish(parent, &result);
            Ok(doc)
        })?;
        Ok(doc)
    }

    /// Decodes an `UpdateDocument` request into its write.
    pub fn plan_update(req: &pb::UpdateDocumentRequest) -> Result<(Parent, Write), Status> {
        let doc = req
            .document
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("missing document"))?;
        let path = decode_document_name(&doc.name).map_err(status)?;
        let parent = parse_parent(&doc.name).map_err(status)?;
        let write = Write {
            op: WriteOp::Set {
                path,
                fields: decode_fields(&doc.fields).map_err(status)?,
                update_mask: decode_mask(req.update_mask.as_ref()).map_err(status)?,
            },
            precondition: decode_precondition(req.current_document.as_ref()).map_err(status)?,
            transforms: vec![],
        };
        Ok((parent, write))
    }

    /// `UpdateDocument`.
    pub fn update_document(&self, req: &pb::UpdateDocumentRequest) -> Result<pb::Document, Status> {
        let (parent, write) = Self::plan_update(req)?;
        self.execute_planned(&parent, write, req.mask.as_ref())
    }

    /// Decodes a `DeleteDocument` request into its write.
    pub fn plan_delete(req: &pb::DeleteDocumentRequest) -> Result<(Parent, Write), Status> {
        let path = decode_document_name(&req.name).map_err(status)?;
        let parent = parse_parent(&req.name).map_err(status)?;
        let write = Write {
            op: WriteOp::Delete { path },
            precondition: decode_precondition(req.current_document.as_ref()).map_err(status)?,
            transforms: vec![],
        };
        Ok((parent, write))
    }

    /// `DeleteDocument`.
    pub fn delete_document(&self, req: &pb::DeleteDocumentRequest) -> Result<(), Status> {
        self.delete_document_with(req, &allow_all)
    }

    /// `DeleteDocument` with a write guard.
    pub fn delete_document_with(
        &self,
        req: &pb::DeleteDocumentRequest,
        guard: WriteGuard<'_>,
    ) -> Result<(), Status> {
        let (parent, write) = Self::plan_delete(req)?;
        self.fault(parent.project.as_str(), "firestore.commit")?;
        let now = self.now();
        self.with_db(&parent, |db| {
            guard(db, std::slice::from_ref(&write), now)?;
            let result = db
                .commit(&[write], None, now)
                .map_err(|e| status_from_error(&e))?;
            self.publish(&parent, &result);
            Ok(())
        })
    }

    /// Decodes the writes of a `Commit` request (also used for authorization).
    pub fn plan_commit(req: &pb::CommitRequest) -> Result<(Parent, Vec<Write>), Status> {
        let parent = parse_parent(&format!("{}/documents", req.database)).map_err(status)?;
        let writes = req
            .writes
            .iter()
            .map(decode_write)
            .collect::<Result<Vec<_>, _>>()
            .map_err(status)?;
        for w in &writes {
            Self::check_database(&parent, &w.op.path().resource_name())?;
        }
        Ok((parent, writes))
    }

    /// Decodes the writes of a `BatchWrite` request that are well-formed (malformed writes
    /// are reported per write by [`Self::batch_write`]).
    pub fn plan_batch_write(req: &pb::BatchWriteRequest) -> Result<(Parent, Vec<Write>), Status> {
        let parent = parse_parent(&format!("{}/documents", req.database)).map_err(status)?;
        let writes = req
            .writes
            .iter()
            .filter_map(|w| decode_write(w).ok())
            .filter(|w| Self::check_database(&parent, &w.op.path().resource_name()).is_ok())
            .collect();
        Ok((parent, writes))
    }

    /// `BeginTransaction`.
    pub fn begin_transaction(&self, req: &pb::BeginTransactionRequest) -> Result<Vec<u8>, Status> {
        let parent = parse_parent(&format!("{}/documents", req.database)).map_err(status)?;
        self.fault(parent.project.as_str(), "firestore.beginTransaction")?;
        // BeginTransaction without options is read-write (unlike `new_transaction`).
        let now = self.now();
        self.with_db(&parent, |db| {
            let id = match req.options.as_ref().and_then(|o| o.mode.as_ref()) {
                Some(pb::transaction_options::Mode::ReadOnly(ro)) => {
                    match &ro.consistency_selector {
                        Some(
                            pb::transaction_options::read_only::ConsistencySelector::ReadTime(ts),
                        ) => {
                            let at = Self::read_time_selector(ts, now)?;
                            db.begin_transaction_at(at, now)
                        }
                        None => db.begin_transaction(true, now),
                    }
                }
                _ => db.begin_transaction(false, now),
            }
            .map_err(|e| status_from_error(&e))?;
            Ok(Self::token(&parent, &id))
        })
    }

    /// `Commit`.
    pub fn commit(&self, req: &pb::CommitRequest) -> Result<pb::CommitResponse, Status> {
        self.commit_with(req, &allow_all)
    }

    /// `Commit` with a write guard.
    pub fn commit_with(
        &self,
        req: &pb::CommitRequest,
        guard: WriteGuard<'_>,
    ) -> Result<pb::CommitResponse, Status> {
        let (parent, writes) = Self::plan_commit(req)?;
        self.fault(parent.project.as_str(), "firestore.commit")?;
        let txn = Self::txn(&parent, &req.transaction)?;
        let now = self.now();
        let result = self.with_db(&parent, |db| {
            guard(db, &writes, now)?;
            let result = db
                .commit(&writes, txn.as_ref(), now)
                .map_err(|e| status_from_error(&e))?;
            self.publish(&parent, &result);
            Ok(result)
        })?;
        Ok(encode_commit(&result))
    }

    /// `Rollback`.
    pub fn rollback(&self, req: &pb::RollbackRequest) -> Result<(), Status> {
        let parent = parse_parent(&format!("{}/documents", req.database)).map_err(status)?;
        let txn = Self::required_txn(&parent, &req.transaction)?;
        self.with_db(&parent, |db| {
            db.rollback(&txn).map_err(|e| status_from_error(&e))
        })
    }

    /// `RunQuery`: validates through the strict gateway, then executes locally.
    pub fn run_query(
        &self,
        req: &pb::RunQueryRequest,
        guard: ReadGuard<'_>,
    ) -> Result<(Vec<pb::RunQueryResponse>, Vec<String>), Status> {
        let parent = parse_parent(&req.parent).map_err(status)?;
        self.fault(parent.project.as_str(), "firestore.read")?;
        let Some(pb::run_query_request::QueryType::StructuredQuery(sq)) = &req.query_type else {
            return Err(Status::invalid_argument(
                "RunQuery requires a structured_query",
            ));
        };
        let query = decode_structured_query(&parent, sq).map_err(status)?;
        let accepted = self
            .gateway
            .validate_query(&query)
            .map_err(|r| r.to_status())?;
        let now = self.now();
        let read_at = match &req.consistency_selector {
            Some(pb::run_query_request::ConsistencySelector::ReadTime(ts)) => {
                Some(Self::read_time_selector(ts, now)?)
            }
            _ => None,
        };
        self.with_db(&parent, |db| {
            let (txn, report) = match &req.consistency_selector {
                Some(pb::run_query_request::ConsistencySelector::Transaction(t)) => {
                    let t = Self::required_txn(&parent, t)?;
                    db.touch_transaction(&t, now)
                        .map_err(|e| status_from_error(&e))?;
                    (Some(t), Vec::new())
                }
                Some(pb::run_query_request::ConsistencySelector::NewTransaction(opts)) => {
                    let id = Self::new_transaction(db, opts, now)?;
                    let bytes = Self::token(&parent, &id);
                    (Some(id), bytes)
                }
                Some(pb::run_query_request::ConsistencySelector::ReadTime(_)) | None => {
                    (None, Vec::new())
                }
            };
            let run = |db: &mut FirestoreState| -> Result<(Vec<pb::RunQueryResponse>, Vec<String>), Status> {
            let version = match (&txn, read_at) {
                (Some(t), _) => Some(
                    db.transaction_read_version(t)
                        .map_err(|e| status_from_error(&e))?,
                ),
                (None, Some(at)) => Some(db.version_at(at)),
                (None, None) => None,
            };
            // Authorized from the query constraints before any data is touched.
            guard(
                db,
                version,
                ReadCheck::Query {
                    parent: &parent,
                    query: &accepted.query,
                },
            )?;
            let docs = match &txn {
                Some(t) => db
                    .run_query_in_transaction(t, &accepted.query)
                    .map_err(|e| status_from_error(&e))?,
                None => db
                    .run_query(&accepted.query, version)
                    .map_err(|e| status_from_error(&e))?,
            };
            let read_time = Some(encode_instant(match (&txn, read_at) {
                (Some(t), _) => db
                    .transaction_read_time(t)
                    .map_err(|e| status_from_error(&e))?,
                (None, Some(at)) => at,
                (None, None) => db.read_time(now),
            }));
            Ok((
                query_responses(&docs, read_time, &report),
                accepted.warnings.clone(),
            ))
            };
            let outcome = run(db);
            if outcome.is_err() && !report.is_empty() {
                if let Some(id) = &txn {
                    db.abandon_transaction(id);
                }
            }
            outcome
        })
    }

    /// `RunAggregationQuery`.
    pub fn run_aggregation_query(
        &self,
        req: &pb::RunAggregationQueryRequest,
        guard: ReadGuard<'_>,
    ) -> Result<pb::RunAggregationQueryResponse, Status> {
        let parent = parse_parent(&req.parent).map_err(status)?;
        self.fault(parent.project.as_str(), "firestore.read")?;
        let Some(pb::run_aggregation_query_request::QueryType::StructuredAggregationQuery(saq)) =
            &req.query_type
        else {
            return Err(Status::invalid_argument(
                "RunAggregationQuery requires a structured_aggregation_query",
            ));
        };
        let Some(pb::structured_aggregation_query::QueryType::StructuredQuery(sq)) =
            &saq.query_type
        else {
            return Err(Status::invalid_argument(
                "aggregation query requires a structured_query",
            ));
        };
        let query = decode_structured_query(&parent, sq).map_err(status)?;
        let accepted = self
            .gateway
            .validate_query(&query)
            .map_err(|r| r.to_status())?;
        let (aliases, aggregations) = decode_aggregations(saq)?;
        let now = self.now();
        let read_at = match &req.consistency_selector {
            Some(pb::run_aggregation_query_request::ConsistencySelector::ReadTime(ts)) => {
                Some(Self::read_time_selector(ts, now)?)
            }
            _ => None,
        };
        self.with_db(&parent, |db| {
            let (txn, report) = match &req.consistency_selector {
                Some(pb::run_aggregation_query_request::ConsistencySelector::Transaction(t)) => {
                    let t = Self::required_txn(&parent, t)?;
                    db.touch_transaction(&t, now)
                        .map_err(|e| status_from_error(&e))?;
                    (Some(t), Vec::new())
                }
                Some(pb::run_aggregation_query_request::ConsistencySelector::NewTransaction(
                    opts,
                )) => {
                    let id = Self::new_transaction(db, opts, now)?;
                    let bytes = Self::token(&parent, &id);
                    (Some(id), bytes)
                }
                Some(pb::run_aggregation_query_request::ConsistencySelector::ReadTime(_))
                | None => (None, Vec::new()),
            };
            let run = |db: &mut FirestoreState| -> Result<pb::RunAggregationQueryResponse, Status> {
                let version = match (&txn, read_at) {
                    (Some(t), _) => Some(
                        db.transaction_read_version(t)
                            .map_err(|e| status_from_error(&e))?,
                    ),
                    (None, Some(at)) => Some(db.version_at(at)),
                    (None, None) => None,
                };
                // The underlying query is authorized from its constraints, like a list.
                guard(
                    db,
                    version,
                    ReadCheck::Query {
                        parent: &parent,
                        query: &accepted.query,
                    },
                )?;
                // Inside a transaction the aggregation is computed at the snapshot and the query
                // is recorded so that later changes abort the commit.
                if let Some(t) = &txn {
                    db.run_query_in_transaction(t, &accepted.query)
                        .map_err(|e| status_from_error(&e))?;
                }
                let read_time = match (&txn, read_at) {
                    (Some(t), _) => db
                        .transaction_read_time(t)
                        .map_err(|e| status_from_error(&e))?,
                    (None, Some(at)) => at,
                    (None, None) => db.read_time(now),
                };
                let values = db
                    .run_aggregation(&accepted.query, &aggregations, version)
                    .map_err(|e| status_from_error(&e))?;
                let aggregate_fields: HashMap<String, pb::Value> = aliases
                    .into_iter()
                    .zip(values.iter().map(encode_value))
                    .collect();
                Ok(pb::RunAggregationQueryResponse {
                    result: Some(pb::AggregationResult { aggregate_fields }),
                    transaction: report.clone(),
                    read_time: Some(encode_instant(read_time)),
                    explain_metrics: None,
                })
            };
            let outcome = run(db);
            if outcome.is_err() && !report.is_empty() {
                if let Some(id) = &txn {
                    db.abandon_transaction(id);
                }
            }
            outcome
        })
    }

    /// `ListDocuments`: paged by name; transaction and `read_time` snapshots supported.
    pub fn list_documents(
        &self,
        req: &pb::ListDocumentsRequest,
        guard: ReadGuard<'_>,
    ) -> Result<pb::ListDocumentsResponse, Status> {
        let parent = parse_parent(&req.parent).map_err(status)?;
        self.fault(parent.project.as_str(), "firestore.read")?;
        let now = self.now();
        let (txn, read_at) = match &req.consistency_selector {
            Some(pb::list_documents_request::ConsistencySelector::ReadTime(ts)) => {
                (None, Some(Self::read_time_selector(ts, now)?))
            }
            Some(pb::list_documents_request::ConsistencySelector::Transaction(t)) => {
                (Some(Self::required_txn(&parent, t)?), None)
            }
            None => (None, None),
        };
        // Page tokens carry the resource name of the last document of the previous page
        // (documents are listed by name) and the identity of the listing they continue:
        // parent, collection, mask, and the snapshot (live, read_time or transaction).
        let identity = format!(
            "{}|{}|{}|{}",
            req.parent,
            req.collection_id,
            req.mask
                .as_ref()
                .map(|m| m.field_paths.join(","))
                .unwrap_or_default(),
            match (&txn, read_at) {
                (Some(t), _) => format!(
                    "txn:{}",
                    crate::rest::json::base64_encode(&encode_transaction(t))
                ),
                (None, Some(at)) => format!("rt:{}", at.as_nanos()),
                (None, None) => "live".to_owned(),
            }
        );
        let after = list_page_cursor(&req.page_token, &identity)?;
        let mask = decode_mask(req.mask.as_ref()).map_err(status)?;
        if req.page_size < 0 {
            return Err(Status::invalid_argument("page_size must not be negative"));
        }
        let accepted = self.accepted_query(&parent, &list_query(req))?;
        // The rules see the page size as `request.query.limit` (the number of documents the
        // request can return); the scan itself stays unlimited so the page cursor applies
        // before truncation.
        let page_size = if req.page_size > 0 {
            usize::try_from(req.page_size).unwrap_or(usize::MAX)
        } else {
            DEFAULT_LIST_PAGE_SIZE
        };
        let mut proof_query = accepted.query.clone();
        proof_query.limit = Some(u32::try_from(page_size).unwrap_or(u32::MAX));
        self.with_db(&parent, |db| {
            let version = match (&txn, read_at) {
                (Some(t), _) => {
                    db.touch_transaction(t, now)
                        .map_err(|e| status_from_error(&e))?;
                    Some(
                        db.transaction_read_version(t)
                            .map_err(|e| status_from_error(&e))?,
                    )
                }
                (None, Some(at)) => Some(db.version_at(at)),
                (None, None) => None,
            };
            guard(
                db,
                version,
                ReadCheck::Query {
                    parent: &parent,
                    query: &proof_query,
                },
            )?;
            // Inside a transaction the scan is recorded like a query, so a concurrent
            // change to the collection aborts the commit.
            let mut docs = match &txn {
                Some(t) => db
                    .run_query_in_transaction(t, &accepted.query)
                    .map_err(|e| status_from_error(&e))?,
                None => db.list_documents_at(parent.document.as_ref(), &req.collection_id, version),
            };
            if let Some(after) = &after {
                docs.retain(|d| d.path.resource_name() > *after);
            }
            let has_more = docs.len() > page_size;
            docs.truncate(page_size);
            let next_page_token = if has_more {
                docs.last().map_or(String::new(), |d| {
                    crate::rest::json::base64_encode(
                        format!("{}\n{identity}", d.path.resource_name()).as_bytes(),
                    )
                })
            } else {
                String::new()
            };
            let documents = docs
                .iter()
                .map(|d| {
                    let mut d = d.clone();
                    if let Some(mask) = &mask {
                        d.fields = project_fields(&d.fields, mask);
                    }
                    encode_document(&d)
                })
                .collect();
            Ok(pb::ListDocumentsResponse {
                documents,
                next_page_token,
            })
        })
    }

    /// `ListCollectionIds`.
    pub fn list_collection_ids(
        &self,
        req: &pb::ListCollectionIdsRequest,
    ) -> Result<pb::ListCollectionIdsResponse, Status> {
        let parent = parse_parent(&req.parent).map_err(status)?;
        let after: Option<String> = if req.page_token.is_empty() {
            None
        } else {
            Some(
                String::from_utf8(
                    crate::rest::json::base64_decode(&req.page_token)
                        .map_err(|_| Status::invalid_argument("malformed page_token"))?,
                )
                .map_err(|_| Status::invalid_argument("malformed page_token"))?,
            )
        };
        let page_size = if req.page_size > 0 {
            usize::try_from(req.page_size).unwrap_or(usize::MAX)
        } else {
            DEFAULT_LIST_PAGE_SIZE
        };
        self.with_db(&parent, |db| {
            let mut ids = db.list_collection_ids(parent.document.as_ref());
            if let Some(after) = &after {
                ids.retain(|id| id > after);
            }
            let has_more = ids.len() > page_size;
            ids.truncate(page_size);
            let next_page_token = if has_more {
                ids.last().map_or(String::new(), |id| {
                    crate::rest::json::base64_encode(id.as_bytes())
                })
            } else {
                String::new()
            };
            Ok(pb::ListCollectionIdsResponse {
                collection_ids: ids,
                next_page_token,
            })
        })
    }

    /// `BatchWrite`: each write is applied independently and reported with its own status.
    pub fn batch_write(
        &self,
        req: &pb::BatchWriteRequest,
    ) -> Result<pb::BatchWriteResponse, Status> {
        self.batch_write_with(req, &allow_all)
    }

    /// `BatchWrite` with a write guard (run per write, inside the critical section).
    pub fn batch_write_with(
        &self,
        req: &pb::BatchWriteRequest,
        guard: WriteGuard<'_>,
    ) -> Result<pb::BatchWriteResponse, Status> {
        let parent = parse_parent(&format!("{}/documents", req.database)).map_err(status)?;
        self.fault(parent.project.as_str(), "firestore.commit")?;
        let now = self.now();
        let decoded: Vec<Result<Write, Status>> = req
            .writes
            .iter()
            .map(|w| {
                let write = decode_write(w).map_err(status)?;
                Self::check_database(&parent, &write.op.path().resource_name())?;
                Ok(write)
            })
            .collect();
        let mut targets = std::collections::BTreeSet::new();
        for path in decoded
            .iter()
            .filter_map(|w| w.as_ref().ok().map(|w| w.op.path()))
        {
            if !targets.insert(path.clone()) {
                return Err(Status::invalid_argument(format!(
                    "BatchWrite contains multiple writes to {}",
                    path.resource_name()
                )));
            }
        }
        self.with_db(&parent, |db| {
            let mut write_results = Vec::with_capacity(req.writes.len());
            let mut statuses = Vec::with_capacity(req.writes.len());
            for decoded in decoded {
                let outcome = decoded.and_then(|write| {
                    guard(db, std::slice::from_ref(&write), now)?;
                    db.commit(std::slice::from_ref(&write), None, now)
                        .map_err(|e| status_from_error(&e))
                });
                match outcome {
                    Ok(result) => {
                        let encoded = encode_commit(&result);
                        // Every successful write is its own commit and is published as such,
                        // in write order, with its own commit time.
                        self.publish(&parent, &result);
                        write_results
                            .push(encoded.write_results.into_iter().next().unwrap_or_default());
                        statuses.push(ftd_proto_firestore::google::rpc::Status {
                            code: 0,
                            message: String::new(),
                            details: Vec::new(),
                        });
                    }
                    Err(s) => {
                        write_results.push(pb::WriteResult::default());
                        statuses.push(ftd_proto_firestore::google::rpc::Status {
                            code: i32::from(s.code()),
                            message: s.message().to_owned(),
                            details: Vec::new(),
                        });
                    }
                }
            }
            Ok(pb::BatchWriteResponse {
                write_results,
                status: statuses,
            })
        })
    }
}

/// Core commit result → wire.
#[must_use]
pub fn encode_commit(result: &CommitResult) -> pb::CommitResponse {
    pb::CommitResponse {
        write_results: result
            .write_results
            .iter()
            .map(|w| pb::WriteResult {
                update_time: w.update_time.map(encode_instant),
                transform_results: w.transform_results.iter().map(encode_value).collect(),
            })
            .collect(),
        commit_time: Some(encode_instant(result.commit_time)),
    }
}

/// Firestore accepts at most this many aggregations in one query.
const MAX_AGGREGATIONS_PER_QUERY: usize = 5;

/// Decodes and validates the aggregation list: 1..=5 entries, positive `count.up_to`,
/// unique aliases.
fn decode_aggregations(
    saq: &pb::StructuredAggregationQuery,
) -> Result<(Vec<String>, Vec<Aggregation>), Status> {
    if saq.aggregations.is_empty() || saq.aggregations.len() > MAX_AGGREGATIONS_PER_QUERY {
        return Err(Status::invalid_argument(format!(
            "an aggregation query needs 1..={MAX_AGGREGATIONS_PER_QUERY} aggregations"
        )));
    }
    let mut aliases: Vec<String> = Vec::with_capacity(saq.aggregations.len());
    let mut aggregations = Vec::with_capacity(saq.aggregations.len());
    for (i, a) in saq.aggregations.iter().enumerate() {
        use pb::structured_aggregation_query::aggregation::Operator as O;
        let field =
            |f: &Option<pb::structured_query::FieldReference>| -> Result<FieldPath, Status> {
                let r = f
                    .as_ref()
                    .ok_or_else(|| Status::invalid_argument("aggregation without field"))?;
                FieldPath::parse(&r.field_path).map_err(|e| Status::invalid_argument(e.to_string()))
            };
        let agg = match &a.operator {
            Some(O::Count(c)) => Aggregation::Count {
                up_to: match c.up_to {
                    None => None,
                    Some(n) if n > 0 => Some(u64::try_from(n).unwrap_or(u64::MAX)),
                    Some(_) => {
                        return Err(Status::invalid_argument("count.up_to must be positive"))
                    }
                },
            },
            Some(O::Sum(s)) => Aggregation::Sum(field(&s.field)?),
            Some(O::Avg(v)) => Aggregation::Avg(field(&v.field)?),
            None => return Err(Status::invalid_argument("aggregation without operator")),
        };
        let alias = if a.alias.is_empty() {
            format!("field_{}", i + 1)
        } else {
            a.alias.clone()
        };
        if aliases.contains(&alias) {
            return Err(Status::invalid_argument(format!(
                "duplicate aggregation alias {alias:?}"
            )));
        }
        aliases.push(alias);
        aggregations.push(agg);
    }
    Ok((aliases, aggregations))
}

fn database_tag(parent: &Parent) -> u64 {
    // FNV-1a over "project\0database": stable, dependency-free.
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in parent
        .project
        .as_str()
        .bytes()
        .chain(core::iter::once(0))
        .chain(parent.database.as_str().bytes())
    {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    h
}

fn encode_masked(doc: &Document, mask: Option<&[FieldPath]>) -> pb::Document {
    match mask {
        Some(mask) => {
            let mut d = doc.clone();
            d.fields = project_fields(&d.fields, mask);
            encode_document(&d)
        }
        None => encode_document(doc),
    }
}

fn project_fields(
    fields: &BTreeMap<String, ftd_core_firestore::value::Value>,
    mask: &[FieldPath],
) -> BTreeMap<String, ftd_core_firestore::value::Value> {
    ftd_core_firestore::store::project(fields, mask)
}

/// Convenience for tests: documents as (relative path, fields).
#[must_use]
pub fn document_summary(
    doc: &Document,
) -> (String, BTreeMap<String, ftd_core_firestore::value::Value>) {
    (doc.path.relative(), doc.fields.clone())
}

/// Structured query of a `ListDocuments` request (unfiltered collection scan).
#[must_use]
pub fn list_query(req: &pb::ListDocumentsRequest) -> pb::StructuredQuery {
    pb::StructuredQuery {
        from: vec![pb::structured_query::CollectionSelector {
            collection_id: req.collection_id.clone(),
            all_descendants: false,
        }],
        ..Default::default()
    }
}

/// The document name a `ListDocuments` page token continues after; the token must have been
/// issued for the same listing (`identity`).
fn list_page_cursor(page_token: &str, identity: &str) -> Result<Option<String>, Status> {
    if page_token.is_empty() {
        return Ok(None);
    }
    let malformed = || Status::invalid_argument("malformed page_token");
    let token =
        String::from_utf8(crate::rest::json::base64_decode(page_token).map_err(|_| malformed())?)
            .map_err(|_| malformed())?;
    let (name, token_identity) = token.split_once('\n').ok_or_else(malformed)?;
    if token_identity != identity {
        return Err(Status::invalid_argument(
            "page_token was issued for a different listing (parent, collection, mask or snapshot)",
        ));
    }
    decode_document_name(name).map_err(|_| malformed())?;
    Ok(Some(name.to_owned()))
}

/// `RunQuery` responses for `docs`: one per document (or one empty response carrying the
/// read time), preceded by a dedicated response announcing a new transaction.
fn query_responses(
    docs: &[Document],
    read_time: Option<prost_types::Timestamp>,
    new_transaction: &[u8],
) -> Vec<pb::RunQueryResponse> {
    let mut responses: Vec<pb::RunQueryResponse> = docs
        .iter()
        .map(|d| pb::RunQueryResponse {
            transaction: Vec::new(),
            document: Some(encode_document(d)),
            read_time,
            skipped_results: 0,
            ..Default::default()
        })
        .collect();
    if responses.is_empty() {
        // A result-less query still answers with one response carrying read_time.
        responses.push(pb::RunQueryResponse {
            transaction: Vec::new(),
            document: None,
            read_time,
            skipped_results: 0,
            ..Default::default()
        });
    }
    if !new_transaction.is_empty() {
        // A new transaction is announced in a dedicated first response that carries nothing
        // else (RunQueryResponse contract).
        responses.insert(
            0,
            pb::RunQueryResponse {
                transaction: new_transaction.to_vec(),
                ..Default::default()
            },
        );
    }
    responses
}

/// A gRPC status code from its name (or `UNKNOWN`).
fn grpc_code(name: &str) -> tonic::Code {
    match name.to_ascii_uppercase().as_str() {
        "CANCELLED" => tonic::Code::Cancelled,
        "INVALID_ARGUMENT" => tonic::Code::InvalidArgument,
        "DEADLINE_EXCEEDED" => tonic::Code::DeadlineExceeded,
        "NOT_FOUND" => tonic::Code::NotFound,
        "ALREADY_EXISTS" => tonic::Code::AlreadyExists,
        "PERMISSION_DENIED" => tonic::Code::PermissionDenied,
        "RESOURCE_EXHAUSTED" => tonic::Code::ResourceExhausted,
        "FAILED_PRECONDITION" => tonic::Code::FailedPrecondition,
        "ABORTED" => tonic::Code::Aborted,
        "OUT_OF_RANGE" => tonic::Code::OutOfRange,
        "UNIMPLEMENTED" => tonic::Code::Unimplemented,
        "INTERNAL" => tonic::Code::Internal,
        "UNAVAILABLE" => tonic::Code::Unavailable,
        "DATA_LOSS" => tonic::Code::DataLoss,
        "UNAUTHENTICATED" => tonic::Code::Unauthenticated,
        _ => tonic::Code::Unknown,
    }
}
