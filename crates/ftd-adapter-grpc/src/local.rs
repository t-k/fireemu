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
    ids: Mutex<SplitMix64>,
    commits: tokio::sync::broadcast::Sender<CommitEvent>,
    /// Bumped by every reset; long-lived streams compare it to refuse stale sessions.
    epoch: std::sync::atomic::AtomicU64,
    /// Called for every commit inside the database critical section, in commit order and
    /// before the commit's response is returned (event triggers): nothing is lost or
    /// reordered, and `await-idle` sees the event as soon as the write returns.
    change_sink: Mutex<Option<ChangeSink>>,
}

/// Synchronous observer of commits (see [`LocalBackend::set_change_sink`]).
pub type ChangeSink = Arc<dyn Fn(&CommitEvent) + Send + Sync>;

/// Published after every successful commit (drives `Listen` streams).
#[derive(Debug, Clone, PartialEq)]
pub struct CommitEvent {
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
            ids: Mutex::new(SplitMix64::new(seed)),
            commits: tokio::sync::broadcast::channel(1024).0,
            epoch: std::sync::atomic::AtomicU64::new(0),
            change_sink: Mutex::new(None),
        }
    }

    /// Installs the synchronous commit observer (at most one).
    pub fn set_change_sink(&self, sink: ChangeSink) {
        if let Ok(mut slot) = self.change_sink.lock() {
            *slot = Some(sink);
        }
    }

    /// Current reset epoch.
    pub fn epoch(&self) -> u64 {
        self.epoch.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Drops every database (session reset). Listen streams observe the wipe as deletes.
    pub fn reset(&self) {
        // Streams opened before the reset see the epoch change before any data is dropped.
        self.epoch.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let cleared: Vec<(String, String)> = match self.databases.lock() {
            Ok(mut dbs) => {
                let keys = dbs.keys().cloned().collect();
                dbs.clear();
                keys
            }
            Err(_) => Vec::new(),
        };
        for (project, database) in cleared {
            let _ = self.commits.send(CommitEvent {
                project,
                database,
                version: 0,
                commit_time: None,
                changes: Arc::new(Vec::new()),
            });
        }
    }

    /// Subscribes to commit events.
    #[must_use]
    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<CommitEvent> {
        self.commits.subscribe()
    }

    /// Publishes a commit: the change sink first (synchronously, inside the database
    /// critical section the caller holds), then the `Listen` broadcast.
    fn publish(&self, parent: &Parent, result: &CommitResult) {
        let event = CommitEvent {
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

    /// Current logical time of the backend clock.
    pub fn now(&self) -> ftd_core_types::time::LogicalInstant {
        self.clock
            .lock()
            .map(|c| c.now())
            .unwrap_or(ftd_core_types::time::LogicalInstant::UNIX_EPOCH)
    }

    fn with_db<T>(
        &self,
        parent: &Parent,
        f: impl FnOnce(&mut FirestoreState) -> Result<T, Status>,
    ) -> Result<T, Status> {
        let mut dbs = self.databases.lock().map_err(|_| lock_poisoned())?;
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
        let accepted = self.accepted_query(&parent, &list_query(req))?;
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
                    query: &accepted.query,
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
            let page_size = if req.page_size > 0 {
                usize::try_from(req.page_size).unwrap_or(usize::MAX)
            } else {
                DEFAULT_LIST_PAGE_SIZE
            };
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
