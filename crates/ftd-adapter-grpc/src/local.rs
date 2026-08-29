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
    Aggregation, CommitResult, CommitVersion, Document, FirestoreState, Precondition,
    TransactionId, Write, WriteOp,
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
use crate::gateway::{Gateway, Rejection};

/// Local backend state.
pub struct LocalBackend {
    gateway: Gateway,
    clock: Arc<Mutex<VirtualClock>>,
    databases: Mutex<BTreeMap<(String, String), FirestoreState>>,
    ids: Mutex<SplitMix64>,
    commits: tokio::sync::broadcast::Sender<CommitEvent>,
}

/// Published after every successful commit (drives `Listen` streams).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitEvent {
    /// Project.
    pub project: String,
    /// Database.
    pub database: String,
    /// Version after the commit.
    pub version: u64,
}

fn status(e: DecodeError) -> Status {
    Rejection::Decode(e).to_status()
}

fn lock_poisoned() -> Status {
    Status::internal("backend state lock poisoned")
}

/// Response of a batch get.
#[derive(Debug)]
pub enum BatchGetItem {
    /// Found document.
    Found(pb::Document),
    /// Missing document name.
    Missing(String),
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
        }
    }

    /// Subscribes to commit events.
    #[must_use]
    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<CommitEvent> {
        self.commits.subscribe()
    }

    fn publish(&self, parent: &Parent, version: CommitVersion) {
        let _ = self.commits.send(CommitEvent {
            project: parent.project.as_str().to_owned(),
            database: parent.database.as_str().to_owned(),
            version: version.value(),
        });
    }

    /// Commits `writes` outside a transaction (used by the `Write` stream).
    pub fn commit_writes(
        &self,
        parent: &Parent,
        writes: &[Write],
    ) -> Result<crate::streams::WireCommit, Status> {
        let now = self.now();
        let result = self.with_db(parent, |db| {
            db.commit(writes, None, now)
                .map_err(|e| status_from_error(&e))
        })?;
        self.publish(parent, result.version);
        Ok(crate::streams::WireCommit::from_result(&result))
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

    fn new_transaction_is_read_only(opts: &pb::TransactionOptions) -> bool {
        // Firestore defaults `new_transaction` without a mode to read-only.
        !matches!(opts.mode, Some(pb::transaction_options::Mode::ReadWrite(_)))
    }

    /// `GetDocument`.
    pub fn get_document(&self, req: &pb::GetDocumentRequest) -> Result<pb::Document, Status> {
        let path = decode_document_name(&req.name).map_err(status)?;
        let parent = parse_parent(&req.name).map_err(status)?;
        let txn = match &req.consistency_selector {
            Some(pb::get_document_request::ConsistencySelector::Transaction(t)) => {
                Self::txn(&parent, t)?
            }
            Some(pb::get_document_request::ConsistencySelector::ReadTime(_)) => {
                return Err(Status::unimplemented(
                    "read_time consistency is not implemented",
                ))
            }
            None => None,
        };
        let mask = decode_mask(req.mask.as_ref()).map_err(status)?;
        let now = self.now();
        self.with_db(&parent, |db| {
            let doc = match &txn {
                Some(t) => {
                    db.touch_transaction(t, now)
                        .map_err(|e| status_from_error(&e))?;
                    db.get_in_transaction(t, &path)
                        .map_err(|e| status_from_error(&e))?
                }
                None => db.get(&path).cloned(),
            };
            let mut doc = doc.ok_or_else(|| {
                Status::not_found(format!("Document not found: {}", path.resource_name()))
            })?;
            if let Some(mask) = &mask {
                doc.fields = project_fields(&doc.fields, mask);
            }
            Ok(encode_document(&doc))
        })
    }

    /// `BatchGetDocuments`: returns the items and the transaction to report (new or given).
    pub fn batch_get_documents(
        &self,
        req: &pb::BatchGetDocumentsRequest,
    ) -> Result<
        (
            Vec<BatchGetItem>,
            Vec<u8>,
            ftd_core_types::time::LogicalInstant,
        ),
        Status,
    > {
        let parent = parse_parent(&format!("{}/documents", req.database)).map_err(status)?;
        let now = self.now();
        let mask = decode_mask(req.mask.as_ref()).map_err(status)?;
        let paths = req
            .documents
            .iter()
            .map(|name| Self::check_database(&parent, name))
            .collect::<Result<Vec<_>, _>>()?;
        self.with_db(&parent, |db| {
            let (txn, report) = match &req.consistency_selector {
                Some(pb::batch_get_documents_request::ConsistencySelector::Transaction(t)) => {
                    let t = Self::txn(&parent, t)?;
                    if let Some(t) = &t {
                        db.touch_transaction(t, now)
                            .map_err(|e| status_from_error(&e))?;
                    }
                    (t, Vec::new())
                }
                Some(pb::batch_get_documents_request::ConsistencySelector::NewTransaction(
                    opts,
                )) => {
                    let id = db
                        .begin_transaction(Self::new_transaction_is_read_only(opts), now)
                        .map_err(|e| status_from_error(&e))?;
                    let bytes = Self::token(&parent, &id);
                    (Some(id), bytes)
                }
                Some(pb::batch_get_documents_request::ConsistencySelector::ReadTime(_)) => {
                    return Err(Status::unimplemented(
                        "read_time consistency is not implemented",
                    ))
                }
                None => (None, Vec::new()),
            };
            let read_time = match &txn {
                Some(t) => db
                    .transaction_read_time(t)
                    .map_err(|e| status_from_error(&e))?,
                None => db.read_time(now),
            };
            let mut items = Vec::with_capacity(req.documents.len());
            for (name, path) in req.documents.iter().zip(&paths) {
                let path = path.clone();
                let doc = match &txn {
                    Some(t) => db
                        .get_in_transaction(t, &path)
                        .map_err(|e| status_from_error(&e))?,
                    None => db.get(&path).cloned(),
                };
                items.push(match doc {
                    Some(mut d) => {
                        if let Some(mask) = &mask {
                            d.fields = project_fields(&d.fields, mask);
                        }
                        BatchGetItem::Found(encode_document(&d))
                    }
                    None => BatchGetItem::Missing(name.clone()),
                });
            }
            Ok((items, report, read_time))
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
        let mask = decode_mask(mask).map_err(status)?;
        let path = write.op.path().clone();
        let now = self.now();
        let (doc, version) = self.with_db(parent, |db| {
            let result = db
                .commit(&[write], None, now)
                .map_err(|e| status_from_error(&e))?;
            let doc = db
                .get(&path)
                .map(|d| encode_masked(d, mask.as_deref()))
                .ok_or_else(|| Status::internal("document vanished after commit"))?;
            Ok((doc, result.version))
        })?;
        self.publish(parent, version);
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
        let (parent, write) = Self::plan_delete(req)?;
        let now = self.now();
        let version = self.with_db(&parent, |db| {
            db.commit(&[write], None, now)
                .map(|r| r.version)
                .map_err(|e| status_from_error(&e))
        })?;
        self.publish(&parent, version);
        Ok(())
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
        let read_only = matches!(
            req.options.as_ref().and_then(|o| o.mode.as_ref()),
            Some(pb::transaction_options::Mode::ReadOnly(_))
        );
        let now = self.now();
        self.with_db(&parent, |db| {
            db.begin_transaction(read_only, now)
                .map(|id| Self::token(&parent, &id))
                .map_err(|e| status_from_error(&e))
        })
    }

    /// `Commit`.
    pub fn commit(&self, req: &pb::CommitRequest) -> Result<pb::CommitResponse, Status> {
        let (parent, writes) = Self::plan_commit(req)?;
        let txn = Self::txn(&parent, &req.transaction)?;
        let now = self.now();
        let result = self.with_db(&parent, |db| {
            db.commit(&writes, txn.as_ref(), now)
                .map_err(|e| status_from_error(&e))
        })?;
        self.publish(&parent, result.version);
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
        self.with_db(&parent, |db| {
            let (txn, report) = match &req.consistency_selector {
                Some(pb::run_query_request::ConsistencySelector::Transaction(t)) => {
                    let t = Self::txn(&parent, t)?;
                    if let Some(t) = &t {
                        db.touch_transaction(t, now)
                            .map_err(|e| status_from_error(&e))?;
                    }
                    (t, Vec::new())
                }
                Some(pb::run_query_request::ConsistencySelector::NewTransaction(opts)) => {
                    let id = db
                        .begin_transaction(Self::new_transaction_is_read_only(opts), now)
                        .map_err(|e| status_from_error(&e))?;
                    let bytes = Self::token(&parent, &id);
                    (Some(id), bytes)
                }
                Some(pb::run_query_request::ConsistencySelector::ReadTime(_)) => {
                    return Err(Status::unimplemented(
                        "read_time consistency is not implemented",
                    ))
                }
                None => (None, Vec::new()),
            };
            let docs = match &txn {
                Some(t) => db
                    .run_query_in_transaction(t, &accepted.query)
                    .map_err(|e| status_from_error(&e))?,
                None => db
                    .run_query(&accepted.query, None)
                    .map_err(|e| status_from_error(&e))?,
            };
            let read_time = Some(encode_instant(match &txn {
                Some(t) => db
                    .transaction_read_time(t)
                    .map_err(|e| status_from_error(&e))?,
                None => db.read_time(now),
            }));
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
            if !report.is_empty() {
                // A new transaction is announced in a dedicated first response that carries
                // nothing else (RunQueryResponse contract).
                responses.insert(
                    0,
                    pb::RunQueryResponse {
                        transaction: report,
                        ..Default::default()
                    },
                );
            }
            Ok((responses, accepted.warnings))
        })
    }

    /// `RunAggregationQuery`.
    pub fn run_aggregation_query(
        &self,
        req: &pb::RunAggregationQueryRequest,
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
        self.with_db(&parent, |db| {
            let (txn, report) = match &req.consistency_selector {
                Some(pb::run_aggregation_query_request::ConsistencySelector::Transaction(t)) => {
                    let t = Self::txn(&parent, t)?;
                    if let Some(t) = &t {
                        db.touch_transaction(t, now)
                            .map_err(|e| status_from_error(&e))?;
                    }
                    (t, Vec::new())
                }
                Some(pb::run_aggregation_query_request::ConsistencySelector::NewTransaction(
                    opts,
                )) => {
                    let id = db
                        .begin_transaction(Self::new_transaction_is_read_only(opts), now)
                        .map_err(|e| status_from_error(&e))?;
                    let bytes = Self::token(&parent, &id);
                    (Some(id), bytes)
                }
                Some(pb::run_aggregation_query_request::ConsistencySelector::ReadTime(_)) => {
                    return Err(Status::unimplemented(
                        "read_time consistency is not implemented",
                    ))
                }
                None => (None, Vec::new()),
            };
            // Inside a transaction the aggregation is computed at the snapshot and the query
            // is recorded so that later changes abort the commit.
            let version = match &txn {
                Some(t) => {
                    db.run_query_in_transaction(t, &accepted.query)
                        .map_err(|e| status_from_error(&e))?;
                    Some(
                        db.transaction_read_version(t)
                            .map_err(|e| status_from_error(&e))?,
                    )
                }
                None => None,
            };
            let read_time = match &txn {
                Some(t) => db
                    .transaction_read_time(t)
                    .map_err(|e| status_from_error(&e))?,
                None => db.read_time(now),
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
                transaction: report,
                read_time: Some(encode_instant(read_time)),
                explain_metrics: None,
            })
        })
    }

    /// `ListDocuments` (no pagination tokens yet: the whole collection is returned).
    pub fn list_documents(
        &self,
        req: &pb::ListDocumentsRequest,
    ) -> Result<pb::ListDocumentsResponse, Status> {
        let parent = parse_parent(&req.parent).map_err(status)?;
        if !req.page_token.is_empty() {
            return Err(Status::unimplemented(
                "ListDocuments pagination tokens are not implemented",
            ));
        }
        if req.consistency_selector.is_some() {
            // Never serve live data for a snapshot request.
            return Err(Status::unimplemented(
                "ListDocuments transaction / read_time consistency is not implemented",
            ));
        }
        let mask = decode_mask(req.mask.as_ref()).map_err(status)?;
        self.with_db(&parent, |db| {
            let mut docs = db.list_documents(parent.document.as_ref(), &req.collection_id);
            if req.page_size > 0 {
                docs.truncate(usize::try_from(req.page_size).unwrap_or(usize::MAX));
            }
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
                next_page_token: String::new(),
            })
        })
    }

    /// `ListCollectionIds`.
    pub fn list_collection_ids(
        &self,
        req: &pb::ListCollectionIdsRequest,
    ) -> Result<pb::ListCollectionIdsResponse, Status> {
        let parent = parse_parent(&req.parent).map_err(status)?;
        self.with_db(&parent, |db| {
            Ok(pb::ListCollectionIdsResponse {
                collection_ids: db.list_collection_ids(parent.document.as_ref()),
                next_page_token: String::new(),
            })
        })
    }

    /// `BatchWrite`: each write is applied independently and reported with its own status.
    pub fn batch_write(
        &self,
        req: &pb::BatchWriteRequest,
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
                    db.commit(std::slice::from_ref(&write), None, now)
                        .map_err(|e| status_from_error(&e))
                });
                match outcome {
                    Ok(result) => {
                        let encoded = encode_commit(&result);
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
            Ok((
                pb::BatchWriteResponse {
                    write_results,
                    status: statuses,
                },
                db.current_version(),
            ))
        })
        .map(|(response, version)| {
            self.publish(&parent, version);
            response
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
