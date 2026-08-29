//! Local execution backend: one `FirestoreState` per (project, database) behind a mutex, a
//! shared virtual clock, strict gateway validation before every query.

// `tonic::Status` is the error type dictated by the generated service trait.
#![allow(clippy::result_large_err)]

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

use ftd_core_firestore::field_path::FieldPath;
use ftd_core_firestore::path::DocumentPath;
use ftd_core_firestore::store::{
    Aggregation, CommitResult, Document, FirestoreState, Precondition, TransactionId, Write,
    WriteOp,
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
        }
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

    fn txn(bytes: &[u8]) -> Result<Option<TransactionId>, Status> {
        if bytes.is_empty() {
            Ok(None)
        } else {
            decode_transaction(bytes).map(Some).map_err(status)
        }
    }

    /// `GetDocument`.
    pub fn get_document(&self, req: &pb::GetDocumentRequest) -> Result<pb::Document, Status> {
        let path = decode_document_name(&req.name).map_err(status)?;
        let parent = parse_parent(&req.name).map_err(status)?;
        let txn = match &req.consistency_selector {
            Some(pb::get_document_request::ConsistencySelector::Transaction(t)) => Self::txn(t)?,
            Some(pb::get_document_request::ConsistencySelector::ReadTime(_)) => {
                return Err(Status::unimplemented(
                    "read_time consistency is not implemented",
                ))
            }
            None => None,
        };
        let mask = decode_mask(req.mask.as_ref()).map_err(status)?;
        self.with_db(&parent, |db| {
            let doc = match &txn {
                Some(t) => db
                    .get_in_transaction(t, &path)
                    .map_err(|e| status_from_error(&e))?,
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
    ) -> Result<(Vec<BatchGetItem>, Vec<u8>), Status> {
        let parent = parse_parent(&format!("{}/documents", req.database)).map_err(status)?;
        let now = self.now();
        let mask = decode_mask(req.mask.as_ref()).map_err(status)?;
        self.with_db(&parent, |db| {
            let (txn, report) = match &req.consistency_selector {
                Some(pb::batch_get_documents_request::ConsistencySelector::Transaction(t)) => {
                    (Self::txn(t)?, Vec::new())
                }
                Some(pb::batch_get_documents_request::ConsistencySelector::NewTransaction(
                    opts,
                )) => {
                    let read_only =
                        matches!(opts.mode, Some(pb::transaction_options::Mode::ReadOnly(_)));
                    let id = db
                        .begin_transaction(read_only, now)
                        .map_err(|e| status_from_error(&e))?;
                    let bytes = encode_transaction(&id);
                    (Some(id), bytes)
                }
                Some(pb::batch_get_documents_request::ConsistencySelector::ReadTime(_)) => {
                    return Err(Status::unimplemented(
                        "read_time consistency is not implemented",
                    ))
                }
                None => (None, Vec::new()),
            };
            let mut items = Vec::with_capacity(req.documents.len());
            for name in &req.documents {
                let path = decode_document_name(name).map_err(status)?;
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
            Ok((items, report))
        })
    }

    /// `CreateDocument`.
    pub fn create_document(&self, req: &pb::CreateDocumentRequest) -> Result<pb::Document, Status> {
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
                path: path.clone(),
                fields,
                update_mask: None,
            },
            precondition: Some(Precondition::Exists(false)),
            transforms: vec![],
        };
        let now = self.now();
        self.with_db(&parent, |db| {
            db.commit(&[write], None, now)
                .map_err(|e| status_from_error(&e))?;
            db.get(&path)
                .map(encode_document)
                .ok_or_else(|| Status::internal("document vanished after commit"))
        })
    }

    /// `UpdateDocument`.
    pub fn update_document(&self, req: &pb::UpdateDocumentRequest) -> Result<pb::Document, Status> {
        let doc = req
            .document
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("missing document"))?;
        let path = decode_document_name(&doc.name).map_err(status)?;
        let parent = parse_parent(&doc.name).map_err(status)?;
        let write = Write {
            op: WriteOp::Set {
                path: path.clone(),
                fields: decode_fields(&doc.fields).map_err(status)?,
                update_mask: decode_mask(req.update_mask.as_ref()).map_err(status)?,
            },
            precondition: decode_precondition(req.current_document.as_ref()),
            transforms: vec![],
        };
        let now = self.now();
        self.with_db(&parent, |db| {
            db.commit(&[write], None, now)
                .map_err(|e| status_from_error(&e))?;
            db.get(&path)
                .map(encode_document)
                .ok_or_else(|| Status::internal("document vanished after commit"))
        })
    }

    /// `DeleteDocument`.
    pub fn delete_document(&self, req: &pb::DeleteDocumentRequest) -> Result<(), Status> {
        let path = decode_document_name(&req.name).map_err(status)?;
        let parent = parse_parent(&req.name).map_err(status)?;
        let write = Write {
            op: WriteOp::Delete { path },
            precondition: decode_precondition(req.current_document.as_ref()),
            transforms: vec![],
        };
        let now = self.now();
        self.with_db(&parent, |db| {
            db.commit(&[write], None, now)
                .map(|_| ())
                .map_err(|e| status_from_error(&e))
        })
    }

    /// `BeginTransaction`.
    pub fn begin_transaction(&self, req: &pb::BeginTransactionRequest) -> Result<Vec<u8>, Status> {
        let parent = parse_parent(&format!("{}/documents", req.database)).map_err(status)?;
        let read_only = matches!(
            req.options.as_ref().and_then(|o| o.mode.as_ref()),
            Some(pb::transaction_options::Mode::ReadOnly(_))
        );
        let now = self.now();
        self.with_db(&parent, |db| {
            db.begin_transaction(read_only, now)
                .map(|id| encode_transaction(&id))
                .map_err(|e| status_from_error(&e))
        })
    }

    /// `Commit`.
    pub fn commit(&self, req: &pb::CommitRequest) -> Result<pb::CommitResponse, Status> {
        let parent = parse_parent(&format!("{}/documents", req.database)).map_err(status)?;
        let writes = req
            .writes
            .iter()
            .map(decode_write)
            .collect::<Result<Vec<_>, _>>()
            .map_err(status)?;
        let txn = Self::txn(&req.transaction)?;
        let now = self.now();
        self.with_db(&parent, |db| {
            let result = db
                .commit(&writes, txn.as_ref(), now)
                .map_err(|e| status_from_error(&e))?;
            Ok(encode_commit(&result))
        })
    }

    /// `Rollback`.
    pub fn rollback(&self, req: &pb::RollbackRequest) -> Result<(), Status> {
        let parent = parse_parent(&format!("{}/documents", req.database)).map_err(status)?;
        let txn = decode_transaction(&req.transaction).map_err(status)?;
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
                    (Self::txn(t)?, Vec::new())
                }
                Some(pb::run_query_request::ConsistencySelector::NewTransaction(opts)) => {
                    let read_only =
                        matches!(opts.mode, Some(pb::transaction_options::Mode::ReadOnly(_)));
                    let id = db
                        .begin_transaction(read_only, now)
                        .map_err(|e| status_from_error(&e))?;
                    let bytes = encode_transaction(&id);
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
            let read_time = Some(encode_instant(now));
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
                responses.push(pb::RunQueryResponse {
                    transaction: report.clone(),
                    document: None,
                    read_time,
                    skipped_results: 0,
                    ..Default::default()
                });
            } else if let Some(first) = responses.first_mut() {
                first.transaction = report;
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
        let mut aliases = Vec::with_capacity(saq.aggregations.len());
        let mut aggregations = Vec::with_capacity(saq.aggregations.len());
        for (i, a) in saq.aggregations.iter().enumerate() {
            use pb::structured_aggregation_query::aggregation::Operator as O;
            let field =
                |f: &Option<pb::structured_query::FieldReference>| -> Result<FieldPath, Status> {
                    let r = f
                        .as_ref()
                        .ok_or_else(|| Status::invalid_argument("aggregation without field"))?;
                    FieldPath::parse(&r.field_path)
                        .map_err(|e| Status::invalid_argument(e.to_string()))
                };
            let agg = match &a.operator {
                Some(O::Count(c)) => Aggregation::Count {
                    up_to: c.up_to.and_then(|n| u64::try_from(n).ok()),
                },
                Some(O::Sum(s)) => Aggregation::Sum(field(&s.field)?),
                Some(O::Avg(v)) => Aggregation::Avg(field(&v.field)?),
                None => return Err(Status::invalid_argument("aggregation without operator")),
            };
            aliases.push(if a.alias.is_empty() {
                format!("field_{}", i + 1)
            } else {
                a.alias.clone()
            });
            aggregations.push(agg);
        }
        let now = self.now();
        self.with_db(&parent, |db| {
            let txn = match &req.consistency_selector {
                Some(pb::run_aggregation_query_request::ConsistencySelector::Transaction(t)) => {
                    Self::txn(t)?
                }
                Some(pb::run_aggregation_query_request::ConsistencySelector::ReadTime(_)) => {
                    return Err(Status::unimplemented(
                        "read_time consistency is not implemented",
                    ))
                }
                _ => None,
            };
            let version = match &txn {
                Some(t) => Some(
                    db.run_query_in_transaction(t, &accepted.query)
                        .map(|_| db.current_version())
                        .map_err(|e| status_from_error(&e))?,
                ),
                None => None,
            };
            let _ = version;
            let values = db
                .run_aggregation(&accepted.query, &aggregations, None)
                .map_err(|e| status_from_error(&e))?;
            let aggregate_fields: HashMap<String, pb::Value> = aliases
                .into_iter()
                .zip(values.iter().map(encode_value))
                .collect();
            Ok(pb::RunAggregationQueryResponse {
                result: Some(pb::AggregationResult { aggregate_fields }),
                transaction: Vec::new(),
                read_time: Some(encode_instant(now)),
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
        self.with_db(&parent, |db| {
            let mut write_results = Vec::with_capacity(req.writes.len());
            let mut statuses = Vec::with_capacity(req.writes.len());
            for w in &req.writes {
                let outcome = decode_write(w).map_err(status).and_then(|write| {
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
            Ok(pb::BatchWriteResponse {
                write_results,
                status: statuses,
            })
        })
    }
}

fn encode_commit(result: &CommitResult) -> pb::CommitResponse {
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

fn project_fields(
    fields: &BTreeMap<String, ftd_core_firestore::value::Value>,
    mask: &[FieldPath],
) -> BTreeMap<String, ftd_core_firestore::value::Value> {
    let mut out = BTreeMap::new();
    for p in mask {
        if let Some(v) = ftd_core_firestore::store::get_field(fields, p) {
            let first = p.segments()[0].clone();
            if p.segments().len() == 1 {
                out.insert(first, v.clone());
            } else if let Some(root) = fields.get(&first) {
                // Nested masks copy the containing top-level field; finer projection is a
                // later refinement.
                out.insert(first, root.clone());
            }
        }
    }
    out
}

/// Convenience for tests: documents as (relative path, fields).
#[must_use]
pub fn document_summary(
    doc: &Document,
) -> (String, BTreeMap<String, ftd_core_firestore::value::Value>) {
    (doc.path.relative(), doc.fields.clone())
}
