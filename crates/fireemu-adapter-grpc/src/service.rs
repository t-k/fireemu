//! `google.firestore.v1.Firestore` service: strict gateway in front of a backend.
//!
//! The backend is either the local execution engine ([`LocalBackend`]), an upstream channel
//! (official Emulator or real service, proxy mode), or nothing (validation-only mode, where
//! validated requests answer `UNIMPLEMENTED` rather than a fake success).

// `tonic::Status` is the error type dictated by the generated trait.
#![allow(clippy::result_large_err)]

use std::sync::Arc;

use fireemu_core_firestore::path::DocumentPath;
use fireemu_core_firestore::query::{Direction, Query};
use fireemu_proto_firestore::google::firestore::v1 as pb;
use fireemu_proto_firestore::google::firestore::v1::firestore_client::FirestoreClient;
use fireemu_proto_firestore::google::firestore::v1::firestore_server::Firestore;
use tonic::codegen::tokio_stream;
use tonic::transport::Channel;
use tonic::{Request, Response, Status, Streaming};

use crate::decode::{decode_structured_query, parse_parent};
use crate::encode::decode_document_name;
use crate::gateway::{Gateway, Rejection};
use crate::local::{decode_aggregations, LocalBackend};
use crate::rules::{is_owner_credential, same_epoch, Principal, RulesEnforcer};
use fireemu_core_app_check::admission::{AdmissionRequest, PrivilegedBypass, ServiceAdmission};
use fireemu_core_app_check::header::{classify_app_check_header, is_app_check_header};

/// Boxed response stream.
pub type BoxStream<T> = tonic::codegen::BoxStream<T>;

const RUN_QUERY_BATCH_SIZE: i32 = 32;
const RUN_QUERY_CHANNEL_CAPACITY: usize = 16;

/// Where validated requests go.
pub enum Backend {
    /// Execute locally.
    Local(Arc<LocalBackend>),
    /// Forward to an upstream Firestore endpoint.
    Upstream(Channel),
    /// Validation only.
    None,
}

/// Gateway service state.
pub struct GatewayService {
    gateway: Arc<Gateway>,
    backend: Backend,
    rules: Option<Arc<RulesEnforcer>>,
    app_check: Option<Arc<ServiceAdmission>>,
    #[cfg(test)]
    first_query_page_ready: Option<Arc<dyn Fn() + Send + Sync>>,
    #[cfg(test)]
    continuation_query_page_ready: Option<Arc<dyn Fn() + Send + Sync>>,
}

impl GatewayService {
    /// Creates the service with an upstream channel (proxy mode) or validation-only mode.
    #[must_use]
    pub fn new(gateway: Gateway, upstream: Option<Channel>) -> Self {
        let backend = upstream.map_or(Backend::None, Backend::Upstream);
        Self {
            gateway: Arc::new(gateway),
            backend,
            rules: None,
            app_check: None,
            #[cfg(test)]
            first_query_page_ready: None,
            #[cfg(test)]
            continuation_query_page_ready: None,
        }
    }

    /// Creates the service with the local execution backend.
    #[must_use]
    pub fn local(gateway: Gateway, backend: Arc<LocalBackend>) -> Self {
        Self {
            gateway: Arc::new(gateway),
            backend: Backend::Local(backend),
            rules: None,
            app_check: None,
            #[cfg(test)]
            first_query_page_ready: None,
            #[cfg(test)]
            continuation_query_page_ready: None,
        }
    }

    /// Enforces Security Rules on the local backend.
    #[must_use]
    pub fn with_rules(mut self, rules: Arc<RulesEnforcer>) -> Self {
        self.rules = Some(rules);
        self
    }

    /// Enforces the Firestore App Check baseline (`appCheck.services.firestore`).
    ///
    /// The policy is deliberately independent of [`Self::with_rules`]: disabling Security
    /// Rules makes every caller the owner without a credential, and that is not an App Check
    /// bypass (specification section 12.2).
    #[must_use]
    pub fn with_app_check(mut self, policy: Arc<ServiceAdmission>) -> Self {
        self.app_check = Some(policy);
        self
    }

    fn principal(&self, metadata: &tonic::metadata::MetadataMap) -> Result<Principal, Status> {
        match &self.rules {
            Some(r) => r.principal(metadata),
            None => Ok(Principal::Owner),
        }
    }

    fn principal_for_project(
        &self,
        metadata: &tonic::metadata::MetadataMap,
        project: &str,
    ) -> Result<Principal, Status> {
        match &self.rules {
            Some(r) => r.principal_for_project(metadata, project),
            None => Ok(Principal::Owner),
        }
    }

    /// The caller of a unary request: its principal plus the reset epoch it started in.
    /// The epoch is read before the token is verified, so a reset that clears the Auth
    /// store between verification and admission is detected by the guards.
    ///
    /// App Check is decided here, between the resolved route and the Firebase Auth
    /// credential, which is the order specification section 7.4 requires. Taking the
    /// resource and the method name is what makes that unmissable: every unary handler has
    /// to name its target, so no method can silently skip admission.
    fn caller(
        &self,
        metadata: &tonic::metadata::MetadataMap,
        resource: &str,
        operation: &'static str,
    ) -> Result<Caller, Status> {
        let epoch = self.local_backend().map_or(0, |l| l.barrier().epoch());
        self.admit_app_check(metadata, resource, operation)?;
        Ok(Caller {
            principal: self.principal_for_project(metadata, project_of_resource(resource))?,
            epoch,
        })
    }

    /// The App Check decision of one unary request (specification sections 12 and 13.1).
    ///
    /// The owner bypass is the emulator's exact owner credential, verified here rather than
    /// taken from the principal, because the principal is `Owner` for everyone while
    /// Security Rules are disabled.
    fn admit_app_check(
        &self,
        metadata: &tonic::metadata::MetadataMap,
        resource: &str,
        operation: &'static str,
    ) -> Result<(), Status> {
        let Some(policy) = &self.app_check else {
            return Ok(());
        };
        let values = app_check_values(metadata);
        let header = classify_app_check_header(&values);
        let authorization = metadata.get("authorization").and_then(|v| v.to_str().ok());
        let now = self
            .local_backend()
            .map_or(fireemu_core_types::time::LogicalInstant::UNIX_EPOCH, |l| {
                l.now()
            });
        let decision = policy.admit(&AdmissionRequest {
            project_id: project_of_resource(resource),
            transport: "grpc",
            operation,
            bypass: if is_owner_credential(authorization) {
                PrivilegedBypass::FirestoreOwner
            } else {
                PrivilegedBypass::None
            },
            header: &header,
            now,
        });
        match decision.reason {
            None => Ok(()),
            Some(reason) => Err(app_check_denied(reason)),
        }
    }

    /// A user token must be minted for the project of `database` (transaction requests
    /// carry no document the guards could check).
    fn check_database_audience(&self, caller: &Caller, database: &str) -> Result<(), Status> {
        if self.rules.is_none() {
            return Ok(());
        }
        let parent = crate::decode::parse_parent(&format!("{database}/documents"))
            .map_err(|e| crate::gateway::Rejection::Decode(e).to_status())?;
        crate::rules::check_audience(&caller.principal, parent.project.as_str())
    }

    /// Read guard for the local backend (runs inside the read's critical section, after
    /// admission: a caller from a previous epoch is refused there).
    fn read_guard<'a>(&'a self, caller: &'a Caller) -> crate::rules::BoxedReadGuard<'a> {
        let inner = crate::rules::read_guard(self.rules.as_ref(), &caller.principal);
        let Some(local) = self.local_backend() else {
            return inner;
        };
        let barrier = local.barrier();
        let epoch = caller.epoch;
        Box::new(move |db, version, check| {
            same_epoch(&barrier, epoch)?;
            inner(db, version, check)
        })
    }

    /// Write guard for the local backend (runs inside the commit critical section, after
    /// admission: a caller from a previous epoch is refused there).
    fn write_guard<'a>(&'a self, caller: &'a Caller) -> crate::rules::BoxedWriteGuard<'a> {
        let inner = crate::rules::write_guard(self.rules.as_ref(), &caller.principal);
        let Some(local) = self.local_backend() else {
            return inner;
        };
        let barrier = local.barrier();
        let epoch = caller.epoch;
        let actor = crate::local::Actor::from_principal(&caller.principal);
        let local = local.clone();
        Box::new(move |db, writes, now| {
            same_epoch(&barrier, epoch)?;
            local.set_actor(actor.clone());
            inner(db, writes, now)
        })
    }

    fn client(&self) -> Result<FirestoreClient<Channel>, Status> {
        match &self.backend {
            Backend::Upstream(c) => Ok(FirestoreClient::new(c.clone())),
            _ => Err(Status::unimplemented(
                "request passed strict validation but no backend is configured; local execution is disabled (FS-GW-1)",
            )),
        }
    }

    fn stream_context(
        &self,
        metadata: &tonic::metadata::MetadataMap,
    ) -> Result<crate::streams::StreamContext, Status> {
        let Some(local) = self.local_backend() else {
            return Err(Status::unimplemented(
                "streaming RPCs are only served by the local backend",
            ));
        };
        let authorization = metadata.get("authorization").and_then(|v| v.to_str().ok());
        // The opening metadata is classified once, here; the decision it produces is taken
        // when the first request names the database, and holds for the stream's whole life
        // (specification section 13.1).
        let app_check = self.app_check.as_ref().map(|policy| {
            crate::streams::StreamAdmission::new(
                policy.clone(),
                &app_check_values(metadata),
                if is_owner_credential(authorization) {
                    PrivilegedBypass::FirestoreOwner
                } else {
                    PrivilegedBypass::None
                },
                "grpc",
            )
        });
        Ok(crate::streams::StreamContext {
            local: local.clone(),
            gateway: self.gateway.clone(),
            rules: self.rules.clone(),
            // A stream cannot decide App Check before its first request names the database,
            // and section 7.4 puts the Firebase Auth credential after that decision. So a
            // credential that does not resolve is not reported here: `refresh_principal`
            // re-derives it on every message, which is what actually gates the stream, and it
            // runs after admission. Resolving it here would let a bad Auth token answer an
            // enforced stream that never presented an App Check token at all.
            principal: self.principal(metadata).unwrap_or(Principal::Anonymous),
            authorization: authorization.map(str::to_owned),
            epoch: local.epoch(),
            app_check,
        })
    }

    fn local_backend(&self) -> Option<&Arc<LocalBackend>> {
        match &self.backend {
            Backend::Local(l) => Some(l),
            _ => None,
        }
    }

    fn validate_run_query(&self, req: &pb::RunQueryRequest) -> Result<Vec<String>, Status> {
        let parent = parse_parent(&req.parent).map_err(|e| Rejection::Decode(e).to_status())?;
        let Some(pb::run_query_request::QueryType::StructuredQuery(sq)) = &req.query_type else {
            return Err(Status::invalid_argument(
                "RunQuery requires a structured_query",
            ));
        };
        let accepted = if let Some(local) = self.local_backend() {
            local.accepted_query(&parent, sq)?
        } else {
            let query = decode_structured_query(&parent, sq)
                .map_err(|e| Rejection::Decode(e).to_status())?;
            self.gateway
                .validate_query(&query)
                .map_err(|r| r.to_status())?
        };
        Ok(accepted.warnings)
    }
}

impl GatewayService {
    /// The aggregation's underlying query goes through the gateway before it is forwarded
    /// (a missing composite index is refused here, never by the upstream).
    fn validate_run_aggregation_query(
        &self,
        req: &pb::RunAggregationQueryRequest,
    ) -> Result<Vec<String>, Status> {
        let parent = parse_parent(&req.parent).map_err(|e| Rejection::Decode(e).to_status())?;
        let Some(pb::run_aggregation_query_request::QueryType::StructuredAggregationQuery(
            aggregation,
        )) = &req.query_type
        else {
            return Err(Status::invalid_argument(
                "RunAggregationQuery requires a structured_aggregation_query",
            ));
        };
        let Some(pb::structured_aggregation_query::QueryType::StructuredQuery(sq)) =
            &aggregation.query_type
        else {
            return Err(Status::invalid_argument(
                "structured_aggregation_query requires a structured_query",
            ));
        };
        let (_, aggregations) = decode_aggregations(aggregation)?;
        let accepted = if let Some(local) = self.local_backend() {
            local.accepted_aggregation_query(&parent, sq, &aggregations)?
        } else {
            let query = decode_structured_query(&parent, sq)
                .map_err(|e| Rejection::Decode(e).to_status())?;
            self.gateway
                .validate_aggregation_query(&query, &aggregations)
                .map_err(|r| r.to_status())?
        };
        Ok(accepted.warnings)
    }
}

fn with_warnings<T>(mut response: Response<T>, warnings: &[String]) -> Response<T> {
    for w in warnings {
        if let Ok(v) = w.parse() {
            response.metadata_mut().append("fireemu-warning", v);
        }
    }
    response
}

async fn blocking_read<T, F>(
    local: Arc<LocalBackend>,
    rules: Option<Arc<RulesEnforcer>>,
    caller: Caller,
    operation: F,
) -> Result<T, Status>
where
    T: Send + 'static,
    F: for<'a> FnOnce(&LocalBackend, crate::rules::ReadGuard<'a>) -> Result<T, Status>
        + Send
        + 'static,
{
    tokio::task::spawn_blocking(move || {
        let barrier = local.barrier();
        let guard: crate::rules::BoxedReadGuard<'_> = Box::new(move |db, version, check| {
            same_epoch(&barrier, caller.epoch)?;
            let inner = crate::rules::read_guard(rules.as_ref(), &caller.principal);
            inner(db, version, check)
        });
        operation(&local, &*guard)
    })
    .await
    .map_err(|error| Status::internal(format!("Firestore blocking task failed: {error}")))?
}

async fn blocking_local<T, F>(local: Arc<LocalBackend>, operation: F) -> Result<T, Status>
where
    T: Send + 'static,
    F: FnOnce(&LocalBackend) -> Result<T, Status> + Send + 'static,
{
    tokio::task::spawn_blocking(move || operation(&local))
        .await
        .map_err(|error| Status::internal(format!("Firestore blocking task failed: {error}")))?
}

#[tonic::async_trait]
impl Firestore for GatewayService {
    async fn get_document(
        &self,
        request: Request<pb::GetDocumentRequest>,
    ) -> Result<Response<pb::Document>, Status> {
        if let Some(local) = self.local_backend() {
            let caller = self.caller(request.metadata(), &request.get_ref().name, "GetDocument")?;
            let guard = self.read_guard(&caller);
            let snapshot = local.get_document_snapshot(request.get_ref(), &*guard)?;
            return snapshot.into_response().map(Response::new);
        }
        self.client()?.get_document(request.into_inner()).await
    }

    async fn list_documents(
        &self,
        request: Request<pb::ListDocumentsRequest>,
    ) -> Result<Response<pb::ListDocumentsResponse>, Status> {
        if let Some(local) = self.local_backend() {
            let caller = self.caller(
                request.metadata(),
                &request.get_ref().parent,
                "ListDocuments",
            )?;
            let local = local.clone();
            let rules = self.rules.clone();
            let request = request.into_inner();
            return blocking_read(local, rules, caller, move |local, guard| {
                local.list_documents(&request, guard)
            })
            .await
            .map(Response::new);
        }
        self.client()?.list_documents(request.into_inner()).await
    }

    async fn update_document(
        &self,
        request: Request<pb::UpdateDocumentRequest>,
    ) -> Result<Response<pb::Document>, Status> {
        if let Some(local) = self.local_backend() {
            let caller = self.caller(
                request.metadata(),
                request
                    .get_ref()
                    .document
                    .as_ref()
                    .map_or("", |d| d.name.as_str()),
                "UpdateDocument",
            )?;
            let (parent, write) = LocalBackend::plan_update(request.get_ref())?;
            return local
                .retry_on_contention_async(&parent, None, std::slice::from_ref(&write), || {
                    let guard = self.write_guard(&caller);
                    local.execute_planned_once(
                        &parent,
                        &write,
                        request.get_ref().mask.as_ref(),
                        &*guard,
                    )
                })
                .await
                .map(Response::new);
        }
        self.client()?.update_document(request.into_inner()).await
    }

    async fn delete_document(
        &self,
        request: Request<pb::DeleteDocumentRequest>,
    ) -> Result<Response<()>, Status> {
        if let Some(local) = self.local_backend() {
            let caller = self.caller(
                request.metadata(),
                &request.get_ref().name,
                "DeleteDocument",
            )?;
            let (parent, write) = LocalBackend::plan_delete(request.get_ref())?;
            return local
                .retry_on_contention_async(&parent, None, std::slice::from_ref(&write), || {
                    let guard = self.write_guard(&caller);
                    local.delete_document_once(request.get_ref(), &*guard)
                })
                .await
                .map(Response::new);
        }
        self.client()?.delete_document(request.into_inner()).await
    }

    type BatchGetDocumentsStream = BoxStream<pb::BatchGetDocumentsResponse>;
    async fn batch_get_documents(
        &self,
        request: Request<pb::BatchGetDocumentsRequest>,
    ) -> Result<Response<Self::BatchGetDocumentsStream>, Status> {
        if let Some(local) = self.local_backend() {
            let caller = self.caller(
                request.metadata(),
                &request.get_ref().database,
                "BatchGetDocuments",
            )?;
            // An empty batch never reaches the guard: the audience is checked here so a
            // token of another project cannot open a transaction in this one.
            self.check_database_audience(&caller, &request.get_ref().database)?;
            let local = local.clone();
            let rules = self.rules.clone();
            let request = request.into_inner();
            let outcome = blocking_read(local, rules, caller, move |local, guard| {
                local.batch_get_documents(&request, guard)
            })
            .await?;
            let read_time = Some(crate::encode::encode_instant(outcome.read_time));
            if outcome.items.is_empty() && !outcome.transaction.is_empty() {
                // An empty batch still has to hand back the new transaction.
                let only = pb::BatchGetDocumentsResponse {
                    transaction: outcome.transaction,
                    read_time,
                    result: None,
                };
                return Ok(Response::new(Box::pin(tokio_stream::iter(vec![Ok(only)]))));
            }
            let mask = outcome.mask;
            let transaction = outcome.transaction;
            let responses: Vec<Result<pb::BatchGetDocumentsResponse, Status>> = outcome
                .items
                .iter()
                .enumerate()
                .map(|(i, item)| {
                    Ok(pb::BatchGetDocumentsResponse {
                        transaction: if i == 0 {
                            transaction.clone()
                        } else {
                            Vec::new()
                        },
                        read_time,
                        result: Some(item.encode(mask.as_deref())),
                    })
                })
                .collect();
            return Ok(Response::new(Box::pin(tokio_stream::iter(responses))));
        }
        let response = self
            .client()?
            .batch_get_documents(request.into_inner())
            .await?;
        Ok(Response::new(Box::pin(response.into_inner())))
    }

    async fn begin_transaction(
        &self,
        request: Request<pb::BeginTransactionRequest>,
    ) -> Result<Response<pb::BeginTransactionResponse>, Status> {
        if let Some(local) = self.local_backend() {
            let caller = self.caller(
                request.metadata(),
                &request.get_ref().database,
                "BeginTransaction",
            )?;
            self.check_database_audience(&caller, &request.get_ref().database)?;
            let transaction = local.begin_transaction(request.get_ref())?;
            return Ok(Response::new(pb::BeginTransactionResponse { transaction }));
        }
        self.client()?.begin_transaction(request.into_inner()).await
    }

    async fn commit(
        &self,
        request: Request<pb::CommitRequest>,
    ) -> Result<Response<pb::CommitResponse>, Status> {
        if let Some(local) = self.local_backend() {
            let caller = self.caller(request.metadata(), &request.get_ref().database, "Commit")?;
            // A commit that collides with an active transaction's locks waits (off the
            // runtime) for a release, then tries again; the guard is rebuilt per attempt so
            // nothing non-Send is held across the wait.
            let (parent, writes) = LocalBackend::plan_commit(request.get_ref())?;
            let own = local.txn_of(&parent, &request.get_ref().transaction)?;
            return local
                .retry_on_contention_async(&parent, own.as_ref(), &writes, || {
                    let guard = self.write_guard(&caller);
                    local.commit_once(request.get_ref(), &*guard)
                })
                .await
                .map(Response::new);
        }
        self.client()?.commit(request.into_inner()).await
    }

    async fn rollback(
        &self,
        request: Request<pb::RollbackRequest>,
    ) -> Result<Response<()>, Status> {
        if let Some(local) = self.local_backend() {
            let caller =
                self.caller(request.metadata(), &request.get_ref().database, "Rollback")?;
            self.check_database_audience(&caller, &request.get_ref().database)?;
            return local.rollback(request.get_ref()).map(Response::new);
        }
        self.client()?.rollback(request.into_inner()).await
    }

    type RunQueryStream = BoxStream<pb::RunQueryResponse>;
    #[allow(clippy::too_many_lines)]
    async fn run_query(
        &self,
        request: Request<pb::RunQueryRequest>,
    ) -> Result<Response<Self::RunQueryStream>, Status> {
        let caller = self.caller(request.metadata(), &request.get_ref().parent, "RunQuery")?;
        let req = request.into_inner();
        if let Some(local) = self.local_backend() {
            let local = Arc::clone(local);
            let name_order_continuation = match req.query_type.as_ref() {
                Some(pb::run_query_request::QueryType::StructuredQuery(query)) => {
                    let parent = parse_parent(&req.parent)
                        .map_err(|error| Rejection::Decode(error).to_status())?;
                    let accepted = local.accepted_query(&parent, query)?;
                    is_name_ordered_query(&accepted.query)
                }
                None => false,
            };
            let original_limit = req.query_type.as_ref().and_then(|query| match query {
                pb::run_query_request::QueryType::StructuredQuery(query) => query.limit,
            });
            let original_offset = req.query_type.as_ref().map_or(0, |query| match query {
                pb::run_query_request::QueryType::StructuredQuery(query) => query.offset,
            });
            let internal_transaction = req.consistency_selector.is_none();
            let mut first_request = req.clone();
            set_run_query_page(&mut first_request, original_offset, original_limit);
            if internal_transaction {
                first_request.consistency_selector =
                    Some(pb::run_query_request::ConsistencySelector::NewTransaction(
                        pb::TransactionOptions {
                            mode: Some(pb::transaction_options::Mode::ReadOnly(
                                pb::transaction_options::ReadOnly::default(),
                            )),
                        },
                    ));
            }
            let first_authorization = req.clone();
            let query_execution_id = local.next_query_execution_id();
            let guard_database = database_name_from_query_parent(&req.parent);
            // Newly minted transactions remain owned by the worker result until delivery.
            // Dropping an unreceived spawn_blocking result must release its snapshot.
            let creates_transaction = matches!(
                first_request.consistency_selector,
                Some(pb::run_query_request::ConsistencySelector::NewTransaction(
                    _
                ))
            );
            let guard_local = Arc::clone(&local);
            #[cfg(test)]
            let first_query_page_ready = self.first_query_page_ready.clone();
            let (mut first, warnings, selection, mut rollback) = blocking_read(
                local.clone(),
                self.rules.clone(),
                caller.clone(),
                move |local, guard| {
                    let (first, warnings, selection) = local
                        .run_query_authorized_as_for_execution(
                            &first_request,
                            &first_authorization,
                            guard,
                            query_execution_id,
                        )?;
                    let rollback = creates_transaction.then(|| QueryTransactionGuard {
                        local: guard_local,
                        database: guard_database,
                        transaction: announced_transaction(&first).unwrap_or_default(),
                    });
                    #[cfg(test)]
                    if let Some(ready) = first_query_page_ready {
                        ready();
                    }
                    Ok((first, warnings, selection, rollback))
                },
            )
            .await?;
            let transaction =
                announced_transaction(&first).or_else(|| match &req.consistency_selector {
                    Some(pb::run_query_request::ConsistencySelector::Transaction(transaction)) => {
                        Some(transaction.clone())
                    }
                    _ => None,
                });
            if internal_transaction {
                // Hide only the dedicated transaction announcement, preserving offset metadata.
                first.retain(|response| response.transaction.is_empty());
            }
            let first_documents = first
                .iter()
                .filter(|response| response.document.is_some())
                .count();
            let first_after_document = if name_order_continuation {
                last_query_document_path(&first)?
            } else {
                None
            };
            let (sender, receiver) = tokio::sync::mpsc::channel(RUN_QUERY_CHANNEL_CAPACITY);
            let rules = self.rules.clone();
            let announcement_guard = if internal_transaction {
                None
            } else {
                rollback.take()
            };
            #[cfg(test)]
            let continuation_query_page_ready = self.continuation_query_page_ready.clone();
            tokio::spawn(async move {
                let rollback = rollback;
                // Keep one response until exhaustion and execution finalization are known.
                // Page-local completion must never terminate the public query stream.
                let mut pending = None;
                for mut response in first {
                    response.continuation_selector = None;
                    if let Some(previous) = pending.replace(response) {
                        if sender.send(Ok(previous)).await.is_err() {
                            return;
                        }
                    }
                }
                let mut delivered = i32::try_from(first_documents).unwrap_or(i32::MAX);
                let mut batch_documents = delivered;
                let mut after_document = first_after_document;
                while batch_documents == RUN_QUERY_BATCH_SIZE
                    && original_limit.is_none_or(|limit| delivered < limit)
                {
                    let mut page = req.clone();
                    if let Some(transaction) = transaction.clone() {
                        page.consistency_selector = Some(
                            pb::run_query_request::ConsistencySelector::Transaction(transaction),
                        );
                    } else if !matches!(
                        page.consistency_selector,
                        Some(pb::run_query_request::ConsistencySelector::ReadTime(_))
                    ) {
                        let _ = sender
                            .send(Err(Status::internal(
                                "RunQuery snapshot transaction was not returned",
                            )))
                            .await;
                        return;
                    }
                    let continuation = after_document.clone();
                    if name_order_continuation {
                        set_run_query_page(
                            &mut page,
                            0,
                            original_limit.map(|limit| limit.saturating_sub(delivered)),
                        );
                    } else {
                        set_run_query_page(
                            &mut page,
                            original_offset.saturating_add(delivered),
                            original_limit.map(|limit| limit.saturating_sub(delivered)),
                        );
                    }
                    let authorization = req.clone();
                    let selection = selection.clone();
                    #[cfg(test)]
                    let continuation_query_page_ready = continuation_query_page_ready.clone();
                    let batch = blocking_read(
                        local.clone(),
                        rules.clone(),
                        caller.clone(),
                        move |local, guard| {
                            let result = local.run_query_authorized_as_after_for_execution(
                                &page,
                                &authorization,
                                guard,
                                continuation.as_ref(),
                                query_execution_id,
                                selection,
                            );
                            #[cfg(test)]
                            if let Some(ready) = continuation_query_page_ready {
                                ready();
                            }
                            result
                        },
                    )
                    .await;
                    let (mut responses, _) = match batch {
                        Ok(batch) => batch,
                        Err(error) => {
                            let _ = sender.send(Err(error)).await;
                            return;
                        }
                    };
                    for response in &mut responses {
                        response.skipped_results = 0;
                    }
                    batch_documents = i32::try_from(
                        responses
                            .iter()
                            .filter(|response| response.document.is_some())
                            .count(),
                    )
                    .unwrap_or(i32::MAX);
                    if name_order_continuation && batch_documents > 0 {
                        after_document = match last_query_document_path(&responses) {
                            Ok(Some(path)) => Some(path),
                            Ok(None) => {
                                let _ = sender
                                    .send(Err(Status::internal(
                                        "RunQuery page returned documents without names",
                                    )))
                                    .await;
                                return;
                            }
                            Err(error) => {
                                let _ = sender.send(Err(error)).await;
                                return;
                            }
                        };
                    }
                    for mut response in responses {
                        response.continuation_selector = None;
                        if let Some(previous) = pending.replace(response) {
                            if sender.send(Ok(previous)).await.is_err() {
                                return;
                            }
                        }
                    }
                    delivered = delivered.saturating_add(batch_documents);
                }
                if let Some(transaction) = transaction.as_deref() {
                    if let Err(error) = local.finish_query_execution(
                        &database_name_from_query_parent(&req.parent),
                        transaction,
                        query_execution_id,
                    ) {
                        let _ = sender.send(Err(error)).await;
                        return;
                    }
                }
                drop(rollback);
                if let Some(mut response) = pending {
                    response.continuation_selector =
                        Some(pb::run_query_response::ContinuationSelector::Done(true));
                    let _ = sender.send(Ok(response)).await;
                }
            });
            let boxed: Self::RunQueryStream = Box::pin(QueryResponseStream {
                receiver,
                announcement_guard,
            });
            return Ok(with_warnings(Response::new(boxed), &warnings));
        }
        let warnings = self.validate_run_query(&req)?;
        let mut client = self.client()?;
        let response = client.run_query(req).await?;
        let response = with_warnings(response, &warnings);
        Ok(Response::new(Box::pin(response.into_inner())))
    }

    type ExecutePipelineStream = BoxStream<pb::ExecutePipelineResponse>;
    async fn execute_pipeline(
        &self,
        request: Request<pb::ExecutePipelineRequest>,
    ) -> Result<Response<Self::ExecutePipelineStream>, Status> {
        // Strict validation only (FS-PIPE-RPC-1): the pipeline is decoded and canonicalized,
        // unsupported stages are refused explicitly, and a valid pipeline is answered with
        // UNIMPLEMENTED carrying its canonical form (execution is 1.x).
        let caller = self.caller(
            request.metadata(),
            &request.get_ref().database,
            "ExecutePipeline",
        )?;
        if let Some(rules) = &self.rules {
            rules.require_owner(&caller.principal, "ExecutePipeline")?;
        }
        if self.gateway.ctx.edition != fireemu_core_types::edition::FirestoreEdition::Enterprise {
            let mut status = Status::failed_precondition(
                "pipelines require firestore.edition = enterprise (Enterprise Native)",
            );
            if let Ok(v) = "FS_PIPE_EDITION".parse() {
                status.metadata_mut().insert("fireemu-code", v);
            }
            return Err(status);
        }
        let ast = crate::pipeline::validate_pipeline(request.get_ref())?;
        let mut status = Status::unimplemented(format!(
            "FS-PIPE-RPC-1 strict-validation-only: the pipeline is valid ({}) but pipelines are not executed locally",
            ast.canonical_text()
        ));
        if let Ok(v) = ast.canonical_text().parse() {
            status.metadata_mut().insert("fireemu-pipeline", v);
        }
        if let Ok(v) = "FS_PIPE_VALIDATION_ONLY".parse() {
            status.metadata_mut().insert("fireemu-code", v);
        }
        Err(status)
    }

    type RunAggregationQueryStream = BoxStream<pb::RunAggregationQueryResponse>;
    async fn run_aggregation_query(
        &self,
        request: Request<pb::RunAggregationQueryRequest>,
    ) -> Result<Response<Self::RunAggregationQueryStream>, Status> {
        if let Some(local) = self.local_backend() {
            let caller = self.caller(
                request.metadata(),
                &request.get_ref().parent,
                "RunAggregationQuery",
            )?;
            let local = local.clone();
            let rules = self.rules.clone();
            let request = request.into_inner();
            let response = blocking_read(local, rules, caller, move |local, guard| {
                local.run_aggregation_query(&request, guard)
            })
            .await?;
            let stream: Vec<Result<pb::RunAggregationQueryResponse, Status>> = vec![Ok(response)];
            return Ok(Response::new(Box::pin(tokio_stream::iter(stream))));
        }
        let req = request.into_inner();
        let warnings = self.validate_run_aggregation_query(&req)?;
        let response = self.client()?.run_aggregation_query(req).await?;
        let response = with_warnings(response, &warnings);
        Ok(Response::new(Box::pin(response.into_inner())))
    }

    async fn partition_query(
        &self,
        request: Request<pb::PartitionQueryRequest>,
    ) -> Result<Response<pb::PartitionQueryResponse>, Status> {
        if let Some(local) = self.local_backend() {
            // An Admin / data-pipeline surface: owner-only while rules are enforced.
            let caller = self.caller(
                request.metadata(),
                &request.get_ref().parent,
                "PartitionQuery",
            )?;
            if let Some(rules) = &self.rules {
                rules.require_owner(&caller.principal, "PartitionQuery")?;
            }
            let local = local.clone();
            let request = request.into_inner();
            return blocking_local(local, move |local| local.partition_query(&request))
                .await
                .map(Response::new);
        }
        Err(Status::unimplemented(
            "PartitionQuery is served by the local backend only",
        ))
    }

    type WriteStream = BoxStream<pb::WriteResponse>;
    async fn write(
        &self,
        request: Request<Streaming<pb::WriteRequest>>,
    ) -> Result<Response<Self::WriteStream>, Status> {
        let ctx = self.stream_context(request.metadata())?;
        let (tx, rx) = tokio::sync::mpsc::channel(64);
        tokio::spawn(crate::streams::write_stream(ctx, request.into_inner(), tx));
        Ok(Response::new(Box::pin(
            tokio_stream::wrappers::ReceiverStream::new(rx),
        )))
    }

    type ListenStream = BoxStream<pb::ListenResponse>;
    async fn listen(
        &self,
        request: Request<Streaming<pb::ListenRequest>>,
    ) -> Result<Response<Self::ListenStream>, Status> {
        let ctx = self.stream_context(request.metadata())?;
        let (tx, rx) = tokio::sync::mpsc::channel(256);
        tokio::spawn(crate::streams::listen_stream(ctx, request.into_inner(), tx));
        Ok(Response::new(Box::pin(
            tokio_stream::wrappers::ReceiverStream::new(rx),
        )))
    }

    async fn list_collection_ids(
        &self,
        request: Request<pb::ListCollectionIdsRequest>,
    ) -> Result<Response<pb::ListCollectionIdsResponse>, Status> {
        if let Some(local) = self.local_backend() {
            let caller = self.caller(
                request.metadata(),
                &request.get_ref().parent,
                "ListCollectionIds",
            )?;
            if let Some(rules) = &self.rules {
                // Collection enumeration has no rules equivalent: admin-only under rules.
                rules.require_owner(&caller.principal, "ListCollectionIds")?;
            }
            let local = local.clone();
            let request = request.into_inner();
            return blocking_local(local, move |local| local.list_collection_ids(&request))
                .await
                .map(Response::new);
        }
        self.client()?
            .list_collection_ids(request.into_inner())
            .await
    }

    async fn batch_write(
        &self,
        request: Request<pb::BatchWriteRequest>,
    ) -> Result<Response<pb::BatchWriteResponse>, Status> {
        if let Some(local) = self.local_backend() {
            let caller = self.caller(
                request.metadata(),
                &request.get_ref().database,
                "BatchWrite",
            )?;
            let guard = self.write_guard(&caller);
            return local
                .batch_write_with(request.get_ref(), &*guard)
                .map(Response::new);
        }
        self.client()?.batch_write(request.into_inner()).await
    }

    async fn create_document(
        &self,
        request: Request<pb::CreateDocumentRequest>,
    ) -> Result<Response<pb::Document>, Status> {
        if let Some(local) = self.local_backend() {
            let caller = self.caller(
                request.metadata(),
                &request.get_ref().parent,
                "CreateDocument",
            )?;
            let (parent, lease) = LocalBackend::plan_create_lease(request.get_ref())?;
            return local
                .retry_on_contention_async(&parent, None, std::slice::from_ref(&lease), || {
                    let guard = self.write_guard(&caller);
                    local.create_document_once(request.get_ref(), &*guard)
                })
                .await
                .map(Response::new);
        }
        self.client()?.create_document(request.into_inner()).await
    }
}

/// The target project of a Firestore resource name (`projects/{p}/databases/...`).
///
/// An unparsable name resolves to the empty project, which fails closed: the App Check
/// registry knows no such project, so no presented token can verify against it and an
/// enforced request is denied before the decoder reports what was wrong with the name.
#[must_use]
pub fn project_of_resource(resource: &str) -> &str {
    resource
        .strip_prefix("projects/")
        .and_then(|rest| rest.split('/').next())
        .unwrap_or("")
}

/// Every `x-firebase-appcheck` metadata value, in wire order (specification section 7.3).
///
/// Duplicates survive so the classifier can refuse them; no caller selects one of several. A
/// binary entry can never be the App Check field, because gRPC binary keys end in `-bin` and
/// `as_str` includes that suffix. A value that is not renderable as text becomes an empty
/// string, which classifies as malformed.
#[must_use]
pub fn app_check_values(metadata: &tonic::metadata::MetadataMap) -> Vec<String> {
    metadata
        .iter()
        .filter_map(|entry| match entry {
            tonic::metadata::KeyAndValueRef::Ascii(name, value) => {
                is_app_check_header(name.as_str())
                    .then(|| value.to_str().unwrap_or_default().to_owned())
            }
            tonic::metadata::KeyAndValueRef::Binary(_, _) => None,
        })
        .collect()
}

/// The gRPC shape of an App Check denial (specification section 17): `PERMISSION_DENIED`
/// with the public reason code in `fireemu-code`. The detailed reason stays in the observation.
#[must_use]
pub fn app_check_denied(reason: &'static str) -> Status {
    let message = if reason == fireemu_core_app_check::verify::PUBLIC_REQUIRED_REASON {
        "App Check token is required by this project's Cloud Firestore enforcement."
    } else {
        "App Check token is invalid."
    };
    let mut status = Status::permission_denied(message);
    if let Ok(value) = reason.parse() {
        status.metadata_mut().insert("fireemu-code", value);
    }
    status
}

/// A unary caller: principal and the reset epoch the request started in.
#[derive(Clone)]
struct Caller {
    principal: Principal,
    epoch: u64,
}

fn set_run_query_page(req: &mut pb::RunQueryRequest, offset: i32, remaining: Option<i32>) {
    let Some(pb::run_query_request::QueryType::StructuredQuery(query)) = &mut req.query_type else {
        return;
    };
    query.offset = offset;
    query.limit = Some(remaining.map_or(RUN_QUERY_BATCH_SIZE, |remaining| {
        remaining.min(RUN_QUERY_BATCH_SIZE)
    }));
}

fn is_name_ordered_query(query: &Query) -> bool {
    matches!(
        query.effective_order_by().as_slice(),
        [order]
            if order.field.is_document_name()
                && matches!(order.direction, Direction::Ascending | Direction::Descending)
    )
}

fn last_query_document_path(
    responses: &[pb::RunQueryResponse],
) -> Result<Option<DocumentPath>, Status> {
    responses
        .iter()
        .rev()
        .find_map(|response| response.document.as_ref())
        .map(|document| {
            decode_document_name(&document.name)
                .map_err(|_| Status::internal("RunQuery response contained an invalid name"))
        })
        .transpose()
}

/// The transaction a page announces (`NewTransaction` selectors answer with one).
fn announced_transaction(responses: &[pb::RunQueryResponse]) -> Option<Vec<u8>> {
    responses.iter().find_map(|response| {
        (!response.transaction.is_empty()).then(|| response.transaction.clone())
    })
}

fn database_name_from_query_parent(parent: &str) -> String {
    // The request parent has already been validated. Match resource segments, not a
    // substring that can also occur in a project ID such as `documents-demo`.
    parent.split('/').take(4).collect::<Vec<_>>().join("/")
}

// A channel send only enqueues an announcement. Ownership transfers to the caller when
// tonic polls that announcement out of the stream; physical network receipt is unknowable.
struct QueryResponseStream {
    receiver: tokio::sync::mpsc::Receiver<Result<pb::RunQueryResponse, Status>>,
    announcement_guard: Option<QueryTransactionGuard>,
}

impl tokio_stream::Stream for QueryResponseStream {
    type Item = Result<pb::RunQueryResponse, Status>;

    fn poll_next(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        let this = self.get_mut();
        let response = this.receiver.poll_recv(cx);
        if let std::task::Poll::Ready(Some(Ok(message))) = &response {
            if !message.transaction.is_empty() {
                if let Some(mut guard) = this.announcement_guard.take() {
                    guard.transaction.clear();
                }
            }
        }
        response
    }
}

struct QueryTransactionGuard {
    local: Arc<LocalBackend>,
    database: String,
    transaction: Vec<u8>,
}

impl Drop for QueryTransactionGuard {
    fn drop(&mut self) {
        if !self.transaction.is_empty() {
            let _ = self.local.rollback(&pb::RollbackRequest {
                database: self.database.clone(),
                transaction: self.transaction.clone(),
                ..Default::default()
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use fireemu_core_firestore::field_path::FieldPath;
    use fireemu_core_firestore::index::{IndexSet, PlanningContext};
    use fireemu_core_firestore::store::FirestoreState;
    use fireemu_core_session::clock::VirtualClock;
    use fireemu_core_types::edition::{FirestoreApiMode, FirestoreEdition};
    use fireemu_core_types::ids::CollectionId;
    use fireemu_core_types::time::LogicalInstant;
    use fireemu_proto_firestore::google::firestore::v1::firestore_server::FirestoreServer;
    use tokio_stream::wrappers::TcpListenerStream;

    use super::*;

    fn test_gateway() -> Gateway {
        Gateway {
            enforce_limits: true,
            ctx: PlanningContext {
                edition: FirestoreEdition::Standard,
                api_mode: FirestoreApiMode::Native,
                policy: fireemu_core_firestore::index::IndexValidationPolicy::Production,
            },
            indexes: IndexSet::default(),
        }
    }

    fn test_backend() -> Arc<LocalBackend> {
        Arc::new(LocalBackend::new(
            test_gateway(),
            Arc::new(Mutex::new(VirtualClock::new(LogicalInstant::UNIX_EPOCH))),
            7,
        ))
    }

    fn query_request() -> pb::RunQueryRequest {
        pb::RunQueryRequest {
            parent: "projects/demo-app/databases/(default)/documents".to_owned(),
            query_type: Some(pb::run_query_request::QueryType::StructuredQuery(
                pb::StructuredQuery {
                    from: vec![pb::structured_query::CollectionSelector {
                        collection_id: "items".to_owned(),
                        all_descendants: false,
                    }],
                    ..Default::default()
                },
            )),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn proxy_aggregation_validation_rejects_unindexed_sum_before_upstream() {
        let collection = CollectionId::try_new("orders").unwrap();
        let mut indexes = IndexSet::default();
        indexes.set_single_field_indexes(&collection, &FieldPath::parse("amount").unwrap(), vec![]);
        let gateway = Gateway {
            enforce_limits: true,
            ctx: PlanningContext {
                edition: FirestoreEdition::Standard,
                api_mode: FirestoreApiMode::Native,
                policy: fireemu_core_firestore::index::IndexValidationPolicy::Production,
            },
            indexes,
        };
        let upstream_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_address = upstream_listener.local_addr().unwrap();
        let upstream_gateway = Gateway {
            enforce_limits: true,
            ctx: PlanningContext {
                edition: FirestoreEdition::Standard,
                api_mode: FirestoreApiMode::Native,
                policy: fireemu_core_firestore::index::IndexValidationPolicy::Production,
            },
            indexes: IndexSet::default(),
        };
        let upstream_service = FirestoreServer::new(GatewayService::new(upstream_gateway, None));
        let upstream_handle = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(upstream_service)
                .serve_with_incoming(TcpListenerStream::new(upstream_listener))
                .await
                .unwrap();
        });
        let channel = tonic::transport::Endpoint::from_shared(format!("http://{upstream_address}"))
            .unwrap()
            .connect()
            .await
            .unwrap();
        let service = GatewayService::new(gateway, Some(channel));
        let request = pb::RunAggregationQueryRequest {
            parent: "projects/demo-app/databases/(default)/documents".to_owned(),
            query_type: Some(
                pb::run_aggregation_query_request::QueryType::StructuredAggregationQuery(
                    pb::StructuredAggregationQuery {
                        query_type: Some(
                            pb::structured_aggregation_query::QueryType::StructuredQuery(
                                pb::StructuredQuery {
                                    from: vec![pb::structured_query::CollectionSelector {
                                        collection_id: "orders".to_owned(),
                                        all_descendants: false,
                                    }],
                                    ..Default::default()
                                },
                            ),
                        ),
                        aggregations: vec![pb::structured_aggregation_query::Aggregation {
                            alias: "total".to_owned(),
                            operator: Some(
                                pb::structured_aggregation_query::aggregation::Operator::Sum(
                                    pb::structured_aggregation_query::aggregation::Sum {
                                        field: Some(pb::structured_query::FieldReference {
                                            field_path: "amount".to_owned(),
                                        }),
                                    },
                                ),
                            ),
                        }],
                    },
                ),
            ),
            ..Default::default()
        };

        let Err(error) = Firestore::run_aggregation_query(&service, Request::new(request)).await
        else {
            panic!("proxy aggregation unexpectedly reached the upstream client")
        };
        assert_eq!(error.code(), tonic::Code::FailedPrecondition);
        assert!(error.message().contains("amount Ascending"), "{error}");
        upstream_handle.abort();
    }

    #[test]
    fn guards_refuse_a_caller_from_before_a_reset() {
        let gateway = Gateway {
            enforce_limits: true,
            ctx: PlanningContext {
                edition: FirestoreEdition::Standard,
                api_mode: FirestoreApiMode::Native,
                policy: fireemu_core_firestore::index::IndexValidationPolicy::Production,
            },
            indexes: IndexSet::default(),
        };
        let clock = Arc::new(Mutex::new(VirtualClock::new(LogicalInstant::UNIX_EPOCH)));
        let backend = Arc::new(LocalBackend::new(gateway.clone(), clock, 7));
        let svc = GatewayService::local(gateway, backend.clone());
        let caller = Caller {
            principal: Principal::Owner,
            epoch: backend.barrier().epoch(),
        };
        let db = FirestoreState::new();
        let read = svc.read_guard(&caller);
        let write = svc.write_guard(&caller);
        assert!(read(&db, None, crate::rules::ReadCheck::Documents(&[])).is_ok());
        assert!(write(&db, &[], LogicalInstant::UNIX_EPOCH).is_ok());
        drop(backend.barrier().exclusive());
        let refused = read(&db, None, crate::rules::ReadCheck::Documents(&[])).unwrap_err();
        assert_eq!(refused.code(), tonic::Code::Unavailable);
        assert_eq!(
            write(&db, &[], LogicalInstant::UNIX_EPOCH)
                .unwrap_err()
                .code(),
            tonic::Code::Unavailable
        );
    }

    fn transaction_stats(
        backend: &LocalBackend,
    ) -> fireemu_core_firestore::store::TransactionBookkeepingStats {
        transaction_stats_for(backend, &query_request().parent)
    }

    fn transaction_stats_for(
        backend: &LocalBackend,
        parent: &str,
    ) -> fireemu_core_firestore::store::TransactionBookkeepingStats {
        backend
            .database_handle(&parse_parent(parent).unwrap())
            .unwrap()
            .with(|state| Ok(state.transaction_bookkeeping_stats()))
            .unwrap()
    }

    fn new_query_transaction(read_only: bool) -> pb::run_query_request::ConsistencySelector {
        pb::run_query_request::ConsistencySelector::NewTransaction(pb::TransactionOptions {
            mode: Some(if read_only {
                pb::transaction_options::Mode::ReadOnly(pb::transaction_options::ReadOnly::default())
            } else {
                pb::transaction_options::Mode::ReadWrite(
                    pb::transaction_options::ReadWrite::default(),
                )
            }),
        })
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn run_query_cancelled_before_its_first_page_releases_new_transactions() {
        for selector in [
            None,
            Some(new_query_transaction(true)),
            Some(new_query_transaction(false)),
        ] {
            let backend = test_backend();
            let mut service = GatewayService::local(test_gateway(), backend.clone());
            let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
            let ready_tx = Mutex::new(Some(ready_tx));
            let (release_tx, release_rx) = mpsc::channel();
            let release_rx = Mutex::new(release_rx);
            service.first_query_page_ready = Some(Arc::new(move || {
                ready_tx.lock().unwrap().take().unwrap().send(()).unwrap();
                release_rx
                    .lock()
                    .unwrap()
                    .recv_timeout(Duration::from_secs(5))
                    .unwrap();
            }));
            let mut request = query_request();
            request.parent = "projects/documents-demo/databases/(default)/documents".to_owned();
            let parent = request.parent.clone();
            request.consistency_selector = selector;
            let query = tokio::spawn(async move {
                Firestore::run_query(&service, Request::new(request))
                    .await
                    .map(|_| ())
            });
            tokio::time::timeout(Duration::from_secs(5), ready_rx)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(transaction_stats_for(&backend, &parent).active, 1);
            query.abort();
            assert!(query.await.unwrap_err().is_cancelled());
            release_tx.send(()).unwrap();
            tokio::time::timeout(Duration::from_secs(5), async {
                while transaction_stats_for(&backend, &parent).finished != 1 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("unreceived transaction must be released");
            assert_eq!(transaction_stats_for(&backend, &parent).active, 0);
        }
    }

    #[test]
    fn query_database_name_uses_resource_segments() {
        for database in [
            "projects/demo-app/databases/(default)",
            "projects/documents-demo/databases/(default)",
            "projects/demo-app/databases/documents-db",
        ] {
            for suffix in ["/documents", "/documents/items/parent"] {
                assert_eq!(
                    database_name_from_query_parent(&format!("{database}{suffix}")),
                    database
                );
            }
        }
    }

    #[tokio::test]
    async fn run_query_unpolled_stream_releases_new_transactions() {
        for read_only in [true, false] {
            let backend = test_backend();
            let service = GatewayService::local(test_gateway(), backend.clone());
            let mut request = query_request();
            request.parent = "projects/documents-demo/databases/(default)/documents".to_owned();
            let parent = request.parent.clone();
            request.consistency_selector = Some(new_query_transaction(read_only));
            let stream = Firestore::run_query(&service, Request::new(request))
                .await
                .unwrap();
            drop(stream);
            tokio::time::timeout(Duration::from_secs(5), async {
                while transaction_stats_for(&backend, &parent).finished != 1 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("unpolled transaction announcement must be released");
            assert_eq!(transaction_stats_for(&backend, &parent).active, 0);
        }
    }

    #[tokio::test]
    async fn run_query_delivered_and_existing_transactions_remain_usable() {
        use tokio_stream::StreamExt;
        for read_only in [true, false] {
            for drain in [false, true] {
                let backend = test_backend();
                let service = GatewayService::local(test_gateway(), backend.clone());
                let mut request = query_request();
                request.consistency_selector = Some(new_query_transaction(read_only));
                let mut stream = Firestore::run_query(&service, Request::new(request))
                    .await
                    .unwrap()
                    .into_inner();
                let announcement = stream.next().await.unwrap().unwrap();
                assert!(!announcement.transaction.is_empty());
                if drain {
                    while let Some(response) = stream.next().await {
                        response.unwrap();
                    }
                }
                drop(stream);
                assert_eq!(transaction_stats(&backend).active, 1);
                // Reusing the delivered token also covers existing-token stream cancellation.
                let mut reuse = query_request();
                reuse.consistency_selector =
                    Some(pb::run_query_request::ConsistencySelector::Transaction(
                        announcement.transaction.clone(),
                    ));
                let existing = Firestore::run_query(&service, Request::new(reuse.clone()))
                    .await
                    .unwrap();
                drop(existing);
                assert_eq!(transaction_stats(&backend).active, 1);
                let mut existing = Firestore::run_query(&service, Request::new(reuse))
                    .await
                    .unwrap()
                    .into_inner();
                while let Some(response) = existing.next().await {
                    response.unwrap();
                }
                assert_eq!(transaction_stats(&backend).active, 1);
                backend
                    .rollback(&pb::RollbackRequest {
                        database: database_name_from_query_parent(&query_request().parent),
                        transaction: announcement.transaction,
                        ..Default::default()
                    })
                    .unwrap();
                assert_eq!(transaction_stats(&backend).active, 0);
            }
        }
    }

    mod query_transaction_tests;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn saturated_blocking_queries_leave_runtime_and_other_databases_responsive() {
        const QUERIES: usize = 4;
        let backend = test_backend();
        let epoch = backend.barrier().epoch();
        let mut entered = Vec::new();
        let mut releases = Vec::new();
        let mut tasks = Vec::new();
        for _ in 0..QUERIES {
            let (entered_tx, entered_rx) = mpsc::channel();
            let (release_tx, release_rx) = mpsc::channel();
            entered.push(entered_rx);
            releases.push(release_tx);
            let local = backend.clone();
            tasks.push(tokio::spawn(blocking_read(
                local,
                None,
                Caller {
                    principal: Principal::Owner,
                    epoch,
                },
                move |local, guard| {
                    entered_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                    local.run_query(&query_request(), guard).map(|_| ())
                },
            )));
        }
        for receiver in entered {
            receiver.recv_timeout(Duration::from_secs(1)).unwrap();
        }

        tokio::time::timeout(Duration::from_millis(100), tokio::task::yield_now())
            .await
            .expect("the async runtime remains responsive");
        let other_database = backend.clone();
        tokio::time::timeout(Duration::from_millis(100), async move {
            other_database.get_document_snapshot(
                &pb::GetDocumentRequest {
                    name: "projects/demo-app/databases/other/documents/items/missing".to_owned(),
                    ..Default::default()
                },
                &crate::rules::allow_all_reads,
            )
        })
        .await
        .expect("another database answers within the normal latency bound")
        .expect("a missing document still has a valid snapshot");

        for release in releases {
            release.send(()).unwrap();
        }
        for task in tasks {
            task.await.unwrap().unwrap();
        }
    }
}
