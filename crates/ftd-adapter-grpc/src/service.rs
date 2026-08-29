//! `google.firestore.v1.Firestore` service: strict gateway in front of a backend.
//!
//! The backend is either the local execution engine ([`LocalBackend`]), an upstream channel
//! (official Emulator or real service, proxy mode), or nothing (validation-only mode, where
//! validated requests answer `UNIMPLEMENTED` rather than a fake success).

// `tonic::Status` is the error type dictated by the generated trait.
#![allow(clippy::result_large_err)]

use std::sync::Arc;

use ftd_proto_firestore::google::firestore::v1 as pb;
use ftd_proto_firestore::google::firestore::v1::firestore_client::FirestoreClient;
use ftd_proto_firestore::google::firestore::v1::firestore_server::Firestore;
use tonic::codegen::tokio_stream;
use tonic::transport::Channel;
use tonic::{Request, Response, Status, Streaming};

use crate::decode::{decode_structured_query, parse_parent};
use crate::gateway::{Gateway, Rejection};
use crate::local::LocalBackend;
use crate::rules::{Principal, RulesEnforcer};

/// Boxed response stream.
pub type BoxStream<T> = tonic::codegen::BoxStream<T>;

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
        }
    }

    /// Creates the service with the local execution backend.
    #[must_use]
    pub fn local(gateway: Gateway, backend: Arc<LocalBackend>) -> Self {
        Self {
            gateway: Arc::new(gateway),
            backend: Backend::Local(backend),
            rules: None,
        }
    }

    /// Enforces Security Rules on the local backend.
    #[must_use]
    pub fn with_rules(mut self, rules: Arc<RulesEnforcer>) -> Self {
        self.rules = Some(rules);
        self
    }

    fn principal(&self, metadata: &tonic::metadata::MetadataMap) -> Result<Principal, Status> {
        match &self.rules {
            Some(r) => r.principal(metadata),
            None => Ok(Principal::Owner),
        }
    }

    /// Authorizes a single-document read against its snapshot.
    fn authorize_get(
        &self,
        principal: &Principal,
        path: &ftd_core_firestore::path::DocumentPath,
        snapshot: Option<&ftd_core_firestore::store::Document>,
    ) -> Result<(), Status> {
        match &self.rules {
            Some(r) => r.authorize_get(principal, path, snapshot),
            None => Ok(()),
        }
    }

    /// Authorizes a query from its constraints.
    fn authorize_query(
        &self,
        principal: &Principal,
        parent: &crate::decode::Parent,
        query: &ftd_core_firestore::query::Query,
    ) -> Result<(), Status> {
        match &self.rules {
            Some(r) => r.authorize_query(principal, parent, query),
            None => Ok(()),
        }
    }

    /// Write guard for the local backend (runs inside the commit critical section).
    fn write_guard<'a>(&'a self, principal: &'a Principal) -> crate::rules::BoxedWriteGuard<'a> {
        crate::rules::write_guard(self.rules.as_ref(), principal)
    }

    /// Structured query of a `ListDocuments` request (unfiltered collection scan).
    fn list_query(req: &pb::ListDocumentsRequest) -> pb::StructuredQuery {
        pb::StructuredQuery {
            from: vec![pb::structured_query::CollectionSelector {
                collection_id: req.collection_id.clone(),
                all_descendants: false,
            }],
            ..Default::default()
        }
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
        Ok(crate::streams::StreamContext {
            local: local.clone(),
            gateway: self.gateway.clone(),
            rules: self.rules.clone(),
            principal: self.principal(metadata)?,
            authorization: metadata
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned),
            epoch: local.epoch(),
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
        let query =
            decode_structured_query(&parent, sq).map_err(|e| Rejection::Decode(e).to_status())?;
        let accepted = self
            .gateway
            .validate_query(&query)
            .map_err(|r| r.to_status())?;
        Ok(accepted.warnings)
    }
}

fn with_warnings<T>(mut response: Response<T>, warnings: &[String]) -> Response<T> {
    for w in warnings {
        if let Ok(v) = w.parse() {
            response.metadata_mut().append("ftd-warning", v);
        }
    }
    response
}

#[tonic::async_trait]
impl Firestore for GatewayService {
    async fn get_document(
        &self,
        request: Request<pb::GetDocumentRequest>,
    ) -> Result<Response<pb::Document>, Status> {
        if let Some(local) = self.local_backend() {
            let principal = self.principal(request.metadata())?;
            let snapshot = local.get_document_snapshot(request.get_ref())?;
            self.authorize_get(&principal, &snapshot.path, snapshot.document.as_ref())?;
            return snapshot.into_response().map(Response::new);
        }
        self.client()?.get_document(request.into_inner()).await
    }

    async fn list_documents(
        &self,
        request: Request<pb::ListDocumentsRequest>,
    ) -> Result<Response<pb::ListDocumentsResponse>, Status> {
        if let Some(local) = self.local_backend() {
            let principal = self.principal(request.metadata())?;
            let req = request.get_ref();
            let parent = parse_parent(&req.parent).map_err(|e| Rejection::Decode(e).to_status())?;
            let accepted = local.accepted_query(&parent, &Self::list_query(req))?;
            self.authorize_query(&principal, &parent, &accepted.query)?;
            return local.list_documents(req).map(Response::new);
        }
        self.client()?.list_documents(request.into_inner()).await
    }

    async fn update_document(
        &self,
        request: Request<pb::UpdateDocumentRequest>,
    ) -> Result<Response<pb::Document>, Status> {
        if let Some(local) = self.local_backend() {
            let principal = self.principal(request.metadata())?;
            let (parent, write) = LocalBackend::plan_update(request.get_ref())?;
            let guard = self.write_guard(&principal);
            return local
                .execute_planned_with(&parent, write, request.get_ref().mask.as_ref(), &*guard)
                .map(Response::new);
        }
        self.client()?.update_document(request.into_inner()).await
    }

    async fn delete_document(
        &self,
        request: Request<pb::DeleteDocumentRequest>,
    ) -> Result<Response<()>, Status> {
        if let Some(local) = self.local_backend() {
            let principal = self.principal(request.metadata())?;
            let guard = self.write_guard(&principal);
            return local
                .delete_document_with(request.get_ref(), &*guard)
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
            let principal = self.principal(request.metadata())?;
            let outcome = local.batch_get_documents(request.get_ref())?;
            for item in &outcome.items {
                self.authorize_get(&principal, &item.path()?, item.document())?;
            }
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
            let principal = self.principal(request.metadata())?;
            let guard = self.write_guard(&principal);
            return local
                .commit_with(request.get_ref(), &*guard)
                .map(Response::new);
        }
        self.client()?.commit(request.into_inner()).await
    }

    async fn rollback(
        &self,
        request: Request<pb::RollbackRequest>,
    ) -> Result<Response<()>, Status> {
        if let Some(local) = self.local_backend() {
            return local.rollback(request.get_ref()).map(Response::new);
        }
        self.client()?.rollback(request.into_inner()).await
    }

    type RunQueryStream = BoxStream<pb::RunQueryResponse>;
    async fn run_query(
        &self,
        request: Request<pb::RunQueryRequest>,
    ) -> Result<Response<Self::RunQueryStream>, Status> {
        let principal = self.principal(request.metadata())?;
        let req = request.into_inner();
        if let Some(local) = self.local_backend() {
            let parent = parse_parent(&req.parent).map_err(|e| Rejection::Decode(e).to_status())?;
            let Some(pb::run_query_request::QueryType::StructuredQuery(sq)) = &req.query_type
            else {
                return Err(Status::invalid_argument(
                    "RunQuery requires a structured_query",
                ));
            };
            let accepted = local.accepted_query(&parent, sq)?;
            // Authorized from the query constraints before any data is touched.
            self.authorize_query(&principal, &parent, &accepted.query)?;
            let (responses, warnings) = local.run_query(&req)?;
            let stream: Vec<Result<pb::RunQueryResponse, Status>> =
                responses.into_iter().map(Ok).collect();
            let boxed: Self::RunQueryStream = Box::pin(tokio_stream::iter(stream));
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
        _request: Request<pb::ExecutePipelineRequest>,
    ) -> Result<Response<Self::ExecutePipelineStream>, Status> {
        Err(Status::unimplemented(
            "ExecutePipeline decode arrives with FS-PIPE-RPC-1; never forwarded unvalidated",
        ))
    }

    type RunAggregationQueryStream = BoxStream<pb::RunAggregationQueryResponse>;
    async fn run_aggregation_query(
        &self,
        request: Request<pb::RunAggregationQueryRequest>,
    ) -> Result<Response<Self::RunAggregationQueryStream>, Status> {
        if let Some(local) = self.local_backend() {
            let principal = self.principal(request.metadata())?;
            let req = request.get_ref();
            let parent = parse_parent(&req.parent).map_err(|e| Rejection::Decode(e).to_status())?;
            let sq = match &req.query_type {
                Some(pb::run_aggregation_query_request::QueryType::StructuredAggregationQuery(
                    saq,
                )) => match &saq.query_type {
                    Some(pb::structured_aggregation_query::QueryType::StructuredQuery(sq)) => sq,
                    None => {
                        return Err(Status::invalid_argument(
                            "aggregation query requires a structured_query",
                        ))
                    }
                },
                None => {
                    return Err(Status::invalid_argument(
                        "RunAggregationQuery requires a structured_aggregation_query",
                    ))
                }
            };
            let accepted = local.accepted_query(&parent, sq)?;
            // The underlying query is authorized from its constraints, like a list.
            self.authorize_query(&principal, &parent, &accepted.query)?;
            let response = local.run_aggregation_query(req)?;
            let stream: Vec<Result<pb::RunAggregationQueryResponse, Status>> = vec![Ok(response)];
            return Ok(Response::new(Box::pin(tokio_stream::iter(stream))));
        }
        let response = self
            .client()?
            .run_aggregation_query(request.into_inner())
            .await?;
        Ok(Response::new(Box::pin(response.into_inner())))
    }

    async fn partition_query(
        &self,
        _request: Request<pb::PartitionQueryRequest>,
    ) -> Result<Response<pb::PartitionQueryResponse>, Status> {
        Err(Status::unimplemented(
            "PartitionQuery is not part of FS-GW-1",
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
            let principal = self.principal(request.metadata())?;
            if let Some(rules) = &self.rules {
                // Collection enumeration has no rules equivalent: admin-only under rules.
                rules.require_owner(&principal, "ListCollectionIds")?;
            }
            return local
                .list_collection_ids(request.get_ref())
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
            let principal = self.principal(request.metadata())?;
            let guard = self.write_guard(&principal);
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
            let principal = self.principal(request.metadata())?;
            let (parent, write) = local.plan_create(request.get_ref())?;
            let guard = self.write_guard(&principal);
            return local
                .execute_planned_with(&parent, write, request.get_ref().mask.as_ref(), &*guard)
                .map(Response::new);
        }
        self.client()?.create_document(request.into_inner()).await
    }
}
