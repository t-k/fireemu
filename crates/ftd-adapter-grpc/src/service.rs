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
use crate::encode::decode_document_name;
use crate::gateway::{Gateway, Rejection};
use crate::local::{BatchGetItem, LocalBackend};
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

    fn authorize_get(
        &self,
        principal: &Principal,
        local: &LocalBackend,
        name: &str,
    ) -> Result<(), Status> {
        let Some(rules) = &self.rules else {
            return Ok(());
        };
        let path = decode_document_name(name).map_err(|e| Rejection::Decode(e).to_status())?;
        let parent = parse_parent(name).map_err(|e| Rejection::Decode(e).to_status())?;
        rules.authorize_get(principal, local, &parent, &path)
    }

    fn authorize_list(
        &self,
        principal: &Principal,
        local: &LocalBackend,
        parent: &crate::decode::Parent,
        names: &[String],
        collection_id: &str,
    ) -> Result<(), Status> {
        let Some(rules) = &self.rules else {
            return Ok(());
        };
        let documents = names
            .iter()
            .map(|n| decode_document_name(n).map_err(|e| Rejection::Decode(e).to_status()))
            .collect::<Result<Vec<_>, _>>()?;
        let placeholder = placeholder_path(parent, collection_id)?;
        rules.authorize_list(principal, local, parent, &documents, &placeholder)
    }

    fn authorize_writes(
        &self,
        principal: &Principal,
        local: &LocalBackend,
        parent: &crate::decode::Parent,
        writes: &[ftd_core_firestore::store::Write],
    ) -> Result<(), Status> {
        let Some(rules) = &self.rules else {
            return Ok(());
        };
        for w in writes {
            rules.authorize_write(principal, local, parent, w)?;
        }
        Ok(())
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

/// Document path standing in for "any document of this collection" when a list returns
/// nothing (the wildcard binds to `ftd-placeholder`).
fn placeholder_path(
    parent: &crate::decode::Parent,
    collection_id: &str,
) -> Result<ftd_core_firestore::path::DocumentPath, Status> {
    let relative = match &parent.document {
        Some(p) => format!("{}/{collection_id}/ftd-placeholder", p.relative()),
        None => format!("{collection_id}/ftd-placeholder"),
    };
    ftd_core_firestore::path::DocumentPath::parse(&parent.project, &parent.database, &relative)
        .map_err(|e| Status::invalid_argument(e.to_string()))
}

fn collection_of_query(req: &pb::RunQueryRequest) -> String {
    match &req.query_type {
        Some(pb::run_query_request::QueryType::StructuredQuery(sq)) => sq
            .from
            .first()
            .map(|f| f.collection_id.clone())
            .unwrap_or_default(),
        _ => String::new(),
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
            self.authorize_get(&principal, local, &request.get_ref().name)?;
            return local.get_document(request.get_ref()).map(Response::new);
        }
        self.client()?.get_document(request.into_inner()).await
    }

    async fn list_documents(
        &self,
        request: Request<pb::ListDocumentsRequest>,
    ) -> Result<Response<pb::ListDocumentsResponse>, Status> {
        if let Some(local) = self.local_backend() {
            let principal = self.principal(request.metadata())?;
            let response = local.list_documents(request.get_ref())?;
            let parent = parse_parent(&request.get_ref().parent)
                .map_err(|e| Rejection::Decode(e).to_status())?;
            let names: Vec<String> = response.documents.iter().map(|d| d.name.clone()).collect();
            self.authorize_list(
                &principal,
                local,
                &parent,
                &names,
                &request.get_ref().collection_id,
            )?;
            return Ok(Response::new(response));
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
            self.authorize_writes(&principal, local, &parent, std::slice::from_ref(&write))?;
            return local.update_document(request.get_ref()).map(Response::new);
        }
        self.client()?.update_document(request.into_inner()).await
    }

    async fn delete_document(
        &self,
        request: Request<pb::DeleteDocumentRequest>,
    ) -> Result<Response<()>, Status> {
        if let Some(local) = self.local_backend() {
            let principal = self.principal(request.metadata())?;
            let (parent, write) = LocalBackend::plan_delete(request.get_ref())?;
            self.authorize_writes(&principal, local, &parent, std::slice::from_ref(&write))?;
            return local.delete_document(request.get_ref()).map(Response::new);
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
            for name in &request.get_ref().documents {
                self.authorize_get(&principal, local, name)?;
            }
            let (items, transaction, read_at) = local.batch_get_documents(request.get_ref())?;
            let read_time = Some(crate::encode::encode_instant(read_at));
            if items.is_empty() && !transaction.is_empty() {
                // An empty batch still has to hand back the new transaction.
                let only = pb::BatchGetDocumentsResponse {
                    transaction,
                    read_time,
                    result: None,
                };
                return Ok(Response::new(Box::pin(tokio_stream::iter(vec![Ok(only)]))));
            }
            let responses: Vec<Result<pb::BatchGetDocumentsResponse, Status>> = items
                .into_iter()
                .enumerate()
                .map(|(i, item)| {
                    Ok(pb::BatchGetDocumentsResponse {
                        transaction: if i == 0 {
                            transaction.clone()
                        } else {
                            Vec::new()
                        },
                        read_time,
                        result: Some(match item {
                            BatchGetItem::Found(d) => {
                                pb::batch_get_documents_response::Result::Found(d)
                            }
                            BatchGetItem::Missing(n) => {
                                pb::batch_get_documents_response::Result::Missing(n)
                            }
                        }),
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
            let (parent, writes) = LocalBackend::plan_commit(request.get_ref())?;
            self.authorize_writes(&principal, local, &parent, &writes)?;
            return local.commit(request.get_ref()).map(Response::new);
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
            let (responses, warnings) = local.run_query(&req)?;
            let parent = parse_parent(&req.parent).map_err(|e| Rejection::Decode(e).to_status())?;
            let names: Vec<String> = responses
                .iter()
                .filter_map(|r| r.document.as_ref().map(|d| d.name.clone()))
                .collect();
            self.authorize_list(
                &principal,
                local,
                &parent,
                &names,
                &collection_of_query(&req),
            )?;
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
            let collection = match &req.query_type {
                Some(pb::run_aggregation_query_request::QueryType::StructuredAggregationQuery(
                    saq,
                )) => match &saq.query_type {
                    Some(pb::structured_aggregation_query::QueryType::StructuredQuery(sq)) => sq
                        .from
                        .first()
                        .map(|f| f.collection_id.clone())
                        .unwrap_or_default(),
                    None => String::new(),
                },
                None => String::new(),
            };
            // Aggregations return no documents: evaluated like an empty list.
            self.authorize_list(&principal, local, &parent, &[], &collection)?;
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
            let (parent, writes) = LocalBackend::plan_batch_write(request.get_ref())?;
            self.authorize_writes(&principal, local, &parent, &writes)?;
            return local.batch_write(request.get_ref()).map(Response::new);
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
            self.authorize_writes(&principal, local, &parent, std::slice::from_ref(&write))?;
            // Execute the planned write so that the auto-generated ID is the authorized one.
            return local
                .execute_planned(&parent, write, request.get_ref().mask.as_ref())
                .map(Response::new);
        }
        self.client()?.create_document(request.into_inner()).await
    }
}
