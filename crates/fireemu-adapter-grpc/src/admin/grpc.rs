//! The gRPC `google.firestore.admin.v1.FirestoreAdmin` and `google.longrunning.Operations`
//! services (scope decision C7).
//!
//! Each call is answered by the same Admin core as REST: the request is rendered as the REST
//! request it corresponds to, and the JSON answer is read back into the protobuf message, so
//! the two transports cannot disagree. The representative methods C7 names are served;
//! every other method is refused with `UNIMPLEMENTED`.

use std::fmt::Write as _;
use std::sync::Arc;

use fireemu_proto_firestore::google::firestore::admin::v1 as admin;
use fireemu_proto_firestore::google::longrunning as lro;
use prost::Message;
use serde_json::{json, Value};
use tonic::{Request, Response, Status};

use crate::rest::{RestRequest, RestState};

/// The Admin gRPC services over a REST state.
#[derive(Clone)]
pub struct AdminGrpc {
    rest: Arc<RestState>,
}

impl AdminGrpc {
    /// Serves the Admin API of `rest`.
    #[must_use]
    pub fn new(rest: Arc<RestState>) -> Self {
        Self { rest }
    }

    // Every tonic handler returns a Status; boxing it here would only unbox it again.
    #[allow(clippy::result_large_err)]
    fn call<T>(
        &self,
        request: &Request<T>,
        method: &str,
        path: &str,
        query: &str,
        body: Value,
    ) -> Result<Value, Status> {
        let authorization = request
            .metadata()
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let response = self.rest.handle(&RestRequest {
            method: method.to_owned(),
            path: format!("/v1/{path}"),
            query: query.to_owned(),
            authorization,
            app_check: Vec::new(),
            body,
            origin: None,
            browser_metadata: false,
        });
        if response.status == 200 {
            return Ok(response.body);
        }
        let error = &response.body["error"];
        let code = code_of(error["status"].as_str().unwrap_or("UNKNOWN"));
        Err(Status::new(
            code,
            error["message"].as_str().unwrap_or("").to_owned(),
        ))
    }
}

fn code_of(status: &str) -> tonic::Code {
    use tonic::Code;
    match status {
        "INVALID_ARGUMENT" => Code::InvalidArgument,
        "FAILED_PRECONDITION" => Code::FailedPrecondition,
        "OUT_OF_RANGE" => Code::OutOfRange,
        "UNAUTHENTICATED" => Code::Unauthenticated,
        "PERMISSION_DENIED" => Code::PermissionDenied,
        "NOT_FOUND" => Code::NotFound,
        "ALREADY_EXISTS" => Code::AlreadyExists,
        "ABORTED" => Code::Aborted,
        "RESOURCE_EXHAUSTED" => Code::ResourceExhausted,
        "CANCELLED" => Code::Cancelled,
        "UNIMPLEMENTED" => Code::Unimplemented,
        "UNAVAILABLE" => Code::Unavailable,
        "DEADLINE_EXCEEDED" => Code::DeadlineExceeded,
        "INTERNAL" => Code::Internal,
        _ => Code::Unknown,
    }
}

fn encode_query(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .filter(|(_, v)| !v.is_empty())
        .map(|(k, v)| format!("{k}={}", percent_encode(v)))
        .collect::<Vec<_>>()
        .join("&")
}

/// Percent-encodes a query parameter value (RFC 3986 unreserved characters kept).
fn percent_encode(value: &str) -> String {
    let mut out = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            out.push(char::from(byte));
        } else {
            let _ = write!(out, "%{byte:02X}");
        }
    }
    out
}

// ---- JSON -> protobuf ------------------------------------------------------------------------

fn timestamp(value: &Value) -> Option<prost_types::Timestamp> {
    let instant = fireemu_core_types::time::LogicalInstant::parse_rfc3339(value.as_str()?).ok()?;
    Some(crate::encode::encode_instant(instant))
}

fn duration(value: &Value) -> Option<prost_types::Duration> {
    let text = value.as_str()?.strip_suffix('s')?;
    let (whole, fraction) = text.split_once('.').unwrap_or((text, ""));
    Some(prost_types::Duration {
        seconds: whole.parse().ok()?,
        nanos: if fraction.is_empty() {
            0
        } else {
            format!("{fraction:0<9}")[..9].parse().ok()?
        },
    })
}

fn string(value: &Value, key: &str) -> String {
    value[key].as_str().unwrap_or_default().to_owned()
}

fn strings(value: &Value, key: &str) -> Vec<String> {
    value[key]
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn enumeration<E>(value: &Value, key: &str, parse: fn(&str) -> Option<E>) -> i32
where
    E: Into<i32>,
{
    value[key].as_str().and_then(parse).map_or(0, Into::into)
}

fn database(v: &Value) -> admin::Database {
    use admin::database as d;
    admin::Database {
        name: string(v, "name"),
        uid: string(v, "uid"),
        create_time: timestamp(&v["createTime"]),
        update_time: timestamp(&v["updateTime"]),
        delete_time: timestamp(&v["deleteTime"]),
        location_id: string(v, "locationId"),
        r#type: enumeration(v, "type", d::DatabaseType::from_str_name),
        concurrency_mode: enumeration(v, "concurrencyMode", d::ConcurrencyMode::from_str_name),
        version_retention_period: duration(&v["versionRetentionPeriod"]),
        earliest_version_time: timestamp(&v["earliestVersionTime"]),
        point_in_time_recovery_enablement: enumeration(
            v,
            "pointInTimeRecoveryEnablement",
            d::PointInTimeRecoveryEnablement::from_str_name,
        ),
        app_engine_integration_mode: enumeration(
            v,
            "appEngineIntegrationMode",
            d::AppEngineIntegrationMode::from_str_name,
        ),
        delete_protection_state: enumeration(
            v,
            "deleteProtectionState",
            d::DeleteProtectionState::from_str_name,
        ),
        previous_id: string(v, "previousId"),
        free_tier: v["freeTier"].as_bool(),
        etag: string(v, "etag"),
        database_edition: enumeration(v, "databaseEdition", d::DatabaseEdition::from_str_name),
        realtime_updates_mode: enumeration(
            v,
            "realtimeUpdatesMode",
            admin::RealtimeUpdatesMode::from_str_name,
        ),
        firestore_data_access_mode: enumeration(
            v,
            "firestoreDataAccessMode",
            d::DataAccessMode::from_str_name,
        ),
        mongodb_compatible_data_access_mode: enumeration(
            v,
            "mongodbCompatibleDataAccessMode",
            d::DataAccessMode::from_str_name,
        ),
        ..admin::Database::default()
    }
}

fn index(v: &Value) -> admin::Index {
    use admin::index as i;
    let fields = v["fields"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|f| i::IndexField {
            field_path: string(f, "fieldPath"),
            value_mode: if let Some(order) = f["order"].as_str() {
                i::index_field::Order::from_str_name(order)
                    .map(|o| i::index_field::ValueMode::Order(o.into()))
            } else if let Some(config) = f["arrayConfig"].as_str() {
                i::index_field::ArrayConfig::from_str_name(config)
                    .map(|c| i::index_field::ValueMode::ArrayConfig(c.into()))
            } else if f["vectorConfig"].is_object() {
                Some(i::index_field::ValueMode::VectorConfig(
                    i::index_field::VectorConfig {
                        dimension: f["vectorConfig"]["dimension"]
                            .as_i64()
                            .and_then(|d| i32::try_from(d).ok())
                            .unwrap_or(0),
                        r#type: Some(i::index_field::vector_config::Type::Flat(
                            i::index_field::vector_config::FlatIndex {},
                        )),
                    },
                ))
            } else {
                None
            },
        })
        .collect();
    admin::Index {
        name: string(v, "name"),
        query_scope: enumeration(v, "queryScope", i::QueryScope::from_str_name),
        fields,
        state: enumeration(v, "state", i::State::from_str_name),
        density: enumeration(v, "density", i::Density::from_str_name),
        ..admin::Index::default()
    }
}

fn progress(v: &Value) -> Option<admin::Progress> {
    v.is_object().then(|| admin::Progress {
        estimated_work: v["estimatedWork"]
            .as_str()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0),
        completed_work: v["completedWork"]
            .as_str()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0),
    })
}

fn any(type_url: &str, bytes: Vec<u8>) -> prost_types::Any {
    prost_types::Any {
        type_url: type_url.to_owned(),
        value: bytes,
    }
}

/// A JSON `Any` (`{"@type": ..., fields}`) packed as its protobuf message.
fn pack(v: &Value) -> Option<prost_types::Any> {
    let type_url = v["@type"].as_str()?;
    let name = type_url.rsplit('/').next()?;
    let bytes = match name {
        "google.firestore.admin.v1.Database" => database(v).encode_to_vec(),
        "google.firestore.admin.v1.Index" => index(v).encode_to_vec(),
        "google.firestore.admin.v1.ExportDocumentsResponse" => admin::ExportDocumentsResponse {
            output_uri_prefix: string(v, "outputUriPrefix"),
        }
        .encode_to_vec(),
        "google.protobuf.Empty"
        | "google.firestore.admin.v1.CreateDatabaseMetadata"
        | "google.firestore.admin.v1.UpdateDatabaseMetadata"
        | "google.firestore.admin.v1.DeleteDatabaseMetadata" => Vec::new(),
        "google.firestore.admin.v1.IndexOperationMetadata" => admin::IndexOperationMetadata {
            start_time: timestamp(&v["startTime"]),
            end_time: timestamp(&v["endTime"]),
            index: string(v, "index"),
            state: enumeration(v, "state", admin::OperationState::from_str_name),
            progress_documents: progress(&v["progressDocuments"]),
            progress_bytes: progress(&v["progressBytes"]),
        }
        .encode_to_vec(),
        "google.firestore.admin.v1.ExportDocumentsMetadata" => admin::ExportDocumentsMetadata {
            start_time: timestamp(&v["startTime"]),
            end_time: timestamp(&v["endTime"]),
            operation_state: enumeration(v, "operationState", admin::OperationState::from_str_name),
            progress_documents: progress(&v["progressDocuments"]),
            progress_bytes: progress(&v["progressBytes"]),
            collection_ids: strings(v, "collectionIds"),
            output_uri_prefix: string(v, "outputUriPrefix"),
            namespace_ids: strings(v, "namespaceIds"),
            snapshot_time: timestamp(&v["snapshotTime"]),
        }
        .encode_to_vec(),
        "google.firestore.admin.v1.ImportDocumentsMetadata" => admin::ImportDocumentsMetadata {
            start_time: timestamp(&v["startTime"]),
            end_time: timestamp(&v["endTime"]),
            operation_state: enumeration(v, "operationState", admin::OperationState::from_str_name),
            progress_documents: progress(&v["progressDocuments"]),
            progress_bytes: progress(&v["progressBytes"]),
            collection_ids: strings(v, "collectionIds"),
            input_uri_prefix: string(v, "inputUriPrefix"),
            namespace_ids: strings(v, "namespaceIds"),
        }
        .encode_to_vec(),
        _ => return None,
    };
    Some(any(type_url, bytes))
}

fn operation(v: &Value) -> lro::Operation {
    let result = if let Some(error) = v.get("error") {
        Some(lro::operation::Result::Error(
            fireemu_proto_firestore::google::rpc::Status {
                code: error["code"]
                    .as_i64()
                    .and_then(|c| i32::try_from(c).ok())
                    .unwrap_or(0),
                message: string(error, "message"),
                details: Vec::new(),
            },
        ))
    } else {
        v.get("response")
            .and_then(pack)
            .map(lro::operation::Result::Response)
    };
    lro::Operation {
        name: string(v, "name"),
        metadata: v.get("metadata").and_then(pack),
        done: v["done"].as_bool().unwrap_or(false),
        result,
    }
}

// ---- protobuf -> JSON --------------------------------------------------------------------------

fn enum_name<E: TryFrom<i32>>(value: i32, name: fn(&E) -> &'static str) -> Option<&'static str> {
    if value == 0 {
        return None;
    }
    E::try_from(value).ok().map(|e| name(&e))
}

fn database_body(d: &admin::Database) -> Value {
    use admin::database as db;
    let mut body = json!({});
    if !d.location_id.is_empty() {
        body["locationId"] = json!(d.location_id);
    }
    let pairs = [
        ("type", enum_name(d.r#type, db::DatabaseType::as_str_name)),
        (
            "concurrencyMode",
            enum_name(d.concurrency_mode, db::ConcurrencyMode::as_str_name),
        ),
        (
            "deleteProtectionState",
            enum_name(
                d.delete_protection_state,
                db::DeleteProtectionState::as_str_name,
            ),
        ),
        (
            "databaseEdition",
            enum_name(d.database_edition, db::DatabaseEdition::as_str_name),
        ),
        (
            "appEngineIntegrationMode",
            enum_name(
                d.app_engine_integration_mode,
                db::AppEngineIntegrationMode::as_str_name,
            ),
        ),
    ];
    for (key, value) in pairs {
        if let Some(value) = value {
            body[key] = json!(value);
        }
    }
    body
}

fn index_body(i: &admin::Index) -> Value {
    use admin::index as ix;
    let fields: Vec<Value> = i
        .fields
        .iter()
        .map(|f| match &f.value_mode {
            Some(ix::index_field::ValueMode::Order(o)) => json!({
                "fieldPath": f.field_path,
                "order": ix::index_field::Order::try_from(*o).map_or("", |o| o.as_str_name()),
            }),
            Some(ix::index_field::ValueMode::ArrayConfig(c)) => json!({
                "fieldPath": f.field_path,
                "arrayConfig": ix::index_field::ArrayConfig::try_from(*c).map_or("", |c| c.as_str_name()),
            }),
            Some(ix::index_field::ValueMode::VectorConfig(v)) => {
                json!({"fieldPath": f.field_path, "vectorConfig": {"dimension": v.dimension, "flat": {}}})
            }
            _ => json!({"fieldPath": f.field_path}),
        })
        .collect();
    let mut body = json!({"fields": fields});
    if let Some(scope) = enum_name(i.query_scope, ix::QueryScope::as_str_name) {
        body["queryScope"] = json!(scope);
    }
    body
}

fn unimplemented(method: &str) -> Status {
    Status::unimplemented(format!(
        "fireemu serves {method} over REST only, or not at all (FS-CONFIG-LIFECYCLE scope decisions C1 and C7)"
    ))
}

type R<T> = Result<Response<T>, Status>;

#[tonic::async_trait]
impl admin::firestore_admin_server::FirestoreAdmin for AdminGrpc {
    async fn create_index(&self, request: Request<admin::CreateIndexRequest>) -> R<lro::Operation> {
        let parent = request.get_ref().parent.clone();
        let body = request
            .get_ref()
            .index
            .as_ref()
            .map(index_body)
            .unwrap_or_default();
        let answer = self.call(&request, "POST", &format!("{parent}/indexes"), "", body)?;
        Ok(Response::new(operation(&answer)))
    }
    async fn list_indexes(
        &self,
        _r: Request<admin::ListIndexesRequest>,
    ) -> R<admin::ListIndexesResponse> {
        Err(unimplemented("ListIndexes"))
    }
    async fn get_index(&self, request: Request<admin::GetIndexRequest>) -> R<admin::Index> {
        let name = request.get_ref().name.clone();
        let answer = self.call(&request, "GET", &name, "", Value::Null)?;
        Ok(Response::new(index(&answer)))
    }
    async fn delete_index(&self, _r: Request<admin::DeleteIndexRequest>) -> R<()> {
        Err(unimplemented("DeleteIndex"))
    }
    async fn get_field(&self, _r: Request<admin::GetFieldRequest>) -> R<admin::Field> {
        Err(unimplemented("GetField"))
    }
    async fn update_field(&self, _r: Request<admin::UpdateFieldRequest>) -> R<lro::Operation> {
        Err(unimplemented("UpdateField"))
    }
    async fn list_fields(
        &self,
        _r: Request<admin::ListFieldsRequest>,
    ) -> R<admin::ListFieldsResponse> {
        Err(unimplemented("ListFields"))
    }
    async fn export_documents(
        &self,
        request: Request<admin::ExportDocumentsRequest>,
    ) -> R<lro::Operation> {
        let r = request.get_ref();
        let mut body = json!({"outputUriPrefix": r.output_uri_prefix});
        if !r.collection_ids.is_empty() {
            body["collectionIds"] = json!(r.collection_ids);
        }
        if !r.namespace_ids.is_empty() {
            body["namespaceIds"] = json!(r.namespace_ids);
        }
        let path = format!("{}:exportDocuments", r.name);
        let answer = self.call(&request, "POST", &path, "", body)?;
        Ok(Response::new(operation(&answer)))
    }
    async fn import_documents(
        &self,
        request: Request<admin::ImportDocumentsRequest>,
    ) -> R<lro::Operation> {
        let r = request.get_ref();
        let mut body = json!({"inputUriPrefix": r.input_uri_prefix});
        if !r.collection_ids.is_empty() {
            body["collectionIds"] = json!(r.collection_ids);
        }
        if !r.namespace_ids.is_empty() {
            body["namespaceIds"] = json!(r.namespace_ids);
        }
        let path = format!("{}:importDocuments", r.name);
        let answer = self.call(&request, "POST", &path, "", body)?;
        Ok(Response::new(operation(&answer)))
    }
    async fn bulk_delete_documents(
        &self,
        _r: Request<admin::BulkDeleteDocumentsRequest>,
    ) -> R<lro::Operation> {
        Err(unimplemented("BulkDeleteDocuments"))
    }
    async fn create_database(
        &self,
        request: Request<admin::CreateDatabaseRequest>,
    ) -> R<lro::Operation> {
        let r = request.get_ref();
        let body = r
            .database
            .as_ref()
            .map_or_else(|| json!({}), database_body);
        let query = encode_query(&[("databaseId", &r.database_id)]);
        let path = format!("{}/databases", r.parent);
        let answer = self.call(&request, "POST", &path, &query, body)?;
        Ok(Response::new(operation(&answer)))
    }
    async fn get_database(
        &self,
        request: Request<admin::GetDatabaseRequest>,
    ) -> R<admin::Database> {
        let name = request.get_ref().name.clone();
        let answer = self.call(&request, "GET", &name, "", Value::Null)?;
        Ok(Response::new(database(&answer)))
    }
    async fn list_databases(
        &self,
        request: Request<admin::ListDatabasesRequest>,
    ) -> R<admin::ListDatabasesResponse> {
        let r = request.get_ref();
        let query = if r.show_deleted {
            "showDeleted=true"
        } else {
            ""
        };
        let path = format!("{}/databases", r.parent);
        let answer = self.call(&request, "GET", &path, query, Value::Null)?;
        Ok(Response::new(admin::ListDatabasesResponse {
            databases: answer["databases"]
                .as_array()
                .into_iter()
                .flatten()
                .map(database)
                .collect(),
            unreachable: strings(&answer, "unreachable"),
        }))
    }
    async fn update_database(
        &self,
        _r: Request<admin::UpdateDatabaseRequest>,
    ) -> R<lro::Operation> {
        Err(unimplemented("UpdateDatabase"))
    }
    async fn delete_database(
        &self,
        request: Request<admin::DeleteDatabaseRequest>,
    ) -> R<lro::Operation> {
        let r = request.get_ref();
        let query = encode_query(&[("etag", &r.etag)]);
        let name = r.name.clone();
        let answer = self.call(&request, "DELETE", &name, &query, Value::Null)?;
        Ok(Response::new(operation(&answer)))
    }
    async fn create_user_creds(
        &self,
        _r: Request<admin::CreateUserCredsRequest>,
    ) -> R<admin::UserCreds> {
        Err(unimplemented("CreateUserCreds"))
    }
    async fn get_user_creds(&self, _r: Request<admin::GetUserCredsRequest>) -> R<admin::UserCreds> {
        Err(unimplemented("GetUserCreds"))
    }
    async fn list_user_creds(
        &self,
        _r: Request<admin::ListUserCredsRequest>,
    ) -> R<admin::ListUserCredsResponse> {
        Err(unimplemented("ListUserCreds"))
    }
    async fn enable_user_creds(
        &self,
        _r: Request<admin::EnableUserCredsRequest>,
    ) -> R<admin::UserCreds> {
        Err(unimplemented("EnableUserCreds"))
    }
    async fn disable_user_creds(
        &self,
        _r: Request<admin::DisableUserCredsRequest>,
    ) -> R<admin::UserCreds> {
        Err(unimplemented("DisableUserCreds"))
    }
    async fn reset_user_password(
        &self,
        _r: Request<admin::ResetUserPasswordRequest>,
    ) -> R<admin::UserCreds> {
        Err(unimplemented("ResetUserPassword"))
    }
    async fn delete_user_creds(&self, _r: Request<admin::DeleteUserCredsRequest>) -> R<()> {
        Err(unimplemented("DeleteUserCreds"))
    }
    async fn get_backup(&self, _r: Request<admin::GetBackupRequest>) -> R<admin::Backup> {
        Err(unimplemented("GetBackup"))
    }
    async fn list_backups(
        &self,
        _r: Request<admin::ListBackupsRequest>,
    ) -> R<admin::ListBackupsResponse> {
        Err(unimplemented("ListBackups"))
    }
    async fn delete_backup(&self, _r: Request<admin::DeleteBackupRequest>) -> R<()> {
        Err(unimplemented("DeleteBackup"))
    }
    async fn restore_database(
        &self,
        _r: Request<admin::RestoreDatabaseRequest>,
    ) -> R<lro::Operation> {
        Err(unimplemented("RestoreDatabase"))
    }
    async fn create_backup_schedule(
        &self,
        _r: Request<admin::CreateBackupScheduleRequest>,
    ) -> R<admin::BackupSchedule> {
        Err(unimplemented("CreateBackupSchedule"))
    }
    async fn get_backup_schedule(
        &self,
        _r: Request<admin::GetBackupScheduleRequest>,
    ) -> R<admin::BackupSchedule> {
        Err(unimplemented("GetBackupSchedule"))
    }
    async fn list_backup_schedules(
        &self,
        _r: Request<admin::ListBackupSchedulesRequest>,
    ) -> R<admin::ListBackupSchedulesResponse> {
        Err(unimplemented("ListBackupSchedules"))
    }
    async fn update_backup_schedule(
        &self,
        _r: Request<admin::UpdateBackupScheduleRequest>,
    ) -> R<admin::BackupSchedule> {
        Err(unimplemented("UpdateBackupSchedule"))
    }
    async fn delete_backup_schedule(
        &self,
        _r: Request<admin::DeleteBackupScheduleRequest>,
    ) -> R<()> {
        Err(unimplemented("DeleteBackupSchedule"))
    }
    async fn clone_database(&self, _r: Request<admin::CloneDatabaseRequest>) -> R<lro::Operation> {
        Err(unimplemented("CloneDatabase"))
    }
}

#[tonic::async_trait]
impl lro::operations_server::Operations for AdminGrpc {
    async fn list_operations(
        &self,
        _r: Request<lro::ListOperationsRequest>,
    ) -> R<lro::ListOperationsResponse> {
        Err(unimplemented("ListOperations"))
    }
    async fn get_operation(&self, request: Request<lro::GetOperationRequest>) -> R<lro::Operation> {
        let name = request.get_ref().name.clone();
        let answer = self.call(&request, "GET", &name, "", Value::Null)?;
        Ok(Response::new(operation(&answer)))
    }
    async fn delete_operation(&self, _r: Request<lro::DeleteOperationRequest>) -> R<()> {
        Err(unimplemented("DeleteOperation"))
    }
    async fn cancel_operation(&self, _r: Request<lro::CancelOperationRequest>) -> R<()> {
        Err(unimplemented("CancelOperation"))
    }
    async fn wait_operation(&self, _r: Request<lro::WaitOperationRequest>) -> R<lro::Operation> {
        Err(unimplemented("WaitOperation"))
    }
}

/// The daemon's one gRPC service: the Admin and long-running-operation services by path, the
/// Firestore data plane for everything else.
#[derive(Clone)]
pub struct AdminRouter<F> {
    firestore: F,
    admin: admin::firestore_admin_server::FirestoreAdminServer<AdminGrpc>,
    operations: lro::operations_server::OperationsServer<AdminGrpc>,
}

impl<F> AdminRouter<F> {
    /// Routes the Admin services of `rest` ahead of `firestore`.
    pub fn new(firestore: F, rest: Arc<RestState>) -> Self {
        let service = AdminGrpc::new(rest);
        Self {
            firestore,
            admin: admin::firestore_admin_server::FirestoreAdminServer::new(service.clone())
                .max_decoding_message_size(crate::serve::MAX_GRPC_MESSAGE_BYTES)
                .max_encoding_message_size(crate::serve::MAX_GRPC_MESSAGE_BYTES),
            operations: lro::operations_server::OperationsServer::new(service),
        }
    }
}

type BoxResponse = std::pin::Pin<
    Box<
        dyn std::future::Future<
                Output = Result<
                    tonic::codegen::http::Response<tonic::body::Body>,
                    std::convert::Infallible,
                >,
            > + Send,
    >,
>;

impl<F> tonic::codegen::Service<tonic::codegen::http::Request<tonic::body::Body>> for AdminRouter<F>
where
    F: tonic::codegen::Service<
            tonic::codegen::http::Request<tonic::body::Body>,
            Response = tonic::codegen::http::Response<tonic::body::Body>,
            Error = std::convert::Infallible,
        > + Clone
        + Send
        + 'static,
    F::Future: Send + 'static,
{
    type Response = tonic::codegen::http::Response<tonic::body::Body>;
    type Error = std::convert::Infallible;
    type Future = BoxResponse;

    fn poll_ready(
        &mut self,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: tonic::codegen::http::Request<tonic::body::Body>) -> Self::Future {
        let path = request.uri().path();
        if path.starts_with("/google.firestore.admin.v1.FirestoreAdmin/") {
            let mut service = self.admin.clone();
            Box::pin(async move { service.call(request).await })
        } else if path.starts_with("/google.longrunning.Operations/") {
            let mut service = self.operations.clone();
            Box::pin(async move { service.call(request).await })
        } else {
            let mut service = self.firestore.clone();
            Box::pin(async move { service.call(request).await })
        }
    }
}
