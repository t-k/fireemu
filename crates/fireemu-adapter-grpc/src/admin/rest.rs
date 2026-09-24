//! REST routes of the Firestore Admin API: `projects/{p}/databases[...]`, `projects/{p}/locations`
//! and the Enterprise-only collections production refuses on a Standard database.
//!
//! Every answer here was shaped after production (`conformance/fs-config-lifecycle-production.json`):
//! `databases.create` answers a finished operation, `databases.delete` an unfinished one that
//! never finishes, and a deleted database stays listed under its uid with `showDeleted=true`.

use std::collections::BTreeMap;

use serde_json::{json, Map, Value};
use tonic::Status;

use super::catalog::{
    CatalogRefusal, ConcurrencyMode, CreateRequest, DatabaseEdition, DatabaseRecord, DatabaseType,
    DeletedDatabase,
};
use super::locations;
use super::operations::{self, OperationKind};
use crate::encode::encode_instant;
use crate::rest::json::timestamp_to_json;
use crate::rest::{RestRequest, RestResponse, RestState};

const DATABASE_TYPE_URL: &str = "type.googleapis.com/google.firestore.admin.v1.Database";

/// How far back a read may address on a database without point-in-time recovery (C1: it is
/// never enabled locally).
const VERSION_RETENTION_SECONDS: i128 = 3600;

/// A JSON error envelope with production's optional `details`.
pub(crate) fn error(code: tonic::Code, message: &str, details: Option<Value>) -> RestResponse {
    let status = crate::rest::error_response(&Status::new(code, message));
    let mut body = status.body;
    if let Some(details) = details {
        body["error"]["details"] = details;
    }
    RestResponse {
        status: status.status,
        body,
    }
}

fn ok(body: Value) -> RestResponse {
    RestResponse { status: 200, body }
}

fn instant(at: fireemu_core_types::time::LogicalInstant) -> Value {
    json!(timestamp_to_json(&encode_instant(at)))
}

/// The resource a database answers with; `deleted` adds what a tombstone carries.
pub(crate) fn database_json(
    record: &DatabaseRecord,
    now: fireemu_core_types::time::LogicalInstant,
    deleted: Option<fireemu_core_types::time::LogicalInstant>,
) -> Value {
    let earliest = deleted.unwrap_or_else(|| {
        let window = VERSION_RETENTION_SECONDS * 1_000_000_000;
        std::cmp::max(
            record.create_time,
            fireemu_core_types::time::LogicalInstant::from_nanos(now.as_nanos() - window),
        )
    });
    let native = record.database_type == DatabaseType::FirestoreNative
        && record.edition == DatabaseEdition::Standard;
    let mut resource = Map::new();
    let name_id = if deleted.is_some() {
        &record.uid
    } else {
        &record.database
    };
    resource.insert(
        "name".into(),
        json!(format!("projects/{}/databases/{name_id}", record.project)),
    );
    resource.insert("uid".into(), json!(record.uid));
    resource.insert("createTime".into(), instant(record.create_time));
    resource.insert("updateTime".into(), instant(record.update_time));
    if let Some(at) = deleted {
        resource.insert("deleteTime".into(), instant(at));
    }
    resource.insert("locationId".into(), json!(record.location_id));
    resource.insert("type".into(), json!(record.database_type.as_str()));
    resource.insert("concurrencyMode".into(), json!(record.concurrency.as_str()));
    resource.insert(
        "versionRetentionPeriod".into(),
        json!(format!("{VERSION_RETENTION_SECONDS}s")),
    );
    resource.insert("earliestVersionTime".into(), instant(earliest));
    resource.insert("appEngineIntegrationMode".into(), json!("DISABLED"));
    resource.insert(
        "pointInTimeRecoveryEnablement".into(),
        json!("POINT_IN_TIME_RECOVERY_DISABLED"),
    );
    resource.insert(
        "deleteProtectionState".into(),
        json!(if record.delete_protection {
            "DELETE_PROTECTION_ENABLED"
        } else {
            "DELETE_PROTECTION_DISABLED"
        }),
    );
    if deleted.is_some() {
        resource.insert("previousId".into(), json!(record.database));
    }
    resource.insert("databaseEdition".into(), json!(record.edition.as_str()));
    resource.insert("freeTier".into(), json!(record.free_tier));
    resource.insert(
        "realtimeUpdatesMode".into(),
        json!(if native {
            "REALTIME_UPDATES_MODE_ENABLED"
        } else {
            "REALTIME_UPDATES_MODE_DISABLED"
        }),
    );
    if record.edition == DatabaseEdition::Enterprise {
        resource.insert(
            "firestoreDataAccessMode".into(),
            json!("DATA_ACCESS_MODE_DISABLED"),
        );
        resource.insert(
            "mongodbCompatibleDataAccessMode".into(),
            json!("DATA_ACCESS_MODE_ENABLED"),
        );
    }
    resource.insert(
        "enhancedTextSearchQueryMode".into(),
        json!("ENHANCED_QUERY_MODE_ENABLED"),
    );
    let mut value = Value::Object(resource);
    // Production's etag changes on every read; this one is a digest of the resource and the
    // read instant, which is all a caller can rely on.
    let mut digest = fireemu_core_types::hash::Sha256::new();
    digest.update(b"fireemu:database-etag:");
    digest.update(value.to_string().as_bytes());
    digest.update(&now.as_nanos().to_be_bytes());
    let etag = fireemu_core_types::hash::base64_standard(&digest.finalize()[..18]);
    value["etag"] = json!(etag);
    value
}

fn query_params(query: &str) -> BTreeMap<String, Vec<String>> {
    let decode = |s: &str| {
        fireemu_core_types::codec::percent_decode(s, fireemu_core_types::codec::PlusMode::Space)
    };
    let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for kv in query.split('&').filter(|s| !s.is_empty()) {
        let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
        out.entry(decode(k)).or_default().push(decode(v));
    }
    out
}

fn param<'a>(params: &'a BTreeMap<String, Vec<String>>, key: &str) -> Option<&'a str> {
    params.get(key).and_then(|v| v.first()).map(String::as_str)
}

/// A valid database id: 4-63 characters of `[a-z0-9-]`, starting with a letter and not ending
/// with a hyphen, or `(default)`.
pub(crate) fn valid_database_id(id: &str) -> bool {
    if id == fireemu_core_types::ids::DatabaseId::DEFAULT {
        return true;
    }
    (4..=63).contains(&id.len())
        && id.starts_with(|c: char| c.is_ascii_lowercase())
        && !id.ends_with('-')
        && id
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// Production's answer to a request body whose enum field names no value:
/// `Invalid value at 'database.database_edition' (type....DatabaseEdition), "PREMIUM"`.
fn invalid_enum(field: &str, type_name: &str, value: &Value) -> RestResponse {
    let message = format!(
        "Invalid value at '{field}' (type.googleapis.com/google.firestore.admin.v1.{type_name}), {value}"
    );
    error(
        tonic::Code::InvalidArgument,
        &message,
        Some(json!([{
            "@type": "type.googleapis.com/google.rpc.BadRequest",
            "fieldViolations": [{"field": field, "description": message}]
        }])),
    )
}

fn parse_enum<T>(
    body: &Value,
    key: &str,
    field: &str,
    type_name: &str,
    values: &[(&str, T)],
) -> Result<Option<T>, RestResponse>
where
    T: Copy,
{
    match body.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => values
            .iter()
            .find(|(name, _)| value.as_str() == Some(name))
            .map(|(_, v)| Some(*v))
            .ok_or_else(|| invalid_enum(field, type_name, value)),
    }
}

const TYPES: &[(&str, Option<DatabaseType>)] = &[
    ("DATABASE_TYPE_UNSPECIFIED", None),
    ("FIRESTORE_NATIVE", Some(DatabaseType::FirestoreNative)),
    ("DATASTORE_MODE", Some(DatabaseType::DatastoreMode)),
];
const EDITIONS: &[(&str, Option<DatabaseEdition>)] = &[
    ("DATABASE_EDITION_UNSPECIFIED", None),
    ("STANDARD", Some(DatabaseEdition::Standard)),
    ("ENTERPRISE", Some(DatabaseEdition::Enterprise)),
];
const CONCURRENCY: &[(&str, Option<ConcurrencyMode>)] = &[
    ("CONCURRENCY_MODE_UNSPECIFIED", None),
    ("PESSIMISTIC", Some(ConcurrencyMode::Pessimistic)),
    ("OPTIMISTIC", Some(ConcurrencyMode::Optimistic)),
    (
        "OPTIMISTIC_WITH_ENTITY_GROUPS",
        Some(ConcurrencyMode::OptimisticWithEntityGroups),
    ),
];
const PROTECTION: &[(&str, Option<bool>)] = &[
    ("DELETE_PROTECTION_STATE_UNSPECIFIED", None),
    ("DELETE_PROTECTION_DISABLED", Some(false)),
    ("DELETE_PROTECTION_ENABLED", Some(true)),
];

fn missing_database(project: &str, database: &str) -> RestResponse {
    error(
        tonic::Code::NotFound,
        &format!("Project '{project}' or database '{database}' does not exist."),
        None,
    )
}

fn refusal_response(refusal: &CatalogRefusal, project: &str, database: &str) -> RestResponse {
    match refusal {
        CatalogRefusal::AlreadyExists => error(
            tonic::Code::AlreadyExists,
            "Database already exists. Please use another database_id",
            None,
        ),
        CatalogRefusal::CoolingDown(seconds) => error(
            tonic::Code::FailedPrecondition,
            &format!(
                "Database ID '{database}' is not available in project '{project}'. Please retry in {seconds} seconds."
            ),
            None,
        ),
        CatalogRefusal::NotFound { deleted: true } => {
            error(tonic::Code::NotFound, "Requested database was not found.", None)
        }
        CatalogRefusal::NotFound { deleted: false } => missing_database(project, database),
        CatalogRefusal::Protected => error(
            tonic::Code::FailedPrecondition,
            "Cannot delete the database because delete protection state is set to DELETE_PROTECTION_ENABLED.",
            None,
        ),
    }
}

/// What fireemu answers for the managed-infrastructure surfaces scope decision C1 keeps out.
pub(crate) const MANAGED_INFRASTRUCTURE: &str = "fireemu does not serve backups, backup \
    schedules, restore, clone or point-in-time recovery (FS-CONFIG-LIFECYCLE scope decision C1)";

/// Whether a request names a managed-infrastructure surface: `databases:restore`,
/// `databases:clone`, `databases/{d}/backupSchedules[...]` or `locations/{l}/backups[...]`.
fn managed_infrastructure(segments: &[&str], action: Option<&str>) -> bool {
    match (segments.get(1).copied(), segments.len(), action) {
        (Some("databases"), 2, Some("restore" | "clone")) => true,
        (Some("databases"), n, _) if n >= 4 => segments[3] == "backupSchedules",
        (Some("locations"), n, _) if n >= 4 => segments[3] == "backups",
        _ => false,
    }
}

/// Whether a path under `projects/` is one of the Admin routes this module serves.
fn is_admin_path(segments: &[&str], action: Option<&str>) -> bool {
    match (segments.get(1).copied(), segments.len(), action) {
        (Some("locations" | "databases"), 2 | 3, None)
        | (
            Some("databases"),
            3,
            Some("exportDocuments" | "importDocuments" | "bulkDeleteDocuments"),
        ) => true,
        (Some("databases"), 4 | 5, None) => {
            matches!(segments[3], "operations" | "changeStreams" | "userCreds")
        }
        (Some("databases"), 6 | 7, None) => {
            segments[3] == "collectionGroups" && segments[5] == "indexes"
        }
        (Some("databases"), 5, Some("cancel")) => segments[3] == "operations",
        _ => false,
    }
}

/// Routes an Admin request, or returns `None` for a path this module does not serve.
pub(crate) fn route(state: &RestState, req: &RestRequest) -> Option<RestResponse> {
    let path = req.path.strip_prefix("/v1/projects/")?;
    let (resource, action) = match path.rsplit_once(':') {
        Some((resource, action)) if !action.contains('/') => (resource, Some(action)),
        _ => (path, None),
    };
    let segments: Vec<&str> = resource.split('/').collect();
    let project = *segments.first()?;
    if managed_infrastructure(&segments, action) {
        return Some(crate::rest::error_response(&Status::unimplemented(
            MANAGED_INFRASTRUCTURE,
        )));
    }
    let admin = is_admin_path(&segments, action);
    if !admin {
        return None;
    }
    if !crate::rules::is_owner_credential(req.authorization.as_deref()) {
        return Some(crate::rest::error_response(&Status::permission_denied(
            "Admin database inventory requires owner credentials",
        )));
    }
    // The Admin API is served for Standard Native daemons; the Enterprise and MongoDB
    // compatible configurations have their own, unimplemented, surfaces.
    if state.gateway.ctx.edition != fireemu_core_types::edition::FirestoreEdition::Standard
        || state.gateway.ctx.api_mode != fireemu_core_types::edition::FirestoreApiMode::Native
    {
        return Some(crate::rest::error_response(&Status::unimplemented(
            "the Admin API is supported only for Standard Native databases",
        )));
    }
    if project.is_empty() || segments.iter().skip(1).any(|s| s.is_empty()) {
        return Some(crate::rest::error_response(&Status::invalid_argument(
            "database resource must be projects/{project}/databases/{database}",
        )));
    }
    let params = query_params(&req.query);
    let decoded: Vec<String> = segments
        .iter()
        .map(|s| {
            fireemu_core_types::codec::percent_decode(
                s,
                fireemu_core_types::codec::PlusMode::Literal,
            )
        })
        .collect();
    let seg: Vec<&str> = decoded.iter().map(String::as_str).collect();
    Some(match (req.method.as_str(), seg.as_slice(), action) {
        ("GET", [_, "locations"], None) => locations::list(project, &params),
        ("GET", [_, "locations", location], None) => locations::get(project, location),
        ("GET", [_, "databases"], None) => list_databases(state, project, &params),
        ("POST", [_, "databases"], None) => create_database(state, project, &params, &req.body),
        ("GET", [_, "databases", database], None) => get_database(state, project, database),
        ("PATCH", [_, "databases", database], None) => {
            patch_database(state, project, database, &params, &req.body)
        }
        ("DELETE", [_, "databases", database], None) => {
            delete_database(state, project, database, &params)
        }
        (
            method,
            [_, "databases", database, "collectionGroups", group, "indexes", rest @ ..],
            None,
        ) => match live_native(state, project, database) {
            Ok(()) => {
                super::index_rest::route(state, project, database, group, method, rest, &req.body)
            }
            Err(response) => response,
        },
        (
            "POST",
            [_, "databases", database],
            Some(action @ ("exportDocuments" | "importDocuments" | "bulkDeleteDocuments")),
        ) => match live_native(state, project, database) {
            Err(response) => response,
            Ok(()) => match action {
                "exportDocuments" => super::managed::export(state, project, database, &req.body),
                "importDocuments" => super::managed::import(state, project, database, &req.body),
                _ => super::managed::bulk_delete(state, project, database, &req.body),
            },
        },
        (_, [_, "databases", database, "changeStreams" | "userCreds", ..], None) => {
            enterprise_only(state, project, database)
        }
        (method, [_, "databases", database, "operations", rest @ ..], action) => {
            operations::route(state, project, database, method, rest, action, &params)
        }
        _ => crate::rest::not_found_text(),
    })
}

/// The databases of `project` that exist without an Admin create: `(default)`, the declared
/// ones, and any the data plane materialized (an import, the emulator profile's first touch).
fn unprompted_databases(state: &RestState, project: &str) -> Vec<String> {
    let mut databases = vec![fireemu_core_types::ids::DatabaseId::DEFAULT.to_owned()];
    databases.extend(state.local.declared_databases());
    if let Ok(catalog) = state.local.database_catalog() {
        databases.extend(
            catalog
                .into_iter()
                .filter(|((p, _), _)| p == project)
                .map(|((_, d), _)| d),
        );
    }
    databases
}

fn exists_unprompted(state: &RestState, project: &str, database: &str) -> bool {
    unprompted_databases(state, project)
        .iter()
        .any(|d| d == database)
}

fn list_databases(
    state: &RestState,
    project: &str,
    params: &BTreeMap<String, Vec<String>>,
) -> RestResponse {
    match params.get("showDeleted").map(Vec::as_slice) {
        None => {}
        Some([value]) if value == "true" || value == "false" => {}
        Some(_) => {
            return crate::rest::error_response(&Status::invalid_argument(
                "showDeleted must be true or false",
            ))
        }
    }
    if params.contains_key("pageSize") || params.contains_key("pageToken") {
        return crate::rest::error_response(&Status::invalid_argument(
            "pageSize and pageToken are not supported",
        ));
    }
    let now = state.local.admin_now();
    let unprompted = unprompted_databases(state, project);
    let admin = state.local.admin();
    let mut databases: Vec<Value> = admin
        .list(project, &unprompted)
        .iter()
        .map(|record| database_json(record, now, None))
        .collect();
    if param(params, "showDeleted") == Some("true") {
        databases.extend(admin.deleted(project).iter().map(
            |DeletedDatabase {
                 record,
                 delete_time,
             }| { database_json(record, now, Some(*delete_time)) },
        ));
    }
    ok(json!({ "databases": databases }))
}

fn get_database(state: &RestState, project: &str, database: &str) -> RestResponse {
    let admin = state.local.admin();
    match admin.get(
        project,
        database,
        exists_unprompted(state, project, database),
    ) {
        Some(record) => ok(database_json(&record, state.local.admin_now(), None)),
        None if admin
            .deleted(project)
            .iter()
            .any(|d| d.record.database == database) =>
        {
            error(
                tonic::Code::NotFound,
                "Requested database was not found.",
                None,
            )
        }
        None => missing_database(project, database),
    }
}

/// Production's refusal of a customer-managed key (the sandbox project may create none) and
/// of resource tags (none exists locally), which no local database can satisfy (C3).
fn managed_binding_refusal(body: &Value) -> Option<RestResponse> {
    if body.get("cmekConfig").is_some_and(|c| !c.is_null()) {
        let message = "You have reached the maximum number of CMEK (Customer-managed encryption keys) databases per project or per organization. Please delete an unused CMEK database and try again. Or you haven't requested CMEK database creation allowlist for this project. Please request access by filling out the form at https://forms.gle/D3cB7xY6A44aVusY9";
        return Some(error(
            tonic::Code::ResourceExhausted,
            message,
            Some(json!([{
                "@type": "type.googleapis.com/google.rpc.QuotaFailure",
                "violations": [{"description": message}]
            }])),
        ));
    }
    if body
        .get("tags")
        .and_then(Value::as_object)
        .is_some_and(|t| !t.is_empty())
    {
        return Some(error(
            tonic::Code::InvalidArgument,
            "INVALID_ARGUMENT: field [tags.tagKey] has issue [Invalid tag key specified. Please specify a valid tag key in the format <tag namespace>/<tag key name> where the tag namespace is the ID of the organization or name of the project that the tag key is defined in or tagKeys/<tag_key_id>. For example: \"123/environment\", or \"my-project/env\", or \"tagKeys/123\".]\nfield [tags.tagValue] has issue [Invalid tag value specified. Please specify a valid tag value. This must be the name of the value created under the specified tag key. For example: \"production\", or \"tagValues/456\".]",
            None,
        ));
    }
    None
}

/// Validates a `databases.create` request the way production does, in production's order.
fn parse_create(
    project: &str,
    params: &BTreeMap<String, Vec<String>>,
    body: &Value,
) -> Result<CreateRequest, RestResponse> {
    let database = param(params, "databaseId").unwrap_or("");
    if !valid_database_id(database) {
        return Err(error(
            tonic::Code::InvalidArgument,
            "database_id should be 4-63 characters, and valid characters are /[a-z][0-9]-/",
            None,
        ));
    }
    let database_type = match parse_enum(
        body,
        "type",
        "database.type",
        "Database.DatabaseType",
        TYPES,
    ) {
        Ok(v) => v.flatten(),
        Err(response) => return Err(response),
    };
    let edition = match parse_enum(
        body,
        "databaseEdition",
        "database.database_edition",
        "Database.DatabaseEdition",
        EDITIONS,
    ) {
        Ok(v) => v.flatten(),
        Err(response) => return Err(response),
    };
    let concurrency = match parse_enum(
        body,
        "concurrencyMode",
        "database.concurrency_mode",
        "Database.ConcurrencyMode",
        CONCURRENCY,
    ) {
        Ok(v) => v.flatten(),
        Err(response) => return Err(response),
    };
    let protection = match parse_enum(
        body,
        "deleteProtectionState",
        "database.delete_protection_state",
        "Database.DeleteProtectionState",
        PROTECTION,
    ) {
        Ok(v) => v.flatten(),
        Err(response) => return Err(response),
    };
    let Some(location) = body
        .get("locationId")
        .and_then(Value::as_str)
        .filter(|l| !l.is_empty())
    else {
        return Err(error(
            tonic::Code::InvalidArgument,
            "location_id must be specified when creating a database.",
            None,
        ));
    };
    let Some(database_type) = database_type else {
        return Err(error(
            tonic::Code::InvalidArgument,
            "database type must be set.",
            None,
        ));
    };
    if !locations::exists(location) {
        return Err(error(
            tonic::Code::PermissionDenied,
            &format!("Permission denied on 'locations/{location}' (or it may not exist)."),
            None,
        ));
    }
    if let Some(refusal) = managed_binding_refusal(body) {
        return Err(refusal);
    }
    Ok(CreateRequest {
        project: project.to_owned(),
        database: database.to_owned(),
        location_id: location.to_owned(),
        database_type,
        edition: edition.unwrap_or(DatabaseEdition::Standard),
        concurrency,
        delete_protection: protection.unwrap_or(false),
    })
}

fn create_database(
    state: &RestState,
    project: &str,
    params: &BTreeMap<String, Vec<String>>,
    body: &Value,
) -> RestResponse {
    let request = match parse_create(project, params, body) {
        Ok(request) => request,
        Err(response) => return response,
    };
    let database = request.database.clone();
    let database = database.as_str();
    let now = state.local.admin_now();
    match state
        .local
        .admin()
        .create(request, exists_unprompted(state, project, database), now)
    {
        Ok(record) => {
            if record.database_type == DatabaseType::FirestoreNative
                && record.edition == DatabaseEdition::Standard
            {
                if let Ok(parent) = crate::decode::parse_parent(&format!(
                    "projects/{project}/databases/{database}/documents"
                )) {
                    let _ = state.local.ensure_database(&parent);
                }
            }
            let resource = database_json(&record, now, None);
            let operation = operations::record(
                state,
                project,
                database,
                OperationKind::CreateDatabase,
                &json!({"@type": "type.googleapis.com/google.firestore.admin.v1.CreateDatabaseMetadata"}),
                Some(with_type(DATABASE_TYPE_URL, resource)),
            );
            ok(operation.initial)
        }
        Err(refusal) => refusal_response(&refusal, project, database),
    }
}

fn with_type(type_url: &str, value: Value) -> Value {
    let mut out = Map::new();
    out.insert("@type".into(), json!(type_url));
    if let Value::Object(fields) = value {
        out.extend(fields);
    }
    Value::Object(out)
}

fn patch_database(
    state: &RestState,
    project: &str,
    database: &str,
    params: &BTreeMap<String, Vec<String>>,
    body: &Value,
) -> RestResponse {
    let mask: Vec<String> = param(params, "updateMask")
        .map(|m| {
            m.split(',')
                .map(str::trim)
                .filter(|p| !p.is_empty())
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    for path in &mask {
        match path.as_str() {
            "deleteProtectionState"
            | "delete_protection_state"
            | "concurrencyMode"
            | "concurrency_mode" => {}
            "pointInTimeRecoveryEnablement" | "point_in_time_recovery_enablement" => {
                return crate::rest::error_response(&Status::unimplemented(MANAGED_INFRASTRUCTURE))
            }
            "locationId" | "location_id" => {
                return error(
                    tonic::Code::InvalidArgument,
                    "Changing database location is not supported.",
                    None,
                )
            }
            other => {
                return error(
                    tonic::Code::InvalidArgument,
                    &format!("Updating field '{other}' is not supported."),
                    None,
                )
            }
        }
    }
    let concurrency = match parse_enum(
        body,
        "concurrencyMode",
        "database.concurrency_mode",
        "Database.ConcurrencyMode",
        CONCURRENCY,
    ) {
        Ok(v) => v.flatten(),
        Err(response) => return response,
    };
    let protection = match parse_enum(
        body,
        "deleteProtectionState",
        "database.delete_protection_state",
        "Database.DeleteProtectionState",
        PROTECTION,
    ) {
        Ok(v) => v.flatten(),
        Err(response) => return response,
    };
    let masked =
        |names: [&str; 2]| mask.is_empty() || mask.iter().any(|p| names.contains(&p.as_str()));
    let now = state.local.admin_now();
    let result = state.local.admin().update(
        project,
        database,
        exists_unprompted(state, project, database),
        now,
        |record| {
            if masked(["concurrencyMode", "concurrency_mode"]) {
                if let Some(mode) = concurrency {
                    record.concurrency = mode;
                }
            }
            if masked(["deleteProtectionState", "delete_protection_state"]) {
                if let Some(protected) = protection {
                    record.delete_protection = protected;
                }
            }
        },
    );
    match result {
        Ok(record) => {
            let operation = operations::record(
                state,
                project,
                database,
                OperationKind::UpdateDatabase,
                &json!({"@type": "type.googleapis.com/google.firestore.admin.v1.UpdateDatabaseMetadata"}),
                Some(with_type(
                    DATABASE_TYPE_URL,
                    database_json(&record, now, None),
                )),
            );
            ok(operation.initial)
        }
        Err(refusal) => refusal_response(&refusal, project, database),
    }
}

fn delete_database(
    state: &RestState,
    project: &str,
    database: &str,
    params: &BTreeMap<String, Vec<String>>,
) -> RestResponse {
    let admin = state.local.admin();
    let unprompted = exists_unprompted(state, project, database);
    if let Some(etag) = param(params, "etag") {
        // Production answers INTERNAL for an etag it cannot parse and ABORTED for a stale one.
        let parses = base64_ok(etag);
        if !parses {
            return error(tonic::Code::Internal, "Internal error encountered.", None);
        }
        if admin.get(project, database, unprompted).is_some() {
            return error(
                tonic::Code::Aborted,
                "The database etag does not match the current etag.",
                None,
            );
        }
    }
    let now = state.local.admin_now();
    match admin.delete(project, database, unprompted, now) {
        Ok(tombstone) => {
            state.local.delete_database(project, database);
            admin.indexes().forget(|p, d| p == project && d == database);
            admin.fields().forget(|p, d| p == project && d == database);
            let resource = database_json(&tombstone.record, now, Some(tombstone.delete_time));
            let operation = operations::record(
                state,
                project,
                database,
                OperationKind::DeleteDatabase,
                &json!({"@type": "type.googleapis.com/google.firestore.admin.v1.DeleteDatabaseMetadata"}),
                Some(with_type(DATABASE_TYPE_URL, resource)),
            );
            ok(operation.initial)
        }
        Err(refusal) => refusal_response(&refusal, project, database),
    }
}

fn base64_ok(text: &str) -> bool {
    !text.is_empty()
        && text.len() % 4 == 0
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=' | '-' | '_'))
}

/// Whether a database exists for the Admin surfaces below it (fields, indexes).
pub(crate) fn database_exists(state: &RestState, project: &str, database: &str) -> bool {
    state
        .local
        .admin()
        .get(
            project,
            database,
            exists_unprompted(state, project, database),
        )
        .is_some()
}

/// Whether the Admin surface of a database's indexes, fields and documents is served: it must
/// exist and be a Standard Native database.
fn live_native(state: &RestState, project: &str, database: &str) -> Result<(), RestResponse> {
    match state.local.admin().get(
        project,
        database,
        exists_unprompted(state, project, database),
    ) {
        None => Err(missing_database(project, database)),
        Some(_) => Ok(()),
    }
}

fn enterprise_only(state: &RestState, project: &str, database: &str) -> RestResponse {
    if state
        .local
        .admin()
        .get(
            project,
            database,
            exists_unprompted(state, project, database),
        )
        .is_none()
    {
        return missing_database(project, database);
    }
    error(
        tonic::Code::FailedPrecondition,
        "This operation requires an Enterprise database.",
        None,
    )
}
