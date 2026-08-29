//! Cloud Storage for Firebase over HTTP (Milestone D shell): the Firebase Storage protocol
//! used by the web / mobile SDKs (`/v0/b/{bucket}/o...`, `X-Goog-Upload-*` resumable
//! uploads, download tokens) and the JSON API used by the Admin SDK / `@google-cloud/storage`
//! (`/storage/v1/...`, `/upload/storage/v1/...`, `/download/storage/v1/...`,
//! `Content-Range` resumable uploads). Both surfaces share one [`StorageState`] and the
//! Storage Security Rules (`service firebase.storage`).
//!
//! Object names are percent-decoded exactly once from the URL segment and never
//! interpreted as paths. The JSON API dialect is a privileged (admin) surface, as in the
//! official Emulator; only loopback origins reach either surface.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, RwLock};

use ftd_core_auth::jwt::{decode_unsigned, verify_id_token};
use ftd_core_auth::store::AuthStore;
use ftd_core_rules::eval::{
    evaluate_request, Decision, DenyReason, Method, RequestContext, RulesService,
};
use ftd_core_rules::runtime::LoadedRules;
use ftd_core_rules::value::{AuthContext, RulesValue};
use ftd_core_session::clock::VirtualClock;
use ftd_core_storage::name::{BucketName, ObjectName};
use ftd_core_storage::store::{
    MetadataPatch, NewMetadata, ObjectMetadata, Precondition, StorageError,
    StorageState as ObjectStore, UploadId,
};
use ftd_core_types::determinism::Clock;
use ftd_core_types::time::LogicalInstant;
use serde_json::{json, Map, Value};

/// Shared Storage state behind the HTTP surface.
pub struct StorageState {
    /// Object store.
    pub store: Mutex<ObjectStore>,
    /// Virtual clock.
    pub clock: Arc<Mutex<VirtualClock>>,
    /// Users (ID token verification).
    pub auth: Arc<Mutex<AuthStore>>,
    /// Storage Security Rules (`service firebase.storage`).
    pub rules: Arc<RwLock<LoadedRules>>,
    /// Project (default buckets `{project}.appspot.com` / `{project}.firebasestorage.app`).
    pub project: String,
}

/// One HTTP request of the Storage surface.
#[derive(Debug, Clone, Default)]
pub struct StorageRequest {
    /// Method.
    pub method: String,
    /// Raw path (not decoded).
    pub path: String,
    /// Raw query string.
    pub query: String,
    /// `Host` header (upload session URLs are absolute).
    pub host: Option<String>,
    /// Selected request headers (lowercase names).
    pub headers: BTreeMap<String, String>,
    /// Body.
    pub body: Vec<u8>,
}

impl StorageRequest {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).map(String::as_str)
    }
}

/// One HTTP response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageResponse {
    /// Status.
    pub status: u16,
    /// Headers.
    pub headers: Vec<(String, String)>,
    /// Body.
    pub body: Vec<u8>,
}

impl StorageResponse {
    fn json(status: u16, body: &Value) -> Self {
        Self {
            status,
            headers: vec![(
                "content-type".into(),
                "application/json; charset=utf-8".into(),
            )],
            body: serde_json::to_vec(body).unwrap_or_default(),
        }
    }

    fn empty(status: u16) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    fn with_header(mut self, name: &str, value: impl Into<String>) -> Self {
        self.headers.push((name.to_owned(), value.into()));
        self
    }
}

/// Which protocol dialect a request uses (error and metadata shapes differ).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Dialect {
    Firebase,
    Gcs,
}

fn error_response(dialect: Dialect, status: u16, message: &str) -> StorageResponse {
    let status_name = match status {
        400 => "INVALID_ARGUMENT",
        401 => "UNAUTHENTICATED",
        403 => "PERMISSION_DENIED",
        404 => "NOT_FOUND",
        412 => "FAILED_PRECONDITION",
        413 => "OUT_OF_RANGE",
        _ => "INTERNAL",
    };
    let body = match dialect {
        Dialect::Firebase => {
            json!({"error": {"code": status, "message": message, "status": status_name}})
        }
        Dialect::Gcs => {
            json!({"error": {"code": status, "message": message, "errors": [{"domain": "global", "reason": status_name.to_ascii_lowercase(), "message": message}]}})
        }
    };
    StorageResponse::json(status, &body)
}

fn storage_error(dialect: Dialect, e: &StorageError) -> StorageResponse {
    match e {
        StorageError::NotFound => error_response(dialect, 404, "Not Found. Could not get object"),
        StorageError::PreconditionFailed(m) => error_response(dialect, 412, m),
        StorageError::TooLarge => error_response(dialect, 413, "object too large"),
        StorageError::MetadataTooLarge => error_response(dialect, 400, "custom metadata too large"),
        StorageError::UploadNotFound => error_response(dialect, 404, "upload session not found"),
        StorageError::UploadOffset { expected } => error_response(
            dialect,
            400,
            &format!("upload offset mismatch, expected {expected}"),
        ),
        StorageError::UploadFinalized => error_response(dialect, 400, "upload already finalized"),
        StorageError::UploadSizeMismatch => error_response(dialect, 400, "upload size mismatch"),
    }
}

// ------------------------------------------------------------------------------------------
// decoding helpers
// ------------------------------------------------------------------------------------------

/// Percent-decodes one URL segment exactly once (invalid UTF-8 is an error).
fn decode_segment(s: &str) -> Result<String, String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = s
                .get(i + 1..i + 3)
                .and_then(|h| u8::from_str_radix(h, 16).ok())
                .ok_or_else(|| "malformed percent escape".to_owned())?;
            out.push(hex);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| "path is not UTF-8".to_owned())
}

fn form_decode(s: &str) -> String {
    let with_spaces = s.replace('+', " ");
    decode_segment(&with_spaces).unwrap_or(with_spaces)
}

fn query_params(query: &str) -> BTreeMap<String, String> {
    query
        .split('&')
        .filter(|kv| !kv.is_empty())
        .map(|kv| {
            let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
            (form_decode(k), form_decode(v))
        })
        .collect()
}

fn encode_segment(s: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
            out.push(b as char);
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

fn rfc3339(t: LogicalInstant) -> String {
    t.to_rfc3339()
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned())
}

/// multipart/related: returns (metadata JSON part, data content type, data bytes).
fn parse_multipart(
    content_type: &str,
    body: &[u8],
) -> Result<(Value, Option<String>, Vec<u8>), String> {
    let boundary = content_type
        .split(';')
        .map(str::trim)
        .find_map(|p| p.strip_prefix("boundary="))
        .map(|b| b.trim_matches('"').to_owned())
        .ok_or_else(|| "multipart/related without boundary".to_owned())?;
    let delimiter = format!("--{boundary}").into_bytes();
    let mut parts: Vec<(BTreeMap<String, String>, Vec<u8>)> = Vec::new();
    let mut cursor = 0;
    while let Some(pos) = find(&body[cursor..], &delimiter) {
        let start = cursor + pos + delimiter.len();
        if body.get(start..start + 2) == Some(b"--") {
            break;
        }
        // Skip the line break after the delimiter.
        let mut p = start;
        while body.get(p).is_some_and(|c| *c == b'\r' || *c == b'\n') {
            p += 1;
        }
        let Some(next) = find(&body[p..], &delimiter) else {
            return Err("unterminated multipart part".into());
        };
        let mut part = &body[p..p + next];
        // Strip the line break before the next delimiter.
        while part.last().is_some_and(|c| *c == b'\r' || *c == b'\n') {
            part = &part[..part.len() - 1];
        }
        let (headers, content) = split_headers(part);
        parts.push((headers, content.to_vec()));
        cursor = p + next;
    }
    if parts.is_empty() {
        return Err("multipart body has no parts".into());
    }
    let metadata: Value = if parts.len() >= 2 {
        serde_json::from_slice(&parts[0].1).map_err(|e| format!("metadata part: {e}"))?
    } else {
        Value::Object(Map::new())
    };
    let data = parts.last().map(|(_, c)| c.clone()).unwrap_or_default();
    let ct = parts
        .last()
        .and_then(|(h, _)| h.get("content-type").cloned())
        .filter(|_| parts.len() >= 2);
    Ok((metadata, ct, data))
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn split_headers(part: &[u8]) -> (BTreeMap<String, String>, &[u8]) {
    let sep = find(part, b"\r\n\r\n")
        .map(|i| (i, 4))
        .or_else(|| find(part, b"\n\n").map(|i| (i, 2)));
    match sep {
        Some((i, n)) => {
            let text = String::from_utf8_lossy(&part[..i]);
            let headers = text
                .lines()
                .filter_map(|l| l.split_once(':'))
                .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_owned()))
                .collect();
            (headers, &part[i + n..])
        }
        None => (BTreeMap::new(), part),
    }
}

fn new_metadata_from_json(v: &Value, content_type: Option<String>) -> NewMetadata {
    let s = |k: &str| v.get(k).and_then(Value::as_str).map(str::to_owned);
    let custom = v
        .get("metadata")
        .or_else(|| v.get("customMetadata"))
        .and_then(Value::as_object)
        .map(|m| {
            m.iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_owned())))
                .collect()
        })
        .unwrap_or_default();
    NewMetadata {
        content_type: s("contentType").or(content_type),
        content_disposition: s("contentDisposition"),
        content_encoding: s("contentEncoding"),
        content_language: s("contentLanguage"),
        cache_control: s("cacheControl"),
        custom,
    }
}

fn patch_from_json(v: &Value) -> MetadataPatch {
    let field = |k: &str| -> Option<Option<String>> {
        match v.get(k) {
            None => None,
            Some(Value::Null) => Some(None),
            Some(x) => Some(x.as_str().map(str::to_owned)),
        }
    };
    let custom = v
        .get("metadata")
        .or_else(|| v.get("customMetadata"))
        .map(|m| match m {
            Value::Object(o) => o
                .iter()
                .map(|(k, v)| (k.clone(), v.as_str().map(str::to_owned)))
                .collect(),
            _ => BTreeMap::new(),
        });
    MetadataPatch {
        content_type: field("contentType"),
        content_disposition: field("contentDisposition"),
        content_encoding: field("contentEncoding"),
        content_language: field("contentLanguage"),
        cache_control: field("cacheControl"),
        custom,
    }
}

// ------------------------------------------------------------------------------------------
// metadata JSON
// ------------------------------------------------------------------------------------------

fn firebase_json(m: &ObjectMetadata) -> Value {
    let mut v = json!({
        "name": m.name.as_str(),
        "bucket": m.bucket.as_str(),
        "generation": m.generation.to_string(),
        "metageneration": m.metageneration.to_string(),
        "contentType": m.content_type,
        "timeCreated": rfc3339(m.time_created),
        "updated": rfc3339(m.updated),
        "storageClass": "STANDARD",
        "size": m.size.to_string(),
        "md5Hash": m.md5_base64(),
        "crc32c": m.crc32c_base64(),
        "etag": m.etag(),
        "downloadTokens": m.download_tokens.join(","),
        "metadata": m.custom,
    });
    for (k, val) in [
        ("cacheControl", &m.cache_control),
        ("contentDisposition", &m.content_disposition),
        ("contentEncoding", &m.content_encoding),
        ("contentLanguage", &m.content_language),
    ] {
        if let Some(x) = val {
            v[k] = Value::String(x.clone());
        }
    }
    v
}

fn gcs_json(m: &ObjectMetadata, host: &str) -> Value {
    let encoded = encode_segment(m.name.as_str());
    let mut v = json!({
        "kind": "storage#object",
        "id": format!("{}/{}/{}", m.bucket.as_str(), m.name.as_str(), m.generation),
        "selfLink": format!("http://{host}/storage/v1/b/{}/o/{encoded}", m.bucket.as_str()),
        "mediaLink": format!("http://{host}/download/storage/v1/b/{}/o/{encoded}?generation={}&alt=media", m.bucket.as_str(), m.generation),
        "name": m.name.as_str(),
        "bucket": m.bucket.as_str(),
        "generation": m.generation.to_string(),
        "metageneration": m.metageneration.to_string(),
        "contentType": m.content_type,
        "storageClass": "STANDARD",
        "size": m.size.to_string(),
        "md5Hash": m.md5_base64(),
        "crc32c": m.crc32c_base64(),
        "etag": m.etag(),
        "timeCreated": rfc3339(m.time_created),
        "updated": rfc3339(m.updated),
        "timeStorageClassUpdated": rfc3339(m.time_created),
        "metadata": m.custom,
    });
    for (k, val) in [
        ("cacheControl", &m.cache_control),
        ("contentDisposition", &m.content_disposition),
        ("contentEncoding", &m.content_encoding),
        ("contentLanguage", &m.content_language),
    ] {
        if let Some(x) = val {
            v[k] = Value::String(x.clone());
        }
    }
    v
}

fn metadata_json(dialect: Dialect, m: &ObjectMetadata, host: &str) -> Value {
    match dialect {
        Dialect::Firebase => firebase_json(m),
        Dialect::Gcs => gcs_json(m, host),
    }
}

// ------------------------------------------------------------------------------------------
// rules
// ------------------------------------------------------------------------------------------

/// Caller of a Storage request.
#[derive(Debug, Clone, PartialEq)]
enum Principal {
    Owner,
    User(AuthContext),
    Anonymous,
}

fn storage_rules_value(m: &ObjectMetadata) -> RulesValue {
    let mut map = BTreeMap::new();
    let s = |v: &str| RulesValue::String(v.to_owned());
    map.insert("name".into(), s(m.name.as_str()));
    map.insert("bucket".into(), s(m.bucket.as_str()));
    map.insert(
        "generation".into(),
        RulesValue::Int(i64::try_from(m.generation).unwrap_or(i64::MAX)),
    );
    map.insert(
        "metageneration".into(),
        RulesValue::Int(i64::try_from(m.metageneration).unwrap_or(i64::MAX)),
    );
    map.insert(
        "size".into(),
        RulesValue::Int(i64::try_from(m.size).unwrap_or(i64::MAX)),
    );
    map.insert(
        "timeCreated".into(),
        RulesValue::Timestamp(m.time_created.as_nanos()),
    );
    map.insert(
        "updated".into(),
        RulesValue::Timestamp(m.updated.as_nanos()),
    );
    map.insert("md5Hash".into(), s(&m.md5_base64()));
    map.insert("crc32c".into(), s(&m.crc32c_base64()));
    map.insert("etag".into(), s(&m.etag()));
    map.insert("contentType".into(), s(&m.content_type));
    for (k, val) in [
        ("cacheControl", &m.cache_control),
        ("contentDisposition", &m.content_disposition),
        ("contentEncoding", &m.content_encoding),
        ("contentLanguage", &m.content_language),
    ] {
        map.insert(k.into(), val.as_deref().map_or(RulesValue::Null, s));
    }
    map.insert(
        "metadata".into(),
        RulesValue::Map(m.custom.iter().map(|(k, v)| (k.clone(), s(v))).collect()),
    );
    RulesValue::Map(map)
}

/// The `request.resource` of an upload (declared metadata, declared size).
fn incoming_rules_value(
    bucket: &BucketName,
    name: &ObjectName,
    meta: &NewMetadata,
    size: u64,
    now: LogicalInstant,
) -> RulesValue {
    let mut map = BTreeMap::new();
    let s = |v: &str| RulesValue::String(v.to_owned());
    map.insert("name".into(), s(name.as_str()));
    map.insert("bucket".into(), s(bucket.as_str()));
    map.insert(
        "size".into(),
        RulesValue::Int(i64::try_from(size).unwrap_or(i64::MAX)),
    );
    map.insert("timeCreated".into(), RulesValue::Timestamp(now.as_nanos()));
    map.insert("updated".into(), RulesValue::Timestamp(now.as_nanos()));
    map.insert(
        "contentType".into(),
        s(meta
            .content_type
            .as_deref()
            .unwrap_or("application/octet-stream")),
    );
    for (k, val) in [
        ("cacheControl", &meta.cache_control),
        ("contentDisposition", &meta.content_disposition),
        ("contentEncoding", &meta.content_encoding),
        ("contentLanguage", &meta.content_language),
    ] {
        map.insert(k.into(), val.as_deref().map_or(RulesValue::Null, s));
    }
    map.insert(
        "metadata".into(),
        RulesValue::Map(meta.custom.iter().map(|(k, v)| (k.clone(), s(v))).collect()),
    );
    RulesValue::Map(map)
}

impl StorageState {
    fn now(&self) -> LogicalInstant {
        self.clock
            .lock()
            .map(|c| c.now())
            .unwrap_or(LogicalInstant::UNIX_EPOCH)
    }

    fn principal(&self, authorization: Option<&str>) -> Result<Principal, String> {
        let Some(value) = authorization else {
            return Ok(Principal::Anonymous);
        };
        let token = value
            .strip_prefix("Bearer ")
            .or_else(|| value.strip_prefix("Firebase "))
            .ok_or_else(|| {
                "authorization must be 'Bearer <token>' or 'Firebase <token>'".to_owned()
            })?;
        if token == "owner" {
            return Ok(Principal::Owner);
        }
        let store = self
            .auth
            .lock()
            .map_err(|_| "auth store poisoned".to_owned())?;
        verify_id_token(token, &store, self.now()).map_err(|e| format!("invalid ID token: {e}"))?;
        drop(store);
        let decoded = decode_unsigned(token).map_err(|e| format!("invalid ID token: {e}"))?;
        let ctx = AuthContext::from_id_token_json(&decoded.payload_json)
            .map_err(|e| format!("invalid ID token claims: {e}"))?;
        Ok(Principal::User(ctx))
    }

    /// Evaluates the Storage rules; `Ok(())` = allowed.
    fn authorize(
        &self,
        principal: &Principal,
        method: Method,
        bucket: &BucketName,
        object_path: &str,
        resource: Option<RulesValue>,
        request_resource: Option<RulesValue>,
    ) -> Result<(), String> {
        if matches!(principal, Principal::Owner) {
            return Ok(());
        }
        let rules = self.rules.read().map_err(|_| "rules poisoned".to_owned())?;
        let Some(ruleset) = &rules.ruleset else {
            return Ok(());
        };
        let path = if object_path.is_empty() {
            format!("/b/{}/o", bucket.as_str())
        } else {
            format!("/b/{}/o/{object_path}", bucket.as_str())
        };
        let ctx = RequestContext {
            service: RulesService::Storage,
            method,
            path,
            auth: match principal {
                Principal::User(a) => Some(a.clone()),
                _ => None,
            },
            resource,
            request_resource,
            time_unix_nanos: self.now().as_nanos(),
            abstract_path: false,
        };
        match evaluate_request(ruleset, &ctx).decision {
            Decision::Allow => Ok(()),
            Decision::Deny(reason) => Err(format!(
                "{} on {} denied by Storage Rules: {}",
                method_name(method),
                ctx.path,
                match reason {
                    DenyReason::NoMatchingRule => "no match block covers this path".to_owned(),
                    DenyReason::NoMatchingAllow =>
                        "no allow statement evaluated to true".to_owned(),
                    DenyReason::Unsupported(m) => format!("unsupported rules feature: {m}"),
                    DenyReason::BudgetExceeded {
                        limit_id,
                        current,
                        maximum,
                    } => format!("{limit_id}: {current} exceeds {maximum}"),
                }
            )),
        }
    }
}

const fn method_name(m: Method) -> &'static str {
    match m {
        Method::Get => "get",
        Method::List => "list",
        Method::Create => "create",
        Method::Update => "update",
        Method::Delete => "delete",
    }
}

// ------------------------------------------------------------------------------------------
// routing
// ------------------------------------------------------------------------------------------

/// Parsed target of a request.
enum Route {
    /// `/o` of a bucket (list, upload start).
    Bucket { dialect: Dialect, bucket: String },
    /// One object.
    Object {
        dialect: Dialect,
        bucket: String,
        name: String,
    },
    /// `/storage/v1/b/{bucket}` (bucket metadata).
    BucketMeta { bucket: String },
    /// `/storage/v1/b/{b}/o/{n}/rewriteTo/b/{db}/o/{dn}` and `copyTo`.
    Rewrite {
        bucket: String,
        name: String,
        dst_bucket: String,
        dst_name: String,
    },
    /// `/upload/storage/v1/b/{bucket}/o` (JSON API uploads).
    GcsUpload { bucket: String },
}

fn route(path: &str) -> Result<Route, String> {
    let segments: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    match segments.as_slice() {
        ["v0", "b", bucket, "o"] => Ok(Route::Bucket {
            dialect: Dialect::Firebase,
            bucket: decode_segment(bucket)?,
        }),
        ["v0", "b", bucket, "o", name] => Ok(Route::Object {
            dialect: Dialect::Firebase,
            bucket: decode_segment(bucket)?,
            name: decode_segment(name)?,
        }),
        // The Node client library against an emulator host omits the `/storage/v1` prefix.
        ["storage", "v1", "b", bucket] | ["b", bucket] => Ok(Route::BucketMeta {
            bucket: decode_segment(bucket)?,
        }),
        ["storage", "v1", "b", bucket, "o"] | ["b", bucket, "o"] => Ok(Route::Bucket {
            dialect: Dialect::Gcs,
            bucket: decode_segment(bucket)?,
        }),
        ["storage", "v1", "b", bucket, "o", name]
        | ["b", bucket, "o", name]
        | ["download", "storage", "v1", "b", bucket, "o", name] => Ok(Route::Object {
            dialect: Dialect::Gcs,
            bucket: decode_segment(bucket)?,
            name: decode_segment(name)?,
        }),
        ["storage", "v1", "b", bucket, "o", name, verb, "b", dst_bucket, "o", dst_name]
        | ["b", bucket, "o", name, verb, "b", dst_bucket, "o", dst_name]
            if *verb == "rewriteTo" || *verb == "copyTo" =>
        {
            Ok(Route::Rewrite {
                bucket: decode_segment(bucket)?,
                name: decode_segment(name)?,
                dst_bucket: decode_segment(dst_bucket)?,
                dst_name: decode_segment(dst_name)?,
            })
        }
        ["upload", "storage", "v1", "b", bucket, "o"] => Ok(Route::GcsUpload {
            bucket: decode_segment(bucket)?,
        }),
        _ => Err(format!("unknown path {path}")),
    }
}

fn precondition(params: &BTreeMap<String, String>) -> Precondition {
    Precondition {
        if_generation_match: params.get("ifGenerationMatch").and_then(|v| v.parse().ok()),
        if_metageneration_match: params
            .get("ifMetagenerationMatch")
            .and_then(|v| v.parse().ok()),
    }
}

/// Handles one request.
#[must_use]
pub fn handle(state: &StorageState, req: &StorageRequest) -> StorageResponse {
    let params = query_params(&req.query);
    let host = req.host.clone().unwrap_or_else(|| "127.0.0.1".to_owned());
    let route = match route(&req.path) {
        Ok(r) => r,
        Err(e) => return error_response(Dialect::Firebase, 404, &e),
    };
    let dialect = match &route {
        Route::Bucket { dialect, .. } | Route::Object { dialect, .. } => *dialect,
        _ => Dialect::Gcs,
    };
    // The JSON API surface is what the Admin SDK / gcloud use: like the official Emulator
    // it is a privileged surface (rules bypassed) unless the caller presents an end-user
    // `Firebase <token>`; the Firebase protocol always goes through the rules.
    let authorization = req.header("authorization");
    let principal = match (dialect, authorization) {
        (Dialect::Gcs, None) => Principal::Owner,
        (Dialect::Gcs, Some(a)) if a.starts_with("Bearer ") => Principal::Owner,
        _ => match state.principal(authorization) {
            Ok(p) => p,
            Err(e) => return error_response(dialect, 401, &e),
        },
    };
    let outcome = match route {
        Route::BucketMeta { bucket } => bucket_meta(&bucket, &host),
        Route::Bucket { dialect, bucket } => match req.method.as_str() {
            "GET" => list(state, &principal, dialect, &bucket, &params, &host),
            "POST" => upload(state, &principal, dialect, &bucket, req, &params, &host),
            _ => Err((405, "method not allowed".to_owned())),
        },
        Route::GcsUpload { bucket } => match req.method.as_str() {
            "POST" | "PUT" => upload(
                state,
                &principal,
                Dialect::Gcs,
                &bucket,
                req,
                &params,
                &host,
            ),
            _ => Err((405, "method not allowed".to_owned())),
        },
        Route::Object {
            dialect,
            bucket,
            name,
        } => object(
            state, &principal, dialect, &bucket, &name, req, &params, &host,
        ),
        Route::Rewrite {
            bucket,
            name,
            dst_bucket,
            dst_name,
        } => rewrite(
            state,
            &principal,
            &bucket,
            &name,
            &dst_bucket,
            &dst_name,
            req,
            &params,
            &host,
        ),
    };
    match outcome {
        Ok(r) => r,
        Err((status, message)) => error_response(dialect, status, &message),
    }
}

type Outcome = Result<StorageResponse, (u16, String)>;

fn bucket_name(bucket: &str) -> Result<BucketName, (u16, String)> {
    BucketName::try_new(bucket).map_err(|e| (400, format!("invalid bucket name: {e}")))
}

fn object_name(name: &str) -> Result<ObjectName, (u16, String)> {
    ObjectName::try_new(name).map_err(|e| (400, format!("invalid object name: {e}")))
}

fn bucket_meta(bucket: &str, host: &str) -> Outcome {
    let b = bucket_name(bucket)?;
    Ok(StorageResponse::json(
        200,
        &json!({
            "kind": "storage#bucket",
            "id": b.as_str(),
            "name": b.as_str(),
            "selfLink": format!("http://{host}/storage/v1/b/{}", b.as_str()),
            "location": "US",
            "storageClass": "STANDARD",
            "timeCreated": "2026-01-01T00:00:00Z",
            "updated": "2026-01-01T00:00:00Z",
            "metageneration": "1",
            "projectNumber": "0",
        }),
    ))
}

fn deny(e: String) -> (u16, String) {
    (403, e)
}

fn list(
    state: &StorageState,
    principal: &Principal,
    dialect: Dialect,
    bucket: &str,
    params: &BTreeMap<String, String>,
    host: &str,
) -> Outcome {
    let b = bucket_name(bucket)?;
    let prefix = params.get("prefix").cloned().unwrap_or_default();
    let delimiter = params.get("delimiter").cloned();
    let page_token = params.get("pageToken").cloned();
    let max_results = params
        .get("maxResults")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0);
    state
        .authorize(
            principal,
            Method::List,
            &b,
            prefix.trim_end_matches('/'),
            None,
            None,
        )
        .map_err(deny)?;
    let store = state
        .store
        .lock()
        .map_err(|_| (500, "store poisoned".to_owned()))?;
    let page = store.list(
        &b,
        &prefix,
        delimiter.as_deref(),
        page_token.as_deref(),
        max_results,
    );
    let mut body = match dialect {
        Dialect::Firebase => json!({
            "prefixes": page.prefixes,
            "items": page.items.iter().map(|m| json!({"name": m.name.as_str(), "bucket": m.bucket.as_str()})).collect::<Vec<_>>(),
        }),
        Dialect::Gcs => json!({
            "kind": "storage#objects",
            "prefixes": page.prefixes,
            "items": page.items.iter().map(|m| gcs_json(m, host)).collect::<Vec<_>>(),
        }),
    };
    if let Some(t) = page.next_page_token {
        body["nextPageToken"] = Value::String(t);
    }
    Ok(StorageResponse::json(200, &body))
}

/// Uploads: multipart, media, resumable start / continue (both dialects).
#[allow(clippy::too_many_lines)]
fn upload(
    state: &StorageState,
    principal: &Principal,
    dialect: Dialect,
    bucket: &str,
    req: &StorageRequest,
    params: &BTreeMap<String, String>,
    host: &str,
) -> Outcome {
    let b = bucket_name(bucket)?;
    let now = state.now();
    // Continuation of a resumable upload.
    if let Some(upload_id) = params.get("upload_id") {
        return resumable_continue(state, dialect, &b, upload_id, req, params, host);
    }
    let upload_type = params.get("uploadType").map(String::as_str);
    let protocol = req.header("x-goog-upload-protocol");
    let command = req.header("x-goog-upload-command").unwrap_or("");
    let content_type = req.header("content-type").unwrap_or("").to_owned();
    let is_multipart = upload_type == Some("multipart")
        || protocol == Some("multipart")
        || content_type.starts_with("multipart/related");
    let is_resumable = upload_type == Some("resumable")
        || protocol == Some("resumable")
        || command.contains("start");
    if is_multipart {
        let (meta_json, part_ct, data) =
            parse_multipart(&content_type, &req.body).map_err(|e| (400, e))?;
        let name = params
            .get("name")
            .cloned()
            .or_else(|| {
                meta_json
                    .get("name")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            })
            .ok_or_else(|| (400, "object name is required".to_owned()))?;
        let n = object_name(&name)?;
        let meta = new_metadata_from_json(&meta_json, part_ct);
        let pre = precondition(params);
        return commit_bytes(
            state, principal, dialect, &b, &n, data, meta, pre, now, host,
        );
    }
    if is_resumable {
        let name = params
            .get("name")
            .cloned()
            .or_else(|| {
                serde_json::from_slice::<Value>(&req.body)
                    .ok()
                    .and_then(|v| v.get("name").and_then(Value::as_str).map(str::to_owned))
            })
            .ok_or_else(|| (400, "object name is required".to_owned()))?;
        let n = object_name(&name)?;
        let meta_json: Value = if req.body.is_empty() {
            Value::Object(Map::new())
        } else {
            serde_json::from_slice(&req.body).map_err(|e| (400, format!("metadata JSON: {e}")))?
        };
        let declared_ct = req
            .header("x-goog-upload-header-content-type")
            .or_else(|| req.header("x-upload-content-type"))
            .map(str::to_owned);
        let declared_len: Option<u64> = req
            .header("x-goog-upload-header-content-length")
            .or_else(|| req.header("x-upload-content-length"))
            .and_then(|v| v.parse().ok());
        let meta = new_metadata_from_json(&meta_json, declared_ct);
        let pre = precondition(params);
        // Rules run when the upload starts, with the declared metadata and size.
        let existing = state
            .store
            .lock()
            .map_err(|_| (500, "store poisoned".to_owned()))?
            .get(&b, &n)
            .cloned();
        let method = if existing.is_some() {
            Method::Update
        } else {
            Method::Create
        };
        state
            .authorize(
                principal,
                method,
                &b,
                n.as_str(),
                existing.as_ref().map(storage_rules_value),
                Some(incoming_rules_value(
                    &b,
                    &n,
                    &meta,
                    declared_len.unwrap_or(0),
                    now,
                )),
            )
            .map_err(deny)?;
        let id = state
            .store
            .lock()
            .map_err(|_| (500, "store poisoned".to_owned()))?
            .begin_upload(&b, &n, meta, pre, declared_len, now)
            .map_err(|e| {
                let r = storage_error(dialect, &e);
                (r.status, String::from_utf8_lossy(&r.body).into_owned())
            })?;
        let session_url = match dialect {
            Dialect::Firebase => format!(
                "http://{host}/v0/b/{}/o?name={}&upload_id={}&upload_protocol=resumable",
                encode_segment(b.as_str()),
                encode_segment(n.as_str()),
                id.as_str()
            ),
            Dialect::Gcs => format!(
                "http://{host}/upload/storage/v1/b/{}/o?uploadType=resumable&name={}&upload_id={}",
                encode_segment(b.as_str()),
                encode_segment(n.as_str()),
                id.as_str()
            ),
        };
        let response = StorageResponse::empty(200)
            .with_header("x-goog-upload-url", session_url.clone())
            .with_header("x-goog-upload-status", "active")
            .with_header("x-goog-upload-chunk-granularity", "262144")
            .with_header("location", session_url);
        return Ok(response);
    }
    // uploadType=media: the body is the object.
    let name = params
        .get("name")
        .cloned()
        .ok_or_else(|| (400, "object name is required".to_owned()))?;
    let n = object_name(&name)?;
    let meta = NewMetadata {
        content_type: Some(content_type).filter(|c| !c.is_empty()),
        ..NewMetadata::default()
    };
    let pre = precondition(params);
    commit_bytes(
        state,
        principal,
        dialect,
        &b,
        &n,
        req.body.clone(),
        meta,
        pre,
        now,
        host,
    )
}

#[allow(clippy::too_many_arguments)]
fn commit_bytes(
    state: &StorageState,
    principal: &Principal,
    dialect: Dialect,
    b: &BucketName,
    n: &ObjectName,
    data: Vec<u8>,
    meta: NewMetadata,
    pre: Precondition,
    now: LogicalInstant,
    host: &str,
) -> Outcome {
    let mut store = state
        .store
        .lock()
        .map_err(|_| (500, "store poisoned".to_owned()))?;
    let existing = store.get(b, n).cloned();
    let method = if existing.is_some() {
        Method::Update
    } else {
        Method::Create
    };
    state
        .authorize(
            principal,
            method,
            b,
            n.as_str(),
            existing.as_ref().map(storage_rules_value),
            Some(incoming_rules_value(b, n, &meta, data.len() as u64, now)),
        )
        .map_err(deny)?;
    let m = store.put(b, n, data, meta, pre, now).map_err(|e| {
        let r = storage_error(dialect, &e);
        (r.status, String::from_utf8_lossy(&r.body).into_owned())
    })?;
    Ok(StorageResponse::json(
        200,
        &metadata_json(dialect, &m, host),
    ))
}

fn resumable_continue(
    state: &StorageState,
    dialect: Dialect,
    b: &BucketName,
    upload_id: &str,
    req: &StorageRequest,
    params: &BTreeMap<String, String>,
    host: &str,
) -> Outcome {
    let id = UploadId::from_str_unchecked(upload_id);
    let now = state.now();
    let mut store = state
        .store
        .lock()
        .map_err(|_| (500, "store poisoned".to_owned()))?;
    let map_err = |e: StorageError| {
        let r = storage_error(dialect, &e);
        (r.status, String::from_utf8_lossy(&r.body).into_owned())
    };
    let _ = b;
    let _ = params;
    // Firebase X-Goog-Upload protocol.
    if let Some(command) = req.header("x-goog-upload-command") {
        let commands: Vec<&str> = command.split(',').map(str::trim).collect();
        if commands.contains(&"cancel") {
            store.cancel_upload(&id).map_err(map_err)?;
            return Ok(StorageResponse::empty(200).with_header("x-goog-upload-status", "cancelled"));
        }
        if commands.contains(&"query") {
            let (received, committed) = store.upload_status(&id).map_err(map_err)?;
            let mut r = StorageResponse::empty(200)
                .with_header("x-goog-upload-size-received", received.to_string());
            return Ok(match committed {
                Some(m) => {
                    r = StorageResponse::json(200, &metadata_json(dialect, &m, host))
                        .with_header("x-goog-upload-size-received", received.to_string());
                    r.with_header("x-goog-upload-status", "final")
                }
                None => r.with_header("x-goog-upload-status", "active"),
            });
        }
        let offset: u64 = req
            .header("x-goog-upload-offset")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        let finalize = commands.contains(&"finalize");
        let progress = store
            .upload_chunk(&id, offset, &req.body, finalize, now)
            .map_err(map_err)?;
        return Ok(match progress.committed {
            Some(m) => StorageResponse::json(200, &metadata_json(dialect, &m, host))
                .with_header("x-goog-upload-status", "final")
                .with_header("x-goog-upload-size-received", progress.received.to_string()),
            None => StorageResponse::empty(200)
                .with_header("x-goog-upload-status", "active")
                .with_header("x-goog-upload-size-received", progress.received.to_string()),
        });
    }
    // JSON API protocol: Content-Range on PUT.
    let content_range = req.header("content-range");
    let (offset, end, total) = match content_range {
        Some(cr) => {
            parse_content_range(cr).ok_or_else(|| (400, format!("invalid Content-Range {cr:?}")))?
        }
        None => (Some(0), None, Some(req.body.len() as u64)),
    };
    // Status query: `bytes */TOTAL`.
    if offset.is_none() {
        let (received, committed) = store.upload_status(&id).map_err(map_err)?;
        return Ok(if let Some(m) = committed {
            StorageResponse::json(200, &gcs_json(&m, host))
        } else {
            incomplete(received)
        });
    }
    let offset = offset.unwrap_or(0);
    let last = end.unwrap_or(offset + req.body.len() as u64);
    // A known total finishes when reached; an open-ended range (or no Content-Range at all)
    // carries the rest of the object in this request.
    let finalize = match total {
        Some(t) => last == t,
        None => end.is_none(),
    };
    let progress = store
        .upload_chunk(&id, offset, &req.body, finalize, now)
        .map_err(map_err)?;
    Ok(if let Some(m) = progress.committed {
        StorageResponse::json(200, &gcs_json(&m, host))
    } else {
        incomplete(progress.received)
    })
}

/// `308 Resume Incomplete` with the persisted range.
fn incomplete(received: u64) -> StorageResponse {
    let r = StorageResponse::empty(308);
    if received > 0 {
        r.with_header("range", format!("bytes=0-{}", received - 1))
    } else {
        r
    }
}

/// `bytes START-END/TOTAL`, `bytes */TOTAL`, `bytes START-END/*` → (start, end+1, total).
fn parse_content_range(cr: &str) -> Option<(Option<u64>, Option<u64>, Option<u64>)> {
    let rest = cr.trim().strip_prefix("bytes ")?;
    let (range, total) = rest.split_once('/')?;
    let total = if total == "*" {
        None
    } else {
        Some(total.parse().ok()?)
    };
    if range == "*" {
        return Some((None, None, total));
    }
    let (start, end) = range.split_once('-')?;
    let start: u64 = start.parse().ok()?;
    if end == "*" {
        // `START-*/*`: the body runs to the end of the object.
        return Some((Some(start), None, total));
    }
    let end: u64 = end.parse().ok()?;
    Some((Some(start), Some(end + 1), total))
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn object(
    state: &StorageState,
    principal: &Principal,
    dialect: Dialect,
    bucket: &str,
    name: &str,
    req: &StorageRequest,
    params: &BTreeMap<String, String>,
    host: &str,
) -> Outcome {
    let b = bucket_name(bucket)?;
    let n = object_name(name)?;
    let now = state.now();
    match req.method.as_str() {
        "GET" => {
            let store = state
                .store
                .lock()
                .map_err(|_| (500, "store poisoned".to_owned()))?;
            let meta = store.get(&b, &n).cloned();
            let media = params.get("alt").map(String::as_str) == Some("media")
                || req.path.starts_with("/download/");
            // A valid download token grants the read without rules.
            let token_ok = params.get("token").is_some_and(|t| {
                meta.as_ref()
                    .is_some_and(|m| m.download_tokens.iter().any(|x| x == t))
            });
            if !token_ok {
                state
                    .authorize(
                        principal,
                        Method::Get,
                        &b,
                        n.as_str(),
                        meta.as_ref().map(storage_rules_value),
                        None,
                    )
                    .map_err(deny)?;
            }
            let meta = meta.ok_or_else(|| (404, "Not Found. Could not get object".to_owned()))?;
            if !media {
                return Ok(StorageResponse::json(
                    200,
                    &metadata_json(dialect, &meta, host),
                ));
            }
            let bytes = store.bytes(&meta);
            let mut headers = vec![
                ("content-type".to_owned(), meta.content_type.clone()),
                ("x-goog-generation".to_owned(), meta.generation.to_string()),
                (
                    "x-goog-metageneration".to_owned(),
                    meta.metageneration.to_string(),
                ),
                (
                    "x-goog-stored-content-length".to_owned(),
                    meta.size.to_string(),
                ),
                (
                    "x-goog-hash".to_owned(),
                    format!("crc32c={},md5={}", meta.crc32c_base64(), meta.md5_base64()),
                ),
                ("etag".to_owned(), meta.etag()),
                ("accept-ranges".to_owned(), "bytes".to_owned()),
            ];
            if let Some(cd) = &meta.content_disposition {
                headers.push(("content-disposition".to_owned(), cd.clone()));
            }
            if let Some(ce) = &meta.content_encoding {
                headers.push(("content-encoding".to_owned(), ce.clone()));
            }
            if let Some(cc) = &meta.cache_control {
                headers.push(("cache-control".to_owned(), cc.clone()));
            }
            if let Some(range) = req.header("range").and_then(|r| r.strip_prefix("bytes=")) {
                let (s, e) = range.split_once('-').unwrap_or((range, ""));
                let start: usize = s.parse().unwrap_or(0);
                let end: usize = e
                    .parse::<usize>()
                    .map_or(bytes.len(), |e| (e + 1).min(bytes.len()));
                if start > end || start >= bytes.len() && !bytes.is_empty() {
                    return Ok(StorageResponse {
                        status: 416,
                        headers: vec![(
                            "content-range".to_owned(),
                            format!("bytes */{}", bytes.len()),
                        )],
                        body: Vec::new(),
                    });
                }
                headers.push((
                    "content-range".to_owned(),
                    format!("bytes {start}-{}/{}", end.saturating_sub(1), bytes.len()),
                ));
                return Ok(StorageResponse {
                    status: 206,
                    headers,
                    body: bytes[start..end].to_vec(),
                });
            }
            Ok(StorageResponse {
                status: 200,
                headers,
                body: bytes.to_vec(),
            })
        }
        "PATCH" | "PUT" => {
            let body: Value = if req.body.is_empty() {
                Value::Object(Map::new())
            } else {
                serde_json::from_slice(&req.body)
                    .map_err(|e| (400, format!("metadata JSON: {e}")))?
            };
            let mut store = state
                .store
                .lock()
                .map_err(|_| (500, "store poisoned".to_owned()))?;
            let existing = store
                .get(&b, &n)
                .cloned()
                .ok_or_else(|| (404, "Not Found. Could not update object".to_owned()))?;
            let patch = patch_from_json(&body);
            // request.resource = the object as it will be after the patch.
            let mut preview = existing.clone();
            if let Some(Some(ct)) = &patch.content_type {
                preview.content_type.clone_from(ct);
            }
            if let Some(custom) = &patch.custom {
                for (k, v) in custom {
                    match v {
                        Some(v) => {
                            preview.custom.insert(k.clone(), v.clone());
                        }
                        None => {
                            preview.custom.remove(k);
                        }
                    }
                }
            }
            state
                .authorize(
                    principal,
                    Method::Update,
                    &b,
                    n.as_str(),
                    Some(storage_rules_value(&existing)),
                    Some(storage_rules_value(&preview)),
                )
                .map_err(deny)?;
            let m = store
                .update_metadata(&b, &n, patch, precondition(params), now)
                .map_err(|e| {
                    let r = storage_error(dialect, &e);
                    (r.status, String::from_utf8_lossy(&r.body).into_owned())
                })?;
            Ok(StorageResponse::json(
                200,
                &metadata_json(dialect, &m, host),
            ))
        }
        "DELETE" => {
            let mut store = state
                .store
                .lock()
                .map_err(|_| (500, "store poisoned".to_owned()))?;
            let existing = store.get(&b, &n).cloned();
            state
                .authorize(
                    principal,
                    Method::Delete,
                    &b,
                    n.as_str(),
                    existing.as_ref().map(storage_rules_value),
                    None,
                )
                .map_err(deny)?;
            store.delete(&b, &n, precondition(params)).map_err(|e| {
                let r = storage_error(dialect, &e);
                (r.status, String::from_utf8_lossy(&r.body).into_owned())
            })?;
            Ok(StorageResponse::empty(204))
        }
        "POST" if dialect == Dialect::Firebase => {
            // Resumable continuation posts to the object URL with upload_id.
            if let Some(upload_id) = params.get("upload_id") {
                return resumable_continue(state, dialect, &b, upload_id, req, params, host);
            }
            Err((405, "method not allowed".to_owned()))
        }
        _ => Err((405, "method not allowed".to_owned())),
    }
}

#[allow(clippy::too_many_arguments)]
fn rewrite(
    state: &StorageState,
    principal: &Principal,
    bucket: &str,
    name: &str,
    dst_bucket: &str,
    dst_name: &str,
    req: &StorageRequest,
    params: &BTreeMap<String, String>,
    host: &str,
) -> Outcome {
    let b = bucket_name(bucket)?;
    let n = object_name(name)?;
    let db = bucket_name(dst_bucket)?;
    let dn = object_name(dst_name)?;
    let now = state.now();
    let override_meta: Option<NewMetadata> = if req.body.is_empty() {
        None
    } else {
        serde_json::from_slice::<Value>(&req.body)
            .ok()
            .filter(|v| v.as_object().is_some_and(|o| !o.is_empty()))
            .map(|v| new_metadata_from_json(&v, None))
    };
    let mut store = state
        .store
        .lock()
        .map_err(|_| (500, "store poisoned".to_owned()))?;
    let src = store
        .get(&b, &n)
        .cloned()
        .ok_or_else(|| (404, format!("No such object: {bucket}/{name}")))?;
    state
        .authorize(
            principal,
            Method::Get,
            &b,
            n.as_str(),
            Some(storage_rules_value(&src)),
            None,
        )
        .map_err(deny)?;
    let existing = store.get(&db, &dn).cloned();
    let method = if existing.is_some() {
        Method::Update
    } else {
        Method::Create
    };
    let meta_for_rules = override_meta.clone().unwrap_or(NewMetadata {
        content_type: Some(src.content_type.clone()),
        content_disposition: src.content_disposition.clone(),
        content_encoding: src.content_encoding.clone(),
        content_language: src.content_language.clone(),
        cache_control: src.cache_control.clone(),
        custom: src.custom.clone(),
    });
    state
        .authorize(
            principal,
            method,
            &db,
            dn.as_str(),
            existing.as_ref().map(storage_rules_value),
            Some(incoming_rules_value(
                &db,
                &dn,
                &meta_for_rules,
                src.size,
                now,
            )),
        )
        .map_err(deny)?;
    let m = store
        .copy(
            (&b, &n),
            (&db, &dn),
            override_meta,
            precondition(params),
            now,
        )
        .map_err(|e| {
            let r = storage_error(Dialect::Gcs, &e);
            (r.status, String::from_utf8_lossy(&r.body).into_owned())
        })?;
    let resource = gcs_json(&m, host);
    Ok(StorageResponse::json(
        200,
        &json!({
            "kind": "storage#rewriteResponse",
            "totalBytesRewritten": m.size.to_string(),
            "objectSize": m.size.to_string(),
            "done": true,
            "resource": resource,
        }),
    ))
}
