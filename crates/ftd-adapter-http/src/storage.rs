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

use ftd_core_auth::jwt::verify_id_token_decoded;
use ftd_core_auth::store::AuthStore;
use ftd_core_rules::eval::{
    evaluate_request_with, Decision, DenyReason, DocumentAccess, Method, RequestContext,
    RulesService,
};
use ftd_core_rules::runtime::LoadedRules;
use ftd_core_rules::value::{AuthContext, RulesValue};
use ftd_core_session::clock::VirtualClock;
use ftd_core_storage::hash::{crc32c, md5};
use ftd_core_storage::name::{BucketName, ObjectName};
use ftd_core_storage::store::{
    MetadataPatch, NewMetadata, ObjectMetadata, Precondition, StorageError, StorageEvent,
    StorageState as ObjectStore, UploadId, UploadOptions,
};
use ftd_core_types::determinism::Clock;
use ftd_core_types::time::{LogicalDuration, LogicalInstant};
use serde_json::{json, Map, Value};

/// Observer of Storage object events (see [`StorageState::events`]).
pub type StorageEventSink = Arc<dyn Fn(&StorageEvent) + Send + Sync>;

/// A locked object store that hands the events of its critical section to the sink when
/// it is released (still inside the lock, so events leave in commit order).
pub struct StoreGuard<'a> {
    guard: std::sync::MutexGuard<'a, ObjectStore>,
    sink: Option<&'a StorageEventSink>,
}

impl std::ops::Deref for StoreGuard<'_> {
    type Target = ObjectStore;
    fn deref(&self) -> &ObjectStore {
        &self.guard
    }
}

impl std::ops::DerefMut for StoreGuard<'_> {
    fn deref_mut(&mut self) -> &mut ObjectStore {
        &mut self.guard
    }
}

impl Drop for StoreGuard<'_> {
    fn drop(&mut self) {
        let events = self.guard.drain_events();
        if let Some(sink) = self.sink {
            for event in &events {
                sink(event);
            }
        }
    }
}

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
    /// Observer of object events (Storage triggers), called inside the store's critical
    /// section in commit order; `None` drops them.
    pub events: Option<StorageEventSink>,
    /// Session admission barrier (reset waits for requests in flight), when shared.
    pub barrier: Option<Arc<ftd_core_session::barrier::AdmissionBarrier>>,
    /// `firestore.get()` / `firestore.exists()` in Storage rules: the latest Firestore
    /// state of the project; `None` makes those calls fail closed.
    pub firestore: Option<Arc<dyn DocumentAccess + Send + Sync>>,
    /// The session's fault plan, when one is shared.
    pub faults: Option<ftd_core_session::fault::SharedFaults>,
}

/// The fault plan's answer for `operation`: an error response, or nothing (a delay moved
/// the clock).
fn fault_response(
    state: &StorageState,
    dialect: Dialect,
    operation: &str,
) -> Option<StorageResponse> {
    use ftd_core_session::fault::FaultAction;
    for action in
        ftd_core_session::fault::decide_shared(state.faults.as_ref(), operation, None, None)
    {
        match action {
            FaultAction::ReturnError { code } => {
                return Some(error_response(
                    dialect,
                    http_code(&code),
                    &format!("fault plan: {operation} returns {code}"),
                ))
            }
            FaultAction::Timeout => {
                return Some(error_response(
                    dialect,
                    504,
                    &format!("fault plan: {operation} timed out"),
                ))
            }
            FaultAction::DropConnection => {
                return Some(error_response(
                    dialect,
                    503,
                    &format!("fault plan: connection dropped during {operation}"),
                ))
            }
            FaultAction::TransactionConflict => {
                return Some(error_response(
                    dialect,
                    412,
                    &format!("fault plan: {operation} conflicts"),
                ))
            }
            FaultAction::Delay { seconds } => {
                if let Ok(mut clock) = state.clock.lock() {
                    let _ = clock.advance(LogicalDuration::from_seconds(seconds.max(0)));
                }
            }
            FaultAction::Duplicate { .. } | FaultAction::CrashRunner | FaultAction::DeadLetter => {}
        }
    }
    None
}

/// An HTTP status from a number or a gRPC code name.
fn http_code(code: &str) -> u16 {
    if let Ok(n) = code.parse::<u16>() {
        return n;
    }
    match code.to_ascii_uppercase().as_str() {
        "INVALID_ARGUMENT" | "FAILED_PRECONDITION" | "OUT_OF_RANGE" => 400,
        "UNAUTHENTICATED" => 401,
        "PERMISSION_DENIED" => 403,
        "NOT_FOUND" => 404,
        "ALREADY_EXISTS" | "ABORTED" => 409,
        "RESOURCE_EXHAUSTED" => 429,
        "CANCELLED" => 499,
        "UNIMPLEMENTED" => 501,
        "UNAVAILABLE" => 503,
        "DEADLINE_EXCEEDED" => 504,
        _ => 500,
    }
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
    let (status_name, reason) = match status {
        400 => ("INVALID_ARGUMENT", "invalid"),
        401 => ("UNAUTHENTICATED", "required"),
        403 => ("PERMISSION_DENIED", "forbidden"),
        404 => ("NOT_FOUND", "notFound"),
        405 => ("INVALID_ARGUMENT", "methodNotAllowed"),
        412 => ("FAILED_PRECONDITION", "conditionNotMet"),
        413 => ("OUT_OF_RANGE", "uploadTooLarge"),
        416 => ("OUT_OF_RANGE", "requestedRangeNotSatisfiable"),
        429 => ("RESOURCE_EXHAUSTED", "rateLimitExceeded"),
        _ => ("INTERNAL", "internalError"),
    };
    let body = match dialect {
        Dialect::Firebase => {
            json!({"error": {"code": status, "message": message, "status": status_name}})
        }
        Dialect::Gcs => {
            json!({"error": {"code": status, "message": message, "errors": [{"domain": "global", "reason": reason, "message": message}]}})
        }
    };
    StorageResponse::json(status, &body)
}

/// HTTP status and plain message of a core error (serialized once, by [`handle`]).
fn core_err(e: StorageError) -> (u16, String) {
    match e {
        StorageError::NotFound => (404, "Not Found. Could not get object".to_owned()),
        StorageError::PreconditionFailed(m) | StorageError::NotModified(m) => (412, m),
        StorageError::TooLarge => (413, "object too large".to_owned()),
        StorageError::MetadataTooLarge => (400, "custom metadata too large".to_owned()),
        StorageError::UploadNotFound => (404, "upload session not found".to_owned()),
        StorageError::UploadOffset { expected } => {
            (400, format!("upload offset mismatch, expected {expected}"))
        }
        StorageError::UploadFinalized => (400, "upload already finalized".to_owned()),
        StorageError::UploadSizeMismatch => (400, "upload size mismatch".to_owned()),
        StorageError::TooManyUploads => (429, "too many open upload sessions".to_owned()),
        StorageError::ChecksumMismatch(m) => (400, format!("checksum mismatch: {m}")),
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

/// multipart/related: returns (metadata JSON part, data content type, data bytes). A
/// delimiter is recognized only at the start of a line and exactly the framing line break
/// before it is removed, so payloads ending in line breaks survive intact.
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
    let Some(mut cursor) = find_delimiter(body, 0, &delimiter) else {
        return Err("multipart body has no parts".into());
    };
    loop {
        let after = cursor + delimiter.len();
        if body.get(after..after + 2) == Some(b"--") {
            break;
        }
        // Skip the line break after the delimiter line.
        let mut p = after;
        if body.get(p) == Some(&b'\r') {
            p += 1;
        }
        if body.get(p) == Some(&b'\n') {
            p += 1;
        }
        let Some(next) = find_delimiter(body, p, &delimiter) else {
            return Err("unterminated multipart part".into());
        };
        let mut part = &body[p..next];
        if part.ends_with(b"\r\n") {
            part = &part[..part.len() - 2];
        } else if part.ends_with(b"\n") {
            part = &part[..part.len() - 1];
        }
        let (headers, content) = split_headers(part);
        parts.push((headers, content.to_vec()));
        cursor = next;
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

/// Position of the next delimiter at or after `from` that starts a line.
fn find_delimiter(body: &[u8], from: usize, delimiter: &[u8]) -> Option<usize> {
    let mut at = from;
    while let Some(rel) = find(body.get(at..)?, delimiter) {
        let pos = at + rel;
        let line_start = pos == 0 || body[pos - 1] == b'\n';
        // A delimiter line is the delimiter followed by `--`, a line break or the end.
        let after = pos + delimiter.len();
        let line_end = matches!(body.get(after), None | Some(b'\r' | b'\n'))
            || (body.get(after..after + 2) == Some(b"--") && {
                // Closing delimiter: optional transport padding, then a line break or
                // the end of the body.
                let mut q = after + 2;
                while matches!(body.get(q), Some(b' ' | b'\t')) {
                    q += 1;
                }
                matches!(body.get(q), None | Some(b'\r' | b'\n'))
            });
        if line_start && line_end {
            return Some(pos);
        }
        at = pos + 1;
    }
    None
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
pub enum Principal {
    /// Admin credentials (JSON API without an end-user token, `Bearer owner`): rules bypassed.
    Owner,
    /// A verified end user.
    User(AuthContext),
    /// No credentials.
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

/// The `request.resource` of an upload: the object as it will be stored, without the
/// server-assigned `generation`, `metageneration`, `etag`, `timeCreated` and `updated`
/// (production excludes them); hashes are present once the bytes are known.
fn incoming_rules_value(
    bucket: &BucketName,
    name: &ObjectName,
    meta: &NewMetadata,
    size: u64,
    hashes: Option<(&[u8; 16], u32)>,
) -> RulesValue {
    let mut map = BTreeMap::new();
    let s = |v: &str| RulesValue::String(v.to_owned());
    map.insert("name".into(), s(name.as_str()));
    map.insert("bucket".into(), s(bucket.as_str()));
    map.insert(
        "size".into(),
        RulesValue::Int(i64::try_from(size).unwrap_or(i64::MAX)),
    );
    if let Some((digest, crc)) = hashes {
        map.insert("md5Hash".into(), s(&ftd_core_storage::hash::base64(digest)));
        map.insert(
            "crc32c".into(),
            s(&ftd_core_storage::hash::base64(&crc.to_be_bytes())),
        );
    }
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

/// The `request.resource` of a metadata update: the object after the patch, without the
/// server-assigned fields.
fn prospective_rules_value(m: &ObjectMetadata) -> RulesValue {
    match storage_rules_value(m) {
        RulesValue::Map(mut map) => {
            for k in [
                "generation",
                "metageneration",
                "etag",
                "timeCreated",
                "updated",
            ] {
                map.remove(k);
            }
            RulesValue::Map(map)
        }
        other => other,
    }
}

impl StorageState {
    /// Locks the object store; events produced while locked reach the sink on release.
    pub fn store(&self) -> Result<StoreGuard<'_>, (u16, String)> {
        let guard = self
            .store
            .lock()
            .map_err(|_| (500, "store poisoned".to_owned()))?;
        Ok(StoreGuard {
            guard,
            sink: self.events.as_ref(),
        })
    }

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
        let (_, decoded) = verify_id_token_decoded(token, &store, self.now())
            .map_err(|e| format!("invalid ID token: {e}"))?;
        drop(store);
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
        if method == Method::List && ruleset.version.as_deref() != Some("2") {
            // Storage list requests exist only under rules_version = '2'; a v1 `read` never
            // grants them.
            return Err(format!(
                "list on /b/{}/o/{object_path} denied by Storage Rules: list requires rules_version = '2'",
                bucket.as_str()
            ));
        }
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
            request_query: None,
        };
        let access = self.firestore.as_deref().map(|a| a as &dyn DocumentAccess);
        match evaluate_request_with(ruleset, &ctx, access).decision {
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

/// Strictly parsed write preconditions: a malformed value is an error, never ignored.
fn precondition(params: &BTreeMap<String, String>) -> Result<Precondition, (u16, String)> {
    precondition_named(params, "if")
}

/// `ifGenerationMatch` & co. (`prefix = "if"`) or `ifSourceGenerationMatch` & co.
/// (`prefix = "ifSource"`); a match and a not-match predicate on the same field conflict.
fn precondition_named(
    params: &BTreeMap<String, String>,
    prefix: &str,
) -> Result<Precondition, (u16, String)> {
    let pre = Precondition {
        if_generation_match: u64_param(params, &format!("{prefix}GenerationMatch"))?,
        if_metageneration_match: u64_param(params, &format!("{prefix}MetagenerationMatch"))?,
        if_generation_not_match: u64_param(params, &format!("{prefix}GenerationNotMatch"))?,
        if_metageneration_not_match: u64_param(params, &format!("{prefix}MetagenerationNotMatch"))?,
    };
    if (pre.if_generation_match.is_some() && pre.if_generation_not_match.is_some())
        || (pre.if_metageneration_match.is_some() && pre.if_metageneration_not_match.is_some())
    {
        return Err((
            400,
            format!(
                "{prefix}...Match and {prefix}...NotMatch on the same field are mutually exclusive"
            ),
        ));
    }
    Ok(pre)
}

fn u64_param(params: &BTreeMap<String, String>, key: &str) -> Result<Option<u64>, (u16, String)> {
    match params.get(key) {
        None => Ok(None),
        Some(v) => v
            .parse::<u64>()
            .map(Some)
            .map_err(|_| (400, format!("invalid {key}: {v:?}"))),
    }
}

/// Applies a `generation` / `sourceGeneration` selector: a generation other than the
/// current one is not available (historical versions are not kept).
fn select_generation(
    meta: Option<ObjectMetadata>,
    params: &BTreeMap<String, String>,
    key: &str,
) -> Result<Option<ObjectMetadata>, (u16, String)> {
    match u64_param(params, key)? {
        Some(g) => Ok(meta.filter(|m| m.generation == g)),
        None => Ok(meta),
    }
}

/// Expected hashes of an upload (`X-Goog-Hash` and the `md5Hash` / `crc32c` metadata
/// fields); a mismatch with the received bytes refuses the upload before it is committed.
fn verify_hashes(
    req: &StorageRequest,
    meta_json: Option<&Value>,
    bytes: &[u8],
) -> Result<([u8; 16], u32), (u16, String)> {
    let digest = md5(bytes);
    let crc = crc32c(bytes);
    let (expected_md5, expected_crc) = declared_hashes(req, meta_json)?;
    if let Some(e) = expected_md5 {
        if e != digest {
            return Err((
                400,
                format!(
                    "md5 checksum mismatch: expected {}, received {}",
                    ftd_core_storage::hash::base64(&e),
                    ftd_core_storage::hash::base64(&digest)
                ),
            ));
        }
    }
    if let Some(e) = expected_crc {
        if e != crc {
            return Err((
                400,
                format!(
                    "crc32c checksum mismatch: expected {}, received {}",
                    ftd_core_storage::hash::base64(&e.to_be_bytes()),
                    ftd_core_storage::hash::base64(&crc.to_be_bytes())
                ),
            ));
        }
    }
    Ok((digest, crc))
}

/// Checksums the client declared for the whole object: `X-Goog-Hash`, `Content-MD5` and the
/// `md5Hash` / `crc32c` metadata fields. Malformed values are errors.
#[allow(clippy::type_complexity)]
fn declared_hashes(
    req: &StorageRequest,
    meta_json: Option<&Value>,
) -> Result<(Option<[u8; 16]>, Option<u32>), (u16, String)> {
    let mut md5_b64: Option<String> = None;
    let mut crc_b64: Option<String> = None;
    if let Some(h) = req.header("x-goog-hash") {
        for item in h.split(',') {
            if let Some((k, v)) = item.trim().split_once('=') {
                match k.trim().to_ascii_lowercase().as_str() {
                    "md5" => md5_b64 = Some(v.trim().to_owned()),
                    "crc32c" => crc_b64 = Some(v.trim().to_owned()),
                    _ => {}
                }
            }
        }
    }
    if let Some(v) = req.header("content-md5") {
        md5_b64 = Some(v.trim().to_owned());
    }
    if let Some(m) = meta_json {
        if let Some(v) = m.get("md5Hash").and_then(Value::as_str) {
            md5_b64 = Some(v.to_owned());
        }
        if let Some(v) = m.get("crc32c").and_then(Value::as_str) {
            crc_b64 = Some(v.to_owned());
        }
    }
    let md5 = match md5_b64 {
        None => None,
        Some(v) => Some(
            base64_decode(&v)
                .ok()
                .and_then(|b| <[u8; 16]>::try_from(b).ok())
                .ok_or_else(|| (400, format!("malformed md5 checksum {v:?}")))?,
        ),
    };
    let crc = match crc_b64 {
        None => None,
        Some(v) => Some(
            base64_decode(&v)
                .ok()
                .and_then(|b| <[u8; 4]>::try_from(b).ok())
                .map(u32::from_be_bytes)
                .ok_or_else(|| (400, format!("malformed crc32c checksum {v:?}")))?,
        ),
    };
    Ok((md5, crc))
}

/// Standard base64 (RFC 4648, padded or unpadded) decoding.
fn base64_decode(text: &str) -> Result<Vec<u8>, ()> {
    let mut out = Vec::with_capacity(text.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut bits = 0;
    for c in text.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            b'=' => break,
            _ => return Err(()),
        };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((acc >> bits) & 0xFF).map_err(|_| ())?);
        }
    }
    Ok(out)
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
    let operation = match (&route, req.method.as_str()) {
        (Route::Object { .. }, "GET") => "storage.read",
        (Route::Object { .. }, "DELETE") => "storage.delete",
        (Route::Object { .. }, _) | (Route::Bucket { .. }, "POST" | "PUT") => "storage.upload",
        (Route::Bucket { .. }, _) => "storage.list",
        _ => "storage.request",
    };
    if let Some(refused) = fault_response(state, dialect, operation) {
        return refused;
    }
    // The JSON API surface is what the Admin SDK / gcloud use: like the official Emulator
    // it is a privileged surface (rules bypassed) unless the caller presents an end-user
    // `Firebase <token>`; the Firebase protocol always goes through the rules.
    // Admitted for the whole request, before the token is verified: a reset waits for it,
    // and a request cannot verify against the old Auth store and then write into the new
    // session. Requests are synchronous, so the admission is short-lived.
    let _admitted = state.barrier.as_ref().map(|b| b.admit());
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
    let store = state.store()?;
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
        return resumable_continue(state, dialect, upload_id, req, host);
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
        let pre = precondition(params)?;
        let hashes = verify_hashes(req, Some(&meta_json), &data)?;
        return commit_bytes(
            state, principal, dialect, &b, &n, data, meta, pre, hashes, now, host,
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
        let declared_len: Option<u64> = match req
            .header("x-goog-upload-header-content-length")
            .or_else(|| req.header("x-upload-content-length"))
        {
            None => None,
            Some(v) => Some(
                v.parse()
                    .map_err(|_| (400, format!("invalid declared content length {v:?}")))?,
            ),
        };
        let meta = new_metadata_from_json(&meta_json, declared_ct);
        let pre = precondition(params)?;
        let (expected_md5, expected_crc32c) = declared_hashes(req, Some(&meta_json))?;
        // Rules run at finalization against the received bytes (as the official Emulator
        // does): the declared size and metadata alone cannot decide rules that inspect the
        // hashes, and the destination may change while the session is open. The session
        // keeps the credentials it was started with.
        let authorization = match principal {
            Principal::Owner => Some("Bearer owner".to_owned()),
            Principal::Anonymous => None,
            Principal::User(_) => req.header("authorization").map(str::to_owned),
        };
        let id = state
            .store()?
            .begin_upload_with(
                &b,
                &n,
                meta,
                pre,
                UploadOptions {
                    total: declared_len,
                    authorization,
                    expected_md5,
                    expected_crc32c,
                },
                now,
            )
            .map_err(core_err)?;
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
    let pre = precondition(params)?;
    let hashes = verify_hashes(req, None, &req.body)?;
    commit_bytes(
        state,
        principal,
        dialect,
        &b,
        &n,
        req.body.clone(),
        meta,
        pre,
        hashes,
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
    hashes: ([u8; 16], u32),
    now: LogicalInstant,
    host: &str,
) -> Outcome {
    let mut store = state.store()?;
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
            Some(incoming_rules_value(
                b,
                n,
                &meta,
                data.len() as u64,
                Some((&hashes.0, hashes.1)),
            )),
        )
        .map_err(deny)?;
    let m = store.put(b, n, data, meta, pre, now).map_err(core_err)?;
    Ok(StorageResponse::json(
        200,
        &metadata_json(dialect, &m, host),
    ))
}

/// Authorizes and commits a resumable upload against the bytes actually received (the
/// principal that started the session; the then-current destination).
fn finalize_resumable(
    state: &StorageState,
    store: &mut ObjectStore,
    id: &UploadId,
    req: &StorageRequest,
    now: LogicalInstant,
) -> Result<ObjectMetadata, (u16, String)> {
    // Checksums declared on the finalizing request are verified by the store when it
    // commits (a mismatch ends the session).
    let (md5_declared, crc_declared) = declared_hashes(req, None)?;
    store
        .set_upload_hashes(id, md5_declared, crc_declared, now)
        .map_err(core_err)?;
    let (b, n, meta, size, hashes, authorization) = {
        let pending = store.pending_upload(id, now).map_err(core_err)?;
        (
            pending.bucket.clone(),
            pending.name.clone(),
            pending.metadata.clone(),
            pending.bytes.len() as u64,
            (md5(pending.bytes), crc32c(pending.bytes)),
            pending.authorization.map(str::to_owned),
        )
    };
    // The caller is the one that started the session (its credentials are verified again
    // now, as the official Emulator does).
    let principal = state
        .principal(authorization.as_deref())
        .map_err(|e| (401, e))?;
    let existing = store.get(&b, &n).cloned();
    let method = if existing.is_some() {
        Method::Update
    } else {
        Method::Create
    };
    state
        .authorize(
            &principal,
            method,
            &b,
            n.as_str(),
            existing.as_ref().map(storage_rules_value),
            Some(incoming_rules_value(
                &b,
                &n,
                &meta,
                size,
                Some((&hashes.0, hashes.1)),
            )),
        )
        .map_err(deny)?;
    store.finalize_upload(id, now).map_err(core_err)
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn resumable_continue(
    state: &StorageState,
    dialect: Dialect,
    upload_id: &str,
    req: &StorageRequest,
    host: &str,
) -> Outcome {
    let id = UploadId::from_str_unchecked(upload_id);
    let now = state.now();
    let mut store = state.store()?;
    // Firebase X-Goog-Upload protocol.
    if let Some(command) = req.header("x-goog-upload-command") {
        let commands: Vec<&str> = command.split(',').map(str::trim).collect();
        if commands.contains(&"cancel") {
            store.cancel_upload(&id, now).map_err(core_err)?;
            return Ok(StorageResponse::empty(200).with_header("x-goog-upload-status", "cancelled"));
        }
        if commands.contains(&"query") {
            let (received, committed) = store.upload_status(&id, now).map_err(core_err)?;
            return Ok(match committed {
                Some(m) => StorageResponse::json(200, &metadata_json(dialect, &m, host))
                    .with_header("x-goog-upload-size-received", received.to_string())
                    .with_header("x-goog-upload-status", "final"),
                None => StorageResponse::empty(200)
                    .with_header("x-goog-upload-size-received", received.to_string())
                    .with_header("x-goog-upload-status", "active"),
            });
        }
        let offset: u64 = match req.header("x-goog-upload-offset") {
            None => 0,
            Some(v) => v
                .parse()
                .map_err(|_| (400, format!("invalid X-Goog-Upload-Offset {v:?}")))?,
        };
        if commands.contains(&"upload") {
            store
                .append_upload(&id, offset, &req.body, now)
                .map_err(core_err)?;
        } else if !req.body.is_empty() {
            return Err((400, "a body needs the upload command".to_owned()));
        }
        if commands.contains(&"finalize") {
            let m = finalize_resumable(state, &mut store, &id, req, now)?;
            return Ok(
                StorageResponse::json(200, &metadata_json(dialect, &m, host))
                    .with_header("x-goog-upload-status", "final")
                    .with_header("x-goog-upload-size-received", m.size.to_string()),
            );
        }
        let (received, _) = store.upload_status(&id, now).map_err(core_err)?;
        return Ok(StorageResponse::empty(200)
            .with_header("x-goog-upload-status", "active")
            .with_header("x-goog-upload-size-received", received.to_string()));
    }
    // JSON API protocol: Content-Range on PUT.
    let range = match req.header("content-range") {
        Some(cr) => {
            parse_content_range(cr).ok_or_else(|| (400, format!("invalid Content-Range {cr:?}")))?
        }
        None => ContentRange::Span {
            start: 0,
            end: Some(req.body.len() as u64),
            total: Some(req.body.len() as u64),
        },
    };
    let (start, end, total) = match range {
        ContentRange::Status => {
            let (received, committed) = store.upload_status(&id, now).map_err(core_err)?;
            return Ok(if let Some(m) = committed {
                StorageResponse::json(200, &gcs_json(&m, host))
            } else {
                incomplete(received)
            });
        }
        ContentRange::Span { start, end, total } => (start, end, total),
    };
    let body_len = req.body.len() as u64;
    if let Some(end) = end {
        if end.checked_sub(start) != Some(body_len) {
            return Err((
                400,
                format!(
                    "Content-Range spans {} bytes but the body has {body_len}",
                    end.saturating_sub(start)
                ),
            ));
        }
        if total.is_some_and(|t| end > t) {
            return Err((400, "Content-Range exceeds the declared total".to_owned()));
        }
    }
    if let Some(t) = total {
        store.set_upload_total(&id, t, now).map_err(core_err)?;
    }
    store
        .append_upload(&id, start, &req.body, now)
        .map_err(core_err)?;
    // A known total finishes when reached; an open-ended range (`START-*/*`, or no
    // Content-Range at all) carries the rest of the object in this request.
    let finalize = match (end, total) {
        (Some(e), Some(t)) => e == t,
        (Some(_), None) => false,
        (None, _) => true,
    };
    if finalize {
        let m = finalize_resumable(state, &mut store, &id, req, now)?;
        return Ok(StorageResponse::json(200, &gcs_json(&m, host)));
    }
    let (received, _) = store.upload_status(&id, now).map_err(core_err)?;
    Ok(incomplete(received))
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

/// A parsed `Content-Range` request header.
enum ContentRange {
    /// `bytes */TOTAL` (status query).
    Status,
    /// `bytes START-END/TOTAL`, `bytes START-*/*`: `end` is exclusive.
    Span {
        start: u64,
        end: Option<u64>,
        total: Option<u64>,
    },
}

fn parse_content_range(cr: &str) -> Option<ContentRange> {
    let rest = cr.trim().strip_prefix("bytes ")?;
    let (range, total) = rest.split_once('/')?;
    let total = if total == "*" {
        None
    } else {
        Some(total.trim().parse::<u64>().ok()?)
    };
    if range == "*" {
        return Some(ContentRange::Status);
    }
    let (start, end) = range.split_once('-')?;
    let start: u64 = start.trim().parse().ok()?;
    if end == "*" {
        return Some(ContentRange::Span {
            start,
            end: None,
            total,
        });
    }
    let end: u64 = end.trim().parse().ok()?;
    if end < start {
        return None;
    }
    Some(ContentRange::Span {
        start,
        end: Some(end.checked_add(1)?),
        total,
    })
}

/// One satisfiable byte range of a `Range: bytes=...` header (RFC 7233): `Ok(None)` when
/// the header is absent or syntactically ignorable, `Err(())` when unsatisfiable (416).
fn parse_range(header: Option<&str>, len: u64) -> Result<Option<(u64, u64)>, ()> {
    let Some(spec) = header.and_then(|h| h.trim().strip_prefix("bytes=")) else {
        return Ok(None);
    };
    if spec.contains(',') {
        return Ok(None);
    }
    let Some((first, last)) = spec.split_once('-') else {
        return Ok(None);
    };
    let (first, last) = (first.trim(), last.trim());
    let (start, end) = if first.is_empty() {
        // Suffix range: the final N bytes.
        let Ok(suffix) = last.parse::<u64>() else {
            return Ok(None);
        };
        if suffix == 0 || len == 0 {
            return Err(());
        }
        (len.saturating_sub(suffix), len)
    } else {
        let Ok(start) = first.parse::<u64>() else {
            return Ok(None);
        };
        let end = if last.is_empty() {
            len
        } else {
            match last.parse::<u64>() {
                Ok(e) if e >= start => e.saturating_add(1).min(len),
                _ => return Ok(None),
            }
        };
        if start >= len {
            return Err(());
        }
        (start, end)
    };
    Ok(Some((start, end)))
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
            let store = state.store()?;
            let meta = select_generation(store.get(&b, &n).cloned(), params, "generation")?;
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
            // Conditional reads: a not-match predicate naming the current value is 304.
            match precondition(params)?.check(Some(&meta)) {
                Ok(()) => {}
                Err(StorageError::NotModified(_)) => {
                    return Ok(StorageResponse::empty(304).with_header("etag", meta.etag()))
                }
                Err(e) => return Err(core_err(e)),
            }
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
            let len = bytes.len() as u64;
            match parse_range(req.header("range"), len) {
                Err(()) => Ok(StorageResponse {
                    status: 416,
                    headers: vec![("content-range".to_owned(), format!("bytes */{len}"))],
                    body: Vec::new(),
                }),
                Ok(Some((start, end))) => {
                    headers.push((
                        "content-range".to_owned(),
                        format!("bytes {start}-{}/{len}", end - 1),
                    ));
                    headers.push(("content-length".to_owned(), (end - start).to_string()));
                    let (s, e) = (
                        usize::try_from(start).unwrap_or(usize::MAX),
                        usize::try_from(end).unwrap_or(usize::MAX),
                    );
                    Ok(StorageResponse {
                        status: 206,
                        headers,
                        body: bytes.get(s..e).unwrap_or_default().to_vec(),
                    })
                }
                Ok(None) => {
                    headers.push(("content-length".to_owned(), len.to_string()));
                    Ok(StorageResponse {
                        status: 200,
                        headers,
                        body: bytes.to_vec(),
                    })
                }
            }
        }
        "PATCH" | "PUT" => {
            let body: Value = if req.body.is_empty() {
                Value::Object(Map::new())
            } else {
                serde_json::from_slice(&req.body)
                    .map_err(|e| (400, format!("metadata JSON: {e}")))?
            };
            let pre = precondition(params)?;
            let mut store = state.store()?;
            let existing = select_generation(store.get(&b, &n).cloned(), params, "generation")?
                .ok_or_else(|| (404, "Not Found. Could not update object".to_owned()))?;
            let patch = patch_from_json(&body);
            // request.resource = the object exactly as the patch will store it.
            let preview = patch.apply(&existing);
            state
                .authorize(
                    principal,
                    Method::Update,
                    &b,
                    n.as_str(),
                    Some(storage_rules_value(&existing)),
                    Some(prospective_rules_value(&preview)),
                )
                .map_err(deny)?;
            let m = store
                .update_metadata(&b, &n, &patch, pre, now)
                .map_err(core_err)?;
            Ok(StorageResponse::json(
                200,
                &metadata_json(dialect, &m, host),
            ))
        }
        "DELETE" => {
            let pre = precondition(params)?;
            let mut store = state.store()?;
            let existing = select_generation(store.get(&b, &n).cloned(), params, "generation")?;
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
            if existing.is_none() {
                return Err((404, "Not Found. Could not delete object".to_owned()));
            }
            store.delete(&b, &n, pre).map_err(core_err)?;
            Ok(StorageResponse::empty(204))
        }
        "POST" if dialect == Dialect::Firebase => {
            // Resumable continuation posts to the object URL with upload_id.
            if let Some(upload_id) = params.get("upload_id") {
                return resumable_continue(state, dialect, upload_id, req, host);
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
    let mut store = state.store()?;
    let source_pre = precondition_named(params, "ifSource")?;
    let pre = precondition(params)?;
    let selected = select_generation(store.get(&b, &n).cloned(), params, "sourceGeneration")?;
    // The source read is authorized before existence, generation or precondition outcomes
    // become observable.
    state
        .authorize(
            principal,
            Method::Get,
            &b,
            n.as_str(),
            selected.as_ref().map(storage_rules_value),
            None,
        )
        .map_err(deny)?;
    let src = selected.ok_or_else(|| (404, format!("No such object: {bucket}/{name}")))?;
    source_pre.check(Some(&src)).map_err(|e| match e {
        StorageError::NotModified(m) => (412, m),
        other => core_err(other),
    })?;
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
                Some((&src.md5, src.crc32c)),
            )),
        )
        .map_err(deny)?;
    let m = store
        .copy((&b, &n), (&db, &dn), override_meta, pre, now)
        .map_err(core_err)?;
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
