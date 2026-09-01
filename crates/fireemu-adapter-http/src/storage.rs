//! Cloud Storage for Firebase over HTTP: the Firebase Storage protocol used by the web /
//! mobile SDKs (`/v0/b/{bucket}/o...`, `X-Goog-Upload-*` resumable uploads, download
//! tokens) and the JSON API used by the Admin SDK / `@google-cloud/storage`
//! (`/b/...`, `/storage/v1/...`, `/upload/storage/v1/...`, `/download/storage/v1/...`,
//! `Content-Range` resumable uploads). Both surfaces share one [`StorageState`] and the
//! Storage Security Rules (`service firebase.storage`).
//!
//! Response shapes, error bodies, route registration and dialect quirks are aligned with
//! the pinned official Cloud Storage emulator as measured by the storage probe
//! (`conformance/src/storage-probe/`); the deliberate differences are pinned in
//! `conformance/storage-matrix.json` through `conformance/divergences.json`. In
//! particular, like the official emulator:
//!
//! - the JSON API dialect is a privileged surface: Security Rules never run on it,
//!   whatever credential is presented;
//! - the JSON API registers object update (PATCH) and copy only on the short `/b/...`
//!   spelling; the `/storage/v1/...` spelling of those falls through to the 501 catch-all;
//! - an unknown GET with a bucket-shaped path serves object bytes (the XML-ish
//!   `/{bucket}/{object}` route) and answers `No such object: ...` otherwise;
//! - the Firebase dialect answers plain-text statuses where the official emulator's
//!   express `sendStatus` does, and the exact `Permission denied. No READ|WRITE|LIST
//!   permission.` rules-denial envelopes.
//!
//! Object names are percent-decoded exactly once from the URL segment and never
//! interpreted as paths. Only loopback origins reach either surface.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, RwLock};

use fireemu_core_app_check::admission::{AdmissionRequest, PrivilegedBypass, ServiceAdmission};
use fireemu_core_app_check::header::classify_app_check_header;
use fireemu_core_app_check::verify::BaselineMode;
use fireemu_core_auth::jwt::{verify_rules_token, TokenAcceptance};
use fireemu_core_rules::eval::{
    evaluate_request_with, Decision, DocumentAccess, Method, RequestContext, RulesService,
};
use fireemu_core_rules::runtime::LoadedRules;
use fireemu_core_rules::value::{AuthContext, RulesValue};
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_storage::hash::{crc32c, md5};
use fireemu_core_storage::name::{BucketName, ObjectName};
use fireemu_core_storage::store::{
    CustomMetadataPatch, MetadataPatch, NewMetadata, ObjectMetadata, Precondition, StorageError,
    StorageEvent, StorageState as ObjectStore, UploadAdmission, UploadId, UploadOptions,
    UploadPhase,
};
use fireemu_core_types::determinism::Clock;
use fireemu_core_types::time::{LogicalDuration, LogicalInstant};
use serde_json::{json, Map, Value};

/// The custom-metadata key download tokens ride in on, exactly as upstream stores them.
const TOKENS_KEY: &str = "firebaseStorageDownloadTokens";

/// The longest MIME multipart boundary accepted (RFC 2046 caps it at 70). A longer one is a
/// red flag rather than a real client, and refusing it is a second line of defence for the
/// multipart scanner behind its O(N) fix (S-3).
const MAX_MULTIPART_BOUNDARY_LEN: usize = 70;

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
    /// Users of every session project (ID tokens are verified against the store of their
    /// audience, which must be the bucket's project).
    pub auth: Arc<fireemu_core_auth::store::AuthRegistry>,
    /// Which session owns which bucket; `None` puts every bucket in `project`.
    pub tenancy: Option<fireemu_core_session::tenancy::SharedTenancy>,
    /// Storage Security Rules (`service firebase.storage`).
    pub rules: Arc<RwLock<LoadedRules>>,
    /// Project (default buckets `{project}.appspot.com` / `{project}.firebasestorage.app`).
    pub project: String,
    /// Observer of object events (Storage triggers), called inside the store's critical
    /// section in commit order; `None` drops them.
    pub events: Option<StorageEventSink>,
    /// Session admission barrier (reset waits for requests in flight), when shared.
    pub barrier: Option<Arc<fireemu_core_session::barrier::AdmissionBarrier>>,
    /// `firestore.get()` / `firestore.exists()` in Storage rules: the latest Firestore
    /// state of the project; `None` makes those calls fail closed.
    pub firestore: Option<Arc<dyn DocumentAccess + Send + Sync>>,
    /// The sessions' fault plans (by the bucket's project), when shared.
    pub faults: Option<fireemu_core_session::fault::SharedFaultRegistry>,
    /// Told after a fault plan moved the virtual clock.
    pub clock_observer: Option<Arc<dyn Fn() + Send + Sync>>,
    /// The App Check baseline policy of Cloud Storage (`appCheck.services.storage`). `None`
    /// is the `off` mode: no header is collected and nothing is classified.
    pub app_check_policy: Option<Arc<ServiceAdmission>>,
    /// Per-run capability used only by the Admin Storage SDK endpoint inherited by an
    /// `exec` child. It is distinct from the owner and control credentials.
    pub admin_capability: Option<String>,
    /// How a caller's ID token is verified before Storage Rules see it: the compatibility
    /// profile decides (`firebase` admits the official emulator's mock tokens, `strict`
    /// does not).
    pub token_acceptance: TokenAcceptance,
}

impl StorageState {
    /// The project a bucket belongs to (the session tenancy, else the configured project).
    #[must_use]
    pub fn project_of_bucket(&self, bucket: &str) -> String {
        self.tenancy
            .as_ref()
            .and_then(|t| t.read().ok())
            .map_or_else(
                || self.project.clone(),
                |t| t.project_of_bucket(bucket).to_owned(),
            )
    }
}

/// Header a `dropConnection` fault sets on its response: the server closes the connection
/// instead of sending it.
pub const DROP_CONNECTION_HEADER: &str = "x-fireemu-drop-connection";

/// The fault plan's answer for `operation`: an error response, or nothing (a delay moved
/// the clock).
fn fault_response(
    state: &StorageState,
    dialect: Dialect,
    project: &str,
    operation: &str,
) -> Option<StorageResponse> {
    use fireemu_core_session::fault::FaultAction;
    for action in fireemu_core_session::fault::decide_for(
        state.faults.as_ref(),
        project,
        operation,
        None,
        None,
    ) {
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
                // The server closes the connection instead of sending this response.
                let mut response = error_response(
                    dialect,
                    503,
                    &format!("fault plan: connection dropped during {operation}"),
                );
                response
                    .headers
                    .push((DROP_CONNECTION_HEADER.to_owned(), "1".to_owned()));
                return Some(response);
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
                if let Some(observer) = &state.clock_observer {
                    observer();
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
    /// Selected request headers (lowercase names). The App Check field is deliberately not
    /// here: a map collapses duplicates, which the canonical contract must refuse.
    pub headers: BTreeMap<String, String>,
    /// Every `X-Firebase-AppCheck` field instance, in wire order (specification section 7.3).
    pub app_check: Vec<String>,
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

impl From<(u16, String)> for StorageResponse {
    /// Internal faults (a poisoned lock) as a response; nothing protocol-shaped.
    fn from((status, message): (u16, String)) -> Self {
        error_response(Dialect::Gcs, status, &message)
    }
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

/// Whether a presented download token is one of the object's, compared in constant time.
///
/// The token is an explicit bearer capability (section 12.2), so the comparison must not leak
/// a prefix, and it binds to the metadata the caller actually resolved: the same bucket, the
/// same decoded object name and the same generation the request selected.
fn download_token_matches(meta: Option<&ObjectMetadata>, presented: Option<&str>) -> bool {
    use subtle::ConstantTimeEq as _;
    let (Some(meta), Some(presented)) = (meta, presented) else {
        return false;
    };
    let mut matched = false;
    for token in &meta.download_tokens {
        let same = token.len() == presented.len()
            && bool::from(token.as_bytes().ct_eq(presented.as_bytes()));
        matched |= same;
    }
    matched
}

/// The fireemu error envelope, used only where no official response shape exists: the
/// fault plan's injected errors and the App Check denials (section 17), which the official
/// emulator cannot produce at all.
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

// ------------------------------------------------------------------------------------------
// official response shapes
// ------------------------------------------------------------------------------------------

/// The express `STATUS_CODES` text the official emulator's `sendStatus` answers with.
const fn status_text(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        501 => "Not Implemented",
        _ => "",
    }
}

/// `res.sendStatus(status)`: the status text as `text/plain; charset=utf-8`.
fn plain_status(status: u16) -> StorageResponse {
    StorageResponse {
        status,
        headers: vec![("content-type".into(), "text/plain; charset=utf-8".into())],
        body: status_text(status).as_bytes().to_vec(),
    }
}

/// `res.status(status).send(text)`: express types a bare string as HTML.
fn html_text(status: u16, text: &str) -> StorageResponse {
    StorageResponse {
        status,
        headers: vec![("content-type".into(), "text/html; charset=utf-8".into())],
        body: text.as_bytes().to_vec(),
    }
}

/// The Firebase dialect's error envelope: `{"error": {"code", "message"}}`, no more.
fn fb_json_error(status: u16, message: &str) -> StorageResponse {
    StorageResponse::json(
        status,
        &json!({"error": {"code": status, "message": message}}),
    )
}

/// The Firebase dialect's rules denial, worded per operation as the official emulator words
/// it. The detailed rules trace is a control-API diagnostic, not an API body.
fn fb_denied(method: Method) -> StorageResponse {
    let verb = match method {
        Method::Get => "READ",
        Method::List => "LIST",
        Method::Create | Method::Update | Method::Delete => "WRITE",
    };
    fb_json_error(403, &format!("Permission denied. No {verb} permission."))
}

fn set_rules_error(message: &str) -> StorageResponse {
    StorageResponse::json(400, &json!({"message": message}))
}

fn set_rules(state: &StorageState, body: &[u8]) -> StorageResponse {
    let parsed: Value = match serde_json::from_slice(body) {
        Ok(value) => value,
        Err(_) => return set_rules_error("Request body must be valid JSON"),
    };
    let Some(files) = parsed.pointer("/rules/files").and_then(Value::as_array) else {
        return set_rules_error("Request body must include 'rules.files' array");
    };
    if files.is_empty() {
        return set_rules_error("Request body must include 'rules.files' array");
    }
    if files.len() != 1 {
        return set_rules_error("Request body must include exactly one rules file");
    }
    let Some(file) = files[0].as_object() else {
        return set_rules_error("Each rules file must contain string 'name' and 'content' fields");
    };
    let (Some(_name), Some(content)) = (
        file.get("name").and_then(Value::as_str),
        file.get("content").and_then(Value::as_str),
    ) else {
        return set_rules_error("Each rules file must contain string 'name' and 'content' fields");
    };
    let loaded = match LoadedRules::from_source(content) {
        Ok(loaded) => loaded,
        Err(_) => {
            return set_rules_error("There was an error updating rules, see logs for more details")
        }
    };
    match state.rules.write() {
        Ok(mut active) => *active = loaded,
        Err(_) => {
            return StorageResponse::json(500, &json!({"message": "Internal error updating rules"}))
        }
    }
    StorageResponse::json(200, &json!({"message": "Rules updated successfully"}))
}

/// The JSON API's Google error envelope.
fn gcs_json_error(status: u16, message: &str, reason: &str) -> StorageResponse {
    StorageResponse::json(
        status,
        &json!({"error": {"code": status, "message": message, "errors": [{"domain": "global", "reason": reason, "message": message}]}}),
    )
}

/// The JSON API's missing-object answer: a plain sentence for a media request, the JSON
/// envelope otherwise.
///
/// The media branch is a **documented divergence** from the official emulator, which types
/// this body `text/html`: the message reflects the decoded object name, and the route is a
/// top-level `GET` reachable with no `Origin` (so the loopback CORS guard never fires), so a
/// `text/html` reflection is a stored-data-stealing reflected-XSS vector on the emulator's
/// own origin (the JSON API dialect is unauthenticated and rules-free). fireemu answers the
/// identical status and body bytes as `text/plain`, which no browser executes. The
/// divergence is pinned in `conformance/storage-matrix.json`.
fn gcs_no_such_object(bucket: &str, name: &str, media: bool) -> StorageResponse {
    let message = format!("No such object: {bucket}/{name}");
    if media {
        plain_text(404, &message)
    } else {
        gcs_json_error(404, &message, "notFound")
    }
}

/// A `text/plain; charset=utf-8` body of arbitrary text (used where the official emulator
/// reflects caller-influenced text that must never be typed as HTML).
fn plain_text(status: u16, text: &str) -> StorageResponse {
    StorageResponse {
        status,
        headers: vec![("content-type".into(), "text/plain; charset=utf-8".into())],
        body: text.as_bytes().to_vec(),
    }
}

/// HTTP status and plain message of a core error, for the JSON API's envelope paths.
fn core_err(e: StorageError) -> (u16, String, &'static str) {
    match e {
        StorageError::NotFound => (
            404,
            "Not Found. Could not get object".to_owned(),
            "notFound",
        ),
        StorageError::PreconditionFailed(m) | StorageError::NotModified(m) => {
            (412, m, "conditionNotMet")
        }
        StorageError::TooLarge => (413, "object too large".to_owned(), "uploadTooLarge"),
        StorageError::MetadataTooLarge => (400, "custom metadata too large".to_owned(), "invalid"),
        StorageError::UploadNotFound => (404, "upload session not found".to_owned(), "notFound"),
        StorageError::UploadOffset { expected } => (
            400,
            format!("upload offset mismatch, expected {expected}"),
            "invalid",
        ),
        StorageError::UploadFinalized => (400, "upload already finalized".to_owned(), "invalid"),
        StorageError::UploadSizeMismatch => (400, "upload size mismatch".to_owned(), "invalid"),
        StorageError::TooManyUploads => (
            429,
            "too many open upload sessions".to_owned(),
            "rateLimitExceeded",
        ),
        StorageError::ChecksumMismatch(m) => (400, format!("checksum mismatch: {m}"), "invalid"),
        StorageError::InvalidImportedIdentity(m) => {
            (400, format!("invalid imported identity: {m}"), "invalid")
        }
        StorageError::IdentityExhausted => (
            507,
            "storage identity space exhausted".to_owned(),
            "internalError",
        ),
    }
}

fn gcs_core_err(e: StorageError) -> StorageResponse {
    let (status, message, reason) = core_err(e);
    gcs_json_error(status, &message, reason)
}

fn fb_core_err(e: StorageError) -> StorageResponse {
    match e {
        // The official Firebase dialect answers missing things with a bare status.
        StorageError::NotFound | StorageError::UploadNotFound => plain_status(404),
        other => {
            let (status, message, _) = core_err(other);
            fb_json_error(status, &message)
        }
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

/// The official emulator's `encodeRFC5987`: `encodeURIComponent`, with `'`, `(`, `)` and
/// `*` escaped and `|`, `` ` `` and `^` kept literal.
fn rfc5987_encode(s: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.!~|`^".contains(&b) {
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

// ------------------------------------------------------------------------------------------
// multipart
// ------------------------------------------------------------------------------------------

/// multipart/related, parsed the way the official emulator parses it: the body must hold
/// exactly a metadata part and a data part, each led by a `Content-Type` line, and exactly
/// the framing line break before a delimiter is removed, so payloads ending in line breaks
/// survive intact. The error messages are the official ones, verbatim.
///
/// The request buffer is taken by value and the data part is carved out of it in place
/// (`truncate` + `drain`), so a near-limit payload is never duplicated (`STG-MEM-02`).
fn parse_multipart(content_type: &str, mut body: Vec<u8>) -> Result<(Value, Vec<u8>), String> {
    if !content_type.starts_with("multipart/related") {
        return Err(format!("Bad content type. {content_type}"));
    }
    let Some(boundary) = content_type
        .split(';')
        .map(str::trim)
        .find_map(|p| p.strip_prefix("boundary="))
        .map(|b| b.trim_matches('"').trim_matches('\'').to_owned())
    else {
        return Err(format!("Bad content type. {content_type}"));
    };
    if boundary.len() > MAX_MULTIPART_BOUNDARY_LEN {
        return Err("multipart boundary is too long".to_owned());
    }
    let delimiter = format!("--{boundary}").into_bytes();
    let parts = split_multipart_parts(&body, &delimiter)
        .map_err(|()| "Unexpected number of parts in request body".to_owned())?;
    if parts.len() != 2 {
        return Err("Unexpected number of parts in request body".to_owned());
    }
    for (headers, _) in &parts {
        if !headers.contains_key("content-type") {
            return Err(
                "Failed to parse multipart request body part. Missing content type.".to_owned(),
            );
        }
    }
    let metadata: Value = serde_json::from_slice(&body[parts[0].1.clone()])
        .map_err(|_| "Unexpected number of parts in request body".to_owned())?;
    let data = parts[1].1.clone();
    // Carve the data part out of the request buffer: `truncate` and `drain` keep the
    // allocation, so the payload is moved inside its own buffer instead of copied.
    body.truncate(data.end);
    body.drain(..data.start);
    Ok((metadata, body))
}

/// Ranges of the parts of a multipart body (headers parsed, content borrowed as a range).
type MultipartPart = (BTreeMap<String, String>, std::ops::Range<usize>);

fn split_multipart_parts(body: &[u8], delimiter: &[u8]) -> Result<Vec<MultipartPart>, ()> {
    let mut parts: Vec<MultipartPart> = Vec::new();
    let Some(mut cursor) = find_delimiter(body, 0, delimiter) else {
        return Err(());
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
        let Some(next) = find_delimiter(body, p, delimiter) else {
            return Err(());
        };
        let mut end = next;
        if body[p..end].ends_with(b"\r\n") {
            end -= 2;
        } else if body[p..end].ends_with(b"\n") {
            end -= 1;
        }
        let (headers, content_start) = split_headers(&body[p..end]);
        parts.push((headers, (p + content_start)..end));
        cursor = next;
    }
    if parts.is_empty() {
        return Err(());
    }
    Ok(parts)
}

/// Position of the next delimiter at or after `from` that starts a line.
fn find_delimiter(body: &[u8], from: usize, delimiter: &[u8]) -> Option<usize> {
    // A delimiter line begins at the body start or immediately after a '\n', so only those
    // offsets are candidates. Walking newline-to-newline visits each byte a bounded number of
    // times -- O(N) -- rather than testing the delimiter at every offset, which is O(N*M): a
    // body of pure delimiter bytes used to make every offset match, get rejected for not
    // starting a line, and advance by a single byte, burning minutes of CPU on one
    // unauthenticated request (S-3).
    let mut pos = if from == 0 || body.get(from.wrapping_sub(1)) == Some(&b'\n') {
        from
    } else {
        next_line_start(body, from)?
    };
    loop {
        if pos + delimiter.len() <= body.len() && &body[pos..pos + delimiter.len()] == delimiter {
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
            if line_end {
                return Some(pos);
            }
        }
        pos = next_line_start(body, pos)?;
    }
}

/// The index just after the next `'\n'` at or after `from`, or `None` when there is none.
/// Each call only moves forward, so a scan driven by it is linear in the body length.
fn next_line_start(body: &[u8], from: usize) -> Option<usize> {
    body.get(from..)?
        .iter()
        .position(|&b| b == b'\n')
        .map(|i| from + i + 1)
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Part headers and the offset of the part content inside `part`.
fn split_headers(part: &[u8]) -> (BTreeMap<String, String>, usize) {
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
            (headers, i + n)
        }
        None => (BTreeMap::new(), 0),
    }
}

/// One parsed part of a `multipart/form-data` body (the XML-ish POST upload).
enum FormPart {
    Field {
        name: String,
        value: String,
    },
    File {
        content_type: Option<String>,
        data: std::ops::Range<usize>,
    },
}

fn parse_form_data(content_type: &str, body: &[u8]) -> Result<Vec<FormPart>, String> {
    let Some(boundary) = content_type
        .split(';')
        .map(str::trim)
        .find_map(|p| p.strip_prefix("boundary="))
        .map(|b| b.trim_matches('"').trim_matches('\'').to_owned())
    else {
        return Err(format!("Bad content type. {content_type}"));
    };
    if boundary.len() > MAX_MULTIPART_BOUNDARY_LEN {
        return Err("multipart boundary is too long".to_owned());
    }
    let delimiter = format!("--{boundary}").into_bytes();
    let parts = split_multipart_parts(body, &delimiter).map_err(|()| {
        "Failed to parse multipart part: Missing header-body separator.".to_owned()
    })?;
    let mut out = Vec::new();
    for (headers, range) in parts {
        let disposition = headers
            .get("content-disposition")
            .cloned()
            .unwrap_or_default();
        let param = |name: &str| {
            disposition.split(';').map(str::trim).find_map(|p| {
                p.strip_prefix(&format!("{name}="))
                    .map(|v| v.trim_matches('"').to_owned())
            })
        };
        let name = param("name").ok_or_else(|| {
            "Failed to parse multipart form-data. Missing 'name' in Content-Disposition header."
                .to_owned()
        })?;
        if param("filename").is_some() {
            out.push(FormPart::File {
                content_type: headers.get("content-type").cloned(),
                data: range,
            });
        } else {
            let value = String::from_utf8_lossy(&body[range]).into_owned();
            out.push(FormPart::Field { name, value });
        }
    }
    Ok(out)
}

// ------------------------------------------------------------------------------------------
// metadata JSON
// ------------------------------------------------------------------------------------------

/// One string out of an incoming JSON metadata value, coerced the way the official
/// emulator coerces custom metadata values (`JSON.stringify` for anything not a string).
fn coerce_custom_value(v: &Value) -> Option<String> {
    match v {
        Value::Null => None,
        Value::String(s) => Some(s.clone()),
        other => Some(other.to_string()),
    }
}

/// Rejects a metadata string that carries a C0 control character (`0x00`-`0x1F`) or `DEL`
/// (`0x7F`).
///
/// The five standard fields (`contentType`, `contentDisposition`, `contentEncoding`,
/// `contentLanguage`, `cacheControl`) are echoed verbatim into response headers by
/// [`send_file_bytes`] and [`with_object_headers`]; a `CR`/`LF` in one would be a header
/// value hyper refuses, and hyper's refusal is a deferred error that would collapse the whole
/// response to a silent empty 200 (S-4). Rejecting the character at the input boundary is
/// also what the project's input-canonicalization rule requires of every stored string. The
/// object name is already held to the same rule (`name.rs`), so this closes the gap for
/// metadata.
fn header_safe(field: &str, value: &str) -> Result<(), String> {
    if value.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err(format!("{field} contains a control character"));
    }
    Ok(())
}

/// Custom metadata whose keys and values are all control-character-free.
fn checked_custom(m: &Map<String, Value>) -> Result<BTreeMap<String, String>, String> {
    let mut out = BTreeMap::new();
    for (k, val) in m {
        header_safe(&format!("metadata key {k:?}"), k)?;
        if let Some(sv) = coerce_custom_value(val) {
            header_safe(&format!("metadata.{k}"), &sv)?;
            out.insert(k.clone(), sv);
        }
    }
    Ok(out)
}

fn new_metadata_from_json(v: &Value, content_type: Option<String>) -> Result<NewMetadata, String> {
    let s = |k: &str| v.get(k).and_then(Value::as_str).map(str::to_owned);
    // `metadata: null` and no `metadata` member both leave custom metadata undefined; an
    // object defines it, with `null` values dropped and non-strings stringified.
    let custom = match v.get("metadata") {
        Some(Value::Object(m)) => Some(checked_custom(m)?),
        _ => None,
    };
    let meta = NewMetadata {
        content_type: s("contentType").or(content_type),
        content_disposition: s("contentDisposition"),
        content_encoding: s("contentEncoding"),
        content_language: s("contentLanguage"),
        cache_control: s("cacheControl"),
        custom,
    };
    for (name, val) in [
        ("contentType", &meta.content_type),
        ("contentDisposition", &meta.content_disposition),
        ("contentEncoding", &meta.content_encoding),
        ("contentLanguage", &meta.content_language),
        ("cacheControl", &meta.cache_control),
    ] {
        if let Some(val) = val {
            header_safe(name, val)?;
        }
    }
    Ok(meta)
}

fn patch_from_json(v: &Value) -> Result<MetadataPatch, String> {
    let field = |k: &str| -> Result<Option<Option<String>>, String> {
        match v.get(k) {
            None => Ok(None),
            Some(Value::Null) => Ok(Some(None)),
            Some(x) => {
                let val = x.as_str().map(str::to_owned);
                if let Some(val) = &val {
                    header_safe(k, val)?;
                }
                Ok(Some(val))
            }
        }
    };
    let custom = match v.get("metadata") {
        Some(Value::Null) => Some(CustomMetadataPatch::Clear),
        Some(Value::Object(m)) => {
            let mut out = BTreeMap::new();
            for (k, val) in m {
                header_safe(&format!("metadata key {k:?}"), k)?;
                let sv = coerce_custom_value(val);
                if let Some(sv) = &sv {
                    header_safe(&format!("metadata.{k}"), sv)?;
                }
                out.insert(k.clone(), sv);
            }
            Some(CustomMetadataPatch::Merge(out))
        }
        _ => None,
    };
    Ok(MetadataPatch {
        content_type: field("contentType")?,
        content_disposition: field("contentDisposition")?,
        content_encoding: field("contentEncoding")?,
        content_language: field("contentLanguage")?,
        cache_control: field("cacheControl")?,
        custom,
    })
}

/// The Firebase dialect's metadata document (`OutgoingFirebaseMetadata`): `crc32c` is the
/// decimal spelling, `contentEncoding` defaults to `identity` in the response, and the
/// `metadata` member exists exactly when custom metadata is defined, even when empty.
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
        "crc32c": m.crc32c.to_string(),
        "etag": m.etag(),
        "downloadTokens": m.download_tokens.join(","),
        "contentEncoding": m.content_encoding.as_deref().unwrap_or("identity"),
    });
    if m.custom_defined {
        v["metadata"] = json!(m.custom);
    }
    for (k, val) in [
        ("cacheControl", &m.cache_control),
        ("contentDisposition", &m.content_disposition),
        ("contentLanguage", &m.content_language),
    ] {
        if let Some(x) = val {
            v[k] = Value::String(x.clone());
        }
    }
    v
}

/// The JSON API's object resource (`CloudStorageObjectMetadata`): download tokens ride
/// inside `metadata.firebaseStorageDownloadTokens`, and the member is dropped when there is
/// nothing to carry.
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
    });
    let mut metadata = m.custom.clone();
    if !m.download_tokens.is_empty() {
        metadata.insert(TOKENS_KEY.to_owned(), m.download_tokens.join(","));
    }
    if !metadata.is_empty() {
        v["metadata"] = json!(metadata);
    }
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

/// The object headers the official emulator's `setObjectHeaders` adds to its metadata-update
/// and token responses.
fn with_object_headers(mut response: StorageResponse, m: &ObjectMetadata) -> StorageResponse {
    for (name, value) in [
        ("content-disposition", &m.content_disposition),
        ("content-encoding", &m.content_encoding),
        ("cache-control", &m.cache_control),
        ("content-language", &m.content_language),
    ] {
        if let Some(v) = value {
            response.headers.push((name.to_owned(), v.clone()));
        }
    }
    response
}

// ------------------------------------------------------------------------------------------
// rules
// ------------------------------------------------------------------------------------------

/// Caller of a Storage request.
#[derive(Debug, Clone, PartialEq)]
pub enum Principal {
    /// Admin credentials (the JSON API dialect, `Bearer owner` / `Firebase owner`): rules
    /// bypassed.
    Owner,
    /// A verified end user.
    User(AuthContext),
    /// No credentials.
    Anonymous,
}

/// The rules `resource` of a stored object. `crc32c` is the decimal spelling the official
/// rules runtime receives; `cacheControl` and `contentLanguage` are production resource
/// fields the official runtime omits — fireemu keeps them, as published in the contract.
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
    map.insert("crc32c".into(), s(&m.crc32c.to_string()));
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

/// The `request.resource` of an upload: the whole prospective object, exactly as the
/// official emulator builds it before its rules run — generation and timestamps included.
/// The `firebaseStorageDownloadTokens` key never reaches `request.resource.metadata`.
#[allow(clippy::too_many_arguments)]
fn incoming_rules_value(
    bucket: &BucketName,
    name: &ObjectName,
    meta: &NewMetadata,
    size: u64,
    hashes: ([u8; 16], u32),
    generation: u64,
    now: LogicalInstant,
) -> RulesValue {
    let mut map = BTreeMap::new();
    let s = |v: &str| RulesValue::String(v.to_owned());
    map.insert("name".into(), s(name.as_str()));
    map.insert("bucket".into(), s(bucket.as_str()));
    map.insert(
        "generation".into(),
        RulesValue::Int(i64::try_from(generation).unwrap_or(i64::MAX)),
    );
    map.insert("metageneration".into(), RulesValue::Int(1));
    map.insert(
        "size".into(),
        RulesValue::Int(i64::try_from(size).unwrap_or(i64::MAX)),
    );
    map.insert("timeCreated".into(), RulesValue::Timestamp(now.as_nanos()));
    map.insert("updated".into(), RulesValue::Timestamp(now.as_nanos()));
    map.insert(
        "md5Hash".into(),
        s(&fireemu_core_storage::hash::base64(&hashes.0)),
    );
    map.insert("crc32c".into(), s(&hashes.1.to_string()));
    map.insert("etag".into(), s(&format!("\"{generation}-1\"")));
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
        RulesValue::Map(
            meta.custom
                .iter()
                .flatten()
                .filter(|(k, _)| k.as_str() != TOKENS_KEY)
                .map(|(k, v)| (k.clone(), s(v)))
                .collect(),
        ),
    );
    RulesValue::Map(map)
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

    /// The caller of a request on `bucket`: an end-user token is verified against the
    /// store of its audience, which must be the bucket's project (production Storage
    /// accepts only tokens minted for its own project).
    ///
    /// Under the `firebase` profile a value that does not even decode as a JWT is an
    /// anonymous caller, as the official emulator's `jwt.decode` answers; a token that
    /// decodes but names another project's audience, or carries a signature that does not
    /// verify, is still refused — the published divergence from the official emulator's
    /// verify-nothing behaviour.
    fn principal(&self, authorization: Option<&str>, bucket: &str) -> Result<Principal, String> {
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
        let project = self.project_of_bucket(bucket);
        let store_arc = self
            .auth
            .store_for(&project)
            .ok_or_else(|| format!("invalid ID token: no Auth store for project {project:?}"))?;
        let parent = store_arc
            .lock()
            .map_err(|_| "auth store poisoned".to_owned())?;
        // The audience is checked before the signature so a token of another session
        // says so, instead of failing as an unknown user of this one.
        let decoded = fireemu_core_auth::jwt::decode_token(token, parent.signer());
        let Ok(decoded_token) = decoded else {
            return if self.token_acceptance == TokenAcceptance::EmulatorMock {
                Ok(Principal::Anonymous)
            } else {
                Err("invalid ID token: not a decodable JWT".to_owned())
            };
        };
        let aud = decoded_token
            .payload
            .get("aud")
            .and_then(fireemu_core_types::json::JsonValue::as_str)
            .unwrap_or_default()
            .to_owned();
        if aud != project {
            return Err(format!(
                "invalid ID token: audience {aud:?} does not match the bucket's project {project:?}"
            ));
        }
        let tenant = decoded_token
            .payload
            .get("firebase")
            .and_then(|firebase| firebase.get("tenant"))
            .and_then(fireemu_core_types::json::JsonValue::as_str)
            .map(str::to_owned);
        drop(parent);
        let store_arc = match tenant {
            Some(tenant) => self
                .auth
                .tenant_store(&project, &tenant)
                .ok_or_else(|| format!("invalid ID token: unknown tenant {tenant:?}"))?,
            None => store_arc,
        };
        let store = store_arc
            .lock()
            .map_err(|_| "auth store poisoned".to_owned())?;
        let decoded = verify_rules_token(token, &store, self.now(), self.token_acceptance)
            .map_err(|e| format!("invalid ID token: {e}"))?;
        drop(store);
        let ctx = AuthContext::from_id_token_json(&decoded.payload_json)
            .map_err(|e| format!("invalid ID token claims: {e}"))?;
        Ok(Principal::User(ctx))
    }

    /// Evaluates the Storage rules; `Ok(())` = allowed. The Firebase dialect is the only
    /// caller: the JSON API is a privileged surface on which rules never run, as in the
    /// official emulator.
    fn authorize(
        &self,
        principal: &Principal,
        method: Method,
        bucket: &BucketName,
        object_path: &str,
        resource: Option<RulesValue>,
        request_resource: RulesValue,
    ) -> Result<(), StorageResponse> {
        if matches!(principal, Principal::Owner) {
            return Ok(());
        }
        let rules = self
            .rules
            .read()
            .map_err(|_| error_response(Dialect::Firebase, 500, "rules poisoned"))?;
        let Some(ruleset) = &rules.ruleset else {
            return Ok(());
        };
        if method == Method::List && ruleset.version.as_deref() != Some("2") {
            // Storage list requests exist only under rules_version = '2'; a v1 `read` never
            // grants them.
            return Err(fb_denied(Method::List));
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
            resource: Some(resource.unwrap_or(RulesValue::Null)),
            request_resource: Some(request_resource),
            time_unix_nanos: self.now().as_nanos(),
            abstract_path: false,
            request_query: None,
        };
        let access = self.firestore.as_deref().map(|a| a as &dyn DocumentAccess);
        match evaluate_request_with(ruleset, &ctx, access).decision {
            Decision::Allow => Ok(()),
            Decision::Deny(_) => Err(fb_denied(method)),
        }
    }
}

// ------------------------------------------------------------------------------------------
// routing
// ------------------------------------------------------------------------------------------

/// Which `/storage/v1`-family spelling addressed an object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GcsSpelling {
    /// `/b/{bucket}/o/{name}` — the only spelling the official emulator registers for
    /// PATCH and copy.
    Short,
    /// `/storage/v1/b/{bucket}/o/{name}` — GET and DELETE only upstream.
    StorageV1,
    /// `/download/storage/v1/b/{bucket}/o/{name}` — GET only.
    Download,
}

/// Parsed target of a request, method already taken into account the way the official
/// emulator's express routers register their handlers.
enum Route {
    /// `PUT /internal/setRules`, used by `@firebase/rules-unit-testing`.
    SetRules,
    /// `GET /v0/` -> `{"emulator": "storage"}`.
    FbRoot,
    /// `/v0/b/{bucket}/o`: list (GET), upload (POST / PUT).
    FbBucket { bucket: String },
    /// `/v0/b/{bucket}/o/{name}`.
    FbObject { bucket: String, name: String },
    /// `GET /b`: the bucket listing (short spelling only).
    GcsListBuckets,
    /// `GET /b/{bucket}/o` or `GET /storage/v1/b/{bucket}/o`.
    GcsList { bucket: String },
    /// One object on the JSON API.
    GcsObject {
        bucket: String,
        name: String,
        spelling: GcsSpelling,
    },
    /// `POST /b/{b}/o/{n}/(copyTo|rewriteTo)/b/{db}/o/{dn}` (short spelling only).
    GcsCopy {
        bucket: String,
        name: String,
        rewrite: bool,
        dst_bucket: String,
        dst_name: String,
    },
    /// `POST /b/{b}/o/{n}/acl` (short spelling only).
    GcsAcl { bucket: String, name: String },
    /// `/upload/storage/v1/b/{bucket}/o` (POST and PUT).
    GcsUpload { bucket: String },
    /// `POST /{bucket}`: the form-data upload.
    FormUpload { bucket: String },
    /// The `GET /{bucket}/{object...}` fallback: bytes when the object exists.
    XmlStyle { bucket: String, name: String },
    /// Everything else on the JSON API side: the official catch-all.
    NotImplemented,
}

#[allow(clippy::too_many_lines)]
fn route(method: &str, path: &str) -> Result<Route, String> {
    let mut segments: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    while segments.last() == Some(&"") {
        segments.pop();
    }
    let d = decode_segment;
    // The Firebase router is mounted at /v0; whatever it does not match falls through to
    // the JSON API routers, exactly as the official emulator stacks them.
    if segments.first() == Some(&"v0") {
        match (method, &segments[1..]) {
            ("GET", []) => return Ok(Route::FbRoot),
            ("GET" | "POST" | "PUT", ["b", b, "o"]) => {
                return Ok(Route::FbBucket { bucket: d(b)? });
            }
            ("GET" | "POST" | "PUT" | "PATCH" | "DELETE", ["b", b, "o", n]) => {
                return Ok(Route::FbObject {
                    bucket: d(b)?,
                    name: d(n)?,
                });
            }
            _ => return fallthrough(method, &segments),
        }
    }
    match (method, segments.as_slice()) {
        ("PUT", ["internal", "setRules"]) => Ok(Route::SetRules),
        ("GET", ["b"]) => Ok(Route::GcsListBuckets),
        ("GET", ["b", b, "o"] | ["storage", "v1", "b", b, "o"]) => {
            Ok(Route::GcsList { bucket: d(b)? })
        }
        ("GET" | "PATCH" | "DELETE", ["b", b, "o", n]) => Ok(Route::GcsObject {
            bucket: d(b)?,
            name: d(n)?,
            spelling: GcsSpelling::Short,
        }),
        ("GET" | "DELETE", ["storage", "v1", "b", b, "o", n]) => Ok(Route::GcsObject {
            bucket: d(b)?,
            name: d(n)?,
            spelling: GcsSpelling::StorageV1,
        }),
        ("GET", ["download", "storage", "v1", "b", b, "o", n]) => Ok(Route::GcsObject {
            bucket: d(b)?,
            name: d(n)?,
            spelling: GcsSpelling::Download,
        }),
        ("POST", ["b", b, "o", n, "acl"]) => Ok(Route::GcsAcl {
            bucket: d(b)?,
            name: d(n)?,
        }),
        ("POST", ["b", b, "o", n, verb, "b", db, "o", dn])
            if *verb == "copyTo" || *verb == "rewriteTo" =>
        {
            Ok(Route::GcsCopy {
                bucket: d(b)?,
                name: d(n)?,
                rewrite: *verb == "rewriteTo",
                dst_bucket: d(db)?,
                dst_name: d(dn)?,
            })
        }
        ("POST" | "PUT", ["upload", "storage", "v1", "b", b, "o"]) => {
            Ok(Route::GcsUpload { bucket: d(b)? })
        }
        _ => fallthrough(method, &segments),
    }
}

/// What the official JSON API router does with anything its named routes did not match:
/// a GET with a bucket-shaped path is the XML-ish object read, a single-segment POST is the
/// form-data upload, and everything else is the 501 catch-all.
fn fallthrough(method: &str, segments: &[&str]) -> Result<Route, String> {
    match (method, segments) {
        ("GET", [bucket, rest @ ..]) if !rest.is_empty() => {
            let name = rest
                .iter()
                .map(|s| decode_segment(s))
                .collect::<Result<Vec<_>, _>>()?
                .join("/");
            Ok(Route::XmlStyle {
                bucket: decode_segment(bucket)?,
                name,
            })
        }
        ("POST", [bucket]) => Ok(Route::FormUpload {
            bucket: decode_segment(bucket)?,
        }),
        _ => Ok(Route::NotImplemented),
    }
}

/// Strictly parsed write preconditions (JSON API only; the official emulator ignores them,
/// fireemu honours them as production does — a published divergence).
fn precondition(params: &BTreeMap<String, String>) -> Result<Precondition, StorageResponse> {
    precondition_named(params, "if")
}

fn precondition_named(
    params: &BTreeMap<String, String>,
    prefix: &str,
) -> Result<Precondition, StorageResponse> {
    let pre = Precondition {
        if_generation_match: u64_param(params, &format!("{prefix}GenerationMatch"))?,
        if_metageneration_match: u64_param(params, &format!("{prefix}MetagenerationMatch"))?,
        if_generation_not_match: u64_param(params, &format!("{prefix}GenerationNotMatch"))?,
        if_metageneration_not_match: u64_param(params, &format!("{prefix}MetagenerationNotMatch"))?,
    };
    if (pre.if_generation_match.is_some() && pre.if_generation_not_match.is_some())
        || (pre.if_metageneration_match.is_some() && pre.if_metageneration_not_match.is_some())
    {
        return Err(gcs_json_error(
            400,
            &format!(
                "{prefix}...Match and {prefix}...NotMatch on the same field are mutually exclusive"
            ),
            "invalid",
        ));
    }
    Ok(pre)
}

fn u64_param(params: &BTreeMap<String, String>, key: &str) -> Result<Option<u64>, StorageResponse> {
    match params.get(key) {
        None => Ok(None),
        Some(v) => v
            .parse::<u64>()
            .map(Some)
            .map_err(|_| gcs_json_error(400, &format!("invalid {key}: {v:?}"), "invalid")),
    }
}

/// Applies a `generation` / `sourceGeneration` selector (JSON API only): a generation other
/// than the current one is not available (historical versions are not kept).
fn select_generation(
    meta: Option<ObjectMetadata>,
    params: &BTreeMap<String, String>,
    key: &str,
) -> Result<Option<ObjectMetadata>, StorageResponse> {
    match u64_param(params, key)? {
        Some(g) => Ok(meta.filter(|m| m.generation == g)),
        None => Ok(meta),
    }
}

/// Expected hashes of an upload (`X-Goog-Hash` and the `md5Hash` / `crc32c` metadata
/// fields); a mismatch with the received bytes refuses the upload before it is committed
/// (the official emulator verifies nothing — a published divergence).
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
                    fireemu_core_storage::hash::base64(&e),
                    fireemu_core_storage::hash::base64(&digest)
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
                    fireemu_core_storage::hash::base64(&e.to_be_bytes()),
                    fireemu_core_storage::hash::base64(&crc.to_be_bytes())
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

// ------------------------------------------------------------------------------------------
// App Check admission (specification sections 12-13)
// ------------------------------------------------------------------------------------------

/// Which privileged credential a Storage route already authenticated (section 12.2).
///
/// Two surfaces bypass. The JSON API dialect is the privileged server surface the Admin SDK
/// and `gcloud` use, but only once the caller presented the emulator's owner credential: the
/// path shape alone is not a credential, and an unauthenticated request to a JSON API path is
/// an ordinary request as far as App Check is concerned. A Firebase download URL bypasses only
/// when it carries a download token bound, in constant time, to the object the request
/// resolved.
fn storage_bypass(
    state: &StorageState,
    route: &Route,
    method: &str,
    params: &BTreeMap<String, String>,
    json_api_authenticated: bool,
) -> PrivilegedBypass {
    if json_api_authenticated {
        return PrivilegedBypass::StorageJsonApi;
    }
    let Route::FbObject { bucket, name } = route else {
        return PrivilegedBypass::None;
    };
    if method != "GET" || !params.contains_key("token") {
        return PrivilegedBypass::None;
    }
    let (Ok(b), Ok(n)) = (bucket_name(bucket), object_name(name)) else {
        return PrivilegedBypass::None;
    };
    let Ok(store) = state.store() else {
        return PrivilegedBypass::None;
    };
    let meta = store.get(&b, &n).cloned();
    if download_token_matches(meta.as_ref(), params.get("token").map(String::as_str)) {
        PrivilegedBypass::StorageDownloadToken
    } else {
        PrivilegedBypass::None
    }
}

/// What App Check admitted for one Storage request, as far as a resumable upload session cares
/// (specification section 13.2).
///
/// A resumable upload outlives its initiating request, so the initiation records the app it was
/// admitted for and every later request on that session has to present the same one. `None`
/// everywhere means the session carries no binding: the service is `off` or `unenforced`, or the
/// route authenticated a privileged credential instead of an App Check token.
#[derive(Debug, Clone, Default)]
pub struct AdmittedApp {
    /// The verified app this request was admitted on, under an `enforced` policy.
    binding: Option<UploadAdmission>,
    /// The route authenticated a privileged credential of its own (section 12.2).
    privileged: bool,
}

impl AdmittedApp {
    /// The binding an upload initiated by this request must record.
    fn binding(&self) -> Option<UploadAdmission> {
        self.binding.clone()
    }

    /// Whether this request may act on a session bound to `expected`.
    ///
    /// A privileged route passes: the bypass matrix already grants it the whole Storage
    /// surface. Anything else must be the same app under the same session epoch, so a token
    /// from another app — and a token minted after a reset — is refused before the session is
    /// read, advanced, finalized or cancelled.
    fn may_continue(&self, expected: Option<&UploadAdmission>) -> bool {
        match expected {
            None => true,
            Some(bound) => self.privileged || self.binding.as_ref() == Some(bound),
        }
    }
}

/// The App Check outcome of a Storage request: the denial to answer with, or what was admitted.
///
/// This runs after the route, the target project and the privileged classification and before
/// the fault plan, the Auth credential, Security Rules and every mutation, so a denied request
/// creates no object generation, no metadata change, no upload session, no upload offset and
/// no Storage event (`INV-APPCHECK-003`).
fn app_check_admission(
    state: &StorageState,
    app_check: &[String],
    dialect: Dialect,
    project_id: &str,
    operation: &'static str,
    bypass: PrivilegedBypass,
) -> Result<AdmittedApp, StorageResponse> {
    let Some(policy) = state.app_check_policy.as_ref() else {
        return Ok(AdmittedApp::default());
    };
    let header = classify_app_check_header(app_check);
    // The epoch comes back from the same registry read as the decision, so the binding a
    // session records and the binding a continuation presents belong to one policy snapshot
    // (`INV-APPCHECK-005`).
    let (decision, epoch) = policy.admit_bound(&AdmissionRequest {
        project_id,
        transport: "http",
        operation,
        bypass,
        header: &header,
        now: state.now(),
    });
    if let Some(reason) = decision.reason {
        let message = if reason == fireemu_core_app_check::verify::PUBLIC_REQUIRED_REASON {
            "App Check token is required by this project's Cloud Storage enforcement."
        } else {
            "App Check token is invalid."
        };
        return Err(error_with_reason(dialect, 403, message, reason));
    }
    // Only an `enforced` policy binds a session: under `unenforced` a client may legitimately
    // stop presenting a token mid-upload, and binding it would enforce by the back door.
    let binding = match (decision.mode, decision.identity(), epoch) {
        (BaselineMode::Enforced, Some(identity), Some(epoch)) => Some(UploadAdmission::new(
            identity.app_id.clone(),
            epoch.claim_text(),
        )),
        _ => None,
    };
    Ok(AdmittedApp {
        binding,
        privileged: bypass.is_privileged(),
    })
}

/// The denial of a resumable request that does not belong to the app that started the session.
///
/// It is refused before the session is read, advanced, finalized or cancelled, so a foreign
/// continuation neither deletes nor advances the upload (specification section 13.2).
fn foreign_session(dialect: Dialect) -> StorageResponse {
    error_with_reason(
        dialect,
        403,
        "this resumable upload belongs to another app",
        fireemu_core_app_check::verify::PUBLIC_DENIAL_REASON,
    )
}

/// The Storage error envelope with the stable App Check reason code (section 17). The public
/// code is `APP_CHECK_REQUIRED` or `APP_CHECK_INVALID`; the detailed reason stays privileged.
fn error_with_reason(
    dialect: Dialect,
    status: u16,
    message: &str,
    reason: &'static str,
) -> StorageResponse {
    let mut response = error_response(dialect, status, message);
    let mut body: Value = serde_json::from_slice(&response.body).unwrap_or(Value::Null);
    if let Some(error) = body.get_mut("error").and_then(Value::as_object_mut) {
        error.insert("reason".to_owned(), json!(reason));
    }
    response.body = serde_json::to_vec(&body).unwrap_or_default();
    response
}

// ------------------------------------------------------------------------------------------
// dispatch
// ------------------------------------------------------------------------------------------

type Outcome = Result<StorageResponse, StorageResponse>;

fn respond(outcome: Outcome) -> StorageResponse {
    match outcome {
        Ok(r) | Err(r) => r,
    }
}

fn bucket_name(bucket: &str) -> Result<BucketName, StorageResponse> {
    BucketName::try_new(bucket)
        .map_err(|e| gcs_json_error(400, &format!("invalid bucket name: {e}"), "invalid"))
}

fn admin_storage_authenticated(state: &StorageState, req: &StorageRequest) -> bool {
    use subtle::ConstantTimeEq as _;

    let (Some(capability), Some(presented)) = (
        state.admin_capability.as_deref(),
        req.header("authorization"),
    ) else {
        return false;
    };
    if req.header("origin").is_some()
        || req.header("sec-fetch-site").is_some()
        || req.header("sec-fetch-mode").is_some()
        || req.header("sec-fetch-dest").is_some()
    {
        return false;
    }
    let expected = format!(
        "Basic {}",
        fireemu_core_storage::hash::base64(format!("fireemu:{capability}").as_bytes())
    );
    presented.len() == expected.len() && bool::from(presented.as_bytes().ct_eq(expected.as_bytes()))
}

fn object_name(name: &str) -> Result<ObjectName, StorageResponse> {
    ObjectName::try_new(name)
        .map_err(|e| gcs_json_error(400, &format!("invalid object name: {e}"), "invalid"))
}

/// The request is taken by value: upload routes move [`StorageRequest::body`] all the way
/// into the object store, so a near-limit upload is never duplicated (`STG-MEM-01`).
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn handle(state: &StorageState, req: StorageRequest) -> StorageResponse {
    let params = query_params(&req.query);
    let host = req.host.clone().unwrap_or_else(|| "127.0.0.1".to_owned());
    let Ok(route) = route(&req.method, &req.path) else {
        return plain_status(400);
    };
    // Admitted for the whole request, before the fault plan is consulted and the token is
    // verified: a reset waits for it, a fault is counted only for a request that runs, and
    // a request cannot verify against the old Auth store and then write into the new
    // session. Requests are synchronous, so the admission is short-lived. Internal rules
    // activation shares the barrier but is not a bucket data operation, so it returns before
    // client App Check, Auth and fault plans.
    let _admitted = state.barrier.as_ref().map(|b| b.admit());
    if matches!(route, Route::SetRules) {
        return set_rules(state, &req.body);
    }
    let dialect = match &route {
        Route::FbRoot | Route::FbBucket { .. } | Route::FbObject { .. } => Dialect::Firebase,
        _ => Dialect::Gcs,
    };
    let operation = match (&route, req.method.as_str()) {
        (Route::FbObject { .. } | Route::GcsObject { .. } | Route::XmlStyle { .. }, "GET") => {
            "storage.read"
        }
        (Route::FbObject { .. } | Route::GcsObject { .. }, "DELETE") => "storage.delete",
        (Route::FbObject { .. } | Route::GcsObject { .. }, _)
        | (
            Route::FbBucket { .. }
            | Route::GcsUpload { .. }
            | Route::GcsCopy { .. }
            | Route::FormUpload { .. },
            "POST" | "PUT",
        ) => "storage.upload",
        (Route::FbBucket { .. } | Route::GcsList { .. }, _) => "storage.list",
        _ => "storage.request",
    };
    let bucket_of_route = match &route {
        Route::FbBucket { bucket }
        | Route::FbObject { bucket, .. }
        | Route::GcsList { bucket }
        | Route::GcsObject { bucket, .. }
        | Route::GcsCopy { bucket, .. }
        | Route::GcsAcl { bucket, .. }
        | Route::GcsUpload { bucket }
        | Route::FormUpload { bucket }
        | Route::XmlStyle { bucket, .. } => bucket.clone(),
        Route::SetRules | Route::FbRoot | Route::GcsListBuckets | Route::NotImplemented => {
            state.project.clone()
        }
    };
    let bucket_project = state.project_of_bucket(&bucket_of_route);
    let authorization = req.header("authorization");
    // The JSON API dialect bypasses Security Rules entirely, as the official emulator's
    // `adminStorageLayer` does. That is deliberately *not* the App Check bypass:
    // specification section 12.2 grants it to the "authenticated JSON API privileged/Admin
    // dialect" and says a dialect-like path is never sufficient on its own, so the App Check
    // bypass requires the emulator's exact owner credential, exactly as Firestore and
    // Identity Toolkit do.
    let json_api_authenticated = dialect == Dialect::Gcs
        && (authorization == Some(crate::identity_toolkit::OWNER_CREDENTIAL)
            || admin_storage_authenticated(state, &req));
    // App Check, before the fault plan, the Auth credential, the rules and every mutation.
    let admitted = if state.app_check_policy.is_some() {
        // The bypass classification reads the object store for a download-token URL, so it
        // runs only when a policy exists: an `off` service does no work at all (spec 12.1).
        let bypass = storage_bypass(state, &route, &req.method, &params, json_api_authenticated);
        match app_check_admission(
            state,
            &req.app_check,
            dialect,
            &bucket_project,
            operation,
            bypass,
        ) {
            Ok(admitted) => admitted,
            Err(denial) => return denial,
        }
    } else {
        AdmittedApp::default()
    };
    if let Some(refused) = fault_response(state, dialect, &bucket_project, operation) {
        return refused;
    }
    let principal = match dialect {
        // The whole JSON API side is the privileged dialect: rules never run there.
        Dialect::Gcs => Principal::Owner,
        Dialect::Firebase => match state.principal(authorization, &bucket_of_route) {
            Ok(p) => p,
            Err(e) => return error_response(dialect, 401, &e),
        },
    };
    let method = req.method.clone();
    if let Route::GcsCopy { dst_bucket, .. } = &route {
        let dst_project = state.project_of_bucket(dst_bucket);
        if dst_project != bucket_project {
            // A copy across sessions is a fireemu tenancy boundary the single-project
            // official emulator cannot observe; the destination's fault plan has its say.
            if !json_api_authenticated {
                return gcs_json_error(
                    403,
                    "the destination bucket belongs to another project",
                    "forbidden",
                );
            }
            if let Some(refused) = fault_response(state, dialect, &dst_project, "storage.upload") {
                return refused;
            }
        }
    }
    let outcome = match route {
        Route::SetRules => unreachable!("setRules returns before Storage data dispatch"),
        Route::FbRoot => Ok(StorageResponse::json(200, &json!({"emulator": "storage"}))),
        Route::FbBucket { bucket } => match method.as_str() {
            "GET" => fb_list(state, &principal, &bucket, &params),
            "POST" | "PUT" => fb_object_post(
                state, &principal, &bucket, None, req, &params, &host, &admitted,
            ),
            _ => Ok(plain_status(501)),
        },
        Route::FbObject { bucket, name } => match method.as_str() {
            "GET" => fb_get(state, &principal, &bucket, &name, &req, &params),
            "PATCH" => fb_patch(state, &principal, &bucket, &name, &req),
            "DELETE" => fb_delete(state, &principal, &bucket, &name),
            "POST" => fb_object_post(
                state,
                &principal,
                &bucket,
                Some(name),
                req,
                &params,
                &host,
                &admitted,
            ),
            "PUT" => {
                if req
                    .header("x-http-method-override")
                    .is_some_and(|v| v.eq_ignore_ascii_case("patch"))
                {
                    fb_patch(state, &principal, &bucket, &name, &req)
                } else {
                    fb_object_post(
                        state,
                        &principal,
                        &bucket,
                        Some(name),
                        req,
                        &params,
                        &host,
                        &admitted,
                    )
                }
            }
            _ => Ok(plain_status(501)),
        },
        Route::GcsListBuckets => gcs_list_buckets(state, &host),
        Route::GcsList { bucket } => gcs_list(state, &bucket, &params, &host),
        Route::GcsObject {
            bucket,
            name,
            spelling,
        } => gcs_object(
            state, &bucket, &name, spelling, &method, &req, &params, &host,
        ),
        Route::GcsCopy {
            bucket,
            name,
            rewrite,
            dst_bucket,
            dst_name,
        } => gcs_copy(
            state,
            &bucket,
            &name,
            rewrite,
            &dst_bucket,
            &dst_name,
            &req,
            &params,
            &host,
        ),
        Route::GcsAcl { bucket, name } => gcs_acl(state, &bucket, &name, &req, &host),
        Route::GcsUpload { bucket } => gcs_upload(state, &bucket, req, &params, &host, &admitted),
        Route::FormUpload { bucket } => form_upload(state, &bucket, &req),
        Route::XmlStyle { bucket, name } => xml_style_get(state, &bucket, &name, &req, &params),
        Route::NotImplemented => Ok(plain_status(501)),
    };
    respond(outcome)
}

// ------------------------------------------------------------------------------------------
// Firebase dialect
// ------------------------------------------------------------------------------------------

fn fb_list(
    state: &StorageState,
    principal: &Principal,
    bucket: &str,
    params: &BTreeMap<String, String>,
) -> Outcome {
    let b = bucket_name(bucket)?;
    let prefix = params.get("prefix").cloned().unwrap_or_default();
    if !prefix.is_empty() && !prefix.ends_with('/') {
        return Err(fb_json_error(
            400,
            "The prefix parameter is required to be empty or ends with a single / character.",
        ));
    }
    let delimiter = params.get("delimiter").cloned().unwrap_or_default();
    let page_token = params.get("pageToken").cloned();
    let max_results = params
        .get("maxResults")
        .and_then(|v| v.parse::<usize>().ok());
    state.authorize(
        principal,
        Method::List,
        &b,
        prefix.trim_end_matches('/'),
        None,
        RulesValue::Null,
    )?;
    let store = state.store()?;
    let page = store.list(
        &b,
        &prefix,
        Some(delimiter.as_str()),
        page_token.as_deref(),
        max_results,
    );
    // The official Firebase list filters malformed names out of the answer.
    let is_valid = |name: &str| !name.is_empty() && name.split('/').all(|s| !s.is_empty());
    let mut body = json!({
        "prefixes": page
            .prefixes
            .iter()
            .filter(|p| is_valid(p.trim_end_matches('/')))
            .collect::<Vec<_>>(),
        "items": page
            .items
            .iter()
            .filter(|m| is_valid(m.name.as_str()))
            .map(|m| json!({"name": m.name.as_str(), "bucket": m.bucket.as_str()}))
            .collect::<Vec<_>>(),
    });
    if let Some(t) = page.next_page_token {
        body["nextPageToken"] = Value::String(t);
    }
    Ok(StorageResponse::json(200, &body))
}

/// `GET /v0/b/{bucket}/o/{name}`: metadata or bytes, with the download-token bypass, and
/// the official emulator's quirk of minting a download token on first read.
fn fb_get(
    state: &StorageState,
    principal: &Principal,
    bucket: &str,
    name: &str,
    req: &StorageRequest,
    params: &BTreeMap<String, String>,
) -> Outcome {
    let b = bucket_name(bucket)?;
    let n = object_name(name)?;
    let now = state.now();
    let mut store = state.store()?;
    let meta = store.get(&b, &n).cloned();
    let token_ok = download_token_matches(meta.as_ref(), params.get("token").map(String::as_str));
    if !token_ok {
        state.authorize(
            principal,
            Method::Get,
            &b,
            n.as_str(),
            meta.as_ref().map(storage_rules_value),
            RulesValue::Null,
        )?;
    }
    let Some(mut meta) = meta else {
        return Ok(plain_status(404));
    };
    // The official emulator mints a download token the first time the Firebase dialect
    // reads an object that has none; that is a metadata update, event included.
    if meta.download_tokens.is_empty() {
        meta = store.add_download_token(&b, &n, now).map_err(fb_core_err)?;
    }
    let media = params.get("alt").map(String::as_str) == Some("media");
    if media {
        Ok(send_file_bytes(&store, &meta, req))
    } else {
        Ok(StorageResponse::json(200, &firebase_json(&meta)))
    }
}

/// The official `sendFileBytes`: object bytes with the header set both dialects share.
fn send_file_bytes(
    store: &ObjectStore,
    meta: &ObjectMetadata,
    req: &StorageRequest,
) -> StorageResponse {
    let bytes = store.bytes(meta);
    let filename = meta
        .name
        .as_str()
        .rsplit('/')
        .next()
        .unwrap_or(meta.name.as_str());
    let mut headers = vec![
        ("accept-ranges".to_owned(), "bytes".to_owned()),
        ("content-type".to_owned(), meta.content_type.clone()),
        (
            "content-disposition".to_owned(),
            format!(
                "{}; filename*={}",
                meta.content_disposition.as_deref().unwrap_or("attachment"),
                rfc5987_encode(filename)
            ),
        ),
        (
            "content-encoding".to_owned(),
            meta.content_encoding.clone().unwrap_or_default(),
        ),
        ("etag".to_owned(), meta.etag()),
        (
            "cache-control".to_owned(),
            meta.cache_control.clone().unwrap_or_default(),
        ),
        ("x-goog-generation".to_owned(), meta.generation.to_string()),
        (
            "x-goog-metadatageneration".to_owned(),
            meta.metageneration.to_string(),
        ),
        ("x-goog-storage-class".to_owned(), "STANDARD".to_owned()),
        (
            "x-goog-hash".to_owned(),
            format!("crc32c={},md5={}", meta.crc32c_base64(), meta.md5_base64()),
        ),
    ];
    let len = bytes.len() as u64;
    // An unsatisfiable or malformed range is ignored (the official emulator's `req.range`
    // answers -1 and the handler falls through to the whole object).
    if let Some((start, end)) = parse_range(req.header("range"), len) {
        headers.push((
            "content-range".to_owned(),
            format!("bytes {start}-{}/{len}", end - 1),
        ));
        let (s, e) = (
            usize::try_from(start).unwrap_or(usize::MAX),
            usize::try_from(end).unwrap_or(usize::MAX),
        );
        return StorageResponse {
            status: 206,
            headers,
            body: bytes.get(s..e).unwrap_or_default().to_vec(),
        };
    }
    StorageResponse {
        status: 200,
        headers,
        body: bytes.to_vec(),
    }
}

/// One satisfiable byte range of a `Range: bytes=...` header; anything else is ignored.
fn parse_range(header: Option<&str>, len: u64) -> Option<(u64, u64)> {
    let spec = header?.trim().strip_prefix("bytes=")?;
    if spec.contains(',') {
        return None;
    }
    let (first, last) = spec.split_once('-')?;
    let (first, last) = (first.trim(), last.trim());
    if first.is_empty() {
        // Suffix range: the final N bytes.
        let suffix = last.parse::<u64>().ok()?;
        if suffix == 0 || len == 0 {
            return None;
        }
        return Some((len.saturating_sub(suffix), len));
    }
    let start = first.parse::<u64>().ok()?;
    let end = if last.is_empty() {
        len
    } else {
        let e = last.parse::<u64>().ok()?;
        if e < start {
            return None;
        }
        e.saturating_add(1).min(len)
    };
    if start >= len {
        return None;
    }
    Some((start, end))
}

fn fb_patch(
    state: &StorageState,
    principal: &Principal,
    bucket: &str,
    name: &str,
    req: &StorageRequest,
) -> Outcome {
    let b = bucket_name(bucket)?;
    let n = object_name(name)?;
    let now = state.now();
    let body: Value = if req.body.is_empty() {
        Value::Object(Map::new())
    } else {
        serde_json::from_slice(&req.body)
            .map_err(|e| fb_json_error(400, &format!("metadata JSON: {e}")))?
    };
    let patch = patch_from_json(&body).map_err(|e| fb_json_error(400, &e))?;
    let mut store = state.store()?;
    let existing = store.get(&b, &n).cloned();
    // Rules run before existence is revealed, as the official emulator orders them.
    let request_resource = existing.as_ref().map_or(RulesValue::Null, |m| {
        let mut preview = patch.apply(m);
        preview.metageneration += 1;
        preview.updated = now;
        storage_rules_value(&preview)
    });
    state.authorize(
        principal,
        Method::Update,
        &b,
        n.as_str(),
        existing.as_ref().map(storage_rules_value),
        request_resource,
    )?;
    if existing.is_none() {
        return Ok(plain_status(404));
    }
    let m = store
        .update_metadata(&b, &n, &patch, Precondition::default(), now)
        .map_err(fb_core_err)?;
    Ok(with_object_headers(
        StorageResponse::json(200, &firebase_json(&m)),
        &m,
    ))
}

fn fb_delete(state: &StorageState, principal: &Principal, bucket: &str, name: &str) -> Outcome {
    let b = bucket_name(bucket)?;
    let n = object_name(name)?;
    let mut store = state.store()?;
    let existing = store.get(&b, &n).cloned();
    state.authorize(
        principal,
        Method::Delete,
        &b,
        n.as_str(),
        existing.as_ref().map(storage_rules_value),
        RulesValue::Null,
    )?;
    if existing.is_none() {
        return Ok(plain_status(404));
    }
    store
        .delete(&b, &n, Precondition::default())
        .map_err(fb_core_err)?;
    Ok(StorageResponse::empty(204))
}

/// The Firebase dialect's POST / PUT on `/o` and object URLs: download-token management,
/// resumable commands, multipart and media uploads.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn fb_object_post(
    state: &StorageState,
    principal: &Principal,
    bucket: &str,
    path_name: Option<String>,
    mut req: StorageRequest,
    params: &BTreeMap<String, String>,
    host: &str,
    admitted: &AdmittedApp,
) -> Outcome {
    let b = bucket_name(bucket)?;
    let now = state.now();
    // Token management routes come first, as the official router orders them.
    if params.contains_key("create_token") || params.contains_key("delete_token") {
        let Some(name) = path_name else {
            return Ok(plain_status(400));
        };
        let n = object_name(&name)?;
        if !matches!(principal, Principal::Owner) {
            return Err(fb_json_error(403, "Missing admin credentials."));
        }
        let mut store = state.store()?;
        let m = if let Some(create) = params.get("create_token") {
            if create != "true" {
                return Ok(plain_status(400));
            }
            store.add_download_token(&b, &n, now).map_err(fb_core_err)?
        } else {
            let token = params.get("delete_token").cloned().unwrap_or_default();
            store
                .remove_download_token(&b, &n, &token, now)
                .map_err(fb_core_err)?
        };
        return Ok(with_object_headers(
            StorageResponse::json(200, &firebase_json(&m)),
            &m,
        ));
    }
    let name = path_name.or_else(|| params.get("name").cloned());
    let protocol = req.header("x-goog-upload-protocol").map(str::to_owned);
    let command = req.header("x-goog-upload-command").map(str::to_owned);
    if protocol.as_deref() == Some("resumable") || command.is_some() {
        let Some(command) = command else {
            return Ok(plain_status(400));
        };
        if command == "start" {
            let Some(name) = name else {
                return Ok(plain_status(400));
            };
            let n = object_name(&name)?;
            let meta_json: Value = if req.body.is_empty() {
                Value::Object(Map::new())
            } else {
                serde_json::from_slice(&req.body)
                    .map_err(|e| fb_json_error(400, &format!("metadata JSON: {e}")))?
            };
            // The official Firebase dialect reads the content type from the metadata
            // document alone.
            let mut meta =
                new_metadata_from_json(&meta_json, None).map_err(|e| fb_json_error(400, &e))?;
            inject_download_token(state, &mut meta)?;
            let (expected_md5, expected_crc32c) =
                declared_hashes(&req, Some(&meta_json)).map_err(|(s, m)| fb_json_error(s, &m))?;
            // Rules run at finalization against the received bytes (as the official
            // emulator does). The session keeps the credentials it was started with.
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
                    Precondition::default(),
                    UploadOptions {
                        total: None,
                        authorization,
                        // The app the initiation was admitted for: every later request on
                        // this session must present the same one (spec section 13.2).
                        admission: admitted.binding(),
                        expected_md5,
                        expected_crc32c,
                    },
                    now,
                )
                .map_err(fb_core_err)?;
            let session_url = format!(
                "http://{host}/v0/b/{}/o?name={}&upload_id={}&upload_protocol=resumable",
                encode_segment(b.as_str()),
                encode_segment(n.as_str()),
                id.as_str()
            );
            return Ok(plain_status(200)
                .with_header("x-goog-upload-chunk-granularity", "10000")
                .with_header("x-goog-upload-control-url", "")
                .with_header("x-goog-upload-status", "active")
                .with_header("x-gupload-uploadid", id.as_str())
                .with_header("x-goog-upload-url", session_url));
        }
        let Some(upload_id) = params.get("upload_id") else {
            return Ok(plain_status(400));
        };
        return fb_resumable_command(state, &b, upload_id, &command, req, host, admitted);
    }
    let Some(name) = name else {
        return Ok(plain_status(400));
    };
    let n = object_name(&name)?;
    if protocol.as_deref() == Some("multipart") {
        let content_type = req.header("content-type").unwrap_or("").to_owned();
        let body = std::mem::take(&mut req.body);
        let (meta_json, data) =
            parse_multipart(&content_type, body).map_err(|e| html_text(400, &e))?;
        // The data part's own content type is ignored, as upstream ignores it.
        let mut meta =
            new_metadata_from_json(&meta_json, None).map_err(|e| fb_json_error(400, &e))?;
        inject_download_token(state, &mut meta)?;
        let hashes =
            verify_hashes(&req, Some(&meta_json), &data).map_err(|(s, m)| fb_json_error(s, &m))?;
        return fb_commit(state, principal, &b, &n, data, meta, hashes, now);
    }
    // Media upload: the body is the object; the request content type is the object's.
    let content_type = req
        .header("content-type")
        .filter(|c| !c.is_empty())
        .map(str::to_owned);
    let body = std::mem::take(&mut req.body);
    let hashes = verify_hashes(&req, None, &body).map_err(|(s, m)| fb_json_error(s, &m))?;
    let mut meta = NewMetadata {
        content_type,
        ..NewMetadata::default()
    };
    inject_download_token(state, &mut meta)?;
    fb_commit(state, principal, &b, &n, body, meta, hashes, now)
}

/// The Firebase dialect always defines custom metadata on an upload, injecting a fresh
/// download token unless the client supplied `firebaseStorageDownloadTokens` itself,
/// exactly as the official `finalizeOneShotUpload` does before the object is stored.
fn inject_download_token(
    state: &StorageState,
    meta: &mut NewMetadata,
) -> Result<(), StorageResponse> {
    let custom = meta.custom.get_or_insert_with(BTreeMap::new);
    if !custom.contains_key(TOKENS_KEY) {
        let token = state.store()?.mint_download_token();
        custom.insert(TOKENS_KEY.to_owned(), token);
    }
    Ok(())
}

/// Commits a Firebase-dialect one-shot upload: rules on the received bytes, then the
/// commit, then the `contentDisposition: "inline"` default (after the finalize event, as
/// upstream mutates its stored metadata).
#[allow(clippy::too_many_arguments)]
fn fb_commit(
    state: &StorageState,
    principal: &Principal,
    b: &BucketName,
    n: &ObjectName,
    data: Vec<u8>,
    meta: NewMetadata,
    hashes: ([u8; 16], u32),
    now: LogicalInstant,
) -> Outcome {
    let mut store = state.store()?;
    let existing = store.get(b, n).cloned();
    let method = if existing.is_some() {
        Method::Update
    } else {
        Method::Create
    };
    let next_generation = store.next_generation_preview().map_err(fb_core_err)?;
    state
        .authorize(
            principal,
            method,
            b,
            n.as_str(),
            existing.as_ref().map(storage_rules_value),
            incoming_rules_value(b, n, &meta, data.len() as u64, hashes, next_generation, now),
        )
        .map_err(|denial| denial.with_header("x-goog-upload-status", "final"))?;
    store
        .put(b, n, data, meta, Precondition::default(), now)
        .map_err(fb_core_err)?;
    let m = store
        .default_content_disposition_inline(b, n)
        .map_err(fb_core_err)?;
    Ok(StorageResponse::json(200, &firebase_json(&m)))
}

/// A Firebase resumable command on an existing session: query, cancel, upload, finalize.
#[allow(clippy::too_many_lines)]
fn fb_resumable_command(
    state: &StorageState,
    bucket: &BucketName,
    upload_id: &str,
    command: &str,
    mut req: StorageRequest,
    host: &str,
    admitted: &AdmittedApp,
) -> Outcome {
    let _ = host;
    let id = UploadId::from_str_unchecked(upload_id);
    let now = state.now();
    let chunk = std::mem::take(&mut req.body);
    let mut store = state.store()?;
    // The upload belongs to the app that started it. This is checked before the command is
    // read and before anything is queried, appended, finalized or cancelled, so a foreign
    // request neither advances nor deletes the session (specification section 13.2).
    if let Ok(expected) = store.upload_admission(&id, now) {
        if !admitted.may_continue(expected) {
            return Ok(foreign_session(Dialect::Firebase));
        }
    }
    // The upload belongs to the bucket its URL names: another bucket's URL (and so another
    // session's fault plan and ownership) cannot drive it.
    if store.upload_bucket(&id, now).is_ok_and(|b| b != bucket) {
        return Ok(plain_status(404));
    }
    let commands: Vec<&str> = command.split(',').map(str::trim).collect();
    if commands.contains(&"query") {
        let phase = store.upload_phase(&id, now).map_err(fb_core_err)?;
        let (received, status) = match &phase {
            UploadPhase::Active(n) => (*n, "active"),
            UploadPhase::Finalized(m) => (m.size, "final"),
            UploadPhase::Cancelled(n) => (*n, "cancelled"),
            UploadPhase::Denied(n) => (*n, "final"),
        };
        return Ok(plain_status(200)
            .with_header("x-goog-upload-size-received", received.to_string())
            .with_header("x-goog-upload-status", status));
    }
    if commands.contains(&"cancel") {
        return match store.cancel_upload(&id, now) {
            Ok(()) => Ok(plain_status(200)),
            Err(StorageError::UploadFinalized) => Ok(plain_status(400)),
            Err(e) => Ok(fb_core_err(e)),
        };
    }
    if commands.contains(&"upload") {
        let offset: u64 = match req.header("x-goog-upload-offset") {
            None => 0,
            Some(v) => v
                .parse()
                .map_err(|_| fb_json_error(400, &format!("invalid X-Goog-Upload-Offset {v:?}")))?,
        };
        match store.append_upload_owned(&id, offset, chunk, now) {
            Ok(_) => {}
            Err(StorageError::UploadFinalized) => return Ok(plain_status(400)),
            Err(StorageError::UploadNotFound) => return Ok(plain_status(404)),
            Err(e) => return Ok(fb_core_err(e)),
        }
        if !commands.contains(&"finalize") {
            return Ok(plain_status(200)
                .with_header("x-goog-upload-status", "active")
                .with_header("x-gupload-uploadid", id.as_str()));
        }
    }
    if commands.contains(&"finalize") {
        // A repeated finalize answers with the outcome of the first one, as upstream
        // replays its recorded response code.
        match store.upload_phase(&id, now) {
            Ok(UploadPhase::Finalized(_)) => {
                return Ok(plain_status(200).with_header("x-goog-upload-status", "final"));
            }
            Ok(UploadPhase::Denied(_)) => {
                return Ok(plain_status(403).with_header("x-goog-upload-status", "final"));
            }
            Ok(UploadPhase::Cancelled(_)) => return Ok(plain_status(400)),
            Ok(UploadPhase::Active(_)) => {}
            Err(e) => return Ok(fb_core_err(e)),
        }
        let m = finalize_resumable(state, &mut store, &id, &req, now).map_err(|e| match e {
            FinalizeError::Denied(denial) => denial.with_header("x-goog-upload-status", "final"),
            FinalizeError::Store(StorageError::UploadNotFound) => plain_status(404),
            FinalizeError::Store(err) => fb_core_err(err),
            FinalizeError::Auth(message) => error_response(Dialect::Firebase, 401, &message),
        })?;
        let (b, n) = (m.bucket.clone(), m.name.clone());
        let m = store
            .default_content_disposition_inline(&b, &n)
            .map_err(fb_core_err)?;
        return Ok(StorageResponse::json(200, &firebase_json(&m))
            .with_header("x-goog-upload-status", "final"));
    }
    // A command that names nothing this protocol knows.
    Ok(plain_status(400))
}

enum FinalizeError {
    Denied(StorageResponse),
    Store(StorageError),
    Auth(String),
}

/// Authorizes and commits a resumable upload against the bytes actually received (the
/// principal that started the session; the then-current destination). A rules refusal is
/// terminal: the session remembers it and never publishes.
fn finalize_resumable(
    state: &StorageState,
    store: &mut ObjectStore,
    id: &UploadId,
    req: &StorageRequest,
    now: LogicalInstant,
) -> Result<ObjectMetadata, FinalizeError> {
    // Checksums declared on the finalizing request are verified by the store when it
    // commits (a mismatch ends the session).
    let (md5_declared, crc_declared) = declared_hashes(req, None)
        .map_err(|(_, m)| FinalizeError::Store(StorageError::ChecksumMismatch(m)))?;
    store
        .set_upload_hashes(id, md5_declared, crc_declared, now)
        .map_err(FinalizeError::Store)?;
    let (b, n, meta, size, hashes, authorization) = {
        let pending = store
            .pending_upload(id, now)
            .map_err(FinalizeError::Store)?;
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
    // now, as the official emulator does).
    let principal = state
        .principal(authorization.as_deref(), b.as_str())
        .map_err(FinalizeError::Auth)?;
    let existing = store.get(&b, &n).cloned();
    let method = if existing.is_some() {
        Method::Update
    } else {
        Method::Create
    };
    let next_generation = store
        .next_generation_preview()
        .map_err(FinalizeError::Store)?;
    if let Err(denial) = state.authorize(
        &principal,
        method,
        &b,
        n.as_str(),
        existing.as_ref().map(storage_rules_value),
        incoming_rules_value(&b, &n, &meta, size, hashes, next_generation, now),
    ) {
        let _ = store.mark_upload_denied(id, now);
        return Err(FinalizeError::Denied(denial));
    }
    store.finalize_upload(id, now).map_err(FinalizeError::Store)
}

// ------------------------------------------------------------------------------------------
// JSON API dialect
// ------------------------------------------------------------------------------------------

fn gcs_list_buckets(state: &StorageState, host: &str) -> Outcome {
    let store = state.store()?;
    let default = format!("{}.appspot.com", state.project);
    let mut names = vec![default];
    for bucket in store.buckets() {
        if !names.iter().any(|n| n == bucket.as_str()) {
            names.push(bucket.as_str().to_owned());
        }
    }
    let now = rfc3339(state.now());
    let items: Vec<Value> = names
        .iter()
        .map(|name| {
            json!({
                "kind": "storage#bucket",
                "name": name,
                "id": name,
                "selfLink": format!("http://{host}/v1/b/{name}"),
                "timeCreated": now,
                "updated": now,
                "projectNumber": "000000000000",
                "metageneration": "1",
                "location": "US",
                "storageClass": "STANDARD",
                "etag": "====",
                "locationType": "multi-region",
            })
        })
        .collect();
    Ok(StorageResponse::json(
        200,
        &json!({"kind": "storage#buckets", "items": items}),
    ))
}

fn gcs_list(
    state: &StorageState,
    bucket: &str,
    params: &BTreeMap<String, String>,
    host: &str,
) -> Outcome {
    let b = bucket_name(bucket)?;
    let prefix = params.get("prefix").cloned().unwrap_or_default();
    let delimiter = params.get("delimiter").cloned().unwrap_or_default();
    let page_token = params.get("pageToken").cloned();
    let max_results = params
        .get("maxResults")
        .and_then(|v| v.parse::<usize>().ok());
    let store = state.store()?;
    let page = store.list(
        &b,
        &prefix,
        Some(delimiter.as_str()),
        page_token.as_deref(),
        max_results,
    );
    let mut body = json!({"kind": "storage#objects"});
    if let Some(t) = page.next_page_token {
        body["nextPageToken"] = Value::String(t);
    }
    if !page.prefixes.is_empty() {
        body["prefixes"] = json!(page.prefixes);
    }
    if !page.items.is_empty() {
        body["items"] = Value::Array(page.items.iter().map(|m| gcs_json(m, host)).collect());
    }
    Ok(StorageResponse::json(200, &body))
}

#[allow(clippy::too_many_arguments)]
fn gcs_object(
    state: &StorageState,
    bucket: &str,
    name: &str,
    spelling: GcsSpelling,
    method: &str,
    req: &StorageRequest,
    params: &BTreeMap<String, String>,
    host: &str,
) -> Outcome {
    let b = bucket_name(bucket)?;
    let n = object_name(name)?;
    let now = state.now();
    match method {
        "GET" => {
            let store = state.store()?;
            let meta = select_generation(store.get(&b, &n).cloned(), params, "generation")?;
            let media = params.get("alt").map(String::as_str) == Some("media");
            let Some(meta) = meta else {
                return Ok(gcs_no_such_object(bucket, name, media));
            };
            // Conditional reads: a not-match predicate naming the current value is 304
            // (production semantics; the official emulator reads no preconditions at all).
            match precondition(params)?.check(Some(&meta)) {
                Ok(()) => {}
                Err(StorageError::NotModified(_)) => {
                    return Ok(StorageResponse::empty(304).with_header("etag", meta.etag()))
                }
                Err(e) => return Ok(gcs_core_err(e)),
            }
            if media {
                Ok(send_file_bytes(&store, &meta, req))
            } else {
                Ok(StorageResponse::json(200, &gcs_json(&meta, host)))
            }
        }
        "PATCH" if spelling == GcsSpelling::Short => {
            let body: Value = if req.body.is_empty() {
                Value::Object(Map::new())
            } else {
                serde_json::from_slice(&req.body)
                    .map_err(|e| gcs_json_error(400, &format!("metadata JSON: {e}"), "invalid"))?
            };
            let pre = precondition(params)?;
            let mut store = state.store()?;
            if store.get(&b, &n).is_none() {
                return Ok(gcs_no_such_object(bucket, name, false));
            }
            let patch = patch_from_json(&body).map_err(|e| gcs_json_error(400, &e, "invalid"))?;
            let m = store
                .update_metadata(&b, &n, &patch, pre, now)
                .map_err(gcs_core_err)?;
            Ok(StorageResponse::json(200, &gcs_json(&m, host)))
        }
        "DELETE" => {
            let pre = precondition(params)?;
            let mut store = state.store()?;
            // The generation selector is honoured as production honours it (the official
            // emulator reads neither it nor the preconditions — a published divergence).
            if select_generation(store.get(&b, &n).cloned(), params, "generation")?.is_none() {
                return Ok(gcs_no_such_object(bucket, name, false));
            }
            store.delete(&b, &n, pre).map_err(gcs_core_err)?;
            Ok(StorageResponse::empty(204))
        }
        // PATCH on the /storage/v1 spelling falls into the official catch-all.
        _ => Ok(plain_status(501)),
    }
}

/// The JSON API copy, exactly as `copyObject` behaves: rules never run, the incoming
/// metadata object replaces the source's custom metadata wholesale, and the source's
/// download tokens ride along unless it does.
#[allow(clippy::too_many_arguments)]
fn gcs_copy(
    state: &StorageState,
    bucket: &str,
    name: &str,
    rewrite: bool,
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
    let incoming: Option<Value> = if req.body.is_empty() {
        None
    } else {
        serde_json::from_slice::<Value>(&req.body)
            .ok()
            .filter(|v| v.as_object().is_some_and(|o| !o.is_empty()))
    };
    let mut store = state.store()?;
    let source_pre = precondition_named(params, "ifSource")?;
    let pre = precondition(params)?;
    let selected = select_generation(store.get(&b, &n).cloned(), params, "sourceGeneration")?;
    let Some(src) = selected else {
        return Ok(gcs_no_such_object(bucket, name, false));
    };
    source_pre.check(Some(&src)).map_err(gcs_core_err)?;
    let incoming_meta = incoming
        .as_ref()
        .map(|v| new_metadata_from_json(v, None))
        .transpose()
        .map_err(|e| gcs_json_error(400, &e, "invalid"))?;
    let mut meta = NewMetadata {
        content_type: Some(src.content_type.clone()),
        content_disposition: src.content_disposition.clone(),
        content_encoding: src.content_encoding.clone(),
        content_language: src.content_language.clone(),
        cache_control: src.cache_control.clone(),
        custom: src.custom_defined.then(|| src.custom.clone()),
    };
    if let Some(over) = incoming_meta {
        if over.content_type.is_some()
            || incoming
                .as_ref()
                .is_some_and(|v| v.get("contentType").is_some())
        {
            meta.content_type = over.content_type;
        }
        for (target, value, key) in [
            (
                &mut meta.content_disposition,
                over.content_disposition,
                "contentDisposition",
            ),
            (
                &mut meta.content_encoding,
                over.content_encoding,
                "contentEncoding",
            ),
            (
                &mut meta.content_language,
                over.content_language,
                "contentLanguage",
            ),
            (&mut meta.cache_control, over.cache_control, "cacheControl"),
        ] {
            if incoming.as_ref().is_some_and(|v| v.get(key).is_some()) {
                *target = value;
            }
        }
        if incoming
            .as_ref()
            .is_some_and(|v| v.get("metadata").is_some())
        {
            meta.custom = over.custom;
        }
    }
    // The source's download tokens follow the copy unless the incoming metadata object
    // replaced custom metadata with something of its own.
    let incoming_has_custom = incoming
        .as_ref()
        .and_then(|v| v.get("metadata"))
        .and_then(Value::as_object)
        .is_some_and(|m| !m.is_empty());
    if !src.download_tokens.is_empty() && !incoming_has_custom {
        meta.custom
            .get_or_insert_with(BTreeMap::new)
            .insert(TOKENS_KEY.to_owned(), src.download_tokens.join(","));
    }
    let m = store
        .copy((&b, &n), (&db, &dn), Some(meta), pre, now)
        .map_err(gcs_core_err)?;
    let resource = gcs_json(&m, host);
    if rewrite {
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
    } else {
        Ok(StorageResponse::json(200, &resource))
    }
}

/// The official emulator's ACL stub: the call succeeds, has no effect on access, and still
/// counts as a metadata update (metageneration bump and `metadataUpdate` event).
fn gcs_acl(
    state: &StorageState,
    bucket: &str,
    name: &str,
    req: &StorageRequest,
    host: &str,
) -> Outcome {
    let _ = host;
    let b = bucket_name(bucket)?;
    let n = object_name(name)?;
    let now = state.now();
    let body: Value = serde_json::from_slice(&req.body).unwrap_or(Value::Object(Map::new()));
    let mut store = state.store()?;
    if store.get(&b, &n).is_none() {
        return Ok(gcs_no_such_object(bucket, name, false));
    }
    let m = store
        .update_metadata(
            &b,
            &n,
            &MetadataPatch::default(),
            Precondition::default(),
            now,
        )
        .map_err(gcs_core_err)?;
    Ok(StorageResponse::json(
        200,
        &json!({
            "kind": "storage#objectAccessControl",
            "object": m.name.as_str(),
            "id": format!("{}/{}/{}/allUsers", m.bucket.as_str(), m.name.as_str(), m.generation),
            "selfLink": format!("http://{host}/storage/v1/b/{}/o/{}/acl/allUsers", m.bucket.as_str(), encode_segment(m.name.as_str())),
            "bucket": m.bucket.as_str(),
            "entity": body.get("entity").cloned().unwrap_or(Value::Null),
            "role": body.get("role").cloned().unwrap_or(Value::Null),
            "etag": "someEtag",
            "generation": m.generation.to_string(),
        }),
    ))
}

/// `/upload/storage/v1/b/{bucket}/o`: media, multipart and resumable JSON API uploads.
#[allow(clippy::too_many_lines)]
fn gcs_upload(
    state: &StorageState,
    bucket: &str,
    mut req: StorageRequest,
    params: &BTreeMap<String, String>,
    host: &str,
    admitted: &AdmittedApp,
) -> Outcome {
    let b = bucket_name(bucket)?;
    let now = state.now();
    if req.method == "PUT" {
        // The PUT continuation of a resumable session.
        let Some(upload_id) = params.get("upload_id") else {
            return Ok(plain_status(400));
        };
        return gcs_resumable_put(state, &b, upload_id, req, host, admitted);
    }
    let upload_type = params
        .get("uploadType")
        .cloned()
        .or_else(|| req.header("x-goog-upload-protocol").map(str::to_owned));
    let strip_leading = |name: String| name.strip_prefix('/').map(str::to_owned).unwrap_or(name);
    match upload_type.as_deref() {
        Some("resumable") => {
            let meta_json: Value = if req.body.is_empty() {
                Value::Object(Map::new())
            } else {
                serde_json::from_slice(&req.body)
                    .map_err(|e| gcs_json_error(400, &format!("metadata JSON: {e}"), "invalid"))?
            };
            let name = params
                .get("name")
                .cloned()
                .or_else(|| {
                    meta_json
                        .get("name")
                        .and_then(Value::as_str)
                        .map(str::to_owned)
                })
                .map(strip_leading);
            let Some(name) = name else {
                return Ok(plain_status(400));
            };
            let n = object_name(&name)?;
            let declared_ct = req.header("x-upload-content-type").map(str::to_owned);
            let meta = new_metadata_from_json(&meta_json, declared_ct)
                .map_err(|e| gcs_json_error(400, &e, "invalid"))?;
            let pre = precondition(params)?;
            let (expected_md5, expected_crc32c) = declared_hashes(&req, Some(&meta_json))
                .map_err(|(s, m)| gcs_json_error(s, &m, "invalid"))?;
            let id = state
                .store()?
                .begin_upload_with(
                    &b,
                    &n,
                    meta,
                    pre,
                    UploadOptions {
                        total: None,
                        authorization: Some("Bearer owner".to_owned()),
                        admission: admitted.binding(),
                        expected_md5,
                        expected_crc32c,
                    },
                    now,
                )
                .map_err(gcs_core_err)?;
            let session_url = format!(
                "http://{host}/upload/storage/v1/b/{}/o?name={}&uploadType=resumable&upload_id={}",
                encode_segment(b.as_str()),
                encode_segment(n.as_str()),
                id.as_str()
            );
            Ok(plain_status(200).with_header("location", session_url))
        }
        Some("multipart") => {
            let content_type = req
                .header("content-type")
                .or_else(|| req.header("x-upload-content-type"))
                .unwrap_or("")
                .to_owned();
            let body = std::mem::take(&mut req.body);
            let (meta_json, data) = parse_multipart(&content_type, body).map_err(|e| {
                StorageResponse::json(400, &json!({"error": {"code": 400, "message": e}}))
            })?;
            let name = params
                .get("name")
                .cloned()
                .or_else(|| {
                    meta_json
                        .get("name")
                        .and_then(Value::as_str)
                        .map(str::to_owned)
                })
                .map(strip_leading);
            let Some(name) = name else {
                return Ok(plain_status(400));
            };
            let n = object_name(&name)?;
            let declared_ct = req.header("x-upload-content-type").map(str::to_owned);
            let meta = new_metadata_from_json(&meta_json, declared_ct)
                .map_err(|e| gcs_json_error(400, &e, "invalid"))?;
            let pre = precondition(params)?;
            let hashes = verify_hashes(&req, Some(&meta_json), &data)
                .map_err(|(s, m)| gcs_json_error(s, &m, "invalid"))?;
            let _ = hashes;
            let mut store = state.store()?;
            let m = store
                .put(&b, &n, data, meta, pre, now)
                .map_err(gcs_core_err)?;
            Ok(StorageResponse::json(200, &gcs_json(&m, host)))
        }
        _ => {
            // uploadType=media (or nothing): the body is the object.
            let Some(name) = params.get("name").cloned().map(strip_leading) else {
                return Ok(plain_status(400));
            };
            let n = object_name(&name)?;
            let content_type = req
                .header("content-type")
                .filter(|c| !c.is_empty())
                .map(str::to_owned);
            let pre = precondition(params)?;
            let body = std::mem::take(&mut req.body);
            verify_hashes(&req, None, &body).map_err(|(s, m)| gcs_json_error(s, &m, "invalid"))?;
            let meta = NewMetadata {
                content_type,
                ..NewMetadata::default()
            };
            let mut store = state.store()?;
            let m = store
                .put(&b, &n, body, meta, pre, now)
                .map_err(gcs_core_err)?;
            Ok(StorageResponse::json(200, &gcs_json(&m, host)))
        }
    }
}

/// The JSON API PUT continuation. fireemu serves the production `Content-Range` chunk
/// protocol here (308 between chunks); the official emulator appends whatever arrives and
/// finalizes on every PUT — a published divergence.
fn gcs_resumable_put(
    state: &StorageState,
    bucket: &BucketName,
    upload_id: &str,
    mut req: StorageRequest,
    host: &str,
    admitted: &AdmittedApp,
) -> Outcome {
    let id = UploadId::from_str_unchecked(upload_id);
    let now = state.now();
    let chunk = std::mem::take(&mut req.body);
    let mut store = state.store()?;
    if let Ok(expected) = store.upload_admission(&id, now) {
        if !admitted.may_continue(expected) {
            return Ok(foreign_session(Dialect::Gcs));
        }
    }
    match store.upload_phase(&id, now) {
        Err(StorageError::UploadNotFound) => return Ok(plain_status(404)),
        Err(e) => return Ok(gcs_core_err(e)),
        Ok(UploadPhase::Finalized(_) | UploadPhase::Denied(_) | UploadPhase::Cancelled(_)) => {
            return Ok(plain_status(400));
        }
        Ok(UploadPhase::Active(_)) => {}
    }
    if store.upload_bucket(&id, now).is_ok_and(|b| b != bucket) {
        return Ok(plain_status(404));
    }
    let range = match req.header("content-range") {
        Some(cr) => parse_content_range(cr).ok_or_else(|| {
            gcs_json_error(400, &format!("invalid Content-Range {cr:?}"), "invalid")
        })?,
        None => ContentRange::Span {
            start: 0,
            end: Some(chunk.len() as u64),
            total: Some(chunk.len() as u64),
        },
    };
    let (start, end, total) = match range {
        ContentRange::Status => {
            let (received, committed) = store.upload_status(&id, now).map_err(gcs_core_err)?;
            return Ok(if let Some(m) = committed {
                StorageResponse::json(200, &gcs_json(&m, host))
            } else {
                incomplete(received)
            });
        }
        ContentRange::Span { start, end, total } => (start, end, total),
    };
    let body_len = chunk.len() as u64;
    if let Some(end) = end {
        if end.checked_sub(start) != Some(body_len) {
            return Err(gcs_json_error(
                400,
                &format!(
                    "Content-Range spans {} bytes but the body has {body_len}",
                    end.saturating_sub(start)
                ),
                "invalid",
            ));
        }
        if total.is_some_and(|t| end > t) {
            return Err(gcs_json_error(
                400,
                "Content-Range exceeds the declared total",
                "invalid",
            ));
        }
    }
    if let Some(t) = total {
        store.set_upload_total(&id, t, now).map_err(gcs_core_err)?;
    }
    store
        .append_upload_owned(&id, start, chunk, now)
        .map_err(gcs_core_err)?;
    // A known total finishes when reached; an open-ended range (`START-*/*`, or no
    // Content-Range at all) carries the rest of the object in this request.
    let finalize = match (end, total) {
        (Some(e), Some(t)) => e == t,
        (Some(_), None) => false,
        (None, _) => true,
    };
    if finalize {
        let m = finalize_resumable(state, &mut store, &id, &req, now).map_err(|e| match e {
            // The JSON API dialect runs no rules, so a denial cannot happen here.
            FinalizeError::Denied(denial) => denial,
            FinalizeError::Store(err) => gcs_core_err(err),
            FinalizeError::Auth(message) => error_response(Dialect::Gcs, 401, &message),
        })?;
        return Ok(StorageResponse::json(200, &gcs_json(&m, host)));
    }
    let (received, _) = store.upload_status(&id, now).map_err(gcs_core_err)?;
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

/// The XML-ish `POST /{bucket}` form-data upload: a `key` field names the object, a file
/// part carries the bytes, and header-named fields set the metadata. Rules never run (the
/// gcloud router is the privileged dialect) and the answer is a bare 204.
fn form_upload(state: &StorageState, bucket: &str, req: &StorageRequest) -> Outcome {
    let content_type = req.header("content-type").unwrap_or("");
    if !content_type.starts_with("multipart/form-data") {
        return Ok(html_text(400, "Content-Type must be multipart/form-data"));
    }
    let b = bucket_name(bucket)?;
    let now = state.now();
    let parts = parse_form_data(content_type, &req.body).map_err(|e| html_text(400, &e))?;
    let mut key: Option<String> = None;
    let mut file: Option<(Option<String>, std::ops::Range<usize>)> = None;
    let mut fields: Vec<(String, String)> = Vec::new();
    for part in parts {
        match part {
            FormPart::Field { name, value } => {
                if name == "key" {
                    key = Some(value);
                } else {
                    fields.push((name, value));
                }
            }
            FormPart::File { content_type, data } => file = Some((content_type, data)),
        }
    }
    let (Some(key), Some((file_ct, data))) = (key, file) else {
        return Ok(html_text(400, "Missing 'key' or file."));
    };
    let n = object_name(&key)?;
    let mut meta = NewMetadata {
        content_type: file_ct,
        custom: Some(BTreeMap::new()),
        ..NewMetadata::default()
    };
    for (name, value) in fields {
        let lower = name.to_ascii_lowercase();
        if let Some(rest) = lower.strip_prefix("x-goog-meta-") {
            if let Some(custom) = meta.custom.as_mut() {
                custom.insert(rest.to_owned(), value);
            }
        } else {
            let trimmed = value.trim().to_owned();
            match lower.as_str() {
                "content-type" => meta.content_type = Some(trimmed),
                "cache-control" => meta.cache_control = Some(trimmed),
                "content-disposition" => meta.content_disposition = Some(trimmed),
                "content-encoding" => meta.content_encoding = Some(trimmed),
                "content-language" => meta.content_language = Some(trimmed),
                _ => {}
            }
        }
    }
    // The form field values are raw body bytes and `value.trim()` does not strip an internal
    // CR/LF or NUL, so the same control-character boundary check the JSON dialects run applies
    // here before any of these strings can be echoed into a response header (S-4).
    for (name, val) in [
        ("contentType", &meta.content_type),
        ("contentDisposition", &meta.content_disposition),
        ("contentEncoding", &meta.content_encoding),
        ("contentLanguage", &meta.content_language),
        ("cacheControl", &meta.cache_control),
    ] {
        if let Some(val) = val {
            header_safe(name, val).map_err(|e| html_text(400, &e))?;
        }
    }
    for (k, v) in meta.custom.iter().flatten() {
        header_safe(&format!("metadata key {k:?}"), k).map_err(|e| html_text(400, &e))?;
        header_safe(&format!("metadata.{k}"), v).map_err(|e| html_text(400, &e))?;
    }
    let bytes = req.body[data].to_vec();
    let mut store = state.store()?;
    store
        .put(&b, &n, bytes, meta, Precondition::default(), now)
        .map_err(gcs_core_err)?;
    Ok(StorageResponse::empty(204))
}

/// The `GET /{bucket}/{object...}` fallback: object bytes when it exists, the JSON API's
/// missing-object answer otherwise.
fn xml_style_get(
    state: &StorageState,
    bucket: &str,
    name: &str,
    req: &StorageRequest,
    params: &BTreeMap<String, String>,
) -> Outcome {
    let media = params.get("alt").map(String::as_str) == Some("media");
    let (Ok(b), Ok(n)) = (BucketName::try_new(bucket), ObjectName::try_new(name)) else {
        return Ok(gcs_no_such_object(bucket, name, media));
    };
    let store = state.store()?;
    let Some(meta) = store.get(&b, &n).cloned() else {
        return Ok(gcs_no_such_object(bucket, name, media));
    };
    Ok(send_file_bytes(&store, &meta, req))
}
