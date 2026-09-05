//! Firestore REST API (`FS-REST-1`) on the local backend: the JSON form of the v1 RPCs,
//! served on the Firestore port next to gRPC. Every request is translated to the protobuf
//! request the local backend already understands, so REST and gRPC share validation,
//! execution and Security Rules.

// `tonic::Status` is the error type shared with the gRPC surface.
#![allow(clippy::result_large_err)]

pub mod coverage;
pub mod json;

use std::collections::BTreeMap;
use std::sync::Arc;

use fireemu_proto_firestore::google::firestore::v1 as pb;
use serde_json::{json, Value};
use tonic::{Code, Status};

use crate::encode::encode_instant;
use crate::gateway::Gateway;
use crate::local::LocalBackend;
use crate::rules::{self, Principal, RulesEnforcer};
use json::{
    aggregation_query_from_json, base64_decode, base64_encode, commit_to_json, document_from_json,
    document_to_json, mask_from_json, mask_from_paths, optional_timestamp_to_json,
    precondition_from_json, structured_query_from_json, transaction_options_from_json,
    value_to_json, write_from_json, write_result_to_json, JsonError,
};

/// Shared REST state.
pub struct RestState {
    /// Local backend.
    pub local: Arc<LocalBackend>,
    /// Strict gateway (query validation for `Listen`-less REST does not need it directly,
    /// kept for parity with the stream context).
    pub gateway: Arc<Gateway>,
    /// Rules enforcement, if configured.
    pub rules: Option<Arc<RulesEnforcer>>,
    /// The App Check baseline policy of Cloud Firestore (`appCheck.services.firestore`).
    /// `None` is the `off` mode: no header is collected and nothing is classified.
    pub app_check: Option<Arc<fireemu_core_app_check::admission::ServiceAdmission>>,
}

/// One REST request.
#[derive(Debug, Clone)]
pub struct RestRequest {
    /// HTTP method.
    pub method: String,
    /// Path without query string.
    pub path: String,
    /// Raw query string.
    pub query: String,
    /// `Authorization` header.
    pub authorization: Option<String>,
    /// Every `X-Firebase-AppCheck` field instance, in wire order (specification section 7.3).
    pub app_check: Vec<String>,
    /// Parsed JSON body (`{}` when empty).
    pub body: Value,
}

/// HTTP status + JSON body.
#[derive(Debug, Clone, PartialEq)]
pub struct RestResponse {
    /// HTTP status.
    pub status: u16,
    /// Body.
    pub body: Value,
}

fn http_status(code: Code) -> u16 {
    match code {
        Code::Ok => 200,
        Code::InvalidArgument | Code::FailedPrecondition | Code::OutOfRange => 400,
        Code::Unauthenticated => 401,
        Code::PermissionDenied => 403,
        Code::NotFound => 404,
        Code::AlreadyExists | Code::Aborted => 409,
        Code::ResourceExhausted => 429,
        Code::Cancelled => 499,
        Code::Unimplemented => 501,
        Code::Unavailable => 503,
        Code::DeadlineExceeded => 504,
        _ => 500,
    }
}

fn status_name(code: Code) -> &'static str {
    match code {
        Code::Ok => "OK",
        Code::Cancelled => "CANCELLED",
        Code::Unknown => "UNKNOWN",
        Code::InvalidArgument => "INVALID_ARGUMENT",
        Code::DeadlineExceeded => "DEADLINE_EXCEEDED",
        Code::NotFound => "NOT_FOUND",
        Code::AlreadyExists => "ALREADY_EXISTS",
        Code::PermissionDenied => "PERMISSION_DENIED",
        Code::ResourceExhausted => "RESOURCE_EXHAUSTED",
        Code::FailedPrecondition => "FAILED_PRECONDITION",
        Code::Aborted => "ABORTED",
        Code::OutOfRange => "OUT_OF_RANGE",
        Code::Unimplemented => "UNIMPLEMENTED",
        Code::Internal => "INTERNAL",
        Code::Unavailable => "UNAVAILABLE",
        Code::DataLoss => "DATA_LOSS",
        Code::Unauthenticated => "UNAUTHENTICATED",
    }
}

/// gRPC status → Google JSON error envelope.
#[must_use]
pub fn error_response(status: &Status) -> RestResponse {
    let code = status.code();
    let mut body = fireemu_adapter_support::api_error::google_rpc(
        http_status(code),
        status.message(),
        status_name(code),
    );
    if status
        .metadata()
        .contains_key(crate::local::DROP_CONNECTION_KEY)
    {
        // The server drops the connection instead of sending this body.
        body["error"]["ftdDropConnection"] = json!(true);
    }
    RestResponse {
        status: http_status(code),
        body,
    }
}

/// Whether a response stands for a `dropConnection` fault (the connection is closed
/// without it).
#[must_use]
pub fn drops_connection(response: &RestResponse) -> bool {
    response.body["error"]["ftdDropConnection"] == json!(true)
}

fn ok(body: Value) -> RestResponse {
    RestResponse { status: 200, body }
}

/// The single key of a response whose body is plain text rather than JSON (the server
/// renders it with `text/plain`), used for the `404 Not Found` of an unknown route.
pub const TEXT_KEY: &str = "fireemuText";

/// `404 Not Found` as plain text: what the official emulator's HTTP adapter answers for a
/// path or method it has no route for, before any JSON error envelope exists.
fn not_found_text() -> RestResponse {
    RestResponse {
        status: 404,
        body: json!({TEXT_KEY: "Not Found\n"}),
    }
}

fn bad(e: &JsonError) -> Status {
    Status::invalid_argument(e.to_string())
}

/// Parsed query parameters (repeated keys keep every value).
fn query_params(query: &str) -> BTreeMap<String, Vec<String>> {
    fn decode(s: &str) -> String {
        let bytes = s.as_bytes();
        let mut out = Vec::with_capacity(bytes.len());
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'%' && i + 2 < bytes.len() {
                if let Some(b) = s
                    .get(i + 1..i + 3)
                    .and_then(|h| u8::from_str_radix(h, 16).ok())
                {
                    out.push(b);
                    i += 3;
                    continue;
                }
            }
            out.push(if bytes[i] == b'+' { b' ' } else { bytes[i] });
            i += 1;
        }
        String::from_utf8_lossy(&out).into_owned()
    }
    let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for kv in query.split('&').filter(|s| !s.is_empty()) {
        let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
        out.entry(decode(k)).or_default().push(decode(v));
    }
    out
}

fn first<'a>(params: &'a BTreeMap<String, Vec<String>>, key: &str) -> Option<&'a str> {
    params.get(key).and_then(|v| v.first()).map(String::as_str)
}

/// What a REST path names.
enum Target {
    /// `.../documents` (database root) or a document path.
    Resource(String),
    /// A collection: parent resource + collection ID.
    Collection {
        parent: String,
        collection_id: String,
    },
}

fn classify(resource: &str) -> Result<Target, Status> {
    let Some((db, rest)) = resource.split_once("/documents") else {
        return Err(Status::not_found(format!("unknown resource {resource}")));
    };
    let rest = rest.trim_start_matches('/');
    if rest.is_empty() {
        return Ok(Target::Resource(format!("{db}/documents")));
    }
    let segments: Vec<&str> = rest.split('/').collect();
    if segments.iter().any(|s| s.is_empty()) {
        return Err(Status::invalid_argument("empty path segment"));
    }
    if segments.len() % 2 == 0 {
        Ok(Target::Resource(resource.to_owned()))
    } else {
        let parent = if segments.len() == 1 {
            format!("{db}/documents")
        } else {
            format!(
                "{db}/documents/{}",
                segments[..segments.len() - 1].join("/")
            )
        };
        Ok(Target::Collection {
            parent,
            collection_id: segments[segments.len() - 1].to_owned(),
        })
    }
}

/// The caller of a REST request: its principal plus the reset epoch the request started in
/// (read before the token is verified; the guards refuse a caller from an earlier epoch).
pub struct Caller {
    principal: Principal,
    epoch: u64,
}

impl std::ops::Deref for Caller {
    type Target = Principal;
    fn deref(&self) -> &Principal {
        &self.principal
    }
}

impl RestState {
    /// A user token must be minted for the project of `database` (transaction requests
    /// carry no document the guards could check).
    fn check_database_audience(&self, caller: &Caller, database: &str) -> Result<(), Status> {
        if self.rules.is_none() {
            return Ok(());
        }
        let parent = crate::decode::parse_parent(&format!("{database}/documents"))
            .map_err(|e| crate::gateway::Rejection::Decode(e).to_status())?;
        rules::check_audience(&caller.principal, parent.project.as_str())
    }

    fn principal(&self, authorization: Option<&str>, project: &str) -> Result<Caller, Status> {
        let epoch = self.local.barrier().epoch();
        let principal = match &self.rules {
            Some(r) => r.principal_from_authorization_for_project(authorization, project)?,
            None => Principal::Owner,
        };
        Ok(Caller { principal, epoch })
    }

    fn write_guard<'a>(&'a self, caller: &'a Caller) -> rules::BoxedWriteGuard<'a> {
        let inner = rules::write_guard(self.rules.as_ref(), &caller.principal);
        let barrier = self.local.barrier();
        let epoch = caller.epoch;
        let actor = crate::local::Actor::from_principal(&caller.principal);
        let local = self.local.clone();
        Box::new(move |db, writes, now| {
            rules::same_epoch(&barrier, epoch)?;
            local.set_actor(actor.clone());
            inner(db, writes, now)
        })
    }

    fn read_guard<'a>(&'a self, caller: &'a Caller) -> rules::BoxedReadGuard<'a> {
        let inner = rules::read_guard(self.rules.as_ref(), &caller.principal);
        let barrier = self.local.barrier();
        let epoch = caller.epoch;
        Box::new(move |db, version, check| {
            rules::same_epoch(&barrier, epoch)?;
            inner(db, version, check)
        })
    }

    /// The App Check decision of one REST request (specification sections 12 and 13.1).
    ///
    /// The owner bypass is the emulator's exact owner credential, verified here rather than
    /// taken from the principal, because the principal is `Owner` for everyone while
    /// Security Rules are disabled.
    fn admit_app_check(
        &self,
        req: &RestRequest,
        path: &str,
        action: Option<&str>,
    ) -> Result<(), Status> {
        use fireemu_core_app_check::admission::{AdmissionRequest, PrivilegedBypass};
        let Some(policy) = &self.app_check else {
            return Ok(());
        };
        let header = fireemu_core_app_check::header::classify_app_check_header(&req.app_check);
        let decision = policy.admit(&AdmissionRequest {
            project_id: crate::service::project_of_resource(path),
            transport: "http",
            operation: action.unwrap_or(match req.method.as_str() {
                "GET" => "get",
                "POST" => "create",
                "PATCH" => "patch",
                "DELETE" => "delete",
                _ => "request",
            }),
            bypass: if rules::is_owner_credential(req.authorization.as_deref()) {
                PrivilegedBypass::FirestoreOwner
            } else {
                PrivilegedBypass::None
            },
            header: &header,
            now: self.local.now(),
        });
        match decision.reason {
            None => Ok(()),
            Some(reason) => Err(crate::service::app_check_denied(reason)),
        }
    }

    /// The Firestore emulator's own routes, under `/emulator/v1/projects/`.
    ///
    /// Only `DELETE .../databases/{database}/documents` exists: it drops every document of
    /// the project, which is what `@firebase/rules-unit-testing`'s `clearFirestore()` and
    /// the Emulator UI's "clear data" button call between tests. It takes no credential,
    /// exactly as the official emulator's route does not -- `clearFirestore` sends no
    /// headers at all -- and is reachable only from the loopback listener. A browser page
    /// cannot reach it either: `DELETE` is not a CORS-simple method, so it needs a preflight
    /// that this surface never answers.
    ///
    /// `PUT .../{project}:securityRules` replaces the session's Firestore ruleset, which is
    /// what `@firebase/rules-unit-testing` calls from `initializeTestEnvironment` and from
    /// `loadFirestoreRules`. It carries the same guard as the clear route and for the same
    /// reason: a loopback-only listener plus a method no CORS-simple request can use.
    fn emulator_route(&self, req: &RestRequest, rest: &str) -> Result<RestResponse, Status> {
        if let Some(project) = rest.strip_suffix(":securityRules") {
            return self.security_rules_route(req, project);
        }
        for (suffix, html) in [(":ruleCoverage.html", true), (":ruleCoverage", false)] {
            if let Some(project) = rest.strip_suffix(suffix) {
                return self.rule_coverage_route(req, project, html);
            }
        }
        let mut parts = rest.split('/');
        let (Some(project), Some("databases"), Some(database), Some("documents"), None) = (
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
        ) else {
            return Ok(not_found_text());
        };
        if req.method != "DELETE" {
            return Ok(not_found_text());
        }
        if project.is_empty() || database.is_empty() {
            return Err(Status::invalid_argument(
                "the project and database of an emulator clear must both be named",
            ));
        }
        // The wipe is per project: fireemu isolates a session's databases by project, so
        // clearing one never touches another session's data.
        self.local.reset_project(project);
        Ok(ok(Value::Object(serde_json::Map::new())))
    }

    /// `PUT /emulator/v1/projects/{project}:securityRules`.
    ///
    /// The body is the official one, `{"rules": {"files": [{"name", "content"}]}}`, and the
    /// answer is the official one too: `200` with the compiler's `issues` (fireemu reports
    /// none, so the list is empty) or `400` whose message names the first rejected position
    /// as `L<line>:<column>`, which is the form the CLI and the test libraries print.
    ///
    /// fireemu keeps one Firestore ruleset per session rather than per project -- exactly as
    /// `PUT /v1/rules` on the control API does, and as the official emulator's
    /// `singleProjectMode` does -- so the project in the path is validated but names no
    /// separate slot.
    fn security_rules_route(
        &self,
        req: &RestRequest,
        project: &str,
    ) -> Result<RestResponse, Status> {
        if req.method != "PUT" {
            return Err(Status::invalid_argument(format!(
                "{} is not supported on {}; the ruleset is replaced with PUT",
                req.method, req.path
            )));
        }
        if project.is_empty() || project.contains('/') {
            return Err(Status::invalid_argument(
                "the project of a securityRules load must be named",
            ));
        }
        let Some(rules) = self.rules.as_ref() else {
            return Err(Status::failed_precondition(
                "this daemon evaluates no Security Rules, so none can be loaded",
            ));
        };
        let files = req.body["rules"]["files"].as_array().ok_or_else(|| {
            Status::invalid_argument("rules.files must be an array of {name, content}")
        })?;
        let [file] = files.as_slice() else {
            return Err(Status::invalid_argument(format!(
                "Cloud Firestore takes exactly one rules file, got {}",
                files.len()
            )));
        };
        let source = file["content"].as_str().ok_or_else(|| {
            Status::invalid_argument("rules.files[0].content must be the rules source")
        })?;
        let barrier = self.local.barrier();
        let _admitted = barrier.admit();
        match rules.replace_source(source) {
            // No issues: `{}`, the proto3 JSON of an empty list (what the official
            // emulator answers).
            Ok(()) => Ok(ok(json!({}))),
            Err(rules::RulesLoadError::Compile(e)) => Err(Status::invalid_argument(format!(
                "Error compiling rules:\nL{}:{} {}",
                e.line, e.column, e.message
            ))),
            Err(rules::RulesLoadError::Publish(error)) => Err(Status::internal(format!(
                "rules publication failed: {error}"
            ))),
        }
    }

    /// `GET /emulator/v1/projects/{project}:ruleCoverage` and its `.html` form.
    fn rule_coverage_route(
        &self,
        req: &RestRequest,
        project: &str,
        html: bool,
    ) -> Result<RestResponse, Status> {
        if req.method != "GET" {
            return Err(Status::invalid_argument(format!(
                "{} is not supported on {}; a coverage report is read with GET",
                req.method, req.path
            )));
        }
        if project.is_empty() || project.contains('/') {
            return Err(Status::invalid_argument(
                "the project of a coverage report must be named",
            ));
        }
        let Some(rules) = self.rules.as_ref() else {
            return Err(Status::failed_precondition(
                "this daemon evaluates no Security Rules, so it reports no coverage",
            ));
        };
        let loaded = rules.rules().snapshot().map_err(Status::internal)?;
        let diagnostics = loaded
            .diagnostics
            .lock()
            .map_err(|_| Status::internal("rules diagnostics lock poisoned"))?;
        Ok(if html {
            ok(json!({
                coverage::HTML_KEY: coverage::coverage_html(&loaded, diagnostics.coverage()),
            }))
        } else {
            ok(coverage::coverage_json(&loaded, diagnostics.coverage()))
        })
    }

    /// Handles one request.
    pub fn handle(&self, req: &RestRequest) -> RestResponse {
        match self.dispatch(req) {
            Ok(r) => r,
            Err(s) => error_response(&s),
        }
    }

    fn dispatch(&self, req: &RestRequest) -> Result<RestResponse, Status> {
        // The custom-method suffix is recognised on the raw path (an encoded colon inside a
        // document ID is data, not routing syntax); segments are decoded afterwards.
        if let Some(rest) = decode_path(&req.path)?.strip_prefix("/emulator/v1/projects/") {
            return self.emulator_route(req, rest);
        }
        let (raw_resource, action) = match req.path.rsplit_once(':') {
            Some((r, a)) if CUSTOM_METHODS.contains(&a) => (r, Some(a)),
            // A colon in the last segment is routing syntax (a document ID carries it
            // percent-encoded), so an unknown method is a route that does not exist -- never
            // a collection whose ID happens to contain the colon.
            Some((_, a)) if !a.contains('/') => return Ok(not_found_text()),
            _ => (req.path.as_str(), None),
        };
        let decoded = decode_path(raw_resource)?;
        let Some(path) = decoded.strip_prefix("/v1/") else {
            return Ok(not_found_text());
        };
        // Only the documents surface is served: `/v1/projects/{p}/databases` and the
        // database resources are the Admin API, which the official emulator has no route
        // for either.
        if !path.contains("/documents") {
            return Ok(not_found_text());
        }
        let params = query_params(&req.query);
        // App Check, once the route and the target project are resolved and before the
        // Firebase Auth credential, Security Rules and every mutation (spec 7.4).
        self.admit_app_check(req, path, action)?;
        let principal = self.principal(
            req.authorization.as_deref(),
            crate::service::project_of_resource(path),
        )?;
        if let Some(action) = action {
            if req.method != "POST" {
                return Ok(not_found_text());
            }
            return self.custom_method(&principal, path, action, &req.body);
        }
        match (req.method.as_str(), classify(path)?) {
            ("GET", Target::Resource(name)) => self.get(&principal, &name, &params),
            (
                "GET",
                Target::Collection {
                    parent,
                    collection_id,
                },
            ) => self.list(&principal, &parent, &collection_id, &params),
            (
                "POST",
                Target::Collection {
                    parent,
                    collection_id,
                },
            ) => self.create(&principal, &parent, &collection_id, &params, &req.body),
            ("PATCH", Target::Resource(name)) => self.patch(&principal, &name, &params, &req.body),
            ("DELETE", Target::Resource(name)) => self.delete(&principal, &name, &params),
            ("DELETE", Target::Collection { .. }) => Err(Status::invalid_argument(format!(
                "Document name \"{path}\" lacks \"/\" at index {}.",
                path.len()
            ))),
            _ => Ok(not_found_text()),
        }
    }

    fn get(
        &self,
        principal: &Caller,
        name: &str,
        params: &BTreeMap<String, Vec<String>>,
    ) -> Result<RestResponse, Status> {
        let req = pb::GetDocumentRequest {
            name: name.to_owned(),
            mask: mask_from_paths(params.get("mask.fieldPaths").map_or(&[][..], Vec::as_slice)),
            consistency_selector: match (first(params, "transaction"), first(params, "readTime")) {
                (Some(_), Some(_)) => {
                    return Err(Status::invalid_argument(
                        "transaction and readTime are mutually exclusive",
                    ))
                }
                (Some(t), None) => {
                    Some(pb::get_document_request::ConsistencySelector::Transaction(
                        base64_decode(t).map_err(|e| bad(&e))?,
                    ))
                }
                (None, Some(rt)) => Some(pb::get_document_request::ConsistencySelector::ReadTime(
                    json::read_time_from_json(&json!({"readTime": rt}))
                        .map_err(|e| bad(&e))?
                        .unwrap_or_default(),
                )),
                (None, None) => None,
            },
            request_options: None,
        };
        let guard = self.read_guard(principal);
        let snapshot = self.local.get_document_snapshot(&req, &*guard)?;
        let doc = snapshot.into_response()?;
        Ok(ok(document_to_json(&doc)))
    }

    fn list(
        &self,
        principal: &Caller,
        parent: &str,
        collection_id: &str,
        params: &BTreeMap<String, Vec<String>>,
    ) -> Result<RestResponse, Status> {
        let req = pb::ListDocumentsRequest {
            parent: parent.to_owned(),
            collection_id: collection_id.to_owned(),
            page_size: first(params, "pageSize")
                .and_then(|s| s.parse().ok())
                .unwrap_or(0),
            page_token: first(params, "pageToken").unwrap_or("").to_owned(),
            order_by: first(params, "orderBy").unwrap_or("").to_owned(),
            mask: mask_from_paths(params.get("mask.fieldPaths").map_or(&[][..], Vec::as_slice)),
            show_missing: first(params, "showMissing") == Some("true"),
            consistency_selector: match (first(params, "transaction"), first(params, "readTime")) {
                (Some(_), Some(_)) => {
                    return Err(Status::invalid_argument(
                        "transaction and readTime are mutually exclusive",
                    ))
                }
                (Some(t), None) => Some(
                    pb::list_documents_request::ConsistencySelector::Transaction(
                        base64_decode(t).map_err(|e| bad(&e))?,
                    ),
                ),
                (None, Some(rt)) => {
                    Some(pb::list_documents_request::ConsistencySelector::ReadTime(
                        json::read_time_from_json(&json!({"readTime": rt}))
                            .map_err(|e| bad(&e))?
                            .unwrap_or_default(),
                    ))
                }
                (None, None) => None,
            },
            request_options: None,
        };
        let guard = self.read_guard(principal);
        let response = self.local.list_documents(&req, &*guard)?;
        let mut body = json!({"documents": response.documents.iter().map(document_to_json).collect::<Vec<_>>()});
        if !response.next_page_token.is_empty() {
            body["nextPageToken"] = Value::String(response.next_page_token);
        }
        Ok(ok(json::without_empty(body)))
    }

    fn create(
        &self,
        principal: &Caller,
        parent: &str,
        collection_id: &str,
        params: &BTreeMap<String, Vec<String>>,
        body: &Value,
    ) -> Result<RestResponse, Status> {
        let req = pb::CreateDocumentRequest {
            parent: parent.to_owned(),
            collection_id: collection_id.to_owned(),
            document_id: first(params, "documentId").unwrap_or("").to_owned(),
            document: Some(document_from_json(body).map_err(|e| bad(&e))?),
            mask: mask_from_paths(params.get("mask.fieldPaths").map_or(&[][..], Vec::as_slice)),
            request_options: None,
        };
        let guard = self.write_guard(principal);
        let doc = self.local.create_document_with(&req, &*guard)?;
        Ok(ok(document_to_json(&doc)))
    }

    fn patch(
        &self,
        principal: &Caller,
        name: &str,
        params: &BTreeMap<String, Vec<String>>,
        body: &Value,
    ) -> Result<RestResponse, Status> {
        let mut document = document_from_json(body).map_err(|e| bad(&e))?;
        if document.name.is_empty() {
            name.clone_into(&mut document.name);
        } else if document.name != name {
            return Err(Status::invalid_argument(
                "document.name does not match the URL",
            ));
        }
        let req = pb::UpdateDocumentRequest {
            document: Some(document),
            update_mask: mask_from_paths(
                params
                    .get("updateMask.fieldPaths")
                    .map_or(&[][..], Vec::as_slice),
            ),
            mask: mask_from_paths(params.get("mask.fieldPaths").map_or(&[][..], Vec::as_slice)),
            current_document: precondition_from_params(params)?,
            request_options: None,
        };
        let (parsed, write) = LocalBackend::plan_update(&req)?;
        let guard = self.write_guard(principal);
        let doc = self
            .local
            .execute_planned_with(&parsed, &write, req.mask.as_ref(), &*guard)?;
        Ok(ok(document_to_json(&doc)))
    }

    fn delete(
        &self,
        principal: &Caller,
        name: &str,
        params: &BTreeMap<String, Vec<String>>,
    ) -> Result<RestResponse, Status> {
        let req = pb::DeleteDocumentRequest {
            name: name.to_owned(),
            current_document: precondition_from_params(params)?,
            request_options: None,
        };
        let guard = self.write_guard(principal);
        self.local.delete_document_with(&req, &*guard)?;
        Ok(ok(json!({})))
    }

    fn custom_method(
        &self,
        principal: &Caller,
        resource: &str,
        action: &str,
        body: &Value,
    ) -> Result<RestResponse, Status> {
        match action {
            "commit" => self.commit(principal, resource, body),
            "batchWrite" => self.batch_write(principal, resource, body),
            "batchGet" => self.batch_get(principal, resource, body),
            "beginTransaction" => {
                let database = database_of(resource)?;
                self.check_database_audience(principal, &database)?;
                let token = self.local.begin_transaction(&pb::BeginTransactionRequest {
                    database,
                    options: Some(
                        transaction_options_from_json(body.get("options")).map_err(|e| bad(&e))?,
                    ),
                    request_options: None,
                })?;
                Ok(ok(json!({"transaction": base64_encode(&token)})))
            }
            "rollback" => {
                let database = database_of(resource)?;
                self.check_database_audience(principal, &database)?;
                self.local.rollback(&pb::RollbackRequest {
                    database,
                    transaction: transaction_bytes(body.get("transaction"))?,
                    request_options: None,
                })?;
                Ok(ok(json!({})))
            }
            "runQuery" => self.run_query(principal, resource, body),
            "runAggregationQuery" => self.run_aggregation_query(principal, resource, body),
            "partitionQuery" => self.partition_query(principal, resource, body),
            "listCollectionIds" => {
                if let Some(rules) = &self.rules {
                    rules.require_owner(principal, "listCollectionIds")?;
                }
                let response = self
                    .local
                    .list_collection_ids(&pb::ListCollectionIdsRequest {
                        parent: resource.to_owned(),
                        page_size: json::int32(body.get("pageSize"), "pageSize")
                            .map_err(|e| bad(&e))?
                            .unwrap_or(0),
                        page_token: body
                            .get("pageToken")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_owned(),
                        request_options: None,
                        consistency_selector: None,
                    })?;
                let mut out = json!({"collectionIds": response.collection_ids});
                if !response.next_page_token.is_empty() {
                    out["nextPageToken"] = Value::String(response.next_page_token);
                }
                Ok(ok(out))
            }
            _ => Ok(not_found_text()),
        }
    }

    /// `:partitionQuery`, which the official emulator answers `UNIMPLEMENTED` (a documented
    /// divergence: fireemu serves it).
    fn partition_query(
        &self,
        principal: &Caller,
        resource: &str,
        body: &Value,
    ) -> Result<RestResponse, Status> {
        json::strict_keys(
            body,
            &[
                "structuredQuery",
                "partitionCount",
                "pageToken",
                "pageSize",
                "readTime",
            ],
        )
        .map_err(|e| bad(&e))?;
        if let Some(rules) = &self.rules {
            rules.require_owner(principal, "partitionQuery")?;
        }
        let Some(sq) = body.get("structuredQuery") else {
            return Err(Status::invalid_argument("structuredQuery is required"));
        };
        let structured = structured_query_from_json(sq).map_err(|e| bad(&e))?;
        let partition_count = match body.get("partitionCount") {
            None => 0,
            Some(Value::String(s)) => s
                .parse::<i64>()
                .map_err(|_| Status::invalid_argument("partitionCount must be an integer"))?,
            Some(Value::Number(n)) => n
                .as_i64()
                .ok_or_else(|| Status::invalid_argument("partitionCount must be an integer"))?,
            Some(_) => {
                return Err(Status::invalid_argument(
                    "partitionCount must be an integer",
                ))
            }
        };
        let response = self.local.partition_query(&pb::PartitionQueryRequest {
            parent: resource.to_owned(),
            partition_count,
            page_token: body
                .get("pageToken")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            page_size: json::int32(body.get("pageSize"), "pageSize")
                .map_err(|e| bad(&e))?
                .unwrap_or(0),
            query_type: Some(pb::partition_query_request::QueryType::StructuredQuery(
                structured,
            )),
            consistency_selector: json::read_time_from_json(body)
                .map_err(|e| bad(&e))?
                .map(pb::partition_query_request::ConsistencySelector::ReadTime),
            request_options: None,
        })?;
        let mut out = json!({
            "partitions": response.partitions.iter().map(|c| json!({
                "values": c.values.iter().map(value_to_json).collect::<Vec<_>>(),
                "before": c.before,
            })).collect::<Vec<_>>(),
        });
        if !response.next_page_token.is_empty() {
            out["nextPageToken"] = Value::String(response.next_page_token);
        }
        Ok(ok(out))
    }

    fn commit(
        &self,
        principal: &Caller,
        resource: &str,
        body: &Value,
    ) -> Result<RestResponse, Status> {
        json::strict_keys(body, &["writes", "transaction"]).map_err(|e| bad(&e))?;
        let req = pb::CommitRequest {
            database: database_of(resource)?,
            writes: writes_from_json(body)?,
            transaction: transaction_bytes(body.get("transaction"))?,
            request_options: None,
        };
        let guard = self.write_guard(principal);
        let response = self.local.commit_with(&req, &*guard)?;
        Ok(ok(commit_to_json(&response)))
    }

    fn batch_write(
        &self,
        principal: &Caller,
        resource: &str,
        body: &Value,
    ) -> Result<RestResponse, Status> {
        json::strict_keys(body, &["writes", "labels"]).map_err(|e| bad(&e))?;
        let req = pb::BatchWriteRequest {
            database: database_of(resource)?,
            writes: writes_from_json(body)?,
            labels: std::collections::HashMap::new(),
            request_options: None,
        };
        let guard = self.write_guard(principal);
        let response = self.local.batch_write_with(&req, &*guard)?;
        Ok(ok(json::without_empty(json!({
            "writeResults": response.write_results.iter().map(write_result_to_json).collect::<Vec<_>>(),
            "status": response.status.iter().map(|s| json!({"code": s.code, "message": s.message})).collect::<Vec<_>>(),
        }))))
    }

    fn batch_get(
        &self,
        principal: &Caller,
        resource: &str,
        body: &Value,
    ) -> Result<RestResponse, Status> {
        json::strict_keys(
            body,
            &[
                "documents",
                "mask",
                "transaction",
                "newTransaction",
                "readTime",
            ],
        )
        .map_err(|e| bad(&e))?;
        let documents: Vec<String> = body
            .get("documents")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default();
        exclusive_selectors(body)?;
        let consistency_selector = if let Some(t) = body.get("transaction") {
            Some(
                pb::batch_get_documents_request::ConsistencySelector::Transaction(
                    transaction_bytes(Some(t))?,
                ),
            )
        } else if let Some(rt) = json::read_time_from_json(body).map_err(|e| bad(&e))? {
            Some(pb::batch_get_documents_request::ConsistencySelector::ReadTime(rt))
        } else {
            match body.get("newTransaction") {
                Some(o) => Some(
                    pb::batch_get_documents_request::ConsistencySelector::NewTransaction(
                        transaction_options_from_json(Some(o)).map_err(|e| bad(&e))?,
                    ),
                ),
                None => None,
            }
        };
        let req = pb::BatchGetDocumentsRequest {
            database: database_of(resource)?,
            documents,
            mask: mask_from_json(body.get("mask")).map_err(|e| bad(&e))?,
            request_options: None,
            consistency_selector,
        };
        let guard = self.read_guard(principal);
        let outcome = self.local.batch_get_documents(&req, &*guard)?;
        let read_time = optional_timestamp_to_json(Some(&encode_instant(outcome.read_time)));
        let mut out: Vec<Value> = outcome
            .items
            .iter()
            .map(|item| match item.encode(outcome.mask.as_deref()) {
                pb::batch_get_documents_response::Result::Found(d) => {
                    json!({"found": document_to_json(&d), "readTime": read_time})
                }
                pb::batch_get_documents_response::Result::Missing(n) => {
                    json!({"missing": n, "readTime": read_time})
                }
            })
            .collect();
        if !outcome.transaction.is_empty() {
            // The new transaction is announced in a response of its own, ahead of the
            // documents, as the official emulator streams it.
            let token = Value::String(base64_encode(&outcome.transaction));
            out.insert(0, json!({"transaction": token}));
        }
        Ok(ok(Value::Array(out)))
    }

    fn run_query(
        &self,
        principal: &Caller,
        resource: &str,
        body: &Value,
    ) -> Result<RestResponse, Status> {
        json::strict_keys(
            body,
            &[
                "structuredQuery",
                "transaction",
                "newTransaction",
                "readTime",
                "explainOptions",
            ],
        )
        .map_err(|e| bad(&e))?;
        let Some(sq) = body.get("structuredQuery") else {
            return Err(Status::invalid_argument("structuredQuery is required"));
        };
        let structured = structured_query_from_json(sq).map_err(|e| bad(&e))?;
        exclusive_selectors(body)?;
        let consistency_selector = if let Some(t) = body.get("transaction") {
            Some(pb::run_query_request::ConsistencySelector::Transaction(
                transaction_bytes(Some(t))?,
            ))
        } else if let Some(rt) = json::read_time_from_json(body).map_err(|e| bad(&e))? {
            Some(pb::run_query_request::ConsistencySelector::ReadTime(rt))
        } else {
            match body.get("newTransaction") {
                Some(o) => Some(pb::run_query_request::ConsistencySelector::NewTransaction(
                    transaction_options_from_json(Some(o)).map_err(|e| bad(&e))?,
                )),
                None => None,
            }
        };
        let req = pb::RunQueryRequest {
            parent: resource.to_owned(),
            explain_options: None,
            request_options: None,
            query_type: Some(pb::run_query_request::QueryType::StructuredQuery(
                structured,
            )),
            consistency_selector,
        };
        let guard = self.read_guard(principal);
        let (responses, _warnings) = self.local.run_query(&req, &*guard)?;
        let out: Vec<Value> = responses
            .iter()
            .map(|r| {
                let mut v = json!({});
                if let Some(d) = &r.document {
                    v["document"] = document_to_json(d);
                }
                if r.read_time.is_some() {
                    v["readTime"] = optional_timestamp_to_json(r.read_time.as_ref());
                }
                if !r.transaction.is_empty() {
                    v["transaction"] = Value::String(base64_encode(&r.transaction));
                }
                if r.skipped_results != 0 {
                    v["skippedResults"] = json!(r.skipped_results);
                }
                if matches!(
                    r.continuation_selector,
                    Some(pb::run_query_response::ContinuationSelector::Done(true))
                ) {
                    v["done"] = json!(true);
                }
                v
            })
            .collect();
        Ok(ok(Value::Array(out)))
    }

    fn run_aggregation_query(
        &self,
        principal: &Caller,
        resource: &str,
        body: &Value,
    ) -> Result<RestResponse, Status> {
        json::strict_keys(
            body,
            &[
                "structuredAggregationQuery",
                "transaction",
                "newTransaction",
                "readTime",
                "explainOptions",
            ],
        )
        .map_err(|e| bad(&e))?;
        let Some(saq) = body.get("structuredAggregationQuery") else {
            return Err(Status::invalid_argument(
                "structuredAggregationQuery is required",
            ));
        };
        let aggregation = aggregation_query_from_json(saq).map_err(|e| bad(&e))?;
        if !matches!(
            aggregation.query_type,
            Some(pb::structured_aggregation_query::QueryType::StructuredQuery(_))
        ) {
            return Err(Status::invalid_argument(
                "aggregation query requires a structuredQuery",
            ));
        }
        exclusive_selectors(body)?;
        let consistency_selector = if let Some(t) = body.get("transaction") {
            Some(
                pb::run_aggregation_query_request::ConsistencySelector::Transaction(
                    transaction_bytes(Some(t))?,
                ),
            )
        } else if let Some(rt) = json::read_time_from_json(body).map_err(|e| bad(&e))? {
            Some(pb::run_aggregation_query_request::ConsistencySelector::ReadTime(rt))
        } else {
            match body.get("newTransaction") {
                Some(o) => Some(
                    pb::run_aggregation_query_request::ConsistencySelector::NewTransaction(
                        transaction_options_from_json(Some(o)).map_err(|e| bad(&e))?,
                    ),
                ),
                None => None,
            }
        };
        let req = pb::RunAggregationQueryRequest {
            parent: resource.to_owned(),
            explain_options: None,
            request_options: None,
            query_type: Some(
                pb::run_aggregation_query_request::QueryType::StructuredAggregationQuery(
                    aggregation,
                ),
            ),
            consistency_selector,
        };
        let guard = self.read_guard(principal);
        let response = self.local.run_aggregation_query(&req, &*guard)?;
        let fields: serde_json::Map<String, Value> = response
            .result
            .as_ref()
            .map(|r| {
                r.aggregate_fields
                    .iter()
                    .map(|(k, v)| (k.clone(), value_to_json(v)))
                    .collect()
            })
            .unwrap_or_default();
        let mut v = json!({"result": {"aggregateFields": fields}, "readTime": optional_timestamp_to_json(response.read_time.as_ref()), "done": true});
        if !response.transaction.is_empty() {
            v["transaction"] = Value::String(base64_encode(&response.transaction));
        }
        Ok(ok(Value::Array(vec![v])))
    }
}

/// Percent-decodes every path segment (document IDs may carry spaces, Unicode, `%`);
/// an escape that would introduce a `/` changes the structure and is refused.
fn decode_path(path: &str) -> Result<String, Status> {
    let mut out = String::with_capacity(path.len());
    for (i, segment) in path.split('/').enumerate() {
        if i > 0 {
            out.push('/');
        }
        if !segment.contains('%') {
            out.push_str(segment);
            continue;
        }
        let bytes = segment.as_bytes();
        let mut raw = Vec::with_capacity(bytes.len());
        let mut k = 0;
        while k < bytes.len() {
            if bytes[k] == b'%' {
                let hex = segment
                    .get(k + 1..k + 3)
                    .and_then(|h| u8::from_str_radix(h, 16).ok())
                    .ok_or_else(|| Status::invalid_argument("malformed percent escape in path"))?;
                raw.push(hex);
                k += 3;
            } else {
                raw.push(bytes[k]);
                k += 1;
            }
        }
        let text = String::from_utf8(raw)
            .map_err(|_| Status::invalid_argument("path segment is not UTF-8"))?;
        if text.contains('/') {
            return Err(Status::invalid_argument("encoded '/' in a path segment"));
        }
        out.push_str(&text);
    }
    Ok(out)
}

/// Custom methods of the REST surface (`resource:method`).
const CUSTOM_METHODS: &[&str] = &[
    "commit",
    "batchWrite",
    "batchGet",
    "beginTransaction",
    "rollback",
    "runQuery",
    "runAggregationQuery",
    "listCollectionIds",
    "partitionQuery",
];

fn database_of(resource: &str) -> Result<String, Status> {
    resource
        .strip_suffix("/documents")
        .map(str::to_owned)
        .ok_or_else(|| {
            Status::invalid_argument(format!("{resource} is not a database documents root"))
        })
}

/// `transaction`, `readTime` and `newTransaction` form a oneof: at most one may be given.
fn exclusive_selectors(body: &Value) -> Result<(), Status> {
    let given = ["transaction", "readTime", "newTransaction"]
        .iter()
        .filter(|k| body.get(**k).is_some_and(|v| !v.is_null()))
        .count();
    if given > 1 {
        return Err(Status::invalid_argument(
            "transaction, readTime and newTransaction are mutually exclusive",
        ));
    }
    Ok(())
}

fn transaction_bytes(v: Option<&Value>) -> Result<Vec<u8>, Status> {
    match v {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::String(s)) => base64_decode(s).map_err(|e| bad(&e)),
        Some(_) => Err(Status::invalid_argument(
            "transaction must be a base64 string",
        )),
    }
}

fn writes_from_json(body: &Value) -> Result<Vec<pb::Write>, Status> {
    body.get("writes")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .map(write_from_json)
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()
        .map_err(|e| bad(&e))
        .map(Option::unwrap_or_default)
}

fn precondition_from_params(
    params: &BTreeMap<String, Vec<String>>,
) -> Result<Option<pb::Precondition>, Status> {
    if let Some(e) = first(params, "currentDocument.exists") {
        let exists = match e {
            "true" => true,
            "false" => false,
            _ => {
                return Err(Status::invalid_argument(
                    "currentDocument.exists must be true or false",
                ))
            }
        };
        return Ok(Some(pb::Precondition {
            condition_type: Some(pb::precondition::ConditionType::Exists(exists)),
        }));
    }
    if let Some(t) = first(params, "currentDocument.updateTime") {
        return precondition_from_json(Some(&json!({"updateTime": t}))).map_err(|e| bad(&e));
    }
    Ok(None)
}
