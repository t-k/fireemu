//! `/ui/api/*`: privileged, same-origin fronts to the runtime's surfaces.

use std::sync::Arc;

use ftd_adapter_grpc::rest::RestRequest;
use ftd_adapter_http::identity_toolkit::RequestHeaders;
use ftd_adapter_http::storage::StorageRequest;
use ftd_core_functions::manifest::Trigger;
use serde_json::{json, Value};

use crate::{sse, UiBody, UiRequest, UiResponse, UiState, MAX_JSON_BODY_BYTES};

/// Routes `rest` (the path after `/ui/api/`).
pub async fn route(state: &Arc<UiState>, rest: &str, req: &UiRequest) -> UiResponse {
    if let Some(path) = rest.strip_prefix("firestore/") {
        return if path == "watch" {
            sse::firestore_watch(state, req)
        } else {
            firestore(state, path, req)
        };
    }
    if let Some(path) = rest.strip_prefix("auth/") {
        return auth(state, path, req);
    }
    if let Some(path) = rest.strip_prefix("storage/") {
        return if path == "buckets" {
            buckets(state, req)
        } else {
            storage(state, path, req)
        };
    }
    if rest == "functions" {
        return functions(state);
    }
    if rest == "functions/logs" {
        return sse::functions_logs(state, req);
    }
    if let Some(path) = rest.strip_prefix("control/") {
        return control(state, path, req).await;
    }
    UiResponse::error(404, "NOT_FOUND")
}

/// The JSON body of a request (`{}` when empty), or the error to answer with.
fn json_body(req: &UiRequest) -> Result<Value, UiResponse> {
    if req.body.len() > MAX_JSON_BODY_BYTES {
        return Err(UiResponse::error(413, "PAYLOAD_TOO_LARGE"));
    }
    if req.body.is_empty() {
        return Ok(Value::Object(serde_json::Map::new()));
    }
    serde_json::from_slice(&req.body)
        .map_err(|e| UiResponse::error(400, &format!("INVALID_JSON_PAYLOAD : {e}")))
}

/// Firestore REST as owner: `firestore/v1/projects/...` → `/v1/projects/...`.
fn firestore(state: &UiState, path: &str, req: &UiRequest) -> UiResponse {
    let body = match json_body(req) {
        Ok(b) => b,
        Err(r) => return r,
    };
    let response = state.rest.handle(&RestRequest {
        method: req.method.clone(),
        path: format!("/{path}"),
        query: req.query.clone(),
        authorization: Some("Bearer owner".to_owned()),
        body,
    });
    let mut out = UiResponse::json(response.status, &response.body);
    if ftd_adapter_grpc::rest::drops_connection(&response) {
        // The fault plan's `dropConnection` keeps its meaning through this front.
        out.headers
            .push((crate::DROP_CONNECTION_HEADER.to_owned(), "1".to_owned()));
    }
    out
}

/// Identity Toolkit as owner: `auth/identitytoolkit.googleapis.com/v1/projects/{p}/...` and
/// `auth/emulator/v1/projects/{p}/...`.
fn auth(state: &UiState, path: &str, req: &UiRequest) -> UiResponse {
    if !path.starts_with("identitytoolkit.googleapis.com/v1/projects/")
        && !path.starts_with("emulator/v1/projects/")
    {
        return UiResponse::error(
            404,
            "NOT_FOUND : only project-scoped Identity Toolkit and emulator routes are exposed",
        );
    }
    let body = match json_body(req) {
        Ok(b) => b,
        Err(r) => return r,
    };
    let full = if req.query.is_empty() {
        format!("/{path}")
    } else {
        format!("/{path}?{}", req.query)
    };
    let headers = RequestHeaders {
        authorization: Some("Bearer owner".to_owned()),
        origin: None,
        content_type: Some("application/json".to_owned()),
        // Action links point at the Auth listener, not at this one.
        host: Some(state.info.http_addr.clone()),
    };
    let response = ftd_adapter_http::identity_toolkit::handle_with(
        &state.auth,
        &req.method,
        &full,
        &headers,
        &body,
    );
    UiResponse::json(response.status, &response.body)
}

/// The buckets of one session project (`?project=`, the default project otherwise): its
/// two conventional buckets plus the ones the session declared.
fn buckets(state: &UiState, req: &UiRequest) -> UiResponse {
    let project = req
        .param("project")
        .unwrap_or_else(|| state.info.project.clone());
    let known = state
        .control
        .sessions
        .lock()
        .is_ok_and(|s| s.values().any(|p| *p == project));
    if !known {
        return UiResponse::error(
            404,
            &format!("NOT_FOUND : no session owns project {project:?}"),
        );
    }
    let mut list = Vec::new();
    for suffix in ["appspot.com", "firebasestorage.app"] {
        list.push(json!({"name": format!("{project}.{suffix}"), "project": project, "default": suffix == "appspot.com"}));
    }
    let declared = state
        .control
        .tenancy
        .read()
        .map(|t| t.declared_buckets(&project))
        .unwrap_or_default();
    for name in declared {
        list.push(json!({"name": name, "project": project, "default": false}));
    }
    UiResponse::json(200, &json!({"buckets": list}))
}

/// Storage JSON API as owner: `storage/storage/v1/b/...`, `storage/upload/storage/v1/...`,
/// `storage/download/storage/v1/...`.
fn storage(state: &UiState, path: &str, req: &UiRequest) -> UiResponse {
    if !path.starts_with("storage/v1/")
        && !path.starts_with("upload/storage/v1/")
        && !path.starts_with("download/storage/v1/")
    {
        return UiResponse::error(404, "NOT_FOUND : only the JSON API is exposed");
    }
    let mut headers = std::collections::BTreeMap::new();
    headers.insert("authorization".to_owned(), "Bearer owner".to_owned());
    for name in [
        "content-type",
        "content-range",
        "range",
        "x-upload-content-type",
    ] {
        if let Some(v) = req.header(name) {
            headers.insert(name.to_owned(), v.to_owned());
        }
    }
    // The Storage handler takes the request by value and moves the body into the object
    // store. This front only borrows its own request, so it still copies once here; the
    // copy ends at this boundary.
    let response = ftd_adapter_http::storage::handle(
        &state.storage,
        StorageRequest {
            method: req.method.clone(),
            path: format!("/{path}"),
            query: req.query.clone(),
            host: req.header("host").map(str::to_owned),
            headers,
            body: req.body.clone(),
        },
    );
    let mut headers = response.headers;
    if path.starts_with("download/storage/v1/") {
        // Object bytes come back with the content type they were uploaded with; on this
        // privileged origin they are never rendered, only saved (the app downloads them
        // as blobs).
        headers.retain(|(k, _)| k != "content-disposition" && k != "x-content-type-options");
        headers.push(("content-disposition".to_owned(), "attachment".to_owned()));
        headers.push(("x-content-type-options".to_owned(), "nosniff".to_owned()));
    }
    UiResponse {
        status: response.status,
        headers,
        body: UiBody::Full(response.body),
    }
}

/// A trigger as JSON (kind plus what it binds to).
#[must_use]
pub fn trigger_json(trigger: &Trigger) -> Value {
    match trigger {
        Trigger::Http { callable } => json!({"kind": "http", "callable": callable}),
        Trigger::Firestore {
            event,
            database,
            document,
            with_auth_context,
        } => json!({
            "kind": "firestore",
            "event": event.event_type(),
            "database": database,
            "document": document.as_str(),
            "withAuthContext": with_auth_context,
        }),
        Trigger::PubSub { topic } => json!({"kind": "pubsub", "topic": topic}),
        Trigger::Auth { event } => json!({"kind": "auth", "event": event.event_type()}),
        Trigger::Storage { event, bucket } => {
            json!({"kind": "storage", "event": event.event_type(), "bucket": bucket})
        }
        Trigger::Schedule {
            schedule,
            time_zone,
        } => json!({"kind": "schedule", "schedule": schedule.as_str(), "timeZone": time_zone}),
    }
}

fn record_json(r: &ftd_adapter_functions::runtime::InvocationRecord) -> Value {
    json!({"eventId": r.event_id.to_string(), "function": r.function, "attempt": r.attempt, "outcome": r.outcome})
}

/// `GET functions`: the manifest with trigger details, the runtime status, the invocation
/// history and dead letters.
fn functions(state: &UiState) -> UiResponse {
    let Some(runtime) = &state.functions else {
        return UiResponse::json(
            200,
            &json!({"configured": false, "functions": [], "history": [], "deadLetters": []}),
        );
    };
    let functions: Vec<Value> = runtime
        .manifest()
        .functions
        .iter()
        .map(|f| {
            json!({
                "name": f.name,
                "region": f.region,
                "entryPoint": f.entry_point,
                "trigger": trigger_json(&f.trigger),
                "timeoutSeconds": f.timeout_seconds,
                "retry": f.retry,
                "concurrency": f.concurrency,
            })
        })
        .collect();
    UiResponse::json(
        200,
        &json!({
            "configured": true,
            "project": runtime.project(),
            "source": state.info.functions_source,
            "functions": functions,
            "status": runtime.status(),
            "history": runtime.history().iter().map(record_json).collect::<Vec<_>>(),
            "deadLetters": runtime.dead_letters().iter().map(record_json).collect::<Vec<_>>(),
            "logs": runtime.runner().logs(),
        }),
    )
}

/// The control API: `control/v1/...` → `/v1/...` (no `Origin`: the UI guard already ran).
async fn control(state: &UiState, path: &str, req: &UiRequest) -> UiResponse {
    if !path.starts_with("v1/") && !path.starts_with("health/") {
        return UiResponse::error(404, "NOT_FOUND");
    }
    let body = match json_body(req) {
        Ok(b) => b,
        Err(r) => return r,
    };
    let full = if req.query.is_empty() {
        format!("/{path}")
    } else {
        format!("/{path}?{}", req.query)
    };
    let headers = RequestHeaders::default();
    let response = if req.method == "POST" && ftd_adapter_http::control::is_await_idle_path(&full) {
        ftd_adapter_http::control::await_idle(&state.control, &body).await
    } else {
        ftd_adapter_http::control::handle_with(&state.control, &req.method, &full, &headers, &body)
    };
    UiResponse::json(response.status, &response.body)
}
