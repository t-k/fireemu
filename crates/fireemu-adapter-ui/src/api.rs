//! `/ui/api/*`: privileged, same-origin fronts to the runtime's surfaces.

use std::sync::Arc;

use fireemu_adapter_grpc::rest::RestRequest;
use fireemu_adapter_http::identity_toolkit::RequestHeaders;
use fireemu_adapter_http::storage::StorageRequest;
use fireemu_core_functions::manifest::Trigger;
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
    if rest == "functions/alerts" {
        return alerts(state, req);
    }
    if let Some(name) = rest
        .strip_prefix("functions/")
        .and_then(|r| r.strip_suffix(":invoke"))
    {
        return invoke_function(state, name, req).await;
    }
    if let Some(name) = rest
        .strip_prefix("functions/")
        .and_then(|r| r.strip_suffix(":enqueue"))
    {
        return enqueue_task(state, name, req);
    }
    if let Some(path) = rest.strip_prefix("appcheck/") {
        return app_check(state, path, req);
    }
    if let Some(path) = rest.strip_prefix("control/") {
        return control(state, path, req).await;
    }
    UiResponse::error(404, "NOT_FOUND")
}

/// The `CloudEvent` type every `onAlertPublished` family member is registered under
/// (`firebase-functions/v2/alerts` `eventType`).
const ALERT_EVENT_TYPE: &str = "google.firebase.firebasealerts.alerts.v1.published";

/// Publishes a Firebase alert the way the official Emulator Suite UI does: it builds the
/// `CloudEvent` an alert carries and POSTs it to the Eventarc emulator's `/google/publishEvents`
/// route. fireemu serves that route on the Eventarc port; this front reaches the same code
/// in process (`accept_verbatim` + `publish_custom_event` on the sentinel `google` channel),
/// so a registered `onAlertPublished` handler fires exactly as it would for the Admin SDK.
/// This is the official mechanism, not a fireemu-only injection.
///
/// Body: `{ "alertType": <one of the official alerttype values>, "appId"?: <string>,
/// "payload"?: <the alert's data.payload object> }`. The answer reports how many handlers the
/// alert reached.
fn alerts(state: &UiState, req: &UiRequest) -> UiResponse {
    if req.method != "POST" {
        return UiResponse::error(405, "METHOD_NOT_ALLOWED");
    }
    let Some(runtime) = state.functions.clone() else {
        return UiResponse::error(404, "NOT_FOUND : no functions runtime is configured");
    };
    let body = match json_body(req) {
        Ok(b) => b,
        Err(r) => return r,
    };
    // The alerttype filter an onAlertPublished trigger matches on: a non-empty, bounded,
    // control-character-free string (it becomes an Eventarc attribute).
    let Some(alert_type) = body.get("alertType").and_then(Value::as_str).filter(|s| {
        !s.is_empty() && s.len() <= 128 && s.bytes().all(|b| (0x20..0x7f).contains(&b))
    }) else {
        return UiResponse::error(
            400,
            "INVALID_ARGUMENT : alertType is required (an alerttype such as crashlytics.newFatalIssue)",
        );
    };
    let app_id = body.get("appId").and_then(Value::as_str);
    let payload = body.get("payload").cloned().unwrap_or_else(|| json!({}));
    let mut event = json!({
        "specversion": "1.0",
        "type": ALERT_EVENT_TYPE,
        "source": format!("//firebasealerts.googleapis.com/projects/{}", state.info.project),
        "id": "ui-alert",
        "alerttype": alert_type,
        "data": payload,
    });
    if let Some(app_id) = app_id {
        event["appid"] = json!(app_id);
    }
    let published = match fireemu_adapter_functions::eventarc::accept_verbatim(&event) {
        Ok(p) => p,
        Err(why) => return UiResponse::error(400, &format!("INVALID_ARGUMENT : {why}")),
    };
    let delivered = match runtime.publish_registered_custom_events(
        fireemu_adapter_functions::eventarc::GOOGLE_CHANNEL,
        std::slice::from_ref(&published),
    ) {
        Ok(delivered) => delivered,
        Err(fireemu_adapter_functions::runtime::EventarcPublishError::Capacity) => {
            return UiResponse::error(
                429,
                "RESOURCE_EXHAUSTED : Eventarc delivery capacity exceeded",
            )
        }
        Err(fireemu_adapter_functions::runtime::EventarcPublishError::InvalidEvent) => {
            return UiResponse::error(400, "INVALID_ARGUMENT : invalid Eventarc event")
        }
        Err(fireemu_adapter_functions::runtime::EventarcPublishError::Unavailable) => {
            return UiResponse::error(500, "INTERNAL : Eventarc registry unavailable")
        }
    };
    no_store(UiResponse::json(
        200,
        &json!({"delivered": delivered, "alertType": alert_type}),
    ))
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
        // The UI front is privileged local administration: it presents the owner credential
        // above and takes the bypass of specification section 12.2.
        app_check: Vec::new(),
        body,
    });
    let mut out = UiResponse::json(response.status, &response.body);
    if fireemu_adapter_grpc::rest::drops_connection(&response) {
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
        // The Emulator UI is privileged local administration: it presents the owner
        // credential above and takes the Admin bypass of specification section 12.2, so it
        // never forwards an App Check field of its own.
        app_check: Vec::new(),
    };
    let response = fireemu_adapter_http::identity_toolkit::handle_with(
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
    let response = fireemu_adapter_http::storage::handle(
        &state.storage,
        StorageRequest {
            method: req.method.clone(),
            path: format!("/{path}"),
            query: req.query.clone(),
            host: req.header("host").map(str::to_owned),
            headers,
            // The UI front reaches the privileged JSON API dialect and takes the bypass of
            // specification section 12.2; it never forwards an App Check field of its own.
            app_check: Vec::new(),
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
        Trigger::Http { callable, .. } => json!({"kind": "http", "callable": callable}),
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
        Trigger::TaskQueue { retry, rate_limits } => json!({
            "kind": "tasks",
            "maxAttempts": retry.max_attempts,
            "maxConcurrentDispatches": rate_limits.max_concurrent_dispatches,
        }),
        Trigger::Eventarc {
            event_type,
            channel,
            filters,
        } => json!({
            "kind": "eventarc",
            "event": event_type,
            "channel": channel,
            "filters": filters,
        }),
        Trigger::Auth { event } => json!({"kind": "auth", "event": event.event_type()}),
        Trigger::BlockingAuth {
            event,
            token_policy,
        } => {
            json!({
                "kind": "blockingAuth",
                "event": event.as_str(),
                "tokenPolicy": {
                    "accessToken": token_policy.access_token,
                    "idToken": token_policy.id_token,
                    "refreshToken": token_policy.refresh_token,
                }
            })
        }
        Trigger::Storage { event, bucket } => {
            json!({"kind": "storage", "event": event.event_type(), "bucket": bucket})
        }
        Trigger::Schedule {
            schedule,
            time_zone,
            retry,
        } => json!({
            "kind": "schedule",
            "schedule": schedule.as_str(),
            "timeZone": time_zone,
            "retryConfig": {
                "retryCount": retry.retry_count,
                "maxRetrySeconds": retry.max_retry_seconds,
                "maxBackoffSeconds": retry.max_backoff_seconds,
                "maxDoublings": retry.max_doublings,
                "minBackoffSeconds": retry.min_backoff_seconds,
            },
        }),
    }
}

fn record_json(r: &fireemu_adapter_functions::runtime::InvocationRecord) -> Value {
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
    let now = runtime.now();
    let functions: Vec<Value> = runtime
        .manifest()
        .functions
        .iter()
        .map(|f| {
            let mut entry = json!({
                "name": f.name,
                "region": f.region,
                "entryPoint": f.entry_point,
                "trigger": trigger_json(&f.trigger),
                "timeoutSeconds": f.timeout_seconds,
                "retry": f.retry,
                "concurrency": f.effective_concurrency(),
                "configuredConcurrency": f.concurrency,
            });
            // A scheduled function reports when it next runs on the virtual clock, so the
            // console can offer to advance the clock straight to it.
            if let Trigger::Schedule {
                schedule,
                time_zone,
                ..
            } = &f.trigger
            {
                if let Some(next) =
                    crate::functions_actions::next_run_rfc3339(schedule, time_zone.as_deref(), now)
                {
                    entry["nextRun"] = Value::String(next);
                }
            }
            entry
        })
        .collect();
    let logs = runtime.runner().logs_since(None);
    let mut lines = logs
        .lines
        .iter()
        .map(fireemu_adapter_functions::runner::RunnerLog::display)
        .collect::<Vec<_>>();
    if logs.truncated {
        lines.insert(0, "[fireemu] earlier function logs were truncated");
    }
    // The functions runtime belongs to one session -- the one whose project is the runtime's
    // (functions and Pub/Sub are served only for the default session, server-enforced). The
    // console targets that session for every functions action, whatever the top bar selects,
    // so an invoke or task never lands on a different project's data.
    let functions_session = state
        .control
        .sessions
        .lock()
        .ok()
        .and_then(|sessions| {
            sessions
                .iter()
                .find(|(_, project)| project.as_str() == runtime.project())
                .map(|(name, _)| name.clone())
        })
        .unwrap_or_else(|| "default".to_owned());
    UiResponse::json(
        200,
        &json!({
            "configured": true,
            "project": runtime.project(),
            // The session the functions belong to; the console operates on it, not the top-bar
            // selection, and warns when they differ.
            "session": functions_session,
            "source": state.info.functions_source,
            // The current virtual clock, so the console can show a schedule's next run
            // relative to now and offer to advance to it.
            "clock": now.to_rfc3339().unwrap_or_else(|_| now.to_string()),
            // Whether an HTTP / callable function can be invoked from here: the front forwards
            // to the Functions port, which is only bound when a codebase is loaded.
            "functionsAddr": state.info.functions_addr,
            "functions": functions,
            "status": runtime.status(),
            "history": runtime.history().iter().map(record_json).collect::<Vec<_>>(),
            "deadLetters": runtime.dead_letters().iter().map(record_json).collect::<Vec<_>>(),
            "logs": lines,
        }),
    )
}

/// `POST functions/{name}:invoke`: invokes an HTTP or callable function by forwarding the
/// caller's request to the Functions port over loopback, so the callable trust boundary (App
/// Check, ID-token verification, CORS) is exercised exactly as it is for an SDK client. The
/// response is the function's own, with its body rendered as UTF-8 or base64.
async fn invoke_function(state: &UiState, name: &str, req: &UiRequest) -> UiResponse {
    let Some(runtime) = &state.functions else {
        return UiResponse::error(404, "NOT_FOUND : no functions runtime is configured");
    };
    if req.method != "POST" {
        return UiResponse::error(405, "METHOD_NOT_ALLOWED");
    }
    let body = match json_body(req) {
        Ok(b) => b,
        Err(r) => return r,
    };
    // The function must exist and be HTTP-invokable; its region is resolved here so the caller
    // never has to name it.
    let Some(spec) = runtime.manifest().get(name) else {
        return UiResponse::error(404, &format!("NOT_FOUND : no function named {name:?}"));
    };
    if !matches!(spec.trigger, Trigger::Http { .. }) {
        return UiResponse::error(
            400,
            &format!("INVALID_ARGUMENT : {name:?} is not an HTTP or callable function"),
        );
    }
    let Some(addr) = state.info.functions_addr.clone() else {
        return UiResponse::error(
            503,
            "UNAVAILABLE : the Functions port is not bound, so no function can be invoked",
        );
    };
    let plan = match crate::functions_actions::build_invoke(
        runtime.project(),
        &spec.region,
        name,
        &body,
    ) {
        Ok(plan) => plan,
        Err(message) => return UiResponse::error(400, &format!("INVALID_ARGUMENT : {message}")),
    };
    let started = std::time::Instant::now();
    match fireemu_adapter_functions::http::forward(
        &addr,
        &plan.method,
        &plan.path_and_query,
        &plan.headers,
        &plan.body,
    )
    .await
    {
        Ok(response) => UiResponse::json(
            200,
            &crate::functions_actions::encode_response(
                response.status,
                &response.headers,
                &response.body,
                started.elapsed().as_millis(),
            ),
        ),
        Err(message) => UiResponse::error(502, &format!("BAD_GATEWAY : {message}")),
    }
}

/// `POST functions/{name}:enqueue`: enqueues a Cloud Task onto an `onTaskDispatched` queue
/// with `{data, id?, headers?}`, building the Admin SDK's own request body so the runtime
/// accepts it unchanged and dispatches it to the handler on the virtual clock.
fn enqueue_task(state: &UiState, name: &str, req: &UiRequest) -> UiResponse {
    let Some(runtime) = &state.functions else {
        return UiResponse::error(404, "NOT_FOUND : no functions runtime is configured");
    };
    if req.method != "POST" {
        return UiResponse::error(405, "METHOD_NOT_ALLOWED");
    }
    let body = match json_body(req) {
        Ok(b) => b,
        Err(r) => return r,
    };
    let Some(spec) = runtime.manifest().get(name) else {
        return UiResponse::error(404, &format!("NOT_FOUND : no function named {name:?}"));
    };
    if !matches!(spec.trigger, Trigger::TaskQueue { .. }) {
        return UiResponse::error(
            400,
            &format!("INVALID_ARGUMENT : {name:?} is not a task-queue function"),
        );
    }
    let region = spec.region.clone();
    let data = body.get("data").cloned().unwrap_or(Value::Null);
    let id = match body.get("id") {
        None | Some(Value::Null) => None,
        Some(Value::String(id)) => Some(id.clone()),
        Some(_) => return UiResponse::error(400, "INVALID_ARGUMENT : id must be a string"),
    };
    let headers = match body.get("headers") {
        None | Some(Value::Null) => None,
        Some(Value::Object(map)) => Some(map.clone()),
        Some(_) => {
            return UiResponse::error(
                400,
                "INVALID_ARGUMENT : headers must be an object of strings",
            )
        }
    };
    let task_body = match crate::functions_actions::build_task_body(
        runtime.project(),
        &region,
        name,
        &data,
        id.as_deref(),
        headers.as_ref(),
    ) {
        Ok(body) => body,
        Err(message) => return UiResponse::error(400, &format!("INVALID_ARGUMENT : {message}")),
    };
    // Apply the Cloud Tasks port's own request-body ceiling to the assembled task JSON (the
    // base64 body, headers and name -- not the raw `data`), so the same task is accepted or
    // refused identically whether it is enqueued here or sent to the Tasks port by the SDK.
    let serialized = serde_json::to_vec(&task_body).unwrap_or_default();
    if serialized.len() > fireemu_adapter_functions::http::MAX_TASK_BODY_BYTES {
        return UiResponse::error(
            413,
            "PAYLOAD_TOO_LARGE : the task exceeds the Cloud Tasks request size limit",
        );
    }
    match runtime.enqueue_task(runtime.project(), &region, name, &task_body) {
        Ok(answer) => UiResponse::json(200, &answer),
        Err(refusal) => {
            let status = if (100..600).contains(&refusal.status) {
                refusal.status
            } else {
                400
            };
            UiResponse::error(status, &refusal.body)
        }
    }
}

/// The same response with `Cache-Control: no-store`: what it carries is privileged and, for
/// one creation response, a credential that exists nowhere else.
fn no_store(mut response: UiResponse) -> UiResponse {
    response
        .headers
        .push(("cache-control".to_owned(), "no-store".to_owned()));
    response
}

/// The App Check surface (specification sections 9 and 15).
///
/// `appcheck/config` is a read-only summary of the static registration: the apps this runtime
/// knows, whether each is enabled, how many debug-token digests each carries, and the
/// effective baseline mode of every service. It deliberately carries no digest, no raw secret
/// and no project epoch: a digest is a credential verifier and an epoch never leaves the
/// runtime (specification section 7.2).
///
/// `appcheck/projects/{p}/apps/{a}/debugTokens[/{id}]` fronts the daemon's own privileged
/// management routes. Those require the control token on every method whatever the `Origin`,
/// so the front presents the credential the target route asks for; the browser already proved
/// it knows the token to reach this front at all ([`crate::guard`]).
fn app_check(state: &UiState, path: &str, req: &UiRequest) -> UiResponse {
    if path == "config" {
        return if req.method == "GET" {
            app_check_config(state, req)
        } else {
            UiResponse::error(405, "METHOD_NOT_ALLOWED")
        };
    }
    if !path.starts_with("projects/") {
        return UiResponse::error(
            404,
            "NOT_FOUND : only the configuration summary and the debug-token routes are exposed",
        );
    }
    let Some(app_check) = &state.app_check else {
        return app_check_disabled();
    };
    if req.body.len() > MAX_JSON_BODY_BYTES {
        return UiResponse::error(413, "PAYLOAD_TOO_LARGE");
    }
    let headers = RequestHeaders {
        authorization: Some(format!("Bearer {}", app_check.control_token)),
        ..RequestHeaders::default()
    };
    let full = format!("/emulator/v1/{path}");
    let response = fireemu_adapter_http::app_check::handle_raw(
        app_check,
        &fireemu_adapter_http::app_check::RawRequest {
            method: &req.method,
            path: &full,
            headers: &headers,
            body: &req.body,
        },
    );
    // A creation response carries the raw debug secret exactly once; nothing on the way to
    // the page may keep a copy.
    no_store(UiResponse::json(response.status, &response.body))
}

/// The answer when the runtime never enabled App Check.
fn app_check_disabled() -> UiResponse {
    UiResponse::error(
        404,
        "NOT_FOUND : App Check is not enabled in this runtime (appCheck.enabled)",
    )
}

/// `GET appcheck/config[?project=]`: the registration summary described on [`app_check`].
fn app_check_config(state: &UiState, req: &UiRequest) -> UiResponse {
    let info = state.info.app_check.as_ref();
    let modes: Vec<Value> = info.map_or_else(Vec::new, |i| {
        i.modes
            .iter()
            .map(|(service, mode)| json!({"service": service, "mode": mode}))
            .collect()
    });
    let Some(app_check) = &state.app_check else {
        return no_store(UiResponse::json(
            200,
            &json!({"enabled": false, "kid": Value::Null, "modes": modes, "apps": []}),
        ));
    };
    let Ok(registry) = app_check.registry.read() else {
        return UiResponse::error(500, "INTERNAL");
    };
    let filter = req.param("project");
    let apps: Vec<Value> = registry
        .apps()
        .filter(|a| filter.as_deref().is_none_or(|p| p == a.project_id()))
        .map(|a| {
            let dynamic = a.dynamic_tokens().len();
            json!({
                "appId": a.app_id(),
                "projectId": a.project_id(),
                "projectNumber": a.project_number(),
                "enabled": a.enabled(),
                "staticDigestCount": a.digest_count().saturating_sub(dynamic),
                "dynamicTokenCount": dynamic,
            })
        })
        .collect();
    no_store(UiResponse::json(
        200,
        &json!({
            "enabled": true,
            "kid": info.map(|i| i.kid.as_str()),
            "modes": modes,
            "tokenTtlSeconds": registry.token_ttl_seconds(),
            "apps": apps,
        }),
    ))
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
    // The App Check observation route is privileged for every method whatever the `Origin`,
    // unlike the rest of the control API, whose guard only challenges browser requests. The
    // front therefore presents the daemon's control token: the browser already proved it knows
    // it to reach this front at all ([`crate::guard`]), so this grants no authority the
    // caller did not already have.
    let headers = RequestHeaders {
        authorization: Some(format!("Bearer {}", state.control_token)),
        ..RequestHeaders::default()
    };
    let response =
        if req.method == "POST" && fireemu_adapter_http::control::is_await_idle_path(&full) {
            fireemu_adapter_http::control::await_idle(&state.control, &body).await
        } else {
            fireemu_adapter_http::control::handle_with(
                &state.control,
                &req.method,
                &full,
                &headers,
                &body,
            )
        };
    let out = UiResponse::json(response.status, &response.body);
    if fireemu_adapter_http::control::is_no_store_path(&full) {
        no_store(out)
    } else {
        out
    }
}
