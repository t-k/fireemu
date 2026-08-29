//! Control API (`CTL-1` subset, spec 15): virtual clock manipulation, health, capabilities.
//!
//! ```text
//! GET  /health/live
//! GET  /health/ready
//! GET  /v1/capabilities
//! GET  /v1/sessions/{session}                 -> { "clock": "<rfc3339>" }
//! POST /v1/sessions/{session}/clock:set       { "instant": "<rfc3339>" }
//! POST /v1/sessions/{session}/clock:advance   { "seconds": n } | { "millis": n }
//! POST /v1/sessions/{session}/clock:advanceTo { "instant": "<rfc3339>" }
//! POST /v1/sessions/{session}:awaitIdle       { "timeoutSeconds": n }
//! GET  /v1/sessions/{session}/functions
//! POST /v1/sessions/{session}/functions/{name}:run
//! ```
//!
//! The daemon currently runs one implicit session; every session name maps to it. Sessions,
//! snapshots and `await-idle` arrive with the session runtime.

use std::sync::{Arc, Mutex, RwLock};

use ftd_core_rules::runtime::LoadedRules;
use ftd_core_session::clock::VirtualClock;
use ftd_core_types::determinism::Clock;
use ftd_core_types::edition::FirestoreEdition;
use ftd_core_types::time::{LogicalDuration, LogicalInstant};
use serde_json::{json, Value};

use crate::identity_toolkit::{JsonResponse, RequestHeaders};

/// The functions runtime as the control API sees it (spec 10.5 `await-idle`, 11.2 clock
/// operations, manual schedule runs).
pub trait FunctionsHook: Send + Sync {
    /// The virtual clock moved: enqueue due schedules and release due retries.
    fn on_clock_changed(&self);
    /// Runs a scheduled function now.
    fn run_schedule(&self, function: &str) -> Result<(), String>;
    /// Whether no event is pending, leased, running or retry-waiting.
    fn is_idle(&self) -> bool;
    /// Notified whenever work completes.
    fn idle_notify(&self) -> Arc<tokio::sync::Notify>;
    /// Status JSON (queue depths, functions).
    fn status(&self) -> Value;
}

/// Shared control-plane state.
pub struct ControlState {
    /// The virtual clock shared by every adapter.
    pub clock: Arc<Mutex<VirtualClock>>,
    /// Only `demo-` project IDs are accepted by the Firestore surface.
    pub require_demo_prefix: bool,
    /// Configured edition.
    pub edition: FirestoreEdition,
    /// Capability manifest served at `/v1/capabilities`.
    pub capabilities: Value,
    /// Loaded Firestore Security Rules (shared with the gRPC adapter).
    pub rules: Arc<RwLock<LoadedRules>>,
    /// Loaded Storage Security Rules (shared with the Storage adapter).
    pub storage_rules: Arc<RwLock<LoadedRules>>,
    /// Hooks run by `POST /v1/sessions/{s}/reset` (Firestore wipe, Auth wipe, ...).
    pub reset_hooks: Vec<Arc<dyn Fn() + Send + Sync>>,
    /// Functions runtime, when configured.
    pub functions: Option<Arc<dyn FunctionsHook>>,
    /// Control token (spec 15.2): browser requests (those carrying an `Origin`) must present
    /// it as `Authorization: Bearer <token>` on privileged routes, so a page on localhost
    /// cannot reset state, move the clock or change rules; command-line clients on loopback
    /// need not.
    pub control_token: String,
}

fn error(status: u16, message: &str) -> JsonResponse {
    JsonResponse {
        status,
        body: json!({"error": {"code": status, "message": message}}),
    }
}

fn ok(body: Value) -> JsonResponse {
    JsonResponse { status: 200, body }
}

fn clock_json(clock: &VirtualClock) -> Value {
    json!({"clock": clock.now().to_rfc3339().unwrap_or_else(|_| clock.now().to_string()), "backwardsSets": clock.backwards_sets()})
}

/// Whether `path` belongs to the control API.
#[must_use]
pub fn is_control_path(path: &str) -> bool {
    path.starts_with("/v1/") || path.starts_with("/health/")
}

/// Routes one control request.
#[must_use]
pub fn handle(state: &ControlState, method: &str, path: &str, body: &Value) -> JsonResponse {
    handle_with(state, method, path, &RequestHeaders::default(), body)
}

/// Routes one control request with its headers: browser requests from non-loopback origins
/// are refused (the control API mutates runtime state).
#[must_use]
pub fn handle_with(
    state: &ControlState,
    method: &str,
    path: &str,
    headers: &RequestHeaders,
    body: &Value,
) -> JsonResponse {
    if let Some(refusal) = browser_guard(state, method, path, headers) {
        return refusal;
    }
    let path = path.split('?').next().unwrap_or(path);
    match (method, path) {
        ("GET", "/health/live" | "/health/ready") => ok(json!({"status": "ok"})),
        ("GET", "/v1/capabilities") => ok(state.capabilities.clone()),
        ("GET", "/v1/limits") => ok(json!({
            "catalogs": ftd_core_limits::catalogs::ALL_CATALOGS.iter().map(|c| json!({
                "id": c.meta.id,
                "product": c.meta.product,
                "edition": c.meta.edition,
                "officialLastUpdatedUtc": c.meta.official_last_updated_utc,
                "limits": c.limits.iter().map(|l| json!({
                    "id": l.id,
                    "boundary": format!("{:?}", l.boundary),
                    "unit": format!("{:?}", l.unit),
                    "maximum": match l.maximum {
                        ftd_core_limits::model::LimitMaximum::Fixed(v) => json!(v),
                        ftd_core_limits::model::LimitMaximum::PlanDependent { billing_disabled, billing_enabled } => json!({"billingDisabled": billing_disabled, "billingEnabled": billing_enabled}),
                        ftd_core_limits::model::LimitMaximum::NotApplicable => Value::Null,
                    },
                    "precision": format!("{:?}", l.precision),
                    "implemented": format!("{:?}", l.implemented),
                })).collect::<Vec<_>>(),
            })).collect::<Vec<_>>()
        })),
        (m, p) if p.starts_with("/v1/sessions/") => session_route(state, m, p, body),
        ("GET" | "PUT" | "DELETE", "/v1/storage/rules") => {
            rules_route(&state.storage_rules, method, body)
        }
        ("GET", "/v1/rules") => match state.rules.read() {
            Ok(r) => ok(json!({"loaded": r.is_loaded(), "source": r.source})),
            Err(_) => error(500, "INTERNAL"),
        },
        ("PUT", "/v1/rules") => {
            let Some(source) = body.get("source").and_then(Value::as_str) else {
                return error(
                    400,
                    "INVALID_ARGUMENT : body.source (rules text) is required",
                );
            };
            match LoadedRules::from_source(source) {
                Ok(loaded) => match state.rules.write() {
                    Ok(mut slot) => {
                        *slot = loaded;
                        ok(json!({"loaded": true}))
                    }
                    Err(_) => error(500, "INTERNAL"),
                },
                Err(e) => error(400, &format!("INVALID_ARGUMENT : rules do not parse: {e}")),
            }
        }
        ("DELETE", "/v1/rules") => match state.rules.write() {
            Ok(mut slot) => {
                *slot = LoadedRules::default();
                ok(json!({"loaded": false}))
            }
            Err(_) => error(500, "INTERNAL"),
        },
        _ => error(404, "NOT_FOUND"),
    }
}

/// GET / PUT / DELETE on a rules slot.
fn rules_route(slot: &RwLock<LoadedRules>, method: &str, body: &Value) -> JsonResponse {
    match method {
        "GET" => match slot.read() {
            Ok(r) => ok(json!({"loaded": r.is_loaded(), "source": r.source})),
            Err(_) => error(500, "INTERNAL"),
        },
        "PUT" => {
            let Some(source) = body.get("source").and_then(Value::as_str) else {
                return error(
                    400,
                    "INVALID_ARGUMENT : body.source (rules text) is required",
                );
            };
            match LoadedRules::from_source(source) {
                Ok(loaded) => match slot.write() {
                    Ok(mut s) => {
                        *s = loaded;
                        ok(json!({"loaded": true}))
                    }
                    Err(_) => error(500, "INTERNAL"),
                },
                Err(e) => error(400, &format!("INVALID_ARGUMENT : rules do not parse: {e}")),
            }
        }
        _ => match slot.write() {
            Ok(mut s) => {
                *s = LoadedRules::default();
                ok(json!({"loaded": false}))
            }
            Err(_) => error(500, "INTERNAL"),
        },
    }
}

fn session_route(state: &ControlState, method: &str, path: &str, body: &Value) -> JsonResponse {
    let rest = &path["/v1/sessions/".len()..];
    let (session, action) = rest.split_once('/').map_or((rest, ""), |(s, a)| (s, a));
    if session.is_empty() {
        return error(404, "NOT_FOUND");
    }
    if (method, action) == ("POST", "reset") {
        for hook in &state.reset_hooks {
            hook();
        }
        return ok(json!({"session": session, "reset": true, "hooks": state.reset_hooks.len()}));
    }
    if let Some(rest) = action.strip_prefix("functions") {
        return functions_route(state, method, rest);
    }
    let response = clock_route(state, session, method, action, body);
    if response.status == 200 && action.starts_with("clock:") {
        if let Some(f) = &state.functions {
            f.on_clock_changed();
        }
    }
    response
}

fn functions_route(state: &ControlState, method: &str, rest: &str) -> JsonResponse {
    let Some(functions) = &state.functions else {
        return error(404, "NOT_FOUND : no functions runtime is configured");
    };
    match (method, rest) {
        ("GET", "") => ok(functions.status()),
        ("POST", r) => match r.strip_prefix('/').and_then(|r| r.strip_suffix(":run")) {
            Some(name) if !name.is_empty() => match functions.run_schedule(name) {
                Ok(()) => ok(json!({"function": name, "enqueued": true})),
                Err(e) => error(400, &format!("INVALID_ARGUMENT : {e}")),
            },
            _ => error(404, "NOT_FOUND"),
        },
        _ => error(404, "NOT_FOUND"),
    }
}

/// The browser policy of every control route (also applied by the asynchronous
/// `awaitIdle` path): foreign origins are refused, and a page on a loopback origin needs
/// the control token for anything but reads.
#[must_use]
pub fn browser_guard(
    state: &ControlState,
    method: &str,
    path: &str,
    headers: &RequestHeaders,
) -> Option<JsonResponse> {
    let origin = headers.origin.as_deref()?;
    if !crate::identity_toolkit::origin_is_local(origin) {
        return Some(error(403, "FORBIDDEN_ORIGIN"));
    }
    let privileged = method != "GET" && !path.starts_with("/health/");
    let presented = headers
        .authorization
        .as_deref()
        .and_then(|a| a.strip_prefix("Bearer "))
        .map(str::trim);
    if privileged && presented != Some(state.control_token.as_str()) {
        return Some(error(
            403,
            "CONTROL_TOKEN_REQUIRED : browser requests need Authorization: Bearer <control token> (printed at start, FTD_CONTROL_TOKEN)",
        ));
    }
    None
}

/// `POST /v1/sessions/{s}:awaitIdle`: waits until the functions runtime has no outstanding
/// work (or `timeoutSeconds`, default 30, elapses).
pub async fn await_idle(state: &ControlState, body: &Value) -> JsonResponse {
    let timeout = body
        .get("timeoutSeconds")
        .and_then(Value::as_f64)
        .unwrap_or(30.0)
        .clamp(0.0, 600.0);
    let Some(functions) = &state.functions else {
        return ok(json!({"idle": true, "note": "no functions runtime is configured"}));
    };
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs_f64(timeout);
    loop {
        if functions.is_idle() {
            return ok(json!({"idle": true, "status": functions.status()}));
        }
        let notify = functions.idle_notify();
        let notified = notify.notified();
        if functions.is_idle() {
            return ok(json!({"idle": true, "status": functions.status()}));
        }
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() || tokio::time::timeout(remaining, notified).await.is_err() {
            return JsonResponse {
                status: 504,
                body: json!({"error": {"code": 504, "message": "DEADLINE_EXCEEDED : work is still outstanding", "status": functions.status()}}),
            };
        }
    }
}

/// Whether `path` is the `awaitIdle` endpoint (served asynchronously by the server).
#[must_use]
pub fn is_await_idle_path(path: &str) -> bool {
    let path = path.split('?').next().unwrap_or(path);
    path.starts_with("/v1/sessions/") && path.ends_with(":awaitIdle")
}

fn clock_route(
    state: &ControlState,
    session: &str,
    method: &str,
    action: &str,
    body: &Value,
) -> JsonResponse {
    let Ok(mut clock) = state.clock.lock() else {
        return error(500, "INTERNAL");
    };
    match (method, action) {
        ("GET", "") => ok(
            json!({"session": session, "edition": state.edition.as_config_str(), "requireDemoPrefix": state.require_demo_prefix, "clock": clock_json(&clock)}),
        ),
        ("POST", "clock:advance") => {
            let duration = if let Some(s) = body.get("seconds").and_then(Value::as_i64) {
                LogicalDuration::from_seconds(s)
            } else if let Some(ms) = body.get("millis").and_then(Value::as_i64) {
                LogicalDuration::from_millis(ms)
            } else {
                return error(400, "INVALID_ARGUMENT : seconds or millis required");
            };
            match clock.advance(duration) {
                Ok(_) => ok(clock_json(&clock)),
                Err(e) => error(400, &format!("INVALID_ARGUMENT : {e}")),
            }
        }
        ("POST", "clock:set" | "clock:advanceTo") => {
            let Some(instant) = body.get("instant").and_then(Value::as_str) else {
                return error(400, "INVALID_ARGUMENT : instant required");
            };
            let Ok(target) = LogicalInstant::parse_rfc3339(instant) else {
                return error(400, "INVALID_ARGUMENT : instant must be RFC 3339");
            };
            let allow_backwards = body
                .get("allowBackwards")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            if action == "clock:set" && allow_backwards {
                clock.set_allow_backwards(target);
                return ok(clock_json(&clock));
            }
            match clock.advance_to(target) {
                Ok(_) => ok(clock_json(&clock)),
                Err(e) => error(400, &format!("INVALID_ARGUMENT : {e}")),
            }
        }
        _ => error(404, "NOT_FOUND"),
    }
}
