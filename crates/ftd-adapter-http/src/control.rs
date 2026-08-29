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

use crate::identity_toolkit::JsonResponse;

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
    /// Loaded Security Rules (shared with the gRPC adapter).
    pub rules: Arc<RwLock<LoadedRules>>,
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

fn session_route(state: &ControlState, method: &str, path: &str, body: &Value) -> JsonResponse {
    let rest = &path["/v1/sessions/".len()..];
    let (session, action) = rest.split_once('/').map_or((rest, ""), |(s, a)| (s, a));
    if session.is_empty() {
        return error(404, "NOT_FOUND");
    }
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
