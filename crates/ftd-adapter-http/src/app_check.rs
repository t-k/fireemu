//! App Check HTTP routes (specification sections 9 and 10).
//!
//! ```text
//! POST   /v1/projects/{project}/apps/{appId}:exchangeDebugToken
//! POST   /v1beta/projects/{project}/apps/{appId}:exchangeDebugToken
//! GET    /v1/jwks
//! GET    /v1beta/jwks
//! POST   /emulator/v1/projects/{project}/apps/{appId}/debugTokens
//! GET    /emulator/v1/projects/{project}/apps/{appId}/debugTokens
//! DELETE /emulator/v1/projects/{project}/apps/{appId}/debugTokens/{tokenId}
//! ```
//!
//! These routes share the Auth/control listener but are dispatched before the control API, so
//! the exchange and the JWKS stay reachable from a browser SDK while every management route
//! requires the control token for every method, whether or not an `Origin` is present. Every
//! response sets `Cache-Control: no-store` ([`crate::server`] adds it for this module).
//!
//! No decision is taken here: the module parses the transport, asks `ftd-core-app-check`, and
//! renders the answer. Unknown project, unknown app and unknown secret all render as the same
//! `403 App attestation failed.`, so the body is not an enumeration oracle.

use std::sync::{Arc, Mutex, RwLock};

use ftd_core_app_check::crypto::{AppCheckSigner, ConstantTimeEq, DebugTokenHasher};
use ftd_core_app_check::exchange::{
    canonical_debug_token, exchange, ExchangeOutcome, ExchangeRequest,
};
use ftd_core_app_check::limits::MAX_EXCHANGE_BODY_BYTES;
use ftd_core_app_check::observe::{CredentialCategory, Observation, UNKNOWN_APP_LABEL};
use ftd_core_app_check::registry::{
    validate_display_name, AppCheckRegistry, DebugTokenDigest, RegistryError,
};
use ftd_core_app_check::verify::{AppCheckFailure, BaselineMode};
use ftd_core_session::clock::VirtualClock;
use ftd_core_types::determinism::Clock;
use ftd_core_types::time::LogicalInstant;
use serde_json::{json, Value};

use crate::identity_toolkit::{JsonResponse, RequestHeaders};
use crate::signing::DebugSecretSource;

/// The public message every attestation failure renders, whatever the internal reason.
pub const ATTESTATION_FAILED: &str = "App attestation failed.";

/// The stable code of a refused limited-use exchange.
pub const REPLAY_UNSUPPORTED: &str = "APP_CHECK_REPLAY_UNSUPPORTED";

/// Where the public App Check key is served.
pub const JWKS_PATHS: &[&str] = &["/v1/jwks", "/v1beta/jwks"];

const EXCHANGE_VERB: &str = "exchangeDebugToken";
const MANAGEMENT_PREFIX: &str = "/emulator/v1/projects/";

/// Everything the App Check routes need. The registry is shared with the future product
/// adapters; the signer is the daemon instance's dedicated key.
pub struct AppCheckState {
    /// The project-scoped registry, from canonical configuration.
    pub registry: Arc<RwLock<AppCheckRegistry>>,
    /// The instance's App Check RS256 signer.
    pub signer: Arc<dyn AppCheckSigner>,
    /// The virtual clock shared with the other adapters.
    pub clock: Arc<Mutex<VirtualClock>>,
    /// The control token every management request must present.
    pub control_token: String,
    /// SHA-256 over canonical debug-token text.
    pub hasher: Arc<dyn DebugTokenHasher>,
    /// Constant-time digest comparison.
    pub constant_time: Arc<dyn ConstantTimeEq>,
    /// Source of generated raw debug secrets.
    pub secrets: Arc<dyn DebugSecretSource>,
    /// Session admission barrier, when shared.
    pub barrier: Option<Arc<ftd_core_session::barrier::AdmissionBarrier>>,
}

impl AppCheckState {
    /// The shared handle the product adapters and the lifecycle hooks decide against
    /// (specification section 7.4). It carries no control token and no secret source.
    #[must_use]
    pub fn gate(&self) -> ftd_core_app_check::admission::AppCheckGate {
        ftd_core_app_check::admission::AppCheckGate::new(self.registry.clone(), self.signer.clone())
    }
}

impl std::fmt::Debug for AppCheckState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppCheckState")
            .field("signer", &self.signer.kid())
            .field("control_token", &"[redacted]")
            .finish_non_exhaustive()
    }
}

/// One request as the network glue hands it over: the body stays raw so that the 16 KiB
/// exchange budget and the "no trailing JSON value" rule are enforced here.
#[derive(Debug, Clone, Copy)]
pub struct RawRequest<'a> {
    /// HTTP method.
    pub method: &'a str,
    /// Path with query.
    pub path: &'a str,
    /// Normalized headers.
    pub headers: &'a RequestHeaders,
    /// Raw request body.
    pub body: &'a [u8],
}

/// Whether `path` belongs to the App Check surface.
#[must_use]
pub fn is_app_check_path(path: &str) -> bool {
    let path = path.split('?').next().unwrap_or(path);
    JWKS_PATHS.contains(&path) || exchange_route(path).is_some() || management_route(path).is_some()
}

/// `{project}` and `{appId}` of an exchange route, still percent-encoded.
fn exchange_route(path: &str) -> Option<(&str, &str)> {
    let rest = path
        .strip_prefix("/v1/projects/")
        .or_else(|| path.strip_prefix("/v1beta/projects/"))?;
    let (project, rest) = rest.split_once("/apps/")?;
    // The app ID itself contains colons, so the verb is the last one.
    let (app_id, verb) = rest.rsplit_once(':')?;
    if verb != EXCHANGE_VERB || project.is_empty() || app_id.is_empty() {
        return None;
    }
    Some((project, app_id))
}

/// `{project}`, `{appId}` and the optional `{tokenId}` of a management route.
fn management_route(path: &str) -> Option<(&str, &str, Option<&str>)> {
    let rest = path.strip_prefix(MANAGEMENT_PREFIX)?;
    let (project, rest) = rest.split_once("/apps/")?;
    let (app_id, rest) = rest.split_once("/debugTokens")?;
    if project.is_empty() || app_id.is_empty() {
        return None;
    }
    let token = match rest {
        "" => None,
        rest => Some(rest.strip_prefix('/').filter(|t| !t.is_empty())?),
    };
    if token.is_some_and(|t| t.contains('/')) {
        return None;
    }
    Some((project, app_id, token))
}

/// `%XX` decoded. Unlike form decoding, `+` stays a plus: it is a legal path character.
fn decode_segment(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let digit = |b: u8| (b as char).to_digit(16);
            if let (Some(hi), Some(lo)) = (digit(bytes[i + 1]), digit(bytes[i + 2])) {
                out.push(u8::try_from(hi * 16 + lo).unwrap_or(b'?'));
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// A Google-shaped JSON error.
fn error(code: u16, status: &str, message: &str) -> JsonResponse {
    JsonResponse {
        status: code,
        body: json!({"error": {"code": code, "message": message, "status": status}}),
    }
}

/// A Google-shaped JSON error carrying a stable machine-readable reason.
fn error_with_reason(code: u16, status: &str, message: &str, reason: &str) -> JsonResponse {
    JsonResponse {
        status: code,
        body: json!({
            "error": {"code": code, "message": message, "status": status, "reason": reason}
        }),
    }
}

/// The one public failure of the exchange: no caller can tell which part was wrong.
fn attestation_failed() -> JsonResponse {
    error(403, "PERMISSION_DENIED", ATTESTATION_FAILED)
}

/// The one public failure of the management routes: an unconfigured app reads exactly like an
/// unknown project.
fn not_configured() -> JsonResponse {
    error(
        404,
        "NOT_FOUND",
        "no such App Check app in this project's static configuration",
    )
}

fn now(state: &AppCheckState) -> LogicalInstant {
    state
        .clock
        .lock()
        .map(|c| c.now())
        .unwrap_or(LogicalInstant::UNIX_EPOCH)
}

/// Routes one App Check request.
#[must_use]
pub fn handle_raw(state: &AppCheckState, request: &RawRequest<'_>) -> JsonResponse {
    let path = request.path.split('?').next().unwrap_or(request.path);
    let _admitted = state.barrier.as_ref().map(|b| b.admit());
    if JWKS_PATHS.contains(&path) {
        return if request.method == "GET" {
            jwks(state)
        } else {
            error(405, "FAILED_PRECONDITION", "the JWKS endpoint is read-only")
        };
    }
    if let Some((project, app_id)) = exchange_route(path) {
        return if request.method == "POST" {
            exchange_debug_token(
                state,
                &decode_segment(project),
                &decode_segment(app_id),
                request.body,
            )
        } else {
            error(
                405,
                "FAILED_PRECONDITION",
                "exchangeDebugToken accepts POST only",
            )
        };
    }
    if let Some((project, app_id, token)) = management_route(path) {
        return debug_tokens(
            state,
            request,
            &decode_segment(project),
            &decode_segment(app_id),
            token.map(decode_segment).as_deref(),
        );
    }
    error(404, "NOT_FOUND", "not an App Check route")
}

/// `GET /v1/jwks`: the public App Check key, and nothing else.
fn jwks(state: &AppCheckState) -> JsonResponse {
    let key: Value = serde_json::from_str(&state.signer.public_jwk_json()).unwrap_or(Value::Null);
    let keys: Vec<Value> = if key.is_null() { Vec::new() } else { vec![key] };
    JsonResponse {
        status: 200,
        body: json!({"keys": keys}),
    }
}

/// The accepted body fields of an exchange request. Unknown members fail closed (ADR-005).
const EXCHANGE_BODY_KEYS: [&str; 2] = ["debugToken", "limitedUse"];

fn invalid_argument(message: &str) -> JsonResponse {
    error(400, "INVALID_ARGUMENT", message)
}

/// `POST .../apps/{appId}:exchangeDebugToken`.
fn exchange_debug_token(
    state: &AppCheckState,
    project_selector: &str,
    app_id: &str,
    body: &[u8],
) -> JsonResponse {
    if body.len() > MAX_EXCHANGE_BODY_BYTES {
        return invalid_argument("the exchange body is limited to 16 KiB");
    }
    // `from_slice` refuses a trailing JSON value, so `{"debugToken":"..."} {}` is malformed.
    let Ok(parsed) = serde_json::from_slice::<Value>(body) else {
        return invalid_argument("the request body must be one JSON object");
    };
    let Some(object) = parsed.as_object() else {
        return invalid_argument("the request body must be one JSON object");
    };
    for key in object.keys() {
        if !EXCHANGE_BODY_KEYS.contains(&key.as_str()) {
            return invalid_argument(&format!("unknown request field {key}"));
        }
    }
    let Some(debug_token) = object.get("debugToken").and_then(Value::as_str) else {
        return invalid_argument("debugToken is required and must be a string");
    };
    let limited_use = match object.get("limitedUse") {
        None => false,
        Some(Value::Bool(b)) => *b,
        Some(_) => return invalid_argument("limitedUse must be a boolean"),
    };

    let at = now(state);
    let Ok(registry) = state.registry.read() else {
        return error(500, "INTERNAL", "the App Check registry is unavailable");
    };
    let outcome = exchange(
        &registry,
        &ExchangeRequest {
            project_selector,
            app_id,
            debug_token,
            limited_use,
        },
        state.hasher.as_ref(),
        state.constant_time.as_ref(),
        at,
    );
    let project = registry
        .resolve_project(project_selector)
        .unwrap_or(UNKNOWN_APP_LABEL)
        .to_owned();
    let generation = registry.policy_generation(&project);

    let (response, observation) = match outcome {
        ExchangeOutcome::ReplayUnsupported => (
            error_with_reason(
                501,
                "UNIMPLEMENTED",
                "limited-use App Check tokens need replay protection (APPCHECK-REPLAY-1), which this runtime does not implement",
                REPLAY_UNSUPPORTED,
            ),
            observation(&project, UNKNOWN_APP_LABEL, false, Some(AppCheckFailure::Malformed), at, generation),
        ),
        ExchangeOutcome::AttestationFailed => (
            attestation_failed(),
            observation(&project, UNKNOWN_APP_LABEL, false, Some(AppCheckFailure::UnknownApp), at, generation),
        ),
        ExchangeOutcome::Issued(claims) => {
            let token = ftd_core_app_check::jwt::encode(&claims, state.signer.as_ref());
            (
                JsonResponse {
                    status: 200,
                    body: json!({"token": token, "ttl": format!("{}s", claims.ttl_seconds())}),
                },
                observation(&project, &claims.sub, true, None, at, generation),
            )
        }
    };
    registry.record_observation(observation);
    response
}

/// One secret-free record of an exchange (section 15). No token, no secret, no digest.
fn observation(
    project_id: &str,
    app_id: &str,
    admitted: bool,
    failure: Option<AppCheckFailure>,
    at: LogicalInstant,
    policy_generation: u64,
) -> Observation {
    Observation {
        project_id: project_id.to_owned(),
        service: "app-check",
        transport: "http",
        operation: EXCHANGE_VERB.to_owned(),
        // The exchange bootstraps App Check and is never baseline protected itself.
        mode: BaselineMode::Off,
        category: if admitted {
            CredentialCategory::Valid
        } else {
            CredentialCategory::Invalid
        },
        failure,
        app_id: app_id.to_owned(),
        at,
        policy_generation,
        admitted,
    }
}

/// Every management request needs the control token, for every method, whether or not an
/// `Origin` is present and whether or not the request would otherwise be read-only
/// (`INV-APPCHECK-012`).
fn control_guard(state: &AppCheckState, headers: &RequestHeaders) -> Option<JsonResponse> {
    let presented = headers
        .authorization
        .as_deref()
        .and_then(|a| a.strip_prefix("Bearer "))
        .map(str::trim);
    if presented == Some(state.control_token.as_str()) {
        return None;
    }
    Some(error(
        403,
        "PERMISSION_DENIED",
        "CONTROL_TOKEN_REQUIRED : App Check debug-token management needs Authorization: Bearer <control token> (printed at start, FTD_CONTROL_TOKEN)",
    ))
}

/// The accepted body fields of a debug-token creation.
const CREATE_BODY_KEYS: [&str; 3] = ["displayName", "debugToken", "generate"];

/// `/emulator/v1/projects/{p}/apps/{a}/debugTokens[/{tokenId}]`.
fn debug_tokens(
    state: &AppCheckState,
    request: &RawRequest<'_>,
    project_selector: &str,
    app_id: &str,
    token_id: Option<&str>,
) -> JsonResponse {
    if let Some(refusal) = control_guard(state, request.headers) {
        return refusal;
    }
    match (request.method, token_id) {
        ("GET", None) => list_debug_tokens(state, project_selector, app_id),
        ("POST", None) => create_debug_token(state, project_selector, app_id, request.body),
        ("DELETE", Some(id)) => delete_debug_token(state, project_selector, app_id, id),
        ("DELETE", None) => error(
            405,
            "FAILED_PRECONDITION",
            "DELETE needs a debug-token identifier",
        ),
        (_, Some(_)) => error(
            405,
            "FAILED_PRECONDITION",
            "only DELETE applies to one debug token",
        ),
        _ => error(
            405,
            "FAILED_PRECONDITION",
            "debugTokens accepts GET, POST and DELETE",
        ),
    }
}

/// Resolves the target project of a management request.
fn resolve(registry: &AppCheckRegistry, selector: &str, app_id: &str) -> Option<String> {
    let project = registry.resolve_project(selector)?.to_owned();
    registry.app(&project, app_id)?;
    Some(project)
}

fn list_debug_tokens(state: &AppCheckState, selector: &str, app_id: &str) -> JsonResponse {
    let Ok(registry) = state.registry.read() else {
        return error(500, "INTERNAL", "the App Check registry is unavailable");
    };
    let Some(project) = resolve(&registry, selector, app_id) else {
        return not_configured();
    };
    let Ok(records) = registry.list_debug_tokens(&project, app_id) else {
        return not_configured();
    };
    // Never the raw secret, never the full digest: the prefix is enough to recognise an entry.
    let tokens: Vec<Value> = records
        .iter()
        .map(|r| {
            json!({
                "tokenId": r.id,
                "displayName": r.display_name,
                "createdAt": r.created_at.to_rfc3339().unwrap_or_default(),
                "digestPrefix": r.digest.prefix(),
            })
        })
        .collect();
    JsonResponse {
        status: 200,
        body: json!({"debugTokens": tokens}),
    }
}

fn create_debug_token(
    state: &AppCheckState,
    selector: &str,
    app_id: &str,
    body: &[u8],
) -> JsonResponse {
    if body.len() > MAX_EXCHANGE_BODY_BYTES {
        return invalid_argument("the request body is limited to 16 KiB");
    }
    let Ok(parsed) = serde_json::from_slice::<Value>(body) else {
        return invalid_argument("the request body must be one JSON object");
    };
    let Some(object) = parsed.as_object() else {
        return invalid_argument("the request body must be one JSON object");
    };
    for key in object.keys() {
        if !CREATE_BODY_KEYS.contains(&key.as_str()) {
            return invalid_argument(&format!("unknown request field {key}"));
        }
    }
    let display_name = object
        .get("displayName")
        .and_then(Value::as_str)
        .unwrap_or("debug token");
    if let Err(e) = validate_display_name(display_name) {
        return invalid_argument(&e.to_string());
    }
    let generate = match object.get("generate") {
        None => false,
        Some(Value::Bool(b)) => *b,
        Some(_) => return invalid_argument("generate must be a boolean"),
    };
    let supplied = object.get("debugToken").and_then(Value::as_str);
    let secret = match (supplied, generate) {
        (Some(_), true) => return invalid_argument("pass either debugToken or generate, not both"),
        (Some(text), false) => match canonical_debug_token(text) {
            Some(canonical) => canonical,
            None => return invalid_argument("debugToken must be a canonical UUIDv4"),
        },
        (None, true) => match state.secrets.new_uuid_v4() {
            Ok(secret) => secret,
            Err(e) => return error(500, "INTERNAL", &e),
        },
        (None, false) => return invalid_argument("pass a debugToken or ask for generate: true"),
    };
    let digest = DebugTokenDigest::from_bytes(state.hasher.sha256(secret.as_bytes()));

    let at = now(state);
    let Ok(mut registry) = state.registry.write() else {
        return error(500, "INTERNAL", "the App Check registry is unavailable");
    };
    let Some(project) = resolve(&registry, selector, app_id) else {
        return not_configured();
    };
    match registry.add_debug_token(&project, app_id, display_name, digest, at) {
        Ok(record) => JsonResponse {
            status: 200,
            // The raw secret is returned exactly once and is never stored or logged.
            body: json!({
                "tokenId": record.id,
                "displayName": record.display_name,
                "createdAt": record.created_at.to_rfc3339().unwrap_or_default(),
                "digestPrefix": record.digest.prefix(),
                "debugToken": secret,
            }),
        },
        Err(RegistryError::TooManyDebugTokens) => error(
            429,
            "RESOURCE_EXHAUSTED",
            &RegistryError::TooManyDebugTokens.to_string(),
        ),
        Err(RegistryError::UnknownApp) => not_configured(),
        Err(e) => invalid_argument(&e.to_string()),
    }
}

fn delete_debug_token(
    state: &AppCheckState,
    selector: &str,
    app_id: &str,
    token_id: &str,
) -> JsonResponse {
    let Ok(mut registry) = state.registry.write() else {
        return error(500, "INTERNAL", "the App Check registry is unavailable");
    };
    let Some(project) = resolve(&registry, selector, app_id) else {
        return not_configured();
    };
    match registry.delete_debug_token(&project, app_id, token_id) {
        // Deletion stops future exchanges; it does not revoke already issued session tokens.
        Ok(()) => JsonResponse {
            status: 200,
            body: json!({"deleted": true, "tokenId": token_id}),
        },
        Err(RegistryError::UnknownApp) => not_configured(),
        Err(_) => error(404, "NOT_FOUND", "no such debug token"),
    }
}
