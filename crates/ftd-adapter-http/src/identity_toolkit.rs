//! Identity Toolkit REST handlers (spec 12A.2, 12A.8).
//!
//! Paths follow the official emulator layout:
//!
//! ```text
//! POST /identitytoolkit.googleapis.com/v1/accounts:signUp
//! POST /identitytoolkit.googleapis.com/v1/accounts:signInWithPassword
//! POST /identitytoolkit.googleapis.com/v1/accounts:lookup
//! POST /identitytoolkit.googleapis.com/v1/accounts:update          (Admin: customAttributes)
//! POST /identitytoolkit.googleapis.com/v2/accounts/mfaEnrollment:start
//! POST /identitytoolkit.googleapis.com/v2/accounts/mfaEnrollment:finalize
//! POST /identitytoolkit.googleapis.com/v2/accounts/mfaSignIn:finalize
//! POST /securetoken.googleapis.com/v1/token
//! ```
//!
//! Error bodies use the Firebase shape `{"error": {"code": 400, "message": "EMAIL_EXISTS"}}`.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use ftd_core_auth::base32;
use ftd_core_auth::claims::{ClaimValue, CustomClaims};
use ftd_core_auth::jwt::{encode_unsigned, verify_id_token, JwtError};
use ftd_core_auth::mfa::MfaError;
use ftd_core_auth::store::{
    AuthError, AuthStore, LocalId, NewUser, PendingSignInId, SecondFactorAssertion,
};
use ftd_core_session::clock::VirtualClock;
use ftd_core_types::determinism::Clock;
use ftd_core_types::json::JsonValue;
use ftd_core_types::time::LogicalInstant;
use serde_json::{json, Value};

/// Shared Auth state behind the REST surface.
pub struct AuthState {
    /// User store (shared with the gRPC adapter, which verifies ID tokens against it).
    pub store: Arc<Mutex<AuthStore>>,
    /// Virtual clock shared with the other adapters.
    pub clock: Arc<Mutex<VirtualClock>>,
}

/// An HTTP response: status code and JSON body.
#[derive(Debug, Clone, PartialEq)]
pub struct JsonResponse {
    /// Status code.
    pub status: u16,
    /// Body.
    pub body: Value,
}

fn error(status: u16, message: &str) -> JsonResponse {
    JsonResponse {
        status,
        body: json!({"error": {"code": status, "message": message, "errors": [{"message": message, "domain": "global", "reason": "invalid"}]}}),
    }
}

fn auth_error(e: &AuthError) -> JsonResponse {
    match e {
        AuthError::EmailExists => error(400, "EMAIL_EXISTS"),
        AuthError::InvalidEmail => error(400, "INVALID_EMAIL"),
        AuthError::WeakPassword => error(
            400,
            "WEAK_PASSWORD : Password should be at least 6 characters",
        ),
        AuthError::InvalidCredentials => error(400, "INVALID_LOGIN_CREDENTIALS"),
        AuthError::UserDisabled => error(400, "USER_DISABLED"),
        AuthError::InvalidRefreshToken => error(400, "INVALID_REFRESH_TOKEN"),
        AuthError::UserNotFound => error(400, "USER_NOT_FOUND"),
        AuthError::InvalidLocalId => error(400, "INVALID_LOCAL_ID"),
        AuthError::LocalIdExists => error(400, "DUPLICATE_LOCAL_ID"),
        AuthError::LimitExceeded(v) => error(400, &format!("INVALID_CLAIMS : {}", v.limit_id)),
    }
}

fn mfa_error(e: &MfaError) -> JsonResponse {
    match e {
        MfaError::InvalidCode => error(400, "INVALID_CODE"),
        MfaError::CodeAlreadyUsed => error(400, "INVALID_CODE : verification code already used"),
        MfaError::EnrollmentSessionExpired => error(400, "SESSION_EXPIRED"),
        MfaError::EnrollmentSessionUnknown | MfaError::PendingSignInUnknown => {
            error(400, "INVALID_SESSION_INFO")
        }
        MfaError::NoEnrolledFactor => error(400, "MFA_ENROLLMENT_NOT_FOUND"),
        MfaError::LimitExceeded(_) => error(400, "SECOND_FACTOR_EXISTS"),
        MfaError::UserDisabled => error(400, "USER_DISABLED"),
        MfaError::UserNotFound => error(400, "USER_NOT_FOUND"),
    }
}

fn jwt_error(e: &JwtError) -> JsonResponse {
    match e {
        JwtError::Expired => error(400, "TOKEN_EXPIRED"),
        JwtError::Revoked => error(400, "TOKEN_EXPIRED : credentials revoked"),
        _ => error(400, "INVALID_ID_TOKEN"),
    }
}

fn now(state: &AuthState) -> LogicalInstant {
    state
        .clock
        .lock()
        .map(|c| c.now())
        .unwrap_or(LogicalInstant::UNIX_EPOCH)
}

fn str_field<'a>(body: &'a Value, key: &str) -> Option<&'a str> {
    body.get(key).and_then(Value::as_str)
}

fn issue_tokens(
    store: &mut AuthStore,
    uid: &LocalId,
    second: Option<&SecondFactorAssertion>,
    at: LogicalInstant,
) -> Result<Value, JsonResponse> {
    issue_tokens_with(store, uid, second, at, None)
}

/// Issues an ID token + refresh token; `extra` claims (custom-token developer claims) are
/// merged into the token without being stored on the user.
fn issue_tokens_with(
    store: &mut AuthStore,
    uid: &LocalId,
    second: Option<&SecondFactorAssertion>,
    at: LogicalInstant,
    extra: Option<&CustomClaims>,
) -> Result<Value, JsonResponse> {
    let mut claims = store
        .id_token_claims(uid, second, at)
        .map_err(|e| auth_error(&e))?;
    if let Some(extra) = extra {
        for (k, v) in extra.entries() {
            claims
                .custom
                .insert(k, v.clone())
                .map_err(|e| error(400, &format!("INVALID_CUSTOM_TOKEN : {e}")))?;
        }
    }
    let refresh = store
        .issue_refresh_token(uid, at)
        .map_err(|e| auth_error(&e))?;
    Ok(json!({
        "idToken": encode_unsigned(&claims),
        "refreshToken": refresh,
        "expiresIn": "3600",
        "localId": uid.as_str(),
        "email": claims.email,
    }))
}

fn verify(store: &AuthStore, body: &Value, at: LogicalInstant) -> Result<LocalId, JsonResponse> {
    let token = str_field(body, "idToken").ok_or_else(|| error(400, "MISSING_ID_TOKEN"))?;
    let v = verify_id_token(token, store, at).map_err(|e| jwt_error(&e))?;
    store
        .user_by_id(&v.uid)
        .map(|u| u.local_id.clone())
        .ok_or_else(|| error(400, "USER_NOT_FOUND"))
}

/// Request metadata the JSON handlers need beyond the body.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RequestHeaders {
    /// `Authorization` header.
    pub authorization: Option<String>,
    /// `Origin` header (browser requests).
    pub origin: Option<String>,
    /// `Content-Type` header.
    pub content_type: Option<String>,
}

/// Whether a browser `Origin` names this machine (loopback) — the only origins allowed to
/// reach privileged routes.
#[must_use]
pub fn origin_is_local(origin: &str) -> bool {
    let rest = origin
        .strip_prefix("http://")
        .or_else(|| origin.strip_prefix("https://"));
    let Some(rest) = rest else { return false };
    let host = rest.strip_prefix('[').map_or_else(
        || rest.split(':').next().unwrap_or(""),
        |v6| v6.split(']').next().unwrap_or(""),
    );
    matches!(host, "localhost" | "127.0.0.1" | "::1")
}

/// Guards the Admin SDK (project-scoped) routes: owner credential, loopback origin, JSON
/// body, matching project.
fn admin_guard(
    headers: &RequestHeaders,
    method: &str,
    project: &str,
    store: &AuthStore,
) -> Result<(), JsonResponse> {
    if headers.authorization.as_deref() != Some("Bearer owner") {
        return Err(error(
            401,
            "MISSING_OWNER_CREDENTIAL : project-scoped routes require 'Authorization: Bearer owner'",
        ));
    }
    if let Some(origin) = &headers.origin {
        if !origin_is_local(origin) {
            return Err(error(403, "FORBIDDEN_ORIGIN"));
        }
    }
    if method == "POST" {
        if let Some(ct) = &headers.content_type {
            if !ct.trim_start().starts_with("application/json") {
                return Err(error(
                    415,
                    "UNSUPPORTED_MEDIA_TYPE : application/json required",
                ));
            }
        }
    }
    if project.is_empty() || project != store.project_id() {
        return Err(error(
            400,
            &format!(
                "INVALID_PROJECT_ID : this runtime serves project {}",
                store.project_id()
            ),
        ));
    }
    Ok(())
}

/// Routes one request. Unknown paths return 404; every handler is JSON in / JSON out.
#[must_use]
pub fn handle(state: &AuthState, method: &str, path: &str, body: &Value) -> JsonResponse {
    handle_with(state, method, path, &RequestHeaders::default(), body)
}

/// Routes one request with its headers (privileged routes check them).
#[must_use]
pub fn handle_with(
    state: &AuthState,
    method: &str,
    path: &str,
    headers: &RequestHeaders,
    body: &Value,
) -> JsonResponse {
    let (path, query) = match path.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (path, None),
    };
    let at = now(state);
    let Ok(mut store) = state.store.lock() else {
        return error(500, "INTERNAL");
    };
    // Admin SDK paths are project-scoped: /identitytoolkit.googleapis.com/v1/projects/{p}/accounts...
    let admin = path
        .strip_prefix("/identitytoolkit.googleapis.com/v1/projects/")
        .and_then(|rest| rest.split_once('/'));
    if let Some((project, action)) = admin {
        if let Err(r) = admin_guard(headers, method, project, &store) {
            return r;
        }
        return match (method, action) {
            ("POST", "accounts") => admin_create(&mut store, body, at),
            ("POST", "accounts:lookup") => lookup(&store, body, at),
            ("POST", "accounts:update") => update(&mut store, body, at),
            ("POST", "accounts:delete") => admin_delete(&mut store, body),
            ("GET" | "POST", "accounts:batchGet") => admin_batch_get(&store, query, body),
            (_, "accounts" | "accounts:lookup" | "accounts:update" | "accounts:delete") => {
                error(405, "METHOD_NOT_ALLOWED")
            }
            _ => error(404, "NOT_FOUND"),
        };
    }
    if method != "POST" {
        return error(405, "METHOD_NOT_ALLOWED");
    }
    match path {
        "/identitytoolkit.googleapis.com/v1/accounts:signUp" => sign_up(&mut store, body, at),
        "/identitytoolkit.googleapis.com/v1/accounts:signInWithPassword" => {
            sign_in_with_password(&mut store, body, at)
        }
        "/identitytoolkit.googleapis.com/v1/accounts:signInWithCustomToken" => {
            sign_in_with_custom_token(&mut store, body, at)
        }
        "/identitytoolkit.googleapis.com/v1/accounts:lookup" => lookup(&store, body, at),
        "/identitytoolkit.googleapis.com/v1/accounts:update" => update(&mut store, body, at),
        "/identitytoolkit.googleapis.com/v2/accounts/mfaEnrollment:start" => {
            mfa_enrollment_start(&mut store, body, at)
        }
        "/identitytoolkit.googleapis.com/v2/accounts/mfaEnrollment:finalize" => {
            mfa_enrollment_finalize(&mut store, body, at)
        }
        "/identitytoolkit.googleapis.com/v2/accounts/mfaSignIn:start" => error(
            400,
            "INVALID_MFA_PENDING_CREDENTIAL : TOTP sign-in has no start step",
        ),
        "/identitytoolkit.googleapis.com/v2/accounts/mfaSignIn:finalize" => {
            mfa_sign_in_finalize(&mut store, body, at)
        }
        "/securetoken.googleapis.com/v1/token" => refresh(&mut store, body, at),
        _ => error(404, "NOT_FOUND"),
    }
}

fn sign_up(store: &mut AuthStore, body: &Value, at: LogicalInstant) -> JsonResponse {
    let new_user = match (str_field(body, "email"), str_field(body, "password")) {
        (Some(_), None) => return error(400, "MISSING_PASSWORD"),
        (Some(email), Some(_)) => NewUser::email(email),
        (None, _) => NewUser::anonymous(),
    };
    let uid = match store.create_user(new_user, at) {
        Ok(uid) => uid,
        Err(e) => return auth_error(&e),
    };
    if let Some(password) = str_field(body, "password") {
        if let Err(e) = store.set_password(&uid, password) {
            return auth_error(&e);
        }
    }
    match issue_tokens(store, &uid, None, at) {
        Ok(body) => JsonResponse { status: 200, body },
        Err(r) => r,
    }
}

/// Audience every Firebase custom token carries.
pub const CUSTOM_TOKEN_AUDIENCE: &str =
    "https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit";

/// `accounts:signInWithCustomToken`: the Admin SDK mints unsigned (`alg: none`) custom
/// tokens against an emulator; the user is created on first sign-in.
fn sign_in_with_custom_token(
    store: &mut AuthStore,
    body: &Value,
    at: LogicalInstant,
) -> JsonResponse {
    let Some(token) = str_field(body, "token") else {
        return error(400, "MISSING_CUSTOM_TOKEN");
    };
    let decoded = match ftd_core_auth::jwt::decode_unsigned(token) {
        Ok(d) => d,
        Err(e) => return error(400, &format!("INVALID_CUSTOM_TOKEN : {e}")),
    };
    if decoded.payload.get("aud").and_then(JsonValue::as_str) != Some(CUSTOM_TOKEN_AUDIENCE) {
        return error(400, "INVALID_CUSTOM_TOKEN : wrong audience");
    }
    let Some(uid) = decoded.payload.get("uid").and_then(JsonValue::as_str) else {
        return error(400, "INVALID_CUSTOM_TOKEN : missing uid");
    };
    let now_secs = i64::try_from(at.as_nanos().div_euclid(1_000_000_000)).unwrap_or(i64::MAX);
    if decoded.exp().is_some_and(|exp| now_secs >= exp) {
        return error(400, "TOKEN_EXPIRED");
    }
    let mut extra = CustomClaims::default();
    if let Some(JsonValue::Object(claims)) = decoded.payload.get("claims") {
        for (k, v) in claims {
            let Some(cv) = claims_from_json(v) else {
                return error(400, "INVALID_CUSTOM_TOKEN : unsupported claim value");
            };
            if let Err(e) = extra.insert(k, cv) {
                return error(400, &format!("INVALID_CUSTOM_TOKEN : {e}"));
            }
        }
    }
    let (uid, is_new) = if let Some(u) = store.user_by_id(uid) {
        (u.local_id.clone(), false)
    } else {
        let new_user = NewUser {
            email: None,
            email_verified: false,
            provider: ftd_core_auth::store::Provider::Custom,
        };
        match store.create_user_with_id(new_user, Some(uid), at) {
            Ok(id) => (id, true),
            Err(e) => return auth_error(&e),
        }
    };
    if store.user(&uid).is_some_and(|u| u.disabled) {
        return error(400, "USER_DISABLED");
    }
    match issue_tokens_with(store, &uid, None, at, Some(&extra)) {
        Ok(mut body) => {
            body["kind"] = json!("identitytoolkit#VerifyCustomTokenResponse");
            body["isNewUser"] = json!(is_new);
            JsonResponse { status: 200, body }
        }
        Err(r) => r,
    }
}

fn sign_in_with_password(store: &mut AuthStore, body: &Value, at: LogicalInstant) -> JsonResponse {
    let (Some(email), Some(password)) = (str_field(body, "email"), str_field(body, "password"))
    else {
        return error(400, "MISSING_PASSWORD");
    };
    let uid = match store.verify_password(email, password, at) {
        Ok(uid) => uid,
        Err(e) => return auth_error(&e),
    };
    let factors: Vec<Value> = store
        .user(&uid)
        .map(|u| {
            u.mfa
                .totp_factors()
                .iter()
                .map(|f| json!({"mfaEnrollmentId": f.mfa_enrollment_id, "displayName": f.display_name, "totpInfo": {}}))
                .collect()
        })
        .unwrap_or_default();
    if !factors.is_empty() {
        // Second factor required: no ID token yet, only a pending credential.
        return match store.start_mfa_sign_in(&uid, at) {
            Ok(pending) => JsonResponse {
                status: 200,
                body: json!({"mfaPendingCredential": pending.as_str(), "mfaInfo": factors, "localId": uid.as_str(), "email": email}),
            },
            Err(e) => mfa_error(&e),
        };
    }
    match issue_tokens(store, &uid, None, at) {
        Ok(body) => JsonResponse { status: 200, body },
        Err(r) => r,
    }
}

fn user_json(store: &AuthStore, uid: &LocalId) -> Value {
    let Some(u) = store.user(uid) else {
        return Value::Null;
    };
    let mfa: Vec<Value> = u
        .mfa
        .totp_factors()
        .iter()
        .map(|f| json!({"mfaEnrollmentId": f.mfa_enrollment_id, "displayName": f.display_name, "enrolledAt": LogicalInstant::to_rfc3339(f.enrolled_at).unwrap_or_default(), "totpInfo": {}}))
        .collect();
    json!({
        "localId": u.local_id.as_str(),
        "email": u.email,
        "displayName": u.display_name,
        "emailVerified": u.email_verified,
        "disabled": u.disabled,
        "customAttributes": u.custom_claims.canonical_json(),
        "mfaInfo": mfa,
        "createdAt": (u.created_at.as_nanos() / 1_000_000).to_string(),
        "lastLoginAt": u.last_sign_in_at.map(|t| (t.as_nanos() / 1_000_000).to_string()),
    })
}

/// Maximum identifiers per lookup (Admin SDK `getUsers`).
const MAX_LOOKUP_IDENTIFIERS: usize = 100;

/// Optional string field; a present non-string (other than null) is a type error.
fn opt_str<'a>(body: &'a Value, key: &str) -> Result<Option<&'a str>, JsonResponse> {
    match body.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.as_str())),
        Some(_) => Err(error(
            400,
            &format!("INVALID_ARGUMENT : {key} must be a string"),
        )),
    }
}

/// Optional boolean field; a present non-boolean (other than null) is a type error.
fn opt_bool(body: &Value, key: &str) -> Result<Option<bool>, JsonResponse> {
    match body.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Bool(b)) => Ok(Some(*b)),
        Some(_) => Err(error(
            400,
            &format!("INVALID_ARGUMENT : {key} must be a boolean"),
        )),
    }
}

/// A string or an array of strings (lookup identifiers); bounded.
fn id_list(body: &Value, key: &str) -> Result<Vec<String>, JsonResponse> {
    let items = match body.get(key) {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::String(s)) => vec![s.clone()],
        Some(Value::Array(items)) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                match item {
                    Value::String(s) => out.push(s.clone()),
                    _ => {
                        return Err(error(
                            400,
                            &format!("INVALID_ARGUMENT : {key} must contain strings"),
                        ))
                    }
                }
            }
            out
        }
        Some(_) => {
            return Err(error(
                400,
                &format!("INVALID_ARGUMENT : {key} must be a string or an array of strings"),
            ))
        }
    };
    if items.len() > MAX_LOOKUP_IDENTIFIERS {
        return Err(error(
            400,
            &format!("INVALID_ARGUMENT : at most {MAX_LOOKUP_IDENTIFIERS} identifiers per lookup"),
        ));
    }
    Ok(items)
}

fn lookup(store: &AuthStore, body: &Value, at: LogicalInstant) -> JsonResponse {
    let local_ids = match id_list(body, "localId") {
        Ok(v) => v,
        Err(r) => return r,
    };
    let emails = match id_list(body, "email") {
        Ok(v) => v,
        Err(r) => return r,
    };
    if local_ids.is_empty() && emails.is_empty() {
        return match verify(store, body, at) {
            Ok(uid) => JsonResponse {
                status: 200,
                body: json!({"users": [user_json(store, &uid)]}),
            },
            Err(r) => r,
        };
    }
    // Resolve every identifier, in request order, without duplicates.
    let mut found: Vec<LocalId> = Vec::new();
    let mut push = |uid: LocalId| {
        if !found.contains(&uid) {
            found.push(uid);
        }
    };
    for id in &local_ids {
        if let Some(u) = store.user_by_id(id) {
            push(u.local_id.clone());
        }
    }
    for email in &emails {
        if let Some(u) = store.user_by_email(email) {
            push(u.local_id.clone());
        }
    }
    let users: Vec<Value> = found.iter().map(|uid| user_json(store, uid)).collect();
    JsonResponse {
        status: 200,
        body: json!({"users": users}),
    }
}

fn claims_from_json(v: &JsonValue) -> Option<ClaimValue> {
    Some(match v {
        JsonValue::Null => ClaimValue::Null,
        JsonValue::Bool(b) => ClaimValue::Bool(*b),
        JsonValue::Int(i) => ClaimValue::Int(*i),
        JsonValue::Float(f) => ClaimValue::Float(*f),
        JsonValue::String(s) => ClaimValue::String(s.clone()),
        JsonValue::Array(items) => ClaimValue::List(
            items
                .iter()
                .map(claims_from_json)
                .collect::<Option<Vec<_>>>()?,
        ),
        JsonValue::Object(m) => ClaimValue::Map(
            m.iter()
                .map(|(k, v)| claims_from_json(v).map(|c| (k.clone(), c)))
                .collect::<Option<_>>()?,
        ),
    })
}

/// `accounts:update`: used by the Admin SDK for custom claims and disable / enable.
/// Everything an `accounts:update` request asks for, validated before any mutation.
struct UpdatePlan {
    claims: Option<CustomClaims>,
    password: Option<String>,
    display_name: Option<String>,
    email_verified: Option<bool>,
    disable: Option<bool>,
    revoke: bool,
}

fn parse_custom_claims(attrs: &str) -> Result<CustomClaims, JsonResponse> {
    let Ok(JsonValue::Object(parsed)) = ftd_core_types::json::parse(attrs) else {
        return Err(error(
            400,
            "INVALID_CLAIMS : customAttributes must be a JSON object",
        ));
    };
    let mut claims = CustomClaims::default();
    for (k, v) in &parsed {
        let Some(cv) = claims_from_json(v) else {
            return Err(error(400, "INVALID_CLAIMS"));
        };
        if let Err(e) = claims.insert(k, cv) {
            return Err(error(400, &format!("FORBIDDEN_CLAIM : {e}")));
        }
    }
    Ok(claims)
}

fn parse_update(body: &Value) -> Result<UpdatePlan, JsonResponse> {
    let claims = match opt_str(body, "customAttributes")? {
        Some(attrs) => Some(parse_custom_claims(attrs)?),
        None => None,
    };
    let password = opt_str(body, "password")?.map(str::to_owned);
    if let Some(p) = &password {
        AuthStore::validate_password(p).map_err(|e| auth_error(&e))?;
    }
    Ok(UpdatePlan {
        claims,
        password,
        display_name: opt_str(body, "displayName")?.map(str::to_owned),
        email_verified: opt_bool(body, "emailVerified")?,
        disable: opt_bool(body, "disableUser")?,
        revoke: body.get("validSince").is_some(),
    })
}

fn update(store: &mut AuthStore, body: &Value, at: LogicalInstant) -> JsonResponse {
    let local_id = match opt_str(body, "localId") {
        Ok(v) => v,
        Err(r) => return r,
    };
    let uid = if let Some(local_id) = local_id {
        match store.user_by_id(local_id) {
            Some(u) => u.local_id.clone(),
            None => return error(400, "USER_NOT_FOUND"),
        }
    } else {
        match verify(store, body, at) {
            Ok(uid) => uid,
            Err(r) => return r,
        }
    };
    // Validate the whole request before touching the store (a rejected request changes
    // nothing).
    let plan = match parse_update(body) {
        Ok(p) => p,
        Err(r) => return r,
    };
    if let Some(claims) = plan.claims {
        if let Err(e) = store.set_custom_claims(&uid, claims) {
            return auth_error(&e);
        }
    }
    if let Some(password) = &plan.password {
        if let Err(e) = store.set_password(&uid, password) {
            return auth_error(&e);
        }
        // A password change ends every existing session.
        let _ = store.revoke_tokens(&uid, at);
        store.revoke_refresh_tokens(&uid);
    }
    if let Some(u) = store.user_mut(&uid) {
        if let Some(name) = plan.display_name {
            u.display_name = Some(name);
        }
        if let Some(verified) = plan.email_verified {
            u.email_verified = verified;
        }
        if let Some(disable) = plan.disable {
            u.disabled = disable;
        }
    }
    if plan.disable == Some(true) || plan.revoke {
        let _ = store.revoke_tokens(&uid, at);
        store.revoke_refresh_tokens(&uid);
    }
    JsonResponse {
        status: 200,
        body: json!({"localId": uid.as_str(), "kind": "identitytoolkit#SetAccountInfoResponse"}),
    }
}

/// Admin `POST /v1/projects/{p}/accounts` (createUser). The request is validated in full
/// before the user is inserted, so a rejected request leaves the store unchanged.
fn admin_create(store: &mut AuthStore, body: &Value, at: LogicalInstant) -> JsonResponse {
    let parsed = (|| -> Result<_, JsonResponse> {
        let email = opt_str(body, "email")?.map(str::to_owned);
        let password = opt_str(body, "password")?.map(str::to_owned);
        if let Some(p) = &password {
            AuthStore::validate_password(p).map_err(|e| auth_error(&e))?;
        }
        if password.is_some() && email.is_none() {
            return Err(error(400, "INVALID_ARGUMENT : password requires an email"));
        }
        Ok((
            email,
            password,
            opt_str(body, "localId")?.map(str::to_owned),
            opt_str(body, "displayName")?.map(str::to_owned),
            opt_bool(body, "emailVerified")?.unwrap_or(false),
            opt_bool(body, "disabled")?.unwrap_or(false),
        ))
    })();
    let (email, password, requested_id, display_name, email_verified, disabled) = match parsed {
        Ok(p) => p,
        Err(r) => return r,
    };
    let new_user = match &email {
        Some(email) => NewUser {
            email: Some(email.clone()),
            email_verified,
            provider: ftd_core_auth::store::Provider::Password,
        },
        None => NewUser::anonymous(),
    };
    let uid = match store.create_user_with_id(new_user, requested_id.as_deref(), at) {
        Ok(uid) => uid,
        Err(e) => return auth_error(&e),
    };
    if let Some(password) = &password {
        if let Err(e) = store.set_password(&uid, password) {
            // Unreachable after validate_password; keep the store consistent regardless.
            let _ = store.delete_user_by_id(uid.as_str());
            return auth_error(&e);
        }
    }
    if let Some(u) = store.user_mut(&uid) {
        u.display_name = display_name;
        u.disabled = disabled;
    }
    JsonResponse {
        status: 200,
        body: json!({"kind": "identitytoolkit#SignupNewUserResponse", "localId": uid.as_str(), "email": email}),
    }
}

/// Admin `accounts:delete`.
fn admin_delete(store: &mut AuthStore, body: &Value) -> JsonResponse {
    let local_id = match opt_str(body, "localId") {
        Ok(Some(id)) => id,
        Ok(None) => return error(400, "MISSING_LOCAL_ID"),
        Err(r) => return r,
    };
    match store.delete_user_by_id(local_id) {
        Ok(()) => JsonResponse {
            status: 200,
            body: json!({"kind": "identitytoolkit#DeleteAccountResponse"}),
        },
        Err(e) => auth_error(&e),
    }
}

/// Minimal `application/x-www-form-urlencoded` query decoding (ASCII percent escapes).
fn query_params(query: Option<&str>) -> BTreeMap<String, String> {
    fn decode(s: &str) -> String {
        let bytes = s.as_bytes();
        let mut out = Vec::with_capacity(bytes.len());
        let mut i = 0;
        while i < bytes.len() {
            match bytes[i] {
                b'%' if i + 2 < bytes.len() => {
                    if let Some(b) = s
                        .get(i + 1..i + 3)
                        .and_then(|hex| u8::from_str_radix(hex, 16).ok())
                    {
                        out.push(b);
                        i += 3;
                    } else {
                        out.push(b'%');
                        i += 1;
                    }
                }
                b'+' => {
                    out.push(b' ');
                    i += 1;
                }
                b => {
                    out.push(b);
                    i += 1;
                }
            }
        }
        String::from_utf8_lossy(&out).into_owned()
    }
    query
        .unwrap_or("")
        .split('&')
        .filter(|kv| !kv.is_empty())
        .map(|kv| match kv.split_once('=') {
            Some((k, v)) => (decode(k), decode(v)),
            None => (decode(kv), String::new()),
        })
        .collect()
}

/// Admin `accounts:batchGet` (`listUsers`): `GET ?maxResults=&nextPageToken=`; the page
/// token is the last user ID of the previous page (opaque to clients).
fn admin_batch_get(store: &AuthStore, query: Option<&str>, body: &Value) -> JsonResponse {
    let params = query_params(query);
    let max_text = params.get("maxResults").cloned().or_else(|| {
        body.get("maxResults").map(|v| match v {
            Value::String(s) => s.clone(),
            other => other.to_string(),
        })
    });
    let max = match max_text.as_deref() {
        None => 1_000usize,
        Some(t) => match t.parse::<usize>() {
            Ok(n) if (1..=1_000).contains(&n) => n,
            _ => return error(400, "INVALID_ARGUMENT : maxResults must be 1..=1000"),
        },
    };
    let after = params
        .get("nextPageToken")
        .cloned()
        .or_else(|| {
            body.get("nextPageToken")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .filter(|t| !t.is_empty());
    let ids = store.all_user_ids();
    let page: Vec<&LocalId> = ids
        .iter()
        .filter(|uid| after.as_deref().is_none_or(|a| uid.as_str() > a))
        .take(max + 1)
        .collect();
    let has_more = page.len() > max;
    let page = &page[..page.len().min(max)];
    let users: Vec<Value> = page.iter().map(|uid| user_json(store, uid)).collect();
    let mut response = json!({"kind": "identitytoolkit#DownloadAccountResponse", "users": users});
    if has_more {
        if let Some(last) = page.last() {
            response["nextPageToken"] = Value::String(last.as_str().to_owned());
        }
    }
    JsonResponse {
        status: 200,
        body: response,
    }
}

fn mfa_enrollment_start(store: &mut AuthStore, body: &Value, at: LogicalInstant) -> JsonResponse {
    let uid = match verify(store, body, at) {
        Ok(uid) => uid,
        Err(r) => return r,
    };
    if body.get("totpEnrollmentInfo").is_none() {
        return error(400, "INVALID_ARGUMENT : only TOTP enrollment is supported");
    }
    match store.start_totp_enrollment(&uid, at) {
        Ok(material) => {
            let policy = *store.policy();
            JsonResponse {
                status: 200,
                body: json!({
                    "totpSessionInfo": {
                        "sharedSecretKey": base32::encode(material.secret_for_test()),
                        "verificationCodeLength": policy.digits,
                        "hashingAlgorithm": "HMAC_SHA1",
                        "periodSec": policy.period_seconds,
                        "sessionInfo": material.session_id,
                        "finalizeEnrollmentTime": LogicalInstant::to_rfc3339(material.expires_at).unwrap_or_default(),
                    }
                }),
            }
        }
        Err(e) => mfa_error(&e),
    }
}

fn parse_code(v: Option<&Value>) -> Option<u32> {
    match v {
        Some(Value::String(s)) if s.len() <= 8 && s.bytes().all(|b| b.is_ascii_digit()) => {
            s.parse().ok()
        }
        Some(Value::Number(n)) => n.as_u64().and_then(|n| u32::try_from(n).ok()),
        _ => None,
    }
}

fn mfa_enrollment_finalize(
    store: &mut AuthStore,
    body: &Value,
    at: LogicalInstant,
) -> JsonResponse {
    let uid = match verify(store, body, at) {
        Ok(uid) => uid,
        Err(r) => return r,
    };
    let info = body.get("totpVerificationInfo");
    let session = info
        .and_then(|i| i.get("sessionInfo"))
        .and_then(Value::as_str);
    let code = parse_code(info.and_then(|i| i.get("verificationCode")));
    let (Some(session), Some(code)) = (session, code) else {
        return error(
            400,
            "INVALID_CODE : missing sessionInfo or verificationCode",
        );
    };
    match store.finalize_totp_enrollment(&uid, session, code, at) {
        Ok(factor) => {
            let assertion = SecondFactorAssertion {
                sign_in_second_factor: "totp".to_owned(),
                second_factor_identifier: factor.mfa_enrollment_id.clone(),
                verified_at: at,
            };
            match issue_tokens(store, &uid, Some(&assertion), at) {
                Ok(mut tokens) => {
                    tokens["mfaEnrollmentId"] = json!(factor.mfa_enrollment_id);
                    JsonResponse {
                        status: 200,
                        body: tokens,
                    }
                }
                Err(r) => r,
            }
        }
        Err(e) => mfa_error(&e),
    }
}

fn mfa_sign_in_finalize(store: &mut AuthStore, body: &Value, at: LogicalInstant) -> JsonResponse {
    let Some(pending) = str_field(body, "mfaPendingCredential") else {
        return error(400, "MISSING_MFA_PENDING_CREDENTIAL");
    };
    let code = parse_code(
        body.get("totpVerificationInfo")
            .and_then(|i| i.get("verificationCode")),
    );
    let Some(code) = code else {
        return error(400, "INVALID_CODE : missing verificationCode");
    };
    let Some(uid) = PendingSignInId::parse(pending).and_then(|p| store.pending_sign_in_user(&p))
    else {
        return error(400, "INVALID_MFA_PENDING_CREDENTIAL");
    };
    let pending_id = PendingSignInId::parse(pending)
        .unwrap_or_else(|| PendingSignInId::parse("").expect("empty id parses"));
    match store.finalize_mfa_sign_in(&uid, &pending_id, code, at) {
        Ok(assertion) => match issue_tokens(store, &uid, Some(&assertion), at) {
            Ok(body) => JsonResponse { status: 200, body },
            Err(r) => r,
        },
        Err(e) => mfa_error(&e),
    }
}

fn refresh(store: &mut AuthStore, body: &Value, at: LogicalInstant) -> JsonResponse {
    if str_field(body, "grant_type") != Some("refresh_token") {
        return error(400, "INVALID_GRANT_TYPE");
    }
    let Some(token) = str_field(body, "refresh_token") else {
        return error(400, "MISSING_REFRESH_TOKEN");
    };
    let uid = match store.redeem_refresh_token(token) {
        Ok(uid) => uid,
        Err(e) => return auth_error(&e),
    };
    match store.id_token_claims(&uid, None, at) {
        Ok(claims) => JsonResponse {
            status: 200,
            body: json!({
                "id_token": encode_unsigned(&claims),
                "refresh_token": token,
                "expires_in": "3600",
                "token_type": "Bearer",
                "user_id": uid.as_str(),
                "project_id": store.project_id(),
            }),
        },
        Err(e) => auth_error(&e),
    }
}
