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
use ftd_core_auth::jwt::{encode_with, verify_id_token, JwtError};
use ftd_core_auth::mfa::MfaError;
use ftd_core_auth::store::{
    AuthError, AuthStore, FederatedIdentity, LocalId, NewUser, OobRequestType, PendingSignInId,
    SecondFactorAssertion, VerificationPurpose,
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
    /// Session admission barrier (reset waits for requests in flight), when shared.
    pub barrier: Option<Arc<ftd_core_session::barrier::AdmissionBarrier>>,
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
        AuthError::PhoneNumberExists => error(400, "PHONE_NUMBER_EXISTS"),
        AuthError::InvalidPhoneNumber => error(400, "INVALID_PHONE_NUMBER"),
        AuthError::EmailNotFound => error(400, "EMAIL_NOT_FOUND"),
        AuthError::InvalidOobCode => error(400, "INVALID_OOB_CODE"),
        AuthError::InvalidSessionInfo => error(400, "INVALID_SESSION_INFO"),
        AuthError::InvalidVerificationCode => error(400, "INVALID_CODE"),
        AuthError::FederatedUserIdAlreadyLinked => error(400, "FEDERATED_USER_ID_ALREADY_LINKED"),
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
        MfaError::TooManyFactors => error(400, "SECOND_FACTOR_LIMIT_EXCEEDED"),
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
    issue_tokens_with(store, uid, second, at, None, None)
}

/// Issues an ID token + refresh token; `extra` claims (custom-token developer claims) and
/// `provider` are merged into the token and remembered by the refresh session.
fn issue_tokens_with(
    store: &mut AuthStore,
    uid: &LocalId,
    second: Option<&SecondFactorAssertion>,
    at: LogicalInstant,
    extra: Option<&CustomClaims>,
    provider: Option<ftd_core_auth::store::Provider>,
) -> Result<Value, JsonResponse> {
    let mut claims = store
        .id_token_claims(uid, second, at)
        .map_err(|e| auth_error(&e))?;
    if let Some(p) = &provider {
        p.id().clone_into(&mut claims.firebase.sign_in_provider);
    }
    if let Some(extra) = extra {
        for (k, v) in extra.entries() {
            claims
                .custom
                .insert(k, v.clone())
                .map_err(|e| error(400, &format!("INVALID_CUSTOM_TOKEN : {e}")))?;
        }
    }
    let refresh = store
        .issue_refresh_session(
            uid,
            at,
            provider,
            extra.cloned().unwrap_or_default(),
            second.cloned(),
        )
        .map_err(|e| auth_error(&e))?;
    Ok(json!({
        "idToken": encode_with(&claims, store.signer()),
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
    /// `Host` header (action links name this daemon).
    pub host: Option<String>,
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

/// Where the session's JWKS is served (the Google path the SDKs know, and the well-known one).
pub const JWKS_PATHS: &[&str] = &[
    "/.well-known/jwks.json",
    "/www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com",
];

/// Routes one request with its headers (privileged routes check them).
#[must_use]
#[allow(clippy::too_many_lines)]
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
    let _admitted = state.barrier.as_ref().map(|b| b.admit());
    let Ok(mut store) = state.store.lock() else {
        return error(500, "INTERNAL");
    };
    if method == "GET" && JWKS_PATHS.contains(&path) {
        // The public keys signed ID tokens verify against (empty for unsigned sessions).
        let keys: Vec<Value> = store
            .signer()
            .and_then(|s| serde_json::from_str::<Value>(&s.public_jwk_json()).ok())
            .into_iter()
            .collect();
        return JsonResponse {
            status: 200,
            body: json!({"keys": keys}),
        };
    }
    // Emulator inspection routes (what tests read instead of an inbox or an SMS).
    if let Some(rest) = path.strip_prefix("/emulator/v1/projects/") {
        let (project, resource) = rest.split_once('/').unwrap_or((rest, ""));
        if let Some(origin) = &headers.origin {
            if !origin_is_local(origin) {
                return error(403, "FORBIDDEN_ORIGIN");
            }
        }
        if project != store.project_id() {
            return error(400, "INVALID_PROJECT_ID");
        }
        return emulator_route(&mut store, method, resource, headers);
    }
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
            ("POST", "accounts:lookup") => lookup(&store, body, at, true),
            ("POST", "accounts:update") => update(&mut store, body, at),
            ("POST", "accounts:delete") => admin_delete(&mut store, body),
            ("GET" | "POST", "accounts:batchGet") => admin_batch_get(&store, query, body),
            // Admin link generators: the code and link come back to the caller.
            ("POST", "accounts:sendOobCode") => {
                let mut with_link = body.clone();
                with_link["returnOobLink"] = json!(true);
                send_oob_code(&mut store, &with_link, at, headers)
            }
            (
                _,
                "accounts"
                | "accounts:lookup"
                | "accounts:update"
                | "accounts:delete"
                | "accounts:sendOobCode",
            ) => error(405, "METHOD_NOT_ALLOWED"),
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
        "/identitytoolkit.googleapis.com/v1/accounts:lookup" => lookup(&store, body, at, false),
        "/identitytoolkit.googleapis.com/v1/accounts:update" => update(&mut store, body, at),
        "/identitytoolkit.googleapis.com/v1/accounts:sendOobCode" => {
            send_oob_code(&mut store, body, at, headers)
        }
        "/identitytoolkit.googleapis.com/v1/accounts:resetPassword" => {
            reset_password(&mut store, body, at)
        }
        "/identitytoolkit.googleapis.com/v1/accounts:signInWithEmailLink" => {
            sign_in_with_email_link(&mut store, body, at)
        }
        "/identitytoolkit.googleapis.com/v1/accounts:sendVerificationCode" => {
            send_verification_code(&mut store, body, at)
        }
        "/identitytoolkit.googleapis.com/v1/accounts:signInWithPhoneNumber" => {
            sign_in_with_phone_number(&mut store, body, at)
        }
        "/identitytoolkit.googleapis.com/v1/accounts:signInWithIdp" => {
            sign_in_with_idp(&mut store, body, at)
        }
        "/identitytoolkit.googleapis.com/v1/accounts:createAuthUri" => {
            create_auth_uri(&store, body)
        }
        "/identitytoolkit.googleapis.com/v2/accounts/mfaEnrollment:start" => {
            mfa_enrollment_start(&mut store, body, at)
        }
        "/identitytoolkit.googleapis.com/v2/accounts/mfaEnrollment:finalize" => {
            mfa_enrollment_finalize(&mut store, body, at)
        }
        "/identitytoolkit.googleapis.com/v2/accounts/mfaEnrollment:withdraw" => {
            mfa_enrollment_withdraw(&mut store, body, at)
        }
        "/identitytoolkit.googleapis.com/v2/accounts/mfaSignIn:start" => {
            mfa_sign_in_start(&mut store, body, at)
        }
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
    store.record_sign_in(&uid, at);
    match issue_tokens_with(
        store,
        &uid,
        None,
        at,
        Some(&extra),
        Some(ftd_core_auth::store::Provider::Custom),
    ) {
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
    let factors = mfa_info(store, &uid);
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
    let mfa = mfa_info(store, uid);
    let mut providers: Vec<Value> = Vec::new();
    if let Some(email) = &u.email {
        let provider_id = if store.has_password(uid) {
            "password"
        } else {
            "emailLink"
        };
        providers.push(json!({"providerId": provider_id, "rawId": email, "email": email, "displayName": u.display_name, "photoUrl": u.photo_url}));
    }
    if let Some(phone) = &u.phone_number {
        providers.push(json!({"providerId": "phone", "rawId": phone, "phoneNumber": phone}));
    }
    for f in &u.federated {
        providers.push(json!({"providerId": f.provider_id, "rawId": f.raw_id, "federatedId": f.raw_id, "email": f.email, "displayName": f.display_name, "photoUrl": f.photo_url}));
    }
    json!({
        "localId": u.local_id.as_str(),
        "email": u.email,
        "displayName": u.display_name,
        "photoUrl": u.photo_url,
        "phoneNumber": u.phone_number,
        "emailVerified": u.email_verified,
        "disabled": u.disabled,
        "customAttributes": u.custom_claims.canonical_json(),
        "providerUserInfo": providers,
        "mfaInfo": mfa,
        "createdAt": (u.created_at.as_nanos() / 1_000_000).to_string(),
        "lastLoginAt": u.last_sign_in_at.map(|t| (t.as_nanos() / 1_000_000).to_string()),
        "validSince": (u.tokens_valid_after.as_nanos() / 1_000_000_000).to_string(),
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

fn lookup(store: &AuthStore, body: &Value, at: LogicalInstant, admin: bool) -> JsonResponse {
    let lists = (|| -> Result<_, JsonResponse> {
        let federated: Vec<(String, String)> =
            match body.get("federatedUserId") {
                None | Some(Value::Null) => Vec::new(),
                Some(Value::Array(items)) if items.iter().all(Value::is_object) => items
                    .iter()
                    .map(|i| {
                        (
                            str_field(i, "providerId").unwrap_or("").to_owned(),
                            str_field(i, "rawId").unwrap_or("").to_owned(),
                        )
                    })
                    .collect(),
                Some(_) => return Err(error(
                    400,
                    "INVALID_ARGUMENT : federatedUserId must be an array of {providerId, rawId}",
                )),
            };
        Ok((
            id_list(body, "localId")?,
            id_list(body, "email")?,
            id_list(body, "phoneNumber")?,
            federated,
        ))
    })();
    let (local_ids, emails, phones, federated) = match lists {
        Ok(l) => l,
        Err(r) => return r,
    };
    let total = local_ids.len() + emails.len() + phones.len() + federated.len();
    if total > MAX_LOOKUP_IDENTIFIERS {
        return error(
            400,
            &format!("INVALID_ARGUMENT : at most {MAX_LOOKUP_IDENTIFIERS} identifiers per lookup"),
        );
    }
    if total == 0 {
        if admin {
            return error(
                400,
                "MISSING_IDENTIFIER : localId, email, phoneNumber or federatedUserId",
            );
        }
        return match verify(store, body, at) {
            Ok(uid) => JsonResponse {
                status: 200,
                body: json!({"users": [user_json(store, &uid)]}),
            },
            Err(r) => r,
        };
    }
    // Resolve every identifier, in request order, without duplicates. Federated
    // identities are never linked in this runtime, so they match nobody.
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
    for phone in &phones {
        if let Some(u) = store.user_by_phone(phone) {
            push(u.local_id.clone());
        }
    }
    for (provider_id, raw_id) in &federated {
        if let Some(u) = store.user_by_federated(provider_id, raw_id) {
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
/// Requested change of an optional attribute.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Change {
    /// Not mentioned by the request.
    Keep,
    /// `deleteAttribute` / `deleteProvider`.
    Clear,
    /// New value.
    Set(String),
}

impl Change {
    fn apply(self, slot: &mut Option<String>) {
        match self {
            Self::Keep => {}
            Self::Clear => *slot = None,
            Self::Set(v) => *slot = Some(v),
        }
    }
}

/// Everything an `accounts:update` request asks for, validated before any mutation.
struct UpdatePlan {
    claims: Option<CustomClaims>,
    password: Option<String>,
    email: Option<String>,
    phone_number: Change,
    display_name: Change,
    photo_url: Change,
    email_verified: Option<bool>,
    disable: Option<bool>,
    revoke: bool,
    /// `linkProviderUserInfo`.
    link: Option<FederatedIdentity>,
    /// `deleteProvider` entries naming federated providers.
    unlink: Vec<String>,
    /// `mfa.enrollments` (phone factors replace the current ones).
    phone_factors: Option<Vec<(String, Option<String>)>>,
}

/// Request fields this runtime does not model; a non-empty value is refused instead of
/// being silently dropped.
const UNSUPPORTED_UPDATE_FIELDS: &[&str] = &["mfaInfo"];

/// `{providerId, rawId, email?, displayName?, photoUrl?}` of a link request.
fn parse_identity(v: &Value) -> Result<FederatedIdentity, JsonResponse> {
    let provider_id = opt_str(v, "providerId")?
        .filter(|p| !p.is_empty())
        .ok_or_else(|| error(400, "INVALID_ARGUMENT : providerId is required"))?;
    let raw_id = opt_str(v, "rawId")?
        .filter(|p| !p.is_empty())
        .ok_or_else(|| error(400, "INVALID_ARGUMENT : rawId is required"))?;
    if matches!(provider_id, "password" | "phone" | "emailLink") {
        return Err(error(
            400,
            "INVALID_ARGUMENT : linkProviderUserInfo takes a federated providerId",
        ));
    }
    Ok(FederatedIdentity {
        provider_id: provider_id.to_owned(),
        raw_id: raw_id.to_owned(),
        email: opt_str(v, "email")?.map(str::to_owned),
        display_name: opt_str(v, "displayName")?.map(str::to_owned),
        photo_url: opt_str(v, "photoUrl")?.map(str::to_owned),
    })
}

/// Phone factors of `mfaInfo` / `mfa.enrollments` entries (`{phoneInfo, displayName}`).
fn parse_phone_factors(entries: &Value) -> Result<Vec<(String, Option<String>)>, JsonResponse> {
    let Some(items) = entries.as_array() else {
        return Err(error(
            400,
            "INVALID_ARGUMENT : enrollments must be an array",
        ));
    };
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let Some(phone) = str_field(item, "phoneInfo") else {
            return Err(error(
                400,
                "INVALID_ARGUMENT : only phone second factors (phoneInfo) can be enrolled by an admin",
            ));
        };
        AuthStore::validate_phone_number(phone).map_err(|e| auth_error(&e))?;
        out.push((
            phone.to_owned(),
            opt_str(item, "displayName")?.map(str::to_owned),
        ));
    }
    Ok(out)
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

fn reject_unsupported(body: &Value, fields: &[&str]) -> Result<(), JsonResponse> {
    for f in fields {
        let present = match body.get(*f) {
            None | Some(Value::Null) => false,
            Some(Value::Array(a)) => !a.is_empty(),
            Some(Value::Object(o)) => !o.is_empty(),
            Some(Value::String(s)) => !s.is_empty(),
            Some(_) => true,
        };
        if present {
            return Err(error(
                400,
                &format!("UNSUPPORTED_FIELD : {f} is not supported by this runtime"),
            ));
        }
    }
    Ok(())
}

fn string_list(v: &Value, what: &str) -> Result<Vec<String>, JsonResponse> {
    let Some(items) = v.as_array() else {
        return Err(error(
            400,
            &format!("INVALID_ARGUMENT : {what} must be an array"),
        ));
    };
    items
        .iter()
        .map(|a| {
            a.as_str().map(str::to_owned).ok_or_else(|| {
                error(
                    400,
                    &format!("INVALID_ARGUMENT : {what} entries must be strings"),
                )
            })
        })
        .collect()
}

fn parse_update(body: &Value) -> Result<UpdatePlan, JsonResponse> {
    reject_unsupported(body, UNSUPPORTED_UPDATE_FIELDS)?;
    let claims = match opt_str(body, "customAttributes")? {
        Some(attrs) => Some(parse_custom_claims(attrs)?),
        None => None,
    };
    let password = opt_str(body, "password")?.map(str::to_owned);
    if let Some(p) = &password {
        AuthStore::validate_password(p).map_err(|e| auth_error(&e))?;
    }
    let change = |key: &str| -> Result<Change, JsonResponse> {
        Ok(opt_str(body, key)?.map_or(Change::Keep, |v| Change::Set(v.to_owned())))
    };
    let mut display_name = change("displayName")?;
    let mut photo_url = change("photoUrl")?;
    let mut phone_number = change("phoneNumber")?;
    if let Change::Set(p) = &phone_number {
        AuthStore::validate_phone_number(p).map_err(|e| auth_error(&e))?;
    }
    if let Some(attrs) = body.get("deleteAttribute") {
        for a in string_list(attrs, "deleteAttribute")? {
            match a.as_str() {
                "DISPLAY_NAME" => display_name = Change::Clear,
                "PHOTO_URL" => photo_url = Change::Clear,
                other => {
                    return Err(error(
                        400,
                        &format!("INVALID_ARGUMENT : unknown deleteAttribute {other:?}"),
                    ))
                }
            }
        }
    }
    let mut unlink = Vec::new();
    if let Some(providers) = body.get("deleteProvider") {
        for p in string_list(providers, "deleteProvider")? {
            match p.as_str() {
                "phone" => phone_number = Change::Clear,
                "password" | "emailLink" => {
                    return Err(error(
                        400,
                        &format!("UNSUPPORTED_FIELD : deleteProvider {p:?} is not supported"),
                    ))
                }
                _ => unlink.push(p),
            }
        }
    }
    let link = match body.get("linkProviderUserInfo") {
        None | Some(Value::Null) => None,
        Some(v) => Some(parse_identity(v)?),
    };
    let phone_factors = match body.get("mfa").and_then(|m| m.get("enrollments")) {
        None | Some(Value::Null) => None,
        Some(v) => Some(parse_phone_factors(v)?),
    };
    Ok(UpdatePlan {
        claims,
        password,
        email: opt_str(body, "email")?.map(str::to_owned),
        phone_number,
        display_name,
        photo_url,
        email_verified: opt_bool(body, "emailVerified")?,
        disable: opt_bool(body, "disableUser")?,
        revoke: body.get("validSince").is_some(),
        link,
        unlink,
        phone_factors,
    })
}

#[allow(clippy::too_many_lines)]
fn update(store: &mut AuthStore, body: &Value, at: LogicalInstant) -> JsonResponse {
    // `applyActionCode`: an email verification / change code instead of a session.
    if let Some(code) = str_field(body, "oobCode") {
        return apply_oob_code(store, code);
    }
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
    // nothing); email / phone uniqueness is part of the validation.
    let plan = match parse_update(body) {
        Ok(p) => p,
        Err(r) => return r,
    };
    if let Some(email) = &plan.email {
        if store
            .user_by_email(email)
            .is_some_and(|u| u.local_id != uid)
        {
            return error(400, "EMAIL_EXISTS");
        }
    }
    if let Change::Set(phone) = &plan.phone_number {
        if store
            .user_by_phone(phone)
            .is_some_and(|u| u.local_id != uid)
        {
            return error(400, "PHONE_NUMBER_EXISTS");
        }
    }
    if let Some(identity) = &plan.link {
        if store
            .user_by_federated(&identity.provider_id, &identity.raw_id)
            .is_some_and(|u| u.local_id != uid)
        {
            return error(400, "FEDERATED_USER_ID_ALREADY_LINKED");
        }
    }
    if let Some(claims) = plan.claims {
        if let Err(e) = store.set_custom_claims(&uid, claims) {
            return auth_error(&e);
        }
    }
    if let Some(identity) = plan.link {
        if let Err(e) = store.link_federated(&uid, identity) {
            return auth_error(&e);
        }
    }
    for provider in &plan.unlink {
        if let Err(e) = store.unlink_federated(&uid, provider) {
            return auth_error(&e);
        }
    }
    if let Some(factors) = plan.phone_factors {
        if let Err(e) = store.set_phone_factors(&uid, factors, at) {
            return mfa_error(&e);
        }
    }
    if let Some(email) = &plan.email {
        if let Err(e) = store.set_email(&uid, email) {
            return auth_error(&e);
        }
    }
    match &plan.phone_number {
        Change::Keep => {}
        Change::Clear => {
            if let Err(e) = store.set_phone_number(&uid, None) {
                return auth_error(&e);
            }
        }
        Change::Set(phone) => {
            if let Err(e) = store.set_phone_number(&uid, Some(phone)) {
                return auth_error(&e);
            }
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
        plan.display_name.apply(&mut u.display_name);
        plan.photo_url.apply(&mut u.photo_url);
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
        reject_unsupported(body, &["mfa", "providerUserInfo"])?;
        let email = opt_str(body, "email")?.map(str::to_owned);
        let password = opt_str(body, "password")?.map(str::to_owned);
        if let Some(p) = &password {
            AuthStore::validate_password(p).map_err(|e| auth_error(&e))?;
        }
        if password.is_some() && email.is_none() {
            return Err(error(400, "INVALID_ARGUMENT : password requires an email"));
        }
        let phone = opt_str(body, "phoneNumber")?.map(str::to_owned);
        if let Some(p) = &phone {
            AuthStore::validate_phone_number(p).map_err(|e| auth_error(&e))?;
            if store.user_by_phone(p).is_some() {
                return Err(error(400, "PHONE_NUMBER_EXISTS"));
            }
        }
        let factors = match body.get("mfaInfo") {
            None | Some(Value::Null) => Vec::new(),
            Some(v) => parse_phone_factors(v)?,
        };
        Ok((
            email,
            password,
            phone,
            opt_str(body, "localId")?.map(str::to_owned),
            opt_str(body, "displayName")?.map(str::to_owned),
            opt_str(body, "photoUrl")?.map(str::to_owned),
            opt_bool(body, "emailVerified")?.unwrap_or(false),
            opt_bool(body, "disabled")?.unwrap_or(false),
            factors,
        ))
    })();
    let (
        email,
        password,
        phone,
        requested_id,
        display_name,
        photo_url,
        email_verified,
        disabled,
        factors,
    ) = match parsed {
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
    if let Err(e) = store.set_phone_number(&uid, phone.as_deref()) {
        let _ = store.delete_user_by_id(uid.as_str());
        return auth_error(&e);
    }
    if let Some(u) = store.user_mut(&uid) {
        u.display_name = display_name;
        u.photo_url = photo_url;
        u.disabled = disabled;
    }
    if let Err(e) = store.set_phone_factors(&uid, factors, at) {
        let _ = store.delete_user_by_id(uid.as_str());
        return mfa_error(&e);
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

/// Admin `accounts:batchGet` (`listUsers`): `GET ?maxResults=&nextPageToken=`, users in
/// creation order; the page token is an opaque versioned cursor.
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
    let token = params
        .get("nextPageToken")
        .cloned()
        .or_else(|| {
            body.get("nextPageToken")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .filter(|t| !t.is_empty());
    let after: u64 = match token.as_deref() {
        None => 0,
        Some(t) => match t.strip_prefix("v1:").and_then(|n| n.parse::<u64>().ok()) {
            Some(n) => n,
            None => return error(400, "INVALID_PAGE_TOKEN"),
        },
    };
    let page: Vec<&ftd_core_auth::store::UserRecord> = store
        .users_by_creation()
        .into_iter()
        .filter(|u| u.sequence > after)
        .take(max + 1)
        .collect();
    let has_more = page.len() > max;
    let page = &page[..page.len().min(max)];
    let users: Vec<Value> = page.iter().map(|u| user_json(store, &u.local_id)).collect();
    let mut response = json!({"kind": "identitytoolkit#DownloadAccountResponse", "users": users});
    if has_more {
        if let Some(last) = page.last() {
            response["nextPageToken"] = Value::String(format!("v1:{}", last.sequence));
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
    if let Some(phone) = body.get("phoneEnrollmentInfo") {
        let Some(number) = str_field(phone, "phoneNumber") else {
            return error(400, "INVALID_PHONE_NUMBER : phoneNumber is required");
        };
        return match store.send_verification_code(
            number,
            VerificationPurpose::Enrollment { uid },
            at,
        ) {
            Ok(code) => JsonResponse {
                status: 200,
                body: json!({"phoneSessionInfo": {"sessionInfo": code.session_info}}),
            },
            Err(e) => auth_error(&e),
        };
    }
    if body.get("totpEnrollmentInfo").is_none() {
        return error(
            400,
            "INVALID_ARGUMENT : totpEnrollmentInfo or phoneEnrollmentInfo is required",
        );
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
    if let Some(phone) = body.get("phoneVerificationInfo") {
        return finalize_phone_enrollment(store, &uid, phone, body, at);
    }
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
    if let Some(phone) = body.get("phoneVerificationInfo") {
        return finalize_phone_sign_in(store, pending, phone, at);
    }
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
    let session = match store.refresh_session(token) {
        Ok(s) => s.clone(),
        Err(e) => return auth_error(&e),
    };
    match store.id_token_claims_for_session(&session, at) {
        Ok(claims) => JsonResponse {
            status: 200,
            body: json!({
                "id_token": encode_with(&claims, store.signer()),
                "refresh_token": token,
                "expires_in": "3600",
                "token_type": "Bearer",
                "user_id": session.uid.as_str(),
                "project_id": store.project_id(),
            }),
        },
        Err(e) => auth_error(&e),
    }
}

// ---- email actions --------------------------------------------------------------------

/// `mfaInfo` entries of every enrolled factor.
fn mfa_info(store: &AuthStore, uid: &LocalId) -> Vec<Value> {
    let Some(u) = store.user(uid) else {
        return Vec::new();
    };
    let mut out: Vec<Value> = u
        .mfa
        .totp_factors()
        .iter()
        .map(|f| json!({"mfaEnrollmentId": f.mfa_enrollment_id, "displayName": f.display_name, "enrolledAt": LogicalInstant::to_rfc3339(f.enrolled_at).unwrap_or_default(), "totpInfo": {}}))
        .collect();
    out.extend(u.mfa.phone_factors().iter().map(|f| {
        json!({"mfaEnrollmentId": f.mfa_enrollment_id, "displayName": f.display_name, "enrolledAt": LogicalInstant::to_rfc3339(f.enrolled_at).unwrap_or_default(), "phoneInfo": f.phone_number})
    }));
    out
}

/// The action link of an email action (what the Emulator's console prints).
fn oob_link(
    headers: &RequestHeaders,
    request_type: OobRequestType,
    code: &str,
    body: &Value,
) -> String {
    let host = headers.host.as_deref().unwrap_or("127.0.0.1:9099");
    let mode = match request_type {
        OobRequestType::PasswordReset => "resetPassword",
        OobRequestType::VerifyEmail => "verifyEmail",
        OobRequestType::EmailSignIn => "signIn",
        OobRequestType::VerifyAndChangeEmail => "verifyAndChangeEmail",
    };
    let mut link = format!(
        "http://{host}/emulator/action?mode={mode}&lang=en&oobCode={code}&apiKey=fake-api-key"
    );
    if let Some(url) = str_field(body, "continueUrl") {
        link.push_str("&continueUrl=");
        link.push_str(&percent_encode(url));
    }
    link
}

fn percent_encode(s: &str) -> String {
    use std::fmt::Write as _;
    s.bytes()
        .fold(String::with_capacity(s.len()), |mut out, b| {
            if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
                out.push(b as char);
            } else {
                let _ = write!(out, "%{b:02X}");
            }
            out
        })
}

/// `accounts:sendOobCode`: `PASSWORD_RESET` (email), `VERIFY_EMAIL` (idToken),
/// `EMAIL_SIGNIN` (email), `VERIFY_AND_CHANGE_EMAIL` (idToken + newEmail). Nothing is
/// mailed: the code is kept for `/emulator/v1/projects/{p}/oobCodes`, and returned here
/// with its link when `returnOobLink` is set (the Admin SDK's link generators).
fn send_oob_code(
    store: &mut AuthStore,
    body: &Value,
    at: LogicalInstant,
    headers: &RequestHeaders,
) -> JsonResponse {
    let Some(request_type) = str_field(body, "requestType").and_then(OobRequestType::parse) else {
        return error(400, "INVALID_REQ_TYPE");
    };
    let (email, uid, new_email) = match request_type {
        OobRequestType::PasswordReset => {
            let Some(email) = str_field(body, "email") else {
                return error(400, "MISSING_EMAIL");
            };
            match store.user_by_email(email) {
                Some(u) => (email.to_owned(), Some(u.local_id.clone()), None),
                None => return error(400, "EMAIL_NOT_FOUND"),
            }
        }
        OobRequestType::EmailSignIn => {
            let Some(email) = str_field(body, "email") else {
                return error(400, "MISSING_EMAIL");
            };
            if !email.contains('@') {
                return error(400, "INVALID_EMAIL");
            }
            let uid = store.user_by_email(email).map(|u| u.local_id.clone());
            (email.to_owned(), uid, None)
        }
        OobRequestType::VerifyEmail | OobRequestType::VerifyAndChangeEmail => {
            // A session, or (Admin link generators) the email itself.
            let uid = match (str_field(body, "idToken"), str_field(body, "email")) {
                (Some(_), _) => match verify(store, body, at) {
                    Ok(uid) => uid,
                    Err(r) => return r,
                },
                (None, Some(email)) => match store.user_by_email(email) {
                    Some(u) => u.local_id.clone(),
                    None => return error(400, "EMAIL_NOT_FOUND"),
                },
                (None, None) => return error(400, "MISSING_ID_TOKEN"),
            };
            let Some(email) = store.user(&uid).and_then(|u| u.email.clone()) else {
                return error(400, "MISSING_EMAIL : the user has no email");
            };
            let new_email = if request_type == OobRequestType::VerifyAndChangeEmail {
                let Some(new_email) = str_field(body, "newEmail") else {
                    return error(400, "MISSING_NEW_EMAIL");
                };
                if store
                    .user_by_email(new_email)
                    .is_some_and(|u| u.local_id != uid)
                {
                    return error(400, "EMAIL_EXISTS");
                }
                Some(new_email.to_owned())
            } else {
                None
            };
            (email, Some(uid), new_email)
        }
    };
    let code = store.create_oob_code(request_type, &email, uid, new_email, at);
    let mut response =
        json!({"kind": "identitytoolkit#GetOobConfirmationCodeResponse", "email": email});
    if body.get("returnOobLink").and_then(Value::as_bool) == Some(true) {
        response["oobCode"] = json!(code);
        response["oobLink"] = json!(oob_link(headers, request_type, &code, body));
    }
    JsonResponse {
        status: 200,
        body: response,
    }
}

/// `accounts:resetPassword`: verifies a `PASSWORD_RESET` code (`verifyPasswordResetCode`)
/// and, with `newPassword`, consumes it and sets the password (`confirmPasswordReset`).
fn reset_password(store: &mut AuthStore, body: &Value, at: LogicalInstant) -> JsonResponse {
    let Some(code) = str_field(body, "oobCode") else {
        return error(400, "MISSING_OOB_CODE");
    };
    let Some(entry) = store.oob_code(code).cloned() else {
        return error(400, "INVALID_OOB_CODE");
    };
    if entry.request_type != OobRequestType::PasswordReset {
        return error(400, "INVALID_OOB_CODE");
    }
    let Some(uid) = entry.uid.clone() else {
        return error(400, "INVALID_OOB_CODE");
    };
    let Some(new_password) = str_field(body, "newPassword") else {
        return JsonResponse {
            status: 200,
            body: json!({"kind": "identitytoolkit#ResetPasswordResponse", "email": entry.email, "requestType": "PASSWORD_RESET"}),
        };
    };
    if let Err(e) = AuthStore::validate_password(new_password) {
        return auth_error(&e);
    }
    if store.user(&uid).is_none_or(|u| u.disabled) {
        return error(400, "USER_DISABLED");
    }
    if let Err(e) = store.consume_oob_code(code, Some(OobRequestType::PasswordReset)) {
        return auth_error(&e);
    }
    if let Err(e) = store.set_password(&uid, new_password) {
        return auth_error(&e);
    }
    // A reset ends every existing session and verifies the address (the user read the mail).
    let _ = store.revoke_tokens(&uid, at);
    store.revoke_refresh_tokens(&uid);
    if let Some(u) = store.user_mut(&uid) {
        u.email_verified = true;
    }
    JsonResponse {
        status: 200,
        body: json!({"kind": "identitytoolkit#ResetPasswordResponse", "email": entry.email, "requestType": "PASSWORD_RESET"}),
    }
}

/// `accounts:update` with an `oobCode` (`applyActionCode`): `VERIFY_EMAIL` marks the
/// address verified, `VERIFY_AND_CHANGE_EMAIL` switches to the new address.
fn apply_oob_code(store: &mut AuthStore, code: &str) -> JsonResponse {
    let Some(entry) = store.oob_code(code).cloned() else {
        return error(400, "INVALID_OOB_CODE");
    };
    let Some(uid) = entry.uid.clone() else {
        return error(400, "INVALID_OOB_CODE");
    };
    match entry.request_type {
        OobRequestType::VerifyEmail => {
            if let Err(e) = store.consume_oob_code(code, None) {
                return auth_error(&e);
            }
            if let Some(u) = store.user_mut(&uid) {
                u.email_verified = true;
            }
        }
        OobRequestType::VerifyAndChangeEmail => {
            let Some(new_email) = entry.new_email.clone() else {
                return error(400, "INVALID_OOB_CODE");
            };
            if let Err(e) = store.set_email(&uid, &new_email) {
                return auth_error(&e);
            }
            if let Err(e) = store.consume_oob_code(code, None) {
                return auth_error(&e);
            }
            if let Some(u) = store.user_mut(&uid) {
                u.email_verified = true;
            }
        }
        OobRequestType::PasswordReset | OobRequestType::EmailSignIn => {
            return error(400, "INVALID_OOB_CODE");
        }
    }
    let email = store.user(&uid).and_then(|u| u.email.clone());
    JsonResponse {
        status: 200,
        body: json!({"kind": "identitytoolkit#SetAccountInfoResponse", "localId": uid.as_str(), "email": email, "emailVerified": true}),
    }
}

/// `accounts:signInWithEmailLink`: an `EMAIL_SIGNIN` code for `email`.
fn sign_in_with_email_link(
    store: &mut AuthStore,
    body: &Value,
    at: LogicalInstant,
) -> JsonResponse {
    let (Some(email), Some(code)) = (str_field(body, "email"), str_field(body, "oobCode")) else {
        return error(400, "MISSING_OOB_CODE");
    };
    let matches = store
        .oob_code(code)
        .is_some_and(|c| c.request_type == OobRequestType::EmailSignIn && c.email == email);
    if !matches {
        return error(400, "INVALID_OOB_CODE");
    }
    if let Err(e) = store.consume_oob_code(code, Some(OobRequestType::EmailSignIn)) {
        return auth_error(&e);
    }
    // With a session: link the (now verified) email to that user instead.
    if str_field(body, "idToken").is_some() {
        let uid = match verify(store, body, at) {
            Ok(uid) => uid,
            Err(r) => return r,
        };
        if store
            .user_by_email(email)
            .is_some_and(|u| u.local_id != uid)
        {
            return error(400, "EMAIL_EXISTS");
        }
        if let Err(e) = store.set_email(&uid, email) {
            return auth_error(&e);
        }
        if let Some(u) = store.user_mut(&uid) {
            u.email_verified = true;
        }
        return match issue_tokens(store, &uid, None, at) {
            Ok(mut tokens) => {
                tokens["isNewUser"] = json!(false);
                JsonResponse {
                    status: 200,
                    body: tokens,
                }
            }
            Err(r) => r,
        };
    }
    let (uid, is_new) = match store.sign_in_with_email_link(email, at) {
        Ok(r) => r,
        Err(e) => return auth_error(&e),
    };
    match issue_tokens_with(
        store,
        &uid,
        None,
        at,
        None,
        Some(ftd_core_auth::store::Provider::EmailLink),
    ) {
        Ok(mut tokens) => {
            tokens["kind"] = json!("identitytoolkit#EmailLinkSigninResponse");
            tokens["isNewUser"] = json!(is_new);
            JsonResponse {
                status: 200,
                body: tokens,
            }
        }
        Err(r) => r,
    }
}

// ---- phone sign-in ----------------------------------------------------------------------

/// `accounts:sendVerificationCode`: no SMS is sent; the code is kept for
/// `/emulator/v1/projects/{p}/verificationCodes` (reCAPTCHA tokens are not checked).
fn send_verification_code(store: &mut AuthStore, body: &Value, at: LogicalInstant) -> JsonResponse {
    let Some(phone) = str_field(body, "phoneNumber") else {
        return error(400, "MISSING_PHONE_NUMBER");
    };
    match store.send_verification_code(phone, VerificationPurpose::SignIn, at) {
        Ok(code) => JsonResponse {
            status: 200,
            body: json!({"sessionInfo": code.session_info}),
        },
        Err(e) => auth_error(&e),
    }
}

/// `accounts:signInWithPhoneNumber`: `sessionInfo` + `code`; with an `idToken` the number
/// is linked to that user instead of signing in.
fn sign_in_with_phone_number(
    store: &mut AuthStore,
    body: &Value,
    at: LogicalInstant,
) -> JsonResponse {
    let (Some(session), Some(code)) = (str_field(body, "sessionInfo"), str_field(body, "code"))
    else {
        return error(400, "MISSING_SESSION_INFO");
    };
    let verified = match store.verify_phone_code(session, code) {
        Ok(v) => v,
        Err(e) => return auth_error(&e),
    };
    if verified.purpose != VerificationPurpose::SignIn {
        return error(400, "INVALID_SESSION_INFO");
    }
    if str_field(body, "idToken").is_some() {
        let uid = match verify(store, body, at) {
            Ok(uid) => uid,
            Err(r) => return r,
        };
        if store
            .user_by_phone(&verified.phone_number)
            .is_some_and(|u| u.local_id != uid)
        {
            return error(400, "PHONE_NUMBER_EXISTS");
        }
        if let Err(e) = store.set_phone_number(&uid, Some(&verified.phone_number)) {
            return auth_error(&e);
        }
        return match issue_tokens(store, &uid, None, at) {
            Ok(mut tokens) => {
                tokens["phoneNumber"] = json!(verified.phone_number);
                tokens["isNewUser"] = json!(false);
                JsonResponse {
                    status: 200,
                    body: tokens,
                }
            }
            Err(r) => r,
        };
    }
    let (uid, is_new) = match store.sign_in_with_phone(&verified.phone_number, at) {
        Ok(r) => r,
        Err(e) => return auth_error(&e),
    };
    match issue_tokens_with(
        store,
        &uid,
        None,
        at,
        None,
        Some(ftd_core_auth::store::Provider::Phone),
    ) {
        Ok(mut tokens) => {
            tokens["phoneNumber"] = json!(verified.phone_number);
            tokens["isNewUser"] = json!(is_new);
            JsonResponse {
                status: 200,
                body: tokens,
            }
        }
        Err(r) => r,
    }
}

// ---- federated sign-in (fixture identity providers) --------------------------------------

/// The identity carried by a provider token. The token is not verified against any
/// provider: like the Emulator, a JWT's payload or a bare JSON object with `sub` is
/// trusted as the provider's assertion.
fn parse_idp_token(token: &str) -> Option<Value> {
    let payload = if token.trim_start().starts_with('{') {
        token.to_owned()
    } else {
        let middle = token.split('.').nth(1)?;
        let bytes = ftd_core_auth::jwt::base64url_decode(middle).ok()?;
        String::from_utf8(bytes).ok()?
    };
    serde_json::from_str(&payload).ok()
}

/// `accounts:signInWithIdp`: `postBody` carries `id_token=...&providerId=google.com`
/// (an `access_token` alone is not an identity); with an `idToken` the identity is linked
/// to that user.
fn sign_in_with_idp(store: &mut AuthStore, body: &Value, at: LogicalInstant) -> JsonResponse {
    let Some(post_body) = str_field(body, "postBody") else {
        return error(400, "MISSING_POST_BODY");
    };
    let params = query_params(Some(post_body));
    let Some(provider_id) = params.get("providerId").filter(|p| !p.is_empty()) else {
        return error(400, "INVALID_IDP_RESPONSE : providerId is required");
    };
    let Some(token) = params.get("id_token") else {
        return error(
            400,
            "INVALID_IDP_RESPONSE : id_token is required (access_token flows are not modelled)",
        );
    };
    let Some(payload) = parse_idp_token(token) else {
        return error(
            400,
            "INVALID_IDP_RESPONSE : id_token is neither a JWT nor JSON",
        );
    };
    let Some(sub) = str_field(&payload, "sub").filter(|s| !s.is_empty()) else {
        return error(400, "INVALID_IDP_RESPONSE : id_token has no sub");
    };
    let identity = FederatedIdentity {
        provider_id: provider_id.clone(),
        raw_id: sub.to_owned(),
        email: str_field(&payload, "email").map(str::to_owned),
        display_name: str_field(&payload, "name").map(str::to_owned),
        photo_url: str_field(&payload, "picture").map(str::to_owned),
    };
    let (uid, is_new) = if str_field(body, "idToken").is_some() {
        let uid = match verify(store, body, at) {
            Ok(uid) => uid,
            Err(r) => return r,
        };
        if let Err(e) = store.link_federated(&uid, identity.clone()) {
            return auth_error(&e);
        }
        (uid, false)
    } else {
        match store.sign_in_with_idp(identity.clone(), at) {
            Ok(r) => r,
            Err(e) => return auth_error(&e),
        }
    };
    match issue_tokens_with(
        store,
        &uid,
        None,
        at,
        None,
        Some(ftd_core_auth::store::Provider::Federated(
            provider_id.clone(),
        )),
    ) {
        Ok(mut tokens) => {
            let verified = store.user(&uid).is_some_and(|u| u.email_verified);
            tokens["kind"] = json!("identitytoolkit#VerifyAssertionResponse");
            tokens["providerId"] = json!(provider_id);
            tokens["federatedId"] = json!(sub);
            tokens["rawId"] = json!(sub);
            tokens["oauthIdToken"] = json!(token);
            tokens["isNewUser"] = json!(is_new);
            tokens["emailVerified"] = json!(verified);
            tokens["displayName"] = json!(identity.display_name);
            tokens["fullName"] = json!(identity.display_name);
            tokens["photoUrl"] = json!(identity.photo_url);
            tokens["rawUserInfo"] = json!(payload.to_string());
            JsonResponse {
                status: 200,
                body: tokens,
            }
        }
        Err(r) => r,
    }
}

/// `accounts:createAuthUri` (`fetchSignInMethodsForEmail`): whether the email is
/// registered and how it can sign in.
fn create_auth_uri(store: &AuthStore, body: &Value) -> JsonResponse {
    let Some(email) = str_field(body, "identifier") else {
        return error(400, "MISSING_IDENTIFIER");
    };
    if !email.contains('@') {
        return error(400, "INVALID_IDENTIFIER");
    }
    let mut methods: Vec<String> = Vec::new();
    let registered = match store.user_by_email(email) {
        Some(u) => {
            if store.has_password(&u.local_id) {
                methods.push("password".to_owned());
            } else if u.provider == ftd_core_auth::store::Provider::EmailLink {
                methods.push("emailLink".to_owned());
            }
            methods.extend(u.federated.iter().map(|f| f.provider_id.clone()));
            true
        }
        None => false,
    };
    JsonResponse {
        status: 200,
        body: json!({
            "kind": "identitytoolkit#CreateAuthUriResponse",
            "registered": registered,
            "signinMethods": methods,
            "allProviders": methods,
            "sessionId": "ftd-session",
        }),
    }
}

// ---- phone second factor --------------------------------------------------------------------

fn finalize_phone_enrollment(
    store: &mut AuthStore,
    uid: &LocalId,
    phone: &Value,
    body: &Value,
    at: LogicalInstant,
) -> JsonResponse {
    let (Some(session), Some(code)) = (str_field(phone, "sessionInfo"), str_field(phone, "code"))
    else {
        return error(400, "INVALID_CODE : missing sessionInfo or code");
    };
    let verified = match store.verify_phone_code(session, code) {
        Ok(v) => v,
        Err(e) => return auth_error(&e),
    };
    if verified.purpose != (VerificationPurpose::Enrollment { uid: uid.clone() }) {
        return error(400, "INVALID_SESSION_INFO");
    }
    let display_name = str_field(body, "displayName").map(str::to_owned);
    match store.enroll_phone_factor(uid, &verified.phone_number, display_name, at) {
        Ok(factor) => {
            let assertion = SecondFactorAssertion {
                sign_in_second_factor: "phone".to_owned(),
                second_factor_identifier: factor.mfa_enrollment_id.clone(),
                verified_at: at,
            };
            match issue_tokens(store, uid, Some(&assertion), at) {
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

/// `mfaEnrollment:withdraw`: removes a factor of any kind.
fn mfa_enrollment_withdraw(
    store: &mut AuthStore,
    body: &Value,
    at: LogicalInstant,
) -> JsonResponse {
    let uid = match verify(store, body, at) {
        Ok(uid) => uid,
        Err(r) => return r,
    };
    let Some(id) = str_field(body, "mfaEnrollmentId") else {
        return error(400, "MISSING_MFA_ENROLLMENT_ID");
    };
    match store.unenroll_factor(&uid, id) {
        Ok(true) => match issue_tokens(store, &uid, None, at) {
            Ok(tokens) => JsonResponse {
                status: 200,
                body: tokens,
            },
            Err(r) => r,
        },
        Ok(false) => error(400, "MFA_ENROLLMENT_NOT_FOUND"),
        Err(e) => mfa_error(&e),
    }
}

/// `mfaSignIn:start`: sends the code of the chosen phone factor (TOTP has no start step).
fn mfa_sign_in_start(store: &mut AuthStore, body: &Value, at: LogicalInstant) -> JsonResponse {
    let Some(pending) = str_field(body, "mfaPendingCredential") else {
        return error(400, "MISSING_MFA_PENDING_CREDENTIAL");
    };
    let Some(pending_id) = PendingSignInId::parse(pending) else {
        return error(400, "INVALID_MFA_PENDING_CREDENTIAL");
    };
    let Some(uid) = store.pending_sign_in_user(&pending_id) else {
        return error(400, "INVALID_MFA_PENDING_CREDENTIAL");
    };
    if body.get("phoneSignInInfo").is_none() {
        return error(
            400,
            "INVALID_ARGUMENT : TOTP sign-in has no start step; call mfaSignIn:finalize",
        );
    }
    let Some(enrollment_id) = str_field(body, "mfaEnrollmentId") else {
        return error(400, "MISSING_MFA_ENROLLMENT_ID");
    };
    let Some(phone) = store.user(&uid).and_then(|u| {
        u.mfa
            .phone_factors()
            .iter()
            .find(|f| f.mfa_enrollment_id == enrollment_id)
            .map(|f| f.phone_number.clone())
    }) else {
        return error(400, "MFA_ENROLLMENT_NOT_FOUND");
    };
    match store.send_verification_code(
        &phone,
        VerificationPurpose::MfaSignIn {
            uid,
            pending: pending_id,
            enrollment_id: enrollment_id.to_owned(),
        },
        at,
    ) {
        Ok(code) => JsonResponse {
            status: 200,
            body: json!({"phoneResponseInfo": {"sessionInfo": code.session_info}}),
        },
        Err(e) => auth_error(&e),
    }
}

fn finalize_phone_sign_in(
    store: &mut AuthStore,
    pending: &str,
    phone: &Value,
    at: LogicalInstant,
) -> JsonResponse {
    let (Some(session), Some(code)) = (str_field(phone, "sessionInfo"), str_field(phone, "code"))
    else {
        return error(400, "INVALID_CODE : missing sessionInfo or code");
    };
    let verified = match store.verify_phone_code(session, code) {
        Ok(v) => v,
        Err(e) => return auth_error(&e),
    };
    let VerificationPurpose::MfaSignIn {
        uid,
        pending: pending_id,
        enrollment_id,
    } = verified.purpose
    else {
        return error(400, "INVALID_SESSION_INFO");
    };
    if pending_id.as_str() != pending {
        return error(400, "INVALID_MFA_PENDING_CREDENTIAL");
    }
    match store.finalize_phone_mfa_sign_in(&uid, &pending_id, &enrollment_id, at) {
        Ok(assertion) => match issue_tokens(store, &uid, Some(&assertion), at) {
            Ok(body) => JsonResponse { status: 200, body },
            Err(r) => r,
        },
        Err(e) => mfa_error(&e),
    }
}

// ---- emulator inspection routes -----------------------------------------------------------

/// `/emulator/v1/projects/{p}/{oobCodes | verificationCodes | accounts | config}`: what the
/// Firebase Auth Emulator exposes so tests can read codes and wipe users.
fn emulator_route(
    store: &mut AuthStore,
    method: &str,
    resource: &str,
    headers: &RequestHeaders,
) -> JsonResponse {
    match (method, resource) {
        ("GET", "oobCodes") => {
            let codes: Vec<Value> = store
                .oob_codes()
                .into_iter()
                .map(|c| {
                    json!({
                        "email": c.email,
                        "oobCode": c.code,
                        "oobLink": oob_link(headers, c.request_type, &c.code, &Value::Null),
                        "requestType": c.request_type.as_str(),
                    })
                })
                .collect();
            JsonResponse {
                status: 200,
                body: json!({"oobCodes": codes}),
            }
        }
        ("GET", "verificationCodes") => {
            let codes: Vec<Value> = store
                .verification_codes()
                .into_iter()
                .map(|c| json!({"phoneNumber": c.phone_number, "sessionInfo": c.session_info, "code": c.code}))
                .collect();
            JsonResponse {
                status: 200,
                body: json!({"verificationCodes": codes}),
            }
        }
        ("DELETE", "accounts") => {
            store.clear();
            JsonResponse {
                status: 200,
                body: json!({}),
            }
        }
        ("GET", "config") => JsonResponse {
            status: 200,
            body: json!({"signIn": {"allowDuplicateEmails": false}, "emailPrivacyConfig": {"enableImprovedEmailPrivacy": false}}),
        },
        (_, "oobCodes" | "verificationCodes" | "accounts" | "config") => {
            error(405, "METHOD_NOT_ALLOWED")
        }
        _ => error(404, "NOT_FOUND"),
    }
}
