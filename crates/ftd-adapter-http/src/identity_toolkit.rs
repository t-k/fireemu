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
    let claims = store
        .id_token_claims(uid, second, at)
        .map_err(|e| auth_error(&e))?;
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

/// Routes one request. Unknown paths return 404; every handler is JSON in / JSON out.
#[must_use]
pub fn handle(state: &AuthState, method: &str, path: &str, body: &Value) -> JsonResponse {
    if method != "POST" {
        return error(405, "METHOD_NOT_ALLOWED");
    }
    let path = path.split('?').next().unwrap_or(path);
    let at = now(state);
    let Ok(mut store) = state.store.lock() else {
        return error(500, "INTERNAL");
    };
    // Admin SDK paths are project-scoped: /identitytoolkit.googleapis.com/v1/projects/{p}/accounts...
    let admin = path
        .strip_prefix("/identitytoolkit.googleapis.com/v1/projects/")
        .and_then(|rest| rest.split_once('/'));
    if let Some((_project, action)) = admin {
        return match action {
            "accounts" => admin_create(&mut store, body, at),
            "accounts:lookup" => lookup(&store, body, at),
            "accounts:update" => update(&mut store, body, at),
            "accounts:delete" => admin_delete(&mut store, body),
            "accounts:batchGet" => admin_batch_get(&store, body),
            _ => error(404, "NOT_FOUND"),
        };
    }
    match path {
        "/identitytoolkit.googleapis.com/v1/accounts:signUp" => sign_up(&mut store, body, at),
        "/identitytoolkit.googleapis.com/v1/accounts:signInWithPassword" => {
            sign_in_with_password(&mut store, body, at)
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

fn first_of(body: &Value, key: &str) -> Option<String> {
    match body.get(key) {
        Some(Value::String(s)) => Some(s.clone()),
        Some(Value::Array(items)) => items.first().and_then(Value::as_str).map(str::to_owned),
        _ => None,
    }
}

fn lookup(store: &AuthStore, body: &Value, at: LogicalInstant) -> JsonResponse {
    let local_id = first_of(body, "localId");
    let email = first_of(body, "email");
    let uid = if let Some(local_id) = local_id.as_deref() {
        match store.user_by_id(local_id) {
            Some(u) => u.local_id.clone(),
            None => {
                return JsonResponse {
                    status: 200,
                    body: json!({"users": []}),
                }
            }
        }
    } else if let Some(email) = email.as_deref() {
        match store.user_by_email(email) {
            Some(u) => u.local_id.clone(),
            None => {
                return JsonResponse {
                    status: 200,
                    body: json!({"users": []}),
                }
            }
        }
    } else {
        match verify(store, body, at) {
            Ok(uid) => uid,
            Err(r) => return r,
        }
    };
    JsonResponse {
        status: 200,
        body: json!({"users": [user_json(store, &uid)]}),
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
fn update(store: &mut AuthStore, body: &Value, at: LogicalInstant) -> JsonResponse {
    let uid = if let Some(local_id) = str_field(body, "localId") {
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
    if let Some(attrs) = str_field(body, "customAttributes") {
        let Ok(JsonValue::Object(parsed)) = ftd_core_types::json::parse(attrs) else {
            return error(
                400,
                "INVALID_CLAIMS : customAttributes must be a JSON object",
            );
        };
        let mut claims = CustomClaims::default();
        for (k, v) in &parsed {
            let Some(cv) = claims_from_json(v) else {
                return error(400, "INVALID_CLAIMS");
            };
            if let Err(e) = claims.insert(k, cv) {
                return error(400, &format!("FORBIDDEN_CLAIM : {e}"));
            }
        }
        if let Err(e) = store.set_custom_claims(&uid, claims) {
            return auth_error(&e);
        }
    }
    if let Some(password) = str_field(body, "password") {
        if let Err(e) = store.set_password(&uid, password) {
            return auth_error(&e);
        }
    }
    if let Some(name) = str_field(body, "displayName") {
        if let Some(u) = store.user_mut(&uid) {
            u.display_name = Some(name.to_owned());
        }
    }
    if let Some(verified) = body.get("emailVerified").and_then(Value::as_bool) {
        if let Some(u) = store.user_mut(&uid) {
            u.email_verified = verified;
        }
    }
    if let Some(disable) = body.get("disableUser").and_then(Value::as_bool) {
        if let Some(u) = store.user_mut(&uid) {
            u.disabled = disable;
        }
        if disable {
            let _ = store.revoke_tokens(&uid, at);
        }
    }
    if body.get("validSince").is_some() {
        let _ = store.revoke_tokens(&uid, at);
    }
    JsonResponse {
        status: 200,
        body: json!({"localId": uid.as_str(), "kind": "identitytoolkit#SetAccountInfoResponse"}),
    }
}

/// Admin `POST /v1/projects/{p}/accounts` (createUser).
fn admin_create(store: &mut AuthStore, body: &Value, at: LogicalInstant) -> JsonResponse {
    let new_user = match str_field(body, "email") {
        Some(email) => NewUser {
            email: Some(email.to_owned()),
            email_verified: body
                .get("emailVerified")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            provider: ftd_core_auth::store::Provider::Password,
        },
        None => NewUser::anonymous(),
    };
    let requested_id = str_field(body, "localId").map(str::to_owned);
    let uid = match store.create_user_with_id(new_user, requested_id.as_deref(), at) {
        Ok(uid) => uid,
        Err(e) => return auth_error(&e),
    };
    if let Some(password) = str_field(body, "password") {
        if let Err(e) = store.set_password(&uid, password) {
            return auth_error(&e);
        }
    }
    if let Some(u) = store.user_mut(&uid) {
        u.display_name = str_field(body, "displayName").map(str::to_owned);
        u.disabled = body
            .get("disabled")
            .and_then(Value::as_bool)
            .unwrap_or(false);
    }
    JsonResponse {
        status: 200,
        body: json!({"kind": "identitytoolkit#SignupNewUserResponse", "localId": uid.as_str(), "email": str_field(body, "email")}),
    }
}

/// Admin `accounts:delete`.
fn admin_delete(store: &mut AuthStore, body: &Value) -> JsonResponse {
    let Some(local_id) = str_field(body, "localId") else {
        return error(400, "MISSING_LOCAL_ID");
    };
    match store.delete_user_by_id(local_id) {
        Ok(()) => JsonResponse {
            status: 200,
            body: json!({"kind": "identitytoolkit#DeleteAccountResponse"}),
        },
        Err(e) => auth_error(&e),
    }
}

/// Admin `accounts:batchGet` (listUsers) without pagination.
fn admin_batch_get(store: &AuthStore, body: &Value) -> JsonResponse {
    let max = body
        .get("maxResults")
        .and_then(Value::as_u64)
        .unwrap_or(1_000);
    let users: Vec<Value> = store
        .all_user_ids()
        .into_iter()
        .take(usize::try_from(max).unwrap_or(usize::MAX))
        .map(|uid| user_json(store, &uid))
        .collect();
    JsonResponse {
        status: 200,
        body: json!({"kind": "identitytoolkit#DownloadAccountResponse", "users": users}),
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
