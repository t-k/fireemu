//! Separate lifetimes of the transient credentials one account holds, through the real
//! Identity Toolkit handler (TP-AUTH-D-02). The store-level twin is
//! `crates/fireemu-core-auth/tests/mfa_lifetimes.rs`.
//!
//! One email/password account with a verified email and an enrolled phone factor holds, at
//! the same time, an email action code (3600 s), a pending second-factor sign-in with its SMS
//! code (600 s), a bare pending second-factor sign-in (3600 s, declared local policy), a TOTP
//! enrollment session (300 s, one further lifetime of grace) and, in the same namespace, an
//! `IdP` continuation `pendingToken` (300 s). Each row crosses one lifetime alone and asserts:
//! the crossed object is refused with its typed error and nothing else moves (account
//! snapshot, population, registries); every other object still completes; a fresh object of
//! the crossed kind issued after the expiry works. Every row runs under the emulator and the
//! strict profile.
//!
//! The pending-credential lifetime of 3600 s is the declared local value, not a production
//! one: production refused a pending credential at 600 s once (GAP-AUTH-007) after surviving
//! 300 s once (GAP-AUTH-006). The virtual clock is not production time.

use std::sync::{Arc, Barrier, Mutex};

use fireemu_adapter_http::identity_toolkit::{
    handle, handle_with, AuthQueryLimits, AuthState, FakeCustomTokenExpiry, IdpContinuationPolicy,
    RequestHeaders,
};
use fireemu_core_auth::federation::PENDING_IDP_TTL_SECONDS;
use fireemu_core_auth::jwt::{base64url_encode, decode_unsigned};
use fireemu_core_auth::mfa::TotpPolicy;
use fireemu_core_auth::store::{
    AuthStore, OOB_CODE_TTL_SECONDS, PENDING_SIGN_IN_TTL_SECONDS, SMS_CODE_TTL_SECONDS,
};
use fireemu_core_auth::{base32, totp::totp_at};
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_types::determinism::SplitMix64;
use fireemu_core_types::time::{LogicalDuration, LogicalInstant};
use serde_json::{json, Value};

const V1: &str = "/identitytoolkit.googleapis.com/v1";
const V2: &str = "/identitytoolkit.googleapis.com/v2";
const EMU: &str = "/emulator/v1/projects/demo-app";
const EMAIL: &str = "lifetimes@example.com";
const PASSWORD: &str = "hunter22";
const PHONE: &str = "+15559876543";

fn t0() -> LogicalInstant {
    LogicalInstant::from_unix_seconds(1_788_004_860)
}

/// The emulator profile, or the strict profile when `strict`; both with the TOTP extension
/// and local `IdP` continuations enabled so that every object of the matrix exists.
fn state(strict: bool) -> AuthState {
    let mut s = AuthState {
        store: Arc::new(Mutex::new(AuthStore::new(
            "demo-app",
            SplitMix64::new(5),
            TotpPolicy::default(),
        ))),
        clock: Arc::new(Mutex::new(VirtualClock::new(t0()))),
        wall_clock: None,
        totp_extension_enabled: true,
        barrier: None,
        events: None,
        notices: None,
        blocking: None,
        operation_gate: Arc::new(Mutex::new(())),
        control_token: None,
        registry: None,
        allow_routed_projects: false,
        stateless_refresh_tokens: true,
        idp_continuations: IdpContinuationPolicy::LocalBounded,
        query_limits: AuthQueryLimits::EmulatorUnbounded,
        client_api_key: fireemu_adapter_http::identity_toolkit::ClientApiKeyPolicy::Optional,
        fake_custom_token_expiry: FakeCustomTokenExpiry::Ignore,
        custom_token_trust: None,
        app_check: None,
        app_check_policy: None,
        tenancy: None,
    };
    if strict {
        s.stateless_refresh_tokens = false;
        s.query_limits = AuthQueryLimits::ProductionBounded;
        s.fake_custom_token_expiry = FakeCustomTokenExpiry::Reject;
    }
    s
}

fn post(s: &AuthState, path: &str, body: &Value) -> (u16, Value) {
    let r = handle(s, "POST", path, body);
    (r.status, r.body)
}

fn get(s: &AuthState, path: &str) -> (u16, Value) {
    let r = handle(s, "GET", path, &json!({}));
    (r.status, r.body)
}

fn admin(s: &AuthState, path: &str, body: &Value) -> (u16, Value) {
    let headers = RequestHeaders {
        authorization: Some("Bearer owner".to_owned()),
        origin: None,
        content_type: Some("application/json".to_owned()),
        host: Some("127.0.0.1:9099".to_owned()),
        app_check: Vec::new(),
        peer_ip: None,
    };
    let r = handle_with(s, "POST", path, &headers, body);
    (r.status, r.body)
}

fn claims(id_token: &str) -> Value {
    serde_json::from_str(&decode_unsigned(id_token).unwrap().payload_json).unwrap()
}

fn now(s: &AuthState) -> LogicalInstant {
    s.clock.lock().unwrap().now_for_test()
}

fn advance_to(s: &AuthState, offset_seconds: i64) {
    let target = t0()
        .checked_add(LogicalDuration::from_seconds(offset_seconds))
        .unwrap();
    s.clock.lock().unwrap().advance_to(target).unwrap();
}

fn enrollment_ttl_seconds() -> i64 {
    i64::try_from(TotpPolicy::default().enrollment_session_ttl.as_seconds()).unwrap()
}

/// The account under test: email/password, verified, one phone factor. Returns its
/// `localId` and the sign-up ID token (issued before the factor, valid for 3600 s).
fn account(s: &AuthState) -> (String, String) {
    let (status, user) = post(
        s,
        &format!("{V1}/accounts:signUp"),
        &json!({"email": EMAIL, "password": PASSWORD}),
    );
    assert_eq!(status, 200, "{user}");
    let local_id = user["localId"].as_str().unwrap().to_owned();
    let (status, seeded) = admin(
        s,
        &format!("{V1}/projects/demo-app/accounts:update"),
        &json!({"localId": local_id, "emailVerified": true,
            "mfa": {"enrollments": [{"phoneInfo": PHONE}]}}),
    );
    assert_eq!(status, 200, "{seeded}");
    (local_id, user["idToken"].as_str().unwrap().to_owned())
}

/// The Admin lookup record with the two fields a successful sign-in legitimately changes
/// removed, so that rows can compare it before and after.
fn snapshot(s: &AuthState, local_id: &str) -> Value {
    let (status, lookup) = admin(
        s,
        &format!("{V1}/projects/demo-app/accounts:lookup"),
        &json!({"localId": [local_id]}),
    );
    assert_eq!(status, 200, "{lookup}");
    let mut record = lookup["users"][0].clone();
    let object = record.as_object_mut().unwrap();
    object.remove("lastLoginAt");
    object.remove("lastRefreshAt");
    record
}

/// Counts of every transient registry plus the population.
fn counts(s: &AuthState) -> (usize, usize, usize, usize, usize) {
    let store = s.store.lock().unwrap();
    (
        store.oob_codes().len(),
        store.verification_codes().len(),
        store.pending_sign_in_count(),
        store.pending_idp_count(),
        store.user_count(),
    )
}

fn pending_login(s: &AuthState) -> Value {
    let (status, response) = post(
        s,
        &format!("{V1}/accounts:signInWithPassword"),
        &json!({"email": EMAIL, "password": PASSWORD}),
    );
    assert_eq!(status, 200, "{response}");
    assert!(response.get("idToken").is_none(), "{response}");
    assert!(response["mfaPendingCredential"].is_string());
    response
}

fn phone_factor_id(pending: &Value) -> Value {
    pending["mfaInfo"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f.get("phoneInfo").is_some())
        .map(|f| f["mfaEnrollmentId"].clone())
        .unwrap()
}

fn start_phone_step(s: &AuthState, pending: &Value) -> (u16, Value) {
    post(
        s,
        &format!("{V2}/accounts/mfaSignIn:start"),
        &json!({"mfaPendingCredential": pending["mfaPendingCredential"],
            "mfaEnrollmentId": phone_factor_id(pending), "phoneSignInInfo": {}}),
    )
}

/// Starts the phone step and returns its `phoneVerificationInfo` from the inspection route.
fn start_phone_code(s: &AuthState, pending: &Value) -> Value {
    let (status, started) = start_phone_step(s, pending);
    assert_eq!(status, 200, "{started}");
    let session = started["phoneResponseInfo"]["sessionInfo"].clone();
    let (_, codes) = get(s, &format!("{EMU}/verificationCodes"));
    let code = codes["verificationCodes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["sessionInfo"] == session)
        .map(|c| c["code"].clone())
        .unwrap();
    json!({"sessionInfo": session, "code": code})
}

fn finalize_phone_step(s: &AuthState, pending: &Value, phone: &Value) -> (u16, Value) {
    post(
        s,
        &format!("{V2}/accounts/mfaSignIn:finalize"),
        &json!({"mfaPendingCredential": pending["mfaPendingCredential"], "phoneVerificationInfo": phone}),
    )
}

fn finalize_totp_step(s: &AuthState, pending: &Value, factor: &Value, code: u32) -> (u16, Value) {
    post(
        s,
        &format!("{V2}/accounts/mfaSignIn:finalize"),
        &json!({"mfaPendingCredential": pending["mfaPendingCredential"],
            "mfaEnrollmentId": factor, "totpVerificationInfo": {"verificationCode": code}}),
    )
}

/// Starts a TOTP enrollment and returns `(sessionInfo, secret)`.
fn start_totp_enrollment(s: &AuthState, id_token: &str) -> (Value, Vec<u8>) {
    let (status, started) = post(
        s,
        &format!("{V2}/accounts/mfaEnrollment:start"),
        &json!({"idToken": id_token, "totpEnrollmentInfo": {}}),
    );
    assert_eq!(status, 200, "{started}");
    let secret = base32::decode(
        started["totpSessionInfo"]["sharedSecretKey"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    (started["totpSessionInfo"]["sessionInfo"].clone(), secret)
}

fn finalize_totp_enrollment(
    s: &AuthState,
    id_token: &str,
    session: &Value,
    secret: &[u8],
) -> (u16, Value) {
    let code = totp_at(secret, &TotpPolicy::default().params(), now(s));
    post(
        s,
        &format!("{V2}/accounts/mfaEnrollment:finalize"),
        &json!({"idToken": id_token, "totpVerificationInfo": {
            "sessionInfo": session, "verificationCode": code}}),
    )
}

fn send_verify_email(s: &AuthState, id_token: &str) -> Value {
    let (status, sent) = post(
        s,
        &format!("{V1}/accounts:sendOobCode"),
        &json!({"requestType": "VERIFY_EMAIL", "idToken": id_token}),
    );
    assert_eq!(status, 200, "{sent}");
    let (_, codes) = get(s, &format!("{EMU}/oobCodes"));
    codes["oobCodes"]
        .as_array()
        .unwrap()
        .iter()
        .rfind(|c| c["requestType"] == "VERIFY_EMAIL")
        .map(|c| c["oobCode"].clone())
        .unwrap()
}

fn apply_oob_code(s: &AuthState, code: &Value) -> (u16, Value) {
    post(
        s,
        &format!("{V1}/accounts:update"),
        &json!({"oobCode": code}),
    )
}

fn idp_jwt(payload: &Value) -> String {
    format!(
        "{}.{}.",
        base64url_encode(br#"{"alg":"RS256","typ":"JWT"}"#),
        base64url_encode(payload.to_string().as_bytes())
    )
}

/// A fixture `IdP` sign-in in continuation mode; returns its `pendingToken`.
fn idp_continuation(s: &AuthState, subject: &str) -> Value {
    let (status, signed) = post(
        s,
        &format!("{V1}/accounts:signInWithIdp"),
        &json!({"requestUri": "http://localhost", "returnSecureToken": true,
            "postBody": format!("providerId=github.com&id_token={}",
                idp_jwt(&json!({"sub": subject, "email": format!("{subject}@example.test")})))}),
    );
    assert_eq!(status, 200, "{signed}");
    assert!(signed["pendingToken"].is_string(), "{signed}");
    signed["pendingToken"].clone()
}

fn resume_continuation(s: &AuthState, token: &Value) -> (u16, Value) {
    post(
        s,
        &format!("{V1}/accounts:signInWithIdp"),
        &json!({"requestUri": "http://localhost", "pendingToken": token, "returnSecureToken": true}),
    )
}

/// The objects of the matrix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Object {
    Oob,
    Sms,
    Pending,
    TotpEnrollment,
    PendingToken,
}

impl Object {
    const ALL: [Self; 5] = [
        Self::Oob,
        Self::Sms,
        Self::Pending,
        Self::TotpEnrollment,
        Self::PendingToken,
    ];

    /// Largest age (seconds) at which the object is still usable.
    fn last_valid_age(self) -> i64 {
        match self {
            Self::Oob => OOB_CODE_TTL_SECONDS,
            Self::Sms => SMS_CODE_TTL_SECONDS,
            Self::Pending => PENDING_SIGN_IN_TTL_SECONDS,
            Self::TotpEnrollment => enrollment_ttl_seconds(),
            // The continuation cache is half-open: the handle is gone at exactly its TTL.
            Self::PendingToken => PENDING_IDP_TTL_SECONDS - 1,
        }
    }
}

/// Creation offset (seconds after `t0`) of `other` in the row that crosses `crossed` at
/// `check_at`: an object that outlives the check instant is created at `t0`, every other one
/// at half its lifetime before the check, so at the check only the crossed object is expired.
fn creation_offset(crossed: Object, other: Object, check_at: i64) -> i64 {
    if other == crossed || other.last_valid_age() > check_at {
        0
    } else {
        check_at - other.last_valid_age() / 2
    }
}

#[derive(Default)]
struct Objects {
    oob: Value,
    sms_pending: Value,
    sms_code: Value,
    pending: Value,
    enrollment_session: Value,
    enrollment_secret: Vec<u8>,
    idp_token: Value,
}

fn create(s: &AuthState, id_token: &str, object: Object, into: &mut Objects) {
    match object {
        Object::Oob => into.oob = send_verify_email(s, id_token),
        Object::Sms => {
            into.sms_pending = pending_login(s);
            into.sms_code = start_phone_code(s, &into.sms_pending);
        }
        Object::Pending => into.pending = pending_login(s),
        Object::TotpEnrollment => {
            let (session, secret) = start_totp_enrollment(s, id_token);
            into.enrollment_session = session;
            into.enrollment_secret = secret;
        }
        Object::PendingToken => into.idp_token = idp_continuation(s, "continuation"),
    }
}

/// Creates the five objects in creation-time order and moves the clock to the check
/// instant; returns the objects.
fn build(s: &AuthState, id_token: &str, crossed: Object) -> Objects {
    let check_at = crossed.last_valid_age() + 1;
    let mut schedule: Vec<(i64, Object)> = Object::ALL
        .iter()
        .map(|&o| (creation_offset(crossed, o, check_at), o))
        .collect();
    schedule.sort_by_key(|(offset, _)| *offset);
    let mut objects = Objects::default();
    for (offset, object) in schedule {
        advance_to(s, offset);
        create(s, id_token, object, &mut objects);
    }
    advance_to(s, check_at);
    objects
}

fn assert_refused(response: &(u16, Value), message: &str, context: &str) {
    assert_eq!(response.0, 400, "{context}: {}", response.1);
    assert_eq!(response.1["error"]["message"], message, "{context}");
    assert!(response.1.get("idToken").is_none(), "{context}");
    assert!(response.1.get("refreshToken").is_none(), "{context}");
}

#[test]
#[allow(clippy::too_many_lines)]
fn crossing_each_lifetime_alone_leaves_the_other_objects_usable() {
    for strict in [false, true] {
        for crossed in Object::ALL {
            let context = format!("strict={strict} crossed={crossed:?}");
            let s = state(strict);
            let (local_id, id_token) = account(&s);
            let objects = build(&s, &id_token, crossed);
            // Two federated accounts exist when the continuation was created (its own).
            let before = snapshot(&s, &local_id);
            let counts_before = counts(&s);
            let population = counts_before.4;

            // The crossed object is refused with its typed error; the refusal creates and
            // consumes nothing observable on the account.
            match crossed {
                Object::Oob => {
                    assert_refused(
                        &apply_oob_code(&s, &objects.oob),
                        "INVALID_OOB_CODE",
                        &context,
                    );
                }
                Object::Sms => {
                    assert_refused(
                        &finalize_phone_step(&s, &objects.sms_pending, &objects.sms_code),
                        "INVALID_SESSION_INFO",
                        &context,
                    );
                }
                Object::Pending => {
                    assert_refused(
                        &start_phone_step(&s, &objects.pending),
                        "INVALID_MFA_PENDING_CREDENTIAL",
                        &context,
                    );
                    assert_refused(
                        &finalize_totp_step(&s, &objects.pending, &json!("any"), 0),
                        "INVALID_MFA_PENDING_CREDENTIAL",
                        &context,
                    );
                }
                Object::TotpEnrollment => {
                    assert_refused(
                        &finalize_totp_enrollment(
                            &s,
                            &id_token,
                            &objects.enrollment_session,
                            &objects.enrollment_secret,
                        ),
                        "SESSION_EXPIRED",
                        &context,
                    );
                }
                Object::PendingToken => {
                    assert_refused(
                        &resume_continuation(&s, &objects.idp_token),
                        "INVALID_PENDING_TOKEN",
                        &context,
                    );
                }
            }
            assert_eq!(
                snapshot(&s, &local_id),
                before,
                "{context}: refusal must not mutate"
            );
            assert_eq!(
                counts(&s).4,
                population,
                "{context}: refusal must not create"
            );

            // Every other object still completes at the same instant. The SMS sign-in goes
            // first: past 3600 s the sign-up token has expired, and its ID token (with the
            // phone second factor) carries the remaining requests.
            let mut fresh_token = id_token.clone();
            if crossed != Object::Sms {
                let (status, signed) =
                    finalize_phone_step(&s, &objects.sms_pending, &objects.sms_code);
                assert_eq!(status, 200, "{context}: sms should be live: {signed}");
                let c = claims(signed["idToken"].as_str().unwrap());
                assert_eq!(c["firebase"]["sign_in_second_factor"], "phone");
                assert_eq!(c["user_id"], local_id);
                fresh_token = signed["idToken"].as_str().unwrap().to_owned();
            }
            if crossed != Object::TotpEnrollment {
                let (status, enrolled) = finalize_totp_enrollment(
                    &s,
                    &fresh_token,
                    &objects.enrollment_session,
                    &objects.enrollment_secret,
                );
                assert_eq!(
                    status, 200,
                    "{context}: enrollment should be live: {enrolled}"
                );
                assert_eq!(
                    claims(enrolled["idToken"].as_str().unwrap())["firebase"]
                        ["sign_in_second_factor"],
                    "totp"
                );
            }
            if crossed != Object::Pending {
                let code = start_phone_code(&s, &objects.pending);
                let (status, signed) = finalize_phone_step(&s, &objects.pending, &code);
                assert_eq!(status, 200, "{context}: pending should be live: {signed}");
                assert_eq!(
                    claims(signed["idToken"].as_str().unwrap())["user_id"],
                    local_id
                );
            }
            if crossed != Object::PendingToken {
                let (status, resumed) = resume_continuation(&s, &objects.idp_token);
                assert_eq!(
                    status, 200,
                    "{context}: continuation should be live: {resumed}"
                );
                assert_eq!(resumed["isNewUser"], false);
                assert_eq!(resumed["pendingToken"], objects.idp_token);
            }
            if crossed != Object::Oob {
                let (status, applied) = apply_oob_code(&s, &objects.oob);
                assert_eq!(status, 200, "{context}: oob should be live: {applied}");
                assert_eq!(applied["localId"], local_id);
            }

            // Post-state: only the surviving pending credential of an expired SMS code and the
            // reusable continuation remain; the population is unchanged.
            let (oob, sms, pending, idp, users) = counts(&s);
            assert_eq!(oob, 0, "{context}");
            assert_eq!(sms, 0, "{context}");
            assert_eq!(pending, usize::from(crossed == Object::Sms), "{context}");
            assert_eq!(
                idp,
                usize::from(crossed != Object::PendingToken),
                "{context}"
            );
            assert_eq!(users, population, "{context}");
            let after = snapshot(&s, &local_id);
            let totp_factors = after["mfaInfo"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|f| f.get("totpInfo").is_some())
                .count();
            assert_eq!(
                totp_factors,
                usize::from(crossed != Object::TotpEnrollment),
                "{context}"
            );
            assert!(after["mfaInfo"]
                .as_array()
                .unwrap()
                .iter()
                .any(|f| f["phoneInfo"] == PHONE));
            for key in [
                "email",
                "emailVerified",
                "localId",
                "passwordHash",
                "createdAt",
            ] {
                assert_eq!(after[key], before[key], "{context}: {key}");
            }

            // Fresh control: a new object of the crossed kind, issued after the expiry, works.
            match crossed {
                Object::Oob => {
                    let code = send_verify_email(&s, &fresh_token);
                    assert_eq!(apply_oob_code(&s, &code).0, 200, "{context}");
                }
                Object::Sms => {
                    // The pending credential outlived its code: a fresh code completes it.
                    let code = start_phone_code(&s, &objects.sms_pending);
                    let (status, signed) = finalize_phone_step(&s, &objects.sms_pending, &code);
                    assert_eq!(status, 200, "{context}: {signed}");
                    assert_eq!(s.store.lock().unwrap().pending_sign_in_count(), 0);
                }
                Object::Pending => {
                    let pending = pending_login(&s);
                    let code = start_phone_code(&s, &pending);
                    let (status, signed) = finalize_phone_step(&s, &pending, &code);
                    assert_eq!(status, 200, "{context}: {signed}");
                    assert_eq!(s.store.lock().unwrap().pending_sign_in_count(), 0);
                }
                Object::TotpEnrollment => {
                    let (session, secret) = start_totp_enrollment(&s, &fresh_token);
                    let (status, enrolled) =
                        finalize_totp_enrollment(&s, &fresh_token, &session, &secret);
                    assert_eq!(status, 200, "{context}: {enrolled}");
                }
                Object::PendingToken => {
                    let token = idp_continuation(&s, "continuation");
                    assert_ne!(token, objects.idp_token);
                    assert_eq!(resume_continuation(&s, &token).0, 200, "{context}");
                }
            }
            assert!(s.store.lock().unwrap().verification_codes().is_empty());
        }
    }
}

#[test]
fn an_expired_totp_enrollment_is_session_expired_in_grace_and_unknown_after_it() {
    for strict in [false, true] {
        let s = state(strict);
        let (_, id_token) = account(&s);
        let ttl = enrollment_ttl_seconds();
        let (first, first_secret) = start_totp_enrollment(&s, &id_token);
        // Exactly at the lifetime the session still finalizes (INV-AUTH-007) on another
        // account's sibling test; here: one second past it, inside the grace window.
        advance_to(&s, ttl + 1);
        let refused = finalize_totp_enrollment(&s, &id_token, &first, &first_secret);
        assert_refused(&refused, "SESSION_EXPIRED", "in grace");
        // The refusal reaped it: the same session is now unknown.
        let refused = finalize_totp_enrollment(&s, &id_token, &first, &first_secret);
        assert_refused(&refused, "INVALID_SESSION_INFO", "after reap");

        // An untouched session is reaped by the sweep once the grace window has passed.
        let (second, second_secret) = start_totp_enrollment(&s, &id_token);
        advance_to(&s, ttl + 1 + 2 * ttl + 1);
        let refused = finalize_totp_enrollment(&s, &id_token, &second, &second_secret);
        assert_refused(&refused, "INVALID_SESSION_INFO", "past grace");
        assert!(s
            .store
            .lock()
            .unwrap()
            .user_by_id(claims(&id_token)["user_id"].as_str().unwrap())
            .unwrap()
            .mfa
            .totp_factors()
            .is_empty());
        // The sign-up token still has 3600 s of life: a fresh session enrolls.
        let (third, third_secret) = start_totp_enrollment(&s, &id_token);
        let (status, enrolled) = finalize_totp_enrollment(&s, &id_token, &third, &third_secret);
        assert_eq!(status, 200, "{enrolled}");
    }
}

/// Enrolls a TOTP factor on the account at `t0` and returns `(localId, factorId, secret)`.
fn totp_account(s: &AuthState) -> (String, Value, Vec<u8>) {
    let (local_id, id_token) = account(s);
    let (session, secret) = start_totp_enrollment(s, &id_token);
    let (status, enrolled) = finalize_totp_enrollment(s, &id_token, &session, &secret);
    assert_eq!(status, 200, "{enrolled}");
    let factor = claims(enrolled["idToken"].as_str().unwrap())["firebase"]
        ["second_factor_identifier"]
        .clone();
    (local_id, factor, secret)
}

#[test]
fn a_wrong_totp_code_keeps_the_pending_credential_and_the_correct_code_then_signs_in() {
    for strict in [false, true] {
        let s = state(strict);
        let (local_id, factor, secret) = totp_account(&s);
        // One step past enrollment so the enrollment step is not the sign-in step.
        advance_to(&s, 30);
        let pending = pending_login(&s);
        let before = snapshot(&s, &local_id);
        let right = totp_at(&secret, &TotpPolicy::default().params(), now(&s));
        let wrong = (right + 1) % 1_000_000;

        assert_refused(
            &finalize_totp_step(&s, &pending, &factor, wrong),
            "INVALID_CODE",
            "wrong code",
        );
        assert_eq!(s.store.lock().unwrap().pending_sign_in_count(), 1);
        assert_eq!(snapshot(&s, &local_id), before);

        // Same pending credential, correct code: accepted. The current runtime keeps the
        // session usable after a wrong attempt (no attempt counter).
        let (status, signed) = finalize_totp_step(&s, &pending, &factor, right);
        assert_eq!(status, 200, "{signed}");
        let c = claims(signed["idToken"].as_str().unwrap());
        assert_eq!(c["firebase"]["sign_in_second_factor"], "totp");
        assert_eq!(c["firebase"]["second_factor_identifier"], factor);
        assert_eq!(s.store.lock().unwrap().pending_sign_in_count(), 0);
    }
}

#[test]
fn replaying_a_consumed_step_after_success_is_refused() {
    for strict in [false, true] {
        let s = state(strict);
        let (local_id, factor, secret) = totp_account(&s);
        advance_to(&s, 30);
        let code = totp_at(&secret, &TotpPolicy::default().params(), now(&s));

        // TOTP: the consumed pending credential is unknown; a new pending credential with the
        // same code is a replay.
        let pending = pending_login(&s);
        assert_eq!(finalize_totp_step(&s, &pending, &factor, code).0, 200);
        assert_refused(
            &finalize_totp_step(&s, &pending, &factor, code),
            "INVALID_MFA_PENDING_CREDENTIAL",
            "consumed pending",
        );
        let next = pending_login(&s);
        assert_refused(
            &finalize_totp_step(&s, &next, &factor, code),
            "INVALID_CODE : verification code already used",
            "replayed step",
        );
        assert_eq!(s.store.lock().unwrap().pending_sign_in_count(), 1);

        // Phone: the consumed code is unknown, and so is the consumed pending credential.
        let sms = start_phone_code(&s, &next);
        assert_eq!(finalize_phone_step(&s, &next, &sms).0, 200);
        assert_refused(
            &finalize_phone_step(&s, &next, &sms),
            "INVALID_SESSION_INFO",
            "consumed code",
        );
        assert_refused(
            &start_phone_step(&s, &next),
            "INVALID_MFA_PENDING_CREDENTIAL",
            "consumed pending after phone",
        );
        let (oob, codes, pending, _, _) = counts(&s);
        assert_eq!((oob, codes, pending), (0, 0, 0));
        let after = snapshot(&s, &local_id);
        assert_eq!(after["mfaInfo"].as_array().unwrap().len(), 2);
    }
}

/// Two threads finalize one pending credential through the handler at the same instant:
/// exactly one wins, the loser is refused with the typed error of a consumed credential,
/// and the post-state is that of a single sign-in.
#[test]
fn two_threads_finalizing_one_pending_credential_succeed_exactly_once() {
    for strict in [false, true] {
        let s = state(strict);
        let (local_id, factor, secret) = totp_account(&s);
        advance_to(&s, 30);
        let code = totp_at(&secret, &TotpPolicy::default().params(), now(&s));

        // TOTP finalize.
        let pending = pending_login(&s);
        let start = Arc::new(Barrier::new(2));
        let results: Vec<(u16, Value)> = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..2)
                .map(|_| {
                    let start = Arc::clone(&start);
                    let (s, pending, factor) = (&s, &pending, &factor);
                    scope.spawn(move || {
                        start.wait();
                        finalize_totp_step(s, pending, factor, code)
                    })
                })
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        });
        let winners: Vec<&Value> = results
            .iter()
            .filter(|(status, _)| *status == 200)
            .map(|(_, body)| body)
            .collect();
        assert_eq!(winners.len(), 1, "{results:?}");
        let loser = results.iter().find(|(status, _)| *status != 200).unwrap();
        assert_refused(loser, "INVALID_MFA_PENDING_CREDENTIAL", "totp loser");
        assert_eq!(
            claims(winners[0]["idToken"].as_str().unwrap())["user_id"],
            local_id
        );
        assert_eq!(s.store.lock().unwrap().pending_sign_in_count(), 0);

        // Phone finalize: the loser sees the consumed code.
        let pending = pending_login(&s);
        let sms = start_phone_code(&s, &pending);
        let start = Arc::new(Barrier::new(2));
        let results: Vec<(u16, Value)> = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..2)
                .map(|_| {
                    let start = Arc::clone(&start);
                    let (s, pending, sms) = (&s, &pending, &sms);
                    scope.spawn(move || {
                        start.wait();
                        finalize_phone_step(s, pending, sms)
                    })
                })
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        });
        assert_eq!(
            results.iter().filter(|(status, _)| *status == 200).count(),
            1,
            "{results:?}"
        );
        let loser = results.iter().find(|(status, _)| *status != 200).unwrap();
        assert_refused(loser, "INVALID_SESSION_INFO", "phone loser");
        let (oob, codes, pending_count, _, users) = counts(&s);
        assert_eq!((oob, codes, pending_count, users), (0, 0, 0, 1));
        let after = snapshot(&s, &local_id);
        assert_eq!(after["mfaInfo"].as_array().unwrap().len(), 2);
    }
}
