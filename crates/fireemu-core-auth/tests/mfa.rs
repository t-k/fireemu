//! TOTP enrollment and sign-in state machine on the virtual clock (INV-AUTH-001..003).

use fireemu_core_auth::claims::{ClaimValue, CustomClaims, CustomClaimsError};
use fireemu_core_auth::mfa::{
    MfaError, PendingSignInContext, PendingSignInCredentials, TotpFactor, TotpPolicy, TotpSecret,
};
use fireemu_core_auth::store::{AuthStore, NewUser, SecondFactorAssertion};
use fireemu_core_auth::totp::totp_at;
use fireemu_core_types::determinism::SplitMix64;
use fireemu_core_types::time::{LogicalDuration, LogicalInstant};

fn store() -> AuthStore {
    AuthStore::new("demo-app", SplitMix64::new(7), TotpPolicy::default())
}

fn t0() -> LogicalInstant {
    LogicalInstant::from_unix_seconds(1_788_004_860)
}

fn secs(n: i64) -> LogicalDuration {
    LogicalDuration::from_seconds(n)
}

#[test]
fn enrollment_then_sign_in_with_a_valid_code() {
    let mut s = store();
    let uid = s
        .create_user(NewUser::email("alice@example.com"), t0())
        .unwrap();
    let material = s.start_totp_enrollment(&uid, t0()).unwrap();
    assert!(material
        .otpauth_uri
        .starts_with("otpauth://totp/demo-app:alice@example.com?secret="));
    assert!(material
        .otpauth_uri
        .contains("&issuer=demo-app&algorithm=SHA1&digits=6&period=30"));
    let secret = material.secret_for_test().to_vec();
    let code = totp_at(&secret, &s.policy().params(), t0());
    let factor = s
        .finalize_totp_enrollment(&uid, &material.session_id, code, t0())
        .unwrap();
    assert_eq!(factor.display_name, None);
    let user = s.user(&uid).unwrap();
    assert_eq!(user.mfa.totp_factors().len(), 1);

    // Sign in: password step then second factor at a later step.
    let later = t0().checked_add(secs(90)).unwrap();
    let pending = s.start_mfa_sign_in(&uid, later).unwrap();
    let code = totp_at(&secret, &s.policy().params(), later);
    let assertion: SecondFactorAssertion =
        s.finalize_mfa_sign_in(&uid, &pending, code, later).unwrap();
    assert_eq!(assertion.sign_in_second_factor, "totp");
    assert_eq!(assertion.second_factor_identifier, factor.mfa_enrollment_id);
}

#[test]
fn totp_finalize_keeps_pending_sign_in_after_a_wrong_code() {
    let mut s = store();
    let uid = s
        .create_user(NewUser::email("retry@example.com"), t0())
        .unwrap();
    let material = s.start_totp_enrollment(&uid, t0()).unwrap();
    let secret = material.secret_for_test().to_vec();
    s.finalize_totp_enrollment(
        &uid,
        &material.session_id,
        totp_at(&secret, &s.policy().params(), t0()),
        t0(),
    )
    .unwrap();
    let now = t0().checked_add(secs(90)).unwrap();
    let pending = s.start_mfa_sign_in(&uid, now).unwrap();
    let enrollment_id = s.user(&uid).unwrap().mfa.totp_factors()[0]
        .mfa_enrollment_id
        .clone();
    let wrong = (totp_at(&secret, &s.policy().params(), now) + 1) % 1_000_000;
    let last_accepted_before = s.user(&uid).unwrap().mfa.totp_factors()[0].last_accepted_step;

    assert_eq!(
        s.finalize_mfa_sign_in_for_factor(&uid, &pending, &enrollment_id, wrong, now),
        Err(MfaError::InvalidCode)
    );
    assert_eq!(s.pending_sign_in_user(&pending), Some(uid.clone()));
    assert_eq!(
        s.user(&uid).unwrap().mfa.totp_factors()[0].last_accepted_step,
        last_accepted_before
    );

    let assertion = s
        .finalize_mfa_sign_in_for_factor(
            &uid,
            &pending,
            &enrollment_id,
            totp_at(&secret, &s.policy().params(), now),
            now,
        )
        .unwrap();
    assert_eq!(assertion.second_factor_identifier, enrollment_id);
    assert!(s.pending_sign_in_user(&pending).is_none());
}

#[test]
fn totp_finalize_verifies_only_the_selected_enrollment() {
    let mut s = store();
    let uid = s
        .create_user(NewUser::email("selected@example.com"), t0())
        .unwrap();
    let first_secret = vec![
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
    ];
    let second_secret = vec![
        21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
    ];
    s.user_mut(&uid)
        .unwrap()
        .mfa
        .import_factors(
            vec![
                TotpFactor {
                    mfa_enrollment_id: "factor-one".to_owned(),
                    display_name: None,
                    secret: TotpSecret::new(first_secret.clone()),
                    enrolled_at: t0(),
                    last_accepted_step: None,
                },
                TotpFactor {
                    mfa_enrollment_id: "factor-two".to_owned(),
                    display_name: None,
                    secret: TotpSecret::new(second_secret.clone()),
                    enrolled_at: t0(),
                    last_accepted_step: None,
                },
            ],
            vec![],
        )
        .unwrap();
    let pending = s.start_mfa_sign_in(&uid, t0()).unwrap();
    let assertion = s
        .finalize_mfa_sign_in_for_factor(
            &uid,
            &pending,
            "factor-two",
            totp_at(&second_secret, &s.policy().params(), t0()),
            t0(),
        )
        .unwrap();

    assert_eq!(assertion.second_factor_identifier, "factor-two");
    let factors = s.user(&uid).unwrap().mfa.totp_factors();
    assert_eq!(factors[0].last_accepted_step, None);
    assert!(factors[1].last_accepted_step.is_some());

    let legacy_pending = s.start_mfa_sign_in(&uid, t0()).unwrap();
    let legacy = s
        .finalize_mfa_sign_in(
            &uid,
            &legacy_pending,
            totp_at(&first_secret, &s.policy().params(), t0()),
            t0(),
        )
        .unwrap();
    assert_eq!(legacy.second_factor_identifier, "factor-one");
}

#[test]
fn pending_sign_in_provenance_is_redacted_and_consumed_with_the_credential() {
    let mut s = store();
    let uid = s
        .create_user(NewUser::email("claims@example.com"), t0())
        .unwrap();
    let material = s.start_totp_enrollment(&uid, t0()).unwrap();
    let secret = material.secret_for_test().to_vec();
    let code = totp_at(&secret, &s.policy().params(), t0());
    s.finalize_totp_enrollment(&uid, &material.session_id, code, t0())
        .unwrap();
    let retained_before_pending = s.retained_user_bytes();
    let attributes = ClaimValue::Map(std::collections::BTreeMap::from([(
        "private-marker".to_owned(),
        ClaimValue::String("must-not-appear-in-debug".to_owned()),
    )]));
    let context = PendingSignInContext::new(
        Some("oidc.corp".to_owned()),
        false,
        Some(attributes.clone()),
    );
    let later = t0().checked_add(secs(90)).unwrap();
    let pending = s
        .start_mfa_sign_in_with_context(&uid, later, context)
        .unwrap();
    let stored = s.pending_sign_in_context(&pending).unwrap();
    assert_eq!(stored.sign_in_provider(), Some("oidc.corp"));
    assert_eq!(stored.sign_in_attributes(), Some(&attributes));
    let debug = format!("{stored:?}");
    assert!(debug.contains("[redacted]"));
    assert!(!debug.contains("must-not-appear-in-debug"));
    assert!(
        s.retained_user_bytes()
            >= retained_before_pending + "must-not-appear-in-debug".len() as u64,
        "the snapshot budget must include retained first-factor attributes"
    );

    let code = totp_at(&secret, &s.policy().params(), later);
    s.finalize_mfa_sign_in(&uid, &pending, code, later).unwrap();
    assert!(s.pending_sign_in_context(&pending).is_none());
    assert!(s.retained_user_bytes() < retained_before_pending + 64);
}

#[test]
fn pending_sign_in_credentials_are_redacted_and_counted() {
    let mut s = store();
    let uid = s
        .create_user(NewUser::email("credentials@example.com"), t0())
        .unwrap();
    let material = s.start_totp_enrollment(&uid, t0()).unwrap();
    let secret = material.secret_for_test().to_vec();
    let code = totp_at(&secret, &s.policy().params(), t0());
    s.finalize_totp_enrollment(&uid, &material.session_id, code, t0())
        .unwrap();
    let credentials = PendingSignInCredentials::new(
        Some("access-sentinel".to_owned()),
        Some("id-sentinel".to_owned()),
        Some("refresh-sentinel".to_owned()),
    );
    let context = PendingSignInContext::new_with_credentials(
        Some("oidc.corp".to_owned()),
        false,
        None,
        Some(credentials.clone()),
    );
    let pending = s
        .start_mfa_sign_in_with_context(&uid, t0(), context)
        .unwrap();
    let stored = s.pending_sign_in_context(&pending).unwrap();
    assert_eq!(stored.inbound_credentials(), Some(&credentials));
    let debug = format!("{stored:?}");
    assert!(debug.contains("[redacted]"));
    assert!(!debug.contains("access-sentinel"));
    assert!(!debug.contains("id-sentinel"));
    assert!(!debug.contains("refresh-sentinel"));
    assert!(s.retained_user_bytes() >= "access-sentinel".len() as u64);
}

#[test]
fn window_accepts_adjacent_steps_and_rejects_beyond() {
    let mut s = store();
    let uid = s
        .create_user(NewUser::email("a@example.com"), t0())
        .unwrap();
    let m = s.start_totp_enrollment(&uid, t0()).unwrap();
    let secret = m.secret_for_test().to_vec();
    let params = s.policy().params();
    s.finalize_totp_enrollment(&uid, &m.session_id, totp_at(&secret, &params, t0()), t0())
        .unwrap();

    // Codes for steps -1 and +1 relative to `now` are accepted (window_steps = 1); -2 / +2 are not.
    for (offset, ok) in [
        (-60, false),
        (-30, true),
        (0, true),
        (30, true),
        (60, false),
    ] {
        let now = t0().checked_add(secs(600)).unwrap();
        let code_time = now.checked_add(secs(offset)).unwrap();
        let code = totp_at(&secret, &params, code_time);
        let pending = s.start_mfa_sign_in(&uid, now).unwrap();
        let result = s.finalize_mfa_sign_in(&uid, &pending, code, now);
        assert_eq!(result.is_ok(), ok, "offset {offset}");
        // Advance beyond the window so that accepted counters do not collide between iterations.
        s.user_mut(&uid).unwrap().mfa.reset_replay_state_for_test();
    }
}

#[test]
fn a_code_is_never_accepted_twice() {
    // INV-AUTH-001 / M-AUTH-002
    let mut s = store();
    let uid = s
        .create_user(NewUser::email("a@example.com"), t0())
        .unwrap();
    let m = s.start_totp_enrollment(&uid, t0()).unwrap();
    let secret = m.secret_for_test().to_vec();
    let params = s.policy().params();
    s.finalize_totp_enrollment(&uid, &m.session_id, totp_at(&secret, &params, t0()), t0())
        .unwrap();
    let now = t0().checked_add(secs(300)).unwrap();
    let code = totp_at(&secret, &params, now);
    let p1 = s.start_mfa_sign_in(&uid, now).unwrap();
    s.finalize_mfa_sign_in(&uid, &p1, code, now).unwrap();
    let p2 = s.start_mfa_sign_in(&uid, now).unwrap();
    assert_eq!(
        s.finalize_mfa_sign_in(&uid, &p2, code, now),
        Err(MfaError::CodeAlreadyUsed)
    );
    // Even a code from an earlier step than the last accepted one is refused.
    let earlier = totp_at(&secret, &params, now.checked_add(secs(-30)).unwrap());
    let p3 = s.start_mfa_sign_in(&uid, now).unwrap();
    assert_eq!(
        s.finalize_mfa_sign_in(&uid, &p3, earlier, now),
        Err(MfaError::CodeAlreadyUsed)
    );
    // The next step is fine.
    let next_time = now.checked_add(secs(30)).unwrap();
    let p4 = s.start_mfa_sign_in(&uid, next_time).unwrap();
    assert!(s
        .finalize_mfa_sign_in(&uid, &p4, totp_at(&secret, &params, next_time), next_time)
        .is_ok());
}

#[test]
fn wrong_code_and_expired_enrollment_session() {
    let mut s = store();
    let uid = s
        .create_user(NewUser::email("a@example.com"), t0())
        .unwrap();
    let m = s.start_totp_enrollment(&uid, t0()).unwrap();
    let secret = m.secret_for_test().to_vec();
    let params = s.policy().params();
    let right = totp_at(&secret, &params, t0());
    let wrong = (right + 1) % 1_000_000;
    assert_eq!(
        s.finalize_totp_enrollment(&uid, &m.session_id, wrong, t0()),
        Err(MfaError::InvalidCode)
    );
    // Session TTL is 300 s: at exactly 300 s it is still valid, at 301 s it has expired.
    let at_ttl = t0().checked_add(secs(300)).unwrap();
    let m2 = s.start_totp_enrollment(&uid, t0()).unwrap();
    let secret2 = m2.secret_for_test().to_vec();
    assert!(s
        .finalize_totp_enrollment(
            &uid,
            &m2.session_id,
            totp_at(&secret2, &params, at_ttl),
            at_ttl
        )
        .is_ok());
    let uid2 = s
        .create_user(NewUser::email("b@example.com"), t0())
        .unwrap();
    let m3 = s.start_totp_enrollment(&uid2, t0()).unwrap();
    let secret3 = m3.secret_for_test().to_vec();
    let past = t0().checked_add(secs(301)).unwrap();
    assert_eq!(
        s.finalize_totp_enrollment(
            &uid2,
            &m3.session_id,
            totp_at(&secret3, &params, past),
            past
        ),
        Err(MfaError::EnrollmentSessionExpired)
    );
}

#[test]
fn only_one_totp_factor_per_user() {
    let mut s = store();
    let uid = s
        .create_user(NewUser::email("a@example.com"), t0())
        .unwrap();
    let m = s.start_totp_enrollment(&uid, t0()).unwrap();
    let secret = m.secret_for_test().to_vec();
    s.finalize_totp_enrollment(
        &uid,
        &m.session_id,
        totp_at(&secret, &s.policy().params(), t0()),
        t0(),
    )
    .unwrap();
    assert!(
        matches!(s.start_totp_enrollment(&uid, t0()), Err(MfaError::LimitExceeded(v)) if v.limit_id == "AUTH-LIMIT-TOTP-FACTORS-PER-USER")
    );
}

#[test]
fn second_factor_requires_an_enrolled_factor() {
    // INV-AUTH-002 / M-AUTH-003
    let mut s = store();
    let uid = s
        .create_user(NewUser::email("a@example.com"), t0())
        .unwrap();
    assert_eq!(
        s.start_mfa_sign_in(&uid, t0()).unwrap_err(),
        MfaError::NoEnrolledFactor
    );
    let claims = s.id_token_claims(&uid, None, t0()).unwrap();
    assert!(claims.firebase.sign_in_second_factor.is_none());
}

#[test]
fn secrets_are_redacted_in_debug_output() {
    // INV-AUTH-003 / M-AUTH-004
    let mut s = store();
    let uid = s
        .create_user(NewUser::email("a@example.com"), t0())
        .unwrap();
    let m = s.start_totp_enrollment(&uid, t0()).unwrap();
    let debug = format!("{m:?}");
    let base32 = fireemu_core_auth::base32::encode(m.secret_for_test());
    assert!(
        !debug.contains(&base32),
        "debug output must not leak the shared secret"
    );
    assert!(debug.contains("[redacted]"));
    let user_debug = format!("{:?}", s.user(&uid).unwrap());
    assert!(!user_debug.contains(&base32));
}

#[test]
fn id_token_claims_follow_the_documented_shape() {
    let mut s = store();
    let uid = s
        .create_user(NewUser::email("alice@example.com"), t0())
        .unwrap();
    let mut custom = CustomClaims::default();
    custom
        .insert("role", ClaimValue::String("admin".to_owned()))
        .unwrap();
    s.set_custom_claims(&uid, custom).unwrap();
    let claims = s.id_token_claims(&uid, None, t0()).unwrap();
    assert_eq!(claims.iss, "https://securetoken.google.com/demo-app");
    assert_eq!(claims.aud, "demo-app");
    assert_eq!(claims.sub, uid.as_str());
    assert_eq!(claims.exp - claims.iat, 3_600);
    assert_eq!(claims.firebase.sign_in_provider, "password");
    assert_eq!(
        claims.firebase.identities.get("email").map(Vec::len),
        Some(1)
    );
    assert_eq!(
        claims.custom.get("role"),
        Some(&ClaimValue::String("admin".to_owned()))
    );
    assert!(claims.canonical_json().contains("\"firebase\":{"));
}

#[test]
fn custom_claims_reject_reserved_names_and_enforce_the_byte_limit() {
    let mut claims = CustomClaims::default();
    assert_eq!(
        claims.insert("sub", ClaimValue::Null),
        Err(CustomClaimsError::ReservedName("sub".to_owned()))
    );
    assert_eq!(
        claims.insert("firebase", ClaimValue::Null),
        Err(CustomClaimsError::ReservedName("firebase".to_owned()))
    );
    // {"k":"<v>"} = 8 + len(v) bytes; 992 chars of value makes exactly 1,000 bytes.
    claims
        .insert("k", ClaimValue::String("x".repeat(992)))
        .unwrap();
    assert_eq!(claims.canonical_json().len(), 1_000);
    assert!(claims.check_size().is_ok());
    let mut over = CustomClaims::default();
    over.insert("k", ClaimValue::String("x".repeat(993)))
        .unwrap();
    let err = over.check_size().unwrap_err();
    assert_eq!(err.limit_id, "AUTH-LIMIT-CUSTOM-CLAIMS-BYTES");
    assert_eq!(err.current.value(), 1_001);
    // Multibyte values count UTF-8 bytes: 330 three-byte characters = 990 + 8 = 998 bytes.
    let mut jp = CustomClaims::default();
    jp.insert("k", ClaimValue::String("日".repeat(330)))
        .unwrap();
    assert!(jp.check_size().is_ok());
    let mut jp_over = CustomClaims::default();
    jp_over
        .insert("k", ClaimValue::String("日".repeat(331)))
        .unwrap();
    assert!(jp_over.check_size().is_err());
}

#[test]
fn blocking_response_claims_use_the_functions_sdk_reserved_names() {
    let mut claims = CustomClaims::default();
    claims
        .insert_blocking_response("sub", ClaimValue::String("ignored-subject".to_owned()))
        .unwrap();
    claims
        .insert_blocking_response("", ClaimValue::Bool(true))
        .unwrap();
    assert_eq!(
        claims.insert_blocking_response("firebase", ClaimValue::Null),
        Err(CustomClaimsError::ReservedName("firebase".to_owned()))
    );
}
