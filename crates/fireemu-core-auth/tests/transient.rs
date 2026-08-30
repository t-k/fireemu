//! The lifecycle of transient credentials: email action codes, phone verification codes,
//! TOTP enrollment sessions and pending second-factor sign-ins are swept by the virtual clock
//! at their boundaries, each kind has an outstanding budget that refuses without a side
//! effect, and pending sign-ins resolve through a direct ownership lookup
//! (`AUTH-TRANSIENT-01` .. `-05`). Refresh tokens are not part of it (`AUTH-TRANSIENT-06`).

use fireemu_core_auth::mfa::{MfaError, TotpPolicy, MAX_PENDING_PER_USER};
use fireemu_core_auth::store::{
    AuthError, AuthSnapshot, AuthStore, NewUser, OobRequestType, VerificationPurpose,
    MAX_OUTSTANDING_CODES, OOB_CODE_TTL_SECONDS, PENDING_SIGN_IN_TTL_SECONDS, SMS_CODE_TTL_SECONDS,
};
use fireemu_core_auth::totp::totp_at;
use fireemu_core_types::determinism::SplitMix64;
use fireemu_core_types::time::{LogicalDuration, LogicalInstant};

fn t0() -> LogicalInstant {
    LogicalInstant::from_unix_seconds(1_788_004_860)
}

fn after(seconds: i64) -> LogicalInstant {
    t0().checked_add(LogicalDuration::from_seconds(seconds))
        .unwrap()
}

fn store() -> AuthStore {
    AuthStore::new("demo-app", SplitMix64::new(3), TotpPolicy::default())
}

#[test]
fn oob_and_sms_codes_are_swept_at_their_exact_boundaries() {
    let mut s = store();
    let uid = s
        .create_user(NewUser::email("a@example.com"), t0())
        .unwrap();
    let oob = s
        .create_oob_code(
            OobRequestType::PasswordReset,
            "a@example.com",
            Some(uid),
            None,
            t0(),
        )
        .unwrap();
    let sms = s
        .send_verification_code("+15550001111", VerificationPurpose::SignIn, t0())
        .unwrap();

    // Exactly at the lifetime both are still outstanding.
    s.sweep_transient_credentials(after(SMS_CODE_TTL_SECONDS));
    assert_eq!(s.verification_codes().len(), 1);
    s.sweep_transient_credentials(after(OOB_CODE_TTL_SECONDS));
    assert_eq!(s.oob_codes().len(), 1);
    // One second past the SMS lifetime the code is gone and unredeemable; the OOB code is
    // gone one second past its own.
    s.sweep_transient_credentials(after(SMS_CODE_TTL_SECONDS + 1));
    assert!(s.verification_codes().is_empty());
    assert_eq!(
        s.check_phone_code(
            &sms.session_info,
            &sms.code,
            after(SMS_CODE_TTL_SECONDS + 1)
        ),
        Err(AuthError::InvalidSessionInfo)
    );
    s.sweep_transient_credentials(after(OOB_CODE_TTL_SECONDS + 1));
    assert!(s.oob_codes().is_empty());
    assert_eq!(
        s.consume_oob_code(&oob, None, after(OOB_CODE_TTL_SECONDS + 1)),
        Err(AuthError::InvalidOobCode)
    );
}

#[test]
fn abandoned_flows_stay_bounded_and_the_budget_refuses_atomically() {
    let mut s = store();
    let uid = s
        .create_user(NewUser::email("a@example.com"), t0())
        .unwrap();
    for i in 0..MAX_OUTSTANDING_CODES {
        s.create_oob_code(
            OobRequestType::EmailSignIn,
            &format!("u{i}@example.com"),
            None,
            None,
            t0(),
        )
        .unwrap();
    }
    assert_eq!(s.oob_codes().len(), MAX_OUTSTANDING_CODES);
    assert_eq!(
        s.create_oob_code(
            OobRequestType::PasswordReset,
            "a@example.com",
            Some(uid.clone()),
            None,
            after(1)
        ),
        Err(AuthError::TooManyOutstandingCodes)
    );
    assert_eq!(
        s.oob_codes().len(),
        MAX_OUTSTANDING_CODES,
        "a refusal creates nothing"
    );
    // Consuming one entry admits the next; expiry admits everything again.
    let first = s.oob_codes()[0].code.clone();
    s.consume_oob_code(&first, None, after(1)).unwrap();
    s.create_oob_code(
        OobRequestType::PasswordReset,
        "a@example.com",
        Some(uid.clone()),
        None,
        after(1),
    )
    .unwrap();
    s.create_oob_code(
        OobRequestType::PasswordReset,
        "a@example.com",
        Some(uid.clone()),
        None,
        after(OOB_CODE_TTL_SECONDS + 2),
    )
    .unwrap();
    assert_eq!(
        s.oob_codes().len(),
        1,
        "the sweep at creation reaped the abandoned codes"
    );

    // The same budget, separately, for phone codes.
    for i in 0..MAX_OUTSTANDING_CODES {
        s.send_verification_code(&format!("+1555{i:07}"), VerificationPurpose::SignIn, t0())
            .unwrap();
    }
    assert_eq!(
        s.send_verification_code("+15559999999", VerificationPurpose::SignIn, after(1))
            .unwrap_err(),
        AuthError::TooManyOutstandingCodes
    );
    assert_eq!(s.verification_codes().len(), MAX_OUTSTANDING_CODES);
}

#[test]
fn pending_enrollments_and_sign_ins_expire_and_the_per_user_budget_refuses() {
    let mut s = store();
    let uid = s
        .create_user(NewUser::email("a@example.com"), t0())
        .unwrap();
    let ttl = i64::try_from(s.policy().enrollment_session_ttl.as_seconds()).unwrap();
    // Pending enrollments: expired at ttl + 1 (SESSION_EXPIRED for one grace window), reaped
    // after 2 * ttl.
    let material = s.start_totp_enrollment(&uid, t0()).unwrap();
    let code = totp_at(
        material.secret_for_test(),
        &s.policy().params(),
        after(ttl + 1),
    );
    s.sweep_transient_credentials(after(ttl + 1));
    assert_eq!(
        s.finalize_totp_enrollment(&uid, &material.session_id, code, after(ttl + 1)),
        Err(MfaError::EnrollmentSessionExpired)
    );
    let material = s.start_totp_enrollment(&uid, t0()).unwrap();
    s.sweep_transient_credentials(after(2 * ttl + 1));
    assert_eq!(
        s.finalize_totp_enrollment(&uid, &material.session_id, code, after(2 * ttl + 1)),
        Err(MfaError::EnrollmentSessionUnknown),
        "reaped after the grace window"
    );
    assert_eq!(s.user(&uid).unwrap().mfa.pending_count(), 0);

    // The per-user budget counts enrollments and sign-ins together and refuses atomically.
    for _ in 0..MAX_PENDING_PER_USER {
        s.start_totp_enrollment(&uid, after(10)).unwrap();
    }
    assert_eq!(
        s.start_totp_enrollment(&uid, after(10)).unwrap_err(),
        MfaError::TooManyPending
    );
    assert_eq!(
        s.user(&uid).unwrap().mfa.pending_count(),
        MAX_PENDING_PER_USER
    );
    // Past their lifetime and grace the slots free up.
    s.start_totp_enrollment(&uid, after(10 + 2 * ttl + 1))
        .unwrap();
    assert_eq!(s.user(&uid).unwrap().mfa.pending_count(), 1);

    // Pending sign-ins: enrol a factor, start sign-ins, and let them expire.
    let material = s.start_totp_enrollment(&uid, after(1000)).unwrap();
    let secret = material.secret_for_test().to_vec();
    let code = totp_at(&secret, &s.policy().params(), after(1000));
    s.finalize_totp_enrollment(&uid, &material.session_id, code, after(1000))
        .unwrap();
    let pending = s.start_mfa_sign_in(&uid, after(1000)).unwrap();
    assert_eq!(s.pending_sign_in_user(&pending), Some(uid.clone()));
    assert_eq!(s.pending_sign_in_count(), 1);
    s.sweep_transient_credentials(after(1000 + PENDING_SIGN_IN_TTL_SECONDS));
    assert_eq!(
        s.pending_sign_in_user(&pending),
        Some(uid.clone()),
        "kept at the boundary"
    );
    s.sweep_transient_credentials(after(1000 + PENDING_SIGN_IN_TTL_SECONDS + 1));
    assert_eq!(s.pending_sign_in_user(&pending), None);
    assert_eq!(s.pending_sign_in_count(), 0);
    let late = after(1000 + PENDING_SIGN_IN_TTL_SECONDS + 1);
    assert_eq!(
        s.finalize_mfa_sign_in(
            &uid,
            &pending,
            totp_at(&secret, &s.policy().params(), late),
            late
        ),
        Err(MfaError::PendingSignInUnknown)
    );
}

#[test]
fn pending_sign_in_lookup_is_direct_and_never_crosses_users_or_projects() {
    let mut a = store();
    let mut b = AuthStore::new("demo-b", SplitMix64::new(3), TotpPolicy::default());
    let enrol = |s: &mut AuthStore, email: &str| {
        let uid = s.create_user(NewUser::email(email), t0()).unwrap();
        let material = s.start_totp_enrollment(&uid, t0()).unwrap();
        let code = totp_at(material.secret_for_test(), &s.policy().params(), t0());
        s.finalize_totp_enrollment(&uid, &material.session_id, code, t0())
            .unwrap();
        uid
    };
    let ua = enrol(&mut a, "a@example.com");
    let ua2 = enrol(&mut a, "a2@example.com");
    let ub = enrol(&mut b, "b@example.com");
    // Both stores share a seed, so their generated ids collide on purpose.
    let pa = a.start_mfa_sign_in(&ua, after(1)).unwrap();
    let pa2 = a.start_mfa_sign_in(&ua2, after(1)).unwrap();
    let pb = b.start_mfa_sign_in(&ub, after(1)).unwrap();
    assert_eq!(a.pending_sign_in_user(&pa), Some(ua.clone()));
    assert_eq!(a.pending_sign_in_user(&pa2), Some(ua2.clone()));
    assert_eq!(b.pending_sign_in_user(&pb), Some(ub));
    assert_eq!(a.pending_sign_in_count(), 2);
    // Deleting the owner removes its pending sign-in from the index.
    a.delete_user_by_id(ua.as_str()).unwrap();
    assert_eq!(a.pending_sign_in_user(&pa), None);
    assert_eq!(a.pending_sign_in_count(), 1);
    // A reset clears everything.
    a.clear();
    assert_eq!(a.pending_sign_in_user(&pa2), None);
    assert_eq!(a.pending_sign_in_count(), 0);
}

#[test]
fn a_snapshot_keeps_the_lifecycle_and_refresh_tokens_are_never_swept() {
    let mut s = store();
    let uid = s
        .create_user(NewUser::email("a@example.com"), t0())
        .unwrap();
    let refresh = s.issue_refresh_token(&uid, t0()).unwrap();
    s.send_verification_code("+15550001111", VerificationPurpose::SignIn, t0())
        .unwrap();
    let snapshot = AuthSnapshot::capture(&s);
    // Time passes; the restore brings the code back, and the next sweep reaps it by the
    // virtual clock like any other entry.
    let mut restored = store();
    snapshot.restore_into(&mut restored);
    assert_eq!(restored.verification_codes().len(), 1);
    restored.sweep_transient_credentials(after(SMS_CODE_TTL_SECONDS + 1));
    assert!(restored.verification_codes().is_empty());
    // Years later the refresh token still redeems (`AUTH-TRANSIENT-06`).
    restored.sweep_transient_credentials(after(10 * 365 * 24 * 3600));
    assert_eq!(restored.redeem_refresh_token(&refresh), Ok(uid));
}
