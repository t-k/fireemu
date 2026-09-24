//! The project's `mfa` config decides the TOTP window: `adjacentIntervals` steps on either side
//! of the current one (AUTH-MFA, `auth-mfa/totp/enroll` window rows). Without it the store keeps
//! its policy's window.

use fireemu_core_auth::mfa::{MfaError, TotpPolicy};
use fireemu_core_auth::mfa_config::{MfaConfigState, MfaProjectConfig, TotpProviderConfig};
use fireemu_core_auth::store::{AuthStore, NewUser};
use fireemu_core_auth::totp::{totp_at, TotpParams};
use fireemu_core_types::determinism::SplitMix64;
use fireemu_core_types::time::{LogicalDuration, LogicalInstant};

const PARAMS: TotpParams = TotpParams {
    period_seconds: 30,
    digits: 6,
};

fn t0() -> LogicalInstant {
    // The middle of a 30-second step.
    LogicalInstant::from_unix_seconds(1_788_004_875)
}

fn steps(n: i64) -> LogicalInstant {
    t0().checked_add(LogicalDuration::from_seconds(30 * n))
        .unwrap()
}

fn enabled(adjacent_intervals: Option<u8>) -> MfaProjectConfig {
    MfaProjectConfig {
        state: MfaConfigState::Enabled,
        phone_sms: true,
        totp: Some(TotpProviderConfig {
            state: MfaConfigState::Enabled,
            adjacent_intervals,
        }),
    }
}

/// Starts an enrollment for a fresh verified account and offers the code of `offset` steps.
fn enroll_with_offset(config: Option<MfaProjectConfig>, offset: i64) -> Result<(), MfaError> {
    let mut s = AuthStore::new("demo-app", SplitMix64::new(3), TotpPolicy::default());
    if let Some(config) = config {
        s.set_mfa_config(config);
    }
    let mut user = NewUser::email("a@example.com");
    user.email_verified = true;
    let uid = s.create_user_with_id(user, Some("a"), t0()).unwrap();
    let material = s.start_totp_enrollment(&uid, t0()).unwrap();
    let code = totp_at(material.secret_for_test(), &PARAMS, steps(offset));
    s.finalize_totp_enrollment_named(&uid, &material.session_id, code, Some("A".to_owned()), t0())
        .map(|_| ())
}

#[test]
fn the_configured_window_accepts_its_edges_and_refuses_beyond_them() {
    for offset in [-5, 0, 5] {
        assert!(
            enroll_with_offset(Some(enabled(Some(5))), offset).is_ok(),
            "{offset}"
        );
    }
    for offset in [-6, 6] {
        assert_eq!(
            enroll_with_offset(Some(enabled(Some(5))), offset),
            Err(MfaError::InvalidCode),
            "{offset}"
        );
    }
}

#[test]
fn without_a_configured_window_the_policy_window_applies() {
    let policy = i64::from(TotpPolicy::default().window_steps);
    for config in [None, Some(enabled(None))] {
        assert!(enroll_with_offset(config.clone(), policy).is_ok());
        assert_eq!(
            enroll_with_offset(config, policy + 1),
            Err(MfaError::InvalidCode)
        );
    }
}

// ---- TOTP enrollment under production's rules (sandbox recording 2026-09-24) -------------------

fn production_store() -> AuthStore {
    let mut s = AuthStore::new("demo-app", SplitMix64::new(3), TotpPolicy::default());
    s.set_production_mfa(true);
    s.set_mfa_config(enabled(Some(5)));
    s
}

fn started(
    s: &mut AuthStore,
) -> (
    fireemu_core_auth::store::LocalId,
    fireemu_core_auth::mfa::TotpEnrollmentMaterial,
) {
    let mut user = NewUser::email("a@example.com");
    user.email_verified = true;
    let uid = s.create_user_with_id(user, Some("a"), t0()).unwrap();
    let material = s.start_totp_enrollment(&uid, t0()).unwrap();
    (uid, material)
}

fn seconds(n: i64) -> LogicalInstant {
    t0().checked_add(LogicalDuration::from_seconds(n)).unwrap()
}

fn code_at(material: &fireemu_core_auth::mfa::TotpEnrollmentMaterial, at: LogicalInstant) -> u32 {
    totp_at(material.secret_for_test(), &PARAMS, at)
}

/// `auth-mfa/lifetime`: a session finalized at 870 s is accepted and one at 930 s and at
/// 1800 s is `SESSION_EXPIRED` (the start answer announces 900 s).
#[test]
fn a_production_enrollment_session_lives_900_seconds_and_stays_expired() {
    let mut s = production_store();
    let (uid, material) = started(&mut s);
    assert_eq!(
        material.expires_at,
        seconds(900),
        "the default lifetime is production's"
    );
    for age in [930, 1805] {
        let mut s2 = production_store();
        let (uid2, material2) = started(&mut s2);
        s2.sweep_transient_credentials(seconds(age));
        assert_eq!(
            s2.finalize_totp_enrollment_named(
                &uid2,
                &material2.session_id,
                code_at(&material2, seconds(age)),
                Some("A".to_owned()),
                seconds(age)
            ),
            Err(MfaError::EnrollmentSessionExpired),
            "{age}"
        );
    }
    assert!(s
        .finalize_totp_enrollment_named(
            &uid,
            &material.session_id,
            code_at(&material, seconds(870)),
            Some("A".to_owned()),
            seconds(870)
        )
        .is_ok());
}

/// `auth-mfa/totp/enroll`: two wrong codes, the right one, then the session again is
/// `TOO_MANY_ENROLLMENT_ATTEMPTS`; a session used once and offered again is already complete
/// (exploration 2026-09-24). The factor keeps its display name and has a UUID.
#[test]
fn a_production_enrollment_session_counts_its_attempts_and_remembers_completion() {
    let mut s = production_store();
    let (uid, material) = started(&mut s);
    let wrong = (code_at(&material, t0()) + 1) % 1_000_000;
    for _ in 0..2 {
        assert_eq!(
            s.finalize_totp_enrollment_named(
                &uid,
                &material.session_id,
                wrong,
                Some("A".to_owned()),
                t0()
            ),
            Err(MfaError::InvalidCode)
        );
    }
    let factor = s
        .finalize_totp_enrollment_named(
            &uid,
            &material.session_id,
            code_at(&material, t0()),
            Some("Authenticator".to_owned()),
            t0(),
        )
        .unwrap();
    assert_eq!(factor.display_name.as_deref(), Some("Authenticator"));
    let id = &factor.mfa_enrollment_id;
    assert_eq!(id.len(), 36, "{id}");
    assert_eq!(&id[14..15], "4", "a version-4 UUID: {id}");
    assert_eq!(
        s.finalize_totp_enrollment_named(
            &uid,
            &material.session_id,
            code_at(&material, steps(1)),
            Some("A".to_owned()),
            t0()
        ),
        Err(MfaError::TooManyEnrollmentAttempts)
    );
    let stored = s.user_by_id("a").unwrap().mfa.totp_factors()[0]
        .display_name
        .clone();
    assert_eq!(stored.as_deref(), Some("Authenticator"));

    let mut s = production_store();
    let (uid, material) = started(&mut s);
    assert!(s
        .finalize_totp_enrollment_named(
            &uid,
            &material.session_id,
            code_at(&material, t0()),
            Some("A".to_owned()),
            t0()
        )
        .is_ok());
    assert_eq!(
        s.finalize_totp_enrollment_named(
            &uid,
            &material.session_id,
            code_at(&material, steps(1)),
            Some("A".to_owned()),
            t0()
        ),
        Err(MfaError::EnrollmentAlreadyComplete)
    );
}

/// Under the official emulator's rules a finalized session is gone.
#[test]
fn an_emulator_enrollment_session_is_gone_once_finalized() {
    let mut s = AuthStore::new("demo-app", SplitMix64::new(3), TotpPolicy::default());
    s.set_mfa_config(enabled(Some(5)));
    let (uid, material) = started(&mut s);
    let factor = s
        .finalize_totp_enrollment_named(
            &uid,
            &material.session_id,
            code_at(&material, t0()),
            Some("A".to_owned()),
            t0(),
        )
        .unwrap();
    assert_eq!(factor.mfa_enrollment_id.len(), 28);
    assert_eq!(
        s.finalize_totp_enrollment_named(
            &uid,
            &material.session_id,
            code_at(&material, steps(1)),
            Some("A".to_owned()),
            t0()
        ),
        Err(MfaError::EnrollmentSessionUnknown)
    );
}

// ---- phone enrollment sessions (sandbox recording 2026-09-24, auth-mfa/lifetime) -----------------

/// A phone enrollment session's code checked `age` seconds after the session was sent.
fn phone_enrollment_at(
    production: bool,
    age: i64,
) -> Result<(), fireemu_core_auth::store::AuthError> {
    use fireemu_core_auth::store::VerificationPurpose;
    let mut s = AuthStore::new("demo-app", SplitMix64::new(3), TotpPolicy::default());
    s.set_production_mfa(production);
    s.set_mfa_config(enabled(Some(5)));
    let uid = s
        .create_user_with_id(NewUser::email("a@example.com"), Some("a"), t0())
        .unwrap();
    let sent = s
        .send_verification_code(
            "+16505550101",
            VerificationPurpose::Enrollment { uid },
            t0(),
        )
        .unwrap();
    s.sweep_transient_credentials(seconds(age));
    s.check_phone_code(&sent.session_info, &sent.code, seconds(age))
        .map(|_| ())
}

/// Production still enrolled with a session about 1803 seconds old (`#aged-session-s1800`, both
/// recordings); longer is unobserved, so it stays refused.
#[test]
fn a_production_phone_enrollment_session_lives_as_long_as_observed() {
    for age in [603, 1_803, 1_805] {
        assert!(phone_enrollment_at(true, age).is_ok(), "{age}");
    }
    assert_eq!(
        phone_enrollment_at(true, 1_806),
        Err(fireemu_core_auth::store::AuthError::InvalidSessionInfo)
    );
}

/// The emulator profile keeps the ten minutes of every phone code.
#[test]
fn an_emulator_phone_enrollment_session_lives_ten_minutes() {
    assert!(phone_enrollment_at(false, 600).is_ok());
    assert_eq!(
        phone_enrollment_at(false, 601),
        Err(fireemu_core_auth::store::AuthError::InvalidSessionInfo)
    );
}
