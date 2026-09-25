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

/// Production enrolled with sessions of every age it was shown, up to about 1803 seconds
/// (`#aged-session-s1800`, both recordings), and never refused one, so under its rules a phone
/// enrollment session does not expire (owner decision M12, as AUTH-ACTION's long codes).
#[test]
fn a_production_phone_enrollment_session_does_not_expire() {
    for age in [603, 1_805, 1_806, 3 * 86_400] {
        assert!(phone_enrollment_at(true, age).is_ok(), "{age}");
    }
}

/// Each account holds at most [`MAX_PENDING_PER_USER`] phone enrollment sessions: at that
/// number its own oldest session older than the observed ages makes room, and until one is
/// that old the next send is refused (follow-up directive, Should 2).
#[test]
fn an_account_holds_a_bounded_number_of_phone_enrollment_sessions() {
    use fireemu_core_auth::mfa::MAX_PENDING_PER_USER;
    use fireemu_core_auth::store::{AuthError, VerificationPurpose};
    let mut s = AuthStore::new("demo-app", SplitMix64::new(3), TotpPolicy::default());
    s.set_production_mfa(true);
    s.set_mfa_config(enabled(Some(5)));
    let uid = s
        .create_user_with_id(NewUser::email("a@example.com"), Some("a"), t0())
        .unwrap();
    let enroll = || VerificationPurpose::Enrollment { uid: uid.clone() };
    let oldest = s
        .send_verification_code("+16505550101", enroll(), t0())
        .unwrap();
    for _ in 1..MAX_PENDING_PER_USER {
        s.send_verification_code("+16505550101", enroll(), seconds(1))
            .unwrap();
    }
    assert_eq!(
        s.send_verification_code("+16505550101", enroll(), seconds(1_805)),
        Err(AuthError::TooManyOutstandingCodes),
        "no own session is older than the observed ages yet"
    );
    s.send_verification_code("+16505550101", enroll(), seconds(1_806))
        .unwrap();
    assert_eq!(
        s.check_phone_code(&oldest.session_info, &oldest.code, seconds(1_806)),
        Err(AuthError::InvalidSessionInfo),
        "the account's oldest session made room"
    );
}

/// At the project's cap on outstanding phone codes an account makes room only from its own old
/// sessions; another account's sessions are never dropped, and an account without one is
/// refused (follow-up directive, Should 2).
#[test]
fn at_the_code_cap_no_account_drops_another_accounts_session() {
    use fireemu_core_auth::mfa::MAX_PENDING_PER_USER;
    use fireemu_core_auth::store::{AuthError, VerificationPurpose, MAX_OUTSTANDING_CODES};
    let mut s = AuthStore::new("demo-app", SplitMix64::new(3), TotpPolicy::default());
    s.set_production_mfa(true);
    s.set_mfa_config(enabled(Some(5)));
    let accounts = MAX_OUTSTANDING_CODES.div_ceil(MAX_PENDING_PER_USER - 1) + 1;
    let uids: Vec<_> = (0..accounts)
        .map(|n| {
            s.create_user_with_id(
                NewUser::email(&format!("u{n}@example.com")),
                Some(&format!("u{n}")),
                t0(),
            )
            .unwrap()
        })
        .collect();
    let mut first = Vec::new();
    'fill: for uid in &uids[..accounts - 1] {
        for k in 0..MAX_PENDING_PER_USER - 1 {
            if s.verification_codes().len() >= MAX_OUTSTANDING_CODES {
                break 'fill;
            }
            let sent = s
                .send_verification_code(
                    "+16505550101",
                    VerificationPurpose::Enrollment { uid: uid.clone() },
                    t0(),
                )
                .unwrap();
            if k == 0 {
                first.push(sent);
            }
        }
    }
    let late = seconds(1_806);
    let newcomer = uids.last().unwrap().clone();
    assert_eq!(
        s.send_verification_code(
            "+16505550101",
            VerificationPurpose::Enrollment { uid: newcomer },
            late
        ),
        Err(AuthError::TooManyOutstandingCodes)
    );
    s.send_verification_code(
        "+16505550101",
        VerificationPurpose::Enrollment {
            uid: uids[0].clone(),
        },
        late,
    )
    .unwrap();
    assert_eq!(
        s.check_phone_code(&first[0].session_info, &first[0].code, late),
        Err(AuthError::InvalidSessionInfo),
        "the sender's own oldest session made room"
    );
    for other in &first[1..] {
        assert!(
            s.check_phone_code(&other.session_info, &other.code, late)
                .is_ok(),
            "another account's session stays"
        );
    }
}

/// The project's `mfa` config is control-plane state of its namespace: a snapshot restored into
/// another namespace keeps the destination's (safety review 2026-09-25, SF-1), as the client
/// permissions and the sign-in config do. A restore into its own namespace brings it back.
#[test]
fn a_cross_namespace_restore_keeps_the_destination_mfa_config() {
    let mut source = AuthStore::new("source", SplitMix64::new(3), TotpPolicy::default());
    let snapshot = fireemu_core_auth::store::AuthSnapshot::capture(&source);
    let mut destination = AuthStore::new("destination", SplitMix64::new(4), TotpPolicy::default());
    destination.set_mfa_config(enabled(Some(5)));
    snapshot.restore_into(&mut destination);
    assert_eq!(destination.mfa_config(), &enabled(Some(5)));

    source.set_mfa_config(enabled(Some(3)));
    let snapshot = fireemu_core_auth::store::AuthSnapshot::capture(&source);
    source.set_mfa_config(enabled(None));
    snapshot.restore_into(&mut source);
    assert_eq!(source.mfa_config(), &enabled(Some(3)));
}

/// A phone code checked `age` seconds after it was sent for `purpose` under production's
/// rules.
fn phone_code_at(
    purpose: impl FnOnce(
        fireemu_core_auth::store::LocalId,
    ) -> fireemu_core_auth::store::VerificationPurpose,
    age: i64,
) -> Result<(), fireemu_core_auth::store::AuthError> {
    let mut s = AuthStore::new("demo-app", SplitMix64::new(3), TotpPolicy::default());
    s.set_production_mfa(true);
    s.set_mfa_config(enabled(Some(5)));
    let uid = s
        .create_user_with_id(NewUser::email("a@example.com"), Some("a"), t0())
        .unwrap();
    let sent = s
        .send_verification_code("+16505550101", purpose(uid), t0())
        .unwrap();
    s.sweep_transient_credentials(seconds(age));
    s.check_phone_code(&sent.session_info, &sent.code, seconds(age))
        .map(|_| ())
}

/// The observed lifetime of a phone enrollment session reaches no other phone code: first-factor
/// codes keep ten minutes under production's rules too (safety review 2026-09-25, SF-3 d).
#[test]
fn only_a_phone_enrollment_session_outlives_ten_minutes() {
    use fireemu_core_auth::store::{AuthError, VerificationPurpose};
    assert!(phone_code_at(|_| VerificationPurpose::SignIn, 600).is_ok());
    assert_eq!(
        phone_code_at(|_| VerificationPurpose::SignIn, 601),
        Err(AuthError::InvalidSessionInfo)
    );
    assert!(phone_code_at(|uid| VerificationPurpose::Enrollment { uid }, 1_806).is_ok());
}

/// A tenant's second factors keep their earlier rules under a store that follows production's
/// (scope decision M2; safety review 2026-09-25, SF-3 b): no challenge timeout, no recent
/// sign-in, and a pending credential is spent by its success.
#[test]
fn a_tenant_keeps_its_earlier_second_factor_rules() {
    let mut s = fireemu_core_auth::store::AuthStore::new_tenant(
        "demo-app",
        "tenant-a",
        SplitMix64::new(3),
        TotpPolicy::default(),
    );
    s.set_production_mfa(true);
    assert!(!s.second_factor_rules_are_production());
    assert!(!s.totp_enrollment_login_too_old(1_788_004_875, seconds(1_800)));
    let (uid, material) = started(&mut s);
    s.finalize_totp_enrollment_named(
        &uid,
        &material.session_id,
        code_at(&material, t0()),
        None,
        t0(),
    )
    .unwrap();
    let pending = s.start_mfa_sign_in(&uid, t0()).unwrap();
    let factor = s.user_by_id("a").unwrap().mfa.totp_factors()[0]
        .mfa_enrollment_id
        .clone();
    let late = seconds(1_800);
    s.finalize_mfa_sign_in_for_factor(&uid, &pending, &factor, code_at(&material, late), late)
        .unwrap();
    assert_eq!(
        s.finalize_mfa_sign_in_for_factor(
            &uid,
            &pending,
            &factor,
            code_at(&material, seconds(1_830)),
            seconds(1_830)
        ),
        Err(MfaError::PendingSignInUnknown)
    );
}

/// The refusals this parent added describe themselves (mutation follow-up,
/// docs.local/mutation/auth-mfa/20260925).
#[test]
fn the_new_mfa_refusals_describe_themselves() {
    for (error, text) in [
        (MfaError::TotpChallengeTimeout, "TOTP challenge timeout"),
        (
            MfaError::EnrollmentAlreadyComplete,
            "enrollment already complete",
        ),
    ] {
        assert_eq!(error.to_string(), text);
    }
    assert!(!MfaError::TooManyEnrollmentAttempts.to_string().is_empty());
}

/// Below the cap nothing makes room: an enrollment session older than the observed ages stays
/// usable while other codes are sent (mutation follow-up, 20260925-followup).
#[test]
fn below_the_code_cap_an_old_enrollment_session_stays() {
    use fireemu_core_auth::store::VerificationPurpose;
    let mut s = AuthStore::new("demo-app", SplitMix64::new(3), TotpPolicy::default());
    s.set_production_mfa(true);
    s.set_mfa_config(enabled(Some(5)));
    let uid = s
        .create_user_with_id(NewUser::email("a@example.com"), Some("a"), t0())
        .unwrap();
    let old = s
        .send_verification_code(
            "+16505550101",
            VerificationPurpose::Enrollment { uid: uid.clone() },
            t0(),
        )
        .unwrap();
    s.send_verification_code(
        "+16505550101",
        VerificationPurpose::Enrollment { uid },
        seconds(1_806),
    )
    .unwrap();
    assert!(s
        .check_phone_code(&old.session_info, &old.code, seconds(1_806))
        .is_ok());
}

/// A pending sign-in's debug form names it and whether it completed, never its credentials
/// (mutation follow-up, 20260925-followup).
#[test]
fn a_pending_sign_in_debugs_its_state() {
    let mut s = production_store();
    let (uid, material) = started(&mut s);
    s.finalize_totp_enrollment_named(
        &uid,
        &material.session_id,
        code_at(&material, t0()),
        Some("A".to_owned()),
        t0(),
    )
    .unwrap();
    s.start_mfa_sign_in(&uid, t0()).unwrap();
    let debug = format!("{:?}", s.user_by_id("a").unwrap().mfa);
    assert!(debug.contains("PendingSignIn"), "{debug}");
    assert!(debug.contains("completed: false"), "{debug}");
}

/// Production's enrollment ids are version-4 UUIDs: version nibble 4, variant 8 to b, and the
/// variant byte's low bits random (mutation follow-up, docs.local/mutation/auth-mfa/20260925).
#[test]
fn production_enrollment_ids_are_random_version_4_uuids() {
    let mut s = AuthStore::new("demo-app", SplitMix64::new(7), TotpPolicy::default());
    s.set_production_mfa(true);
    let mut variant_bytes = std::collections::BTreeSet::new();
    for n in 0..64 {
        let id = s.imported_factor_defaults(t0()).unwrap().0;
        let parts: Vec<&str> = id.split('-').collect();
        assert_eq!(
            parts.iter().map(|p| p.len()).collect::<Vec<_>>(),
            [8, 4, 4, 4, 12],
            "{n}: {id}"
        );
        assert!(
            id.chars().all(|c| c == '-' || c.is_ascii_hexdigit()),
            "{id}"
        );
        assert_eq!(&parts[2][..1], "4", "version: {id}");
        assert!("89ab".contains(&parts[3][..1]), "variant: {id}");
        variant_bytes.insert(parts[3][..2].to_owned());
    }
    assert!(variant_bytes.len() > 8, "{variant_bytes:?}");
}

/// Under the official emulator's rules an enrollment session is reaped one lifetime after it
/// expired, also when another session of the same user ended first, by success or by expiry
/// (mutation follow-up, docs.local/mutation/auth-mfa/20260925).
#[test]
fn an_emulator_enrollment_session_is_reaped_after_its_sibling_ends() {
    for sibling_succeeds in [true, false] {
        let mut s = AuthStore::new("demo-app", SplitMix64::new(3), TotpPolicy::default());
        s.set_mfa_config(enabled(Some(5)));
        let (uid, first) = started(&mut s);
        let second = s.start_totp_enrollment(&uid, t0()).unwrap();
        let ended_at = if sibling_succeeds { t0() } else { seconds(901) };
        let _ = s.finalize_totp_enrollment_named(
            &uid,
            &first.session_id,
            code_at(&first, ended_at),
            Some("A".to_owned()),
            ended_at,
        );
        s.sweep_transient_credentials(seconds(1_801));
        assert_eq!(
            s.finalize_totp_enrollment_named(
                &uid,
                &second.session_id,
                code_at(&second, seconds(1_801)),
                Some("B".to_owned()),
                seconds(1_801)
            ),
            Err(MfaError::EnrollmentSessionUnknown),
            "sibling succeeds: {sibling_succeeds}"
        );
    }
}

/// Under the official emulator's rules a pending sign-in is reaped after its hour, also when
/// another pending sign-in of the same user succeeded first (mutation follow-up,
/// docs.local/mutation/auth-mfa/20260925).
#[test]
fn an_emulator_pending_sign_in_is_reaped_after_its_sibling_succeeds() {
    let mut s = AuthStore::new("demo-app", SplitMix64::new(3), TotpPolicy::default());
    s.set_mfa_config(enabled(Some(5)));
    let (uid, material) = started(&mut s);
    s.finalize_totp_enrollment_named(
        &uid,
        &material.session_id,
        code_at(&material, t0()),
        None,
        t0(),
    )
    .unwrap();
    let factor = s.user_by_id("a").unwrap().mfa.totp_factors()[0]
        .mfa_enrollment_id
        .clone();
    let first = s.start_mfa_sign_in(&uid, seconds(60)).unwrap();
    let second = s.start_mfa_sign_in(&uid, seconds(60)).unwrap();
    s.finalize_mfa_sign_in_for_factor(
        &uid,
        &first,
        &factor,
        code_at(&material, seconds(60)),
        seconds(60),
    )
    .unwrap();
    let late = seconds(60 + 3_601);
    s.sweep_transient_credentials(late);
    assert_eq!(
        s.finalize_mfa_sign_in_for_factor(&uid, &second, &factor, code_at(&material, late), late),
        Err(MfaError::PendingSignInUnknown)
    );
}
