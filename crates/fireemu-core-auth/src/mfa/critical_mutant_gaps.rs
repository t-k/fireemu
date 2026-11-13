use super::{
    wipe_secret, MfaState, PendingEnrollment, PendingSignIn, PendingSignInContext,
    PendingSignInCredentials, TotpSecret, SECRET_DROPS,
};
use fireemu_core_types::time::LogicalInstant;

#[test]
fn wipe_secret_zeros_every_byte() {
    let mut bytes = [1, 0, 42, 255];
    wipe_secret(&mut bytes);
    assert!(bytes.iter().all(|&byte| byte == 0));
}

#[test]
fn dropping_totp_secret_runs_drop() {
    let before = SECRET_DROPS.with(std::cell::Cell::get);
    drop(TotpSecret::new(vec![1, 2, 3]));
    assert_eq!(SECRET_DROPS.with(std::cell::Cell::get), before + 1);
}

fn enrollment(expires: i64) -> PendingEnrollment {
    PendingEnrollment {
        secret: TotpSecret::new(vec![1]),
        expires_at: LogicalInstant::from_unix_seconds(expires),
        attempts: 0,
        completed: false,
    }
}

fn sign_in(completed: bool) -> PendingSignIn {
    PendingSignIn {
        started_at: LogicalInstant::from_unix_seconds(2),
        context: PendingSignInContext::new_with_credentials(
            None,
            false,
            None,
            Some(PendingSignInCredentials::new(
                Some("access".into()),
                None,
                None,
            )),
        ),
        completed,
    }
}

#[test]
fn expired_enrollment_precedes_completed_sign_in_at_strict_boundary() {
    for (expires, expected_sign_in) in [(9, false), (10, true), (11, true)] {
        let mut state = MfaState::default();
        state
            .pending_enrollments
            .insert("enrollment".into(), enrollment(expires));
        state
            .pending_sign_ins
            .insert("finished".into(), sign_in(true));
        let dropped = state.drop_one_finished(LogicalInstant::from_unix_seconds(10));
        if expected_sign_in {
            assert_eq!(dropped.as_deref(), Some("finished"));
            assert!(state.has_enrollment_session("enrollment"));
        } else {
            assert_eq!(dropped, None);
            assert!(!state.has_enrollment_session("enrollment"));
        }
    }
}

#[test]
fn pending_ids_credentials_and_clear_are_observable() {
    let mut state = MfaState::default();
    assert!(!state.has_enrollment_session("missing"));
    assert!(!state.has_pending_sign_in("missing"));
    assert!(!state.clear_pending_sign_in_credentials("missing"));
    assert!(state.holds_no_inbound_credentials());
    state
        .pending_enrollments
        .insert("enrollment".into(), enrollment(10));
    state
        .pending_sign_ins
        .insert("signin".into(), sign_in(false));
    assert!(state.has_enrollment_session("enrollment"));
    assert!(state.has_pending_sign_in("signin"));
    assert!(!state.holds_no_inbound_credentials());
    assert_eq!(
        state.pending_sign_in_ids_and_starts(),
        vec![("signin".into(), LogicalInstant::from_unix_seconds(2))]
    );
    assert!(state.clear_pending_sign_in_credentials("signin"));
    assert!(state.holds_no_inbound_credentials());
    assert_eq!(state.clear_pending(), vec!["signin"]);
    assert_eq!(state.pending_count(), 0);
    assert_eq!(state.clear_pending(), Vec::<String>::new());
}
