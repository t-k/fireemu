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
    s.finalize_totp_enrollment(&uid, &material.session_id, code, t0())
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
