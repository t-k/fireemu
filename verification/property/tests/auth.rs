//! Property artifacts for INV-AUTH-001 and INV-AUTH-003 (spec 33, RFC 6238).

use fireemu_core_auth::base32;
use fireemu_core_auth::mfa::{match_code, CodeMatch, PendingEnrollment, TotpFactor, TotpSecret};
use fireemu_core_auth::totp::{time_step, totp_at, TotpParams};
use fireemu_core_types::time::LogicalInstant;
use proptest::prelude::*;

fn params(period_seconds: u32, digits: u8) -> TotpParams {
    TotpParams {
        period_seconds,
        digits,
    }
}

proptest! {
    /// INV-AUTH-001: the code is a function of the time step alone, so two instants inside the
    /// same step always produce the same code. That is what makes a code at or below the last
    /// accepted step recognisable as a replay.
    #[test]
    fn prop_same_step_same_code(
        secret in prop::collection::vec(any::<u8>(), 1..40),
        period in 1u32..=120,
        digits in 6u8..=8,
        step in 0u64..100_000,
        offset in 0u32..120,
    ) {
        let p = params(period, digits);
        let base = i64::try_from(step * u64::from(period)).unwrap();
        let inside = i64::from(offset % period);
        let first = LogicalInstant::from_unix_seconds(base);
        let same = LogicalInstant::from_unix_seconds(base + inside);
        prop_assert_eq!(time_step(&p, first), time_step(&p, same));
        let code = totp_at(&secret, &p, first);
        prop_assert_eq!(code, totp_at(&secret, &p, same));
        prop_assert!(u64::from(code) < 10u64.pow(u32::from(digits)));

        // The replay guard is expressed in the same steps: a code from a step at or below the
        // last accepted one is never accepted again, at either instant of the step.
        let secret = TotpSecret::new(secret);
        let current = time_step(&p, first);
        for at in [first, same] {
            prop_assert_eq!(
                match_code(&secret, &p, 0, None, code, at),
                CodeMatch::Accepted { step: current }
            );
            prop_assert_eq!(
                match_code(&secret, &p, 0, Some(current), code, at),
                CodeMatch::Replayed
            );
        }
    }

    /// INV-AUTH-003: no `Debug` rendering of a secret-carrying type ever contains the secret
    /// bytes, their base32 encoding, or the `otpauth` URI that embeds them.
    #[test]
    fn prop_debug_never_contains_secret(secret in prop::collection::vec(any::<u8>(), 8..40)) {
        let encoded = base32::encode(&secret);
        let bytes = format!("{secret:?}");
        let wrapped = TotpSecret::new(secret.clone());
        let factor = TotpFactor {
            mfa_enrollment_id: "enrollment-1".to_owned(),
            display_name: Some("phone".to_owned()),
            secret: wrapped.clone(),
            enrolled_at: LogicalInstant::UNIX_EPOCH,
            last_accepted_step: Some(7),
        };
        let pending = PendingEnrollment {
            secret: wrapped.clone(),
            expires_at: LogicalInstant::UNIX_EPOCH,
        };
        for rendered in [
            format!("{wrapped:?}"),
            format!("{factor:?}"),
            format!("{pending:?}"),
        ] {
            prop_assert!(rendered.contains("[redacted]"), "{rendered}");
            prop_assert!(!rendered.contains(&encoded), "{rendered}");
            prop_assert!(!rendered.contains(&bytes), "{rendered}");
            prop_assert!(!rendered.contains("otpauth://"), "{rendered}");
        }
    }
}
