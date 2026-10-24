//! Regression tests for the production TOTP window and replay selector.

use fireemu_core_auth::mfa::{match_code, match_step_window, CodeMatch, TotpSecret};
use fireemu_core_auth::totp::{hotp, TotpParams};
use fireemu_core_types::time::LogicalInstant;

#[test]
fn saturated_windows_include_their_endpoints_and_prefer_fresh_matches() {
    assert_eq!(
        match_step_window(0, 2, None, |step| step == 2),
        CodeMatch::Accepted { step: 2 }
    );
    assert_eq!(
        match_step_window(u64::MAX, 2, None, |step| step == u64::MAX),
        CodeMatch::Accepted { step: u64::MAX }
    );
    assert_eq!(
        match_step_window(5, 1, Some(5), |_| true),
        CodeMatch::Accepted { step: 6 }
    );
    assert_eq!(
        match_step_window(5, 1, Some(6), |_| true),
        CodeMatch::Replayed
    );
    assert_eq!(
        match_step_window(5, 0, None, |step| step == 4),
        CodeMatch::NoMatch
    );
    assert_eq!(
        match_step_window(5, 0, Some(5), |_| true),
        CodeMatch::Replayed
    );
}

#[test]
fn real_hotp_wrapper_preserves_window_and_replay_semantics() {
    let secret = TotpSecret::new(b"12345678901234567890".to_vec());
    let params = TotpParams {
        period_seconds: 30,
        digits: 6,
    };
    for step in 9..=11 {
        let code = hotp(secret.expose_for_enrollment(), step, 6);
        let now = LogicalInstant::from_unix_seconds(300);
        assert_eq!(
            match_code(&secret, &params, 1, None, code, now),
            CodeMatch::Accepted { step }
        );
        assert_eq!(
            match_code(&secret, &params, 1, Some(step), code, now),
            CodeMatch::Replayed
        );
    }
    let empty_secret_code = hotp(&[], 0, params.digits);
    assert_eq!(
        match_code(
            &TotpSecret::detached(),
            &params,
            1,
            None,
            empty_secret_code,
            LogicalInstant::UNIX_EPOCH
        ),
        CodeMatch::NoMatch
    );
}

proptest::proptest! {
    #[test]
    fn selector_matches_independent_bounded_offset_reference(current in proptest::prelude::any::<u64>(), window in 0u8..=2, last in proptest::option::of(proptest::prelude::any::<u64>()), mask in proptest::prelude::any::<u8>()) {
        let low = current.saturating_sub(u64::from(window));
        let high = current.saturating_add(u64::from(window));
        let matches = |step: u64| mask & (1u8 << (step - low)) != 0;
        let mut expected = CodeMatch::NoMatch;
        for offset in 0..5u64 {
            if let Some(step) = low.checked_add(offset).filter(|step| *step <= high) {
                if matches(step) {
                    if last.is_none_or(|last| step > last) {
                        expected = CodeMatch::Accepted { step };
                        break;
                    }
                    expected = CodeMatch::Replayed;
                }
            }
        }
        proptest::prop_assert_eq!(match_step_window(current, window, last, matches), expected);
    }
}

#[test]
#[ignore = "requires generated PICT rows in FIREEMU_FORMAL_MATRIX_DIR"]
fn generated_pict_windows_match_the_independent_selector_reference() {
    let directory = std::env::var("FIREEMU_FORMAL_MATRIX_DIR").expect("PICT fixture directory");
    let table = std::fs::read_to_string(std::path::Path::new(&directory).join("totp.tsv")).unwrap();
    let mut count = 0;
    for row in table.lines().skip(1) {
        let fields = row.split('\t').collect::<Vec<_>>();
        let current: u64 = match fields[0] {
            "zero" => 0,
            "middle" => 10,
            "max" => u64::MAX,
            value => panic!("unknown current {value}"),
        };
        let window: u8 = fields[1].parse().unwrap();
        let last = match fields[2] {
            "none" => None,
            "before" => Some(current.saturating_sub(1)),
            "equal" => Some(current),
            "after" => Some(current.saturating_add(1)),
            value => panic!("unknown last {value}"),
        };
        let matches = |step| match fields[3] {
            "none" => false,
            "stale" => last.is_some_and(|last| step <= last),
            "fresh" => last.is_none_or(|last| step > last),
            "both" => true,
            value => panic!("unknown matches {value}"),
        };
        let low = current.saturating_sub(u64::from(window));
        let high = current.saturating_add(u64::from(window));
        let mut expected = CodeMatch::NoMatch;
        for offset in 0..5u64 {
            if let Some(step) = low.checked_add(offset).filter(|step| *step <= high) {
                if matches(step) {
                    if last.is_none_or(|last| step > last) {
                        expected = CodeMatch::Accepted { step };
                        break;
                    }
                    expected = CodeMatch::Replayed;
                }
            }
        }
        assert_eq!(
            match_step_window(current, window, last, matches),
            expected,
            "{row}"
        );
        count += 1;
    }
    assert!(count >= 20);
}

proptest::proptest! {
    #[test]
    fn full_u8_window_matches_independent_reference(current in proptest::prelude::any::<u64>(), window in proptest::prelude::any::<u8>(), last in proptest::option::of(proptest::prelude::any::<u64>()), pattern in proptest::prelude::any::<u64>()) {
        let low = current.saturating_sub(u64::from(window));
        let high = current.saturating_add(u64::from(window));
        let matches = |step: u64| pattern & (1u64 << ((step - low) % 64)) != 0;
        let mut expected = CodeMatch::NoMatch;
        for offset in 0..=510u64 {
            if let Some(step) = low.checked_add(offset).filter(|step| *step <= high) {
                if matches(step) {
                    if last.is_none_or(|last| step > last) { expected = CodeMatch::Accepted { step }; break; }
                    expected = CodeMatch::Replayed;
                }
            }
        }
        proptest::prop_assert_eq!(match_step_window(current, window, last, matches), expected);
    }
}
