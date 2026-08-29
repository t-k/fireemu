//! Logical time: nanoseconds since the Unix epoch with checked arithmetic only.

use ftd_core_types::time::{LogicalDuration, LogicalInstant, TimeFormatError, TimeParseError};
use proptest::prelude::*;

#[test]
fn instant_arithmetic_is_checked() {
    let t = LogicalInstant::from_unix_seconds(10);
    let later = t.checked_add(LogicalDuration::from_seconds(5)).unwrap();
    assert_eq!(later, LogicalInstant::from_unix_seconds(15));
    assert_eq!(
        later.checked_duration_since(t),
        Some(LogicalDuration::from_seconds(5))
    );
    assert_eq!(
        t.checked_duration_since(later),
        Some(LogicalDuration::from_seconds(-5))
    );
    assert!(LogicalInstant::MAX
        .checked_add(LogicalDuration::from_nanos(1))
        .is_none());
}

#[test]
fn rfc3339_round_trips_utc_with_nanoseconds() {
    let t = LogicalInstant::parse_rfc3339("2026-08-29T12:01:00Z").unwrap();
    assert_eq!(t, LogicalInstant::from_unix_seconds(1_788_004_860));
    assert_eq!(t.to_rfc3339().unwrap(), "2026-08-29T12:01:00Z");

    let frac = LogicalInstant::parse_rfc3339("2026-08-29T12:01:00.000000123Z").unwrap();
    assert_eq!(frac.as_nanos(), t.as_nanos() + 123);
    assert_eq!(frac.to_rfc3339().unwrap(), "2026-08-29T12:01:00.000000123Z");
}

#[test]
fn rfc3339_accepts_numeric_offsets() {
    let tokyo = LogicalInstant::parse_rfc3339("2026-08-29T21:01:00+09:00").unwrap();
    let utc = LogicalInstant::parse_rfc3339("2026-08-29T12:01:00Z").unwrap();
    assert_eq!(tokyo, utc);
    let west = LogicalInstant::parse_rfc3339("2026-08-29T05:01:00-07:00").unwrap();
    assert_eq!(west, utc);
}

#[test]
fn rfc3339_handles_epoch_and_negative_instants() {
    assert_eq!(
        LogicalInstant::parse_rfc3339("1970-01-01T00:00:00Z")
            .unwrap()
            .as_nanos(),
        0
    );
    let before = LogicalInstant::parse_rfc3339("1969-12-31T23:59:59Z").unwrap();
    assert_eq!(before, LogicalInstant::from_unix_seconds(-1));
    assert_eq!(before.to_rfc3339().unwrap(), "1969-12-31T23:59:59Z");
    let leap = LogicalInstant::parse_rfc3339("2000-02-29T00:00:00Z").unwrap();
    assert_eq!(leap.to_rfc3339().unwrap(), "2000-02-29T00:00:00Z");
}

#[test]
fn rfc3339_rejects_malformed_input_without_panicking() {
    for bad in [
        "",
        "2026-08-29",
        "2026-08-29T12:01:00",
        "2026-13-01T00:00:00Z",
        "2026-02-30T00:00:00Z",
        "2026-08-29T24:00:00Z",
        "2026-08-29T12:60:00Z",
        "2026-08-29T12:01:00+9:00",
        "2026-08-29T12:01:00.Z",
        "2026-08-29T12:01:00.0000000001Z",
        "２０２６-08-29T12:01:00Z",
    ] {
        assert!(
            matches!(
                LogicalInstant::parse_rfc3339(bad),
                Err(TimeParseError { .. })
            ),
            "expected rejection for {bad:?}"
        );
    }
}

#[test]
fn duration_conversions() {
    assert_eq!(
        LogicalDuration::from_millis(1_500).as_nanos(),
        1_500_000_000
    );
    assert_eq!(LogicalDuration::from_seconds(2).as_millis(), 2_000);
    assert!(LogicalDuration::from_seconds(1).is_positive());
    assert!(!LogicalDuration::ZERO.is_positive());
}

#[test]
fn formatting_outside_rfc3339_year_range_is_an_error_not_a_bogus_string() {
    let before_year_zero = LogicalInstant::from_unix_seconds(-62_167_219_201);
    assert_eq!(
        before_year_zero.to_rfc3339(),
        Err(TimeFormatError { year: -1 })
    );
    assert!(matches!(
        LogicalInstant::MAX.to_rfc3339(),
        Err(TimeFormatError { .. })
    ));
    assert!(matches!(
        LogicalInstant::MIN.to_rfc3339(),
        Err(TimeFormatError { .. })
    ));
    // Display never panics and never emits something that looks like RFC 3339 but is not.
    assert_eq!(
        LogicalInstant::MAX.to_string(),
        format!("nanos={}", i128::MAX)
    );
    // Year 0000 and 9999 are the inclusive edges.
    assert_eq!(
        LogicalInstant::parse_rfc3339("0000-01-01T00:00:00Z")
            .unwrap()
            .to_rfc3339()
            .unwrap(),
        "0000-01-01T00:00:00Z"
    );
    assert_eq!(
        LogicalInstant::parse_rfc3339("9999-12-31T23:59:59.999999999Z")
            .unwrap()
            .to_rfc3339()
            .unwrap(),
        "9999-12-31T23:59:59.999999999Z"
    );
}

proptest! {
    #[test]
    fn rfc3339_round_trips_over_the_representable_domain(
        // 0000-01-01T00:00:00Z .. 9999-12-31T23:59:59.999999999Z in nanoseconds.
        nanos in -62_167_219_200_000_000_000i128..=253_402_300_799_999_999_999i128
    ) {
        let t = LogicalInstant::from_nanos(nanos);
        let s = t.to_rfc3339().unwrap();
        prop_assert_eq!(LogicalInstant::parse_rfc3339(&s).unwrap(), t);
    }
}
