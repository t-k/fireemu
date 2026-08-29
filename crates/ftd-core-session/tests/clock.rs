//! Virtual clock: the default clock never reads wall-clock time and never moves backwards
//! during normal operation (INV-TIME-001).

use ftd_core_session::clock::{ClockError, VirtualClock};
use ftd_core_types::determinism::Clock;
use ftd_core_types::time::{LogicalDuration, LogicalInstant};

#[test]
fn starts_at_configured_instant_and_advances() {
    let start = LogicalInstant::parse_rfc3339("2026-08-29T00:00:00Z").unwrap();
    let mut clock = VirtualClock::new(start);
    assert_eq!(clock.now(), start);
    let after = clock.advance(LogicalDuration::from_seconds(90)).unwrap();
    assert_eq!(
        after,
        LogicalInstant::parse_rfc3339("2026-08-29T00:01:30Z").unwrap()
    );
    assert_eq!(clock.now(), after);
}

#[test]
fn advance_rejects_negative_duration_and_overflow() {
    let mut clock = VirtualClock::new(LogicalInstant::UNIX_EPOCH);
    assert_eq!(
        clock.advance(LogicalDuration::from_seconds(-1)),
        Err(ClockError::NegativeDuration)
    );
    let mut at_max = VirtualClock::new(LogicalInstant::MAX);
    assert_eq!(
        at_max.advance(LogicalDuration::from_nanos(1)),
        Err(ClockError::Overflow)
    );
    assert_eq!(at_max.now(), LogicalInstant::MAX);
}

#[test]
fn advance_to_only_moves_forward() {
    let mut clock = VirtualClock::new(LogicalInstant::from_unix_seconds(100));
    assert!(clock
        .advance_to(LogicalInstant::from_unix_seconds(100))
        .is_ok());
    assert_eq!(
        clock.advance_to(LogicalInstant::from_unix_seconds(99)),
        Err(ClockError::WouldMoveBackwards {
            current: LogicalInstant::from_unix_seconds(100),
            requested: LogicalInstant::from_unix_seconds(99),
        })
    );
    assert!(clock
        .advance_to(LogicalInstant::from_unix_seconds(200))
        .is_ok());
}

#[test]
fn set_backwards_requires_explicit_permission() {
    let mut clock = VirtualClock::new(LogicalInstant::from_unix_seconds(100));
    assert!(matches!(
        clock.set(LogicalInstant::from_unix_seconds(50)),
        Err(ClockError::WouldMoveBackwards { .. })
    ));
    clock.set_allow_backwards(LogicalInstant::from_unix_seconds(50));
    assert_eq!(clock.now(), LogicalInstant::from_unix_seconds(50));
    assert_eq!(clock.backwards_sets(), 1);
}

#[test]
fn tick_is_one_nanosecond_for_fixture_ordering() {
    let mut clock = VirtualClock::new(LogicalInstant::UNIX_EPOCH);
    let a = clock.tick().unwrap();
    let b = clock.tick().unwrap();
    assert_eq!(
        b.checked_duration_since(a),
        Some(LogicalDuration::from_nanos(1))
    );
}

#[test]
fn zero_advance_and_equal_set_are_not_backwards() {
    let mut clock = VirtualClock::new(LogicalInstant::from_unix_seconds(100));
    assert!(clock.advance(LogicalDuration::ZERO).is_ok());
    assert!(clock.set(LogicalInstant::from_unix_seconds(100)).is_ok());
    clock.set_allow_backwards(LogicalInstant::from_unix_seconds(100));
    assert_eq!(
        clock.backwards_sets(),
        0,
        "setting the same instant is not a backwards move"
    );
    clock.set_allow_backwards(LogicalInstant::from_unix_seconds(50));
    clock.set_allow_backwards(LogicalInstant::from_unix_seconds(40));
    assert_eq!(clock.backwards_sets(), 2);
    assert!(ClockError::NegativeDuration
        .to_string()
        .contains("negative"));
    assert!(ClockError::Overflow.to_string().contains("overflow"));
}
