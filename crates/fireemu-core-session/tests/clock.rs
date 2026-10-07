//! Virtual clock: the default clock never reads wall-clock time and never moves backwards
//! during normal operation (INV-TIME-001).

use fireemu_core_session::clock::{ClockError, VirtualClock};
use fireemu_core_types::determinism::Clock;
use fireemu_core_types::time::{LogicalDuration, LogicalInstant};
use std::sync::{Arc, Mutex};

#[test]
fn observer_tracks_every_writer_and_positive_elapsed_time_across_rewinds() {
    let samples = Arc::new(Mutex::new(Vec::new()));
    let sink = samples.clone();
    let observer: Arc<fireemu_core_session::clock::ClockObserver> =
        Arc::new(move |sample| sink.lock().unwrap().push(sample));
    let mut clock = VirtualClock::new(LogicalInstant::UNIX_EPOCH);
    clock.observe(&observer);
    clock.advance(LogicalDuration::from_nanos(500_000)).unwrap();
    clock.set_allow_backwards(LogicalInstant::from_nanos(-1_000_000));
    clock
        .advance_to(LogicalInstant::from_nanos(-500_000))
        .unwrap();
    clock.tick().unwrap();
    let snapshot = clock.snapshot();
    assert_eq!(snapshot.instant, LogicalInstant::from_nanos(-499_999));
    assert_eq!(snapshot.elapsed_nanos, 1_000_001);
    assert_eq!(snapshot.revision, 4);
    assert_eq!(samples.lock().unwrap().len(), 5);
    let before = snapshot;
    assert!(clock.advance(LogicalDuration::from_nanos(-1)).is_err());
    assert_eq!(clock.snapshot(), before);
    let mut independent = clock.clone();
    independent.tick().unwrap();
    assert_eq!(
        samples.lock().unwrap().len(),
        5,
        "clock clones cannot notify another world's observers"
    );
}

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

proptest::proptest! {
    #[test]
    fn positive_elapsed_and_world_projection_match_an_independent_model(
        commands in proptest::collection::vec((0usize..3, 0u8..4, -1_000_000i64..1_000_000),0..128),
    ) {
        let mut worlds = [VirtualClock::new(LogicalInstant::UNIX_EPOCH),VirtualClock::new(LogicalInstant::UNIX_EPOCH),VirtualClock::new(LogicalInstant::UNIX_EPOCH)];
        let mut model = [(0i128,0u128,0u64);3];
        let mut projected = VirtualClock::new(LogicalInstant::UNIX_EPOCH);
        for (owner,kind,value) in commands {
            let (before,elapsed,revision) = model[owner];
            let target = match kind { 0 => before+i128::from(value.max(0)), 1 => i128::from(value), 2 => before+1, _ => 0 };
            if kind == 3 {
                worlds[owner] = VirtualClock::new(LogicalInstant::UNIX_EPOCH);
                model[owner] = (0,0,0);
            } else {
                match kind {
                    0 => { worlds[owner].advance(LogicalDuration::from_nanos(i128::from(value.max(0)))).unwrap(); },
                    1 => worlds[owner].set_allow_backwards(LogicalInstant::from_nanos(target)),
                    _ => { worlds[owner].tick().unwrap(); },
                }
                model[owner] = (target,elapsed+u128::try_from((target-before).max(0)).unwrap(),revision+1);
            }
            if owner == 1 {
                if kind == 3 { projected = VirtualClock::new(LogicalInstant::UNIX_EPOCH); }
                else { projected.set_allow_backwards(LogicalInstant::from_nanos(target)); }
            }
            for index in 0..3 {
                let snapshot = worlds[index].snapshot();
                proptest::prop_assert_eq!((snapshot.instant.as_nanos(),snapshot.elapsed_nanos,snapshot.revision),model[index]);
            }
            proptest::prop_assert_eq!(worlds[1].snapshot(),projected.snapshot());
        }
    }
}

#[test]
fn configured_clock_range_rejects_every_writer_without_publishing_partial_state() {
    let mut clock = VirtualClock::new(LogicalInstant::UNIX_EPOCH);
    let minimum = LogicalInstant::from_nanos(-1000);
    let maximum = LogicalInstant::from_nanos(1000);
    clock.restrict_range(minimum, maximum).unwrap();
    clock.advance_to(maximum).unwrap();
    let before = clock.snapshot();
    assert!(clock.advance(LogicalDuration::from_seconds(1)).is_err());
    assert!(clock.tick().is_err());
    assert!(clock.advance_to(LogicalInstant::MAX).is_err());
    assert!(clock.try_set_allow_backwards(LogicalInstant::MIN).is_err());
    assert_eq!(clock.snapshot(), before);
    clock.set_allow_backwards(LogicalInstant::MIN);
    assert_eq!(clock.snapshot(), before);
    assert!(clock
        .clone()
        .advance(LogicalDuration::from_nanos(1))
        .is_err());
}
