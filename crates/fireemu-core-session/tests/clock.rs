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

// ---- A clock that follows real time ----------------------------------------------------------

use std::time::{Duration, Instant};

fn five_seconds_in() -> (VirtualClock, LogicalInstant) {
    let start = LogicalInstant::from_unix_seconds(1_800_000_000);
    let anchor = Instant::now()
        .checked_sub(Duration::from_secs(5))
        .expect("the monotonic clock has run for five seconds");
    (VirtualClock::following_since(start, anchor), start)
}

#[test]
fn a_following_clock_runs_from_its_start_and_a_frozen_one_does_not() {
    let (clock, start) = five_seconds_in();
    let now = clock.now().as_nanos() - start.as_nanos();
    assert!((5_000_000_000..6_000_000_000).contains(&now), "{now}");
    let snapshot = clock.snapshot();
    assert!(
        snapshot.instant >= clock.now()
            || snapshot.instant.as_nanos() >= start.as_nanos() + 5_000_000_000
    );
    assert!(snapshot.elapsed_nanos >= 5_000_000_000);
    assert_eq!(snapshot.revision, 0, "reading publishes nothing");
    let frozen = VirtualClock::new(start);
    std::thread::sleep(Duration::from_millis(5));
    assert_eq!(frozen.now(), start);
    assert_eq!(frozen.snapshot().elapsed_nanos, 0);
}

#[test]
fn a_following_clock_keeps_moving_between_reads() {
    let mut clock = VirtualClock::following(LogicalInstant::from_unix_seconds(1_800_000_000));
    let first = clock.now();
    std::thread::sleep(Duration::from_millis(20));
    let second = clock.now();
    assert!(second.as_nanos() - first.as_nanos() >= 20_000_000);
    // Moving it by hand is an offset on top: it keeps running from the new instant.
    let moved = clock.advance(LogicalDuration::from_seconds(60)).unwrap();
    assert!(moved.as_nanos() - second.as_nanos() >= 60_000_000_000);
    std::thread::sleep(Duration::from_millis(10));
    assert!(clock.now().as_nanos() - moved.as_nanos() >= 10_000_000);
}

#[test]
fn a_following_clock_refuses_to_go_back_to_a_time_it_has_passed() {
    let (mut clock, start) = five_seconds_in();
    assert!(matches!(
        clock.advance_to(start),
        Err(ClockError::WouldMoveBackwards { .. })
    ));
    let ahead = LogicalInstant::from_nanos(start.as_nanos() + 3_600_000_000_000);
    assert_eq!(clock.advance_to(ahead), Ok(ahead));
    assert!(clock.now() >= ahead);
    // A rewind is explicit and keeps counting from where it lands.
    clock.set_allow_backwards(start);
    assert_eq!(clock.backwards_sets(), 1);
    let after = clock.now().as_nanos() - start.as_nanos();
    assert!((0..1_000_000_000).contains(&after), "{after}");
}

#[test]
fn syncing_publishes_the_running_time_to_observers_once_it_has_moved() {
    let samples = Arc::new(Mutex::new(Vec::new()));
    let sink = samples.clone();
    let observer: Arc<fireemu_core_session::clock::ClockObserver> =
        Arc::new(move |sample| sink.lock().unwrap().push(sample));
    let (mut clock, start) = five_seconds_in();
    clock.observe(&observer);
    assert_eq!(samples.lock().unwrap().len(), 1);
    assert!(clock.sync());
    {
        let seen = samples.lock().unwrap();
        assert_eq!(seen.len(), 2);
        assert!(seen[1].instant.as_nanos() >= start.as_nanos() + 5_000_000_000);
        assert_eq!(seen[1].revision, seen[0].revision + 1);
    }
    let mut frozen = VirtualClock::new(start);
    frozen.observe(&observer);
    let before = samples.lock().unwrap().len();
    assert!(!frozen.sync(), "a frozen clock has nothing to publish");
    assert_eq!(samples.lock().unwrap().len(), before);
}

proptest::proptest! {
    #[test]
    fn a_following_clock_never_goes_back_and_hand_moves_add_at_least_their_size(
        moves in proptest::collection::vec((0u8..3, 0i64..10_000_000_000), 0..32),
    ) {
        let mut clock = VirtualClock::following(LogicalInstant::from_unix_seconds(1_800_000_000));
        let mut last = clock.now();
        for (kind, nanos) in moves {
            match kind {
                0 => {
                    let before = clock.now();
                    let after = clock.advance(LogicalDuration::from_nanos(i128::from(nanos))).unwrap();
                    proptest::prop_assert!(after.as_nanos() - before.as_nanos() >= i128::from(nanos));
                }
                1 => {
                    let target = LogicalInstant::from_nanos(clock.now().as_nanos() + i128::from(nanos));
                    proptest::prop_assert_eq!(clock.advance_to(target), Ok(target));
                }
                _ => { clock.sync(); }
            }
            let now = clock.now();
            proptest::prop_assert!(now >= last);
            proptest::prop_assert!(clock.snapshot().instant >= now || clock.snapshot().instant.as_nanos() >= last.as_nanos());
            last = now;
        }
    }
}

// A source the test moves by hand makes every case exact.

fn manual_clock(start: LogicalInstant) -> (VirtualClock, Arc<Mutex<i128>>) {
    let reading = Arc::new(Mutex::new(1_000_000_000_000_i128));
    let source = reading.clone();
    let clock = VirtualClock::following_with(
        start,
        Arc::new(move || *source.lock().unwrap()),
        *reading.lock().unwrap(),
    );
    (clock, reading)
}

fn run_for(reading: &Arc<Mutex<i128>>, nanos: i128) {
    *reading.lock().unwrap() += nanos;
}

#[test]
fn a_source_that_steps_back_holds_the_clock_until_it_catches_up() {
    let start = LogicalInstant::from_unix_seconds(1_800_000_000);
    let (mut clock, reading) = manual_clock(start);
    run_for(&reading, 10_000_000_000);
    assert_eq!(clock.now().as_nanos() - start.as_nanos(), 10_000_000_000);
    run_for(&reading, -4_000_000_000);
    assert_eq!(clock.now().as_nanos() - start.as_nanos(), 10_000_000_000);
    assert_eq!(clock.snapshot().elapsed_nanos, 10_000_000_000);
    run_for(&reading, 5_000_000_000);
    assert_eq!(clock.now().as_nanos() - start.as_nanos(), 11_000_000_000);
    // A move resets the hold along with everything else.
    let moved = clock.advance(LogicalDuration::from_seconds(1)).unwrap();
    assert_eq!(moved.as_nanos() - start.as_nanos(), 12_000_000_000);
    assert_eq!(clock.snapshot().elapsed_nanos, 12_000_000_000);
    run_for(&reading, -3_000_000_000);
    assert_eq!(clock.now(), moved);
}

#[test]
fn elapsed_time_counts_real_time_and_hand_moves_once_each() {
    let start = LogicalInstant::from_unix_seconds(1_800_000_000);
    let (mut clock, reading) = manual_clock(start);
    run_for(&reading, 2_000_000_000);
    clock.advance(LogicalDuration::from_seconds(10)).unwrap();
    run_for(&reading, 3_000_000_000);
    let snapshot = clock.snapshot();
    assert_eq!(
        snapshot.instant.as_nanos() - start.as_nanos(),
        15_000_000_000
    );
    assert_eq!(snapshot.elapsed_nanos, 15_000_000_000);
    assert_eq!(snapshot.revision, 1);
    assert!(clock.is_following());
    assert!(!VirtualClock::new(start).is_following());
    assert_eq!(clock.now_for_test(), snapshot.instant);
    assert_eq!(VirtualClock::new(start).now_for_test(), start);
}

#[test]
fn syncing_publishes_nothing_when_no_time_passed_or_the_range_is_spent() {
    let start = LogicalInstant::from_unix_seconds(1_800_000_000);
    let (mut clock, reading) = manual_clock(start);
    assert!(!clock.sync(), "no time has passed");
    assert_eq!(clock.snapshot().revision, 0);
    let high = LogicalInstant::from_nanos(start.as_nanos() + 10_000_000_000);
    clock.restrict_range(start, high).unwrap();
    run_for(&reading, 20_000_000_000);
    assert!(clock.sync(), "the clock reaches the end of its range once");
    assert_eq!(clock.snapshot().instant, high);
    assert_eq!(clock.snapshot().revision, 1);
    run_for(&reading, 1_000_000_000);
    assert!(!clock.sync(), "and has nothing past it to publish");
    assert_eq!(clock.snapshot().revision, 1);
    let (mut free, free_reading) = manual_clock(start);
    run_for(&free_reading, 20_000_000_000);
    assert!(free.sync());
    assert_eq!(free.snapshot().revision, 1);
}

#[test]
fn a_runtime_range_includes_its_ends_and_only_narrows() {
    let at = |seconds: i64| LogicalInstant::from_unix_seconds(seconds);
    let mut clock = VirtualClock::new(at(10));
    assert_eq!(clock.restrict_range(at(10), at(20)), Ok(()));
    assert_eq!(clock.restrict_range(at(0), at(10)), Ok(()));
    let mut clock = VirtualClock::new(at(10));
    assert_eq!(
        clock.restrict_range(at(11), at(20)),
        Err(ClockError::OutOfRange)
    );
    assert_eq!(
        clock.restrict_range(at(0), at(9)),
        Err(ClockError::OutOfRange)
    );
    assert_eq!(
        clock.restrict_range(at(20), at(0)),
        Err(ClockError::OutOfRange)
    );
    clock.restrict_range(at(0), at(100)).unwrap();
    clock.restrict_range(at(5), at(200)).unwrap();
    assert!(
        clock.advance_to(at(101)).is_err(),
        "100 is the upper end now"
    );
    assert!(clock.advance_to(at(100)).is_ok());
    assert!(
        clock.try_set_allow_backwards(at(4)).is_err(),
        "5 is the lower end now"
    );
    assert!(clock.try_set_allow_backwards(at(5)).is_ok());
}

#[test]
fn one_operation_reads_the_source_once_so_no_running_time_is_lost() {
    let start = LogicalInstant::from_unix_seconds(1_800_000_000);
    let calls = Arc::new(Mutex::new(0_i128));
    let counted = calls.clone();
    // Every read of the source finds it ten nanoseconds further on.
    let mut clock = VirtualClock::following_with(
        start,
        Arc::new(move || {
            let mut calls = counted.lock().unwrap();
            *calls += 1;
            *calls * 10
        }),
        0,
    );
    assert!(clock.sync());
    let after_sync = clock.snapshot();
    let reading = *calls.lock().unwrap() * 10;
    assert_eq!(
        after_sync.instant.as_nanos() - start.as_nanos(),
        reading,
        "the clock reads what the source read, with nothing dropped on the way"
    );
    assert_eq!(after_sync.elapsed_nanos, u128::try_from(reading).unwrap());
    let moved = clock.advance(LogicalDuration::from_nanos(1_000)).unwrap();
    let reading = *calls.lock().unwrap() * 10;
    assert_eq!(moved.as_nanos() - start.as_nanos(), reading + 1_000 - 10);
}

#[test]
fn reads_stop_at_the_runtime_range_like_writes() {
    let start = LogicalInstant::from_unix_seconds(1_800_000_000);
    let (mut clock, reading) = manual_clock(start);
    let high = LogicalInstant::from_nanos(start.as_nanos() + 10_000_000_000);
    clock.restrict_range(start, high).unwrap();
    run_for(&reading, 20_000_000_000);
    assert_eq!(clock.now(), high);
    assert_eq!(clock.now_for_test(), high);
    let snapshot = clock.snapshot();
    assert_eq!(snapshot.instant, high);
    assert_eq!(snapshot.elapsed_nanos, 10_000_000_000);
    assert!(clock.sync(), "the end of the range is published once");
    assert!(!clock.sync(), "there is nothing past the range to publish");
    // A rewind inside the range runs on again, and stops at the range again.
    let middle = LogicalInstant::from_nanos(start.as_nanos() + 5_000_000_000);
    clock.try_set_allow_backwards(middle).unwrap();
    run_for(&reading, 3_000_000_000);
    assert_eq!(clock.now().as_nanos() - middle.as_nanos(), 3_000_000_000);
    run_for(&reading, 30_000_000_000);
    assert_eq!(clock.now(), high);
}

#[test]
fn validating_a_target_judges_it_without_moving_anything() {
    let at = |seconds: i64| LogicalInstant::from_unix_seconds(seconds);
    let mut clock = VirtualClock::new(at(10));
    clock.restrict_range(at(0), at(100)).unwrap();
    let before = clock.snapshot();
    assert_eq!(clock.validate_target(at(100)), Ok(()));
    assert_eq!(clock.validate_target(at(0)), Ok(()));
    assert_eq!(clock.validate_target(at(101)), Err(ClockError::OutOfRange));
    assert_eq!(clock.validate_target(at(-1)), Err(ClockError::OutOfRange));
    assert_eq!(clock.snapshot(), before, "nothing was published");
}
