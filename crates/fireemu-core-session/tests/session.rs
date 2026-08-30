//! Session lifecycle and epoch isolation (spec 7.3, 7.4).

use fireemu_core_session::session::{
    Session, SessionAction, SessionState, SessionTransitionError, WorkResult,
};
use fireemu_core_types::ids::{Epoch, SessionId};
use fireemu_core_types::time::LogicalInstant;

fn active_session() -> Session {
    let mut s = Session::create(SessionId::new(7), 99, LogicalInstant::UNIX_EPOCH);
    s.activate().unwrap();
    s
}

#[test]
fn lifecycle_creating_active_resetting_active_closing_closed() {
    let mut s = Session::create(SessionId::new(1), 0, LogicalInstant::UNIX_EPOCH);
    assert_eq!(s.state(), SessionState::Creating);
    assert_eq!(s.epoch(), Epoch::initial());
    s.activate().unwrap();
    assert_eq!(s.state(), SessionState::Active);
    let new_epoch = s.begin_reset().unwrap();
    assert_eq!(s.state(), SessionState::Resetting);
    assert_eq!(new_epoch, Epoch::new(1));
    s.complete_reset().unwrap();
    assert_eq!(s.state(), SessionState::Active);
    assert_eq!(s.epoch(), Epoch::new(1));
    s.begin_close().unwrap();
    assert_eq!(s.state(), SessionState::Closing);
    s.complete_close().unwrap();
    assert_eq!(s.state(), SessionState::Closed);
}

#[test]
fn invalid_transitions_are_typed_errors_and_do_not_change_state() {
    let mut s = Session::create(SessionId::new(1), 0, LogicalInstant::UNIX_EPOCH);
    assert_eq!(
        s.begin_reset(),
        Err(SessionTransitionError {
            from: SessionState::Creating,
            action: SessionAction::BeginReset
        })
    );
    assert_eq!(s.state(), SessionState::Creating);
    s.activate().unwrap();
    assert_eq!(
        s.activate(),
        Err(SessionTransitionError {
            from: SessionState::Active,
            action: SessionAction::Activate
        })
    );
    assert_eq!(
        s.complete_reset(),
        Err(SessionTransitionError {
            from: SessionState::Active,
            action: SessionAction::CompleteReset
        })
    );
    s.begin_close().unwrap();
    s.complete_close().unwrap();
    assert!(s.begin_reset().is_err());
    assert!(s.activate().is_err());
    assert_eq!(s.state(), SessionState::Closed);
}

#[test]
fn epoch_increases_monotonically_on_every_reset() {
    let mut s = active_session();
    let mut seen = vec![s.epoch()];
    for _ in 0..3 {
        let e = s.begin_reset().unwrap();
        s.complete_reset().unwrap();
        assert!(e > *seen.last().unwrap());
        seen.push(e);
    }
}

#[test]
fn work_from_an_old_epoch_is_discarded() {
    let mut s = active_session();
    let old = s.epoch();
    assert_eq!(s.check_work_epoch(old), WorkResult::Proceed);
    s.begin_reset().unwrap();
    // While resetting, both old and new epoch work must not mutate state.
    assert_eq!(s.check_work_epoch(old), WorkResult::DiscardedStaleEpoch);
    assert_eq!(
        s.check_work_epoch(s.epoch()),
        WorkResult::SessionNotActive(SessionState::Resetting)
    );
    s.complete_reset().unwrap();
    assert_eq!(s.check_work_epoch(old), WorkResult::DiscardedStaleEpoch);
    assert_eq!(s.check_work_epoch(s.epoch()), WorkResult::Proceed);
    // Work claiming a future epoch is a bug, never accepted.
    assert_eq!(
        s.check_work_epoch(s.epoch().next().unwrap()),
        WorkResult::DiscardedStaleEpoch
    );
}

#[test]
fn reset_reseeds_ids_deterministically_per_epoch() {
    use fireemu_core_types::determinism::IdSource;
    let mut a = active_session();
    let mut b = active_session();
    let a1 = a.ids().next_event_id();
    assert_eq!(a1, b.ids().next_event_id());
    a.begin_reset().unwrap();
    a.complete_reset().unwrap();
    b.begin_reset().unwrap();
    b.complete_reset().unwrap();
    let a2 = a.ids().next_event_id();
    assert_eq!(a2, b.ids().next_event_id());
    assert_ne!(
        a1, a2,
        "a new epoch must not replay the previous epoch's IDs"
    );
}

#[test]
fn clock_is_owned_by_the_session_and_survives_reset() {
    use fireemu_core_types::determinism::Clock;
    use fireemu_core_types::time::LogicalDuration;
    let mut s = active_session();
    s.clock_mut()
        .advance(LogicalDuration::from_seconds(5))
        .unwrap();
    s.begin_reset().unwrap();
    s.complete_reset().unwrap();
    assert_eq!(s.clock().now(), LogicalInstant::from_unix_seconds(5));
}

#[test]
fn a_session_stuck_in_resetting_can_still_be_closed() {
    let mut s = active_session();
    s.begin_reset().unwrap();
    assert_eq!(s.state(), SessionState::Resetting);
    s.begin_close().unwrap();
    assert_eq!(s.state(), SessionState::Closing);
    s.complete_close().unwrap();
    assert_eq!(s.state(), SessionState::Closed);
    assert_eq!(
        s.check_work_epoch(s.epoch()),
        WorkResult::SessionNotActive(SessionState::Closed)
    );
}

#[test]
fn seed_accessor_and_error_display() {
    let s = Session::create(SessionId::new(3), 99, LogicalInstant::UNIX_EPOCH);
    assert_eq!(s.seed(), 99);
    assert_eq!(s.id(), SessionId::new(3));
    let err = SessionTransitionError {
        from: SessionState::Creating,
        action: SessionAction::BeginReset,
    };
    assert!(err.to_string().contains("BeginReset") && err.to_string().contains("Creating"));
}
