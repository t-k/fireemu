//! Every source of nondeterminism is an explicit adapter with a deterministic default.

use ftd_core_types::determinism::{DeterministicIdSource, DeterministicRng, IdSource, SplitMix64};
use ftd_core_types::ids::SessionId;

#[test]
fn id_source_is_reproducible_from_seed_and_distinct_per_kind() {
    let mut a = DeterministicIdSource::new(SessionId::new(42), 7);
    let mut b = DeterministicIdSource::new(SessionId::new(42), 7);
    let e1 = a.next_event_id();
    let e2 = a.next_event_id();
    assert_ne!(e1, e2);
    assert_eq!(e1, b.next_event_id());
    assert_eq!(e2, b.next_event_id());
    // Different kinds never collide even with the same counter value.
    let mut c = DeterministicIdSource::new(SessionId::new(42), 7);
    let mut d = DeterministicIdSource::new(SessionId::new(42), 7);
    assert_ne!(c.next_event_id().value(), d.next_invocation_id().value());
}

#[test]
fn id_source_differs_across_sessions_and_seeds() {
    let mut a = DeterministicIdSource::new(SessionId::new(1), 7);
    let mut b = DeterministicIdSource::new(SessionId::new(2), 7);
    let mut c = DeterministicIdSource::new(SessionId::new(1), 8);
    let x = a.next_transaction_id();
    assert_ne!(x, b.next_transaction_id());
    assert_ne!(x, c.next_transaction_id());
}

#[test]
fn command_ids_are_dense_and_monotonic() {
    let mut s = DeterministicIdSource::new(SessionId::new(9), 0);
    assert_eq!(s.next_command_id().value(), 1);
    assert_eq!(s.next_command_id().value(), 2);
}

#[test]
fn splitmix64_is_deterministic_and_bounded() {
    let mut a = SplitMix64::new(1234);
    let mut b = SplitMix64::new(1234);
    let xs: Vec<u64> = (0..8).map(|_| a.next_u64()).collect();
    let ys: Vec<u64> = (0..8).map(|_| b.next_u64()).collect();
    assert_eq!(xs, ys);
    assert!(xs.windows(2).any(|w| w[0] != w[1]));
    for _ in 0..1000 {
        assert!(a.next_below(10) < 10);
    }
    assert_eq!(a.next_below(0), 0);
    assert_eq!(a.next_below(1), 0);
}
