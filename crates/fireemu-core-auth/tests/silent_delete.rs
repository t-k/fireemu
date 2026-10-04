#![allow(missing_docs)]
//! A bulk delete (`deleteUsers`) removes users without a lifecycle event; a single delete announces
//! its user. Production does not fire the v1 `onDelete` trigger for `deleteUsers`.

use fireemu_core_auth::mfa::TotpPolicy;
use fireemu_core_auth::store::{AuthError, AuthStore, NewUser, UserEventKind};
use fireemu_core_types::determinism::SplitMix64;
use fireemu_core_types::time::LogicalInstant;
use proptest::prelude::*;

const NOW: LogicalInstant = LogicalInstant::UNIX_EPOCH;

fn store() -> AuthStore {
    AuthStore::new("demo-app", SplitMix64::new(7), TotpPolicy::default())
}

#[test]
fn a_silent_delete_removes_the_user_and_records_no_event() {
    let mut store = store();
    let uid = store
        .create_user(NewUser::email("gone@example.test"), NOW)
        .unwrap();
    let _ = store.take_user_events();
    store.delete_user_by_id_without_event(uid.as_str()).unwrap();
    assert!(store.user_by_id(uid.as_str()).is_none());
    assert!(store.user_by_email("gone@example.test").is_none());
    assert!(store.take_user_events().is_empty());
    assert_eq!(
        store.delete_user_by_id_without_event(uid.as_str()),
        Err(AuthError::UserNotFound),
        "an unknown id is still refused"
    );
}

#[test]
fn a_single_delete_still_announces_the_user_as_it_was() {
    let mut store = store();
    let uid = store
        .create_user(NewUser::email("seen@example.test"), NOW)
        .unwrap();
    let _ = store.take_user_events();
    store.delete_user_by_id(uid.as_str()).unwrap();
    let events = store.take_user_events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].kind, UserEventKind::Deleted);
    assert_eq!(events[0].user.local_id, uid);
    assert_eq!(events[0].user.email.as_deref(), Some("seen@example.test"));
}

proptest! {
    /// Whatever subset of users is deleted silently, the store ends in the same state as if
    /// they were deleted normally, and the events are exactly those of the normal deletes, in
    /// the order they were made.
    #[test]
    fn silent_and_announced_deletes_leave_the_same_store_and_only_the_latter_announce(
        silent in proptest::collection::vec(any::<bool>(), 1..12),
        order_seed in any::<u64>(),
    ) {
        let (mut quiet, mut loud) = (store(), store());
        let mut uids = Vec::new();
        for index in 0..silent.len() {
            let email = format!("user{index}@example.test");
            let a = quiet.create_user(NewUser::email(&email), NOW).unwrap();
            let b = loud.create_user(NewUser::email(&email), NOW).unwrap();
            prop_assert_eq!(a.as_str(), b.as_str());
            uids.push(a);
        }
        let _ = quiet.take_user_events();
        let _ = loud.take_user_events();
        // Delete in a seed-dependent order.
        let mut order: Vec<usize> = (0..silent.len()).collect();
        let mut state = order_seed;
        for i in (1..order.len()).rev() {
            state = state.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
            order.swap(i, (state >> 33) as usize % (i + 1));
        }
        let mut expected = Vec::new();
        for &index in &order {
            let uid = uids[index].as_str();
            if silent[index] {
                quiet.delete_user_by_id_without_event(uid).unwrap();
            } else {
                quiet.delete_user_by_id(uid).unwrap();
                expected.push(uid.to_owned());
            }
            loud.delete_user_by_id(uid).unwrap();
        }
        let announced: Vec<String> = quiet
            .take_user_events()
            .into_iter()
            .map(|event| {
                assert_eq!(event.kind, UserEventKind::Deleted);
                event.user.local_id.as_str().to_owned()
            })
            .collect();
        prop_assert_eq!(announced, expected);
        prop_assert_eq!(quiet.user_count(), 0);
        prop_assert_eq!(loud.user_count(), 0);
        for index in 0..silent.len() {
            let email = format!("user{index}@example.test");
            prop_assert!(quiet.user_by_email(&email).is_none());
            prop_assert!(loud.user_by_email(&email).is_none());
        }
    }
}
