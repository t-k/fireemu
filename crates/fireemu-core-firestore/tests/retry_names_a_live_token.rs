//! A retry (`retryTransaction`) leaves the token it names alone in the emulator profile, as the official emulator does.
//!
//! Official emulator (firebase-tools 15.28.2, Cloud Firestore Emulator v1.22.0, native gRPC, measured 2026-10-02; rows in
//! docs.local/runs/fs-transaction-p13b-official-emulator-20261002/official-live-named-rows.json): a retry begins a new transaction and does nothing to the token it
//! names. After a retry names a live token that read a document (v=7), the named token still reads (served from its snapshot; a missing document answers 5), still
//! holds its read lock (an outside write of the document, and the retry token's own write of it, answer 10 "Transaction lock timeout." after 2 s), still commits a
//! write (0) and its Rollback releases the lock (0); a second retry naming the same token is accepted again; a committed origin stays committed (a read after the
//! retry answers 10 with the expired text).
//!
//! Strict (production) is not recorded for these shapes and keeps finishing the named attempt at the retry (the tests in store.rs pin that).

use std::collections::BTreeMap;

use fireemu_core_firestore::path::DocumentPath;
use fireemu_core_firestore::store::{FirestoreError, FirestoreState, LimitScope, Write, WriteOp};
use fireemu_core_firestore::value::Value;
use fireemu_core_types::ids::{DatabaseId, ProjectId};
use fireemu_core_types::time::LogicalInstant;

fn path(p: &str) -> DocumentPath {
    DocumentPath::parse(
        &ProjectId::try_new("demo-app").unwrap(),
        &DatabaseId::default_database(),
        p,
    )
    .unwrap()
}

fn t(n: i64) -> LogicalInstant {
    LogicalInstant::from_unix_seconds(1_788_000_000 + n)
}

fn set(p: &str, value: i64) -> Write {
    Write {
        op: WriteOp::Set {
            path: path(p),
            fields: BTreeMap::from([("v".to_owned(), Value::Integer(value))]),
            update_mask: None,
        },
        precondition: None,
        transforms: vec![],
    }
}

fn emulator() -> FirestoreState {
    let mut state = FirestoreState::with_limit_scope(LimitScope::OfficialEmulator);
    state.commit(&[set("live/d", 7)], None, t(0)).unwrap();
    state
}

fn value(
    state: &mut FirestoreState,
    token: &fireemu_core_firestore::store::TransactionId,
) -> Option<Value> {
    state
        .get_in_transaction(token, &path("live/d"))
        .unwrap()
        .and_then(|document| document.fields.get("v").cloned())
}

fn contended<T: std::fmt::Debug>(result: &Result<T, FirestoreError>) {
    assert!(
        matches!(result, Err(FirestoreError::Aborted(_))),
        "a lock timeout: {result:?}"
    );
}

#[test]
fn the_named_live_token_still_reads_and_holds_its_read_lock_after_a_retry() {
    let mut state = emulator();
    let named = state.begin_read_write_transaction(t(1)).unwrap();
    state.touch_transaction(&named, t(2)).unwrap();
    assert_eq!(value(&mut state, &named), Some(Value::Integer(7)));
    let retry = state.retry_transaction(&named, t(3)).unwrap();
    // the named token still reads from its snapshot, and a missing document is a missing document, not an expiry
    state.touch_transaction(&named, t(4)).unwrap();
    assert_eq!(value(&mut state, &named), Some(Value::Integer(7)));
    assert!(state
        .get_in_transaction(&named, &path("live/missing"))
        .unwrap()
        .is_none());
    // its read lock holds against an outside write and against the retry token's own write
    contended(&state.commit(&[set("live/d", 1)], None, t(5)));
    state.touch_transaction(&retry, t(6)).unwrap();
    assert_eq!(value(&mut state, &retry), Some(Value::Integer(7)));
    contended(&state.commit(&[set("live/d", 5)], Some(&retry), t(7)));
    // the Rollback of the named token releases its lock; the retry token read the document too, so its own lock holds until it rolls back
    state.rollback(&named).unwrap();
    contended(&state.commit(&[set("live/d", 1)], None, t(8)));
    state.rollback(&retry).unwrap();
    state.commit(&[set("live/d", 1)], None, t(9)).unwrap();
}

#[test]
fn the_named_live_token_still_commits_and_a_second_retry_naming_it_is_accepted() {
    let mut state = emulator();
    let named = state.begin_read_write_transaction(t(1)).unwrap();
    state.touch_transaction(&named, t(2)).unwrap();
    assert_eq!(value(&mut state, &named), Some(Value::Integer(7)));
    let first = state.retry_transaction(&named, t(3)).unwrap();
    let second = state.retry_transaction(&named, t(4));
    assert!(
        second.is_ok(),
        "a second retry naming the same token: {second:?}"
    );
    assert_ne!(first, second.unwrap());
    // the named token commits its write after the retries, and is finished by that commit
    state
        .commit(&[set("live/d", 99)], Some(&named), t(5))
        .unwrap();
    assert!(state.commit(&[], Some(&named), t(6)).is_err());
}

#[test]
fn a_committed_origin_stays_committed_after_a_retry() {
    let mut state = emulator();
    let named = state.begin_read_write_transaction(t(1)).unwrap();
    state.touch_transaction(&named, t(2)).unwrap();
    state.commit(&[], Some(&named), t(3)).unwrap();
    let retry = state.retry_transaction(&named, t(4)).unwrap();
    assert!(
        state.touch_transaction(&named, t(5)).is_err(),
        "a read of the committed token answers the expiry"
    );
    state.rollback(&named).unwrap();
    state.touch_transaction(&retry, t(6)).unwrap();
    state.rollback(&retry).unwrap();
}

#[test]
fn strict_still_finishes_a_live_token_at_the_retry_that_names_it() {
    let mut state = FirestoreState::with_limit_scope(LimitScope::Production);
    state.commit(&[set("live/d", 7)], None, t(0)).unwrap();
    let named = state.begin_read_write_transaction(t(1)).unwrap();
    state.touch_transaction(&named, t(2)).unwrap();
    assert_eq!(value(&mut state, &named), Some(Value::Integer(7)));
    let retry = state.retry_transaction(&named, t(3)).unwrap();
    // production is not recorded for this shape: the named attempt is abandoned and its lock released, as before
    assert!(state.touch_transaction(&named, t(4)).is_err());
    state.commit(&[set("live/d", 1)], None, t(5)).unwrap();
    state.touch_transaction(&retry, t(6)).unwrap();
    state.rollback(&retry).unwrap();
}

#[test]
fn without_a_retry_the_rollback_of_a_committed_token_still_answers_as_production_recorded() {
    // `finished-token/rollback-after-commit` (production, expiry-retry-04): 10 with the expired text. The emulator profile has always answered it so, and the
    // closure comparison holds it equal to the recording; only a Rollback after a retry named the token is accepted (official emulator, measured 2026-10-02).
    let mut state = emulator();
    let token = state.begin_read_write_transaction(t(1)).unwrap();
    state.touch_transaction(&token, t(2)).unwrap();
    state.commit(&[], Some(&token), t(3)).unwrap();
    let rolled = state.rollback(&token);
    assert!(
        matches!(&rolled, Err(FirestoreError::Aborted(message)) if message == "The referenced transaction has expired or is no longer valid."),
        "{rolled:?}"
    );
}
