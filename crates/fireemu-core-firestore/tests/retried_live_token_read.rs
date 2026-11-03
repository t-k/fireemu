//! A transactional read of a token that a retry (`retryTransaction`) has named.
//!
//! The official emulator (firebase-tools 15.28.2, v1.22.0, native gRPC) serves a read of a token that a retry named while the token
//! was live: the document is read, and a missing one answers `NOT_FOUND`, not an expiry. A read of a token that a retry named after the
//! token had been rolled back answers `ABORTED` (code 10) with the expired text. Strict (production) is not recorded for this shape and
//! keeps its answer, the expired text, for every retried token.

use std::collections::BTreeMap;

use fireemu_core_firestore::path::DocumentPath;
use fireemu_core_firestore::store::{
    FirestoreError, FirestoreState, LimitScope, TransactionId, Write, WriteOp,
};
use fireemu_core_firestore::value::Value;
use fireemu_core_types::ids::{DatabaseId, ProjectId};
use fireemu_core_types::time::LogicalInstant;

const EXPIRED: &str = "The referenced transaction has expired or is no longer valid.";

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

fn state(scope: LimitScope) -> FirestoreState {
    let mut state = FirestoreState::with_limit_scope(scope);
    state.commit(&[set("c/present", 1)], None, t(0)).unwrap();
    state
}

/// The transactional read path an adapter drives: touch (pin the snapshot), then read and record it.
fn read(
    state: &mut FirestoreState,
    token: &TransactionId,
    p: &str,
    at: i64,
) -> Result<Option<i64>, FirestoreError> {
    state.touch_transaction(token, t(at))?;
    state.transaction_read_version(token)?;
    let document = state.get_in_transaction(token, &path(p))?;
    Ok(document.map(|document| match document.fields.get("v") {
        Some(Value::Integer(v)) => *v,
        other => panic!("unexpected field {other:?}"),
    }))
}

fn expired(result: &Result<Option<i64>, FirestoreError>) {
    assert!(
        matches!(result, Err(FirestoreError::Aborted(message)) if message == EXPIRED),
        "{result:?}"
    );
}

/// Begins a read-write token, reads with it, and retries naming it while it is live.
fn retried_live(state: &mut FirestoreState) -> (TransactionId, TransactionId) {
    let token = state.begin_read_write_transaction(t(1)).unwrap();
    assert_eq!(read(state, &token, "c/present", 2).unwrap(), Some(1));
    let retry = state.retry_transaction(&token, t(3)).unwrap();
    (token, retry)
}

#[test]
fn official_emulator_serves_a_read_of_a_token_a_retry_named_while_live() {
    let mut state = state(LimitScope::OfficialEmulator);
    let (token, retry) = retried_live(&mut state);
    assert_eq!(read(&mut state, &token, "c/present", 4).unwrap(), Some(1));
    // A missing document is `NOT_FOUND` (no document), not an expiry.
    assert_eq!(read(&mut state, &token, "c/missing", 5).unwrap(), None);
    // The retry attempt itself is unaffected and commits.
    assert_eq!(read(&mut state, &retry, "c/present", 6).unwrap(), Some(1));
    state
        .commit(&[set("c/present", 2)], Some(&retry), t(7))
        .unwrap();
    // The Rollback exception for a retried token is unchanged.
    state.rollback_at(&token, t(8)).unwrap();
}

#[test]
fn official_emulator_serves_a_retried_live_token_that_had_not_read() {
    let mut state = state(LimitScope::OfficialEmulator);
    let token = state.begin_read_write_transaction(t(1)).unwrap();
    state.retry_transaction(&token, t(2)).unwrap();
    assert_eq!(read(&mut state, &token, "c/present", 3).unwrap(), Some(1));
}

#[test]
fn official_emulator_refuses_a_commit_of_a_retried_live_token() {
    let mut state = state(LimitScope::OfficialEmulator);
    let (token, _) = retried_live(&mut state);
    read(&mut state, &token, "c/present", 4).unwrap();
    let result = state.commit(&[set("c/present", 3)], Some(&token), t(5));
    assert!(
        matches!(&result, Err(FirestoreError::Aborted(message)) if message == EXPIRED),
        "{result:?}"
    );
}

#[test]
fn official_emulator_refuses_a_read_of_a_token_a_retry_named_after_its_rollback() {
    let mut state = state(LimitScope::OfficialEmulator);
    let token = state.begin_read_write_transaction(t(1)).unwrap();
    read(&mut state, &token, "c/present", 2).unwrap();
    state.rollback_at(&token, t(3)).unwrap();
    state.retry_transaction(&token, t(4)).unwrap();
    expired(&read(&mut state, &token, "c/present", 5));
    expired(&read(&mut state, &token, "c/missing", 6));
}

#[test]
fn official_emulator_refuses_a_read_of_a_token_a_retry_named_after_its_commit() {
    let mut state = state(LimitScope::OfficialEmulator);
    let token = state.begin_read_write_transaction(t(1)).unwrap();
    read(&mut state, &token, "c/present", 2).unwrap();
    state
        .commit(&[set("c/present", 2)], Some(&token), t(3))
        .unwrap();
    state.retry_transaction(&token, t(4)).unwrap();
    expired(&read(&mut state, &token, "c/present", 5));
}

#[test]
fn strict_refuses_a_read_of_a_token_a_retry_named_while_live() {
    let mut state = state(LimitScope::Production);
    let (token, _) = retried_live(&mut state);
    expired(&read(&mut state, &token, "c/present", 4));
    expired(&read(&mut state, &token, "c/missing", 5));
}

#[test]
fn strict_refuses_a_read_of_a_token_a_retry_named_after_its_rollback() {
    let mut state = state(LimitScope::Production);
    let token = state.begin_read_write_transaction(t(1)).unwrap();
    read(&mut state, &token, "c/present", 2).unwrap();
    state.rollback_at(&token, t(3)).unwrap();
    state.retry_transaction(&token, t(4)).unwrap();
    expired(&read(&mut state, &token, "c/present", 5));
}

#[test]
fn official_emulator_refuses_a_read_of_a_token_a_retry_named_after_its_idle_expiry() {
    let mut state = state(LimitScope::OfficialEmulator);
    let token = state.begin_read_write_transaction(t(1)).unwrap();
    read(&mut state, &token, "c/present", 2).unwrap();
    // The emulator profile idles a token out after 60 s.
    state.retry_transaction(&token, t(80)).unwrap();
    expired(&read(&mut state, &token, "c/present", 81));
}
