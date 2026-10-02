//! A retry (`retryTransaction`) that names a token production has already expired, and the snapshot a retry attempt reads.
//!
//! Production recordings (FS-TRANSACTION P13b, REST, two agreeing recordings against `fireemu-oracle-txn`):
//! - a retry that names an idle-expired token (130 s idle, token age about 132 s), with no Rollback first, is accepted (0) and mints a new token;
//! - a Rollback of an idle-expired token (idle about 131 s) answers 0, and a retry that names it afterwards is accepted too;
//! - a retry that names a lifetime-expired token (age 280 to 283 s, past the 270 s lifetime and inside the remembered window) is accepted, and the Rollback of that
//!   named token afterwards answers 10 with the expired text, while the Rollback of an idle-expired named token answers 0;
//! - the first read of a retry attempt shows an outside write committed after the retry's begin, so a retry attempt takes its snapshot at its first use, as a plain
//!   read-write begin does, and its Commit is accepted.
//!
//! The official emulator (v1.22.0) is not recorded for a retry of an expired token, so the emulator profile keeps refusing it.

use std::collections::BTreeMap;

use fireemu_core_firestore::path::DocumentPath;
use fireemu_core_firestore::store::{
    FirestoreError, FirestoreState, LimitScope, TransactionId, Write, WriteOp,
};
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

fn strict() -> FirestoreState {
    FirestoreState::with_limit_scope(LimitScope::Production)
}

fn invalid_retry(result: &Result<TransactionId, FirestoreError>) {
    assert!(
        matches!(result, Err(FirestoreError::InvalidArgument(message)) if message == "Invalid transaction."),
        "{result:?}"
    );
}

fn aborted(result: &Result<(), FirestoreError>) {
    assert!(
        matches!(result, Err(FirestoreError::Aborted(message)) if message == "The referenced transaction has expired or is no longer valid."),
        "{result:?}"
    );
}

/// A read-write transaction that has read, so that it idles out at its idle limit (60 s plus the strict allowance of 60 s).
fn read_token(state: &mut FirestoreState, at: i64) -> TransactionId {
    let token = state.begin_read_write_transaction(t(at)).unwrap();
    state.touch_transaction(&token, t(at + 1)).unwrap();
    token
}

#[test]
fn strict_accepts_a_retry_that_names_an_idle_expired_token_and_still_rolls_the_named_token_back() {
    let mut state = strict();
    let token = read_token(&mut state, 0);
    // 132 s after the begin the token has idled out (P13b: the retry answered 0 at about 132 s of age).
    let retry = state.retry_transaction(&token, t(132)).unwrap();
    assert_ne!(retry, token, "the retry mints a token of its own");
    state.touch_transaction(&retry, t(133)).unwrap();
    // The named token is still an idle-expired token whose Rollback is accepted before 270 s (P13b: the chain-end Rollback of it answered 0).
    state.rollback_at(&token, t(140)).unwrap();
    state.rollback_at(&retry, t(141)).unwrap();
}

#[test]
fn strict_accepts_a_retry_after_the_rollback_of_an_idle_expired_token() {
    let mut state = strict();
    let token = read_token(&mut state, 0);
    state.rollback_at(&token, t(131)).unwrap();
    let retry = state.retry_transaction(&token, t(132)).unwrap();
    state.rollback_at(&retry, t(133)).unwrap();
}

#[test]
fn strict_accepts_a_retry_that_names_a_lifetime_expired_token_and_the_named_token_answers_expired()
{
    let mut state = strict();
    let token = state.begin_read_write_transaction(t(0)).unwrap();
    // Keepalive reads every 24 s keep the token past its idle limit; the lifetime ends at 270 s.
    for second in (1..=246).step_by(24) {
        state.touch_transaction(&token, t(second)).unwrap();
    }
    state.touch_transaction(&token, t(247)).unwrap();
    // The first request after the lifetime, at 281 s of age, finds the token expired but remembered (P13b: the retry answered 0 at 280 to 283 s).
    let retry = state.retry_transaction(&token, t(281)).unwrap();
    assert_ne!(retry, token);
    state.touch_transaction(&retry, t(282)).unwrap();
    aborted(&state.rollback_at(&token, t(284)));
    state.rollback_at(&retry, t(285)).unwrap();
}

#[test]
fn strict_refuses_a_retry_that_names_a_token_it_has_forgotten() {
    let mut state = strict();
    let token = read_token(&mut state, 0);
    // The expired token is remembered until about 300 s of token age; far past that it is unknown, like a token never issued.
    invalid_retry(&state.retry_transaction(&token, t(400)));
    invalid_retry(&state.retry_transaction(&TransactionId::from_value(u64::MAX), t(1)));
}

#[test]
fn a_retry_attempt_reads_at_its_first_use_in_strict_and_in_the_emulator_profile() {
    for scope in [LimitScope::Production, LimitScope::OfficialEmulator] {
        let mut state = FirestoreState::with_limit_scope(scope);
        state.commit(&[set("snap/a", 1)], None, t(0)).unwrap();
        let first = state.begin_read_write_transaction(t(1)).unwrap();
        state.touch_transaction(&first, t(2)).unwrap();
        state.rollback(&first).unwrap();
        let retry = state.retry_transaction(&first, t(3)).unwrap();
        // An outside write acknowledged between the retry's begin and its first read is shown by that read, and the retry's Commit is accepted.
        state.commit(&[set("snap/a", 2)], None, t(4)).unwrap();
        state.touch_transaction(&retry, t(5)).unwrap();
        let read = state
            .get_in_transaction(&retry, &path("snap/a"))
            .unwrap()
            .unwrap();
        assert_eq!(read.fields["v"], Value::Integer(2), "{scope:?}");
        state
            .commit(&[set("snap/a", 3)], Some(&retry), t(6))
            .unwrap();
    }
}

#[test]
fn the_emulator_profile_accepts_a_retry_that_names_an_expired_token_like_the_official_emulator() {
    // firebase-tools 15.28.2 (emulator v1.22.0), measured over REST and native gRPC: a retry that names a token idle for 130 s, or kept alive past its 270 s
    // lifetime (282 s of age), answers 0 with a new token, and the new token's Rollback answers 0. The named token stays expired: its first request answers
    // the expiry, a Rollback after that 0.
    for lifetime in [false, true] {
        let mut state = FirestoreState::with_limit_scope(LimitScope::OfficialEmulator);
        let token = state.begin_read_write_transaction(t(0)).unwrap();
        state.touch_transaction(&token, t(1)).unwrap();
        let at = if lifetime {
            for second in (25..=265).step_by(24) {
                state.touch_transaction(&token, t(second)).unwrap();
            }
            282
        } else {
            132
        };
        let retry = state.retry_transaction(&token, t(at));
        assert!(retry.is_ok(), "lifetime={lifetime}: {retry:?}");
        let retry = retry.unwrap();
        assert_ne!(retry, token);
        state.touch_transaction(&retry, t(at + 1)).unwrap();
        state.rollback(&retry).unwrap();
        // the named token still answers as an expired one (the retry did not consume it)
        assert!(state.touch_transaction(&token, t(at + 2)).is_err());
        state.rollback(&token).unwrap();
    }
    // a token it never issued answers the text the official emulator gives (gRPC and REST)
    let mut state = FirestoreState::with_limit_scope(LimitScope::OfficialEmulator);
    invalid_retry(&state.retry_transaction(&TransactionId::from_value(u64::MAX), t(1)));
}

/// Official emulator (firebase-tools 15.28.2, v1.22.0, native gRPC, measured 2026-10-02): after a retry names a token, a Rollback of the named token answers 0
/// whether the token was live, committed or rolled back, and again when repeated; its retry token's Rollback answers 0. Strict (production) keeps its recorded
/// answer for a retried committed token: 10 with the expired text.
#[test]
fn the_emulator_profile_accepts_the_rollback_of_a_token_a_retry_named_in_every_state() {
    for origin in ["live", "committed", "rolled back"] {
        let mut state = FirestoreState::with_limit_scope(LimitScope::OfficialEmulator);
        let token = state.begin_read_write_transaction(t(0)).unwrap();
        state.touch_transaction(&token, t(1)).unwrap();
        match origin {
            "committed" => {
                state.commit(&[], Some(&token), t(2)).unwrap();
            }
            "rolled back" => state.rollback(&token).unwrap(),
            _ => {}
        }
        let retry = state.retry_transaction(&token, t(3)).unwrap();
        assert!(state.rollback(&token).is_ok(), "{origin}: the named token");
        assert!(
            state.rollback(&token).is_ok(),
            "{origin}: the named token again"
        );
        state.touch_transaction(&retry, t(4)).unwrap();
        assert!(state.rollback(&retry).is_ok(), "{origin}: the retry token");
    }
}

#[test]
fn strict_keeps_the_recorded_answer_for_the_rollback_of_a_retried_committed_token() {
    let mut state = strict();
    let token = state.begin_read_write_transaction(t(0)).unwrap();
    state.touch_transaction(&token, t(1)).unwrap();
    state.commit(&[], Some(&token), t(2)).unwrap();
    state.retry_transaction(&token, t(3)).unwrap();
    aborted(&state.rollback(&token));
}
