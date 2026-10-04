//! The first request on a token that idled out answers `INVALID_ARGUMENT` in the emulator profile, as the official emulator does.
//!
//! Official emulator (firebase-tools 15.28.2, Cloud Firestore Emulator v1.22.0, native gRPC, measured 2026-10-02; rows in
//! docs.local/runs/fs-transaction-p13b-official-emulator-20261002/official-idle-{request,boundary,reset,sequence}-rows.json): a read-write token is usable for 60 s
//! after its last request (60 s is accepted, 61 s is not) and every request restarts the clock. The first request that finds it expired (a get, a batch get, a
//! query, a Commit with or without writes, or a Rollback; also a token never touched since its begin) answers `INVALID_ARGUMENT` "The referenced transaction has
//! expired or is no longer valid." and a Commit writes nothing. Afterwards every read and Commit answers `ABORTED` (10) with the same text and a Rollback is accepted.
//!
//! The Rollback row (the first request being a Rollback answers 3, in the official emulator) is its own change; here a Rollback only has to leave the first-request
//! answer used up for the requests after it, as the official emulator does.
//!
//! Strict (production) keeps answering `ABORTED` for the first request on an idle-expired token.

use std::collections::BTreeMap;

use fireemu_core_firestore::path::DocumentPath;
use fireemu_core_firestore::store::{
    FirestoreError, FirestoreState, LimitScope, TransactionId, Write, WriteOp,
};
use fireemu_core_firestore::value::Value;
use fireemu_core_types::ids::{DatabaseId, ProjectId};
use fireemu_core_types::time::LogicalInstant;
use proptest::prelude::*;

const GONE: &str = "The referenced transaction has expired or is no longer valid.";

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

fn seeded(scope: LimitScope) -> (FirestoreState, TransactionId) {
    let mut state = FirestoreState::with_limit_scope(scope);
    state.commit(&[set("idle/d", 7)], None, t(0)).unwrap();
    let token = state.begin_read_write_transaction(t(1)).unwrap();
    state.touch_transaction(&token, t(2)).unwrap();
    (state, token)
}

fn refused_with(result: &Result<(), FirestoreError>, invalid_argument: bool) -> bool {
    match result {
        Err(FirestoreError::InvalidArgument(message)) => invalid_argument && message == GONE,
        Err(FirestoreError::Aborted(message)) => !invalid_argument && message == GONE,
        _ => false,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Request {
    Read,
    CommitWrite,
    CommitEmpty,
    Rollback,
}

fn request(
    state: &mut FirestoreState,
    token: &TransactionId,
    kind: Request,
    at: LogicalInstant,
) -> Result<(), FirestoreError> {
    match kind {
        Request::Read => state.touch_transaction(token, at),
        Request::CommitWrite => state
            .commit(&[set("idle/d", 99)], Some(token), at)
            .map(|_| ()),
        Request::CommitEmpty => state.commit(&[], Some(token), at).map(|_| ()),
        Request::Rollback => state.rollback_at(token, at),
    }
}

#[test]
fn a_token_is_usable_for_60_seconds_after_its_last_request_and_every_request_restarts_the_clock() {
    let (mut state, token) = seeded(LimitScope::OfficialEmulator);
    // 58 s after the begin's read, then 59 s after that one, then 59 s again: each request restarts the clock
    state.touch_transaction(&token, t(60)).unwrap();
    state.touch_transaction(&token, t(119)).unwrap();
    state.touch_transaction(&token, t(178)).unwrap();
    // 61 s of idleness is over the limit
    let late = state.touch_transaction(&token, t(178 + 61));
    assert!(refused_with(&late, true), "{late:?}");
}

#[test]
fn the_first_request_after_an_idle_expiry_answers_invalid_argument_whatever_its_kind() {
    for kind in [
        Request::Read,
        Request::CommitWrite,
        Request::CommitEmpty,
    ] {
        let (mut state, token) = seeded(LimitScope::OfficialEmulator);
        let first = request(&mut state, &token, kind, t(70));
        assert!(refused_with(&first, true), "{kind:?}: {first:?}");
        // the expired Commit wrote nothing
        assert_eq!(
            state
                .get(&path("idle/d"))
                .and_then(|document| document.fields.get("v").cloned()),
            Some(Value::Integer(7)),
            "{kind:?}"
        );
    }
}

#[test]
fn after_the_first_answer_reads_and_commits_answer_aborted_and_a_rollback_is_accepted() {
    for first in [Request::Read, Request::CommitWrite, Request::CommitEmpty] {
        for second in [Request::Read, Request::CommitWrite, Request::CommitEmpty] {
            let (mut state, token) = seeded(LimitScope::OfficialEmulator);
            assert!(refused_with(
                &request(&mut state, &token, first, t(70)),
                true
            ));
            let later = request(&mut state, &token, second, t(71));
            assert!(refused_with(&later, false), "{first:?} then {second:?}: {later:?}");
            let again = request(&mut state, &token, Request::Read, t(72));
            assert!(refused_with(&again, false), "{first:?} then {second:?} twice: {again:?}");
            request(&mut state, &token, Request::Rollback, t(73)).unwrap();
        }
    }
}

#[test]
fn a_token_the_store_already_finished_still_answers_its_first_request_invalid_argument() {
    // another request found the deadline passed first (a begin prunes the finished-by-timeout tokens), no request on this token has been answered yet
    for kind in [Request::Read, Request::CommitWrite, Request::CommitEmpty] {
        let (mut state, token) = seeded(LimitScope::OfficialEmulator);
        let other = state.begin_read_write_transaction(t(70)).unwrap();
        let first = request(&mut state, &token, kind, t(71));
        assert!(refused_with(&first, true), "{kind:?}: {first:?}");
        let second = request(&mut state, &token, kind, t(72));
        assert!(refused_with(&second, false), "{kind:?}: {second:?}");
        // the token begun at 70 is untouched by the other's expiry
        state.touch_transaction(&other, t(73)).unwrap();
    }
}

#[test]
fn a_rollback_uses_up_the_first_answer_so_a_later_read_answers_aborted() {
    for pruned_first in [false, true] {
        let (mut state, token) = seeded(LimitScope::OfficialEmulator);
        if pruned_first {
            state.begin_read_write_transaction(t(70)).unwrap();
        }
        state.rollback_at(&token, t(71)).unwrap();
        let read = request(&mut state, &token, Request::Read, t(72));
        assert!(refused_with(&read, false), "pruned_first {pruned_first}: {read:?}");
        let commit = request(&mut state, &token, Request::CommitEmpty, t(73));
        assert!(refused_with(&commit, false), "pruned_first {pruned_first}: {commit:?}");
        state.rollback_at(&token, t(74)).unwrap();
    }
}

#[test]
fn a_token_never_touched_since_its_begin_is_expired_like_any_other() {
    let mut state = FirestoreState::with_limit_scope(LimitScope::OfficialEmulator);
    let token = state.begin_read_write_transaction(t(1)).unwrap();
    let first = state.touch_transaction(&token, t(70));
    assert!(refused_with(&first, true), "{first:?}");
    let second = state.touch_transaction(&token, t(71));
    assert!(refused_with(&second, false), "{second:?}");
}

#[test]
fn strict_keeps_answering_aborted_to_the_first_request_after_an_idle_expiry() {
    // strict allows 120 s of idleness; 130 s is expired. Production recordings: ABORTED "no longer valid".
    for pruned_first in [false, true] {
        for kind in [Request::Read, Request::CommitWrite, Request::CommitEmpty] {
            let (mut state, token) = seeded(LimitScope::Production);
            if pruned_first {
                state.begin_read_write_transaction(t(130)).unwrap();
            }
            let first = request(&mut state, &token, kind, t(132));
            assert!(
                refused_with(&first, false),
                "{kind:?} pruned_first {pruned_first}: {first:?}"
            );
        }
    }
}

#[test]
fn a_lifetime_expiry_keeps_its_own_answers_in_the_emulator_profile() {
    // official emulator, measured before: after the total lifetime a read answers INVALID_ARGUMENT, a Commit ABORTED, a Rollback is accepted
    let (mut state, token) = seeded(LimitScope::OfficialEmulator);
    for second in (50..270).step_by(50) {
        state.touch_transaction(&token, t(second)).unwrap();
    }
    state.touch_transaction(&token, t(260)).unwrap();
    let commit = request(&mut state, &token, Request::CommitEmpty, t(275));
    assert!(refused_with(&commit, false), "{commit:?}");
    let read = request(&mut state, &token, Request::Read, t(276));
    assert!(refused_with(&read, true), "{read:?}");
    request(&mut state, &token, Request::Rollback, t(277)).unwrap();
}

fn kind_strategy() -> impl Strategy<Value = Request> {
    prop_oneof![
        Just(Request::Read),
        Just(Request::CommitWrite),
        Just(Request::CommitEmpty),
        Just(Request::Rollback),
    ]
}

proptest! {
    /// Every sequence of requests on a token that idled out (a begin in between may have pruned it first) is answered by one table: the first request
    /// answers `INVALID_ARGUMENT` unless it is a Rollback (still accepted here), then reads and commits answer `ABORTED` and a Rollback is accepted.
    #[test]
    fn the_emulator_profile_answers_the_requests_after_an_idle_expiry_by_the_measured_table(
        kinds in proptest::collection::vec(kind_strategy(), 1..8),
        pruned_first in any::<bool>(),
        idle in 61_i64..250,
    ) {
        let (mut state, token) = seeded(LimitScope::OfficialEmulator);
        if pruned_first {
            state.begin_read_write_transaction(t(2 + idle - 1)).unwrap();
        }
        let mut first = true;
        for (index, kind) in kinds.iter().enumerate() {
            let at = t(2 + idle + i64::try_from(index).unwrap());
            let answer = request(&mut state, &token, *kind, at);
            match (*kind, first) {
                (Request::Rollback, _) => prop_assert!(answer.is_ok(), "{kinds:?} #{index}: {answer:?}"),
                (_, true) => prop_assert!(refused_with(&answer, true), "{kinds:?} #{index}: {answer:?}"),
                (_, false) => prop_assert!(refused_with(&answer, false), "{kinds:?} #{index}: {answer:?}"),
            }
            first = false;
        }
        // nothing a refused Commit asked for was written
        prop_assert_eq!(
            state.get(&path("idle/d")).and_then(|document| document.fields.get("v").cloned()),
            Some(Value::Integer(7))
        );
    }

    /// A token touched at least every 59 s is never expired by idleness (the deadline is inclusive at 60 s, as the official emulator's measured 60 s probe,
    /// which really idled a little under 60 s, was accepted), and 61 s after its last request expires it.
    #[test]
    fn the_idle_clock_restarts_at_every_request(gaps in proptest::collection::vec(1_i64..=59, 1..8)) {
        let (mut state, token) = seeded(LimitScope::OfficialEmulator);
        let mut now = 2;
        for gap in &gaps {
            // stay inside the 270 s total lifetime, which is a different expiry (a read after it answers `INVALID_ARGUMENT` as well)
            if now + gap > 260 { break; }
            now += gap;
            prop_assert!(state.touch_transaction(&token, t(now)).is_ok(), "gap {gap} at {now}");
        }
        let late = state.touch_transaction(&token, t(now + 61));
        prop_assert!(refused_with(&late, true), "{late:?}");
    }
}
