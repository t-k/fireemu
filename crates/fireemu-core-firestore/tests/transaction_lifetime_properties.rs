//! Property tests of a transaction's lifetime rules against the recorded answer table.
//!
//! Production (strict) rules, recorded in P11 (REST and gRPC), P12, P13a and E003 (see docs/compatibility/fs-transaction-next-campaign-preparation.md):
//! a transaction that ran out of its total lifetime (270 s) or its idle limit (120 s) is remembered until about 300 s of token age and answers every
//! request `ABORTED` "no longer valid" (a read, a Commit, and a Rollback past 270 s) until then; after that every request answers `INVALID_ARGUMENT`
//! "Invalid transaction.". The emulator profile follows the official emulator (v1.22.0): after 270 s a read answers `INVALID_ARGUMENT` with the expired
//! text, a Commit `ABORTED`, and a Rollback is accepted; a live transaction is accepted in both profiles.
//!
//! The generated sequences stay inside what was recorded: a Rollback of a not-yet-noticed idle-expired token before 270 s turns it into a rolled-back
//! transaction whose lineage the code ends at 270 s, which production was not asked about, so it is left out of the generator. Failing cases persist
//! under `proptest-regressions/` and are replayed first on every run.

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
const LIFETIME: i64 = 270;
const FORGOTTEN_AT: i64 = 300;

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
    let mut fields = BTreeMap::new();
    fields.insert("v".to_owned(), Value::Integer(value));
    Write {
        op: WriteOp::Set {
            path: path(p),
            fields,
            update_mask: None,
        },
        precondition: None,
        transforms: vec![],
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Request {
    Read,
    CommitWrite,
    CommitEmpty,
    Rollback,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Answer {
    Accepted,
    /// `ABORTED` with the expired text (production's 10).
    Gone,
    /// `INVALID_ARGUMENT` with the expired text (the emulator profile's answer to a read).
    GoneInvalid,
    /// `INVALID_ARGUMENT` "Invalid transaction." (production's 3: the token is forgotten).
    Forgotten,
    Other(String),
}

fn classify(result: Result<(), FirestoreError>) -> Answer {
    match result {
        Ok(()) => Answer::Accepted,
        Err(FirestoreError::Aborted(message)) if message == GONE => Answer::Gone,
        Err(FirestoreError::InvalidArgument(message)) if message == GONE => Answer::GoneInvalid,
        Err(FirestoreError::InvalidArgument(message)) if message == "Invalid transaction." => {
            Answer::Forgotten
        }
        Err(other) => Answer::Other(format!("{other:?}")),
    }
}

fn send(state: &mut FirestoreState, id: &TransactionId, request: Request, age: i64) -> Answer {
    match request {
        Request::Read => classify(state.touch_transaction(id, t(age))),
        Request::CommitWrite => classify(
            state
                .commit(&[set("prop/doc", age)], Some(id), t(age))
                .map(|_| ()),
        ),
        Request::CommitEmpty => classify(state.commit(&[], Some(id), t(age)).map(|_| ())),
        Request::Rollback => classify(state.rollback_at(id, t(age))),
    }
}

fn seeded(scope: LimitScope) -> (FirestoreState, TransactionId) {
    let mut state = FirestoreState::with_limit_scope(scope);
    state.commit(&[set("prop/doc", 0)], None, t(0)).unwrap();
    let transaction = state.begin_transaction(false, t(0)).unwrap();
    (state, transaction)
}

/// The ages of keepalive reads: gaps of at most `max_gap` seconds, none at or past `limit`.
fn keepalive_ages(gaps: &[i64], limit: i64) -> Vec<i64> {
    let mut age = 0;
    let mut ages = Vec::new();
    for gap in gaps {
        age += gap;
        if age >= limit {
            break;
        }
        ages.push(age);
    }
    ages
}

/// Keepalive ages with random gaps (at most `max_gap`), topped up at the `max_gap` cadence so that the last one is at `end`: the token is never idle for
/// more than `max_gap` seconds before `end`.
fn alive_until(gaps: &[i64], max_gap: i64, end: i64) -> Vec<i64> {
    let mut ages = keepalive_ages(gaps, end - max_gap);
    let mut last = ages.last().copied().unwrap_or(0);
    while last + max_gap < end {
        last += max_gap;
        ages.push(last);
    }
    ages.push(end);
    ages
}

fn any_request() -> impl Strategy<Value = Request> {
    prop_oneof![
        Just(Request::Read),
        Just(Request::CommitWrite),
        Just(Request::CommitEmpty),
        Just(Request::Rollback),
    ]
}

/// What strict answers an expired token (lifetime or idle expiry that a request noticed): 10 until 300 s of token age, 3 after.
fn strict_expired(age: i64) -> Answer {
    if age < FORGOTTEN_AT {
        Answer::Gone
    } else {
        Answer::Forgotten
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// A transaction kept alive past its total lifetime answers every request by the recorded table, whatever mix of reads, commits and rollbacks
    /// asks and however the keepalives were spaced; the answer never goes from 3 back to 10.
    #[test]
    fn strict_a_lifetime_expired_token_answers_by_the_recorded_table(
        gaps in prop::collection::vec(1i64..=24, 0..14),
        first in 270i64..=340,
        requests in prop::collection::vec((any_request(), 0i64..=25), 1..8),
    ) {
        let (mut state, transaction) = seeded(LimitScope::Production);
        for age in keepalive_ages(&gaps, LIFETIME) {
            prop_assert_eq!(classify(state.touch_transaction(&transaction, t(age))), Answer::Accepted, "keepalive at {}", age);
        }
        let mut age = first;
        let mut forgotten = false;
        for (request, gap) in requests {
            age += gap;
            let answer = send(&mut state, &transaction, request, age);
            prop_assert_eq!(&answer, &strict_expired(age), "{:?} at {} s", request, age);
            if answer == Answer::Forgotten {
                forgotten = true;
            } else {
                prop_assert!(!forgotten, "the token answered 10 again after it was forgotten");
            }
        }
    }

    /// A token that idled out is remembered like a lifetime-expired one (P13a), a Rollback of it before 270 s is accepted once a request has noticed
    /// the expiry (E003 recorded the first request at about 121 s), from 270 s it answers 10 like any request, and from 300 s everything answers 3.
    #[test]
    fn strict_an_idle_expired_token_answers_by_the_recorded_table(
        gaps in prop::collection::vec(1i64..=100, 0..3),
        silence in 121i64..=170,
        requests in prop::collection::vec((any_request(), 0i64..=60), 1..8),
    ) {
        let (mut state, transaction) = seeded(LimitScope::Production);
        let mut last = 0;
        for age in keepalive_ages(&gaps, LIFETIME) {
            prop_assert_eq!(classify(state.touch_transaction(&transaction, t(age))), Answer::Accepted, "keepalive at {}", age);
            last = age;
        }
        let mut age = last + silence;
        let mut noticed = false;
        for (request, gap) in requests {
            age += gap;
            // a Rollback of a token no request noticed, before 270 s, is outside what was recorded
            let request = if request == Request::Rollback && age < LIFETIME && !noticed { Request::Read } else { request };
            let expected = match request {
                Request::Rollback if age < LIFETIME => Answer::Accepted,
                _ => strict_expired(age),
            };
            let answer = send(&mut state, &transaction, request, age);
            prop_assert_eq!(&answer, &expected, "{:?} at {} s", request, age);
            if answer != Answer::Accepted || request != Request::Rollback {
                noticed = true;
            }
        }
    }

    /// A retry that names an idle-expired token is accepted while the token is remembered (P13b: 132 s of age) and mints a token of its own that a
    /// request accepts; the named token still answers a Rollback before 270 s with 0 (P13b: the chain-end Rollback). Past the memory (300 s) the
    /// named token is unknown and the retry is refused like one never issued.
    #[test]
    fn strict_a_retry_of_an_idle_expired_token_follows_the_remembered_window(
        retry_at in 125i64..=265,
        forgotten_at in 320i64..=900,
    ) {
        let (mut state, transaction) = seeded(LimitScope::Production);
        let retry = state.retry_transaction(&transaction, t(retry_at));
        prop_assert!(retry.is_ok(), "retry at {} s: {:?}", retry_at, retry);
        let retry = retry.unwrap();
        prop_assert_ne!(&retry, &transaction);
        prop_assert_eq!(classify(state.touch_transaction(&retry, t(retry_at + 1))), Answer::Accepted);
        prop_assert!(state.rollback_at(&transaction, t(retry_at + 2)).is_ok(), "the named idle-expired token still rolls back");
        prop_assert!(state.rollback_at(&retry, t(retry_at + 3)).is_ok());
        let (mut late, transaction) = seeded(LimitScope::Production);
        let result = late.retry_transaction(&transaction, t(forgotten_at));
        prop_assert!(
            matches!(&result, Err(FirestoreError::InvalidArgument(message)) if message == "Invalid transaction."),
            "retry at {} s: {:?}", forgotten_at, result
        );
    }

    /// A retry that names a lifetime-expired token is accepted while the token is remembered (P13b: 280 to 283 s of age); the named token then answers a
    /// Rollback with 10 and the expired text, as without the retry; far past the memory the retry is refused.
    #[test]
    fn strict_a_retry_of_a_lifetime_expired_token_follows_the_remembered_window(
        gaps in prop::collection::vec(1i64..=24, 0..14),
        retry_at in 272i64..=297,
        forgotten_at in 320i64..=900,
    ) {
        let (mut state, transaction) = seeded(LimitScope::Production);
        for age in keepalive_ages(&gaps, LIFETIME) {
            prop_assert_eq!(classify(state.touch_transaction(&transaction, t(age))), Answer::Accepted, "keepalive at {}", age);
        }
        let mut twin = state.clone();
        let retry = state.retry_transaction(&transaction, t(retry_at));
        prop_assert!(retry.is_ok(), "retry at {} s: {:?}", retry_at, retry);
        let retry = retry.unwrap();
        prop_assert_eq!(classify(state.touch_transaction(&retry, t(retry_at + 1))), Answer::Accepted);
        let rolled = state.rollback_at(&transaction, t(retry_at + 2));
        prop_assert!(
            matches!(&rolled, Err(FirestoreError::Aborted(message)) if message == GONE),
            "the named token answers 10 at {} s: {:?}", retry_at + 2, rolled
        );
        prop_assert!(state.rollback_at(&retry, t(retry_at + 3)).is_ok());
        let result = twin.retry_transaction(&transaction, t(forgotten_at));
        prop_assert!(
            matches!(&result, Err(FirestoreError::InvalidArgument(message)) if message == "Invalid transaction."),
            "retry at {} s: {:?}", forgotten_at, result
        );
    }

    /// The emulator profile answers the order the official emulator was measured in (a read, a Commit, a Rollback after 270 s) as the official
    /// emulator does, at any ages inside its retention, and accepts every request of a live transaction.
    #[test]
    fn emulator_profile_answers_the_measured_order_like_the_official_emulator(
        gaps in prop::collection::vec(1i64..=55, 0..8),
        first in 271i64..=325,
        second_gap in 0i64..=100,
        third_gap in 0i64..=100,
    ) {
        let (mut state, transaction) = seeded(LimitScope::OfficialEmulator);
        // alive (idle at most 55 s) until 265 s, as the official emulator's lifetime probe kept its transaction
        for age in alive_until(&gaps, 55, 265) {
            prop_assert_eq!(classify(state.touch_transaction(&transaction, t(age))), Answer::Accepted, "keepalive at {}", age);
        }
        let read_age = first;
        let commit_age = read_age + second_gap;
        let rollback_age = commit_age + third_gap;
        prop_assert_eq!(send(&mut state, &transaction, Request::Read, read_age), Answer::GoneInvalid);
        prop_assert_eq!(send(&mut state, &transaction, Request::CommitWrite, commit_age), Answer::Gone);
        prop_assert_eq!(send(&mut state, &transaction, Request::Rollback, rollback_age), Answer::Accepted);
    }

    /// Neither profile refuses a live transaction: reads inside the idle limit, then a commit before the lifetime, are accepted.
    #[test]
    fn both_profiles_accept_a_live_transaction(
        strict in any::<bool>(),
        gaps in prop::collection::vec(1i64..=55, 0..12),
        commit in prop::bool::ANY,
    ) {
        let scope = if strict { LimitScope::Production } else { LimitScope::OfficialEmulator };
        let (mut state, transaction) = seeded(scope);
        let ages = keepalive_ages(&gaps, LIFETIME);
        for age in &ages {
            prop_assert_eq!(classify(state.touch_transaction(&transaction, t(*age))), Answer::Accepted, "keepalive at {}", age);
        }
        let last = ages.last().copied().unwrap_or(0);
        let end = (last + 1).min(LIFETIME - 1);
        let answer = if commit { send(&mut state, &transaction, Request::CommitWrite, end) } else { send(&mut state, &transaction, Request::Rollback, end) };
        prop_assert_eq!(answer, Answer::Accepted);
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4))]

    /// A flood of finished transactions never makes production forget a still-remembered expired token early.
    #[test]
    fn strict_a_flood_of_finished_transactions_does_not_end_the_memory_early(
        flood in prop::sample::select(vec![0usize, 8_300, 9_100]),
        probe in 271i64..=299,
    ) {
        let (mut state, transaction) = seeded(LimitScope::Production);
        prop_assert_eq!(send(&mut state, &transaction, Request::Read, 271), Answer::Gone);
        for _ in 0..flood {
            let other = state.begin_transaction(false, t(272)).unwrap();
            state.rollback_at(&other, t(272)).unwrap();
        }
        prop_assert_eq!(send(&mut state, &transaction, Request::Read, probe), Answer::Gone);
        prop_assert_eq!(send(&mut state, &transaction, Request::Read, FORGOTTEN_AT), Answer::Forgotten);
    }
}

/// Fixed regression cases at the edges the properties explore (kept beside the generated seeds in `proptest-regressions/`).
#[test]
fn the_edges_of_the_recorded_table_hold() {
    for (age, expected) in [
        (269, Answer::Accepted),
        (270, Answer::Gone),
        (299, Answer::Gone),
        (300, Answer::Forgotten),
    ] {
        let (mut state, transaction) = seeded(LimitScope::Production);
        // keep it alive until just before the age asked about
        let mut keep = 24;
        while keep < age.min(269) {
            state.touch_transaction(&transaction, t(keep)).unwrap();
            keep += 24;
        }
        let answer = send(&mut state, &transaction, Request::Read, age);
        assert_eq!(answer, expected, "read at {age} s");
    }
}
