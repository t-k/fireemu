//! MVCC history compaction under the documented retention roots (`FS-MVCC-01` .. `05`):
//! the one-hour `read_time` window, the read version of every active transaction and the
//! newest version or tombstone of every path.

use std::collections::BTreeMap;

use fireemu_core_firestore::path::DocumentPath;
use fireemu_core_firestore::store::{
    CommitVersion, FirestoreError, FirestoreState, HistoryLimits, Precondition, Write, WriteOp,
    READ_TIME_RETENTION_SECONDS,
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

#[test]
fn fixed_clock_unique_path_churn_is_refused_at_the_database_history_budget() {
    let mut state = FirestoreState::with_history_limits(HistoryLimits {
        max_bytes: u64::MAX,
        max_versions: 4,
    });

    state.commit(&[set("docs/a", &[])], None, t(0)).unwrap();
    state.commit(&[delete("docs/a")], None, t(0)).unwrap();
    state.commit(&[set("docs/b", &[])], None, t(0)).unwrap();
    state.commit(&[delete("docs/b")], None, t(0)).unwrap();
    let before = state.history_usage();

    let error = state.commit(&[set("docs/c", &[])], None, t(0)).unwrap_err();

    assert!(matches!(error, FirestoreError::HistoryCapacity(_)));
    assert_eq!(state.history_usage(), before);
    assert!(state.get(&path("docs/c")).is_none());
    assert_eq!(state.retained_versions(), 4);
}

#[test]
fn history_capacity_recovers_after_retention_roots_expire() {
    let mut state = FirestoreState::with_history_limits(HistoryLimits {
        max_bytes: u64::MAX,
        max_versions: 3,
    });
    state.commit(&[set("docs/a", &[])], None, t(0)).unwrap();
    let transaction = state.begin_transaction(true, t(0)).unwrap();
    state.commit(&[set("docs/b", &[])], None, t(0)).unwrap();
    state.commit(&[delete("docs/b")], None, t(0)).unwrap();

    assert!(matches!(
        state.commit(&[set("docs/c", &[])], None, t(0)),
        Err(FirestoreError::HistoryCapacity(_))
    ));
    assert!(state
        .get_in_transaction(&transaction, &path("docs/a"))
        .unwrap()
        .is_some());

    state.rollback(&transaction).unwrap();
    state
        .commit(
            &[set("docs/c", &[])],
            None,
            t(READ_TIME_RETENTION_SECONDS + 1),
        )
        .unwrap();
    assert!(state.history_usage().versions <= 3);
}

#[test]
fn an_aged_cross_path_version_is_forecast_as_reclaimable() {
    let mut state = FirestoreState::with_history_limits(HistoryLimits {
        max_bytes: u64::MAX,
        max_versions: 2,
    });
    state
        .commit(&[set("docs/a", &[("v", Value::Integer(1))])], None, t(0))
        .unwrap();
    state
        .commit(&[set("docs/a", &[("v", Value::Integer(2))])], None, t(1))
        .unwrap();

    state
        .commit(
            &[set("docs/b", &[("v", Value::Integer(3))])],
            None,
            t(READ_TIME_RETENTION_SECONDS + 2),
        )
        .unwrap();

    assert_eq!(state.history_usage().versions, 2);
}

#[test]
fn an_accepted_noop_releases_expired_history() {
    let latest = set("docs/a", &[("v", Value::Integer(2))]);
    let mut state = FirestoreState::new();
    state
        .commit(&[set("docs/a", &[("v", Value::Integer(1))])], None, t(0))
        .unwrap();
    state
        .commit(std::slice::from_ref(&latest), None, t(1))
        .unwrap();
    assert_eq!(state.history_usage().versions, 2);

    let result = state
        .commit(&[latest], None, t(READ_TIME_RETENTION_SECONDS + 2))
        .unwrap();

    assert!(result.changes.is_empty());
    assert_eq!(state.history_usage().versions, 1);
}

#[test]
fn history_byte_budget_refuses_a_multi_write_commit_whole() {
    let first = set("docs/a", &[("v", Value::String("payload".repeat(8)))]);
    let mut probe = FirestoreState::new();
    probe
        .commit(std::slice::from_ref(&first), None, t(0))
        .unwrap();
    let exact_first_commit_bytes = probe.history_usage().total_bytes;
    let mut state = FirestoreState::with_history_limits(HistoryLimits {
        max_bytes: exact_first_commit_bytes,
        max_versions: u64::MAX,
    });
    state.commit(&[first], None, t(0)).unwrap();
    let before = state.history_usage();

    let error = state
        .commit(
            &[
                set("docs/b", &[("v", Value::String("one".into()))]),
                set("docs/c", &[("v", Value::String("two".into()))]),
            ],
            None,
            t(0),
        )
        .unwrap_err();

    assert!(matches!(
        error,
        FirestoreError::HistoryCapacity(ref capacity) if capacity.dimension == "bytes"
    ));
    assert_eq!(state.history_usage(), before);
    assert!(state.get(&path("docs/b")).is_none());
    assert!(state.get(&path("docs/c")).is_none());
}

#[test]
fn a_noop_succeeds_when_the_history_budget_is_full() {
    let write = set("docs/a", &[("v", Value::Integer(1))]);
    let mut state = FirestoreState::with_history_limits(HistoryLimits {
        max_bytes: u64::MAX,
        max_versions: 1,
    });
    state
        .commit(std::slice::from_ref(&write), None, t(0))
        .unwrap();
    let before = state.history_usage();

    let result = state.commit(&[write], None, t(0)).unwrap();

    assert!(result.changes.is_empty());
    assert_eq!(state.history_usage(), before);
}

#[test]
fn a_hot_path_replacement_uses_the_capacity_it_atomically_reclaims() {
    let mut state = FirestoreState::with_history_limits(HistoryLimits {
        max_bytes: u64::MAX,
        max_versions: 1,
    })
    .with_retained_version_limit(1);
    state
        .commit(&[set("docs/a", &[("v", Value::Integer(1))])], None, t(0))
        .unwrap();

    state
        .commit(&[set("docs/a", &[("v", Value::Integer(2))])], None, t(0))
        .unwrap();

    assert_eq!(state.history_usage().versions, 1);
    assert_eq!(
        state
            .get(&path("docs/a"))
            .and_then(|document| document.fields.get("v")),
        Some(&Value::Integer(2))
    );
}

#[test]
fn a_refused_write_does_not_run_expired_history_maintenance() {
    let mut state = FirestoreState::new();
    state.commit(&[set("docs/a", &[])], None, t(0)).unwrap();
    state.commit(&[delete("docs/a")], None, t(1)).unwrap();
    let before = state.history_usage();
    let floor = state.compaction_floor();
    let mut refused = set("docs/a", &[]);
    refused.precondition = Some(Precondition::Exists(true));

    let error = state
        .commit(&[refused], None, t(READ_TIME_RETENTION_SECONDS + 2))
        .unwrap_err();

    assert!(matches!(error, FirestoreError::NotFound(_)));
    assert_eq!(state.history_usage(), before);
    assert_eq!(state.compaction_floor(), floor);
}

fn fields(entries: &[(&str, Value)]) -> BTreeMap<String, Value> {
    entries
        .iter()
        .map(|(k, v)| ((*k).to_owned(), v.clone()))
        .collect()
}

fn t(n: i64) -> LogicalInstant {
    LogicalInstant::from_unix_seconds(1_788_000_000 + n)
}

fn set(p: &str, f: &[(&str, Value)]) -> Write {
    Write {
        op: WriteOp::Set {
            path: path(p),
            fields: fields(f),
            update_mask: None,
        },
        precondition: None,
        transforms: vec![],
    }
}

fn delete(p: &str) -> Write {
    Write {
        op: WriteOp::Delete { path: path(p) },
        precondition: None,
        transforms: vec![],
    }
}

fn write_value(s: &mut FirestoreState, p: &str, v: &str, at: LogicalInstant) -> CommitVersion {
    s.commit(&[set(p, &[("v", Value::String(v.to_owned()))])], None, at)
        .unwrap()
        .version
}

fn value_of(s: &FirestoreState, p: &str, version: CommitVersion) -> Option<String> {
    s.get_at(&path(p), version)
        .map(|d| match d.fields.get("v") {
            Some(Value::String(v)) => v.clone(),
            other => panic!("unexpected field {other:?}"),
        })
}

/// FS-MVCC-01 / FS-MVCC-05: repeated updates of one document keep a bounded number of
/// versions, and the hot path never scans discarded history.
#[test]
fn versions_older_than_every_retention_root_are_compacted() {
    let mut s = FirestoreState::new();
    // One update every minute for three hours.
    for minute in 0..180 {
        write_value(&mut s, "docs/hot", &format!("v{minute}"), t(minute * 60));
    }
    let live = s.get(&path("docs/hot")).unwrap();
    assert_eq!(live.fields.get("v"), Some(&Value::String("v179".into())));
    assert!(
        s.retained_versions() <= 62,
        "the retained window is one hour of commits plus the version it opened with, not the \
         180 lifetime writes: {}",
        s.retained_versions()
    );
    assert!(
        s.compaction_floor() > CommitVersion::default(),
        "the floor advanced past the compacted prefix"
    );
    assert!(
        s.oldest_retained_version().unwrap() >= s.compaction_floor(),
        "nothing below the floor is still stored, except the snapshot the floor itself needs"
    );
    // Reads inside the window are exact; the version the window opened with is retained.
    let now = t(179 * 60);
    let inside = s.version_at_retained(LogicalInstant::from_nanos(
        now.as_nanos() - i128::from(READ_TIME_RETENTION_SECONDS) * 1_000_000_000,
    ));
    assert_eq!(
        value_of(&s, "docs/hot", inside.unwrap()),
        Some("v119".to_owned()),
        "the snapshot one hour ago is still exact"
    );
}

#[test]
fn compacted_tombstones_are_removed_from_scope_indexes() {
    let mut state = FirestoreState::new();
    state.commit(&[set("gone/item", &[])], None, t(0)).unwrap();
    state.commit(&[delete("gone/item")], None, t(1)).unwrap();
    state
        .commit(
            &[set("other/clock", &[])],
            None,
            t(READ_TIME_RETENTION_SECONDS + 2),
        )
        .unwrap();

    let (documents, query_stats) =
        state.list_documents_page_at_with_stats(None, "gone", None, None, 1);
    assert!(documents.is_empty());
    assert_eq!(
        query_stats.scanned, 0,
        "no stale scope-index entry is retained"
    );
}

#[test]
fn a_pinned_clock_uses_the_per_path_capacity_as_an_explicit_retention_root() {
    const LIMIT: usize = 64;
    let mut s = FirestoreState::with_history_version_limit(LIMIT);
    let first = s
        .commit(&[set("docs/hot", &[("v", Value::Integer(0))])], None, t(0))
        .unwrap();

    for value in 1..100_000 {
        s.commit(
            &[set("docs/hot", &[("v", Value::Integer(value))])],
            None,
            t(0),
        )
        .unwrap();
    }

    assert!(s.retained_versions() <= LIMIT, "capacity is a hard root");
    assert!(!s.is_retained(first.version));
    assert_eq!(s.version_at_retained(first.commit_time), None);
    assert!(matches!(
        s.begin_transaction_at(first.commit_time, t(0)),
        Err(FirestoreError::FailedPrecondition(_))
    ));
    assert_eq!(
        s.get(&path("docs/hot"))
            .and_then(|document| document.fields.get("v")),
        Some(&Value::Integer(99_999))
    );
}

#[test]
fn a_pinned_clock_transaction_cannot_bypass_the_history_capacity() {
    let mut s = FirestoreState::with_history_version_limit(4);
    write_value(&mut s, "docs/hot", "first", t(0));
    let transaction = s.begin_transaction(true, t(0)).unwrap();
    s.get_in_transaction(&transaction, &path("docs/hot"))
        .unwrap()
        .unwrap();

    for value in 1..=10 {
        write_value(&mut s, "docs/hot", &format!("v{value}"), t(0));
    }
    assert!(s.retained_versions() <= 4, "capacity is a hard bound");
    assert!(matches!(
        s.get_in_transaction(&transaction, &path("docs/hot")),
        Err(FirestoreError::Aborted(_))
    ));
}

#[test]
fn transaction_capacity_bookkeeping_visits_only_due_deadlines() {
    let mut s = FirestoreState::new();
    for _ in 0..8_192 {
        let transaction = s.begin_transaction(false, t(0)).unwrap();
        s.rollback(&transaction).unwrap();
    }
    for _ in 0..4_096 {
        s.begin_transaction(false, t(0)).unwrap();
    }

    let stats = s.transaction_bookkeeping_stats();
    assert_eq!(stats.active, 4_096);
    assert_eq!(stats.finished, 8_192);
    assert_eq!(stats.deadlines, 4_096);
    assert_eq!(stats.pruned_deadlines, 0);
    assert!(matches!(
        s.begin_transaction(false, t(0)),
        Err(FirestoreError::FailedPrecondition(message))
            if message == "too many active transactions"
    ));
    assert_eq!(
        s.transaction_bookkeeping_stats().pruned_deadlines,
        0,
        "a capacity check does not traverse unrelated transactions"
    );
}

/// FS-MVCC-03: the boundary between retained and compacted history is exact, and a read
/// below it is refused instead of silently answered from another version.
#[test]
fn the_retention_boundary_is_exact_and_older_reads_are_refused() {
    let mut s = FirestoreState::new();
    let v1 = write_value(&mut s, "docs/a", "one", t(0));
    let v2 = write_value(&mut s, "docs/a", "two", t(1_800));
    assert_eq!(s.compaction_floor(), CommitVersion::default());
    // A commit two hours in advances the floor to the version the window opened with.
    let v3 = write_value(&mut s, "docs/a", "three", t(7_200));
    assert_eq!(s.compaction_floor(), v2);

    // Just inside: the start of the window, and the commit time of the retained snapshot.
    assert_eq!(s.version_at_retained(t(3_600)), Some(v2));
    assert_eq!(value_of(&s, "docs/a", v2), Some("two".to_owned()));
    assert_eq!(s.version_at_retained(t(1_800)), Some(v2));
    // Just outside: one nanosecond before the oldest retained snapshot.
    let just_before = LogicalInstant::from_nanos(t(1_800).as_nanos() - 1);
    assert_eq!(s.version_at_retained(just_before), None);
    assert_eq!(s.version_at_retained(t(0)), None);
    assert!(
        !s.is_retained(v1),
        "the first version is gone; a resume token naming it cannot be honoured"
    );
    assert!(s.is_retained(v2) && s.is_retained(v3));

    // A read-only transaction at a compacted read time fails explicitly.
    let err = s.begin_transaction_at(t(0), t(7_200)).unwrap_err();
    assert!(
        matches!(&err, FirestoreError::FailedPrecondition(m) if m == "read_time is no longer retained by this database"),
        "{err}"
    );
    // ... and one inside the window still works.
    let txn = s.begin_transaction_at(t(3_600), t(7_200)).unwrap();
    let doc = s
        .get_in_transaction(&txn, &path("docs/a"))
        .unwrap()
        .unwrap();
    assert_eq!(doc.fields.get("v"), Some(&Value::String("two".into())));
}

/// FS-MVCC-02: a transaction that stays open across compacting commits keeps reading its
/// start snapshot, and the floor never passes the version it reads at.
#[test]
fn an_active_transaction_keeps_its_snapshot_across_compaction() {
    let mut s = FirestoreState::new();
    // Two hours of history, ten seconds apart, so that every further commit compacts.
    for step in 0..=720 {
        write_value(&mut s, "docs/a", &format!("v{step}"), t(step * 10));
    }
    let txn = s.begin_transaction(true, t(7_200)).unwrap();
    let read_version = s.transaction_read_version(&txn).unwrap();
    let observed = s
        .get_in_transaction(&txn, &path("docs/a"))
        .unwrap()
        .unwrap();
    assert_eq!(
        observed.fields.get("v"),
        Some(&Value::String("v720".into()))
    );

    // Three more commits inside the transaction budget, each one compacting.
    let floor_before = s.compaction_floor();
    for step in 1..=3 {
        write_value(
            &mut s,
            "docs/a",
            &format!("later{step}"),
            t(7_200 + step * 15),
        );
    }
    assert!(
        s.compaction_floor() > floor_before,
        "the commits did compact history"
    );
    assert!(
        s.compaction_floor() <= read_version && s.is_retained(read_version),
        "the floor never passes the read version of an open transaction"
    );
    let again = s
        .get_in_transaction(&txn, &path("docs/a"))
        .unwrap()
        .unwrap();
    assert_eq!(
        again, observed,
        "the transaction still observes its start snapshot"
    );
    assert!(
        s.touch_transaction(&txn, t(7_200 + 45)).is_ok(),
        "the transaction is still inside its budget"
    );
}

/// A transaction that outlived its budget can never read again, so it stops being a
/// retention root.
#[test]
fn an_expired_transaction_stops_pinning_history() {
    let mut s = FirestoreState::new();
    let v1 = write_value(&mut s, "docs/a", "one", t(0));
    let txn = s.begin_transaction(true, t(1)).unwrap();
    for minute in 1..=120 {
        write_value(&mut s, "docs/a", &format!("v{minute}"), t(minute * 60));
    }
    assert!(
        !s.is_retained(v1),
        "the transaction budget expired long ago"
    );
    assert!(s.touch_transaction(&txn, t(120 * 60)).is_err());
}

/// The newest version or tombstone of every path survives compaction, and a path whose only
/// remaining version is a compacted tombstone stops costing memory.
#[test]
fn the_newest_version_survives_and_compacted_tombstones_are_dropped() {
    let mut s = FirestoreState::new();
    for i in 0..50 {
        write_value(&mut s, &format!("docs/kept{i}"), "live", t(i));
        write_value(&mut s, &format!("docs/gone{i}"), "temporary", t(i));
    }
    for i in 0..50 {
        s.commit(&[delete(&format!("docs/gone{i}"))], None, t(1_000 + i))
            .unwrap();
    }
    // A commit past the window compacts everything the window no longer covers.
    write_value(&mut s, "docs/last", "now", t(10_000));
    for i in 0..50 {
        assert_eq!(
            value_of(&s, &format!("docs/kept{i}"), s.current_version()),
            Some("live".to_owned()),
            "every live document keeps its newest version"
        );
        assert!(s.get(&path(&format!("docs/gone{i}"))).is_none());
    }
    assert_eq!(
        s.retained_versions(),
        51,
        "50 live documents plus the last write; the deleted ones left nothing behind"
    );
}

/// A named snapshot is an independent clone: compacting the live store never changes it.
#[test]
fn named_snapshots_are_independent_of_live_compaction() {
    let mut s = FirestoreState::new();
    let v1 = write_value(&mut s, "docs/a", "one", t(0));
    write_value(&mut s, "docs/a", "two", t(60));
    let snapshot = s.clone();

    for minute in 2..=120 {
        write_value(&mut s, "docs/a", &format!("v{minute}"), t(minute * 60));
    }
    assert!(!s.is_retained(v1), "the live store compacted v1 away");
    assert!(
        snapshot.is_retained(v1),
        "the snapshot kept the history it captured"
    );
    assert_eq!(value_of(&snapshot, "docs/a", v1), Some("one".to_owned()));
    assert_eq!(
        value_of(&snapshot, "docs/a", snapshot.current_version()),
        Some("two".to_owned()),
        "restoring the snapshot reproduces its exact contents"
    );
}

/// Compaction is a pure function of the commit sequence and the logical times it was given.
#[test]
fn compaction_is_deterministic() {
    let run = || {
        let mut s = FirestoreState::new();
        for minute in 0..90 {
            write_value(&mut s, "docs/a", &format!("v{minute}"), t(minute * 60));
            write_value(&mut s, "docs/b", &format!("v{minute}"), t(minute * 60 + 1));
        }
        (
            s.retained_versions(),
            s.compaction_floor(),
            s.oldest_retained_version(),
            s.oldest_retained_commit_time(),
        )
    };
    assert_eq!(run(), run());
    // An explicit compaction at the same logical time changes nothing further.
    let mut s = FirestoreState::new();
    for minute in 0..90 {
        write_value(&mut s, "docs/a", &format!("v{minute}"), t(minute * 60));
    }
    let before = s.retained_versions();
    let floor = s.compact(t(89 * 60));
    assert_eq!(floor, s.compaction_floor());
    assert_eq!(s.retained_versions(), before);
}
