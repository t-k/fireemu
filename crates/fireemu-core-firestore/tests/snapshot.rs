//! `SNAP-MEM-01` / `SNAP-MEM-03`: a named snapshot retains the visible state -- the newest
//! version of every live document -- and none of the running session's MVCC history,
//! transactions or tombstones, while staying an exact, isolated copy.

use std::collections::BTreeMap;

use fireemu_core_firestore::path::DocumentPath;
use fireemu_core_firestore::store::{FirestoreError, FirestoreState, Write, WriteOp};
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

fn delete(p: &str) -> Write {
    Write {
        op: WriteOp::Delete { path: path(p) },
        precondition: None,
        transforms: vec![],
    }
}

const T0: LogicalInstant = LogicalInstant::from_nanos(1_788_000_000_000_000_000);

#[test]
fn a_visible_snapshot_retains_one_version_per_live_document() {
    let mut live = FirestoreState::new();
    // 100 updates of one document on a still clock: nothing is compacted, the live store
    // retains the whole history.
    for i in 0..100 {
        live.commit(&[set("items/a", i)], None, T0).unwrap();
    }
    live.commit(&[set("items/b", 1), set("gone/x", 1)], None, T0)
        .unwrap();
    live.commit(&[delete("gone/x")], None, T0).unwrap();
    assert!(live.retained_versions() > 100, "the live history is intact");

    let snapshot = live.visible_snapshot();
    assert_eq!(
        snapshot.retained_versions(),
        2,
        "one version per live document, no tombstones"
    );
    assert_eq!(snapshot.get(&path("items/a")), live.get(&path("items/a")));
    assert_eq!(snapshot.get(&path("items/b")), live.get(&path("items/b")));
    assert_eq!(snapshot.get(&path("gone/x")), None);
    assert_eq!(snapshot.current_version(), live.current_version());

    // The copy is independent: later writes to the live store change nothing in it.
    let before = snapshot.get(&path("items/a")).cloned();
    live.commit(&[set("items/a", 999)], None, T0).unwrap();
    assert_eq!(snapshot.get(&path("items/a")).cloned(), before);
}

#[test]
fn a_restored_snapshot_refuses_history_it_does_not_carry_and_keeps_committing() {
    let mut live = FirestoreState::new();
    let first = live.commit(&[set("items/a", 1)], None, T0).unwrap();
    let early = first.version;
    let early_time = first.commit_time;
    live.commit(&[set("items/a", 2)], None, T0).unwrap();

    let mut snapshot = live.visible_snapshot();
    // Only the snapshot's own version is retained: a resume token or read_time from before
    // it is refused exactly as after a compaction, never served from missing history.
    assert!(snapshot.is_retained(snapshot.current_version()));
    assert!(!snapshot.is_retained(early));
    assert_eq!(snapshot.version_at_retained(early_time), None);
    assert!(matches!(
        snapshot.begin_transaction_at(early_time, T0),
        Err(FirestoreError::FailedPrecondition(_))
    ));

    // Open transactions and their budgets belong to the session, not the snapshot.
    let txn = live.begin_transaction(false, T0).unwrap();
    let copy = live.visible_snapshot();
    assert!(
        matches!(
            copy.transaction_read_time(&txn),
            Err(FirestoreError::InvalidArgument(_))
        ),
        "a live transaction does not exist inside the snapshot"
    );

    // Commits continue after a restore: times stay monotonic and versions move forward.
    let result = snapshot.commit(&[set("items/b", 3)], None, T0).unwrap();
    assert!(result.version > early);
    assert!(result.commit_time.as_nanos() > early_time.as_nanos());
}
