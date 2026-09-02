//! Local Firestore execution: commits, preconditions, masks, transforms, atomic rejection.

use std::collections::BTreeMap;

use fireemu_core_firestore::field_path::FieldPath;
use fireemu_core_firestore::path::DocumentPath;
use fireemu_core_firestore::store::{
    CommitVersion, FieldTransform, FirestoreError, FirestoreState, Precondition, TransformKind,
    Write, WriteOp, MAX_TRANSACTION_CONFLICT_LEDGER_BYTES, MAX_TRANSACTION_QUERY_RECORDS,
};
use fireemu_core_firestore::value::Value;
use fireemu_core_types::ids::{DatabaseId, ProjectId};
use fireemu_core_types::time::{LogicalDuration, LogicalInstant};

fn path(p: &str) -> DocumentPath {
    DocumentPath::parse(
        &ProjectId::try_new("demo-app").unwrap(),
        &DatabaseId::default_database(),
        p,
    )
    .unwrap()
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

#[test]
fn create_read_update_delete_with_versions_and_times() {
    let mut s = FirestoreState::new();
    let r = s
        .commit(
            &[set(
                "users/alice",
                &[("name", Value::String("Alice".into()))],
            )],
            None,
            t(0),
        )
        .unwrap();
    assert_eq!(r.commit_time, t(0));
    assert_eq!(r.write_results.len(), 1);
    let doc = s.get(&path("users/alice")).unwrap();
    assert_eq!(doc.create_time, t(0));
    assert_eq!(doc.update_time, t(0));
    assert_eq!(doc.fields.get("name"), Some(&Value::String("Alice".into())));
    let v1 = doc.version;

    s.commit(
        &[set(
            "users/alice",
            &[("name", Value::String("Alicia".into()))],
        )],
        None,
        t(5),
    )
    .unwrap();
    let doc = s.get(&path("users/alice")).unwrap();
    assert_eq!(doc.create_time, t(0), "create time survives updates");
    assert_eq!(doc.update_time, t(5));
    assert!(doc.version > v1);
    assert!(doc.fields.get("name") == Some(&Value::String("Alicia".into())));

    s.commit(
        &[Write {
            op: WriteOp::Delete {
                path: path("users/alice"),
            },
            precondition: None,
            transforms: vec![],
        }],
        None,
        t(6),
    )
    .unwrap();
    assert!(s.get(&path("users/alice")).is_none());
    // Deleting a missing document is a no-op success.
    assert!(s
        .commit(
            &[Write {
                op: WriteOp::Delete {
                    path: path("users/alice")
                },
                precondition: None,
                transforms: vec![]
            }],
            None,
            t(7)
        )
        .is_ok());
}

#[test]
fn preconditions_map_to_the_documented_errors() {
    let mut s = FirestoreState::new();
    let create = Write {
        op: WriteOp::Set {
            path: path("c/d"),
            fields: fields(&[]),
            update_mask: None,
        },
        precondition: Some(Precondition::Exists(false)),
        transforms: vec![],
    };
    s.commit(std::slice::from_ref(&create), None, t(0)).unwrap();
    assert!(matches!(
        s.commit(&[create], None, t(1)),
        Err(FirestoreError::AlreadyExists(_))
    ));
    let update_missing = Write {
        op: WriteOp::Set {
            path: path("c/missing"),
            fields: fields(&[]),
            update_mask: Some(vec![]),
        },
        precondition: Some(Precondition::Exists(true)),
        transforms: vec![],
    };
    assert!(matches!(
        s.commit(&[update_missing], None, t(2)),
        Err(FirestoreError::NotFound(_))
    ));
    let stale = Write {
        op: WriteOp::Set {
            path: path("c/d"),
            fields: fields(&[]),
            update_mask: None,
        },
        precondition: Some(Precondition::UpdateTime(t(99))),
        transforms: vec![],
    };
    assert!(matches!(
        s.commit(&[stale], None, t(3)),
        Err(FirestoreError::FailedPrecondition(_))
    ));
    let fresh = Write {
        op: WriteOp::Set {
            path: path("c/d"),
            fields: fields(&[("x", Value::Integer(1))]),
            update_mask: None,
        },
        precondition: Some(Precondition::UpdateTime(t(0))),
        transforms: vec![],
    };
    assert!(s.commit(&[fresh], None, t(4)).is_ok());
}

#[test]
fn update_mask_merges_nested_fields_and_deletes_masked_absent_fields() {
    let mut s = FirestoreState::new();
    let mut address = BTreeMap::new();
    address.insert("city".to_owned(), Value::String("Tokyo".into()));
    address.insert("zip".to_owned(), Value::String("100".into()));
    s.commit(
        &[set(
            "u/a",
            &[
                ("name", Value::String("A".into())),
                ("address", Value::Map(address)),
                ("age", Value::Integer(1)),
            ],
        )],
        None,
        t(0),
    )
    .unwrap();
    let mut new_address = BTreeMap::new();
    new_address.insert("city".to_owned(), Value::String("Osaka".into()));
    let masked = Write {
        op: WriteOp::Set {
            path: path("u/a"),
            fields: fields(&[("address", Value::Map(new_address))]),
            update_mask: Some(vec![
                FieldPath::parse("address.city").unwrap(),
                FieldPath::parse("age").unwrap(),
            ]),
        },
        precondition: None,
        transforms: vec![],
    };
    s.commit(&[masked], None, t(1)).unwrap();
    let doc = s.get(&path("u/a")).unwrap();
    assert_eq!(
        doc.fields.get("name"),
        Some(&Value::String("A".into())),
        "unmasked fields are kept"
    );
    assert!(
        !doc.fields.contains_key("age"),
        "masked field absent from data is deleted"
    );
    match doc.fields.get("address") {
        Some(Value::Map(m)) => {
            assert_eq!(m.get("city"), Some(&Value::String("Osaka".into())));
            assert_eq!(
                m.get("zip"),
                Some(&Value::String("100".into())),
                "sibling nested field survives"
            );
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn field_transforms_apply_after_the_write_with_the_commit_time() {
    let mut s = FirestoreState::new();
    s.commit(
        &[set(
            "t/d",
            &[
                ("n", Value::Integer(1)),
                ("tags", Value::Array(vec![Value::String("a".into())])),
                ("m", Value::Integer(5)),
            ],
        )],
        None,
        t(0),
    )
    .unwrap();
    let w = Write {
        op: WriteOp::Set {
            path: path("t/d"),
            fields: fields(&[]),
            update_mask: Some(vec![]),
        },
        precondition: Some(Precondition::Exists(true)),
        transforms: vec![
            FieldTransform {
                field: FieldPath::parse("n").unwrap(),
                kind: TransformKind::Increment(Value::Integer(2)),
            },
            FieldTransform {
                field: FieldPath::parse("updatedAt").unwrap(),
                kind: TransformKind::ServerTimestamp,
            },
            FieldTransform {
                field: FieldPath::parse("tags").unwrap(),
                kind: TransformKind::AppendMissingElements(vec![
                    Value::String("a".into()),
                    Value::String("b".into()),
                ]),
            },
            FieldTransform {
                field: FieldPath::parse("tags").unwrap(),
                kind: TransformKind::RemoveAllFromArray(vec![Value::String("a".into())]),
            },
            FieldTransform {
                field: FieldPath::parse("m").unwrap(),
                kind: TransformKind::Maximum(Value::Integer(3)),
            },
            FieldTransform {
                field: FieldPath::parse("m").unwrap(),
                kind: TransformKind::Minimum(Value::Integer(4)),
            },
            FieldTransform {
                field: FieldPath::parse("nested.counter").unwrap(),
                kind: TransformKind::Increment(Value::Double(1.5)),
            },
        ],
    };
    let r = s.commit(&[w], None, t(10)).unwrap();
    assert_eq!(r.write_results[0].transform_results.len(), 7);
    let doc = s.get(&path("t/d")).unwrap();
    assert_eq!(doc.fields.get("n"), Some(&Value::Integer(3)));
    assert_eq!(
        doc.fields.get("tags"),
        Some(&Value::Array(vec![Value::String("b".into())]))
    );
    assert_eq!(doc.fields.get("m"), Some(&Value::Integer(4)));
    let ts = match doc.fields.get("updatedAt") {
        Some(Value::Timestamp(ts)) => *ts,
        other => panic!("{other:?}"),
    };
    assert_eq!(ts.seconds(), 1_788_000_010);
    match doc.fields.get("nested") {
        Some(Value::Map(m)) => assert_eq!(m.get("counter"), Some(&Value::Double(1.5))),
        other => panic!("{other:?}"),
    }
    // Increment on a non-numeric field replaces it (documented behaviour).
    let w = Write {
        op: WriteOp::Set {
            path: path("t/d"),
            fields: fields(&[("s", Value::String("x".into()))]),
            update_mask: Some(vec![FieldPath::parse("s").unwrap()]),
        },
        precondition: None,
        transforms: vec![FieldTransform {
            field: FieldPath::parse("s").unwrap(),
            kind: TransformKind::Increment(Value::Integer(1)),
        }],
    };
    s.commit(&[w], None, t(11)).unwrap();
    assert_eq!(
        s.get(&path("t/d")).unwrap().fields.get("s"),
        Some(&Value::Integer(1))
    );
}

#[test]
fn limit_violations_reject_the_whole_commit_atomically() {
    let mut s = FirestoreState::new();
    s.commit(&[set("a/1", &[("k", Value::Integer(1))])], None, t(0))
        .unwrap();
    let too_big = Value::String("x".repeat(1_048_576));
    let writes = vec![
        set("a/1", &[("k", Value::Integer(2))]),
        set("a/2", &[("blob", too_big)]),
    ];
    match s.commit(&writes, None, t(1)) {
        Err(FirestoreError::ResourceExhausted(v)) => {
            assert_eq!(v.limit_id, "FS-LIMIT-DOCUMENT-BYTES");
        }
        other => panic!("{other:?}"),
    }
    // INV-LIMIT-001: the first write must not have been applied.
    assert_eq!(
        s.get(&path("a/1")).unwrap().fields.get("k"),
        Some(&Value::Integer(1))
    );
    assert!(s.get(&path("a/2")).is_none());
    // Nesting depth 21 is rejected too.
    let mut v = Value::Integer(0);
    for _ in 0..21 {
        v = Value::Array(vec![v]);
    }
    assert!(matches!(
        s.commit(&[set("a/3", &[("deep", v)])], None, t(2)),
        Err(FirestoreError::ResourceExhausted(_))
    ));
    let many: Vec<FieldTransform> = (0..501)
        .map(|i| FieldTransform {
            field: FieldPath::parse(&format!("f{i}")).unwrap(),
            kind: TransformKind::Increment(Value::Integer(1)),
        })
        .collect();
    let w = Write {
        op: WriteOp::Set {
            path: path("a/4"),
            fields: fields(&[]),
            update_mask: None,
        },
        precondition: None,
        transforms: many,
    };
    assert!(
        matches!(s.commit(&[w], None, t(3)), Err(FirestoreError::ResourceExhausted(v)) if v.limit_id == "FS-LIMIT-FIELD-TRANSFORMS-PER-DOCUMENT")
    );
}

#[test]
fn a_concurrent_write_invalidates_the_transaction_read_set() {
    let mut s = FirestoreState::new();
    s.commit(
        &[set("acct/a", &[("balance", Value::Integer(100))])],
        None,
        t(0),
    )
    .unwrap();
    let txn = s.begin_transaction(false, t(1)).unwrap();
    let doc = s
        .get_in_transaction(&txn, &path("acct/a"))
        .unwrap()
        .unwrap();
    assert_eq!(doc.fields.get("balance"), Some(&Value::Integer(100)));
    s.commit(
        &[set("acct/a", &[("balance", Value::Integer(90))])],
        None,
        t(2),
    )
    .unwrap();
    assert_eq!(
        s.get(&path("acct/a")).unwrap().fields.get("balance"),
        Some(&Value::Integer(90)),
        "the independent write commits immediately"
    );
    let write = set("acct/a", &[("balance", Value::Integer(80))]);
    assert!(matches!(
        s.commit(std::slice::from_ref(&write), Some(&txn), t(3)),
        Err(FirestoreError::Aborted(_))
    ));
    assert_eq!(
        s.get(&path("acct/a")).unwrap().fields.get("balance"),
        Some(&Value::Integer(90)),
        "an aborted attempt publishes none of its writes"
    );
    // A finished transaction is ABORTED on reuse, the code the SDKs retry on and the one the
    // official emulator answers (conformance/src/firestore-probe, transactions/lifecycle).
    assert!(
        matches!(
            s.commit(std::slice::from_ref(&write), Some(&txn), t(5)),
            Err(FirestoreError::Aborted(_))
        ),
        "a finished transaction cannot be reused"
    );

    // A missing-document read conflicts with a later create.
    let txn3 = s.begin_transaction(false, t(6)).unwrap();
    let _ = s.get_in_transaction(&txn3, &path("acct/missing")).unwrap();
    s.commit(&[set("acct/missing", &[("x", Value::Null)])], None, t(7))
        .unwrap();
    assert!(s.commit(&[set("acct/other", &[])], None, t(8)).is_ok());
    assert!(matches!(
        s.commit(&[set("acct/txn", &[])], Some(&txn3), t(9)),
        Err(FirestoreError::Aborted(_))
    ));

    let ro = s.begin_transaction(true, t(10)).unwrap();
    assert!(matches!(
        s.commit(&[set("acct/a", &[])], Some(&ro), t(11)),
        Err(FirestoreError::InvalidArgument(_))
    ));
    s.rollback(&ro).unwrap();
    assert!(s.rollback(&ro).is_err());
}

#[test]
fn a_rolled_back_read_write_transaction_can_seed_one_retry() {
    let mut state = FirestoreState::new();
    let original = state.begin_transaction(false, t(0)).unwrap();
    state.rollback(&original).unwrap();

    let retry = state.retry_transaction(&original, t(1)).unwrap();
    assert_ne!(retry, original);
    assert!(matches!(
        state.retry_transaction(&original, t(2)),
        Err(FirestoreError::InvalidArgument(_))
    ));
}

#[test]
fn finished_retry_lineage_expires_at_the_original_total_deadline() {
    let mut before = FirestoreState::new();
    let original = before.begin_transaction(false, t(0)).unwrap();
    before.rollback(&original).unwrap();
    assert!(before.retry_transaction(&original, t(269)).is_ok());

    for elapsed in [270, 271] {
        let mut expired = FirestoreState::new();
        let original = expired.begin_transaction(false, t(0)).unwrap();
        expired.rollback(&original).unwrap();
        assert!(matches!(
            expired.retry_transaction(&original, t(elapsed)),
            Err(FirestoreError::InvalidArgument(message))
                if message == "Invalid retry transaction."
        ));
    }
}

#[test]
fn transaction_snapshot_reads_are_stable() {
    let mut s = FirestoreState::new();
    s.commit(&[set("k/1", &[("v", Value::Integer(1))])], None, t(0))
        .unwrap();
    let txn = s.begin_transaction(true, t(1)).unwrap();
    s.commit(&[set("k/1", &[("v", Value::Integer(2))])], None, t(2))
        .unwrap();
    let seen = s.get_in_transaction(&txn, &path("k/1")).unwrap().unwrap();
    assert_eq!(
        seen.fields.get("v"),
        Some(&Value::Integer(1)),
        "reads see the snapshot at transaction start"
    );
    let latest = s.get(&path("k/1")).unwrap();
    assert_eq!(latest.fields.get("v"), Some(&Value::Integer(2)));
    // Transactions time out after 270 s of logical time (FS-LIMIT-TRANSACTION-TOTAL-TIME).
    let late = t(1)
        .checked_add(LogicalDuration::from_seconds(271))
        .unwrap();
    assert!(matches!(
        s.get_in_transaction(&txn, &path("k/1")).map(|_| ()),
        Ok(())
    ));
    // A transaction past its total budget is ABORTED, as the SDKs expect.
    assert!(matches!(
        s.commit(&[], Some(&txn), late),
        Err(FirestoreError::Aborted(_))
    ));
}

#[test]
fn list_documents_and_collection_ids() {
    let mut s = FirestoreState::new();
    for p in [
        "users/b",
        "users/a",
        "users/a/posts/p1",
        "users/a/notes/n1",
        "rooms/r1",
    ] {
        s.commit(&[set(p, &[("x", Value::Null)])], None, t(0))
            .unwrap();
    }
    let root = s.list_collection_ids(None);
    assert_eq!(root, vec!["rooms", "users"]);
    let under_a = s.list_collection_ids(Some(&path("users/a")));
    assert_eq!(under_a, vec!["notes", "posts"]);
    let docs: Vec<String> = s
        .list_documents(None, "users")
        .iter()
        .map(|d| d.path.relative())
        .collect();
    assert_eq!(docs, vec!["users/a", "users/b"]);
    let posts: Vec<String> = s
        .list_documents(Some(&path("users/a")), "posts")
        .iter()
        .map(|d| d.path.relative())
        .collect();
    assert_eq!(posts, vec!["users/a/posts/p1"]);
}

#[test]
fn commit_times_are_strictly_monotonic_and_no_op_writes_keep_update_time() {
    let mut s = FirestoreState::new();
    let first = s
        .commit(&[set("m/1", &[("v", Value::Integer(1))])], None, t(0))
        .unwrap();
    // Second commit without a clock advance: the commit time still moves forward, so an
    // update-time precondition on the first version can never match the second.
    let second = s
        .commit(&[set("m/2", &[("v", Value::Integer(1))])], None, t(0))
        .unwrap();
    assert!(second.commit_time.as_nanos() > first.commit_time.as_nanos());
    assert_eq!(s.get(&path("m/2")).unwrap().update_time, second.commit_time);
    let stale = Write {
        precondition: Some(Precondition::UpdateTime(t(0))),
        ..set("m/2", &[("v", Value::Integer(9))])
    };
    assert!(matches!(
        s.commit(&[stale], None, t(0)),
        Err(FirestoreError::FailedPrecondition(_))
    ));

    // Writing the same fields again is a no-op: version and update time are preserved.
    let before = s.get(&path("m/1")).unwrap().clone();
    let noop = s
        .commit(&[set("m/1", &[("v", Value::Integer(1))])], None, t(5))
        .unwrap();
    assert_eq!(noop.write_results[0].update_time, Some(before.update_time));
    let after = s.get(&path("m/1")).unwrap();
    assert_eq!(after.version, before.version);
    assert_eq!(after.update_time, before.update_time);

    // Deletes never report an update time.
    let del = s
        .commit(
            &[Write {
                op: WriteOp::Delete { path: path("m/1") },
                precondition: None,
                transforms: vec![],
            }],
            None,
            t(6),
        )
        .unwrap();
    assert_eq!(del.write_results[0].update_time, None);
    assert!(s.get(&path("m/1")).is_none());
}

#[test]
fn array_transforms_report_null_results_and_transform_limit_is_per_document() {
    let mut s = FirestoreState::new();
    let write = Write {
        transforms: vec![FieldTransform {
            field: FieldPath::parse("tags").unwrap(),
            kind: TransformKind::AppendMissingElements(vec![Value::String("a".into())]),
        }],
        ..set("arr/1", &[])
    };
    let result = s.commit(&[write], None, t(0)).unwrap();
    assert_eq!(result.write_results[0].transform_results, vec![Value::Null]);
    assert_eq!(
        s.get(&path("arr/1")).unwrap().fields.get("tags"),
        Some(&Value::Array(vec![Value::String("a".into())]))
    );

    let increments = |n: usize| -> Vec<FieldTransform> {
        (0..n)
            .map(|i| FieldTransform {
                field: FieldPath::parse(&format!("f{i}")).unwrap(),
                kind: TransformKind::Increment(Value::Integer(1)),
            })
            .collect()
    };
    let a = Write {
        transforms: increments(300),
        ..set("arr/2", &[])
    };
    let b = Write {
        transforms: increments(300),
        ..set("arr/2", &[])
    };
    let err = s.commit(&[a, b], None, t(1)).unwrap_err();
    assert!(
        matches!(&err, FirestoreError::ResourceExhausted(v) if v.limit_id == "FS-LIMIT-FIELD-TRANSFORMS-PER-DOCUMENT"),
        "{err}"
    );
    assert!(s.get(&path("arr/2")).is_none(), "nothing was written");
}

#[test]
fn a_query_phantom_aborts_the_transaction_without_partial_writes() {
    use fireemu_core_firestore::query::{Query, QueryScope};
    use fireemu_core_types::ids::CollectionId;
    let mut s = FirestoreState::new();
    let q = Query::new(QueryScope::collection(
        None,
        CollectionId::try_new("ph").unwrap(),
    ))
    .canonicalize()
    .unwrap();
    let txn = s.begin_transaction(false, t(0)).unwrap();
    assert!(s.run_query_in_transaction(&txn, &q).unwrap().is_empty());
    s.commit(&[set("ph/new", &[("v", Value::Integer(1))])], None, t(1))
        .unwrap();
    assert!(s.commit(&[set("other/x", &[])], None, t(1)).is_ok());
    assert!(matches!(
        s.commit(
            &[set("ph/mine", &[]), set("other/txn", &[])],
            Some(&txn),
            t(2)
        ),
        Err(FirestoreError::Aborted(_))
    ));
    assert!(s.get(&path("ph/mine")).is_none());
    assert!(s.get(&path("other/txn")).is_none());

    let txn2 = s.begin_transaction(false, t(4)).unwrap();
    assert_eq!(s.run_query_in_transaction(&txn2, &q).unwrap().len(), 1);
    assert!(s.commit(&[set("other/y", &[])], Some(&txn2), t(5)).is_ok());
}

#[test]
fn transaction_query_records_are_deduplicated_and_overflow_is_retryable() {
    use fireemu_core_firestore::query::{Query, QueryScope};
    use fireemu_core_types::ids::CollectionId;

    let mut state = FirestoreState::new();
    let base = Query::new(QueryScope::collection(
        None,
        CollectionId::try_new("bounded").unwrap(),
    ));
    for index in 0..4 {
        state
            .commit(
                &[set(
                    &format!("bounded/{index}"),
                    &[("value", Value::Integer(index))],
                )],
                None,
                t(0),
            )
            .unwrap();
    }
    let transaction = state.begin_transaction(false, t(0)).unwrap();

    state.run_query_in_transaction(&transaction, &base).unwrap();
    let conflict_ledger_bytes = state.transaction_bookkeeping_stats().conflict_ledger_bytes;
    state.run_query_in_transaction(&transaction, &base).unwrap();
    assert_eq!(
        state
            .transaction_recorded_query_count(&transaction)
            .unwrap(),
        1,
        "identical query snapshots share one conflict record"
    );
    assert_eq!(
        state.transaction_bookkeeping_stats().conflict_ledger_bytes,
        conflict_ledger_bytes,
        "overlapping results retain each observed path only once"
    );

    for offset in 1..MAX_TRANSACTION_QUERY_RECORDS {
        let mut query = base.clone();
        query.offset = u32::try_from(offset).unwrap();
        state
            .run_query_in_transaction(&transaction, &query)
            .unwrap();
    }
    let mut overflow = base;
    overflow.offset = u32::try_from(MAX_TRANSACTION_QUERY_RECORDS).unwrap();
    assert!(matches!(
        state.run_query_in_transaction(&transaction, &overflow),
        Err(FirestoreError::Aborted(message))
            if message == "transaction recorded too many distinct queries"
    ));
    assert!(matches!(
        state.run_query_in_transaction(&transaction, &overflow),
        Err(FirestoreError::Aborted(_))
    ));
}

#[test]
fn one_broad_query_cannot_retain_more_than_the_transaction_size_budget() {
    use fireemu_core_firestore::query::{Query, QueryScope};
    use fireemu_core_types::ids::CollectionId;

    let mut state = FirestoreState::new();
    let payload = "x".repeat(256 * 1024);
    let documents =
        usize::try_from(MAX_TRANSACTION_CONFLICT_LEDGER_BYTES / payload.len() as u64).unwrap() + 1;
    for index in 0..documents {
        state
            .commit(
                &[set(
                    &format!("large/{index}"),
                    &[("payload", Value::String(payload.clone()))],
                )],
                None,
                t(0),
            )
            .unwrap();
    }
    let query = Query::new(QueryScope::collection(
        None,
        CollectionId::try_new("large").unwrap(),
    ));
    for _ in 0..32 {
        let transaction = state.begin_transaction(false, t(0)).unwrap();
        assert!(matches!(
            state.run_query_in_transaction(&transaction, &query),
            Err(FirestoreError::Aborted(message))
                if message == "transaction observed data exceeds the retained conflict-detection budget"
        ));
        state.abandon_transaction(&transaction);
    }
    let bookkeeping = state.transaction_bookkeeping_stats();
    assert_eq!(bookkeeping.conflict_ledger_bytes, 0);
    assert_eq!(bookkeeping.active, 0);
    assert_eq!(bookkeeping.finished, 0);
    assert_eq!(bookkeeping.deadlines, 0);
    assert_eq!(bookkeeping.finished_deadlines, 0);
}

#[test]
fn large_zero_result_queries_are_charged_to_the_conflict_ledger() {
    use fireemu_core_firestore::query::{FieldOp, FilterExpr, Query, QueryScope};
    use fireemu_core_types::ids::CollectionId;

    let mut state = FirestoreState::new();
    let transaction = state.begin_transaction(false, t(0)).unwrap();
    let scope = QueryScope::collection(None, CollectionId::try_new("empty").unwrap());
    let payload = "q".repeat(512 * 1024);
    let mut refused = false;
    for index in 0..MAX_TRANSACTION_QUERY_RECORDS {
        let mut query = Query::new(scope.clone());
        query.filter = Some(FilterExpr::Field {
            field: FieldPath::parse("value").unwrap(),
            op: FieldOp::Equal,
            value: Value::String(format!("{index}{payload}")),
        });
        if matches!(
            state.run_query_in_transaction(&transaction, &query),
            Err(FirestoreError::Aborted(_))
        ) {
            refused = true;
            break;
        }
    }
    assert!(
        refused,
        "query descriptors consume the byte budget before the count cap"
    );
    assert_eq!(
        state.transaction_bookkeeping_stats().conflict_ledger_bytes,
        0
    );
}

#[test]
fn nested_tiny_query_values_are_charged_by_retained_heap_size() {
    use fireemu_core_firestore::query::{FieldOp, FilterExpr, Query, QueryScope};
    use fireemu_core_types::ids::CollectionId;

    let segments: Vec<String> = (0..100).map(|index| format!("field{index}")).collect();
    let field = FieldPath::from_segments(segments.iter().map(String::as_str)).unwrap();
    let array = Value::Array(vec![Value::Null; 400_000]);
    let map = Value::Map(
        (0..70_000)
            .map(|index| (format!("key{index}"), Value::Null))
            .collect(),
    );

    for value in [array, map] {
        let mut state = FirestoreState::new();
        let transaction = state.begin_transaction(false, t(0)).unwrap();
        let mut query = Query::new(QueryScope::collection(
            None,
            CollectionId::try_new("empty").unwrap(),
        ));
        query.filter = Some(FilterExpr::Field {
            field: field.clone(),
            op: FieldOp::Equal,
            value,
        });
        assert!(matches!(
            state.run_query_in_transaction(&transaction, &query),
            Err(FirestoreError::Aborted(_))
        ));
        assert_eq!(
            state.transaction_bookkeeping_stats().conflict_ledger_bytes,
            0
        );
    }
}

#[test]
fn maximum_depth_query_scopes_charge_owned_path_allocations() {
    use fireemu_core_firestore::query::{Query, QueryScope};
    use fireemu_core_types::ids::CollectionId;

    let relative = (0..100)
        .flat_map(|index| [format!("collection{index}"), format!("document{index}")])
        .collect::<Vec<_>>()
        .join("/");
    let parent = path(&relative);
    let serialized_bytes = parent.resource_name().len();
    let query = Query::new(QueryScope::collection(
        Some(parent),
        CollectionId::try_new("empty").unwrap(),
    ));
    let mut state = FirestoreState::new();
    let transaction = state.begin_transaction(false, t(0)).unwrap();

    state
        .run_query_in_transaction(&transaction, &query)
        .unwrap();

    assert!(
        state.transaction_bookkeeping_stats().conflict_ledger_bytes
            > u64::try_from(serialized_bytes + 100 * core::mem::size_of::<String>()).unwrap(),
        "scope accounting includes owned pair and String storage, not only rendered bytes"
    );
}

#[test]
fn aggregate_active_transaction_ledgers_have_a_database_wide_budget() {
    use fireemu_core_firestore::query::{FieldOp, FilterExpr, Query, QueryScope};
    use fireemu_core_types::ids::CollectionId;

    let mut state = FirestoreState::new();
    let mut query = Query::new(QueryScope::collection(
        None,
        CollectionId::try_new("empty").unwrap(),
    ));
    query.filter = Some(FilterExpr::Field {
        field: FieldPath::parse("value").unwrap(),
        op: FieldOp::Equal,
        value: Value::String("q".repeat(1024 * 1024)),
    });
    let mut active = Vec::new();
    let mut refused = false;
    for _ in 0..128 {
        let transaction = state.begin_transaction(false, t(0)).unwrap();
        match state.run_query_in_transaction(&transaction, &query) {
            Ok(_) => active.push(transaction),
            Err(FirestoreError::Aborted(_)) => {
                state.abandon_transaction(&transaction);
                refused = true;
                break;
            }
            Err(error) => panic!("unexpected query failure: {error}"),
        }
    }
    assert!(
        refused,
        "aggregate admission refuses before active ledgers grow without bound"
    );
    for transaction in active {
        state.rollback(&transaction).unwrap();
    }
    assert_eq!(
        state.transaction_bookkeeping_stats().conflict_ledger_bytes,
        0
    );
}

#[test]
fn transactions_expire_on_idle_and_total_time() {
    // Expiry is inclusive at the deadline (`now >= deadline`): a transaction is alive strictly
    // inside its 60 s idle window and 270 s total budget, and gone once a deadline is reached.
    // This is the transaction-validity boundary, so the attempt becomes retryably ABORTED at
    // exactly the instant its own commit would be refused.
    let mut s = FirestoreState::new();
    let txn = s.begin_transaction(false, t(0)).unwrap();
    assert!(s.touch_transaction(&txn, t(59)).is_ok());
    assert!(
        s.touch_transaction(&txn, t(118)).is_ok(),
        "idle window restarts"
    );
    // 60 s after the last activity (t(118)) the idle budget is spent. An expired transaction
    // is ABORTED (the code the SDKs retry), the same as a finished one.
    assert!(matches!(
        s.touch_transaction(&txn, t(178)),
        Err(FirestoreError::Aborted(_))
    ));
    assert!(
        s.touch_transaction(&txn, t(180)).is_err(),
        "expired stays expired"
    );

    let txn = s.begin_transaction(false, t(200)).unwrap();
    // Touching every 59 s keeps the idle window open, but the total budget still fires.
    for step in 1..=4 {
        assert!(s.touch_transaction(&txn, t(200 + step * 59)).is_ok());
    }
    assert!(matches!(
        s.touch_transaction(&txn, t(200 + 270)),
        Err(FirestoreError::Aborted(_))
    ));
}

#[test]
fn read_times_never_precede_the_last_commit_and_no_op_commits_still_consume_time() {
    let mut s = FirestoreState::new();
    let first = s
        .commit(&[set("rt/1", &[("v", Value::Integer(1))])], None, t(0))
        .unwrap();
    let second = s
        .commit(&[set("rt/2", &[("v", Value::Integer(1))])], None, t(0))
        .unwrap();
    assert!(second.commit_time.as_nanos() > first.commit_time.as_nanos());
    // Commit times are microsecond-aligned.
    assert_eq!(second.commit_time.as_nanos().rem_euclid(1_000), 0);
    // A live read at the (unchanged) clock reports the last commit time, never earlier.
    assert_eq!(s.read_time(t(0)), second.commit_time);
    assert_eq!(s.read_time(t(5)), t(5));
    // An all-no-op commit still consumes a commit time.
    let noop = s
        .commit(&[set("rt/2", &[("v", Value::Integer(1))])], None, t(0))
        .unwrap();
    assert!(noop.commit_time.as_nanos() > second.commit_time.as_nanos());
    assert_eq!(noop.write_results[0].update_time, Some(second.commit_time));
    // A transaction reports the snapshot time it started with.
    let txn = s.begin_transaction(true, t(0)).unwrap();
    assert_eq!(s.transaction_read_time(&txn).unwrap(), noop.commit_time);
}

#[test]
fn read_time_snapshots_resolve_to_the_version_committed_at_or_before() {
    let mut s = FirestoreState::new();
    assert_eq!(s.version_at(t(0)), CommitVersion::default());
    let first = s
        .commit(&[set("snap/a", &[("v", Value::Integer(1))])], None, t(10))
        .unwrap();
    let second = s
        .commit(&[set("snap/a", &[("v", Value::Integer(2))])], None, t(20))
        .unwrap();
    assert_eq!(s.version_at(t(5)), CommitVersion::default());
    assert_eq!(s.version_at(t(10)), first.version);
    assert_eq!(s.version_at(t(15)), first.version);
    assert_eq!(s.version_at(t(20)), second.version);
    assert_eq!(s.version_at(t(99)), second.version);
    let at_first = s.get_at(&path("snap/a"), s.version_at(t(12))).unwrap();
    assert_eq!(at_first.fields.get("v"), Some(&Value::Integer(1)));
    assert!(s.get_at(&path("snap/a"), s.version_at(t(1))).is_none());
    assert_eq!(
        s.list_documents_at(None, "snap", Some(s.version_at(t(1))))
            .len(),
        0
    );
    assert_eq!(
        s.list_documents_at(None, "snap", Some(s.version_at(t(30))))
            .len(),
        1
    );
}

fn server_timestamp_write(p: &str) -> Write {
    Write {
        op: WriteOp::Set {
            path: path(p),
            fields: fields(&[]),
            update_mask: None,
        },
        precondition: None,
        transforms: vec![
            FieldTransform {
                field: FieldPath::parse("createdAt").unwrap(),
                kind: TransformKind::ServerTimestamp,
            },
            FieldTransform {
                field: FieldPath::parse("updatedAt").unwrap(),
                kind: TransformKind::ServerTimestamp,
            },
        ],
    }
}

fn timestamp_nanos(s: &FirestoreState, p: &str, field: &str) -> i128 {
    match s.get(&path(p)).unwrap().fields.get(field) {
        Some(Value::Timestamp(ts)) => {
            i128::from(ts.seconds()) * 1_000_000_000 + i128::from(ts.nanos())
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn server_timestamps_follow_the_commit_order_when_the_clock_stands_still() {
    let mut s = FirestoreState::new();
    s.commit(&[server_timestamp_write("t/first")], None, t(0))
        .unwrap();
    s.commit(&[server_timestamp_write("t/second")], None, t(0))
        .unwrap();
    let first = timestamp_nanos(&s, "t/first", "createdAt");
    let second = timestamp_nanos(&s, "t/second", "createdAt");
    // Commit times are microsecond-aligned and strictly increasing: one microsecond apart.
    assert_eq!(second - first, 1_000);
    assert_eq!(first % 1_000, 0);
    // Every transform of one commit observes the same request time.
    assert_eq!(first, timestamp_nanos(&s, "t/first", "updatedAt"));
    // Committed values carry the commit time itself.
    let doc = s.get(&path("t/second")).unwrap();
    assert_eq!(doc.update_time.as_nanos(), second);
}
