//! Local Firestore execution: commits, preconditions, masks, transforms, atomic rejection.

use std::collections::BTreeMap;

use ftd_core_firestore::field_path::FieldPath;
use ftd_core_firestore::path::DocumentPath;
use ftd_core_firestore::store::{
    FieldTransform, FirestoreError, FirestoreState, Precondition, TransformKind, Write, WriteOp,
};
use ftd_core_firestore::value::Value;
use ftd_core_types::ids::{DatabaseId, ProjectId};
use ftd_core_types::time::{LogicalDuration, LogicalInstant};

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
fn transactions_validate_their_read_set_on_commit() {
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
    // A concurrent writer changes the document before the transaction commits.
    s.commit(
        &[set("acct/a", &[("balance", Value::Integer(90))])],
        None,
        t(2),
    )
    .unwrap();
    let write = set("acct/a", &[("balance", Value::Integer(80))]);
    assert!(matches!(
        s.commit(std::slice::from_ref(&write), Some(&txn), t(3)),
        Err(FirestoreError::Aborted(_))
    ));
    assert_eq!(
        s.get(&path("acct/a")).unwrap().fields.get("balance"),
        Some(&Value::Integer(90)),
        "aborted transaction wrote nothing"
    );
    assert!(
        matches!(
            s.commit(std::slice::from_ref(&write), Some(&txn), t(4)),
            Err(FirestoreError::InvalidArgument(_))
        ),
        "a finished transaction cannot be reused"
    );

    let txn2 = s.begin_transaction(false, t(5)).unwrap();
    assert!(s
        .get_in_transaction(&txn2, &path("acct/missing"))
        .unwrap()
        .is_none());
    let _ = s.get_in_transaction(&txn2, &path("acct/a")).unwrap();
    assert!(s.commit(&[write], Some(&txn2), t(6)).is_ok());
    assert_eq!(
        s.get(&path("acct/a")).unwrap().fields.get("balance"),
        Some(&Value::Integer(80))
    );

    let txn3 = s.begin_transaction(false, t(7)).unwrap();
    let _ = s.get_in_transaction(&txn3, &path("acct/missing")).unwrap();
    s.commit(&[set("acct/missing", &[("x", Value::Null)])], None, t(8))
        .unwrap();
    assert!(
        matches!(
            s.commit(&[set("acct/other", &[])], Some(&txn3), t(9)),
            Err(FirestoreError::Aborted(_))
        ),
        "a document created after being read as absent aborts"
    );

    let ro = s.begin_transaction(true, t(10)).unwrap();
    assert!(matches!(
        s.commit(&[set("acct/a", &[])], Some(&ro), t(11)),
        Err(FirestoreError::InvalidArgument(_))
    ));
    s.rollback(&ro).unwrap();
    assert!(s.rollback(&ro).is_err());
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
    assert!(matches!(
        s.commit(&[], Some(&txn), late),
        Err(FirestoreError::InvalidArgument(_))
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
