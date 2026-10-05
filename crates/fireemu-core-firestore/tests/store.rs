//! Local Firestore execution: commits, preconditions, masks, transforms, atomic rejection.

use std::collections::BTreeMap;

use fireemu_core_firestore::field_path::FieldPath;
use fireemu_core_firestore::path::DocumentPath;
use fireemu_core_firestore::store::{
    CommitVersion, FieldTransform, FirestoreError, FirestoreState, LimitScope, Precondition,
    TransactionId, TransformKind, Write, WriteOp, MAX_TRANSACTION_CONFLICT_LEDGER_BYTES,
    MAX_TRANSACTION_QUERY_RECORDS, TOO_MUCH_CONTENTION,
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
fn numeric_extrema_propagate_nan_and_preserve_equal_stored_values() {
    let values = [
        None,
        Some(Value::String("text".into())),
        Some(Value::Integer(0)),
        Some(Value::Double(-0.0)),
        Some(Value::Integer(5)),
        Some(Value::Double(5.0)),
        Some(Value::Double(f64::NAN)),
    ];
    for maximum in [true, false] {
        for current in &values {
            for operand in [
                Value::Integer(0),
                Value::Double(-0.0),
                Value::Integer(5),
                Value::Double(5.0),
                Value::Double(f64::NAN),
            ] {
                let mut state = FirestoreState::new();
                let initial: Vec<_> = current.iter().map(|v| ("x", v.clone())).collect();
                state
                    .commit(&[set("extrema/doc", &initial)], None, t(0))
                    .unwrap();
                let numeric = |v: &Value| match v {
                    Value::Integer(n) => Some(f64::from(i32::try_from(*n).unwrap())),
                    Value::Double(n) => Some(*n),
                    _ => None,
                };
                let expected = match current.as_ref().and_then(numeric) {
                    Some(n) if n.is_nan() || numeric(&operand).unwrap().is_nan() => {
                        Value::Double(f64::NAN)
                    }
                    Some(n)
                        if if maximum {
                            n >= numeric(&operand).unwrap()
                        } else {
                            n <= numeric(&operand).unwrap()
                        } =>
                    {
                        current.clone().unwrap()
                    }
                    _ => operand.clone(),
                };
                let write = Write {
                    op: WriteOp::Set {
                        path: path("extrema/doc"),
                        fields: BTreeMap::new(),
                        update_mask: Some(vec![]),
                    },
                    precondition: None,
                    transforms: vec![FieldTransform {
                        field: FieldPath::parse("x").unwrap(),
                        kind: if maximum {
                            TransformKind::Maximum(operand.clone())
                        } else {
                            TransformKind::Minimum(operand.clone())
                        },
                    }],
                };
                let result = state.commit(&[write], None, t(1)).unwrap();
                for actual in [
                    &result.write_results[0].transform_results[0],
                    state
                        .get(&path("extrema/doc"))
                        .unwrap()
                        .fields
                        .get("x")
                        .unwrap(),
                ] {
                    match (&expected, actual) {
                        (Value::Double(e), Value::Double(a)) if e.is_nan() => assert!(
                            a.is_nan(),
                            "maximum={maximum}, current={current:?}, operand={operand:?}"
                        ),
                        (Value::Double(e), Value::Double(a)) => {
                            assert_eq!(a.to_bits(), e.to_bits());
                        }
                        _ => assert_eq!(actual, &expected),
                    }
                }
            }
        }
    }
}

#[test]
fn nested_map_field_names_are_validated_and_failure_is_atomic() {
    for name in [
        "x".repeat(1501),
        "__reserved__".to_owned(),
        "__name__".to_owned(),
    ] {
        for in_array in [false, true] {
            let mut state = FirestoreState::new();
            let map = Value::Map(BTreeMap::from([(name.clone(), Value::Integer(1))]));
            let value = if in_array {
                Value::Array(vec![map])
            } else {
                map
            };
            let result = state.commit(
                &[
                    set("a/first", &[("ok", Value::Integer(1))]),
                    set("a/second", &[("nested", value)]),
                ],
                None,
                t(0),
            );
            assert!(
                matches!(result, Err(FirestoreError::InvalidArgument(_))),
                "{result:?}"
            );
            assert!(state.get(&path("a/first")).is_none());
            assert!(state.get(&path("a/second")).is_none());
        }
    }
    let mut state = FirestoreState::new();
    let value = Value::Map(BTreeMap::from([("é".repeat(746), Value::Integer(1))]));
    state
        .commit(&[set("a/valid", &[("nested", value)])], None, t(0))
        .unwrap();
}

#[test]
fn vector_dimension_limit_and_nan_components_reject_the_whole_commit() {
    let vector = |dimensions: usize| {
        Value::Map(BTreeMap::from([(
            "embedding".to_owned(),
            Value::Vector(vec![0.5; dimensions]),
        )]))
    };
    let mut state = FirestoreState::new();
    state
        .commit(&[set("v/max", &[("nested", vector(2048))])], None, t(0))
        .unwrap();
    let before = state.get(&path("v/max")).unwrap().clone();

    let rejected = [
        (
            Value::Vector(vec![0.5; 2049]),
            "Vectors must be at most 2048 dimensions.",
        ),
        (
            Value::Vector(vec![f64::NAN; 2049]),
            "Vectors must be at most 2048 dimensions.",
        ),
        (
            Value::Vector(vec![0.5, f64::NAN]),
            "Vector cannot contain NaN values.",
        ),
        (
            Value::Vector(Vec::new()),
            "Cannot have a zero length vector.",
        ),
    ];
    for (bad, message) in rejected {
        for wrap in 0..3 {
            let value = match wrap {
                0 => bad.clone(),
                1 => Value::Array(vec![bad.clone()]),
                _ => Value::Map(BTreeMap::from([("inner".to_owned(), bad.clone())])),
            };
            let result = state.commit(
                &[
                    set("v/other", &[("ok", Value::Integer(1))]),
                    set("v/max", &[("nested", value)]),
                ],
                None,
                t(1),
            );
            match result {
                Err(FirestoreError::InvalidArgument(actual)) => assert_eq!(actual, message),
                other => panic!("{other:?}"),
            }
            assert!(
                state.get(&path("v/other")).is_none(),
                "the valid write must not publish"
            );
            assert_eq!(state.get(&path("v/max")), Some(&before));
        }
    }
    // Infinite components are stored as production stores them.
    state
        .commit(
            &[set(
                "v/inf",
                &[("e", Value::Vector(vec![f64::INFINITY, f64::NEG_INFINITY]))],
            )],
            None,
            t(2),
        )
        .unwrap();
}

#[test]
fn field_payload_size_accepts_the_production_boundary_and_rejects_one_more_byte() {
    for bytes in [false, true] {
        for size in [1_048_486, 1_048_487, 1_048_488] {
            let mut state = FirestoreState::new();
            let value = if bytes {
                Value::Bytes(vec![0; size])
            } else {
                Value::String("x".repeat(size))
            };
            let result = state.commit(&[set("a/b", &[("v", value)])], None, t(0));
            if size <= 1_048_487 {
                assert!(result.is_ok(), "{result:?}");
            } else {
                assert!(
                    matches!(result, Err(FirestoreError::InvalidArgument(_))),
                    "oversized payload was not rejected as INVALID_ARGUMENT"
                );
                assert!(state.get(&path("a/b")).is_none());
            }
        }
    }
}

#[test]
fn import_index_rejection_does_not_publish_the_valid_prefix() {
    let mut source = FirestoreState::new();
    let mut indexes = fireemu_core_firestore::index::IndexSet::default();
    indexes.set_default_single_field_indexes(
        &fireemu_core_types::ids::CollectionId::try_new("a").unwrap(),
        vec![],
    );
    source.set_index_catalog(indexes.clone());
    source
        .commit(
            &[
                set("a/first", &[("v", Value::Integer(1))]),
                set(
                    "a/second",
                    &[("v", Value::Array((0..20_000).map(Value::Integer).collect()))],
                ),
            ],
            None,
            t(0),
        )
        .unwrap();
    let documents = vec![
        source.get(&path("a/first")).unwrap().clone(),
        source.get(&path("a/second")).unwrap().clone(),
    ]
    .into_iter()
    .map(|document| fireemu_core_firestore::store::ImportedDocument {
        path: document.path,
        fields: document.fields,
        create_time: Some(document.create_time),
        update_time: Some(document.update_time),
    })
    .collect::<Vec<_>>();
    let mut target = FirestoreState::new();
    assert!(target.import_documents(documents.clone(), t(1)).is_err());
    assert!(target.get(&path("a/first")).is_none());
    assert!(target.get(&path("a/second")).is_none());
    target.set_index_catalog(indexes);
    target.import_documents(documents, t(1)).unwrap();
    assert!(target.get(&path("a/second")).is_some());
}

#[test]
fn index_entry_limit_rejects_an_entire_commit_and_exemption_allows_the_document() {
    use fireemu_core_firestore::index::{IndexQueryScope, IndexSet, SingleFieldExemption};
    use fireemu_core_types::ids::CollectionId;
    let mut state = FirestoreState::new();
    let at_limit = Value::Array((0..19_999).map(Value::Integer).collect());
    state
        .commit(&[set("a/accepted", &[("v", at_limit)])], None, t(0))
        .unwrap();
    let over = Value::Array((0..20_000).map(Value::Integer).collect());
    let result = state.commit(
        &[
            set("a/first", &[("v", Value::Integer(1))]),
            set("a/oversized", &[("v", over.clone())]),
        ],
        None,
        t(1),
    );
    assert!(
        matches!(result, Err(FirestoreError::InvalidArgument(_))),
        "index entry overflow accepted"
    );
    assert!(state.get(&path("a/first")).is_none());
    assert!(state.get(&path("a/oversized")).is_none());
    let mut indexes = IndexSet::default();
    indexes.add_exemption(&SingleFieldExemption {
        collection_group: CollectionId::try_new("a").unwrap(),
        field: FieldPath::parse("v").unwrap(),
        query_scope: IndexQueryScope::Collection,
    });
    state.set_index_catalog(indexes);
    state
        .commit(&[set("a/exempt", &[("v", over)])], None, t(2))
        .unwrap();
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
fn event_admission_refusal_keeps_the_document_version_and_commit_time_private() {
    let mut state = FirestoreState::new();
    let before_version = state.current_version();
    let refusal = state.commit_with_admission(
        &[set("events/refused", &[("value", Value::Integer(1))])],
        None,
        t(0),
        |result| {
            assert_eq!(result.changes.len(), 1);
            assert_eq!(result.version, CommitVersion::from_value(1));
            Err::<(), _>(FirestoreError::EventAdmission(
                fireemu_core_types::admission::EventAdmissionError::Capacity(
                    "outbox full".to_owned(),
                ),
            ))
        },
    );

    assert!(matches!(refusal, Err(FirestoreError::EventAdmission(_))));
    assert_eq!(state.current_version(), before_version);
    assert!(state.get(&path("events/refused")).is_none());
    let accepted = state
        .commit(
            &[set("events/accepted", &[("value", Value::Integer(2))])],
            None,
            t(0),
        )
        .unwrap();
    assert_eq!(accepted.version, CommitVersion::from_value(1));
    assert_eq!(accepted.commit_time, t(0));
}

#[test]
fn event_admission_refusal_does_not_extend_a_transaction_lease() {
    let mut state = FirestoreState::new();
    let transaction = state.begin_transaction(false, t(0)).unwrap();

    assert!(matches!(
        state.commit_with_admission(
            &[set("events/refused-transaction", &[])],
            Some(&transaction),
            t(59),
            |_| {
                Err::<(), _>(FirestoreError::EventAdmission(
                    fireemu_core_types::admission::EventAdmissionError::Capacity(
                        "outbox full".to_owned(),
                    ),
                ))
            },
        ),
        Err(FirestoreError::EventAdmission(_))
    ));
    // The refusal at t(59) did not renew the lease: it still ends 120 s after t(0).
    assert!(matches!(
        state.touch_transaction(&transaction, t(125)),
        Err(FirestoreError::Aborted(_))
    ));
    assert!(state.get(&path("events/refused-transaction")).is_none());
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
    // Keep each field below the per-value limit so this control exercises the
    // aggregate document-size refusal rather than the property-size diagnostic.
    let too_big = Value::String("x".repeat(600_000));
    let also_too_big = Value::String("y".repeat(500_000));
    let writes = vec![
        set("a/1", &[("k", Value::Integer(2))]),
        set("a/2", &[("blob", too_big), ("other", also_too_big)]),
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
fn a_read_write_transaction_locks_what_it_read_until_it_finishes() {
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
    // Production (PESSIMISTIC): the out-of-band write collides with the lock the read took
    // and is refused with production's wording; nothing of it is published.
    let releases = s.transaction_releases();
    let refused = s
        .commit(
            &[set("acct/a", &[("balance", Value::Integer(90))])],
            None,
            t(2),
        )
        .unwrap_err();
    assert!(
        matches!(&refused, FirestoreError::Aborted(m) if m == TOO_MUCH_CONTENTION),
        "{refused}"
    );
    assert_eq!(
        s.get(&path("acct/a")).unwrap().fields.get("balance"),
        Some(&Value::Integer(100))
    );
    assert_eq!(
        s.transaction_releases(),
        releases,
        "a refusal releases nothing"
    );
    // A write to an unlocked document is not held up by the transaction.
    assert!(s.commit(&[set("acct/other", &[])], None, t(2)).is_ok());
    // The transaction itself commits; its read set was protected.
    let write = set("acct/a", &[("balance", Value::Integer(80))]);
    s.commit(std::slice::from_ref(&write), Some(&txn), t(3))
        .unwrap();
    assert_eq!(
        s.get(&path("acct/a")).unwrap().fields.get("balance"),
        Some(&Value::Integer(80))
    );
    assert_eq!(
        s.transaction_releases(),
        releases + 1,
        "the commit released the locks"
    );
    // Released: the out-of-band write goes through now.
    s.commit(
        &[set("acct/a", &[("balance", Value::Integer(90))])],
        None,
        t(4),
    )
    .unwrap();
    // A finished transaction is ABORTED on reuse, the code the SDKs retry on and the one
    // production answers (conformance/firestore-production-matrix.json, transactions/lifecycle).
    assert!(
        matches!(
            s.commit(std::slice::from_ref(&write), Some(&txn), t(5)),
            Err(FirestoreError::Aborted(_))
        ),
        "a finished transaction cannot be reused"
    );

    // Reading a missing document locks its path too, and a rollback releases it.
    let txn3 = s.begin_transaction(false, t(6)).unwrap();
    let _ = s.get_in_transaction(&txn3, &path("acct/missing")).unwrap();
    assert!(matches!(
        s.commit(&[set("acct/missing", &[("x", Value::Null)])], None, t(7)),
        Err(FirestoreError::Aborted(_))
    ));
    s.rollback(&txn3).unwrap();
    s.commit(&[set("acct/missing", &[("x", Value::Null)])], None, t(8))
        .unwrap();

    // A read-only transaction takes no locks and cannot write.
    let ro = s.begin_transaction(true, t(10)).unwrap();
    let _ = s.get_in_transaction(&ro, &path("acct/a")).unwrap();
    assert!(s.commit(&[set("acct/a", &[])], None, t(10)).is_ok());
    assert!(matches!(
        s.commit(&[set("acct/a", &[])], Some(&ro), t(11)),
        Err(FirestoreError::InvalidArgument(_))
    ));
    s.rollback(&ro).unwrap();
    s.rollback(&ro).unwrap();
}

#[test]
fn two_transactions_contending_for_one_document_resolve_like_a_deadlock() {
    // Both read the lock document, so both hold a read lock on it. The first to commit runs
    // into the other's lock and is held back (the adapter waits for a release); the other's
    // commit then runs into a holder that is waiting, which is the deadlock production
    // resolves by aborting one side: it is aborted for its client to retry, and the first
    // commit goes through once tried again.
    let mut s = FirestoreState::new();
    s.commit(
        &[set("locks/l", &[("locked", Value::Boolean(false))])],
        None,
        t(0),
    )
    .unwrap();
    let first = s.begin_transaction(false, t(1)).unwrap();
    let second = s.begin_transaction(false, t(1)).unwrap();
    let _ = s.get_in_transaction(&first, &path("locks/l")).unwrap();
    let _ = s.get_in_transaction(&second, &path("locks/l")).unwrap();
    let take = set("locks/l", &[("locked", Value::Boolean(true))]);
    let held = s
        .commit(std::slice::from_ref(&take), Some(&first), t(2))
        .unwrap_err();
    assert!(
        matches!(&held, FirestoreError::Aborted(m) if m == TOO_MUCH_CONTENTION),
        "{held}"
    );
    assert!(s.transaction_is_active(&first), "held back, not aborted");
    let victim = s
        .commit(std::slice::from_ref(&take), Some(&second), t(3))
        .unwrap_err();
    assert!(
        matches!(&victim, FirestoreError::Aborted(m) if m == TOO_MUCH_CONTENTION),
        "{victim}"
    );
    assert!(
        !s.transaction_is_active(&second),
        "the deadlock victim is aborted"
    );
    assert_eq!(
        s.get(&path("locks/l")).unwrap().fields.get("locked"),
        Some(&Value::Boolean(false))
    );
    // The victim's locks are gone: the held-back commit goes through.
    s.commit(std::slice::from_ref(&take), Some(&first), t(4))
        .unwrap();
    let retry = s.retry_transaction(&second, t(5)).unwrap();
    s.touch_transaction(&retry, t(5)).unwrap();
    let seen = s
        .get_in_transaction(&retry, &path("locks/l"))
        .unwrap()
        .unwrap();
    assert_eq!(seen.fields.get("locked"), Some(&Value::Boolean(true)));
}

#[test]
fn retrying_an_active_attempt_evicted_from_the_finished_lineage_is_refused_not_a_panic() {
    // Rolling back the active attempt puts it into the bounded finished lineage, which may
    // evict it at once (it has the smallest id); the retry is then refused like any unknown
    // predecessor instead of panicking and poisoning the database lock.
    let mut s = FirestoreState::new();
    let oldest = s.begin_transaction(false, t(0)).unwrap();
    for _ in 0..8_192 {
        let id = s.begin_transaction(false, t(0)).unwrap();
        s.rollback(&id).unwrap();
    }
    let outcome = s.retry_transaction(&oldest, t(1));
    assert!(
        matches!(outcome, Ok(_) | Err(FirestoreError::InvalidArgument(_))),
        "{outcome:?}"
    );
    assert!(!s.transaction_is_active(&oldest));
}

#[test]
fn an_expired_transaction_releases_its_locks() {
    let mut s = FirestoreState::new();
    let txn = s.begin_transaction(false, t(0)).unwrap();
    let _ = s.get_in_transaction(&txn, &path("held/doc")).unwrap();
    assert!(matches!(
        s.commit(&[set("held/doc", &[])], None, t(30)),
        Err(FirestoreError::Aborted(_))
    ));
    // Past the idle deadline (strict: 120 s) the transaction is gone and the write goes through.
    s.commit(&[set("held/doc", &[])], None, t(125)).unwrap();
    assert!(matches!(
        s.commit(&[set("held/doc", &[])], Some(&txn), t(126)),
        Err(FirestoreError::Aborted(_))
    ));
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
fn sandbox_recorded_rollback_after_rollback_is_idempotent() {
    let mut state = FirestoreState::new();
    let transaction = state.begin_transaction(false, t(0)).unwrap();
    state
        .get_in_transaction(&transaction, &path("rollback/locked"))
        .unwrap();
    let before = state.transaction_releases();
    state.rollback(&transaction).unwrap();
    let released = state.transaction_releases();
    assert_eq!(released, before + 1);

    state.rollback(&transaction).unwrap();
    assert_eq!(state.transaction_releases(), released);
    assert!(!state.transaction_is_active(&transaction));
    state
        .commit(&[set("rollback/locked", &[])], None, t(1))
        .unwrap();
    assert!(state.retry_transaction(&transaction, t(2)).is_ok());
}

#[test]
fn locally_expired_transaction_rollback_does_not_revive_finished_lineage() {
    // This later-expiry sample is a local lifecycle contract, not a recorded native production threshold. The recorded 65-second Get-first recipe remains usable.
    let mut state = FirestoreState::new();
    let transaction = state.begin_transaction(false, t(0)).unwrap();
    state
        .get_in_transaction(&transaction, &path("expired/locked"))
        .unwrap();
    assert!(matches!(
        state.touch_transaction(&transaction, t(125)),
        Err(FirestoreError::Aborted(_))
    ));
    let released = state.transaction_releases();

    state.rollback(&transaction).unwrap();
    assert_eq!(state.transaction_releases(), released);
    // Production accepts a retry that names an idle-expired token, whether or not it was rolled back first (P13b, REST, two recordings: 132 s of token age).
    let retry = state.retry_transaction(&transaction, t(126)).unwrap();
    state.touch_transaction(&retry, t(126)).unwrap();
    assert!(matches!(
        state.commit(&[], Some(&transaction), t(127)),
        Err(FirestoreError::Aborted(_))
    ));
    state
        .commit(&[set("expired/locked", &[])], None, t(128))
        .unwrap();
}

#[test]
fn sandbox_recorded_committed_transaction_can_seed_one_retry() {
    let mut state = FirestoreState::new();
    let transaction = state.begin_transaction(false, t(0)).unwrap();
    state
        .commit(
            &[set("retry/document", &[("value", Value::Integer(1))])],
            Some(&transaction),
            t(1),
        )
        .unwrap();
    assert!(matches!(
        state.rollback(&transaction),
        Err(FirestoreError::Aborted(message))
            if message == "The referenced transaction has expired or is no longer valid."
    ));
    state
        .commit(
            &[set("retry/document", &[("value", Value::Integer(2))])],
            None,
            t(2),
        )
        .unwrap();

    let retry = state.retry_transaction(&transaction, t(3)).unwrap();
    state.touch_transaction(&retry, t(3)).unwrap();
    assert_ne!(transaction, retry);
    let document = state
        .get_in_transaction(&retry, &path("retry/document"))
        .unwrap()
        .unwrap();
    assert_eq!(document.fields["value"], Value::Integer(2));
    assert!(matches!(
        state.retry_transaction(&transaction, t(4)),
        Err(FirestoreError::InvalidArgument(_))
    ));
    assert!(matches!(
        state.rollback(&transaction),
        Err(FirestoreError::Aborted(_))
    ));
    state.rollback(&retry).unwrap();
}

#[test]
fn sandbox_recorded_read_only_retry_keeps_its_diagnostic_and_snapshot() {
    let mut state = FirestoreState::new();
    state
        .commit(
            &[set("readonly/document", &[("value", Value::Integer(1))])],
            None,
            t(0),
        )
        .unwrap();
    let transaction = state.begin_transaction(true, t(1)).unwrap();
    state
        .commit(
            &[set("readonly/document", &[("value", Value::Integer(2))])],
            None,
            t(2),
        )
        .unwrap();

    assert!(matches!(
        state.retry_transaction(&transaction, t(3)),
        Err(FirestoreError::InvalidArgument(message)) if message == "Cannot retry a read-only transaction"
    ));
    let document = state
        .get_in_transaction(&transaction, &path("readonly/document"))
        .unwrap()
        .unwrap();
    assert_eq!(document.fields["value"], Value::Integer(1));
    state.rollback(&transaction).unwrap();
    assert!(matches!(
        state.retry_transaction(&transaction, t(4)),
        Err(FirestoreError::InvalidArgument(message)) if message == "Cannot retry a read-only transaction"
    ));
}

#[test]
fn committed_retry_lineage_expires_at_the_original_total_deadline() {
    for elapsed in [269, 270] {
        let mut state = FirestoreState::new();
        let original = state.begin_transaction(false, t(0)).unwrap();
        state.commit(&[], Some(&original), t(1)).unwrap();
        let result = state.retry_transaction(&original, t(elapsed));
        if elapsed == 269 {
            let retry = result.unwrap();
            state.rollback(&retry).unwrap();
        } else {
            assert!(matches!(result, Err(FirestoreError::InvalidArgument(_))));
        }
    }
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
        // The forgotten token answers the text production recorded for a token it never issued (E003 REST, P09 gRPC).
        assert!(matches!(
            expired.retry_transaction(&original, t(elapsed)),
            Err(FirestoreError::InvalidArgument(message))
                if message == "Invalid transaction."
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
fn a_query_in_a_transaction_locks_its_range() {
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
    // A document that would appear in the queried range cannot be created out of band while
    // the transaction is active (production blocks the phantom writer); a document in another
    // collection, or deeper than the range, can.
    let refused = s
        .commit(&[set("ph/new", &[("v", Value::Integer(1))])], None, t(1))
        .unwrap_err();
    assert!(
        matches!(&refused, FirestoreError::Aborted(m) if m == TOO_MUCH_CONTENTION),
        "{refused}"
    );
    assert!(s.commit(&[set("other/x", &[])], None, t(1)).is_ok());
    assert!(s.commit(&[set("ph/new/sub/deep", &[])], None, t(1)).is_ok());
    // The transaction commits into its own range and every write of it is published.
    s.commit(
        &[set("ph/mine", &[]), set("other/txn", &[])],
        Some(&txn),
        t(2),
    )
    .unwrap();
    assert!(s.get(&path("ph/mine")).is_some());
    assert!(s.get(&path("other/txn")).is_some());
    // Released: the phantom write goes through and a later transaction sees both rows.
    s.commit(&[set("ph/new", &[("v", Value::Integer(1))])], None, t(3))
        .unwrap();
    let txn2 = s.begin_transaction(false, t(4)).unwrap();
    assert_eq!(s.run_query_in_transaction(&txn2, &q).unwrap().len(), 2);
    assert!(s.commit(&[set("other/y", &[])], Some(&txn2), t(5)).is_ok());
}

fn delete_write(p: &str) -> Write {
    Write {
        op: WriteOp::Delete { path: path(p) },
        precondition: None,
        transforms: vec![],
    }
}

fn state_is(value: &str) -> fireemu_core_firestore::query::FilterExpr {
    use fireemu_core_firestore::query::{FieldOp, FilterExpr};
    FilterExpr::Field {
        field: FieldPath::parse("state").unwrap(),
        op: FieldOp::Equal,
        value: Value::String(value.into()),
    }
}

/// A transaction that ran `state == "in"` over `rg` and read nothing else, with `rg/inside`
/// (state in) and `rg/outside` (state out) already stored.
fn filtered_range_lock() -> (FirestoreState, TransactionId) {
    use fireemu_core_firestore::query::{Query, QueryScope};
    use fireemu_core_types::ids::CollectionId;
    let mut s = FirestoreState::new();
    s.commit(
        &[
            set("rg/inside", &[("state", Value::String("in".into()))]),
            set("rg/outside", &[("state", Value::String("out".into()))]),
        ],
        None,
        t(0),
    )
    .unwrap();
    let q = Query::new(QueryScope::collection(
        None,
        CollectionId::try_new("rg").unwrap(),
    ))
    .with_filter(state_is("in"))
    .canonicalize()
    .unwrap();
    let txn = s.begin_transaction(false, t(1)).unwrap();
    assert_eq!(s.run_query_in_transaction(&txn, &q).unwrap().len(), 1);
    (s, txn)
}

fn assert_refused(s: &mut FirestoreState, writes: &[Write], what: &str) {
    let refused = s.commit(writes, None, t(2)).unwrap_err();
    assert!(
        matches!(&refused, FirestoreError::Aborted(m) if m == TOO_MUCH_CONTENTION),
        "{what}: {refused}"
    );
}

#[test]
fn a_filtered_query_locks_only_the_documents_that_match_its_filter() {
    let (mut s, _txn) = filtered_range_lock();
    // a phantom (a new document in the range) and a change of a member are blocked ...
    assert_refused(
        &mut s,
        &[set("rg/new-in", &[("state", Value::String("in".into()))])],
        "a new document in the range",
    );
    assert_refused(
        &mut s,
        &[set("rg/inside", &[("state", Value::String("in".into()))])],
        "a rewrite of a member",
    );
    assert_refused(
        &mut s,
        &[set("rg/inside", &[("state", Value::String("out".into()))])],
        "a member leaving the range",
    );
    assert_refused(
        &mut s,
        &[set("rg/outside", &[("state", Value::String("in".into()))])],
        "a document entering the range",
    );
    assert_refused(&mut s, &[delete_write("rg/inside")], "a delete of a member");
    // ... and a write that touches nothing in the range is not
    assert!(s
        .commit(
            &[set("rg/new-out", &[("state", Value::String("out".into()))])],
            None,
            t(3)
        )
        .is_ok());
    assert!(s
        .commit(
            &[set("rg/outside", &[("state", Value::String("still-out".into()))])],
            None,
            t(3)
        )
        .is_ok());
    assert!(s.commit(&[delete_write("rg/outside")], None, t(3)).is_ok());
    assert!(s
        .commit(&[set("rg/no-state", &[("other", Value::Integer(1))])], None, t(3))
        .is_ok());
}

#[test]
fn the_holders_listed_for_a_write_are_the_ones_whose_range_it_touches() {
    let (s, txn) = filtered_range_lock();
    let outside = [set("rg/new-out", &[("state", Value::String("out".into()))])];
    let inside = [set("rg/new-in", &[("state", Value::String("in".into()))])];
    assert!(s.lock_holders(&outside, None).is_empty());
    assert_eq!(s.lock_holders(&inside, None), vec![txn.clone()]);
    // the holder's own writes never wait on itself
    assert!(s.lock_holders(&inside, Some(&txn)).is_empty());
}

#[test]
fn an_unfiltered_query_and_an_unsupported_filter_still_lock_the_whole_collection() {
    use fireemu_core_firestore::query::{Query, QueryScope};
    use fireemu_core_types::ids::CollectionId;
    let mut s = FirestoreState::new();
    let q = Query::new(QueryScope::collection(
        None,
        CollectionId::try_new("rg").unwrap(),
    ))
    .canonicalize()
    .unwrap();
    let _txn = s.begin_transaction(false, t(0)).unwrap();
    assert!(s.run_query_in_transaction(&_txn, &q).unwrap().is_empty());
    assert_refused(
        &mut s,
        &[set("rg/any", &[("state", Value::String("out".into()))])],
        "no filter: every document of the collection is in the range",
    );
}

#[test]
fn a_disjunction_locks_every_document_matching_either_side() {
    use fireemu_core_firestore::query::{FilterExpr, Query, QueryScope};
    use fireemu_core_types::ids::CollectionId;
    let mut s = FirestoreState::new();
    let q = Query::new(QueryScope::collection(
        None,
        CollectionId::try_new("rg").unwrap(),
    ))
    .with_filter(FilterExpr::Or(vec![state_is("a"), state_is("b")]))
    .canonicalize()
    .unwrap();
    let txn = s.begin_transaction(false, t(0)).unwrap();
    assert!(s.run_query_in_transaction(&txn, &q).unwrap().is_empty());
    assert_refused(
        &mut s,
        &[set("rg/x", &[("state", Value::String("a".into()))])],
        "left side",
    );
    assert_refused(
        &mut s,
        &[set("rg/y", &[("state", Value::String("b".into()))])],
        "right side",
    );
    assert!(s
        .commit(&[set("rg/z", &[("state", Value::String("c".into()))])], None, t(3))
        .is_ok());
}

#[test]
fn a_transaction_nearest_query_replays_with_vector_semantics_after_conflict() {
    use fireemu_core_firestore::query::{DistanceMeasure, FindNearest, Query, QueryScope};
    use fireemu_core_types::ids::CollectionId;

    let mut state = FirestoreState::new();
    state
        .commit(
            &[set(
                "items/a",
                &[("embedding", Value::Vector(vec![1.0, 0.0]))],
            )],
            None,
            t(0),
        )
        .unwrap();
    let query = Query::new(QueryScope::collection(
        None,
        CollectionId::try_new("items").unwrap(),
    ))
    .with_find_nearest(FindNearest {
        vector_field: FieldPath::parse("embedding").unwrap(),
        query_vector: vec![1.0, 0.0],
        distance_measure: DistanceMeasure::Euclidean,
        limit: 1,
        distance_result_field: None,
        distance_threshold: None,
    })
    .canonicalize()
    .unwrap();
    let first = state.begin_transaction(false, t(1)).unwrap();
    let second = state.begin_transaction(false, t(1)).unwrap();
    assert_eq!(
        state.run_query_in_transaction(&first, &query).unwrap()[0]
            .path
            .document_id()
            .as_str(),
        "a"
    );
    assert_eq!(
        state.run_query_in_transaction(&second, &query).unwrap()[0]
            .path
            .document_id()
            .as_str(),
        "a"
    );
    let replacement = set("items/a", &[("embedding", Value::Vector(vec![0.0, 1.0]))]);
    assert!(matches!(
        state.commit(std::slice::from_ref(&replacement), Some(&first), t(2)),
        Err(FirestoreError::Aborted(message)) if message == TOO_MUCH_CONTENTION
    ));
    assert!(matches!(
        state.commit(std::slice::from_ref(&replacement), Some(&second), t(3)),
        Err(FirestoreError::Aborted(message)) if message == TOO_MUCH_CONTENTION
    ));
    state
        .commit(std::slice::from_ref(&replacement), Some(&first), t(4))
        .unwrap();
    let retry = state.retry_transaction(&second, t(5)).unwrap();
    state.touch_transaction(&retry, t(5)).unwrap();
    let nearest = state.run_query_in_transaction(&retry, &query).unwrap();
    assert_eq!(nearest.len(), 1);
    assert_eq!(
        nearest[0].fields["embedding"],
        Value::Vector(vec![0.0, 1.0])
    );
}

#[test]
fn an_unrelated_commit_does_not_conflict_with_a_bounded_nearest_observation() {
    use fireemu_core_firestore::query::{DistanceMeasure, FindNearest, Query, QueryScope};
    use fireemu_core_types::ids::CollectionId;

    let mut state = FirestoreState::new();
    state
        .commit(
            &[
                set(
                    "items/near",
                    &[("embedding", Value::Vector(vec![1.0, 0.0]))],
                ),
                set("items/far", &[("embedding", Value::Vector(vec![5.0, 0.0]))]),
            ],
            None,
            t(0),
        )
        .unwrap();
    let query = Query::new(QueryScope::collection(
        None,
        CollectionId::try_new("items").unwrap(),
    ))
    .with_find_nearest(FindNearest {
        vector_field: FieldPath::parse("embedding").unwrap(),
        query_vector: vec![1.0, 0.0],
        distance_measure: DistanceMeasure::Euclidean,
        limit: 1,
        distance_result_field: None,
        distance_threshold: None,
    })
    .canonicalize()
    .unwrap();
    let transaction = state.begin_transaction(false, t(1)).unwrap();
    let nearest = state
        .run_query_in_transaction(&transaction, &query)
        .unwrap();
    assert_eq!(nearest.len(), 1);
    assert_eq!(nearest[0].path.document_id().as_str(), "near");

    state
        .commit(&[set("other/unrelated", &[])], None, t(2))
        .unwrap();
    state
        .commit(
            &[set("other/transaction-write", &[])],
            Some(&transaction),
            t(3),
        )
        .unwrap();
}

#[test]
fn a_maximum_vector_query_is_charged_before_transaction_admission() {
    use fireemu_core_firestore::query::{
        DistanceMeasure, FieldOp, FilterExpr, FindNearest, Query, QueryScope,
    };
    use fireemu_core_types::ids::CollectionId;

    let mut state = FirestoreState::new();
    let baseline = state.begin_transaction(false, t(0)).unwrap();
    let empty = Query::new(QueryScope::collection(
        None,
        CollectionId::try_new("empty").unwrap(),
    ));
    state.run_query_in_transaction(&baseline, &empty).unwrap();
    let baseline_bytes = state.transaction_bookkeeping_stats().conflict_ledger_bytes;
    state.rollback(&baseline).unwrap();

    let query = empty
        .with_find_nearest(FindNearest {
            vector_field: FieldPath::parse("embedding").unwrap(),
            query_vector: vec![1.0; 2048],
            distance_measure: DistanceMeasure::Euclidean,
            limit: 1,
            distance_result_field: Some(FieldPath::parse("distance.result").unwrap()),
            distance_threshold: None,
        })
        .canonicalize()
        .unwrap();
    let transaction = state.begin_transaction(false, t(0)).unwrap();
    state
        .run_query_in_transaction(&transaction, &query)
        .unwrap();
    let charged = state.transaction_bookkeeping_stats().conflict_ledger_bytes;
    assert!(charged > baseline_bytes + 2048 * 8);

    let mut oversized = query;
    oversized.filter = Some(FilterExpr::Field {
        field: FieldPath::parse("unused").unwrap(),
        op: FieldOp::Equal,
        value: Value::String(
            "x".repeat(usize::try_from(MAX_TRANSACTION_CONFLICT_LEDGER_BYTES).unwrap() - 8_000),
        ),
    });
    let refused = state.begin_transaction(false, t(0)).unwrap();
    assert!(matches!(
        state.run_query_in_transaction(&refused, &oversized),
        Err(FirestoreError::Aborted(message))
            if message == "transaction observed data exceeds the retained conflict-detection budget"
    ));
}

#[test]
fn maximum_vector_query_descriptors_share_the_active_transaction_budget() {
    use fireemu_core_firestore::query::{
        DistanceMeasure, FieldOp, FilterExpr, FindNearest, Query, QueryScope,
    };
    use fireemu_core_types::ids::CollectionId;

    let mut state = FirestoreState::new();
    let mut query = Query::new(QueryScope::collection(
        None,
        CollectionId::try_new("empty").unwrap(),
    ));
    query.filter = Some(FilterExpr::Field {
        field: FieldPath::parse("unused").unwrap(),
        op: FieldOp::Equal,
        value: Value::String("q".repeat(1024 * 1024)),
    });
    query.find_nearest = Some(FindNearest {
        vector_field: FieldPath::parse("embedding").unwrap(),
        query_vector: vec![0.0; 2048],
        distance_measure: DistanceMeasure::Euclidean,
        limit: 1,
        distance_result_field: Some(FieldPath::parse("distance").unwrap()),
        distance_threshold: None,
    });
    let mut active = Vec::new();
    let mut refused = false;
    for attempt in 0..128 {
        let transaction = state.begin_transaction(false, t(0)).unwrap();
        match state.run_query_in_transaction(&transaction, &query) {
            Ok(_) => active.push(transaction),
            Err(FirestoreError::Aborted(_)) => {
                state.abandon_transaction(&transaction);
                refused = true;
                break;
            }
            Err(error) => panic!("unexpected vector query failure: {error}"),
        }
        assert!(attempt < 127);
    }
    assert!(
        refused,
        "active vector query descriptors must hit the global cap"
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
fn failed_multiwrite_commit_does_not_publish_any_document() {
    let mut state = FirestoreState::new();
    let invalid = Value::String("x".repeat(1_048_488));

    let result = state.commit(
        &[
            set("atomic/valid", &[("value", Value::Integer(1))]),
            set("atomic/invalid", &[("value", invalid)]),
        ],
        None,
        t(0),
    );

    assert!(matches!(result, Err(FirestoreError::InvalidArgument(_))));
    assert!(state.get(&path("atomic/valid")).is_none());
    assert!(state.get(&path("atomic/invalid")).is_none());
    assert_eq!(state.current_version(), CommitVersion::default());
}

#[test]
fn failed_transaction_commit_keeps_lock_until_explicit_rollback() {
    let mut state = FirestoreState::new();
    state
        .commit(
            &[set("locked/doc", &[("value", Value::Integer(1))])],
            None,
            t(0),
        )
        .unwrap();
    let transaction = state.begin_transaction(false, t(1)).unwrap();
    state
        .get_in_transaction(&transaction, &path("locked/doc"))
        .unwrap();

    let invalid = Value::String("x".repeat(1_048_488));
    let result = state.commit(
        &[
            set("atomic/valid", &[("value", Value::Integer(1))]),
            set("atomic/invalid", &[("value", invalid)]),
        ],
        Some(&transaction),
        t(2),
    );
    assert!(matches!(result, Err(FirestoreError::InvalidArgument(_))));
    assert!(state.transaction_is_active(&transaction));
    assert_eq!(state.transaction_bookkeeping_stats().active, 1);
    assert!(matches!(
        state.commit(&[set("locked/doc", &[("value", Value::Integer(2))])], None, t(3)),
        Err(FirestoreError::Aborted(message)) if message == TOO_MUCH_CONTENTION
    ));

    state.rollback(&transaction).unwrap();
    assert_eq!(state.transaction_bookkeeping_stats().active, 0);
    state
        .commit(
            &[set("locked/doc", &[("value", Value::Integer(2))])],
            None,
            t(4),
        )
        .unwrap();
    assert_eq!(
        state.get(&path("locked/doc")).unwrap().fields.get("value"),
        Some(&Value::Integer(2))
    );
}

#[test]
fn valid_multiwrite_and_transaction_commit_are_near_success_controls() {
    let mut state = FirestoreState::new();
    state
        .commit(
            &[
                set("control/one", &[("value", Value::Integer(1))]),
                set("control/two", &[("value", Value::Integer(2))]),
            ],
            None,
            t(0),
        )
        .unwrap();
    assert!(state.get(&path("control/one")).is_some());
    assert!(state.get(&path("control/two")).is_some());

    let transaction = state.begin_transaction(false, t(1)).unwrap();
    state
        .get_in_transaction(&transaction, &path("control/one"))
        .unwrap();
    state
        .commit(
            &[set("control/one", &[("value", Value::Integer(3))])],
            Some(&transaction),
            t(2),
        )
        .unwrap();
    assert!(!state.transaction_is_active(&transaction));
    state
        .commit(
            &[set("control/one", &[("value", Value::Integer(4))])],
            None,
            t(3),
        )
        .unwrap();
}

#[test]
fn transaction_query_records_are_execution_scoped_and_overflow_is_retryable() {
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
        2,
        "identical query executions keep separate conflict records"
    );
    assert!(
        state.transaction_bookkeeping_stats().conflict_ledger_bytes > conflict_ledger_bytes,
        "a repeated execution retains its own query descriptor while sharing read paths"
    );

    state.rollback(&transaction).unwrap();
    let transaction = state.begin_transaction(false, t(0)).unwrap();
    state.run_query_in_transaction(&transaction, &base).unwrap();
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
    for attempt in 0..128 {
        let transaction = state.begin_transaction(attempt % 2 == 0, t(0)).unwrap();
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

fn seed_exactly_charged_documents(state: &mut FirestoreState, target: u64) {
    use fireemu_core_firestore::size::document_size;
    let mut remaining = target;
    for index in 0..64 {
        let name = format!("byte-boundary/{index:03}");
        let empty = fields(&[("payload", Value::String(String::new()))]);
        let overhead = document_size(&path(&name), &empty).unwrap().total;
        let charge = if index == 63 { remaining } else { target / 64 };
        let payload = "x".repeat(usize::try_from(charge - overhead).unwrap());
        state
            .commit(
                &[set(&name, &[("payload", Value::String(payload))])],
                None,
                t(0),
            )
            .unwrap();
        remaining -= charge;
    }
    assert_eq!(remaining, 0);
}

#[test]
fn read_only_document_reads_do_not_consume_the_read_write_byte_budget() {
    for delta in [-1_i64, 0, 1] {
        let target = MAX_TRANSACTION_CONFLICT_LEDGER_BYTES
            .checked_add_signed(delta)
            .unwrap();
        let mut state = FirestoreState::new();
        seed_exactly_charged_documents(&mut state, target);
        for read_only in [true, false] {
            let transaction = state.begin_transaction(read_only, t(0)).unwrap();
            for index in 0..64 {
                let result = state
                    .get_in_transaction(&transaction, &path(&format!("byte-boundary/{index:03}")));
                if !read_only && delta == 1 && index == 63 {
                    assert!(matches!(result, Err(FirestoreError::Aborted(_))));
                } else {
                    assert!(result.unwrap().is_some());
                }
            }
            let expected = if read_only || delta == 1 { 0 } else { target };
            assert_eq!(
                state.transaction_bookkeeping_stats().conflict_ledger_bytes,
                expected
            );
            state.abandon_transaction(&transaction);
        }
        assert_eq!(state.transaction_bookkeeping_stats().active, 0);
    }
}

#[test]
fn large_read_only_queries_retain_descriptors_but_not_document_conflicts() {
    use fireemu_core_firestore::query::{Query, QueryScope};
    use fireemu_core_types::ids::CollectionId;

    let mut state = FirestoreState::new();
    let query = Query::new(QueryScope::collection(
        None,
        CollectionId::try_new("large-ro").unwrap(),
    ));
    let empty = state.begin_transaction(true, t(0)).unwrap();
    assert!(state
        .run_query_in_transaction(&empty, &query)
        .unwrap()
        .is_empty());
    let descriptor_bytes = state.transaction_bookkeeping_stats().conflict_ledger_bytes;
    assert!(descriptor_bytes > 0);
    state.rollback(&empty).unwrap();
    let payload = "x".repeat(192 * 1024);
    for index in 0..65 {
        state
            .commit(
                &[set(
                    &format!("large-ro/{index:03}"),
                    &[("payload", Value::String(payload.clone()))],
                )],
                None,
                t(0),
            )
            .unwrap();
    }
    let transaction = state.begin_transaction(true, t(0)).unwrap();
    let first = state
        .run_query_in_transaction(&transaction, &query)
        .unwrap();
    assert_eq!(first.len(), 65);
    assert_eq!(
        state.transaction_bookkeeping_stats().conflict_ledger_bytes,
        descriptor_bytes
    );
    state
        .commit(
            &[set(
                "large-ro/064",
                &[("payload", Value::String("new".into()))],
            )],
            None,
            t(1),
        )
        .unwrap();
    let second = state
        .run_query_in_transaction(&transaction, &query)
        .unwrap();
    assert_eq!(
        first, second,
        "the read-only snapshot remains pinned across writes"
    );
    assert_eq!(
        state.transaction_bookkeeping_stats().conflict_ledger_bytes,
        descriptor_bytes * 2
    );
    for document in &first {
        assert_eq!(
            state
                .get_in_transaction(&transaction, &document.path)
                .unwrap()
                .as_ref(),
            Some(document)
        );
    }
    assert_eq!(
        state.transaction_bookkeeping_stats().conflict_ledger_bytes,
        descriptor_bytes * 2
    );
    assert_eq!(
        state
            .transaction_recorded_query_count(&transaction)
            .unwrap(),
        2
    );
    state.rollback(&transaction).unwrap();
    assert!(state
        .run_query_in_transaction(&transaction, &query)
        .is_err());
    assert_eq!(state.transaction_bookkeeping_stats().active, 0);
    assert_eq!(
        state.transaction_bookkeeping_stats().conflict_ledger_bytes,
        0
    );
}

#[test]
fn read_only_queries_do_not_consume_document_bytes_at_the_exact_query_budget_boundary() {
    use fireemu_core_firestore::query::{Query, QueryScope};
    use fireemu_core_types::ids::CollectionId;

    for delta in [-1_i64, 0, 1] {
        let mut state = FirestoreState::new();
        let query = Query::new(QueryScope::collection(
            None,
            CollectionId::try_new("byte-boundary").unwrap(),
        ));
        let empty = state.begin_transaction(false, t(0)).unwrap();
        assert!(state
            .run_query_in_transaction(&empty, &query)
            .unwrap()
            .is_empty());
        let descriptor_bytes = state.transaction_bookkeeping_stats().conflict_ledger_bytes;
        assert!(descriptor_bytes > 0);
        state.abandon_transaction(&empty);
        let target = MAX_TRANSACTION_CONFLICT_LEDGER_BYTES
            .checked_add_signed(delta)
            .unwrap();
        seed_exactly_charged_documents(&mut state, target - descriptor_bytes);
        let expected_documents = state.run_query(&query, None).unwrap();
        for read_only in [true, false] {
            let transaction = state.begin_transaction(read_only, t(0)).unwrap();
            let result = state.run_query_in_transaction(&transaction, &query);
            if !read_only && delta == 1 {
                assert!(matches!(result, Err(FirestoreError::Aborted(_))));
            } else {
                assert_eq!(result.unwrap(), expected_documents);
            }
            let expected_charge = if read_only {
                descriptor_bytes
            } else if delta == 1 {
                0
            } else {
                target
            };
            assert_eq!(
                state.transaction_bookkeeping_stats().conflict_ledger_bytes,
                expected_charge
            );
            state.abandon_transaction(&transaction);
        }
        assert_eq!(state.transaction_bookkeeping_stats().active, 0);
        assert_eq!(
            state.transaction_bookkeeping_stats().conflict_ledger_bytes,
            0
        );
    }
}

#[test]
fn read_only_query_descriptors_still_have_count_and_byte_limits() {
    use fireemu_core_firestore::query::{FieldOp, FilterExpr, Query, QueryScope};
    use fireemu_core_types::ids::CollectionId;

    for oversized in [false, true] {
        let mut state = FirestoreState::new();
        let transaction = state.begin_transaction(true, t(0)).unwrap();
        let mut query = Query::new(QueryScope::collection(
            None,
            CollectionId::try_new("empty").unwrap(),
        ));
        if oversized {
            query.filter = Some(FilterExpr::Field {
                field: FieldPath::parse("payload").unwrap(),
                op: FieldOp::Equal,
                value: Value::String("q".repeat(11 * 1024 * 1024)),
            });
        } else {
            for _ in 0..MAX_TRANSACTION_QUERY_RECORDS {
                assert!(state
                    .run_query_in_transaction(&transaction, &query)
                    .unwrap()
                    .is_empty());
            }
        }
        assert!(matches!(
            state.run_query_in_transaction(&transaction, &query),
            Err(FirestoreError::Aborted(_))
        ));
        assert_eq!(
            state.transaction_bookkeeping_stats().conflict_ledger_bytes,
            0
        );
        state.abandon_transaction(&transaction);
    }
}

// These are controlled-clock counterparts of the recorded native 65-second recipes. They do not establish an exact production timeout or equate maintenance with wall time.
#[test]
fn recorded_native_idle_candidate_commit_survives_maintenance() {
    for maintenance in [false, true] {
        let mut state = FirestoreState::new();
        let transaction = state.begin_transaction(false, t(0)).unwrap();
        state
            .get_in_transaction(&transaction, &path("idle/doc"))
            .unwrap();
        if maintenance {
            for second in 0..=65 {
                state.compact(t(second));
            }
        }
        assert_eq!(state.transaction_bookkeeping_stats().active, 1);
        assert_eq!(state.transaction_bookkeeping_stats().deadlines, 1);
        state
            .commit(
                &[set("idle/doc", &[("value", Value::Integer(1))])],
                Some(&transaction),
                t(65),
            )
            .unwrap();
        assert_eq!(
            state.get(&path("idle/doc")).unwrap().fields.get("value"),
            Some(&Value::Integer(1))
        );
    }
}

#[test]
fn recorded_native_idle_candidate_rollback_first_preserves_retry() {
    for maintenance in [false, true] {
        let mut state = FirestoreState::new();
        let transaction = state.begin_transaction(false, t(0)).unwrap();
        state
            .get_in_transaction(&transaction, &path("idle/doc"))
            .unwrap();
        if maintenance {
            for second in 0..=65 {
                state.compact(t(second));
            }
        }
        assert_eq!(state.transaction_bookkeeping_stats().active, 1);
        assert_eq!(state.transaction_bookkeeping_stats().deadlines, 1);
        state.rollback(&transaction).unwrap();
        state
            .commit(
                &[set("idle/doc", &[("value", Value::Integer(2))])],
                None,
                t(65),
            )
            .unwrap();
        let retry = state.retry_transaction(&transaction, t(66)).unwrap();
        state.touch_transaction(&retry, t(66)).unwrap();
        assert_ne!(retry, transaction);
        assert_eq!(
            state
                .get_in_transaction(&retry, &path("idle/doc"))
                .unwrap()
                .unwrap()
                .fields
                .get("value"),
            Some(&Value::Integer(2))
        );
        assert!(matches!(
            state.retry_transaction(&transaction, t(67)),
            Err(FirestoreError::InvalidArgument(_))
        ));
    }
}

#[test]
fn recorded_native_idle_candidate_get_first_refreshes_activity() {
    for maintenance in [false, true] {
        let mut state = FirestoreState::new();
        state
            .commit(
                &[set("idle/doc", &[("value", Value::Integer(1))])],
                None,
                t(0),
            )
            .unwrap();
        let transaction = state.begin_transaction(false, t(0)).unwrap();
        state
            .get_in_transaction(&transaction, &path("idle/doc"))
            .unwrap();
        if maintenance {
            for second in 0..=65 {
                state.compact(t(second));
            }
        }
        assert_eq!(state.transaction_bookkeeping_stats().active, 1);
        assert_eq!(state.transaction_bookkeeping_stats().deadlines, 1);
        state.touch_transaction(&transaction, t(65)).unwrap();
        assert_eq!(
            state
                .get_in_transaction(&transaction, &path("idle/doc"))
                .unwrap()
                .unwrap()
                .fields
                .get("value"),
            Some(&Value::Integer(1))
        );
        state.compact(t(120));
        state.touch_transaction(&transaction, t(120)).unwrap();
    }
}

#[test]
fn recorded_native_idle_candidate_get_then_rollback_preserves_retry() {
    for maintenance in [false, true] {
        let mut state = FirestoreState::new();
        let transaction = state.begin_transaction(false, t(0)).unwrap();
        state
            .get_in_transaction(&transaction, &path("idle/doc"))
            .unwrap();
        if maintenance {
            for second in 0..=65 {
                state.compact(t(second));
            }
        }
        assert_eq!(state.transaction_bookkeeping_stats().active, 1);
        assert_eq!(state.transaction_bookkeeping_stats().deadlines, 1);
        state.touch_transaction(&transaction, t(65)).unwrap();
        assert!(state
            .get_in_transaction(&transaction, &path("idle/doc"))
            .unwrap()
            .is_none());
        state.rollback(&transaction).unwrap();
        state
            .commit(
                &[set("idle/doc", &[("value", Value::Integer(2))])],
                None,
                t(65),
            )
            .unwrap();
        let retry = state.retry_transaction(&transaction, t(66)).unwrap();
        state.touch_transaction(&retry, t(66)).unwrap();
        assert_eq!(
            state
                .get_in_transaction(&retry, &path("idle/doc"))
                .unwrap()
                .unwrap()
                .fields
                .get("value"),
            Some(&Value::Integer(2))
        );
    }
}

#[test]
fn idle_candidate_allowance_is_strict_only() {
    for (scope, accepted) in [
        (LimitScope::Production, true),
        (LimitScope::OfficialEmulator, false),
    ] {
        for maintenance in [false, true] {
            for commit_first in [false, true] {
                let mut state = FirestoreState::with_limit_scope(scope);
                let transaction = state.begin_transaction(false, t(0)).unwrap();
                if maintenance {
                    for second in 0..=65 {
                        state.compact(t(second));
                    }
                }
                let result = if commit_first {
                    state.commit(&[], Some(&transaction), t(65)).map(|_| ())
                } else {
                    state.touch_transaction(&transaction, t(65))
                };
                if accepted {
                    result.unwrap();
                } else {
                    assert!(matches!(result, Err(FirestoreError::Aborted(_))));
                }
            }
        }
    }
}

/// An instant `ms` milliseconds after `t(0)`.
fn t_ms(ms: i64) -> LogicalInstant {
    LogicalInstant::from_nanos((1_788_000_000_i128 * 1_000 + i128::from(ms)) * 1_000_000)
}

#[test]
fn strict_idle_limit_follows_the_p10c_bracket() {
    // Production accepted a native Commit after a nominal 110 s idle (its measured idle lay in
    // [110.58, 113.12] s, P10-C, twice) and refused one after 120 s ([120.54, 122.97] s, twice); the
    // REST refusal sat at about 121 s. Strict takes the limit at 120 s: it must not refuse what
    // production accepted (113.12 s and the earlier 65 to 70 s samples, the latest at 72.9 s) and
    // must refuse what production refused (120.54 s). The gap 113.12 to 120 s is unobserved and
    // accepted. This is a provisional bracket, not an exact production threshold.
    let cases: [(i64, bool); 9] = [
        (60_100, true),
        (72_900, true),
        (113_120, true),
        (113_200, true),
        (119_000, true),
        (119_900, true),
        (120_000, false),
        (120_540, false),
        (120_600, false),
    ];
    for (millis, accepted) in cases {
        for maintenance in [false, true] {
            for commit_first in [false, true] {
                let mut state = FirestoreState::new();
                let transaction = state.begin_transaction(false, t(0)).unwrap();
                if maintenance {
                    state.compact(t_ms(millis));
                    let expected = usize::from(accepted);
                    assert_eq!(state.transaction_bookkeeping_stats().active, expected);
                    assert_eq!(state.transaction_bookkeeping_stats().deadlines, expected);
                }
                let result = if commit_first {
                    state
                        .commit(&[], Some(&transaction), t_ms(millis))
                        .map(|_| ())
                } else {
                    state.touch_transaction(&transaction, t_ms(millis))
                };
                if accepted {
                    result.unwrap_or_else(|error| panic!("{millis} ms refused: {error:?}"));
                } else {
                    assert!(
                        matches!(result, Err(FirestoreError::Aborted(_))),
                        "{millis} ms accepted"
                    );
                }
            }
        }
    }
}

#[test]
fn the_official_emulator_profile_keeps_the_nominal_idle_budget() {
    // The pinned official emulator has no allowance: 60.1 s idle is refused, 59.9 s is not.
    for (millis, accepted) in [
        (59_900, true),
        (60_100, false),
        (72_900, false),
        (120_600, false),
    ] {
        for commit_first in [false, true] {
            let mut state = FirestoreState::with_limit_scope(LimitScope::OfficialEmulator);
            let transaction = state.begin_transaction(false, t(0)).unwrap();
            let result = if commit_first {
                state
                    .commit(&[], Some(&transaction), t_ms(millis))
                    .map(|_| ())
            } else {
                state.touch_transaction(&transaction, t_ms(millis))
            };
            if accepted {
                result.unwrap();
            } else {
                assert!(
                    matches!(result, Err(FirestoreError::Aborted(_))),
                    "{millis} ms"
                );
            }
        }
    }
}

#[test]
fn transactions_expire_on_idle_and_total_time() {
    // Strict adds a provisional allowance to the nominal idle quota. A safely later local sample checks irreversible expiry; it does not measure an exact production boundary.
    // The independent 270 s total budget remains unchanged.
    let mut s = FirestoreState::new();
    let txn = s.begin_transaction(false, t(0)).unwrap();
    assert!(s.touch_transaction(&txn, t(59)).is_ok());
    assert!(
        s.touch_transaction(&txn, t(118)).is_ok(),
        "idle window restarts"
    );
    // More than 120 s after the last activity (t(118)) the local idle budget is spent. An expired transaction is ABORTED (the code the SDKs retry), the same as a finished one.
    assert!(matches!(
        s.touch_transaction(&txn, t(240)),
        Err(FirestoreError::Aborted(_))
    ));
    assert!(
        s.touch_transaction(&txn, t(242)).is_err(),
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

#[test]
fn rewriting_a_nan_document_is_a_no_op_but_a_type_change_is_not() {
    for current in [
        Value::Double(f64::NAN),
        Value::Array(vec![Value::Double(f64::NAN), Value::Integer(1)]),
        Value::Map(fields(&[("inner", Value::Double(f64::NAN))])),
    ] {
        let mut s = FirestoreState::new();
        let first = s
            .commit(&[set("nan/doc", &[("v", current.clone())])], None, t(0))
            .unwrap();
        assert_eq!(first.changes.len(), 1);
        let before = s.get(&path("nan/doc")).unwrap().clone();

        // The same NaN payload again: no change, no new version, no update time.
        let rewrite = s
            .commit(&[set("nan/doc", &[("v", current.clone())])], None, t(5))
            .unwrap();
        assert!(
            rewrite.changes.is_empty(),
            "{current:?} rewrite produced changes"
        );
        assert_eq!(rewrite.version, first.version);
        assert_eq!(
            rewrite.write_results[0].update_time,
            Some(before.update_time)
        );
        let after = s.get(&path("nan/doc")).unwrap();
        assert_eq!(after.version, before.version);
        assert_eq!(after.update_time, before.update_time);

        // A verify changes nothing either, even with NaN in the document.
        let verify = Write {
            op: WriteOp::Verify {
                path: path("nan/doc"),
            },
            precondition: Some(Precondition::Exists(true)),
            transforms: vec![],
        };
        let verified = s.commit(&[verify], None, t(6)).unwrap();
        assert!(verified.changes.is_empty());
        assert_eq!(verified.version, first.version);
        assert_eq!(
            verified.write_results[0].update_time,
            Some(before.update_time)
        );
    }

    // Storing NaN over NaN via a maximum transform is a no-op as well.
    let mut s = FirestoreState::new();
    let first = s
        .commit(
            &[set("nan/max", &[("v", Value::Double(f64::NAN))])],
            None,
            t(0),
        )
        .unwrap();
    let transform = Write {
        transforms: vec![FieldTransform {
            field: FieldPath::parse("v").unwrap(),
            kind: TransformKind::Maximum(Value::Integer(5)),
        }],
        ..set("nan/max", &[])
    };
    let mut transform = transform;
    if let WriteOp::Set { update_mask, .. } = &mut transform.op {
        *update_mask = Some(vec![]);
    }
    let maxed = s.commit(&[transform], None, t(1)).unwrap();
    assert!(maxed.changes.is_empty());
    assert_eq!(maxed.version, first.version);
    assert!(matches!(
        s.get(&path("nan/max")).unwrap().fields.get("v"),
        Some(Value::Double(d)) if d.is_nan()
    ));

    // Control: changing the numeric type (integer to double) is a real change.
    let mut s = FirestoreState::new();
    let first = s
        .commit(&[set("num/doc", &[("v", Value::Integer(1))])], None, t(0))
        .unwrap();
    let retyped = s
        .commit(&[set("num/doc", &[("v", Value::Double(1.0))])], None, t(1))
        .unwrap();
    assert_eq!(retyped.changes.len(), 1);
    assert_ne!(retyped.version, first.version);
}

#[test]
fn stored_timestamps_are_truncated_to_microseconds() {
    use fireemu_core_firestore::value::Timestamp;
    let nanos = |n: u32| Value::Timestamp(Timestamp::new(1_788_000_000, n).unwrap());
    let mut s = FirestoreState::new();
    let doc = fields(&[
        ("at", nanos(123_456_789)),
        ("list", Value::Array(vec![nanos(123_456_001)])),
        ("nested", Value::Map(fields(&[("at", nanos(999_999_999))]))),
    ]);
    let entries: Vec<_> = doc.iter().map(|(k, v)| (k.as_str(), v.clone())).collect();
    let first = s.commit(&[set("ts/doc", &entries)], None, t(0)).unwrap();
    let stored = s.get(&path("ts/doc")).unwrap();
    assert_eq!(stored.fields.get("at"), Some(&nanos(123_456_000)));
    assert_eq!(
        stored.fields.get("list"),
        Some(&Value::Array(vec![nanos(123_456_000)]))
    );
    assert_eq!(
        stored.fields.get("nested"),
        Some(&Value::Map(fields(&[("at", nanos(999_999_000))])))
    );

    // A rewrite that only differs below microsecond precision is a no-op.
    let rewrite = s.commit(&[set("ts/doc", &entries)], None, t(1)).unwrap();
    assert!(rewrite.changes.is_empty());
    assert_eq!(rewrite.version, first.version);

    // Partial updates and array transforms go through the same normalization.
    let mut masked = set("ts/doc", &[("at", nanos(5_001))]);
    if let WriteOp::Set { update_mask, .. } = &mut masked.op {
        *update_mask = Some(vec![FieldPath::parse("at").unwrap()]);
    }
    masked.transforms.push(FieldTransform {
        field: FieldPath::parse("list").unwrap(),
        kind: TransformKind::AppendMissingElements(vec![nanos(7_999)]),
    });
    s.commit(&[masked], None, t(2)).unwrap();
    let stored = s.get(&path("ts/doc")).unwrap();
    assert_eq!(stored.fields.get("at"), Some(&nanos(5_000)));
    assert_eq!(
        stored.fields.get("list"),
        Some(&Value::Array(vec![nanos(123_456_000), nanos(7_000)]))
    );
}

#[test]
fn resource_names_round_trip_and_non_document_names_are_rejected() {
    let doc = path("users/jeff/tasks/t1");
    assert_eq!(
        DocumentPath::from_resource_name(&doc.resource_name()),
        Some(doc.clone())
    );
    for name in [
        "projects/demo-app/databases/(default)/documents/users",
        "projects/demo-app/databases/(default)/documents/",
        "projects/demo-app/databases/(default)/documents",
        "projects/demo-app/documents/users/jeff",
        "users/jeff",
        "projects//databases/(default)/documents/users/jeff",
        "projects/demo-app/databases/(default)/documents/users//tasks/t1",
    ] {
        assert_eq!(DocumentPath::from_resource_name(name), None, "{name}");
    }
}

// Same REST inputs observed on production fireemu-35fe6 on 2026-09-08.
#[test]
fn timestamp_array_transforms_compare_storage_precision_recursively() {
    use fireemu_core_firestore::value::Timestamp;
    for shape in 0..3 {
        let item = |nanos| {
            let value = Value::Timestamp(Timestamp::new(1_788_220_800, nanos).unwrap());
            match shape {
                0 => value,
                1 => Value::Map(fields(&[("at", value)])),
                _ => Value::Map(fields(&[(
                    "nested",
                    Value::Array(vec![Value::Map(fields(&[("at", value)]))]),
                )])),
            }
        };
        for precision in [123_456_789, 123_456_000] {
            let raw = item(precision);
            let same_microsecond = item(123_456_001);
            let stored = item(123_456_000);
            let mut state = FirestoreState::new();
            let array = |items| Value::Array(items);
            let mut transform = set("timestamps/array", &[]);
            if let WriteOp::Set { update_mask, .. } = &mut transform.op {
                *update_mask = Some(vec![]);
            }
            transform.transforms.push(FieldTransform {
                field: FieldPath::parse("values").unwrap(),
                kind: TransformKind::AppendMissingElements(vec![
                    raw.clone(),
                    same_microsecond.clone(),
                ]),
            });
            let first = state.commit(&[transform.clone()], None, t(0)).unwrap();
            assert_eq!(
                state.get(&path("timestamps/array")).unwrap().fields["values"],
                array(vec![stored.clone()]),
                "union deduplicates operands at storage precision: shape={shape}, precision={precision}"
            );
            for now in [1, 2] {
                let repeated = state.commit(&[transform.clone()], None, t(now)).unwrap();
                assert_eq!(repeated.version, first.version);
                assert_eq!(
                    repeated.write_results[0].update_time,
                    first.write_results[0].update_time
                );
                assert_eq!(
                    repeated.write_results[0].transform_results,
                    vec![Value::Null]
                );
                assert!(repeated.changes.is_empty());
            }
            transform.transforms[0].kind = TransformKind::RemoveAllFromArray(vec![raw.clone()]);
            let removed = state.commit(&[transform.clone()], None, t(3)).unwrap();
            assert_eq!(removed.changes.len(), 1);
            assert_eq!(
                state.get(&path("timestamps/array")).unwrap().fields["values"],
                array(vec![])
            );
            let repeated = state.commit(&[transform], None, t(4)).unwrap();
            assert!(repeated.changes.is_empty());
            assert_eq!(
                repeated.write_results[0].update_time,
                removed.write_results[0].update_time
            );

            // A normal set preserves user-supplied duplicates after normalization.
            let duplicate = set(
                "timestamps/array",
                &[("values", array(vec![raw.clone(), same_microsecond.clone()]))],
            );
            state.commit(&[duplicate], None, t(5)).unwrap();
            assert_eq!(
                state.get(&path("timestamps/array")).unwrap().fields["values"],
                array(vec![stored.clone(), stored.clone()])
            );

            // Both sides of the comparison originate in this write, before storage.
            for remove in [false, true] {
                let mut write = set("timestamps/array", &[("values", array(vec![raw.clone()]))]);
                write.transforms.push(FieldTransform {
                    field: FieldPath::parse("values").unwrap(),
                    kind: if remove {
                        TransformKind::RemoveAllFromArray(vec![same_microsecond.clone()])
                    } else {
                        TransformKind::AppendMissingElements(vec![same_microsecond.clone()])
                    },
                });
                state
                    .commit(&[write], None, t(6 + i64::from(remove)))
                    .unwrap();
                assert_eq!(
                    state.get(&path("timestamps/array")).unwrap().fields["values"],
                    array(if remove { vec![] } else { vec![stored.clone()] })
                );
            }
        }
    }
}

#[test]
fn verify_observes_staged_writes_and_preserves_atomic_validation() {
    let verify = |precondition| Write {
        op: WriteOp::Verify {
            path: path("verify/doc"),
        },
        precondition,
        transforms: vec![],
    };
    let mut state = FirestoreState::new();
    let absent = state
        .commit(&[verify(Some(Precondition::Exists(false)))], None, t(0))
        .unwrap();
    assert!(absent.changes.is_empty());
    assert_eq!(absent.write_results[0].update_time, None);
    let created = state
        .commit(
            &[
                set("verify/doc", &[("n", Value::Integer(1))]),
                verify(Some(Precondition::Exists(true))),
            ],
            None,
            t(1),
        )
        .unwrap();
    assert_eq!(created.changes.len(), 1);
    assert_eq!(
        created.write_results[0].update_time,
        created.write_results[1].update_time
    );
    let update_time = created.write_results[0].update_time.unwrap();
    assert!(state
        .commit(
            &[verify(Some(Precondition::UpdateTime(update_time)))],
            None,
            t(2)
        )
        .unwrap()
        .changes
        .is_empty());
    let changed = set("verify/doc", &[("n", Value::Integer(2))]);
    assert!(state
        .commit(
            &[
                changed.clone(),
                verify(Some(Precondition::UpdateTime(update_time)))
            ],
            None,
            t(3)
        )
        .is_err());
    assert_eq!(
        state.get(&path("verify/doc")).unwrap().fields["n"],
        Value::Integer(1)
    );
    let mut invalid = verify(None);
    invalid.transforms.push(FieldTransform {
        field: FieldPath::parse("n").unwrap(),
        kind: TransformKind::Increment(Value::Integer(1)),
    });
    assert!(matches!(
        state.commit(&[changed, invalid], None, t(4)),
        Err(FirestoreError::InvalidArgument(_))
    ));
    assert_eq!(
        state.get(&path("verify/doc")).unwrap().fields["n"],
        Value::Integer(1)
    );
    let removed = state
        .commit(
            &[
                Write {
                    op: WriteOp::Delete {
                        path: path("verify/doc"),
                    },
                    precondition: None,
                    transforms: vec![],
                },
                verify(Some(Precondition::Exists(false))),
            ],
            None,
            t(5),
        )
        .unwrap();
    assert_eq!(removed.changes.len(), 1);
    assert_eq!(removed.write_results[1].update_time, None);
    assert!(state.get(&path("verify/doc")).is_none());
    assert!(state
        .commit(&[verify(Some(Precondition::Exists(true)))], None, t(6))
        .is_err());
}

/// FS-TXN-002 (a). `FS-LIMIT-TRANSACTION-TOTAL-TIME` is 270 s from the transaction's start on
/// the virtual clock, whatever the activity in between: a read-write transaction whose idle
/// window is kept open commits its write at 269 s total and is refused at 271 s total with
/// `ABORTED` and the expiry wording, its write unpublished and its lock released.
#[test]
fn a_transaction_commits_at_269_s_total_and_is_refused_at_271_s_total() {
    for (scope, elapsed, commits) in [
        (LimitScope::Production, 269, true),
        (LimitScope::Production, 271, false),
        (LimitScope::OfficialEmulator, 269, true),
        (LimitScope::OfficialEmulator, 271, false),
    ] {
        let mut s = FirestoreState::with_limit_scope(scope);
        s.commit(&[set("total/doc", &[("v", Value::Integer(0))])], None, t(0))
            .unwrap();
        let txn = s.begin_transaction(false, t(0)).unwrap();
        assert!(s
            .get_in_transaction(&txn, &path("total/doc"))
            .unwrap()
            .is_some());
        // Activity every 59 s keeps either profile's idle window open up to t(236); both commit instants are then inside the idle window, so only the total budget decides.
        for step in 1..=4 {
            s.touch_transaction(&txn, t(step * 59)).unwrap();
        }
        let outcome = s.commit(
            &[set("total/doc", &[("v", Value::Integer(1))])],
            Some(&txn),
            t(elapsed),
        );
        if commits {
            outcome.unwrap_or_else(|error| panic!("commit at {elapsed} s: {error}"));
            assert_eq!(
                s.get(&path("total/doc")).unwrap().fields.get("v"),
                Some(&Value::Integer(1))
            );
        } else {
            assert!(
                matches!(
                    &outcome,
                    Err(FirestoreError::Aborted(message))
                        if message == "The referenced transaction has expired or is no longer valid."
                ),
                "commit at {elapsed} s: {outcome:?}"
            );
            assert_eq!(
                s.get(&path("total/doc")).unwrap().fields.get("v"),
                Some(&Value::Integer(0)),
                "nothing of the expired transaction is published"
            );
            assert!(!s.transaction_is_active(&txn));
            // The expired transaction holds no lock: an out-of-band write goes through.
            s.commit(
                &[set("total/doc", &[("v", Value::Integer(2))])],
                None,
                t(elapsed),
            )
            .unwrap();
        }
    }
}

/// A query's lock covers the range its filter selects, not the whole collection: an
/// out-of-band write to a document inside the queried collection but outside the query's
/// filter is not held back by the transaction, while a write to a document the query
/// returned is refused `ABORTED` with the contention wording until the transaction ends.
///
/// Production, observed: in the P14 recordings (two, `fireemu-oracle-txn`) the REST control
/// writer of a document outside the query's filter (`rest/q1/writer`) answered `OK` in about
/// 1.1 s while the holder was still active, and the phantom writers inside the range were
/// held. The earlier local reading, the whole collection, was a stricter hypothesis
/// (compat-v2 scout report of 2026-09-21, hypothesis 1) that these recordings refute.
#[test]
fn a_transactional_query_does_not_lock_documents_its_filter_excluded() {
    use fireemu_core_firestore::query::{FieldOp, FilterExpr, Query, QueryScope};
    use fireemu_core_types::ids::CollectionId;
    let mut s = FirestoreState::new();
    s.commit(
        &[
            set("qf/selected", &[("v", Value::Integer(1))]),
            set("qf/excluded", &[("v", Value::Integer(2))]),
        ],
        None,
        t(0),
    )
    .unwrap();
    let query = Query::new(QueryScope::collection(
        None,
        CollectionId::try_new("qf").unwrap(),
    ))
    .with_filter(FilterExpr::Field {
        field: FieldPath::parse("v").unwrap(),
        op: FieldOp::Equal,
        value: Value::Integer(1),
    })
    .canonicalize()
    .unwrap();
    let txn = s.begin_transaction(false, t(1)).unwrap();
    let selected = s.run_query_in_transaction(&txn, &query).unwrap();
    assert_eq!(selected.len(), 1);
    assert_eq!(selected[0].path, path("qf/selected"));

    // A document the query returned is locked (production-documented).
    let refused = s
        .commit(
            &[set("qf/selected", &[("v", Value::Integer(3))])],
            None,
            t(2),
        )
        .unwrap_err();
    assert!(
        matches!(&refused, FirestoreError::Aborted(m) if m == TOO_MUCH_CONTENTION),
        "{refused}"
    );
    // A document the filter excluded, inside the same collection, is outside the query's range:
    // its write is not held back (production, P14 `rest/q1/writer`).
    s.commit(
        &[set("qf/excluded", &[("v", Value::Integer(3))])],
        None,
        t(2),
    )
    .unwrap();
    assert_eq!(
        s.get(&path("qf/excluded")).unwrap().fields.get("v"),
        Some(&Value::Integer(3))
    );
    // Outside the queried collection nothing is locked.
    s.commit(&[set("elsewhere/doc", &[])], None, t(2)).unwrap();

    // Rollback releases the range: the document the query returned accepts the write again.
    s.rollback(&txn).unwrap();
    s.commit(
        &[set("qf/selected", &[("v", Value::Integer(3))])],
        None,
        t(3),
    )
    .unwrap();
    assert_eq!(
        s.get(&path("qf/selected")).unwrap().fields.get("v"),
        Some(&Value::Integer(3))
    );
}

// A commit refused by a precondition ends its transaction, as production does (P08, both
// transports, both recordings): the same token then answers INVALID_ARGUMENT in strict (the
// official emulator answers ABORTED, measured at v1.22.0), a Rollback is accepted any number of
// times, the transaction's read locks are gone at once, and the token may still be retried.
// Observed: only the `exists: true` refusal (code 5, "No document to update"). The refusals by
// `exists: false` and by `update_time` are inferred to end the transaction the same way, not
// observed; the rows below stay until a production recording settles them.
const NO_LONGER_VALID: &str = "The referenced transaction has expired or is no longer valid.";

fn precondition_write(p: &str, precondition: Precondition) -> Write {
    Write {
        op: WriteOp::Set {
            path: path(p),
            fields: fields(&[("v", Value::Integer(9))]),
            update_mask: None,
        },
        precondition: Some(precondition),
        transforms: vec![],
    }
}

fn refused_commit_state(scope: LimitScope) -> (FirestoreState, TransactionId) {
    let mut state = FirestoreState::with_limit_scope(scope);
    state
        .commit(&[set("p08/held", &[("v", Value::Integer(1))])], None, t(0))
        .unwrap();
    let transaction = state.begin_transaction(false, t(1)).unwrap();
    state
        .get_in_transaction(&transaction, &path("p08/held"))
        .unwrap();
    (state, transaction)
}

#[test]
fn a_precondition_refused_commit_ends_its_transaction_with_each_profiles_code() {
    let refusals = [
        (
            precondition_write("p08/missing", Precondition::Exists(true)),
            "not found",
        ),
        // Inferred, not observed: `exists: false` and `update_time` refusals.
        (
            precondition_write("p08/held", Precondition::Exists(false)),
            "already exists",
        ),
        (
            precondition_write("p08/held", Precondition::UpdateTime(t(500))),
            "failed precondition",
        ),
    ];
    for (scope, strict) in [
        (LimitScope::Production, true),
        (LimitScope::OfficialEmulator, false),
    ] {
        for (refusing, label) in &refusals {
            let (mut state, transaction) = refused_commit_state(scope);
            let commit = [
                set("p08/held", &[("v", Value::Integer(9))]),
                refusing.clone(),
            ];
            let refused = state.commit(&commit, Some(&transaction), t(2)).unwrap_err();
            assert!(
                matches!(
                    refused,
                    FirestoreError::NotFound(_)
                        | FirestoreError::AlreadyExists(_)
                        | FirestoreError::FailedPrecondition(_)
                ),
                "{label}: the refusal itself keeps its code"
            );
            // The transaction is finished in the bookkeeping too, not only marked: a state that
            // was set without `finish_transaction` would leave it counted as active.
            let bookkeeping = state.transaction_bookkeeping_stats();
            assert_eq!(
                (
                    bookkeeping.active,
                    bookkeeping.finished,
                    bookkeeping.deadlines,
                    bookkeeping.conflict_ledger_bytes,
                ),
                (0, 1, 0, 0),
                "{label}: the refused transaction is finished"
            );
            let gone = |result: Result<(), FirestoreError>| match result {
                Err(FirestoreError::InvalidArgument(message)) if strict => message,
                Err(FirestoreError::Aborted(message)) if !strict => message,
                other => panic!("{label} strict={strict}: {other:?}"),
            };
            assert_eq!(
                gone(
                    state
                        .get_in_transaction(&transaction, &path("p08/held"))
                        .map(|_| ())
                ),
                NO_LONGER_VALID
            );
            assert_eq!(
                gone(state.commit(&commit, Some(&transaction), t(3)).map(|_| ())),
                NO_LONGER_VALID
            );
            for _ in 0..2 {
                state.rollback(&transaction).unwrap();
            }
            assert_eq!(
                state
                    .get(&path("p08/held"))
                    .unwrap()
                    .fields
                    .get("v")
                    .cloned(),
                Some(Value::Integer(1)),
                "{label}: nothing of the refused commit is published"
            );
        }
    }
}

#[test]
fn a_precondition_refused_commit_releases_the_transactions_locks_at_once() {
    for scope in [LimitScope::Production, LimitScope::OfficialEmulator] {
        let (mut state, transaction) = refused_commit_state(scope);
        // While the transaction is active its read of `held` locks a writer out.
        let writer = [set("p08/held", &[("v", Value::Integer(5))])];
        assert!(matches!(
            state.commit(&writer, None, t(2)),
            Err(FirestoreError::Aborted(message)) if message == TOO_MUCH_CONTENTION
        ));
        let missing = precondition_write("p08/missing", Precondition::Exists(true));
        assert!(state.commit(&[missing], Some(&transaction), t(3)).is_err());
        state.commit(&writer, None, t(4)).unwrap();
    }
}

// P02 (both transports): the empty commit of a fresh read-only transaction succeeds and finishes
// it; a write commit of one is refused "Cannot modify entities in a read-only transaction." and
// the Rollback that follows answers 0. The 2026-09-07 matrix row (conformance/firestore-production-
// matrix.json, transactions/lifecycle#read-only-commit-without-writes, REST) recorded a refused write
// commit followed by an empty commit on the same token answering INVALID_ARGUMENT "no longer valid":
// a refused write commit ends the read-only transaction. P02b (REST and gRPC, two recordings): after
// the refusal a GetDocument and an empty commit, in either order, answer 3 with the expired text, and
// a Rollback answers 0.
#[test]
fn a_read_only_transaction_commits_empty_and_ends_when_a_write_commit_is_refused() {
    let mut state = FirestoreState::with_limit_scope(LimitScope::Production);
    state
        .commit(&[set("p02/doc", &[("v", Value::Integer(1))])], None, t(0))
        .unwrap();
    let empty = state.begin_transaction(true, t(1)).unwrap();
    state.get_in_transaction(&empty, &path("p02/doc")).unwrap();
    state.commit(&[], Some(&empty), t(2)).unwrap();
    assert!(matches!(
        state.commit(&[], Some(&empty), t(3)),
        Err(FirestoreError::Aborted(message)) if message == NO_LONGER_VALID
    ));

    let refused = state.begin_transaction(true, t(4)).unwrap();
    let write = [set("p02/doc", &[("v", Value::Integer(2))])];
    assert!(matches!(
        state.commit(&write, Some(&refused), t(5)),
        Err(FirestoreError::InvalidArgument(message))
            if message == "Cannot modify entities in a read-only transaction."
    ));
    assert_eq!(state.transaction_bookkeeping_stats().active, 0);
    assert!(matches!(
        state.commit(&[], Some(&refused), t(6)),
        Err(FirestoreError::InvalidArgument(message)) if message == NO_LONGER_VALID
    ));
    state.rollback(&refused).unwrap();

    // P02b: a read on the ended token answers 3 with the expired text too, in either order with the
    // empty commit, and the Rollback still answers 0.
    for read_first in [true, false] {
        let ended = state.begin_read_only_transaction(t(7)).unwrap();
        assert!(state.commit(&write, Some(&ended), t(8)).is_err());
        let read = |state: &mut FirestoreState| state.touch_transaction(&ended, t(9));
        if read_first {
            assert!(matches!(
                read(&mut state),
                Err(FirestoreError::InvalidArgument(message)) if message == NO_LONGER_VALID
            ));
        }
        assert!(matches!(
            state.commit(&[], Some(&ended), t(10)),
            Err(FirestoreError::InvalidArgument(message)) if message == NO_LONGER_VALID
        ));
        if !read_first {
            assert!(matches!(
                read(&mut state),
                Err(FirestoreError::InvalidArgument(message)) if message == NO_LONGER_VALID
            ));
        }
        state.rollback(&ended).unwrap();
    }

    // The official emulator (v1.22.0) keeps the transaction open after that refusal: a later
    // empty commit answers 200 and a read still works. The emulator profile refuses nothing more.
    let mut emulator = FirestoreState::with_limit_scope(LimitScope::OfficialEmulator);
    emulator
        .commit(&[set("p02/doc", &[("v", Value::Integer(1))])], None, t(0))
        .unwrap();
    let kept = emulator.begin_read_only_transaction(t(1)).unwrap();
    assert!(matches!(
        emulator.commit(&write, Some(&kept), t(2)),
        Err(FirestoreError::InvalidArgument(message))
            if message == "Cannot modify entities in a read-only transaction."
    ));
    assert_eq!(emulator.transaction_bookkeeping_stats().active, 1);
    emulator
        .get_in_transaction(&kept, &path("p02/doc"))
        .unwrap();
    emulator.commit(&[], Some(&kept), t(3)).unwrap();
}

// P02 (both transports): the empty commit of a read-only transaction answers the snapshot time and
// consumes no commit time; production's `commitTime` lies before an outside writer's commit that
// was acknowledged between the snapshot and the empty commit.
#[test]
fn an_empty_read_only_commit_answers_the_snapshot_time_and_consumes_no_commit_time() {
    let mut state = FirestoreState::with_limit_scope(LimitScope::Production);
    state
        .commit(&[set("p02/doc", &[("v", Value::Integer(1))])], None, t(0))
        .unwrap();
    let transaction = state.begin_read_only_transaction(t(1)).unwrap();
    state.touch_transaction(&transaction, t(2)).unwrap();
    let snapshot = state.transaction_read_time(&transaction).unwrap();
    let writer = state
        .commit(&[set("p02/doc", &[("v", Value::Integer(2))])], None, t(3))
        .unwrap();
    // At the writer's own instant the next commit time is one microsecond later; an empty commit that
    // wrote the older snapshot time into the commit clock would take that back.
    let next = state.next_commit_time(t(3));
    assert!(next > writer.commit_time);
    let empty = state.commit(&[], Some(&transaction), t(4)).unwrap();
    assert_eq!(empty.commit_time, snapshot);
    assert!(empty.commit_time < writer.commit_time);
    assert_eq!(
        state.next_commit_time(t(3)),
        next,
        "no commit time is used up or moved back"
    );
    // A commit outside a transaction, and a read-write empty commit, still take a new time.
    let plain = state.commit(&[], None, t(5)).unwrap();
    assert!(plain.commit_time > writer.commit_time);
}

// The empty commit of a transaction answers the time of its first read, and none when it has not
// read (P01 REST and gRPC read-write, P02 read-only, matrix `#empty-commit`); it uses up no commit
// time. Not recorded, and inferred from those rows: a read-write one after a read over gRPC, one
// without a read over REST, a read-only one without a read, and the time of a later read.
#[test]
fn an_empty_commit_answers_the_first_read_time_of_its_transaction_or_none() {
    for read_only in [false, true] {
        let mut state = FirestoreState::with_limit_scope(LimitScope::Production);
        state
            .commit(&[set("p01/doc", &[("v", Value::Integer(1))])], None, t(0))
            .unwrap();
        let transaction = if read_only {
            state.begin_read_only_transaction(t(1))
        } else {
            state.begin_read_write_transaction(t(1))
        }
        .unwrap();
        state.touch_transaction(&transaction, t(2)).unwrap();
        state.touch_transaction(&transaction, t(3)).unwrap();
        let writer = state
            .commit(&[set("p01/other", &[("v", Value::Integer(2))])], None, t(4))
            .unwrap();
        let next = state.next_commit_time(t(4));
        let empty = state.commit(&[], Some(&transaction), t(5)).unwrap();
        assert!(empty.stamped, "read_only={read_only}");
        assert_eq!(
            empty.commit_time,
            t(2),
            "the first read's time, read_only={read_only}"
        );
        assert!(empty.commit_time < writer.commit_time);
        assert_eq!(
            state.next_commit_time(t(4)),
            next,
            "no commit time is used up"
        );

        // Without a read the answer carries no time, and it consumes one as before.
        let unread = if read_only {
            state.begin_read_only_transaction(t(6))
        } else {
            state.begin_read_write_transaction(t(6))
        }
        .unwrap();
        let bare = state.commit(&[], Some(&unread), t(7)).unwrap();
        assert!(!bare.stamped, "read_only={read_only}");
        assert!(bare.commit_time > writer.commit_time);
    }
    let mut state = FirestoreState::with_limit_scope(LimitScope::Production);
    assert!(
        !state.commit(&[], None, t(0)).unwrap().stamped,
        "outside a transaction"
    );
    let written = state
        .commit(&[set("p01/doc", &[("v", Value::Integer(1))])], None, t(1))
        .unwrap();
    assert!(
        written.stamped,
        "a commit with writes always carries its time"
    );
    // The emulator profile stamps every commit.
    let mut emulator = FirestoreState::with_limit_scope(LimitScope::OfficialEmulator);
    assert!(emulator.commit(&[], None, t(0)).unwrap().stamped);
    let bare = emulator.begin_transaction(false, t(1)).unwrap();
    assert!(emulator.commit(&[], Some(&bare), t(2)).unwrap().stamped);
}

// A read-only transaction begun at a `readTime` has the read time as its snapshot time; its empty
// commit answering that time is unrecorded and follows the read-only rule (P02).
#[test]
fn an_empty_commit_of_a_read_time_transaction_answers_that_read_time() {
    let mut state = FirestoreState::with_limit_scope(LimitScope::Production);
    state
        .commit(&[set("p03/doc", &[("v", Value::Integer(1))])], None, t(1))
        .unwrap();
    let transaction = state.begin_transaction_at(t(2), t(5)).unwrap();
    state.touch_transaction(&transaction, t(6)).unwrap();
    let empty = state.commit(&[], Some(&transaction), t(7)).unwrap();
    assert!(empty.stamped);
    assert_eq!(empty.commit_time, t(2));
}

// A `readTime` begin and a retry attempt have not read either: their empty commits carry no time in
// production until they read (inferred from the rule; only explicit begins are recorded).
#[test]
fn a_read_time_begin_and_a_retry_attempt_answer_no_time_until_they_read() {
    let mut state = FirestoreState::with_limit_scope(LimitScope::Production);
    state
        .commit(&[set("p03/doc", &[("v", Value::Integer(1))])], None, t(1))
        .unwrap();
    let at = state.begin_transaction_at(t(1), t(5)).unwrap();
    assert!(!state.commit(&[], Some(&at), t(6)).unwrap().stamped);

    let first = state.begin_read_write_transaction(t(7)).unwrap();
    state.rollback(&first).unwrap();
    let retried = state.retry_transaction(&first, t(8)).unwrap();
    assert!(!state.commit(&[], Some(&retried), t(9)).unwrap().stamped);
}

// The official emulator (v1.22.0, REST measured) reads a retried read-write transaction at its first
// use, like a plain begin, and its commit succeeds; the emulator profile matches it.
#[test]
fn both_profiles_read_a_retried_transaction_at_its_first_use() {
    let mut state = FirestoreState::with_limit_scope(LimitScope::OfficialEmulator);
    state
        .commit(&[set("p02/doc", &[("v", Value::Integer(1))])], None, t(0))
        .unwrap();
    let first = state.begin_read_write_transaction(t(1)).unwrap();
    state.rollback(&first).unwrap();
    let retried = state.retry_transaction(&first, t(2)).unwrap();
    state
        .commit(&[set("p02/doc", &[("v", Value::Integer(2))])], None, t(3))
        .unwrap();
    state.touch_transaction(&retried, t(4)).unwrap();
    let shown = state
        .get_in_transaction(&retried, &path("p02/doc"))
        .unwrap()
        .and_then(|document| document.fields.get("v").cloned());
    assert_eq!(
        shown,
        Some(Value::Integer(2)),
        "the first read shows the writer"
    );
    state
        .commit(
            &[set("p02/doc", &[("v", Value::Integer(3))])],
            Some(&retried),
            t(5),
        )
        .unwrap();

    // Production reads a retry attempt at its first use too (P13b: the first read showed the writer committed after the retry's begin).
    let mut strict = FirestoreState::with_limit_scope(LimitScope::Production);
    strict
        .commit(&[set("p02/doc", &[("v", Value::Integer(1))])], None, t(0))
        .unwrap();
    let first = strict.begin_read_write_transaction(t(1)).unwrap();
    strict.rollback(&first).unwrap();
    let retried = strict.retry_transaction(&first, t(2)).unwrap();
    strict
        .commit(&[set("p02/doc", &[("v", Value::Integer(2))])], None, t(3))
        .unwrap();
    strict.touch_transaction(&retried, t(4)).unwrap();
    let shown = strict
        .get_in_transaction(&retried, &path("p02/doc"))
        .unwrap()
        .and_then(|document| document.fields.get("v").cloned());
    assert_eq!(shown, Some(Value::Integer(2)));
}

// An embedded `newTransaction` reads in the request that begins it, so its empty commit already
// answers that time.
#[test]
fn an_empty_commit_of_an_embedded_transaction_answers_its_begin_time() {
    let mut state = FirestoreState::with_limit_scope(LimitScope::Production);
    let transaction = state.begin_transaction(false, t(1)).unwrap();
    let empty = state.commit(&[], Some(&transaction), t(5)).unwrap();
    assert!(empty.stamped);
    assert_eq!(empty.commit_time, t(1));
}

// An idle expiry found by maintenance keeps its lineage (E003: the first request ABORTED, a later
// read ABORTED, a Rollback 0); only a total-lifetime expiry is forgotten after a refused request.
#[test]
fn an_idle_expiry_found_by_maintenance_still_answers_aborted_and_accepts_a_rollback() {
    let mut state = FirestoreState::with_limit_scope(LimitScope::Production);
    let transaction = state.begin_transaction(false, t(0)).unwrap();
    let _other = state.begin_transaction(true, t(130)).unwrap();
    aborted_no_longer_valid(state.touch_transaction(&transaction, t(131)));
    aborted_no_longer_valid(state.touch_transaction(&transaction, t(132)));
    state.rollback(&transaction).unwrap();
}

// Evicting finished lineage removes the deadline key an expired token was filed under. The emulator
// profile keeps an expired token for 600 s, long enough for three waves to overflow the bounded lineage
// (production remembers for 30 s and holds at most 4 096 active transactions, so it cannot overflow it).
#[test]
fn evicting_expired_tokens_leaves_no_stale_deadline_entries() {
    let mut state = FirestoreState::with_limit_scope(LimitScope::OfficialEmulator);
    // Three waves of 4 000 transactions, each kept alive by reads until its total lifetime ends and
    // found by the next wave's begin, overflow the bounded finished lineage (8 192) inside that
    // retention.
    for wave in 0..3 {
        let base = wave * 271;
        let ids: Vec<_> = (0..4_000)
            .map(|_| state.begin_transaction(false, t(base)).unwrap())
            .collect();
        for second in (24..=264).step_by(24) {
            for id in &ids {
                state.touch_transaction(id, t(base + second)).unwrap();
            }
        }
    }
    let _late = state.begin_transaction(true, t(3 * 271)).unwrap();
    let bookkeeping = state.transaction_bookkeeping_stats();
    assert_eq!(bookkeeping.finished, 8_192);
    assert_eq!(bookkeeping.finished, bookkeeping.finished_deadlines);
}

// A read-write transaction reads at its first use in both profiles: an outside write between the
// begin and the first read is shown, and the transaction's commit then succeeds (P02b chain Z, REST
// and gRPC, two recordings, for production; the official emulator v1.22.0, measured on both
// transports, for the emulator profile).
#[test]
fn a_read_write_transaction_reads_at_its_first_use_in_both_profiles() {
    for scope in [LimitScope::Production, LimitScope::OfficialEmulator] {
        read_write_reads_at_its_first_use(scope);
    }
}

fn read_write_reads_at_its_first_use(scope: LimitScope) {
    let mut state = FirestoreState::with_limit_scope(scope);
    state
        .commit(&[set("p02/doc", &[("v", Value::Integer(1))])], None, t(0))
        .unwrap();
    let transaction = state.begin_read_write_transaction(t(1)).unwrap();
    state
        .commit(&[set("p02/doc", &[("v", Value::Integer(2))])], None, t(2))
        .unwrap();
    state.touch_transaction(&transaction, t(3)).unwrap();
    let shown = state
        .get_in_transaction(&transaction, &path("p02/doc"))
        .unwrap()
        .and_then(|document| document.fields.get("v").cloned());
    assert_eq!(
        shown,
        Some(Value::Integer(2)),
        "the first read shows the writer"
    );
    state
        .commit(
            &[set("p02/doc", &[("v", Value::Integer(3))])],
            Some(&transaction),
            t(4),
        )
        .unwrap();

    // A transaction that began with a read is not moved by a later use.
    let eager = state.begin_transaction(false, t(5)).unwrap();
    state
        .commit(&[set("p02/doc", &[("v", Value::Integer(4))])], None, t(6))
        .unwrap();
    state.touch_transaction(&eager, t(7)).unwrap();
    assert_eq!(
        state
            .get_in_transaction(&eager, &path("p02/doc"))
            .unwrap()
            .and_then(|document| document.fields.get("v").cloned()),
        Some(Value::Integer(3))
    );
}

// P02 (both transports): a read-only transaction takes its snapshot at its first use, not at its
// begin. A write acknowledged between the two is shown by the first read (S1), and a write after
// the first read is not shown by the second (S2). A read-only transaction begun through a read's
// `newTransaction` (the eager begin) and one begun at a `readTime` keep their begin-time snapshot.
#[test]
fn a_read_only_transaction_takes_its_snapshot_at_its_first_use() {
    let value = |state: &FirestoreState, transaction: &TransactionId| {
        state
            .transaction_read_version(transaction)
            .map(|version| {
                state
                    .get_at(&path("p02/doc"), version)
                    .and_then(|d| d.fields.get("v").cloned())
            })
            .unwrap()
    };
    let mut state = FirestoreState::with_limit_scope(LimitScope::Production);
    state
        .commit(&[set("p02/doc", &[("v", Value::Integer(1))])], None, t(0))
        .unwrap();

    let lazy = state.begin_read_only_transaction(t(1)).unwrap();
    state
        .commit(&[set("p02/doc", &[("v", Value::Integer(2))])], None, t(2))
        .unwrap();
    state.touch_transaction(&lazy, t(3)).unwrap();
    assert_eq!(
        value(&state, &lazy),
        Some(Value::Integer(2)),
        "the first use pins the snapshot"
    );
    assert!(state.transaction_read_time(&lazy).unwrap() >= t(3));
    state
        .commit(&[set("p02/doc", &[("v", Value::Integer(3))])], None, t(4))
        .unwrap();
    state.touch_transaction(&lazy, t(5)).unwrap();
    assert_eq!(
        value(&state, &lazy),
        Some(Value::Integer(2)),
        "later reads keep the first snapshot"
    );

    let eager = state.begin_transaction(true, t(6)).unwrap();
    state
        .commit(&[set("p02/doc", &[("v", Value::Integer(4))])], None, t(7))
        .unwrap();
    state.touch_transaction(&eager, t(8)).unwrap();
    assert_eq!(
        value(&state, &eager),
        Some(Value::Integer(3)),
        "a begun-with-a-read transaction keeps its begin"
    );

    // The official emulator (v1.22.0, measured, REST and gRPC) takes the snapshot at the begin.
    let mut emulator = FirestoreState::with_limit_scope(LimitScope::OfficialEmulator);
    emulator
        .commit(&[set("p02/doc", &[("v", Value::Integer(1))])], None, t(0))
        .unwrap();
    let pinned = emulator.begin_read_only_transaction(t(1)).unwrap();
    emulator
        .commit(&[set("p02/doc", &[("v", Value::Integer(2))])], None, t(2))
        .unwrap();
    emulator.touch_transaction(&pinned, t(3)).unwrap();
    assert_eq!(value(&emulator, &pinned), Some(Value::Integer(1)));

    let unused = state.begin_read_only_transaction(t(9)).unwrap();
    state.rollback(&unused).unwrap();
    assert_eq!(state.transaction_bookkeeping_stats().active, 2);

    // Pinning moves the transaction's hold on history from its begin to its snapshot: once every
    // transaction is finished and the one-hour window has passed, only the newest version and the
    // one at the floor remain.
    state.rollback(&lazy).unwrap();
    state.rollback(&eager).unwrap();
    assert_eq!(state.transaction_bookkeeping_stats().active, 0);
    state
        .commit(
            &[set("p02/doc", &[("v", Value::Integer(5))])],
            None,
            t(10_000),
        )
        .unwrap();
    assert_eq!(state.retained_versions(), 2);
}

// P11 (REST and gRPC, P11 v4 two recordings and REST recording 1): a transaction kept alive by reads past its 270 s total
// lifetime. Recorded: at token ages of 283 to 288 s a read, a Commit and a Rollback each answer ABORTED
// "no longer valid" (10) and a writer outside the transaction is not held; at 298.7 to 301.0 s a read
// still answers 10 and the Commit about a second later answers INVALID_ARGUMENT "Invalid transaction."
// (3), as does a Rollback after it: the token is forgotten at about 300 s. An idle expiry keeps the
// lineage until the total lifetime, so its later requests still answer ABORTED (E003).
fn invalid_transaction(result: Result<(), FirestoreError>) {
    match result {
        Err(FirestoreError::InvalidArgument(message)) if message == "Invalid transaction." => {}
        other => panic!("expected Invalid transaction., got {other:?}"),
    }
}

fn aborted_no_longer_valid(result: Result<(), FirestoreError>) {
    match result {
        Err(FirestoreError::Aborted(message)) if message == NO_LONGER_VALID => {}
        other => panic!("expected ABORTED no longer valid, got {other:?}"),
    }
}

fn aged_transaction() -> (FirestoreState, TransactionId) {
    let mut state = FirestoreState::with_limit_scope(LimitScope::Production);
    state
        .commit(&[set("p11/doc", &[("v", Value::Integer(1))])], None, t(0))
        .unwrap();
    let transaction = state.begin_transaction(false, t(0)).unwrap();
    for second in (24..=264).step_by(24) {
        state.touch_transaction(&transaction, t(second)).unwrap();
    }
    (state, transaction)
}

#[test]
fn after_the_total_lifetime_every_request_is_aborted_until_the_token_is_forgotten_at_300_s() {
    let (mut state, transaction) = aged_transaction();
    let write = [set("p11/doc", &[("v", Value::Integer(2))])];
    aborted_no_longer_valid(state.touch_transaction(&transaction, t(271)));
    aborted_no_longer_valid(state.commit(&write, Some(&transaction), t(272)).map(|_| ()));
    aborted_no_longer_valid(state.rollback(&transaction));
    aborted_no_longer_valid(state.touch_transaction(&transaction, t(299)));
    assert_eq!(state.transaction_bookkeeping_stats().active, 0);
    // forgotten by 301 s of token age: every request now answers "Invalid transaction."
    invalid_transaction(state.touch_transaction(&transaction, t(301)));
    invalid_transaction(state.commit(&write, Some(&transaction), t(302)).map(|_| ()));
    invalid_transaction(state.rollback(&transaction));
}

#[test]
fn an_expired_token_that_no_request_asked_about_is_still_aborted_until_300_s_and_then_invalid() {
    let (mut state, transaction) = aged_transaction();
    // Maintenance at the deadline (here another begin) must not forget it before its 300 s.
    let other = state.begin_transaction(true, t(271)).unwrap();
    aborted_no_longer_valid(state.touch_transaction(&transaction, t(272)));
    let bookkeeping = state.transaction_bookkeeping_stats();
    assert_eq!(bookkeeping.finished, bookkeeping.finished_deadlines);
    state.rollback(&other).unwrap();

    let (mut late, transaction) = aged_transaction();
    let _other = late.begin_transaction(true, t(301)).unwrap();
    invalid_transaction(late.touch_transaction(&transaction, t(302)));
}

// P12 (REST, two recordings): at a token age of about 325 s every request answers "Invalid transaction.", the first
// request (a Commit or a Rollback, or a read) included.
#[test]
fn every_first_request_past_the_forgetting_age_answers_invalid_transaction() {
    let write = [set("p11/doc", &[("v", Value::Integer(2))])];
    let (mut state, transaction) = aged_transaction();
    invalid_transaction(state.commit(&write, Some(&transaction), t(325)).map(|_| ()));
    invalid_transaction(state.touch_transaction(&transaction, t(326)));
    invalid_transaction(state.rollback_at(&transaction, t(327)));

    let (mut state, transaction) = aged_transaction();
    invalid_transaction(state.rollback_at(&transaction, t(325)));
    invalid_transaction(state.touch_transaction(&transaction, t(326)));
    invalid_transaction(state.commit(&write, Some(&transaction), t(327)).map(|_| ()));

    let (mut state, transaction) = aged_transaction();
    invalid_transaction(state.touch_transaction(&transaction, t(325)));
}

#[test]
fn a_commit_or_a_rollback_as_the_first_request_after_the_lifetime_is_aborted_like_a_read() {
    let write = [set("p11/doc", &[("v", Value::Integer(2))])];
    let (mut state, transaction) = aged_transaction();
    aborted_no_longer_valid(state.commit(&write, Some(&transaction), t(271)).map(|_| ()));
    aborted_no_longer_valid(state.commit(&write, Some(&transaction), t(272)).map(|_| ()));
    aborted_no_longer_valid(state.touch_transaction(&transaction, t(273)));
    aborted_no_longer_valid(state.rollback(&transaction));

    // With no maintenance in between, the Rollback itself finds the lifetime over.
    let (mut state, transaction) = aged_transaction();
    aborted_no_longer_valid(state.rollback_at(&transaction, t(271)));
    aborted_no_longer_valid(state.touch_transaction(&transaction, t(272)));

    // An idle expiry keeps its retry lineage when the Rollback comes first (rolled back, not finished).
    let mut idle = FirestoreState::with_limit_scope(LimitScope::Production);
    let transaction = idle.begin_transaction(false, t(0)).unwrap();
    idle.rollback_at(&transaction, t(200)).unwrap();
    idle.retry_transaction(&transaction, t(201)).unwrap();

    let (mut state, transaction) = aged_transaction();
    let other = state.begin_transaction(true, t(271)).unwrap();
    aborted_no_longer_valid(state.rollback(&transaction));
    aborted_no_longer_valid(state.rollback(&transaction));
    state.rollback(&other).unwrap();
}

#[test]
fn a_rollback_after_the_token_is_forgotten_answers_invalid_transaction() {
    // A read at 271 s finds the lifetime over (10); the Rollback that follows at 301 s finds the token forgotten (3).
    let (mut state, transaction) = aged_transaction();
    aborted_no_longer_valid(state.touch_transaction(&transaction, t(271)));
    invalid_transaction(state.rollback_at(&transaction, t(301)));
}

// P13a (REST, two recordings): an idle-expired token is remembered like a lifetime-expired one. Reads at about 132 s and 232 s answered
// 10, a Rollback at about 287 s answered 10 as well, and a read at about 310 s answered 3 "Invalid transaction.".
#[test]
fn an_idle_expired_token_answers_everything_10_until_it_is_forgotten() {
    let write = [set("p11/doc", &[("v", Value::Integer(2))])];
    let mut state = FirestoreState::with_limit_scope(LimitScope::Production);
    state
        .commit(&[set("p11/doc", &[("v", Value::Integer(1))])], None, t(0))
        .unwrap();
    let transaction = state.begin_transaction(false, t(0)).unwrap();
    aborted_no_longer_valid(state.touch_transaction(&transaction, t(132)));
    aborted_no_longer_valid(state.touch_transaction(&transaction, t(232)));
    aborted_no_longer_valid(state.commit(&write, Some(&transaction), t(260)).map(|_| ()));
    aborted_no_longer_valid(state.rollback_at(&transaction, t(287)));
    aborted_no_longer_valid(state.touch_transaction(&transaction, t(288)));
    invalid_transaction(state.touch_transaction(&transaction, t(310)));
    invalid_transaction(state.rollback_at(&transaction, t(311)));

    // a token whose only request after the idle expiry came late is forgotten too
    let mut late = FirestoreState::with_limit_scope(LimitScope::Production);
    let transaction = late.begin_transaction(false, t(0)).unwrap();
    aborted_no_longer_valid(late.touch_transaction(&transaction, t(132)));
    invalid_transaction(late.touch_transaction(&transaction, t(310)));
}

// E003 (REST): the first request after an idle expiry, a Rollback at about 121 s, answered 0. A Rollback before the total lifetime keeps
// being accepted for an idle-expired token (P13a refuted the same answer only past 270 s).
#[test]
fn a_rollback_of_an_idle_expired_token_before_the_lifetime_is_accepted() {
    let mut state = FirestoreState::with_limit_scope(LimitScope::Production);
    let transaction = state.begin_transaction(false, t(0)).unwrap();
    state.rollback_at(&transaction, t(125)).unwrap();
    let mut noticed = FirestoreState::with_limit_scope(LimitScope::Production);
    let transaction = noticed.begin_transaction(false, t(0)).unwrap();
    aborted_no_longer_valid(noticed.touch_transaction(&transaction, t(131)));
    noticed.rollback_at(&transaction, t(132)).unwrap();
}

// The 270 s edge of that rule: an idle-expired token's Rollback is accepted up to 269 s and answered 10 from 270 s (the total lifetime).
#[test]
fn the_past_lifetime_rollback_rule_starts_exactly_at_270_s() {
    let mut finished = FirestoreState::with_limit_scope(LimitScope::Production);
    let transaction = finished.begin_transaction(false, t(0)).unwrap();
    aborted_no_longer_valid(finished.touch_transaction(&transaction, t(131)));
    finished.rollback_at(&transaction, t(269)).unwrap();
    let mut at_edge = FirestoreState::with_limit_scope(LimitScope::Production);
    let transaction = at_edge.begin_transaction(false, t(0)).unwrap();
    aborted_no_longer_valid(at_edge.touch_transaction(&transaction, t(131)));
    aborted_no_longer_valid(at_edge.rollback_at(&transaction, t(270)));
}

// INFERRED, not recorded: an idle-expired token that no request noticed also answers a Rollback past 270 s with 10 (P13a recorded it only
// after reads that answered 10), and a lifetime-expired token does so as its first request (P12, P13a).
#[test]
fn a_rollback_of_an_unnoticed_idle_expired_token_after_270_s_answers_expired() {
    let mut state = FirestoreState::with_limit_scope(LimitScope::Production);
    let transaction = state.begin_transaction(false, t(0)).unwrap();
    aborted_no_longer_valid(state.rollback_at(&transaction, t(290)));
}

// Production remembers an expired token for 30 s even when more than 8 192 finished transactions pile up in the
// meantime: eviction takes the oldest finished lineage first, but never a token still remembered as expired.
#[test]
fn a_flood_of_finished_transactions_does_not_make_production_forget_an_expired_token_early() {
    let (mut state, transaction) = aged_transaction();
    aborted_no_longer_valid(state.touch_transaction(&transaction, t(271)));
    for _ in 0..9_000 {
        let other = state.begin_transaction(false, t(272)).unwrap();
        state.rollback_at(&other, t(272)).unwrap();
    }
    let bookkeeping = state.transaction_bookkeeping_stats();
    assert_eq!(bookkeeping.finished, 8_192);
    assert_eq!(bookkeeping.finished, bookkeeping.finished_deadlines);
    aborted_no_longer_valid(state.touch_transaction(&transaction, t(280)));
    invalid_transaction(state.touch_transaction(&transaction, t(301)));
}

// The same holds for a token an idle expiry finished (P13a: remembered until about 300 s too). Found by a property test with 8 300 finished
// transactions and a probe at 271 s (proptest-regressions keeps the seed; this is the fixed form).
#[test]
fn a_flood_of_finished_transactions_does_not_make_production_forget_an_idle_expired_token_early() {
    let mut state = FirestoreState::with_limit_scope(LimitScope::Production);
    let transaction = state.begin_transaction(false, t(0)).unwrap();
    aborted_no_longer_valid(state.touch_transaction(&transaction, t(271)));
    for _ in 0..9_000 {
        let other = state.begin_transaction(false, t(272)).unwrap();
        state.rollback_at(&other, t(272)).unwrap();
    }
    aborted_no_longer_valid(state.touch_transaction(&transaction, t(280)));
    invalid_transaction(state.touch_transaction(&transaction, t(300)));
}

// The emulator profile is exactly as before: a bare Rollback past 270 s finishes the transaction, and a later read
// answers ABORTED (not INVALID_ARGUMENT), as it did before production began to prune first.
#[test]
fn the_emulator_profiles_bare_rollback_past_the_lifetime_is_unchanged() {
    let (mut state, transaction) = emulator_aged_transaction();
    state.rollback_at(&transaction, t(275)).unwrap();
    aborted_no_longer_valid(state.touch_transaction(&transaction, t(276)));
}

#[test]
fn a_writer_outside_an_expired_transaction_is_not_held_by_its_locks() {
    // P11 v4: the outside writer after the expiry answered 0 at normal pace.
    let (mut state, transaction) = aged_transaction();
    aborted_no_longer_valid(state.touch_transaction(&transaction, t(271)));
    state
        .commit(&[set("p11/doc", &[("v", Value::Integer(3))])], None, t(272))
        .unwrap();
}

#[test]
fn an_idle_expiry_keeps_answering_aborted_until_the_total_lifetime() {
    let mut state = FirestoreState::with_limit_scope(LimitScope::Production);
    let transaction = state.begin_transaction(false, t(0)).unwrap();
    aborted_no_longer_valid(state.touch_transaction(&transaction, t(130)));
    aborted_no_longer_valid(state.touch_transaction(&transaction, t(131)));
}

fn invalid_argument_expired(result: Result<(), FirestoreError>) {
    match result {
        Err(FirestoreError::InvalidArgument(message)) if message == NO_LONGER_VALID => {}
        other => panic!("expected INVALID_ARGUMENT no longer valid, got {other:?}"),
    }
}

fn emulator_aged_transaction() -> (FirestoreState, TransactionId) {
    let mut state = FirestoreState::with_limit_scope(LimitScope::OfficialEmulator);
    state
        .commit(&[set("p11/doc", &[("v", Value::Integer(1))])], None, t(0))
        .unwrap();
    let transaction = state.begin_transaction(false, t(0)).unwrap();
    for second in (30..=240).step_by(30) {
        state.touch_transaction(&transaction, t(second)).unwrap();
    }
    (state, transaction)
}

// The official emulator (v1.22.0, REST, real time, measured): a transaction kept alive by reads answers a
// read at 270.3 s HTTP 400 INVALID_ARGUMENT "no longer valid", a Commit right after HTTP 409 ABORTED with the
// same text, and a Rollback 200. The emulator profile matches it in each order below; only read, Commit,
// Rollback was measured, the rest keeps the same answers by request kind. gRPC's wire form is unmeasured.
#[test]
fn the_emulator_profile_answers_a_read_after_the_total_lifetime_invalid_argument() {
    let (mut state, transaction) = emulator_aged_transaction();
    invalid_argument_expired(state.touch_transaction(&transaction, t(271)));
    // Maintenance at the deadline (another begin) keeps the transaction for the first request that asks.
    let (mut state, transaction) = emulator_aged_transaction();
    let _other = state.begin_transaction(true, t(271)).unwrap();
    invalid_argument_expired(state.touch_transaction(&transaction, t(272)));
}

#[test]
fn the_emulator_profile_answers_a_commit_after_the_total_lifetime_aborted_also_after_a_read() {
    let write = [set("p11/doc", &[("v", Value::Integer(2))])];
    let (mut state, transaction) = emulator_aged_transaction();
    aborted_no_longer_valid(state.commit(&write, Some(&transaction), t(271)).map(|_| ()));
    let (mut state, transaction) = emulator_aged_transaction();
    invalid_argument_expired(state.touch_transaction(&transaction, t(271)));
    aborted_no_longer_valid(state.commit(&write, Some(&transaction), t(272)).map(|_| ()));
    let (mut state, transaction) = emulator_aged_transaction();
    let _other = state.begin_transaction(true, t(271)).unwrap();
    aborted_no_longer_valid(state.commit(&write, Some(&transaction), t(272)).map(|_| ()));
}

#[test]
fn the_emulator_profile_accepts_a_rollback_after_the_total_lifetime() {
    let write = [set("p11/doc", &[("v", Value::Integer(2))])];
    let (mut state, transaction) = emulator_aged_transaction();
    invalid_argument_expired(state.touch_transaction(&transaction, t(271)));
    aborted_no_longer_valid(state.commit(&write, Some(&transaction), t(272)).map(|_| ()));
    state.rollback(&transaction).unwrap();
    // As the first request, whether the request or maintenance found the expiry.
    let (mut state, transaction) = emulator_aged_transaction();
    state.rollback(&transaction).unwrap();
    let (mut state, transaction) = emulator_aged_transaction();
    let _other = state.begin_transaction(true, t(271)).unwrap();
    state.rollback(&transaction).unwrap();
}

// Bounded, like the production profile's: an expiry nobody asked about is forgotten after the retention bound.
#[test]
fn the_emulator_profile_forgets_an_unasked_lifetime_expiry_after_the_retention_bound() {
    let (mut state, transaction) = emulator_aged_transaction();
    let _other = state.begin_transaction(true, t(271 + 601)).unwrap();
    invalid_transaction(state.touch_transaction(&transaction, t(271 + 602)));
}

#[test]
fn a_transaction_with_no_preconditions_refused_is_not_ended_by_other_refusals() {
    // Only the precondition refusal is measured; a commit that fails for another reason (here a
    // document that is too large to store) keeps its transaction as before.
    let (mut state, transaction) = refused_commit_state(LimitScope::Production);
    let huge = Value::String("x".repeat(1_100_000));
    let failing = set("p08/held", &[("v", huge)]);
    assert!(state.commit(&[failing], Some(&transaction), t(2)).is_err());
    assert!(state
        .get_in_transaction(&transaction, &path("p08/held"))
        .is_ok());
}

#[test]
fn a_transaction_ended_by_a_refused_commit_may_be_retried_like_a_rolled_back_one() {
    for scope in [LimitScope::Production, LimitScope::OfficialEmulator] {
        let (mut state, transaction) = refused_commit_state(scope);
        let missing = precondition_write("p08/missing", Precondition::Exists(true));
        assert!(state.commit(&[missing], Some(&transaction), t(2)).is_err());
        let retried = state.retry_transaction(&transaction, t(3)).unwrap();
        state.touch_transaction(&retried, t(3)).unwrap();
        state
            .get_in_transaction(&retried, &path("p08/held"))
            .unwrap();
        state
            .commit(
                &[set("p08/held", &[("v", Value::Integer(2))])],
                Some(&retried),
                t(4),
            )
            .unwrap();
    }
}

#[test]
fn a_precondition_refused_commit_outside_a_transaction_leaves_every_transaction_alone() {
    for scope in [LimitScope::Production, LimitScope::OfficialEmulator] {
        let (mut state, transaction) = refused_commit_state(scope);
        let missing = precondition_write("p08/missing", Precondition::Exists(true));
        assert!(matches!(
            state.commit(&[missing], None, t(2)),
            Err(FirestoreError::NotFound(_))
        ));
        state
            .get_in_transaction(&transaction, &path("p08/held"))
            .unwrap();
        state
            .commit(
                &[set("p08/held", &[("v", Value::Integer(4))])],
                Some(&transaction),
                t(3),
            )
            .unwrap();
        let fresh = state.begin_transaction(false, t(4)).unwrap();
        assert!(state
            .get_in_transaction(&fresh, &path("p08/missing"))
            .is_ok());
    }
}

/// A request whose clock is behind the last commit time reads at that commit time (the snapshot never precedes a commit it
/// can already see): the pending snapshot and the first-read time both take the later of the two.
#[test]
fn a_first_use_behind_the_last_commit_time_reads_at_the_commit_time() {
    let mut s = FirestoreState::new();
    s.commit(&[set("ahead/a", &[])], None, t(5)).unwrap();
    let txn = s.begin_read_write_transaction(t(2)).unwrap();
    s.touch_transaction(&txn, t(3)).unwrap();
    assert_eq!(s.transaction_read_time(&txn).unwrap(), t(5));
    // The empty commit of a transaction that has read answers the time of its first read.
    let committed = s.commit(&[], Some(&txn), t(4)).unwrap();
    assert_eq!(committed.commit_time, t(5));
}

/// Every transaction query entry point of the store returns the page it ran and records it in the read set, so a
/// document the page returned cannot be created or changed out of band while the transaction is active.
#[test]
fn every_transaction_query_entry_point_returns_its_page_and_records_it() {
    use fireemu_core_firestore::query::{Query, QueryScope};
    use fireemu_core_firestore::store::QueryExecutionId;
    use fireemu_core_types::ids::CollectionId;
    let ids = |docs: &[fireemu_core_firestore::store::Document]| -> Vec<String> {
        docs.iter()
            .map(|d| d.path.document_id().as_str().to_owned())
            .collect()
    };
    let mut s = FirestoreState::new();
    s.commit(
        &[set("pg/a", &[]), set("pg/b", &[]), set("pg/c", &[])],
        None,
        t(0),
    )
    .unwrap();
    let query = Query::new(QueryScope::collection(
        None,
        CollectionId::try_new("pg").unwrap(),
    ))
    .canonicalize()
    .unwrap();
    let txn = s.begin_transaction(false, t(1)).unwrap();
    let execution = QueryExecutionId::from_value(7);
    let (docs, _) = s
        .run_query_in_transaction_with_stats_as_with_execution(
            &txn, &query, &query, execution, false,
        )
        .unwrap();
    assert_eq!(ids(&docs), ["a", "b", "c"]);
    let (docs, _) = s
        .run_query_in_transaction_continuation_with_stats_as_with_execution(
            &txn, &query, &query, execution, false,
        )
        .unwrap();
    assert_eq!(ids(&docs), ["a", "b", "c"]);
    let paths = [path("pg/b"), path("pg/c")];
    let (docs, stats) = s
        .run_query_in_transaction_from_paths_with_stats_as_with_execution(
            &txn, &query, &query, &paths, execution, true, false,
        )
        .unwrap();
    assert_eq!(ids(&docs), ["b", "c"]);
    assert_eq!(stats.matched, 2);
    let (docs, _) = s
        .run_query_in_transaction_after_document_with_stats_as_with_execution(
            &txn,
            &query,
            &query,
            &path("pg/a"),
            execution,
            false,
        )
        .unwrap();
    assert_eq!(ids(&docs), ["b", "c"]);
    let (docs, _) = s
        .run_query_in_transaction_after_document_with_stats(&txn, &query, &path("pg/b"))
        .unwrap();
    assert_eq!(ids(&docs), ["c"]);
    // The execution is still unfinished (the pages said "not complete"); finishing it succeeds.
    s.finish_transaction_query_execution(&txn, execution)
        .unwrap();
}
