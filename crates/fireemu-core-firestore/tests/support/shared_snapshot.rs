use super::*;
use fireemu_core_types::ids::{DatabaseId, ProjectId};

fn path(name: &str) -> DocumentPath {
    DocumentPath::parse(
        &ProjectId::try_new("demo-app").unwrap(),
        &DatabaseId::default_database(),
        name,
    )
    .unwrap()
}
fn write(name: &str, score: i32) -> Write {
    Write {
        op: WriteOp::Set {
            path: path(name),
            fields: BTreeMap::from([
                ("score".into(), Value::Integer(i64::from(score))),
                ("body".into(), Value::String("x".repeat(20_000))),
                (
                    "embedding".into(),
                    Value::Vector(vec![f64::from(score) + 1.0, 1.0]),
                ),
            ]),
            update_mask: None,
        },
        precondition: None,
        transforms: Vec::new(),
    }
}
fn seeded() -> FirestoreState {
    let mut state = FirestoreState::default();
    let writes = [
        write("items/a", 1),
        write("items/b", 2),
        write("items/c", 3),
        write("parents/p/items/d", 4),
    ];
    state
        .commit(&writes, None, LogicalInstant::UNIX_EPOCH)
        .unwrap();
    state
}
fn query() -> Query {
    Query::new(QueryScope::collection(
        None,
        CollectionId::try_new("items").unwrap(),
    ))
}

#[test]
fn ordinary_shared_selection_reuses_existing_payloads_and_counts_no_clones() {
    let state = seeded();
    let (owned, mut expected) = state.run_query_with_stats(&query(), None).unwrap();
    let (shared, counters) = state.run_query_shared_with_stats(&query(), None).unwrap();
    assert_eq!(
        shared.iter().map(Arc::as_ref).collect::<Vec<_>>(),
        owned.iter().collect::<Vec<_>>()
    );
    for document in &shared {
        assert!(Arc::ptr_eq(
            document,
            &state.get_shared(&document.path).unwrap()
        ));
    }
    expected.cloned_documents = 0;
    expected.cloned_field_bytes = 0;
    assert_eq!(counters, expected);
}

#[test]
fn shared_current_and_historical_handles_survive_update_delete_and_compaction() {
    let mut state = seeded();
    let version = state.current_version();
    let old = state.get_at_shared(&path("items/a"), version).unwrap();
    let expected = old.as_ref().clone();
    let (snapshot, _) = state
        .run_query_shared_with_stats(&query(), Some(version))
        .unwrap();
    assert!(Arc::ptr_eq(
        &old,
        &state.get_shared(&path("items/a")).unwrap()
    ));
    assert!(state.get_shared(&path("items/missing")).is_none());
    assert!(state
        .get_at_shared(&path("items/a"), CommitVersion::default())
        .is_none());
    state
        .commit(
            &[write("items/a", 7)],
            None,
            LogicalInstant::from_unix_seconds(1),
        )
        .unwrap();
    assert_eq!(
        state.get_at_shared(&path("items/a"), version).as_deref(),
        Some(&expected)
    );
    let (historical, _) = state
        .run_query_shared_with_stats(&query(), Some(version))
        .unwrap();
    assert_eq!(historical[0].as_ref(), &expected);
    drop(historical);
    assert_eq!(
        state.get_shared(&path("items/a")).as_deref(),
        state.get(&path("items/a"))
    );
    state
        .commit(
            &[Write {
                op: WriteOp::Delete {
                    path: path("items/a"),
                },
                precondition: None,
                transforms: Vec::new(),
            }],
            None,
            LogicalInstant::from_unix_seconds(2),
        )
        .unwrap();
    assert!(state.get_shared(&path("items/a")).is_none());
    let tombstone = state.current_version();
    assert!(state.get_at_shared(&path("items/a"), tombstone).is_none());
    state.compact(LogicalInstant::from_unix_seconds(36_000));
    assert_eq!(old.as_ref(), &expected);
    assert_eq!(snapshot[0].as_ref(), &expected);
    assert_eq!(
        state.get_at_shared(&path("items/a"), version).as_deref(),
        state.get_at(&path("items/a"), version)
    );
    let weak = Arc::downgrade(&old);
    drop(old);
    assert!(weak.upgrade().is_some());
    drop(snapshot);
    assert!(weak.upgrade().is_none());
}

#[test]
fn shared_queries_match_owned_order_versions_and_fallback_counters() {
    let state = seeded();
    let mut ordered = query();
    ordered.order_by = vec![OrderClause {
        field: FieldPath::parse("score").unwrap(),
        direction: Direction::Descending,
    }];
    ordered.offset = 1;
    ordered.limit = Some(2);
    let mut projected = ordered.clone();
    projected.projection = Some(vec![FieldPath::parse("score").unwrap()]);
    let nearest = query().with_find_nearest(crate::query::FindNearest {
        vector_field: FieldPath::parse("embedding").unwrap(),
        query_vector: vec![1.0, 2.0],
        distance_measure: DistanceMeasure::Cosine,
        limit: 2,
        distance_result_field: Some(FieldPath::parse("distance").unwrap()),
        distance_threshold: None,
    });
    for candidate in [
        query(),
        ordered,
        projected,
        nearest,
        Query::new(QueryScope::collection_group(
            CollectionId::try_new("items").unwrap(),
        )),
    ] {
        for version in [
            None,
            Some(state.current_version()),
            Some(CommitVersion::default()),
        ] {
            let (owned, mut expected) = state.run_query_with_stats(&candidate, version).unwrap();
            let (shared, counters) = state
                .run_query_shared_with_stats(&candidate, version)
                .unwrap();
            assert_eq!(
                shared.iter().map(Arc::as_ref).collect::<Vec<_>>(),
                owned.iter().collect::<Vec<_>>()
            );
            if candidate.projection.is_none() && candidate.find_nearest.is_none() {
                expected.cloned_documents = 0;
                expected.cloned_field_bytes = 0;
            }
            assert_eq!(counters, expected);
        }
    }
}

proptest::proptest! {
    #![proptest_config(proptest::test_runner::Config::with_cases(64))]
    #[test]
    fn frozen_shared_results_match_owned_reference_across_mutations(operations in proptest::collection::vec((0usize..4, proptest::bool::ANY, -10i32..10), 0..32)) {
        let mut state = seeded();
        let version = state.current_version();
        let (snapshot, _) = state.run_query_shared_with_stats(&query(), Some(version)).unwrap();
        let expected = state.run_query(&query(), Some(version)).unwrap();
        for (id, delete, value) in operations {
            let name = format!("items/{}", ["a", "b", "c", "d"][id]);
            let operation = if delete { Write { op: WriteOp::Delete { path: path(&name) }, precondition: None, transforms: Vec::new() } } else { write(&name, value) };
            state.commit(&[operation], None, LogicalInstant::UNIX_EPOCH).unwrap();
            let (current, mut expected_counters) = state.run_query_with_stats(&query(), None).unwrap();
            let (shared, counters) = state.run_query_shared_with_stats(&query(), None).unwrap();
            proptest::prop_assert_eq!(shared.iter().map(Arc::as_ref).collect::<Vec<_>>(), current.iter().collect::<Vec<_>>());
            expected_counters.cloned_documents = 0; expected_counters.cloned_field_bytes = 0;
            proptest::prop_assert_eq!(counters, expected_counters);
            for document in &shared { proptest::prop_assert!(Arc::ptr_eq(document, &state.get_shared(&document.path).unwrap())); }
            let (historical, _) = state.run_query_shared_with_stats(&query(), Some(version)).unwrap();
            proptest::prop_assert_eq!(historical.iter().map(Arc::as_ref).collect::<Vec<_>>(), expected.iter().collect::<Vec<_>>());
            proptest::prop_assert_eq!(snapshot.iter().map(Arc::as_ref).collect::<Vec<_>>(), expected.iter().collect::<Vec<_>>());
        }
    }
}
