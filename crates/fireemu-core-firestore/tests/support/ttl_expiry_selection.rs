use super::*;
use fireemu_core_types::ids::{DatabaseId, ProjectId};

fn path(index: usize) -> DocumentPath {
    DocumentPath::parse(
        &ProjectId::try_new("demo-app").unwrap(),
        &DatabaseId::default_database(),
        &format!("items/d{index:05}"),
    )
    .unwrap()
}
fn timestamp(seconds: i64) -> Timestamp {
    Timestamp::new(seconds, 0).unwrap()
}
fn catalog() -> crate::ttl::TtlCatalog {
    let mut catalog = crate::ttl::TtlCatalog::new();
    catalog
        .enable(
            CollectionId::try_new("items").unwrap(),
            FieldPath::parse("expires").unwrap(),
        )
        .unwrap();
    catalog
}
fn fixture(count: usize, expired: usize) -> FirestoreState {
    let mut state = FirestoreState::default();
    state
        .import_documents(
            (0..count)
                .map(|i| ImportedDocument {
                    path: path(i),
                    fields: BTreeMap::from([(
                        "expires".into(),
                        Value::Timestamp(timestamp(if i < expired { 0 } else { 100 })),
                    )]),
                    create_time: None,
                    update_time: None,
                })
                .collect(),
            LogicalInstant::UNIX_EPOCH,
        )
        .unwrap();
    state
}
#[test]
fn steady_sparse_selection_visits_only_expired_prefix_and_boundary() {
    let mut state = fixture(1_000, 1);
    let catalog = catalog();
    let group = CollectionId::try_new("items").unwrap();
    state
        .select_ttl_expiry(&catalog, &group, timestamp(50))
        .unwrap();
    let mut selected = state
        .select_ttl_expiry(&catalog, &group, timestamp(50))
        .unwrap();
    assert_eq!(
        selected.next_page(std::num::NonZeroUsize::new(3).unwrap()),
        vec![Arc::new(path(0))]
    );
    assert!(selected.is_exhausted());
    assert_eq!(
        selected.inspected, 2,
        "steady selection must not scan unexpired rows"
    );
}

fn reference(
    state: &FirestoreState,
    catalog: &crate::ttl::TtlCatalog,
    group: &CollectionId,
    now: Timestamp,
) -> Result<Vec<Arc<DocumentPath>>, FirestoreError> {
    let Some((_, policy)) = catalog.iter().find(|(key, _)| *key == group) else {
        return Ok(Vec::new());
    };
    let query = Query {
        projection: Some(vec![policy.field.clone()]),
        ..Query::new(QueryScope::collection_group(group.clone()))
    };
    Ok(state
        .run_query(&query, None)?
        .into_iter()
        .filter(|doc| policy.is_expired(&doc.fields, now))
        .map(|doc| Arc::new(doc.path))
        .collect())
}
fn capture(
    state: &mut FirestoreState,
    catalog: &crate::ttl::TtlCatalog,
    now: Timestamp,
    page: usize,
) -> Vec<Arc<DocumentPath>> {
    let mut selection = state
        .select_ttl_expiry(catalog, &CollectionId::try_new("items").unwrap(), now)
        .unwrap();
    let mut paths = Vec::new();
    while !selection.is_exhausted() {
        paths.extend(selection.next_page(std::num::NonZeroUsize::new(page).unwrap()));
    }
    paths
}
fn import_fields(state: &mut FirestoreState, index: usize, fields: BTreeMap<String, Value>) {
    state
        .import_documents(
            vec![ImportedDocument {
                path: path(index),
                fields,
                create_time: None,
                update_time: None,
            }],
            LogicalInstant::UNIX_EPOCH,
        )
        .unwrap();
}
fn assert_index(state: &FirestoreState) {
    for (group, index) in &state.ttl_expiry_indexes {
        let expected: BTreeSet<_> = state
            .live_collection_group_paths
            .get(group)
            .into_iter()
            .flatten()
            .filter_map(|path| {
                let document = state.get(path)?;
                let Value::Timestamp(at) = get_field(&document.fields, &index.field)? else {
                    return None;
                };
                Some((*at, Arc::clone(path)))
            })
            .collect();
        assert_eq!(index.entries, expected);
        for (_, path) in &index.entries {
            assert!(Arc::ptr_eq(path, &state.retained_scope_path(path)));
        }
    }
}
#[test]
fn selection_is_path_ordered_frozen_and_exact_at_the_last_page() {
    let mut state = fixture(4, 4);
    import_fields(
        &mut state,
        0,
        BTreeMap::from([("expires".into(), Value::Timestamp(timestamp(40)))]),
    );
    let policies = catalog();
    let group = CollectionId::try_new("items").unwrap();
    let expected = reference(&state, &policies, &group, timestamp(50)).unwrap();
    let mut selection = state
        .select_ttl_expiry(&policies, &group, timestamp(50))
        .unwrap();
    import_fields(&mut state, 0, BTreeMap::new());
    import_fields(
        &mut state,
        5,
        BTreeMap::from([("expires".into(), Value::Timestamp(timestamp(0)))]),
    );
    assert_eq!(
        selection.next_page(std::num::NonZeroUsize::new(3).unwrap()),
        expected[..3]
    );
    assert!(!selection.is_exhausted());
    assert_eq!(
        selection.next_page(std::num::NonZeroUsize::new(3).unwrap()),
        expected[3..]
    );
    assert!(selection.is_exhausted());
    assert!(selection
        .next_page(std::num::NonZeroUsize::new(3).unwrap())
        .is_empty());
    assert_index(&state);
}
#[test]
fn imports_clone_snapshots_field_changes_and_disable_rebuild_exact_membership() {
    let mut state = fixture(8, 4);
    let mut policies = catalog();
    let group = CollectionId::try_new("items").unwrap();
    for i in 0..32 {
        let fields = match i % 4 {
            0 => BTreeMap::new(),
            1 => BTreeMap::from([("expires".into(), Value::Integer(1))]),
            _ => BTreeMap::from([("expires".into(), Value::Timestamp(timestamp(i)))]),
        };
        import_fields(&mut state, usize::try_from(i % 8).unwrap(), fields);
        for now in [timestamp(0), timestamp(i), timestamp(50)] {
            let expected = reference(&state, &policies, &group, now).unwrap();
            assert_eq!(capture(&mut state, &policies, now, 3), expected);
            assert_index(&state);
            let mut clone = state.clone();
            let mut snapshot = state.visible_snapshot();
            assert_eq!(capture(&mut clone, &policies, now, 1), expected);
            assert_eq!(capture(&mut snapshot, &policies, now, 2), expected);
            assert_index(&clone);
            assert_index(&snapshot);
        }
    }
    assert!(policies.disable(&group, &FieldPath::parse("expires").unwrap()));
    assert!(capture(&mut state, &policies, timestamp(50), 1).is_empty());
    assert!(state.ttl_expiry_indexes.is_empty());
    policies
        .enable(group.clone(), FieldPath::parse("other.at").unwrap())
        .unwrap();
    import_fields(
        &mut state,
        1,
        BTreeMap::from([(
            "other".into(),
            Value::Map(BTreeMap::from([(
                "at".into(),
                Value::Timestamp(timestamp(0)),
            )])),
        )]),
    );
    assert_eq!(
        capture(&mut state, &policies, timestamp(50), 1),
        reference(&state, &policies, &group, timestamp(50)).unwrap()
    );
    assert_index(&state);
}

#[test]
fn offsets_strict_boundaries_and_extreme_timestamps_match_projected_reference() {
    let mut state = fixture(0, 0);
    let group = CollectionId::try_new("items").unwrap();
    for (i, at) in [
        timestamp(Timestamp::MIN_SECONDS),
        timestamp(-1),
        timestamp(0),
        timestamp(1),
        Timestamp::new(Timestamp::MAX_SECONDS, 999_999_999).unwrap(),
    ]
    .into_iter()
    .enumerate()
    {
        import_fields(
            &mut state,
            i,
            BTreeMap::from([("expires".into(), Value::Timestamp(at))]),
        );
    }
    let mut policies = catalog();
    for nanos in [i128::MIN, -1, 0, 1, i128::MAX] {
        policies
            .enable_with_offset(
                group.clone(),
                FieldPath::parse("expires").unwrap(),
                Some(LogicalDuration::from_nanos(nanos)),
            )
            .unwrap();
        for now in [
            timestamp(Timestamp::MIN_SECONDS),
            timestamp(0),
            timestamp(1),
            Timestamp::new(Timestamp::MAX_SECONDS, 999_999_999).unwrap(),
        ] {
            assert_eq!(
                capture(&mut state, &policies, now, 2),
                reference(&state, &policies, &group, now).unwrap(),
                "offset {nanos}, now {now:?}"
            );
            assert_index(&state);
        }
    }
}

proptest::proptest! {
    #![proptest_config(proptest::test_runner::Config::with_cases(64))]
    #[test]
    fn mutation_sequences_preserve_the_projected_selection_reference(ops in proptest::collection::vec((0usize..32, 0u8..7, -20i64..120), 1..128)) {
        let mut state = fixture(32, 16);
        let mut policies = catalog();
        let group = CollectionId::try_new("items").unwrap();
        for (index, op, seconds) in ops {
            match op {
                0 => { state.commit(&[Write {op: WriteOp::Delete {path: path(index)}, precondition: None, transforms: Vec::new()}], None, LogicalInstant::UNIX_EPOCH).unwrap(); }
                1 => import_fields(&mut state, index, BTreeMap::new()),
                2 => import_fields(&mut state, index, BTreeMap::from([("expires".into(), Value::Integer(seconds))])),
                3 => { state = state.visible_snapshot(); }
                4 => { state = state.clone(); }
                5 => { policies.enable_with_offset(group.clone(), FieldPath::parse("expires").unwrap(), Some(LogicalDuration::from_nanos(i128::from(seconds)))).unwrap(); }
                _ => import_fields(&mut state, index, BTreeMap::from([("expires".into(), Value::Timestamp(timestamp(seconds)))])),
            }
            let now = timestamp(seconds);
            let expected = reference(&state, &policies, &group, now).unwrap();
            proptest::prop_assert_eq!(capture(&mut state, &policies, now, index % 5 + 1), expected);
            assert_index(&state);
        }
    }
}

#[test]
fn sparse_dense_work_and_physical_retention_are_measured_separately_from_cold_build() {
    let mut measurements = Vec::new();
    let policies = catalog();
    let group = CollectionId::try_new("items").unwrap();
    for count in [1_000, 10_000] {
        for expired in [0, 1, count] {
            let mut state = fixture(count, expired);
            TTL_INDEX_BUILD_VISITS.with(|counter| counter.set(0));
            let cold = state
                .select_ttl_expiry(&policies, &group, timestamp(50))
                .unwrap();
            assert_eq!(TTL_INDEX_BUILD_VISITS.with(std::cell::Cell::get), count);
            TTL_INDEX_BUILD_VISITS.with(|counter| counter.set(0));
            let mut steady = state
                .select_ttl_expiry(&policies, &group, timestamp(50))
                .unwrap();
            assert_eq!(TTL_INDEX_BUILD_VISITS.with(std::cell::Cell::get), 0);
            assert_eq!(steady.inspected, expired + usize::from(expired < count));
            assert_eq!(steady.paths.len(), expired);
            let capacity = steady.retained_capacity;
            let mut transferred = 0;
            while !steady.is_exhausted() {
                let page = steady.next_page(std::num::NonZeroUsize::new(64).unwrap());
                assert!(page.len() <= 64);
                transferred += page.len();
            }
            assert_eq!(transferred, expired);
            let query = Query {
                projection: Some(vec![FieldPath::parse("expires").unwrap()]),
                ..Query::new(QueryScope::collection_group(group.clone()))
            };
            let (_, old_stats) = state.run_query_with_stats(&query, None).unwrap();
            assert_eq!(old_stats.cloned_documents, count as u64);
            measurements.push((
                count,
                expired,
                cold.inspected,
                steady.inspected,
                capacity,
                std::mem::size_of::<(Timestamp, Arc<DocumentPath>)>(),
            ));
            let weak = Arc::downgrade(
                &state
                    .ttl_expiry_indexes
                    .get(&group)
                    .unwrap()
                    .entries
                    .first()
                    .unwrap()
                    .1,
            );
            drop(state);
            assert_eq!(weak.upgrade().is_some(), expired > 0);
            drop(cold);
            assert!(weak.upgrade().is_none());
        }
    }
    eprintln!("TTL work (N,E,cold_prefix,steady_prefix,selection_capacity,key_payload_bytes): {measurements:?}; tree node/allocator overhead excluded; dense path sorting O(E log E); selection O(E) handles");
}

#[test]
fn accepted_sets_replace_keys_but_noops_and_refused_batches_leave_the_index_unchanged() {
    let mut state = fixture(2, 1);
    let policies = catalog();
    capture(&mut state, &policies, timestamp(50), 1);
    let original = state
        .ttl_expiry_indexes
        .get(&CollectionId::try_new("items").unwrap())
        .unwrap()
        .entries
        .clone();
    let set = |index, value| Write {
        op: WriteOp::Set {
            path: path(index),
            fields: BTreeMap::from([("expires".into(), Value::Timestamp(timestamp(value)))]),
            update_mask: None,
        },
        precondition: None,
        transforms: Vec::new(),
    };
    let noop = state
        .commit(&[set(0, 0)], None, LogicalInstant::UNIX_EPOCH)
        .unwrap();
    assert!(noop.changes.is_empty());
    assert_eq!(
        state
            .ttl_expiry_indexes
            .get(&CollectionId::try_new("items").unwrap())
            .unwrap()
            .entries,
        original
    );
    let bad = Write {
        op: WriteOp::Set {
            path: path(9),
            fields: BTreeMap::from([("body".into(), Value::String("x".repeat(1_100_000)))]),
            update_mask: None,
        },
        precondition: None,
        transforms: Vec::new(),
    };
    assert!(state
        .commit(&[set(0, 100), bad], None, LogicalInstant::UNIX_EPOCH)
        .is_err());
    assert_eq!(
        state
            .ttl_expiry_indexes
            .get(&CollectionId::try_new("items").unwrap())
            .unwrap()
            .entries,
        original
    );
    state
        .commit(&[set(0, 100), set(1, 0)], None, LogicalInstant::UNIX_EPOCH)
        .unwrap();
    assert_eq!(
        capture(&mut state, &policies, timestamp(50), 1),
        vec![Arc::new(path(1))]
    );
    assert_index(&state);
}

#[test]
fn literal_nested_and_absent_fields_have_the_same_success_contract_as_projection() {
    let mut state = fixture(0, 0);
    let fields = BTreeMap::from([
        ("literal.dot".into(), Value::Timestamp(timestamp(1))),
        (
            "nested".into(),
            Value::Map(BTreeMap::from([(
                "at".into(),
                Value::Timestamp(timestamp(1)),
            )])),
        ),
        ("wrong".into(), Value::Integer(1)),
    ]);
    import_fields(&mut state, 0, fields);
    let group = CollectionId::try_new("items").unwrap();
    for spelling in ["`literal.dot`", "nested.at", "wrong", "absent.at"] {
        let mut policies = crate::ttl::TtlCatalog::new();
        policies
            .enable(group.clone(), FieldPath::parse(spelling).unwrap())
            .unwrap();
        let expected = reference(&state, &policies, &group, timestamp(2)).unwrap();
        assert_eq!(capture(&mut state, &policies, timestamp(2), 1), expected);
        assert_index(&state);
    }
    let mut policies = crate::ttl::TtlCatalog::new();
    assert!(policies
        .enable(group.clone(), FieldPath::parse("__name__").unwrap())
        .is_err());
    assert!(state
        .select_ttl_expiry(&policies, &group, timestamp(2))
        .unwrap()
        .is_exhausted());
}

#[test]
fn a_field_replaced_between_selections_rebuilds_without_an_intermediate_disabled_scan() {
    let mut state = fixture(1, 0);
    import_fields(
        &mut state,
        0,
        BTreeMap::from([
            ("expires".into(), Value::Timestamp(timestamp(100))),
            ("other".into(), Value::Timestamp(timestamp(0))),
        ]),
    );
    assert!(capture(&mut state, &catalog(), timestamp(50), 1).is_empty());
    let group = CollectionId::try_new("items").unwrap();
    let mut replacement = crate::ttl::TtlCatalog::new();
    replacement
        .enable(group.clone(), FieldPath::parse("other").unwrap())
        .unwrap();
    let expected = reference(&state, &replacement, &group, timestamp(50)).unwrap();
    assert_eq!(expected, vec![Arc::new(path(0))]);
    assert_eq!(
        capture(&mut state, &replacement, timestamp(50), 1),
        expected
    );
    assert_index(&state);
}
