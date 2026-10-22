use super::*;
use fireemu_core_types::ids::{DatabaseId, ProjectId};

#[test]
fn admission_reuses_validated_sizes_without_cloning_retained_history() {
    let path = DocumentPath::parse(
        &ProjectId::try_new("demo-app").unwrap(),
        &DatabaseId::default_database(),
        "items/hot",
    )
    .unwrap();
    let mut measurements = Vec::new();
    for history in [1, 100, 1000] {
        let mut state = FirestoreState::default();
        let write = |score| Write {
            op: WriteOp::Set {
                path: path.clone(),
                fields: BTreeMap::from([
                    ("score".into(), Value::Integer(score)),
                    ("body".into(), Value::String("x".repeat(20_000))),
                ]),
                update_mask: None,
            },
            precondition: None,
            transforms: Vec::new(),
        };
        for score in 0..history {
            state
                .commit(&[write(score)], None, LogicalInstant::UNIX_EPOCH)
                .unwrap();
        }
        crate::size::DOCUMENT_BYTE_VISITS.with(|count| count.set(0));
        RETAINED_DOCUMENT_CLONES.with(|count| count.set(0));
        crate::size::DOCUMENT_BREAKDOWNS.with(|count| count.set(0));
        state
            .commit(&[write(history)], None, LogicalInstant::UNIX_EPOCH)
            .unwrap();
        assert_eq!(
            crate::size::DOCUMENT_BREAKDOWNS.with(std::cell::Cell::get),
            2
        );
        let bytes = crate::size::DOCUMENT_BYTE_VISITS.with(std::cell::Cell::get);
        let clones = RETAINED_DOCUMENT_CLONES.with(std::cell::Cell::get);
        eprintln!("history={history} tree_size_visits={bytes} retained_document_clones={clones}");
        measurements.push((history, bytes, clones));
    }
    for (history, bytes, clones) in measurements {
        assert_eq!((bytes, clones), (0, 2), "history={history}");
    }
}

fn path(index: u8) -> DocumentPath {
    DocumentPath::parse(
        &ProjectId::try_new("demo-app").unwrap(),
        &DatabaseId::default_database(),
        &format!("items/d{index}"),
    )
    .unwrap()
}

// Frozen tree-sizing reference: deliberately independent of retained scalar charges.
fn reference_usage(state: &FirestoreState) -> HistoryUsage {
    let mut all = HistoryUsage::default();
    for (path, versions) in &state.history {
        if versions.is_empty() {
            continue;
        }
        let mut usage = HistoryUsage {
            paths: 1,
            path_and_index_bytes: history_path_and_index_bytes(
                path,
                versions.last().unwrap().1.is_some(),
            ),
            ..HistoryUsage::default()
        };
        for (index, (_, document)) in versions.iter().enumerate() {
            usage.versions = usage.versions.saturating_add(1);
            usage.version_metadata_bytes = usage
                .version_metadata_bytes
                .saturating_add(HISTORY_VERSION_METADATA_BYTES);
            if let Some(document) = document {
                let bytes = document_size_bytes(path, &document.fields).unwrap_or(u64::MAX);
                assert_eq!(document.logical_bytes, bytes);
                if index + 1 == versions.len() {
                    usage.live_document_bytes = usage.live_document_bytes.saturating_add(bytes);
                } else {
                    usage.historical_document_bytes =
                        usage.historical_document_bytes.saturating_add(bytes);
                }
            } else {
                usage.tombstones = usage.tombstones.saturating_add(1);
                usage.tombstone_bytes = usage
                    .tombstone_bytes
                    .saturating_add(HISTORY_TOMBSTONE_BYTES);
            }
        }
        all = add_history_usage(all, finish_history_usage(usage));
    }
    all.commit_times = u64::try_from(state.commit_times.len()).unwrap();
    all.commit_time_bytes = all.commit_times.saturating_mul(HISTORY_COMMIT_TIME_BYTES);
    finish_history_usage(all)
}

#[test]
fn scalar_usage_preserves_saturation_and_live_tombstone_boundaries() {
    let path = path(0);
    let usage = history_path_usage_from_sizes(&path, [Some(u64::MAX), Some(4), Some(5)]);
    assert_eq!(usage.historical_document_bytes, u64::MAX);
    assert_eq!(usage.live_document_bytes, 5);
    let tail = history_path_usage_from_sizes(&path, [Some(4), Some(5)]);
    assert_eq!(tail.historical_document_bytes, 4);
    assert_eq!(tail.live_document_bytes, 5);
    let tombstone = history_path_usage_from_sizes(&path, [Some(4), None]);
    assert_eq!(tombstone.historical_document_bytes, 4);
    assert_eq!(tombstone.live_document_bytes, 0);
    assert_eq!(tombstone.tombstones, 1);
    assert_eq!(
        history_path_usage_from_sizes(&path, []),
        HistoryUsage::default()
    );
}

proptest::proptest! {
    #![proptest_config(proptest::test_runner::Config::with_cases(128))]
    #[test]
    fn cached_usage_matches_tree_reference_through_state_changes(operations in proptest::collection::vec((0u8..8, 0u8..8, 0u16..1000), 1..96)) {
        let mut state = FirestoreState::with_history_version_limit(8);
        let mut now = LogicalInstant::UNIX_EPOCH;
        for (index, operation, length) in operations {
            let path = path(index);
            match operation {
                0..=2 => {
                    let write = Write { op: WriteOp::Set { path, fields: BTreeMap::from([("body".into(), Value::String("x".repeat(usize::from(length))))]), update_mask: None }, precondition: None, transforms: Vec::new() };
                    state.commit(&[write], None, now).unwrap();
                }
                3 => { state.commit(&[Write { op: WriteOp::Delete { path }, precondition: None, transforms: Vec::new() }], None, now).unwrap(); }
                4 => { now = LogicalInstant::from_nanos(now.as_nanos() + 4_000_000_000_000); state.compact(now); }
                5 => { state = state.visible_snapshot(); }
                6 => { state = state.clone(); }
                _ => { state.import_documents(vec![ImportedDocument { path, fields: BTreeMap::from([("body".into(), Value::String("y".repeat(usize::from(length))))]), create_time: None, update_time: None }], now).unwrap(); }
            }
            proptest::prop_assert_eq!(state.history_usage(), reference_usage(&state));
        }
    }
}

#[test]
fn physical_cache_overhead_reports_allocated_history_capacity() {
    let old_slot = std::mem::size_of::<(CommitVersion, Option<SharedDocument>)>();
    let new_slot = std::mem::size_of::<(CommitVersion, Option<RetainedDocument>)>();
    assert!(new_slot >= old_slot);
    let mut state = FirestoreState::default();
    for score in 0..1000 {
        state
            .commit(
                &[Write {
                    op: WriteOp::Set {
                        path: path(0),
                        fields: BTreeMap::from([("score".into(), Value::Integer(score))]),
                        update_mask: None,
                    },
                    precondition: None,
                    transforms: Vec::new(),
                }],
                None,
                LogicalInstant::UNIX_EPOCH,
            )
            .unwrap();
    }
    for phase in ["retained", "compacted"] {
        if phase == "compacted" {
            state.compact(LogicalInstant::from_unix_seconds(4000));
        }
        let length = state.history.values().map(Vec::len).sum::<usize>();
        let capacity = state.history.values().map(Vec::capacity).sum::<usize>();
        eprintln!("phase={phase} old_slot={old_slot} cached_slot={new_slot} length={length} capacity={capacity} incremental_capacity_bytes={}", capacity * (new_slot - old_slot));
    }
    assert_eq!(state.history_usage(), reference_usage(&state));
}

#[test]
fn cached_admission_refusal_does_not_publish_or_change_usage() {
    let mut state = FirestoreState::default();
    let write = |body: &str| Write {
        op: WriteOp::Set {
            path: path(0),
            fields: BTreeMap::from([("body".into(), Value::String(body.into()))]),
            update_mask: None,
        },
        precondition: None,
        transforms: Vec::new(),
    };
    state
        .commit(&[write("old")], None, LogicalInstant::UNIX_EPOCH)
        .unwrap();
    let before = state.get_shared(&path(0)).unwrap();
    let usage = state.history_usage();
    state.history_limits.max_bytes = usage.total_bytes;
    assert!(matches!(
        state.commit(
            &[write(&"x".repeat(1000))],
            None,
            LogicalInstant::UNIX_EPOCH
        ),
        Err(FirestoreError::HistoryCapacity(_))
    ));
    assert!(Arc::ptr_eq(&before, &state.get_shared(&path(0)).unwrap()));
    assert_eq!(state.history_usage(), usage);
    assert_eq!(state.history_usage(), reference_usage(&state));
}

#[test]
fn cache_tracks_import_overwrite_delete_noop_and_capacity_floor() {
    let mut state = FirestoreState::with_history_version_limit(2);
    for length in [2, 20, 200] {
        state
            .import_documents(
                vec![ImportedDocument {
                    path: path(0),
                    fields: BTreeMap::from([("body".into(), Value::String("z".repeat(length)))]),
                    create_time: None,
                    update_time: None,
                }],
                LogicalInstant::UNIX_EPOCH,
            )
            .unwrap();
        assert_eq!(state.history_usage(), reference_usage(&state));
    }
    let document = state.get_shared(&path(0)).unwrap();
    state
        .commit(
            &[Write {
                op: WriteOp::Set {
                    path: path(0),
                    fields: document.fields.clone(),
                    update_mask: None,
                },
                precondition: None,
                transforms: Vec::new(),
            }],
            None,
            LogicalInstant::UNIX_EPOCH,
        )
        .unwrap();
    assert!(Arc::ptr_eq(&document, &state.get_shared(&path(0)).unwrap()));
    state
        .commit(
            &[Write {
                op: WriteOp::Delete { path: path(0) },
                precondition: None,
                transforms: Vec::new(),
            }],
            None,
            LogicalInstant::UNIX_EPOCH,
        )
        .unwrap();
    assert_eq!(state.history_usage(), reference_usage(&state));
    state.compact(LogicalInstant::from_unix_seconds(4000));
    assert_eq!(state.history_usage(), reference_usage(&state));
    assert!(state.history.is_empty());
}

#[test]
fn projected_usage_equals_tree_reference_at_capacity_and_time_floors() {
    for limit in [1, 2, 8] {
        let mut state = FirestoreState::with_history_version_limit(limit);
        for (step, length) in [1, 4, 20, 0, 200, 2, 0, 7, 30, 1].into_iter().enumerate() {
            let now = if step > 6 {
                LogicalInstant::from_unix_seconds(4000)
            } else {
                LogicalInstant::UNIX_EPOCH
            };
            let op = if length == 0 {
                WriteOp::Delete { path: path(0) }
            } else {
                WriteOp::Set {
                    path: path(0),
                    fields: BTreeMap::from([("body".into(), Value::String("x".repeat(length)))]),
                    update_mask: None,
                }
            };
            let before = reference_usage(&state);
            let (_, projection) = state
                .commit_with_history_admission(
                    &[Write {
                        op,
                        precondition: None,
                        transforms: Vec::new(),
                    }],
                    None,
                    now,
                    |_, projection| Ok(projection),
                )
                .unwrap();
            assert_eq!(projection.before, before);
            assert_eq!(
                projection.after,
                reference_usage(&state),
                "limit={limit} step={step}"
            );
        }
    }
}
