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
fn imported(index: usize, value: i64) -> ImportedDocument {
    ImportedDocument {
        path: path(index),
        fields: BTreeMap::from([("score".into(), Value::Integer(value))]),
        create_time: None,
        update_time: None,
    }
}
fn fixture(count: usize, eligible: usize) -> FirestoreState {
    let mut state = FirestoreState::default();
    state
        .import_documents(
            (0..count).map(|i| imported(i, 0)).collect(),
            LogicalInstant::UNIX_EPOCH,
        )
        .unwrap();
    // Keep version 2 even when the early group is empty.
    if eligible == 0 {
        state
            .import_documents(
                vec![ImportedDocument {
                    path: path(count),
                    ..imported(count, 0)
                }],
                LogicalInstant::UNIX_EPOCH,
            )
            .unwrap();
    } else {
        state
            .import_documents(
                (0..eligible).map(|i| imported(i, 1)).collect(),
                LogicalInstant::UNIX_EPOCH,
            )
            .unwrap();
    }
    if eligible < count {
        state
            .import_documents(
                (eligible..count).map(|i| imported(i, 1)).collect(),
                LogicalInstant::UNIX_EPOCH,
            )
            .unwrap();
    }
    state.capacity_floor = CommitVersion(2);
    state
}
#[test]
fn forecast_and_compaction_inspect_only_paths_reclaimable_at_the_floor() {
    let mut measurements = Vec::new();
    for count in [1000, 10000] {
        for eligible in [0, 1, 100, count] {
            let mut state = fixture(count, eligible);
            assert!(state.history_accounting_exact);
            FORECAST_PATH_VISITS.with(|count| count.set(0));
            RECLAIM_THRESHOLD_VISITS.with(|count| count.set(0));
            state.base_compaction_reclaim(CommitVersion(2));
            let forecast = FORECAST_PATH_VISITS.with(std::cell::Cell::get);
            let threshold_visits = RECLAIM_THRESHOLD_VISITS.with(std::cell::Cell::get);
            assert_eq!(threshold_visits, eligible + usize::from(eligible < count));
            let selected = state.reclaim_candidates(CommitVersion(2));
            assert_eq!(selected.len(), eligible);
            eprintln!("eligible={eligible} threshold_visits={threshold_visits} selected_capacity={} selected_capacity_bytes={}", selected.capacity(), selected.capacity() * std::mem::size_of::<Arc<DocumentPath>>());
            drop(selected);
            COMPACTION_PATH_VISITS.with(|count| count.set(0));
            state.compact(LogicalInstant::UNIX_EPOCH);
            let compact = COMPACTION_PATH_VISITS.with(std::cell::Cell::get);
            eprintln!("compactable={count} eligible={eligible} forecast_paths={forecast} compact_paths={compact}");
            measurements.push((count, eligible, forecast, compact));
        }
    }
    for (count, eligible, forecast, compact) in measurements {
        assert_eq!(
            (forecast, compact),
            (eligible, eligible),
            "compactable={count}"
        );
    }
}

// Frozen pre-index compaction reference: derive candidates by scanning history.
fn reference_compact(state: &mut FirestoreState, now: LogicalInstant) -> CommitVersion {
    state.prune_transactions(now);
    let floor = state.retention_floor(now);
    if floor <= state.compaction_floor {
        return state.compaction_floor;
    }
    state.compaction_forecast = None;
    state.compaction_floor = floor;
    let mut removed_commit_times = 0u64;
    while state
        .commit_times
        .front()
        .is_some_and(|(version, _)| *version < floor)
    {
        state.commit_times.pop_front();
        removed_commit_times = removed_commit_times.saturating_add(1);
    }
    state.history_usage.commit_times = state
        .history_usage
        .commit_times
        .saturating_sub(removed_commit_times);
    state.history_usage.commit_time_bytes = state
        .history_usage
        .commit_time_bytes
        .saturating_sub(removed_commit_times.saturating_mul(HISTORY_COMMIT_TIME_BYTES));
    state.history_usage = finish_history_usage(state.history_usage);
    let mut compactable: BTreeSet<DocumentPath> = state
        .history
        .iter()
        .filter(|(_, h)| h.len() > 1 || matches!(h.first(), Some((_, None))))
        .map(|(path, _)| path.clone())
        .collect();
    let mut removed_paths = Vec::new();
    let mut usage_changes = Vec::new();
    compactable.retain(|path| {
        let Some(h) = state.history.get_mut(path) else {
            return false;
        };
        let before_usage = history_path_usage(path, h);
        // Keep the newest version at or before the floor plus everything after it; drop
        // the prefix nothing can observe.
        let cut = h.partition_point(|(v, _)| *v <= floor).saturating_sub(1);
        if cut > 0 {
            h.drain(..cut);
        }
        let emptied = match h.as_slice() {
            [] => true,
            [(v, None)] => *v <= floor,
            _ => false,
        };
        if emptied {
            state.history.remove(path);
            removed_paths.push(path.clone());
            usage_changes.push((before_usage, HistoryUsage::default()));
            return false;
        }
        let after_usage = state
            .history
            .get(path)
            .map_or_else(HistoryUsage::default, |history| {
                history_path_usage(path, history)
            });
        usage_changes.push((before_usage, after_usage));
        state
            .history
            .get(path)
            .is_some_and(|h| h.len() > 1 || matches!(h.first(), Some((_, None))))
    });

    for (before, after) in usage_changes {
        state.history_usage =
            add_history_usage(subtract_history_usage(state.history_usage, before), after);
    }
    for path in removed_paths {
        state.remove_scope_path(&path);
    }
    floor
}

// Frozen pre-index forecast reference.
fn reference_forecast(state: &mut FirestoreState, floor: CommitVersion) -> HistoryUsage {
    if floor <= state.compaction_floor {
        return HistoryUsage::default();
    }
    if let Some(forecast) = state
        .compaction_forecast
        .filter(|forecast| forecast.version == state.version && forecast.floor == floor)
    {
        return forecast.reclaimed;
    }

    let mut reclaimed = HistoryUsage::default();
    for path in state
        .history
        .iter()
        .filter(|(_, h)| h.len() > 1 || matches!(h.first(), Some((_, None))))
        .map(|(path, _)| path)
    {
        let versions = state
            .history
            .get(path)
            .map(Vec::as_slice)
            .unwrap_or_default();
        reclaimed = add_history_usage(
            reclaimed,
            subtract_history_usage(
                history_path_usage(path, versions),
                history_path_usage_after_floor(path, versions, floor),
            ),
        );
    }
    let removed_commit_times = u64::try_from(
        state
            .commit_times
            .iter()
            .take_while(|(version, _)| *version < floor)
            .count(),
    )
    .unwrap_or(u64::MAX);
    reclaimed.commit_times = removed_commit_times;
    reclaimed.commit_time_bytes = removed_commit_times.saturating_mul(HISTORY_COMMIT_TIME_BYTES);
    state.compaction_forecast = Some(CompactionForecast {
        version: state.version,
        floor,
        reclaimed,
    });
    reclaimed
}

fn assert_index(state: &FirestoreState) {
    if state.history_accounting_exact {
        assert_eq!(state.history_usage(), state.recount_history_usage());
    }
    let expected = state
        .history
        .iter()
        .filter_map(|(path, h)| {
            let version = h
                .get(1)
                .map(|(version, _)| *version)
                .or(match h.as_slice() {
                    [(version, None)] => Some(*version),
                    _ => None,
                })?;
            Some((version, path.clone()))
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        state
            .reclaim_thresholds
            .iter()
            .map(|(version, path)| (*version, path.as_ref().clone()))
            .collect::<BTreeSet<_>>(),
        expected
    );
    assert_eq!(
        state
            .compactable
            .iter()
            .map(|(path, version)| (*version, path.as_ref().clone()))
            .collect::<BTreeSet<_>>(),
        expected
    );
    for (_, path) in &state.reclaim_thresholds {
        assert!(Arc::ptr_eq(path, &state.retained_scope_path(path)));
    }
}
type HistoryView = Vec<(DocumentPath, Vec<(CommitVersion, Option<Document>)>)>;

fn history_view(state: &FirestoreState) -> HistoryView {
    state
        .history
        .iter()
        .map(|(path, history)| {
            (
                path.clone(),
                history
                    .iter()
                    .map(|(version, doc)| (*version, doc.as_deref().cloned()))
                    .collect(),
            )
        })
        .collect()
}
proptest::proptest! {
    #![proptest_config(proptest::test_runner::Config::with_cases(128))]
    #[test]
    fn exact_thresholds_follow_mutations_snapshots_and_floors(operations in proptest::collection::vec((0usize..8, 0u8..8, -20i64..20), 1..96)) {
        let mut state = FirestoreState::with_history_version_limit(8);
        let mut now = LogicalInstant::UNIX_EPOCH;
        for (index, operation, value) in operations {
            match operation {
                0..=2 => { state.commit(&[Write { op: WriteOp::Set { path: path(index), fields: imported(index, value).fields, update_mask: None }, precondition: None, transforms: Vec::new() }], None, now).unwrap(); }
                3 => { state.commit(&[Write { op: WriteOp::Delete { path: path(index) }, precondition: None, transforms: Vec::new() }], None, now).unwrap(); }
                4 => { state.import_documents(vec![imported(index, value)], now).unwrap(); }
                5 => { state = state.visible_snapshot(); }
                6 => { state = state.clone(); }
                _ => { now = LogicalInstant::from_nanos(now.as_nanos() + 4_000_000_000_000); }
            }
            assert_index(&state);
            let floor = state.retention_floor(now);
            let mut expected = state.clone();
            expected.compaction_forecast = None;
            state.compaction_forecast = None;
            proptest::prop_assert_eq!(state.base_compaction_reclaim(floor), reference_forecast(&mut expected, floor));
            proptest::prop_assert_eq!(state.compact(now), reference_compact(&mut expected, now));
            proptest::prop_assert_eq!(state.history_usage(), expected.history_usage());
            proptest::prop_assert_eq!(history_view(&state), history_view(&expected));
            assert_index(&state);
            proptest::prop_assert!(state.history_accounting_exact);
        }
    }
}

#[test]
fn candidate_path_order_preserves_saturated_accounting() {
    let mut state = fixture(2, 1);
    let a = state.get_shared(&path(0)).unwrap();
    let b = state.get_shared(&path(1)).unwrap();
    let entry = |version, document: &SharedDocument, bytes| {
        (
            CommitVersion(version),
            Some(RetainedDocument {
                document: Arc::clone(document),
                logical_bytes: bytes,
            }),
        )
    };
    state.history.insert(
        path(0),
        vec![
            entry(0, &a, 10),
            entry(2, &a, u64::MAX - 10),
            entry(4, &a, 0),
        ],
    );
    state
        .history
        .insert(path(1), vec![entry(0, &b, 10), entry(1, &b, 0)]);
    state.version = CommitVersion(4);
    state.compaction_floor = CommitVersion(0);
    state.capacity_floor = CommitVersion(2);
    state.rebuild_history_usage();
    state.refresh_reclaim_threshold(&path(0));
    state.refresh_reclaim_threshold(&path(1));
    assert_eq!(
        state
            .reclaim_candidates(CommitVersion(2))
            .iter()
            .map(|path| path.as_ref().clone())
            .collect::<Vec<_>>(),
        vec![path(0), path(1)]
    );
    let mut expected = state.clone();
    reference_compact(&mut expected, LogicalInstant::UNIX_EPOCH);
    state.compact(LogicalInstant::UNIX_EPOCH);
    assert_eq!(state.history_usage(), expected.history_usage());
    assert_eq!(
        state.history_usage().historical_document_bytes,
        u64::MAX - 20
    );
    assert_index(&state);
}

#[test]
fn threshold_keys_share_paths_and_release_with_last_tombstone() {
    let mut state = fixture(1000, 1);
    assert_index(&state);
    let paths = state.reclaim_candidates(CommitVersion(2));
    eprintln!("registered={} ordered_key_bytes={} reverse_key_value_bytes={} selection_len={} selection_capacity={} selection_capacity_bytes={}", state.compactable.len(), std::mem::size_of::<(CommitVersion, Arc<DocumentPath>)>(), std::mem::size_of::<(Arc<DocumentPath>, CommitVersion)>(), paths.len(), paths.capacity(), paths.capacity() * std::mem::size_of::<Arc<DocumentPath>>());
    let captured = state.retained_scope_path(&path(0));
    let weak = Arc::downgrade(&captured);
    drop(captured);
    drop(paths);
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
    assert_index(&state);
    state.compact(LogicalInstant::from_unix_seconds(4000));
    assert_index(&state);
    assert!(weak.upgrade().is_none());
}

#[test]
fn refused_and_noop_commits_preserve_exact_index_keys() {
    let mut state = fixture(3, 1);
    state.compact(LogicalInstant::UNIX_EPOCH);
    let before = state.reclaim_thresholds.clone();
    let current = state.get_shared(&path(0)).unwrap();
    state
        .commit(
            &[Write {
                op: WriteOp::Set {
                    path: path(0),
                    fields: current.fields.clone(),
                    update_mask: None,
                },
                precondition: None,
                transforms: Vec::new(),
            }],
            None,
            LogicalInstant::UNIX_EPOCH,
        )
        .unwrap();
    assert_eq!(state.reclaim_thresholds, before);
    state.history_limits.max_versions = 0;
    assert!(matches!(
        state.commit(
            &[Write {
                op: WriteOp::Set {
                    path: path(0),
                    fields: imported(0, 99).fields,
                    update_mask: None
                },
                precondition: None,
                transforms: Vec::new()
            }],
            None,
            LogicalInstant::UNIX_EPOCH
        ),
        Err(FirestoreError::HistoryCapacity(_))
    ));
    assert_eq!(state.reclaim_thresholds, before);
    assert_index(&state);
}

#[test]
fn lone_tombstone_reclaims_at_its_exact_version() {
    let mut state = FirestoreState {
        version: CommitVersion(2),
        ..FirestoreState::default()
    };
    state.insert_scope_path(&path(0));
    state
        .history
        .insert(path(0), vec![(CommitVersion(2), None)]);
    state.rebuild_history_usage();
    state.refresh_reclaim_threshold(&path(0));
    assert_index(&state);
    assert!(state.reclaim_candidates(CommitVersion(1)).is_empty());
    assert_eq!(state.reclaim_candidates(CommitVersion(2)).len(), 1);
    state.capacity_floor = CommitVersion(2);
    state.compact(LogicalInstant::UNIX_EPOCH);
    assert!(state.history.is_empty());
    assert_index(&state);
}

#[test]
fn mixed_eligibility_preserves_unchanged_saturated_path_repair() {
    let mut state = fixture(2, 1);
    let a = state.get_shared(&path(0)).unwrap();
    let b = state.get_shared(&path(1)).unwrap();
    let entry = |version, document: &SharedDocument, bytes| {
        (
            CommitVersion(version),
            Some(RetainedDocument {
                document: Arc::clone(document),
                logical_bytes: bytes,
            }),
        )
    };
    state
        .history
        .insert(path(0), vec![entry(0, &a, 10), entry(2, &a, 0)]);
    state
        .history
        .insert(path(1), vec![entry(0, &b, u64::MAX), entry(3, &b, 0)]);
    state.rebuild_history_usage();
    assert!(!state.history_accounting_exact);
    state.refresh_reclaim_threshold(&path(0));
    state.refresh_reclaim_threshold(&path(1));
    let mut expected = state.clone();
    reference_compact(&mut expected, LogicalInstant::UNIX_EPOCH);
    state.compact(LogicalInstant::UNIX_EPOCH);
    assert_eq!(state.history_usage(), expected.history_usage());
    assert!(!state.history_accounting_exact);
    assert_eq!(state.history_usage().historical_document_bytes, u64::MAX);
    assert_eq!(history_view(&state), history_view(&expected));
}

#[test]
fn earlier_saturation_requires_fallback_after_aggregate_falls_below_max() {
    let mut state = fixture(2, 1);
    let a = state.get_shared(&path(0)).unwrap();
    let b = state.get_shared(&path(1)).unwrap();
    let entry = |version, document: &SharedDocument, bytes| {
        (
            CommitVersion(version),
            Some(RetainedDocument {
                document: Arc::clone(document),
                logical_bytes: bytes,
            }),
        )
    };
    state.history.insert(
        path(0),
        vec![
            entry(0, &a, 999),
            entry(1, &a, u64::MAX - 1000),
            entry(4, &a, 0),
        ],
    );
    state.history.insert(
        path(1),
        vec![
            entry(0, &b, 999),
            entry(1, &b, u64::MAX - 1000),
            entry(5, &b, 0),
        ],
    );
    state.version = CommitVersion(5);
    state.capacity_floor = CommitVersion(1);
    state.rebuild_history_usage();
    assert!(!state.history_accounting_exact);
    state.refresh_reclaim_threshold(&path(0));
    state.refresh_reclaim_threshold(&path(1));
    let mut expected = state.clone();
    reference_compact(&mut expected, LogicalInstant::UNIX_EPOCH);
    state.compact(LogicalInstant::UNIX_EPOCH);
    assert_eq!(state.history_usage(), expected.history_usage());
    assert!(!state.history_accounting_exact);
    assert_eq!(
        state.history_usage().historical_document_bytes,
        u64::MAX - 1000
    );
    assert!(state.history_usage().unsaturated());
    state.capacity_floor = CommitVersion(2);
    expected.capacity_floor = CommitVersion(2);
    reference_compact(&mut expected, LogicalInstant::UNIX_EPOCH);
    state.compact(LogicalInstant::UNIX_EPOCH);
    assert_eq!(state.history_usage(), expected.history_usage());
    assert!(!state.history_accounting_exact);
    state.capacity_floor = CommitVersion(4);
    expected.capacity_floor = CommitVersion(4);
    reference_compact(&mut expected, LogicalInstant::UNIX_EPOCH);
    state.compact(LogicalInstant::UNIX_EPOCH);
    assert_eq!(state.history_usage(), expected.history_usage());
    assert!(!state.history_accounting_exact);
    assert_eq!(history_view(&state), history_view(&expected));
}

#[test]
fn certificate_checks_every_component_and_keeps_uncertainty_sticky() {
    macro_rules! component {
        ($field:ident) => {{
            let left = finish_history_usage(HistoryUsage {
                $field: 3,
                ..HistoryUsage::default()
            });
            let before = finish_history_usage(HistoryUsage {
                $field: 5,
                ..HistoryUsage::default()
            });
            assert!(
                !checked_history_change(left, before, HistoryUsage::default()),
                stringify!($field)
            );
            let after = finish_history_usage(HistoryUsage {
                $field: u64::MAX - 2,
                ..HistoryUsage::default()
            });
            assert!(
                !checked_history_change(left, HistoryUsage::default(), after),
                stringify!($field)
            );
        }};
    }
    component!(live_document_bytes);
    component!(historical_document_bytes);
    component!(path_and_index_bytes);
    component!(version_metadata_bytes);
    component!(tombstone_bytes);
    component!(commit_time_bytes);
    component!(versions);
    component!(tombstones);
    component!(paths);
    component!(commit_times);
    let saturated = finish_history_usage(HistoryUsage {
        historical_document_bytes: u64::MAX,
        tombstone_bytes: u64::MAX,
        ..HistoryUsage::default()
    });
    let removed = finish_history_usage(HistoryUsage {
        historical_document_bytes: 10,
        tombstone_bytes: 20,
        ..HistoryUsage::default()
    });
    let reduced = subtract_history_usage(saturated, removed);
    let repaired = add_history_usage(subtract_history_usage(reduced, saturated), saturated);
    assert_eq!(repaired.historical_document_bytes, u64::MAX);
    assert_eq!(repaired.tombstone_bytes, u64::MAX);
    assert!(!checked_history_change(reduced, saturated, saturated));
    let one_component = finish_history_usage(HistoryUsage {
        historical_document_bytes: u64::MAX,
        tombstone_bytes: 1,
        ..HistoryUsage::default()
    });
    let disagreement = add_history_usage(
        subtract_history_usage(reduced, one_component),
        one_component,
    );
    assert_eq!(disagreement.historical_document_bytes, u64::MAX);
    assert_eq!(disagreement.tombstone_bytes, u64::MAX - 20);
    assert_eq!(disagreement.total_bytes, u64::MAX);
    let mut exact = true;
    assert_eq!(certified_history_add(u64::MAX - 1, 2, &mut exact), u64::MAX);
    assert!(!exact);
    assert_eq!(certified_history_sub(100, 1, &mut exact), 99);
    assert!(!exact);
    let mut exact = true;
    assert_eq!(certified_history_sub(1, 2, &mut exact), 0);
    assert!(!exact);
}

#[test]
fn certificate_clone_import_and_snapshot_require_checked_new_state() {
    eprintln!(
        "certificate_flag_bytes={} current_state_layout_bytes={}",
        std::mem::size_of::<bool>(),
        std::mem::size_of::<FirestoreState>()
    );
    let mut state = fixture(2, 1);
    assert!(state.history_accounting_exact);
    state.history.get_mut(&path(0)).unwrap()[0]
        .1
        .as_mut()
        .unwrap()
        .logical_bytes = u64::MAX;
    state.rebuild_history_usage();
    assert!(!state.history_accounting_exact);
    assert!(!state.clone().history_accounting_exact);
    let snapshot = state.visible_snapshot();
    assert!(snapshot.history_accounting_exact);
    assert_index(&snapshot);
    state
        .history
        .get_mut(&path(0))
        .unwrap()
        .last_mut()
        .unwrap()
        .1
        .as_mut()
        .unwrap()
        .logical_bytes = u64::MAX;
    state.rebuild_history_usage();
    assert!(!state.visible_snapshot().history_accounting_exact);
    state
        .import_documents(vec![imported(1, 9)], LogicalInstant::UNIX_EPOCH)
        .unwrap();
    assert!(!state.history_accounting_exact);
    for (path, history) in &mut state.history {
        for (_, document) in history {
            if let Some(document) = document {
                document.logical_bytes = document_size_bytes(path, &document.fields).unwrap();
            }
        }
    }
    state.rebuild_history_usage();
    assert!(state.history_accounting_exact);
    assert!(state.clone().history_accounting_exact);
    assert!(FirestoreState::default().history_accounting_exact);
}

#[test]
fn projection_and_refusal_do_not_publish_certificate_changes() {
    let mut state = fixture(2, 1);
    state.compact(LogicalInstant::UNIX_EPOCH);
    assert!(state.history_accounting_exact);
    let document = state.get_shared(&path(0)).unwrap();
    let synthetic = RetainedDocument {
        document,
        logical_bytes: u64::MAX,
    };
    let (_, _, projected_exact) = state.projected_history_usage(
        &[(path(0), None, Some(synthetic))],
        LogicalInstant::UNIX_EPOCH,
    );
    assert!(!projected_exact);
    assert!(state.history_accounting_exact);
    for certified in [true, false] {
        state.history_accounting_exact = certified;
        let usage = state.history_usage();
        let history = history_view(&state);
        let write = Write {
            op: WriteOp::Set {
                path: path(0),
                fields: imported(0, 88).fields,
                update_mask: None,
            },
            precondition: None,
            transforms: Vec::new(),
        };
        let result = state.commit_with_history_admission(
            &[write],
            None,
            LogicalInstant::UNIX_EPOCH,
            |_, _| Err::<(), _>(FirestoreError::InvalidArgument("declined".into())),
        );
        assert!(result.is_err());
        assert_eq!(state.history_accounting_exact, certified);
        assert_eq!(state.history_usage(), usage);
        assert_eq!(history_view(&state), history);
        let current = state.get_shared(&path(0)).unwrap();
        state
            .commit(
                &[Write {
                    op: WriteOp::Set {
                        path: path(0),
                        fields: current.fields.clone(),
                        update_mask: None,
                    },
                    precondition: None,
                    transforms: Vec::new(),
                }],
                None,
                LogicalInstant::UNIX_EPOCH,
            )
            .unwrap();
        assert_eq!(state.history_accounting_exact, certified);
    }
}

#[test]
fn uncertain_all_ineligible_compaction_keeps_legacy_path_steps() {
    let mut state = fixture(2, 1);
    state.capacity_floor = CommitVersion(1);
    state.history.get_mut(&path(0)).unwrap()[0]
        .1
        .as_mut()
        .unwrap()
        .logical_bytes = u64::MAX;
    state.rebuild_history_usage();
    assert!(!state.history_accounting_exact);
    let mut expected = state.clone();
    let before = history_view(&state);
    COMPACTION_PATH_VISITS.with(|count| count.set(0));
    state.compact(LogicalInstant::UNIX_EPOCH);
    reference_compact(&mut expected, LogicalInstant::UNIX_EPOCH);
    assert_eq!(COMPACTION_PATH_VISITS.with(std::cell::Cell::get), 2);
    assert_eq!(state.history_usage(), expected.history_usage());
    assert_eq!(history_view(&state), before);
    assert!(!state.history_accounting_exact);
}
