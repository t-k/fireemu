use super::*;
use fireemu_core_types::ids::{DatabaseId, ProjectId};

fn path(index: usize) -> DocumentPath {
    DocumentPath::parse(
        &ProjectId::try_new("demo-app").unwrap(),
        &DatabaseId::default_database(),
        &format!("items/d{index}"),
    )
    .unwrap()
}
fn write(index: usize, value: i64) -> Write {
    Write {
        op: WriteOp::Set {
            path: path(index),
            fields: BTreeMap::from([("score".into(), Value::Integer(value))]),
            update_mask: None,
        },
        precondition: None,
        transforms: Vec::new(),
    }
}
fn query(value: i64) -> Query {
    Query::new(QueryScope::collection(
        None,
        CollectionId::try_new("items").unwrap(),
    ))
    .with_filter(crate::query::FilterExpr::Field {
        field: FieldPath::parse("score").unwrap(),
        op: crate::query::FieldOp::Equal,
        value: Value::Integer(value),
    })
}

#[test]
fn holder_checks_group_raw_input_once_across_paths_queries_and_holders() {
    for batch in [32, 256, 500] {
        for unique in [1, 16, batch] {
            for queries in [1, 16] {
                for holders in [1, 8] {
                    let mut state = FirestoreState::default();
                    for _ in 0..holders {
                        let id = state
                            .begin_transaction(false, LogicalInstant::UNIX_EPOCH)
                            .unwrap();
                        for _ in 0..queries {
                            state.run_query_in_transaction(&id, &query(999)).unwrap();
                        }
                    }
                    let writes = (0..batch).map(|i| write(i % unique, 0)).collect::<Vec<_>>();
                    CONFLICT_BATCH_INPUT_VISITS.with(|visits| visits.set(0));
                    assert!(state.lock_holders(&writes, None).is_empty());
                    let visits = CONFLICT_BATCH_INPUT_VISITS.with(std::cell::Cell::get);
                    eprintln!("batch={batch} unique={unique} queries={queries} holders={holders} raw_batch_visits={visits}");
                    assert_eq!(visits, batch);
                }
            }
        }
    }
}

// Frozen full-batch reference: do not call the grouped range helpers here.
fn reference_covers(state: &FirestoreState, query: &Query, writes: &[Write]) -> bool {
    let mut seen = Vec::new();
    for write in writes {
        let path = write.op.path();
        if seen.contains(&path) {
            continue;
        }
        seen.push(path);
        if !path_in_scope(path, &query.scope) {
            continue;
        }
        let Some(filter) = query.filter.as_ref() else {
            return true;
        };
        let own = || writes.iter().filter(|write| write.op.path() == path);
        if own().any(|write| !write.transforms.is_empty()) {
            return true;
        }
        let passes = |document: &Document| eval_filter(filter, document).unwrap_or(true);
        let before = state.get(path);
        if before.is_some_and(passes) {
            return true;
        }
        let mut current = before.cloned();
        for write in own() {
            match FirestoreState::preview_from(current.as_ref(), write, LogicalInstant::UNIX_EPOCH)
            {
                Ok(next) => current = next,
                Err(_) => return true,
            }
        }
        if current.as_ref().is_some_and(passes) {
            return true;
        }
    }
    false
}

#[test]
fn grouped_range_preserves_before_and_final_composed_order() {
    let mut state = FirestoreState::default();
    let writes = [write(0, 1), write(1, 0), write(0, 2)];
    let grouped = group_writes(&writes);
    assert_eq!(grouped[&path(0)][0], &writes[0]);
    assert_eq!(grouped[&path(0)][1], &writes[2]);
    assert!(!state.range_covers_writes(&query(1), &grouped));
    state
        .commit(&[write(0, 1)], None, LogicalInstant::UNIX_EPOCH)
        .unwrap();
    assert!(state.range_covers_writes(&query(1), &group_writes(&[write(0, 2)])));
}

#[test]
fn grouped_range_remains_conservative_for_transforms() {
    let state = FirestoreState::default();
    let mut changed = write(0, 0);
    changed.transforms.push(FieldTransform {
        field: FieldPath::parse("score").unwrap(),
        kind: TransformKind::Increment(Value::Integer(0)),
    });
    assert!(state.range_covers_writes(&query(1), &group_writes(&[changed])));
}

#[test]
fn deadlock_cycles_group_the_holders_own_pending_batch() {
    for owned in [false, true] {
        let mut state = FirestoreState::default();
        let requester = state
            .begin_transaction(false, LogicalInstant::UNIX_EPOCH)
            .unwrap();
        state
            .run_query_in_transaction(&requester, &query(1))
            .unwrap();
        let holder = state
            .begin_transaction(false, LogicalInstant::from_unix_seconds(1))
            .unwrap();
        state.run_query_in_transaction(&holder, &query(2)).unwrap();
        let pending = [write(0, 1)];
        let owner = CommitWaitOwner::new();
        if owned {
            state
                .transactions
                .get_mut(&holder)
                .unwrap()
                .owned_commit_waits
                .insert(&owner, &pending);
        } else {
            state
                .transactions
                .get_mut(&holder)
                .unwrap()
                .waiting_to_commit = Some(pending.to_vec());
        }
        assert!(state
            .check_contention(
                &[write(0, 2)],
                Some(&requester),
                LogicalInstant::from_unix_seconds(2),
                None
            )
            .is_ok());
        assert!(!state.transaction_is_active(&holder));
        assert!(state.transaction_is_active(&requester));
    }
}

proptest::proptest! {
    #![proptest_config(proptest::test_runner::Config::with_cases(256))]
    #[test]
    fn grouped_ranges_match_full_batch_reference(before in proptest::collection::vec(proptest::option::of(-2i64..3), 3), operations in proptest::collection::vec((0usize..3, 0u8..5, -2i64..3), 0..32), target in -2i64..3, other_scope in proptest::bool::ANY) {
        let mut state = FirestoreState::default();
        for (id, value) in before.into_iter().enumerate() { if let Some(value) = value { state.commit(&[write(id, value)], None, LogicalInstant::UNIX_EPOCH).unwrap(); } }
        let writes = operations.into_iter().map(|(id, kind, value)| {
            let mut operation = write(id, value);
            match kind {
                1 => operation.op = WriteOp::Delete { path: path(id) },
                2 => operation.op = WriteOp::Verify { path: path(id) },
                3 => operation.op = WriteOp::Set { path: path(id), fields: BTreeMap::new(), update_mask: Some(vec![FieldPath::parse("score").unwrap()]) },
                4 => operation.transforms.push(FieldTransform { field: FieldPath::parse("score").unwrap(), kind: TransformKind::Increment(Value::Integer(value)) }),
                _ => {}
            }
            operation
        }).collect::<Vec<_>>();
        let mut candidate = query(target);
        if other_scope { candidate.scope = QueryScope::collection(None, CollectionId::try_new("other").unwrap()); }
        candidate.offset = 1; candidate.limit = Some(0);
        proptest::prop_assert_eq!(state.range_covers_writes(&candidate, &group_writes(&writes)), reference_covers(&state, &candidate, &writes));
    }
}

#[test]
fn irrelevant_holders_do_not_build_a_batch_group() {
    for mode in 0..4 {
        let mut state = FirestoreState::default();
        let mut own = None;
        if mode != 0 {
            let id = state
                .begin_transaction(mode == 2, LogicalInstant::UNIX_EPOCH)
                .unwrap();
            state.run_query_in_transaction(&id, &query(999)).unwrap();
            if mode == 1 {
                state.finish_transaction(&id, TransactionState::Finished);
            }
            if mode == 3 {
                own = Some(id);
            }
        }
        let writes = (0..32).map(|_| write(0, 0)).collect::<Vec<_>>();
        CONFLICT_BATCH_INPUT_VISITS.with(|visits| visits.set(0));
        assert!(state.lock_holders(&writes, own.as_ref()).is_empty());
        assert_eq!(CONFLICT_BATCH_INPUT_VISITS.with(std::cell::Cell::get), 0);
        assert!(state
            .check_contention(&writes, own.as_ref(), LogicalInstant::UNIX_EPOCH, None)
            .is_ok());
        assert_eq!(CONFLICT_BATCH_INPUT_VISITS.with(std::cell::Cell::get), 0);
    }
}
