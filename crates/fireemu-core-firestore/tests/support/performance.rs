use super::*;
use fireemu_core_types::ids::{DatabaseId, ProjectId};

fn reference_floor(
    state: &FirestoreState,
    capacity: CommitVersion,
    version: CommitVersion,
    now: LogicalInstant,
) -> CommitVersion {
    let oldest = LogicalInstant::from_nanos(
        now.as_nanos()
            .saturating_sub(i128::from(READ_TIME_RETENTION_SECONDS) * 1_000_000_000),
    );
    let floor = state.version_at(oldest).max(capacity);
    state
        .transactions
        .values()
        .filter(|transaction| {
            transaction.state == TransactionState::Active
                && transaction_deadline(transaction, state.limit_scope) > now
        })
        .map(|transaction| transaction.read_version)
        .min()
        .map_or(floor, |oldest| floor.min(oldest))
        .max(capacity)
        .min(version)
}

#[test]
fn projected_floor_work_excludes_finished_lineage() {
    let mut state = FirestoreState::default();
    let now = LogicalInstant::from_unix_seconds(2);
    for _ in 0..8 {
        state.begin_transaction(false, now).unwrap();
    }
    let mut finished = state.transactions.values().next().unwrap().clone();
    finished.state = TransactionState::Finished;
    for id in 100..1100 {
        state
            .transactions
            .insert(TransactionId(id), finished.clone());
    }
    RETENTION_PROJECTION_VISITS.with(|visits| visits.set(0));
    assert_eq!(
        state.projected_retention_floor(CommitVersion(0), CommitVersion(10), now),
        reference_floor(&state, CommitVersion(0), CommitVersion(10), now)
    );
    assert_eq!(RETENTION_PROJECTION_VISITS.with(std::cell::Cell::get), 8);
}

#[test]
fn projected_floor_matches_reference_at_exact_deadlines_without_mutation() {
    for scope in [LimitScope::Production, LimitScope::OfficialEmulator] {
        let mut state = FirestoreState::with_limit_scope(scope);
        state.version = CommitVersion(10);
        state
            .commit_times
            .push_back((CommitVersion(10), LogicalInstant::from_unix_seconds(-36000)));
        let now = LogicalInstant::from_unix_seconds(2);
        let id = state.begin_transaction(false, now).unwrap();
        state.transactions.get_mut(&id).unwrap().read_version = CommitVersion(2);
        let deadline = transaction_deadline(&state.transactions[&id], scope);
        for delta in [-1, 0, 1] {
            let at = LogicalInstant::from_nanos(deadline.as_nanos() + delta);
            for capacity in [CommitVersion(0), CommitVersion(3)] {
                assert_eq!(
                    state.projected_retention_floor(capacity, CommitVersion(10), at),
                    reference_floor(&state, capacity, CommitVersion(10), at)
                );
                assert_eq!(state.transactions[&id].state, TransactionState::Active);
            }
        }
    }
}

#[test]
fn cosine_normalizes_the_query_once_per_execution() {
    for count in [1, 100, 1000] {
        let mut state = FirestoreState::default();
        let writes = (0..count)
            .map(|id| Write {
                op: WriteOp::Set {
                    path: DocumentPath::parse(
                        &ProjectId::try_new("demo-app").unwrap(),
                        &DatabaseId::default_database(),
                        &format!("items/d{id}"),
                    )
                    .unwrap(),
                    fields: BTreeMap::from([(
                        "embedding".to_owned(),
                        Value::Vector(vec![3.0, 4.0]),
                    )]),
                    update_mask: None,
                },
                precondition: None,
                transforms: vec![],
            })
            .collect::<Vec<_>>();
        for chunk in writes.chunks(100) {
            state
                .commit(chunk, None, LogicalInstant::UNIX_EPOCH)
                .unwrap();
        }
        let query = Query::new(QueryScope::collection(
            None,
            CollectionId::try_new("items").unwrap(),
        ))
        .with_find_nearest(crate::query::FindNearest {
            vector_field: FieldPath::parse("embedding").unwrap(),
            query_vector: vec![1.0, 2.0],
            distance_measure: DistanceMeasure::Cosine,
            limit: 10,
            distance_result_field: None,
            distance_threshold: None,
        });
        NORMALIZATION_CALLS.with(|calls| calls.set(0));
        let (rows, counters) = state.run_query_with_stats(&query, None).unwrap();
        assert_eq!(rows.len(), count.min(10));
        assert_eq!(counters.scanned, count as u64);
        assert_eq!(NORMALIZATION_CALLS.with(std::cell::Cell::get), count + 1);
    }
}

proptest::proptest! {
    #![proptest_config(proptest::test_runner::Config::with_cases(128))]
    #[test]
    fn indexed_projection_matches_full_lineage_reference(finished in proptest::collection::vec(proptest::bool::ANY, 1..64), second in 0i64..400, capacity in 0u64..64, production in proptest::bool::ANY) {
        let scope = if production { LimitScope::Production } else { LimitScope::OfficialEmulator };
        let mut state = FirestoreState::with_limit_scope(scope);
        for (i, finish) in finished.iter().enumerate() {
            state.version = CommitVersion(i as u64);
            let id = state.begin_transaction(false, LogicalInstant::from_unix_seconds(i64::try_from(i).unwrap())).unwrap();
            if *finish { state.finish_transaction(&id, TransactionState::Finished); }
        }
        state.version = CommitVersion(finished.len() as u64);
        state.commit_times.push_back((state.version, LogicalInstant::from_unix_seconds(-36000)));
        let at = LogicalInstant::from_unix_seconds(second);
        let capacity = CommitVersion(capacity.min(state.version.0));
        proptest::prop_assert_eq!(state.projected_retention_floor(capacity, state.version, at), reference_floor(&state, capacity, state.version, at));
    }
}
