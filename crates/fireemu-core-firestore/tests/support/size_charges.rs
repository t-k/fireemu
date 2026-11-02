// Document size charges that need only the total (FSM-3).
use super::*;
use crate::size::DOCUMENT_BREAKDOWNS;
use fireemu_core_types::ids::{DatabaseId, ProjectId};

fn breakdowns_during<T>(work: impl FnOnce() -> T) -> (T, usize) {
    DOCUMENT_BREAKDOWNS.with(|count| count.set(0));
    let result = work();
    (result, DOCUMENT_BREAKDOWNS.with(std::cell::Cell::take))
}

#[test]
fn fsm_3_admission_ledger_and_visible_bytes_charge_totals_without_breakdowns() {
    let path = DocumentPath::parse(
        &ProjectId::try_new("demo-app").expect("project id"),
        &DatabaseId::default_database(),
        "items/one",
    )
    .expect("document path");
    let fields: BTreeMap<String, Value> = (0..12)
        .map(|index| (format!("field_{index:02}"), Value::String(format!("v{index}"))))
        .collect();
    let write = Write {
        op: WriteOp::Set {
            path: path.clone(),
            fields: fields.clone(),
            update_mask: None,
        },
        precondition: None,
        transforms: Vec::new(),
    };
    let mut state = FirestoreState::new();

    let (committed, admission) =
        breakdowns_during(|| state.commit(&[write], None, LogicalInstant::UNIX_EPOCH));
    committed.expect("commit");
    assert_eq!(admission, 0, "commit admission builds no size breakdown");

    let now = LogicalInstant::from_unix_seconds(1);
    let transaction = state.begin_transaction(false, now).expect("transaction");
    let query = Query::new(QueryScope::collection(
        None,
        CollectionId::try_new("items").expect("collection id"),
    ));
    let (documents, ledger) =
        breakdowns_during(|| state.run_query_in_transaction(&transaction, &query));
    let documents = documents.expect("transactional query");
    assert_eq!(documents.len(), 1);
    assert_eq!(ledger, 0, "the conflict ledger builds no size breakdown");

    let expected = document_size(&path, &fields).expect("size").total;
    let (visible, estimate) = breakdowns_during(|| state.visible_bytes());
    assert_eq!(visible, expected, "the estimate is still the modelled total");
    assert_eq!(estimate, 0, "the visible-bytes estimate builds no size breakdown");
}
