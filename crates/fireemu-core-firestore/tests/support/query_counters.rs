// Cost of the clone counters a query reports (FSM-1).
use super::*;
use fireemu_core_types::ids::{DatabaseId, ProjectId};

fn mixed_fields(count: usize) -> BTreeMap<String, Value> {
    (0..count)
        .map(|index| {
            let value = match index % 5 {
                0 => Value::Integer(i64::try_from(index).expect("fits i64")),
                1 => Value::String(format!("value-{index}")),
                2 => Value::Bytes(vec![7; index]),
                3 => Value::Array(vec![
                    Value::Null,
                    Value::Vector(vec![1.0, 2.0]),
                    Value::Map(BTreeMap::from([(
                        "deep".to_owned(),
                        Value::String("deep".to_owned()),
                    )])),
                ]),
                _ => Value::Map(BTreeMap::from([
                    ("nested".to_owned(), Value::Array(vec![Value::Boolean(true)])),
                    ("name".to_owned(), Value::String("demo".to_owned())),
                ])),
            };
            (format!("field_{index:02}"), value)
        })
        .collect()
}

#[test]
fn fsm_1_query_sizes_each_result_document_on_one_work_stack() {
    const FIELDS: usize = 64;
    let path = DocumentPath::parse(
        &ProjectId::try_new("demo-app").expect("project id"),
        &DatabaseId::default_database(),
        "items/one",
    )
    .expect("document path");
    let fields = mixed_fields(FIELDS);
    let mut state = FirestoreState::new();
    state
        .commit(
            &[Write {
                op: WriteOp::Set {
                    path,
                    fields: fields.clone(),
                    update_mask: None,
                },
                precondition: None,
                transforms: Vec::new(),
            }],
            None,
            LogicalInstant::UNIX_EPOCH,
        )
        .expect("seed commit");
    let query = Query::new(QueryScope::collection(
        None,
        CollectionId::try_new("items").expect("collection id"),
    ));

    RETAINED_BYTES_WORK_STACKS.with(|count| count.set(0));
    let (documents, query_stats) = state.run_query_with_stats(&query, None).expect("query");
    let work_stacks = RETAINED_BYTES_WORK_STACKS.with(std::cell::Cell::take);

    assert_eq!(documents.len(), 1);
    assert_eq!(
        work_stacks, 1,
        "one work stack per result document, not one per field"
    );
    // The reported figure is still each field's key plus its value sized on its own.
    let per_value = documents[0]
        .fields
        .iter()
        .map(|(key, value)| {
            u64::try_from(key.len())
                .expect("fits u64")
                .saturating_add(value_retained_bytes(value))
        })
        .fold(0u64, u64::saturating_add);
    assert_eq!(query_stats.cloned_field_bytes, per_value);
}

#[test]
fn fsm_1_reused_work_stack_sizes_like_a_fresh_one() {
    let fields = mixed_fields(40);
    let mut pending = Vec::new();
    for value in fields.values() {
        let reused = value_retained_bytes_with(value, &mut pending);
        assert!(pending.is_empty(), "the stack is drained on return");
        assert_eq!(reused, value_retained_bytes(value));
    }
}
