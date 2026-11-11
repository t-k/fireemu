//! Regression tests for query statistics mutation gaps.

use std::collections::BTreeMap;

use fireemu_core_firestore::path::DocumentPath;
use fireemu_core_firestore::query::{Query, QueryScope};
use fireemu_core_firestore::store::{FirestoreState, Write, WriteOp};
use fireemu_core_firestore::value::Value;
use fireemu_core_types::ids::{CollectionId, DatabaseId, ProjectId};
use fireemu_core_types::time::LogicalInstant;

#[test]
fn materialized_page_counts_cloned_documents_and_field_bytes() {
    let path = DocumentPath::parse(
        &ProjectId::try_new("demo-app").unwrap(),
        &DatabaseId::default_database(),
        "items/one",
    )
    .unwrap();
    let fields = BTreeMap::from([("name".to_owned(), Value::String("hello".to_owned()))]);
    let mut state = FirestoreState::new();
    state
        .commit(
            &[Write {
                op: WriteOp::Set {
                    path: path.clone(),
                    fields,
                    update_mask: None,
                },
                precondition: None,
                transforms: Vec::new(),
            }],
            None,
            LogicalInstant::UNIX_EPOCH,
        )
        .unwrap();
    let query = Query::new(QueryScope::collection(
        None,
        CollectionId::try_new("items").unwrap(),
    ));
    let (documents, query_stats) = state.documents_at_query_paths_with_stats(&query, &[path], None);
    assert_eq!(documents.len(), 1);
    assert_eq!(query_stats.cloned_documents, 1);
    assert!(query_stats.cloned_field_bytes >= 9);
}
