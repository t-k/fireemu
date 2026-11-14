use super::*;
use crate::path::DocumentPath;
use fireemu_core_types::ids::{CollectionId, DatabaseId, DocumentId, ProjectId};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use super::super::{CommitVersion, FirestoreState, Write, WriteOp};
use crate::field_path::FieldPath;
use crate::query::{Cursor, Direction, OrderClause, Query, QueryScope};
use crate::value::Value;
use fireemu_core_types::time::LogicalInstant;

fn path(value: &str) -> DocumentPath {
    DocumentPath::parse(
        &ProjectId::try_new("demo-app").expect("valid project"),
        &DatabaseId::default_database(),
        value,
    )
    .expect("valid document path")
}

#[test]
fn retained_and_live_indexes_follow_their_independent_path_sets() {
    let a = path("root/a");
    let child = path("root/a/children/x");
    let b = path("root/b");
    let mut indexes = PathIndexes::default();

    indexes.insert_retained(&a);
    indexes.insert_live(&a);
    indexes.insert_retained(&child);
    indexes.insert_live(&child);
    indexes.insert_retained(&b);

    assert_eq!(
        indexed_paths(indexes.direct_collection_paths().values().flatten()),
        [a.clone(), b.clone(), child.clone()].into()
    );
    assert_eq!(
        indexed_paths(indexes.collection_group_paths().values().flatten()),
        [a.clone(), b.clone(), child.clone()].into()
    );
    assert_eq!(
        indexed_paths(indexes.live_direct_collection_paths().values().flatten()),
        [a.clone(), child.clone()].into()
    );
    assert_eq!(
        indexed_paths(indexes.live_collection_group_paths().values().flatten()),
        [a.clone(), child.clone()].into()
    );
    assert_eq!(
        indexed_paths(indexes.live_paths().iter()),
        [a.clone(), child.clone()].into()
    );

    indexes.remove_live(&child);
    assert_eq!(
        indexed_paths(indexes.live_paths().iter()),
        [a.clone()].into()
    );
    assert_eq!(
        indexed_paths(indexes.collection_group_paths().values().flatten()),
        [a.clone(), b.clone(), child.clone()].into()
    );

    indexes.insert_live(&child);
    indexes.remove_live(&child);
    indexes.remove_retained(&child);
    assert_eq!(
        indexed_paths(indexes.collection_group_paths().values().flatten()),
        [a.clone(), b.clone()].into()
    );
    assert_eq!(
        indexed_paths(indexes.live_paths().iter()),
        [a.clone()].into()
    );
}

#[test]
fn rebuild_uses_one_allocation_across_all_retained_index_families() {
    let a = path("root/a");
    let child = path("root/a/children/x");
    let indexes = PathIndexes::rebuild([(&a, true), (&child, false)]);

    let canonical = indexes
        .collection_group_paths()
        .values()
        .flatten()
        .map(|path| (path.as_ref(), Arc::as_ptr(path)))
        .collect::<BTreeMap<_, _>>();
    for path in indexes
        .direct_collection_paths()
        .values()
        .flatten()
        .chain(indexes.live_direct_collection_paths().values().flatten())
        .chain(indexes.live_collection_group_paths().values().flatten())
        .chain(indexes.live_paths().iter())
    {
        assert_eq!(canonical.get(path.as_ref()), Some(&Arc::as_ptr(path)));
    }
    assert_eq!(
        indexed_paths(indexes.live_paths().iter()),
        [a.clone()].into()
    );
    assert_eq!(
        indexed_paths(indexes.collection_group_paths().values().flatten()),
        [a, child].into()
    );
}

#[test]
fn listing_trie_tracks_retained_prefixes_and_live_candidates() {
    let parent = path("root/a");
    let child = path("root/a/children/x");
    let mut indexes = PathIndexes::default();
    indexes.insert_retained(&parent);
    indexes.insert_live(&parent);
    indexes.insert_retained(&child);

    let root = indexes
        .listing_trie()
        .collection(None, &CollectionId::try_new("root").unwrap())
        .unwrap();
    assert_eq!(root.documents.len(), 1);
    assert!(root
        .live_candidates
        .contains(&DocumentId::try_new("a").unwrap()));
    let nested = indexes
        .listing_trie()
        .collection(Some(&parent), &CollectionId::try_new("children").unwrap())
        .unwrap();
    assert_eq!(nested.documents.len(), 1);
    assert!(nested.live_candidates.is_empty());
}

#[test]
fn generated_pict_rows_drive_scoped_query_snapshot_order_and_cursor_behavior() {
    const CASES: &str = include_str!("path-indexes.generated.tsv");
    let all_paths = [
        "root/a",
        "root/b",
        "root/c",
        "root/a/children/x",
        "root/a/children/y",
        "root/b/children/z",
        "root/a/leaf/q",
    ]
    .map(path);

    for row in CASES.lines().skip(1) {
        assert_generated_pict_row(row, &all_paths);
    }
}

fn assert_generated_pict_row(row: &str, all_paths: &[DocumentPath]) {
    let [scope, read, order, cursor, lifecycle]: [&str; 5] = row
        .split('\t')
        .collect::<Vec<_>>()
        .try_into()
        .expect("PICT table has five columns");
    let (state, model, snapshot_version, snapshot_model) =
        state_for_lifecycle(all_paths, lifecycle);
    let (version, model) = match read {
        "latest" => (None, model),
        "snapshot" => (Some(snapshot_version), snapshot_model),
        other => panic!("unknown PICT read selector {other}"),
    };
    let query_scope = query_scope_for(scope);
    let direction = match order {
        "asc" => Direction::Ascending,
        "desc" => Direction::Descending,
        other => panic!("unknown PICT order {other}"),
    };
    let mut expected = expected_query_paths(&model, scope, direction);
    let mut query = Query::new(query_scope);
    query.order_by.push(OrderClause {
        field: FieldPath::document_name(),
        direction,
    });
    if cursor == "present" {
        let cursor_path = expected
            .first()
            .expect("fixture scope has query results")
            .clone();
        query.start_at = Some(Cursor {
            values: vec![Value::Reference(cursor_path.resource_name())],
            before: false,
        });
        expected.remove(0);
    }
    let actual = state
        .run_query(&query, version)
        .expect("execute PICT query")
        .into_iter()
        .map(|document| document.path)
        .collect::<Vec<_>>();
    assert_eq!(actual, expected, "PICT row: {row}");
    if read == "snapshot" && matches!(lifecycle, "deleted" | "revived") {
        assert!(
            snapshot_version < state.current_version(),
            "PICT row: {row}"
        );
        if scope != "collection" {
            let latest = state
                .run_query(&query, None)
                .expect("execute latest query for comparison")
                .into_iter()
                .map(|document| document.path)
                .collect::<Vec<_>>();
            assert_ne!(actual, latest, "snapshot must differ from latest: {row}");
        }
    }
}

fn state_for_lifecycle(
    all_paths: &[DocumentPath],
    lifecycle: &str,
) -> (
    FirestoreState,
    BTreeSet<DocumentPath>,
    CommitVersion,
    BTreeSet<DocumentPath>,
) {
    let mut state = FirestoreState::new();
    let writes = all_paths.iter().cloned().map(set_write).collect::<Vec<_>>();
    state
        .commit(&writes, None, LogicalInstant::UNIX_EPOCH)
        .expect("create query fixtures");
    let mut model = all_paths.iter().cloned().collect::<BTreeSet<_>>();
    let mut snapshot_version = state.current_version();
    let mut snapshot_model = model.clone();
    let deleted_path = path("root/a/children/x");
    match lifecycle {
        "live" => {}
        "deleted" => {
            state
                .commit(
                    &[delete_write(deleted_path.clone())],
                    None,
                    LogicalInstant::from_unix_seconds(1),
                )
                .expect("delete one fixture");
            model.remove(&deleted_path);
        }
        "revived" => {
            state
                .commit(
                    &[delete_write(deleted_path.clone())],
                    None,
                    LogicalInstant::from_unix_seconds(1),
                )
                .expect("delete before revival");
            snapshot_version = state.current_version();
            snapshot_model.remove(&deleted_path);
            state
                .commit(
                    &[set_write(deleted_path)],
                    None,
                    LogicalInstant::from_unix_seconds(2),
                )
                .expect("revive one fixture");
        }
        "compacted" => {
            state
                .commit(
                    &[delete_write(deleted_path.clone())],
                    None,
                    LogicalInstant::from_unix_seconds(1),
                )
                .expect("delete before compaction");
            state.compact(LogicalInstant::from_unix_seconds(
                super::super::READ_TIME_RETENTION_SECONDS + 2,
            ));
            model.remove(&deleted_path);
            snapshot_version = state.current_version();
            snapshot_model.clone_from(&model);
        }
        other => panic!("unknown PICT lifecycle {other}"),
    }
    (state, model, snapshot_version, snapshot_model)
}

fn query_scope_for(scope: &str) -> QueryScope {
    match scope {
        "collection" => QueryScope::collection(
            None,
            CollectionId::try_new("root").expect("valid collection ID"),
        ),
        "collection_group" => QueryScope::collection_group(
            CollectionId::try_new("children").expect("valid collection ID"),
        ),
        "kindless" => QueryScope::kindless_all_descendants(Some(path("root/a"))),
        other => panic!("unknown PICT scope {other}"),
    }
}

fn expected_query_paths(
    model: &BTreeSet<DocumentPath>,
    scope: &str,
    direction: Direction,
) -> Vec<DocumentPath> {
    let in_scope = |candidate: &DocumentPath| match scope {
        "collection" => {
            candidate.pairs().len() == 1 && candidate.collection_id().as_str() == "root"
        }
        "collection_group" => candidate
            .pairs()
            .iter()
            .any(|(collection, _)| collection.as_str() == "children"),
        "kindless" => {
            candidate.pairs().starts_with(path("root/a").pairs()) && candidate.pairs().len() > 1
        }
        _ => unreachable!(),
    };
    let mut expected = model
        .iter()
        .filter(|candidate| in_scope(candidate))
        .cloned()
        .collect::<Vec<_>>();
    expected.sort();
    if direction == Direction::Descending {
        expected.reverse();
    }
    expected
}

fn set_write(path: DocumentPath) -> Write {
    Write {
        op: WriteOp::Set {
            path,
            fields: BTreeMap::new(),
            update_mask: None,
        },
        precondition: None,
        transforms: Vec::new(),
    }
}

fn delete_write(path: DocumentPath) -> Write {
    Write {
        op: WriteOp::Delete { path },
        precondition: None,
        transforms: Vec::new(),
    }
}

fn indexed_paths<'a>(
    paths: impl IntoIterator<Item = &'a Arc<DocumentPath>>,
) -> BTreeSet<DocumentPath> {
    paths
        .into_iter()
        .map(|path| path.as_ref().clone())
        .collect()
}
