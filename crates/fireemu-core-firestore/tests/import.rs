//! Installing a database from an import artifact: one commit, the recorded times kept, and
//! nothing published when a document is refused.

use std::collections::BTreeMap;

use fireemu_core_firestore::path::DocumentPath;
use fireemu_core_firestore::store::{FirestoreState, ImportedDocument, Write, WriteOp};
use fireemu_core_firestore::value::Value;
use fireemu_core_types::ids::{DatabaseId, ProjectId};
use fireemu_core_types::time::LogicalInstant;

fn path(p: &str) -> DocumentPath {
    DocumentPath::parse(
        &ProjectId::try_new("demo-app").unwrap(),
        &DatabaseId::default_database(),
        p,
    )
    .unwrap()
}

fn fields(entries: &[(&str, Value)]) -> BTreeMap<String, Value> {
    entries
        .iter()
        .map(|(k, v)| ((*k).to_owned(), v.clone()))
        .collect()
}

fn t(n: i64) -> LogicalInstant {
    LogicalInstant::from_unix_seconds(1_788_000_000 + n)
}

fn imported(p: &str, f: &[(&str, Value)]) -> ImportedDocument {
    ImportedDocument {
        path: path(p),
        fields: fields(f),
        create_time: None,
        update_time: None,
    }
}

#[test]
fn an_import_publishes_every_document_at_one_commit_version() {
    let mut state = FirestoreState::new();
    let result = state
        .import_documents(
            vec![
                imported("cities/SF", &[("name", Value::String("SF".to_owned()))]),
                imported("cities/LA", &[("name", Value::String("LA".to_owned()))]),
                imported(
                    "cities/SF/landmarks/gg",
                    &[("bridge", Value::Boolean(true))],
                ),
            ],
            t(0),
        )
        .expect("the import succeeds");
    assert_eq!(result.changes.len(), 3);
    assert_eq!(state.current_version().value(), 1);
    assert_eq!(state.documents().len(), 3);
    for change in &result.changes {
        assert!(
            change.before.is_none(),
            "an import into an empty database creates"
        );
        let after = change.after.as_ref().expect("a document");
        assert_eq!(after.version, state.current_version());
        assert_eq!(after.create_time, result.commit_time);
        assert_eq!(after.update_time, result.commit_time);
    }
}

#[test]
fn an_imported_document_keeps_the_times_the_artifact_recorded() {
    let mut state = FirestoreState::new();
    let created = t(-5_000);
    let updated = t(-10);
    state
        .import_documents(
            vec![ImportedDocument {
                path: path("cities/SF"),
                fields: fields(&[("population", Value::Integer(860_000))]),
                create_time: Some(created),
                update_time: Some(updated),
            }],
            t(0),
        )
        .expect("the import succeeds");
    let document = state.get(&path("cities/SF")).expect("the document");
    assert_eq!(document.create_time, created);
    assert_eq!(document.update_time, updated);
    // The commit version is still the one this import produced, so a Listen resume token
    // taken after it names the imported state.
    assert_eq!(document.version, state.current_version());
}

#[test]
fn an_import_over_existing_documents_replaces_them_and_reports_the_previous_version() {
    let mut state = FirestoreState::new();
    state
        .commit(
            &[Write {
                op: WriteOp::Set {
                    path: path("cities/SF"),
                    fields: fields(&[("name", Value::String("before".to_owned()))]),
                    update_mask: None,
                },
                precondition: None,
                transforms: vec![],
            }],
            None,
            t(0),
        )
        .expect("the seed commits");
    let before_version = state.current_version();

    let result = state
        .import_documents(
            vec![imported(
                "cities/SF",
                &[("name", Value::String("after".to_owned()))],
            )],
            t(1),
        )
        .expect("the import succeeds");
    assert_eq!(result.changes.len(), 1);
    assert_eq!(
        result.changes[0]
            .before
            .as_ref()
            .expect("the previous version")
            .fields
            .get("name"),
        Some(&Value::String("before".to_owned()))
    );
    assert!(state.current_version().value() > before_version.value());
    assert_eq!(
        state.get(&path("cities/SF")).expect("the document").fields["name"],
        Value::String("after".to_owned())
    );
}

#[test]
fn a_refused_document_leaves_the_database_untouched() {
    let mut state = FirestoreState::new();
    state
        .import_documents(
            vec![imported("cities/LA", &[("a", Value::Integer(1))])],
            t(0),
        )
        .expect("the first import succeeds");
    let version = state.current_version();

    // A field name that is not a valid field path is refused, and the whole import with it.
    let refused = state.import_documents(
        vec![
            imported("cities/SF", &[("ok", Value::Integer(1))]),
            ImportedDocument {
                path: path("cities/NY"),
                fields: fields(&[("", Value::Integer(1))]),
                create_time: None,
                update_time: None,
            },
        ],
        t(1),
    );
    assert!(refused.is_err(), "an invalid document refuses the import");
    assert_eq!(state.current_version(), version, "no version was consumed");
    assert!(state.get(&path("cities/SF")).is_none());
    assert_eq!(state.documents().len(), 1);
}

#[test]
fn an_empty_import_consumes_no_version() {
    let mut state = FirestoreState::new();
    let result = state
        .import_documents(Vec::new(), t(0))
        .expect("an empty import succeeds");
    assert!(result.changes.is_empty());
    assert_eq!(state.current_version().value(), 0);
    assert!(state.documents().is_empty());
}

#[test]
fn writes_after_an_import_keep_the_strictly_increasing_commit_times() {
    let mut state = FirestoreState::new();
    let import = state
        .import_documents(
            vec![imported("cities/SF", &[("a", Value::Integer(1))])],
            t(0),
        )
        .expect("the import succeeds");
    let commit = state
        .commit(
            &[Write {
                op: WriteOp::Set {
                    path: path("cities/LA"),
                    fields: fields(&[("a", Value::Integer(2))]),
                    update_mask: None,
                },
                precondition: None,
                transforms: vec![],
            }],
            None,
            t(0),
        )
        .expect("a later write commits");
    assert!(
        commit.commit_time.as_nanos() > import.commit_time.as_nanos(),
        "the commit after an import takes a strictly later commit time"
    );
    assert_eq!(state.documents().len(), 2);
}

#[test]
fn documents_lists_the_live_state_in_path_order() {
    let mut state = FirestoreState::new();
    state
        .import_documents(
            vec![
                imported("cities/SF", &[("a", Value::Integer(1))]),
                imported("bulk/doc-001", &[("a", Value::Integer(2))]),
                imported("bulk/doc-000", &[("a", Value::Integer(3))]),
            ],
            t(0),
        )
        .expect("the import succeeds");
    let paths: Vec<String> = state
        .documents()
        .iter()
        .map(|d| d.path.relative())
        .collect();
    assert_eq!(paths, vec!["bulk/doc-000", "bulk/doc-001", "cities/SF"]);
}
