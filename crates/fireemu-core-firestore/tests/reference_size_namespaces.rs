//! Reference storage charges must not depend on project/database identifiers.
//!
//! These are local regressions for the published storage-size formula, not
//! production-observation receipts. Reference values use document-name size:
//! only collection/document segments contribute UTF-8 bytes + 1, then 16 bytes.

use std::collections::BTreeMap;

use fireemu_core_firestore::path::DocumentPath;
use fireemu_core_firestore::size::{
    document_name_size, document_size, field_value_size, index_entry_size, indexed_value_size,
    IndexEntryScope,
};
use fireemu_core_firestore::store::{FirestoreState, LimitScope, Write, WriteOp};
use fireemu_core_firestore::value::Value;
use fireemu_core_types::ids::{DatabaseId, ProjectId};
use fireemu_core_types::time::LogicalInstant;

const NAMESPACES: &[(&str, &str)] = &[
    ("demo-app", "(default)"),
    ("documents", "(default)"),
    ("demo-app", "documents"),
    ("documents", "documents"),
    ("databases", "documents"),
    ("documents", "databases"),
];

fn path(project: &str, database: &str, relative: &str) -> DocumentPath {
    DocumentPath::parse(
        &ProjectId::try_new(project).unwrap(),
        &DatabaseId::try_new(database).unwrap(),
        relative,
    )
    .unwrap()
}

fn reference(project: &str, database: &str, relative: &str) -> Value {
    Value::Reference(path(project, database, relative).resource_name())
}

#[test]
fn references_charge_only_document_segments_for_every_namespace() {
    for &(project, database) in NAMESPACES {
        for (relative, expected) in [
            ("a/b", 20),
            ("items/doc", 26),
            ("資料/利用者", 33),
            ("a/b/documents/c", 32),
            ("documents/documents", 36),
        ] {
            let target = path(project, database, relative);
            assert_eq!(document_name_size(&target), Ok(expected));
            assert_eq!(
                field_value_size(&Value::Reference(target.resource_name())),
                Ok(expected),
                "project={project}, database={database}, path={relative}"
            );
        }
    }
}

#[test]
fn nested_reference_charges_are_namespace_independent() {
    for &(project, database) in NAMESPACES {
        let value = reference(project, database, "a/b");
        // Array sum: 20 + 20. Map: string_size("r") + array sum.
        let array = Value::Array(vec![value.clone(), value]);
        assert_eq!(field_value_size(&array), Ok(40));
        let map = Value::Map(BTreeMap::from([("r".to_owned(), array)]));
        assert_eq!(field_value_size(&map), Ok(42));
    }
}

#[test]
fn indexed_references_keep_the_full_relative_charge() {
    for &(project, database) in NAMESPACES {
        // 16 + (735 + 1) + (tail + 1) = 753 + tail.
        for (tail, full) in [(746, 1499), (747, 1500), (748, 1501)] {
            let relative = format!("{}/{}", "a".repeat(735), "b".repeat(tail));
            let value = reference(project, database, &relative);
            assert_eq!(field_value_size(&value), Ok(full));
            assert_eq!(indexed_value_size(&value), Ok(full));
        }
    }
}

#[test]
fn every_index_entry_scope_uses_the_correct_reference_charge() {
    let document = path("demo-app", "(default)", "a/b");
    for &(project, database) in NAMESPACES {
        let value = reference(project, database, "a/b");
        for (scope, expected) in [
            (IndexEntryScope::SingleFieldCollection, 74),
            (IndexEntryScope::SingleFieldCollectionGroup, 90),
            (IndexEntryScope::CompositeCollection, 72),
            (IndexEntryScope::CompositeCollectionGroup, 72),
        ] {
            assert_eq!(
                index_entry_size(scope, &document, None, &[("r", &value)]),
                Ok(expected),
                "{scope:?}, project={project}, database={database}"
            );
        }
    }
}

fn write(path: DocumentPath, fields: BTreeMap<String, Value>) -> Write {
    Write {
        op: WriteOp::Set {
            path,
            fields,
            update_mask: None,
        },
        precondition: None,
        transforms: vec![],
    }
}

#[test]
fn document_boundary_and_commit_atomicity_are_namespace_independent() {
    const MAX: u64 = 1_048_576;
    for scope in [LimitScope::Production, LimitScope::OfficialEmulator] {
        for &(project, database) in NAMESPACES {
            let document = path("demo-app", "(default)", "a/b");
            let control = path("demo-app", "(default)", "a/control");
            // 20 (document name) + 32 + (2 + 20) (r) + 5 (left) + 6 (right) = 85.
            // Two payloads keep each value below the independent field-value maximum.
            let fields = BTreeMap::from([
                ("r".to_owned(), reference(project, database, "a/b")),
                ("left".to_owned(), Value::Bytes(vec![0; 524_240])),
                ("right".to_owned(), Value::Bytes(vec![0; 524_251])),
            ]);
            assert_eq!(document_size(&document, &fields).unwrap().total, MAX);
            let mut store = FirestoreState::with_limit_scope(scope);
            let now = LogicalInstant::from_unix_seconds(1_788_000_000);
            store
                .commit(
                    &[
                        write(document.clone(), fields.clone()),
                        write(
                            control.clone(),
                            BTreeMap::from([("v".to_owned(), Value::Integer(1))]),
                        ),
                    ],
                    None,
                    now,
                )
                .expect("exact document limit must not overcharge reference namespaces");
            let before = store.get(&document).cloned();
            let control_before = store.get(&control).cloned();
            let mut oversized = fields;
            oversized.insert("left".to_owned(), Value::Bytes(vec![0; 524_241]));
            assert_eq!(document_size(&document, &oversized).unwrap().total, MAX + 1);
            let refused = store.commit(
                &[
                    write(document.clone(), oversized),
                    write(
                        control.clone(),
                        BTreeMap::from([("v".to_owned(), Value::Integer(2))]),
                    ),
                ],
                None,
                LogicalInstant::from_unix_seconds(1_788_000_001),
            );
            assert!(
                refused.is_err(),
                "one byte over the document limit must fail"
            );
            assert!(
                store.get(&document).cloned() == before,
                "an oversized replacement must leave the original document unchanged"
            );
            assert_eq!(store.get(&control).cloned(), control_before);
        }
    }
}
