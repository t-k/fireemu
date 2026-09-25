//! The write-path byte limits production enforces on a stored document
//! (`FS-LIMIT-FIELD-PATH-BYTES`, `FS-LIMIT-FIELD-VALUE-BYTES`,
//! `FS-LIMIT-INDEXED-FIELD-VALUE-BYTES`).
//!
//! `FS-LIMIT-FIELD-NAME` already bounds one segment and the single string or bytes payload
//! of `FS-LIMIT-FIELD-VALUE-BYTES` is production-observed, so both are refused under either
//! scope. `FS-LIMIT-FIELD-PATH-BYTES` likewise already refused a nested path over 1,500
//! bytes under either scope, as a side effect of automatic index accounting; the checks
//! here pin that boundary so it cannot be lost.
//!
//! The aggregate-map recording fixes map accounting but does not bracket the aggregate size
//! limit for a map or array value. It is therefore refused only under [`LimitScope::Production`] (the
//! `strict` profile), because the compatibility contract forbids adding a refusal to the
//! `emulator` profile.
//!
//! `FS-LIMIT-INDEXED-FIELD-VALUE-BYTES` is a truncating maximum: production truncates the
//! indexed representation and refuses nothing, so it is identical under both scopes.

use std::collections::BTreeMap;

use fireemu_core_firestore::path::DocumentPath;
use fireemu_core_firestore::size::{indexed_value_size, INDEXED_VALUE_TRUNCATION_BYTES};
use fireemu_core_firestore::store::{
    FirestoreError, FirestoreState, ImportedDocument, LimitScope, Write, WriteOp,
};
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

fn t(n: i64) -> LogicalInstant {
    LogicalInstant::from_unix_seconds(1_788_000_000 + n)
}

fn set(p: &str, name: &str, value: Value) -> Write {
    Write {
        op: WriteOp::Set {
            path: path(p),
            fields: BTreeMap::from([(name.to_owned(), value)]),
            update_mask: None,
        },
        precondition: None,
        transforms: vec![],
    }
}

fn state(scope: LimitScope) -> FirestoreState {
    FirestoreState::with_limit_scope(scope)
}

#[test]
fn an_index_entry_count_refusal_preserves_the_whole_commit_state() {
    let mut store = state(LimitScope::Production);
    store
        .commit(&[set("ie2/control", "v", Value::Integer(1))], None, t(0))
        .expect("control");
    let before = store.get(&path("ie2/control")).cloned();
    let refused = store.commit(
        &[
            set(
                "ie2/arr20000",
                "a",
                Value::Array((0..20_000).map(Value::Integer).collect()),
            ),
            set("ie2/control", "v", Value::Integer(2)),
        ],
        None,
        t(1),
    );
    assert!(
        matches!(refused, Err(FirestoreError::InvalidArgument(ref message))
            if message == "too many index entries for entity /ie2/arr20000"),
        "{}",
        outcome(&refused)
    );
    assert!(store.get(&path("ie2/arr20000")).is_none());
    assert_eq!(store.get(&path("ie2/control")).cloned(), before);
}

/// A one-line rendering of a commit outcome. The values under test are megabytes wide, so a
/// failure must never print the request back.
fn outcome<T>(result: &Result<T, FirestoreError>) -> String {
    match result {
        Ok(_) => "accepted".to_owned(),
        Err(error) => format!("refused: {error}"),
    }
}

/// A map value whose aggregate `field_value_size` is exactly `total`, built from one string
/// payload that stays below the production-observed single-payload boundary.
///
/// `map_size = string_size("s") + string_size(payload) = 2 + len + 1`.
fn aggregate_map(total: usize) -> Value {
    let payload = total
        .checked_sub(3)
        .expect("an aggregate map is at least 3 bytes");
    Value::Map(BTreeMap::from([(
        "s".to_owned(),
        Value::String("x".repeat(payload)),
    )]))
}

/// A field whose canonical path is exactly `total` bytes: `segments` names joined by `.`.
fn nested_path_field(segments: &[usize]) -> (String, Value) {
    let names: Vec<String> = segments
        .iter()
        .enumerate()
        .map(|(index, len)| {
            let mut name = String::from(char::from(b'a' + u8::try_from(index % 26).unwrap()));
            name.push_str(&"z".repeat(len - 1));
            name
        })
        .collect();
    let mut value = Value::Integer(1);
    for name in names.iter().skip(1).rev() {
        value = Value::Map(BTreeMap::from([(name.clone(), value)]));
    }
    (names[0].clone(), value)
}

fn canonical_len(segments: &[usize]) -> usize {
    segments.iter().sum::<usize>() + segments.len() - 1
}

// ---------------------------------------------------------------------------
// FS-LIMIT-FIELD-VALUE-BYTES: aggregate accounting
// ---------------------------------------------------------------------------

#[test]
fn an_aggregate_field_value_at_the_production_boundary_is_accepted_and_one_more_byte_is_refused() {
    // `document_size` for `a/b` with one field `v` is 20 (name) + 32 + 2 (field name) + value,
    // so the accepted case is still inside FS-LIMIT-DOCUMENT-BYTES.
    let mut store = state(LimitScope::Production);
    store
        .commit(&[set("a/b", "v", aggregate_map(1_048_487))], None, t(0))
        .expect("the inclusive maximum is accepted");

    let mut store = state(LimitScope::Production);
    store
        .commit(&[set("a/control", "v", Value::Integer(1))], None, t(0))
        .expect("control");
    let before = store.get(&path("a/control")).cloned();
    let refused = store.commit(
        &[
            set("a/b", "v", aggregate_map(1_048_488)),
            set("a/control", "v", Value::Integer(2)),
        ],
        None,
        t(1),
    );
    assert!(
        matches!(refused, Err(FirestoreError::InvalidArgument(ref m))
            if m == "The value of property \"v\" is longer than 1048487 bytes."),
        "{}",
        outcome(&refused)
    );
    assert!(
        store.get(&path("a/b")).is_none(),
        "the refused write must publish nothing"
    );
    assert_eq!(
        store.get(&path("a/control")).cloned(),
        before,
        "the sibling write in the same commit must not publish"
    );
}

#[test]
fn a_map_accepted_by_the_saved_production_recording_has_no_extra_map_overhead() {
    let value = Value::Map(BTreeMap::from([(
        "s".to_owned(),
        Value::String("x".repeat(1_048_460)),
    )]));
    let mut store = state(LimitScope::Production);
    let result = store.commit(&[set("a/b", "v", value)], None, t(0));
    assert!(result.is_ok(), "{}", outcome(&result));
    assert!(store.get(&path("a/b")).is_some());
}

#[test]
fn an_aggregate_array_value_over_the_boundary_is_refused_under_production() {
    let mut store = state(LimitScope::Production);
    // 1,048,488 bytes across two payloads, neither of which trips the single-payload rule.
    let refused = store.commit(
        &[set(
            "a/b",
            "v",
            Value::Array(vec![
                Value::String("x".repeat(524_243)),
                Value::String("x".repeat(524_243)),
            ]),
        )],
        None,
        t(0),
    );
    assert!(
        matches!(refused, Err(FirestoreError::InvalidArgument(_))),
        "{}",
        outcome(&refused)
    );
    assert!(store.get(&path("a/b")).is_none());
}

#[test]
fn the_emulator_scope_admits_an_aggregate_field_value_over_the_boundary() {
    let mut store = state(LimitScope::OfficialEmulator);
    store
        .commit(&[set("a/b", "v", aggregate_map(1_048_488))], None, t(0))
        .expect("the emulator profile may not gain a refusal");
    assert!(store.get(&path("a/b")).is_some());
}

#[test]
fn a_single_payload_over_the_boundary_is_refused_under_both_scopes() {
    for scope in [LimitScope::Production, LimitScope::OfficialEmulator] {
        let mut store = state(scope);
        let refused = store.commit(
            &[set("a/b", "v", Value::String("x".repeat(1_048_488)))],
            None,
            t(0),
        );
        assert!(
            matches!(refused, Err(FirestoreError::InvalidArgument(ref m))
                if m == "The value of property \"v\" is longer than 1048487 bytes."),
            "{scope:?}: {}",
            outcome(&refused)
        );
    }
}

// ---------------------------------------------------------------------------
// FS-LIMIT-FIELD-PATH-BYTES: the canonical path of a nested field
// ---------------------------------------------------------------------------

/// Fourteen 100-byte segments plus one 86-byte segment: 1,500 canonical bytes.
const PATH_AT_MAXIMUM: [usize; 15] = [
    100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 86,
];
/// The same shape one byte longer.
const PATH_OVER_MAXIMUM: [usize; 15] = [
    100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 87,
];

#[test]
fn the_nested_path_fixtures_are_the_exact_boundary_pair() {
    assert_eq!(canonical_len(&PATH_AT_MAXIMUM), 1_500);
    assert_eq!(canonical_len(&PATH_OVER_MAXIMUM), 1_501);
}

#[test]
fn a_nested_field_path_at_the_boundary_is_accepted_and_one_more_byte_is_refused() {
    for scope in [LimitScope::Production, LimitScope::OfficialEmulator] {
        let mut store = state(scope);
        let (name, value) = nested_path_field(&PATH_AT_MAXIMUM);
        store
            .commit(&[set("a/b", &name, value)], None, t(0))
            .unwrap_or_else(|e| panic!("{scope:?}: the inclusive maximum is accepted: {e}"));

        let mut store = state(scope);
        store
            .commit(&[set("a/control", "v", Value::Integer(1))], None, t(0))
            .expect("control");
        let before = store.get(&path("a/control")).cloned();
        let (name, value) = nested_path_field(&PATH_OVER_MAXIMUM);
        let refused = store.commit(
            &[
                set("a/b", &name, value),
                set("a/control", "v", Value::Integer(2)),
            ],
            None,
            t(1),
        );
        assert!(
            matches!(refused, Err(FirestoreError::InvalidArgument(ref m))
                if m.starts_with("Property ") && m.len() == 400),
            "{scope:?}: {}",
            outcome(&refused)
        );
        assert!(
            store.get(&path("a/b")).is_none(),
            "{scope:?}: the refused write must publish nothing"
        );
        assert_eq!(store.get(&path("a/control")).cloned(), before, "{scope:?}");
    }
}

#[test]
fn an_implied_map_path_uses_the_saved_production_error_prefix() {
    let mut store = state(LimitScope::Production);
    let value = Value::Map(BTreeMap::from([("i".repeat(750), Value::Integer(1))]));
    let refused = store.commit(&[set("a/b", &"o".repeat(750), value)], None, t(0));
    let expected = format!("Property {}", "o".repeat(391));
    assert!(
        matches!(refused, Err(FirestoreError::InvalidArgument(ref message)) if message == &expected),
        "{}",
        outcome(&refused)
    );
}

/// The refusal must come from the document's shape, not from the indexes the field happens
/// to attract: a single-field exemption removes every automatic index entry for a field, and
/// the path limit still applies.
#[test]
fn an_index_exempt_nested_field_path_over_the_boundary_is_still_refused() {
    let mut indexes = fireemu_core_firestore::index::IndexSet::default();
    indexes.set_default_single_field_indexes(
        &fireemu_core_types::ids::CollectionId::try_new("a").unwrap(),
        vec![],
    );
    for scope in [LimitScope::Production, LimitScope::OfficialEmulator] {
        let mut store = state(scope);
        store.set_index_catalog(indexes.clone());
        let (name, value) = nested_path_field(&PATH_OVER_MAXIMUM);
        let refused = store.commit(&[set("a/b", &name, value)], None, t(0));
        assert!(
            matches!(refused, Err(FirestoreError::InvalidArgument(ref m))
                if m.starts_with("Property ") && m.len() == 400),
            "{scope:?}: {}",
            outcome(&refused)
        );
        assert!(store.get(&path("a/b")).is_none(), "{scope:?}");

        // The boundary itself is still accepted with the exemption in force.
        let mut store = state(scope);
        store.set_index_catalog(indexes.clone());
        let (name, value) = nested_path_field(&PATH_AT_MAXIMUM);
        store
            .commit(&[set("a/b", &name, value)], None, t(0))
            .unwrap_or_else(|e| panic!("{scope:?}: {e}"));
    }
}

#[test]
fn a_single_field_name_over_the_name_limit_is_refused_under_both_scopes() {
    for scope in [LimitScope::Production, LimitScope::OfficialEmulator] {
        let mut store = state(scope);
        let refused = store.commit(
            &[set("a/b", &"n".repeat(1_501), Value::Integer(1))],
            None,
            t(0),
        );
        assert!(
            matches!(refused, Err(FirestoreError::InvalidArgument(_))),
            "{scope:?}: {}",
            outcome(&refused)
        );
    }
}

/// A map inside an array has an implied path too, but automatic index accounting never
/// walks into array elements, so nothing bounded that path before. Bounding it is a new
/// refusal and belongs to the strict profile alone.
#[test]
fn a_field_path_implied_through_an_array_is_strict_only() {
    let deep = |len: usize| {
        Value::Array(vec![Value::Map(BTreeMap::from([(
            "z".repeat(len),
            Value::Integer(1),
        )]))])
    };
    // Production accepts a 1,494-byte direct key inside an array map and rejects 1,495,
    // independently of the ordinary 1,500-byte stored-field-name maximum.
    let over = deep(1_495);
    let at = deep(1_494);

    let mut store = state(LimitScope::OfficialEmulator);
    store
        .commit(&[set("a/b", "arr", over.clone())], None, t(0))
        .expect("the emulator profile may not gain a refusal");
    assert!(store.get(&path("a/b")).is_some());

    let mut store = state(LimitScope::Production);
    store
        .commit(&[set("a/at", "arr", at)], None, t(0))
        .expect("the production array-map key boundary is accepted");
    let refused = store.commit(&[set("a/over", "arr", over)], None, t(1));
    assert!(
        matches!(refused, Err(FirestoreError::InvalidArgument(ref m))
            if m == "Property array contains an invalid nested entity."),
        "{}",
        outcome(&refused)
    );
    assert!(store.get(&path("a/over")).is_none());
}

/// A path implied by nested maps was already refused by automatic index accounting, so it
/// stays refused under either scope. This pins the asymmetry with the array case above.
#[test]
fn a_field_path_implied_through_nested_maps_is_refused_under_both_scopes() {
    for scope in [LimitScope::Production, LimitScope::OfficialEmulator] {
        let mut store = state(scope);
        let (name, value) = nested_path_field(&PATH_OVER_MAXIMUM);
        let refused = store.commit(&[set("a/b", &name, value)], None, t(0));
        assert!(
            matches!(refused, Err(FirestoreError::InvalidArgument(ref m))
                if m.starts_with("Property ") && m.len() == 400),
            "{scope:?}: {}",
            outcome(&refused)
        );
    }
}

/// A document that breaks two limits at once must still report the one it reported before:
/// the document charge is production-observed wording, the path limit is not.
#[test]
fn an_oversized_document_with_an_over_long_path_still_reports_the_document_charge() {
    for scope in [LimitScope::Production, LimitScope::OfficialEmulator] {
        let mut store = state(scope);
        let (name, value) = nested_path_field(&PATH_OVER_MAXIMUM);
        let refused = store.commit(
            &[Write {
                op: WriteOp::Set {
                    path: path("a/b"),
                    fields: BTreeMap::from([
                        (name, value),
                        ("big".to_owned(), Value::String("x".repeat(1_048_400))),
                    ]),
                    update_mask: None,
                },
                precondition: None,
                transforms: vec![],
            }],
            None,
            t(0),
        );
        assert!(
            matches!(refused, Err(FirestoreError::ResourceExhausted(_))),
            "{scope:?}: {}",
            outcome(&refused)
        );
        assert!(store.get(&path("a/b")).is_none(), "{scope:?}");
    }
}

// ---------------------------------------------------------------------------
// Import applies the same rules
// ---------------------------------------------------------------------------

#[test]
fn an_import_applies_the_write_path_byte_limits_and_publishes_nothing_on_refusal() {
    for (label, value) in [
        ("aggregate value", aggregate_map(1_048_488)),
        ("nested path", nested_path_field(&PATH_OVER_MAXIMUM).1),
    ] {
        let name = if label == "nested path" {
            nested_path_field(&PATH_OVER_MAXIMUM).0
        } else {
            "v".to_owned()
        };
        let mut store = state(LimitScope::Production);
        let refused = store.import_documents(
            vec![
                ImportedDocument {
                    path: path("a/good"),
                    fields: BTreeMap::from([("v".to_owned(), Value::Integer(1))]),
                    create_time: None,
                    update_time: None,
                },
                ImportedDocument {
                    path: path("a/bad"),
                    fields: BTreeMap::from([(name, value)]),
                    create_time: None,
                    update_time: None,
                },
            ],
            t(0),
        );
        assert!(
            matches!(refused, Err(FirestoreError::InvalidArgument(_))),
            "{label}: {}",
            outcome(&refused)
        );
        assert!(store.get(&path("a/good")).is_none(), "{label}");
        assert!(store.get(&path("a/bad")).is_none(), "{label}");
    }

    // The emulator scope imports what the official emulator imports: only the aggregate
    // value rule is strict-only, the path rule applies under either scope.
    let mut store = state(LimitScope::OfficialEmulator);
    store
        .import_documents(
            vec![ImportedDocument {
                path: path("a/bad"),
                fields: BTreeMap::from([("v".to_owned(), aggregate_map(1_048_488))]),
                create_time: None,
                update_time: None,
            }],
            t(0),
        )
        .expect("the emulator profile may not gain a refusal");
}

// ---------------------------------------------------------------------------
// FS-LIMIT-INDEXED-FIELD-VALUE-BYTES: a truncating maximum, never a refusal
// ---------------------------------------------------------------------------

#[test]
fn an_indexed_value_is_truncated_at_the_boundary_and_never_refused() {
    assert_eq!(INDEXED_VALUE_TRUNCATION_BYTES, 1_500);
    // `string_size` is the payload plus one, so 1,499 payload bytes is the last value whose
    // indexed representation is its own size.
    assert_eq!(
        indexed_value_size(&Value::String("x".repeat(1_499))).unwrap(),
        1_500
    );
    assert_eq!(
        indexed_value_size(&Value::String("x".repeat(1_500))).unwrap(),
        1_500
    );
    assert_eq!(
        indexed_value_size(&Value::String("x".repeat(100_000))).unwrap(),
        1_500
    );
    // A value over the indexed maximum is stored, not refused, under either scope.
    for scope in [LimitScope::Production, LimitScope::OfficialEmulator] {
        let mut store = state(scope);
        store
            .commit(
                &[set("a/b", "v", Value::String("x".repeat(100_000)))],
                None,
                t(0),
            )
            .unwrap_or_else(|e| panic!("{scope:?}: {e}"));
        assert!(store.get(&path("a/b")).is_some());
    }
}

/// A field name at the ordinary `FS-LIMIT-FIELD-NAME` maximum inside an array is legal as a
/// name, but production's tighter direct array-map key boundary refuses the nested entity.
#[test]
fn the_reviewed_array_field_path_fixture_is_emulator_ok_and_strict_refused() {
    let document = || {
        Value::Array(vec![Value::Map(BTreeMap::from([(
            "z".repeat(1_500),
            Value::Integer(1),
        )]))])
    };

    let mut store = state(LimitScope::OfficialEmulator);
    store
        .commit(&[set("a/b", "arr", document())], None, t(0))
        .expect("the emulator profile may not gain a refusal");
    assert!(store.get(&path("a/b")).is_some());

    let mut store = state(LimitScope::Production);
    let refused = store.commit(&[set("a/b", "arr", document())], None, t(0));
    assert!(
        matches!(refused, Err(FirestoreError::InvalidArgument(ref m))
            if m == "Property array contains an invalid nested entity."),
        "{}",
        outcome(&refused)
    );
    assert!(store.get(&path("a/b")).is_none());
}
