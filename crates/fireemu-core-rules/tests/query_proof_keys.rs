//! Query proofs over the keys of `resource.data` and the nullness of `resource`, as the
//! FS-RULES-DIFFS production recording of 2026-11-08 decided them
//! (`conformance/fs-rules-v1-observation.json`, `fs-rules-v1/diffs/queries`):
//!
//! - `resource != null` holds for a query: its `resource` is a map, never null
//!   (`#members-bare-nofilter`, `#members-guarded-in`).
//! - A key the query does not constrain is not in `resource.data`
//!   (`#blocked-nofilter` allowed `!("blocked" in resource.data)`, `#has-owner-nofilter`
//!   refused `"owner" in resource.data`, `#has-owner-filtered` allowed it).
//!
//! FS-RULES-SHAPES (2026-11-08) extended this to the recorded key-set reads of
//! `resource.data` (a negated `keys().hasAny`, `keys().hasAll`, `size()` from below, `get()`
//! with a default), `in` also on a map the query constrains in part, and a list or map built
//! from an unconstrained field is not provably non-null. An exact key set or size, equality
//! of the map and its values stay undetermined.

use std::collections::BTreeMap;

use fireemu_core_rules::eval::{evaluate_request, Decision, Method, RequestContext, RulesService};
use fireemu_core_rules::parse::parse_ruleset;
use fireemu_core_rules::value::{AuthContext, RulesValue};
use proptest::prelude::*;

const KEYS: [&str; 4] = ["a", "b", "owner", "blocked"];

fn ctx(data: BTreeMap<String, RulesValue>, abstract_path: bool) -> RequestContext {
    let mut resource = BTreeMap::new();
    let data = if abstract_path {
        RulesValue::PartialMap(data)
    } else {
        RulesValue::Map(data)
    };
    resource.insert("data".to_owned(), data);
    resource.insert(
        "id".to_owned(),
        if abstract_path {
            RulesValue::Unknown
        } else {
            RulesValue::String("n1".to_owned())
        },
    );
    RequestContext {
        service: RulesService::Firestore,
        method: Method::List,
        path: "/databases/(default)/documents/notes/fireemu-placeholder".to_owned(),
        auth: Some(AuthContext {
            uid: "alice".to_owned(),
            token: BTreeMap::new(),
        }),
        resource: Some(RulesValue::Map(resource)),
        request_resource: None,
        time_unix_nanos: 1_788_004_860_i128 * 1_000_000_000,
        abstract_path,
        request_query: None,
    }
}

fn allows(condition: &str, ctx: &RequestContext) -> bool {
    let source = format!(
        "rules_version = '2';\nservice cloud.firestore {{ match /databases/{{d}}/documents {{ match /notes/{{id}} {{ allow list: if {condition}; }} }} }}"
    );
    let ruleset = parse_ruleset(&source).unwrap();
    matches!(evaluate_request(&ruleset, ctx).decision, Decision::Allow)
}

/// A constraint a query can put on a field.
fn constraint() -> impl Strategy<Value = RulesValue> {
    prop_oneof![
        Just(RulesValue::Null),
        any::<i64>().prop_map(RulesValue::Int),
        "[a-z]{0,3}".prop_map(RulesValue::String),
        Just(RulesValue::Unknown),
        Just(RulesValue::OneOf(vec![
            RulesValue::String("x".to_owned()),
            RulesValue::Int(1)
        ])),
        Just(RulesValue::NotOneOf(vec![RulesValue::Int(1)])),
        Just(RulesValue::PartialList(vec![RulesValue::Int(1)])),
        Just(RulesValue::PartialMap(BTreeMap::from([(
            "role".to_owned(),
            RulesValue::String("ADMIN".to_owned()),
        )]))),
        Just(RulesValue::PartialMapExcluding {
            fields: BTreeMap::from([("role".to_owned(), RulesValue::Unknown)]),
            excluded: vec![RulesValue::Map(BTreeMap::new())],
        }),
    ]
}

fn constrained_data() -> impl Strategy<Value = BTreeMap<String, RulesValue>> {
    prop::collection::btree_map(prop::sample::select(KEYS.to_vec()), constraint(), 0..=4)
        .prop_map(|m| m.into_iter().map(|(k, v)| (k.to_owned(), v)).collect())
}

/// The test's own reading of "holds a value the query does not determine anywhere".
fn holds_unknown(value: &RulesValue) -> bool {
    match value {
        RulesValue::Unknown => true,
        RulesValue::List(items)
        | RulesValue::Set(items)
        | RulesValue::PartialList(items)
        | RulesValue::PartialListAny(items)
        | RulesValue::OneOf(items)
        | RulesValue::NotOneOf(items) => items.iter().any(holds_unknown),
        RulesValue::Map(fields) | RulesValue::PartialMap(fields) => {
            fields.values().any(holds_unknown)
        }
        RulesValue::PartialMapExcluding { fields, .. } => fields.values().any(holds_unknown),
        _ => false,
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, ..ProptestConfig::default() })]

    /// `k in resource.data` is decided by whether the query constrains `k`, both ways.
    #[test]
    fn membership_in_the_query_data_is_whether_the_query_constrains_the_key(
        data in constrained_data(),
        key in prop::sample::select(KEYS.to_vec()),
    ) {
        let constrained = data.contains_key(key);
        let query = ctx(data, true);
        prop_assert_eq!(allows(&format!("'{key}' in resource.data"), &query), constrained);
        prop_assert_eq!(allows(&format!("!('{key}' in resource.data)"), &query), !constrained);
        prop_assert_eq!(allows(&format!("('{key}' in resource.data) == false"), &query), !constrained);
    }

    /// The query resource is never null, whatever the query constrains, and the reverse
    /// comparisons are never provable.
    #[test]
    fn the_query_resource_is_never_null(data in constrained_data()) {
        let query = ctx(data, true);
        prop_assert!(allows("resource != null", &query));
        prop_assert!(allows("null != resource", &query));
        prop_assert!(!allows("resource == null", &query));
        prop_assert!(!allows("null == resource", &query));
    }

    /// A container built from a value the query does not determine is not provably non-null:
    /// building it from the stored document may fail on a missing field (review 2026-11-08:
    /// `[resource.data.secret] != null`). Built from constrained values it cannot fail.
    #[test]
    fn a_container_of_an_undetermined_read_is_not_provably_non_null(
        data in constrained_data(),
        key in prop::sample::select(KEYS.to_vec()),
    ) {
        let constrained = data.contains_key(key);
        let unknown_value = data.get(key).is_some_and(holds_unknown);
        let query = ctx(data, true);
        for condition in [
            format!("[resource.data.{key}] != null"),
            format!("{{'k': resource.data.{key}}} != null"),
            format!("[[resource.data.{key}]] != null"),
            format!("null != [1, resource.data.{key}]"),
        ] {
            let expected = constrained && !unknown_value;
            prop_assert_eq!(allows(&condition, &query), expected, "{}", condition);
        }
        for condition in ["[resource.id] != null", "{'r': resource.id} != null", "{'r': resource} != null"] {
            prop_assert!(!allows(condition, &query), "{} must not be provable", condition);
        }
    }

    /// The key-set reads production answered (FS-RULES-SHAPES 2026-11-08): a negated
    /// `keys().hasAny`, `keys().hasAll` of constrained keys, `size()` bounded below by the
    /// constrained keys and `get()` with a default. An exact key set or size, the map's
    /// equality and `diff()` stay undetermined (review 2026-11-08 r2).
    #[test]
    fn the_query_data_key_set_is_the_constrained_keys(data in constrained_data()) {
        let keys: Vec<String> = data.keys().map(|k| format!("'{k}'")).collect();
        let size = data.len();
        let query = ctx(data, true);
        for condition in [
            format!("resource.data.keys().hasAll([{}])", keys.join(", ")),
            format!("resource.data.size() >= {size}"),
            "!resource.data.keys().hasAny(['zz'])".to_owned(),
            "resource.data.get('zz', 7) == 7".to_owned(),
        ] {
            prop_assert!(allows(&condition, &query), "{} must hold", condition);
        }
        for condition in [
            format!("resource.data.keys().hasOnly([{}])", keys.join(", ")),
            format!("resource.data.keys().size() == {size}"),
            format!("resource.data.size() == {size}"),
            format!("resource.data.size() <= {size}"),
            format!("resource.data.size() == {}", size + 1),
            "resource.data.keys().hasAny(['zz'])".to_owned(),
            "resource.data == {}".to_owned(),
            "!('zz' in resource.data.diff({}).affectedKeys())".to_owned(),
        ] {
            prop_assert!(!allows(&condition, &query), "{} must not be provable", condition);
        }
    }

    /// A key's value is what the query determines: `get()` of an unconstrained key answers
    /// the default, of a key held as `Unknown` stays undetermined.
    #[test]
    fn get_answers_the_default_only_for_an_unconstrained_key(
        data in constrained_data(),
        key in prop::sample::select(KEYS.to_vec()),
    ) {
        let unconstrained = !data.contains_key(key);
        let unknown = matches!(data.get(key), Some(RulesValue::Unknown));
        let query = ctx(data, true);
        let condition = format!("resource.data.get('{key}', 'zz-default') == 'zz-default'");
        prop_assert_eq!(allows(&condition, &query), unconstrained);
        if unknown {
            let either = format!("resource.data.get('{key}', 0) != 0");
            prop_assert!(!allows(&either, &query), "{} must not be provable", either);
        }
    }

    /// A nested map the query constrains in part holds its constrained keys for `in` (the
    /// recorded `nested-neg-filtered`); its other key-set reads stay undetermined.
    #[test]
    fn a_nested_partial_map_answers_membership_from_its_constrained_keys(
        inner in constrained_data(),
        key in prop::sample::select(KEYS.to_vec()),
    ) {
        let constrained = inner.contains_key(key);
        let size = inner.len();
        let query = ctx(
            BTreeMap::from([("meta".to_owned(), RulesValue::PartialMap(inner))]),
            true,
        );
        prop_assert_eq!(allows(&format!("'{key}' in resource.data.meta"), &query), constrained);
        prop_assert_eq!(allows(&format!("!('{key}' in resource.data.meta)"), &query), !constrained);
        let sized = format!("resource.data.meta.size() == {size}");
        prop_assert!(!allows(&sized, &query), "{} must not be provable", sized);
    }

    /// A single-document request evaluates the stored map as it is.
    #[test]
    fn a_stored_document_answers_from_its_own_keys(
        stored in prop::collection::btree_set(prop::sample::select(KEYS.to_vec()), 0..=4),
        key in prop::sample::select(KEYS.to_vec()),
    ) {
        let present = stored.contains(key);
        let data: BTreeMap<String, RulesValue> = stored
            .iter()
            .map(|k| ((*k).to_owned(), RulesValue::Int(1)))
            .collect::<BTreeMap<_, _>>();
        let document = ctx(data, false);
        prop_assert_eq!(allows(&format!("'{key}' in resource.data"), &document), present);
        prop_assert_eq!(allows(&format!("!('{key}' in resource.data)"), &document), !present);
        prop_assert!(allows("resource != null", &document));
    }
}
