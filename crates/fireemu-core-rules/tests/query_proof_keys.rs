//! Query proofs over the keys of `resource.data` and the nullness of `resource`, as the
//! FS-RULES-DIFFS production recording of 2026-11-08 decided them
//! (`conformance/fs-rules-v1-observation.json`, `fs-rules-v1/diffs/queries`):
//!
//! - `resource != null` holds for a query: its `resource` is a map, never null
//!   (`#members-bare-nofilter`, `#members-guarded-in`).
//! - A key the query does not constrain is not in the top-level `resource.data`
//!   (`#blocked-nofilter` allowed `!("blocked" in resource.data)`, `#has-owner-nofilter`
//!   refused `"owner" in resource.data`, `#has-owner-filtered` allowed it).
//!
//! Everything else about the map's shape stays undetermined, so these properties also check
//! that no other shape condition becomes provable.

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
    ]
}

fn constrained_data() -> impl Strategy<Value = BTreeMap<String, RulesValue>> {
    prop::collection::btree_map(prop::sample::select(KEYS.to_vec()), constraint(), 0..=4)
        .prop_map(|m| m.into_iter().map(|(k, v)| (k.to_owned(), v)).collect())
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
        prop_assert!(allows("{'r': resource.id} != null", &query), "a map literal is not null");
        prop_assert!(allows("[resource.id] != null", &query));
    }

    /// No other shape of the query data becomes provable: its key set, size, equality to a
    /// concrete map, a nested map's other keys, and an unconstrained field's value.
    #[test]
    fn nothing_else_about_the_query_data_is_provable(
        data in constrained_data(),
        key in prop::sample::select(KEYS.to_vec()),
    ) {
        let constrained = data.contains_key(key);
        let keys: Vec<String> = data.keys().map(|k| format!("'{k}'")).collect();
        let size = data.len();
        let query = ctx(data, true);
        for condition in [
            format!("resource.data.keys().hasOnly([{}])", keys.join(", ")),
            format!("resource.data.keys().size() == {size}"),
            format!("resource.data.size() == {size}"),
            "resource.data == {}".to_owned(),
            "resource.data.keys().hasAny(['zz'])".to_owned(),
            "!resource.data.keys().hasAny(['zz'])".to_owned(),
            "resource.data.get('zz', 0) == 0".to_owned(),
            "!('zz' in resource.data.diff({}).affectedKeys())".to_owned(),
        ] {
            prop_assert!(!allows(&condition, &query), "{} must not be provable", condition);
        }
        if !constrained {
            for condition in [
                format!("resource.data.{key} == null"),
                format!("resource.data.{key} != null"),
                format!("resource.data.{key} is string"),
            ] {
                prop_assert!(!allows(&condition, &query), "{} must not be provable", condition);
            }
        }
    }

    /// A nested map the query constrains in part: its constrained keys are in it, the others
    /// stay undetermined (the recording decided only the top-level `resource.data`).
    #[test]
    fn a_nested_partial_map_keeps_its_other_keys_undetermined(
        inner in constrained_data(),
        key in prop::sample::select(KEYS.to_vec()),
    ) {
        let constrained = inner.contains_key(key);
        let query = ctx(
            BTreeMap::from([("meta".to_owned(), RulesValue::PartialMap(inner))]),
            true,
        );
        prop_assert_eq!(allows(&format!("'{key}' in resource.data.meta"), &query), constrained);
        let negated = format!("!('{key}' in resource.data.meta)");
        prop_assert!(!allows(&negated, &query), "{} must not be provable", negated);
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
