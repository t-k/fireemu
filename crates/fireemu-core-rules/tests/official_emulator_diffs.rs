//! Claimed differences from the official Firestore emulator (firebase-tools 15.28.2).
//!
//! Every `#[ignore]`d test states the official emulator's answer as reported by a user; each
//! is a claim to check, not recorded production behaviour. Unignore a test when its fix lands.

use std::collections::BTreeMap;

use fireemu_core_rules::eval::{evaluate_request, Decision, Method, RequestContext, RulesService};
use fireemu_core_rules::parse::parse_ruleset;
use fireemu_core_rules::value::{AuthContext, RulesValue};

fn context(
    method: Method,
    path: &str,
    resource: Option<RulesValue>,
    abstract_path: bool,
) -> RequestContext {
    RequestContext {
        service: RulesService::Firestore,
        method,
        path: path.to_owned(),
        auth: Some(AuthContext {
            uid: "alice".to_owned(),
            token: BTreeMap::new(),
        }),
        resource,
        request_resource: None,
        time_unix_nanos: 1_788_004_860_i128 * 1_000_000_000,
        abstract_path,
        request_query: None,
    }
}

/// The `resource` a list query proof builds: `data` holds the constrained fields, `id` is
/// unknown.
fn query_resource(data: Vec<(&str, RulesValue)>) -> RulesValue {
    let mut resource = BTreeMap::new();
    resource.insert(
        "data".to_owned(),
        RulesValue::PartialMap(data.into_iter().map(|(k, v)| (k.to_owned(), v)).collect()),
    );
    resource.insert("id".to_owned(), RulesValue::Unknown);
    RulesValue::Map(resource)
}

fn notes_rules(method: &str, condition: &str) -> String {
    format!(
        "rules_version = '2';\nservice cloud.firestore {{ match /databases/{{d}}/documents {{ match /notes/{{id}} {{ allow {method}: if {condition}; }} }} }}"
    )
}

fn list_allowed(condition: &str, data: Vec<(&str, RulesValue)>) -> bool {
    let ruleset = parse_ruleset(&notes_rules("list", condition)).unwrap();
    let ctx = context(
        Method::List,
        "/databases/(default)/documents/notes/fireemu-placeholder",
        Some(query_resource(data)),
        true,
    );
    matches!(evaluate_request(&ruleset, &ctx).decision, Decision::Allow)
}

fn string_index_allowed(condition: &str) -> bool {
    let ruleset = parse_ruleset(&notes_rules("get", condition)).unwrap();
    let ctx = context(
        Method::Get,
        "/databases/(default)/documents/notes/n1",
        None,
        false,
    );
    matches!(evaluate_request(&ruleset, &ctx).decision, Decision::Allow)
}

// ----------------------------------------------------------------------------------------
// Item 2: `resource != null &&` guard over a query resource that holds unknown values
// ----------------------------------------------------------------------------------------

fn member_role_query_data() -> Vec<(&'static str, RulesValue)> {
    // where("members.alice.role", "in", ["ADMIN", "MEMBER"])
    let role = RulesValue::OneOf(vec![
        RulesValue::String("ADMIN".to_owned()),
        RulesValue::String("MEMBER".to_owned()),
    ]);
    let alice = RulesValue::PartialMap(BTreeMap::from([("role".to_owned(), role)]));
    let members = RulesValue::PartialMap(BTreeMap::from([("alice".to_owned(), alice)]));
    vec![("members", members)]
}

/// Control: without the guard both emulators allow (the claim says so; fireemu does).
#[test]
fn members_role_in_query_without_the_resource_guard_is_allowed() {
    assert!(list_allowed(
        r#"resource.data.members[request.auth.uid].role in ["ADMIN", "MEMBER"]"#,
        member_role_query_data()
    ));
}

/// Production allows it (FS-RULES-DIFFS 2026-11-08, `fs-rules-v1/diffs/queries#members-guarded-in`):
/// the query resource is a map, never null, whatever its fields hold.
#[test]
fn members_role_in_query_with_the_resource_not_null_guard_is_allowed() {
    assert!(list_allowed(
        r#"resource != null && resource.data.members[request.auth.uid].role in ["ADMIN", "MEMBER"]"#,
        member_role_query_data()
    ));
}

// ----------------------------------------------------------------------------------------
// Item 3: string indexing is by UTF-16 code unit ("é🔥x" is the units é, D83D, DD25, x)
// ----------------------------------------------------------------------------------------

#[test]
#[ignore = "official indexes strings by UTF-16 code unit; fireemu by Unicode scalar, so index 3 is out of range: rules-string-index-by-utf16-unit.md"]
fn string_index_counts_utf16_units_the_last_unit_is_index_three() {
    assert!(string_index_allowed(r#""é🔥x"[3] == "x""#));
}

/// Index 1 is a lone high surrogate in the official runtime, which never equals the emoji.
#[test]
#[ignore = "official indexes strings by UTF-16 code unit; fireemu returns the whole emoji at index 1: rules-string-index-by-utf16-unit.md"]
fn string_index_one_is_half_an_emoji_and_not_equal_to_it() {
    assert!(!string_index_allowed(r#""é🔥x"[1] == "🔥""#));
}

#[test]
#[ignore = "official indexes strings by UTF-16 code unit; fireemu returns x at index 2: rules-string-index-by-utf16-unit.md"]
fn string_index_two_is_a_low_surrogate_and_not_x() {
    assert!(!string_index_allowed(r#""é🔥x"[2] == "x""#));
}

// ----------------------------------------------------------------------------------------
// Item 4: a function declared at top level, outside `service`
// ----------------------------------------------------------------------------------------

#[test]
#[ignore = "official accepts and evaluates a top-level function after rules_version; fireemu fails to parse with `expected service`: rules-top-level-function-declaration.md"]
fn top_level_function_outside_the_service_is_accepted_and_evaluated() {
    let source = "rules_version = '2';\nfunction isAlice() { return request.auth.uid == 'alice'; }\nservice cloud.firestore { match /databases/{d}/documents { match /notes/{id} { allow get: if isAlice(); } } }";
    let ruleset = parse_ruleset(source).expect("a top-level function must parse");
    let ctx = context(
        Method::Get,
        "/databases/(default)/documents/notes/n1",
        None,
        false,
    );
    assert!(matches!(
        evaluate_request(&ruleset, &ctx).decision,
        Decision::Allow
    ));
}

// ----------------------------------------------------------------------------------------
// Item 5: `!("blocked" in resource.data)` with no filter
// ----------------------------------------------------------------------------------------

/// Production allows it and refuses the plain `"owner" in resource.data` without a filter
/// (FS-RULES-DIFFS 2026-11-08, `fs-rules-v1/diffs/queries#blocked-nofilter` and
/// `#has-owner-nofilter`): a key the query does not constrain is not in `resource.data`.
#[test]
fn not_in_resource_data_is_allowed_for_an_unfiltered_list() {
    assert!(list_allowed(r#"!("blocked" in resource.data)"#, vec![]));
    assert!(!list_allowed(r#""owner" in resource.data"#, vec![]));
    assert!(list_allowed(
        r#""owner" in resource.data"#,
        vec![("owner", RulesValue::String("o1".to_owned()))]
    ));
}
