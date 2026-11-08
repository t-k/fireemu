//! Functions declared at top level, between `rules_version` and `service`.
//!
//! Production rows (2026-11-08, `fs-rules-v1/diffs`, programs `fn-top` and `fn-inner`): a
//! ruleset with `topTrue()`/`topFalse()` declared before `service cloud.firestore` compiles,
//! `allow get: if topTrue()` answers 404 (allowed) and `topFalse()` 403 (denied); the same
//! functions inside the `match` behave alike. Nothing was recorded about shadowing, a call
//! between top-level functions, duplicates, or a declaration after a service.

use std::collections::BTreeMap;

use fireemu_core_rules::eval::{evaluate_request, Decision, Method, RequestContext, RulesService};
use fireemu_core_rules::parse::parse_ruleset;
use fireemu_core_rules::runtime::LoadedRules;
use fireemu_core_rules::value::AuthContext;

fn get_allowed(source: &str) -> bool {
    let ruleset = parse_ruleset(source).unwrap_or_else(|e| panic!("{e:?}"));
    let ctx = RequestContext {
        service: RulesService::Firestore,
        method: Method::Get,
        path: "/databases/(default)/documents/notes/n1".to_owned(),
        auth: Some(AuthContext {
            uid: "alice".to_owned(),
            token: BTreeMap::new(),
        }),
        resource: None,
        request_resource: None,
        time_unix_nanos: 1_788_004_860_i128 * 1_000_000_000,
        abstract_path: false,
        request_query: None,
    };
    matches!(evaluate_request(&ruleset, &ctx).decision, Decision::Allow)
}

fn rules(preamble: &str, inner: &str, condition: &str) -> String {
    format!(
        "rules_version = '2';\n{preamble}\nservice cloud.firestore {{ {inner} match /databases/{{d}}/documents {{ match /notes/{{id}} {{ allow get: if {condition}; }} }} }}"
    )
}

#[test]
fn a_true_top_level_function_allows_and_a_false_one_denies() {
    let preamble = "function topTrue() { return true; }\nfunction topFalse() { return false; }";
    assert!(get_allowed(&rules(preamble, "", "topTrue()")));
    assert!(!get_allowed(&rules(preamble, "", "topFalse()")));
}

#[test]
fn a_top_level_function_sees_the_request_and_takes_arguments() {
    let preamble =
        "function isUser(uid) { return request.auth != null && request.auth.uid == uid; }";
    assert!(get_allowed(&rules(preamble, "", "isUser('alice')")));
    assert!(!get_allowed(&rules(preamble, "", "isUser('bob')")));
}

#[test]
fn top_level_functions_call_each_other_in_either_order() {
    let preamble = "function a() { return b(); }\nfunction b() { return true; }";
    assert!(get_allowed(&rules(preamble, "", "a()")));
}

/// Unrecorded in production: an inner scope shadows an outer one in this evaluator for nested
/// matches (`check_duplicate_functions`), and the service is the scope inside the file.
#[test]
fn a_function_of_the_same_name_inside_the_service_shadows_the_top_level_one() {
    let preamble = "function f() { return false; }";
    assert!(get_allowed(&rules(
        preamble,
        "function f() { return true; }",
        "f()"
    )));
    let preamble = "function f() { return true; }";
    assert!(!get_allowed(&rules(
        preamble,
        "function f() { return false; }",
        "f()"
    )));
}

#[test]
fn a_top_level_function_is_not_visible_without_a_declaration() {
    assert!(parse_ruleset(&rules("", "", "missing()")).is_ok());
    assert!(!get_allowed(&rules("", "", "missing()")));
}

#[test]
fn two_top_level_functions_of_one_name_are_a_compile_error() {
    let preamble = "function f() { return true; }\nfunction f() { return false; }";
    let error = parse_ruleset(&rules(preamble, "", "f()")).unwrap_err();
    assert!(error.message.contains("already defined"), "{error:?}");
}

#[test]
fn a_top_level_function_is_not_a_duplicate_of_a_nested_one() {
    let preamble = "function f() { return true; }";
    let source = format!(
        "rules_version = '2';\n{preamble}\nservice cloud.firestore {{ match /databases/{{d}}/documents {{ match /notes/{{id}} {{ function f() {{ return false; }} allow get: if f(); }} }} }}"
    );
    assert!(!get_allowed(&source));
}

#[test]
fn a_ruleset_of_only_top_level_functions_still_needs_a_service() {
    assert!(parse_ruleset("rules_version = '2';\nfunction f() { return true; }").is_err());
}

#[test]
fn a_top_level_function_loads_as_a_runtime_ruleset() {
    let loaded = LoadedRules::from_source(&rules(
        "function topTrue() { return true; }",
        "",
        "topTrue()",
    ));
    assert!(loaded.is_ok(), "{:?}", loaded.err());
}

#[test]
fn a_top_level_recursion_is_still_refused() {
    let loaded = LoadedRules::from_source(&rules("function f() { return f(); }", "", "f()"));
    assert!(loaded.is_err());
}

#[test]
fn a_top_level_function_may_also_follow_the_service() {
    let source = "rules_version = '2';\nservice cloud.firestore { match /databases/{d}/documents { match /notes/{id} { allow get: if late(); } } }\nfunction late() { return true; }";
    assert!(get_allowed(source));
}
