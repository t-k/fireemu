//! Exercise the ASCII-class contract through the real Rules parser and evaluator.
//! These are local tests, not requests to a Firebase production project.
#![allow(clippy::unicode_not_nfc)]

use std::collections::BTreeMap;

use fireemu_core_rules::eval::{evaluate_request, Decision, Method, RequestContext, RulesService};
use fireemu_core_rules::runtime::LoadedRules;
use fireemu_core_rules::value::AuthContext;

fn quote_rule_string(text: &str) -> String {
    format!("'{}'", text.replace('\\', "\\\\").replace('\'', "\\'"))
}

fn allowed(expression: &str, uid: &str) -> bool {
    let source = format!(
        "rules_version = '2'; service cloud.firestore {{ \
         match /databases/{{database}}/documents {{ \
         match /protected/{{doc}} {{ allow get: if request.auth != null && ({expression}); }} \
         }} }}"
    );
    let loaded = LoadedRules::from_source(&source).expect("well-formed Rules program");
    let request = RequestContext {
        service: RulesService::Firestore,
        method: Method::Get,
        path: "/databases/(default)/documents/protected/doc".to_owned(),
        auth: Some(AuthContext {
            uid: uid.to_owned(),
            token: BTreeMap::new(),
        }),
        resource: None,
        request_resource: None,
        time_unix_nanos: 0,
        abstract_path: false,
        request_query: None,
    };
    let result = evaluate_request(loaded.ruleset.as_ref().unwrap(), &request);
    matches!(result.decision, Decision::Allow)
}

fn matches_uid(pattern: &str, uid: &str) -> bool {
    allowed(
        &format!("request.auth.uid.matches({})", quote_rule_string(pattern)),
        uid,
    )
}

#[test]
fn ascii_only_uid_rule_does_not_grant_access_to_unicode_letters() {
    assert!(matches_uid("[[:alpha:]]+", "Alice"));
    assert!(!matches_uid("[[:alpha:]]+", "Al日ce"));
    assert!(!matches_uid("[[:alpha:]]+", "Élodie"));
    assert!(!matches_uid("[[:alpha:]]+", ""));
}

#[test]
fn intentionally_unicode_uid_rule_still_allows_unicode_letters() {
    assert!(matches_uid(r"\p{L}+", "Élodie日本語"));
    assert!(!matches_uid(r"\p{L}+", "Alice7"));
}

#[test]
fn negated_caseless_ascii_rule_preserves_refusal_and_positive_controls() {
    assert!(!matches_uid("(?i)[[:^lower:]]+", "Alice"));
    assert!(!matches_uid("(?i)[[:^lower:]]+", "Kſ"));
    assert!(matches_uid("(?i)[[:^lower:]]+", "123_"));
    assert!(matches_uid("(?i)[[:^lower:]]+", "日本"));
}

#[test]
fn perl_and_posix_whitespace_remain_distinct_through_rules() {
    assert!(!matches_uid(r"a\sb", "a\u{000b}b"));
    assert!(matches_uid(r"a\sb", "a b"));
    assert!(matches_uid("a[[:space:]]b", "a\u{000b}b"));
    assert!(!matches_uid("a[[:space:]]b", "a\u{00a0}b"));
}

#[test]
fn replace_builtin_preserves_unicode_outside_ascii_matches() {
    let expression = format!(
        "request.auth.uid.replace({}, '_') == {}",
        quote_rule_string("[[:alpha:]]+"),
        quote_rule_string("é_日本_")
    );
    assert!(allowed(&expression, "éabc日本Z"));
    assert!(!allowed(&expression, "éabc日本0"));
}
