//! The Storage list proof over containers the rule builds (integration with the Storage audit
//! of work/rules-string-fix, coordinator ruling A, 2026-11-09): a container holding a value
//! that cannot fail (a path capture) answers as one holding a concrete value; one built from a
//! read that can fail (a `firestore.get()` member of a missing document) answers nothing.

use std::collections::BTreeMap;

use fireemu_core_rules::eval::{
    evaluate_request_with, Decision, DocumentAccess, Method, RequestContext, RulesService,
    ABSTRACT_SEGMENT,
};
use fireemu_core_rules::parse::parse_ruleset;
use fireemu_core_rules::value::{AuthContext, RulesValue};

struct NoDocuments;

impl DocumentAccess for NoDocuments {
    fn get(&self, _: &[String]) -> Option<RulesValue> {
        None
    }
}

fn list_allows(condition: &str) -> bool {
    let rules = format!(
        "rules_version = '2';\nservice firebase.storage {{ match /b/{{bucket}}/o {{ match /docs/{{file}} {{ allow list: if {condition}; }} }} }}"
    );
    let ruleset = parse_ruleset(&rules).unwrap_or_else(|e| panic!("{e:?}"));
    let context = RequestContext {
        service: RulesService::Storage,
        method: Method::List,
        path: format!("/b/bkt/o/docs/{ABSTRACT_SEGMENT}"),
        auth: Some(AuthContext {
            uid: "u1".into(),
            token: BTreeMap::new(),
        }),
        resource: Some(RulesValue::Null),
        request_resource: Some(RulesValue::Null),
        time_unix_nanos: 0,
        abstract_path: true,
        request_query: None,
    };
    matches!(
        evaluate_request_with(&ruleset, &context, Some(&NoDocuments)).decision,
        Decision::Allow
    )
}

/// Copied from `the_storage_list_proof_refuses_what_it_cannot_prove`
/// (crates/fireemu-core-rules/tests/sibling_audit_storage.rs on work/rules-string-fix).
#[test]
fn the_storage_list_proof_refuses_what_it_cannot_prove() {
    let fs = "firestore.get(/databases/(default)/documents/users/$(file))";
    let exists = "firestore.exists(/databases/(default)/documents/users/$(file))";
    assert!(list_allows("true"), "control");
    assert!(
        list_allows("resource == null"),
        "control: a list has no object"
    );
    for condition in [
        "file != 'secret'".to_owned(),
        "file.size() > 0".to_owned(),
        "request.path[4] == 'docs'".to_owned(),
        format!("{{'k': {fs}.data.role}}.size() == 1"),
        format!("{{'k': {fs}.data.role}}.keys().hasOnly(['k'])"),
        format!("[{fs}.data.role].size() == 1"),
        format!("[{fs}.data.role] != null"),
        format!("{fs}.data.role == file"),
        format!("[{fs}.data.role] == [file]"),
        format!("{fs}.data.role == {fs}.data.role"),
        format!("{fs}.data == {fs}.data"),
        format!("{exists} || !{exists}"),
        format!("!{exists}"),
    ] {
        assert!(!list_allows(&condition), "{condition} must not be provable");
    }
    // A container of a capture that cannot fail has a known size.
    assert!(list_allows("{'k': file}.size() == 1"));
}
