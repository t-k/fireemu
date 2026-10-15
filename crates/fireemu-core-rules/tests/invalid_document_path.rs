//! FS-8: `get()` / `exists()` on a path that is not a document of the database being served
//! (a collection path, another database, no `/documents`) raises an evaluation error in
//! Firestore rules, so the allow does not apply. Production answered 403 for every such row of
//! the FS-8 recording, `!exists(<bad path>)` and `get(<bad path>) == null` included; a missing
//! document is still `false` / `null`. Storage rules keep their answers.

use std::collections::BTreeMap;

use fireemu_core_rules::eval::{
    evaluate_request_with, Decision, DenyReason, DocumentAccess, Method, RequestContext,
    RulesService,
};
use fireemu_core_rules::parse::parse_ruleset;
use fireemu_core_rules::value::RulesValue;
use proptest::prelude::*;

/// A database `(default)` holding `c/present`; only `databases/(default)/documents/<even>` is a
/// document path, as the Firestore adapter decides it.
struct Database;

impl Database {
    fn rest(segments: &[String]) -> Option<&[String]> {
        match segments {
            [databases, db, documents, rest @ ..]
                if databases == "databases"
                    && db == "(default)"
                    && documents == "documents"
                    && !rest.is_empty()
                    && rest.len() % 2 == 0 =>
            {
                Some(rest)
            }
            _ => None,
        }
    }
}

impl DocumentAccess for Database {
    fn get(&self, segments: &[String]) -> Option<RulesValue> {
        (Self::rest(segments)? == ["c".to_owned(), "present".to_owned()]).then(|| {
            RulesValue::Map(BTreeMap::from([(
                "data".to_owned(),
                RulesValue::Map(BTreeMap::from([("n".to_owned(), RulesValue::Int(1))])),
            )]))
        })
    }

    fn is_document_path(&self, segments: &[String]) -> bool {
        Self::rest(segments).is_some()
    }
}

fn decide(service: RulesService, condition: &str) -> Decision {
    let (header, path) = match service {
        RulesService::Firestore => (
            "service cloud.firestore {\n  match /databases/{database}/documents {\n    match /{doc=**} { allow get: if CONDITION; }\n  }\n}",
            "/databases/(default)/documents/t/x",
        ),
        RulesService::Storage => (
            "service firebase.storage {\n  match /b/{bucket}/o {\n    match /{file=**} { allow read: if CONDITION; }\n  }\n}",
            "/b/demo/o/f",
        ),
    };
    let source = format!(
        "rules_version = '2';\n{}",
        header.replace("CONDITION", condition)
    );
    let request = RequestContext {
        service,
        method: Method::Get,
        path: path.to_owned(),
        auth: None,
        resource: None,
        request_resource: None,
        time_unix_nanos: 0,
        abstract_path: false,
        request_query: None,
    };
    evaluate_request_with(&parse_ruleset(&source).unwrap(), &request, Some(&Database)).decision
}

fn firestore(condition: &str) -> Decision {
    decide(RulesService::Firestore, condition)
}

const DOCS: &str = "/databases/$(database)/documents";

#[test]
fn a_bad_path_denies_whatever_the_expression_around_it() {
    for path in [
        format!("{DOCS}/c"),
        format!("{DOCS}/c/present/sub"),
        format!("{DOCS}/c/present/sub/deeper/x"),
        "/databases/other/documents/c/present".to_owned(),
        "/databases/$(database)/c/present".to_owned(),
        "/databases/$(database)/documents".to_owned(),
        "/databases/$(database)".to_owned(),
        "/c/present".to_owned(),
    ] {
        for condition in [
            format!("exists({path})"),
            format!("!exists({path})"),
            format!("get({path}) == null"),
            format!("get({path}) != null"),
            format!("get({path}).data.n == 1"),
            format!("existsAfter({path})"),
            format!("!existsAfter({path})"),
            format!("getAfter({path}) == null"),
            format!("firestore.exists({path})"),
            format!("!firestore.exists({path})"),
        ] {
            assert_eq!(
                firestore(&condition),
                Decision::Deny(DenyReason::NoMatchingAllow),
                "{condition}"
            );
        }
    }
}

#[test]
fn a_document_path_is_still_true_false_or_null() {
    // The controls of the recording: a present document, a missing one, and the literal (default).
    assert_eq!(
        firestore(&format!("exists({DOCS}/c/present)")),
        Decision::Allow
    );
    assert_eq!(
        firestore(&format!("!exists({DOCS}/c/absent)")),
        Decision::Allow
    );
    assert_eq!(
        firestore("exists(/databases/(default)/documents/c/present)"),
        Decision::Allow
    );
    assert_eq!(
        firestore(&format!("get({DOCS}/c/absent) == null")),
        Decision::Allow
    );
    assert_eq!(
        firestore(&format!("!exists({DOCS}/c/present)")),
        Decision::Deny(DenyReason::NoMatchingAllow)
    );
}

#[test]
fn the_error_is_an_error_like_any_other_not_a_false() {
    // An error on one side of || does not stop the other side from allowing, as for every other
    // evaluation error; it is not a quiet `false` that `!` could turn into an allow.
    assert_eq!(
        firestore(&format!("exists({DOCS}/c) || true")),
        Decision::Allow
    );
    assert_eq!(
        firestore(&format!("exists({DOCS}/c) && true")),
        Decision::Deny(DenyReason::NoMatchingAllow)
    );
    assert_eq!(
        firestore(&format!("!(exists({DOCS}/c) || false)")),
        Decision::Deny(DenyReason::NoMatchingAllow)
    );
}

#[test]
fn a_bad_path_is_not_a_document_access() {
    // Eleven distinct bad paths, each rescued by `|| true`, stay within RULES-DOC-ACCESS-SINGLE
    // (10): none of them reads a document.
    let condition = (0..11)
        .map(|n| format!("(exists({DOCS}/c/present/s{n}) || true)"))
        .collect::<Vec<_>>()
        .join(" && ");
    assert_eq!(firestore(&condition), Decision::Allow);
    // Eleven distinct document paths exceed it.
    let condition = (0..11)
        .map(|n| format!("(exists({DOCS}/c/d{n}) || true)"))
        .collect::<Vec<_>>()
        .join(" && ");
    assert!(matches!(
        firestore(&condition),
        Decision::Deny(DenyReason::BudgetExceeded {
            limit_id: "RULES-DOC-ACCESS-SINGLE",
            ..
        })
    ));
}

#[test]
fn storage_rules_keep_asking_the_access_for_every_path() {
    // Storage rules read Firestore through `firestore.get()`; the FS-8 recording says nothing
    // about them, so a path the access does not call a document is still a missing one.
    let storage = |condition: &str| decide(RulesService::Storage, condition);
    assert_eq!(
        storage("!firestore.exists(/databases/(default)/documents/c)"),
        Decision::Allow
    );
    assert_eq!(
        storage("firestore.get(/databases/other/documents/c/present) == null"),
        Decision::Deny(DenyReason::NoMatchingAllow)
    );
    assert_eq!(
        storage("firestore.exists(/databases/(default)/documents/c/present)"),
        Decision::Allow
    );
}

proptest! {
    /// For any path, `!exists(path)` allows exactly when the path is a document path of the
    /// database and that document is missing; `exists(path)` exactly when it is present.
    #[test]
    fn exists_and_not_exists_agree_with_the_path_shape(
        segments in proptest::collection::vec("[a-z]{1,3}", 0..6),
        database in prop_oneof![Just("(default)"), Just("other")],
        documents in prop_oneof![Just("documents"), Just("docs")],
    ) {
        let path = format!(
            "/databases/{database}/{documents}{}",
            segments.iter().fold(String::new(), |path, s| path + "/" + s)
        );
        let valid = database == "(default)" && documents == "documents"
            && !segments.is_empty() && segments.len() % 2 == 0;
        let present = valid && segments == ["c", "present"];
        prop_assert_eq!(
            firestore(&format!("exists({path})")) == Decision::Allow,
            present
        );
        prop_assert_eq!(
            firestore(&format!("!exists({path})")) == Decision::Allow,
            valid && !present
        );
        prop_assert_eq!(
            firestore(&format!("get({path}) == null")) == Decision::Allow,
            valid && !present
        );
    }
}
