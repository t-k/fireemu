//! Storage Rules counterparts of the Firestore Rules defects fixed on 2026-11-07/08.
//!
//! Storage shares this crate's evaluator with Firestore, so a string or parser defect of the
//! shared engine is a Storage defect too. Each `#[ignore]`d test states the expected answer
//! and where it comes from; none changes behaviour. Tests without `#[ignore]` pin shapes the
//! audit found sound (the Storage list proof refuses what it cannot prove).
//!
//! Sources, quoted in each test:
//! - OFFICIAL: the official Storage rules runtime (`cloud-storage-rules-runtime-v1.1.3.jar`,
//!   started by firebase-tools 15.23.0 with the Storage emulator), run locally on 2026-11-08;
//!   a rule is set with `PUT /internal/setRules`, an object is created with the owner
//!   credential and read anonymously (200 = the rule allowed it, 403 = denied).
//! - PRODUCTION-FS: a Firestore production row of FS-RULES-SHAPES (record-r1.log). The
//!   Storage runtime has no recording of its own.

use std::collections::BTreeMap;

use fireemu_core_rules::eval::{
    evaluate_request_with, Decision, DocumentAccess, Method, RequestContext, RulesService,
    ABSTRACT_LIST_PREFIX, ABSTRACT_PREFIX, ABSTRACT_SEGMENT,
};
use fireemu_core_rules::parse::parse_ruleset;
use fireemu_core_rules::value::{AuthContext, RulesValue};

struct NoDocuments;

impl DocumentAccess for NoDocuments {
    fn get(&self, _: &[String]) -> Option<RulesValue> {
        None
    }
}

fn storage(body: &str) -> String {
    format!(
        "rules_version = '2';\nservice firebase.storage {{ match /b/{{bucket}}/o {{ {body} }} }}"
    )
}

fn object(name: &str, metadata: &[(&str, &str)]) -> RulesValue {
    let mut map = BTreeMap::new();
    map.insert("name".into(), RulesValue::String(name.into()));
    map.insert("size".into(), RulesValue::Int(5));
    map.insert(
        "metadata".into(),
        RulesValue::Map(
            metadata
                .iter()
                .map(|(k, v)| ((*k).to_owned(), RulesValue::String((*v).to_owned())))
                .collect(),
        ),
    );
    RulesValue::Map(map)
}

fn decide(
    rules: &str,
    path: &str,
    resource: Option<RulesValue>,
    abstract_path: bool,
    method: Method,
) -> bool {
    let ruleset = parse_ruleset(rules).unwrap_or_else(|e| panic!("{e:?}"));
    let context = RequestContext {
        service: RulesService::Storage,
        method,
        path: path.to_owned(),
        auth: abstract_path.then(|| AuthContext {
            uid: "u1".into(),
            token: BTreeMap::new(),
        }),
        resource: Some(resource.unwrap_or(RulesValue::Null)),
        request_resource: Some(RulesValue::Null),
        time_unix_nanos: 0,
        abstract_path,
        request_query: None,
    };
    matches!(
        evaluate_request_with(&ruleset, &context, Some(&NoDocuments)).decision,
        Decision::Allow
    )
}

/// A `get` of the object `name` under `allow get: if <condition>`.
fn get_allows(condition: &str, name: &str) -> bool {
    get_allows_with(condition, name, &[])
}

fn get_allows_with(condition: &str, name: &str, metadata: &[(&str, &str)]) -> bool {
    decide(
        &storage(&format!(
            "match /{{allPaths=**}} {{ allow get: if {condition}; }}"
        )),
        &format!("/b/bkt/o/{name}"),
        Some(object(name, metadata)),
        false,
        Method::Get,
    )
}

/// A strict-profile `list` under `match /docs/{file}`: the proof tail stands for any entry.
fn list_allows(condition: &str) -> bool {
    decide(
        &storage(&format!(
            "match /docs/{{file}} {{ allow list: if {condition}; }}"
        )),
        &format!("/b/bkt/o/docs/{ABSTRACT_SEGMENT}"),
        None,
        true,
        Method::List,
    )
}

// ---------------------------------------------------------------------------------------------
// Class 4: strings read by scalar instead of UTF-16 unit (shared evaluator; fixed for Firestore on
// work/rules-string-fix, which also changes this crate's Storage answers)
// ---------------------------------------------------------------------------------------------

/// Finding S1. SECURITY (a length limit such as `resource.name.size() < 5` admits a name with
/// more units than the limit). OFFICIAL: `size() == 4` 200, `size() == 3` 403 for `é🔥x`, and
/// `size() == 2` 200, `size() == 1` 403 for U+10D83D. PRODUCTION-FS: rows size-4/size-3.
#[test]
fn a_storage_name_is_sized_by_utf16_units() {
    assert!(get_allows("resource.name.size() == 4", "é🔥x"));
    assert!(!get_allows("resource.name.size() == 3", "é🔥x"));
    assert!(get_allows("resource.name.size() == 2", "\u{10D83D}"));
    assert!(!get_allows("resource.name.size() == 1", "\u{10D83D}"));
    // Control: ASCII is the same either way.
    assert!(get_allows("resource.name.size() == 3", "abc"));
}

/// Finding S2. COMPATIBILITY and SECURITY (an index refused where the unit exists, an unit
/// read as another). OFFICIAL: `name[3] == "x"` 200, `name[2] == "x"` 403 for `é🔥x`.
/// PRODUCTION-FS: rows idx2-x, idx3-x.
#[test]
fn a_storage_name_is_indexed_by_utf16_unit() {
    assert!(get_allows("resource.name[3] == 'x'", "é🔥x"));
    assert!(!get_allows("resource.name[2] == 'x'", "é🔥x"));
}

/// Finding S3. OFFICIAL: `name[0:3] == "é🔥"` 200, `name[0:2] == "é🔥"` 403 for `é🔥x`.
/// PRODUCTION-FS: rows rng-03 (allowed), rng-02 (denied).
#[test]
fn a_storage_name_is_sliced_by_utf16_unit() {
    assert!(get_allows("resource.name[0:3] == 'é🔥'", "é🔥x"));
    assert!(!get_allows("resource.name[0:2] == 'é🔥'", "é🔥x"));
}

/// Finding S4. The same size rule over a custom metadata value (`resource.metadata`, and the
/// `request.resource.metadata` of an upload, are built from client strings). Expected from the
/// unit count of the OFFICIAL name rows above and the shared `size()`; the metadata path itself
/// was not run on the official runtime.
#[test]
fn a_storage_metadata_value_is_sized_by_utf16_units() {
    assert!(get_allows_with(
        "resource.metadata.k.size() == 3",
        "o",
        &[("k", "🔥x")]
    ));
    assert!(!get_allows_with(
        "resource.metadata.k.size() == 2",
        "o",
        &[("k", "🔥x")]
    ));
}

/// Finding S5. The control for the above: `.` matches one character outside the Basic
/// Multilingual Plane as one (OFFICIAL: `matches(".{3}")` 200, `matches(".{4}")` 403 for
/// `é🔥x`; PRODUCTION-FS: rows m-dot-fire, rep-dot-fire). Sound today.
#[test]
fn a_dot_matches_a_supplementary_character_as_one() {
    assert!(get_allows("resource.name.matches('.{3}')", "é🔥x"));
    assert!(!get_allows("resource.name.matches('.{4}')", "é🔥x"));
}

/// Finding S6. UNKNOWN EXPECTATION (needs a production row), COMPATIBILITY or SECURITY by
/// which way production goes. OFFICIAL (Storage and, run the same way, the Firestore
/// emulator): `lower()` and `upper()` change ASCII letters only: `"É".lower() == "É"` 200,
/// `"É".lower() == "é"` 403, `"é".upper() == "é"` 200, `"ß".upper() == "SS"` 403,
/// `"ƛ".upper() == "ƛ"` 200, `"AΣ".lower()[1] == "Σ"` 200. fireemu maps with Rust's full
/// Unicode tables, so `"É".lower() == "é"` is true here. No production row has a non-ASCII
/// letter (the FS-RULES-SHAPES `low-*` and `up-*` rows use `A🔥X`).
#[test]
fn lower_and_upper_change_ascii_letters_only_as_the_official_runtime_does() {
    assert!(!get_allows("resource.name.lower() == 'é'", "É"));
    assert!(get_allows("resource.name.lower() == 'É'", "É"));
    assert!(!get_allows("resource.name.upper() == 'É'", "é"));
    assert!(!get_allows("resource.name.upper() == 'SS'", "ß"));
    assert!(get_allows("resource.name.upper() == 'ƛ'", "ƛ"));
    // Control: ASCII.
    assert!(get_allows("resource.name.lower() == 'abc'", "ABC"));
    assert!(get_allows("resource.name.upper() == 'ABC'", "abc"));
}

/// Finding S7. COMPATIBILITY. A ruleset that spells a lone surrogate escape is refused at load
/// (`\ud83d` names no character). OFFICIAL Storage: loads, and `"\ud83d".size() == 1` allows.
/// PRODUCTION-FS: `string-escape#esc-high` publishes (production compiles it; it denies
/// `"é🔥x"[1] == "\ud83d"`).
#[test]
fn a_lone_surrogate_escape_in_a_storage_ruleset_loads() {
    let rules = storage(r#"match /{p=**} { allow get: if "\ud83d".size() == 1; }"#);
    assert!(parse_ruleset(&rules).is_ok());
}

// ---------------------------------------------------------------------------------------------
// Class 6: declarations outside the expected block
// ---------------------------------------------------------------------------------------------

/// Finding S8. COMPATIBILITY. A function declared before or after the `service` block is
/// refused (`expected service`). OFFICIAL Storage: both load and `ok()` allows (200).
/// PRODUCTION-FS: `fn-top-true` allowed, `fn-after-true` recorded 2026-11-08; the Storage
/// runtime itself is unrecorded.
#[test]
fn a_function_outside_the_service_block_loads_in_a_storage_ruleset() {
    let service = "service firebase.storage { match /b/{bucket}/o { match /{p=**} { allow get: if ok(); } } }";
    let before = format!("rules_version = '2';\nfunction ok() {{ return true; }}\n{service}");
    let after = format!("rules_version = '2';\n{service}\nfunction ok() {{ return true; }}");
    for rules in [before, after] {
        let ruleset = parse_ruleset(&rules).unwrap_or_else(|e| panic!("{e:?}"));
        let context = RequestContext {
            service: RulesService::Storage,
            method: Method::Get,
            path: "/b/bkt/o/x".into(),
            auth: None,
            resource: Some(object("x", &[])),
            request_resource: Some(RulesValue::Null),
            time_unix_nanos: 0,
            abstract_path: false,
            request_query: None,
        };
        assert!(matches!(
            evaluate_request_with(&ruleset, &context, None).decision,
            Decision::Allow
        ));
    }
}

// ---------------------------------------------------------------------------------------------
// Storage-specific: object names whose path has an empty segment
// ---------------------------------------------------------------------------------------------

// Finding S9 is answered at the Firebase HTTP boundary, not here: production's v0 API refuses an
// object name with an empty interior segment, a leading slash or a trailing slash with a 400 before
// any rule is evaluated (recorded, STORAGE-RULES-S9). The replay and near-miss tests are in
// `crates/fireemu-adapter-http/tests/storage_s9_replay.rs`.

// ---------------------------------------------------------------------------------------------
// Classes 1, 2, 3, 5: the Storage list proof (strict profile, one synthetic tail segment)
// ---------------------------------------------------------------------------------------------

/// Sound today: an unknown capture is never proven, a container built from a read that can fail
/// (a `firestore.get` on a path made of the capture) is never provably shaped, and two unknown
/// reads are not recognized as equal by their structure. Pins the audited shapes so the query
/// fixes that land on the Firestore side cannot loosen them through the shared evaluator.
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

/// Finding S10. COMPATIBILITY. Production allowed `allow list: if [file] != null` under
/// `match /p/{file=**}` (recorded, STORAGE-RULES-S9, `l1-capture-not-null`, two recordings: 200).
/// A list literal is never null; its members here are captures, which cannot fail. A member that
/// can fail (a read of a document, `firestore.get(...)`) is still refused (see
/// `the_storage_list_proof_refuses_what_it_cannot_prove`).
#[test]
fn a_list_of_a_capture_is_not_null_in_a_storage_list_proof() {
    assert!(list_allows("[file] != null"));
    assert!(!list_allows("[file] == null"));
    assert!(list_allows("null != [file]"));
    assert!(list_allows("[file, 'a'] != null"));
    // Only a list literal is decided: the capture itself stays undetermined.
    assert!(!list_allows("file != null"));
    assert!(!list_allows("file == null"));
}

/// The listing proof of the shape production showed: no delimiter, so `request.path` is the
/// path of the listed prefix (recorded, STORAGE-RULES-S9, `l3-path-prefix`, two recordings:
/// `request.path == /b/$(bucket)/o/<prefix>` allowed a listing of `<prefix>/`). Other proof
/// shapes leave `request.path` undetermined, and so does a path that is not the prefix's.
#[test]
fn request_path_of_a_listing_without_a_delimiter_is_the_prefix_path() {
    let rules = storage("match /docs/{file=**} { allow list: if CONDITION; }");
    let decide_list = |condition: &str, tail: &str| {
        decide(
            &rules.replace("CONDITION", condition),
            &format!("/b/bkt/o/docs/{tail}"),
            None,
            true,
            Method::List,
        )
    };
    let tail = ABSTRACT_LIST_PREFIX;
    assert!(decide_list("request.path == /b/$(bucket)/o/docs", tail));
    assert!(decide_list("request.path[3] == 'docs'", tail));
    assert!(!decide_list("request.path == /b/$(bucket)/o/doc", tail));
    assert!(!decide_list("request.path == /b/$(bucket)/o/docs/x", tail));
    assert!(!decide_list(
        &format!("request.path == /b/$(bucket)/o/docs/{tail}"),
        tail
    ));
    // The same expression is undetermined under the other markers.
    for other in [ABSTRACT_SEGMENT, ABSTRACT_PREFIX] {
        assert!(!decide_list("request.path == /b/$(bucket)/o/docs", other));
        assert!(!decide_list("request.path[3] == 'docs'", other));
    }
}

/// A single-segment `{file}` never consumes a listing proof tail, whichever marker it is (recorded,
/// STORAGE-RULES-S9: `l4-single-segment` denied, two recordings): only a recursive wildcard can.
#[test]
fn a_single_segment_capture_does_not_match_a_listing_proof_tail() {
    let rules = storage("match /docs/{file} { allow list: if true; }");
    for tail in [ABSTRACT_LIST_PREFIX, ABSTRACT_PREFIX] {
        assert!(
            !decide(
                &rules,
                &format!("/b/bkt/o/docs/{tail}"),
                None,
                true,
                Method::List
            ),
            "{tail}"
        );
    }
    // Control: the one-level proof is what `{file}` consumes.
    assert!(decide(
        &rules,
        &format!("/b/bkt/o/docs/{ABSTRACT_SEGMENT}"),
        None,
        true,
        Method::List
    ));
}
