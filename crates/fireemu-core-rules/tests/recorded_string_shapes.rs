//! The rows of the FS-RULES-SHAPES recording (production, 2026-11-08, two identical
//! recordings, program ids `strings`, `regex`, `fn-shadow`, `fn-after`; 404 is allowed, 403 is
//! denied) for string ranges and functions, `lower()`/`upper()`, `split()`, `replace()` and
//! `matches()` over a supplementary character and over a lone high-surrogate escape.
//!
//! Each row states two answers: production's, which the strict profile gives, and the official
//! emulator's (firebase-tools 15.28.2, measured by the same corpus), which the emulator profile
//! gives. They differ in the four rows marked below (and in `string-escape#esc-high`, see `string_utf16.rs`).

use std::collections::BTreeMap;

use fireemu_core_rules::ast::LoneSurrogates;
use fireemu_core_rules::eval::{evaluate_request, Decision, Method, RequestContext, RulesService};
use fireemu_core_rules::parse::parse_ruleset;
use fireemu_core_rules::value::AuthContext;

const PRODUCTION: LoneSurrogates = LoneSurrogates::Production;
const OFFICIAL: LoneSurrogates = LoneSurrogates::Official;

fn get_allowed(source: &str, mode: LoneSurrogates) -> bool {
    let ruleset = parse_ruleset(source)
        .unwrap_or_else(|e| panic!("{source}: {e:?}"))
        .with_lone_surrogates(mode);
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

fn condition_allowed(condition: &str, mode: LoneSurrogates) -> bool {
    get_allowed(
        &format!(
            "rules_version = '2';\nservice cloud.firestore {{ match /databases/{{d}}/documents {{ match /notes/{{id}} {{ allow get: if {condition}; }} }} }}"
        ),
        mode,
    )
}

/// id, expression, production allowed, official emulator allowed.
type Row = (&'static str, &'static str, bool, bool);

const STRINGS: &[Row] = &[
    ("rng-ctl-true", r#""abc"[0:2] == "ab""#, true, true),
    ("rng-ctl-false", r#""abc"[0:2] == "abc""#, false, false),
    ("rng-02", r#""é🔥x"[0:2] == "é🔥""#, false, false),
    ("rng-03", r#""é🔥x"[0:3] == "é🔥""#, true, true),
    ("rng-13", r#""é🔥x"[1:3] == "🔥""#, true, true),
    ("rng-34", r#""é🔥x"[3:4] == "x""#, true, true),
    ("rng-12-size", r#""é🔥x"[1:2].size() == 1"#, true, true),
    ("rng-hi", r#""a\ud83dz"[1:2] == "\ud83d""#, true, true),
    ("low-ctl-true", r#""ABC".lower() == "abc""#, true, true),
    ("low-ctl-false", r#""ABC".lower() == "ABC""#, false, false),
    ("low-fire", r#""A🔥X".lower() == "a🔥x""#, true, true),
    ("low-fire-size", r#""A🔥X".lower().size() == 4"#, true, true),
    ("low-hi", r#""A\ud83d".lower() == "a\ud83d""#, true, true),
    (
        "low-hi-size",
        r#""A\ud83d".lower().size() == 2"#,
        true,
        true,
    ),
    ("up-ctl-true", r#""abc".upper() == "ABC""#, true, true),
    ("up-ctl-false", r#""abc".upper() == "abc""#, false, false),
    ("up-fire", r#""a🔥x".upper() == "A🔥X""#, true, true),
    ("up-hi", r#""a\ud83d".upper() == "A\ud83d""#, true, true),
    ("hi-size", r#""\ud83d".size() == 1"#, true, true),
    ("hi-self", r#""\ud83d" == "\ud83d""#, true, true),
    ("hi-fffd", r#""\ud83d" == "�""#, false, false),
];

const REGEX: &[Row] = &[
    (
        "split-ctl-true",
        r#""a,b".split(",").size() == 2"#,
        true,
        true,
    ),
    (
        "split-ctl-false",
        r#""a,b".split(",").size() == 3"#,
        false,
        false,
    ),
    (
        "split-fire",
        r#""a🔥b".split("🔥").size() == 2"#,
        true,
        true,
    ),
    (
        "split-fire-by-hi",
        r#""a🔥b".split("\ud83d").size() == 2"#,
        false,
        false,
    ),
    // Production fails the rule; the official emulator finds no lone unit inside the pair.
    (
        "split-fire-by-hi-1",
        r#""a🔥b".split("\ud83d").size() == 1"#,
        false,
        true,
    ),
    (
        "split-hi",
        r#""a\ud83dz".split("\ud83d").size() == 2"#,
        false,
        true,
    ),
    (
        "rep-ctl-true",
        r#""abc".replace("b", "x") == "axc""#,
        true,
        true,
    ),
    (
        "rep-ctl-false",
        r#""abc".replace("b", "x") == "abc""#,
        false,
        false,
    ),
    (
        "rep-fire",
        r#""a🔥b".replace("🔥", "x") == "axb""#,
        true,
        true,
    ),
    (
        "rep-dot-fire",
        r#""🔥".replace(".", "x") == "x""#,
        true,
        true,
    ),
    (
        "rep-dot-fire-xx",
        r#""🔥".replace(".", "x") == "xx""#,
        false,
        false,
    ),
    (
        "rep-hi",
        r#""a\ud83dz".replace("\ud83d", "x") == "axz""#,
        false,
        true,
    ),
    ("m-ctl-true", r#""abc".matches("a.c")"#, true, true),
    ("m-ctl-false", r#""abc".matches("a.")"#, false, false),
    ("m-dot-fire", r#""🔥".matches(".")"#, true, true),
    ("m-dotdot-fire", r#""🔥".matches("..")"#, false, false),
    ("m-hi-dot", r#""\ud83d".matches(".")"#, true, true),
    ("m-hi-lit", r#""a\ud83d".matches("a\ud83d")"#, false, true),
];

fn check(rows: &[Row]) {
    for (id, condition, production, official) in rows {
        assert_eq!(
            condition_allowed(condition, PRODUCTION),
            *production,
            "strict {id}: {condition}"
        );
        assert_eq!(
            condition_allowed(condition, OFFICIAL),
            *official,
            "emulator {id}: {condition}"
        );
    }
}

#[test]
fn string_ranges_lower_and_upper_answer_as_recorded() {
    check(STRINGS);
}

#[test]
fn split_replace_and_matches_answer_as_recorded() {
    check(REGEX);
}

#[test]
fn production_and_the_official_emulator_differ_in_four_rows_only() {
    // They are the rows with a lone surrogate in a pattern, a separator or a replacement.
    let differing: Vec<&str> = STRINGS
        .iter()
        .chain(REGEX)
        .filter(|(_, _, production, official)| production != official)
        .map(|row| row.0)
        .collect();
    assert_eq!(
        differing,
        ["split-fire-by-hi-1", "split-hi", "rep-hi", "m-hi-lit"]
    );
}

fn rules_with(preamble: &str, inner: &str, postamble: &str, condition: &str) -> String {
    format!(
        "rules_version = '2';\n{preamble}\nservice cloud.firestore {{ {inner} match /databases/{{d}}/documents {{ match /notes/{{id}} {{ allow get: if {condition}; }} }} }}\n{postamble}"
    )
}

/// `fn-shadow`: `pick()` is declared at top level as false and inside the service as true.
#[test]
fn a_function_declared_inside_the_service_shadows_the_top_level_one() {
    let preamble = "function pick() { return false; }\nfunction topOnly() { return true; }";
    let inner = "function pick() { return true; } function innerOnly() { return false; }";
    for mode in [PRODUCTION, OFFICIAL] {
        for (condition, expected) in [
            ("pick()", true),
            ("topOnly()", true),
            ("innerOnly()", false),
        ] {
            assert_eq!(
                get_allowed(&rules_with(preamble, inner, "", condition), mode),
                expected,
                "{mode:?} {condition}"
            );
        }
    }
}

/// `fn-after`: the functions are declared after the closing brace of `service`.
#[test]
fn a_function_declared_after_the_service_is_called_from_inside_it() {
    let postamble =
        "function afterTrue() { return true; }\nfunction afterFalse() { return false; }";
    for mode in [PRODUCTION, OFFICIAL] {
        for (condition, expected) in [("afterTrue()", true), ("afterFalse()", false)] {
            assert_eq!(
                get_allowed(&rules_with("", "", postamble, condition), mode),
                expected,
                "{mode:?} {condition}"
            );
        }
    }
}
