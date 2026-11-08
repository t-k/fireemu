//! Rules strings are indexed and sized by UTF-16 code unit, as production does.
//!
//! The rows come from the 2026-11-08 production recording of the FS-RULES differences corpus
//! (`string-index#*`, `string-escape#*`, program `fs-rules-v1/diffs`). Its subject is
//! "é🔥x", the units é, D83D, DD25, x. A half of the emoji cannot be a Rust `String`, so it is
//! held as U+FFFD (the Realtime Database rules reader does the same for a lone surrogate).

use std::collections::BTreeMap;

use fireemu_core_rules::eval::{evaluate_request, Decision, Method, RequestContext, RulesService};
use fireemu_core_rules::parse::parse_ruleset;
use fireemu_core_rules::value::AuthContext;
use proptest::prelude::*;

fn decide(service: RulesService, source: &str) -> Decision {
    let ruleset = parse_ruleset(source).unwrap_or_else(|e| panic!("{source}: {e:?}"));
    let path = match service {
        RulesService::Firestore => "/databases/(default)/documents/notes/n1",
        RulesService::Storage => "/b/bucket/o/notes/n1",
    };
    let ctx = RequestContext {
        service,
        method: Method::Get,
        path: path.to_owned(),
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
    evaluate_request(&ruleset, &ctx).decision
}

fn firestore_rules(condition: &str) -> String {
    format!(
        "rules_version = '2';\nservice cloud.firestore {{ match /databases/{{d}}/documents {{ match /notes/{{id}} {{ allow get: if {condition}; }} }} }}"
    )
}

fn storage_rules(condition: &str) -> String {
    format!(
        "rules_version = '2';\nservice firebase.storage {{ match /b/{{bucket}}/o {{ match /notes/{{id}} {{ allow get: if {condition}; }} }} }}"
    )
}

fn allowed(condition: &str) -> bool {
    matches!(
        decide(RulesService::Firestore, &firestore_rules(condition)),
        Decision::Allow
    )
}

// ---- production rows `string-index#*` ----

#[test]
fn ascii_index_is_unchanged() {
    assert!(allowed(r#""abc"[1] == "b""#));
}

#[test]
fn index_zero_is_the_first_unit() {
    assert!(allowed(r#""é🔥x"[0] == "é""#));
}

#[test]
fn index_one_is_half_the_emoji_and_not_equal_to_it() {
    assert!(!allowed(r#""é🔥x"[1] == "🔥""#));
}

#[test]
fn index_two_is_the_other_half_and_not_x() {
    assert!(!allowed(r#""é🔥x"[2] == "x""#));
}

#[test]
fn index_three_is_the_last_unit() {
    assert!(allowed(r#""é🔥x"[3] == "x""#));
}

#[test]
fn index_four_is_out_of_range_and_denies_either_way() {
    assert!(!allowed(r#""é🔥x"[4] == "x""#));
    assert!(!allowed(r#"!("é🔥x"[4] == "x")"#));
}

#[test]
fn size_counts_utf16_units() {
    assert!(allowed(r#""é🔥x".size() == 4"#));
    assert!(!allowed(r#""é🔥x".size() == 3"#));
}

// ---- production rows `string-escape#*` ----

#[test]
fn a_bmp_escape_equals_the_character() {
    assert!(allowed(r#""\u00e9" == "é""#));
}

/// Production compiled the ruleset (`string-escape#publishes`) and answered 403 for
/// `"é🔥x"[1] == "\ud83d"`; the official emulator (firebase-tools 15.28.2) answers allow. The
/// evaluator has no profile, so it follows the official answer for both profiles; the strict
/// answer is pinned below.
#[test]
fn a_lone_high_surrogate_escape_compiles_and_the_emulator_answer_is_allow() {
    assert!(allowed(r#""é🔥x"[1] == "\ud83d""#));
}

#[test]
#[ignore = "production answered 403 for this row (string-escape#esc-high, 2026-11-08); the evaluator has no strict profile yet"]
fn a_lone_high_surrogate_escape_is_not_the_indexed_half_in_production() {
    assert!(!allowed(r#""é🔥x"[1] == "\ud83d""#));
}

// ---- not recorded: an escaped pair (kept consistent with the lone-escape row) ----

#[test]
fn an_escaped_surrogate_pair_is_one_character_of_two_units() {
    assert!(allowed(r#""\ud83d\ude00" == "😀""#));
    assert!(allowed(r#""\ud83d\ude00".size() == 2"#));
    assert!(allowed(r#""\ud83d\ude00"[0] != "😀""#));
}

#[test]
fn escapes_in_the_wrong_order_are_two_lone_surrogates() {
    assert!(allowed(r#""\ude00\ud83d".size() == 2"#));
    assert!(!allowed(r#""\ude00\ud83d" == "😀""#));
}

#[test]
fn only_a_u_escape_of_a_high_surrogate_takes_the_low_escape_after_it() {
    // A BMP escape and a wide escape are not high halves, whatever follows them.
    assert!(allowed(r#""\u0041\ude00".size() == 2"#));
    assert!(allowed(r#""\u0041\ude00"[0] == "A""#));
    assert!(allowed(r#""\U0000d83d\ude00".size() == 2"#));
    // A high half followed by something else, or by a high half, is not a pair.
    assert!(allowed(r#""\ud83dx".size() == 2"#));
    assert!(allowed(r#""\ud83d\ud83d".size() == 2"#));
    assert!(allowed(r#""\ud83d\u0041".size() == 2"#));
    assert!(allowed(r#""\ud83d\ude00x"[2] == "x""#));
    assert!(allowed(r#""\ud83d\uDe00" == "😀""#));
}

// ---- Storage Rules share the evaluator ----

#[test]
fn storage_rules_index_and_size_by_utf16_unit_too() {
    for (condition, expected) in [
        (r#""é🔥x"[3] == "x""#, true),
        (r#""é🔥x"[2] == "x""#, false),
        (r#""é🔥x".size() == 4"#, true),
        (r#""abc"[1] == "b""#, true),
    ] {
        assert_eq!(
            matches!(
                decide(RulesService::Storage, &storage_rules(condition)),
                Decision::Allow
            ),
            expected,
            "{condition}"
        );
    }
}

// ---- properties ----

fn literal(text: &str) -> String {
    use std::fmt::Write;
    text.chars().fold(String::new(), |mut out, c| {
        write!(out, "\\U{:08x}", c as u32).unwrap();
        out
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(96))]

    #[test]
    fn size_is_the_utf16_length(text in "\\PC{0,12}|[é🔥x😀a]{0,8}") {
        let condition = format!("\"{}\".size() == {}", literal(&text), text.encode_utf16().count());
        prop_assert!(allowed(&condition));
        let wrong = format!("\"{}\".size() == {}", literal(&text), text.encode_utf16().count() + 1);
        prop_assert!(!allowed(&wrong));
    }

    #[test]
    fn index_reads_the_unit_and_denies_past_the_end(text in "[é🔥x😀a]{0,8}", extra in 0usize..3) {
        let units: Vec<u16> = text.encode_utf16().collect();
        for (i, unit) in units.iter().enumerate() {
            let same = format!("\"{}\"[{i}] == \"\\u{unit:04x}\"", literal(&text));
            prop_assert!(allowed(&same), "{same}");
            if !(0xD800..0xE000).contains(unit) {
                // A whole character differs from every other character.
                let other = format!("\"{}\"[{i}] == \"\\u{:04x}\"", literal(&text), unit ^ 1);
                prop_assert!(!allowed(&other), "{other}");
            }
        }
        let past = format!("\"{}\"[{}] == \"x\"", literal(&text), units.len() + extra);
        prop_assert!(!allowed(&past));
        let negated = format!("!(\"{}\"[{}] == \"x\")", literal(&text), units.len() + extra);
        prop_assert!(!allowed(&negated));
    }
}
