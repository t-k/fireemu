//! Rules strings are indexed and sized by UTF-16 code unit, as production does.
//!
//! The rows come from the 2026-11-08 production recording of the FS-RULES differences corpus
//! (`string-index#*`, `string-escape#*`, program `fs-rules-v1/diffs`). Its subject is
//! "é🔥x", the units é, D83D, DD25, x. A half of the emoji cannot be a Rust `String`, so it is
//! held as U+FFFD (the Realtime Database rules reader does the same for a lone surrogate).

use std::collections::BTreeMap;

use fireemu_core_rules::ast::LoneSurrogateLiterals;
use fireemu_core_rules::eval::{evaluate_request, Decision, Method, RequestContext, RulesService};
use fireemu_core_rules::parse::parse_ruleset;
use fireemu_core_rules::runtime::{LoadedRules, RulesetSlot};
use fireemu_core_rules::value::AuthContext;

/// What the official emulator does: a lone surrogate escape and a half read by index are the
/// same lone unit.
const OFFICIAL: LoneSurrogateLiterals = LoneSurrogateLiterals::Unit;
/// What production does (recorded `string-escape#esc-high`): the escape is U+FFFD and differs
/// from the half.
const PRODUCTION: LoneSurrogateLiterals = LoneSurrogateLiterals::Replacement;
use proptest::prelude::*;

fn decide(service: RulesService, source: &str) -> Decision {
    decide_in(service, source, PRODUCTION)
}

fn decide_in(service: RulesService, source: &str, mode: LoneSurrogateLiterals) -> Decision {
    let ruleset = parse_ruleset(source)
        .unwrap_or_else(|e| panic!("{source}: {e:?}"))
        .with_lone_surrogate_literals(mode);
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
    allowed_in(condition, PRODUCTION)
}

fn allowed_in(condition: &str, mode: LoneSurrogateLiterals) -> bool {
    matches!(
        decide_in(RulesService::Firestore, &firestore_rules(condition), mode),
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
/// `"é🔥x"[1] == "\ud83d"` in both recordings; the official emulator (firebase-tools 15.28.2)
/// answers allow. The strict profile follows production, the emulator profile the official
/// emulator.
#[test]
fn a_lone_high_surrogate_escape_is_not_the_indexed_half_in_production() {
    assert!(!allowed_in(r#""é🔥x"[1] == "\ud83d""#, PRODUCTION));
}

#[test]
fn a_lone_high_surrogate_escape_is_the_indexed_half_in_the_official_emulator() {
    assert!(allowed_in(r#""é🔥x"[1] == "\ud83d""#, OFFICIAL));
}

#[test]
fn production_is_the_default_of_a_parsed_ruleset() {
    let ruleset = parse_ruleset("service cloud.firestore {}").unwrap();
    assert_eq!(ruleset.lone_surrogate_literals(), PRODUCTION);
    assert_eq!(
        ruleset
            .with_lone_surrogate_literals(OFFICIAL)
            .lone_surrogate_literals(),
        OFFICIAL
    );
}

/// Every other recorded row answers the same in both profiles.
#[test]
fn the_other_recorded_rows_do_not_depend_on_the_profile() {
    let rows = [
        (r#""abc"[1] == "b""#, true),
        (r#""é🔥x"[0] == "é""#, true),
        (r#""é🔥x"[1] == "🔥""#, false),
        (r#""é🔥x"[2] == "x""#, false),
        (r#""é🔥x"[3] == "x""#, true),
        (r#""é🔥x"[4] == "x""#, false),
        (r#"!("é🔥x"[4] == "x")"#, false),
        (r#""é🔥x".size() == 4"#, true),
        (r#""é🔥x".size() == 3"#, false),
        (r#""\u00e9" == "é""#, true),
    ];
    for mode in [OFFICIAL, PRODUCTION] {
        for (condition, expected) in rows {
            assert_eq!(
                allowed_in(condition, mode),
                expected,
                "{mode:?} {condition}"
            );
        }
    }
}

#[test]
fn the_two_halves_of_an_emoji_are_different_units_in_both_profiles() {
    for mode in [OFFICIAL, PRODUCTION] {
        assert!(allowed_in(r#""😀"[0] == "😀"[0]"#, mode), "{mode:?}");
        assert!(allowed_in(r#""😀"[0] != "😀"[1]"#, mode), "{mode:?}");
        assert!(allowed_in(r#""😀"[0].size() == 1"#, mode), "{mode:?}");
    }
}

/// Not recorded: what a lone escape equals. The official emulator keeps it as a lone unit,
/// which is not U+FFFD; production is taken to hold it as U+FFFD (the reading that gives its
/// recorded answer).
#[test]
fn a_lone_escape_is_a_lone_unit_for_the_official_emulator_and_u_fffd_for_production() {
    assert!(allowed_in(r#""\ud83d" != "\ufffd""#, OFFICIAL));
    assert!(allowed_in(r#""\ud83d" == "\ufffd""#, PRODUCTION));
    assert!(allowed_in(r#""\ud83d" == "\ud83d""#, OFFICIAL));
    assert!(allowed_in(r#""\ud83d" != "\ude00""#, OFFICIAL));
    assert!(allowed_in(r#""\ud83d".size() == 1"#, OFFICIAL));
    assert!(allowed_in(r#""\ud83d".size() == 1"#, PRODUCTION));
}

#[test]
fn a_ruleset_carries_its_profile_through_a_loaded_ruleset_and_a_slot() {
    let source = firestore_rules(r#""é🔥x"[1] == "\ud83d""#);
    let ctx = RequestContext {
        service: RulesService::Firestore,
        method: Method::Get,
        path: "/databases/(default)/documents/notes/n1".to_owned(),
        auth: None,
        resource: None,
        request_resource: None,
        time_unix_nanos: 0,
        abstract_path: false,
        request_query: None,
    };
    let decision = |slot: &RulesetSlot| {
        let snapshot = slot.snapshot().unwrap();
        let ruleset = snapshot.ruleset.as_ref().unwrap();
        evaluate_request(ruleset, &ctx).decision
    };
    let loaded = LoadedRules::from_source(&source).unwrap();
    assert_eq!(
        loaded.ruleset.as_ref().unwrap().lone_surrogate_literals(),
        PRODUCTION
    );
    let official = loaded.clone().with_lone_surrogate_literals(OFFICIAL);
    assert_eq!(
        official.ruleset.as_ref().unwrap().lone_surrogate_literals(),
        OFFICIAL
    );
    // The original is not changed by the copy.
    assert_eq!(
        loaded.ruleset.as_ref().unwrap().lone_surrogate_literals(),
        PRODUCTION
    );

    // A slot without a profile keeps what is loaded.
    let plain = RulesetSlot::new(official.clone());
    assert_eq!(plain.lone_surrogate_literals(), None);
    assert!(matches!(decision(&plain), Decision::Allow));

    // A slot with a profile sets it on what it holds and on every replacement.
    let slot = RulesetSlot::new(loaded.clone()).with_lone_surrogate_literals(OFFICIAL);
    assert_eq!(slot.lone_surrogate_literals(), Some(OFFICIAL));
    assert!(matches!(decision(&slot), Decision::Allow));
    slot.replace_loaded(loaded.clone()).unwrap();
    assert!(matches!(decision(&slot), Decision::Allow));
    let strict = RulesetSlot::new(official).with_lone_surrogate_literals(PRODUCTION);
    assert!(matches!(decision(&strict), Decision::Deny(_)));
    strict
        .replace_loaded(loaded.with_lone_surrogate_literals(OFFICIAL))
        .unwrap();
    assert!(matches!(decision(&strict), Decision::Deny(_)));

    // A slot made like another one has the same profile and no rules.
    let like = slot.empty_like();
    assert_eq!(like.lone_surrogate_literals(), Some(OFFICIAL));
    assert!(like.snapshot().unwrap().ruleset.is_none());
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

/// The stand-ins of lone surrogates are U+10D800 to U+10DFFF; their neighbours are ordinary
/// private-use characters of two UTF-16 units.
#[test]
fn only_the_stand_in_range_counts_as_one_unit() {
    for mode in [OFFICIAL, PRODUCTION] {
        assert!(allowed_in(r#""\U0010d7ff".size() == 2"#, mode), "{mode:?}");
        assert!(allowed_in(r#""\U0010e000".size() == 2"#, mode), "{mode:?}");
        assert!(allowed_in(r#""\U0010ffff".size() == 2"#, mode), "{mode:?}");
        assert!(allowed_in(r#""\U0010d7ff"[0] != "\U0010d7ff"[1]"#, mode));
        assert!(allowed_in(r#""\U0010e000"[1] != "\U0010d800""#, mode));
        assert!(allowed_in(r#""\U0010d7ff" != "\ufffd""#, mode), "{mode:?}");
        assert!(allowed_in(r#""\U0010e000" != "\ufffd""#, mode), "{mode:?}");
    }
}

#[test]
fn rulesets_are_equal_when_source_and_profile_agree() {
    let a = "service cloud.firestore { match /{p=**} { allow read: if true; } }";
    let b = "service cloud.firestore { match /{p=**} { allow read: if false; } }";
    let parsed = |source: &str| parse_ruleset(source).unwrap();
    assert!(parsed(a) == parsed(a));
    assert!(parsed(a) != parsed(b));
    assert!(parsed(a) != parsed(a).with_lone_surrogate_literals(OFFICIAL));
    assert!(
        parsed(a).with_lone_surrogate_literals(OFFICIAL)
            == parsed(a).with_lone_surrogate_literals(OFFICIAL)
    );
    let versioned = format!("rules_version = '2';\n{a}");
    assert!(parsed(a) != parsed(&versioned));
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
    fn size_is_the_utf16_length(text in "\\PC{0,12}|[é🔥x😀a]{0,8}", official in any::<bool>()) {
        let mode = if official { OFFICIAL } else { PRODUCTION };
        let condition = format!("\"{}\".size() == {}", literal(&text), text.encode_utf16().count());
        prop_assert!(allowed_in(&condition, mode));
        let wrong = format!("\"{}\".size() == {}", literal(&text), text.encode_utf16().count() + 1);
        prop_assert!(!allowed_in(&wrong, mode));
    }

    #[test]
    fn index_reads_the_unit_and_denies_past_the_end(
        text in "[é🔥x😀a]{0,8}",
        extra in 0usize..3,
        official in any::<bool>(),
    ) {
        let mode = if official { OFFICIAL } else { PRODUCTION };
        let units: Vec<u16> = text.encode_utf16().collect();
        for (i, unit) in units.iter().enumerate() {
            let same = format!("\"{}\"[{i}] == \"\\u{unit:04x}\"", literal(&text));
            if (0xD800..0xE000).contains(unit) {
                // Only the official emulator reads the escape of a half as that half.
                prop_assert_eq!(allowed_in(&same, mode), official, "{}", same);
            } else {
                prop_assert!(allowed_in(&same, mode), "{}", same);
                // A whole character differs from every other character.
                let other = format!("\"{}\"[{i}] == \"\\u{:04x}\"", literal(&text), unit ^ 1);
                prop_assert!(!allowed_in(&other, mode), "{}", other);
            }
            // A unit is equal to itself, and different from every other unit.
            for (j, other_unit) in units.iter().enumerate() {
                let compare = format!("\"{}\"[{i}] == \"{}\"[{j}]", literal(&text), literal(&text));
                prop_assert_eq!(allowed_in(&compare, mode), unit == other_unit, "{}", compare);
            }
        }
        let past = format!("\"{}\"[{}] == \"x\"", literal(&text), units.len() + extra);
        prop_assert!(!allowed_in(&past, mode));
        let negated = format!("!(\"{}\"[{}] == \"x\")", literal(&text), units.len() + extra);
        prop_assert!(!allowed_in(&negated, mode));
    }
}
