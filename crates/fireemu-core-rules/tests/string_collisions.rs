//! Valid Unicode never collides with a lone surrogate (Sol, round 6): U+10D83D is two UTF-16
//! units and differs from a lone D83D, whatever the profile, and a valid `\U0010d83d` literal
//! is never rewritten. The table is the review's; the properties mix BMP, supplementary,
//! private-use and lone-surrogate text.

use std::collections::BTreeMap;

use fireemu_core_rules::ast::LoneSurrogates;
use fireemu_core_rules::eval::{evaluate_request, Decision, Method, RequestContext, RulesService};
use fireemu_core_rules::parse::parse_ruleset;
use fireemu_core_rules::value::{AuthContext, RulesValue};
use proptest::prelude::*;

const MODES: [LoneSurrogates; 2] = [LoneSurrogates::Official, LoneSurrogates::Production];

/// The private-use character U+10D83D, which an earlier stand-in scheme confused with D83D.
const PUA: &str = "\u{10D83D}";

fn allowed_with(
    condition: &str,
    mode: LoneSurrogates,
    data: &[(&str, &str)],
    token: &[(&str, &str)],
) -> bool {
    let source = format!(
        "rules_version = '2';\nservice cloud.firestore {{ match /databases/{{d}}/documents {{ match /notes/{{id}} {{ allow get: if {condition}; }} }} }}"
    );
    let ruleset = parse_ruleset(&source)
        .unwrap_or_else(|e| panic!("{source}: {e:?}"))
        .with_lone_surrogates(mode);
    let fields: BTreeMap<String, RulesValue> = data
        .iter()
        .map(|(k, v)| ((*k).to_owned(), RulesValue::String((*v).to_owned())))
        .collect();
    let resource = RulesValue::Map(BTreeMap::from([
        ("data".to_owned(), RulesValue::Map(fields)),
        ("id".to_owned(), RulesValue::String("n1".to_owned())),
    ]));
    let ctx = RequestContext {
        service: RulesService::Firestore,
        method: Method::Get,
        path: "/databases/(default)/documents/notes/n1".to_owned(),
        auth: Some(AuthContext {
            uid: "alice".to_owned(),
            token: token
                .iter()
                .map(|(k, v)| ((*k).to_owned(), RulesValue::String((*v).to_owned())))
                .collect(),
        }),
        resource: Some(resource),
        request_resource: None,
        time_unix_nanos: 1_788_004_860_i128 * 1_000_000_000,
        abstract_path: false,
        request_query: None,
    };
    matches!(evaluate_request(&ruleset, &ctx).decision, Decision::Allow)
}

/// Both profiles answer the same: (condition, allowed).
#[test]
fn the_reviews_table_holds_in_both_profiles() {
    for mode in MODES {
        for (condition, expected) in [
            ("resource.data.s.size() == 1", false),
            ("resource.data.s.size() == 2", true),
            (r#"resource.data.s == "🔥"[0]"#, false),
            (r#"resource.data.s == "\ud83d""#, false),
            (r#"resource.data.s == "\U0010d83d""#, true),
            (r#""\U0010d83d" == "\ufffd""#, false),
            (r#""\U0010d83d".size() == 2"#, true),
            (r#"resource.data.s.matches("\ud83d")"#, false),
            (r#"resource.data.s.matches("\U0010d83d")"#, true),
            (r#"resource.data.s.replace("\U0010d83d", "x") == "x""#, true),
            (r#"resource.data.s[0:2] == "\U0010d83d""#, true),
            (r#"resource.data.s[0:1] == "\ud83d""#, false),
        ] {
            assert_eq!(
                allowed_with(condition, mode, &[("s", PUA)], &[]),
                expected,
                "{mode:?} {condition}"
            );
        }
    }
}

/// A name that is the private-use character, as a Storage capture or a token claim would give.
#[test]
fn a_token_claim_holding_the_private_use_character_is_not_a_lone_surrogate() {
    for mode in MODES {
        for (condition, expected) in [
            ("request.auth.token.s.size() == 2", true),
            (r#"request.auth.token.s == "\ud83d""#, false),
            (r#"request.auth.token.s == "\U0010d83d""#, true),
            (r#"{"\U0010d83d": true}[request.auth.token.s]"#, true),
            (r#"request.auth.token.s in {"\U0010d83d": true}"#, true),
        ] {
            assert_eq!(
                allowed_with(condition, mode, &[], &[("s", PUA)]),
                expected,
                "{mode:?} {condition}"
            );
        }
    }
}

/// Not recorded: a separator that is a lone surrogate. Production fails the rule (recorded for
/// every pattern, separator and replacement that holds one); the official emulator finds no
/// lone unit inside the character.
#[test]
fn a_lone_separator_never_splits_the_private_use_character() {
    let condition = r#"resource.data.s.split("\ud83d").size() == 1"#;
    assert!(allowed_with(
        condition,
        LoneSurrogates::Official,
        &[("s", PUA)],
        &[]
    ));
    assert!(!allowed_with(
        condition,
        LoneSurrogates::Production,
        &[("s", PUA)],
        &[]
    ));
}

/// A map key is a `String`, so a lone surrogate cannot be one: such a ruleset does not
/// compile (not recorded). The key of a real character is an ordinary key.
#[test]
fn a_lone_surrogate_is_not_a_map_key() {
    for source in [
        r#"{"\ud83d": true}[request.auth.token.s]"#,
        r#"{"\ud83d": 1}["\ud83d"] == 1"#,
    ] {
        let rules =
            format!("service cloud.firestore {{ match /{{d=**}} {{ allow get: if {source}; }} }}");
        assert!(parse_ruleset(&rules).is_err(), "{source}");
    }
}

/// A literal pattern is compiled once at load; it must mean what the dynamic one means.
#[test]
fn a_literal_pattern_and_a_computed_pattern_agree() {
    for mode in MODES {
        for pattern in [r#""\U0010d83d""#, r#""\ud83d""#, r#""\ud83d" + """#] {
            let literal = allowed_with(
                &format!("resource.data.s.matches({pattern})"),
                mode,
                &[("s", PUA)],
                &[],
            );
            let computed = allowed_with(
                &format!(r#"resource.data.s.matches({pattern} + "")"#),
                mode,
                &[("s", PUA)],
                &[],
            );
            assert_eq!(literal, computed, "{mode:?} {pattern}");
        }
    }
}

/// Composition on ordinary text (the review's "Should" list): the whole string behaves as
/// before when no half cut from a pair takes part.
#[test]
fn ordinary_strings_keep_their_operations() {
    for mode in MODES {
        for condition in [
            r#""é🔥x"[0:"é🔥x".size()] == "é🔥x""#,
            r#""🔥x".split("x").size() == 2"#,
            r#""🔥x".replace("🔥", "!") == "!x""#,
            r#""🔥x".matches("🔥.")"#,
            r#""🔥x".lower() == "🔥x""#,
            r#""🔥x" < "🔥y""#,
            r#""🔥x".toUtf8().size() == 5"#,
            r#"{"🔥": 1}["🔥"] == 1"#,
        ] {
            assert!(
                allowed_with(condition, mode, &[], &[]),
                "{mode:?} {condition}"
            );
        }
    }
}

/// Composition on halves: the official emulator rebuilds the pair and splits on characters;
/// production, which holds a cut half as U+FFFD, does not rebuild it.
#[test]
fn halves_of_a_pair_compose_by_profile() {
    for (condition, production, official) in [
        (r#""🔥"[0] + "🔥"[1] == "🔥""#, false, true),
        (r#""🔥x".split("🔥x"[0]).size() == 1"#, true, true),
        (r#""🔥x".replace("🔥x"[0], "!") == "🔥x""#, true, true),
        (r#""🔥"[0] + "🔥"[1] != "🔥""#, true, false),
        // Two halves of one character: different units for the official emulator, both
        // U+FFFD in production (not recorded).
        ("resource.data.s[0] != resource.data.s[1]", false, true),
    ] {
        assert_eq!(
            allowed_with(condition, LoneSurrogates::Production, &[("s", PUA)], &[]),
            production,
            "strict {condition}"
        );
        assert_eq!(
            allowed_with(condition, LoneSurrogates::Official, &[("s", PUA)], &[]),
            official,
            "emulator {condition}"
        );
    }
}

/// Operations nothing was recorded for fail on a string that holds a lone surrogate.
#[test]
fn what_was_not_recorded_fails_on_a_lone_surrogate() {
    for mode in MODES {
        for condition in [
            r#""\ud83d".toUtf8().size() == 3"#,
            r#""\ud83d".trim() == "\ud83d""#,
            r#""\ud83d" < "\ude00""#,
            r#"hashing.sha256("\ud83d").size() == 32"#,
        ] {
            assert!(
                !allowed_with(condition, mode, &[], &[]),
                "{mode:?} {condition}"
            );
        }
    }
}

// ---- properties over mixed text ----

/// (UTF-16 units, rule-source spelling) of the eight kinds of piece.
fn piece(kind: usize) -> (Vec<u16>, &'static str) {
    let units = |c: char| c.encode_utf16(&mut [0u16; 2]).to_vec();
    match kind % 8 {
        0 => (units('a'), "a"),
        1 => (units('é'), "é"),
        2 => (units('\u{1F600}'), r"\U0001f600"),
        3 => (units('\u{10D83D}'), r"\U0010d83d"),
        4 => (vec![0xD83D], r"\ud83d"),
        5 => (vec![0xDE00], r"\ude00"),
        6 => (units('\u{10DE00}'), r"\U0010de00"),
        _ => (units('\u{FFFD}'), r"\ufffd"),
    }
}

fn text(kinds: &[usize]) -> (Vec<u16>, String) {
    let mut units = Vec::new();
    let mut source = String::new();
    for kind in kinds {
        let (u, s) = piece(*kind);
        units.extend(u);
        source.push_str(s);
    }
    (units, source)
}

fn spelled_by_unit(units: &[u16]) -> String {
    units
        .iter()
        .fold(String::new(), |out, unit| out + &format!("\\u{unit:04x}"))
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn mixed_text_is_read_by_unit_and_never_collides(
        kinds in prop::collection::vec(0usize..8, 0..6),
        official in any::<bool>(),
    ) {
        let mode = if official { LoneSurrogates::Official } else { LoneSurrogates::Production };
        let (units, source) = text(&kinds);
        let literal = format!("\"{source}\"");
        // The length is the number of units, however the text is spelled.
        let size = format!("{literal}.size() == {}", units.len());
        prop_assert!(allowed_with(&size, mode, &[], &[]), "{}", size);
        // Spelled one unit at a time it is the same string.
        let respelled = format!("{literal} == \"{}\"", spelled_by_unit(&units));
        prop_assert!(allowed_with(&respelled, mode, &[], &[]), "{}", respelled);
        let concatenated = format!("{literal} + \"\" == {literal}");
        prop_assert!(allowed_with(&concatenated, mode, &[], &[]), "{}", concatenated);
        if !units.is_empty() {
            let whole = format!("{literal}[0:{}] == {literal}", units.len());
            prop_assert!(allowed_with(&whole, mode, &[], &[]), "{}", whole);
        }
        // A string of valid text equals the same text read from a document.
        if let Ok(valid) = String::from_utf16(&units) {
            let from_data = format!("resource.data.s == {literal}");
            prop_assert!(allowed_with(&from_data, mode, &[("s", &valid)], &[]), "{}", from_data);
            let sized = format!("resource.data.s.size() == {}", units.len());
            prop_assert!(allowed_with(&sized, mode, &[("s", &valid)], &[]), "{}", sized);
        }
        // Each unit: a character that is not a surrogate, a lone unit of the string, and a
        // half of a pair that production holds as U+FFFD.
        let decoded: Vec<Result<char, u16>> = char::decode_utf16(units.iter().copied())
            .map(|r| r.map_err(|e| e.unpaired_surrogate()))
            .collect();
        let mut at = 0;
        for piece in decoded {
            match piece {
                Ok(c) => {
                    let width = c.len_utf16();
                    let range = format!("{literal}[{at}:{}] == \"\\U{:08x}\"", at + width, c as u32);
                    prop_assert!(allowed_with(&range, mode, &[], &[]), "{}", range);
                    for half in 0..width {
                        let unit = units[at + half];
                        let index = format!("{literal}[{}] == \"\\u{unit:04x}\"", at + half);
                        let expected = width == 1 || official;
                        prop_assert_eq!(allowed_with(&index, mode, &[], &[]), expected, "{}", index);
                    }
                    at += width;
                }
                Err(unit) => {
                    let index = format!("{literal}[{at}] == \"\\u{unit:04x}\"");
                    prop_assert!(allowed_with(&index, mode, &[], &[]), "{}", index);
                    at += 1;
                }
            }
        }
    }
}
