//! The rows of the FS-RULES-UNICODE recording (production, 2026-11-08, two identical
//! recordings, programs `units`, `case`, `regex`, `stored`; 404 allowed, 403 denied): sizes by
//! UTF-16 unit, no normalization, ASCII-only case mapping, and `.` as one code point. Production
//! matched the official emulator on every row, so both profiles answer alike. The source holds
//! only escapes, so nothing normalizes it.

use std::collections::BTreeMap;

use fireemu_core_rules::ast::LoneSurrogates;
use fireemu_core_rules::eval::{evaluate_request, Decision, Method, RequestContext, RulesService};
use fireemu_core_rules::parse::parse_ruleset;
use fireemu_core_rules::value::RulesValue;

const E_NFC: &str = "\u{e9}";
const E_NFD: &str = "e\u{301}";
const GA_NFC: &str = "\u{304c}";
const GA_NFD: &str = "\u{304b}\u{3099}";
const KA_MARK: &str = "\u{304b}\u{309a}";
const HFISH: &str = "\u{29e3d}";
const IVS: &str = "\u{8fbb}\u{e0100}";
const ZWJ: &str = "\u{1f468}\u{200d}\u{1f469}\u{200d}\u{1f467}";
const SKIN: &str = "\u{1f44d}\u{1f3fd}";
const FIRE: &str = "\u{1f525}";
const SHARP: &str = "\u{df}";
const DOTTED: &str = "\u{130}";
const FI: &str = "\u{fb01}";
const SIGMA_UP: &str = "\u{391}\u{3a3}";
const SIGMA_LOW: &str = "\u{3b1}\u{3c2}";
const SIGMA_SIMPLE: &str = "\u{3b1}\u{3c3}";
const ALPHA_UP: &str = "\u{391}";
const ALPHA_LOW: &str = "\u{3b1}";
const E_UP: &str = "\u{c9}";

fn allowed(condition: &str, mode: LoneSurrogates) -> bool {
    let stored: BTreeMap<String, RulesValue> = [
        ("ctl", "abc"),
        ("nfc", E_NFC),
        ("nfd", E_NFD),
        ("hfish", HFISH),
        ("ivs", IVS),
        ("zwj", ZWJ),
        ("skin", SKIN),
        ("sharp", SHARP),
        ("dotted", DOTTED),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_owned(), RulesValue::String(v.to_owned())))
    .collect();
    let source = format!(
        "rules_version = '2';\nservice cloud.firestore {{ match /databases/{{d}}/documents {{ match /notes/{{id}} {{ allow get: if {condition}; }} }} }}"
    );
    let ruleset = parse_ruleset(&source)
        .unwrap_or_else(|e| panic!("{source}: {e:?}"))
        .with_lone_surrogates(mode);
    let ctx = RequestContext {
        service: RulesService::Firestore,
        method: Method::Get,
        path: "/databases/(default)/documents/notes/n1".to_owned(),
        auth: None,
        resource: Some(RulesValue::Map(BTreeMap::from([(
            "data".to_owned(),
            RulesValue::Map(stored),
        )]))),
        request_resource: None,
        time_unix_nanos: 1_788_004_860_i128 * 1_000_000_000,
        abstract_path: false,
        request_query: None,
    };
    matches!(evaluate_request(&ruleset, &ctx).decision, Decision::Allow)
}

fn check(rows: &[(&str, String, bool)]) {
    for mode in [LoneSurrogates::Production, LoneSurrogates::Official] {
        for (id, condition, expected) in rows {
            assert_eq!(
                allowed(condition, mode),
                *expected,
                "{mode:?} {id}: {condition}"
            );
        }
    }
}

#[test]
fn sizes_are_utf16_units_and_nothing_is_normalized() {
    check(&[
        ("ctl-true", r#""abc".size() == 3"#.into(), true),
        ("ctl-false", r#""abc".size() == 4"#.into(), false),
        ("hfish-2", format!(r#""{HFISH}".size() == 2"#), true),
        ("hfish-1", format!(r#""{HFISH}".size() == 1"#), false),
        ("kana-2", format!(r#""{KA_MARK}".size() == 2"#), true),
        ("ivs-3", format!(r#""{IVS}".size() == 3"#), true),
        ("zwj-8", format!(r#""{ZWJ}".size() == 8"#), true),
        ("zwj-5", format!(r#""{ZWJ}".size() == 5"#), false),
        ("skin-4", format!(r#""{SKIN}".size() == 4"#), true),
        ("e-eq", format!(r#""{E_NFC}" == "{E_NFD}""#), false),
        ("e-nfd-size", format!(r#""{E_NFD}".size() == 2"#), true),
        ("ga-eq", format!(r#""{GA_NFC}" == "{GA_NFD}""#), false),
    ]);
}

#[test]
fn case_mapping_is_ascii_only() {
    check(&[
        ("ctl-true", r#""abc".upper() == "ABC""#.into(), true),
        ("ctl-false", r#""abc".upper() == "abc""#.into(), false),
        ("sharp-eq", format!(r#""{SHARP}".upper() == "SS""#), false),
        (
            "sharp-simple",
            format!(r#""{SHARP}".upper() == "{SHARP}""#),
            true,
        ),
        (
            "sharp-size",
            format!(r#""{SHARP}".upper().size() == 2"#),
            false,
        ),
        (
            "dotted-size",
            format!(r#""{DOTTED}".lower().size() == 2"#),
            false,
        ),
        (
            "dotted-simple",
            format!(r#""{DOTTED}".lower().size() == 1"#),
            true,
        ),
        (
            "dotted-same",
            format!(r#""{DOTTED}".lower() == "{DOTTED}""#),
            true,
        ),
        ("fi-size", format!(r#""{FI}".upper().size() == 2"#), false),
        ("fi-simple", format!(r#""{FI}".upper().size() == 1"#), true),
        ("lower-i", r#""I".lower() == "i""#.into(), true),
        (
            "sigma",
            format!(r#""{SIGMA_UP}".lower() == "{SIGMA_LOW}""#),
            false,
        ),
        (
            "sigma-simple",
            format!(r#""{SIGMA_UP}".lower() == "{SIGMA_SIMPLE}""#),
            false,
        ),
        (
            "sigma-same",
            format!(r#""{SIGMA_UP}".lower() == "{SIGMA_UP}""#),
            true,
        ),
        (
            "greek-lower",
            format!(r#""{ALPHA_UP}".lower() == "{ALPHA_LOW}""#),
            false,
        ),
        (
            "acute-upper",
            format!(r#""{E_NFC}".upper() == "{E_UP}""#),
            false,
        ),
    ]);
}

#[test]
fn a_dot_is_one_code_point() {
    check(&[
        ("ctl-true", r#""abc".matches("a.c")"#.into(), true),
        ("ctl-false", r#""abc".matches("a.")"#.into(), false),
        ("fire-dot", format!(r#""{FIRE}".matches(".")"#), true),
        ("fire-dotdot", format!(r#""{FIRE}".matches("..")"#), false),
        (
            "fire-two",
            format!(r#""{FIRE}".matches("^.{{2}}$")"#),
            false,
        ),
        ("e-nfd-dot", format!(r#""{E_NFD}".matches(".")"#), false),
        ("zwj-dot", format!(r#""{ZWJ}".matches(".")"#), false),
        ("zwj-five", format!(r#""{ZWJ}".matches("^.{{5}}$")"#), true),
    ]);
}

#[test]
fn stored_values_are_read_like_literals() {
    let d = "resource.data";
    check(&[
        ("ctl-true", format!(r#"{d}.ctl == "abc""#), true),
        ("ctl-false", format!(r#"{d}.ctl == "abd""#), false),
        ("nfc-size", format!("{d}.nfc.size() == 1"), true),
        ("nfd-size", format!("{d}.nfd.size() == 2"), true),
        ("nfd-lit-eq", format!(r#"{d}.nfd == "{E_NFD}""#), true),
        ("nfd-nfc-lit-eq", format!(r#"{d}.nfd == "{E_NFC}""#), false),
        ("nfd-nfc-field-eq", format!("{d}.nfd == {d}.nfc"), false),
        ("hfish-size", format!("{d}.hfish.size() == 2"), true),
        ("ivs-size", format!("{d}.ivs.size() == 3"), true),
        ("zwj-size", format!("{d}.zwj.size() == 8"), true),
        ("skin-size", format!("{d}.skin.size() == 4"), true),
        (
            "sharp-upper-size",
            format!("{d}.sharp.upper().size() == 2"),
            false,
        ),
        (
            "sharp-upper-simple",
            format!("{d}.sharp.upper().size() == 1"),
            true,
        ),
        (
            "dotted-lower-size",
            format!("{d}.dotted.lower().size() == 2"),
            false,
        ),
        (
            "dotted-lower-simple",
            format!("{d}.dotted.lower().size() == 1"),
            true,
        ),
    ]);
}

// ---- properties: case mapping touches ASCII letters only, whatever the text holds ----

use proptest::prelude::*;

/// (UTF-16 units, rule source) of the pieces: ASCII letters of both cases, letters with a
/// Unicode case mapping, supplementary and private-use characters, and lone surrogates.
fn piece(kind: usize) -> (Vec<u16>, String) {
    let units = |c: char| c.encode_utf16(&mut [0u16; 2]).to_vec();
    let escaped = |c: char| format!("\\U{:08x}", c as u32);
    match kind % 12 {
        0 => (units('a'), "a".to_owned()),
        1 => (units('Z'), "Z".to_owned()),
        2 => (units('\u{c9}'), escaped('\u{c9}')),
        3 => (units('\u{df}'), escaped('\u{df}')),
        4 => (units('\u{130}'), escaped('\u{130}')),
        5 => (units('\u{fb01}'), escaped('\u{fb01}')),
        6 => (units('\u{3a3}'), escaped('\u{3a3}')),
        7 => (units('\u{10400}'), escaped('\u{10400}')),
        8 => (units('\u{10D83D}'), escaped('\u{10D83D}')),
        9 => (vec![0xD83D], "\\ud83d".to_owned()),
        10 => (vec![0xDE00], "\\ude00".to_owned()),
        _ => (units('7'), "7".to_owned()),
    }
}

fn spelled(units: &[u16]) -> String {
    units
        .iter()
        .fold(String::new(), |out, unit| out + &format!("\\u{unit:04x}"))
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    #[test]
    fn lower_and_upper_change_ascii_letters_only(
        kinds in prop::collection::vec(0usize..12, 0..7),
        official in any::<bool>(),
    ) {
        let mode = if official { LoneSurrogates::Official } else { LoneSurrogates::Production };
        let (units, source): (Vec<u16>, String) = kinds.iter().fold(
            (Vec::new(), String::new()),
            |(mut units, mut source), kind| {
                let (u, s) = piece(*kind);
                units.extend(u);
                source.push_str(&s);
                (units, source)
            },
        );
        for (method, map) in [
            ("lower", u8::to_ascii_lowercase as fn(&u8) -> u8),
            ("upper", u8::to_ascii_uppercase as fn(&u8) -> u8),
        ] {
            let expected: Vec<u16> = units
                .iter()
                .map(|unit| match u8::try_from(*unit) {
                    Ok(byte) if byte.is_ascii() => u16::from(map(&byte)),
                    _ => *unit,
                })
                .collect();
            let condition = format!("\"{source}\".{method}() == \"{}\"", spelled(&expected));
            prop_assert!(allowed(&condition, mode), "{mode:?} {condition}");
            let same_size = format!("\"{source}\".{method}().size() == {}", units.len());
            prop_assert!(allowed(&same_size, mode), "{mode:?} {same_size}");
        }
    }
}
