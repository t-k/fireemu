//! The construct x function x profile matrix. Every construct with a recorded row must answer
//! that row in both profiles; every construct no row records stays unobserved in strict, and the
//! emulator profile answers it with the engine's result.

use super::replay::{outcome, rows, FUNCTIONS};
use fireemu_core_firestore::pipeline_exec::Unrecorded;
use serde_json::{json, Value};

/// A construct a row records: the label of that row.
const RECORDED: [(&str, &str); 17] = [
    ("digit", "nd-arabic"),
    ("word", "nw-cafe"),
    ("space", "s-vt"),
    ("boundary", "b-cafe-edge"),
    ("unicode_prop", "pnd-arabic"),
    ("posix", "posix-digit"),
    ("flag_i_literal", "i-ascii-ctl"),
    ("flag_s", "s-dotall"),
    ("flag_m", "m-anchor"),
    ("flag_unicode", "u-flag"),
    ("flag_ungreedy", "ungreedy"),
    ("hex_control_escape", "ctl-hex"),
    ("backslash", "bs-hex"),
    ("trailing_backslash", "bs-trailing"),
    ("captures_none", "cap-noncapturing"),
    ("captures_one", "cap-named"),
    ("captures_many", "cap-two"),
];

fn found(value: &str) -> [Value; 4] {
    [
        json!({"kind": "bool", "value": true}),
        json!({"kind": "bool", "value": true}),
        json!({"kind": "string", "value": value}),
        json!({"kind": "array", "items": [{"kind": "string", "value": value}]}),
    ]
}

/// A construct no row records: subject, pattern and the emulator profile's answers.
fn unrecorded() -> Vec<(&'static str, &'static str, &'static str, [Value; 4])> {
    let refused = || std::array::from_fn(|_| json!({"kind": "refused-syntax"}));
    vec![
        ("br_unrecorded_braces", "aa", "a{2}", found("aa")),
        ("br_unrecorded_anchor", "a", r"\Aa", found("a")),
        ("br_unrecorded_lookaround", "ab", "a(?=b)", refused()),
        (
            "br_unrecorded_prop_name",
            "\u{3b1}",
            r"\p{Greek}",
            found("\u{3b1}"),
        ),
        ("br_unrecorded_flag_combo", "Ab", "(?is)ab", found("Ab")),
        ("br_unrecorded_class_fold", "B", "(?i)[a-c]", found("B")),
        ("br_unrecorded_nested_class", "a", "[a[b]]", found("a")),
        ("br_unrecorded_escape", "a\nb", r"a\nb", found("a\nb")),
    ]
}

#[test]
fn the_construct_function_profile_matrix_answers_as_recorded_or_stays_unobserved() {
    let table = rows();
    let mut cells = 0;
    for (construct, label) in RECORDED {
        let row = table.iter().find(|row| row.label == label).unwrap();
        for name in FUNCTIONS {
            for mode in [Unrecorded::Refuse, Unrecorded::OfficialEmulator] {
                assert_eq!(
                    outcome(name, &row.subject, &row.pattern, mode),
                    row.answers[name],
                    "{construct} {name} {mode:?}"
                );
                cells += 1;
            }
        }
    }
    for (construct, subject, pattern, emulator) in unrecorded() {
        for (index, name) in FUNCTIONS.into_iter().enumerate() {
            assert_eq!(
                outcome(name, subject, pattern, Unrecorded::Refuse),
                json!({"kind": "unimplemented"}),
                "{construct} {name} strict"
            );
            assert_eq!(
                outcome(name, subject, pattern, Unrecorded::OfficialEmulator),
                emulator[index],
                "{construct} {name} emulator"
            );
            cells += 2;
        }
    }
    assert_eq!(cells, 25 * 4 * 2);
}

#[test]
fn several_capture_groups_are_refused_only_by_find_and_find_all() {
    for mode in [Unrecorded::Refuse, Unrecorded::OfficialEmulator] {
        for pattern in ["(a)(b)", "(a)|(b)", "((a))b", "(a)(b)?"] {
            for name in ["regex_contains", "regex_match"] {
                assert_eq!(
                    outcome(name, "ab", pattern, mode)["kind"],
                    "bool",
                    "{pattern} {name}"
                );
            }
            for name in ["regex_find", "regex_find_all"] {
                assert_eq!(
                    outcome(name, "ab", pattern, mode),
                    json!({"kind": "refused-captures"}),
                    "{pattern} {name}"
                );
            }
        }
        // One group is fine, and an unmatched optional group is null.
        assert_eq!(
            outcome("regex_find_all", "abab", "(a)|b", mode),
            json!({"kind": "array", "items": [
                {"kind": "string", "value": "a"}, {"kind": "null"},
                {"kind": "string", "value": "a"}, {"kind": "null"},
            ]})
        );
    }
}
