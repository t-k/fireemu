//! Tests of `analyze` (the pattern rewrite and validation) and of the ASCII-class rewrite against
//! an oracle written as plain character predicates, checked against the recorded rows first.

use super::analysis::{analyze, apply_edits, MAX_PATTERN_BYTES, MAX_REWRITTEN_BYTES};
use super::replay::{outcome, rows};
use fireemu_core_firestore::pipeline_exec::{RegexError, Unrecorded};
use proptest::prelude::*;
use serde_json::json;

const STRICT: Unrecorded = Unrecorded::Refuse;
const EMULATOR: Unrecorded = Unrecorded::OfficialEmulator;
const BOTH: [Unrecorded; 2] = [STRICT, EMULATOR];

fn rewritten(pattern: &str, mode: Unrecorded) -> String {
    analyze(pattern, mode)
        .unwrap_or_else(|error| panic!("{pattern:?} {mode:?}: {error:?}"))
        .pattern
}

#[test]
fn shorthand_classes_and_boundaries_become_ascii_forms_in_both_profiles() {
    for mode in BOTH {
        for (pattern, expected) in [
            (r"\d", "[0-9]"),
            (r"\D", "[^0-9]"),
            (r"\w", "[0-9A-Za-z_]"),
            (r"\W", "[^0-9A-Za-z_]"),
            (r"\s", r"[\t\n\x0B\x0C\r\x20]"),
            (r"\S", r"[^\t\n\x0B\x0C\r\x20]"),
            (r"\b", r"(?-u:\b)"),
            (r"\B", r"(?-u:\B)"),
            (r"a\sb", r"a[\t\n\x0B\x0C\r\x20]b"),
            (r"\d+\.\d*", r"[0-9]+\.[0-9]*"),
            (r"[\d]", "[0-9]"),
            (r"[\w]", "[0-9A-Za-z_]"),
            (r"[^\d]", "[^0-9]"),
            (r"[\d\s]", r"[0-9\t\n\x0B\x0C\r\x20]"),
            (r"[a\dz]", "[a0-9z]"),
            (r"[\W]", "[[^0-9A-Za-z_]]"),
            (r"[\D]", "[[^0-9]]"),
            (r"\\d", r"\\d"),
            (r"[\\d]", r"[\\d]"),
            (r"\p{Nd}+", r"\p{Nd}+"),
            (r"\pL", r"\pL"),
        ] {
            assert_eq!(rewritten(pattern, mode), expected, "{pattern} {mode:?}");
        }
    }
}

#[test]
fn inline_flags_are_resolved_into_ascii_semantics() {
    for mode in BOTH {
        for (pattern, expected) in [
            ("(?i)ab", "[aA][bB]"),
            ("(?i:a)b", "(?:[aA])b"),
            ("(?i)a(?-i)b", "[aA]b"),
            ("(?i)é", "é"),
            ("(?i)k1", "[kK]1"),
            ("(?U)a+", "a+"),
            ("(?u)a", "a"),
            ("(?-u)a", "a"),
            ("(?s)a.b", "(?s)a.b"),
            ("a(?i)b|c", "a[bB]|[cC]"),
            ("(a(?i)b)c", "(a[bB])c"),
        ] {
            assert_eq!(rewritten(pattern, mode), expected, "{pattern} {mode:?}");
        }
    }
    // Unrecorded, so only the emulator profile evaluates them.
    for (pattern, expected) in [
        ("(?is)a.", "(?s)[aA]."),
        ("(?x)a b", "(?x)a b"),
        ("(?R)a", "(?R)a"),
        ("(?-s)a", "(?-s)a"),
        ("(?s-x)a", "(?s-x)a"),
        ("(?-sxR)a", "(?-sxR)a"),
        ("(?is-xR)a", "(?s-xR)[aA]"),
        ("(?-m)a", "a"),
        ("(?-m:a)", "(?:a)"),
        ("(?i-s:a)", "(?-s:[aA])"),
        ("(?i)[a-c]", "[a-cA-C]"),
        ("(?i)[^k]", "[^kK]"),
        ("(?i)[x-z0]", "[x-zX-Z0]"),
        ("(?i)[a-z]", "[a-zA-Z]"),
        ("(?i)[Z-a]", "[Z-aAz]"),
    ] {
        assert_eq!(rewritten(pattern, EMULATOR), expected, "{pattern}");
    }
}

#[test]
fn capture_groups_are_counted_without_counting_groups_that_do_not_capture() {
    for mode in BOTH {
        for (pattern, groups) in [
            ("a", 0),
            ("(?:a)", 0),
            ("(?i:a)", 0),
            ("(a)", 1),
            ("(?P<x>a)b", 1),
            ("(a)(b)", 2),
            ("((a))", 2),
            ("(a)|(b)", 2),
            ("(a)(b)?", 2),
            (r"\(a\)", 0),
            ("[(]", 0),
            ("(a*)", 1),
        ] {
            assert_eq!(
                analyze(pattern, mode).unwrap().capture_groups,
                groups,
                "{pattern}"
            );
        }
    }
}

#[test]
fn posix_classes_and_multiline_are_syntax_errors_in_both_profiles() {
    for mode in BOTH {
        for pattern in [
            "[[:digit:]]",
            "[[:word:]]",
            "[[:space:]]",
            "[[:cntrl:]]",
            "[[:alpha:]x]",
            "[^[:digit:]]",
            "(?m)^b$",
            "(?m:a)",
            "(?im:a)",
            "a(?m)b",
            "(?i:(?m)a)",
            "((?m)a)",
        ] {
            assert_eq!(
                analyze(pattern, mode).map(|_| ()),
                Err(RegexError::InvalidSyntax),
                "{pattern} {mode:?}"
            );
        }
    }
}

#[test]
fn recorded_syntax_errors_are_syntax_errors_and_other_parse_failures_are_unobserved_in_strict() {
    // Recorded: an unclosed group or class and a trailing backslash. Kept from before this
    // change, which let the engine decide them: an unopened group and a missing repetition operand.
    for mode in BOTH {
        for pattern in ["(", "[", "\\", "a)", "*a", "a(b", "a[b"] {
            assert_eq!(
                analyze(pattern, mode).map(|_| ()),
                Err(RegexError::InvalidSyntax),
                "{pattern:?} {mode:?}"
            );
        }
    }
    // Any other failure of the parser says nothing about production: strict refuses it as
    // unobserved, the emulator profile reports the engine's syntax error.
    for pattern in [r"\Q", r"\C", "a{2,1}", r"\xZ", "(?<n", "(?P<n", "[z-a]"] {
        assert_eq!(
            analyze(pattern, STRICT).map(|_| ()),
            Err(RegexError::Unobserved),
            "{pattern:?}"
        );
        assert_eq!(
            analyze(pattern, EMULATOR).map(|_| ()),
            Err(RegexError::InvalidSyntax),
            "{pattern:?}"
        );
    }
    // The parser accepts an unknown property name; the engine rejects it later.
    assert_eq!(
        analyze(r"\p{NoSuchClass}", STRICT).map(|_| ()),
        Err(RegexError::Unobserved)
    );
    assert!(analyze(r"\p{NoSuchClass}", EMULATOR).is_ok());
}

#[test]
fn constructs_no_row_records_are_unobserved_in_strict_and_left_to_the_engine_in_the_emulator() {
    for pattern in [
        "(?x)a b",
        r"\A",
        r"\z",
        r"a\z",
        "a{2}",
        "a{2,}",
        r"\p{Greek}",
        r"\pN",
        r"\PL",
        r"\p{L}",
        "[\\p{L}]",
        "[a&&b]",
        "[a--b]",
        "[a~~b]",
        "[a[b]]",
        "(?<n>a)",
        "(?is)a",
        "(?-s)a",
        "(?-U)a",
        "(?s:a)",
        "(?u:a)",
        "(?R)a",
        "(?U)[a-z]+",
        "(?U)a+?",
        "(?U).+",
        "(?U)a.",
        r"[\x01-\n]",
        r"[\n-\x7f]",
        r"(?U)\d+",
        "(?i)[a-c]",
        r"(?i)\w",
        r"\n",
        r"\r",
        r"\u{41}",
        r"\v",
        r"\b{start}",
    ] {
        assert_eq!(
            analyze(pattern, STRICT).map(|_| ()),
            Err(RegexError::Unobserved),
            "{pattern:?}"
        );
    }
    // The engine decides in the emulator profile: these it accepts.
    for pattern in [
        "(?x)a b",
        r"\A",
        r"a\z",
        "a{2}",
        r"\p{Greek}",
        r"\pN",
        "[a--b]",
        "[a[b]]",
        "(?<n>a)",
        "(?-s)a",
        "(?U)[a-z]+",
        "(?i)[a-c]",
        r"\n",
        "(?is)a",
        r"(?i)\w",
    ] {
        analyze(pattern, EMULATOR).unwrap_or_else(|error| panic!("{pattern:?}: {error:?}"));
    }
}

#[test]
fn a_nesting_deeper_than_the_parser_allows_is_a_resource_limit_not_a_syntax_error() {
    let deep = format!("{}a{}", "(".repeat(1000), ")".repeat(1000));
    for mode in BOTH {
        assert_eq!(
            analyze(&deep, mode).map(|_| ()),
            Err(RegexError::ResourceLimit)
        );
    }
}

#[test]
fn recorded_literal_and_class_forms_are_accepted_in_strict() {
    for pattern in [
        "",
        "abc",
        "o W",
        "héllo ☃😀",
        r"\\",
        r"a\\b",
        r"[\\]",
        r"\x{5c}",
        r"\x{a0}",
        r"a\x01b",
        r"[\x00-\x1f]",
        r"a\tb",
        r"\.",
        r"\[",
        r"\{",
        r"\?",
        "[a-z]",
        "[^a]",
        "a*",
        "a+",
        "a?",
        "a|b",
        "^b$",
        "(?:ab)",
        "(a)",
        "(?P<x>a)b",
        "x*",
        "(a*)",
        "(?i)ab",
        "(?i:a)b",
        "(?i)a(?-i)b",
        "(?s)a.b",
        "(?u)a",
        "(?-u)a",
        "(?U)a+",
        r"\d",
        r"\W+",
        r"\bcaf\b",
        r"\B",
        r"\pL",
        r"\p{Nd}+",
        r"[\d]",
        r"[\w]",
    ] {
        analyze(pattern, STRICT).unwrap_or_else(|error| panic!("{pattern:?}: {error:?}"));
    }
}

fn atom() -> impl Strategy<Value = String> {
    prop::sample::select(vec![
        "a", "b", "z", "0", " ", "é", "☃", ".", r"\.", r"\\", r"\[", r"\(", r"\x01", r"\x{5c}",
        r"\t", "[a-z]", "[^a]", r"[\\]", "(?:ab)", "(a)", "^", "$", "(?P<x>a)",
    ])
    .prop_map(str::to_owned)
}

fn suffix() -> impl Strategy<Value = &'static str> {
    prop::sample::select(vec!["", "", "*", "+", "?"])
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    /// A pattern with no shorthand class, boundary or case-folding flag is handed to the engine
    /// as written: the rewrite never touches a literal, a punctuation or hex escape, a plain class
    /// or a group.
    #[test]
    fn a_pattern_without_shorthand_tokens_is_unchanged(
        parts in prop::collection::vec((atom(), suffix()), 0..6),
        alternate in any::<bool>(),
    ) {
        let joiner = if alternate { "|" } else { "" };
        let pattern = parts
            .iter()
            .map(|(atom, suffix)| format!("{atom}{suffix}"))
            .collect::<Vec<_>>()
            .join(joiner);
        for mode in BOTH {
            prop_assume!(analyze(&pattern, EMULATOR).is_ok());
            let analysis = analyze(&pattern, mode).unwrap();
            prop_assert_eq!(&analysis.pattern, &pattern);
        }
    }

    /// Escaped backslashes before a shorthand letter are literals, so the rewrite leaves them.
    #[test]
    fn an_escaped_backslash_before_a_shorthand_letter_is_never_rewritten(
        letter in prop::sample::select(vec!['d', 'D', 'w', 'W', 's', 'S', 'b', 'B']),
        count in 1usize..4,
    ) {
        let pattern = format!("{}{letter}", r"\\".repeat(count));
        for mode in BOTH {
            prop_assert_eq!(rewritten(&pattern, mode), pattern.clone());
        }
    }
}

// The oracle: plain predicates over characters, no pattern text involved.

fn is_digit(c: char) -> bool {
    c.is_ascii_digit()
}
fn is_word(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}
fn is_space(c: char) -> bool {
    matches!(c, '\t' | '\n' | '\u{b}' | '\u{c}' | '\r' | ' ')
}

/// What `regex_find_all(subject, "\\<letter>")` answers for the oracle: each satisfying char.
fn single_class_matches(subject: &str, predicate: fn(char) -> bool, negated: bool) -> Vec<String> {
    subject
        .chars()
        .filter(|c| predicate(*c) != negated)
        .map(String::from)
        .collect()
}

fn strings(items: &[String]) -> serde_json::Value {
    json!({
        "kind": "array",
        "items": items.iter().map(|s| json!({"kind": "string", "value": s})).collect::<Vec<_>>(),
    })
}

/// Number of ASCII word boundaries of `subject`: char positions (including both ends) where
/// exactly one side is an ASCII word character.
fn boundaries(subject: &str) -> usize {
    let chars: Vec<char> = subject.chars().collect();
    (0..=chars.len())
        .filter(|&i| {
            let before = i > 0 && is_word(chars[i - 1]);
            let after = i < chars.len() && is_word(chars[i]);
            before != after
        })
        .count()
}

/// A shorthand class, its oracle predicate and whether the class is the negated form.
type ClassOracle = (&'static str, fn(char) -> bool, bool);

const CLASSES: [ClassOracle; 6] = [
    (r"\d", is_digit, false),
    (r"\D", is_digit, true),
    (r"\w", is_word, false),
    (r"\W", is_word, true),
    (r"\s", is_space, false),
    (r"\S", is_space, true),
];

#[test]
fn the_oracle_predicates_agree_with_every_recorded_single_class_row() {
    let mut checked = 0;
    for row in rows() {
        let Some((_, predicate, negated)) = CLASSES.iter().find(|c| c.0 == row.pattern) else {
            continue;
        };
        let expected = single_class_matches(&row.subject, *predicate, *negated);
        assert_eq!(
            row.answers["regex_find_all"],
            strings(&expected),
            "{}",
            row.label
        );
        checked += 1;
    }
    assert!(checked >= 5, "{checked}");
    for row in rows() {
        let counted = match row.pattern.as_str() {
            r"\b" => boundaries(&row.subject),
            r"\B" => row.subject.chars().count() + 1 - boundaries(&row.subject),
            _ => continue,
        };
        assert_eq!(
            row.answers["regex_find_all"]["items"]
                .as_array()
                .unwrap()
                .len(),
            counted,
            "{}",
            row.label
        );
    }
}

fn subject_char() -> impl Strategy<Value = char> {
    prop_oneof![
        4 => prop::sample::select(vec![
            'a', 'Z', '0', '9', '_', ' ', '\t', '\n', '\u{b}', '\u{c}', '\r', '-', '.',
            '\u{a0}', '\u{85}', '\u{2003}', '\u{661}', '\u{e9}', '\u{212a}', '\u{3c2}', '\u{1}',
            '\u{7f}', '☃', '😀',
        ]),
        1 => any::<char>(),
    ]
}

fn subject() -> impl Strategy<Value = String> {
    prop::collection::vec(subject_char(), 0..12).prop_map(|chars| chars.into_iter().collect())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(96))]

    #[test]
    fn shorthand_classes_match_exactly_the_oracle_characters(subject in subject()) {
        for (pattern, predicate, negated) in CLASSES {
            let expected = strings(&single_class_matches(&subject, predicate, negated));
            let bracket = format!("[{pattern}]");
            let negated_bracket = format!("[^{pattern}]");
            for mode in BOTH {
                prop_assert_eq!(&outcome("regex_find_all", &subject, pattern, mode), &expected, "{}", pattern);
                prop_assert_eq!(&outcome("regex_find_all", &subject, &bracket, mode), &expected, "{}", bracket);
                let complement = strings(&single_class_matches(&subject, predicate, !negated));
                prop_assert_eq!(&outcome("regex_find_all", &subject, &negated_bracket, mode), &complement, "{}", negated_bracket);
            }
        }
    }

    #[test]
    fn word_boundaries_are_counted_as_the_oracle_counts_them(subject in subject()) {
        let total = subject.chars().count() + 1;
        for mode in BOTH {
            let found = outcome("regex_find_all", &subject, r"\b", mode);
            prop_assert_eq!(found["items"].as_array().unwrap().len(), boundaries(&subject));
            let not_found = outcome("regex_find_all", &subject, r"\B", mode);
            prop_assert_eq!(not_found["items"].as_array().unwrap().len(), total - boundaries(&subject));
            prop_assert_eq!(
                outcome("regex_contains", &subject, r"\b", mode),
                json!({"kind": "bool", "value": boundaries(&subject) > 0})
            );
        }
    }

    #[test]
    fn case_insensitive_literals_fold_ascii_only(
        subject in subject(),
        letter in prop::sample::select(vec!['a', 'k', 's', 'z', 'K', 'Q']),
    ) {
        let expected = subject.chars().any(|c| c.eq_ignore_ascii_case(&letter));
        for mode in BOTH {
            prop_assert_eq!(
                outcome("regex_contains", &subject, &format!("(?i){letter}"), mode),
                json!({"kind": "bool", "value": expected})
            );
        }
    }
}

#[test]
fn the_unicode_property_classes_stay_unicode() {
    for mode in BOTH {
        assert_eq!(
            outcome("regex_find_all", "a\u{e9}\u{661}1_", r"\pL", mode),
            strings(&["a".to_owned(), "\u{e9}".to_owned()])
        );
        assert_eq!(
            outcome("regex_find_all", "a\u{e9}\u{661}1_", r"\p{Nd}", mode),
            strings(&["\u{661}".to_owned(), "1".to_owned()])
        );
    }
}

// Preprocessing is linear in the pattern and bounded before it runs.

/// The patterns of every recorded row and some more, with what `analyze` answered before the
/// edits were applied in one pass (generated from the repeated-`replace_range` implementation).
#[test]
fn the_single_pass_rewrite_gives_the_output_of_the_previous_rewrite_on_every_fixture_pattern() {
    let golden: serde_json::Value =
        serde_json::from_str(include_str!("rewritten_golden.json")).unwrap();
    let mut checked = 0;
    for (key, mode) in [("strict", STRICT), ("emulator", EMULATOR)] {
        for entry in golden[key].as_array().unwrap() {
            let pattern = entry["pattern"].as_str().unwrap();
            match analyze(pattern, mode) {
                Ok(analysis) => {
                    assert_eq!(entry["ok"], analysis.pattern.as_str(), "{key} {pattern:?}");
                    assert_eq!(
                        entry["groups"], analysis.capture_groups,
                        "{key} {pattern:?}"
                    );
                }
                Err(error) => assert_eq!(entry["err"], format!("{error:?}"), "{key} {pattern:?}"),
            }
            checked += 1;
        }
    }
    assert!(checked >= 2 * 68, "{checked}");
    // Every recorded pattern is in the golden table.
    for row in rows() {
        assert!(
            golden["strict"]
                .as_array()
                .unwrap()
                .iter()
                .any(|entry| entry["pattern"] == row.pattern.as_str()),
            "{}",
            row.label
        );
    }
}

/// The edits applied from the end with `replace_range`, the way the first version did it.
fn apply_edits_by_replace_range(pattern: &str, edits: &[(usize, usize, String)]) -> String {
    let mut result = pattern.to_owned();
    for (start, end, replacement) in edits.iter().rev() {
        result.replace_range(*start..*end, replacement);
    }
    result
}

fn edit_case() -> impl Strategy<Value = (String, Vec<(usize, usize, String)>)> {
    (
        prop::collection::vec(
            prop::sample::select(vec!['a', 'b', '\\', '[', 'é', '☃', '😀']),
            0..24,
        ),
        prop::collection::vec(
            (
                any::<prop::sample::Index>(),
                any::<prop::sample::Index>(),
                "[a-z\\[\\]^0-9é]{0,8}",
            ),
            0..6,
        ),
    )
        .prop_map(|(chars, picks)| {
            let text: String = chars.iter().collect();
            let mut bounds: Vec<usize> = text.char_indices().map(|(i, _)| i).collect();
            bounds.push(text.len());
            let mut points: Vec<usize> = picks
                .iter()
                .flat_map(|(a, b, _)| {
                    [bounds[a.index(bounds.len())], bounds[b.index(bounds.len())]]
                })
                .collect();
            points.sort_unstable();
            let edits = picks
                .iter()
                .zip(points.chunks(2))
                .map(|((_, _, replacement), pair)| (pair[0], pair[1], replacement.clone()))
                .collect();
            (text, edits)
        })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn applying_edits_in_one_pass_equals_applying_them_one_by_one(case in edit_case()) {
        let (text, edits) = case;
        // The edits are ordered and do not overlap (points are sorted and paired).
        prop_assert!(edits.windows(2).all(|pair| pair[0].1 <= pair[1].0));
        prop_assert_eq!(
            apply_edits(&text, &edits),
            apply_edits_by_replace_range(&text, &edits)
        );
    }
}

#[test]
fn ten_thousand_consecutive_shorthand_tokens_rewrite_quickly() {
    let pattern = r"\w".repeat(10_000);
    let started = std::time::Instant::now();
    for mode in BOTH {
        let analysis = analyze(&pattern, mode).unwrap();
        assert_eq!(analysis.pattern, "[0-9A-Za-z_]".repeat(10_000));
    }
    // The rewrite itself takes a few milliseconds; the bound only catches a quadratic blow-up.
    assert!(
        started.elapsed() < std::time::Duration::from_secs(5),
        "{:?}",
        started.elapsed()
    );
    for mode in BOTH {
        assert_eq!(
            outcome("regex_match", &"a".repeat(10_000), &pattern, mode),
            json!({"kind": "bool", "value": true})
        );
    }
}

#[test]
fn a_pattern_over_the_length_limit_or_expanding_past_the_rewritten_limit_is_a_resource_limit() {
    for mode in BOTH {
        assert!(analyze(&"a".repeat(MAX_PATTERN_BYTES), mode).is_ok());
        assert_eq!(
            analyze(&"a".repeat(MAX_PATTERN_BYTES + 1), mode).map(|_| ()),
            Err(RegexError::ResourceLimit)
        );
        // An over-long pattern is refused before it is parsed, so an invalid one is no different.
        assert_eq!(
            analyze(&"(".repeat(MAX_PATTERN_BYTES + 1), mode).map(|_| ()),
            Err(RegexError::ResourceLimit)
        );
        // `\S` is two bytes and becomes 21: this pattern is within the length limit and its
        // rewrite is not.
        let wide = r"\S".repeat(MAX_PATTERN_BYTES / 2);
        assert!(wide.len() <= MAX_PATTERN_BYTES);
        assert_eq!(
            analyze(&wide, mode).map(|_| ()),
            Err(RegexError::ResourceLimit)
        );
        // Just under the rewritten limit is accepted.
        let fits = r"\S".repeat(MAX_REWRITTEN_BYTES / 21);
        let analysis = analyze(&fits, mode).unwrap();
        assert!(analysis.pattern.len() <= MAX_REWRITTEN_BYTES);
    }
    assert!(MAX_PATTERN_BYTES < MAX_REWRITTEN_BYTES);
}
