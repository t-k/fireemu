//! RE2's ASCII POSIX/Perl classes must not inherit Unicode property membership.
//!
//! Contract: <https://github.com/google/re2/wiki/Syntax> (ASCII and Perl class tables).
//! This is native local regression coverage, not a production observation.
#![allow(clippy::invalid_regex)]
#![allow(clippy::unicode_not_nfc)]

use fireemu_core_rules::regex::Regex;

const EXPANSIONS: [(&str, &str); 14] = [
    ("alnum", r"[0-9A-Za-z]"),
    ("alpha", r"[A-Za-z]"),
    ("ascii", r"[\x00-\x7F]"),
    ("blank", r"[\t ]"),
    ("cntrl", r"[\x00-\x1F\x7F]"),
    ("digit", r"[0-9]"),
    ("graph", r"[!-~]"),
    ("lower", r"[a-z]"),
    ("print", r"[ -~]"),
    ("punct", r"[!-/:-@\[-`{-~]"),
    ("space", r"[\t\n\v\f\r ]"),
    ("upper", r"[A-Z]"),
    ("word", r"[0-9A-Za-z_]"),
    ("xdigit", r"[0-9A-Fa-f]"),
];

fn check(pattern: &str, text: &str, expected: bool) {
    let regex = Regex::new(pattern).unwrap_or_else(|e| panic!("{pattern:?}: {e}"));
    assert_eq!(
        regex.is_full_match(text),
        Ok(expected),
        "{pattern:?}, {text:?}"
    );
}

fn check_polarities(name: &str, text: &str, expected: bool, fold: bool) {
    let prefix = if fold { "(?i)" } else { "" };
    for (pattern, want) in [
        (format!("{prefix}[[:{name}:]]"), expected),
        (format!("{prefix}[[:^{name}:]]"), !expected),
        (format!("{prefix}[^[:{name}:]]"), !expected),
        (format!("{prefix}[^[:^{name}:]]"), expected),
    ] {
        check(&pattern, text, want);
    }
}

#[test]
fn all_fourteen_posix_classes_agree_with_explicit_ranges_over_ascii() {
    for (name, expansion) in EXPANSIONS {
        let named = Regex::new(&format!("[[:{name}:]]")).unwrap();
        let expanded = Regex::new(expansion).unwrap();
        for codepoint in 0..=127 {
            let text = char::from_u32(codepoint).unwrap().to_string();
            assert_eq!(
                named.is_full_match(&text),
                expanded.is_full_match(&text),
                "{name} at U+{codepoint:04X}"
            );
        }
    }
}

#[test]
fn positive_posix_classes_exclude_non_ascii_without_case_folding() {
    for (name, _) in EXPANSIONS {
        for text in [
            "é", "É", "日", "語", "α", "Ж", "１", "١", "Ⅳ", "²", "—", "！", "😀", "\u{0085}",
            "\u{009f}", "\u{00a0}", "\u{2003}", "\u{200b}", "\u{2028}", "\u{0301}", "\u{017f}",
            "\u{212a}",
        ] {
            check_polarities(name, text, false, false);
        }
    }
}

#[test]
fn inner_outer_and_double_negations_have_the_correct_ascii_complements() {
    for (name, expansion) in EXPANSIONS {
        let expanded = Regex::new(expansion).unwrap();
        for codepoint in 0..=127 {
            let text = char::from_u32(codepoint).unwrap().to_string();
            check_polarities(name, &text, expanded.is_full_match(&text).unwrap(), false);
        }
    }
}

#[test]
fn class_names_are_lowercase_posix_names_not_unicode_aliases() {
    for invalid in [
        "L", "Lu", "Ll", "N", "Nd", "Cc", "P", "Zs", "Alpha", "Alnum", "ASCII", "Upper", "Lower",
        "Number", "Word", "Print", "Graph", "Blank",
    ] {
        for pattern in [format!("[[:{invalid}:]]"), format!("[[:^{invalid}:]]")] {
            assert!(Regex::new(&pattern).is_err(), "{pattern}");
        }
    }
}

#[test]
fn posix_unicode_and_literal_members_remain_distinct_in_unions() {
    check(r"[[:alpha:]\p{L}]", "日", true);
    check(r"[[:alpha:]\p{L}]", "7", false);
    check("[[:alpha:]日]", "日", true);
    check("[[:alpha:]日]", "語", false);
    check("[[:^alpha:]A]", "A", true);
    check("[[:^alpha:]A]", "B", false);
    check("[[:^alpha:]A]", "日", true);
    check("[[:alpha:][:digit:]_]", "_", true);
    check("[[:alpha:][:digit:]_]", "１", false);
}

#[test]
fn unicode_letter_and_case_properties_keep_their_existing_non_ascii_controls() {
    check(r"\p{L}+", "日本語éΩ", true);
    check(r"\P{L}+", "123!", true);
    check(r"\P{L}", "日", false);
    check(r"[\p{L}]", "é", true);
    check(r"\p{Lu}", "É", true);
    check(r"\p{Ll}", "é", true);
    check(r"\p{Lu}", "é", false);
    check(r"\p{Cc}", "\u{0085}", true);
    check("[[:cntrl:]]", "\u{0085}", false);
}

#[test]
fn perl_space_excludes_vertical_tab_while_posix_space_includes_it() {
    for text in [" ", "\t", "\n", "\r", "\u{000c}"] {
        check(r"\s", text, true);
        check(r"\S", text, false);
        check("[[:space:]]", text, true);
    }
    for pattern in [r"\s", r"[\s]", r"[^\S]", r"(?i)\s"] {
        check(pattern, "\u{000b}", false);
    }
    for pattern in [r"\S", r"[\S]", r"[^\s]", r"(?i)\S"] {
        check(pattern, "\u{000b}", true);
    }
    check("[[:space:]]", "\u{000b}", true);
    check("[[:^space:]]", "\u{000b}", false);
}

#[test]
fn ascii_whitespace_rejects_unicode_whitespace() {
    for text in [
        "\u{0085}", "\u{00a0}", "\u{1680}", "\u{2003}", "\u{2028}", "\u{3000}",
    ] {
        check("[[:space:]]", text, false);
        check(r"\s", text, false);
        check(r"\S", text, true);
    }
}

#[test]
fn posix_print_graph_control_and_blank_keep_exact_edges() {
    for (name, text, want) in [
        ("print", " ", true),
        ("graph", " ", false),
        ("blank", " ", true),
        ("print", "~", true),
        ("graph", "~", true),
        ("cntrl", "~", false),
        ("print", "\u{007f}", false),
        ("cntrl", "\u{007f}", true),
        ("ascii", "\u{007f}", true),
        ("ascii", "\u{0080}", false),
        ("cntrl", "\0", true),
        ("graph", "!", true),
        ("blank", "\t", true),
        ("blank", "\n", false),
        ("punct", "_", true),
        ("word", "_", true),
        ("alnum", "_", false),
        ("xdigit", "F", true),
        ("xdigit", "G", false),
    ] {
        check_polarities(name, text, want, false);
    }
}

#[test]
fn case_insensitive_positive_ascii_classes_fold_both_ascii_cases() {
    for name in [
        "alpha", "alnum", "lower", "upper", "word", "ascii", "graph", "print",
    ] {
        for text in ["a", "A", "z", "Z"] {
            check_polarities(name, text, true, true);
        }
    }
    for name in ["digit", "blank", "cntrl", "punct", "space"] {
        check_polarities(name, "A", false, true);
    }
}

#[test]
fn case_folding_precedes_inner_negation() {
    for name in ["lower", "upper"] {
        for text in ["a", "A", "k", "K", "s", "S"] {
            check_polarities(name, text, true, true);
        }
        for text in ["0", "_", "!", "é"] {
            check_polarities(name, text, false, true);
        }
    }
}

#[test]
fn ascii_simple_fold_cycles_include_kelvin_sign_and_long_s() {
    for name in [
        "alpha", "alnum", "lower", "upper", "word", "ascii", "graph", "print",
    ] {
        for text in ["\u{017f}", "\u{212a}"] {
            check_polarities(name, text, true, true);
        }
    }
    for name in ["digit", "blank", "cntrl", "punct", "space", "xdigit"] {
        for text in ["\u{017f}", "\u{212a}"] {
            check_polarities(name, text, false, true);
        }
    }
}

#[test]
fn ascii_simple_folding_does_not_expand_sharp_s_or_turkish_i() {
    for name in [
        "alpha", "alnum", "lower", "upper", "word", "ascii", "graph", "print",
    ] {
        for text in ["ß", "\u{0130}", "\u{0131}", "é", "日"] {
            check_polarities(name, text, false, true);
        }
    }
}

#[test]
fn perl_word_and_its_complement_use_the_same_simple_fold_closure() {
    for text in ["a", "A", "_", "5", "ſ", "K"] {
        for (pattern, expected) in [
            (r"(?i)\w", true),
            (r"(?i)[\w]", true),
            (r"(?i)\W", false),
            (r"(?i)[^\w]", false),
            (r"(?i)[^\W]", true),
        ] {
            check(pattern, text, expected);
        }
    }
    for text in ["ß", "İ", "ı", "日", "!", " "] {
        check(r"(?i)\w", text, false);
        check(r"(?i)\W", text, true);
    }
    for text in ["ſ", "K"] {
        check(r"\w", text, false);
    }
}

#[test]
fn negated_ascii_members_in_unions_do_not_absorb_excluded_letters() {
    check("(?i)[[:^lower:]_]", "A", false);
    check("(?i)[[:^lower:]_]", "_", true);
    check("(?i)[[:^lower:]A]", "A", true);
    check("(?i)[[:^lower:]A]", "a", true);
    check("(?i)[[:^lower:]A]", "B", false);
    check("(?i)[^[:^lower:]_]", "A", true);
    check("(?i)[^[:^lower:]_]", "_", false);
}

#[test]
fn repeats_and_alternation_use_ascii_membership_on_every_path() {
    check("[[:alpha:]]+", "AZaz", true);
    check("[[:alpha:]]+", "A日z", false);
    check("(?:[[:alpha:]]|[[:digit:]])+", "A1b2", true);
    check("(?:[[:alpha:]]|[[:digit:]])+", "A١b2", false);
    check("(?:[[:alpha:]]x|[[:digit:]]y)+", "ax1y", true);
    check("(?:[[:alpha:]]x|[[:digit:]]y)+", "日x1y", false);
}

#[test]
fn repeated_immutable_regex_does_not_retain_previous_match_state() {
    let regex = Regex::new("[[:alpha:]]+").unwrap();
    for _ in 0..5 {
        assert_eq!(regex.is_full_match("日"), Ok(false));
        assert_eq!(regex.is_full_match("abc"), Ok(true));
        assert_eq!(regex.is_full_match(""), Ok(false));
    }
}

#[test]
fn replacement_preserves_non_ascii_text_outside_ascii_matches() {
    assert_eq!(
        Regex::new("[[:alpha:]]+")
            .unwrap()
            .replace_all("éabc日本Z", "_"),
        Ok("é_日本_".to_owned())
    );
    assert_eq!(
        Regex::new("[[:^alpha:]]+")
            .unwrap()
            .replace_all("éabc日本Z", "_"),
        Ok("_abc_Z".to_owned())
    );
    assert_eq!(
        Regex::new(r"\p{L}+").unwrap().replace_all("éabc日本Z", "_"),
        Ok("_".to_owned())
    );
}

#[test]
fn replacement_captures_preserve_original_case_and_spelling() {
    assert_eq!(
        Regex::new("(?i)([[:lower:]]+)")
            .unwrap()
            .replace_all("KAéſ", "<$1>"),
        Ok("<KA>é<ſ>".to_owned())
    );
}

#[test]
fn replacement_distinguishes_perl_space_from_posix_space() {
    let text = "a\u{000b}b c\u{00a0}d";
    assert_eq!(
        Regex::new(r"\s+").unwrap().replace_all(text, "_"),
        Ok("a\u{000b}b_c\u{00a0}d".to_owned())
    );
    assert_eq!(
        Regex::new("[[:space:]]+").unwrap().replace_all(text, "_"),
        Ok("a_b_c\u{00a0}d".to_owned())
    );
}

#[test]
fn long_posix_runs_keep_the_existing_bounded_matcher_path() {
    let regex = Regex::new("[[:alpha:]]+").unwrap();
    let diagnostics = regex.full_match_diagnostics(&"a".repeat(3_000));
    assert_eq!(diagnostics.result, Ok(true));
    assert!(diagnostics.maximum_depth <= 32);
    assert!(diagnostics.charged_steps <= 200_000);
    assert_eq!(
        regex.is_full_match(&format!("{}日", "a".repeat(3_000))),
        Ok(false)
    );
}
