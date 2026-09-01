//! RE2-style subset used by `string.matches()` / `string.replace()`.

// The lint mistakes this crate's `Regex::new` for the regex crate; invalid patterns are
// the point of some of these tests.
#![allow(clippy::invalid_regex)]

use fireemu_core_rules::regex::{Regex, RegexRuntimeError};

fn full(p: &str, s: &str) -> bool {
    Regex::new(p).unwrap().is_full_match(s).unwrap()
}

#[test]
fn matches_is_a_full_match_with_the_documented_syntax() {
    assert!(full("image/.*", "image/png"));
    assert!(!full("image/.*", "text/plain"));
    assert!(!full("image", "image/png"), "matches() anchors both ends");
    assert!(full("^image$", "image"));
    assert!(full("[a-z]+@[a-z]+\\.(com|jp)", "alice@example.jp"));
    assert!(!full("[a-z]+@[a-z]+\\.(com|jp)", "alice@example.org"));
    assert!(full("\\d{3}-\\d{4}", "123-4567"));
    assert!(!full("\\d{3}-\\d{4}", "12-4567"));
    assert!(full("[^/]+", "no-slash"));
    assert!(!full("[^/]+", "a/b"));
    assert!(full("a?b+c*", "bb"));
    assert!(full("(ab){2,3}", "ababab"));
    assert!(!full("(ab){2,3}", "abababab"));
    assert!(full("\\w+\\s\\w+", "hello world"));
    assert!(full("日本.*", "日本語のテキスト"));
    assert!(full("x*?", ""));
    assert!(full("(?:a|b)c", "bc"));
    assert!(!full("a.c", "a\nc"), ". does not match a newline");
    assert!(Regex::new("(unclosed").is_err());
    assert!(Regex::new("*bad").is_err());
    // The official runtime compiles these and answers `true`; a first differential run
    // recorded every one of them (`conformance/rules-matrix.json`, area `regex`).
    assert!(full("(?i)flags", "FLAGS"), "(?i) folds case");
    assert!(full("(?s)a.b", "a\nb"), "(?s) lets . cross a newline");
    assert!(full("[[:alpha:]][[:digit:]]", "a1"), "POSIX classes");
    assert!(full("\\p{L}+", "abc"), "Unicode classes");
    assert!(full("a\\x62c", "abc"), "hex escapes");
}

#[test]
fn replace_all_replaces_every_match_with_a_literal() {
    let re = Regex::new("[aeiou]").unwrap();
    assert_eq!(re.replace_all("banana", "_").unwrap(), "b_n_n_");
    let re = Regex::new("\\s+").unwrap();
    assert_eq!(re.replace_all("a  b\tc", "-").unwrap(), "a-b-c");
    let re = Regex::new("x").unwrap();
    assert_eq!(re.replace_all("none", "y").unwrap(), "none");
}

#[test]
fn pathological_patterns_report_step_budget_exhaustion() {
    let re = Regex::new("(a+)+b").unwrap();
    assert!(matches!(
        re.is_full_match(&"a".repeat(40)),
        Err(RegexRuntimeError::StepBudgetExceeded { current, maximum })
            if current > maximum
    ));
    assert!(matches!(
        re.replace_all(&"a".repeat(40), "replacement"),
        Err(RegexRuntimeError::StepBudgetExceeded { current, maximum })
            if current > maximum
    ));
}

#[test]
fn quantifier_group_escape_and_class_syntax_boundaries() {
    for ok in [
        "a{0,1000}",
        "a{1000}",
        "a{2,}",
        "(?:ab)+",
        "\\.",
        "\\ ",
        "\\-",
        "[a-c]",
        "[\\d]",
        "[-a]",
        "[a-]",
        "[\\w-]",
        "[^a]",
        "[]a]",
        "a+?",
        "a*?",
        "a??",
    ] {
        assert!(Regex::new(ok).is_ok(), "{ok}");
    }
    for bad in [
        "a{2,1}",
        "a{1001}",
        "a{0,1001}",
        "a{2",
        "(?P<n>a)",
        "(?=a)",
        "(?!a)",
        "(?<=a)",
        "(?<!a)",
        "\\q",
        "\\b",
        "[c-a]",
        "[a",
        "[\\b]",
        "(a",
    ] {
        assert!(Regex::new(bad).is_err(), "{bad}");
    }
    assert!(!Regex::new("(?=a)").unwrap_err().to_string().is_empty());
    // A backreference is RE2's other refusal, and the official compiler's too.
    assert!(Regex::new("(a)\\1").is_err());
}

#[test]
fn matching_boundaries_and_replace_all_edge_cases() {
    let re = |p: &str| Regex::new(p).unwrap();
    assert!(re("a{2,3}").is_full_match("aa").unwrap());
    assert!(re("a{2,3}").is_full_match("aaa").unwrap());
    assert!(!re("a{2,3}").is_full_match("a").unwrap());
    assert!(!re("a{2,3}").is_full_match("aaaa").unwrap());
    assert!(re("a{2,}").is_full_match(&"a".repeat(50)).unwrap());
    assert!(!re("a{3,}").is_full_match("aa").unwrap());
    assert!(
        !re(".").is_full_match("\n").unwrap(),
        "`.` never matches a newline"
    );
    assert!(re("[^a]").is_full_match("\n").unwrap());
    assert!(re("a|b|c").is_full_match("c").unwrap());
    assert!(re("^ab$").is_full_match("ab").unwrap());
    assert!(
        re("[a-c]+").is_full_match("cab").unwrap() && !re("[a-c]+").is_full_match("cad").unwrap()
    );
    assert!(
        re("[\\d]+").is_full_match("123").unwrap() && !re("[\\d]+").is_full_match("12a").unwrap()
    );
    assert!(re("\\.").is_full_match(".").unwrap() && !re("\\.").is_full_match("a").unwrap());
    assert!(re("[^\\d]").is_full_match("x").unwrap() && !re("[^\\d]").is_full_match("5").unwrap());
    assert!(
        re("(ab)*").is_full_match("abab").unwrap() && !re("(ab)*").is_full_match("aba").unwrap()
    );
    // replace_all: an empty match inserts the replacement before every character and at
    // the end; non-empty matches consume their text. An empty match right after a
    // non-empty one is emitted (JavaScript semantics: "baab".replace(/a*/g, "-")).
    assert_eq!(re("x*").replace_all("ab", "-").unwrap(), "-a-b-");
    assert_eq!(re("a*").replace_all("baab", "-").unwrap(), "-b--b-");
    assert_eq!(re("ab").replace_all("abab", "X").unwrap(), "XX");
    assert_eq!(re("a").replace_all("aaa", "bb").unwrap(), "bbbbbb");
    assert_eq!(re("a+").replace_all("aaa", "b").unwrap(), "b");
    assert_eq!(re("b").replace_all("", "x").unwrap(), "");
    assert_eq!(re("^").replace_all("ab", "^").unwrap(), "^ab");
}

#[test]
fn replace_expands_the_capture_group_references_the_official_runtime_expands() {
    let re = |p: &str| Regex::new(p).unwrap();
    // Recorded against the official emulator: `'abc'.replace('(a)(b)', '$2$1') == 'bac'`
    // is true and the `\2\1` spelling is false.
    assert_eq!(re("(a)(b)").replace_all("abc", "$2$1").unwrap(), "bac");
    assert_eq!(
        re("(a)(b)").replace_all("abc", "\\2\\1").unwrap(),
        "\\2\\1c"
    );
    assert_eq!(re("a").replace_all("a", "$0$0").unwrap(), "aa");
    assert_eq!(re("(a)").replace_all("ab", "[$1]").unwrap(), "[a]b");
    assert_eq!(re("a").replace_all("a", "$$").unwrap(), "$");
    // A group that never participated expands to nothing, and a reference past the last
    // group is dropped rather than raising.
    assert_eq!(re("(a)|(b)").replace_all("a", "<$2>").unwrap(), "<>");
    assert_eq!(re("a").replace_all("a", "$7").unwrap(), "");
}

#[test]
fn inline_flags_and_named_classes_behave_as_the_official_runtime_records_them() {
    let full = |p: &str, s: &str| Regex::new(p).unwrap().is_full_match(s).unwrap();
    assert!(full("(?i)abc", "ABC"));
    assert!(!full("abc", "ABC"));
    assert!(full("(?i)[a-z]+", "ABC"), "case folding reaches classes");
    assert!(full("(?s)a.b", "a\nb"));
    assert!(!full("a.b", "a\nb"));
    assert!(full("[[:digit:]]+", "123"));
    assert!(!full("[[:digit:]]+", "abc"));
    assert!(full("[[:alpha:][:digit:]]+", "a1"));
    assert!(full("\\p{Lu}", "A"));
    assert!(!full("\\p{Lu}", "a"));
    assert!(full("\\x41", "A"));
    assert!(full("\\x{1F600}", "\u{1F600}"));
    assert!(full("a\\sb", "a b"));
    assert!(Regex::new("[[:bogus:]]").is_err());
    assert!(Regex::new("\\p{Bogus}").is_err());
}

#[test]
fn null_escape_matches_u0000_and_nothing_else() {
    let null = Regex::new("\\0").unwrap();
    assert!(null.is_full_match("\0").unwrap());
    assert!(!null.is_full_match("0").unwrap());
    assert!(!null.is_full_match("\\0").unwrap());
}

#[test]
fn null_escape_works_in_groups_quantifiers_and_character_classes() {
    assert!(full("(\\0)+", "\0\0"));
    assert!(full("[\\0]", "\0"));
    assert!(!full("[\\0]", "0"));
    assert!(full("[^\\0]", "0"));
    assert!(!full("[^\\0]", "\0"));
}

#[test]
fn backreferences_one_through_nine_remain_compile_errors() {
    for digit in '1'..='9' {
        let backreference = format!("\\{digit}");
        assert!(Regex::new(&backreference).is_err(), "{backreference}");
        let class_backreference = format!("[\\{digit}]");
        assert!(
            Regex::new(&class_backreference).is_err(),
            "{class_backreference}"
        );
    }
}
