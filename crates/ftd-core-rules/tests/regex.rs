//! RE2-style subset used by `string.matches()` / `string.replace()`.

// The lint mistakes this crate's `Regex::new` for the regex crate; invalid patterns are
// the point of some of these tests.
#![allow(clippy::invalid_regex)]

use ftd_core_rules::regex::Regex;

fn full(p: &str, s: &str) -> bool {
    Regex::new(p).unwrap().is_full_match(s)
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
    assert!(
        Regex::new("(?i)flags").is_err(),
        "unsupported syntax fails closed"
    );
}

#[test]
fn replace_all_replaces_every_match_with_a_literal() {
    let re = Regex::new("[aeiou]").unwrap();
    assert_eq!(re.replace_all("banana", "_"), "b_n_n_");
    let re = Regex::new("\\s+").unwrap();
    assert_eq!(re.replace_all("a  b\tc", "-"), "a-b-c");
    let re = Regex::new("x").unwrap();
    assert_eq!(re.replace_all("none", "y"), "none");
}

#[test]
fn pathological_patterns_fail_closed_within_the_step_budget() {
    let re = Regex::new("(a+)+b").unwrap();
    assert!(!re.is_full_match(&"a".repeat(40)));
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
        "(?i)a",
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
    assert!(!Regex::new("(?i)a").unwrap_err().to_string().is_empty());
}

#[test]
fn matching_boundaries_and_replace_all_edge_cases() {
    let re = |p: &str| Regex::new(p).unwrap();
    assert!(re("a{2,3}").is_full_match("aa"));
    assert!(re("a{2,3}").is_full_match("aaa"));
    assert!(!re("a{2,3}").is_full_match("a"));
    assert!(!re("a{2,3}").is_full_match("aaaa"));
    assert!(re("a{2,}").is_full_match(&"a".repeat(50)));
    assert!(!re("a{3,}").is_full_match("aa"));
    assert!(!re(".").is_full_match("\n"), "`.` never matches a newline");
    assert!(re("[^a]").is_full_match("\n"));
    assert!(re("a|b|c").is_full_match("c"));
    assert!(re("^ab$").is_full_match("ab"));
    assert!(re("[a-c]+").is_full_match("cab") && !re("[a-c]+").is_full_match("cad"));
    assert!(re("[\\d]+").is_full_match("123") && !re("[\\d]+").is_full_match("12a"));
    assert!(re("\\.").is_full_match(".") && !re("\\.").is_full_match("a"));
    assert!(re("[^\\d]").is_full_match("x") && !re("[^\\d]").is_full_match("5"));
    assert!(re("(ab)*").is_full_match("abab") && !re("(ab)*").is_full_match("aba"));
    // replace_all: an empty match inserts the replacement before every character and at
    // the end; non-empty matches consume their text. An empty match right after a
    // non-empty one is emitted (JavaScript semantics: "baab".replace(/a*/g, "-")).
    assert_eq!(re("x*").replace_all("ab", "-"), "-a-b-");
    assert_eq!(re("a*").replace_all("baab", "-"), "-b--b-");
    assert_eq!(re("ab").replace_all("abab", "X"), "XX");
    assert_eq!(re("a").replace_all("aaa", "bb"), "bbbbbb");
    assert_eq!(re("a+").replace_all("aaa", "b"), "b");
    assert_eq!(re("b").replace_all("", "x"), "");
    assert_eq!(re("^").replace_all("ab", "^"), "^ab");
}
