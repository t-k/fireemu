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
