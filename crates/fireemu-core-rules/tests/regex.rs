//! RE2-style subset used by `string.matches()` / `string.replace()`.

// The lint mistakes this crate's `Regex::new` for the regex crate; invalid patterns are
// the point of some of these tests.
#![allow(clippy::invalid_regex)]

use fireemu_core_rules::regex::{Regex, RegexRuntimeError};

const LINEAR_CONTROL_FILTER: &str = r"^(?:[\t\n\r]|[^\p{Cc}])*$";

fn full(p: &str, s: &str) -> bool {
    Regex::new(p).unwrap().is_full_match(s).unwrap()
}

#[test]
fn character_class_alternative_repeats_do_not_spend_subject_length_as_match_depth() {
    let regex = Regex::new(LINEAR_CONTROL_FILTER).unwrap();
    for length in [0, 1, 6, 7, 32, 33, 3_000] {
        let subject = "a".repeat(length);
        assert_eq!(regex.is_full_match(&subject), Ok(true), "length={length}");
    }
    for allowed in ["\t", "\n", "\r", "a\tb\nc\r", "日本語\ntext"] {
        assert_eq!(regex.is_full_match(allowed), Ok(true), "{allowed:?}");
    }
    for forbidden in [
        '\0', '\u{0007}', '\u{000b}', '\u{000c}', '\u{007f}', '\u{0085}',
    ] {
        assert_eq!(
            regex.is_full_match(&format!("ok{forbidden}no")),
            Ok(false),
            "{forbidden:?}"
        );
    }
}

#[test]
fn linear_character_alternative_repeat_uses_constant_native_stack() {
    let result = std::thread::Builder::new()
        .stack_size(64 * 1024)
        .spawn(|| {
            Regex::new(LINEAR_CONTROL_FILTER)
                .unwrap()
                .is_full_match(&"x".repeat(10_000))
        })
        .unwrap()
        .join()
        .expect("the matcher must not overflow the small stack");
    assert_eq!(result, Ok(true));
}

#[test]
fn fixed_width_alternative_branch_probes_are_step_bounded() {
    let mut branches = (0..80)
        .map(|index| format!("[\\x{{{:x}}}]", 0x100 + index))
        .collect::<Vec<_>>();
    branches.push("[z]".to_owned());
    let regex = Regex::new(&format!("(?:{})*", branches.join("|"))).unwrap();
    assert!(matches!(
        regex.is_full_match(&"z".repeat(3_000)),
        Err(RegexRuntimeError::StepBudgetExceeded { current, maximum })
            if current > maximum
    ));
}

#[test]
fn fixed_width_alternative_diagnostics_charge_every_attempted_branch() {
    let regex = Regex::new("(?:a|b|c)*").unwrap();
    let first = regex.full_match_diagnostics("aaa");
    let last = regex.full_match_diagnostics("ccc");
    let forbidden = regex.full_match_diagnostics("aad");

    for diagnostics in [&first, &last, &forbidden] {
        assert_eq!(
            diagnostics.attempted_branch_probes,
            diagnostics.charged_branch_probes
        );
    }
    assert!(last.attempted_branch_probes > first.attempted_branch_probes);
    assert_eq!(forbidden.result, Ok(false));
}

#[test]
fn fixed_width_alternatives_preserve_capture_and_fallback_semantics() {
    assert_eq!(
        Regex::new("((?:[a]|[b]))+")
            .unwrap()
            .replace_all("ab", "<$1>")
            .unwrap(),
        "<b>"
    );
    assert_eq!(
        Regex::new("([a])|([a])")
            .unwrap()
            .replace_all("a", "<$1:$2>")
            .unwrap(),
        "<a:>"
    );
    assert!(Regex::new("(?:[a]|[a-z])+")
        .unwrap()
        .is_full_match("az")
        .unwrap());
    assert!(Regex::new("(?:ab|c)+")
        .unwrap()
        .is_full_match("abc")
        .unwrap());
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
    assert!(full("(?:)*", ""));
    assert!(!full("a*?b", ""));
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
fn pathological_patterns_report_runtime_budget_exhaustion() {
    let re = Regex::new("(a+)+b").unwrap();
    let error = re.is_full_match(&"a".repeat(18)).unwrap_err();
    let RegexRuntimeError::DepthBudgetExceeded { current, maximum } = error else {
        panic!("unexpected runtime error: {error}");
    };
    assert!(current > maximum);
    assert_eq!(
        error.to_string(),
        format!("regular expression depth budget exceeded: {current} > {maximum}")
    );
    assert!(matches!(
        re.replace_all(&"a".repeat(18), "replacement"),
        Err(RegexRuntimeError::DepthBudgetExceeded { current, maximum })
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
    assert!(!re("$a").is_full_match("a").unwrap());
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
    assert!(Regex::new("(?m)a").is_ok());
    assert!(Regex::new("(?U)a").is_ok());
    assert!(full("(?i:a)", "A"));
    assert!(!full("(?i-i:a)", "A"));
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
fn zero_prefixed_octal_escapes_follow_official_regex_boundaries() {
    assert!(full("\\00", "\0"));
    assert!(full("\\000", "\0"));
    assert!(full("\\0000", concat!("\0", "0")));
    assert!(full("\\01", "\u{1}"));
    assert!(full("\\001", "\u{1}"));
    assert!(full("\\011", "\t"));
    assert!(full("\\08", concat!("\0", "8")));
    assert!(full("\\09", concat!("\0", "9")));
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

#[test]
fn replace_budget_is_shared_across_all_scan_positions() {
    let input = "a".repeat(210_000);
    let error = Regex::new("z")
        .unwrap()
        .replace_all(&input, "x")
        .unwrap_err();
    let RegexRuntimeError::StepBudgetExceeded { current, maximum } = error else {
        panic!("unexpected runtime error: {error}");
    };
    assert!(current > maximum);
    assert_eq!(
        error.to_string(),
        format!("regular expression step budget exceeded: {current} > {maximum}")
    );
}

#[test]
fn deep_linear_matches_fail_within_a_small_thread_stack() {
    const CHILD_ENV: &str = "FIREEMU_REGEX_SMALL_STACK_CHILD";
    if std::env::var_os(CHILD_ENV).is_some() {
        let result = std::thread::Builder::new()
            .stack_size(64 * 1024)
            .spawn(|| {
                let at_limit = format!("{}a{}", "(".repeat(8), ")".repeat(8));
                assert!(Regex::new(&at_limit).unwrap().is_full_match("a").unwrap());
                let above_limit = format!("{}a{}", "(".repeat(9), ")".repeat(9));
                assert_eq!(
                    Regex::new(&above_limit).unwrap_err().to_string(),
                    "invalid regular expression: pattern nesting too deep"
                );
                let nested = format!("{}a{}", "(".repeat(1_000), ")".repeat(1_000));
                assert_eq!(
                    Regex::new(&nested).unwrap_err().to_string(),
                    "invalid regular expression: pattern nesting too deep"
                );

                let input = "a".repeat(10_000);
                assert!(Regex::new("a*").unwrap().is_full_match(&input).unwrap());
                let literal = "a".repeat(1_000);
                assert!(Regex::new(&literal)
                    .unwrap()
                    .is_full_match(&literal)
                    .unwrap());
                assert!(Regex::new("(ab)*")
                    .unwrap()
                    .is_full_match(&"ab".repeat(1_000))
                    .unwrap());
                assert!(Regex::new("(a|b)*").unwrap().is_full_match(&input).unwrap());

                let matcher = Regex::new("(a|aa)*b").unwrap();
                assert!(matches!(
                    matcher.is_full_match(&input),
                    Err(RegexRuntimeError::DepthBudgetExceeded { current, maximum })
                        if current > maximum
                ));
                assert!(matches!(
                    matcher.replace_all(&input, "x"),
                    Err(RegexRuntimeError::DepthBudgetExceeded { current, maximum })
                        if current > maximum
                ));
            })
            .unwrap()
            .join();
        assert!(result.is_ok(), "small-stack matcher thread panicked");
        return;
    }

    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "deep_linear_matches_fail_within_a_small_thread_stack",
        ])
        .env(CHILD_ENV, "1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "child status: {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn capture_snapshot_work_is_bounded_before_candidates_accumulate() {
    let pattern = format!("{}a*", "()".repeat(1_000));
    let error = Regex::new(&pattern)
        .unwrap()
        .is_full_match(&"a".repeat(250))
        .unwrap_err();
    assert!(matches!(
        error,
        RegexRuntimeError::StepBudgetExceeded { current, maximum } if current > maximum
    ));
}

#[test]
fn compile_nesting_preflight_ignores_escaped_and_class_parentheses() {
    assert!(Regex::new(&"\\(".repeat(20))
        .unwrap()
        .is_full_match(&"(".repeat(20))
        .unwrap());
    assert!(Regex::new("[[:alpha:](((((((((]").is_ok());
    assert!(Regex::new("[](((((((((]")
        .unwrap()
        .is_full_match("]")
        .unwrap());
    assert!(Regex::new("[^](((((((((]")
        .unwrap()
        .is_full_match("a")
        .unwrap());

    for class in [
        "[^]x]",
        r"[\]]",
        "[[:alpha:]]",
        "[abcdefghij[:alpha:]]",
        "[[:alpha]",
    ] {
        let above_limit = format!("{class}{}a{}", "(".repeat(9), ")".repeat(9));
        assert_eq!(
            Regex::new(&above_limit).unwrap_err().to_string(),
            "invalid regular expression: pattern nesting too deep"
        );
    }

    let nested_non_capturing = format!("{}a{}", "(?:".repeat(8), ")".repeat(8));
    assert!(Regex::new(&nested_non_capturing)
        .unwrap()
        .is_full_match("a")
        .unwrap());

    let sequential = "(a)".repeat(9);
    assert!(Regex::new(&sequential)
        .unwrap()
        .is_full_match(&"a".repeat(9))
        .unwrap());
}

#[test]
fn deterministic_groups_and_lazy_repeats_avoid_recursive_or_eager_work() {
    let captures = Regex::new("(a)(b)(c)(d)(e)(f)(g)(h)").unwrap();
    assert_eq!(
        captures
            .replace_all("abcdefgh", "$8$7$6$5$4$3$2$1")
            .unwrap(),
        "hgfedcba"
    );
    assert_eq!(
        Regex::new("(a)(b|c)")
            .unwrap()
            .replace_all("ab", "$1$2")
            .unwrap(),
        "ab"
    );
    assert!(Regex::new("(a|b)*")
        .unwrap()
        .is_full_match(&"ab".repeat(500))
        .unwrap());
    assert_eq!(
        Regex::new("(?:(?:a)|b)*").unwrap().is_full_match("aaaaaaa"),
        Ok(true)
    );
    assert_eq!(Regex::new("a|").unwrap().is_full_match(""), Ok(true));
    assert_eq!(
        Regex::new("((a)|ab)c")
            .unwrap()
            .replace_all("abc", "<$1><$2>"),
        Ok("<ab><>".to_owned())
    );
    assert_eq!(
        Regex::new("(?:(a)(b|bb)d|abc)")
            .unwrap()
            .replace_all("abc", "<$1><$2>"),
        Ok("<><>".to_owned())
    );
    assert_eq!(
        Regex::new("(a|aa){1}").unwrap().replace_all("a", "X"),
        Ok("X".to_owned())
    );
    assert_eq!(
        Regex::new("(a|)*").unwrap().replace_all("", "X"),
        Ok("X".to_owned())
    );
    assert_eq!(Regex::new("(a+)+?").unwrap().is_full_match(""), Ok(false));
    assert_eq!(Regex::new("a{1}?").unwrap().is_full_match("a"), Ok(true));
    assert_eq!(Regex::new("a{2}?").unwrap().is_full_match("a"), Ok(false));
    assert_eq!(Regex::new("a{0}?").unwrap().is_full_match("a"), Ok(false));
    assert_eq!(Regex::new("(?:)*?a").unwrap().is_full_match("b"), Ok(false));
    assert_eq!(
        Regex::new("a{0,1}?b").unwrap().is_full_match("aab"),
        Ok(false)
    );
    assert!(!Regex::new("(a|aa){1,2}")
        .unwrap()
        .is_full_match("aaaaa")
        .unwrap());

    let input = "a".repeat(1_000);
    let expected = format!("{}x", "xa".repeat(1_000));
    assert_eq!(
        Regex::new("a*?").unwrap().replace_all(&input, "x").unwrap(),
        expected
    );
}
