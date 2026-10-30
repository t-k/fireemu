//! Bounded regular-expression evaluation for pipeline expressions.

use fireemu_core_firestore::pipeline_exec::{RegexError, RegexOperation, RegexResult};

pub(crate) fn resolve(
    subject: &str,
    pattern: &str,
    operation: RegexOperation,
) -> Result<RegexResult, RegexError> {
    let pattern = if operation == RegexOperation::Match {
        format!(r"\A(?:{pattern})\z")
    } else {
        pattern.to_owned()
    };
    let compiled = regex::RegexBuilder::new(&pattern)
        .size_limit(10 * 1024 * 1024)
        .dfa_size_limit(2 * 1024 * 1024)
        .build()
        .map_err(|error| match error {
            regex::Error::Syntax(_) => RegexError::InvalidSyntax,
            _ => RegexError::ResourceLimit,
        })?;
    Ok(match operation {
        RegexOperation::Contains | RegexOperation::Match => {
            RegexResult::Boolean(compiled.is_match(subject))
        }
        RegexOperation::Find => {
            RegexResult::Match(compiled.captures(subject).and_then(|captures| {
                captures
                    .get(usize::from(captures.len() > 1))
                    .map(|value| value.as_str().to_owned())
            }))
        }
        RegexOperation::FindAll => RegexResult::Matches(
            compiled
                .captures_iter(subject)
                .map(|captures| {
                    captures
                        .get(usize::from(captures.len() > 1))
                        .map(|value| value.as_str().to_owned())
                })
                .collect(),
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::resolve;
    use fireemu_core_firestore::field_path::FieldPath;
    use fireemu_core_firestore::pipeline_exec::{
        Eval, EvalError, Expr, Placement, Row, RuntimeContext, Unrecorded,
    };
    use fireemu_core_firestore::value::Value;
    use proptest::prelude::*;
    use std::collections::BTreeMap;

    fn text(value: &str) -> Eval {
        Eval::Value(Value::String(value.to_owned()))
    }
    fn int(value: i64) -> Eval {
        Eval::Value(Value::Integer(value))
    }
    fn null() -> Eval {
        Eval::Value(Value::Null)
    }
    fn array(values: Vec<Value>) -> Eval {
        Eval::Value(Value::Array(values))
    }
    fn is_unobserved(value: &Eval) -> bool {
        matches!(value, Eval::Error(EvalError::Unobserved { .. }))
    }
    fn wrong(function: &'static str, expected: &'static str, got: &'static str) -> Eval {
        Eval::Error(EvalError::WrongType {
            function,
            expected,
            got,
        })
    }
    fn invalid(message: &str) -> Eval {
        Eval::Error(EvalError::Invalid(message.to_owned()))
    }
    fn call_in(name: &str, args: &[Eval], mode: Unrecorded) -> Eval {
        let args = args
            .iter()
            .map(|arg| match arg {
                Eval::Value(value) => Expr::Constant(value.clone()),
                Eval::Absent => Expr::Field(FieldPath::parse("missing").unwrap()),
                Eval::Error(_) => panic!("unexpected test input error"),
            })
            .collect();
        Expr::call(name, args, Placement::Value)
            .unwrap()
            .eval_in_with_runtime(
                &Row::derived(BTreeMap::new()),
                mode,
                RuntimeContext {
                    regex_resolver: Some(resolve),
                    ..RuntimeContext::default()
                },
            )
    }
    fn strict(name: &str, args: &[Eval]) -> Eval {
        call_in(name, args, Unrecorded::Refuse)
    }
    fn emulator(name: &str, args: &[Eval]) -> Eval {
        call_in(name, args, Unrecorded::OfficialEmulator)
    }
    fn both(name: &str, args: &[Eval]) -> Eval {
        let (a, b) = (strict(name, args), emulator(name, args));
        assert_eq!(format!("{a:?}"), format!("{b:?}"), "{name} {args:?}");
        a
    }
    #[test]
    #[allow(clippy::too_many_lines)]
    fn regex_recorded_production_cases() {
        let subject = text("Hello World");
        let yes = Eval::Value(Value::Boolean(true));
        let no = Eval::Value(Value::Boolean(false));
        let strings = |items: &[&str]| {
            array(
                items
                    .iter()
                    .map(|s| Value::String((*s).to_owned()))
                    .collect(),
            )
        };
        for (name, args, expected) in [
            (
                "regex_contains",
                vec![subject.clone(), text("o W")],
                yes.clone(),
            ),
            (
                "regex_contains",
                vec![subject.clone(), text("xyz")],
                no.clone(),
            ),
            (
                "regex_contains",
                vec![subject.clone(), text("^Hello")],
                yes.clone(),
            ),
            (
                "regex_contains",
                vec![subject.clone(), text("^World")],
                no.clone(),
            ),
            (
                "regex_contains",
                vec![subject.clone(), text("hello")],
                no.clone(),
            ),
            (
                "regex_contains",
                vec![subject.clone(), text("(?i)hello")],
                yes.clone(),
            ),
            (
                "regex_contains",
                vec![subject.clone(), text("")],
                yes.clone(),
            ),
            (
                "regex_contains",
                vec![text("héllo ☃😀"), text("☃")],
                yes.clone(),
            ),
            (
                "regex_match",
                vec![subject.clone(), text("H.*d")],
                yes.clone(),
            ),
            (
                "regex_match",
                vec![subject.clone(), text("o W")],
                no.clone(),
            ),
            (
                "regex_match",
                vec![subject.clone(), text("^Hello World$")],
                yes.clone(),
            ),
            ("regex_match", vec![text(""), text("")], yes.clone()),
            ("regex_find", vec![subject.clone(), text("o")], text("o")),
            ("regex_find", vec![subject.clone(), text("xyz")], null()),
            (
                "regex_find",
                vec![subject.clone(), text("(W)orld")],
                text("W"),
            ),
            ("regex_find", vec![subject.clone(), text("x*")], text("")),
            (
                "regex_find_all",
                vec![subject.clone(), text("o")],
                strings(&["o", "o"]),
            ),
            (
                "regex_find_all",
                vec![subject.clone(), text("xyz")],
                strings(&[]),
            ),
            (
                "regex_find_all",
                vec![text("aaa"), text("aa")],
                strings(&["aa"]),
            ),
            (
                "regex_find_all",
                vec![text("abc"), text("x*")],
                strings(&["", "", "", ""]),
            ),
        ] {
            assert_eq!(both(name, &args), expected, "{name} {args:?}");
        }
        assert_eq!(
            both("regex_match", &[subject.clone(), text("[")]),
            invalid("Unsupported regex syntax.")
        );
        for name in [
            "regex_contains",
            "regex_match",
            "regex_find",
            "regex_find_all",
        ] {
            assert_eq!(
                both(name, &[subject.clone(), text("(")]),
                invalid("Unsupported regex syntax.")
            );
            assert_eq!(both(name, &[null(), text("a")]), null());
            assert_eq!(both(name, &[Eval::Absent, text("a")]), null());
            assert_eq!(
                both(name, &[int(1), text("a")]),
                wrong(name, "String", "LONG")
            );
            assert_eq!(both(name, &[subject.clone(), null()]), null());
            assert_eq!(
                both(name, &[subject.clone(), int(1)]),
                wrong(name, "String or Regex", "LONG")
            );
            for (n, verb) in [(0, "were"), (1, "was")] {
                let result = match name {
                    "regex_contains" | "regex_match" => "boolean",
                    "regex_find" => "string?",
                    _ => "array[string?]",
                };
                let args = vec![Expr::Constant(Value::Null); n];
                let signature =
                    format!("{name}[T: string | regex](search_space: string, regexp: T): {result}");
                assert_eq!(
                    Expr::call(name, args, Placement::Value)
                        .unwrap_err()
                        .to_string(),
                    format!(
                    "The function '{signature}' takes [2..2] argument(s), but {n} {verb} provided."
                )
                );
            }
        }
    }

    #[test]
    fn regex_pict_generated_cases() {
        let cases = [
            ("contains", "text", "match", "strict"),
            ("match", "text", "match", "strict"),
            ("find", "text", "match", "strict"),
            ("find_all", "text", "match", "strict"),
            ("contains", "null", "match", "strict"),
            ("contains", "text", "invalid", "strict"),
            ("match", "null", "empty", "emulator"),
            ("find_all", "absent", "match", "emulator"),
            ("match", "empty", "no_match", "emulator"),
            ("match", "empty", "invalid", "emulator"),
            ("find", "empty", "null", "emulator"),
            ("find", "empty", "invalid", "strict"),
            ("contains", "text", "wrong", "emulator"),
            ("contains", "absent", "empty", "strict"),
            ("find_all", "text", "empty", "strict"),
            ("find_all", "empty", "wrong", "strict"),
            ("contains", "empty", "match", "emulator"),
            ("find_all", "wrong", "no_match", "strict"),
            ("find", "wrong", "empty", "emulator"),
            ("find_all", "empty", "empty", "emulator"),
            ("find", "null", "no_match", "strict"),
            ("find", "text", "wrong", "emulator"),
            ("find_all", "null", "null", "strict"),
            ("contains", "text", "no_match", "strict"),
            ("contains", "wrong", "match", "strict"),
            ("find_all", "text", "invalid", "emulator"),
            ("match", "absent", "null", "emulator"),
            ("contains", "text", "null", "strict"),
            ("match", "wrong", "match", "emulator"),
            ("find", "absent", "no_match", "emulator"),
            ("match", "empty", "wrong", "strict"),
        ];
        for (function, subject, pattern, profile) in cases {
            let name = match function {
                "contains" => "regex_contains",
                "match" => "regex_match",
                "find" => "regex_find",
                _ => "regex_find_all",
            };
            let input = match subject {
                "text" => text("abc"),
                "empty" => text(""),
                "null" => null(),
                "absent" => Eval::Absent,
                "wrong" => int(1),
                _ => unreachable!(),
            };
            let pattern_arg = match pattern {
                "match" => text("b"),
                "no_match" => text("z"),
                "empty" => text(""),
                "invalid" => text("("),
                "null" => null(),
                "wrong" => int(1),
                _ => unreachable!(),
            };
            let expected = if subject == "wrong" {
                wrong(name, "String", "LONG")
            } else if pattern == "wrong" {
                wrong(name, "String or Regex", "LONG")
            } else if subject == "null" || subject == "absent" || pattern == "null" {
                null()
            } else if pattern == "invalid" {
                invalid("Unsupported regex syntax.")
            } else {
                let matches = pattern == "empty" || (pattern == "match" && subject == "text");
                let full = pattern == "empty" && subject == "empty";
                match function {
                    "contains" => Eval::Value(Value::Boolean(matches)),
                    "match" => Eval::Value(Value::Boolean(full)),
                    "find" if !matches => null(),
                    "find" => text(if pattern == "empty" { "" } else { "b" }),
                    "find_all" if !matches => array(vec![]),
                    "find_all" if pattern == "empty" => {
                        array(vec![
                            Value::String(String::new());
                            if subject == "empty" { 1 } else { 4 }
                        ])
                    }
                    "find_all" => array(vec![Value::String("b".to_owned())]),
                    _ => unreachable!(),
                }
            };
            let got = if profile == "strict" {
                strict(name, &[input, pattern_arg])
            } else {
                emulator(name, &[input, pattern_arg])
            };
            assert_eq!(got, expected, "{function} {subject} {pattern} {profile}");
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]
        #[test]
        fn regex_contains_and_match_agree_with_literal_reference(prefix in "[a-z]{0,8}", suffix in "[a-z]{0,8}") {
            let subject = format!("{prefix}Q{suffix}");
            prop_assert_eq!(strict("regex_contains", &[text(&subject), text("Q")]), Eval::Value(Value::Boolean(true)));
            prop_assert_eq!(strict("regex_match", &[text(&subject), text("Q")]), Eval::Value(Value::Boolean(prefix.is_empty() && suffix.is_empty())));
            prop_assert_eq!(strict("regex_find_all", &[text(&subject), text("Q")]), array(vec![Value::String("Q".to_owned())]));
        }
    }

    #[test]
    fn regex_strict_guards_known_re2_differences() {
        for (subject, pattern) in [
            ("١", r"\d"),
            ("١", r"\D"),
            ("é", r"\w"),
            ("é", r"\W"),
            (" ", r"\s"),
            (" ", r"\S"),
            ("é", r"\bé\b"),
            ("é", r"\B"),
            ("\u{000b}", r"\s"),
            ("ab", "(?x)a b"),
            ("a", "[a&&b]"),
            ("α", r"\p{Greek}"),
            ("a", r"[\d]"),
            ("a", r"\Qabc\E"),
            ("a", r"\C"),
            ("a", "(?u)a"),
            ("a", "(?R)^a$"),
            ("a", "[a--b]"),
            ("a", "[a~~b]"),
            ("a", "[a[b]]"),
            ("a", "a{2}"),
        ] {
            assert!(
                is_unobserved(&strict("regex_contains", &[text(subject), text(pattern)])),
                "{subject:?} {pattern:?}"
            );
        }
        for name in [
            "regex_contains",
            "regex_match",
            "regex_find",
            "regex_find_all",
        ] {
            assert!(is_unobserved(&strict(name, &[text("١"), text(r"\d")])));
        }
        assert_eq!(
            emulator("regex_contains", &[text("١"), text(r"\d")]),
            Eval::Value(Value::Boolean(true))
        );
        assert_eq!(
            strict("regex_contains", &[text("☃"), text("☃")]),
            Eval::Value(Value::Boolean(true))
        );
        assert_eq!(
            strict("regex_contains", &[text(r"\d"), text(r"\\d")]),
            Eval::Value(Value::Boolean(true))
        );
        for (subject, pattern) in [
            ("[", r"\["),
            ("{", r"\{"),
            ("?", r"\?"),
            ("a", "[a-z]"),
            ("z", "[^a]"),
            ("foo", "(?im:foo)"),
            ("a&&b", "a&&b"),
            (r"\s", r"\\s"),
        ] {
            assert_eq!(
                strict("regex_contains", &[text(subject), text(pattern)]),
                Eval::Value(Value::Boolean(true)),
                "{pattern}"
            );
        }
        assert_eq!(
            strict("regex_contains", &[text("Hello"), text("(?i)hello")]),
            Eval::Value(Value::Boolean(true))
        );
    }
    #[test]
    fn like_wildcards_escapes_and_dynamic_pattern() {
        for (subject, pattern, expected) in [
            ("apricot", "%ap%", true),
            ("berry", "%ap%", false),
            ("abc", "a_c", true),
            ("ac", "a_c", false),
            ("a%c", r"a\%c", true),
            ("abc", r"a\%c", false),
            ("a.c", "a.c", true),
            ("abc", "a.c", false),
        ] {
            for mode in [Unrecorded::Refuse, Unrecorded::OfficialEmulator] {
                let expression = Expr::call(
                    "like",
                    vec![
                        Expr::Field(FieldPath::parse("subject").unwrap()),
                        Expr::Field(FieldPath::parse("pattern").unwrap()),
                    ],
                    Placement::Value,
                )
                .unwrap();
                let row = Row::derived(BTreeMap::from([
                    ("subject".to_owned(), Value::String(subject.to_owned())),
                    ("pattern".to_owned(), Value::String(pattern.to_owned())),
                ]));
                let actual = expression.eval_in_with_runtime(
                    &row,
                    mode,
                    RuntimeContext {
                        regex_resolver: Some(resolve),
                        ..RuntimeContext::default()
                    },
                );
                assert_eq!(
                    actual,
                    Eval::Value(Value::Boolean(expected)),
                    "{subject:?} {pattern:?} {mode:?}"
                );
            }
        }
    }
    proptest! {
        #[test]
        fn like_without_wildcards_matches_literal_equality(subject in "[a-z]{0,12}", pattern in "[a-z]{0,12}") {
            prop_assert_eq!(both("like", &[text(&subject), text(&pattern)]), Eval::Value(Value::Boolean(subject == pattern)));
        }
    }
}
