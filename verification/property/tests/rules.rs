//! Property artifacts for REQ-RULES-PARITY-01, REQ-RULES-PARITY-03 and INV-RULES-SET-001.
//!
//! The differential matrix in `conformance/src/rules-probe` decides what the language *is*
//! by asking the official runtime. These properties then hold fireemu to that answer over
//! every input rather than the finitely many the matrix names: the slice bounds, the set
//! algebra, the three-valued boolean operators, and the two call-graph rules the compiler
//! enforces.

use std::collections::BTreeMap;

use fireemu_core_rules::ast::{ExprKind, Item};
use fireemu_core_rules::eval::{
    evaluate_request, Decision, DenyReason, Method, RequestContext, RulesService,
};
use fireemu_core_rules::parse::parse_ruleset;
use fireemu_core_rules::runtime::LoadedRules;
use fireemu_core_rules::value::RulesValue;
use proptest::prelude::*;

/// A ruleset whose single `allow get` condition is `condition`.
fn ruleset(condition: &str) -> String {
    format!(
        "rules_version = '2';\nservice cloud.firestore {{ match /databases/{{db}}/documents {{ match /notes/{{id}} {{ allow get: if {condition}; }} }} }}"
    )
}

fn ctx() -> RequestContext {
    RequestContext {
        service: RulesService::Firestore,
        method: Method::Get,
        path: "/databases/(default)/documents/notes/n1".to_owned(),
        auth: None,
        resource: None,
        request_resource: None,
        time_unix_nanos: 1_788_004_860_i128 * 1_000_000_000,
        abstract_path: false,
        request_query: None,
    }
}

/// `true` when the condition evaluated to true, `false` when it was false or raised.
fn holds(condition: &str) -> bool {
    let Ok(parsed) = parse_ruleset(&ruleset(condition)) else {
        return false;
    };
    matches!(evaluate_request(&parsed, &ctx()).decision, Decision::Allow)
}

fn document(entries: impl IntoIterator<Item = (String, RulesValue)>) -> RulesValue {
    let mut document = BTreeMap::new();
    document.insert(
        "data".to_owned(),
        RulesValue::Map(entries.into_iter().collect()),
    );
    RulesValue::Map(document)
}

/// A chain of `n` functions, `f0` calling `f1` ... and the last returning `true`, so the
/// ruleset makes `n - 1` function-to-function calls.
fn chain(n: usize) -> String {
    let functions: Vec<String> = (0..n)
        .map(|i| {
            let body = if i + 1 < n {
                format!("f{}()", i + 1)
            } else {
                "true".to_owned()
            };
            format!("function f{i}() {{ return {body}; }}")
        })
        .collect();
    format!(
        "rules_version = '2';\nservice cloud.firestore {{ match /databases/{{db}}/documents {{ {} match /notes/{{id}} {{ allow get: if f0(); }} }} }}",
        functions.join(" ")
    )
}

#[test]
fn prop_rules_regex_exhaustion_never_allows() {
    for negation in [
        "!resource.data.value.matches('(a|aa)*b')",
        "resource.data.value.matches('(a|aa)*b') == false",
    ] {
        for nested_allow in [false, true] {
            let source = format!(
                "rules_version = '2'; service cloud.firestore {{ match /databases/{{db}}/documents {{ match /notes/{{id}} {{ allow get: if {negation}; match /{{rest=**}} {{ allow get: if {nested_allow}; }} }} }} }}"
            );
            let parsed = parse_ruleset(&source).unwrap();
            let mut request = ctx();
            request.resource = Some(document([(
                "value".to_owned(),
                RulesValue::String("a".repeat(10_000)),
            )]));

            let decision = evaluate_request(&parsed, &request).decision;
            // Exhaustion never grants anything by itself; an allow that holds on its own still
            // decides, as allow statements are alternatives (FS-RULES 2026-09-24).
            if nested_allow {
                assert!(matches!(decision, Decision::Allow), "negation={negation}");
            } else {
                assert!(
                    matches!(
                        decision,
                        Decision::Deny(DenyReason::BudgetExceeded {
                            limit_id: "FIREEMU-REGEX-STEPS-PER-MATCH",
                            current,
                            maximum,
                        }) if current > maximum
                    ),
                    "negation={negation}"
                );
            }
        }
    }
}

const CALL_DEPTH_MAXIMUM: usize = 20;

fn allowed_linear_control(character: char) -> bool {
    matches!(character, '\t' | '\n' | '\r') || !character.is_control()
}

fn linear_control_character() -> impl Strategy<Value = char> {
    prop_oneof![
        any::<char>().prop_filter("ordinary noncontrol character", |character| {
            !character.is_control()
        }),
        Just('\t'),
        Just('\n'),
        Just('\r'),
        (0_u32..=0x9f).prop_filter_map("C0 or C1 control", |value| {
            char::from_u32(value).filter(|character| character.is_control())
        }),
    ]
}

proptest! {
    /// REQ-RULES-PARITY-01: a capture-free one-character alternative repeat makes the
    /// same decision as its Unicode character predicate for every generated subject.
    #[test]
    fn prop_rules_regex_linear_control_filter_matches_the_character_predicate(
        characters in prop::collection::vec(linear_control_character(), 0..256),
    ) {
        let source = "rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /messages/{id} {
      allow create: if request.resource.data.content.matches('^(?:[\\t\\n\\r]|[^\\\\p{Cc}])*$');
    }
  }
}";
        let parsed = parse_ruleset(source).unwrap();
        let subject = characters.iter().collect::<String>();
        let mut request = ctx();
        request.method = Method::Create;
        request.path = "/databases/(default)/documents/messages/m1".to_owned();
        request.request_resource = Some(document([(
            "content".to_owned(),
            RulesValue::String(subject),
        )]));
        let actual = matches!(evaluate_request(&parsed, &request).decision, Decision::Allow);
        let expected = characters.iter().copied().all(allowed_linear_control);
        prop_assert_eq!(actual, expected);
    }

    /// REQ-RULES-PARITY-01: after Rules string decoding, regex `\0` matches U+0000 and
    /// never ASCII `0` or the two-character backslash-zero spelling, for arbitrary safe
    /// surrounding text.
    #[test]
    fn prop_rules_regex_null_escape_matches_only_u0000(
        prefix in prop::collection::vec(b'a'..=b'z', 0..65),
        suffix in prop::collection::vec(b'a'..=b'z', 0..65),
    ) {
        let prefix = String::from_utf8(prefix).unwrap();
        let suffix = String::from_utf8(suffix).unwrap();
        let with_u0000 = format!("'{prefix}\\u0000{suffix}'.matches('.*\\\\0.*')");
        let with_ascii_zero = format!("'{prefix}0{suffix}'.matches('.*\\\\0.*')");
        let with_backslash_zero = format!("'{prefix}\\\\0{suffix}'.matches('.*\\\\0.*')");

        prop_assert!(holds(&with_u0000), "{}", with_u0000);
        prop_assert!(!holds(&with_ascii_zero), "{}", with_ascii_zero);
        prop_assert!(!holds(&with_backslash_zero), "{}", with_backslash_zero);
    }

    /// REQ-RULES-PARITY-01: list length, layout, one optional trailing comma and the final
    /// return semicolon vary independently without changing the parsed list members.
    #[test]
    fn prop_rules_list_and_final_return_delimiters(
        values in prop::collection::vec(-100i64..100, 0..9),
        trailing_comma: bool,
        return_semicolon: bool,
        multiline: bool,
        separator_comment: bool,
    ) {
        let separator = match (multiline, separator_comment) {
            (true, true) => ", /* separator */\n      ",
            (true, false) => ",\n      ",
            (false, true) => ", /* separator */ ",
            (false, false) => ", ",
        };
        let mut items = values.iter().map(i64::to_string).collect::<Vec<_>>().join(separator);
        if trailing_comma && !items.is_empty() {
            items.push(',');
            if separator_comment {
                items.push_str(" /* trailing */");
            }
        }
        let terminator = if return_semicolon { ";" } else { "" };
        let source = format!(
            "service cloud.firestore {{\n  function values() {{\n    return [\n      {items}\n    ]{terminator}\n  }}\n}}"
        );
        let parsed = parse_ruleset(&source);
        prop_assert!(parsed.is_ok(), "{}", parsed.unwrap_err());
        let parsed = parsed.unwrap();
        let Item::Function(function) = &parsed.services[0].items[0] else {
            unreachable!("the generated first item is a function");
        };
        let ExprKind::List(parsed_items) = function.body.kind() else {
            unreachable!("the generated function returns a list");
        };
        prop_assert_eq!(parsed_items.len(), values.len());
    }

    /// REQ-RULES-PARITY-01: a range index is in range exactly when the start is a valid
    /// index and the end is a valid position after one -- `0 <= i < len` and
    /// `0 < j <= len`, with `i <= j` -- and it yields exactly that sub-list. The asymmetry
    /// is the official runtime's, recorded in the `slice` area of the matrix.
    #[test]
    fn prop_rules_slice_is_in_range_exactly_where_the_official_runtime_says(
        len in 0usize..6,
        i in -1i64..7,
        j in -1i64..7,
    ) {
        let items: Vec<String> = (0..len).map(|n| n.to_string()).collect();
        let literal = format!("[{}]", items.join(", "));
        let len_i = i64::try_from(len).unwrap_or(0);
        let in_range = i >= 0 && i < len_i && j > 0 && j <= len_i && i <= j;
        let expected: Vec<String> = if in_range {
            items[usize::try_from(i).unwrap_or(0)..usize::try_from(j).unwrap_or(0)].to_vec()
        } else {
            Vec::new()
        };
        let claim = format!("{literal}[{i}:{j}] == [{}]", expected.join(", "));
        prop_assert_eq!(holds(&claim), in_range, "{}", claim);

        // A string slices by the same rule, over characters.
        let text: String = (0..len).map(|n| char::from(b'a' + u8::try_from(n).unwrap_or(0))).collect();
        let expected: String = if in_range {
            text[usize::try_from(i).unwrap_or(0)..usize::try_from(j).unwrap_or(0)].to_owned()
        } else {
            String::new()
        };
        let claim = format!("'{text}'[{i}:{j}] == '{expected}'");
        prop_assert_eq!(holds(&claim), in_range, "{}", claim);
    }

    /// REQ-RULES-PARITY-01: `toSet()` is set-theoretic. Membership, union, intersection and
    /// difference agree with the sets the members describe, order and duplicates do not
    /// change a set, and a set never equals a list.
    #[test]
    fn prop_rules_set_operations_are_set_theoretic(
        a in prop::collection::vec(0i64..6, 0..5),
        b in prop::collection::vec(0i64..6, 0..5),
        probe in 0i64..6,
    ) {
        let list = |xs: &[i64]| format!("[{}]", xs.iter().map(i64::to_string).collect::<Vec<_>>().join(", "));
        let set = |xs: &[i64]| format!("{}.toSet()", list(xs));
        let mut union: Vec<i64> = a.iter().chain(&b).copied().collect();
        union.sort_unstable();
        union.dedup();
        let intersection: Vec<i64> = {
            let mut v: Vec<i64> = a.iter().copied().filter(|x| b.contains(x)).collect();
            v.sort_unstable();
            v.dedup();
            v
        };
        let difference: Vec<i64> = {
            let mut v: Vec<i64> = a.iter().copied().filter(|x| !b.contains(x)).collect();
            v.sort_unstable();
            v.dedup();
            v
        };
        for (name, expected) in [
            ("union", &union),
            ("intersection", &intersection),
            ("difference", &difference),
        ] {
            let claim = format!("{}.{name}({}) == {}", set(&a), set(&b), set(expected));
            prop_assert!(holds(&claim), "{}", claim);
        }
        prop_assert_eq!(
            holds(&format!("{probe} in {}", set(&a))),
            a.contains(&probe)
        );
        prop_assert_eq!(
            holds(&format!("{}.hasAll({})", set(&a), list(&b))),
            b.iter().all(|x| a.contains(x))
        );
        // A reversed, duplicated list makes the same set, and a set is never a list.
        let mut shuffled: Vec<i64> = a.clone();
        shuffled.reverse();
        shuffled.extend(a.iter().copied());
        let claim = format!("{} == {}", set(&shuffled), set(&a));
        prop_assert!(holds(&claim), "{}", claim);
        if !a.is_empty() {
            let claim = format!("{} == {}", set(&a), list(&a));
            prop_assert!(!holds(&claim), "{}", claim);
        }
        // `is` never recognises a set, whatever the type name.
        for name in ["set", "list", "map", "int", "string", "bool"] {
            let claim = format!("{} is {name}", set(&a));
            prop_assert!(!holds(&claim), "{}", claim);
        }
    }

    /// INV-RULES-SET-001: set operations on collections large enough to take the hash
    /// indexes (at least 64 members, at least 32 distinct) and mixing scalar types decide
    /// membership by Rules equality: an integer equals the float of the same value, nothing
    /// else crosses a type, and duplicates collapse. Sizes and membership answers agree with a
    /// reference computed from that equality.
    #[test]
    fn prop_rules_large_mixed_set_operations_agree_with_equality(
        a in prop::collection::vec(mixed_member(), 64..120),
        b in prop::collection::vec(mixed_member(), 8..80),
    ) {
        let list = |xs: &[Member]| format!("[{}]", xs.iter().map(Member::literal).collect::<Vec<_>>().join(", "));
        let distinct = |xs: &[Member]| {
            let mut out: Vec<Member> = Vec::new();
            for x in xs {
                if !out.iter().any(|y| y.equals(x)) {
                    out.push(x.clone());
                }
            }
            out
        };
        let (da, db) = (distinct(&a), distinct(&b));
        let in_b = |x: &Member| db.iter().any(|y| y.equals(x));
        let in_a = |x: &Member| da.iter().any(|y| y.equals(x));
        let union = distinct(&a.iter().chain(&b).cloned().collect::<Vec<_>>()).len();
        let intersection = da.iter().filter(|x| in_b(x)).count();
        let difference = da.len() - intersection;
        let (set_a, set_b) = (format!("{}.toSet()", list(&a)), format!("{}.toSet()", list(&b)));
        for (claim, expected) in [
            (format!("{set_a}.size() == {}", da.len()), true),
            (format!("{set_a}.union({set_b}).size() == {union}"), true),
            (format!("{set_a}.intersection({set_b}).size() == {intersection}"), true),
            (format!("{set_a}.difference({set_b}).size() == {difference}"), true),
            (format!("{set_a}.hasAll({})", list(&b)), db.iter().all(&in_a)),
            (format!("{set_a}.hasAny({})", list(&b)), db.iter().any(&in_a)),
            (format!("{}.hasAll({})", list(&a), list(&b)), db.iter().all(&in_a)),
            (format!("{}.hasOnly({})", list(&b), list(&a)), db.iter().all(&in_a)),
            (format!("{}.removeAll({}).size() == {}", list(&a), list(&b), a.iter().filter(|x| !in_b(x)).count()), true),
        ] {
            prop_assert_eq!(holds(&claim), expected, "{}", claim);
        }
    }
    /// REQ-RULES-PARITY-01: `&&` and `||` are the official three-valued operators. A
    /// deciding operand -- `false` for `&&`, `true` for `||` -- settles the answer whatever
    /// the other operand did, including when the other one raised.
    #[test]
    fn prop_rules_boolean_operators_absorb_a_raised_operand(
        left in 0u8..3,
        right in 0u8..3,
        conjunction: bool,
    ) {
        // 0 = false, 1 = true, 2 = raises.
        let operand = |n: u8| match n {
            0 => "false".to_owned(),
            1 => "true".to_owned(),
            _ => "(1 / 0 == 1)".to_owned(),
        };
        let op = if conjunction { "&&" } else { "||" };
        let claim = format!("{} {op} {}", operand(left), operand(right));
        let deciding = u8::from(!conjunction);
        let both_defined = left != 2 && right != 2;
        let expected = if left == deciding || right == deciding {
            // The deciding value wins, error or not.
            !conjunction
        } else if both_defined {
            conjunction
        } else {
            // Nothing decides and something raised: the whole expression raises, which is a
            // denial rather than a `true`.
            false
        };
        prop_assert_eq!(holds(&claim), expected, "{}", claim);
    }

    /// REQ-RULES-PARITY-03: the call-graph limits are compile errors. A chain of `n`
    /// functions loads exactly when it makes at most twenty calls, and a ruleset with a
    /// recursive call never loads at all.
    #[test]
    fn prop_rules_call_graph_limits_are_compile_errors(n in 1usize..30) {
        let loaded = LoadedRules::from_source(&chain(n)).is_ok();
        prop_assert_eq!(loaded, n - 1 <= CALL_DEPTH_MAXIMUM, "a chain of {} functions", n);
        if !loaded {
            let message = LoadedRules::from_source(&chain(n)).unwrap_err().message;
            prop_assert!(message.starts_with("Maximum allowed call depth of"), "{}", message);
        }
        // A self call is refused whatever the chain around it looks like.
        let recursive = format!(
            "rules_version = '2';\nservice cloud.firestore {{ match /databases/{{db}}/documents {{ function loop(n) {{ return n <= 0 ? true : loop(n - 1); }} match /notes/{{id}} {{ allow get: if loop({n}); }} }} }}"
        );
        let error = LoadedRules::from_source(&recursive).unwrap_err();
        prop_assert_eq!(error.message, "Recursive call is not allowed.");
    }
}

/// A scalar member of the large set property, with its Rules literal and Rules equality.
#[derive(Clone, Debug)]
enum Member {
    Int(i64),
    /// Halves, so integral and non-integral floats both occur and stay exact.
    Half(i64),
    Str(u8),
    Bool(bool),
    Null,
}

impl Member {
    fn literal(&self) -> String {
        match self {
            Self::Int(i) => i.to_string(),
            Self::Half(h) if h % 2 == 0 => format!("{}.0", h / 2),
            Self::Half(h) => format!("{}.5", h / 2),
            Self::Str(c) => format!("'s{c}'"),
            Self::Bool(b) => b.to_string(),
            Self::Null => "null".to_owned(),
        }
    }

    /// Twice the numeric value, when numeric.
    fn doubled(&self) -> Option<i64> {
        match self {
            Self::Int(i) => Some(i * 2),
            Self::Half(h) => Some(*h),
            _ => None,
        }
    }

    fn equals(&self, other: &Self) -> bool {
        match (self.doubled(), other.doubled()) {
            (Some(x), Some(y)) => x == y,
            (None, None) => match (self, other) {
                (Self::Str(x), Self::Str(y)) => x == y,
                (Self::Bool(x), Self::Bool(y)) => x == y,
                (Self::Null, Self::Null) => true,
                _ => false,
            },
            _ => false,
        }
    }
}

fn mixed_member() -> impl Strategy<Value = Member> {
    prop_oneof![
        4 => (0i64..40).prop_map(Member::Int),
        3 => (0i64..80).prop_map(Member::Half),
        3 => (0u8..30).prop_map(Member::Str),
        1 => any::<bool>().prop_map(Member::Bool),
        1 => Just(Member::Null),
    ]
}
