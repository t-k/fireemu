//! Evaluator, parser, value and runtime behaviour pinned by the mutation run: per-method
//! coverage, arithmetic and comparison tables, indexing, conversions, unsupported calls,
//! parser lexing and budgets.

use std::collections::BTreeMap;

use fireemu_core_rules::eval::{
    evaluate_request, Decision, DenyReason, Method, RequestContext, RulesService,
};
use fireemu_core_rules::parse::{parse_ruleset, MAX_EXPR_DEPTH, MAX_PARSE_BYTES};
use fireemu_core_rules::runtime::LoadedRules;
use fireemu_core_rules::value::RulesValue;

const DOC: &str = "/databases/(default)/documents/notes/n1";

fn ctx(method: Method, data: &[(&str, RulesValue)]) -> RequestContext {
    let mut resource = BTreeMap::new();
    resource.insert(
        "data".to_owned(),
        RulesValue::Map(
            data.iter()
                .map(|(k, v)| ((*k).to_owned(), v.clone()))
                .collect(),
        ),
    );
    resource.insert("id".to_owned(), RulesValue::String("n1".into()));
    RequestContext {
        service: RulesService::Firestore,
        method,
        path: DOC.to_owned(),
        auth: None,
        resource: Some(RulesValue::Map(resource.clone())),
        request_resource: Some(RulesValue::Map(resource)),
        time_unix_nanos: 1_788_004_860_i128 * 1_000_000_000,
        abstract_path: false,
        request_query: None,
    }
}

fn rules(allow: &str, cond: &str) -> String {
    format!(
        "rules_version = '2';\nservice cloud.firestore {{ match /databases/{{database}}/documents {{ match /notes/{{id}} {{ allow {allow}: if {cond}; }} }} }}"
    )
}

fn decide(src: &str, ctx: &RequestContext) -> Decision {
    evaluate_request(&parse_ruleset(src).unwrap(), ctx).decision
}

fn allowed(cond: &str) -> bool {
    matches!(
        decide(&rules("read", cond), &ctx(Method::Get, &[])),
        Decision::Allow
    )
}

#[test]
fn each_allow_method_covers_exactly_its_operations() {
    let all = [
        Method::Get,
        Method::List,
        Method::Create,
        Method::Update,
        Method::Delete,
    ];
    let table: &[(&str, &[Method])] = &[
        ("get", &[Method::Get]),
        ("list", &[Method::List]),
        ("create", &[Method::Create]),
        ("update", &[Method::Update]),
        ("delete", &[Method::Delete]),
        ("read", &[Method::Get, Method::List]),
        ("write", &[Method::Create, Method::Update, Method::Delete]),
    ];
    for (allow, covered) in table {
        for m in all {
            let d = decide(&rules(allow, "true"), &ctx(m, &[]));
            let expect_allow = covered.contains(&m);
            assert_eq!(
                matches!(d, Decision::Allow),
                expect_allow,
                "allow {allow} vs {m:?}: {d:?}"
            );
            if !expect_allow {
                assert!(
                    matches!(d, Decision::Deny(DenyReason::NoMatchingAllow)),
                    "{d:?}"
                );
            }
        }
    }
    // request.method spells the operation.
    for (m, name) in [
        (Method::Get, "get"),
        (Method::List, "list"),
        (Method::Create, "create"),
        (Method::Update, "update"),
        (Method::Delete, "delete"),
    ] {
        let src = rules("read, write", &format!("request.method == '{name}'"));
        assert!(
            matches!(decide(&src, &ctx(m, &[])), Decision::Allow),
            "{name}"
        );
    }
    // A path no match block covers is NoMatchingRule, not NoMatchingAllow.
    let mut elsewhere = ctx(Method::Get, &[]);
    elsewhere.path = "/databases/(default)/documents/other/x".to_owned();
    assert!(matches!(
        decide(&rules("read", "true"), &elsewhere),
        Decision::Deny(DenyReason::NoMatchingRule)
    ));
    // request.path is the concrete path outside a proof.
    assert!(allowed(
        "request.path[0] == 'databases' && request.path[3] == 'notes'"
    ));
    assert!(allowed("request.path[4] is string"));
}

#[test]
fn arithmetic_comparison_and_equality_tables() {
    for ok in [
        "1 + 2 == 3",
        "5 - 3 == 2",
        "2 * 3 == 6",
        "7 / 2 == 3",
        "7 % 3 == 1",
        "1.5 + 1.0 == 2.5",
        "1.5 - 0.5 == 1.0",
        "1.5 * 2.0 == 3.0",
        "3.0 / 2.0 == 1.5",
        "5.5 % 2.0 == 1.5",
        "1 + 0.5 == 1.5",
        "1 < 2",
        "2 > 1",
        "2 <= 2 && 2 >= 2",
        "!(2 < 2) && !(2 > 2)",
        "1 < 1.5 && 1.5 > 1",
        "'a' < 'b' && 'b' > 'a'",
        "1 == 1.0",
        "!(1 == 1.5)",
        "1 != 1.5",
        "request.time == request.time && !(request.time > request.time)",
        "request.time.seconds() == 1788004860",
        "'ab' + 'c' == 'abc'",
        "[1] + [2] == [1, 2]",
        "-(3) == -3",
        "'a' in ['a'] && !('b' in ['a'])",
        "'k' in {'k': 1}",
        "1 in [1, 2] && 2 in [1, 2]",
    ] {
        assert!(allowed(ok), "{ok}");
    }
    for err in [
        "1 / 0 == 0",
        "1 % 0 == 0",
        "9223372036854775807 + 1 > 0",
        "'a' < 1",
        "1 in 'abc'",
        "request.time > 1",
    ] {
        assert!(!allowed(err), "{err}");
    }
}

#[test]
fn indexing_conversions_and_calls() {
    for ok in [
        "[1, 2, 3][1] == 2",
        "'abc'[1] == 'b'",
        "{'a': 1}['a'] == 1",
        "path('/a/b')[1] == 'b'",
        // The official runtime has no `size()` on a path -- it is one of the type errors
        // the differential matrix recorded -- but it does have `bind()`.
        "path('/a/b').bind({}) == path('/a/b')",
        "path('/a/{seg}').bind({'seg': 'b'}) == path('/a/b')",
        "int(2.0) == 2",
        "int('7') == 7",
        "float(1) == 1.0",
        "float('1.5') == 1.5",
        "string(12) == '12'",
        "string(true) == 'true'",
        "string('s') == 's'",
        "{'a': 1}.get('a', 0) == 1",
        "{'a': 1}.get('b', 0) == 0",
        "'a,b'.split(',')[1] == 'b'",
        "int(2.5) == 2",
        "[1, 2, 3][0:2] == [1, 2]",
        "'abcdef'[1:3] == 'bc'",
        "[1, 2, 3].removeAll([2]) == [1, 3]",
        "[1, 2].toSet().union([3].toSet()) == [1, 2, 3].toSet()",
        "['a', 'b'].join('-') == 'a-b'",
        "{'a': 1}.keys()[0] == 'a'",
        "{'a': 1}.values()[0] == 1",
        "'x'.size() == 1",
        "[1].concat([2]).size() == 2",
        "debug(true)",
    ] {
        assert!(allowed(ok), "{ok}");
    }
    for err in [
        "[1, 2, 3][3] == 1",
        "[1, 2, 3][-1] == 3",
        "'abc'[5] == 'b'",
        "{'a': 1}['b'] == 1",
        "int(true) == 1",
        "int('x') == 0",
        "{'a': 1}.get(1, 0) == 0",
        "'a,b'.split(1)[0] == 'a'",
        "['a'].join(1) == 'a'",
        "getAfter(/databases/$(database)/documents/notes/n1).data.x == 1",
        "timestamp.value(1) == request.time",
        "duration.value(1, 's') == 1",
        "hashing.md5('x') == 'x'",
        "unknownFunction(1)",
        "path('/a/b').size() == 2",
        "[1, 2].toSet() is set",
        "[1, 2, 3][0:0] == []",
        "'abc'[3:3] == ''",
        "math.isInfinite(1.0)",
    ] {
        assert!(!allowed(err), "{err}");
    }
}

#[test]
fn function_call_depth_boundary_comes_from_the_catalog() {
    let max = fireemu_core_limits::catalogs::ALL_CATALOGS
        .iter()
        .find_map(|c| c.find("RULES-FUNCTION-CALL-DEPTH"))
        .and_then(|l| match l.maximum {
            fireemu_core_limits::model::LimitMaximum::Fixed(v) => Some(v),
            _ => None,
        })
        .unwrap();
    // A chain of distinct functions, because a recursive one does not compile at all. `n`
    // functions make `n - 1` calls once the allow has entered the first.
    let src = |n: u64| {
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
            "rules_version = '2';\nservice cloud.firestore {{ match /databases/{{d}}/documents {{ {} match /notes/{{id}} {{ allow read: if f0(); }} }} }}",
            functions.join(" ")
        )
    };
    let at_limit = decide(&src(max + 1), &ctx(Method::Get, &[]));
    assert!(
        matches!(at_limit, Decision::Allow),
        "{max} calls: {at_limit:?}"
    );
    let over = decide(&src(max + 2), &ctx(Method::Get, &[]));
    assert!(
        matches!(
            over,
            Decision::Deny(DenyReason::BudgetExceeded {
                limit_id: "RULES-FUNCTION-CALL-DEPTH",
                ..
            })
        ),
        "{} calls: {over:?}",
        max + 1
    );
    // Depth is released on return: many sequential calls are fine.
    let sequential = format!(
        "rules_version = '2';\nservice cloud.firestore {{ match /databases/{{d}}/documents {{ function one() {{ return true; }} match /notes/{{id}} {{ allow read: if {}; }} }} }}",
        vec!["one()"; 30].join(" && ")
    );
    assert!(matches!(
        decide(&sequential, &ctx(Method::Get, &[])),
        Decision::Allow
    ));
}

#[test]
fn proofs_keep_known_captures_and_never_decide_through_undetermined_containers() {
    let abstract_ctx = |data: Vec<(&str, RulesValue)>| {
        let mut resource = BTreeMap::new();
        resource.insert(
            "data".to_owned(),
            RulesValue::PartialMap(data.into_iter().map(|(k, v)| (k.to_owned(), v)).collect()),
        );
        resource.insert("id".to_owned(), RulesValue::Unknown);
        RequestContext {
            service: RulesService::Firestore,
            method: Method::List,
            path: "/databases/(default)/documents/notes/fireemu-placeholder".to_owned(),
            auth: None,
            resource: Some(RulesValue::Map(resource)),
            request_resource: None,
            time_unix_nanos: 0,
            abstract_path: true,
            request_query: None,
        }
    };
    let list = |cond: &str| rules("list", cond);
    let tagged = abstract_ctx(vec![(
        "tags",
        RulesValue::PartialList(vec![RulesValue::String("x".into())]),
    )]);
    // The database capture is a concrete segment even in a proof; the id is not.
    assert!(matches!(
        decide(&list("database == '(default)'"), &tagged),
        Decision::Allow
    ));
    assert!(!matches!(
        decide(&list("id == 'n1'"), &tagged),
        Decision::Allow
    ));
    assert!(!matches!(
        decide(&list("request.path[3] == 'notes'"), &tagged),
        Decision::Allow
    ));
    // A container holding an undetermined member cannot decide `!=` either way.
    for cond in [
        "{'a': resource.data.x} != {'a': 1}",
        "[resource.data.x] != [1]",
        "resource.data.x in resource.data.tags",
        "resource.data.tags.hasAny([resource.data.x])",
    ] {
        assert!(
            !matches!(decide(&list(cond), &tagged), Decision::Allow),
            "{cond}"
        );
    }
    assert!(matches!(
        decide(&list("'x' in resource.data.tags"), &tagged),
        Decision::Allow
    ));
}

#[test]
fn parser_lexes_numbers_strings_comments_and_enforces_budgets() {
    for ok in [
        "1.5 == 1.5",
        "10 == 10",
        "'a\\nb'.size() == 3",
        "'\\t'.size() == 1 && '\\r'.size() == 1",
        "'it\\'s' == \"it's\"",
        "'a\\\\b'.size() == 3",
        "false == false",
        "!false",
        "true // trailing comment\n",
        "/* block */ true",
        "true /* multi\nline */ && true",
        "1 in [1] && 1 is int",
        "1 == 1 ? true : false",
    ] {
        assert!(allowed(ok), "{ok}");
    }
    for bad in ["'\\q' == 'q'", "1.5.3 == 1", "/* unterminated", "'open"] {
        assert!(parse_ruleset(&rules("read", bad)).is_err(), "{bad}");
    }
    // Errors carry the position of the offending token, after comments.
    let err = parse_ruleset("rules_version = '2';\n// comment\nservice cloud.firestore {\n  match /x/{y} { allow read: if ; }\n}").unwrap_err();
    assert_eq!(err.line, 4, "{err}");
    assert!(err.column > 20, "{err}");
    assert!(!err.to_string().is_empty());
    // Only `match`, `function` and `allow` may appear in a match body.
    assert!(parse_ruleset(
        "rules_version = '2';\nservice cloud.firestore { match /x/{y} { deny read: if true; } }"
    )
    .is_err());
}

#[test]
fn nesting_budgets_refuse_deep_sources_without_overflowing() {
    // Expression nesting budget: just under MAX_EXPR_DEPTH parentheses parse and evaluate
    // (no stack overflow), the budget itself is a parse error, and so is anything deeper
    // (a hostile source of thousands of parentheses is refused, never a crash).
    let nested = |n: usize| format!("{}true{}", "(".repeat(n), ")".repeat(n));
    let deepest_ok = MAX_EXPR_DEPTH as usize - 2;
    assert!(allowed(&nested(deepest_ok)));
    assert!(parse_ruleset(&rules("read", &nested(MAX_EXPR_DEPTH as usize + 1))).is_err());
    assert!(parse_ruleset(&rules("read", &nested(5000))).is_err());
    let negations = |n: usize| format!("{}true", "!".repeat(n));
    assert!(parse_ruleset(&rules("read", &negations(MAX_EXPR_DEPTH as usize + 1))).is_err());
    assert!(parse_ruleset(&rules("read", &negations(5000))).is_err());
    assert!(allowed(&negations(4)));
    // Left-nested operator chains are bounded by the evaluator, not the parser: a long
    // chain is denied (a soft error), never a crash; a realistic one evaluates.
    let chained = |n: usize| vec!["1"; n].join(" + ") + &format!(" == {n}");
    assert!(allowed(&chained(40)));
    assert!(parse_ruleset(&rules("read", &chained(5000))).is_ok());
    assert!(!allowed(&chained(5000)));
    let conjunction = |n: usize| vec!["true"; n].join(" && ");
    assert!(allowed(&conjunction(500)), "&& / || chains are flattened");
    // Source size budget.
    let padding = "/".repeat(2) + &" ".repeat(MAX_PARSE_BYTES);
    assert!(parse_ruleset(&format!("{padding}\n{}", rules("read", "true"))).is_err());
}

#[test]
fn values_display_and_loaded_rules_report_their_state() {
    let list = RulesValue::List(vec![RulesValue::Int(1), RulesValue::Int(2)]);
    assert_eq!(list.to_string(), "[1, 2]");
    let mut m = BTreeMap::new();
    m.insert("a".to_owned(), RulesValue::Int(1));
    m.insert("b".to_owned(), RulesValue::Bool(true));
    let text = RulesValue::Map(m).to_string();
    assert!(text.contains(", "), "{text}");
    assert!(text.starts_with('{') && text.ends_with('}'), "{text}");
    assert_eq!(RulesValue::List(vec![]).to_string(), "[]");
    let loaded = LoadedRules::from_source(&rules("read", "true")).unwrap();
    assert!(loaded.is_loaded());
    assert_eq!(
        loaded.source.as_deref(),
        Some(rules("read", "true").as_str())
    );
    assert!(!LoadedRules::default().is_loaded());
    assert!(LoadedRules::from_source("nonsense").is_err());
}

fn range_ctx(lower: Option<(i64, bool)>, upper: Option<(i64, bool)>) -> RequestContext {
    use fireemu_core_rules::value::{RangeBound, ValueRange};
    let bound = |b: (i64, bool)| RangeBound {
        value: Box::new(RulesValue::Int(b.0)),
        inclusive: b.1,
    };
    let mut data = BTreeMap::new();
    data.insert(
        "age".to_owned(),
        RulesValue::Range(ValueRange {
            lower: lower.map(bound),
            upper: upper.map(bound),
        }),
    );
    let mut resource = BTreeMap::new();
    resource.insert("data".to_owned(), RulesValue::PartialMap(data));
    resource.insert("id".to_owned(), RulesValue::Unknown);
    RequestContext {
        service: RulesService::Firestore,
        method: Method::List,
        path: "/databases/(default)/documents/notes/fireemu-placeholder".to_owned(),
        auth: None,
        resource: Some(RulesValue::Map(resource)),
        request_resource: None,
        time_unix_nanos: 0,
        abstract_path: true,
        request_query: None,
    }
}

#[test]
fn range_relation_truth_table_for_every_operator_and_bound_kind() {
    let proves = |ctx: &RequestContext, cond: &str| {
        matches!(decide(&rules("list", cond), ctx), Decision::Allow)
    };
    // 18 <= age < 65
    let r = range_ctx(Some((18, true)), Some((65, false)));
    for provable in [
        "!(resource.data.age == 10)",
        "!(resource.data.age == 65)",
        "!(resource.data.age == 100)",
        "resource.data.age != 10",
        "resource.data.age != 65",
        "resource.data.age < 100",
        "resource.data.age < 65",
        "!(resource.data.age < 18)",
        "!(resource.data.age < 10)",
        "resource.data.age <= 65",
        "resource.data.age <= 100",
        "!(resource.data.age <= 10)",
        "resource.data.age > 10",
        "resource.data.age > 17",
        "!(resource.data.age > 65)",
        "!(resource.data.age > 100)",
        "resource.data.age >= 18",
        "resource.data.age >= 17",
        "!(resource.data.age >= 65)",
        "!(resource.data.age >= 100)",
        "!(resource.data.age == 'x')",
        "resource.data.age != 'x'",
        "10 < resource.data.age",
        "65 > resource.data.age",
        "18 <= resource.data.age",
        "100 >= resource.data.age",
    ] {
        assert!(proves(&r, provable), "{provable}");
    }
    for unprovable in [
        "resource.data.age == 30",
        "resource.data.age != 30",
        "resource.data.age < 30",
        "resource.data.age < 64",
        "resource.data.age <= 18",
        "resource.data.age <= 64",
        "resource.data.age > 18",
        "resource.data.age > 30",
        "resource.data.age >= 19",
        "resource.data.age >= 30",
        "resource.data.age == 18",
    ] {
        assert!(!proves(&r, unprovable), "{unprovable}");
    }
    // 18 < age <= 65: exclusive lower, inclusive upper.
    let r = range_ctx(Some((18, false)), Some((65, true)));
    for provable in [
        "!(resource.data.age == 18)",
        "resource.data.age != 18",
        "resource.data.age > 18",
        "!(resource.data.age <= 18)",
        "resource.data.age <= 65",
        "!(resource.data.age > 65)",
        "resource.data.age >= 18",
        "!(resource.data.age < 18)",
    ] {
        assert!(proves(&r, provable), "{provable}");
    }
    for unprovable in [
        "resource.data.age < 65",
        "resource.data.age >= 19",
        "resource.data.age == 65",
        "resource.data.age != 65",
        "resource.data.age >= 65",
        "resource.data.age > 64",
    ] {
        assert!(!proves(&r, unprovable), "{unprovable}");
    }
    // Pinned: 18 <= age <= 18 is the value itself.
    let r = range_ctx(Some((18, true)), Some((18, true)));
    for provable in [
        "resource.data.age == 18",
        "!(resource.data.age != 18)",
        "resource.data.age <= 18 && resource.data.age >= 18",
        "!(resource.data.age < 18) && !(resource.data.age > 18)",
    ] {
        assert!(proves(&r, provable), "{provable}");
    }
    // Unbounded above: nothing above is decided.
    let r = range_ctx(Some((18, true)), None);
    assert!(!proves(&r, "resource.data.age < 1000000"));
    assert!(!proves(&r, "resource.data.age <= 1000000"));
    assert!(proves(&r, "!(resource.data.age <= 17)"));
}

#[test]
fn integer_double_ordering_is_exact_at_every_boundary() {
    for ok in [
        "5 < 5.5 && 5.5 > 5",
        "5 > 4.5 && 4.5 < 5",
        "-5 > -5.5 && -5.5 < -5",
        "-5 < -4.5 && -4.5 > -5",
        "5 == 5.0 && !(5 < 5.0) && !(5 > 5.0)",
        "9223372036854775807 < 10000000000000000000000.0",
        "-9223372036854775807 > -10000000000000000000000.0",
        "9223372036854775807 < 1.0 / 0.0",
        "-9223372036854775807 > -1.0 / 0.0",
        "1.0 / 0.0 > 5 && -1.0 / 0.0 < 5",
        "9223372036854775807 < 9223372036854775808.0",
        "!(0.0 / 0.0 == 0.0 / 0.0)",
        "0.0 / 0.0 != 1",
        "1.5 < 2.5 && !(2.5 < 1.5) && 2.5 >= 2.5",
        "9007199254740993 > 9007199254740992.0",
        "9007199254740993 != 9007199254740992.0",
    ] {
        assert!(allowed(ok), "{ok}");
    }
    for err in ["0.0 / 0.0 < 1", "0.0 / 0.0 >= 1", "1 < 0.0 / 0.0"] {
        assert!(!allowed(err), "{err}");
    }
    // Bytes order bytewise.
    let bytes = ctx(
        Method::Get,
        &[
            ("a", RulesValue::Bytes(vec![1, 2])),
            ("b", RulesValue::Bytes(vec![1, 3])),
        ],
    );
    assert!(matches!(
        decide(
            &rules(
                "read",
                "resource.data.a < resource.data.b && !(resource.data.b < resource.data.a)"
            ),
            &bytes
        ),
        Decision::Allow
    ));
}

#[test]
fn proof_captures_partial_map_get_and_absent_resource_reporting() {
    let list = |cond: &str| rules("list", cond);
    let proves =
        |ctx: &RequestContext, cond: &str| matches!(decide(&list(cond), ctx), Decision::Allow);
    let r = range_ctx(Some((18, true)), None);
    // A multi-segment capture that consumed only concrete segments is known; one that
    // swallowed the placeholder is not.
    let prefixed = |cond: &str| {
        format!("rules_version = '2';\nservice cloud.firestore {{ match /{{prefix=**}}/notes/{{id}} {{ allow list: if {cond}; }} match /{{all=**}} {{ allow list: if {cond}; }} }}")
    };
    assert!(matches!(
        decide(
            &prefixed("prefix[0] == 'databases' && prefix[2] == 'documents'"),
            &r
        ),
        Decision::Allow
    ));
    assert!(!matches!(
        decide(&prefixed("all[4] is string"), &r),
        Decision::Allow
    ));
    // PartialMap.get: known key decides, unknown key stays open, non-string key errors.
    let known = {
        let mut c = range_ctx(Some((18, true)), None);
        if let Some(RulesValue::Map(m)) = &mut c.resource {
            if let Some(RulesValue::PartialMap(d)) = m.get_mut("data") {
                d.insert("owner".into(), RulesValue::String("u1".into()));
            }
        }
        c
    };
    assert!(proves(&known, "resource.data.get('owner', 'x') == 'u1'"));
    assert!(!proves(&known, "resource.data.get('missing', 0) == 0"));
    assert!(!proves(&known, "resource.data.get(1, 0) == 0"));
    // A create rule that reads `resource` (absent) is reported as such.
    let mut create = ctx(Method::Create, &[]);
    create.resource = None;
    let report = evaluate_request(
        &parse_ruleset(&rules("create", "resource == null || true")).unwrap(),
        &create,
    );
    assert!(report.absent_resource_used, "{report:?}");
    let report = evaluate_request(&parse_ruleset(&rules("create", "true")).unwrap(), &create);
    assert!(!report.absent_resource_used);
}
