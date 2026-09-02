//! Per-expression coverage recording (`RULES-PARITY-04`).

use std::collections::BTreeMap;

use fireemu_core_rules::coverage::{report, CoverageNode, ExprValue};
use fireemu_core_rules::eval::{
    evaluate_request_traced, Decision, Method, RequestContext, RulesService,
};
use fireemu_core_rules::parse::parse_ruleset;
use fireemu_core_rules::value::{AuthContext, RulesValue};

const RULES: &str = "rules_version = '2';\n\
service cloud.firestore {\n\
  match /databases/{db}/documents {\n\
    match /notes/{id} {\n\
      allow get: if id != 'secret';\n\
      allow create: if request.resource.data.n > 0;\n\
    }\n\
  }\n\
}\n";

fn ctx(method: Method, id: &str) -> RequestContext {
    RequestContext {
        service: RulesService::Firestore,
        method,
        path: format!("/databases/(default)/documents/notes/{id}"),
        auth: None,
        resource: None,
        request_resource: None,
        time_unix_nanos: 1_788_004_860_i128 * 1_000_000_000,
        abstract_path: false,
        request_query: None,
    }
}

/// Every node of the report, flattened, so a test can look one up by its extent.
fn flatten<'a>(nodes: &'a [CoverageNode], out: &mut Vec<&'a CoverageNode>) {
    for node in nodes {
        out.push(node);
        flatten(&node.children, out);
    }
}

#[test]
fn every_evaluated_expression_is_recorded_with_its_extent_and_its_values() {
    let ruleset = parse_ruleset(RULES).unwrap();
    let mut coverage = fireemu_core_rules::coverage::Coverage::default();
    for id in ["a", "secret"] {
        let (report, one) = evaluate_request_traced(&ruleset, &ctx(Method::Get, id), None);
        assert_eq!(
            matches!(report.decision, Decision::Allow),
            id == "a",
            "{id}"
        );
        coverage.merge(&one);
    }
    let report = report(&ruleset, &coverage);
    let mut nodes = Vec::new();
    flatten(&report, &mut nodes);

    // The `get` condition ran twice and answered both ways; the `id` it read took both
    // document ids.
    let condition = &RULES[RULES.find("id != 'secret'").unwrap()..][.."id != 'secret'".len()];
    assert_eq!(condition, "id != 'secret'");
    let start = RULES.find(condition).unwrap();
    let node = nodes
        .iter()
        .find(|n| n.span.offset == start && n.end == start + condition.len())
        .expect("the get condition is a report node");
    assert_eq!(
        node.values,
        vec![(ExprValue::Bool(true), 1), (ExprValue::Bool(false), 1)]
    );
    assert_eq!(node.span.line, 5);
    let id_node = nodes
        .iter()
        .find(|n| n.span.offset == start && n.end == start + 2)
        .expect("`id` is a child node");
    assert_eq!(
        id_node.values,
        vec![
            (ExprValue::String("a".to_owned()), 1),
            (ExprValue::String("secret".to_owned()), 1),
        ]
    );

    // The `create` condition was never reached: it is in the report with children and no
    // values at all, which is what the official report does with an unevaluated expression.
    let create_at = RULES.find("request.resource.data.n > 0").unwrap();
    let create = nodes
        .iter()
        .find(|n| n.span.offset == create_at)
        .expect("the create condition is a report node");
    assert!(create.values.is_empty());
    assert!(!create.children.is_empty());
}

#[test]
fn an_expression_that_raises_is_recorded_as_undefined_with_the_innermost_cause() {
    let src = "rules_version = '2';\nservice cloud.firestore {\n  match /databases/{db}/documents {\n    match /notes/{id} {\n      allow get: if resource.data.n == 1;\n    }\n  }\n}\n";
    let ruleset = parse_ruleset(src).unwrap();
    let (report, coverage) = evaluate_request_traced(&ruleset, &ctx(Method::Get, "a"), None);
    assert!(matches!(report.decision, Decision::Deny(_)));
    let entries = coverage.entries();
    let undefined: Vec<_> = entries
        .iter()
        .filter(|e| matches!(e.values.first(), Some((ExprValue::Undefined(_), _))))
        .collect();
    assert!(!undefined.is_empty(), "a raised expression is recorded");
    // The cause is `resource.data`, the innermost expression that actually raised, not the
    // comparison that propagated it.
    let cause_at = src.find("resource.data").unwrap();
    let Some((ExprValue::Undefined(cause), _)) = undefined
        .iter()
        .find(|e| e.span.offset == cause_at)
        .and_then(|e| e.values.first())
    else {
        panic!("the outermost node carries a cause");
    };
    assert_eq!(cause.span.offset, cause_at);
    assert!(!cause.message.is_empty());
}

#[test]
fn a_cached_lazy_let_error_keeps_its_original_undefined_cause() {
    let src = "rules_version = '2';\nservice cloud.firestore {\n  match /databases/{db}/documents {\n    function mayRead() {\n      let maybe = resource.data.optionalId;\n      return maybe == 'a' || false || maybe == 'b';\n    }\n    match /notes/{id} {\n      allow get: if mayRead();\n    }\n  }\n}\n";
    let ruleset = parse_ruleset(src).unwrap();
    let (report, coverage) = evaluate_request_traced(&ruleset, &ctx(Method::Get, "a"), None);
    assert!(matches!(report.decision, Decision::Deny(_)));

    let cause_at = src.find("resource.data.optionalId").unwrap();
    let return_at = src.find("return maybe").unwrap();
    let maybe_offsets = src[return_at..]
        .match_indices("maybe")
        .map(|(offset, _)| return_at + offset)
        .collect::<Vec<_>>();
    assert_eq!(maybe_offsets.len(), 2);
    for offset in maybe_offsets {
        let entry = coverage
            .entries()
            .into_iter()
            .find(|entry| entry.span.offset == offset)
            .expect("the lazy binding reference is recorded");
        let Some((ExprValue::Undefined(cause), _)) = entry.values.first() else {
            panic!("the lazy binding reference is undefined");
        };
        assert_eq!(cause.span.offset, cause_at);
    }
}

#[test]
fn a_recorded_value_never_carries_a_token() {
    // `request.auth.token` is a map, so it is recorded as a type name and not as its claims.
    let src = "rules_version = '2';\nservice cloud.firestore {\n  match /databases/{db}/documents {\n    match /notes/{id} {\n      allow get: if request.auth.token.role == 'admin';\n    }\n  }\n}\n";
    let ruleset = parse_ruleset(src).unwrap();
    let mut token = BTreeMap::new();
    token.insert("role".to_owned(), RulesValue::String("admin".to_owned()));
    token.insert(
        "secret_claim".to_owned(),
        RulesValue::String("do-not-log".to_owned()),
    );
    let mut c = ctx(Method::Get, "a");
    c.auth = Some(AuthContext {
        uid: "alice".to_owned(),
        token,
    });
    let (report, coverage) = evaluate_request_traced(&ruleset, &c, None);
    assert!(matches!(report.decision, Decision::Allow));
    let printed = format!("{:?}", coverage.entries());
    assert!(!printed.contains("do-not-log"), "{printed}");
    // The claim the rule actually read is recorded, because that is the point of a report.
    assert!(printed.contains("admin"));
}

#[test]
fn coverage_merge_adds_distinct_value_counts_without_replaying_observations() {
    use fireemu_core_rules::ast::Span;
    use fireemu_core_rules::coverage::Coverage;

    let span = Span {
        line: 1,
        column: 1,
        offset: 4,
    };
    let mut accumulated = Coverage::default();
    accumulated.record(span, 9, ExprValue::Bool(true));
    let mut request = Coverage::default();
    for _ in 0..10_000 {
        request.record(span, 9, ExprValue::Bool(true));
    }
    for _ in 0..7 {
        request.record(span, 9, ExprValue::Bool(false));
    }

    accumulated.merge(&request);

    assert_eq!(
        accumulated.entries()[0].values,
        vec![(ExprValue::Bool(true), 10_001), (ExprValue::Bool(false), 7)]
    );
}

#[test]
fn request_trace_payloads_are_lazy_until_a_client_enables_the_ring() {
    use std::cell::Cell;

    use fireemu_core_rules::coverage::{Coverage, RequestTrace, RulesDiagnostics};

    let coverage = Coverage::default();
    let called = Cell::new(0);
    let trace = |sequence| {
        called.set(called.get() + 1);
        RequestTrace {
            sequence,
            method: "get",
            path: "notes/one".to_owned(),
            allowed: true,
            reason: String::new(),
            uid: None,
            expressions: Vec::new(),
        }
    };
    let mut diagnostics = RulesDiagnostics::default();

    diagnostics.push(&coverage, trace);
    assert_eq!(called.get(), 0);
    assert!(diagnostics.requests().is_empty());

    diagnostics.enable_request_traces();
    diagnostics.push(&coverage, trace);
    assert_eq!(called.get(), 1);
    assert_eq!(diagnostics.requests().len(), 1);
}
