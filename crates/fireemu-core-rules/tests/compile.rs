//! What compiles: production's compiler, as the FS-RULES production recording (2026-09-24)
//! observed it and the official emulator's compiler (the same compiler on every recorded
//! row) confirmed locally on 2026-09-25.

use fireemu_core_rules::ast::{Item, Method};
use fireemu_core_rules::eval::{evaluate_request, Decision, RequestContext, RulesService};
use fireemu_core_rules::parse::parse_ruleset;
use fireemu_core_rules::runtime::LoadedRules;

fn wrap(inner: &str) -> String {
    format!(
        "rules_version = '2';\nservice cloud.firestore {{\n  match /databases/{{database}}/documents {{\n{inner}\n  }}\n}}\n"
    )
}

fn get_rule(condition: &str) -> String {
    wrap(&format!(
        "    match /c/{{d}} {{\n      allow get: if {condition};\n    }}"
    ))
}

fn compiles(source: &str) -> Result<(), String> {
    LoadedRules::from_source(source)
        .map(|_| ())
        .map_err(|e| e.message)
}

fn allowed(source: &str, method: fireemu_core_rules::eval::Method) -> bool {
    let ruleset = parse_ruleset(source).unwrap();
    let ctx = RequestContext {
        service: RulesService::Firestore,
        method,
        path: "/databases/(default)/documents/c/x".to_owned(),
        auth: None,
        resource: None,
        request_resource: None,
        time_unix_nanos: 0,
        abstract_path: false,
        request_query: None,
    };
    matches!(evaluate_request(&ruleset, &ctx).decision, Decision::Allow)
}

#[test]
fn semicolons_after_allow_and_the_version_are_optional() {
    for source in [
        wrap("    match /c/{d} {\n      allow get: if true\n      allow list: if true;\n    }"),
        wrap("    match /c/{d} {\n      allow get: if true\n    }"),
        "rules_version = '2'\nservice cloud.firestore {\n  match /databases/{database}/documents {\n    match /c/{d} { allow get: if true; }\n  }\n}\n"
            .to_owned(),
    ] {
        compiles(&source).unwrap_or_else(|e| panic!("{source}: {e}"));
    }
    // A let still needs its semicolon, as in production.
    assert!(compiles(&wrap(
        "    function f() {\n      let v = true\n      return v;\n    }\n    match /c/{d} { allow get: if f(); }"
    ))
    .is_err());
}

#[test]
fn access_methods_are_case_insensitive_and_unknown_ones_grant_nothing() {
    use fireemu_core_rules::eval::Method as Op;
    let get = |methods: &str| {
        wrap(&format!(
            "    match /c/{{d}} {{ allow {methods}: if true; }}"
        ))
    };
    assert!(allowed(&get("Get"), Op::Get));
    assert!(allowed(&get("GET"), Op::Get));
    assert!(allowed(&get("get, fetch"), Op::Get));
    compiles(&get("fetch")).unwrap();
    assert!(!allowed(&get("fetch"), Op::Get));
    let ruleset = parse_ruleset(&get("fetch")).unwrap();
    let Item::Match(databases) = &ruleset.services[0].items[0] else {
        panic!("match");
    };
    let Item::Match(block) = &databases.items[0] else {
        panic!("match");
    };
    assert!(block.allows[0].methods.is_empty());
    let parsed = parse_ruleset(&get("Get, list")).unwrap();
    let Item::Match(databases) = &parsed.services[0].items[0] else {
        panic!("match");
    };
    let Item::Match(block) = &databases.items[0] else {
        panic!("match");
    };
    assert_eq!(block.allows[0].methods, vec![Method::Get, Method::List]);
}

#[test]
fn a_function_defined_twice_in_one_scope_does_not_compile() {
    let twice =
        wrap("    function d() { return true; }\n    function d(x) { return x; }\n    match /c/{x} { allow get: if d(); }");
    assert_eq!(
        compiles(&twice).unwrap_err(),
        "Function d is already defined."
    );
    // Sibling scopes and an inner function shadowing an outer one compile.
    compiles(&wrap(
        "    match /a/{x} {\n      function d() { return true; }\n      allow get: if d();\n    }\n    match /b/{x} {\n      function d() { return false; }\n      allow get: if d();\n    }",
    ))
    .unwrap();
    let shadow = wrap(
        "    function d() { return false; }\n    match /c/{x} {\n      function d() { return true; }\n      allow get: if d();\n    }",
    );
    compiles(&shadow).unwrap();
    assert!(allowed(&shadow, fireemu_core_rules::eval::Method::Get));
}

#[test]
fn a_call_with_the_wrong_number_of_arguments_compiles_and_is_false() {
    for condition in ["two(true)", "one(true, false)"] {
        let source = wrap(&format!(
            "    function one(a) {{ return a; }}\n    function two(a, b) {{ return a; }}\n    match /c/{{x}} {{ allow get: if {condition}; }}"
        ));
        compiles(&source).unwrap_or_else(|e| panic!("{condition}: {e}"));
        assert!(
            !allowed(&source, fireemu_core_rules::eval::Method::Get),
            "{condition}"
        );
    }
}

/// Every construct that nests counts one level: a left-leaning chain of binary operators,
/// `!`, parentheses, a ternary, a list or map literal and a call's arguments. Member access
/// and indexing do not. An expression 99 levels deep compiles; 100 does not.
fn depth_cases(levels: usize) -> Vec<(&'static str, String)> {
    let n = levels;
    vec![
        ("and chain", get_rule(&vec!["true"; n].join(" && "))),
        (
            "plus chain",
            get_rule(&format!("{} > 0", vec!["1"; n - 1].join(" + "))),
        ),
        ("not", get_rule(&format!("{}true", "!".repeat(n - 1)))),
        (
            "parentheses",
            get_rule(&format!("{}true{}", "(".repeat(n - 1), ")".repeat(n - 1))),
        ),
        (
            "ternary",
            get_rule(&format!(
                "{}true{}",
                "true ? ".repeat(n - 1),
                " : false".repeat(n - 1)
            )),
        ),
        (
            "list",
            get_rule(&format!("{}{} != null", "[".repeat(n - 1), "]".repeat(n - 1))),
        ),
        (
            "map",
            get_rule(&format!("{}1{} != null", "{'a': ".repeat(n - 2), "}".repeat(n - 2))),
        ),
        (
            "call",
            wrap(&format!(
                "    function id(x) {{ return x; }}\n    match /c/{{d}} {{ allow get: if {}true{}; }}",
                "id(".repeat(n - 1),
                ")".repeat(n - 1)
            )),
        ),
    ]
}

#[test]
fn expressions_up_to_ninety_nine_levels_deep_compile() {
    for (name, source) in depth_cases(99) {
        compiles(&source).unwrap_or_else(|e| panic!("{name}: {e}"));
    }
    for (name, source) in depth_cases(100) {
        assert_eq!(
            compiles(&source).unwrap_err(),
            "Expression is too complex to evaluate safely.",
            "{name}"
        );
    }
    // Member access and indexing add no level.
    compiles(&get_rule(&format!("request.auth{} == 1", ".a".repeat(300)))).unwrap();
    compiles(&get_rule(&format!("[1]{} == 1", "[0]".repeat(300)))).unwrap();
}

#[test]
fn the_deepest_accepted_expressions_compile_on_a_small_thread_stack() {
    // A request thread's stack, as tokio gives its workers: loading a ruleset must not
    // overflow it at the accepted depth, in a debug build either.
    std::thread::Builder::new()
        .stack_size(2 * 1024 * 1024)
        .spawn(|| {
            for (name, source) in depth_cases(99) {
                compiles(&source).unwrap_or_else(|e| panic!("{name}: {e}"));
            }
            for (name, source) in depth_cases(100) {
                assert!(compiles(&source).is_err(), "{name}");
            }
        })
        .unwrap()
        .join()
        .unwrap();
}
