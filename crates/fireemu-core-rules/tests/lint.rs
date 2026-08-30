//! Static limit linter boundaries (spec 13.5, 13.6, 13.7). N-1 / N / N+1 for every static limit.

use fireemu_core_limits::evaluate::WarningSeverity;
use fireemu_core_rules::lint::{lint_source, DiagnosticLevel, LintOptions};

fn wrap(body: &str) -> String {
    format!("rules_version = '2';\nservice cloud.firestore {{\n  match /databases/{{db}}/documents {{\n{body}\n  }}\n}}\n")
}

fn level_of(src: &str, limit_id: &str) -> Option<DiagnosticLevel> {
    let report = lint_source(src, &LintOptions::default());
    report
        .diagnostics
        .iter()
        .find(|d| d.limit_id == limit_id)
        .map(|d| d.level)
}

fn function_with_params(n: usize) -> String {
    let params: Vec<String> = (0..n).map(|i| format!("p{i}")).collect();
    wrap(&format!(
        "    function f({}) {{ return true; }}\n    allow read: if f({});",
        params.join(", "),
        (0..n).map(|_| "1").collect::<Vec<_>>().join(", ")
    ))
}

#[test]
fn function_arguments_6_7_8() {
    assert_eq!(
        level_of(&function_with_params(5), "RULES-FUNCTION-ARGUMENTS"),
        None
    );
    assert_eq!(
        level_of(&function_with_params(6), "RULES-FUNCTION-ARGUMENTS"),
        Some(DiagnosticLevel::Warning(WarningSeverity::Warning))
    );
    assert_eq!(
        level_of(&function_with_params(7), "RULES-FUNCTION-ARGUMENTS"),
        Some(DiagnosticLevel::Warning(WarningSeverity::Critical))
    );
    assert_eq!(
        level_of(&function_with_params(8), "RULES-FUNCTION-ARGUMENTS"),
        Some(DiagnosticLevel::Error)
    );
    let report = lint_source(&function_with_params(8), &LintOptions::default());
    assert!(
        !report.is_activatable(),
        "an over-limit ruleset must not activate"
    );
    assert!(lint_source(&function_with_params(7), &LintOptions::default()).is_activatable());
}

#[test]
fn call_site_arity_is_checked_independently() {
    let src =
        wrap("    function f(a) { return a; }\n    allow read: if f(1, 2, 3, 4, 5, 6, 7, 8);");
    let report = lint_source(&src, &LintOptions::default());
    assert!(report
        .diagnostics
        .iter()
        .any(|d| d.limit_id == "RULES-FUNCTION-ARGUMENTS" && d.level == DiagnosticLevel::Error));
    assert!(report
        .diagnostics
        .iter()
        .any(|d| d.limit_id == "RULES-CALL-ARITY-MISMATCH"));
}

fn function_with_lets(n: usize) -> String {
    let lets: Vec<String> = (0..n).map(|i| format!("let v{i} = {i};")).collect();
    wrap(&format!(
        "    function f() {{ {} return true; }}\n    allow read: if f();",
        lets.join(" ")
    ))
}

#[test]
fn let_bindings_8_9_10_11() {
    assert_eq!(level_of(&function_with_lets(7), "RULES-LET-BINDINGS"), None);
    assert_eq!(
        level_of(&function_with_lets(8), "RULES-LET-BINDINGS"),
        Some(DiagnosticLevel::Warning(WarningSeverity::Notice))
    );
    assert_eq!(
        level_of(&function_with_lets(9), "RULES-LET-BINDINGS"),
        Some(DiagnosticLevel::Warning(WarningSeverity::Warning))
    );
    assert_eq!(
        level_of(&function_with_lets(10), "RULES-LET-BINDINGS"),
        Some(DiagnosticLevel::Warning(WarningSeverity::Critical))
    );
    assert_eq!(
        level_of(&function_with_lets(11), "RULES-LET-BINDINGS"),
        Some(DiagnosticLevel::Error)
    );
}

#[test]
fn recursion_is_a_compile_error() {
    let direct = wrap("    function f() { return f(); }\n    allow read: if f();");
    assert_eq!(
        level_of(&direct, "RULES-RECURSION"),
        Some(DiagnosticLevel::Error)
    );
    let mutual = wrap("    function f() { return g(); }\n    function g() { return f(); }\n    allow read: if f();");
    assert_eq!(
        level_of(&mutual, "RULES-RECURSION"),
        Some(DiagnosticLevel::Error)
    );
    let acyclic = wrap("    function f() { return g() && g(); }\n    function g() { return true; }\n    allow read: if f();");
    assert_eq!(level_of(&acyclic, "RULES-RECURSION"), None);
}

fn chain(depth: usize) -> String {
    // f0 -> f1 -> ... -> f{depth-1}; the allow calls f0, so the chain has `depth` frames.
    let mut fns = Vec::new();
    for i in 0..depth {
        let body = if i + 1 < depth {
            format!("f{}()", i + 1)
        } else {
            "true".to_owned()
        };
        fns.push(format!("    function f{i}() {{ return {body}; }}"));
    }
    wrap(&format!("{}\n    allow read: if f0();", fns.join("\n")))
}

#[test]
fn call_depth_19_20_21() {
    assert_eq!(
        level_of(&chain(19), "RULES-FUNCTION-CALL-DEPTH"),
        Some(DiagnosticLevel::Warning(WarningSeverity::Critical))
    );
    assert_eq!(
        level_of(&chain(20), "RULES-FUNCTION-CALL-DEPTH"),
        Some(DiagnosticLevel::Warning(WarningSeverity::Critical))
    );
    assert_eq!(
        level_of(&chain(21), "RULES-FUNCTION-CALL-DEPTH"),
        Some(DiagnosticLevel::Error)
    );
    assert_eq!(level_of(&chain(10), "RULES-FUNCTION-CALL-DEPTH"), None);
}

fn nested_matches(depth: usize) -> String {
    // The wrapper already contributes one match level (/databases/{db}/documents).
    use std::fmt::Write as _;
    let mut s = String::new();
    for i in 0..depth {
        writeln!(s, "match /c{i}/{{d{i}}} {{").unwrap();
    }
    s.push_str("allow read: if true;\n");
    for _ in 0..depth {
        s.push('}');
        s.push('\n');
    }
    wrap(&s)
}

#[test]
fn match_depth_10_11() {
    assert_eq!(
        level_of(&nested_matches(9), "RULES-MATCH-DEPTH"),
        Some(DiagnosticLevel::Warning(WarningSeverity::Critical))
    );
    assert_eq!(
        level_of(&nested_matches(10), "RULES-MATCH-DEPTH"),
        Some(DiagnosticLevel::Error)
    );
    assert_eq!(level_of(&nested_matches(6), "RULES-MATCH-DEPTH"), None);
}

#[test]
fn path_segments_and_captures_accumulate_across_nesting() {
    // wrapper: 3 segments, 1 capture. Add a match with 97 segments -> 100 total: allowed.
    let segs: Vec<String> = (0..97).map(|i| format!("s{i}")).collect();
    let ok = wrap(&format!(
        "    match /{} {{ allow read: if true; }}",
        segs.join("/")
    ));
    assert_eq!(
        level_of(&ok, "RULES-MATCH-PATH-SEGMENTS"),
        Some(DiagnosticLevel::Warning(WarningSeverity::Critical))
    );
    let segs: Vec<String> = (0..98).map(|i| format!("s{i}")).collect();
    let over = wrap(&format!(
        "    match /{} {{ allow read: if true; }}",
        segs.join("/")
    ));
    assert_eq!(
        level_of(&over, "RULES-MATCH-PATH-SEGMENTS"),
        Some(DiagnosticLevel::Error)
    );
    // Captures: wrapper has 1; add 19 -> 20 allowed, 20 -> 21 rejected.
    let caps: Vec<String> = (0..19).map(|i| format!("{{c{i}}}")).collect();
    let ok = wrap(&format!(
        "    match /{} {{ allow read: if true; }}",
        caps.join("/")
    ));
    assert_eq!(
        level_of(&ok, "RULES-PATH-CAPTURES"),
        Some(DiagnosticLevel::Warning(WarningSeverity::Critical))
    );
    let caps: Vec<String> = (0..20).map(|i| format!("{{c{i}}}")).collect();
    let over = wrap(&format!(
        "    match /{} {{ allow read: if true; }}",
        caps.join("/")
    ));
    assert_eq!(
        level_of(&over, "RULES-PATH-CAPTURES"),
        Some(DiagnosticLevel::Error)
    );
}

fn padded_to(bytes: usize) -> String {
    let base = wrap("    allow read: if true;");
    // Pad with a trailing comment; multibyte padding checks UTF-8 counting.
    let prefix = format!("{base}// ");
    assert!(bytes > prefix.len());
    let remaining = bytes - prefix.len() - 1; // final newline
    let mut pad = String::new();
    while pad.len() + 3 <= remaining {
        pad.push('日');
    }
    while pad.len() < remaining {
        pad.push('x');
    }
    let s = format!("{prefix}{pad}\n");
    assert_eq!(s.len(), bytes);
    s
}

#[test]
fn source_size_thresholds_and_exclusive_boundary() {
    assert_eq!(level_of(&padded_to(196_607), "RULES-SOURCE-SIZE"), None);
    assert_eq!(
        level_of(&padded_to(196_608), "RULES-SOURCE-SIZE"),
        Some(DiagnosticLevel::Warning(WarningSeverity::Notice))
    );
    assert_eq!(
        level_of(&padded_to(222_822), "RULES-SOURCE-SIZE"),
        Some(DiagnosticLevel::Warning(WarningSeverity::Notice))
    );
    assert_eq!(
        level_of(&padded_to(222_823), "RULES-SOURCE-SIZE"),
        Some(DiagnosticLevel::Warning(WarningSeverity::Warning))
    );
    assert_eq!(
        level_of(&padded_to(249_036), "RULES-SOURCE-SIZE"),
        Some(DiagnosticLevel::Warning(WarningSeverity::Warning))
    );
    assert_eq!(
        level_of(&padded_to(249_037), "RULES-SOURCE-SIZE"),
        Some(DiagnosticLevel::Warning(WarningSeverity::Critical))
    );
    assert_eq!(
        level_of(&padded_to(262_143), "RULES-SOURCE-SIZE"),
        Some(DiagnosticLevel::Warning(WarningSeverity::Critical))
    );
    let report = lint_source(&padded_to(262_144), &LintOptions::default());
    assert_eq!(
        report
            .diagnostics
            .iter()
            .find(|d| d.limit_id == "RULES-SOURCE-SIZE")
            .map(|d| d.level),
        Some(DiagnosticLevel::Error)
    );
    assert!(!report.is_activatable());
    assert_eq!(report.source_size.content_utf8_bytes, 262_144);
}

#[test]
fn source_size_is_reported_even_when_the_source_does_not_parse() {
    let report = lint_source("service cloud.firestore {", &LintOptions::default());
    assert_eq!(report.source_size.content_utf8_bytes, 25);
    assert!(report.parse_error.is_some());
    assert!(!report.is_activatable());
}

#[test]
fn diagnostics_are_deterministically_ordered_and_carry_spans() {
    let src = function_with_params(8);
    let a = lint_source(&src, &LintOptions::default());
    let b = lint_source(&src, &LintOptions::default());
    assert_eq!(a.diagnostics, b.diagnostics);
    let d = a
        .diagnostics
        .iter()
        .find(|d| d.limit_id == "RULES-FUNCTION-ARGUMENTS")
        .unwrap();
    assert!(d.span.is_some());
    assert_eq!(d.subject.as_deref(), Some("f"));
    assert_eq!(d.current, 8);
    assert_eq!(d.maximum, 7);
}

#[test]
fn unused_functions_are_reported_as_notices() {
    let src = wrap("    function unused() { return true; }\n    allow read: if true;");
    let report = lint_source(&src, &LintOptions::default());
    assert!(report
        .diagnostics
        .iter()
        .any(|d| d.limit_id == "RULES-UNUSED-FUNCTION" && d.subject.as_deref() == Some("unused")));
}

#[test]
fn diagnostics_name_their_match_path_and_respect_the_size_boundary() {
    // A deep nest reports the path of the deepest match block.
    let deep = wrap(&format!(
        "{}{}",
        (0..11)
            .map(|i| format!("match /c{i}/{{d{i}}} {{"))
            .collect::<Vec<_>>()
            .join(" "),
        " allow read: if true; }".to_owned() + &"}".repeat(10)
    ));
    let report = lint_source(&deep, &LintOptions::default());
    let depth = report
        .diagnostics
        .iter()
        .find(|d| d.limit_id == "RULES-MATCH-DEPTH")
        .expect("depth diagnostic");
    let subject = depth.subject.as_deref().unwrap_or("");
    assert!(
        subject.contains("{d10}") && subject.contains("c10"),
        "{subject}"
    );
    assert!(depth.current > depth.maximum, "{depth:?}");
    // Below the source size limit there is no size diagnostic at all.
    assert!(level_of(&wrap("allow read: if true;"), "RULES-SOURCE-SIZE").is_none());
    // The deepest call chain is the one reported for RULES-FUNCTION-CALL-DEPTH.
    let chains = wrap(
        "function a1() { return true; } function a2() { return a1(); }\n\
         function b1() { return true; } function b2() { return b1(); } function b3() { return b2(); }\n\
         allow read: if a2() && b3();",
    );
    let report = lint_source(&chains, &LintOptions::default());
    if let Some(d) = report
        .diagnostics
        .iter()
        .find(|d| d.limit_id == "RULES-FUNCTION-CALL-DEPTH")
    {
        assert_eq!(d.current, 3, "{d:?}");
        assert_eq!(d.subject.as_deref(), Some("b3"), "{d:?}");
    }
}
