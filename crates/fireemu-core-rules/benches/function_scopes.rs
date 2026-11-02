//! Per-request setup cost of Rules function scopes with unrelated blocks after an early allow.
//!
//! Compilation (`parse_ruleset`) stays outside the timed loop. Each row reports wall time per
//! evaluation for 0, 100 and 1,000 unrelated match blocks, each declaring one function, appended
//! after a block that allows the request.
//!
//! `function_scopes <literal|function> <unrelated> <iterations>` runs one scenario without
//! timing, so a heap profiler (for example `valgrind --tool=dhat`) can difference the allocation
//! totals of two iteration counts to get allocations per evaluation.

use std::fmt::Write as _;
use std::hint::black_box;
use std::time::Instant;

use fireemu_core_rules::eval::{evaluate_request, Decision, Method, RequestContext, RulesService};
use fireemu_core_rules::parse::parse_ruleset;

fn source(unrelated: usize, condition: &str) -> String {
    let mut source = String::from(
        "rules_version = '2'; service cloud.firestore { function top() { return true; } \
         match /databases/{db}/documents { function inner() { return top(); } \
         match /notes/{id} { allow get: if ",
    );
    source.push_str(condition);
    source.push_str("; }");
    for index in 0..unrelated {
        let _ = write!(
            source,
            " match /unrelated{index}/{{id}} {{ function helper{index}() {{ return id == 'x'; }} allow get: if helper{index}(); }}"
        );
    }
    source.push_str(" } }");
    source
}

fn request() -> RequestContext {
    RequestContext {
        service: RulesService::Firestore,
        method: Method::Get,
        path: "/databases/(default)/documents/notes/one".to_owned(),
        auth: None,
        resource: None,
        request_resource: None,
        time_unix_nanos: 0,
        abstract_path: false,
        request_query: None,
    }
}

fn condition(label: &str) -> &'static str {
    if label == "function" {
        "inner()"
    } else {
        "true"
    }
}

fn main() {
    let request = request();
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let [label, unrelated, iterations] = args.as_slice() {
        let ruleset = parse_ruleset(&source(
            unrelated.parse().expect("unrelated count"),
            condition(label),
        ))
        .expect("rules must parse");
        for _ in 0..iterations.parse::<u32>().expect("iteration count") {
            black_box(evaluate_request(&ruleset, black_box(&request)));
        }
        return;
    }
    let iterations = 2_000u32;
    for label in ["literal", "function"] {
        for unrelated in [0usize, 100, 1_000] {
            let ruleset =
                parse_ruleset(&source(unrelated, condition(label))).expect("rules must parse");
            assert_eq!(
                evaluate_request(&ruleset, &request).decision,
                Decision::Allow
            );
            let started = Instant::now();
            for _ in 0..iterations {
                black_box(evaluate_request(&ruleset, black_box(&request)));
            }
            println!(
                "function_scopes: {label:8} allow, unrelated={unrelated:5}: {:>9.2?}/eval",
                started.elapsed() / iterations,
            );
        }
    }
}
