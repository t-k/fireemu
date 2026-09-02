//! Micro-benchmark separating a roughly 1,000-node Rules evaluation from coverage merge.

use std::hint::black_box;
use std::time::Instant;

use fireemu_core_rules::coverage::Coverage;
use fireemu_core_rules::eval::{evaluate_request_traced, Method, RequestContext, RulesService};
use fireemu_core_rules::parse::parse_ruleset;

fn main() {
    let condition = vec!["true"; 500].join(" && ");
    let ruleset = parse_ruleset(&format!(
        "rules_version = '2'; service cloud.firestore {{ match /databases/{{database}}/documents {{ match /notes/{{id}} {{ allow get: if {condition}; }} }} }}"
    ))
    .expect("benchmark rules must parse");
    let request = RequestContext {
        service: RulesService::Firestore,
        method: Method::Get,
        path: "/databases/(default)/documents/notes/one".to_owned(),
        auth: None,
        resource: None,
        request_resource: None,
        time_unix_nanos: 0,
        abstract_path: false,
        request_query: None,
    };
    let iterations = 1_000u32;

    let evaluation_started = Instant::now();
    let mut recordings = Vec::with_capacity(iterations as usize);
    for _ in 0..iterations {
        let (_, coverage) = evaluate_request_traced(&ruleset, black_box(&request), None);
        recordings.push(coverage);
    }
    let evaluation_elapsed = evaluation_started.elapsed();

    let merge_started = Instant::now();
    let mut accumulated = Coverage::default();
    for coverage in &recordings {
        accumulated.merge(black_box(coverage));
    }
    let merge_elapsed = merge_started.elapsed();

    println!(
        "coverage_merge: {iterations} evaluations in {evaluation_elapsed:?}; merges in {merge_elapsed:?}"
    );
}
