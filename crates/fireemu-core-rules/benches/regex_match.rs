//! Micro-benchmark for a backtracking-heavy compiled Rules regular expression.

use std::hint::black_box;
use std::time::Instant;

use fireemu_core_rules::regex::Regex;

fn main() {
    let regex = Regex::new("^(?:a|aa)*b$").expect("benchmark pattern must compile");
    let subject = format!("{}b", "a".repeat(32));
    let iterations = 100_000u32;
    let started = Instant::now();

    for _ in 0..iterations {
        let matched = regex
            .is_full_match(black_box(&subject))
            .expect("benchmark input must stay within matcher budgets");
        black_box(matched);
    }

    let elapsed = started.elapsed();
    println!(
        "regex_match: {iterations} iterations in {elapsed:?} ({:?}/iteration)",
        elapsed / iterations
    );
}
