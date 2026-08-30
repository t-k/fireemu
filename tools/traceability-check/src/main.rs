//! Requirement traceability check (spec 32, CI step 31.1 #12 and #16).
//!
//! Usage: `traceability-check [--root <repo root>]`.

use std::path::PathBuf;
use std::process::ExitCode;

use traceability_check::check;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut root = PathBuf::from(".");
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--root" {
            if let Some(v) = args.get(i + 1) {
                root = PathBuf::from(v);
            }
            i += 2;
        } else {
            eprintln!("error: unknown argument {}", args[i]);
            return ExitCode::FAILURE;
        }
    }
    let report = check(&root);
    for p in &report.pending {
        println!("pending: {p}");
    }
    if report.is_ok() {
        println!(
            "traceability: ok ({} pending artifact(s))",
            report.pending.len()
        );
        ExitCode::SUCCESS
    } else {
        for p in &report.problems {
            eprintln!("error: {p}");
        }
        eprintln!("traceability: {} problem(s)", report.problems.len());
        ExitCode::FAILURE
    }
}
