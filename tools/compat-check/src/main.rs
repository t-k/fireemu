//! The compatibility-contract gate (`spec/compatibility/contract.json`).
//!
//! Usage: `compat-check [--root <repo root>]`.

use std::path::PathBuf;
use std::process::ExitCode;

use compat_check::check;

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
    for note in &report.notes {
        println!("compatibility: {note}");
    }
    if report.is_ok() {
        println!("compatibility: ok");
        ExitCode::SUCCESS
    } else {
        for problem in &report.problems {
            eprintln!("error: {problem}");
        }
        eprintln!("compatibility: {} problem(s)", report.problems.len());
        ExitCode::FAILURE
    }
}
