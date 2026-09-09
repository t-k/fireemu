//! The compatibility-contract gate (`spec/compatibility/contract.json`).
//!
//! Usage: `compat-check [--root <repo root>] [--write-inventory]`.

use std::path::PathBuf;
use std::process::ExitCode;

use compat_check::check;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut root = PathBuf::from(".");
    let mut write_inventory = false;
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--root" {
            if let Some(v) = args.get(i + 1) {
                root = PathBuf::from(v);
            } else {
                eprintln!("error: --root needs a path");
                return ExitCode::FAILURE;
            }
            i += 2;
        } else if args[i] == "--write-inventory" {
            write_inventory = true;
            i += 1;
        } else {
            eprintln!("error: unknown argument {}", args[i]);
            return ExitCode::FAILURE;
        }
    }
    let mut report = check(&root);
    if write_inventory && report.is_ok() {
        if let Err(problems) = compat_check::inventory::generate(&root) {
            for problem in problems {
                eprintln!("error: {problem}");
            }
            return ExitCode::FAILURE;
        }
    }
    report
        .problems
        .extend(compat_check::inventory::check(&root).problems);
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
