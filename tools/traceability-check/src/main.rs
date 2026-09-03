//! Requirement traceability check (spec 32, CI step 31.1 #12 and #16).
//!
//! Usage: `traceability-check [--root <repo root>]`.

use std::path::PathBuf;
use std::process::ExitCode;

use fireemu_verification_quint::cargo_authority::validate_authority_file;
use traceability_check::check_with_quint_evidence;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut root = PathBuf::from(".");
    let mut quint_evidence_dir = None;
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--root" {
            let Some(value) = args.get(i + 1) else {
                eprintln!("error: missing value for --root");
                return ExitCode::FAILURE;
            };
            root = PathBuf::from(value);
            i += 2;
        } else if args[i] == "--quint-evidence-dir" {
            let Some(value) = args.get(i + 1) else {
                eprintln!("error: missing value for --quint-evidence-dir");
                return ExitCode::FAILURE;
            };
            quint_evidence_dir = Some(PathBuf::from(value));
            i += 2;
        } else {
            eprintln!("error: unknown argument {}", args[i]);
            return ExitCode::FAILURE;
        }
    }
    let quint_evidence_dir =
        quint_evidence_dir.unwrap_or_else(|| root.join("verification/quint/evidence"));
    if let Err(error) =
        validate_authority_file(&root, &quint_evidence_dir.join("cargo-authority.json"))
    {
        eprintln!("error: {error}");
        return ExitCode::FAILURE;
    }
    let report = check_with_quint_evidence(&root, Some(&quint_evidence_dir));
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
