//! Command-line entry point for the private Quint verification pilot.

use std::env;
use std::path::PathBuf;
use std::process::ExitCode;

use fireemu_verification_quint::evidence::validate_evidence_file;
use fireemu_verification_quint::process::{mutate_event_delivery, verify_event_delivery_model};

const USAGE: &str = "Usage:\n  fireemu-verification-quint verify-model [--root PATH]\n  fireemu-verification-quint mutate-event-delivery [--root PATH] [--evidence PATH]\n  fireemu-verification-quint verify-evidence [--root PATH] [--evidence PATH]\n";

fn main() -> ExitCode {
    let arguments = env::args().skip(1).collect::<Vec<_>>();
    match run(&arguments) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}\n\n{USAGE}");
            ExitCode::from(2)
        }
    }
}

fn run(arguments: &[String]) -> Result<(), String> {
    match arguments.first().map(String::as_str) {
        Some("-h" | "--help" | "help") => {
            print!("{USAGE}");
            Ok(())
        }
        Some("verify-model") => verify_model(&arguments[1..]),
        Some("mutate-event-delivery") => mutate_model(&arguments[1..]),
        Some("verify-evidence") => verify_evidence(&arguments[1..]),
        Some(other) => Err(format!("unknown command {other:?}")),
        None => Err("missing command".to_owned()),
    }
}

fn default_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .expect("verification/quint must have a repository parent")
        .to_path_buf()
}

fn verify_model(arguments: &[String]) -> Result<(), String> {
    let root = match arguments {
        [] => default_root(),
        [flag, value] if flag == "--root" => PathBuf::from(value),
        [flag, _] => return Err(format!("unknown flag {flag:?}")),
        _ => {
            return Err("verify-model accepts only one optional --root PATH argument".to_owned());
        }
    };
    verify_event_delivery_model(&root)?;
    println!("EventDelivery Quint/TLC model: ok");
    Ok(())
}

fn mutate_model(arguments: &[String]) -> Result<(), String> {
    let mut root = None;
    let mut evidence = None;
    let mut index = 0;
    while index < arguments.len() {
        let flag = &arguments[index];
        let value = arguments
            .get(index + 1)
            .ok_or_else(|| format!("missing value for {flag:?}"))?;
        match flag.as_str() {
            "--root" if root.is_none() => root = Some(PathBuf::from(value)),
            "--evidence" if evidence.is_none() => evidence = Some(PathBuf::from(value)),
            "--root" | "--evidence" => return Err(format!("repeated flag {flag:?}")),
            _ => return Err(format!("unknown flag {flag:?}")),
        }
        index += 2;
    }
    let root = root.unwrap_or_else(default_root);
    let results = mutate_event_delivery(&root, evidence.as_deref())?;
    println!("EventDelivery Quint mutants killed: {}", results.len());
    Ok(())
}

fn verify_evidence(arguments: &[String]) -> Result<(), String> {
    let mut root = None;
    let mut evidence = None;
    let mut index = 0;
    while index < arguments.len() {
        let flag = &arguments[index];
        let value = arguments
            .get(index + 1)
            .ok_or_else(|| format!("missing value for {flag:?}"))?;
        match flag.as_str() {
            "--root" if root.is_none() => root = Some(PathBuf::from(value)),
            "--evidence" if evidence.is_none() => evidence = Some(PathBuf::from(value)),
            "--root" | "--evidence" => return Err(format!("repeated flag {flag:?}")),
            _ => return Err(format!("unknown flag {flag:?}")),
        }
        index += 2;
    }
    let root = root.unwrap_or_else(default_root);
    let evidence =
        evidence.unwrap_or_else(|| root.join("verification/quint/evidence/EventDelivery.json"));
    validate_evidence_file(&root, &evidence)?;
    println!("EventDelivery Quint evidence: ok");
    Ok(())
}
