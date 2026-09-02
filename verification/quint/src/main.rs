//! Command-line entry point for the private Quint verification authority.

use std::env;
use std::path::PathBuf;
use std::process::ExitCode;

use fireemu_verification_quint::evidence::validate_evidence_file;
use fireemu_verification_quint::model::{model, ModelDescriptor};
use fireemu_verification_quint::process::{
    mutate_model as run_mutations, verify_model as run_model,
};

const USAGE: &str = "Usage:\n  fireemu-verification-quint verify-model --model MODEL [--root PATH]\n  fireemu-verification-quint mutate-model --model MODEL [--root PATH] [--evidence PATH]\n  fireemu-verification-quint verify-evidence --model MODEL [--root PATH] [--evidence PATH]\n";

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
        Some("mutate-model") => mutate_model(&arguments[1..]),
        Some("mutate-event-delivery") => {
            let mut compatible = vec!["--model".to_owned(), "EventDelivery".to_owned()];
            compatible.extend_from_slice(&arguments[1..]);
            mutate_model(&compatible)
        }
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
    let options = parse_options(arguments, false)?;
    run_model(&options.root, options.descriptor)?;
    println!("{} Quint/TLC model: ok", options.descriptor.name);
    Ok(())
}

fn mutate_model(arguments: &[String]) -> Result<(), String> {
    let options = parse_options(arguments, true)?;
    let results = run_mutations(
        &options.root,
        options.descriptor,
        options.evidence.as_deref(),
    )?;
    println!(
        "{} Quint mutants killed: {}",
        options.descriptor.name,
        results.len()
    );
    Ok(())
}

fn verify_evidence(arguments: &[String]) -> Result<(), String> {
    let options = parse_options(arguments, true)?;
    let evidence = options.evidence.unwrap_or_else(|| {
        options.root.join(format!(
            "verification/quint/evidence/{}.json",
            options.descriptor.name
        ))
    });
    let validated = validate_evidence_file(&options.root, &evidence, options.descriptor)?;
    if validated.model != options.descriptor.name {
        return Err(format!(
            "evidence model {} does not match requested model {}",
            validated.model, options.descriptor.name
        ));
    }
    println!("{} Quint evidence: ok", options.descriptor.name);
    Ok(())
}

struct CommandOptions {
    descriptor: &'static ModelDescriptor,
    root: PathBuf,
    evidence: Option<PathBuf>,
}

fn parse_options(arguments: &[String], accepts_evidence: bool) -> Result<CommandOptions, String> {
    let mut model_name = None;
    let mut root = None;
    let mut evidence = None;
    let mut index = 0;
    while index < arguments.len() {
        let flag = &arguments[index];
        let value = arguments
            .get(index + 1)
            .ok_or_else(|| format!("missing value for {flag:?}"))?;
        match flag.as_str() {
            "--model" if model_name.is_none() => model_name = Some(value.as_str()),
            "--root" if root.is_none() => root = Some(PathBuf::from(value)),
            "--evidence" if accepts_evidence && evidence.is_none() => {
                evidence = Some(PathBuf::from(value));
            }
            "--model" | "--root" | "--evidence" => {
                return Err(format!("repeated or unsupported flag {flag:?}"));
            }
            _ => return Err(format!("unknown flag {flag:?}")),
        }
        index += 2;
    }
    let model_name = model_name.ok_or_else(|| "missing required --model MODEL".to_owned())?;
    let descriptor = model(model_name)?;
    Ok(CommandOptions {
        descriptor,
        root: root.unwrap_or_else(default_root),
        evidence,
    })
}
