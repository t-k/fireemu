//! Command-line entry point for the private Quint verification authority.

use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

use fireemu_verification_quint::cargo_authority::{validate_authority_file, write_authority};
use fireemu_verification_quint::evidence::{
    current_input_digest, expected_bound_inputs, validate_evidence_file_with_cargo_authority,
    InputDigest,
};
use fireemu_verification_quint::model::{all_models, model, ModelDescriptor};
use fireemu_verification_quint::process::{
    mutate_model as run_mutations, verify_model as run_model,
};
use fireemu_verification_quint::publication::publish_evidence as publish_evidence_snapshot;

const USAGE: &str = "Usage:\n  fireemu-verification-quint verify-model --model MODEL [--root PATH]\n  fireemu-verification-quint mutate-model --model MODEL [--root PATH] [--evidence PATH] [--cargo-authority PATH]\n  fireemu-verification-quint verify-evidence --model MODEL [--root PATH] [--evidence PATH] [--cargo-authority PATH]\n  fireemu-verification-quint check-evidence\n  fireemu-verification-quint cargo-authority [--root PATH] (--write PATH | --check PATH)\n  fireemu-verification-quint publish-evidence --source PATH --target PATH\n";

fn main() -> ExitCode {
    let arguments = env::args().skip(1).collect::<Vec<_>>();
    if arguments.first().map(String::as_str) == Some("check-evidence") {
        return match check_evidence(&arguments[1..]) {
            Ok(false) => ExitCode::SUCCESS,
            Ok(true) => ExitCode::from(1),
            Err(error) => {
                eprintln!("error: {error}\n\n{USAGE}");
                ExitCode::from(2)
            }
        };
    }
    match run(&arguments) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}\n\n{USAGE}");
            ExitCode::from(2)
        }
    }
}

#[allow(clippy::too_many_lines)]
fn check_evidence(arguments: &[String]) -> Result<bool, String> {
    if !arguments.is_empty() {
        return Err("check-evidence accepts no arguments".to_owned());
    }
    let root =
        env::current_dir().map_err(|error| format!("cannot read current directory: {error}"))?;
    let directory = root.join("verification/quint/evidence");
    let mut files = match fs::read_dir(&directory) {
        Ok(entries) => entries
            .map(|entry| {
                entry
                    .map(|entry| entry.path())
                    .map_err(|error| error.to_string())
            })
            .collect::<Result<Vec<_>, _>>()?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(error) => return Err(format!("cannot read evidence directory: {error}")),
    };
    files.sort();
    let mut stale = 0;
    for descriptor in all_models() {
        let model = descriptor.name;
        if !directory.join(format!("{model}.json")).is_file() {
            stale += 1;
            println!("STALE {model}: evidence file missing; regenerate");
            println!("QUINT_HOME=$HOME/.quint cargo run -p fireemu-verification-quint -- mutate-model --model {model} --evidence verification/quint/evidence/{model}.json");
        }
    }
    for file in files {
        if file.extension().and_then(|extension| extension.to_str()) != Some("json")
            || file.file_name().and_then(|name| name.to_str()) == Some("cargo-authority.json")
        {
            continue;
        }
        let model = file
            .file_stem()
            .and_then(|name| name.to_str())
            .ok_or("invalid evidence filename")?;
        let bytes =
            fs::read(&file).map_err(|error| format!("cannot read {}: {error}", file.display()))?;
        let evidence: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|error| format!("invalid evidence {}: {error}", file.display()))?;
        let digests = evidence.get("digests").and_then(|value| value.as_object());
        let inputs = evidence
            .get("boundInputs")
            .and_then(|value| value.as_array())
            .ok_or_else(|| format!("missing bound inputs in {}", file.display()))?;
        let legacy = digests.is_none_or(|digests| {
            digests.is_empty() || digests.values().any(|digest| digest.get("kind").is_none())
        });
        let obsolete = digests.is_some_and(|digests| {
            digests
                .values()
                .any(|digest| digest.get("kind").and_then(|v| v.as_str()) == Some("yaml-workflow"))
        });
        let obsolete_rust = digests.is_some_and(|digests| {
            digests
                .values()
                .any(|digest| digest.get("kind").and_then(|v| v.as_str()) == Some("rust-semantic"))
        });
        let inventory_changed =
            fireemu_verification_quint::model::model(model).is_ok_and(|descriptor| {
                let recorded = inputs
                    .iter()
                    .map(|input| input.as_str())
                    .collect::<Option<Vec<_>>>();
                match (recorded, expected_bound_inputs(&root, descriptor, None)) {
                    (Some(recorded), Ok(expected)) => {
                        recorded != expected.iter().map(String::as_str).collect::<Vec<_>>()
                    }
                    _ => true,
                }
            });
        let mut changed = Vec::new();
        if !legacy && !obsolete && !obsolete_rust {
            for input in inputs {
                let path = input
                    .as_str()
                    .ok_or_else(|| format!("invalid bound input in {}", file.display()))?;
                let recorded = digests
                    .and_then(|digests| digests.get(path))
                    .and_then(|value| serde_json::from_value::<InputDigest>(value.clone()).ok());
                let current = current_input_digest(&root, path).ok();
                if recorded.is_none() || current.is_none() || recorded != current {
                    changed.push(path);
                }
            }
        }
        if legacy || obsolete || obsolete_rust || inventory_changed || !changed.is_empty() {
            stale += 1;
            if legacy {
                println!("STALE {model}: evidence predates digest kinds; regenerate");
            } else if obsolete {
                println!("STALE {model}: obsolete workflow digest kind; regenerate");
            } else if obsolete_rust {
                println!("STALE {model}: obsolete Rust digest kind; regenerate");
            } else if inventory_changed {
                println!("STALE {model}: required bound input inventory changed; regenerate");
            } else {
                println!(
                    "STALE {model}: {} bound input(s) changed since its evidence was written",
                    changed.len()
                );
                for path in changed {
                    println!("  {path}");
                }
            }
            println!("QUINT_HOME=$HOME/.quint cargo run -p fireemu-verification-quint -- mutate-model --model {model} --evidence verification/quint/evidence/{model}.json");
        }
    }
    println!("evidence digests stale: {stale}");
    Ok(stale != 0)
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
        Some("cargo-authority") => cargo_authority(&arguments[1..]),
        Some("publish-evidence") => publish_evidence(&arguments[1..]),
        Some(other) => Err(format!("unknown command {other:?}")),
        None => Err("missing command".to_owned()),
    }
}

fn publish_evidence(arguments: &[String]) -> Result<(), String> {
    let mut source = None;
    let mut target = None;
    let mut index = 0;
    while index < arguments.len() {
        let flag = &arguments[index];
        let value = arguments
            .get(index + 1)
            .ok_or_else(|| format!("missing value for {flag:?}"))?;
        match flag.as_str() {
            "--source" if source.is_none() => source = Some(PathBuf::from(value)),
            "--target" if target.is_none() => target = Some(PathBuf::from(value)),
            "--source" | "--target" => {
                return Err(format!("repeated flag {flag:?}"));
            }
            _ => return Err(format!("unknown flag {flag:?}")),
        }
        index += 2;
    }
    let source = source.ok_or_else(|| "missing required --source PATH".to_owned())?;
    let target = target.ok_or_else(|| "missing required --target PATH".to_owned())?;
    publish_evidence_snapshot(&source, &target)
}

fn cargo_authority(arguments: &[String]) -> Result<(), String> {
    let mut root = None;
    let mut action = None;
    let mut index = 0;
    while index < arguments.len() {
        let flag = &arguments[index];
        let value = arguments
            .get(index + 1)
            .ok_or_else(|| format!("missing value for {flag:?}"))?;
        match flag.as_str() {
            "--root" if root.is_none() => root = Some(PathBuf::from(value)),
            "--write" | "--check" if action.is_none() => {
                action = Some((flag.as_str(), PathBuf::from(value)));
            }
            _ => return Err(format!("repeated or unsupported flag {flag:?}")),
        }
        index += 2;
    }
    let root = root.unwrap_or_else(default_root);
    match action {
        Some(("--write", path)) => write_authority(&root, &path),
        Some(("--check", path)) => validate_authority_file(&root, &path),
        Some(_) => unreachable!("only known actions are stored"),
        None => Err("missing required --write PATH or --check PATH".to_owned()),
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
        options.cargo_authority.as_deref(),
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
    let validated = validate_evidence_file_with_cargo_authority(
        &options.root,
        &evidence,
        options.descriptor,
        options.cargo_authority.as_deref(),
    )?;
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
    cargo_authority: Option<PathBuf>,
}

fn parse_options(arguments: &[String], accepts_evidence: bool) -> Result<CommandOptions, String> {
    let mut model_name = None;
    let mut root = None;
    let mut evidence = None;
    let mut cargo_authority = None;
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
            "--cargo-authority" if accepts_evidence && cargo_authority.is_none() => {
                cargo_authority = Some(PathBuf::from(value));
            }
            "--model" | "--root" | "--evidence" | "--cargo-authority" => {
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
        cargo_authority,
    })
}
