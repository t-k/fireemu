//! Command-line entry point for the private Quint verification authority.

use std::env;
use std::path::PathBuf;
use std::process::ExitCode;

use fireemu_verification_quint::cargo_authority::{validate_authority_file, write_authority};
use fireemu_verification_quint::evidence::validate_evidence_file_with_cargo_authority;
use fireemu_verification_quint::model::{model, ModelDescriptor};
use fireemu_verification_quint::process::{
    mutate_model as run_mutations, verify_model as run_model, OwnedApalacheServer,
};
use fireemu_verification_quint::publication::publish_evidence as publish_evidence_snapshot;

const USAGE: &str = "Usage:\n  fireemu-verification-quint verify-model --model MODEL --server-endpoint ENDPOINT --server-owner-pid PID [--root PATH]\n  fireemu-verification-quint mutate-model --model MODEL --server-endpoint ENDPOINT --server-owner-pid PID [--root PATH] [--evidence PATH] [--cargo-authority PATH]\n  fireemu-verification-quint verify-evidence --model MODEL [--root PATH] [--evidence PATH] [--cargo-authority PATH]\n  fireemu-verification-quint cargo-authority [--root PATH] (--write PATH | --check PATH)\n  fireemu-verification-quint publish-evidence --source PATH --target PATH\n";

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
    let options = parse_options(arguments, false, true)?;
    run_model(
        &options.root,
        options.descriptor,
        options
            .server
            .as_ref()
            .expect("server is required for model verification"),
    )?;
    println!("{} Quint/TLC model: ok", options.descriptor.name);
    Ok(())
}

fn mutate_model(arguments: &[String]) -> Result<(), String> {
    let options = parse_options(arguments, true, true)?;
    let results = run_mutations(
        &options.root,
        options.descriptor,
        options
            .server
            .as_ref()
            .expect("server is required for mutation verification"),
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
    let options = parse_options(arguments, true, false)?;
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
    server: Option<OwnedApalacheServer>,
}

fn parse_options(
    arguments: &[String],
    accepts_evidence: bool,
    requires_server: bool,
) -> Result<CommandOptions, String> {
    let mut model_name = None;
    let mut root = None;
    let mut evidence = None;
    let mut cargo_authority = None;
    let mut server_endpoint = None;
    let mut server_owner_pid = None;
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
            "--server-endpoint" if requires_server && server_endpoint.is_none() => {
                server_endpoint = Some(value.as_str());
            }
            "--server-owner-pid" if requires_server && server_owner_pid.is_none() => {
                server_owner_pid = Some(value.as_str());
            }
            "--model" | "--root" | "--evidence" | "--cargo-authority" | "--server-endpoint"
            | "--server-owner-pid" => {
                return Err(format!("repeated or unsupported flag {flag:?}"));
            }
            _ => return Err(format!("unknown flag {flag:?}")),
        }
        index += 2;
    }
    let model_name = model_name.ok_or_else(|| "missing required --model MODEL".to_owned())?;
    let descriptor = model(model_name)?;
    let server = if requires_server {
        let endpoint = server_endpoint
            .ok_or_else(|| "missing required --server-endpoint ENDPOINT".to_owned())?;
        let owner_pid =
            server_owner_pid.ok_or_else(|| "missing required --server-owner-pid PID".to_owned())?;
        Some(OwnedApalacheServer::from_authority(endpoint, owner_pid)?)
    } else {
        None
    };
    Ok(CommandOptions {
        descriptor,
        root: root.unwrap_or_else(default_root),
        evidence,
        cargo_authority,
        server,
    })
}
