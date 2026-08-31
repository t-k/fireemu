//! Manual command-line entry point for TLA+ mutation and evidence verification.

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use tla_verification::{
    event_replay::replay_event_trace,
    event_trace::{
        convert_eventdelivery_tlc_trace, generate_eventdelivery_traces, parse_event_trace,
    },
    run_mutations, verify_repository_evidence, verify_triage_report, RunOptions,
};

const USAGE: &str = "Usage:\n  tla-verification mutate --module PATH --config PATH --manifest PATH --jar PATH --evidence PATH [--java PATH] [--timeout-seconds N]\n  tla-verification verify-evidence [--root PATH] [--jar PATH]\n  tla-verification verify-triage [--root PATH] [--report PATH]\n  tla-verification trace-generate-eventdelivery [--root PATH] [--jar PATH] [--output-dir PATH] [--java PATH] [--timeout-seconds N]\n  tla-verification trace-convert --input PATH --output PATH --scenario NAME --max-attempts N\n  tla-verification check-eventdelivery [--root PATH] [--trace PATH]\n";

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
    let Some(command) = arguments.first().map(String::as_str) else {
        return Err("missing command".to_owned());
    };
    match command {
        "-h" | "--help" | "help" => {
            print!("{USAGE}");
            Ok(())
        }
        "mutate" => mutate(&arguments[1..]),
        "verify-evidence" => verify(&arguments[1..]),
        "verify-triage" => verify_triage(&arguments[1..]),
        "trace-generate-eventdelivery" => trace_generate_eventdelivery(&arguments[1..]),
        "trace-convert" => trace_convert(&arguments[1..]),
        "check-eventdelivery" => check_eventdelivery(&arguments[1..]),
        other => Err(format!("unknown command {other:?}")),
    }
}

fn trace_generate_eventdelivery(arguments: &[String]) -> Result<(), String> {
    let mut flags = parse_flags(arguments)?;
    let root = flags
        .remove("root")
        .map_or_else(|| PathBuf::from("."), PathBuf::from);
    let jar = flags
        .remove("jar")
        .map_or_else(|| root.join(".tools/tla2tools-1.8.0.jar"), PathBuf::from);
    let output_dir = flags.remove("output-dir").map_or_else(
        || PathBuf::from("verification/tla/traces/EventDelivery"),
        PathBuf::from,
    );
    let java = flags
        .remove("java")
        .map_or_else(|| PathBuf::from("java"), PathBuf::from);
    let timeout = flags
        .remove("timeout-seconds")
        .map_or(Ok(600_u64), |value| {
            value
                .parse::<u64>()
                .map_err(|error| format!("invalid --timeout-seconds: {error}"))
        })?;
    reject_unused_flags(&flags)?;
    let outputs = generate_eventdelivery_traces(
        &root,
        &jar,
        &java,
        &output_dir,
        Duration::from_secs(timeout),
    )?;
    for output in outputs {
        println!("generated: {}", output.display());
    }
    Ok(())
}

fn trace_convert(arguments: &[String]) -> Result<(), String> {
    let mut flags = parse_flags(arguments)?;
    let input = required_path(&mut flags, "input")?;
    let output = required_path(&mut flags, "output")?;
    let scenario = flags
        .remove("scenario")
        .ok_or_else(|| "missing --scenario".to_owned())?;
    let max_attempts = flags
        .remove("max-attempts")
        .ok_or_else(|| "missing --max-attempts".to_owned())?
        .parse::<u32>()
        .map_err(|error| format!("invalid --max-attempts: {error}"))?;
    reject_unused_flags(&flags)?;
    let raw = fs::read_to_string(&input)
        .map_err(|error| format!("cannot read {}: {error}", input.display()))?;
    let trace = convert_eventdelivery_tlc_trace(&raw, &scenario, max_attempts)?;
    let mut canonical = serde_json::to_string_pretty(&trace).map_err(|error| error.to_string())?;
    canonical.push('\n');
    fs::write(&output, canonical)
        .map_err(|error| format!("cannot write {}: {error}", output.display()))?;
    println!(
        "{}: converted {} TLC states",
        trace.scenario,
        trace.steps.len() + 1
    );
    Ok(())
}

fn check_eventdelivery(arguments: &[String]) -> Result<(), String> {
    let mut flags = parse_flags(arguments)?;
    let root = flags
        .remove("root")
        .map_or_else(|| PathBuf::from("."), PathBuf::from);
    let trace_path = flags.remove("trace").map(PathBuf::from);
    reject_unused_flags(&flags)?;
    let trace_paths = trace_path.map_or_else(
        || {
            ["success", "retry-exhaustion", "stale-discard", "cancel"]
                .map(|scenario| {
                    root.join(format!(
                        "verification/tla/traces/EventDelivery/{scenario}.json"
                    ))
                })
                .to_vec()
        },
        |path| vec![path],
    );
    for trace_path in trace_paths {
        let json = fs::read_to_string(&trace_path)
            .map_err(|error| format!("cannot read {}: {error}", trace_path.display()))?;
        let trace = parse_event_trace(&json)?;
        let report = replay_event_trace(&trace)?;
        println!("{}: ok ({} steps)", report.scenario, report.steps_checked);
    }
    Ok(())
}

fn verify_triage(arguments: &[String]) -> Result<(), String> {
    let mut flags = parse_flags(arguments)?;
    let root = flags
        .remove("root")
        .map_or_else(|| PathBuf::from("."), PathBuf::from);
    let report = flags.remove("report").map_or_else(
        || root.join("verification/tla/triage/2026-08-31-full-property.json"),
        PathBuf::from,
    );
    reject_unused_flags(&flags)?;
    let count = verify_triage_report(&root, &report)?;
    println!("TLA mutation triage: ok ({count} candidates, 0 open)");
    Ok(())
}

fn mutate(arguments: &[String]) -> Result<(), String> {
    let mut flags = parse_flags(arguments)?;
    let timeout = flags
        .remove("timeout-seconds")
        .map_or(Ok(600_u64), |value| {
            value
                .parse::<u64>()
                .map_err(|error| format!("invalid --timeout-seconds: {error}"))
        })?;
    let options = RunOptions {
        module: required_path(&mut flags, "module")?,
        config: required_path(&mut flags, "config")?,
        manifest: required_path(&mut flags, "manifest")?,
        jar: required_path(&mut flags, "jar")?,
        evidence: required_path(&mut flags, "evidence")?,
        java_bin: flags
            .remove("java")
            .map_or_else(|| PathBuf::from("java"), PathBuf::from),
        timeout: Duration::from_secs(timeout),
    };
    reject_unused_flags(&flags)?;
    let evidence = run_mutations(&options)?;
    for result in &evidence.results {
        println!("{}: {:?}", result.id, result.outcome);
    }
    if evidence
        .results
        .iter()
        .all(|result| result.outcome.is_killed())
    {
        Ok(())
    } else {
        Err(format!(
            "one or more {} mutations were not killed",
            evidence.model
        ))
    }
}

fn verify(arguments: &[String]) -> Result<(), String> {
    let mut flags = parse_flags(arguments)?;
    let root = flags
        .remove("root")
        .map_or_else(|| PathBuf::from("."), PathBuf::from);
    let jar = flags
        .remove("jar")
        .map_or_else(|| root.join(".tools/tla2tools-1.8.0.jar"), PathBuf::from);
    reject_unused_flags(&flags)?;
    let verified = verify_repository_evidence(&root, &jar)?;
    for model in &verified {
        println!("verified: {model}");
    }
    println!("TLA mutation evidence: ok ({} model(s))", verified.len());
    Ok(())
}

fn parse_flags(arguments: &[String]) -> Result<BTreeMap<String, String>, String> {
    let mut flags = BTreeMap::new();
    let mut index = 0;
    while index < arguments.len() {
        let flag = arguments[index]
            .strip_prefix("--")
            .ok_or_else(|| format!("expected a --flag, found {:?}", arguments[index]))?;
        let value = arguments
            .get(index + 1)
            .ok_or_else(|| format!("--{flag} requires a value"))?;
        if flags.insert(flag.to_owned(), value.clone()).is_some() {
            return Err(format!("--{flag} was supplied more than once"));
        }
        index += 2;
    }
    Ok(flags)
}

fn required_path(flags: &mut BTreeMap<String, String>, name: &str) -> Result<PathBuf, String> {
    flags
        .remove(name)
        .map(PathBuf::from)
        .ok_or_else(|| format!("missing --{name}"))
}

fn reject_unused_flags(flags: &BTreeMap<String, String>) -> Result<(), String> {
    match flags.keys().next() {
        Some(flag) => Err(format!("unknown flag --{flag}")),
        None => Ok(()),
    }
}
