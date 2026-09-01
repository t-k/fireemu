//! Command-line entry point for the private Quint verification pilot.

use std::env;
use std::path::PathBuf;
use std::process::ExitCode;

use fireemu_verification_quint::process::verify_event_delivery_model;

const USAGE: &str = "Usage:\n  fireemu-verification-quint verify-model [--root PATH]\n";

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
        Some(other) => Err(format!("unknown command {other:?}")),
        None => Err("missing command".to_owned()),
    }
}

fn verify_model(arguments: &[String]) -> Result<(), String> {
    let root = match arguments {
        [] => PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(|path| path.parent())
            .expect("verification/quint must have a repository parent")
            .to_path_buf(),
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
