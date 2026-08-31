//! Safe creation of a canonical `fireemu.json`.

use std::io::{IsTerminal as _, Write};
use std::path::{Path, PathBuf};

use crate::config::CANONICAL_SCHEMA_URL;
use crate::CliError;

#[derive(Clone, Copy)]
enum Profile {
    Strict,
    Firebase,
}

impl Profile {
    fn parse(value: &str) -> Result<Self, CliError> {
        match value {
            "strict" => Ok(Self::Strict),
            "firebase" => Ok(Self::Firebase),
            _ => Err(CliError::usage(format!(
                "--profile {value:?} is not one of strict, firebase"
            ))),
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Strict => "strict",
            Self::Firebase => "firebase",
        }
    }
}

#[derive(Clone, Copy)]
enum Interaction {
    Auto,
    Interactive,
    NonInteractive,
}

struct InitArgs {
    profile: Option<Profile>,
    firebase_json: Option<PathBuf>,
    force: bool,
    interaction: Interaction,
}

/// Creates `fireemu.json` in the current directory.
pub fn run(args: &[String]) -> Result<PathBuf, CliError> {
    let options = parse_args(args)?;
    let cwd = std::env::current_dir()
        .map_err(|e| CliError::refused(format!("cannot resolve the working directory: {e}")))?;
    let terminals = std::io::stdin().is_terminal() && std::io::stdout().is_terminal();
    let mut input = std::io::stdin().lock();
    let mut output = std::io::stdout().lock();
    let options = complete_options(options, &cwd, &mut input, &mut output, terminals)?;
    let destination = cwd.join("fireemu.json");
    let mut document = serde_json::json!({
        "$schema": CANONICAL_SCHEMA_URL,
        "schemaVersion": 1,
        "profile": options.profile.unwrap_or(Profile::Strict).as_str(),
        "firestore": {
            "edition": "standard",
            "apiMode": "native"
        }
    });
    if let Some(firebase_json) = options.firebase_json {
        let firebase_json = firebase_json.to_str().ok_or_else(|| {
            CliError::refused("the Firebase configuration path is not UTF-8".to_owned())
        })?;
        document["firebaseJson"] = firebase_json.into();
    }
    let mut bytes = serde_json::to_vec_pretty(&document)
        .map_err(|e| CliError::refused(format!("cannot serialize fireemu.json: {e}")))?;
    bytes.push(b'\n');
    write_config(&destination, &bytes, options.force)?;
    Ok(destination)
}

fn parse_args(args: &[String]) -> Result<InitArgs, CliError> {
    let mut profile = None;
    let mut firebase_json = None;
    let mut force = false;
    let mut interaction = Interaction::Auto;
    let mut interaction_set = false;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--profile" => {
                if profile.is_some() {
                    return Err(CliError::usage("--profile may be supplied only once"));
                }
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| CliError::usage("--profile needs a value"))?;
                profile = Some(Profile::parse(value)?);
                index += 2;
            }
            "--firebase-json" => {
                if firebase_json.is_some() {
                    return Err(CliError::usage("--firebase-json may be supplied only once"));
                }
                firebase_json =
                    Some(PathBuf::from(args.get(index + 1).ok_or_else(|| {
                        CliError::usage("--firebase-json needs a value")
                    })?));
                index += 2;
            }
            "--interactive" | "--yes" | "--no-interactive" => {
                if interaction_set {
                    return Err(CliError::usage(
                        "use only one of --interactive, --yes, --no-interactive",
                    ));
                }
                interaction = if args[index] == "--interactive" {
                    Interaction::Interactive
                } else {
                    Interaction::NonInteractive
                };
                interaction_set = true;
                index += 1;
            }
            "--force" => {
                if force {
                    return Err(CliError::usage("--force may be supplied only once"));
                }
                force = true;
                index += 1;
            }
            other => return Err(CliError::usage(format!("unknown init argument {other}"))),
        }
    }
    Ok(InitArgs {
        profile,
        firebase_json,
        force,
        interaction,
    })
}

fn complete_options(
    mut options: InitArgs,
    cwd: &Path,
    input: &mut impl std::io::BufRead,
    output: &mut impl Write,
    terminals: bool,
) -> Result<InitArgs, CliError> {
    let interactive = match options.interaction {
        Interaction::Auto => terminals,
        Interaction::Interactive => true,
        Interaction::NonInteractive => false,
    };
    let detected = cwd.join("firebase.json").is_file();
    if !interactive {
        if options.firebase_json.is_none() && detected {
            options.firebase_json = Some(PathBuf::from("firebase.json"));
        }
        return Ok(options);
    }
    if options.profile.is_none() {
        writeln!(
            output,
            "Profiles:\n  strict (recommended): additional validation and production limit checks.\n  firebase: firebase reproduces the pinned official emulator behavior, including its limitations."
        )
        .map_err(output_error)?;
        loop {
            let answer = prompt(input, output, "Profile [strict]: ")?;
            match answer.as_str() {
                "" | "strict" => {
                    options.profile = Some(Profile::Strict);
                    break;
                }
                "firebase" => {
                    options.profile = Some(Profile::Firebase);
                    break;
                }
                _ => writeln!(output, "Enter strict or firebase.").map_err(output_error)?,
            }
        }
    }
    if options.firebase_json.is_none() {
        writeln!(
            output,
            "A Firebase configuration is loaded again on every fireemu start, so rules, indexes, Functions, and emulator ports stay current. Enter none to create no reference."
        )
        .map_err(output_error)?;
        let label = if detected {
            "Firebase configuration [firebase.json]: "
        } else {
            "Firebase configuration [none]: "
        };
        let answer = prompt(input, output, label)?;
        options.firebase_json = match answer.as_str() {
            "" if detected => Some(PathBuf::from("firebase.json")),
            "" | "none" => None,
            path => Some(PathBuf::from(path)),
        };
    }
    let answer = prompt(input, output, "Create fireemu.json? [Y/n] ")?;
    if matches!(answer.to_ascii_lowercase().as_str(), "n" | "no") {
        return Err(CliError::refused("initialization cancelled"));
    }
    if !matches!(answer.to_ascii_lowercase().as_str(), "" | "y" | "yes") {
        return Err(CliError::refused("confirmation must be yes or no"));
    }
    Ok(options)
}

fn prompt(
    input: &mut impl std::io::BufRead,
    output: &mut impl Write,
    text: &str,
) -> Result<String, CliError> {
    output.write_all(text.as_bytes()).map_err(output_error)?;
    output.flush().map_err(output_error)?;
    let mut answer = String::new();
    input
        .read_line(&mut answer)
        .map_err(|e| CliError::refused(format!("cannot read wizard input: {e}")))?;
    Ok(answer.trim().to_owned())
}

fn output_error(error: std::io::Error) -> CliError {
    CliError::refused(format!("cannot write wizard output: {error}"))
}

fn write_config(path: &Path, bytes: &[u8], force: bool) -> Result<(), CliError> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true);
    if force {
        options.truncate(true);
    } else {
        options.create_new(true);
    }
    let mut file = options.open(path).map_err(|e| {
        let detail = if e.kind() == std::io::ErrorKind::AlreadyExists {
            "already exists".to_owned()
        } else {
            e.to_string()
        };
        CliError::refused(format!("cannot create {}: {detail}", path.display()))
    })?;
    file.write_all(bytes)
        .map_err(|e| CliError::refused(format!("cannot write {}: {e}", path.display())))
}
