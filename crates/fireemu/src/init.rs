//! Safe creation of a canonical `fireemu.json`.

use std::io::{IsTerminal as _, Write};
use std::path::{Path, PathBuf};

use crate::config::CANONICAL_SCHEMA_URL;
use crate::CliError;

static NEXT_TEMP: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

#[derive(Clone, Copy)]
enum Profile {
    Strict,
    Emulator,
}

impl Profile {
    fn parse(value: &str) -> Result<Self, CliError> {
        match value {
            "strict" => Ok(Self::Strict),
            "emulator" => Ok(Self::Emulator),
            _ => Err(CliError::usage(format!(
                "--profile {value:?} is not one of strict, emulator"
            ))),
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Strict => "strict",
            Self::Emulator => "emulator",
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
    let terminals = automatic_interaction(
        std::io::stdin().is_terminal(),
        std::io::stdout().is_terminal(),
    );
    let mut input = std::io::stdin().lock();
    let mut output = std::io::stdout().lock();
    let options = complete_options(options, &cwd, &mut input, &mut output, terminals)?;
    let destination = cwd.join("fireemu.json");
    if let Some(reference) = &options.firebase_json {
        let source = if reference.is_absolute() {
            reference.clone()
        } else {
            cwd.join(reference)
        };
        let _ = crate::read_firebase_json(&source)?;
    }
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

const fn automatic_interaction(stdin_terminal: bool, stdout_terminal: bool) -> bool {
    stdin_terminal && stdout_terminal
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
            other => {
                return Err(CliError::usage(format!(
                    "unknown init argument {}",
                    crate::diagnostic_text(other)
                )))
            }
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
            "Profiles:\n  strict (recommended): behaves like production Firebase, including index and limit checks.\n  emulator: reproduces the pinned official emulator behavior, including its limitations."
        )
        .map_err(|error| output_error(&error))?;
        loop {
            let answer = prompt(input, output, "Profile [strict]: ")?;
            match answer.as_str() {
                "" | "strict" => {
                    options.profile = Some(Profile::Strict);
                    break;
                }
                "emulator" => {
                    options.profile = Some(Profile::Emulator);
                    break;
                }
                _ => writeln!(output, "Enter strict or emulator.")
                    .map_err(|error| output_error(&error))?,
            }
        }
    }
    if options.firebase_json.is_none() {
        writeln!(
            output,
            "A Firebase configuration is loaded again on every fireemu start, so rules, indexes, Functions, and emulator ports stay current. Enter none to create no reference."
        )
        .map_err(|error| output_error(&error))?;
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
    output
        .write_all(text.as_bytes())
        .map_err(|error| output_error(&error))?;
    output.flush().map_err(|error| output_error(&error))?;
    let mut answer = String::new();
    input
        .read_line(&mut answer)
        .map_err(|e| CliError::refused(format!("cannot read wizard input: {e}")))?;
    Ok(answer.trim().to_owned())
}

fn output_error(error: &std::io::Error) -> CliError {
    CliError::refused(format!("cannot write wizard output: {error}"))
}

fn write_config(path: &Path, bytes: &[u8], force: bool) -> Result<(), CliError> {
    if force {
        return replace_config(path, bytes);
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    let mut file = options.open(path).map_err(|e| {
        let detail = if e.kind() == std::io::ErrorKind::AlreadyExists {
            "already exists".to_owned()
        } else {
            e.to_string()
        };
        CliError::refused(format!(
            "cannot create {}: {detail}",
            crate::diagnostic_path(path)
        ))
    })?;
    file.write_all(bytes).map_err(|e| {
        CliError::refused(format!(
            "cannot write {}: {e}",
            crate::diagnostic_path(path)
        ))
    })
}

fn replace_config(path: &Path, bytes: &[u8]) -> Result<(), CliError> {
    let existing_permissions = match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(CliError::refused(format!(
                "{} is a symbolic link and will not be replaced",
                crate::diagnostic_path(path)
            )))
        }
        Ok(metadata) if metadata.is_file() => Some(metadata.permissions()),
        Ok(_) => {
            return Err(CliError::refused(format!(
                "{} is not a regular file",
                crate::diagnostic_path(path)
            )))
        }
        Err(error) if destination_is_missing(error.kind()) => None,
        Err(error) => {
            return Err(CliError::refused(format!(
                "cannot inspect {}: {error}",
                crate::diagnostic_path(path)
            )))
        }
    };
    let existing = existing_permissions.is_some();
    let sequence = NEXT_TEMP.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let name = path
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .unwrap_or("fireemu.json");
    let temporary = path.with_file_name(format!(".{name}.{}.{}.tmp", std::process::id(), sequence));
    let write_result = (|| -> Result<(), CliError> {
        let mut temporary_file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|e| {
                CliError::refused(format!(
                    "cannot create {}: {e}",
                    crate::diagnostic_path(&temporary)
                ))
            })?;
        temporary_file.write_all(bytes).map_err(|e| {
            CliError::refused(format!(
                "cannot write {}: {e}",
                crate::diagnostic_path(&temporary)
            ))
        })?;
        if let Some(permissions) = existing_permissions {
            temporary_file.set_permissions(permissions).map_err(|e| {
                CliError::refused(format!(
                    "cannot preserve permissions on {}: {e}",
                    crate::diagnostic_path(&temporary)
                ))
            })?;
        }
        temporary_file.sync_all().map_err(|e| {
            CliError::refused(format!(
                "cannot sync {}: {e}",
                crate::diagnostic_path(&temporary)
            ))
        })?;
        drop(temporary_file);
        replace_path(&temporary, path, existing)
    })();
    if write_result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    write_result
}

const fn destination_is_missing(kind: std::io::ErrorKind) -> bool {
    matches!(kind, std::io::ErrorKind::NotFound)
}

#[cfg(not(windows))]
fn replace_path(temporary: &Path, destination: &Path, _existing: bool) -> Result<(), CliError> {
    std::fs::rename(temporary, destination).map_err(|e| {
        CliError::refused(format!(
            "cannot replace {} with {}: {e}",
            crate::diagnostic_path(destination),
            crate::diagnostic_path(temporary)
        ))
    })
}

#[cfg(windows)]
fn replace_path(temporary: &Path, destination: &Path, existing: bool) -> Result<(), CliError> {
    if !existing {
        return std::fs::rename(temporary, destination).map_err(|e| {
            CliError::refused(format!(
                "cannot install {} as {}: {e}",
                crate::diagnostic_path(temporary),
                crate::diagnostic_path(destination)
            ))
        });
    }
    let backup = temporary.with_extension("bak");
    std::fs::rename(destination, &backup).map_err(|e| {
        CliError::refused(format!(
            "cannot prepare {} for replacement: {e}",
            crate::diagnostic_path(destination)
        ))
    })?;
    match std::fs::rename(temporary, destination) {
        Ok(()) => std::fs::remove_file(&backup).map_err(|error| {
            CliError::refused(format!(
                "replaced {}, but cannot remove the old configuration at {}: {error}",
                crate::diagnostic_path(destination),
                crate::diagnostic_path(&backup)
            ))
        }),
        Err(replace_error) => match std::fs::rename(&backup, destination) {
            Ok(()) => Err(CliError::refused(format!(
                "cannot replace {}: {replace_error}; the original was restored",
                crate::diagnostic_path(destination)
            ))),
            Err(restore_error) => Err(CliError::refused(format!(
                "cannot replace {}: {replace_error}; cannot restore it: {restore_error}; the original remains at {}",
                crate::diagnostic_path(destination),
                crate::diagnostic_path(&backup)
            ))),
        },
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn automatic_interaction_requires_both_terminal_streams() {
        assert!(super::automatic_interaction(true, true));
        assert!(!super::automatic_interaction(true, false));
        assert!(!super::automatic_interaction(false, true));
        assert!(!super::automatic_interaction(false, false));
    }

    #[test]
    fn only_not_found_means_the_destination_is_absent() {
        assert!(super::destination_is_missing(std::io::ErrorKind::NotFound));
        assert!(!super::destination_is_missing(
            std::io::ErrorKind::PermissionDenied
        ));
        assert!(!super::destination_is_missing(
            std::io::ErrorKind::InvalidInput
        ));
    }
}
