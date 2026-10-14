//! Safe creation of a canonical `fireemu.toml`.

use std::fmt::Write as _;
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
    reference: bool,
    interaction: Interaction,
}

/// Creates `fireemu.toml` in the current directory.
pub fn run(args: &[String]) -> Result<PathBuf, CliError> {
    let options = parse_args(args)?;
    let cwd = std::env::current_dir()
        .map_err(|e| CliError::refused(format!("cannot resolve the working directory: {e}")))?;
    if options.reference
        && options.profile.is_none()
        && options.firebase_json.is_none()
        && (cwd.join("fireemu.toml").is_file() || cwd.join("fireemu.json").is_file())
    {
        let is_toml = !cwd.join("fireemu.json").is_file();
        let destination = cwd.join(if is_toml {
            "fireemu.reference.toml"
        } else {
            "fireemu.reference.jsonc"
        });
        let document = reference_document(is_toml);
        write_config(&destination, document.as_bytes(), options.force)?;
        return Ok(destination);
    }
    match std::fs::symlink_metadata(cwd.join("fireemu.json")) {
        Ok(_) => return Err(CliError::refused(
            "fireemu.json already exists; keep using it or remove it before creating fireemu.toml",
        )),
        Err(error) if destination_is_missing(error.kind()) => {}
        Err(error) => {
            return Err(CliError::refused(format!(
                "cannot inspect fireemu.json: {error}"
            )))
        }
    }
    let terminals = automatic_interaction(
        std::io::stdin().is_terminal(),
        std::io::stdout().is_terminal(),
    );
    let mut input = std::io::stdin().lock();
    let mut output = std::io::stdout().lock();
    let options = complete_options(options, &cwd, &mut input, &mut output, terminals)?;
    let destination = cwd.join("fireemu.toml");
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
        "firestore": { "edition": "standard", "apiMode": "native" }
    });
    if let Some(firebase_json) = options.firebase_json {
        let firebase_json = firebase_json.to_str().ok_or_else(|| {
            CliError::refused("the Firebase configuration path is not UTF-8".to_owned())
        })?;
        document["firebaseJson"] = firebase_json.into();
    }
    let mut output_document = format!(
        "#:schema {CANONICAL_SCHEMA_URL}\nschemaVersion = 1\nprofile = {}\n",
        document["profile"]
    );
    // Keep the required version and profile first without changing TOML table scope.
    for (key, value) in document.as_object().expect("configuration object") {
        if matches!(key.as_str(), "schemaVersion" | "profile") {
            continue;
        }
        if let Some(table) = value.as_object() {
            for (name, value) in table {
                let _ = writeln!(
                    output_document,
                    "{key}.{name} = {}",
                    toml::Value::try_from(value).expect("configuration value")
                );
            }
        } else {
            let key = if key == "$schema" { "\"$schema\"" } else { key };
            let _ = writeln!(
                output_document,
                "{key} = {}",
                toml::Value::try_from(value).expect("configuration value")
            );
        }
    }
    let bytes = output_document.into_bytes();
    let reference = cwd.join("fireemu.reference.toml");
    // Both destinations are checked before either is written, so a refusal leaves nothing behind.
    check_destination(&destination, options.force)?;
    if options.reference {
        check_destination(&reference, options.force)?;
    }
    write_config(&destination, &bytes, options.force)?;
    if options.reference {
        write_config(
            &reference,
            reference_document(true).as_bytes(),
            options.force,
        )?;
        writeln!(output, "created {}", crate::diagnostic_path(&reference))
            .map_err(|error| output_error(&error))?;
    }
    Ok(destination)
}

/// The reference is documentation; commented settings must never become implicit defaults.
#[allow(clippy::too_many_lines)]
fn reference_document(is_toml: bool) -> String {
    let governed = crate::config::RuntimeConfig::default().development_defaults;
    let mut entries = crate::config::config_schema();
    if is_toml {
        for key in ["profile", "schemaVersion"] {
            let index = entries
                .iter()
                .position(|(path, _)| path == key)
                .expect("required schema key");
            let entry = entries.remove(index);
            entries.insert(0, entry);
        }
    }
    let mut output = if is_toml {
        format!("#:schema {CANONICAL_SCHEMA_URL}\n# This reference file is not loaded by fireemu. Edit fireemu.toml to configure it.\n# Copying a key into fireemu.toml makes it explicit and stops productionExact from switching that key. Commented examples are not active defaults.\n")
    } else {
        String::from("// This reference file is not loaded by fireemu. Edit fireemu.json to configure it.\n// Do not create fireemu.toml beside fireemu.json.\n// Copying a key into fireemu.json makes it explicit and stops productionExact from switching that key. Commented examples are not active defaults.\n{\n")
    };
    let mut sections: Vec<(String, bool, bool)> = vec![(String::new(), false, false)];
    for (path, schema) in entries {
        let parent = path.rsplit_once('.').map_or("", |(parent, _)| parent);
        while sections.last().expect("root section").0 != parent {
            let (_, commented, _) = sections.pop().expect("section");
            if !is_toml {
                let _ = writeln!(
                    output,
                    "{}{} }}",
                    "  ".repeat(sections.len()),
                    if commented { "//" } else { "" }
                );
            }
        }
        let is_section = schema.get("properties").is_some();
        let production_exact = governed.iter().any(|entry| entry["key"] == path);
        let presence_selects_mode = matches!(
            path.as_str(),
            "auth.idpSigners"
                | "eventarc.oauthCredentials"
                | "auth.totp"
                | "auth.mfa"
                | "auth.providers"
                | "auth.blockingFunctions"
                | "auth.client.permissions"
                | "auth.quota"
                | "auth.quotaSimulation"
                | "auth.signIn.allowDuplicateEmails"
                | "auth.signIn.email.enabled"
                | "auth.signIn.email.passwordRequired"
                | "auth.signIn.anonymous.enabled"
                | "auth.signIn.phoneNumber.enabled"
        );
        let no_effect = crate::config::NO_EFFECT_KEYS.contains(&path.as_str());
        let inherited = sections.last().expect("section").1;
        let commented = inherited
            || production_exact
            || no_effect
            || presence_selects_mode
            || (!is_section && schema.get("default").is_none());
        let indent = if is_toml {
            String::new()
        } else {
            "  ".repeat(sections.len())
        };
        if !is_toml && !commented {
            let (_, _, active) = sections.last_mut().expect("section");
            if *active {
                let _ = writeln!(output, "{indent},");
            }
            *active = true;
        }
        let comment_prefix = if is_toml { "#" } else { "//" };
        let _ = writeln!(output, "\n{indent}{comment_prefix} {path}:");
        let description = schema["description"]
            .as_str()
            .unwrap_or("No description in the schema.");
        let default = schema
            .get("default")
            .map_or_else(|| "no default".to_owned(), ToString::to_string);
        let mut comment = format!("{description} Default: {default}.");
        if production_exact {
            comment.push_str(" Governed by productionExact; leave omitted to follow it.");
        }
        if no_effect {
            comment.push_str(" Accepted for forward compatibility; currently has no effect.");
        }
        if presence_selects_mode {
            comment.push_str(" Presence selects behavior; leave commented unless intended.");
        }
        let _ = writeln!(output, "{indent}{comment_prefix} {comment}");
        if is_section {
            if !is_toml {
                let name = path.rsplit('.').next().expect("schema key");
                let prefix = if commented { "// " } else { "" };
                let _ = writeln!(output, "{indent}{prefix}{name:?}: {{");
            }
            sections.push((path, commented, false));
        } else {
            let value = schema
                .get("default")
                .or_else(|| schema.get("examples").and_then(|v| v.get(0)))
                .or_else(|| schema.get("const"));
            let key = if path == "$schema" {
                "\"$schema\""
            } else {
                &path
            };
            if !is_toml {
                let name = path.rsplit('.').next().expect("schema key");
                let value = value.unwrap_or(&serde_json::Value::Null);
                let prefix = if commented { "// " } else { "" };
                let _ = writeln!(output, "{indent}{prefix}{name:?}: {value}");
            } else if let Some(value) = value {
                if value.is_null() {
                    let _ = writeln!(output, "# {key} is omitted; TOML has no null.");
                } else if let Ok(value) = toml::Value::try_from(value) {
                    let prefix = if commented { "# " } else { "" };
                    let _ = writeln!(output, "{prefix}{key} = {value}");
                } else {
                    let _ = writeln!(
                        output,
                        "# {key} = ... (see the schema; omit nullable keys or array items)"
                    );
                }
            } else {
                let hint = schema
                    .get("type")
                    .and_then(serde_json::Value::as_str)
                    .map_or(String::new(), |kind| format!("; type: {kind}"));
                let _ = writeln!(output, "# {key} = ... (no default; see the schema){hint}");
            }
        }
    }
    if !is_toml {
        while sections.len() > 1 {
            let (_, commented, _) = sections.pop().expect("section");
            let _ = writeln!(
                output,
                "{}{} }}",
                "  ".repeat(sections.len()),
                if commented { "//" } else { "" }
            );
        }
        output.push_str("}\n");
    }
    output
}

const fn automatic_interaction(stdin_terminal: bool, stdout_terminal: bool) -> bool {
    stdin_terminal && stdout_terminal
}

fn parse_args(args: &[String]) -> Result<InitArgs, CliError> {
    let mut profile = None;
    let mut firebase_json = None;
    let mut force = false;
    let mut reference = false;
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
            "--reference" => {
                if reference {
                    return Err(CliError::usage("--reference may be supplied only once"));
                }
                reference = true;
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
        reference,
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
            "Profiles:\n  strict (recommended): behaves like production Firebase, including index and limit checks. Use it when migrating from the official emulator too.\n  emulator: reproduces the pinned official emulator behavior, including its limitations. Only for checking alignment with the official emulator; not needed when migrating."
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
    let answer = prompt(input, output, "Create fireemu.toml? [Y/n] ")?;
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

/// Refuses, without writing, what [`write_config`] would refuse: an existing path unless
/// `force`, and with `force` a symbolic link or anything that is not a regular file.
fn check_destination(path: &Path, force: bool) -> Result<(), CliError> {
    match std::fs::symlink_metadata(path) {
        Err(error) if destination_is_missing(error.kind()) => Ok(()),
        Err(error) => Err(CliError::refused(format!(
            "cannot inspect {}: {error}",
            crate::diagnostic_path(path)
        ))),
        Ok(_) if !force => Err(CliError::refused(format!(
            "cannot create {}: already exists",
            crate::diagnostic_path(path)
        ))),
        Ok(metadata) if metadata.file_type().is_symlink() => Err(CliError::refused(format!(
            "{} is a symbolic link and will not be replaced",
            crate::diagnostic_path(path)
        ))),
        Ok(metadata) if !metadata.is_file() => Err(CliError::refused(format!(
            "{} is not a regular file",
            crate::diagnostic_path(path)
        ))),
        Ok(_) => Ok(()),
    }
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
        .unwrap_or("fireemu.toml");
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
    fn toml_reference_distinguishes_missing_defaults_from_null() {
        let reference = super::reference_document(true);
        for (key, schema) in crate::config::config_schema() {
            if schema.get("properties").is_some() {
                continue;
            }
            let (_, section) = reference.split_once(&format!("# {key}:\n")).unwrap();
            let assignment = section.lines().nth(1).unwrap();
            if schema
                .get("default")
                .or_else(|| schema.get("examples").and_then(|v| v.get(0)))
                .or_else(|| schema.get("const"))
                .is_none()
            {
                assert!(
                    assignment.starts_with(&format!("# {key} = ... (no default; see the schema)")),
                    "{key}: {assignment}"
                );
                assert!(!assignment.contains("null"), "{key}: {assignment}");
            } else if schema
                .get("default")
                .is_some_and(serde_json::Value::is_null)
            {
                assert!(
                    assignment.contains("TOML has no null"),
                    "{key}: {assignment}"
                );
            }
        }
    }

    #[test]
    fn init_reference_keeps_default_sections_active_and_governed_values_commented() {
        let reference = super::reference_document(true);
        let active = reference
            .lines()
            .filter(|line| !line.trim_start().starts_with('#'))
            .collect::<Vec<_>>()
            .join("\n");
        let parsed: serde_json::Value = toml::from_str(&active).unwrap();
        for (pointer, expected) in [
            ("/network/allowNonLoopbackHosts", serde_json::json!(false)),
            ("/projects/requireDemoPrefix", serde_json::json!(true)),
            ("/firestore/location", serde_json::json!("nam5")),
            // Not governed by productionExact: the strict default already is production's.
            ("/firestore/missingIndexes", serde_json::json!("refuse")),
            (
                "/firestore/history/maxBytes",
                serde_json::json!(1_073_741_824),
            ),
            ("/functions/clock/date", serde_json::json!("real")),
        ] {
            assert_eq!(parsed.pointer(pointer), Some(&expected), "{pointer}");
        }
        for pointer in [
            "/auth",
            "/auth/idpSigners",
            "/auth/mfa",
            "/auth/totp",
            "/auth/providers",
            "/auth/client/permissions",
            "/auth/allowUnsignedIdTokens",
            "/auth/idpAssertions",
            "/firestore/indexFile",
        ] {
            assert!(parsed.pointer(pointer).is_none(), "{pointer}");
        }
        for key in [
            "auth.allowUnsignedCustomTokens",
            "auth.allowUnsignedIdTokens",
            "auth.idpAssertions",
            "auth.tenantIdFormat",
            "auth.multiTenant.allowTenants",
            "auth.mfa.state",
            "firestore.listenStreamLifetime",
            "eventarc.authentication",
        ] {
            let (_, section) = reference.split_once(&format!("# {key}:\n")).unwrap();
            let comment = section.lines().next().unwrap();
            assert!(comment.contains("Governed by productionExact;"), "{key}");
        }
        let (_, section) = reference.split_once("# firestore.location:\n").unwrap();
        let comment = section.split_once("firestore.location =").unwrap().0;
        assert!(!comment.contains("Governed by productionExact;"));
        let (_, section) = reference
            .split_once("# firestore.missingIndexes:\n")
            .unwrap();
        let comment = section.split_once("firestore.missingIndexes =").unwrap().0;
        assert!(!comment.contains("Governed by productionExact;"));
    }

    #[test]
    fn init_reference_says_which_keys_currently_have_no_effect() {
        let reference = super::reference_document(true);
        let marker = "Accepted for forward compatibility; currently has no effect.";
        for key in crate::config::NO_EFFECT_KEYS {
            let (_, section) = reference.split_once(&format!("# {key}:\n")).unwrap();
            let comment = section.lines().next().unwrap();
            let comment = comment
                .lines()
                .map(|line| line.trim_start_matches(' ').trim_start_matches("# "))
                .collect::<Vec<_>>()
                .join(" ");
            assert!(comment.contains(marker), "{key}: {comment}");
        }
        for key in [
            "firestore.location",
            "firestore.missingIndexes",
            "rules.source",
        ] {
            let (_, section) = reference.split_once(&format!("# {key}:\n")).unwrap();
            let comment = section.lines().next().unwrap();
            assert!(!comment.contains("no effect"), "{key}");
        }
    }

    #[test]
    fn init_reference_preserves_complete_descriptions_on_one_comment_line() {
        let reference = super::reference_document(true);
        for (key, schema) in crate::config::config_schema() {
            let (_, section) = reference.split_once(&format!("# {key}:\n")).unwrap();
            let description = schema["description"]
                .as_str()
                .unwrap_or("No description in the schema.");
            let default = schema
                .get("default")
                .map_or_else(|| "no default".to_owned(), ToString::to_string);
            assert!(
                section
                    .lines()
                    .next()
                    .unwrap()
                    .starts_with(&format!("# {description} Default: {default}.")),
                "{key}"
            );
        }
    }

    #[test]
    fn automatic_interaction_requires_both_terminal_streams() {
        assert!(super::automatic_interaction(true, true));
        assert!(!super::automatic_interaction(true, false));
        assert!(!super::automatic_interaction(false, true));
        assert!(!super::automatic_interaction(false, false));
    }

    #[cfg(unix)]
    #[test]
    fn a_destination_that_cannot_be_inspected_is_refused_not_treated_as_absent() {
        // /dev/null is not a directory, so its child fails with ENOTDIR rather than ENOENT.
        let path = std::path::Path::new("/dev/null/fireemu.reference.toml");
        for force in [false, true] {
            let error = super::check_destination(path, force).unwrap_err();
            assert!(
                error.message.contains("cannot inspect"),
                "{}",
                error.message
            );
        }
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
