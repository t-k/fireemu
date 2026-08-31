//! Safe creation of a canonical `fireemu.json`.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use crate::config::CANONICAL_SCHEMA_URL;
use crate::CliError;

/// Creates `fireemu.json` in the current directory.
pub fn run(args: &[String]) -> Result<PathBuf, CliError> {
    let mut force = false;
    for argument in args {
        match argument.as_str() {
            "--yes" | "--no-interactive" => {}
            "--force" => force = true,
            other => return Err(CliError::usage(format!("unknown init argument {other}"))),
        }
    }
    let cwd = std::env::current_dir()
        .map_err(|e| CliError::refused(format!("cannot resolve the working directory: {e}")))?;
    let destination = cwd.join("fireemu.json");
    let firebase_json = cwd
        .join("firebase.json")
        .is_file()
        .then_some("firebase.json");
    let mut document = serde_json::json!({
        "$schema": CANONICAL_SCHEMA_URL,
        "schemaVersion": 1,
        "profile": "strict",
        "firestore": {
            "edition": "standard",
            "apiMode": "native"
        }
    });
    if let Some(firebase_json) = firebase_json {
        document["firebaseJson"] = firebase_json.into();
    }
    let mut bytes = serde_json::to_vec_pretty(&document)
        .map_err(|e| CliError::refused(format!("cannot serialize fireemu.json: {e}")))?;
    bytes.push(b'\n');
    write_config(&destination, &bytes, force)?;
    Ok(destination)
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
