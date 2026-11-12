//! Writes a diagnostics bundle from a running control API.

use crate::{CliError, Selection};
use fireemu_adapter_support::diagnostics::{self, ConfigValue};
use std::io::Write;
use std::path::Path;

#[allow(clippy::too_many_lines)] // Keep bundle assembly and guarded file creation together.
pub(super) fn command(args: &[String]) -> Result<(), CliError> {
    let mut url = None;
    let mut out = None;
    let mut flags = Vec::new();
    let mut force = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--force" => {
                force = true;
                i += 1;
            }
            "--url" | "--out" | "--config" | "--firebase-json" => {
                let value = args
                    .get(i + 1)
                    .ok_or_else(|| CliError::usage(format!("{} needs a value", args[i])))?;
                match args[i].as_str() {
                    "--url" => url = Some(value.as_str()),
                    "--out" => out = Some(value.as_str()),
                    _ => flags.extend([args[i].clone(), value.clone()]),
                }
                i += 2;
            }
            other => {
                return Err(CliError::usage(format!(
                    "unknown argument {}",
                    crate::diagnostic_text(other)
                )))
            }
        }
    }
    let url = url
        .filter(|v| !v.is_empty())
        .ok_or_else(|| CliError::usage("dump needs --url <control-url>"))?;
    let out = out
        .filter(|v| !v.is_empty())
        .ok_or_else(|| CliError::usage("dump needs --out <dir>"))?;
    if std::env::var("FIREEMU_CONTROL_TOKEN")
        .ok()
        .filter(|s| !s.is_empty())
        .is_none()
    {
        return Err(CliError::usage("dump needs FIREEMU_CONTROL_TOKEN"));
    }
    let mut raw = crate::parse_raw_options(&flags, crate::OptionContext::Start)?;
    let origin = crate::discover_project_config(&mut raw)?;
    let (mut cfg, root, sources) = crate::load_project_config(&raw, &Selection::default())
        .map_err(crate::note_discovered(&origin))?;
    crate::resolve_project_dependent_config(&mut cfg, &origin, &root)?;
    let input = match &sources.canonical {
        Some(path) => crate::config_document(&raw, path)?.0,
        None => serde_json::Value::Null,
    };
    let path = "/v1/sessions/default/diagnostics/bundle";
    let body = crate::doctor::control_get(url, path).map_err(CliError::usage)?;
    let value: serde_json::Value =
        serde_json::from_str(&body).map_err(|e| CliError::refused(e.to_string()))?;
    let mut bundle = diagnostics::from_value(&value).map_err(CliError::refused)?;
    // The daemon has no config route, so these rows reflect locally loaded configuration.
    bundle.config = cfg
        .config_show(&input)
        .into_iter()
        .map(|row| {
            let key = row["key"].as_str().unwrap_or_default().to_owned();
            let value = match &row["value"] {
                serde_json::Value::Null => ConfigValue::Null,
                serde_json::Value::Bool(v) => ConfigValue::Bool(*v),
                serde_json::Value::Number(v) if v.as_i64().is_some() => {
                    ConfigValue::Int(v.as_i64().unwrap())
                }
                serde_json::Value::String(v) => ConfigValue::Str(v.clone()),
                v => ConfigValue::Str(v.to_string()),
            };
            (key, value)
        })
        .collect();
    let dir = Path::new(out);
    let json_path = dir.join("bundle.json");
    let html_path = dir.join("bundle.html");
    for (path, is_dir) in [
        (dir, true),
        (json_path.as_path(), false),
        (html_path.as_path(), false),
    ] {
        match std::fs::symlink_metadata(path) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink()
                    || (is_dir && !metadata.is_dir())
                    || (!is_dir && (!metadata.is_file() || !force))
                {
                    return Err(CliError::refused(format!(
                        "cannot use {}: already exists or is a symbolic link",
                        crate::diagnostic_path(path)
                    )));
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(CliError::refused(format!(
                    "cannot inspect {}: {e}",
                    crate::diagnostic_path(path)
                )))
            }
        }
    }
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    // On non-Unix targets, directory and file creation use the platform defaults.
    builder.create(dir).map_err(|e| {
        CliError::refused(format!(
            "cannot create {}: {e}",
            crate::diagnostic_path(dir)
        ))
    })?;
    for (path, content) in [
        (&json_path, diagnostics::to_json(&bundle)),
        (&html_path, diagnostics::to_html(&bundle)),
    ] {
        if force {
            match std::fs::symlink_metadata(path) {
                Ok(metadata) if metadata.is_file() => std::fs::remove_file(path).map_err(|e| {
                    CliError::refused(format!(
                        "cannot remove {}: {e}",
                        crate::diagnostic_path(path)
                    ))
                })?,
                Ok(_) => {
                    return Err(CliError::refused(format!(
                        "cannot replace {}",
                        crate::diagnostic_path(path)
                    )))
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => {
                    return Err(CliError::refused(format!(
                        "cannot inspect {}: {e}",
                        crate::diagnostic_path(path)
                    )))
                }
            }
        }
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(path).map_err(|e| {
            CliError::refused(format!(
                "cannot create {}: {e}",
                crate::diagnostic_path(path)
            ))
        })?;
        file.write_all(content.as_bytes()).map_err(|e| {
            CliError::refused(format!(
                "cannot write {}: {e}",
                crate::diagnostic_path(path)
            ))
        })?;
    }
    println!("{}", crate::diagnostic_path(&json_path));
    println!("{}", crate::diagnostic_path(&html_path));
    Ok(())
}
