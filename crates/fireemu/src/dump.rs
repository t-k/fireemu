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
    let previous_redactions = bundle.redactions;
    let previous_truncations = std::mem::take(&mut bundle.truncations);
    bundle = diagnostics::Bundle::from_input(
        diagnostics::BundleInput {
            generated_at: bundle.generated_at,
            versions: bundle.versions,
            config: bundle.config,
            functions: bundle.functions,
            rules: bundle.rules,
            indexes: bundle.indexes,
            pending: bundle.pending,
            logs: bundle.logs,
        },
        diagnostics::Limits::default(),
    );
    bundle.redactions += previous_redactions;
    bundle.truncations.splice(0..0, previous_truncations);
    let dir = Path::new(out);
    let json_path = dir.join("bundle.json");
    let html_path = dir.join("bundle.html");
    #[cfg(unix)]
    {
        use rustix::fs::{self, AtFlags, FileType, Mode, OFlags};
        use std::path::Component;
        let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let mut directory = fs::open(
            if dir.is_absolute() { "/" } else { "." },
            flags,
            Mode::empty(),
        )
        .map_err(|e| CliError::refused(format!("cannot open output root: {e}")))?;
        for component in dir.components() {
            let name = match component {
                Component::RootDir | Component::CurDir => continue,
                Component::Normal(name) => name,
                Component::ParentDir => std::ffi::OsStr::new(".."),
                Component::Prefix(_) => return Err(CliError::refused("invalid output path")),
            };
            match fs::mkdirat(&directory, name, Mode::RWXU) {
                Ok(()) | Err(rustix::io::Errno::EXIST) => {}
                Err(e) => {
                    return Err(CliError::refused(format!(
                        "cannot create {}: {e}",
                        crate::diagnostic_path(dir)
                    )))
                }
            }
            directory = fs::openat(&directory, name, flags, Mode::empty()).map_err(|e| {
                CliError::refused(format!("cannot open {}: {e}", crate::diagnostic_path(dir)))
            })?;
        }
        for name in ["bundle.json", "bundle.html"] {
            match fs::statat(&directory, name, AtFlags::SYMLINK_NOFOLLOW) {
                Ok(stat)
                    if force && FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile => {}
                Ok(_) => {
                    return Err(CliError::refused(format!(
                        "cannot use {name}: already exists or is a symbolic link"
                    )))
                }
                Err(rustix::io::Errno::NOENT) => {}
                Err(e) => return Err(CliError::refused(format!("cannot inspect {name}: {e}"))),
            }
        }
        for (name, content) in [
            ("bundle.json", diagnostics::to_json(&bundle)),
            ("bundle.html", diagnostics::to_html(&bundle)),
        ] {
            if force {
                match fs::unlinkat(&directory, name, AtFlags::empty()) {
                    Ok(()) | Err(rustix::io::Errno::NOENT) => {}
                    Err(e) => return Err(CliError::refused(format!("cannot remove {name}: {e}"))),
                }
            }
            let fd = fs::openat(
                &directory,
                name,
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::RUSR | Mode::WUSR,
            )
            .map_err(|e| CliError::refused(format!("cannot create {name}: {e}")))?;
            let mut file = std::fs::File::from(fd);
            file.write_all(content.as_bytes())
                .map_err(|e| CliError::refused(format!("cannot write {name}: {e}")))?;
        }
    }
    #[cfg(not(unix))]
    write_output(
        dir,
        force,
        &diagnostics::to_json(&bundle),
        &diagnostics::to_html(&bundle),
    )?;
    println!("{}", crate::diagnostic_path(&json_path));
    println!("{}", crate::diagnostic_path(&html_path));
    Ok(())
}

#[cfg(all(test, not(unix)))]
thread_local! {
    static BEFORE_OPEN: std::cell::RefCell<Option<Box<dyn FnMut(&Path)>>> = std::cell::RefCell::new(None);
}

#[cfg(not(unix))]
fn write_output(dir: &Path, force: bool, json: &str, html: &str) -> Result<(), CliError> {
    use cap_fs_ext::{DirExt, FollowSymlinks, OpenOptionsFollowExt};
    use cap_std::fs::{Dir, OpenOptions};
    use std::path::{Component, PathBuf};

    let absolute = if dir.is_absolute() {
        dir.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|e| CliError::refused(format!("cannot open output root: {e}")))?
            .join(dir)
    };
    let mut components = absolute.components();
    let mut root = PathBuf::new();
    if let Some(Component::Prefix(prefix)) = components.next() {
        root.push(prefix.as_os_str());
    } else {
        return Err(CliError::refused("invalid output path"));
    }
    if matches!(components.next(), Some(Component::RootDir)) {
        root.push(std::path::MAIN_SEPARATOR.to_string());
    } else {
        return Err(CliError::refused("invalid output path"));
    }
    let mut directory = Dir::open_ambient_dir(&root, cap_std::ambient_authority())
        .map_err(|e| CliError::refused(format!("cannot open output root: {e}")))?;
    let mut traversed = root;
    for component in components {
        let name = match component {
            Component::Normal(name) => name,
            Component::CurDir => continue,
            _ => {
                return Err(CliError::refused(
                    "invalid output path: parent components are not supported",
                ))
            }
        };
        traversed.push(name);
        match directory.create_dir(name) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => {
                return Err(CliError::refused(format!(
                    "cannot create {}: {e}",
                    crate::diagnostic_path(&traversed)
                )))
            }
        }
        #[cfg(test)]
        BEFORE_OPEN.with(|hook| {
            if let Some(hook) = hook.borrow_mut().as_mut() {
                hook(&traversed);
            }
        });
        directory = directory.open_dir_nofollow(name).map_err(|e| {
            CliError::refused(format!(
                "cannot open {} without following links: {e}",
                crate::diagnostic_path(&traversed)
            ))
        })?;
    }
    for name in ["bundle.json", "bundle.html"] {
        match directory.symlink_metadata(name) {
            Ok(metadata) if force && metadata.is_file() => {}
            Ok(_) => {
                return Err(CliError::refused(format!(
                    "cannot use {name}: already exists or is a symbolic link"
                )))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(CliError::refused(format!("cannot inspect {name}: {e}"))),
        }
    }
    for (name, content) in [("bundle.json", json), ("bundle.html", html)] {
        if force {
            match directory.remove_file(name) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(CliError::refused(format!("cannot remove {name}: {e}"))),
            }
        }
        let mut options = OpenOptions::new();
        options
            .write(true)
            .create_new(true)
            .follow(FollowSymlinks::No);
        let mut file = directory.open_with(name, &options).map_err(|e| {
            CliError::refused(format!("cannot create {name} without following links: {e}"))
        })?;
        file.write_all(content.as_bytes())
            .map_err(|e| CliError::refused(format!("cannot write {name}: {e}")))?;
    }
    Ok(())
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn refuses_ancestor_replaced_by_junction_before_open() {
        let root = std::env::temp_dir().join(format!(
            "fireemu-dump-race-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let ancestor = root.join("ancestor");
        let destination = root.join("destination");
        std::fs::create_dir_all(&ancestor).unwrap();
        std::fs::create_dir(&destination).unwrap();
        let target = ancestor.clone();
        let redirect = destination.clone();
        BEFORE_OPEN.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move |path| {
                if path == target {
                    std::fs::rename(&target, target.with_extension("original")).unwrap();
                    let status = std::process::Command::new("cmd")
                        .args(["/C", "mklink", "/J"])
                        .arg(&target)
                        .arg(&redirect)
                        .status()
                        .unwrap();
                    assert!(status.success());
                }
            }))
        });
        let result = write_output(&ancestor.join("output"), false, "json", "html");
        BEFORE_OPEN.with(|hook| *hook.borrow_mut() = None);
        let error = result.err().expect("the swapped ancestor must be refused");
        assert!(error.message.contains("without following links"));
        assert!(!destination.join("output").exists());
        std::fs::remove_dir(&ancestor).unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }
}
