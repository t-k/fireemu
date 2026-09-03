//! Atomic publication of a complete Quint evidence snapshot.

use std::fs;
use std::path::{Path, PathBuf};

use crate::model::all_models;

/// Replaces the target with one complete evidence snapshot in a single filesystem operation.
pub fn publish_evidence(source: &Path, target: &Path) -> Result<(), String> {
    let source = canonical_directory(source, "evidence source")?;
    let target = canonical_directory(target, "evidence target")?;
    if source == target || source.starts_with(&target) || target.starts_with(&source) {
        return Err("evidence source and target must be separate directory trees".to_owned());
    }
    validate_complete_set(&source, "source")?;
    validate_complete_set(&target, "target")?;

    let target_parent = target
        .parent()
        .ok_or_else(|| format!("evidence target has no parent: {}", target.display()))?;
    let candidate = tempfile::Builder::new()
        .prefix(".evidence-candidate.")
        .tempdir_in(target_parent)
        .map_err(|error| format!("cannot create evidence candidate: {error}"))?;
    for name in evidence_names() {
        fs::copy(source.join(&name), candidate.path().join(&name))
            .map_err(|error| format!("cannot stage evidence file {name}: {error}"))?;
    }

    atomic_exchange(candidate.path(), &target)?;
    drop(candidate);
    Ok(())
}

fn canonical_directory(path: &Path, label: &str) -> Result<PathBuf, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect {label} {}: {error}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(format!("{label} is not a directory: {}", path.display()));
    }
    fs::canonicalize(path)
        .map_err(|error| format!("cannot resolve {label} {}: {error}", path.display()))
}

fn validate_complete_set(directory: &Path, label: &str) -> Result<(), String> {
    for name in evidence_names() {
        let path = directory.join(&name);
        let metadata = fs::symlink_metadata(&path)
            .map_err(|_| format!("incomplete evidence {label}: {}", path.display()))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(format!("incomplete evidence {label}: {}", path.display()));
        }
    }
    Ok(())
}

fn evidence_names() -> Vec<String> {
    let mut names = vec!["cargo-authority.json".to_owned()];
    names.extend(all_models().map(|descriptor| format!("{}.json", descriptor.name)));
    names
}

#[cfg(any(target_os = "linux", target_vendor = "apple"))]
fn atomic_exchange(candidate: &Path, target: &Path) -> Result<(), String> {
    rustix::fs::renameat_with(
        rustix::fs::CWD,
        candidate,
        rustix::fs::CWD,
        target,
        rustix::fs::RenameFlags::EXCHANGE,
    )
    .map_err(|error| {
        format!(
            "cannot atomically exchange evidence {} with {}: {error}",
            candidate.display(),
            target.display()
        )
    })
}

#[cfg(not(any(target_os = "linux", target_vendor = "apple")))]
fn atomic_exchange(_candidate: &Path, _target: &Path) -> Result<(), String> {
    Err("atomic evidence directory exchange is unsupported on this platform".to_owned())
}
