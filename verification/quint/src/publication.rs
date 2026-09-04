//! Atomic publication of a complete Quint evidence snapshot.

use std::fs;
use std::os::unix::io::OwnedFd;
use std::path::{Path, PathBuf};

use rustix::fs::{flock, fstat, openat, FileType, FlockOperation, Mode, OFlags, CWD};

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
    let _publication_lock = PublicationLock::acquire(target_parent)?;
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

struct PublicationLock {
    _descriptor: OwnedFd,
}

impl PublicationLock {
    fn acquire(target_parent: &Path) -> Result<Self, String> {
        let path = target_parent.join(".fireemu-quint-publication.lock");
        let descriptor = openat(
            CWD,
            &path,
            OFlags::CREATE | OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(|error| format!("cannot open evidence publication lock: {error}"))?;
        let metadata = fstat(&descriptor)
            .map_err(|error| format!("cannot inspect evidence publication lock: {error}"))?;
        if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile
            || metadata.st_uid != rustix::process::getuid().as_raw()
            || metadata.st_mode & 0o177 != 0
        {
            return Err("evidence publication lock is not a private regular file".to_owned());
        }
        flock(&descriptor, FlockOperation::LockExclusive)
            .map_err(|error| format!("cannot acquire evidence publication lock: {error}"))?;
        Ok(Self {
            _descriptor: descriptor,
        })
    }
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

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    use super::PublicationLock;

    #[test]
    fn publication_lock_serializes_two_publishers() {
        let temporary = tempfile::tempdir().expect("temporary directory must be created");
        let first = PublicationLock::acquire(temporary.path())
            .expect("first publisher must acquire the lock");
        let target_parent = temporary.path().to_owned();
        let (sender, receiver) = mpsc::channel();
        let second = thread::spawn(move || {
            let lock = PublicationLock::acquire(&target_parent)
                .expect("second publisher must eventually acquire the lock");
            sender.send(()).expect("lock acquisition must be reported");
            drop(lock);
        });

        assert!(receiver.recv_timeout(Duration::from_millis(100)).is_err());
        drop(first);
        receiver
            .recv_timeout(Duration::from_secs(2))
            .expect("second publisher remained blocked after release");
        second.join().expect("second publisher must not panic");
    }

    #[test]
    fn publication_lock_rejects_symlinks_directories_and_public_files() {
        for fixture in ["symlink", "directory", "public-file"] {
            let temporary = tempfile::tempdir().expect("temporary directory must be created");
            let lock = temporary.path().join(".fireemu-quint-publication.lock");
            match fixture {
                "symlink" => {
                    let target = temporary.path().join("target");
                    fs::write(&target, b"").expect("symlink target must be created");
                    symlink(target, &lock).expect("lock symlink must be created");
                }
                "directory" => fs::create_dir(&lock).expect("lock directory must be created"),
                "public-file" => {
                    fs::write(&lock, b"").expect("lock file must be created");
                    fs::set_permissions(&lock, fs::Permissions::from_mode(0o644))
                        .expect("lock mode must be changed");
                }
                _ => unreachable!(),
            }
            assert!(
                PublicationLock::acquire(temporary.path()).is_err(),
                "{fixture} publication lock must fail closed"
            );
        }
    }
}
