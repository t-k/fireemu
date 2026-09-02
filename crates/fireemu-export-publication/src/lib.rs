//! Owner-only staging and atomic export-directory publication.
//!
//! A [`PublicationStage`] owns one private sibling directory and cannot publish it. Only
//! [`CompletePublicationStage`], obtained after the caller has finished the export tree, can
//! replace the captured target identity. Both typestates clean up only the stage identity
//! they created.
//!
//! Unix cleanup requires every canonical namespace ancestor to be root/current-user owned and
//! not group/world writable; macOS extended ACLs are refused. Staged export publication is
//! unavailable on Windows and fails before creating or modifying any export path.

use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(unix)]
static NEXT_STAGE_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, PartialEq, Eq)]
struct TargetIdentity {
    present: bool,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
}

/// An owner-only sibling directory that is not publishable until marked complete.
#[derive(Debug)]
pub struct PublicationStage {
    #[cfg(unix)]
    target: PathBuf,
    root: PathBuf,
    expected_target: TargetIdentity,
    #[cfg(unix)]
    owned_stage: TargetIdentity,
    armed: bool,
}

impl PublicationStage {
    /// Captures and validates the current target identity, then creates an owner-only sibling stage.
    ///
    /// The validator runs between two identity observations. A target replaced while its overwrite
    /// policy is being checked is rejected, and the captured identity is checked again at publish.
    #[cfg(unix)]
    pub fn create(
        target: &Path,
        validate_target: impl FnOnce(&Path) -> Result<(), String>,
    ) -> Result<Self, String> {
        let parent = target
            .parent()
            .ok_or_else(|| "the export path has no parent directory".to_owned())?;
        prepare_parent(parent)?;
        let parent = trusted_canonical_parent(parent)?;
        let target_name = target
            .file_name()
            .ok_or_else(|| "the export path has no directory name".to_owned())?;
        let target = parent.join(target_name);
        let expected_target = target_identity(&target)?;
        validate_target(&target)?;
        if !identity_matches_path(&target, &expected_target)? {
            return Err(
                "the export target changed while its overwrite policy was checked; it was left unchanged"
                    .to_owned(),
            );
        }
        let root = create_stage_sibling(&target, &parent)?;
        let owned_stage = stage_identity(&root)?;
        Ok(Self {
            target,
            root,
            expected_target,
            owned_stage,
            armed: true,
        })
    }

    /// Refuses staged publication on platforms without stable file identities and safe rename.
    #[cfg(not(unix))]
    pub fn create(
        _target: &Path,
        _validate_target: impl FnOnce(&Path) -> Result<(), String>,
    ) -> Result<Self, String> {
        Err(
            "safe atomic export publication is unavailable on Windows; no export was written"
                .to_owned(),
        )
    }

    /// Private directory in which the caller constructs the complete export tree.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Whether a target directory existed when this stage was created.
    #[must_use]
    pub const fn target_was_present(&self) -> bool {
        self.expected_target.present
    }

    /// Marks the caller-owned tree complete and transfers it to the publishable typestate.
    #[must_use]
    pub fn complete(self) -> CompletePublicationStage {
        CompletePublicationStage(self)
    }
}

impl Drop for PublicationStage {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        #[cfg(unix)]
        if target_identity(&self.root).is_ok_and(|identity| identity == self.owned_stage) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }
}

/// A fully written stage that may atomically replace its captured target.
#[derive(Debug)]
pub struct CompletePublicationStage(PublicationStage);

impl CompletePublicationStage {
    /// Atomically publishes the complete stage if the target identity is unchanged.
    #[cfg(unix)]
    pub fn publish(mut self) -> Result<(), String> {
        if !identity_matches_path(&self.0.root, &self.0.owned_stage)? {
            return Err(
                "the owned export stage changed before publication; it was not published"
                    .to_owned(),
            );
        }
        publish_stage(
            &self.0.root,
            &self.0.target,
            &self.0.expected_target,
            &self.0.owned_stage,
        )?;
        if self.0.expected_target.present {
            if !identity_matches_path(&self.0.root, &self.0.expected_target)? {
                return Err(
                    "the displaced export target changed before cleanup; it was not removed"
                        .to_owned(),
                );
            }
            std::fs::remove_dir_all(&self.0.root)
                .map_err(|error| format!("cannot remove the displaced export target: {error}"))?;
        }
        self.0.armed = false;
        Ok(())
    }

    /// Refuses publication on platforms without a safe atomic implementation.
    #[cfg(not(unix))]
    pub fn publish(self) -> Result<(), String> {
        Err(
            "safe atomic export publication is unavailable on Windows; no export was written"
                .to_owned(),
        )
    }

    /// Private directory of the completed stage, for read-only validation before publish.
    #[must_use]
    pub fn root(&self) -> &Path {
        self.0.root()
    }
}

#[cfg(unix)]
fn target_identity(path: &Path) -> Result<TargetIdentity, String> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(TargetIdentity {
                present: false,
                #[cfg(unix)]
                device: 0,
                #[cfg(unix)]
                inode: 0,
            });
        }
        Err(error) => return Err(format!("cannot inspect the export target: {error}")),
    };
    if metadata.file_type().is_symlink() {
        return Err("the export target is a symlink, which an export never follows".to_owned());
    }
    if !metadata.file_type().is_dir() {
        return Err("the export target is not a directory".to_owned());
    }
    Ok(TargetIdentity {
        present: true,
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

#[cfg(unix)]
fn identity_matches_path(path: &Path, expected: &TargetIdentity) -> Result<bool, String> {
    Ok(target_identity(path)? == *expected)
}

#[cfg(unix)]
fn stage_identity(path: &Path) -> Result<TargetIdentity, String> {
    target_identity(path)
}

#[cfg(unix)]
fn prepare_parent(parent: &Path) -> Result<(), String> {
    match std::fs::symlink_metadata(parent) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            Err("the export parent is a symlink, which an export never follows".to_owned())
        }
        Ok(metadata) if !metadata.file_type().is_dir() => {
            Err("the export parent is not a directory".to_owned())
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => create_private_dir(parent),
        Err(error) => Err(format!("cannot inspect the export parent: {error}")),
    }
}

#[cfg(unix)]
fn trusted_canonical_parent(parent: &Path) -> Result<PathBuf, String> {
    use std::os::unix::fs::MetadataExt as _;

    let parent = std::fs::canonicalize(parent)
        .map_err(|error| format!("cannot resolve the export parent: {error}"))?;
    let effective_uid = rustix::process::geteuid().as_raw();
    for ancestor in parent.ancestors() {
        let metadata = std::fs::symlink_metadata(ancestor).map_err(|error| {
            format!(
                "cannot inspect export namespace ancestor {}: {error}",
                ancestor.display()
            )
        })?;
        let mode = metadata.mode();
        if metadata.uid() != 0 && metadata.uid() != effective_uid {
            return Err(format!(
                "export namespace ancestor {} is not owned by the current user or root",
                ancestor.display()
            ));
        }
        if mode & 0o022 != 0 {
            return Err(format!(
                "export namespace ancestor {} is writable by other users, so staged cleanup cannot be made safe",
                ancestor.display()
            ));
        }
        #[cfg(target_os = "macos")]
        reject_extended_acl(ancestor)?;
    }
    Ok(parent)
}

#[cfg(target_os = "macos")]
fn reject_extended_acl(path: &Path) -> Result<(), String> {
    let entries = exacl::getfacl(path, None).map_err(|error| {
        format!(
            "cannot inspect the ACL on export namespace ancestor {}: {error}",
            path.display()
        )
    })?;
    if entries.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "export namespace ancestor {} has an extended ACL, so staged cleanup cannot be made safe",
            path.display()
        ))
    }
}

#[cfg(unix)]
fn create_stage_sibling(target: &Path, parent: &Path) -> Result<PathBuf, String> {
    let name = target
        .file_name()
        .map_or_else(|| "export".into(), |name| name.to_string_lossy());
    for _ in 0..32 {
        let id = NEXT_STAGE_ID.fetch_add(1, Ordering::Relaxed);
        let stage = parent.join(format!(".{name}.fireemu-stage-{}-{id}", std::process::id()));
        match create_private_stage(&stage) {
            Ok(()) => return Ok(stage),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(format!("cannot create private export stage: {error}")),
        }
    }
    Err("cannot allocate a unique private export stage".to_owned())
}

#[cfg(unix)]
fn create_private_stage(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt as _;
    std::fs::DirBuilder::new().mode(0o700).create(path)
}

#[cfg(unix)]
fn create_private_dir(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)
        .map_err(|error| format!("cannot create private export parent: {error}"))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .map_err(|error| format!("cannot restrict export parent permissions: {error}"))
}

#[cfg(unix)]
fn publish_stage(
    stage: &Path,
    target: &Path,
    expected: &TargetIdentity,
    owned_stage: &TargetIdentity,
) -> Result<(), String> {
    if !identity_matches_path(target, expected)? {
        return Err(
            "the export target changed after it was checked; it was left unchanged".to_owned(),
        );
    }
    atomic_publish(stage, target, expected.present, owned_stage)?;
    if expected.present {
        verify_displaced_target_or_rollback(stage, target, expected)?;
    }
    Ok(())
}

#[cfg(unix)]
fn verify_displaced_target_or_rollback(
    stage: &Path,
    target: &Path,
    expected: &TargetIdentity,
) -> Result<(), String> {
    let displaced = identity_matches_path(stage, expected);
    if displaced.as_ref().is_ok_and(|matches| *matches) {
        return Ok(());
    }
    let detail = displaced
        .err()
        .unwrap_or_else(|| "the displaced target has a different identity".to_owned());
    match atomic_publish(stage, target, true, expected) {
        Ok(()) => Err(format!(
            "the export target changed during publication ({detail}); the prior target was restored"
        )),
        Err(rollback) => Err(format!(
            "the export target changed during publication ({detail}), and atomic rollback failed: {rollback}"
        )),
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn atomic_publish(
    stage: &Path,
    target: &Path,
    target_present: bool,
    _owned_stage: &TargetIdentity,
) -> Result<(), String> {
    let flags = if target_present {
        rustix::fs::RenameFlags::EXCHANGE
    } else {
        rustix::fs::RenameFlags::NOREPLACE
    };
    rustix::fs::renameat_with(rustix::fs::CWD, stage, rustix::fs::CWD, target, flags)
        .map_err(|error| format!("atomic export publication is unavailable or failed: {error}"))
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod tests {
    use super::{atomic_publish, target_identity, verify_displaced_target_or_rollback};

    #[test]
    fn a_post_check_identity_race_is_atomically_rolled_back() {
        let root = std::env::temp_dir().join(format!(
            "fireemu-publication-rollback-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir(&root).unwrap();
        let target = root.join("target");
        let displaced = root.join("displaced");
        let stage = root.join("stage");
        std::fs::create_dir(&target).unwrap();
        std::fs::write(target.join("old"), b"old").unwrap();
        let expected = target_identity(&target).unwrap();
        std::fs::rename(&target, &displaced).unwrap();
        std::fs::create_dir(&target).unwrap();
        std::fs::write(target.join("attacker"), b"unchanged").unwrap();
        std::fs::create_dir(&stage).unwrap();
        std::fs::write(stage.join("new"), b"new").unwrap();

        atomic_publish(&stage, &target, true, &expected).unwrap();
        let error = verify_displaced_target_or_rollback(&stage, &target, &expected).unwrap_err();

        assert!(error.contains("prior target was restored"), "{error}");
        assert_eq!(
            std::fs::read(target.join("attacker")).unwrap(),
            b"unchanged"
        );
        assert_eq!(std::fs::read(stage.join("new")).unwrap(), b"new");
        let _ = std::fs::remove_dir_all(root);
    }
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
fn atomic_publish(
    stage: &Path,
    target: &Path,
    target_present: bool,
    _owned_stage: &TargetIdentity,
) -> Result<(), String> {
    if target_present {
        return Err(
            "atomic directory replacement is unavailable on this platform; the existing export was left unchanged"
                .to_owned(),
        );
    }
    std::fs::rename(stage, target)
        .map_err(|error| format!("cannot atomically publish the export directory: {error}"))
}

#[cfg(all(test, windows))]
mod windows_tests {
    use super::PublicationStage;

    #[test]
    fn publication_fails_before_creating_or_modifying_any_path() {
        let parent = std::env::temp_dir().join(format!(
            "fireemu-windows-publication-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&parent);
        let target = parent.join("export");
        let mut validator_called = false;

        let error = PublicationStage::create(&target, |_| {
            validator_called = true;
            Ok(())
        })
        .unwrap_err();

        assert!(error.contains("unavailable on Windows"), "{error}");
        assert!(!validator_called);
        assert!(!parent.exists());
    }
}
