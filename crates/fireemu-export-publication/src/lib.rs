//! Owner-only staging and atomic export-directory publication.
//!
//! A [`PublicationStage`] owns one private sibling directory and cannot publish it. Only
//! [`CompletePublicationStage`], obtained after the caller has finished the export tree, can
//! replace the captured target identity. Both typestates clean up only the stage identity
//! they created.
//!
//! A target that is itself a mount point (a container volume mounted at the export path) cannot
//! be renamed, so its stage is made inside it and publication moves entries instead: the old
//! entries go to a private `.fireemu-displaced-*` directory, `firebase-export-metadata.json`
//! first, and the new ones come in with the manifest last. That publication is not atomic: an
//! interrupted one leaves a directory without the manifest, which an import refuses rather than
//! reads half of.
//!
//! Unix cleanup requires every canonical namespace ancestor to be root/current-user owned and
//! not group/world writable; on macOS an ACL entry that lets another principal change an ancestor
//! (every `allow` entry of a principal but the owner, root and the user running the export) is refused,
//! and a `deny` entry is accepted; the stage's own ACL is cleared when it is created. Staged export publication is
//! unavailable on Windows and fails before creating or modifying any export path.

use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(target_os = "macos")]
mod acl;
#[cfg(unix)]
mod parent;
#[cfg(target_os = "macos")]
mod volume;

#[cfg(unix)]
static NEXT_STAGE_ID: AtomicU64 = AtomicU64::new(1);

/// The name of the manifest that marks a directory as a complete export.
const MANIFEST_NAME: &str = "firebase-export-metadata.json";

/// Where the stage lives and so how it is published.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Placement {
    /// A sibling of the target, published by one atomic rename.
    Sibling,
    /// Inside a target that is a mount point, published by moving entries.
    InsideMountPoint,
}

/// Whether `name`, an entry of an export directory, is a stage or a displaced tree that
/// publication into a mount point keeps there while it runs (or left behind when interrupted).
/// The caller must not copy such an entry into a new export.
#[must_use]
pub fn is_publication_entry(name: &std::ffi::OsStr) -> bool {
    name.to_str().is_some_and(|name| {
        name.starts_with(".fireemu-stage-") || name.starts_with(".fireemu-displaced-")
    })
}

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
    #[cfg(unix)]
    placement: Placement,
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
        Self::create_with(target, validate_target, &is_mount_root)
    }

    /// [`Self::create`] with the mount-point test passed in (the tests cannot mount a volume).
    #[cfg(unix)]
    fn create_with(
        target: &Path,
        validate_target: impl FnOnce(&Path) -> Result<(), String>,
        mount_root: &dyn Fn(&Path, &Path) -> Result<bool, String>,
    ) -> Result<Self, String> {
        // A one-element relative name such as `out` has the empty path as its parent, and
        // every operation on "" fails with ENOENT. Resolving against the working directory
        // here means no caller can lose an export by passing a bare directory name.
        let target = &std::path::absolute(target)
            .map_err(|error| format!("cannot resolve the export path: {error}"))?;
        let parent = target
            .parent()
            .ok_or_else(|| "the export path has no parent directory".to_owned())?;
        let parent = parent::prepare_and_validate_parent(parent)?;
        let target_name = target
            .file_name()
            .ok_or_else(|| "the export path has no directory name".to_owned())?;
        let target = parent.join(target_name);
        let expected_target = target_identity(&target)?;
        // An existing destination can itself be a mount point (a volume mounted at the export path).
        #[cfg(target_os = "macos")]
        if expected_target.present {
            parent::system_volume_check(&target)?;
        }
        validate_target(&target)?;
        if !identity_matches_path(&target, &expected_target)? {
            return Err(
                "the export target changed while its overwrite policy was checked; it was left unchanged"
                    .to_owned(),
            );
        }
        let placement = if expected_target.present && mount_root(&target, &parent)? {
            Placement::InsideMountPoint
        } else {
            Placement::Sibling
        };
        let root = match placement {
            Placement::Sibling => create_stage_sibling(&target, &parent)?,
            // The stage is made inside the target, so the target itself must pass the checks
            // its ancestors pass.
            Placement::InsideMountPoint => {
                let inside = parent::prepare_and_validate_parent(&target)?;
                if inside != target {
                    return Err(
                        "the export target changed while its overwrite policy was checked; it was left unchanged"
                            .to_owned(),
                    );
                }
                create_private_child(&target, "stage")?
            }
        };
        let owned_stage = stage_identity(&root)?;
        Ok(Self {
            target,
            root,
            expected_target,
            owned_stage,
            placement,
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
        if self.0.placement == Placement::InsideMountPoint {
            if !identity_matches_path(&self.0.target, &self.0.expected_target)? {
                return Err(
                    "the export target changed after it was checked; it was left unchanged"
                        .to_owned(),
                );
            }
            publish_into_mount_point(&self.0.root, &self.0.target)?;
            self.0.armed = false;
            return Ok(());
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
fn create_stage_sibling(target: &Path, parent: &Path) -> Result<PathBuf, String> {
    let name = target
        .file_name()
        .map_or_else(|| "export".into(), |name| name.to_string_lossy());
    for _ in 0..32 {
        let id = NEXT_STAGE_ID.fetch_add(1, Ordering::Relaxed);
        let stage = parent.join(format!(".{name}.fireemu-stage-{}-{id}", std::process::id()));
        match create_private_stage(&stage) {
            Ok(()) => {
                // The stage starts with no ACL of its own: it must not inherit one from its parent.
                #[cfg(target_os = "macos")]
                if let Err(error) = acl::clear_stage_acl(&stage) {
                    let _ = std::fs::remove_dir(&stage);
                    return Err(error);
                }
                return Ok(stage);
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(format!("cannot create private export stage: {error}")),
        }
    }
    Err("cannot allocate a unique private export stage".to_owned())
}

/// Creates an owner-only `.fireemu-<kind>-<pid>-<n>` directory inside `directory`.
#[cfg(unix)]
fn create_private_child(directory: &Path, kind: &str) -> Result<PathBuf, String> {
    for _ in 0..32 {
        let id = NEXT_STAGE_ID.fetch_add(1, Ordering::Relaxed);
        let child = directory.join(format!(".fireemu-{kind}-{}-{id}", std::process::id()));
        match create_private_stage(&child) {
            Ok(()) => {
                #[cfg(target_os = "macos")]
                if let Err(error) = acl::clear_stage_acl(&child) {
                    let _ = std::fs::remove_dir(&child);
                    return Err(error);
                }
                return Ok(child);
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(format!("cannot create private export {kind}: {error}")),
        }
    }
    Err(format!("cannot allocate a unique private export {kind}"))
}

/// Whether `target` is the root of a mount, which `rename(2)` refuses to move (`EBUSY` or
/// `EXDEV`): a different device than its parent's, or, on Linux, a bind mount of the same one.
#[cfg(unix)]
fn is_mount_root(target: &Path, parent: &Path) -> Result<bool, String> {
    use std::os::unix::fs::MetadataExt as _;

    let target_device = std::fs::symlink_metadata(target)
        .map_err(|error| format!("cannot inspect the export target: {error}"))?
        .dev();
    let parent_device = std::fs::metadata(parent)
        .map_err(|error| format!("cannot inspect the export parent: {error}"))?
        .dev();
    if target_device != parent_device {
        return Ok(true);
    }
    #[cfg(target_os = "linux")]
    {
        use rustix::fs::{statx, AtFlags, StatxAttributes, StatxFlags};
        if let Ok(status) = statx(
            rustix::fs::CWD,
            target,
            AtFlags::SYMLINK_NOFOLLOW,
            StatxFlags::BASIC_STATS,
        ) {
            if status
                .stx_attributes_mask
                .contains(StatxAttributes::MOUNT_ROOT)
            {
                return Ok(status.stx_attributes.contains(StatxAttributes::MOUNT_ROOT));
            }
        }
    }
    Ok(false)
}

/// Replaces what `target` holds with what `stage` (a directory inside it) holds, by renames on
/// the target's own volume.
///
/// The old manifest leaves first and the new one arrives last, so a directory caught in the
/// middle never holds a manifest beside a partial tree. A failure moves back what was moved;
/// when that fails too, the message names where the old export is.
#[cfg(unix)]
fn publish_into_mount_point(stage: &Path, target: &Path) -> Result<(), String> {
    publish_into_mount_point_with(stage, target, &|from, to| std::fs::rename(from, to))
}

/// [`publish_into_mount_point`] with the rename of each entry passed in (the tests interrupt it).
#[cfg(unix)]
fn publish_into_mount_point_with(
    stage: &Path,
    target: &Path,
    rename: &dyn Fn(&Path, &Path) -> std::io::Result<()>,
) -> Result<(), String> {
    let displaced = create_private_child(target, "displaced")?;
    let mut moved_out: Vec<std::ffi::OsString> = Vec::new();
    let current = |name: &std::ffi::OsStr| {
        let path = target.join(name);
        path != stage && path != displaced
    };
    let result =
        move_entries(target, &displaced, current, false, rename, &mut moved_out).and_then(|()| {
            let mut moved_in = Vec::new();
            move_entries(stage, target, |_| true, true, rename, &mut moved_in).inspect_err(|_| {
                for name in moved_in.iter().rev() {
                    let _ = std::fs::rename(target.join(name), stage.join(name));
                }
            })
        });
    if let Err(error) = result {
        let mut restored = true;
        for name in moved_out.iter().rev() {
            restored &= std::fs::rename(displaced.join(name), target.join(name)).is_ok();
        }
        if restored {
            let _ = std::fs::remove_dir(&displaced);
            return Err(format!(
                "publication into the mount point failed ({error}); the prior export was restored"
            ));
        }
        return Err(format!(
            "publication into the mount point failed ({error}), and the prior export could not be restored; it is in {}",
            displaced.display()
        ));
    }
    let _ = std::fs::remove_dir(stage);
    std::fs::remove_dir_all(&displaced)
        .map_err(|error| format!("cannot remove the displaced export: {error}"))
}

/// Renames every entry of `from` that `keep` selects into `to`, the manifest last when
/// `manifest_last` (entering the target) and first otherwise (leaving it). Each moved name is
/// pushed onto `moved`.
#[cfg(unix)]
fn move_entries(
    from: &Path,
    to: &Path,
    keep: impl Fn(&std::ffi::OsStr) -> bool,
    manifest_last: bool,
    rename: &dyn Fn(&Path, &Path) -> std::io::Result<()>,
    moved: &mut Vec<std::ffi::OsString>,
) -> Result<(), String> {
    let mut names = std::fs::read_dir(from)
        .map_err(|error| format!("cannot read {}: {error}", from.display()))?
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("cannot read {}: {error}", from.display()))?;
    names.retain(|name| keep(name));
    names.sort_by_key(|name| (name == MANIFEST_NAME) == manifest_last);
    for name in names {
        rename(&from.join(&name), &to.join(&name))
            .map_err(|error| format!("cannot move {}: {error}", from.join(&name).display()))?;
        moved.push(name);
    }
    Ok(())
}

#[cfg(unix)]
fn create_private_stage(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt as _;
    std::fs::DirBuilder::new().mode(0o700).create(path)
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
    rename_for(target_present, |flags| {
        rustix::fs::renameat_with(rustix::fs::CWD, stage, rustix::fs::CWD, target, flags)
    })
}

/// Picks the rename flags (exchange an existing target, never replace a missing one) and words a refusal.
/// `rename` is the system call, passed in so the refusal path can be exercised on any volume.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn rename_for(
    target_present: bool,
    rename: impl FnOnce(rustix::fs::RenameFlags) -> rustix::io::Result<()>,
) -> Result<(), String> {
    let flags = if target_present {
        rustix::fs::RenameFlags::EXCHANGE
    } else {
        rustix::fs::RenameFlags::NOREPLACE
    };
    rename(flags).map_err(publication_error)
}

/// The message of a refused atomic rename. A volume that lacks the rename flags (exFAT, FAT, some
/// network filesystems) answers `ENOTSUP`; the message then says why and what to do.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn publication_error(error: rustix::io::Errno) -> String {
    if error == rustix::io::Errno::NOTSUP || error == rustix::io::Errno::OPNOTSUPP {
        format!(
            "atomic export publication is unavailable or failed: {error}; this volume does not support atomic directory rename, so export to a directory on an APFS volume (macOS) or on a local filesystem that supports it"
        )
    } else {
        format!("atomic export publication is unavailable or failed: {error}")
    }
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod tests {
    use super::{
        atomic_publish, publication_error, rename_for, target_identity,
        verify_displaced_target_or_rollback,
    };

    #[test]
    fn an_unsupported_rename_names_the_volume_and_the_way_out() {
        for error in [rustix::io::Errno::NOTSUP, rustix::io::Errno::OPNOTSUPP] {
            let message = publication_error(error);
            assert!(
                message.contains("does not support atomic directory rename"),
                "{message}"
            );
            assert!(message.contains("APFS"), "{message}");
            assert!(
                message.starts_with("atomic export publication is unavailable or failed"),
                "{message}"
            );
        }
    }

    #[test]
    fn a_refused_rename_is_worded_by_publication_error_and_the_flags_follow_the_target() {
        let seen = std::cell::RefCell::new(Vec::new());
        let refuse = |flags| {
            seen.borrow_mut().push(flags);
            Err(rustix::io::Errno::NOTSUP)
        };
        let message = rename_for(true, refuse).unwrap_err();
        assert!(
            message.contains("does not support atomic directory rename"),
            "{message}"
        );
        let message = rename_for(false, refuse).unwrap_err();
        assert!(
            message.contains("does not support atomic directory rename"),
            "{message}"
        );
        assert_eq!(
            *seen.borrow(),
            [
                rustix::fs::RenameFlags::EXCHANGE,
                rustix::fs::RenameFlags::NOREPLACE
            ]
        );
        assert_eq!(rename_for(true, |_| Ok(())), Ok(()));
    }

    #[test]
    fn any_other_rename_failure_keeps_the_plain_message() {
        let message = publication_error(rustix::io::Errno::EXIST);
        assert!(
            message.starts_with("atomic export publication is unavailable or failed"),
            "{message}"
        );
        assert!(!message.contains("does not support"), "{message}");
    }

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

#[cfg(all(test, unix))]
mod mount_point_tests {
    use super::{is_mount_root, is_publication_entry, move_entries, PublicationStage};
    use std::path::{Path, PathBuf};

    fn scratch(name: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "fireemu-publication-mount-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir(&root).unwrap();
        std::fs::canonicalize(root).unwrap()
    }

    fn names(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    /// A target with an old export, staged as a mount point.
    fn staged(root: &Path) -> (PathBuf, PublicationStage) {
        let target = root.join("volume");
        std::fs::create_dir(&target).unwrap();
        std::fs::write(target.join("firebase-export-metadata.json"), b"old").unwrap();
        std::fs::create_dir(target.join("auth_export")).unwrap();
        std::fs::write(target.join("auth_export/accounts.json"), b"old").unwrap();
        let stage = PublicationStage::create_with(&target, |_| Ok(()), &|_, _| Ok(true)).unwrap();
        (target, stage)
    }

    #[test]
    fn a_mount_point_target_is_staged_inside_itself_and_replaced_by_moves() {
        let root = scratch("replace");
        let (target, stage) = staged(&root);
        assert_eq!(stage.root().parent(), Some(target.as_path()));
        assert!(is_publication_entry(stage.root().file_name().unwrap()));
        std::fs::write(stage.root().join("firebase-export-metadata.json"), b"new").unwrap();
        std::fs::create_dir(stage.root().join("firestore_export")).unwrap();

        stage.complete().publish().unwrap();

        assert_eq!(
            names(&target),
            ["firebase-export-metadata.json", "firestore_export"]
        );
        assert_eq!(
            std::fs::read(target.join("firebase-export-metadata.json")).unwrap(),
            b"new"
        );
        assert_eq!(names(&root), ["volume"]);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn an_unpublished_stage_inside_a_mount_point_is_removed_and_the_target_kept() {
        let root = scratch("drop");
        let (target, stage) = staged(&root);
        std::fs::write(stage.root().join("firebase-export-metadata.json"), b"new").unwrap();
        drop(stage);
        assert_eq!(
            names(&target),
            ["auth_export", "firebase-export-metadata.json"]
        );
        assert_eq!(
            std::fs::read(target.join("firebase-export-metadata.json")).unwrap(),
            b"old"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_failed_move_into_a_mount_point_restores_the_prior_export() {
        use std::os::unix::fs::PermissionsExt as _;
        if rustix::process::geteuid().is_root() {
            return; // root ignores the permission that makes the move fail
        }
        let root = scratch("restore");
        let (target, stage) = staged(&root);
        std::fs::write(stage.root().join("firebase-export-metadata.json"), b"new").unwrap();
        let stage_root = stage.root().to_path_buf();
        // Entries cannot be renamed out of a directory its owner cannot write.
        std::fs::set_permissions(&stage_root, std::fs::Permissions::from_mode(0o500)).unwrap();

        let error = stage.complete().publish().unwrap_err();
        std::fs::set_permissions(&stage_root, std::fs::Permissions::from_mode(0o700)).unwrap();

        assert!(error.contains("the prior export was restored"), "{error}");
        assert_eq!(
            std::fs::read(target.join("firebase-export-metadata.json")).unwrap(),
            b"old"
        );
        assert!(target.join("auth_export/accounts.json").is_file());
        assert!(
            !names(&target)
                .iter()
                .any(|name| name.starts_with(".fireemu-displaced-")),
            "{:?}",
            names(&target)
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn the_manifest_leaves_first_and_arrives_last() {
        let root = scratch("order");
        let from = root.join("from");
        let to = root.join("to");
        std::fs::create_dir(&from).unwrap();
        std::fs::create_dir(&to).unwrap();
        for name in ["a", "firebase-export-metadata.json", "z"] {
            std::fs::write(from.join(name), b"").unwrap();
        }
        let plain = |from: &Path, to: &Path| std::fs::rename(from, to);
        let mut moved = Vec::new();
        move_entries(&from, &to, |_| true, false, &plain, &mut moved).unwrap();
        assert_eq!(moved[0], "firebase-export-metadata.json");
        let mut moved = Vec::new();
        move_entries(&to, &from, |_| true, true, &plain, &mut moved).unwrap();
        assert_eq!(moved[2], "firebase-export-metadata.json");
        let mut moved = Vec::new();
        move_entries(&from, &to, |name| name != "a", true, &plain, &mut moved).unwrap();
        assert_eq!(moved, ["z", "firebase-export-metadata.json"]);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_directory_on_another_device_is_a_mount_root_and_an_ordinary_one_is_not() {
        let root = scratch("detect");
        std::fs::create_dir(root.join("plain")).unwrap();
        assert!(!is_mount_root(&root.join("plain"), &root).unwrap());
        #[cfg(target_os = "macos")]
        assert!(is_mount_root(Path::new("/dev"), Path::new("/")).unwrap());
        #[cfg(target_os = "linux")]
        assert!(is_mount_root(Path::new("/proc"), Path::new("/")).unwrap());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn publication_entries_are_the_stage_and_displaced_prefixes_only() {
        for name in [".fireemu-stage-1-2", ".fireemu-displaced-1-2"] {
            assert!(is_publication_entry(name.as_ref()), "{name}");
        }
        for name in [
            "firebase-export-metadata.json",
            ".fireemu-stage",
            "fireemu-stage-1",
            ".out.fireemu-stage-1-2",
        ] {
            assert!(!is_publication_entry(name.as_ref()), "{name}");
        }
    }

    mod properties {
        use super::super::{
            create_private_child, is_publication_entry, publish_into_mount_point_with,
        };
        use proptest::prelude::*;
        use std::cell::Cell;
        use std::collections::BTreeMap;
        use std::path::Path;

        const MANIFEST: &str = "firebase-export-metadata.json";
        const NAMES: [&str; 4] = [
            "auth_export",
            "firestore_export",
            "notes.txt",
            "storage_export",
        ];

        /// What a directory holds: each entry that is not a publication entry, with its content.
        fn contents(dir: &Path) -> BTreeMap<String, Vec<u8>> {
            std::fs::read_dir(dir)
                .unwrap()
                .map(Result::unwrap)
                .filter(|entry| !is_publication_entry(&entry.file_name()))
                .map(|entry| {
                    (
                        entry.file_name().to_string_lossy().into_owned(),
                        std::fs::read(entry.path()).unwrap(),
                    )
                })
                .collect()
        }

        fn tree(names: &[bool], content: &[u8]) -> BTreeMap<String, Vec<u8>> {
            let mut tree: BTreeMap<String, Vec<u8>> = NAMES
                .iter()
                .zip(names)
                .filter(|(_, present)| **present)
                .map(|(name, _)| ((*name).to_owned(), content.to_vec()))
                .collect();
            tree.insert(MANIFEST.to_owned(), content.to_vec());
            tree
        }

        fn write(dir: &Path, tree: &BTreeMap<String, Vec<u8>>) {
            for (name, content) in tree {
                std::fs::write(dir.join(name), content).unwrap();
            }
        }

        #[derive(Debug, Clone, Copy)]
        enum Interruption {
            /// The process dies before rename number `n`: nothing is rolled back.
            Killed(usize),
            /// Rename number `n` fails: publication rolls back.
            Fails(usize),
        }

        fn interruption() -> impl Strategy<Value = Interruption> {
            prop_oneof![
                (0usize..12).prop_map(Interruption::Killed),
                (0usize..12).prop_map(Interruption::Fails),
            ]
        }

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(64))]

            /// Whatever rename is interrupted, an importable target (one holding the manifest)
            /// holds a whole export, old or new, and nothing is lost; a failed rename restores
            /// the old export exactly.
            #[test]
            fn an_interrupted_mount_point_publication_never_leaves_a_partial_importable_export(
                old_names in proptest::collection::vec(any::<bool>(), 4),
                new_names in proptest::collection::vec(any::<bool>(), 4),
                interruption in interruption(),
            ) {
                let root = super::scratch("property");
                let target = root.join("volume");
                std::fs::create_dir(&target).unwrap();
                let old = tree(&old_names, b"old");
                let new = tree(&new_names, b"new");
                write(&target, &old);
                let stage = create_private_child(&target, "stage").unwrap();
                write(&stage, &new);

                let calls = Cell::new(0usize);
                let rename = |from: &Path, to: &Path| {
                    let call = calls.get();
                    calls.set(call + 1);
                    match interruption {
                        Interruption::Killed(n) if call == n => panic!("killed"),
                        Interruption::Fails(n) if call == n => {
                            Err(std::io::Error::other("injected"))
                        }
                        _ => std::fs::rename(from, to),
                    }
                };
                let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    publish_into_mount_point_with(&stage, &target, &rename)
                }));
                let renames = old.len() + new.len();
                let after = contents(&target);
                match (interruption, outcome) {
                    (_, Ok(Ok(()))) => {
                        prop_assert_eq!(&after, &new);
                        let clean = std::fs::read_dir(&target)
                            .unwrap()
                            .all(|entry| !is_publication_entry(&entry.unwrap().file_name()));
                        prop_assert!(clean, "publication entries remain");
                    }
                    (Interruption::Fails(n), Ok(Err(error))) => {
                        prop_assert!(n < renames);
                        prop_assert!(error.contains("the prior export was restored"), "{}", error);
                        prop_assert_eq!(&after, &old);
                        prop_assert_eq!(&contents(&stage), &new);
                    }
                    (Interruption::Killed(n), Err(_)) => {
                        prop_assert!(n < renames);
                        if after.contains_key(MANIFEST) {
                            prop_assert!(after == old || after == new, "{:?}", after);
                        }
                        // Every old entry is in the target or the displaced tree, and every new
                        // one in the target or the stage.
                        let mut kept = contents(&stage);
                        for entry in std::fs::read_dir(&target).unwrap() {
                            let entry = entry.unwrap();
                            if entry.file_name().to_string_lossy().starts_with(".fireemu-displaced-") {
                                kept.extend(contents(&entry.path()).into_iter().map(|(k, v)| (format!("old/{k}"), v)));
                            }
                        }
                        for (name, content) in &after {
                            let key = if content == b"old" { format!("old/{name}") } else { name.clone() };
                            kept.insert(key, content.clone());
                        }
                        for name in old.keys() {
                            prop_assert!(kept.contains_key(&format!("old/{name}")), "lost old {}", name);
                        }
                        for name in new.keys() {
                            prop_assert!(kept.contains_key(name), "lost new {}", name);
                        }
                    }
                    (interruption, outcome) => {
                        prop_assert!(false, "{:?} ended as {:?}", interruption, outcome.map_err(|_| "panic"));
                    }
                }
                let _ = std::fs::remove_dir_all(root);
            }
        }
    }
}
