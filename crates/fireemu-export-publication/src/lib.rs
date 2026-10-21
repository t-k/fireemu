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
//! not group/world writable, or root-owned with the sticky bit (`/tmp`); on macOS an ACL entry that lets another principal change an ancestor
//! (every `allow` entry of a principal but the owner, root and the user running the export) is refused,
//! and a `deny` entry is accepted; the stage's own ACL is cleared when it is created. Below a sticky directory an
//! export target that already exists must be the user's (or root's) and not writable by others,
//! and every symlink on the export path is judged where it is met (see `parent`). Staged export publication is
//! unavailable on Windows and fails before creating or modifying any export path.

#[cfg(unix)]
use std::ffi::{OsStr, OsString};
#[cfg(unix)]
use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(unix)]
use std::sync::Mutex;

#[cfg(target_os = "macos")]
mod acl;
#[cfg(unix)]
mod parent;
#[cfg(target_os = "macos")]
mod volume;

#[cfg(unix)]
static NEXT_STAGE_ID: AtomicU64 = AtomicU64::new(1);

/// The name of the manifest that marks a directory as a complete export.
#[cfg(unix)]
const MANIFEST_NAME: &str = "firebase-export-metadata.json";

/// Where the stage lives and so how it is published.
#[cfg(unix)]
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
    device: rustix::fs::Dev,
    #[cfg(unix)]
    inode: u64,
}

/// A destination a preflight walked and judged, held for the life of the process: an export of
/// its resolved path later (`--export-on-exit`) uses these descriptors and resolves nothing again.
#[cfg(unix)]
struct Held {
    target: PathBuf,
    anchor: parent::Anchor,
    missing: Vec<OsString>,
}

#[cfg(unix)]
static HELD: Mutex<Vec<Held>> = Mutex::new(Vec::new());

/// A second descriptor for the same open directory.
#[cfg(unix)]
fn duplicate(fd: BorrowedFd<'_>) -> Result<OwnedFd, String> {
    rustix::io::fcntl_dupfd_cloexec(fd, 0)
        .map_err(|error| format!("cannot hold the export directory: {error}"))
}

/// The walk a preflight registered for `target` (its resolved path), with fresh descriptors.
#[cfg(unix)]
fn held(target: &Path) -> Result<Option<parent::Walked>, String> {
    let table = HELD
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(held) = table.iter().find(|held| held.target == target) else {
        return Ok(None);
    };
    Ok(Some(parent::Walked {
        anchor: parent::Anchor {
            fd: duplicate(held.anchor.fd.as_fd())?,
            path: held.anchor.path.clone(),
            below_shared: held.anchor.below_shared,
        },
        missing: held.missing.clone(),
    }))
}

/// Checks the existing export namespace without creating, deleting or changing any path.
/// Missing parent components are inspected through their nearest existing ancestor. The caller
/// must separately check its export overwrite/content policy.
///
/// Returns the export path with every symlink on it resolved (each one judged as the export
/// judges it). The walked directory stays open for the life of the process: a later
/// [`PublicationStage::create`] of the returned path (`--export-on-exit`) uses it instead of
/// resolving the path again, so nothing made on the way while the suite runs is followed.
#[cfg(unix)]
pub fn preflight(target: &Path) -> Result<PathBuf, String> {
    preflight_with(target, &is_mount_root)
}

/// The export path with every symlink on it resolved, each one judged as an export judges it;
/// components that do not exist yet are kept as given.
#[cfg(unix)]
pub fn resolve(target: &Path) -> Result<PathBuf, String> {
    let target = std::path::absolute(target)
        .map_err(|error| format!("cannot resolve the export path: {error}"))?;
    let parent = target
        .parent()
        .ok_or("the export path has no parent directory")?;
    let name = target
        .file_name()
        .ok_or("the export path has no directory name")?;
    let walked = parent::walk(parent, &parent::system_volume_check)?;
    Ok(resolved_target(&walked, name))
}

/// Resolution is unsupported on Windows, as publication is.
#[cfg(not(unix))]
pub fn resolve(_target: &Path) -> Result<PathBuf, String> {
    Err(
        "safe atomic export publication is unavailable on Windows; no export was written"
            .to_owned(),
    )
}

#[cfg(unix)]
fn resolved_target(walked: &parent::Walked, name: &OsStr) -> PathBuf {
    walked
        .missing
        .iter()
        .fold(walked.anchor.path.clone(), |path, component| {
            path.join(component)
        })
        .join(name)
}

/// What `fstatat(AT_SYMLINK_NOFOLLOW)` says about `name` in `directory`.
#[cfg(unix)]
fn stat_at(directory: BorrowedFd<'_>, name: &OsStr) -> rustix::io::Result<rustix::fs::Stat> {
    rustix::fs::statat(directory, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)
}

/// Refuses a present export target that another user could have made (see
/// [`parent::target_error`]).
#[cfg(unix)]
fn check_present_target(
    directory: BorrowedFd<'_>,
    name: &OsStr,
    path: &Path,
    below_shared: bool,
) -> Result<(), String> {
    let stat = stat_at(directory, name)
        .map_err(|error| format!("cannot inspect the export target: {error}"))?;
    match parent::target_error(
        path,
        stat.st_uid,
        parent::mode_bits(&stat),
        below_shared,
        rustix::process::geteuid().as_raw(),
    ) {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

/// Opens a present export target as a directory, without following a link.
#[cfg(unix)]
fn open_target(directory: BorrowedFd<'_>, name: &OsStr) -> Result<OwnedFd, String> {
    rustix::fs::openat(
        directory,
        name,
        parent::search_flags(),
        rustix::fs::Mode::empty(),
    )
    .map_err(|error| format!("the export target changed while it was checked: {error}"))
}

/// Whether the effective user may make entries in the directory `directory` holds.
#[cfg(unix)]
fn may_write_in(directory: BorrowedFd<'_>, path: &Path) -> Result<(), String> {
    rustix::fs::accessat(
        directory,
        ".",
        rustix::fs::Access::WRITE_OK | rustix::fs::Access::EXEC_OK,
        rustix::fs::AtFlags::EACCESS,
    )
    .map_err(|error| format!("cannot create an export below {}: {error}", path.display()))
}

/// The test of a mount point, relative to the descriptor of the directory holding the target.
#[cfg(unix)]
type MountRoot<'a> = &'a dyn Fn(BorrowedFd<'_>, &OsStr) -> Result<bool, String>;

#[cfg(unix)]
fn preflight_with(target: &Path, mount_root: MountRoot<'_>) -> Result<PathBuf, String> {
    let target = std::path::absolute(target)
        .map_err(|error| format!("cannot resolve the export path: {error}"))?;
    let parent = target
        .parent()
        .ok_or("the export path has no parent directory")?;
    let name = target
        .file_name()
        .ok_or("the export path has no directory name")?;
    let walked = parent::inspect_parent(parent, &parent::system_volume_check)?;
    let resolved = resolved_target(&walked, name);
    let anchor = &walked.anchor;
    let mut write_below = anchor.fd.as_fd();
    let opened;
    if walked.missing.is_empty() {
        let identity = target_identity_at(anchor.fd.as_fd(), name)?;
        if identity.present {
            check_present_target(anchor.fd.as_fd(), name, &resolved, anchor.below_shared)?;
            opened = open_target(anchor.fd.as_fd(), name)?;
            parent::system_volume_check(&resolved, opened.as_fd())?;
            if mount_root(anchor.fd.as_fd(), name)? {
                // The stage is made inside the target, which must pass what its ancestors pass.
                parent::judge(
                    opened.as_fd(),
                    &resolved,
                    &parent::system_volume_check,
                    rustix::process::geteuid().as_raw(),
                )?;
                write_below = opened.as_fd();
            }
        }
    }
    may_write_in(write_below, &resolved)?;
    let mut table = HELD
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    table.retain(|held| held.target != resolved);
    table.push(Held {
        target: resolved.clone(),
        anchor: walked.anchor,
        missing: walked.missing,
    });
    Ok(resolved)
}

/// Export publication is unsupported on Windows; inspection never changes the destination.
#[cfg(not(unix))]
pub fn preflight(_target: &Path) -> Result<PathBuf, String> {
    Err(
        "safe atomic export publication is unavailable on Windows; no export was written"
            .to_owned(),
    )
}

/// An owner-only sibling directory that is not publishable until marked complete.
#[derive(Debug)]
pub struct PublicationStage {
    /// The resolved export path.
    #[cfg(unix)]
    target: PathBuf,
    /// The directory holding the target, held since the walk.
    #[cfg(unix)]
    parent: OwnedFd,
    #[cfg(unix)]
    target_name: OsString,
    /// The directory holding the stage: the parent, or the target when it is a mount point.
    #[cfg(unix)]
    holder: OwnedFd,
    #[cfg(unix)]
    stage_name: OsString,
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
    /// A target whose resolved path a [`preflight`] returned uses the directory that preflight
    /// holds; any other is walked now. Everything after the walk is relative to the held parent
    /// directory.
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
        mount_root: MountRoot<'_>,
    ) -> Result<Self, String> {
        // A one-element relative name such as `out` has the empty path as its parent, and
        // every operation on "" fails with ENOENT. Resolving against the working directory
        // here means no caller can lose an export by passing a bare directory name.
        let target = std::path::absolute(target)
            .map_err(|error| format!("cannot resolve the export path: {error}"))?;
        let parent_path = target
            .parent()
            .ok_or_else(|| "the export path has no parent directory".to_owned())?;
        let target_name = target
            .file_name()
            .ok_or_else(|| "the export path has no directory name".to_owned())?
            .to_owned();
        let walked = match held(&target)? {
            Some(walked) => {
                // Judged again through the held descriptor: its owner may have changed it.
                parent::judge_held(
                    walked.anchor.fd.as_fd(),
                    &walked.anchor.path,
                    &parent::system_volume_check,
                    rustix::process::geteuid().as_raw(),
                )?;
                walked
            }
            None => parent::inspect_parent(parent_path, &parent::system_volume_check)?,
        };
        let anchor = parent::complete(walked, &parent::system_volume_check, &|_| {})?;
        let target = anchor.path.join(&target_name);
        let expected_target = target_identity_at(anchor.fd.as_fd(), &target_name)?;
        // Before the overwrite policy reads anything in it.
        let opened_target = if expected_target.present {
            check_present_target(
                anchor.fd.as_fd(),
                &target_name,
                &target,
                anchor.below_shared,
            )?;
            let opened = open_target(anchor.fd.as_fd(), &target_name)?;
            // An existing destination can itself be a mount point (a volume mounted there).
            parent::system_volume_check(&target, opened.as_fd())?;
            Some(opened)
        } else {
            None
        };
        validate_target(&target)?;
        if target_identity_at(anchor.fd.as_fd(), &target_name)? != expected_target {
            return Err(
                "the export target changed while its overwrite policy was checked; it was left unchanged"
                    .to_owned(),
            );
        }
        let placement = if expected_target.present && mount_root(anchor.fd.as_fd(), &target_name)? {
            Placement::InsideMountPoint
        } else {
            Placement::Sibling
        };
        let mount_target = opened_target.filter(|_| placement == Placement::InsideMountPoint);
        let (holder, stage_name, root) = if let Some(opened) = mount_target {
            // The stage is made inside the target, so the target itself must pass the
            // checks its ancestors pass.
            parent::judge(
                opened.as_fd(),
                &target,
                &parent::system_volume_check,
                rustix::process::geteuid().as_raw(),
            )?;
            if identity_of(opened.as_fd())? != expected_target {
                return Err(
                    "the export target changed while its overwrite policy was checked; it was left unchanged"
                        .to_owned(),
                );
            }
            let (stage_name, root) = create_private_child(opened.as_fd(), &target, "stage")?;
            (opened, stage_name, root)
        } else {
            let (stage_name, root) =
                create_stage_sibling(anchor.fd.as_fd(), &anchor.path, &target_name)?;
            (duplicate(anchor.fd.as_fd())?, stage_name, root)
        };
        let owned_stage = target_identity_at(holder.as_fd(), &stage_name)?;
        Ok(Self {
            target,
            parent: anchor.fd,
            target_name,
            holder,
            stage_name,
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

    /// The export path, resolved: what the publication replaces. A caller that reads the previous
    /// export (to keep entries it does not manage) reads it here, never by the path it was given.
    #[cfg(unix)]
    #[must_use]
    pub fn target(&self) -> &Path {
        &self.target
    }

    /// The export path; publication is unavailable on Windows.
    #[cfg(not(unix))]
    #[must_use]
    pub fn target(&self) -> &Path {
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
        if target_identity_at(self.holder.as_fd(), &self.stage_name)
            .is_ok_and(|identity| identity == self.owned_stage)
        {
            let _ = parent::remove_tree_at(self.holder.as_fd(), &self.stage_name);
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
        let stage = &self.0;
        if target_identity_at(stage.holder.as_fd(), &stage.stage_name)? != stage.owned_stage {
            return Err(
                "the owned export stage changed before publication; it was not published"
                    .to_owned(),
            );
        }
        if stage.placement == Placement::InsideMountPoint {
            if identity_of(stage.holder.as_fd())? != stage.expected_target {
                return Err(
                    "the export target changed after it was checked; it was left unchanged"
                        .to_owned(),
                );
            }
            publish_into_mount_point(stage.holder.as_fd(), &stage.target, &stage.stage_name)?;
            self.0.armed = false;
            return Ok(());
        }
        let parent = stage.parent.as_fd();
        publish_stage(
            parent,
            &stage.stage_name,
            &stage.target_name,
            &stage.expected_target,
        )?;
        if stage.expected_target.present {
            if target_identity_at(parent, &stage.stage_name)? != stage.expected_target {
                return Err(
                    "the displaced export target changed before cleanup; it was not removed"
                        .to_owned(),
                );
            }
            parent::remove_tree_at(parent, &stage.stage_name)
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
fn identity_from(stat: &rustix::fs::Stat) -> Result<TargetIdentity, String> {
    match rustix::fs::FileType::from_raw_mode(stat.st_mode) {
        rustix::fs::FileType::Symlink => {
            Err("the export target is a symlink, which an export never follows".to_owned())
        }
        rustix::fs::FileType::Directory => Ok(TargetIdentity {
            present: true,
            device: stat.st_dev,
            inode: stat.st_ino,
        }),
        _ => Err("the export target is not a directory".to_owned()),
    }
}

/// The identity of the entry `name` in `directory`, without following a link.
#[cfg(unix)]
fn target_identity_at(directory: BorrowedFd<'_>, name: &OsStr) -> Result<TargetIdentity, String> {
    match stat_at(directory, name) {
        Ok(stat) => identity_from(&stat),
        Err(rustix::io::Errno::NOENT) => Ok(TargetIdentity {
            present: false,
            device: 0,
            inode: 0,
        }),
        Err(error) => Err(format!("cannot inspect the export target: {error}")),
    }
}

/// The identity of the directory a descriptor holds.
#[cfg(unix)]
fn identity_of(directory: BorrowedFd<'_>) -> Result<TargetIdentity, String> {
    let stat = rustix::fs::fstat(directory)
        .map_err(|error| format!("cannot inspect the export target: {error}"))?;
    identity_from(&stat)
}

/// Makes the stage beside the target, in the held parent directory.
#[cfg(unix)]
fn create_stage_sibling(
    parent: BorrowedFd<'_>,
    parent_path: &Path,
    target_name: &OsStr,
) -> Result<(OsString, PathBuf), String> {
    let name = target_name.to_string_lossy();
    for _ in 0..32 {
        let id = NEXT_STAGE_ID.fetch_add(1, Ordering::Relaxed);
        let stage = OsString::from(format!(".{name}.fireemu-stage-{}-{id}", std::process::id()));
        match create_private_stage(parent, &stage) {
            Ok(()) => {
                let path = parent_path.join(&stage);
                // The stage starts with no ACL of its own: it must not inherit one from its parent.
                #[cfg(target_os = "macos")]
                if let Err(error) = acl::clear_stage_acl(&path) {
                    let _ = rustix::fs::unlinkat(parent, &stage, rustix::fs::AtFlags::REMOVEDIR);
                    return Err(error);
                }
                return Ok((stage, path));
            }
            Err(rustix::io::Errno::EXIST) => {}
            Err(error) => return Err(format!("cannot create private export stage: {error}")),
        }
    }
    Err("cannot allocate a unique private export stage".to_owned())
}

/// Creates an owner-only `.fireemu-<kind>-<pid>-<n>` directory inside the directory `directory`
/// holds (`directory_path` names it in messages).
#[cfg(unix)]
fn create_private_child(
    directory: BorrowedFd<'_>,
    directory_path: &Path,
    kind: &str,
) -> Result<(OsString, PathBuf), String> {
    for _ in 0..32 {
        let id = NEXT_STAGE_ID.fetch_add(1, Ordering::Relaxed);
        let child = OsString::from(format!(".fireemu-{kind}-{}-{id}", std::process::id()));
        match create_private_stage(directory, &child) {
            Ok(()) => {
                let path = directory_path.join(&child);
                #[cfg(target_os = "macos")]
                if let Err(error) = acl::clear_stage_acl(&path) {
                    let _ = rustix::fs::unlinkat(directory, &child, rustix::fs::AtFlags::REMOVEDIR);
                    return Err(error);
                }
                return Ok((child, path));
            }
            Err(rustix::io::Errno::EXIST) => {}
            Err(error) => return Err(format!("cannot create private export {kind}: {error}")),
        }
    }
    Err(format!("cannot allocate a unique private export {kind}"))
}

/// Whether the entry `name` of `directory` is the root of a mount, which `rename(2)` refuses to
/// move (`EBUSY` or `EXDEV`): a different device than the directory's, or, on Linux, a bind
/// mount of the same one.
#[cfg(unix)]
fn is_mount_root(directory: BorrowedFd<'_>, name: &OsStr) -> Result<bool, String> {
    let target_device = stat_at(directory, name)
        .map_err(|error| format!("cannot inspect the export target: {error}"))?
        .st_dev;
    let parent_device = rustix::fs::fstat(directory)
        .map_err(|error| format!("cannot inspect the export parent: {error}"))?
        .st_dev;
    if target_device != parent_device {
        return Ok(true);
    }
    #[cfg(target_os = "linux")]
    {
        use rustix::fs::{statx, AtFlags, StatxAttributes, StatxFlags};
        if let Ok(status) = statx(
            directory,
            name,
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

/// Moves the entry `name` from one held directory to another (same name on both sides).
#[cfg(unix)]
type MoveEntry<'a> = &'a dyn Fn(BorrowedFd<'_>, &OsStr, BorrowedFd<'_>) -> std::io::Result<()>;

#[cfg(unix)]
fn rename_entry(from: BorrowedFd<'_>, name: &OsStr, to: BorrowedFd<'_>) -> std::io::Result<()> {
    rustix::fs::renameat(from, name, to, name).map_err(std::io::Error::from)
}

/// Opens a directory below a held one for reading, without following a link.
#[cfg(unix)]
fn open_listable(directory: BorrowedFd<'_>, name: &OsStr) -> rustix::io::Result<OwnedFd> {
    rustix::fs::openat(
        directory,
        name,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
}

/// Replaces what the target (a mount point, held) holds with what its stage (a directory inside
/// it) holds, by renames on the target's own volume, relative to held descriptors.
///
/// The old manifest leaves first and the new one arrives last, so a directory caught in the
/// middle never holds a manifest beside a partial tree. A failure moves back what was moved;
/// when that fails too, the message names where the old export is.
#[cfg(unix)]
fn publish_into_mount_point(
    target: BorrowedFd<'_>,
    target_path: &Path,
    stage_name: &OsStr,
) -> Result<(), String> {
    publish_into_mount_point_with(target, target_path, stage_name, &rename_entry)
}

/// [`publish_into_mount_point`] with the move of each entry passed in (the tests interrupt it).
#[cfg(unix)]
fn publish_into_mount_point_with(
    target: BorrowedFd<'_>,
    target_path: &Path,
    stage_name: &OsStr,
    rename: MoveEntry<'_>,
) -> Result<(), String> {
    let cannot_open = |name: &OsStr, error: rustix::io::Errno| {
        format!("cannot open {}: {error}", target_path.join(name).display())
    };
    let (displaced_name, displaced_path) = create_private_child(target, target_path, "displaced")?;
    let stage =
        open_listable(target, stage_name).map_err(|error| cannot_open(stage_name, error))?;
    let displaced = open_listable(target, &displaced_name)
        .map_err(|error| cannot_open(&displaced_name, error))?;
    let listable = open_listable(target, OsStr::new("."))
        .map_err(|error| cannot_open(OsStr::new("."), error))?;
    let stage_path = target_path.join(stage_name);
    let mut moved_out: Vec<OsString> = Vec::new();
    let current = |name: &OsStr| name != stage_name && name != displaced_name;
    let mut moved_in: Vec<OsString> = Vec::new();
    let result = move_entries(
        (listable.as_fd(), target_path),
        displaced.as_fd(),
        current,
        false,
        rename,
        &mut moved_out,
    )
    .and_then(|()| {
        move_entries(
            (stage.as_fd(), &stage_path),
            target,
            |_| true,
            true,
            rename,
            &mut moved_in,
        )
    });
    if let Err(error) = result {
        return Err(roll_back(
            target,
            stage.as_fd(),
            displaced.as_fd(),
            &displaced_path,
            &moved_in,
            &moved_out,
            rename,
            &error,
        ));
    }
    // The new export is in place; a displaced tree that cannot be removed now is a publication
    // entry, which the next export moves out and removes with the rest.
    let _ = rustix::fs::unlinkat(target, stage_name, rustix::fs::AtFlags::REMOVEDIR);
    let _ = parent::remove_tree_at(target, &displaced_name);
    Ok(())
}

/// Undoes a failed publication into a mount point and words the refusal. The new entries go back
/// to the stage, then the old ones to the target, the old manifest last and only once every
/// other entry is back: a target whose rollback fails part-way holds no manifest, so an import
/// refuses it rather than reading a mixture of the two exports.
#[cfg(unix)]
#[allow(clippy::too_many_arguments)]
fn roll_back(
    target: BorrowedFd<'_>,
    stage: BorrowedFd<'_>,
    displaced: BorrowedFd<'_>,
    displaced_path: &Path,
    moved_in: &[OsString],
    moved_out: &[OsString],
    rename: MoveEntry<'_>,
    error: &str,
) -> String {
    let mut restored = true;
    for name in moved_in.iter().rev() {
        restored &= rename(target, name, stage).is_ok();
    }
    let (manifest, data): (Vec<_>, Vec<_>) =
        moved_out.iter().partition(|name| *name == MANIFEST_NAME);
    for name in data {
        restored &= rename(displaced, name, target).is_ok();
    }
    if restored {
        for name in manifest {
            restored &= rename(displaced, name, target).is_ok();
        }
    }
    if restored {
        if let Some(name) = displaced_path.file_name() {
            let _ = rustix::fs::unlinkat(target, name, rustix::fs::AtFlags::REMOVEDIR);
        }
        return format!(
            "publication into the mount point failed ({error}); the prior export was restored"
        );
    }
    format!(
        "publication into the mount point failed ({error}), and the prior export could not be restored; it is in {}, and the export directory holds no {MANIFEST_NAME}",
        displaced_path.display()
    )
}

/// Moves every entry of `from` (held for reading; its path names it in messages) that `keep`
/// selects into `to`, the manifest last when `manifest_last` (entering the target) and first
/// otherwise (leaving it). Each moved name is pushed onto `moved`.
#[cfg(unix)]
fn move_entries(
    from: (BorrowedFd<'_>, &Path),
    to: BorrowedFd<'_>,
    keep: impl Fn(&OsStr) -> bool,
    manifest_last: bool,
    rename: MoveEntry<'_>,
    moved: &mut Vec<OsString>,
) -> Result<(), String> {
    use std::os::unix::ffi::OsStrExt as _;
    let (from, from_path) = from;
    let cannot_read =
        |error: rustix::io::Errno| format!("cannot read {}: {error}", from_path.display());
    let mut names = Vec::new();
    for entry in rustix::fs::Dir::read_from(from).map_err(cannot_read)? {
        let entry = entry.map_err(cannot_read)?;
        let name = entry.file_name().to_bytes();
        if name != b"." && name != b".." {
            names.push(OsStr::from_bytes(name).to_owned());
        }
    }
    names.retain(|name| keep(name));
    names.sort_by_key(|name| (name == MANIFEST_NAME) == manifest_last);
    for name in names {
        rename(from, &name, to)
            .map_err(|error| format!("cannot move {}: {error}", from_path.join(&name).display()))?;
        moved.push(name);
    }
    Ok(())
}

#[cfg(unix)]
fn create_private_stage(directory: BorrowedFd<'_>, name: &OsStr) -> rustix::io::Result<()> {
    rustix::fs::mkdirat(directory, name, rustix::fs::Mode::from_raw_mode(0o700))
}

#[cfg(unix)]
fn publish_stage(
    parent: BorrowedFd<'_>,
    stage: &OsStr,
    target: &OsStr,
    expected: &TargetIdentity,
) -> Result<(), String> {
    if target_identity_at(parent, target)? != *expected {
        return Err(
            "the export target changed after it was checked; it was left unchanged".to_owned(),
        );
    }
    atomic_publish(parent, stage, target, expected.present)?;
    if expected.present {
        verify_displaced_target_or_rollback(parent, stage, target, expected)?;
    }
    Ok(())
}

#[cfg(unix)]
fn verify_displaced_target_or_rollback(
    parent: BorrowedFd<'_>,
    stage: &OsStr,
    target: &OsStr,
    expected: &TargetIdentity,
) -> Result<(), String> {
    let displaced = target_identity_at(parent, stage).map(|identity| identity == *expected);
    if displaced.as_ref().is_ok_and(|matches| *matches) {
        return Ok(());
    }
    let detail = displaced
        .err()
        .unwrap_or_else(|| "the displaced target has a different identity".to_owned());
    match atomic_publish(parent, stage, target, true) {
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
    parent: BorrowedFd<'_>,
    stage: &OsStr,
    target: &OsStr,
    target_present: bool,
) -> Result<(), String> {
    rename_for(target_present, |flags| {
        rustix::fs::renameat_with(parent, stage, parent, target, flags)
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
    } else if error == rustix::io::Errno::PERM {
        format!(
            "atomic export publication is unavailable or failed: {error}; in a directory with the sticky bit, such as /tmp, only the owner of an entry can replace it, so remove the existing export directory or choose a directory of your own"
        )
    } else {
        format!("atomic export publication is unavailable or failed: {error}")
    }
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod tests {
    use super::{
        atomic_publish, publication_error, rename_for, target_identity_at,
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

    /// A rename the sticky bit refuses (another user's entry in /tmp) names the sticky
    /// directory and what to do; other failures keep the plain message.
    #[test]
    fn a_rename_the_sticky_bit_refuses_names_the_remedy() {
        let sticky = publication_error(rustix::io::Errno::PERM);
        assert!(sticky.contains("sticky bit"), "{sticky}");
        assert!(sticky.contains("a directory of your own"), "{sticky}");
        let other = publication_error(rustix::io::Errno::IO);
        assert!(!other.contains("sticky"), "{other}");
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
        use std::os::fd::AsFd as _;
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
        let held = rustix::fs::openat(
            rustix::fs::CWD,
            &root,
            crate::parent::search_flags(),
            rustix::fs::Mode::empty(),
        )
        .unwrap();
        let expected = target_identity_at(held.as_fd(), "target".as_ref()).unwrap();
        std::fs::rename(&target, &displaced).unwrap();
        std::fs::create_dir(&target).unwrap();
        std::fs::write(target.join("attacker"), b"unchanged").unwrap();
        std::fs::create_dir(&stage).unwrap();
        std::fs::write(stage.join("new"), b"new").unwrap();

        atomic_publish(held.as_fd(), "stage".as_ref(), "target".as_ref(), true).unwrap();
        let error = verify_displaced_target_or_rollback(
            held.as_fd(),
            "stage".as_ref(),
            "target".as_ref(),
            &expected,
        )
        .unwrap_err();

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
    parent: BorrowedFd<'_>,
    stage: &OsStr,
    target: &OsStr,
    target_present: bool,
) -> Result<(), String> {
    if target_present {
        return Err(
            "atomic directory replacement is unavailable on this platform; the existing export was left unchanged"
                .to_owned(),
        );
    }
    rustix::fs::renameat(parent, stage, parent, target)
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
    #[test]
    fn preflight_mount_root_needs_writable_target_not_writable_parent() {
        use std::os::unix::fs::PermissionsExt as _;
        if rustix::process::geteuid().as_raw() == 0 {
            return;
        }
        let root = super::parent::trusted_temp::TrustedTempDir::new("preflight-mount-access");
        let target = root.join("mounted");
        std::fs::create_dir(&target).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o500)).unwrap();
        let result = super::preflight_with(&target, &|_, _| Ok(true));
        let sibling = super::preflight_with(&target, &|_, _| Ok(false));
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(result.is_ok(), "{result:?}");
        assert!(sibling.is_err());
        assert_eq!(std::fs::read_dir(&target).unwrap().count(), 0);
    }

    use super::{is_mount_root, is_publication_entry, move_entries, PublicationStage};
    use std::ffi::OsStr;
    use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};
    use std::path::{Path, PathBuf};

    /// A directory held for reading, as publication holds the ones it moves entries between.
    fn held(path: &Path) -> OwnedFd {
        rustix::fs::openat(
            rustix::fs::CWD,
            path,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .unwrap()
    }

    fn plain(from: BorrowedFd<'_>, name: &OsStr, to: BorrowedFd<'_>) -> std::io::Result<()> {
        rustix::fs::renameat(from, name, to, name).map_err(std::io::Error::from)
    }

    /// A private directory under a trusted per-user base: staging refuses an ancestor that other
    /// users can write, such as Linux's `/tmp`. Each test removes the directory itself.
    fn scratch(name: &str) -> PathBuf {
        let root =
            crate::parent::trusted_temp::TrustedTempDir::new(&format!("publication-mount-{name}"));
        let path = std::fs::canonicalize(root.path()).unwrap();
        std::mem::forget(root);
        path
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
        let (from_fd, to_fd) = (held(&from), held(&to));
        let mut moved = Vec::new();
        move_entries(
            (from_fd.as_fd(), &from),
            to_fd.as_fd(),
            |_| true,
            false,
            &plain,
            &mut moved,
        )
        .unwrap();
        assert_eq!(moved[0], "firebase-export-metadata.json");
        let mut moved = Vec::new();
        move_entries(
            (to_fd.as_fd(), &to),
            from_fd.as_fd(),
            |_| true,
            true,
            &plain,
            &mut moved,
        )
        .unwrap();
        assert_eq!(moved[2], "firebase-export-metadata.json");
        let mut moved = Vec::new();
        move_entries(
            (from_fd.as_fd(), &from),
            to_fd.as_fd(),
            |name| name != "a",
            true,
            &plain,
            &mut moved,
        )
        .unwrap();
        assert_eq!(moved, ["z", "firebase-export-metadata.json"]);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_directory_on_another_device_is_a_mount_root_and_an_ordinary_one_is_not() {
        let root = scratch("detect");
        std::fs::create_dir(root.join("plain")).unwrap();
        assert!(!is_mount_root(held(&root).as_fd(), "plain".as_ref()).unwrap());
        #[cfg(target_os = "macos")]
        assert!(is_mount_root(held(Path::new("/")).as_fd(), "dev".as_ref()).unwrap());
        #[cfg(target_os = "linux")]
        assert!(is_mount_root(held(Path::new("/")).as_fd(), "proc".as_ref()).unwrap());
        let _ = std::fs::remove_dir_all(root);
    }

    /// The renames of one publication: `manifest` and `a` leave (0, 1), `b` and `manifest`
    /// arrive (2, 3); a failure of rename 3 rolls back with `b` back to the stage (4), `a` back
    /// (5) and the old manifest last (6). `failing` names the renames that fail.
    fn publish_failing(name: &str, failing: &[usize]) -> (PathBuf, Result<(), String>) {
        use std::cell::Cell;
        let root = scratch(name);
        let target = root.join("volume");
        std::fs::create_dir(&target).unwrap();
        std::fs::write(target.join("firebase-export-metadata.json"), b"old").unwrap();
        std::fs::write(target.join("a"), b"old").unwrap();
        let target_fd = held(&target);
        let (stage_name, stage) =
            super::create_private_child(target_fd.as_fd(), &target, "stage").unwrap();
        std::fs::write(stage.join("firebase-export-metadata.json"), b"new").unwrap();
        std::fs::write(stage.join("b"), b"new").unwrap();
        let calls = Cell::new(0usize);
        let rename = |from: BorrowedFd<'_>, name: &OsStr, to: BorrowedFd<'_>| {
            let call = calls.get();
            calls.set(call + 1);
            if failing.contains(&call) {
                Err(std::io::Error::other("injected"))
            } else {
                plain(from, name, to)
            }
        };
        let result =
            super::publish_into_mount_point_with(target_fd.as_fd(), &target, &stage_name, &rename);
        (target, result)
    }

    fn visible(dir: &Path) -> Vec<String> {
        names(dir)
            .into_iter()
            .filter(|name| !is_publication_entry(name.as_ref()))
            .collect()
    }

    #[test]
    fn a_failed_publication_whose_rollback_completes_restores_the_prior_export() {
        let (target, result) = publish_failing("rollback-ok", &[3]);
        let error = result.unwrap_err();
        assert!(error.contains("the prior export was restored"), "{error}");
        assert_eq!(visible(&target), ["a", "firebase-export-metadata.json"]);
        assert_eq!(
            std::fs::read(target.join("firebase-export-metadata.json")).unwrap(),
            b"old"
        );
        let _ = std::fs::remove_dir_all(target.parent().unwrap());
    }

    /// When a new entry cannot go back to the stage, or an old one cannot come back, the old
    /// manifest stays out: the target is never an importable mixture.
    #[test]
    fn a_rollback_that_fails_part_way_leaves_no_manifest() {
        for (label, failing) in [
            ("undo-new", [3, 4]),
            ("restore-old", [3, 5]),
            ("manifest", [3, 6]),
        ] {
            let (target, result) = publish_failing(&format!("rollback-{label}"), &failing);
            let error = result.unwrap_err();
            assert!(
                !error.contains("the prior export was restored"),
                "{label}: {error}"
            );
            assert!(error.contains("could not be restored"), "{label}: {error}");
            assert!(
                !visible(&target).contains(&"firebase-export-metadata.json".to_owned()),
                "{label}: {:?}",
                visible(&target)
            );
            let _ = std::fs::remove_dir_all(target.parent().unwrap());
        }
    }

    /// A stage name already taken is skipped for the next one; any other error is reported.
    /// A directory opened to list and move entries is a directory, never a link or a file, and
    /// its descriptor does not leak into a child process.
    #[test]
    fn a_listable_descriptor_opens_a_directory_only_and_closes_on_exec() {
        use std::os::unix::fs::symlink;
        let root = scratch("listable");
        std::fs::create_dir(root.join("dir")).unwrap();
        std::fs::write(root.join("file"), b"").unwrap();
        symlink(root.join("dir"), root.join("link")).unwrap();
        let dir = held(&root);
        let opened = super::open_listable(dir.as_fd(), "dir".as_ref()).unwrap();
        assert!(rustix::io::fcntl_getfd(&opened)
            .unwrap()
            .contains(rustix::io::FdFlags::CLOEXEC));
        assert!(
            rustix::fs::Dir::read_from(&opened).is_ok(),
            "it can be listed"
        );
        for name in ["link", "file"] {
            assert!(
                super::open_listable(dir.as_fd(), name.as_ref()).is_err(),
                "{name}"
            );
        }
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_taken_stage_name_is_skipped_and_another_error_is_reported() {
        use std::sync::atomic::Ordering;
        let root = scratch("collision");
        let next = super::NEXT_STAGE_ID.load(Ordering::Relaxed);
        for id in next..next + 8 {
            std::fs::create_dir(root.join(format!(".fireemu-stage-{}-{id}", std::process::id())))
                .unwrap();
        }
        let (_, made) = super::create_private_child(held(&root).as_fd(), &root, "stage").unwrap();
        assert!(made.is_dir());
        // A directory removed while held takes no entry.
        std::fs::create_dir(root.join("gone")).unwrap();
        let gone = held(&root.join("gone"));
        std::fs::remove_dir(root.join("gone")).unwrap();
        let error =
            super::create_private_child(gone.as_fd(), &root.join("gone"), "stage").unwrap_err();
        assert!(
            error.starts_with("cannot create private export stage"),
            "{error}"
        );
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
        use super::{held, plain};
        use proptest::prelude::*;
        use std::cell::Cell;
        use std::collections::BTreeMap;
        use std::ffi::OsStr;
        use std::os::fd::{AsFd as _, BorrowedFd};
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
            /// Rename number `n` fails, and so does the later rename `n + 1 + m`, one the
            /// rollback makes.
            FailsTwice(usize, usize),
        }

        fn interruption() -> impl Strategy<Value = Interruption> {
            prop_oneof![
                (0usize..12).prop_map(Interruption::Killed),
                (0usize..12).prop_map(Interruption::Fails),
                (0usize..12, 0usize..12).prop_map(|(n, m)| Interruption::FailsTwice(n, m)),
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
                prop_assert!(old.contains_key(MANIFEST) && new.contains_key(MANIFEST));
                write(&target, &old);
                let target_fd = held(&target);
                let (stage_name, stage) =
                    create_private_child(target_fd.as_fd(), &target, "stage").unwrap();
                write(&stage, &new);

                let calls = Cell::new(0usize);
                let rename = |from: BorrowedFd<'_>, name: &OsStr, to: BorrowedFd<'_>| {
                    let call = calls.get();
                    calls.set(call + 1);
                    match interruption {
                        Interruption::Killed(n) if call == n => panic!("killed"),
                        Interruption::Fails(n) | Interruption::FailsTwice(n, _) if call == n => {
                            Err(std::io::Error::other("injected"))
                        }
                        Interruption::FailsTwice(n, m) if call == n + 1 + m => {
                            Err(std::io::Error::other("injected in the rollback"))
                        }
                        _ => plain(from, name, to),
                    }
                };
                let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    publish_into_mount_point_with(target_fd.as_fd(), &target, &stage_name, &rename)
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
                    (Interruption::FailsTwice(n, _), Ok(Err(error))) => {
                        prop_assert!(n < renames);
                        // Restored or not, a target with a manifest is one whole export.
                        if after.contains_key(MANIFEST) {
                            prop_assert!(after == old || after == new, "{:?}", after);
                        }
                        if error.contains("the prior export was restored") {
                            prop_assert_eq!(&after, &old);
                        } else {
                            prop_assert!(!after.contains_key(MANIFEST), "{}", error);
                        }
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
