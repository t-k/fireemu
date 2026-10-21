//! The parent directory of an export: walked once from `/` through descriptors, judged as it is
//! held, created only inside what was judged.
//!
//! The walk opens `/` and every directory below it with `openat(O_DIRECTORY | O_NOFOLLOW)`
//! relative to the descriptor of the directory above, and judges each one while it holds that
//! descriptor (volume ownership, owner, mode, ACL). A name is looked at with
//! `fstatat(AT_SYMLINK_NOFOLLOW)` first: a directory is entered only through the `O_NOFOLLOW`
//! open, so a link swapped in after the look makes the open fail instead of being followed, and a
//! link is read with `readlinkat`, which fails when a directory was swapped in. Nothing is resolved
//! a second time: the descriptor of the deepest existing directory is what creation, the stage and
//! publication use. A missing component is made with `mkdirat` relative to it and restricted with
//! `fchmod` on a descriptor opened without following links, then judged like the rest.
//!
//! Threat model, stated plainly. This protects against other local users and against volumes that
//! ignore ownership: every directory the walk enters (those it leaves again through a link
//! included) must be on a volume that enforces ownership, owned by root or the exporting user,
//! not writable by anyone else (except a root-owned directory with the sticky bit, such as
//! `/tmp`, where other users can add entries but cannot rename or remove the ones the export
//! makes; they can only take a name first, which refuses the export), and free of ACL entries for
//! anyone else. A symlink on the path (anywhere, and at every hop of a chain) is followed only when
//! root owns it, or the user owns it and no one else can write the directory holding it (which the
//! walk has judged); in `/tmp` a link anyone could have made is never followed. Below a directory
//! others can write, an export directory that already exists must be the user's (or root's) and
//! private, since another user could have made it first. It does not defend against the exporting
//! user's own processes, or root, changing the namespace concurrently. The export directory is as
//! safe as the account that runs the export.
//!
//! Needs: the process umask must leave the owner's read permission on new directories (a umask
//! such as 0477 does not), since a component just made is reopened to be restricted; that case is
//! refused with a message that says so. No directory of the walk needs read permission.

use std::ffi::{OsStr, OsString};
use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Path, PathBuf};

use rustix::fs::{AtFlags, FileType, Mode, OFlags};

/// Runs on every directory of the export's namespace, with the descriptor the walk holds for it,
/// before its owner and mode are trusted. On macOS it refuses a volume that ignores ownership;
/// elsewhere it accepts.
pub(crate) type VolumeCheck<'a> = &'a dyn Fn(&Path, BorrowedFd<'_>) -> Result<(), String>;

#[cfg(target_os = "macos")]
pub(crate) fn system_volume_check(path: &Path, directory: BorrowedFd<'_>) -> Result<(), String> {
    crate::volume::require_ownership(path, &|_| crate::volume::mount_of_fd(directory))
}

#[cfg(not(target_os = "macos"))]
#[allow(clippy::unnecessary_wraps)]
pub(crate) fn system_volume_check(_path: &Path, _directory: BorrowedFd<'_>) -> Result<(), String> {
    Ok(())
}

/// The flags of a descriptor that names a directory without reading it: Linux `O_PATH`, macOS
/// `O_SEARCH` (`O_EXEC | O_DIRECTORY`), so a directory the user may search but not list is
/// walked as before. Links are never followed.
pub(crate) fn search_flags() -> OFlags {
    #[cfg(target_os = "linux")]
    let access = OFlags::PATH;
    #[cfg(target_os = "macos")]
    let access = OFlags::from_bits_retain(0x4000_0000);
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let access = OFlags::RDONLY;
    access | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC
}

/// A directory of the export's namespace, held: its descriptor and the physical path the walk
/// built for it (for messages and for the ACL, which has no descriptor interface).
#[derive(Debug)]
pub(crate) struct Anchor {
    pub(crate) fd: OwnedFd,
    pub(crate) path: PathBuf,
    /// Whether a directory of its chain can be written by others (only a root-owned sticky one
    /// passes [`ancestor_error`]).
    pub(crate) below_shared: bool,
}

/// What a walk found: the deepest existing directory, held, and the names below it that do not
/// exist yet.
#[derive(Debug)]
pub(crate) struct Walked {
    pub(crate) anchor: Anchor,
    pub(crate) missing: Vec<OsString>,
}

/// The parent of the export, judged, created where it was missing, held, with the volume check
/// passed in and a hook that runs after each component was made and before it is restricted (the
/// tests swap the component there).
#[cfg(test)]
pub(crate) fn prepare_and_validate_parent_with(
    parent: &Path,
    volume_check: VolumeCheck<'_>,
    between_mkdir_and_chmod: &dyn Fn(&Path),
) -> Result<PathBuf, String> {
    let walked = inspect_parent(parent, volume_check)?;
    complete(walked, volume_check, between_mkdir_and_chmod).map(|anchor| anchor.path)
}

/// Makes the missing components of a walk below its anchor, or returns the anchor when none is
/// missing.
pub(crate) fn complete(
    walked: Walked,
    volume_check: VolumeCheck<'_>,
    between_mkdir_and_chmod: &dyn Fn(&Path),
) -> Result<Anchor, String> {
    if walked.missing.is_empty() {
        return Ok(walked.anchor);
    }
    let (fd, path) = create_missing(
        walked.anchor.fd.as_fd(),
        &walked.anchor.path,
        &walked.missing,
        between_mkdir_and_chmod,
        rustix::process::geteuid().as_raw(),
        volume_check,
    )?;
    Ok(Anchor {
        fd,
        path,
        below_shared: walked.anchor.below_shared,
    })
}

/// Walks and judges the existing namespace without creating missing components.
pub(crate) fn inspect_parent(
    parent: &Path,
    volume_check: VolumeCheck<'_>,
) -> Result<Walked, String> {
    walk(parent, volume_check)
}

/// One component of a path being walked; `Root` restarts at `/` (an absolute link target).
enum Step {
    Root,
    Parent,
    Name(OsString),
}

/// The components of `path` as steps, the first one last (a stack).
fn steps(path: &Path) -> Vec<Step> {
    use std::path::Component;
    let mut steps: Vec<Step> = path
        .components()
        .filter_map(|component| match component {
            Component::RootDir => Some(Step::Root),
            Component::ParentDir => Some(Step::Parent),
            Component::Normal(name) => Some(Step::Name(name.to_owned())),
            Component::CurDir | Component::Prefix(_) => None,
        })
        .collect();
    steps.reverse();
    steps
}

/// The most symlinks one walk expands (the kernel's own bound is of the same order).
const MAX_LINK_HOPS: usize = 40;

/// The mode bits of a `stat` as a `u32` (`mode_t` is 16 bits on macOS and 32 on Linux).
#[allow(clippy::useless_conversion)]
pub(crate) fn mode_bits(stat: &rustix::fs::Stat) -> u32 {
    u32::from(stat.st_mode)
}

/// Judges a directory the walk holds, through its descriptor: the volume first (on a volume that
/// ignores ownership the owner and mode mean nothing), then owner and mode, then (macOS) the ACL,
/// read by `path` between two checks that `path` still names this descriptor's directory.
/// Returns its mode.
pub(crate) fn judge(
    directory: BorrowedFd<'_>,
    path: &Path,
    volume_check: VolumeCheck<'_>,
    effective_uid: u32,
) -> Result<u32, String> {
    let stat = rustix::fs::fstat(directory).map_err(|error| {
        format!(
            "cannot inspect export namespace ancestor {}: {error}",
            path.display()
        )
    })?;
    volume_check(path, directory)?;
    let mode = mode_bits(&stat);
    if let Some(error) = ancestor_error(path, stat.st_uid, mode, effective_uid) {
        return Err(error);
    }
    #[cfg(target_os = "macos")]
    {
        same_directory(path, &stat)?;
        crate::acl::reject_unsafe_acl(
            path,
            &crate::acl::Trusted::of_uids(stat.st_uid, effective_uid, &crate::acl::user_name),
        )?;
        same_directory(path, &stat)?;
    }
    Ok(mode)
}

/// Judges again a directory a preflight walked and holds, through its descriptor only: the
/// volume, owner and mode. The ACL was judged when the walk held it; only its owner (the user or
/// root) can change it, and its path may name something else by now (the user may have renamed
/// it), so it is not read by path again.
pub(crate) fn judge_held(
    directory: BorrowedFd<'_>,
    path: &Path,
    volume_check: VolumeCheck<'_>,
    effective_uid: u32,
) -> Result<(), String> {
    let stat = rustix::fs::fstat(directory).map_err(|error| {
        format!(
            "cannot inspect export namespace ancestor {}: {error}",
            path.display()
        )
    })?;
    volume_check(path, directory)?;
    match ancestor_error(path, stat.st_uid, mode_bits(&stat), effective_uid) {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

/// Refuses when `path` no longer names the directory `held` describes.
#[cfg(target_os = "macos")]
fn same_directory(path: &Path, held: &rustix::fs::Stat) -> Result<(), String> {
    let now = rustix::fs::lstat(path).map_err(|error| {
        format!(
            "cannot inspect export namespace ancestor {}: {error}",
            path.display()
        )
    })?;
    if (now.st_dev, now.st_ino) == (held.st_dev, held.st_ino) {
        Ok(())
    } else {
        Err(format!(
            "export namespace ancestor {} changed while it was checked; nothing was exported",
            path.display()
        ))
    }
}

/// Walks the absolute path `parent` from `/`, one component at a time, through descriptors:
/// each directory entered is opened with `O_NOFOLLOW` relative to the one above and judged
/// ([`judge`]) while held. Every symlink met, in `parent` or in a link's target, is judged by
/// [`link_error`] against the directory holding it (which the walk holds and has judged), then
/// expanded one hop at a time. A `..` right after a symlink of `parent` is refused; a `..` inside
/// a link's target goes to the physical parent, as the kernel does. A dangling link, an empty link
/// target and a `..` below the existing prefix are refused.
#[allow(clippy::too_many_lines)]
pub(crate) fn walk(parent: &Path, volume_check: VolumeCheck<'_>) -> Result<Walked, String> {
    let parent = std::path::absolute(parent)
        .map_err(|error| format!("cannot resolve the export parent: {error}"))?;
    let effective_uid = rustix::process::geteuid().as_raw();
    let root = rustix::fs::openat(rustix::fs::CWD, "/", search_flags(), Mode::empty())
        .map_err(|error| format!("cannot open export namespace ancestor /: {error}"))?;
    let root_mode = judge(root.as_fd(), Path::new("/"), volume_check, effective_uid)?;
    // The directories held, `/` first, each with its physical path and mode.
    let mut chain: Vec<(OwnedFd, PathBuf, u32)> = vec![(root, PathBuf::from("/"), root_mode)];
    // The steps still to take, the next one last; `true` marks a step of `parent` itself.
    let mut pending: Vec<(Step, bool)> = steps(&parent)
        .into_iter()
        .map(|step| (step, true))
        .collect();
    let mut missing = Vec::new();
    let mut hops = 0;
    let mut after_link = false;
    while let Some((step, own)) = pending.pop() {
        let mut was_link = false;
        match step {
            Step::Root => chain.truncate(1),
            Step::Parent => {
                if !missing.is_empty() {
                    return Err(
                        "cannot create the export parent through `..` or from the root".to_owned(),
                    );
                }
                if own && after_link {
                    return Err(format!(
                        "the export path {} has `..` right after a symlink; name the directory itself",
                        parent.display()
                    ));
                }
                if chain.len() > 1 {
                    chain.pop();
                }
            }
            Step::Name(name) if !missing.is_empty() => missing.push(name),
            Step::Name(name) => {
                let (directory, directory_path, directory_mode) =
                    chain.last().expect("the walk always holds `/`");
                let next = directory_path.join(&name);
                match rustix::fs::statat(directory, &name, AtFlags::SYMLINK_NOFOLLOW) {
                    Err(rustix::io::Errno::NOENT) if own => missing.push(name),
                    Err(rustix::io::Errno::NOENT) => {
                        return Err(format!(
                            "the export path goes through a symlink whose target {} does not exist",
                            next.display()
                        ));
                    }
                    Err(error) => {
                        return Err(format!(
                            "cannot inspect the export parent {}: {error}",
                            next.display()
                        ));
                    }
                    Ok(stat) if FileType::from_raw_mode(stat.st_mode) == FileType::Symlink => {
                        hops += 1;
                        if hops > MAX_LINK_HOPS {
                            return Err(format!(
                                "the export path {} goes through more than {MAX_LINK_HOPS} symlinks",
                                parent.display()
                            ));
                        }
                        if let Some(error) =
                            link_error(&next, stat.st_uid, *directory_mode, effective_uid)
                        {
                            return Err(error);
                        }
                        let target = rustix::fs::readlinkat(directory, &name, Vec::new()).map_err(
                            |error| {
                                format!(
                                    "the symlink {} changed while it was checked: {error}",
                                    next.display()
                                )
                            },
                        )?;
                        if target.as_bytes().is_empty() {
                            return Err(format!(
                                "the export path goes through the symlink {}, whose target is empty and names nothing",
                                next.display()
                            ));
                        }
                        pending.extend(
                            steps(Path::new(OsStr::from_bytes(target.as_bytes())))
                                .into_iter()
                                .map(|step| (step, false)),
                        );
                        was_link = true;
                    }
                    Ok(stat) if FileType::from_raw_mode(stat.st_mode) == FileType::Directory => {
                        let entered =
                            rustix::fs::openat(directory, &name, search_flags(), Mode::empty())
                                .map_err(|error| {
                                    format!(
                                        "export namespace ancestor {} changed while it was checked ({error}); nothing was exported",
                                        next.display()
                                    )
                                })?;
                        let mode = judge(entered.as_fd(), &next, volume_check, effective_uid)?;
                        chain.push((entered, next, mode));
                    }
                    Ok(_) => {
                        return Err(format!(
                            "the export parent {} is not a directory",
                            next.display()
                        ));
                    }
                }
            }
        }
        if own {
            after_link = was_link;
        }
    }
    let below_shared = chain.iter().any(|(_, _, mode)| mode & 0o022 != 0);
    let (fd, path, _) = chain.pop().expect("the walk always holds `/`");
    Ok(Walked {
        anchor: Anchor {
            fd,
            path,
            below_shared,
        },
        missing,
    })
}

/// Makes each missing component below `base` (a judged directory, held), private to the owner,
/// and judges it. Every component is made with `mkdirat` relative to the descriptor above it and
/// restricted through a descriptor opened with `O_NOFOLLOW`; a component that already exists, or
/// that is anything but the directory just made, is refused. On a failure the components made
/// are removed again, relative to their parents' descriptors. Returns the last directory.
fn create_missing(
    base: BorrowedFd<'_>,
    base_path: &Path,
    missing: &[OsString],
    between_mkdir_and_chmod: &dyn Fn(&Path),
    expected_uid: u32,
    volume_check: VolumeCheck<'_>,
) -> Result<(OwnedFd, PathBuf), String> {
    let mut made: Vec<OwnedFd> = Vec::new();
    let mut path = base_path.to_path_buf();
    let result = (|| {
        for name in missing {
            let above = made.last().map_or(base, |fd| fd.as_fd());
            path.push(name);
            rustix::fs::mkdirat(above, name, Mode::from_raw_mode(0o700)).map_err(|error| {
                format!(
                    "cannot create private export parent {}: {error}",
                    path.display()
                )
            })?;
            between_mkdir_and_chmod(&path);
            let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
            let opened = rustix::fs::openat(above, name, flags, Mode::empty()).map_err(|error| {
                if error == rustix::io::Errno::ACCESS {
                    format!(
                        "cannot open the export parent component {} that was just made ({error}): the umask of this process removes the owner's read permission from new directories; use a umask such as 022 and run the export again",
                        path.display()
                    )
                } else {
                    format!(
                        "the export parent component {} is not the directory that was just made: {error}",
                        path.display()
                    )
                }
            });
            let opened = match opened {
                Ok(opened) => opened,
                Err(error) => {
                    // Not ours to hold: removed below by name only if it is still a directory.
                    let _ = rustix::fs::unlinkat(above, name, AtFlags::REMOVEDIR);
                    return Err(error);
                }
            };
            made.push(opened);
            let current = made.last().expect("just pushed").as_fd();
            let stat = rustix::fs::fstat(current).map_err(|error| {
                format!("cannot inspect export parent {}: {error}", path.display())
            })?;
            if stat.st_uid != expected_uid {
                return Err(format!(
                    "the export parent component {} is not owned by the current user",
                    path.display()
                ));
            }
            rustix::fs::fchmod(current, Mode::from_raw_mode(0o700))
                .map_err(|error| format!("cannot restrict export parent permissions: {error}"))?;
            judge(current, &path, volume_check, expected_uid)?;
        }
        Ok(())
    })();
    match result {
        Ok(()) => {
            let last = made.pop().expect("at least one component is missing");
            Ok((last, path))
        }
        Err(error) => {
            // Only directories this call made, deepest first, each relative to the one above.
            for (depth, name) in missing.iter().enumerate().take(made.len()).rev() {
                let above = if depth == 0 {
                    base
                } else {
                    made[depth - 1].as_fd()
                };
                let _ = rustix::fs::unlinkat(above, name, AtFlags::REMOVEDIR);
            }
            Err(error)
        }
    }
}

/// Removes the directory `name` in `directory` and everything below it, relative to
/// descriptors opened without following links, so a link inside it is removed, never followed.
pub(crate) fn remove_tree_at(directory: BorrowedFd<'_>, name: &OsStr) -> rustix::io::Result<()> {
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let tree = rustix::fs::openat(directory, name, flags, Mode::empty())?;
    let mut names = Vec::new();
    for entry in rustix::fs::Dir::read_from(&tree)? {
        let entry = entry?;
        let entry_name = entry.file_name().to_bytes();
        if entry_name != b"." && entry_name != b".." {
            names.push(OsStr::from_bytes(entry_name).to_owned());
        }
    }
    for entry in names {
        let stat = rustix::fs::statat(&tree, &entry, AtFlags::SYMLINK_NOFOLLOW)?;
        if FileType::from_raw_mode(stat.st_mode) == FileType::Directory {
            remove_tree_at(tree.as_fd(), &entry)?;
        } else {
            rustix::fs::unlinkat(&tree, &entry, AtFlags::empty())?;
        }
    }
    rustix::fs::unlinkat(directory, name, AtFlags::REMOVEDIR)
}

/// Why an ancestor of the export cannot be trusted, from its owner and mode: it must be owned by
/// root or the exporting user and not writable by anyone else, except a directory root owns
/// with the sticky bit (such as `/tmp`), where other users can add entries but cannot rename or
/// remove the ones the export makes, which is what a swap of the stage or the target needs.
pub(crate) fn ancestor_error(
    path: &Path,
    uid: u32,
    mode: u32,
    effective_uid: u32,
) -> Option<String> {
    if uid != 0 && uid != effective_uid {
        return Some(format!(
            "export namespace ancestor {} is not owned by the current user or root; on a shared machine another user can take a name first (in /tmp too), so choose another name or a directory of your own",
            path.display()
        ));
    }
    let shared = mode & 0o022 != 0;
    let root_sticky = uid == 0 && mode & 0o1000 != 0;
    (shared && !root_sticky).then(|| {
        format!(
            "export namespace ancestor {} is writable by other users, so staged cleanup cannot be made safe; use a directory that only you (or root) can write, or a root-owned directory with the sticky bit such as /tmp",
            path.display()
        )
    })
}

/// Why a symlink on the export path is not followed, from its owner and the mode of the directory
/// holding it (which the walk has entered and judged as an ancestor: volume, owner, mode, ACL).
/// The link must be owned by root, or by the exporting user when no one else can write that
/// directory: a link cannot be changed, only replaced by someone who can write its directory, and
/// in a directory others can write (`/tmp`) anyone can make one, so only root's are followed
/// there.
pub(crate) fn link_error(
    link: &Path,
    link_uid: u32,
    holder_mode: u32,
    effective_uid: u32,
) -> Option<String> {
    let shared = holder_mode & 0o022 != 0;
    let trusted = link_uid == 0 || (link_uid == effective_uid && !shared);
    (!trusted).then(|| {
        let whose = if link_uid == effective_uid {
            "is yours but sits in a directory other users can write, where anyone can make such a link"
        } else {
            "belongs to another user"
        };
        format!(
            "the export path goes through the symlink {}, which {whose}; an export follows a symlink only when root owns it, or when you own it in a directory only you (or root) can write; use the directory it points to, or a directory of your own",
            link.display()
        )
    })
}

/// Why an export directory that already exists is not used, from its owner and mode. Below a
/// directory other users can write (`below_shared`: only a root-owned sticky one, such as
/// `/tmp`, passes [`ancestor_error`]), anyone could have made it first, so it must be the user's
/// (or root's) and not writable by anyone else; elsewhere only the user or root could have
/// made it.
pub(crate) fn target_error(
    target: &Path,
    uid: u32,
    mode: u32,
    below_shared: bool,
    effective_uid: u32,
) -> Option<String> {
    if !below_shared {
        return None;
    }
    if uid != 0 && uid != effective_uid {
        return Some(format!(
            "the export directory {} belongs to another user, so an export neither reads nor replaces it: in a directory other users can write, such as /tmp, another user can take a name first; remove or rename it, or choose a directory of your own",
            target.display()
        ));
    }
    (mode & 0o022 != 0).then(|| {
        format!(
            "the export directory {} is writable by other users in a directory other users can write, such as /tmp; make it private (chmod 700) or choose a directory of your own",
            target.display()
        )
    })
}

#[cfg(test)]
#[allow(dead_code)]
#[path = "../../../tests/support/trusted_temp.rs"]
pub(crate) mod trusted_temp;

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::os::unix::fs::{symlink, MetadataExt as _, PermissionsExt as _};

    use super::*;

    use super::trusted_temp::TrustedTempDir;

    #[allow(clippy::unnecessary_wraps)]
    fn accept(_: &Path, _: BorrowedFd<'_>) -> Result<(), String> {
        Ok(())
    }

    /// A walk's physical path and missing names.
    fn walk_parts(
        path: &Path,
        volume_check: VolumeCheck<'_>,
    ) -> Result<(PathBuf, Vec<OsString>), String> {
        walk(path, volume_check).map(|walked| (walked.anchor.path, walked.missing))
    }

    /// The physical path of an existing directory, walked and judged.
    fn trusted_ancestors(path: &Path, volume_check: VolumeCheck<'_>) -> Result<PathBuf, String> {
        let walked = walk(path, volume_check)?;
        assert!(walked.missing.is_empty(), "{path:?} exists");
        Ok(walked.anchor.path)
    }

    fn mode_of(path: &Path) -> u32 {
        std::fs::metadata(path).unwrap().mode() & 0o7777
    }

    #[test]
    fn every_directory_the_walk_enters_is_judged_root_first_and_nothing_else() {
        let root = TrustedTempDir::new("parent-ancestors");
        std::fs::create_dir_all(root.join("a/b")).unwrap();
        std::fs::create_dir(root.join("c")).unwrap();
        // The route has a `..` and a symlinked component; `c` is entered and left again
        // through the link, and is judged like every other directory entered.
        symlink(root.join("a"), root.join("c/link")).unwrap();
        let route = root.join("c/link/b/../b");
        let seen = RefCell::new(Vec::new());
        let canonical = trusted_ancestors(&route, &|path: &Path, _: BorrowedFd<'_>| {
            seen.borrow_mut().push(path.to_path_buf());
            Ok(())
        })
        .unwrap();
        let base = std::fs::canonicalize(root.path()).unwrap();
        assert_eq!(canonical, base.join("a/b"));
        let seen = seen.into_inner();
        assert_eq!(seen.first().unwrap(), Path::new("/"));
        assert_eq!(seen.last().unwrap(), &base.join("a/b"));
        assert!(seen.contains(&base.join("c")), "{seen:?}");
        assert!(seen.contains(&base.join("a")), "{seen:?}");
        // Only directories: never the link itself.
        assert!(!seen.contains(&base.join("c/link")), "{seen:?}");
    }

    #[test]
    fn a_refusal_at_any_ancestor_refuses_the_parent() {
        let root = TrustedTempDir::new("parent-refuse-each");
        std::fs::create_dir_all(root.join("a/b")).unwrap();
        let canonical = std::fs::canonicalize(root.join("a/b")).unwrap();
        for refused in canonical.ancestors() {
            let error = trusted_ancestors(&canonical, &|path: &Path, _: BorrowedFd<'_>| {
                if path == refused {
                    Err(format!("refused {}", path.display()))
                } else {
                    Ok(())
                }
            })
            .unwrap_err();
            assert_eq!(error, format!("refused {}", refused.display()));
        }
    }

    #[test]
    fn the_volume_is_checked_before_the_owner_and_the_mode() {
        let root = TrustedTempDir::new("parent-volume-first");
        let writable = root.join("open");
        std::fs::create_dir(&writable).unwrap();
        std::fs::set_permissions(&writable, std::fs::Permissions::from_mode(0o777)).unwrap();
        let error = trusted_ancestors(&writable, &|path: &Path, _: BorrowedFd<'_>| {
            if path.ends_with("open") {
                Err("volume refused".to_owned())
            } else {
                Ok(())
            }
        })
        .unwrap_err();
        assert_eq!(error, "volume refused");
    }

    #[test]
    fn a_missing_parent_is_not_created_when_an_existing_ancestor_is_refused() {
        let root = TrustedTempDir::new("parent-nothing-created");
        let existing = std::fs::canonicalize(root.path()).unwrap();
        let made_any = RefCell::new(false);
        let error = prepare_and_validate_parent_with(
            &existing.join("x/y"),
            &|path: &Path, _: BorrowedFd<'_>| {
                if path == existing {
                    Err("volume refused".to_owned())
                } else {
                    Ok(())
                }
            },
            &|_| *made_any.borrow_mut() = true,
        )
        .unwrap_err();
        assert_eq!(error, "volume refused");
        assert!(!*made_any.borrow(), "no directory was even attempted");
        assert!(!existing.join("x").exists(), "nothing was created");
    }

    #[test]
    fn a_missing_parent_is_created_private_and_nested() {
        let root = TrustedTempDir::new("parent-create");
        let existing = std::fs::canonicalize(root.path()).unwrap();
        let made =
            prepare_and_validate_parent_with(&existing.join("x/y/z"), &accept, &|_| {}).unwrap();
        assert_eq!(made, existing.join("x/y/z"));
        for directory in ["x", "x/y", "x/y/z"] {
            assert_eq!(mode_of(&existing.join(directory)), 0o700, "{directory}");
        }
    }

    #[test]
    fn a_restrictive_umask_does_not_leave_the_new_directories_unusable() {
        // mkdirat's mode is reduced by the umask, so the fchmod is what makes the mode exact.
        let root = TrustedTempDir::new("parent-umask");
        let existing = std::fs::canonicalize(root.path()).unwrap();
        let before = rustix::process::umask(Mode::from_raw_mode(0o277));
        let made = prepare_and_validate_parent_with(&existing.join("x/y"), &accept, &|_| {});
        rustix::process::umask(before);
        // x is 0500 for the whole mkdirat..fchmod window, but the chmod makes it 0700 again.
        let made = made.unwrap();
        assert_eq!(made, existing.join("x/y"));
        assert_eq!(mode_of(&existing.join("x")), 0o700);
        assert_eq!(mode_of(&existing.join("x/y")), 0o700);
    }

    #[test]
    fn the_new_directories_are_checked_again_and_removed_when_they_fail() {
        let root = TrustedTempDir::new("parent-recheck");
        let existing = std::fs::canonicalize(root.path()).unwrap();
        let error = prepare_and_validate_parent_with(
            &existing.join("x/y"),
            &|path: &Path, _: BorrowedFd<'_>| {
                if path.ends_with("x/y") {
                    Err("new directory refused".to_owned())
                } else {
                    Ok(())
                }
            },
            &|_| {},
        )
        .unwrap_err();
        assert_eq!(error, "new directory refused");
        assert!(
            !existing.join("x").exists(),
            "the directories made were removed"
        );
    }

    #[test]
    fn a_component_swapped_for_a_symlink_before_the_restriction_is_refused_and_never_chmodded() {
        let root = TrustedTempDir::new("parent-swap");
        let existing = std::fs::canonicalize(root.path()).unwrap();
        let victim = existing.join("victim");
        std::fs::create_dir(&victim).unwrap();
        std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o755)).unwrap();
        let swapped = RefCell::new(false);
        let error = prepare_and_validate_parent_with(&existing.join("x/y"), &accept, &|made| {
            // Between the mkdir and the chmod: the directory just made is replaced by a link.
            if made.ends_with("x") && !*swapped.borrow() {
                *swapped.borrow_mut() = true;
                std::fs::remove_dir(made).unwrap();
                symlink(&victim, made).unwrap();
            }
        })
        .unwrap_err();
        assert!(*swapped.borrow(), "the hook ran");
        assert!(
            error.contains("not the directory that was just made"),
            "{error}"
        );
        assert_eq!(mode_of(&victim), 0o755, "the link target was not chmodded");
        assert!(
            !victim.join("y").exists(),
            "nothing was created through the link"
        );
    }

    #[test]
    fn a_component_swapped_for_a_file_before_the_restriction_is_refused() {
        let root = TrustedTempDir::new("parent-swap-file");
        let existing = std::fs::canonicalize(root.path()).unwrap();
        let error = prepare_and_validate_parent_with(&existing.join("x/y"), &accept, &|made| {
            if made.ends_with("x") {
                std::fs::remove_dir(made).unwrap();
                std::fs::write(made, b"not a directory").unwrap();
            }
        })
        .unwrap_err();
        assert!(
            error.contains("not the directory that was just made"),
            "{error}"
        );
        assert_ne!(
            mode_of(&existing.join("x")),
            0o700,
            "the file was not restricted like a directory"
        );
    }

    #[test]
    fn a_canonical_path_that_is_not_a_directory_is_refused() {
        let root = TrustedTempDir::new("parent-not-a-directory");
        let existing = std::fs::canonicalize(root.path()).unwrap();
        std::fs::write(existing.join("file"), b"x").unwrap();
        let error = trusted_ancestors(&existing.join("file"), &accept).unwrap_err();
        assert!(error.contains("is not a directory"), "{error}");
    }

    #[test]
    fn an_existing_parent_that_the_owner_cannot_read_is_accepted() {
        // Write and search only (0300): nothing is made in it through a read-opened descriptor.
        let root = TrustedTempDir::new("parent-0300");
        let existing = std::fs::canonicalize(root.path()).unwrap();
        let parent = existing.join("search-only");
        std::fs::create_dir(&parent).unwrap();
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o300)).unwrap();
        let made = prepare_and_validate_parent_with(&parent, &accept, &|_| {});
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(made.unwrap(), parent);
    }

    #[test]
    fn a_missing_component_below_a_search_only_parent_is_made() {
        // The walk holds directories by search-only descriptors, so a parent the user may write
        // and search but not list (0300) takes a new component.
        let root = TrustedTempDir::new("parent-0300-missing");
        let existing = std::fs::canonicalize(root.path()).unwrap();
        let parent = existing.join("search-only");
        std::fs::create_dir(&parent).unwrap();
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o300)).unwrap();
        let made = prepare_and_validate_parent_with(&parent.join("x"), &accept, &|_| {});
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(made.unwrap(), parent.join("x"));
        assert_eq!(mode_of(&parent.join("x")), 0o700);
    }

    #[test]
    fn a_umask_that_removes_the_owners_read_permission_is_refused_with_the_reason() {
        if rustix::process::geteuid().is_root() {
            eprintln!("SKIPPED: root reads any directory, so the refusal cannot be observed");
            return;
        }
        let root = TrustedTempDir::new("parent-umask-0477");
        let existing = std::fs::canonicalize(root.path()).unwrap();
        let before = rustix::process::umask(Mode::from_raw_mode(0o477));
        let error = prepare_and_validate_parent_with(&existing.join("x/y"), &accept, &|_| {});
        rustix::process::umask(before);
        let error = error.unwrap_err();
        assert!(error.contains("umask"), "{error}");
        assert!(error.contains("022"), "{error}");
        assert!(
            !existing.join("x").exists(),
            "the directory made was removed"
        );
    }

    fn open_search(path: &Path) -> OwnedFd {
        rustix::fs::openat(rustix::fs::CWD, path, search_flags(), Mode::empty()).unwrap()
    }

    #[test]
    fn a_new_directory_owned_by_someone_else_is_refused_and_removed() {
        let root = TrustedTempDir::new("parent-owner");
        let existing = std::fs::canonicalize(root.path()).unwrap();
        let someone_else = rustix::process::geteuid().as_raw() + 1;
        let base = open_search(&existing);
        let error = create_missing(
            base.as_fd(),
            &existing,
            &[OsString::from("x")],
            &|_| {},
            someone_else,
            &accept,
        )
        .unwrap_err();
        assert!(
            error.contains("is not owned by the current user"),
            "{error}"
        );
        assert!(
            !existing.join("x").exists(),
            "the directory made was removed"
        );
    }

    #[test]
    fn a_component_that_already_exists_is_refused_and_kept() {
        let root = TrustedTempDir::new("parent-exists");
        let existing = std::fs::canonicalize(root.path()).unwrap();
        std::fs::create_dir(existing.join("x")).unwrap();
        std::fs::write(existing.join("x/keep"), b"").unwrap();
        let base = open_search(&existing);
        let error = create_missing(
            base.as_fd(),
            &existing,
            &[OsString::from("x")],
            &|_| {},
            rustix::process::geteuid().as_raw(),
            &accept,
        )
        .unwrap_err();
        assert!(
            error.contains("cannot create private export parent"),
            "{error}"
        );
        assert!(existing.join("x/keep").exists(), "what was there is kept");
    }

    #[test]
    fn dot_dot_below_the_existing_prefix_is_refused() {
        let root = TrustedTempDir::new("parent-dotdot");
        let existing = std::fs::canonicalize(root.path()).unwrap();
        let error = prepare_and_validate_parent_with(&existing.join("x/../y"), &accept, &|_| {})
            .unwrap_err();
        assert!(error.contains("`..`"), "{error}");
        assert!(!existing.join("x").exists());
        // Above the prefix a `..` is resolved by the filesystem as before.
        std::fs::create_dir(existing.join("a")).unwrap();
        let made =
            prepare_and_validate_parent_with(&existing.join("a/../a"), &accept, &|_| {}).unwrap();
        assert_eq!(made, existing.join("a"));
    }

    #[test]
    fn the_walk_follows_own_links_hop_by_hop_and_keeps_missing_components() {
        let root = TrustedTempDir::new("walk-own-links");
        let base = std::fs::canonicalize(root.path()).unwrap();
        std::fs::create_dir_all(base.join("real/sub")).unwrap();
        std::fs::create_dir(base.join("other")).unwrap();
        symlink(base.join("real"), base.join("link")).unwrap();
        // A relative target with `..` inside it follows the physical directory, as the kernel.
        symlink("../real", base.join("other/up")).unwrap();
        symlink(base.join("link"), base.join("chain")).unwrap();
        for route in ["link/sub", "other/up/sub", "chain/sub", "./link/./sub"] {
            let (existing, missing) = walk_parts(&base.join(route).join("x/y"), &accept).unwrap();
            assert_eq!(existing, base.join("real/sub"), "{route}");
            assert_eq!(
                missing,
                [OsString::from("x"), OsString::from("y")],
                "{route}"
            );
        }
        // The walk's result has no link left in it.
        let (existing, _) = walk_parts(&base.join("chain"), &accept).unwrap();
        assert_eq!(existing, std::fs::canonicalize(base.join("real")).unwrap());
    }

    #[test]
    fn the_walk_refuses_dot_dot_after_a_link_a_dangling_link_a_loop_and_an_untrusted_holder() {
        let root = TrustedTempDir::new("walk-refusals");
        let base = std::fs::canonicalize(root.path()).unwrap();
        std::fs::create_dir(base.join("real")).unwrap();
        symlink(base.join("real"), base.join("link")).unwrap();
        let after = walk(&base.join("link/../real/x"), &accept).unwrap_err();
        assert!(after.contains("`..` right after a symlink"), "{after}");
        // `..` before any link is resolved physically, as before.
        assert_eq!(
            walk_parts(&base.join("real/../real"), &accept).unwrap().0,
            base.join("real")
        );
        symlink(base.join("nowhere"), base.join("dangling")).unwrap();
        let dangling = walk(&base.join("dangling/x"), &accept).unwrap_err();
        assert!(dangling.contains("does not exist"), "{dangling}");
        symlink(base.join("loop"), base.join("loop")).unwrap();
        let looped = walk(&base.join("loop/x"), &accept).unwrap_err();
        assert!(looped.contains("more than 40 symlinks"), "{looped}");
        // The user's own link in a directory others in the group can write.
        let open = base.join("open");
        std::fs::create_dir(&open).unwrap();
        symlink(base.join("real"), open.join("link")).unwrap();
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o770)).unwrap();
        let held = walk(&open.join("link/x"), &accept);
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o700)).unwrap();
        let held = held.unwrap_err();
        assert!(held.contains("writable by other users"), "{held}");
        // A link to a file with more below it.
        std::fs::write(base.join("file"), b"x").unwrap();
        symlink(base.join("file"), base.join("to-file")).unwrap();
        assert!(walk(&base.join("to-file/x"), &accept).is_err());
    }

    #[test]
    fn the_walk_keeps_every_component_after_a_missing_one_and_follows_forty_hops() {
        let root = TrustedTempDir::new("walk-missing-hops");
        let base = std::fs::canonicalize(root.path()).unwrap();
        std::fs::create_dir(base.join("real")).unwrap();
        // `real` exists beside the missing `x`, but below `x` it is a name to make.
        let (existing, missing) = walk_parts(&base.join("x/real"), &accept).unwrap();
        assert_eq!(existing, base);
        assert_eq!(missing, [OsString::from("x"), OsString::from("real")]);
        // A chain of exactly 40 links is followed; one more is refused.
        let mut to = base.join("real");
        for hop in 1..=41 {
            let link = base.join(format!("hop{hop}"));
            symlink(&to, &link).unwrap();
            to = link;
        }
        assert_eq!(
            walk_parts(&base.join("hop40"), &accept).unwrap().0,
            base.join("real")
        );
        let error = walk(&base.join("hop41"), &accept).unwrap_err();
        assert!(error.contains("more than 40 symlinks"), "{error}");
    }

    #[test]
    fn a_chain_is_below_a_shared_directory_only_when_one_of_its_directories_others_can_write() {
        let root = TrustedTempDir::new("below-shared");
        let base = std::fs::canonicalize(root.path()).unwrap();
        std::fs::create_dir_all(base.join("a/b")).unwrap();
        let shared = |path: &Path| walk(path, &accept).map(|walked| walked.anchor.below_shared);
        assert!(!shared(&base.join("a/b")).unwrap());
        // Only a root-owned sticky directory can be shared and trusted; the user's own shared
        // one is refused before the question arises.
        std::fs::set_permissions(base.join("a"), std::fs::Permissions::from_mode(0o1777)).unwrap();
        let refused = shared(&base.join("a/b"));
        std::fs::set_permissions(base.join("a"), std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(refused.is_err());
        if let Ok(tmp) = std::fs::canonicalize("/tmp") {
            let metadata = std::fs::metadata(&tmp).unwrap();
            if metadata.uid() == 0 && metadata.mode() & 0o1000 != 0 {
                assert!(shared(&tmp).unwrap());
            }
        }
    }

    #[test]
    fn inspect_parent_judges_a_link_by_its_holder_through_the_walk() {
        // The holder verdict inside the walk, reached through inspect_parent (review S3).
        let root = TrustedTempDir::new("inspect-holder");
        let base = std::fs::canonicalize(root.path()).unwrap();
        std::fs::create_dir(base.join("real")).unwrap();
        let open = base.join("open");
        std::fs::create_dir(&open).unwrap();
        symlink(base.join("real"), open.join("parent")).unwrap();
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o777)).unwrap();
        let refused = inspect_parent(&open.join("parent"), &accept);
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o700)).unwrap();
        let refused = refused.unwrap_err();
        assert!(refused.contains(open.to_str().unwrap()), "{refused}");
        assert!(refused.contains("writable by other users"), "{refused}");
        let followed = inspect_parent(&open.join("parent"), &accept).unwrap();
        assert_eq!(followed.anchor.path, base.join("real"));
    }

    #[test]
    fn an_empty_link_target_is_refused() {
        let root = TrustedTempDir::new("walk-empty-link");
        let base = std::fs::canonicalize(root.path()).unwrap();
        // macOS lets a link hold an empty target; Linux refuses to make one.
        if symlink("", base.join("empty")).is_err() {
            eprintln!("SKIPPED: this system does not make a link with an empty target");
            return;
        }
        let error = walk(&base.join("empty/data"), &accept).unwrap_err();
        assert!(error.contains("target is empty"), "{error}");
    }

    /// A link whose holder carries an ACL entry that lets everyone add and delete entries is
    /// not followed: the holder is judged as an ancestor, ACL included (r2 review M2).
    #[cfg(target_os = "macos")]
    #[test]
    fn a_link_in_a_holder_with_an_unsafe_acl_is_refused() {
        let root = TrustedTempDir::new("walk-acl-holder");
        let base = std::fs::canonicalize(root.path()).unwrap();
        std::fs::create_dir(base.join("real")).unwrap();
        let holder = base.join("holder");
        std::fs::create_dir(&holder).unwrap();
        symlink(base.join("real"), holder.join("link")).unwrap();
        let added = std::process::Command::new("/bin/chmod")
            .args(["+a", "everyone allow add_file,delete_child"])
            .arg(&holder)
            .status()
            .is_ok_and(|status| status.success());
        if !added {
            eprintln!("SKIPPED: chmod +a is unavailable");
            return;
        }
        let refused = walk(&holder.join("link/data"), &system_volume_check);
        let _ = std::process::Command::new("/bin/chmod")
            .args(["-N"])
            .arg(&holder)
            .status();
        let error = refused.unwrap_err();
        assert!(error.contains("ACL"), "{error}");
        assert!(error.contains(holder.to_str().unwrap()), "{error}");
    }

    /// A link on a volume that ignores ownership is not followed out of it: the directory
    /// holding it is judged as an ancestor, volume included (r2 review M2).
    #[cfg(target_os = "macos")]
    #[test]
    fn a_link_on_a_volume_that_ignores_ownership_is_refused() {
        let root = TrustedTempDir::new("walk-noowners");
        let base = std::fs::canonicalize(root.path()).unwrap();
        std::fs::create_dir(base.join("victim")).unwrap();
        let image = base.join("t.dmg");
        let mount = base.join("mnt");
        std::fs::create_dir(&mount).unwrap();
        let run = |args: &[&std::ffi::OsStr]| {
            std::process::Command::new("/usr/bin/hdiutil")
                .args(args)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .is_ok_and(|status| status.success())
        };
        let made = run(&[
            "create".as_ref(),
            "-size".as_ref(),
            "8m".as_ref(),
            "-fs".as_ref(),
            "APFS".as_ref(),
            "-volname".as_ref(),
            "FIREEMUTEST".as_ref(),
            image.as_os_str(),
        ]) && run(&[
            "attach".as_ref(),
            "-owners".as_ref(),
            "off".as_ref(),
            "-nobrowse".as_ref(),
            "-mountpoint".as_ref(),
            mount.as_os_str(),
            image.as_os_str(),
        ]);
        if !made {
            eprintln!("SKIPPED: hdiutil cannot make and attach a volume here");
            return;
        }
        let linked = symlink(base.join("victim"), mount.join("link")).is_ok();
        let refused = walk(&mount.join("link/data"), &system_volume_check);
        let _ = run(&["detach".as_ref(), mount.as_os_str()]);
        assert!(linked);
        let error = refused.unwrap_err();
        assert!(error.contains("ignores ownership"), "{error}");
    }

    /// A search descriptor names a directory only, never a link or a file, and does not leak
    /// into a child process.
    #[test]
    fn a_search_descriptor_opens_a_directory_only_and_closes_on_exec() {
        let root = TrustedTempDir::new("search-flags");
        let base = std::fs::canonicalize(root.path()).unwrap();
        std::fs::create_dir(base.join("dir")).unwrap();
        std::fs::write(base.join("file"), b"").unwrap();
        symlink(base.join("dir"), base.join("link")).unwrap();
        let dir = open_search(&base);
        let opened = rustix::fs::openat(&dir, "dir", search_flags(), Mode::empty()).unwrap();
        assert!(rustix::io::fcntl_getfd(&opened)
            .unwrap()
            .contains(rustix::io::FdFlags::CLOEXEC));
        for name in ["link", "file"] {
            assert!(
                rustix::fs::openat(&dir, name, search_flags(), Mode::empty()).is_err(),
                "{name}"
            );
        }
    }

    /// Removal by descriptor never follows a link at the name and refuses a file there; what the
    /// link points to is kept.
    #[test]
    fn a_tree_is_removed_by_descriptor_without_following_links() {
        let root = TrustedTempDir::new("remove-tree");
        let base = std::fs::canonicalize(root.path()).unwrap();
        std::fs::create_dir_all(base.join("tree/sub")).unwrap();
        std::fs::write(base.join("tree/sub/file"), b"").unwrap();
        std::fs::create_dir(base.join("kept")).unwrap();
        std::fs::write(base.join("kept/file"), b"kept").unwrap();
        symlink(base.join("kept"), base.join("tree/link")).unwrap();
        symlink(base.join("kept"), base.join("link")).unwrap();
        std::fs::write(base.join("file"), b"").unwrap();
        let dir = open_search(&base);
        assert!(remove_tree_at(dir.as_fd(), OsStr::new("link")).is_err());
        assert!(remove_tree_at(dir.as_fd(), OsStr::new("file")).is_err());
        remove_tree_at(dir.as_fd(), OsStr::new("tree")).unwrap();
        assert!(!base.join("tree").exists());
        assert_eq!(std::fs::read(base.join("kept/file")).unwrap(), b"kept");
    }

    /// `..` at `/` stays at `/`, as the kernel resolves it.
    #[test]
    fn dot_dot_at_the_root_stays_at_the_root() {
        let walked = walk(Path::new("/../.."), &accept).unwrap();
        assert_eq!(walked.anchor.path, Path::new("/"));
    }

    /// The ACL is read by path between two checks that the path still names the held directory.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_path_that_names_another_directory_than_the_one_held_is_refused() {
        let root = TrustedTempDir::new("same-directory");
        let base = std::fs::canonicalize(root.path()).unwrap();
        std::fs::create_dir(base.join("a")).unwrap();
        std::fs::create_dir(base.join("b")).unwrap();
        let held = rustix::fs::lstat(base.join("a")).unwrap();
        same_directory(&base.join("a"), &held).unwrap();
        let error = same_directory(&base.join("b"), &held).unwrap_err();
        assert!(error.contains("changed while it was checked"), "{error}");
    }

    const OTHER: u32 = 4242;
    const ME: u32 = 501;

    #[test]
    fn an_ancestor_is_trusted_by_owner_and_mode_with_the_root_sticky_exception() {
        let p = Path::new("/a");
        // Owned by root or the user, not writable by others.
        assert_eq!(ancestor_error(p, 0, 0o40755, ME), None);
        assert_eq!(ancestor_error(p, ME, 0o40700, ME), None);
        // Root-owned and sticky: /tmp (1777) and a group-writable sticky directory.
        assert_eq!(ancestor_error(p, 0, 0o41777, ME), None);
        assert_eq!(ancestor_error(p, 0, 0o41775, ME), None);
        // Writable by others without the sticky bit, or sticky but not root's.
        for (uid, mode) in [
            (0, 0o40777),
            (0, 0o40775),
            (ME, 0o40777),
            (ME, 0o41777),
            (ME, 0o40770),
        ] {
            let error = ancestor_error(p, uid, mode, ME).unwrap();
            assert!(
                error.contains("writable by other users"),
                "{uid} {mode:o}: {error}"
            );
        }
        // Another user's directory, sticky or not.
        for mode in [0o40755, 0o41777, 0o40700] {
            let error = ancestor_error(p, OTHER, mode, ME).unwrap();
            assert!(
                error.contains("not owned by the current user or root"),
                "{mode:o}: {error}"
            );
        }
    }

    #[test]
    fn a_symlink_is_followed_only_when_root_or_the_user_owns_it_in_a_private_directory() {
        let link = Path::new("/h/link");
        // Root's link in /tmp (1777) or in / (0755): macOS /tmp and /var.
        assert_eq!(link_error(link, 0, 0o41777, ME), None);
        assert_eq!(link_error(link, 0, 0o40755, ME), None);
        // The user's own link in a directory only the user (or root) can write.
        assert_eq!(link_error(link, ME, 0o40700, ME), None);
        assert_eq!(link_error(link, ME, 0o40755, ME), None);
        // The user's own link in /tmp: anyone could have made a link there.
        let shared = link_error(link, ME, 0o41777, ME).unwrap();
        assert!(shared.contains("other users can write"), "{shared}");
        assert!(shared.contains("a directory of your own"), "{shared}");
        // Another user's link, anywhere.
        for holder_mode in [0o41777, 0o40755, 0o40700] {
            let theirs = link_error(link, OTHER, holder_mode, ME).unwrap();
            assert!(theirs.contains("another user"), "{theirs}");
            assert!(theirs.contains("/h/link"), "{theirs}");
        }
    }

    #[test]
    fn an_existing_target_below_a_shared_directory_must_be_private_to_the_user_or_root() {
        let target = Path::new("/tmp/data");
        // Not below a shared directory: only the user or root could have made it.
        assert_eq!(target_error(target, OTHER, 0o40777, false, ME), None);
        // Below /tmp: the user's or root's, not writable by others.
        assert_eq!(target_error(target, ME, 0o40700, true, ME), None);
        assert_eq!(target_error(target, ME, 0o40755, true, ME), None);
        assert_eq!(target_error(target, 0, 0o40755, true, ME), None);
        // Another user made it first (a directory pre-created by another uid).
        let theirs = target_error(target, OTHER, 0o40700, true, ME).unwrap();
        assert!(theirs.contains("belongs to another user"), "{theirs}");
        assert!(theirs.contains("remove or rename it"), "{theirs}");
        // The user's, but writable by others, even with the sticky bit.
        for mode in [0o40777, 0o40770, 0o40702, 0o41777] {
            let open = target_error(target, ME, mode, true, ME).unwrap();
            assert!(open.contains("chmod 700"), "{mode:o}: {open}");
        }
    }

    #[test]
    fn another_users_ancestor_is_refused_with_a_remedy() {
        let error = ancestor_error(Path::new("/tmp/taken"), OTHER, 0o40755, ME).unwrap();
        assert!(error.contains("take a name first"), "{error}");
        assert!(error.contains("a directory of your own"), "{error}");
    }

    proptest::proptest! {
        /// A link is followed exactly when its directory is trusted and root owns it, or the
        /// user owns it and no one else can write that directory.
        #[test]
        fn a_link_is_followed_by_owner_and_holder(
            link_owner in 0usize..3,
            holder_mode in 0u32..0o10000,
        ) {
            let link_uid = [0, ME, OTHER][link_owner];
            let verdict = link_error(Path::new("/h/l"), link_uid, 0o40000 | holder_mode, ME);
            let shared = holder_mode & 0o022 != 0;
            let followed = link_uid == 0 || (link_uid == ME && !shared);
            proptest::prop_assert_eq!(verdict.is_none(), followed, "{} {:o}", link_uid, holder_mode);
        }

        /// A present target is refused exactly when it sits below a shared directory and is
        /// another user's or writable by others; every refusal names a remedy.
        #[test]
        fn a_present_target_is_judged_by_owner_and_mode_below_a_shared_directory(
            owner in 0usize..3,
            mode in 0u32..0o10000,
            below_shared: bool,
        ) {
            let uid = [0, ME, OTHER][owner];
            let verdict = target_error(Path::new("/tmp/t"), uid, 0o40000 | mode, below_shared, ME);
            let refused = below_shared && (uid == OTHER || mode & 0o022 != 0);
            proptest::prop_assert_eq!(verdict.is_some(), refused, "{} {:o} {}", uid, mode, below_shared);
            if let Some(error) = verdict {
                proptest::prop_assert!(error.contains("a directory of your own"), "{}", error);
            }
        }

        /// Over every permission bit and three owners: never another user's directory, never one
        /// others can write unless root owns it with the sticky bit.
        #[test]
        fn trust_follows_the_owner_and_the_sticky_bit(mode in 0u32..0o10000, owner in 0usize..3) {
            let uid = [0, ME, OTHER][owner];
            let verdict = ancestor_error(Path::new("/a"), uid, 0o40000 | mode, ME);
            let shared = mode & 0o022 != 0;
            let root_sticky = uid == 0 && mode & 0o1000 != 0;
            let trusted = (uid == 0 || uid == ME) && (!shared || root_sticky);
            proptest::prop_assert_eq!(verdict.is_none(), trusted, "{} {:o}", uid, mode);
        }
    }

    #[test]
    fn a_sticky_directory_the_user_owns_or_a_shared_one_without_it_stays_refused() {
        let root = TrustedTempDir::new("parent-sticky");
        for mode in [0o1777, 0o777, 0o1770] {
            let shared = root.join(format!("shared-{mode:o}"));
            std::fs::create_dir_all(shared.join("mine")).unwrap();
            std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(mode)).unwrap();
            let error = trusted_ancestors(&shared.join("mine"), &accept).unwrap_err();
            assert!(
                error.contains("writable by other users"),
                "{mode:o}: {error}"
            );
            std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
    }

    /// The real `/tmp`, where it is a root-owned sticky directory (Linux 1777; macOS a root-owned
    /// symlink to `/private/tmp`, 1777): a private directory below it is a trusted parent, and on
    /// macOS `/tmp` itself is followed as the export parent.
    #[test]
    fn a_private_directory_below_the_system_tmp_is_trusted() {
        let tmp = Path::new("/tmp");
        let Ok(canonical) = std::fs::canonicalize(tmp) else {
            return;
        };
        let metadata = std::fs::metadata(&canonical).unwrap();
        if metadata.uid() != 0 || metadata.mode() & 0o1000 == 0 {
            eprintln!(
                "skipped: {} is not a root-owned sticky directory",
                canonical.display()
            );
            return;
        }
        let mine = tmp.join(format!(
            "fireemu-export-guard-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&mine).unwrap();
        std::fs::set_permissions(&mine, std::fs::Permissions::from_mode(0o700)).unwrap();
        let result =
            prepare_and_validate_parent_with(&mine.join("export-parent"), &accept, &|_| {});
        let parent = inspect_parent(tmp, &accept).map(|walked| walked.anchor.path);
        let _ = std::fs::remove_dir(mine.join("export-parent"));
        let _ = std::fs::remove_dir(&mine);
        assert_eq!(
            result.unwrap(),
            canonical
                .join(mine.file_name().unwrap())
                .join("export-parent")
        );
        assert_eq!(parent.unwrap(), canonical);
    }

    #[test]
    fn a_parent_that_is_a_file_is_refused_and_an_own_link_is_followed() {
        let root = TrustedTempDir::new("parent-leaf");
        let existing = std::fs::canonicalize(root.path()).unwrap();
        std::fs::create_dir(existing.join("real")).unwrap();
        symlink(existing.join("real"), existing.join("link")).unwrap();
        std::fs::write(existing.join("file"), b"x").unwrap();
        // The user's own link in a private directory is followed to its directory.
        let link =
            prepare_and_validate_parent_with(&existing.join("link"), &accept, &|_| {}).unwrap();
        assert_eq!(link, existing.join("real"));
        let file =
            prepare_and_validate_parent_with(&existing.join("file"), &accept, &|_| {}).unwrap_err();
        assert!(file.contains("not a directory"), "{file}");
        let below = prepare_and_validate_parent_with(&existing.join("file/x"), &accept, &|_| {})
            .unwrap_err();
        assert!(below.to_lowercase().contains("not a directory"), "{below}");
        assert!(!existing.join("file/x").exists());
    }
}
