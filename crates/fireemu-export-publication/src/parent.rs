//! The parent directory of an export: validated first, created only inside what was validated.
//!
//! Nothing is created before the nearest existing ancestor chain has passed every check (volume
//! ownership, owner, mode, ACL). A missing component is then made with `mkdirat` relative to a
//! directory file descriptor opened without following links, and restricted with `fchmod` on a
//! descriptor opened the same way, so no path is resolved again between the creation and the
//! restriction: a local user who swaps the new component for a symlink gets a refusal, never a
//! `chmod` of the link target. The whole chain is validated again once the components exist.
//!
//! Threat model, stated plainly. This protects against other local users and against volumes that
//! ignore ownership: every ancestor must be owned by root or the exporting user, not writable by
//! anyone else (except a root-owned directory with the sticky bit, such as `/tmp`, where other
//! users can add entries but cannot rename or remove the ones the export makes; they can only
//! take a name first, which refuses the export), free of ACL entries for anyone else, and on a
//! volume that enforces ownership. The path is walked from `/` one component at a time, and a
//! symlink on it (anywhere, and at every hop of a chain) is followed only when the directory
//! holding it is trusted and root owns the link, or the user owns it and no one else can write
//! that directory (macOS `/tmp` → `private/tmp`); in `/tmp` a link anyone could have made is
//! never followed. Below a directory others can write, an export directory that already exists
//! must be the user's (or root's) and private, since another user could have made it first. It
//! does not defend against the exporting user's own processes, or root, changing the namespace
//! concurrently: such a process can rename a directory away and put another directory of the same
//! owner in its place (the descriptor reopen accepts any directory that user owns), and the
//! rollback of a failed creation removes directories by path. The export directory is as safe as
//! the account that runs the export.
//!
//! Needs: a missing component is made through a read-opened descriptor, so the directory it is made
//! in must be readable by the exporting user, and the process umask must leave the owner's read
//! permission on new directories (a umask such as 0477 does not). Both cases are refused with a
//! message that says so; an existing parent needs no read permission.

use std::ffi::OsString;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

use rustix::fs::{Mode, OFlags};

/// Runs on every ancestor of the export, after it was inspected and before its owner and mode are
/// trusted. On macOS it refuses a volume that ignores ownership; elsewhere it accepts.
pub(crate) type VolumeCheck<'a> = &'a dyn Fn(&Path) -> Result<(), String>;

#[cfg(target_os = "macos")]
pub(crate) fn system_volume_check(path: &Path) -> Result<(), String> {
    crate::volume::require_ownership(path, &crate::volume::mount_of)
}

#[cfg(not(target_os = "macos"))]
#[allow(clippy::unnecessary_wraps)]
pub(crate) fn system_volume_check(_path: &Path) -> Result<(), String> {
    Ok(())
}

/// The canonical parent of the export, validated, created where it was missing.
pub(crate) fn prepare_and_validate_parent(parent: &Path) -> Result<PathBuf, String> {
    prepare_and_validate_parent_with(parent, &system_volume_check, &|_| {})
}

/// [`prepare_and_validate_parent`] with the volume check passed in and a hook that runs after each
/// component was made and before it is restricted (the tests swap the component there).
pub(crate) fn prepare_and_validate_parent_with(
    parent: &Path,
    volume_check: VolumeCheck<'_>,
    between_mkdir_and_chmod: &dyn Fn(&Path),
) -> Result<PathBuf, String> {
    let (existing, missing) = inspect_parent(parent, volume_check)?;
    if missing.is_empty() {
        return Ok(existing);
    }
    let mut created = Vec::new();
    let result = create_missing(
        &existing,
        &missing,
        between_mkdir_and_chmod,
        &mut created,
        rustix::process::geteuid().as_raw(),
    )
    .and_then(|made| trusted_ancestors(&made, volume_check));
    if result.is_err() {
        // Only directories this call made, deepest first; `remove_dir` never follows a link.
        for directory in created.iter().rev() {
            let _ = std::fs::remove_dir(directory);
        }
    }
    result
}

/// Inspects the existing namespace without creating missing components: the physical existing
/// prefix of `parent`, validated, and the components below it that do not exist yet.
pub(crate) fn inspect_parent(
    parent: &Path,
    volume_check: VolumeCheck<'_>,
) -> Result<(PathBuf, Vec<OsString>), String> {
    let (existing, missing) = walk(parent)?;
    let existing = trusted_ancestors(&existing, volume_check)?;
    Ok((existing, missing))
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

/// Walks the absolute path `parent` from `/`, one component at a time, with `lstat`: the
/// physical (link-free) existing prefix, and the components of `parent` below it that do not
/// exist yet. Every symlink met, in `parent` or in a link's target, is judged by [`link_error`]
/// against the physical directory holding it, then expanded one hop at a time, so every hop of
/// a chain is judged. A `..` right after a symlink of `parent` is refused; a `..` inside a link's
/// target goes to the physical parent, as the kernel does. A dangling link is refused, and so is
/// a `..` below the existing prefix.
pub(crate) fn walk(parent: &Path) -> Result<(PathBuf, Vec<OsString>), String> {
    let parent = std::path::absolute(parent)
        .map_err(|error| format!("cannot resolve the export parent: {error}"))?;
    let effective_uid = rustix::process::geteuid().as_raw();
    // The steps still to take, the next one last; `true` marks a step of `parent` itself.
    let mut pending: Vec<(Step, bool)> = steps(&parent)
        .into_iter()
        .map(|step| (step, true))
        .collect();
    let mut current = PathBuf::from("/");
    let mut missing = Vec::new();
    let mut hops = 0;
    let mut after_link = false;
    while let Some((step, own)) = pending.pop() {
        let mut was_link = false;
        match step {
            Step::Root => current = PathBuf::from("/"),
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
                current.pop();
            }
            Step::Name(name) if !missing.is_empty() => missing.push(name),
            Step::Name(name) => {
                let next = current.join(&name);
                match std::fs::symlink_metadata(&next) {
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound && own => {
                        missing.push(name);
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
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
                    Ok(metadata) if metadata.file_type().is_symlink() => {
                        hops += 1;
                        if hops > MAX_LINK_HOPS {
                            return Err(format!(
                                "the export path {} goes through more than {MAX_LINK_HOPS} symlinks",
                                parent.display()
                            ));
                        }
                        let holder = std::fs::symlink_metadata(&current).map_err(|error| {
                            format!(
                                "cannot inspect the directory holding the symlink {}: {error}",
                                next.display()
                            )
                        })?;
                        if let Some(error) = link_error(
                            &next,
                            metadata.uid(),
                            holder.uid(),
                            holder.mode(),
                            effective_uid,
                        ) {
                            return Err(error);
                        }
                        let target = std::fs::read_link(&next).map_err(|error| {
                            format!("cannot read the symlink {}: {error}", next.display())
                        })?;
                        pending.extend(steps(&target).into_iter().map(|step| (step, false)));
                        was_link = true;
                    }
                    Ok(_) => current = next,
                }
            }
        }
        if own {
            after_link = was_link;
        }
    }
    Ok((current, missing))
}

/// Makes each missing component below `base` (a validated canonical directory), private to the
/// owner. Every component is made with `mkdirat` and restricted through a descriptor opened with
/// `O_NOFOLLOW`; a component that already exists, or that is anything but the directory just made,
/// is refused. Returns the path of the last directory; `created` lists what was made.
fn create_missing(
    base: &Path,
    missing: &[OsString],
    between_mkdir_and_chmod: &dyn Fn(&Path),
    created: &mut Vec<PathBuf>,
    expected_uid: u32,
) -> Result<PathBuf, String> {
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut path = base.to_path_buf();
    let mut current =
        rustix::fs::openat(rustix::fs::CWD, &path, flags, Mode::empty()).map_err(|error| {
            if error == rustix::io::Errno::ACCESS {
                format!(
                    "cannot create the missing export parent below {}: the directory must be readable by you for a component to be made in it safely ({error}); make it readable, or choose an existing destination",
                    path.display()
                )
            } else {
                format!(
                    "cannot open export namespace ancestor {}: {error}",
                    path.display()
                )
            }
        })?;
    for name in missing {
        path.push(name);
        rustix::fs::mkdirat(&current, name, Mode::from_raw_mode(0o700)).map_err(|error| {
            format!(
                "cannot create private export parent {}: {error}",
                path.display()
            )
        })?;
        created.push(path.clone());
        between_mkdir_and_chmod(&path);
        let made = rustix::fs::openat(&current, name, flags, Mode::empty()).map_err(|error| {
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
        })?;
        let stat = rustix::fs::fstat(&made)
            .map_err(|error| format!("cannot inspect export parent {}: {error}", path.display()))?;
        if stat.st_uid != expected_uid {
            return Err(format!(
                "the export parent component {} is not owned by the current user",
                path.display()
            ));
        }
        rustix::fs::fchmod(&made, Mode::from_raw_mode(0o700))
            .map_err(|error| format!("cannot restrict export parent permissions: {error}"))?;
        current = made;
    }
    Ok(path)
}

/// Canonicalizes `parent` and requires every ancestor to be a trusted part of the namespace: on a
/// volume that enforces ownership (`volume_check`), owned by root or the current user, not writable
/// by group or others, and (macOS) without an ACL entry that lets another principal change it.
pub(crate) fn trusted_ancestors(
    parent: &Path,
    volume_check: VolumeCheck<'_>,
) -> Result<PathBuf, String> {
    let parent = std::fs::canonicalize(parent)
        .map_err(|error| format!("cannot resolve the export parent: {error}"))?;
    if !std::fs::metadata(&parent).is_ok_and(|metadata| metadata.is_dir()) {
        return Err("the export parent is not a directory".to_owned());
    }
    let effective_uid = rustix::process::geteuid().as_raw();
    for ancestor in parent.ancestors() {
        let metadata = std::fs::symlink_metadata(ancestor).map_err(|error| {
            format!(
                "cannot inspect export namespace ancestor {}: {error}",
                ancestor.display()
            )
        })?;
        // Before the owner and the mode are trusted: on a volume that ignores ownership they mean nothing.
        volume_check(ancestor)?;
        if let Some(error) =
            ancestor_error(ancestor, metadata.uid(), metadata.mode(), effective_uid)
        {
            return Err(error);
        }
        #[cfg(target_os = "macos")]
        crate::acl::reject_unsafe_acl(
            ancestor,
            &crate::acl::Trusted::of_uids(metadata.uid(), effective_uid, &crate::acl::user_name),
        )?;
    }
    Ok(parent)
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

/// Why a symlink on the export path is not followed. The directory holding it (`holder_*`,
/// the physical directory, never a link) must pass [`ancestor_error`], and the link must be
/// owned by root, or by the exporting user when no one else can write the holder: a link
/// cannot be changed, only replaced by someone who can write its directory, and in a directory
/// others can write (`/tmp`) anyone can make one, so only root's are followed there.
pub(crate) fn link_error(
    link: &Path,
    link_uid: u32,
    holder_uid: u32,
    holder_mode: u32,
    effective_uid: u32,
) -> Option<String> {
    let holder = link.parent().unwrap_or(Path::new("/"));
    if let Some(error) = ancestor_error(holder, holder_uid, holder_mode, effective_uid) {
        return Some(format!(
            "the export path goes through the symlink {}, in a directory that cannot be trusted: {error}",
            link.display()
        ));
    }
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

/// Whether a directory of the canonical chain of `parent` is writable by others (after
/// [`trusted_ancestors`], only a root-owned sticky one can be).
pub(crate) fn below_shared(parent: &Path) -> Result<bool, String> {
    for ancestor in parent.ancestors() {
        let metadata = std::fs::symlink_metadata(ancestor).map_err(|error| {
            format!(
                "cannot inspect export namespace ancestor {}: {error}",
                ancestor.display()
            )
        })?;
        if metadata.mode() & 0o022 != 0 {
            return Ok(true);
        }
    }
    Ok(false)
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
    fn accept(_: &Path) -> Result<(), String> {
        Ok(())
    }

    fn mode_of(path: &Path) -> u32 {
        std::fs::metadata(path).unwrap().mode() & 0o7777
    }

    #[test]
    fn every_canonical_ancestor_is_checked_leaf_first_and_nothing_else() {
        let root = TrustedTempDir::new("parent-ancestors");
        std::fs::create_dir_all(root.join("a/b")).unwrap();
        std::fs::create_dir(root.join("c")).unwrap();
        // The route has a `..` and a symlinked component; only the canonical chain is a namespace.
        symlink(root.join("a"), root.join("c/link")).unwrap();
        let route = root.join("c/link/b/../b");
        let seen = RefCell::new(Vec::new());
        let canonical = trusted_ancestors(&route, &|path: &Path| {
            seen.borrow_mut().push(path.to_path_buf());
            Ok(())
        })
        .unwrap();
        assert_eq!(canonical, std::fs::canonicalize(root.join("a/b")).unwrap());
        let expected: Vec<PathBuf> = canonical.ancestors().map(Path::to_path_buf).collect();
        assert_eq!(*seen.borrow(), expected);
        assert_eq!(expected.last().unwrap(), Path::new("/"));
        assert!(expected.len() >= 4, "{expected:?}");
    }

    #[test]
    fn a_refusal_at_any_ancestor_refuses_the_parent() {
        let root = TrustedTempDir::new("parent-refuse-each");
        std::fs::create_dir_all(root.join("a/b")).unwrap();
        let canonical = std::fs::canonicalize(root.join("a/b")).unwrap();
        for refused in canonical.ancestors() {
            let error = trusted_ancestors(&canonical, &|path: &Path| {
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
        let error = trusted_ancestors(&writable, &|path: &Path| {
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
            &|path: &Path| {
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
            &|path: &Path| {
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
        assert_eq!(error, "the export parent is not a directory");
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
    fn a_missing_component_below_an_unreadable_parent_is_refused_with_the_reason() {
        if rustix::process::geteuid().is_root() {
            eprintln!("SKIPPED: root reads any directory, so the refusal cannot be observed");
            return;
        }
        let root = TrustedTempDir::new("parent-0300-missing");
        let existing = std::fs::canonicalize(root.path()).unwrap();
        let parent = existing.join("search-only");
        std::fs::create_dir(&parent).unwrap();
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o300)).unwrap();
        let error =
            prepare_and_validate_parent_with(&parent.join("x"), &accept, &|_| {}).unwrap_err();
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(error.contains("must be readable by you"), "{error}");
        assert!(!parent.join("x").exists(), "nothing was made");
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

    #[test]
    fn a_new_directory_owned_by_someone_else_is_refused() {
        let root = TrustedTempDir::new("parent-owner");
        let existing = std::fs::canonicalize(root.path()).unwrap();
        let mut created = Vec::new();
        let someone_else = rustix::process::geteuid().as_raw() + 1;
        let error = create_missing(
            &existing,
            &[OsString::from("x")],
            &|_| {},
            &mut created,
            someone_else,
        )
        .unwrap_err();
        assert!(
            error.contains("is not owned by the current user"),
            "{error}"
        );
        assert_eq!(
            created,
            [existing.join("x")],
            "the caller removes what was made"
        );
    }

    #[test]
    fn a_component_that_already_exists_is_refused() {
        let root = TrustedTempDir::new("parent-exists");
        let existing = std::fs::canonicalize(root.path()).unwrap();
        std::fs::create_dir(existing.join("x")).unwrap();
        let mut created = Vec::new();
        let error = create_missing(
            &existing,
            &[OsString::from("x")],
            &|_| {},
            &mut created,
            rustix::process::geteuid().as_raw(),
        )
        .unwrap_err();
        assert!(
            error.contains("cannot create private export parent"),
            "{error}"
        );
        assert!(created.is_empty());
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
            let (existing, missing) = walk(&base.join(route).join("x/y")).unwrap();
            assert_eq!(existing, base.join("real/sub"), "{route}");
            assert_eq!(
                missing,
                [OsString::from("x"), OsString::from("y")],
                "{route}"
            );
        }
        // The walk's result has no link left in it.
        let (existing, _) = walk(&base.join("chain")).unwrap();
        assert_eq!(existing, std::fs::canonicalize(base.join("real")).unwrap());
    }

    #[test]
    fn the_walk_refuses_dot_dot_after_a_link_a_dangling_link_a_loop_and_an_untrusted_holder() {
        let root = TrustedTempDir::new("walk-refusals");
        let base = std::fs::canonicalize(root.path()).unwrap();
        std::fs::create_dir(base.join("real")).unwrap();
        symlink(base.join("real"), base.join("link")).unwrap();
        let after = walk(&base.join("link/../real/x")).unwrap_err();
        assert!(after.contains("`..` right after a symlink"), "{after}");
        // `..` before any link is resolved physically, as before.
        assert_eq!(
            walk(&base.join("real/../real")).unwrap().0,
            base.join("real")
        );
        symlink(base.join("nowhere"), base.join("dangling")).unwrap();
        let dangling = walk(&base.join("dangling/x")).unwrap_err();
        assert!(dangling.contains("does not exist"), "{dangling}");
        symlink(base.join("loop"), base.join("loop")).unwrap();
        let looped = walk(&base.join("loop/x")).unwrap_err();
        assert!(looped.contains("more than 40 symlinks"), "{looped}");
        // The user's own link in a directory others in the group can write.
        let open = base.join("open");
        std::fs::create_dir(&open).unwrap();
        symlink(base.join("real"), open.join("link")).unwrap();
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o770)).unwrap();
        let held = walk(&open.join("link/x"));
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o700)).unwrap();
        let held = held.unwrap_err();
        assert!(held.contains("cannot be trusted"), "{held}");
        // A link to a file with more below it.
        std::fs::write(base.join("file"), b"x").unwrap();
        symlink(base.join("file"), base.join("to-file")).unwrap();
        assert!(walk(&base.join("to-file/x")).is_err());
    }

    #[test]
    fn the_walk_keeps_every_component_after_a_missing_one_and_follows_forty_hops() {
        let root = TrustedTempDir::new("walk-missing-hops");
        let base = std::fs::canonicalize(root.path()).unwrap();
        std::fs::create_dir(base.join("real")).unwrap();
        // `real` exists beside the missing `x`, but below `x` it is a name to make.
        let (existing, missing) = walk(&base.join("x/real")).unwrap();
        assert_eq!(existing, base);
        assert_eq!(missing, [OsString::from("x"), OsString::from("real")]);
        // A chain of exactly 40 links is followed; one more is refused.
        let mut to = base.join("real");
        for hop in 1..=41 {
            let link = base.join(format!("hop{hop}"));
            symlink(&to, &link).unwrap();
            to = link;
        }
        assert_eq!(walk(&base.join("hop40")).unwrap().0, base.join("real"));
        let error = walk(&base.join("hop41")).unwrap_err();
        assert!(error.contains("more than 40 symlinks"), "{error}");
    }

    #[test]
    fn a_chain_is_below_a_shared_directory_only_when_one_of_its_directories_others_can_write() {
        let root = TrustedTempDir::new("below-shared");
        let base = std::fs::canonicalize(root.path()).unwrap();
        std::fs::create_dir_all(base.join("a/b")).unwrap();
        assert!(!below_shared(&base.join("a/b")).unwrap());
        for mode in [0o720, 0o702, 0o1777] {
            std::fs::set_permissions(base.join("a"), std::fs::Permissions::from_mode(mode))
                .unwrap();
            let shared = below_shared(&base.join("a/b"));
            std::fs::set_permissions(base.join("a"), std::fs::Permissions::from_mode(0o700))
                .unwrap();
            assert!(shared.unwrap(), "{mode:o}");
        }
        assert!(below_shared(&base.join("missing")).is_err());
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
        assert!(refused.contains("symlink"), "{refused}");
        assert!(refused.contains("writable by other users"), "{refused}");
        let followed = inspect_parent(&open.join("parent"), &accept).unwrap();
        assert_eq!(followed.0, base.join("real"));
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
    fn a_symlink_is_followed_only_when_root_or_the_user_owns_it_in_a_trusted_directory() {
        let link = Path::new("/h/link");
        // Root's link in /tmp (root, 1777) or in / (root, 0755): macOS /tmp and /var.
        assert_eq!(link_error(link, 0, 0, 0o41777, ME), None);
        assert_eq!(link_error(link, 0, 0, 0o40755, ME), None);
        // The user's own link in a directory only the user (or root) can write.
        assert_eq!(link_error(link, ME, ME, 0o40700, ME), None);
        assert_eq!(link_error(link, ME, 0, 0o40755, ME), None);
        // The user's own link in /tmp: anyone could have made a link there.
        let shared = link_error(link, ME, 0, 0o41777, ME).unwrap();
        assert!(shared.contains("other users can write"), "{shared}");
        assert!(shared.contains("a directory of your own"), "{shared}");
        // Another user's link, anywhere.
        for (holder_uid, holder_mode) in [(0, 0o41777), (0, 0o40755), (ME, 0o40700)] {
            let theirs = link_error(link, OTHER, holder_uid, holder_mode, ME).unwrap();
            assert!(theirs.contains("another user"), "{theirs}");
            assert!(theirs.contains("/h/link"), "{theirs}");
        }
        // Root's link in a directory that fails the ancestor rule.
        for (holder_uid, holder_mode) in [(0, 0o40777), (ME, 0o40770), (OTHER, 0o40755)] {
            let held = link_error(link, 0, holder_uid, holder_mode, ME).unwrap();
            assert!(held.contains("cannot be trusted"), "{held}");
            assert!(held.contains("/h"), "{held}");
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
            holder_owner in 0usize..3,
            holder_mode in 0u32..0o10000,
        ) {
            let link_uid = [0, ME, OTHER][link_owner];
            let holder_uid = [0, ME, OTHER][holder_owner];
            let verdict = link_error(Path::new("/h/l"), link_uid, holder_uid, 0o40000 | holder_mode, ME);
            let holder_trusted = ancestor_error(Path::new("/h"), holder_uid, 0o40000 | holder_mode, ME).is_none();
            let shared = holder_mode & 0o022 != 0;
            let followed = holder_trusted && (link_uid == 0 || (link_uid == ME && !shared));
            proptest::prop_assert_eq!(verdict.is_none(), followed, "{} {} {:o}", link_uid, holder_uid, holder_mode);
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
        let parent = inspect_parent(tmp, &accept);
        let _ = std::fs::remove_dir(mine.join("export-parent"));
        let _ = std::fs::remove_dir(&mine);
        assert_eq!(
            result.unwrap(),
            canonical
                .join(mine.file_name().unwrap())
                .join("export-parent")
        );
        assert_eq!(parent.unwrap().0, canonical);
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
