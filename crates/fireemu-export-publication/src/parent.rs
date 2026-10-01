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
//! anyone else, free of ACL entries for anyone else, and on a volume that enforces ownership. It
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
    match std::fs::symlink_metadata(parent) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err("the export parent is a symlink, which an export never follows".to_owned());
        }
        Ok(metadata) if !metadata.file_type().is_dir() => {
            return Err("the export parent is not a directory".to_owned());
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("cannot inspect the export parent: {error}")),
    }
    let (existing, missing) = split_existing(parent)?;
    let existing = trusted_ancestors(&existing, volume_check)?;
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

/// The longest existing prefix of `parent` and the components below it that do not exist yet.
/// A `..` below the existing prefix is refused: it has no meaning before the components exist.
fn split_existing(parent: &Path) -> Result<(PathBuf, Vec<OsString>), String> {
    let mut existing = parent.to_path_buf();
    let mut missing = Vec::new();
    loop {
        match std::fs::symlink_metadata(&existing) {
            Ok(_) => break,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let Some(name) = existing.file_name() else {
                    return Err(
                        "cannot create the export parent through `..` or from the root".to_owned(),
                    );
                };
                missing.push(name.to_owned());
                existing.pop();
            }
            Err(error) => return Err(format!("cannot inspect the export parent: {error}")),
        }
    }
    missing.reverse();
    Ok((existing, missing))
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
        crate::acl::reject_unsafe_acl(
            ancestor,
            &crate::acl::Trusted::of_uids(metadata.uid(), effective_uid, &crate::acl::user_name),
        )?;
    }
    Ok(parent)
}

#[cfg(test)]
#[allow(dead_code)]
#[path = "../../../tests/support/trusted_temp.rs"]
mod trusted_temp;

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
    fn a_parent_that_is_a_symlink_or_a_file_is_refused() {
        let root = TrustedTempDir::new("parent-leaf");
        let existing = std::fs::canonicalize(root.path()).unwrap();
        std::fs::create_dir(existing.join("real")).unwrap();
        symlink(existing.join("real"), existing.join("link")).unwrap();
        std::fs::write(existing.join("file"), b"x").unwrap();
        let link =
            prepare_and_validate_parent_with(&existing.join("link"), &accept, &|_| {}).unwrap_err();
        assert!(link.contains("symlink"), "{link}");
        let file =
            prepare_and_validate_parent_with(&existing.join("file"), &accept, &|_| {}).unwrap_err();
        assert!(file.contains("not a directory"), "{file}");
        let below = prepare_and_validate_parent_with(&existing.join("file/x"), &accept, &|_| {})
            .unwrap_err();
        assert!(below.to_lowercase().contains("not a directory"), "{below}");
        assert!(!existing.join("file/x").exists());
    }
}
