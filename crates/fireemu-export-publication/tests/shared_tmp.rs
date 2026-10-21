//! The real `/tmp`, a root-owned sticky directory every local user can add entries to: what an
//! export accepts and refuses there. Each test is skipped where `/tmp` is not root-owned sticky.
//! Another user cannot be simulated without `chown`, so links and directories here are the test
//! user's own; the rules for another user's are unit-tested on metadata in `parent.rs`.
#![cfg(unix)]

use std::os::unix::fs::{symlink, MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use fireemu_export_publication::{preflight, resolve, PublicationStage};

#[allow(dead_code)]
#[path = "../../../tests/support/trusted_temp.rs"]
mod trusted_temp;

use trusted_temp::TrustedTempDir;

static NEXT: AtomicU64 = AtomicU64::new(0);

/// The canonical `/tmp` when it is root-owned and sticky.
fn system_tmp() -> Option<PathBuf> {
    let canonical = std::fs::canonicalize("/tmp").ok()?;
    let metadata = std::fs::metadata(&canonical).ok()?;
    if metadata.uid() == 0 && metadata.mode() & 0o1000 != 0 {
        Some(canonical)
    } else {
        eprintln!("SKIPPED: /tmp is not a root-owned sticky directory");
        None
    }
}

/// A fresh name directly in `/tmp`, removed (whatever it became) on drop.
struct TmpName(PathBuf);

impl TmpName {
    fn new(label: &str) -> Self {
        Self(Path::new("/tmp").join(format!(
            "fireemu-shared-tmp-{label}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        )))
    }

    fn dir(label: &str, mode: u32) -> Self {
        let name = Self::new(label);
        std::fs::create_dir(&name.0).unwrap();
        std::fs::set_permissions(&name.0, std::fs::Permissions::from_mode(mode)).unwrap();
        name
    }

    fn link(label: &str, to: &Path) -> Self {
        let name = Self::new(label);
        symlink(to, &name.0).unwrap();
        name
    }
}

impl Drop for TmpName {
    fn drop(&mut self) {
        match std::fs::symlink_metadata(&self.0) {
            Ok(metadata) if metadata.file_type().is_dir() => {
                let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o700));
                let _ = std::fs::remove_dir_all(&self.0);
            }
            Ok(_) => {
                let _ = std::fs::remove_file(&self.0);
            }
            Err(_) => {}
        }
    }
}

fn is_empty(dir: &Path) -> bool {
    std::fs::read_dir(dir).unwrap().next().is_none()
}

#[test]
fn a_symlink_in_tmp_is_never_followed_unless_root_owns_it() {
    let Some(_) = system_tmp() else { return };
    let victim = TrustedTempDir::new("shared-tmp-victim");
    std::fs::create_dir(victim.join("sub")).unwrap();
    let link = TmpName::link("link", victim.path());
    let first = TmpName::link("chain", &link.0);
    for route in [
        link.0.join("sub/data"),
        first.0.join("sub/data"),
        link.0.join("../x"),
        link.0.join("data"),
    ] {
        let error = preflight(&route).unwrap_err();
        assert!(error.contains("symlink"), "{}: {error}", route.display());
        let error = PublicationStage::create(&route, |_| Ok(())).unwrap_err();
        assert!(error.contains("symlink"), "{}: {error}", route.display());
    }
    assert!(
        is_empty(&victim.join("sub")),
        "nothing was made through a link"
    );
    assert_eq!(
        std::fs::read_dir(victim.path()).unwrap().count(),
        1,
        "nothing was made through a link"
    );
}

#[test]
fn a_symlink_at_the_target_name_in_tmp_is_refused() {
    let Some(_) = system_tmp() else { return };
    let victim = TrustedTempDir::new("shared-tmp-target-link");
    let link = TmpName::link("target", victim.path());
    assert!(preflight(&link.0).unwrap_err().contains("symlink"));
    assert!(PublicationStage::create(&link.0, |_| Ok(()))
        .unwrap_err()
        .contains("symlink"));
    assert!(is_empty(victim.path()));
}

#[test]
fn a_child_of_tmp_others_can_write_is_refused_as_a_parent() {
    let Some(_) = system_tmp() else { return };
    for mode in [0o770, 0o777, 0o1777] {
        let child = TmpName::dir("open-parent", mode);
        let error = preflight(&child.0.join("data")).unwrap_err();
        assert!(
            error.contains("writable by other users"),
            "{mode:o}: {error}"
        );
        let error = PublicationStage::create(&child.0.join("data"), |_| Ok(())).unwrap_err();
        assert!(
            error.contains("writable by other users"),
            "{mode:o}: {error}"
        );
        assert!(!child.0.join("data").exists());
    }
}

#[test]
fn an_existing_target_in_tmp_must_be_private() {
    let Some(_) = system_tmp() else { return };
    for mode in [0o777, 0o770, 0o1777, 0o702] {
        let target = TmpName::dir("open-target", mode);
        let error = preflight(&target.0).unwrap_err();
        assert!(error.contains("chmod 700"), "{mode:o}: {error}");
        let read = std::cell::Cell::new(false);
        let error = PublicationStage::create(&target.0, |_| {
            read.set(true);
            Ok(())
        })
        .unwrap_err();
        assert!(error.contains("chmod 700"), "{mode:o}: {error}");
        assert!(!read.get(), "the overwrite policy never saw it");
    }
    let private = TmpName::dir("private-target", 0o700);
    preflight(&private.0).unwrap();
    let stage = PublicationStage::create(&private.0, |_| Ok(())).unwrap();
    assert!(stage.target_was_present());
}

#[test]
fn a_link_planted_after_the_preflight_is_refused_when_exporting() {
    let Some(tmp) = system_tmp() else { return };
    let victim = TrustedTempDir::new("shared-tmp-late-link");
    let late = TmpName::new("late");
    let target = late.0.join("data");
    // The preflight resolves `/tmp` itself (macOS: `/private/tmp`), and the missing directory.
    let resolved = preflight(&target).unwrap();
    assert_eq!(resolved, tmp.join(late.0.file_name().unwrap()).join("data"));
    assert_eq!(resolve(&target).unwrap(), resolved);
    symlink(victim.path(), &late.0).unwrap();
    for path in [&target, &resolved] {
        let error = PublicationStage::create(path, |_| Ok(())).unwrap_err();
        assert!(error.contains("symlink"), "{}: {error}", path.display());
    }
    assert!(is_empty(victim.path()));
}
