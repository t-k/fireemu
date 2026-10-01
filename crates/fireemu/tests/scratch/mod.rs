//! Scratch space and Hub locators that a test removes when it ends, also when it panics.
//!
//! A scratch directory that is removed by the last line of a test stays behind whenever an
//! assertion fails first, and a daemon a test kills cannot remove its own Hub locator. Mutation
//! runs fail tests by the thousand, which is how the shared temp directory reached 767,725
//! entries on 2026-10-01. Under nextest every test also runs with a private `TMPDIR`
//! (`tools/ci/nextest-private-tmpdir.sh`) that fails a passing test that leaves anything there.
//!
//! Any test file in this crate can use it with `mod scratch;`. Each test binary that does so
//! compiles its own copy and uses only part of it, hence the module-wide `dead_code` allowance.

#![allow(dead_code)]

use std::path::{Path, PathBuf};

/// A directory under the temp directory, removed with everything in it when dropped.
#[derive(Debug)]
pub struct Scratch(PathBuf);

impl Scratch {
    /// `<temp dir>/fireemu-<kind>-<name>-<pid>`, created empty (a leftover of an earlier run
    /// with the same process id is removed first).
    pub fn new(kind: &str, name: &str) -> Self {
        let dir =
            std::env::temp_dir().join(format!("fireemu-{kind}-{name}-{}", std::process::id()));
        remove_tree(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    /// The directory as an owned path.
    pub fn to_path_buf(&self) -> PathBuf {
        self.0.clone()
    }
}

impl std::ops::Deref for Scratch {
    type Target = Path;

    fn deref(&self) -> &Path {
        &self.0
    }
}

impl AsRef<Path> for Scratch {
    fn as_ref(&self) -> &Path {
        &self.0
    }
}

impl AsRef<std::ffi::OsStr> for Scratch {
    fn as_ref(&self) -> &std::ffi::OsStr {
        self.0.as_os_str()
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        remove_tree(&self.0);
    }
}

/// Removes `path` and everything under it. A test may have made a directory read-only to
/// provoke an error; those are made writable again and the removal is retried. Symbolic
/// links are removed, never followed.
pub fn remove_tree(path: &Path) {
    if std::fs::remove_dir_all(path).is_ok() || std::fs::symlink_metadata(path).is_err() {
        return;
    }
    make_owner_writable(path);
    let _ = std::fs::remove_dir_all(path);
}

fn make_owner_writable(path: &Path) {
    let Ok(metadata) = std::fs::symlink_metadata(path) else {
        return;
    };
    if !metadata.is_dir() {
        return;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = metadata.permissions().mode() | 0o700;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode));
    }
    #[cfg(windows)]
    {
        let mut permissions = metadata.permissions();
        #[allow(clippy::permissions_set_readonly_false)]
        permissions.set_readonly(false);
        let _ = std::fs::set_permissions(path, permissions);
    }
    if let Ok(entries) = std::fs::read_dir(path) {
        for entry in entries.flatten() {
            make_owner_writable(&entry.path());
        }
    }
}

/// The Hub locator path a daemon for `project` writes: `<temp dir>/hub-<project>.json`.
pub fn hub_locator(project: &str) -> PathBuf {
    std::env::temp_dir().join(format!("hub-{project}.json"))
}

/// Removes the Hub locator of `project` when it is a regular file that records `pid`.
///
/// A daemon removes its locator when it shuts down, but one a test kills cannot. The locator
/// is removed only when it still names that daemon, so a locator another live suite wrote for
/// the same project is left alone.
pub fn remove_killed_daemon_locator(project: &str, pid: u32) {
    let path = hub_locator(project);
    if locator_names_pid(&path, pid) {
        let _ = std::fs::remove_file(path);
    }
}

/// Whether `path` is a regular file holding a locator document whose `pid` is `pid`.
pub fn locator_names_pid(path: &Path, pid: u32) -> bool {
    let Ok(metadata) = std::fs::symlink_metadata(path) else {
        return false;
    };
    if !metadata.is_file() {
        return false;
    }
    std::fs::read(path)
        .ok()
        .and_then(|body| serde_json::from_slice::<serde_json::Value>(&body).ok())
        .and_then(|locator| locator.get("pid").and_then(serde_json::Value::as_u64))
        == Some(u64::from(pid))
}
