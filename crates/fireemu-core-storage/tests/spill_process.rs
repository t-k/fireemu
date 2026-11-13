//! Tests for per-process spill directories.
#![cfg(unix)]

use fireemu_core_storage::spill::{process_state, sweep_stale, ProcessSpill, ProcessState};
use std::fs::{self, DirBuilder};
use std::os::unix::fs::{symlink, DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

fn root() -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "spill-test-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    DirBuilder::new().mode(0o700).create(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    path
}

fn marked(root: &Path, pid: u32, start: &str) -> PathBuf {
    let path = root.join(format!("fireemu-spill-{pid}"));
    fs::create_dir(&path).unwrap();
    fs::write(
        path.join("fireemu-owner"),
        format!("fireemu-spill-owner v1\npid {pid}\nstart {start}\n"),
    )
    .unwrap();
    path
}

#[test]
fn permissions_and_owner_lifetime() {
    let root = root();
    let process = ProcessSpill::create(&root).unwrap();
    let path = process.path().to_owned();
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o700
    );
    let dir = process.spill_dir();
    let file = dir.create_file().unwrap();
    assert_eq!(
        fs::metadata(file.path()).unwrap().permissions().mode() & 0o777,
        0o600
    );
    drop(process);
    assert!(path.exists());
    drop(file);
    drop(dir);
    assert!(!path.exists());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn rejects_symlink_and_writable_roots() {
    let root = root();
    let target = root.join("target");
    fs::create_dir(&target).unwrap();
    let link = root.join("link");
    symlink(&target, &link).unwrap();
    assert!(ProcessSpill::create(&link).is_err());
    assert_eq!(fs::read_dir(&target).unwrap().count(), 0);
    fs::set_permissions(&target, fs::Permissions::from_mode(0o777)).unwrap();
    assert!(ProcessSpill::create(&target).is_err());
    assert_eq!(fs::read_dir(&target).unwrap().count(), 0);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn sweep_requires_valid_identity_and_process_evidence() {
    let root = root();
    let absent = marked(&root, 1, "old");
    let same = marked(&root, 2, "same");
    let reused = marked(&root, 3, "old");
    let unknown = marked(&root, 4, "old");
    let unknown_start = marked(&root, 5, "unknown");
    let missing = root.join("fireemu-spill-6");
    fs::create_dir(&missing).unwrap();
    let mismatch = marked(&root, 9, "old");
    fs::write(
        mismatch.join("fireemu-owner"),
        "fireemu-spill-owner v1\npid 10\nstart old\n",
    )
    .unwrap();
    let file = root.join("fireemu-spill-7");
    fs::write(&file, b"file").unwrap();
    let target = root.join("target");
    fs::create_dir(&target).unwrap();
    fs::write(target.join("body"), b"body").unwrap();
    let link = root.join("fireemu-spill-8");
    symlink(&target, &link).unwrap();
    assert_eq!(
        sweep_stale(&root, |pid| match pid {
            2 => ProcessState::Running {
                start: "same".into()
            },
            3 => ProcessState::Running {
                start: "new".into()
            },
            4 => ProcessState::Unknown,
            _ => ProcessState::Absent,
        })
        .unwrap(),
        1
    );
    assert!(!absent.exists());
    for path in [
        &same,
        &reused,
        &unknown,
        &unknown_start,
        &missing,
        &mismatch,
        &file,
        &link,
        &target.join("body"),
    ] {
        assert!(path.exists());
    }
    assert!(fs::symlink_metadata(link).unwrap().file_type().is_symlink());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn live_directory_survives_different_timezone_and_locale() {
    if let Some(root) = std::env::var_os("FIREEMU_SPILL_TEST_ROOT") {
        let root = PathBuf::from(root);
        let pid: u32 = std::env::var("FIREEMU_SPILL_TEST_PID")
            .unwrap()
            .parse()
            .unwrap();
        let ProcessState::Running { start } = process_state(pid) else {
            panic!("parent process start time is unavailable");
        };
        let marker =
            fs::read_to_string(root.join(format!("fireemu-spill-{pid}/fireemu-owner"))).unwrap();
        assert!(marker.lines().any(|line| line == format!("start {start}")));
        assert_eq!(sweep_stale(&root, process_state).unwrap(), 0);
        assert!(root.join(format!("fireemu-spill-{pid}")).exists());
        return;
    }
    let root = root();
    let process = ProcessSpill::create(&root).unwrap();
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "live_directory_survives_different_timezone_and_locale",
        ])
        .env("FIREEMU_SPILL_TEST_ROOT", &root)
        .env("FIREEMU_SPILL_TEST_PID", std::process::id().to_string())
        .env("TZ", "Pacific/Honolulu")
        .env("LANG", "fr_FR.UTF-8")
        .env_remove("LC_ALL")
        .status()
        .unwrap();
    assert!(status.success());
    assert!(process.path().exists());
    drop(process);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn forgotten_same_pid_directory_is_replaced() {
    let root = root();
    let process = ProcessSpill::create(&root).unwrap();
    let file = process.spill_dir().create_file().unwrap();
    let path = file.path().to_owned();
    std::mem::forget(file);
    std::mem::forget(process);
    let fresh = ProcessSpill::create(&root).unwrap();
    assert!(!path.exists());
    drop(fresh);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn current_process_is_never_absent() {
    match process_state(std::process::id()) {
        ProcessState::Running { start } => assert_ne!(start, ""),
        ProcessState::Unknown => {}
        ProcessState::Absent => panic!("current process is absent"),
    }
}

#[test]
fn sweep_missing_root_succeeds() {
    let root = root();
    fs::remove_dir(&root).unwrap();
    assert_eq!(sweep_stale(&root, |_| ProcessState::Absent).unwrap(), 0);
}
