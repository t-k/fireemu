//! Tests for per-process spill directories.

use std::fs;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use fireemu_core_storage::spill::{process_is_alive, sweep_stale, ProcessSpill};

#[test]
fn sweep_removes_only_dead_process_directories() {
    let root = std::env::temp_dir().join(format!(
        "spill-sweep-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&root).unwrap();
    let live = std::process::id();
    let dead = if live == 8 { 9 } else { 8 };
    let dead_dir = root.join(format!("fireemu-spill-{dead}"));
    let live_dir = root.join(format!("fireemu-spill-{live}"));
    fs::create_dir(&dead_dir).unwrap();
    fs::write(dead_dir.join("body"), b"body").unwrap();
    fs::create_dir(&live_dir).unwrap();
    fs::write(root.join("fireemu-spill-7"), b"file").unwrap();
    fs::create_dir(root.join("other-9")).unwrap();
    fs::create_dir(root.join("fireemu-spill-invalid")).unwrap();

    assert_eq!(sweep_stale(&root, |pid| pid == live).unwrap(), 1);
    assert!(!dead_dir.exists());
    assert!(live_dir.is_dir());
    assert!(root.join("fireemu-spill-7").is_file());
    assert!(root.join("other-9").is_dir());
    assert!(root.join("fireemu-spill-invalid").is_dir());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn spill_dir_keeps_process_directory_alive() {
    let root = std::env::temp_dir().join(format!(
        "spill-owner-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let process = ProcessSpill::create(&root).unwrap();
    let dir = process.path().to_owned();
    let spill = process.spill_dir();
    let clone = spill.clone();
    drop(process);
    assert!(dir.is_dir());
    drop(spill);
    assert!(dir.is_dir());
    drop(clone);
    assert!(!dir.exists());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn process_spill_removes_directory_and_file_on_drop() {
    let root = std::env::temp_dir().join(format!(
        "spill-drop-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let process = ProcessSpill::create(&root).unwrap();
    let dir = root.join(format!("fireemu-spill-{}", std::process::id()));
    assert_eq!(process.path(), dir);
    let mut file = process.spill_dir().create_file().unwrap();
    file.append(b"body").unwrap();
    let path = file.path().to_owned();
    assert!(path.is_file());
    drop(process);
    assert!(!dir.exists());
    assert!(!path.exists());
    drop(file);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn process_spill_cleans_previous_directory_with_same_pid() {
    let root = std::env::temp_dir().join(format!(
        "spill-leftover-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let process = ProcessSpill::create(&root).unwrap();
    let mut file = process.spill_dir().create_file().unwrap();
    file.append(b"body").unwrap();
    let old_path = file.path().to_owned();
    std::mem::forget(file);
    std::mem::forget(process);
    assert!(old_path.exists());
    let fresh = ProcessSpill::create(&root).unwrap();
    assert!(fresh.path().is_dir());
    assert!(!old_path.exists());
    drop(fresh);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn process_spill_removes_real_dead_process_directory() {
    let root = std::env::temp_dir().join(format!(
        "spill-dead-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let mut child = Command::new("true").spawn().unwrap();
    let pid = child.id();
    assert!(child.wait().unwrap().success());
    assert!(
        !process_is_alive(pid),
        "child pid {pid} is still reported alive after wait"
    );
    let stale = root.join(format!("fireemu-spill-{pid}"));
    fs::create_dir_all(&stale).unwrap();
    fs::write(stale.join("body"), b"body").unwrap();
    let process = ProcessSpill::create(&root).unwrap();
    assert!(!stale.exists());
    assert!(process.path().is_dir());
    drop(process);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn current_process_is_alive() {
    assert!(process_is_alive(std::process::id()));
}

#[test]
fn sweep_missing_root_succeeds() {
    let root = std::env::temp_dir().join(format!(
        "spill-missing-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    assert_eq!(sweep_stale(&root, |_| false).unwrap(), 0);
}
