//! Export destination diagnostics run before user work and never modify the namespace.
#![cfg(unix)]

use std::os::unix::fs::PermissionsExt as _;
use std::process::{Command, Stdio};

#[path = "../../../tests/support/trusted_temp.rs"]
mod trusted_temp;
use trusted_temp::TrustedTempDir;

#[test]
fn unsafe_export_ancestor_is_rejected_before_the_child_runs() {
    let root = TrustedTempDir::new("export-preflight-cli");
    let marker = root.join("child-ran");
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o775)).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_fireemu"))
        .args([
            "exec",
            "--no-config-discovery",
            "--only",
            "auth",
            "--http-port",
            "0",
            "--ui-port",
            "0",
            "--hub-port",
            "0",
            "--logging-port",
            "0",
            "--export-on-exit",
        ])
        .arg(root.join("missing/export"))
        .args(["--", "touch"])
        .arg(&marker)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("namespace ancestor"),
        "{output:?}"
    );
    assert!(!marker.exists(), "child ran before export validation");
    assert!(!root.join("missing").exists());
}

#[test]
fn doctor_export_inspection_accepts_missing_paths_without_creating_them() {
    let root = TrustedTempDir::new("export-doctor-missing");
    let target = root.join("missing/export");
    let output = Command::new(env!("CARGO_BIN_EXE_fireemu"))
        .args(["doctor", "--export-dir"])
        .arg(&target)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stdout).contains("export destination"));
    assert!(!root.join("missing").exists());
}

#[test]
fn doctor_export_inspection_rejects_unsafe_ancestors_and_unmanaged_contents() {
    let root = TrustedTempDir::new("export-doctor-refusal");
    let target = root.join("export");
    std::fs::create_dir(&target).unwrap();
    std::fs::write(target.join("notes.txt"), "keep").unwrap();
    for unsafe_mode in [true, false] {
        let mode = if unsafe_mode { 0o775 } else { 0o700 };
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(mode)).unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_fireemu"))
            .args(["doctor", "--export-dir"])
            .arg(&target)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(!output.status.success());
        let expected = if unsafe_mode {
            "namespace ancestor"
        } else {
            "not an export directory"
        };
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(expected),
            "{output:?}"
        );
        assert_eq!(
            std::fs::read_to_string(target.join("notes.txt")).unwrap(),
            "keep"
        );
    }
}
