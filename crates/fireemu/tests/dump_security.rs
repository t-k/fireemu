//! Security tests for CLI diagnostics dumps.
#![cfg(unix)]

mod scratch;

use scratch::Scratch;
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

struct Daemon(Child);
impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn run(dir: &Scratch, args: &[&str], token: &str) -> Output {
    Command::new(env!("CARGO_BIN_EXE_fireemu"))
        .current_dir(dir)
        .args(args)
        .env("FIREEMU_CONTROL_TOKEN", token)
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

fn start(dir: &Scratch) -> (Daemon, String, String) {
    let child = Command::new(env!("CARGO_BIN_EXE_fireemu"))
        .current_dir(dir)
        .args([
            "up",
            "--config",
            "fireemu.json",
            "--only",
            "auth",
            "--http-port",
            "0",
            "--logging-port",
            "0",
            "--ui-port",
            "0",
            "--hub-port",
            "0",
            "--ready-file",
            "ready.json",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut daemon = Daemon(child);
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if let Ok(data) = std::fs::read(dir.join("ready.json")) {
            let value: serde_json::Value = serde_json::from_slice(&data).unwrap();
            return (
                daemon,
                value["controlUrl"].as_str().unwrap().to_owned(),
                value["controlToken"].as_str().unwrap().to_owned(),
            );
        }
        assert!(
            daemon.0.try_wait().unwrap().is_none(),
            "daemon exited before readiness"
        );
        assert!(Instant::now() < deadline, "daemon did not become ready");
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn refuses_symlinked_output_directory() {
    let dir = Scratch::new("dump-security", "directory-link");
    std::fs::write(dir.join("fireemu.json"), r#"{"schemaVersion":1}"#).unwrap();
    std::fs::create_dir(dir.join("target")).unwrap();
    std::os::unix::fs::symlink(dir.join("target"), dir.join("out")).unwrap();
    let (_daemon, url, token) = start(&dir);
    let result = run(&dir, &["dump", "--out", "out", "--url", &url], &token);
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("out"));
    assert!(std::fs::read_dir(dir.join("target"))
        .unwrap()
        .next()
        .is_none());
}

#[test]
fn refuses_symlinked_destination() {
    let dir = Scratch::new("dump-security", "file-link");
    std::fs::write(dir.join("fireemu.json"), r#"{"schemaVersion":1}"#).unwrap();
    std::fs::create_dir(dir.join("out")).unwrap();
    let original = ["outside-", "content"].concat();
    std::fs::write(dir.join("target"), &original).unwrap();
    std::os::unix::fs::symlink(dir.join("target"), dir.join("out/bundle.json")).unwrap();
    let (_daemon, url, token) = start(&dir);
    for extra in [vec![], vec!["--force"]] {
        let mut args = vec!["dump", "--out", "out", "--url", &url];
        args.extend(extra);
        let result = run(&dir, &args, &token);
        assert!(!result.status.success());
        assert!(String::from_utf8_lossy(&result.stderr).contains("bundle.json"));
        assert_eq!(
            std::fs::read_to_string(dir.join("target")).unwrap(),
            original
        );
        assert!(!dir.join("out/bundle.html").exists());
    }
}

#[test]
fn existing_file_requires_force() {
    let dir = Scratch::new("dump-security", "overwrite");
    std::fs::write(dir.join("fireemu.json"), r#"{"schemaVersion":1}"#).unwrap();
    std::fs::create_dir(dir.join("out")).unwrap();
    let original = ["existing-", "content"].concat();
    std::fs::write(dir.join("out/bundle.json"), &original).unwrap();
    let (_daemon, url, token) = start(&dir);
    let args = ["dump", "--out", "out", "--url", &url];
    let result = run(&dir, &args, &token);
    assert!(!result.status.success());
    assert_eq!(
        std::fs::read_to_string(dir.join("out/bundle.json")).unwrap(),
        original
    );
    assert!(!dir.join("out/bundle.html").exists());
    let result = run(
        &dir,
        &["dump", "--out", "out", "--url", &url, "--force"],
        &token,
    );
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_ne!(
        std::fs::read_to_string(dir.join("out/bundle.json")).unwrap(),
        original
    );
}

#[test]
fn creates_private_artifacts() {
    use std::os::unix::fs::PermissionsExt;
    let dir = Scratch::new("dump-security", "permissions");
    std::fs::write(dir.join("fireemu.json"), r#"{"schemaVersion":1}"#).unwrap();
    let (_daemon, url, token) = start(&dir);
    let result = run(&dir, &["dump", "--out", "out", "--url", &url], &token);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    for (path, mode) in [
        ("out", 0o700),
        ("out/bundle.json", 0o600),
        ("out/bundle.html", 0o600),
    ] {
        assert_eq!(
            std::fs::metadata(dir.join(path))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            mode
        );
    }
}

#[test]
fn both_formats_include_local_redacted_config() {
    let dir = Scratch::new("dump-security", "config");
    let bearer = ["sentinel-", "bearer-0001"].concat();
    let client = ["visible-", "client-id"].concat();
    std::fs::write(dir.join("fireemu.json"), serde_json::json!({"schemaVersion":1,"pubsub":{"authentication":{"localBearerToken":bearer}},"daemon":{"authProject":client}}).to_string()).unwrap();
    let (_daemon, url, token) = start(&dir);
    let show = run(
        &dir,
        &["config", "show", "--config", "fireemu.json", "--json"],
        &token,
    );
    assert!(
        show.status.success(),
        "{}",
        String::from_utf8_lossy(&show.stderr)
    );
    let result = run(
        &dir,
        &[
            "dump",
            "--out",
            "out",
            "--url",
            &url,
            "--config",
            "fireemu.json",
        ],
        &token,
    );
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let rows: serde_json::Value = serde_json::from_slice(&show.stdout).unwrap();
    let bundle: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.join("out/bundle.json")).unwrap()).unwrap();
    let html = std::fs::read_to_string(dir.join("out/bundle.html")).unwrap();
    for key in [
        "pubsub.authentication.localBearerToken",
        "daemon.authProject",
    ] {
        let expected = &rows
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["key"] == key)
            .unwrap()["value"];
        let actual = &bundle["config"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row[0] == key)
            .unwrap()[1];
        assert_eq!(actual, expected);
        assert!(html.contains(expected.as_str().unwrap()));
    }
    assert!(!html.contains(&bearer));
}

#[test]
fn refuses_html_symlink_before_writing_json() {
    let dir = Scratch::new("dump-security", "html-link");
    std::fs::write(dir.join("fireemu.json"), r#"{"schemaVersion":1}"#).unwrap();
    std::fs::create_dir(dir.join("out")).unwrap();
    let original = ["outside-", "html"].concat();
    std::fs::write(dir.join("target"), &original).unwrap();
    std::os::unix::fs::symlink(dir.join("target"), dir.join("out/bundle.html")).unwrap();
    let (_daemon, url, token) = start(&dir);
    let result = run(
        &dir,
        &["dump", "--out", "out", "--url", &url, "--force"],
        &token,
    );
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("bundle.html"));
    assert_eq!(
        std::fs::read_to_string(dir.join("target")).unwrap(),
        original
    );
    assert!(!dir.join("out/bundle.json").exists());
}

#[test]
fn exec_preserves_child_status_when_dump_is_refused() {
    let dir = Scratch::new("dump-security", "exec-refusal");
    std::fs::create_dir(dir.join("target")).unwrap();
    std::os::unix::fs::symlink(dir.join("target"), dir.join("out")).unwrap();
    let result = run(
        &dir,
        &[
            "exec",
            "--only",
            "auth",
            "--http-port",
            "0",
            "--logging-port",
            "0",
            "--hub-port",
            "0",
            "--dump-on-failure",
            "out",
            "--",
            "/bin/sh",
            "-c",
            "exit 3",
        ],
        "unused",
    );
    assert_eq!(result.status.code(), Some(3));
    assert!(std::fs::read_dir(dir.join("target"))
        .unwrap()
        .next()
        .is_none());
}
