//! Integration tests for CLI diagnostics dumps.
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
fn dump_without_daemon_names_url() {
    let dir = Scratch::new("dump", "offline");
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    drop(listener);
    let result = run(&dir, &["dump", "--out", "out", "--url", &url], "test-token");
    assert_eq!(result.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&result.stderr).contains(&url));
}

#[test]
fn dump_writes_redacted_bundle() {
    let dir = Scratch::new("dump", "redaction");
    let bearer = ["sentinel-", "bearer-0001"].concat();
    let oidc = ["sentinel-", "oidc-secret-0003"].concat();
    std::fs::write(dir.join("fireemu.json"), serde_json::json!({"schemaVersion":1,"pubsub":{"authentication":{"localBearerToken":bearer}},"auth":{"providers":{"oidc":[{"name":"oidc.fixture","enabled":true,"clientId":"visible-client-id","issuer":"https://issuer.test","clientSecret":oidc}]}}}).to_string()).unwrap();
    let (_daemon, url, token) = start(&dir);
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
    let json = std::fs::read_to_string(dir.join("out/bundle.json")).unwrap();
    let html = std::fs::read_to_string(dir.join("out/bundle.html")).unwrap();
    let value: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(value["schemaVersion"], 1);
    assert!(!value["config"].as_array().unwrap().is_empty());
    assert!(html.starts_with("<!doctype html>"));
    for text in [&json, &html] {
        assert!(!text.contains(&bearer));
        assert!(!text.contains(&oidc));
    }
}

#[test]
fn exec_dump_on_failure_and_success() {
    let dir = Scratch::new("dump", "exec");
    for (status, out) in [(3, "failed"), (0, "success")] {
        let script = format!("exit {status}");
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
                out,
                "--",
                "/bin/sh",
                "-c",
                &script,
            ],
            "unused",
        );
        assert_eq!(
            result.status.code(),
            Some(status),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        if status != 0 {
            assert!(dir.join(out).join("bundle.json").is_file());
            assert!(dir.join(out).join("bundle.html").is_file());
        } else {
            assert!(
                !dir.join(out).exists()
                    || std::fs::read_dir(dir.join(out)).unwrap().next().is_none()
            );
        }
    }
}

#[test]
fn dump_rejects_uncreatable_directory() {
    let dir = Scratch::new("dump", "bad-directory");
    std::fs::write(dir.join("fireemu.json"), "{\"schemaVersion\":1}").unwrap();
    std::fs::write(dir.join("blocker"), "file").unwrap();
    let (_daemon, url, token) = start(&dir);
    let result = run(
        &dir,
        &["dump", "--out", "blocker/out", "--url", &url],
        &token,
    );
    assert!(!result.status.success());
    assert!(!result.stderr.is_empty());
    assert!(!dir.join("blocker/out").exists());
}
