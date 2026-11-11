//! `rules.denialHistory`: the request trace starts at daemon start when enabled, keeps the
//! configured retention, and stays empty until a ruleset is replaced when disabled.

#![cfg(unix)]

#[path = "../../../tests/support/trusted_temp.rs"]
mod trusted_temp;

use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use trusted_temp::TrustedTempDir;

const PROJECT: &str = "demo-history";
const RULES: &str = "rules_version = '2'; service cloud.firestore { match /databases/{database}/documents { match /notes/{id} { allow read: if false; } } }";

/// One HTTP request to the local control API, returning the status and body.
fn http(port: u16, method: &str, path: &str, body: &str) -> (u16, String) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(20)))
        .unwrap();
    write!(stream, "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    let status = response
        .lines()
        .next()
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    (
        status,
        response.split_once("\r\n\r\n").unwrap().1.to_owned(),
    )
}

#[allow(dead_code)] // The temp directory is kept alive, not read.
struct Daemon(Child, TrustedTempDir);
impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn history_starts_at_daemon_start_only_when_enabled_and_survives_replacement() {
    for enabled in [true, false] {
        let dir = TrustedTempDir::new("rules-denial-history");
        std::fs::write(dir.join("firestore.rules"), RULES).unwrap();
        let config = dir.join("fireemu.json");
        std::fs::write(&config, serde_json::json!({"schemaVersion": 1, "profile": "strict", "rules": {"source": dir.join("firestore.rules").to_str().unwrap(), "denialHistory": {"enabled": enabled, "retention": 3}}}).to_string()).unwrap();
        let mut child = Command::new(env!("CARGO_BIN_EXE_fireemu"))
            .args([
                "up",
                "--config",
                config.to_str().unwrap(),
                "--project",
                PROJECT,
                "--only",
                "firestore",
                "--firestore-port",
                "0",
                "--http-port",
                "0",
                "--logging-port",
                "0",
                "--ui-port",
                "0",
                "--hub-port",
                "0",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let output = Arc::new(Mutex::new(String::new()));
        let watched = output.clone();
        let stdout = child.stdout.take().unwrap();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                {
                    let mut text = watched.lock().unwrap();
                    text.push_str(&line);
                    text.push('\n');
                }
            }
        });
        let daemon = Daemon(child, dir);
        let deadline = Instant::now() + Duration::from_secs(60);
        while !output.lock().unwrap().contains("control API:") && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        let banner = output.lock().unwrap().clone();
        let port = |label: &str| -> u16 {
            banner
                .lines()
                .find(|line| line.contains(label))
                .unwrap()
                .split("127.0.0.1:")
                .nth(1)
                .unwrap()
                .split(|c: char| !c.is_ascii_digit())
                .next()
                .unwrap()
                .parse()
                .unwrap()
        };
        let firestore = port("firestore (gRPC + REST):");
        let control = port("control API:");
        for n in 0..5 {
            assert_eq!(
                http(
                    firestore,
                    "GET",
                    &format!("/v1/projects/{PROJECT}/databases/(default)/documents/notes/{n}"),
                    ""
                )
                .0,
                403
            );
        }
        let route = "/v1/sessions/default/rules/requests";
        let (status, body) = http(control, "GET", route, "");
        assert_eq!(status, 200);
        let value: serde_json::Value = serde_json::from_str(&body).unwrap();
        if enabled {
            assert_eq!(value["historyEnabled"], true);
            assert_eq!(value["retention"], 3);
            assert_eq!(value["dropped"], 2);
            let paths: Vec<_> = value["requests"]
                .as_array()
                .unwrap()
                .iter()
                .map(|r| r["path"].as_str().unwrap())
                .collect();
            assert_eq!(paths, ["notes/4", "notes/3", "notes/2"]);
            let replacement = serde_json::json!({"source": RULES}).to_string();
            assert_eq!(http(control, "PUT", "/v1/rules", &replacement).0, 200);
            assert_eq!(
                http(
                    firestore,
                    "GET",
                    &format!("/v1/projects/{PROJECT}/databases/(default)/documents/notes/new"),
                    ""
                )
                .0,
                403
            );
            let value: serde_json::Value =
                serde_json::from_str(&http(control, "GET", route, "").1).unwrap();
            assert_eq!(value["requests"].as_array().unwrap().len(), 1);
            assert_eq!(value["requests"][0]["path"], "notes/new");
            assert_eq!(value["retention"], 3);
            assert_eq!(value["dropped"], 0);
            assert_eq!(value["historyEnabled"], true);
        } else {
            assert_eq!(value["requests"].as_array().unwrap().len(), 0);
        }
        drop(daemon);
    }
}
