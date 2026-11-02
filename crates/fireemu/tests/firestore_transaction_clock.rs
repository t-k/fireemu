//! A Firestore transaction on a daemon whose clock is not pinned expires on its own age, over
//! the real control API and REST surface: the sequence of the issue, end to end.
//!
//! Firestore stamps transactions on the wall clock there while `clock:advance` moves the session
//! clock, so the daemon's clock hook must turn an advance into age for the transactions alive
//! during it; an advance made before a transaction began must not count.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use serde_json::{json, Value};

const PROJECT: &str = "demo-txnclock";

fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

struct Daemon {
    child: Child,
    control: u16,
    firestore: u16,
    config: PathBuf,
    _stdout: BufReader<std::process::ChildStdout>,
}

impl Daemon {
    /// Starts `fireemu up` in `profile` with an unpinned clock (no `daemon.clockStart`).
    fn start(profile: &str) -> Self {
        let config = std::env::temp_dir().join(format!(
            "fireemu-txnclock-{profile}-{}.json",
            std::process::id()
        ));
        std::fs::write(
            &config,
            json!({"schemaVersion": 1, "profile": profile}).to_string(),
        )
        .unwrap();
        let firestore = free_port();
        let mut child = Command::new(env!("CARGO_BIN_EXE_fireemu"))
            .args(["up", "--config"])
            .arg(&config)
            .args([
                "--project",
                PROJECT,
                "--only",
                "firestore",
                "--firestore-port",
                &firestore.to_string(),
                "--http-port",
                "0",
                "--ui-port",
                "0",
                "--logging-port",
                "0",
                "--hub-port",
                "0",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("the daemon binary starts");
        let mut reader = BufReader::new(child.stdout.take().unwrap());
        let mut banner = String::new();
        let mut control = None;
        for _ in 0..80 {
            let mut line = String::new();
            if reader.read_line(&mut line).unwrap_or(0) == 0 {
                break;
            }
            banner.push_str(&line);
            if line.trim_start().starts_with("control API:") {
                control = line
                    .split("http://127.0.0.1:")
                    .nth(1)
                    .and_then(|rest| rest.split(|c: char| !c.is_ascii_digit()).next())
                    .and_then(|digits| digits.parse().ok());
                break;
            }
        }
        let Some(control) = control else {
            let _ = child.kill();
            let _ = child.wait();
            let _ = std::fs::remove_file(&config);
            panic!("the daemon printed no control API line:\n{banner}");
        };
        Self {
            child,
            control,
            firestore,
            config,
            _stdout: reader,
        }
    }

    fn advance(&self, seconds: i64) {
        let (status, body) = http(
            self.control,
            "POST",
            "/v1/sessions/default/clock:advance",
            &json!({ "seconds": seconds }),
        );
        assert_eq!(status, 200, "clock:advance {seconds}: {body}");
    }

    fn firestore(&self, path: &str, body: &Value) -> (u16, Value) {
        http(
            self.firestore,
            "POST",
            &format!("/v1/projects/{PROJECT}/databases/(default)/documents{path}"),
            body,
        )
    }

    /// Begins a read-write transaction, reads in it, lets `idle` seconds pass on the session
    /// clock and commits a write with it; returns the commit's HTTP status and body.
    fn commit_after_idle(&self, idle: i64) -> (u16, Value) {
        let (status, begun) = self.firestore(":beginTransaction", &json!({}));
        assert_eq!(status, 200, "{begun}");
        let transaction = begun["transaction"].as_str().unwrap().to_owned();
        let (status, read) = self.firestore(
            ":batchGet",
            &json!({
                "documents": [format!("projects/{PROJECT}/databases/(default)/documents/items/a")],
                "transaction": transaction,
            }),
        );
        assert_eq!(status, 200, "{read}");
        self.advance(idle);
        self.firestore(
            ":commit",
            &json!({
                "transaction": transaction,
                "writes": [{"update": {
                    "name": format!("projects/{PROJECT}/databases/(default)/documents/items/a"),
                    "fields": {"v": {"integerValue": idle.to_string()}},
                }}],
            }),
        )
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.config);
    }
}

fn http(port: u16, method: &str, path: &str, body: &Value) -> (u16, Value) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(60)))
        .unwrap();
    let body = body.to_string();
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer owner\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .unwrap();
    let mut raw = String::new();
    stream.read_to_string(&mut raw).unwrap();
    let (head, body) = raw.split_once("\r\n\r\n").expect("a header block");
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .expect("a status line");
    let body = body.trim();
    // A chunked body carries its size lines; the JSON starts at the first brace.
    let json = body
        .find(['{', '['])
        .and_then(|start| serde_json::from_str(&body[start..=body.rfind(['}', ']']).unwrap()]).ok())
        .unwrap_or_else(|| Value::String(body.to_owned()));
    (status, json)
}

/// The issue's matrix: 0, 130 and then 400 more seconds advanced before the begin, a 5 s-old
/// transaction commits in both profiles.
#[test]
fn a_transaction_begun_after_clock_advances_commits_on_its_own_age() {
    for profile in ["strict", "emulator"] {
        let daemon = Daemon::start(profile);
        for before in [0, 130, 400] {
            daemon.advance(before.max(1));
            let (status, body) = daemon.commit_after_idle(5);
            assert_eq!(
                status, 200,
                "{profile}, {before} s advanced before the begin: {body}"
            );
        }
    }
}

/// An advance made while the transaction lives still expires it past the idle limit (strict
/// 120 s, emulator 60 s), after earlier advances as well.
#[test]
fn a_transaction_still_expires_when_the_clock_passes_its_idle_limit() {
    for (profile, limit) in [("strict", 120), ("emulator", 60)] {
        let daemon = Daemon::start(profile);
        daemon.advance(400);
        let (status, body) = daemon.commit_after_idle(limit + 5);
        assert!(
            status == 409 || status == 400,
            "{profile}: idle {} s committed: {status} {body}",
            limit + 5
        );
        let (status, body) = daemon.commit_after_idle(limit - 5);
        assert_eq!(status, 200, "{profile}: idle {} s: {body}", limit - 5);
    }
}
