//! `rules.denialLog`: a Firestore Security Rules denial of an end-user request is answered with
//! production's `PERMISSION_DENIED`, which does not say which rule refused, so the daemon prints
//! the request and every `allow` condition it evaluated on stderr (owner decision 2026-10-13).

#![cfg(unix)]

#[path = "../../../tests/support/trusted_temp.rs"]
mod trusted_temp;

use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

use trusted_temp::TrustedTempDir;

const PROJECT: &str = "demo-denial-log";
const STORAGE_RULES: &str = "rules_version = '2';
service firebase.storage {
  match /b/{bucket}/o {
    match /private/{name} {
      allow read: if request.auth != null;
    }
  }
}
";
const RULES: &str = "rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /notes/{id} {
      allow read: if request.auth != null
                  && request.auth.uid == resource.data.owner;
    }
  }
}
";

fn http(port: u16, method: &str, path: &str) -> u16 {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("the daemon accepts");
    stream
        .set_read_timeout(Some(Duration::from_secs(20)))
        .unwrap();
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut raw = String::new();
    stream.read_to_string(&mut raw).unwrap();
    raw.lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse().ok())
        .unwrap_or(0)
}

struct Daemon {
    child: Child,
    stdout: Arc<Mutex<String>>,
    stderr: Arc<Mutex<String>>,
    _dir: TrustedTempDir,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn collect(stream: impl std::io::Read + Send + 'static, into: Arc<Mutex<String>>) {
    std::thread::spawn(move || {
        let mut reader = BufReader::new(stream);
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line).unwrap_or(0) == 0 {
                return;
            }
            into.lock().unwrap().push_str(&line);
        }
    });
}

impl Daemon {
    fn start(denial_log: Option<&str>) -> Self {
        let dir = TrustedTempDir::new("rules-denial-log");
        std::fs::write(dir.join("firestore.rules"), RULES).unwrap();
        std::fs::write(dir.join("storage.rules"), STORAGE_RULES).unwrap();
        let mut rules =
            serde_json::json!({"source": dir.join("firestore.rules").to_str().unwrap()});
        if let Some(value) = denial_log {
            rules["denialLog"] = serde_json::json!(value);
        }
        let config = dir.join("fireemu.json");
        std::fs::write(
            &config,
            serde_json::json!({
                "schemaVersion": 1,
                "profile": "strict",
                "rules": rules,
                "storage": {"rules": dir.join("storage.rules").to_str().unwrap()},
            })
            .to_string(),
        )
        .unwrap();
        let mut child = Command::new(env!("CARGO_BIN_EXE_fireemu"))
            .args([
                "up",
                "--config",
                config.to_str().unwrap(),
                "--project",
                PROJECT,
                "--only",
                "firestore,storage",
                "--firestore-port",
                "0",
                "--storage-port",
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
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let stdout = Arc::new(Mutex::new(String::new()));
        let stderr = Arc::new(Mutex::new(String::new()));
        collect(child.stdout.take().unwrap(), stdout.clone());
        collect(child.stderr.take().unwrap(), stderr.clone());
        let daemon = Self {
            child,
            stdout,
            stderr,
            _dir: dir,
        };
        let (tx, rx) = mpsc::channel();
        let watched = daemon.stdout.clone();
        std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(60);
            while Instant::now() < deadline {
                if watched.lock().unwrap().contains("control API:") {
                    let _ = tx.send(());
                    return;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        });
        assert!(
            rx.recv_timeout(Duration::from_secs(61)).is_ok(),
            "the daemon did not start: {}{}",
            daemon.stdout.lock().unwrap(),
            daemon.stderr.lock().unwrap()
        );
        daemon
    }

    fn firestore_port(&self) -> u16 {
        self.port("firestore (gRPC + REST):")
    }

    fn port(&self, label: &str) -> u16 {
        let banner = self.stdout.lock().unwrap().clone();
        let line = banner
            .lines()
            .find(|l| l.contains(label))
            .unwrap_or_else(|| panic!("the banner names {label}: {banner}"));
        line.split("127.0.0.1:")
            .nth(1)
            .and_then(|rest| rest.split_whitespace().next())
            .and_then(|port| port.parse().ok())
            .expect("a port")
    }

    /// Stderr once `needle` shows up, or after a short wait when it does not.
    fn stderr_after(&self, needle: &str) -> String {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let text = self.stderr.lock().unwrap().clone();
            if text.contains(needle) || Instant::now() >= deadline {
                return text;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

fn note_path() -> String {
    format!("/v1/projects/{PROJECT}/databases/(default)/documents/notes/n1")
}

#[test]
fn a_denied_request_is_printed_with_the_condition_that_refused_it() {
    let daemon = Daemon::start(None);
    let status = http(daemon.firestore_port(), "GET", &note_path());
    assert_eq!(status, 403);
    let stderr = daemon.stderr_after("Security Rules denied");
    let line = stderr
        .lines()
        .find(|l| l.contains("Security Rules denied"))
        .unwrap_or_else(|| panic!("no denial line: {stderr}"));
    assert!(
        line.starts_with("note: firestore: Security Rules denied get on notes/n1 in database (default) (no request.auth): no allow statement evaluated to true; line 5:"),
        "{line}"
    );
    assert!(
        line.contains(
            "`request.auth != null && request.auth.uid == resource.data.owner` was false"
        ),
        "{line}"
    );
}

#[test]
fn the_denial_log_can_be_turned_off() {
    let daemon = Daemon::start(Some("off"));
    let status = http(daemon.firestore_port(), "GET", &note_path());
    assert_eq!(status, 403);
    let bucket = format!("{PROJECT}.appspot.com");
    let status = http(
        daemon.port("storage (HTTP):"),
        "GET",
        &format!("/v0/b/{bucket}/o/private%2Fa.txt"),
    );
    assert_eq!(status, 403);
    let stderr = daemon.stderr_after("Security Rules denied");
    assert!(!stderr.contains("Security Rules denied"), "{stderr}");
}

#[test]
fn a_denied_storage_request_is_printed_with_the_condition_that_refused_it() {
    let daemon = Daemon::start(None);
    let port = daemon.port("storage (HTTP):");
    let bucket = format!("{PROJECT}.appspot.com");
    let status = http(port, "GET", &format!("/v0/b/{bucket}/o/private%2Fa.txt"));
    assert_eq!(status, 403);
    let stderr = daemon.stderr_after("storage: Security Rules denied");
    let line = stderr
        .lines()
        .find(|l| l.contains("storage: Security Rules denied"))
        .unwrap_or_else(|| panic!("no denial line: {stderr}"));
    assert!(
        line.starts_with(&format!("note: storage: Security Rules denied get on private/a.txt in bucket {bucket} (no request.auth): no allow statement evaluated to true; line 5:")),
        "{line}"
    );
    assert!(line.contains("`request.auth != null` was false"), "{line}");
}
