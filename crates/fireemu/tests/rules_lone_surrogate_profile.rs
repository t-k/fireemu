//! `string-escape#esc-high` (recorded in production on 2026-11-08): `"é🔥x"[1] == "\ud83d"` is
//! false in production and true in the official emulator, so the strict profile denies and the
//! emulator profile allows, on the Firestore and the Storage Rules the daemon loads at start.

#![cfg(unix)]

#[path = "../../../tests/support/trusted_temp.rs"]
mod trusted_temp;

use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

use trusted_temp::TrustedTempDir;

const PROJECT: &str = "demo-lone-surrogate";
const STORAGE_RULES: &str = r#"rules_version = '2';
service firebase.storage {
  match /b/{bucket}/o {
    match /private/{name} {
      allow read: if "é🔥x"[1] == "\ud83d";
    }
  }
}
"#;
const RULES: &str = r#"rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /notes/{id} {
      allow read: if "é🔥x"[1] == "\ud83d";
    }
  }
}
"#;

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
    fn start(profile: &str) -> Self {
        let dir = TrustedTempDir::new("rules-lone-surrogate");
        std::fs::write(dir.join("firestore.rules"), RULES).unwrap();
        std::fs::write(dir.join("storage.rules"), STORAGE_RULES).unwrap();
        std::fs::write(
            dir.join("firebase.json"),
            r#"{"firestore": [{"database": "(default)", "rules": "firestore.rules"}, {"database": "named-db", "rules": "firestore.rules"}]}"#,
        )
        .unwrap();
        let config = dir.join("fireemu.json");
        std::fs::write(
            &config,
            serde_json::json!({
                "schemaVersion": 1,
                "profile": profile,
                "firebaseJson": "firebase.json",
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
}

#[test]
fn the_emulator_profile_allows_what_the_official_emulator_allows() {
    let daemon = Daemon::start("emulator");
    let note = format!("/v1/projects/{PROJECT}/databases/(default)/documents/notes/n1");
    // Allowed by the rule: the document is not there.
    assert_eq!(
        http(daemon.port("firestore (gRPC + REST):"), "GET", &note),
        404
    );
    // A database declared in firebase.json has a ruleset of its own.
    let named = format!("/v1/projects/{PROJECT}/databases/named-db/documents/notes/n1");
    assert_eq!(
        http(daemon.port("firestore (gRPC + REST):"), "GET", &named),
        404
    );
    let object = format!("/v0/b/{PROJECT}.appspot.com/o/private%2Fa.txt");
    assert_eq!(http(daemon.port("storage (HTTP):"), "GET", &object), 404);
}

#[test]
fn the_strict_profile_denies_as_production_does() {
    let daemon = Daemon::start("strict");
    let note = format!("/v1/projects/{PROJECT}/databases/(default)/documents/notes/n1");
    assert_eq!(
        http(daemon.port("firestore (gRPC + REST):"), "GET", &note),
        403
    );
    let named = format!("/v1/projects/{PROJECT}/databases/named-db/documents/notes/n1");
    assert_eq!(
        http(daemon.port("firestore (gRPC + REST):"), "GET", &named),
        403
    );
    let object = format!("/v0/b/{PROJECT}.appspot.com/o/private%2Fa.txt");
    assert_eq!(http(daemon.port("storage (HTTP):"), "GET", &object), 403);
}
