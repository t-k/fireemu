//! `auth.allowUnsignedIdTokens` through the real listeners of a daemon started the way a
//! project starts it (owner ledger 1393): the configuration reaches both Security Rules
//! surfaces, Firestore and Storage, in both profiles.
//!
//! The token is the one `@firebase/rules-unit-testing`'s `authenticatedContext("alice")` sends
//! (`createMockUserToken`, `@firebase/util`): header `{"alg":"none","type":"JWT"}`, `iat: 0`,
//! `exp: 3600`, a subject no Auth account has, and an empty signature.

#![cfg(unix)]

#[path = "../../../tests/support/trusted_temp.rs"]
mod trusted_temp;

use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Value};
use trusted_temp::TrustedTempDir;

const PROJECT: &str = "demo-unsigned-id";
const FIRESTORE_RULES: &str = "rules_version = '2';\nservice cloud.firestore {\n  match /databases/{database}/documents {\n    match /owned/{uid} {\n      allow read: if request.auth != null && request.auth.uid == uid;\n    }\n  }\n}\n";
const STORAGE_RULES: &str = "rules_version = '2';\nservice firebase.storage {\n  match /b/{bucket}/o {\n    match /users/{uid}/{path=**} {\n      allow read: if request.auth != null && request.auth.uid == uid;\n    }\n  }\n}\n";

fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

fn http(port: u16, method: &str, path: &str, authorization: Option<&str>) -> (u16, String) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("the daemon accepts");
    stream
        .set_read_timeout(Some(Duration::from_secs(20)))
        .unwrap();
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n"
    )
    .unwrap();
    if let Some(value) = authorization {
        write!(stream, "Authorization: {value}\r\n").unwrap();
    }
    write!(stream, "Content-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
    stream.flush().unwrap();
    let mut raw = String::new();
    stream.read_to_string(&mut raw).unwrap();
    let (head, body) = raw.split_once("\r\n\r\n").unwrap_or((raw.as_str(), ""));
    let status = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    (status, body.to_owned())
}

fn b64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let mut buf = [0u8; 3];
        buf[..chunk.len()].copy_from_slice(chunk);
        let bits = (u32::from(buf[0]) << 16) | (u32::from(buf[1]) << 8) | u32::from(buf[2]);
        for i in 0..=chunk.len() {
            out.push(ALPHABET[((bits >> (18 - i * 6)) & 0x3F) as usize] as char);
        }
    }
    out
}

fn mock_payload(sub: &str) -> String {
    json!({
        "iss": format!("https://securetoken.google.com/{PROJECT}"),
        "aud": PROJECT,
        "iat": 0,
        "exp": 3600,
        "auth_time": 0,
        "sub": sub,
        "user_id": sub,
        "firebase": {"sign_in_provider": "custom", "identities": {}},
    })
    .to_string()
}

fn mock_user_token(sub: &str) -> String {
    format!(
        "{}.{}.",
        b64url(br#"{"alg":"none","type":"JWT"}"#),
        b64url(mock_payload(sub).as_bytes())
    )
}

fn tampered_rs256(sub: &str) -> String {
    format!(
        "{}.{}.{}",
        b64url(br#"{"alg":"RS256","kid":"k1","typ":"JWT"}"#),
        b64url(mock_payload(sub).as_bytes()),
        b64url(b"not a signature")
    )
}

struct Daemon {
    child: Child,
    hub_port: u16,
    _dir: TrustedTempDir,
}

impl Daemon {
    /// A daemon under `profile`, with `auth` as its `auth` configuration section.
    fn start(profile: &str, auth: &Value) -> Self {
        let dir = TrustedTempDir::new("unsigned-id-tokens");
        std::fs::write(dir.join("firestore.rules"), FIRESTORE_RULES).unwrap();
        std::fs::write(dir.join("storage.rules"), STORAGE_RULES).unwrap();
        let firebase_json = dir.join("firebase.json");
        std::fs::write(
            &firebase_json,
            json!({"firestore": {"rules": "firestore.rules"}, "storage": {"rules": "storage.rules"}})
                .to_string(),
        )
        .unwrap();
        let config = dir.join("fireemu.json");
        std::fs::write(
            &config,
            json!({"schemaVersion": 1, "profile": profile, "auth": auth}).to_string(),
        )
        .unwrap();
        let hub_port = free_port();
        let mut child = Command::new(env!("CARGO_BIN_EXE_fireemu"))
            .args([
                "up",
                "--config",
                config.to_str().unwrap(),
                "--firebase-json",
                firebase_json.to_str().unwrap(),
                "--project",
                PROJECT,
                "--only",
                "auth,firestore,storage",
                "--firestore-port",
                "0",
                "--http-port",
                "0",
                "--storage-port",
                "0",
                "--logging-port",
                "0",
                "--ui-port",
                "0",
                "--hub-port",
            ])
            .arg(hub_port.to_string())
            .env("TMPDIR", dir.path())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let stderr = child.stderr.take().unwrap();
        // The child is owned (and killed on drop) before anything below can panic.
        let daemon = Self {
            child,
            hub_port,
            _dir: dir,
        };
        let transcript = Arc::new(Mutex::new(String::new()));
        let collected = Arc::clone(&transcript);
        let (tx, rx) = mpsc::channel::<()>();
        std::thread::spawn(move || {
            let mut reader = BufReader::new(stdout);
            let mut ready = Some(tx);
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or(0) == 0 {
                    return;
                }
                collected.lock().unwrap().push_str(&line);
                if line.contains("control API:") {
                    if let Some(tx) = ready.take() {
                        let _ = tx.send(());
                    }
                }
            }
        });
        let errors = Arc::clone(&transcript);
        std::thread::spawn(move || {
            let mut reader = BufReader::new(stderr);
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or(0) == 0 {
                    return;
                }
                errors.lock().unwrap().push_str(&line);
            }
        });
        assert!(
            rx.recv_timeout(Duration::from_secs(60)).is_ok(),
            "the daemon did not become ready:\n{}",
            transcript.lock().unwrap()
        );
        daemon
    }

    fn port(&self, name: &str) -> u16 {
        let (status, body) = http(self.hub_port, "GET", "/emulators", None);
        assert_eq!(status, 200, "{body}");
        let emulators: Value = serde_json::from_str(&body).unwrap();
        u16::try_from(emulators[name]["port"].as_u64().unwrap()).unwrap()
    }

    /// A Firestore read of the missing `owned/<owner>` document: 404 when the rule admits the
    /// caller.
    fn firestore_read(&self, owner: &str, token: &str) -> (u16, String) {
        http(
            self.port("firestore"),
            "GET",
            &format!("/v1/projects/{PROJECT}/databases/(default)/documents/owned/{owner}"),
            Some(&format!("Bearer {token}")),
        )
    }

    /// A Storage metadata read of the missing `users/<owner>/a.txt`: 404 when the rule admits
    /// the caller.
    fn storage_read(&self, owner: &str, token: &str) -> (u16, String) {
        http(
            self.port("storage"),
            "GET",
            &format!("/v0/b/{PROJECT}.appspot.com/o/users%2F{owner}%2Fa.txt"),
            Some(&format!("Firebase {token}")),
        )
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn the_strict_default_admits_the_rules_unit_testing_token_on_both_surfaces() {
    let daemon = Daemon::start("strict", &json!({}));
    let alice = mock_user_token("alice");
    let (status, body) = daemon.firestore_read("alice", &alice);
    assert_eq!(status, 404, "{body}");
    let (status, body) = daemon.firestore_read("bob", &alice);
    assert_eq!(
        status, 403,
        "the rule still sees the token's subject: {body}"
    );
    let (status, body) = daemon.storage_read("alice", &alice);
    assert_eq!(status, 404, "{body}");
    let (status, body) = daemon.storage_read("bob", &alice);
    assert_eq!(status, 403, "{body}");

    // A token that claims a signature that does not verify is refused as before.
    let forged = tampered_rs256("alice");
    let (status, body) = daemon.firestore_read("alice", &forged);
    assert_eq!(status, 403, "{body}");
    assert!(
        body.contains("Missing or insufficient permissions."),
        "{body}"
    );
    let (status, body) = daemon.storage_read("alice", &forged);
    assert_eq!(status, 401, "{body}");
}

#[test]
fn strict_with_the_setting_off_refuses_as_production_does() {
    let daemon = Daemon::start("strict", &json!({"allowUnsignedIdTokens": false}));
    let alice = mock_user_token("alice");
    let (status, body) = daemon.firestore_read("alice", &alice);
    assert_eq!(status, 401, "{body}");
    assert!(
        body.contains("Missing or invalid authentication."),
        "{body}"
    );
    let (status, body) = daemon.storage_read("alice", &alice);
    assert_eq!(status, 401, "{body}");
    assert!(body.contains("invalid ID token: token expired"), "{body}");
}

#[test]
fn the_emulator_profile_default_is_unchanged() {
    let daemon = Daemon::start("emulator", &json!({}));
    let alice = mock_user_token("alice");
    assert_eq!(daemon.firestore_read("alice", &alice).0, 404);
    assert_eq!(daemon.firestore_read("bob", &alice).0, 403);
    assert_eq!(daemon.storage_read("alice", &alice).0, 404);
    assert_eq!(daemon.storage_read("bob", &alice).0, 403);
}
