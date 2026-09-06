//! Email enumeration protection follows production's default: a daemon started without
//! `auth.improvedEmailPrivacy` answers a wrong password and an unknown address alike, and
//! acknowledges a password reset for an address it does not know. Switching the key off
//! restores the official Auth emulator's revealing answers.

mod census;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Value};

fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "fireemu-auth-privacy-{name}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn http(port: u16, method: &str, path: &str, body: &Value) -> (u16, Value) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("the daemon accepts");
    stream
        .set_read_timeout(Some(Duration::from_secs(20)))
        .unwrap();
    let body = body.to_string();
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .unwrap();
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
    (status, serde_json::from_str(body).unwrap_or(Value::Null))
}

struct Daemon {
    child: Child,
    _banner: Arc<Mutex<String>>,
    hub_port: u16,
}

impl Daemon {
    fn start(name: &str, auth: &Value) -> Self {
        let dir = scratch(name);
        let config = dir.join("fireemu.json");
        std::fs::write(
            &config,
            json!({"schemaVersion": 1, "profile": "strict", "auth": auth}).to_string(),
        )
        .unwrap();
        let hub_port = free_port();
        let mut child = Command::new(env!("CARGO_BIN_EXE_fireemu"))
            .args([
                "up",
                "--config",
                config.to_str().unwrap(),
                "--project",
                &format!("demo-{name}"),
                "--only",
                "auth",
                "--firestore-port",
                "0",
                "--http-port",
                "0",
                "--storage-port",
                "0",
                "--functions-port",
                "0",
                "--pubsub-port",
                "0",
                "--logging-port",
                "0",
                "--ui-port",
                "0",
                "--hub-port",
            ])
            .arg(hub_port.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let banner = Arc::new(Mutex::new(String::new()));
        let collected = Arc::clone(&banner);
        let (tx, rx) = std::sync::mpsc::channel::<()>();
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
        rx.recv_timeout(Duration::from_secs(60))
            .expect("the daemon became ready");
        Self {
            child,
            _banner: banner,
            hub_port,
        }
    }

    fn auth_port(&self) -> u16 {
        let (status, emulators) = http(self.hub_port, "GET", "/emulators", &Value::Null);
        assert_eq!(status, 200, "{emulators}");
        u16::try_from(emulators["auth"]["port"].as_u64().unwrap()).unwrap()
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

const V1: &str = "/identitytoolkit.googleapis.com/v1";

/// Signs one account up, then reports the codes of a wrong password, an unknown address and
/// a password reset for an unknown address.
fn probe(daemon: &Daemon) -> (String, String, u16) {
    let port = daemon.auth_port();
    let (status, body) = http(
        port,
        "POST",
        &format!("{V1}/accounts:signUp?key=fake-api-key"),
        &json!({"email": "known@example.com", "password": "hunter22", "returnSecureToken": true}),
    );
    assert_eq!(status, 200, "{body}");
    let (_, wrong) = http(
        port,
        "POST",
        &format!("{V1}/accounts:signInWithPassword?key=fake-api-key"),
        &json!({"email": "known@example.com", "password": "not-it", "returnSecureToken": true}),
    );
    let (_, unknown) = http(
        port,
        "POST",
        &format!("{V1}/accounts:signInWithPassword?key=fake-api-key"),
        &json!({"email": "nobody@example.com", "password": "hunter22", "returnSecureToken": true}),
    );
    let (reset, _) = http(
        port,
        "POST",
        &format!("{V1}/accounts:sendOobCode?key=fake-api-key"),
        &json!({"requestType": "PASSWORD_RESET", "email": "nobody@example.com"}),
    );
    let code = |v: &Value| v["error"]["message"].as_str().unwrap_or("").to_owned();
    (code(&wrong), code(&unknown), reset)
}

#[test]
fn email_enumeration_protection_is_on_by_default_and_can_be_switched_off() {
    let production_default = Daemon::start("privacy-on", &json!({}));
    assert_eq!(
        probe(&production_default),
        (
            "INVALID_LOGIN_CREDENTIALS".to_owned(),
            "INVALID_LOGIN_CREDENTIALS".to_owned(),
            200
        )
    );
    drop(production_default);

    let official_emulator = Daemon::start("privacy-off", &json!({"improvedEmailPrivacy": false}));
    assert_eq!(
        probe(&official_emulator),
        (
            "INVALID_PASSWORD".to_owned(),
            "EMAIL_NOT_FOUND".to_owned(),
            400
        )
    );
    drop(official_emulator);
    census::assert_no_owned_descendants("the auth privacy daemons", Duration::from_secs(10));
}
