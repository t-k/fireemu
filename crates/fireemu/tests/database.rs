//! The Realtime Database on fireemu's public surface: when it starts (`--only database`,
//! `emulators.database`, `--database-port`), what `exec` exports, what the Emulator Hub
//! lists, and the profile rule for databases without rules (owner decision Q4: open under
//! the emulator and strict profiles, closed under `productionExact` except for the `owner`
//! credential the official tooling uses).

mod scratch;

use scratch::Scratch;

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

const PROJECT: &str = "demo-rtdb";

/// A running `fireemu up`, stopped when dropped.
struct Daemon {
    child: Child,
    banner: Arc<Mutex<String>>,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = Command::new("kill")
            .args(["-TERM", &self.child.id().to_string()])
            .status();
        let _ = self.child.wait();
    }
}

impl Daemon {
    fn start(args: &[&str]) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_fireemu"))
            .args(["up", "--no-config-discovery", "--project", PROJECT])
            .args([
                "--firestore-port",
                "0",
                "--http-port",
                "0",
                "--storage-port",
                "0",
                "--functions-port",
                "0",
                "--logging-port",
                "0",
                "--ui-port",
                "0",
                "--hub-port",
                "0",
            ])
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let daemon = Self {
            child,
            banner: Arc::new(Mutex::new(String::new())),
        };
        let banner = Arc::clone(&daemon.banner);
        let (tx, rx) = mpsc::channel::<()>();
        std::thread::spawn(move || {
            let mut reader = BufReader::new(stdout);
            let mut ready = Some(tx);
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or(0) == 0 {
                    return;
                }
                banner.lock().unwrap().push_str(&line);
                if line.contains("control API:") {
                    if let Some(tx) = ready.take() {
                        let _ = tx.send(());
                    }
                }
            }
        });
        rx.recv_timeout(Duration::from_secs(60))
            .expect("the daemon became ready");
        daemon
    }

    /// The banner line of the Realtime Database.
    fn database_line(&self) -> String {
        self.banner
            .lock()
            .unwrap()
            .lines()
            .find(|line| line.trim_start().starts_with("database:"))
            .unwrap_or_default()
            .to_owned()
    }

    fn database_port(&self) -> u16 {
        let line = self.database_line();
        line.split("127.0.0.1:")
            .nth(1)
            .and_then(|rest| rest.split(|c: char| !c.is_ascii_digit()).next())
            .and_then(|digits| digits.parse().ok())
            .unwrap_or_else(|| panic!("no database port in {line:?}"))
    }
}

/// One HTTP/1.1 request: the status and the body.
fn request(port: u16, method: &str, target: &str, headers: &[&str], body: &str) -> (u16, String) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let extra: String = headers.iter().fold(String::new(), |mut out, h| {
        out.push_str(h);
        out.push_str("\r\n");
        out
    });
    write!(
        stream,
        "{method} {target} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    let (head, body) = response.split_once("\r\n\r\n").unwrap();
    (head[9..12].parse().unwrap(), body.to_owned())
}

#[test]
fn only_database_serves_the_realtime_database_with_zero_configuration() {
    let daemon = Daemon::start(&["--only", "database", "--database-port", "0"]);
    let port = daemon.database_port();
    assert!(
        daemon
            .database_line()
            .contains(&format!("FIREBASE_DATABASE_EMULATOR_HOST=127.0.0.1:{port}")),
        "{}",
        daemon.database_line()
    );
    let ns = "ns=demo-rtdb-default-rtdb";
    assert_eq!(
        request(port, "PUT", &format!("/a.json?{ns}"), &[], r#"{"b":1}"#),
        (200, r#"{"b":1}"#.to_owned())
    );
    assert_eq!(
        request(port, "GET", &format!("/a/b.json?{ns}"), &[], ""),
        (200, "1".to_owned())
    );
    // The WebSocket protocol answers on the same port.
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    write!(
        stream,
        "GET /.ws?v=5&{ns} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
    )
    .unwrap();
    let mut head = [0u8; 12];
    stream.read_exact(&mut head).unwrap();
    assert_eq!(&head, b"HTTP/1.1 101");
}

#[test]
fn the_database_starts_only_when_configured_or_selected() {
    // Without --only and without configuration the default run leaves port 9000 alone.
    let daemon = Daemon::start(&[]);
    assert!(
        daemon.database_line().contains("not started"),
        "{}",
        daemon.database_line()
    );
    drop(daemon);
    // A port starts it.
    let daemon = Daemon::start(&["--database-port", "0"]);
    let port = daemon.database_port();
    assert_eq!(
        request(port, "GET", "/.json?ns=x", &[], "").0,
        200,
        "the configured database answers"
    );
    drop(daemon);
    // --only without database leaves it out even when configured.
    let daemon = Daemon::start(&["--database-port", "0", "--only", "firestore"]);
    assert!(
        daemon.database_line().contains("not started"),
        "{}",
        daemon.database_line()
    );
}

#[test]
fn emulators_database_in_firebase_json_starts_it_on_its_port() {
    let dir = Scratch::new("database", "firebase-json");
    let port = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    };
    let firebase_json = dir.join("firebase.json");
    std::fs::write(
        &firebase_json,
        format!(r#"{{"emulators":{{"database":{{"port":{port}}}}}}}"#),
    )
    .unwrap();
    let daemon = Daemon::start(&["--firebase-json", firebase_json.to_str().unwrap()]);
    assert_eq!(daemon.database_port(), port);
    assert_eq!(request(port, "GET", "/.json?ns=x", &[], "").0, 200);
}

#[test]
fn production_exact_closes_databases_without_rules_except_to_the_owner() {
    let dir = Scratch::new("database", "production-exact");
    let config = dir.join("fireemu.json");
    std::fs::write(
        &config,
        r#"{"schemaVersion":1,"profile":"strict","productionExact":true}"#,
    )
    .unwrap();
    let daemon = Daemon::start(&[
        "--config",
        config.to_str().unwrap(),
        "--only",
        "database",
        "--database-port",
        "0",
    ]);
    let port = daemon.database_port();
    let (status, body) = request(port, "GET", "/.json?ns=x", &[], "");
    assert_eq!(status, 401, "{body}");
    assert!(body.contains("Permission denied"), "{body}");
    assert_eq!(
        request(
            port,
            "PUT",
            "/a.json?ns=x",
            &["Authorization: Bearer owner"],
            "1"
        ),
        (200, "1".to_owned())
    );
    // The strict profile without productionExact stays open, as the official emulator.
    let open = dir.join("strict.json");
    std::fs::write(&open, r#"{"schemaVersion":1,"profile":"strict"}"#).unwrap();
    let daemon = Daemon::start(&[
        "--config",
        open.to_str().unwrap(),
        "--only",
        "database",
        "--database-port",
        "0",
    ]);
    assert_eq!(
        request(daemon.database_port(), "GET", "/.json?ns=x", &[], "").0,
        200
    );
}

#[test]
fn exec_exports_the_database_host() {
    let dir = Scratch::new("database", "exec");
    let out = dir.join("env.txt");
    let output = Command::new(env!("CARGO_BIN_EXE_fireemu"))
        .args(["exec", "--no-config-discovery", "--project", PROJECT])
        .args([
            "--only",
            "database",
            "--database-port",
            "0",
            "--http-port",
            "0",
            "--hub-port",
            "0",
        ])
        .args(["--", "/bin/sh", "-c"])
        .arg(format!("env > {}", out.display()))
        // A selected service overrides an inherited endpoint, as the official CLI does.
        .env("FIREBASE_DATABASE_EMULATOR_HOST", "127.0.0.1:1")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let env: BTreeMap<String, String> = std::fs::read_to_string(&out)
        .unwrap()
        .lines()
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect();
    let host = &env["FIREBASE_DATABASE_EMULATOR_HOST"];
    assert!(
        host.starts_with("127.0.0.1:") && host != "127.0.0.1:1",
        "{host}"
    );
    for absent in ["FIRESTORE_EMULATOR_HOST", "FIREBASE_AUTH_EMULATOR_HOST"] {
        assert!(!env.contains_key(absent), "{absent}");
    }
}

#[test]
fn the_hub_lists_the_database() {
    let hub = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    };
    let daemon = Daemon::start(&[
        "--only",
        "database",
        "--database-port",
        "0",
        "--hub-port",
        &hub.to_string(),
    ]);
    let (status, body) = request(hub, "GET", "/emulators", &[], "");
    assert_eq!(status, 200, "{body}");
    let emulators: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(emulators["database"]["name"], "database", "{emulators}");
    assert_eq!(
        emulators["database"]["port"],
        u64::from(daemon.database_port()),
        "{emulators}"
    );
}

#[test]
fn database_deploy_hooks_in_firebase_json_are_accepted_whatever_is_selected() {
    let dir = Scratch::new("database", "deploy-hooks");
    let firebase_json = dir.join("firebase.json");
    std::fs::write(
        &firebase_json,
        r#"{"database":{"rules":"database.rules.json","predeploy":["echo hi"],"postdeploy":"echo bye"}}"#,
    )
    .unwrap();
    for only in ["auth", "database"] {
        let daemon = Daemon::start(&[
            "--firebase-json",
            firebase_json.to_str().unwrap(),
            "--only",
            only,
            "--database-port",
            "0",
        ]);
        let line = daemon.database_line();
        assert_eq!(
            line.contains("not started"),
            only == "auth",
            "{only}: {line}"
        );
    }
}
