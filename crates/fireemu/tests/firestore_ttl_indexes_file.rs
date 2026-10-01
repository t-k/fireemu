//! `firestore.indexes.json` declares time-to-live policies, as `firebase deploy` creates them
//! from `fieldOverrides[].ttl`: a daemon started with such a file has the policies in force,
//! and Admin `fields.get` reports them the way it reports a `fields.patch` policy.

use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("fireemu-ttl-file-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn http_as_owner(port: u16, method: &str, path: &str) -> (u16, serde_json::Value) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("the daemon accepts");
    stream
        .set_read_timeout(Some(Duration::from_secs(20)))
        .unwrap();
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer owner\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    stream.flush().unwrap();
    let mut raw = String::new();
    stream.read_to_string(&mut raw).unwrap();
    let (head, body) = raw.split_once("\r\n\r\n").unwrap_or((raw.as_str(), ""));
    let status = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .unwrap_or(0);
    (status, serde_json::from_str(body).unwrap_or_default())
}

/// How the daemon is told about the index file.
enum Layout {
    /// `firestore.indexFile` of the canonical configuration: the default database.
    DefaultDatabase,
    /// A `firebase.json` that declares the default database and a named one, `staging`, whose
    /// index file this is.
    NamedDatabase,
}

/// The `fireemu up` command of a daemon whose Firestore reads `indexes` from a file.
fn command(name: &str, layout: &Layout, indexes: &str) -> (Command, u16) {
    let dir = scratch(name);
    let indexes_path = dir.join("firestore.indexes.json");
    std::fs::write(&indexes_path, indexes).unwrap();
    let config = dir.join("fireemu.json");
    let firestore = match layout {
        Layout::DefaultDatabase => format!(
            r#""firestore": {{"indexFile": {}, "edition": "standard", "apiMode": "native"}}"#,
            serde_json::Value::String(indexes_path.display().to_string())
        ),
        Layout::NamedDatabase => {
            std::fs::write(
                dir.join("firebase.json"),
                r#"{"firestore": [{"database": "(default)"}, {"database": "staging", "indexes": "firestore.indexes.json"}]}"#,
            )
            .unwrap();
            r#""firebaseJson": "firebase.json", "firestore": {"edition": "standard", "apiMode": "native"}"#
                .to_owned()
        }
    };
    std::fs::write(
        &config,
        format!(r#"{{"schemaVersion": 1, "profile": "strict", {firestore}}}"#),
    )
    .unwrap();
    let hub_port = free_port();
    let mut command = Command::new(env!("CARGO_BIN_EXE_fireemu"));
    command
        .args([
            "up",
            "--config",
            config.to_str().unwrap(),
            "--project",
            "demo-ttl",
        ])
        .args([
            "--firestore-port",
            "0",
            "--http-port",
            "0",
            "--storage-port",
            "0",
        ])
        .args(["--logging-port", "0", "--ui-port", "0", "--hub-port"])
        .arg(hub_port.to_string())
        .stdin(Stdio::null());
    (command, hub_port)
}

struct Daemon {
    child: Child,
    hub_port: u16,
}

impl Daemon {
    fn start(name: &str, layout: &Layout, indexes: &str) -> Self {
        let (mut command, hub_port) = command(name, layout, indexes);
        let mut child = command
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        std::thread::spawn(move || {
            let mut reader = BufReader::new(stdout);
            let mut ready = Some(tx);
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or(0) == 0 {
                    return;
                }
                if line.contains("control API:") {
                    if let Some(tx) = ready.take() {
                        let _ = tx.send(());
                    }
                }
            }
        });
        rx.recv_timeout(Duration::from_secs(60))
            .expect("the daemon became ready");
        Self { child, hub_port }
    }

    fn field(&self, collection: &str, field: &str) -> (u16, serde_json::Value) {
        self.field_of("(default)", collection, field)
    }

    fn field_of(&self, database: &str, collection: &str, field: &str) -> (u16, serde_json::Value) {
        let (status, emulators) = http_as_owner(self.hub_port, "GET", "/emulators");
        assert_eq!(status, 200);
        let port = u16::try_from(emulators["firestore"]["port"].as_u64().unwrap()).unwrap();
        http_as_owner(
            port,
            "GET",
            &format!("/v1/projects/demo-ttl/databases/{database}/collectionGroups/{collection}/fields/{field}"),
        )
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

const DECLARED: &str = r#"{
  "indexes": [],
  "fieldOverrides": [
    {"collectionGroup": "sessions", "fieldPath": "expireAt", "ttl": true, "indexes": []},
    {"collectionGroup": "logs", "fieldPath": "until", "ttl": false, "indexes": []}
  ]
}"#;

#[test]
fn a_ttl_declared_in_the_indexes_file_is_reported_like_a_patched_one() {
    let daemon = Daemon::start("declared", &Layout::DefaultDatabase, DECLARED);
    let (status, declared) = daemon.field("sessions", "expireAt");
    assert_eq!(status, 200, "{declared}");
    assert_eq!(
        declared["name"],
        "projects/demo-ttl/databases/(default)/collectionGroups/sessions/fields/expireAt"
    );
    assert_eq!(declared["ttlConfig"]["state"], "ACTIVE", "{declared}");
    // `ttl: false`, another field of the collection group, and an unknown one have none.
    for (collection, field) in [
        ("logs", "until"),
        ("sessions", "other"),
        ("nothing", "here"),
    ] {
        let (status, body) = daemon.field(collection, field);
        assert_eq!(status, 200, "{body}");
        assert!(
            body.get("ttlConfig").is_none(),
            "{collection}.{field}: {body}"
        );
    }
}

#[test]
fn two_ttl_fields_in_one_collection_group_stop_the_daemon_with_a_message() {
    let (mut command, _hub) = command(
        "conflict",
        &Layout::DefaultDatabase,
        r#"{"indexes":[],"fieldOverrides":[
            {"collectionGroup":"sessions","fieldPath":"a","ttl":true,"indexes":[]},
            {"collectionGroup":"sessions","fieldPath":"b","ttl":true,"indexes":[]}]}"#,
    );
    let output = command
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("at most one TTL field") && stderr.contains("sessions"),
        "{stderr}"
    );
}

#[test]
fn a_ttl_declared_in_a_named_databases_indexes_file_is_in_force_for_that_database_only() {
    let daemon = Daemon::start("named", &Layout::NamedDatabase, DECLARED);
    let (status, staging) = daemon.field_of("staging", "sessions", "expireAt");
    assert_eq!(status, 200, "{staging}");
    assert_eq!(staging["ttlConfig"]["state"], "ACTIVE", "{staging}");
    let (status, default) = daemon.field_of("(default)", "sessions", "expireAt");
    assert_eq!(status, 200, "{default}");
    assert!(default.get("ttlConfig").is_none(), "{default}");
}
