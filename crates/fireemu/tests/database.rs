//! The Realtime Database on fireemu's public surface: when it starts (`--only database`,
//! `emulators.database`, `--database-port`), what `exec` exports, what the Emulator Hub
//! lists, and the profile rule for databases without rules (owner decision Q4: open under
//! the emulator and strict profiles, closed under `productionExact` except for the `owner`
//! credential the official tooling uses).

mod scratch;
#[cfg(unix)]
#[path = "../../../tests/support/trusted_temp.rs"]
mod trusted_temp;

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

    /// The banner line about Realtime Database rules.
    fn rules_line(&self) -> String {
        self.banner
            .lock()
            .unwrap()
            .lines()
            .find(|line| line.trim_start().starts_with("database rules:"))
            .unwrap_or_default()
            .to_owned()
    }

    /// The port of the Auth emulator's REST surface.
    fn auth_port(&self) -> u16 {
        let banner = self.banner.lock().unwrap().clone();
        let line = banner
            .lines()
            .find(|line| line.trim_start().starts_with("auth (REST):"))
            .unwrap_or_else(|| panic!("no auth line in {banner}"))
            .to_owned();
        line.split("127.0.0.1:")
            .nth(1)
            .and_then(|rest| rest.split(|c: char| !c.is_ascii_digit()).next())
            .and_then(|digits| digits.parse().ok())
            .unwrap_or_else(|| panic!("no auth port in {line:?}"))
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
    std::fs::write(dir.join("database.rules.json"), r#"{"rules":{}}"#).unwrap();
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

#[test]
fn the_banner_says_what_an_instance_without_rules_allows() {
    let dir = Scratch::new("database", "rules-banner");
    let open = Daemon::start(&["--only", "database", "--database-port", "0"]);
    let line = open.rules_line();
    assert!(line.contains("none in firebase.json"), "{line}");
    assert!(line.contains("every request is allowed"), "{line}");
    assert!(
        line.contains("database.defaultAccess = open, default"),
        "{line}"
    );
    drop(open);
    for (config, source) in [
        (
            r#"{"schemaVersion":1,"profile":"strict","productionExact":true}"#,
            "productionExact",
        ),
        (
            r#"{"schemaVersion":1,"profile":"strict","database":{"defaultAccess":"locked"}}"#,
            "explicit",
        ),
    ] {
        let path = dir.join(format!("{source}.json"));
        std::fs::write(&path, config).unwrap();
        let daemon = Daemon::start(&[
            "--config",
            path.to_str().unwrap(),
            "--only",
            "database",
            "--database-port",
            "0",
        ]);
        let line = daemon.rules_line();
        assert!(line.contains("only the owner credential"), "{line}");
        assert!(
            line.contains(&format!("database.defaultAccess = locked, {source}")),
            "{line}"
        );
    }
    // Not served: no rules line.
    let unserved = Daemon::start(&[]);
    assert_eq!(unserved.rules_line(), "");
}

#[test]
fn declared_rules_are_enforced_on_the_default_instance_and_reloaded_when_they_change() {
    let dir = Scratch::new("database", "rules-file");
    let firebase_json = dir.join("firebase.json");
    std::fs::write(
        &firebase_json,
        r#"{"database":{"rules":"database.rules.json"}}"#,
    )
    .unwrap();
    let rules = dir.join("database.rules.json");
    std::fs::write(&rules, r#"{"rules":{".read":false,".write":false}}"#).unwrap();
    let daemon = Daemon::start(&[
        "--firebase-json",
        firebase_json.to_str().unwrap(),
        "--only",
        "database",
        "--database-port",
        "0",
    ]);
    let line = daemon.rules_line();
    assert!(
        line.contains("demo-rtdb-default-rtdb <- ") && line.contains("database.rules.json"),
        "{line}"
    );
    assert!(
        line.contains("another instance: every request is allowed"),
        "{line}"
    );
    let port = daemon.database_port();
    let read = |ns: &str| request(port, "GET", &format!("/.json?ns={ns}"), &[], "").0;
    assert_eq!(read("demo-rtdb-default-rtdb"), 401);
    // Only the default instance has the file's rules.
    assert_eq!(read("other"), 200);
    let eventually = |status: u16| {
        (0..100).any(|_| {
            if read("demo-rtdb-default-rtdb") == status {
                return true;
            }
            std::thread::sleep(Duration::from_millis(100));
            false
        })
    };
    std::fs::write(&rules, r#"{"rules":{".read":true}}"#).unwrap();
    assert!(eventually(200), "the changed rules were not loaded");
    // A change that does not load keeps the rules in force.
    std::fs::write(&rules, r#"{"rules":{".read":"auth.foo()"}}"#).unwrap();
    std::thread::sleep(Duration::from_secs(3));
    assert_eq!(read("demo-rtdb-default-rtdb"), 200);
    std::fs::write(&rules, r#"{"rules":{".read":false}}"#).unwrap();
    assert!(
        eventually(401),
        "a good change after a bad one was not loaded"
    );
}

#[test]
fn a_rules_file_that_does_not_load_stops_the_start_only_when_the_database_is_served() {
    let dir = Scratch::new("database", "rules-start");
    let firebase_json = dir.join("firebase.json");
    std::fs::write(
        &firebase_json,
        r#"{"database":{"rules":"database.rules.json"}}"#,
    )
    .unwrap();
    let run = |only: &str| {
        Command::new(env!("CARGO_BIN_EXE_fireemu"))
            .args(["exec", "--no-config-discovery", "--project", PROJECT])
            .args(["--firebase-json", firebase_json.to_str().unwrap()])
            .args(["--only", only, "--database-port", "0", "--http-port", "0"])
            .args(["--hub-port", "0", "--log-verbosity", "quiet", "--", "true"])
            .stdin(Stdio::null())
            .output()
            .unwrap()
    };
    let missing = run("database");
    let stderr = String::from_utf8_lossy(&missing.stderr);
    assert!(!missing.status.success(), "{stderr}");
    assert!(
        stderr.contains("Failed to load initial Realtime Database rules:")
            && stderr.contains("database.rules.json:"),
        "{stderr}"
    );
    std::fs::write(
        dir.join("database.rules.json"),
        r#"{"rules":{".read":"auth.foo()"}}"#,
    )
    .unwrap();
    let invalid = run("database");
    let stderr = String::from_utf8_lossy(&invalid.stderr);
    assert!(!invalid.status.success(), "{stderr}");
    assert!(
        stderr.contains(
            "database.rules.json:1:20: Type error: Function call on target that is not a function."
        ),
        "{stderr}"
    );
    let unserved = run("auth");
    assert!(
        unserved.status.success(),
        "{}",
        String::from_utf8_lossy(&unserved.stderr)
    );
}

/// Exports go under a parent only this user can write: fireemu refuses to publish an export
/// below a world-writable ancestor such as Linux's `/tmp`.
#[cfg(unix)]
fn export_parent(label: &str) -> trusted_temp::TrustedTempDir {
    trusted_temp::TrustedTempDir::new(label)
}

#[cfg(unix)]
#[test]
fn an_export_carries_the_database_and_an_import_restores_it() {
    let dir = export_parent("database-export-import");
    let export = dir.path().join("export");
    let exec = |extra: &[&str], script: &str| {
        Command::new(env!("CARGO_BIN_EXE_fireemu"))
            .args(["exec", "--no-config-discovery", "--project", PROJECT])
            .args(["--only", "database,firestore", "--database-port", "0"])
            .args([
                "--http-port",
                "0",
                "--firestore-port",
                "0",
                "--hub-port",
                "0",
            ])
            .args(extra)
            .args(["--", "/bin/sh", "-c", script])
            .stdin(Stdio::null())
            .output()
            .unwrap()
    };
    let owner = r#"-H "Authorization: Bearer owner""#;
    let url = |ns: &str, query: &str| {
        format!(r#""http://$FIREBASE_DATABASE_EMULATOR_HOST/.json?ns={ns}{query}""#)
    };
    let ns = format!("{PROJECT}-default-rtdb");
    let write = format!(
        r#"curl -sf -X PUT {owner} {} -d '{{"a":{{"b":1,".priority":3}},"s":"x"}}' >/dev/null && curl -sf -X PUT {owner} {} -d '{{"z":1}}' >/dev/null"#,
        url(&ns, ""),
        url("named", "")
    );
    let output = exec(&["--export-on-exit", export.to_str().unwrap()], &write);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    // The section firebase-tools writes: one file per namespace, as format=export answers.
    let section = export.join("database_export");
    assert_eq!(
        std::fs::read_to_string(section.join(format!("{ns}.json"))).unwrap(),
        r#"{"a":{".priority":3.0,"b":1},"s":"x"}"#
    );
    assert_eq!(
        std::fs::read_to_string(section.join("named.json")).unwrap(),
        r#"{"z":1}"#
    );
    let metadata: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(export.join("firebase-export-metadata.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(
        metadata["database"],
        serde_json::json!({"version": "4.11.2", "path": "database_export"})
    );
    // An import puts every namespace back.
    let read = format!(
        "curl -sf {owner} {} && echo && curl -sf {owner} {}",
        url(&ns, "&format=export"),
        url("named", "")
    );
    let output = exec(&["--import", export.to_str().unwrap()], &read);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    // The command's output follows the banner.
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.trim().ends_with(
            "running command\n{\"a\":{\".priority\":3.0,\"b\":1},\"s\":\"x\"}\n{\"z\":1}"
        ),
        "{stdout}"
    );
    // A file the official emulator would refuse stops the start.
    std::fs::write(section.join("bad.name.json"), "1").unwrap();
    let output = exec(&["--import", export.to_str().unwrap()], "true");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Invalid Firebase database name"),
        "{stderr}"
    );
}

/// One long-polling request: the body.
fn lp(port: u16, target: &str) -> String {
    request(port, "GET", target, &[], "").1
}

/// The SDK's web-safe base64 of a message (`-`, `_`, and `.` for padding).
fn segment(message: &str) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in message.as_bytes().chunks(3) {
        let bytes = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(bytes[0]) << 16) | (u32::from(bytes[1]) << 8) | u32::from(bytes[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(char::from(ALPHABET[((n >> (18 - 6 * i)) & 63) as usize]));
            } else {
                out.push('.');
            }
        }
    }
    out
}

#[test]
fn production_exact_holds_the_realtime_protocol_to_the_owner_too() {
    let dir = Scratch::new("database", "production-exact-lp");
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
    let start = lp(port, "/.lp?start=t&ser=1&cb=1&v=5&ns=pe");
    let line = start
        .lines()
        .find(|l| l.contains("pLPCommand('start'"))
        .unwrap_or_else(|| panic!("{start}"));
    let parts: Vec<&str> = line.split('\'').collect();
    let (id, pw) = (parts[3], parts[5]);
    let send = |n: u64, message: &str| {
        lp(
            port,
            &format!(
                "/.lp?id={id}&pw={pw}&ser={}&ns=pe&seg0={n}&ts0=1&d0={}",
                n + 10,
                segment(message)
            ),
        )
    };
    let denied = send(0, r#"{"t":"d","d":{"r":1,"a":"q","b":{"p":"/a","h":""}}}"#);
    assert!(denied.contains(r#""s":"permission_denied""#), "{denied}");
    let authed = send(
        1,
        r#"{"t":"d","d":{"r":2,"a":"gauth","b":{"cred":"owner"}}}"#,
    );
    assert!(authed.contains(r#""r":2,"b":{"s":"ok""#), "{authed}");
    let wrote = send(2, r#"{"t":"d","d":{"r":3,"a":"p","b":{"p":"/a","d":1}}}"#);
    assert!(wrote.contains(r#""r":3,"b":{"s":"ok""#), "{wrote}");
}

#[cfg(unix)]
#[test]
fn emulators_export_writes_the_database_section_without_a_warning() {
    let export_dir = export_parent("database-hub-export");
    let export = export_dir.path().join("export");
    let output = Command::new(env!("CARGO_BIN_EXE_fireemu"))
        .args(["exec", "--no-config-discovery", "--project", PROJECT])
        .args(["--only", "database,firestore", "--database-port", "0"])
        .args([
            "--http-port",
            "0",
            "--firestore-port",
            "0",
            "--hub-port",
            "auto",
        ])
        .arg("--")
        .arg(env!("CARGO_BIN_EXE_fireemu"))
        .args(["emulators:export"])
        .arg(&export)
        .args(["--project", PROJECT])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stderr}");
    assert!(
        !stderr.contains("Realtime Database data is not exported"),
        "{stderr}"
    );
    let metadata = std::fs::read_to_string(export.join("firebase-export-metadata.json")).unwrap();
    assert!(metadata.contains(r#""database""#), "{metadata}");
}

#[test]
fn a_session_snapshot_restores_the_database() {
    let probe = r#"auth="Authorization: Bearer $FIREEMU_CONTROL_TOKEN"
db="http://$FIREBASE_DATABASE_EMULATOR_HOST/.json?ns=demo-rtdb-default-rtdb"
owner="Authorization: Bearer owner"
curl -s -o /dev/null -X PUT -H "$owner" "$db" -d '{"kept":1}'
curl -s -o /dev/null -w 'capture %{http_code}\n' -X POST -H "$auth" -H 'Content-Type: application/json' "${FIREEMU_CONTROL_URL}sessions/default/snapshots" -d '{"name": "held"}'
curl -s -o /dev/null -X PUT -H "$owner" "$db" -d '{"later":2}'
curl -s -o /dev/null -w 'restore %{http_code}\n' -X POST -H "$auth" -H 'Content-Type: application/json' "${FIREEMU_CONTROL_URL}sessions/default/snapshots/held:restore" -d '{}'
printf 'value '
curl -s -H "$owner" "$db"
echo"#;
    let output = Command::new(env!("CARGO_BIN_EXE_fireemu"))
        .args(["exec", "--no-config-discovery", "--project", PROJECT])
        .args([
            "--only",
            "database",
            "--database-port",
            "0",
            "--http-port",
            "0",
        ])
        .args(["--", "/bin/sh", "-c", probe])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let log = format!("{stdout}{}", String::from_utf8_lossy(&output.stderr));
    assert!(output.status.success(), "{log}");
    assert!(stdout.contains("capture 200"), "{log}");
    assert!(stdout.contains("restore 200"), "{log}");
    assert!(stdout.contains(r#"value {"kept":1}"#), "{log}");
}

#[test]
fn the_inspect_route_needs_the_owner_except_under_the_emulator_profile() {
    let dir = Scratch::new("database", "inspect");
    for (name, config, open) in [
        (
            "emulator",
            r#"{"schemaVersion":1,"profile":"emulator"}"#,
            true,
        ),
        ("strict", r#"{"schemaVersion":1,"profile":"strict"}"#, false),
        (
            "exact",
            r#"{"schemaVersion":1,"profile":"strict","productionExact":true}"#,
            false,
        ),
    ] {
        let path = dir.join(format!("{name}.json"));
        std::fs::write(&path, config).unwrap();
        let daemon = Daemon::start(&[
            "--config",
            path.to_str().unwrap(),
            "--only",
            "database",
            "--database-port",
            "0",
        ]);
        let port = daemon.database_port();
        let inspect = "/.inspect/databases.json?ns=probe";
        let (status, _) = request(port, "GET", inspect, &[], "");
        assert_eq!(status, if open { 200 } else { 401 }, "{name}");
        let (status, body) = request(
            port,
            "GET",
            "/.inspect/databases.json?ns=owner-asked",
            &["Authorization: Bearer owner"],
            "",
        );
        assert_eq!(status, 200, "{name}");
        // A refused request created no namespace.
        assert_eq!(body.contains(r#""probe""#), open, "{name}: {body}");
    }
}

/// A mock token for `uid` of the test project whose claims also hold `extra` (members of the claims object, as text).
fn mock_token_with(uid: &str, extra: &str) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let claims = format!(
        r#"{{"iss":"https://securetoken.google.com/{PROJECT}","aud":"{PROJECT}","iat":{now},"exp":{},"sub":"{uid}",{extra}}}"#,
        now + 3600
    );
    format!(
        "{}.{}.",
        segment(r#"{"alg":"none","type":"JWT"}"#).trim_end_matches('.'),
        segment(&claims).trim_end_matches('.')
    )
}

/// A token whose claims hold a lone surrogate (`"x":"\ud83d"`, or as a claim name) is not read, as before 2286 (owner
/// ledger line 2291, a declared difference: the official emulator keeps the surrogate): the strict profile refuses
/// it (401) and the emulator profile judges the request as an anonymous one, through the daemon's own token verifier.
/// A hand-made token is a user when its `iat` is a number as the official emulator reads one
/// (docs.local/runs/rtdb-token-iat): an integer literal in the i64 range, or a literal with a
/// fraction or an exponent (`1e400` too). Any other `iat`, an integer literal beyond the i64
/// range included, leaves the token nobody (anonymous). Auth's emulator profile admits more
/// hand-made tokens (a string or missing `iat`), but the official RTDB emulator does not read
/// those, so neither does the emulator profile here.
///
/// Strict keeps what it did before: it reads no hand-made token, except the SDK's mock token
/// (the exact header `{"alg":"none","type":"JWT"}`, an empty signature, `aud` the project),
/// which it reads as it always has, as a user when the parsed `iat` is a finite number. That
/// is the old classification: an integer literal beyond the i64 range is a double (a user) and
/// `1e400` is the string "Infinity" (nobody), the reverse of the emulator profile.
#[test]
#[allow(clippy::too_many_lines)] // one matrix: profile x token kind x iat
fn a_hand_made_token_is_a_user_when_its_iat_is_a_number_the_official_emulator_reads() {
    let dir = Scratch::new("database", "token-iat");
    let firebase_json = dir.join("firebase.json");
    std::fs::write(
        &firebase_json,
        r#"{"database":[{"instance":"demo-rtdb-default-rtdb","rules":"database.rules.json"}]}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("database.rules.json"),
        r#"{"rules":{"users":{"$uid":{".read":"auth != null && auth.uid === $uid"}},
            "anon":{".read":"auth == null"}}}"#,
    )
    .unwrap();
    // (iat, a number for the official emulator, a number for strict's mock-token reading)
    let issue_times = [
        ("1", true, true),
        ("-1", true, true),
        ("1.5", true, true),
        ("1e3", true, true),
        ("1e30", true, true),
        ("1e400", true, false),
        ("-1e400", true, false),
        ("9223372036854775807", true, true),
        ("9223372036854775808", false, true),
        ("-9223372036854775809", false, true),
        ("12345678901234567890", false, true),
        (r#""1""#, false, false),
        (r#""Infinity""#, false, false),
        ("null", false, false),
        ("true", false, false),
    ];
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    for (name, config) in [
        ("emulator", r#"{"schemaVersion":1,"profile":"emulator"}"#),
        ("strict", r#"{"schemaVersion":1,"profile":"strict"}"#),
    ] {
        let path = dir.join(format!("{name}.json"));
        std::fs::write(&path, config).unwrap();
        let daemon = Daemon::start(&[
            "--firebase-json",
            firebase_json.to_str().unwrap(),
            "--config",
            path.to_str().unwrap(),
            "--only",
            "database,auth",
            "--database-port",
            "0",
        ]);
        let read = |path: &str, token: &str| {
            let target = format!("{path}.json?ns=demo-rtdb-default-rtdb&auth={token}");
            request(daemon.database_port(), "GET", &target, &[], "").0
        };
        let unsigned = |header: &str, claims: &str| {
            format!(
                "{}.{}.",
                segment(header).trim_end_matches('.'),
                segment(claims).trim_end_matches('.')
            )
        };
        // The header of a hand-made token (`typ`), and the SDK's mock token's (`type`).
        let hand_made = r#"{"alg":"none","typ":"JWT"}"#;
        let sdk_mock = r#"{"alg":"none","type":"JWT"}"#;
        let mut tokens = Vec::new();
        for (iat, number, strict_number) in issue_times {
            // Without `aud` (the claims are read unverified).
            let claims = format!(r#"{{"sub":"u1","iat":{iat}}}"#);
            tokens.push((
                format!("no aud, iat {iat}"),
                unsigned(hand_made, &claims),
                number,
                false,
            ));
            // Of the project, with each header.
            let claims = format!(
                r#"{{"aud":"{PROJECT}","sub":"u1","iat":{iat},"exp":{}}}"#,
                now + 3600
            );
            tokens.push((
                format!("hand-made, iat {iat}"),
                unsigned(hand_made, &claims),
                number,
                false,
            ));
            tokens.push((
                format!("sdk mock, iat {iat}"),
                unsigned(sdk_mock, &claims),
                number,
                strict_number,
            ));
        }
        for (what, token, number, strict_user) in tokens {
            if name == "strict" && strict_user {
                assert_eq!(read("/users/u1", &token), 200, "{name}: {what}");
                assert_eq!(read("/anon", &token), 401, "{name}: {what}");
            } else if name == "strict" {
                // Strict refuses the credential.
                assert_eq!(read("/users/u1", &token), 401, "{name}: {what}");
                assert_eq!(read("/anon", &token), 401, "{name}: {what}");
            } else if number {
                assert_eq!(read("/users/u1", &token), 200, "{name}: {what}");
                assert_eq!(read("/anon", &token), 401, "{name}: {what}");
            } else {
                assert_eq!(read("/users/u1", &token), 401, "{name}: {what}");
                assert_eq!(read("/anon", &token), 200, "{name}: {what}");
            }
        }
        let unsigned = |claims: &str| unsigned(hand_made, claims);
        // A missing `iat` leaves the token nobody too.
        let missing = unsigned(r#"{"sub":"u1"}"#);
        if name != "strict" {
            assert_eq!(read("/users/u1", &missing), 401, "{name}");
            assert_eq!(read("/anon", &missing), 200, "{name}");
        }
    }
}

/// A pair and a plain claim are read as always.
#[test]
fn a_claim_with_a_lone_surrogate_is_not_read_on_either_profile() {
    let dir = Scratch::new("database", "lone-claims");
    let firebase_json = dir.join("firebase.json");
    std::fs::write(
        &firebase_json,
        r#"{"database":[{"instance":"demo-rtdb-default-rtdb","rules":"database.rules.json"}]}"#,
    )
    .unwrap();
    // (rule, extra claims, whether the claims hold a lone surrogate, read of a token that is read)
    let cases = [
        ("auth.token.x == '\\uD83D'", r#""x":"\ud83d""#, true, 0),
        ("auth.token.x.length == 1", r#""x":"\ud83d""#, true, 0),
        ("!(auth.token.x == '\\uD83D')", r#""x":"\ud83d""#, true, 0),
        ("auth.token['\\uD83D'] == 1", r#""\ud83d":1"#, true, 0),
        ("auth.token.x == '😀'", r#""x":"\ud83d\ude00""#, false, 200),
        ("auth.token.x == 'v'", r#""x":"v""#, false, 200),
    ];
    for (name, config) in [
        ("emulator", r#"{"schemaVersion":1,"profile":"emulator"}"#),
        ("strict", r#"{"schemaVersion":1,"profile":"strict"}"#),
    ] {
        let path = dir.join(format!("{name}.json"));
        std::fs::write(&path, config).unwrap();
        for (rule, extra, lone, read) in cases {
            std::fs::write(
                dir.join("database.rules.json"),
                format!(
                    r#"{{"rules":{{"t":{{".read":"{}"}}}}}}"#,
                    rule.replace('\\', "\\\\")
                ),
            )
            .unwrap();
            let daemon = Daemon::start(&[
                "--firebase-json",
                firebase_json.to_str().unwrap(),
                "--config",
                path.to_str().unwrap(),
                "--only",
                "database,auth",
                "--database-port",
                "0",
            ]);
            let token = mock_token_with("u1", extra);
            let target = format!("/t.json?ns=demo-rtdb-default-rtdb&auth={token}");
            let (status, body) = request(daemon.database_port(), "GET", &target, &[], "");
            if !lone {
                assert_eq!(status, read, "{name} {rule} {extra}: {body}");
            } else if name == "strict" {
                assert_eq!(status, 401, "{name} {rule} {extra}: {body}");
            } else {
                let anonymous = "/t.json?ns=demo-rtdb-default-rtdb";
                let (plain, _) = request(daemon.database_port(), "GET", anonymous, &[], "");
                assert_eq!(status, plain, "{name} {rule} {extra}: {body}");
            }
        }
    }
}

/// An import file whose value holds a lone surrogate escape: the emulator profile stores `?` as the official emulator
/// does (firebase-tools sends the file as `PUT /.json`), the strict profile stops the start while the import is
/// prepared, before anything is installed (owner row 2286 and the coordinator's ruling for the import path).
#[test]
fn an_import_with_a_lone_surrogate_follows_the_profile_and_strict_stops_the_start() {
    let dir = export_parent("database-import-lone-surrogate");
    let export = dir.path().join("export");
    let ns = format!("{PROJECT}-default-rtdb");
    let exec = |profile: &str, extra: &[&str], script: &str| {
        let config = dir.path().join(format!("{profile}.json"));
        std::fs::write(
            &config,
            format!(r#"{{"schemaVersion":1,"profile":"{profile}"}}"#),
        )
        .unwrap();
        Command::new(env!("CARGO_BIN_EXE_fireemu"))
            .args(["exec", "--no-config-discovery", "--project", PROJECT])
            .args(["--config", config.to_str().unwrap()])
            .args([
                "--only",
                "database",
                "--database-port",
                "0",
                "--http-port",
                "0",
            ])
            .args(["--hub-port", "0"])
            .args(extra)
            .args(["--", "/bin/sh", "-c", script])
            .stdin(Stdio::null())
            .output()
            .unwrap()
    };
    let owner = r#"-H "Authorization: Bearer owner""#;
    let url = format!(r#""http://$FIREBASE_DATABASE_EMULATOR_HOST/.json?ns={ns}""#);
    let write = format!(r#"curl -sf -X PUT {owner} {url} -d '{{"k":1}}' >/dev/null"#);
    let output = exec(
        "emulator",
        &["--export-on-exit", export.to_str().unwrap()],
        &write,
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let file = export.join("database_export").join(format!("{ns}.json"));
    std::fs::write(&file, r#"{"a":"v\ud83d","b":"\ud83d\ude00","c":"x"}"#).unwrap();
    // A second namespace that would install first and must not be installed when strict refuses the first.
    std::fs::write(
        export.join("database_export").join("aaa.json"),
        r#"{"z":1}"#,
    )
    .unwrap();
    let read = format!("curl -sf {owner} {url}");
    let emulator = exec("emulator", &["--import", export.to_str().unwrap()], &read);
    assert!(
        emulator.status.success(),
        "{}",
        String::from_utf8_lossy(&emulator.stderr)
    );
    assert!(
        String::from_utf8_lossy(&emulator.stdout)
            .trim()
            .ends_with("{\"a\":\"v?\",\"b\":\"\u{1F600}\",\"c\":\"x\"}"),
        "{}",
        String::from_utf8_lossy(&emulator.stdout)
    );
    let strict = exec("strict", &["--import", export.to_str().unwrap()], "true");
    assert!(!strict.status.success());
    let stderr = String::from_utf8_lossy(&strict.stderr);
    assert!(
        stderr.contains(&format!("{ns}.json")) && stderr.contains("couldn't parse JSON"),
        "{stderr}"
    );
    // A key that holds one stops the start on the emulator profile too.
    std::fs::write(&file, r#"{"a\ud83d":1}"#).unwrap();
    let emulator = exec("emulator", &["--import", export.to_str().unwrap()], "true");
    assert!(!emulator.status.success());
}

/// The unsigned ID token `@firebase/rules-unit-testing` mints for `uid` of the test project
/// (the SDK's `mockUserToken` shape).
fn mock_token(uid: &str) -> String {
    mock_token_for(PROJECT, uid)
}

/// The SDK's mock token for `uid` of `project`.
fn mock_token_for(project: &str, uid: &str) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let claims = format!(
        r#"{{"iss":"https://securetoken.google.com/{project}","aud":"{project}","iat":{now},"exp":{},"auth_time":{now},"sub":"{uid}","user_id":"{uid}","firebase":{{"sign_in_provider":"custom","identities":{{}}}}}}"#,
        now + 3600
    );
    format!(
        "{}.{}.",
        segment(r#"{"alg":"none","type":"JWT"}"#).trim_end_matches('.'),
        segment(&claims).trim_end_matches('.')
    )
}

/// Signs a user up on the Auth emulator (in `tenant`, if any): the uid and the ID token.
fn sign_up(daemon: &Daemon, email: &str, tenant: Option<&str>) -> (String, String) {
    let tenant = tenant.map_or(String::new(), |t| format!(r#","tenantId":"{t}""#));
    let (status, body) = request(
        daemon.auth_port(),
        "POST",
        "/identitytoolkit.googleapis.com/v1/accounts:signUp?key=fake-api-key",
        &["Content-Type: application/json"],
        &format!(r#"{{"email":"{email}","password":"hunter22","returnSecureToken":true{tenant}}}"#),
    );
    assert_eq!(status, 200, "{body}");
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();
    (
        body["localId"].as_str().unwrap().to_owned(),
        body["idToken"].as_str().unwrap().to_owned(),
    )
}

#[test]
#[allow(clippy::too_many_lines)] // one ordered, two-round Native observation matrix
fn locally_signed_users_match_twenty_native_auth_rules_cases() {
    let native: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/rtdb-genuine-auth-native.json")).unwrap();
    let cases = native["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 20);
    let ids: std::collections::BTreeSet<_> = cases
        .iter()
        .map(|case| case["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids.len(), 20);

    let dir = Scratch::new("database", "native-signed-users");
    let firebase_json = dir.join("firebase.json");
    std::fs::write(
        &firebase_json,
        r#"{"database":[
            {"instance":"demo-rtdb-default-rtdb","rules":"database.rules.json"},
            {"instance":"other-default-rtdb","rules":"database.rules.json"}]}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("database.rules.json"),
        r#"{"rules":{"rounds":{"$round":{"users":{"$uid":{
            ".read":"auth != null && auth.uid == $uid",
            ".write":"auth != null && auth.uid == $uid"}}}}}}"#,
    )
    .unwrap();
    let config = dir.join("fireemu.json");
    std::fs::write(
        &config,
        r#"{"schemaVersion":1,"profile":"strict","productionExact":true,"auth":{"idTokenSigning":"session-rsa","allowUnsignedIdTokens":false}}"#,
    )
    .unwrap();
    let daemon = Daemon::start(&[
        "--firebase-json",
        firebase_json.to_str().unwrap(),
        "--config",
        config.to_str().unwrap(),
        "--only",
        "database,auth",
        "--database-port",
        "0",
    ]);
    let port = daemon.database_port();
    let pid = daemon.child.id();
    eprintln!(
        "auth03 local daemon pid={pid} database_port={port} auth_port={}",
        daemon.auth_port()
    );
    let users = BTreeMap::from([
        ("a", sign_up(&daemon, "a@example.invalid", None)),
        ("b", sign_up(&daemon, "b@example.invalid", None)),
    ]);
    assert!(users["a"].0 != users["b"].0);
    for (_, token) in users.values() {
        assert_eq!(token.split('.').count(), 3);
        assert!(!token.rsplit('.').next().unwrap().is_empty());
    }
    // Each environment issues its own tokens. Only Rules-visible roles and outcomes
    // are compared; Native token bytes or validity under the local signer are not.
    let target = |round: u64, role: &str, actor: &str| {
        let uid = &users[role].0;
        let auth = users
            .get(actor)
            .map_or(String::new(), |(_, token)| format!("&auth={token}"));
        format!("/rounds/r{round}/users/{uid}.json?ns=demo-rtdb-default-rtdb{auth}")
    };
    let mut covered = std::collections::BTreeSet::new();
    let mut protected_readbacks = 0;
    for case in cases {
        let id = case["id"].as_str().unwrap();
        let round = case["round"].as_u64().unwrap();
        let actor = case["actor"].as_str().unwrap();
        let role = case["target"].as_str().unwrap();
        let method = case["method"].as_str().unwrap();
        assert!(matches!(round, 1 | 2));
        assert!(matches!(actor, "a" | "b" | "anonymous"));
        assert!(matches!(role, "a" | "b"));
        assert!(matches!(method, "GET" | "PUT"));
        assert!(covered.insert((round, actor, role, method)));
        let body = if method == "PUT" {
            serde_json::to_string(&case["requestBody"]).unwrap()
        } else {
            String::new()
        };
        let (status, body) = request(port, method, &target(round, role, actor), &[], &body);
        assert_eq!(u64::from(status), case["status"].as_u64().unwrap(), "{id}");
        let body: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(body, case["body"], "{id}");
        if let Some(protected) = case.get("protectedReadback") {
            // Use the target's genuine user token, never an administrator override.
            let (status, body) = request(port, "GET", &target(round, role, role), &[], "");
            assert_eq!(
                u64::from(status),
                protected["status"].as_u64().unwrap(),
                "{id}"
            );
            let body: serde_json::Value = serde_json::from_str(&body).unwrap();
            assert_eq!(
                body, protected["body"],
                "{id}: denied PUT changed the value"
            );
            protected_readbacks += 1;
        }
    }
    assert_eq!(covered.len(), 20);
    assert_eq!(protected_readbacks, 6);
    for round in [1, 2] {
        for (actor, role) in [
            ("a", "a"),
            ("b", "b"),
            ("a", "b"),
            ("b", "a"),
            ("anonymous", "a"),
        ] {
            for method in ["GET", "PUT"] {
                assert!(covered.contains(&(round, actor, role, method)));
            }
        }
    }

    // A genuine signed token is also bound to the instance's project. The foreign
    // instance has the same rules, so an absent rules file cannot explain this denial.
    let foreign = target(1, "a", "a").replace("ns=demo-rtdb-default-rtdb", "ns=other-default-rtdb");
    assert_eq!(request(port, "GET", &foreign, &[], "").0, 401);

    // A damaged signature must not become a Rules identity through claim decoding.
    let mut parts = users["a"].1.split('.');
    let (head, claims, signature) = (
        parts.next().unwrap(),
        parts.next().unwrap(),
        parts.next().unwrap(),
    );
    let first = if signature.starts_with('A') { 'B' } else { 'A' };
    let damaged = format!("{head}.{claims}.{first}{}", &signature[1..]);
    let own = target(1, "a", "anonymous");
    assert_eq!(
        request(port, "GET", &format!("{own}&auth={damaged}"), &[], "").0,
        401
    );
    drop(daemon);
    eprintln!("auth03 local daemon retired pid={pid}");
}

#[test]
#[allow(clippy::too_many_lines)] // one matrix: profile x token kind x instance kind
fn credentials_follow_the_profile_and_bind_tokens_to_the_instance_project() {
    let dir = Scratch::new("database", "credentials");
    let firebase_json = dir.join("firebase.json");
    std::fs::write(
        &firebase_json,
        r#"{"database":[
            {"instance":"demo-rtdb-default-rtdb","rules":"database.rules.json"},
            {"instance":"demo-rtdb-secondary","rules":"database.rules.json"},
            {"instance":"other-default-rtdb","rules":"database.rules.json"}]}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("database.rules.json"),
        r#"{"rules":{"users":{"$uid":{".read":"auth != null && auth.uid === $uid"}},
            "anon":{".read":"auth == null"}}}"#,
    )
    .unwrap();
    let tenants = r#""auth":{"multiTenant":{"allowTenants":true},"tenants":[{"tenantId":"acme-x7k2q","displayName":"acme","allowPasswordSignup":true}]}"#;
    let profiles = [
        (
            "emulator",
            format!(r#"{{"schemaVersion":1,"profile":"emulator",{tenants}}}"#),
        ),
        (
            "strict",
            format!(r#"{{"schemaVersion":1,"profile":"strict",{tenants}}}"#),
        ),
        (
            "exact",
            format!(r#"{{"schemaVersion":1,"profile":"strict","productionExact":true,{tenants}}}"#),
        ),
    ];
    for (name, config) in profiles {
        let path = dir.join(format!("{name}.json"));
        std::fs::write(&path, config).unwrap();
        let daemon = Daemon::start(&[
            "--firebase-json",
            firebase_json.to_str().unwrap(),
            "--config",
            path.to_str().unwrap(),
            "--only",
            "database,auth",
            "--database-port",
            "0",
        ]);
        let port = daemon.database_port();
        let read = |ns: &str, path: &str, query: &str, headers: &[&str]| {
            let target = format!("{path}.json?ns={ns}{query}");
            request(port, "GET", &target, headers, "").0
        };
        let (uid, signed) = sign_up(&daemon, "rtdb@example.com", None);
        let (tenant_uid, tenant_token) = sign_up(&daemon, "t@example.com", Some("acme-x7k2q"));
        let strict = name != "emulator";
        let exact = name == "exact";
        // A credential that names no one: anonymous under the emulator profile, 401 under strict.
        let nobody = if strict { 401 } else { 200 };
        let own = format!("/users/{uid}");
        let default = "demo-rtdb-default-rtdb";
        let named = "demo-rtdb-secondary";
        let other = "other-default-rtdb";
        let auth = |token: &str| format!("&auth={token}");
        // A token fireemu's Auth issued for the project is its user on every instance of the
        // project, and nobody on another project's instance; under the emulator profile its
        // tokens are unsigned, and an unsigned token is its user anywhere, as on the official
        // emulator.
        assert_eq!(read(default, &own, &auth(&signed), &[]), 200, "{name}");
        assert_eq!(read(named, &own, &auth(&signed), &[]), 200, "{name}");
        let (elsewhere, anonymous) = if strict { (401, 401) } else { (200, 401) };
        assert_eq!(read(other, &own, &auth(&signed), &[]), elsewhere, "{name}");
        assert_eq!(
            read(other, "/anon", &auth(&signed), &[]),
            anonymous,
            "{name}"
        );
        // So is a tenant's token.
        let tenant_own = format!("/users/{tenant_uid}");
        assert_eq!(
            read(default, &tenant_own, &auth(&tenant_token), &[]),
            200,
            "{name}"
        );
        // The SDK's mock token is its user while unsigned tokens are admitted (not under
        // productionExact): on its project's instances, and under the emulator profile on any
        // instance whatever project it names, as on the official emulator; nobody elsewhere.
        let mock = mock_token("u1");
        let mock_status = if exact { 401 } else { 200 };
        assert_eq!(
            read(default, "/users/u1", &auth(&mock), &[]),
            mock_status,
            "{name}"
        );
        assert_eq!(
            read(named, "/users/u1", &auth(&mock), &[]),
            mock_status,
            "{name}"
        );
        let anywhere = if strict { 401 } else { 200 };
        assert_eq!(
            read(other, "/users/u1", &auth(&mock), &[]),
            anywhere,
            "{name}"
        );
        let foreign = mock_token_for("someone-else", "u1");
        assert_eq!(
            read(default, "/users/u1", &auth(&foreign), &[]),
            anywhere,
            "{name}"
        );
        // Under strict it is refused there; under the emulator profile it is a user, not anonymous.
        assert_eq!(read(other, "/anon", &auth(&mock), &[]), 401, "{name}");
        // An unsigned token without `aud` (expired, even): the user its `sub` names under the
        // emulator profile, as on the official emulator, which reads the claims unverified;
        // without `sub` it names no one. Under strict it names no one either way.
        let unsigned = |claims: &str| {
            format!(
                "{}.{}.",
                segment(r#"{"alg":"none","typ":"JWT"}"#).trim_end_matches('.'),
                segment(claims).trim_end_matches('.')
            )
        };
        let no_aud = unsigned(r#"{"sub":"u1","iat":1,"exp":2}"#);
        let user = if strict { 401 } else { 200 };
        assert_eq!(
            read(default, "/users/u1", &auth(&no_aud), &[]),
            user,
            "{name}"
        );
        assert_eq!(read(default, "/anon", &auth(&no_aud), &[]), 401, "{name}");
        let no_sub = unsigned(r#"{"iat":1,"exp":9999999999}"#);
        assert_eq!(
            read(default, "/users/u1", &auth(&no_sub), &[]),
            401,
            "{name}"
        );
        assert_eq!(
            read(default, "/anon", &auth(&no_sub), &[]),
            nobody,
            "{name}"
        );
        // A signed token fireemu cannot verify (G10 rows auth-rs256 and auth-hs256: the official
        // emulator answered 200 for both). The emulator profile reads its claims unverified, in
        // the recorded shape only: RS256 or HS256, a non-empty signature, `aud` the instance's
        // project, `exp` in the future. Strict and productionExact never admit one.
        let forged = |alg: &str, signature: &str, claims: &str| {
            format!(
                "{}.{}.{signature}",
                segment(&format!(r#"{{"alg":"{alg}","typ":"JWT","kid":"unknown"}}"#))
                    .trim_end_matches('.'),
                segment(claims).trim_end_matches('.')
            )
        };
        let own = format!(r#"{{"aud":"{PROJECT}","sub":"u1","iat":1,"exp":9999999999}}"#);
        let admitted = if strict { 401 } else { 200 };
        for alg in ["RS256", "HS256"] {
            let token = forged(alg, "c2ln", &own);
            assert_eq!(
                read(default, "/users/u1", &auth(&token), &[]),
                admitted,
                "{name}: {alg}"
            );
            // It is its user, not anonymous.
            assert_eq!(
                read(default, "/anon", &auth(&token), &[]),
                401,
                "{name}: {alg}"
            );
        }
        for (what, token) in [
            ("ES256", forged("ES256", "c2ln", &own)),
            ("empty signature", forged("RS256", "", &own)),
            (
                "another project",
                forged(
                    "RS256",
                    "c2ln",
                    r#"{"aud":"someone-else","sub":"u1","iat":1,"exp":9999999999}"#,
                ),
            ),
            (
                "expired",
                forged(
                    "RS256",
                    "c2ln",
                    &format!(r#"{{"aud":"{PROJECT}","sub":"u1","iat":1,"exp":2}}"#),
                ),
            ),
            (
                "no exp",
                forged(
                    "HS256",
                    "c2ln",
                    &format!(r#"{{"aud":"{PROJECT}","sub":"u1","iat":1}}"#),
                ),
            ),
            (
                "no aud",
                forged("RS256", "c2ln", r#"{"sub":"u1","iat":1,"exp":9999999999}"#),
            ),
        ] {
            assert_eq!(
                read(default, "/users/u1", &auth(&token), &[]),
                401,
                "{name}: {what}"
            );
            assert_eq!(
                read(default, "/anon", &auth(&token), &[]),
                nobody,
                "{name}: {what}"
            );
        }
        let no_subject = forged(
            "RS256",
            "c2ln",
            &format!(r#"{{"aud":"{PROJECT}","iat":1,"exp":9999999999}}"#),
        );
        assert_eq!(
            read(default, "/users/u1", &auth(&no_subject), &[]),
            401,
            "{name}: no sub"
        );
        assert_eq!(
            read(default, "/anon", &auth(&no_subject), &[]),
            nobody,
            "{name}: no sub"
        );
        // Access tokens: any one is an administrator under the emulator profile, only `owner`
        // under strict; `auth=owner` names no one.
        let other_bearer = ["Authorization: Bearer ya29.other"];
        let expected = if strict { 401 } else { 200 };
        assert_eq!(
            read(default, "/users/u2", "", &other_bearer),
            expected,
            "{name}"
        );
        assert_eq!(
            read(default, "/users/u2", "", &["Authorization: Bearer owner"]),
            200,
            "{name}"
        );
        assert_eq!(read(default, "/anon", "&auth=owner", &[]), nobody, "{name}");
    }
}

#[test]
fn a_deep_rule_from_any_access_token_never_stops_the_daemon() {
    // Under the emulator profile any access token may load rules.
    let dir = Scratch::new("database", "deep-rule");
    let config = dir.join("emulator.json");
    std::fs::write(&config, r#"{"schemaVersion":1,"profile":"emulator"}"#).unwrap();
    let daemon = Daemon::start(&[
        "--config",
        config.to_str().unwrap(),
        "--only",
        "database",
        "--database-port",
        "0",
    ]);
    let port = daemon.database_port();
    let deep_child = format!("root{}.val() == null", ".child('a')".repeat(10_000));
    let deep_ternary = format!(
        "{}true{}",
        "true ? ".repeat(10_000),
        " : false".repeat(10_000)
    );
    for rule in [deep_child, deep_ternary] {
        let body = format!(r#"{{"rules":{{".read":"{rule}"}}}}"#);
        let (status, text) = request(
            port,
            "PUT",
            "/.settings/rules.json?ns=deep",
            &["Authorization: Bearer anything"],
            &body,
        );
        assert_eq!(status, 400, "{text}");
        assert_eq!(request(port, "GET", "/.json?ns=deep", &[], "").0, 200);
    }
}

/// `1 - (inner) - 0 - 0 …`: the inner expression lands `tail` levels below the outermost
/// operator although it is read first.
fn left_nested(inner: &str, tail: usize) -> String {
    format!("1 - ({inner}){}", " - 0".repeat(tail))
}

#[test]
fn a_deep_rule_built_from_shallow_pieces_never_stops_the_daemon() {
    // Each piece nests 590 levels, which alone is within the bound; nested six times they
    // are about 3,500 levels deep (review r3 M6c).
    let dir = Scratch::new("database", "composed-rule");
    let config = dir.join("emulator.json");
    std::fs::write(&config, r#"{"schemaVersion":1,"profile":"emulator"}"#).unwrap();
    let daemon = Daemon::start(&[
        "--config",
        config.to_str().unwrap(),
        "--only",
        "database",
        "--database-port",
        "0",
    ]);
    let port = daemon.database_port();
    let mut sub = "1".to_owned();
    for _ in 0..6 {
        sub = left_nested(&sub, 590);
    }
    let mut parents = "root.child('a')".to_owned();
    for _ in 0..6 {
        parents = format!(
            "root.child({parents}.val() + 'a'){}",
            ".parent()".repeat(590)
        );
    }
    let mut index = "auth".to_owned();
    for _ in 0..6 {
        index = format!("auth[{index} == null ? 'a' : 'b']{}", ".y".repeat(590));
    }
    for rule in [
        format!("{sub} < 0"),
        format!("{parents}.val() == null"),
        format!("{index} == null"),
        format!("({sub} < 0) ? true : false"),
    ] {
        let body = format!(r#"{{"rules":{{".read":"{rule}"}}}}"#);
        let headers = ["Authorization: Bearer anything"];
        let (status, _) = request(
            port,
            "PUT",
            "/.settings/rules.json?ns=deep",
            &headers,
            &body,
        );
        // Whether it is refused or loaded, reading and replacing it leave the daemon running.
        let _ = std::panic::catch_unwind(|| request(port, "GET", "/.json?ns=deep", &[], ""));
        std::thread::sleep(Duration::from_millis(200));
        assert!(
            TcpStream::connect(("127.0.0.1", port)).is_ok(),
            "the daemon stopped on reading a rule it answered {status} to"
        );
        let (replaced, _) = request(
            port,
            "PUT",
            "/.settings/rules.json?ns=deep",
            &headers,
            r#"{"rules":{}}"#,
        );
        assert_eq!(
            replaced,
            200,
            "the daemon stopped after a rule ({status}) {}",
            rule.len()
        );
        assert_eq!(request(port, "GET", "/.json?ns=other", &[], "").0, 200);
    }
}

/// `ServerValue.TIMESTAMP` written through REST, read back as milliseconds.
fn server_timestamp(port: u16, path: &str) -> i64 {
    let ns = "ns=demo-rtdb-default-rtdb";
    let (status, _) = request(
        port,
        "PUT",
        &format!("/{path}.json?{ns}"),
        &[],
        r#"{".sv":"timestamp"}"#,
    );
    assert_eq!(status, 200);
    request(port, "GET", &format!("/{path}.json?{ns}"), &[], "")
        .1
        .parse()
        .unwrap()
}

fn wall_millis() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap()
}

#[test]
fn the_default_clock_follows_real_time() {
    let daemon = Daemon::start(&["--only", "database", "--database-port", "0"]);
    let port = daemon.database_port();
    let before = wall_millis();
    let first = server_timestamp(port, "t/a");
    std::thread::sleep(Duration::from_millis(120));
    let second = server_timestamp(port, "t/b");
    let after = wall_millis();
    assert!(
        before <= first && first <= after,
        "{before} {first} {after}"
    );
    assert!(second - first >= 100, "{first} {second}");
    assert!(second <= after, "{second} {after}");
}

#[test]
fn a_pinned_start_stands_still_unless_the_clock_follows_real_time() {
    const START_MILLIS: i64 = 1_767_225_600_000; // 2026-01-01T00:00:00Z
    let dir = Scratch::new("database", "clock-modes");
    for (clock, frozen) in [
        (None, true),
        (Some("frozen"), true),
        (Some("realtime"), false),
    ] {
        let mut daemon_section = serde_json::json!({"clockStart": "2026-01-01T00:00:00Z"});
        if let Some(clock) = clock {
            daemon_section["clock"] = serde_json::json!(clock);
        }
        let config = dir.join(format!("fireemu-{}.json", clock.unwrap_or("default")));
        std::fs::write(
            &config,
            serde_json::json!({"schemaVersion": 1, "daemon": daemon_section}).to_string(),
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
        let first = server_timestamp(port, "t/a");
        std::thread::sleep(Duration::from_millis(150));
        let second = server_timestamp(port, "t/b");
        if frozen {
            assert_eq!((first, second), (START_MILLIS, START_MILLIS), "{clock:?}");
        } else {
            assert!(
                (START_MILLIS..START_MILLIS + 60_000).contains(&first),
                "{clock:?} {first}"
            );
            assert!(second - first >= 100, "{clock:?} {first} {second}");
        }
    }
}

/// A JWT with the given header algorithm, signature segment and claims text.
fn jwt(alg: &str, signature: &str, claims: &str) -> String {
    format!(
        "{}.{}.{signature}",
        segment(&format!(r#"{{"alg":"{alg}","typ":"JWT"}}"#)).trim_end_matches('.'),
        segment(claims).trim_end_matches('.')
    )
}

/// The status of the answer to a Realtime `auth` message (`ok`, `invalid_token`, ...).
fn websocket_auth(port: u16, ns: &str, cred: &str) -> String {
    use std::io::Read as _;
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    write!(
        stream,
        "GET /.ws?v=5&ns={ns} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
    )
    .unwrap();
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        let mut byte = [0u8; 1];
        stream.read_exact(&mut byte).unwrap();
        head.push(byte[0]);
    }
    let message = format!(r#"{{"t":"d","d":{{"r":1,"a":"auth","b":{{"cred":"{cred}"}}}}}}"#);
    let bytes = message.as_bytes();
    let mut frame = vec![0x81, 0xFE]; // a masked text frame with a 16-bit length
    frame.extend_from_slice(&u16::try_from(bytes.len()).unwrap().to_be_bytes());
    frame.extend_from_slice(&[0, 0, 0, 0]); // a zero mask key leaves the payload as it is
    frame.extend_from_slice(bytes);
    stream.write_all(&frame).unwrap();
    loop {
        let mut two = [0u8; 2];
        stream.read_exact(&mut two).unwrap();
        let mut length = usize::from(two[1] & 0x7f);
        if length == 126 {
            let mut extended = [0u8; 2];
            stream.read_exact(&mut extended).unwrap();
            length = usize::from(u16::from_be_bytes(extended));
        } else if length == 127 {
            let mut extended = [0u8; 8];
            stream.read_exact(&mut extended).unwrap();
            length = usize::try_from(u64::from_be_bytes(extended)).unwrap();
        }
        let mut payload = vec![0u8; length];
        stream.read_exact(&mut payload).unwrap();
        let text = String::from_utf8_lossy(&payload).into_owned();
        if text.contains(r#""r":1"#) {
            let value: serde_json::Value = serde_json::from_str(&text).unwrap();
            return value["d"]["b"]["s"].as_str().unwrap().to_owned();
        }
    }
}

/// A signed token fireemu cannot verify takes the tenant route of an unsigned token (review of the
/// credential answers): a tenant it names must exist, and one that is missing or deleted leaves
/// the token nobody. The decision is the same for a REST read, a REST write and a WebSocket
/// `auth` message, because they share one verifier.
#[test]
#[allow(clippy::too_many_lines)] // one matrix: token kind x tenant state x transport
fn forged_signed_tokens_follow_the_tenant_route_of_unsigned_tokens() {
    let dir = Scratch::new("database", "forged-tenants");
    let firebase_json = dir.join("firebase.json");
    std::fs::write(
        &firebase_json,
        r#"{"database":[{"instance":"demo-rtdb-default-rtdb","rules":"database.rules.json"}]}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("database.rules.json"),
        r#"{"rules":{"users":{"$uid":{".read":"auth != null && auth.uid === $uid"}},
            "box":{".read":true,".write":"auth != null"}}}"#,
    )
    .unwrap();
    let config = dir.join("emulator.json");
    std::fs::write(
        &config,
        r#"{"schemaVersion":1,"profile":"emulator","auth":{"multiTenant":{"allowTenants":true},"tenants":[{"tenantId":"acme-x7k2q","displayName":"acme","allowPasswordSignup":true}]}}"#,
    )
    .unwrap();
    let daemon = Daemon::start(&[
        "--firebase-json",
        firebase_json.to_str().unwrap(),
        "--config",
        config.to_str().unwrap(),
        "--only",
        "database,auth",
        "--database-port",
        "0",
    ]);
    let port = daemon.database_port();
    // A tenant that existed and was deleted.
    let admin = [
        "Authorization: Bearer owner",
        "Content-Type: application/json",
    ];
    let (status, body) = request(
        daemon.auth_port(),
        "POST",
        &format!("/identitytoolkit.googleapis.com/v2/projects/{PROJECT}/tenants"),
        &admin,
        r#"{"displayName":"gone"}"#,
    );
    assert_eq!(status, 200, "{body}");
    let created: serde_json::Value = serde_json::from_str(&body).unwrap();
    let deleted = created["name"]
        .as_str()
        .unwrap()
        .rsplit('/')
        .next()
        .unwrap()
        .to_owned();
    let (status, body) = request(
        daemon.auth_port(),
        "DELETE",
        &format!("/identitytoolkit.googleapis.com/v2/projects/{PROJECT}/tenants/{deleted}"),
        &admin,
        "",
    );
    assert_eq!(status, 200, "{body}");
    let ns = "demo-rtdb-default-rtdb";
    let claims = |tenant: &str| {
        format!(
            r#"{{"aud":"{PROJECT}","sub":"u1","iat":1,"exp":9999999999,"firebase":{{"tenant":"{tenant}"}}}}"#
        )
    };
    let tokens = |tenant: &str| {
        [
            ("unsigned", jwt("none", "", &claims(tenant))),
            ("RS256", jwt("RS256", "c2ln", &claims(tenant))),
            ("HS256", jwt("HS256", "c2ln", &claims(tenant))),
        ]
    };
    for (state, tenant, exists) in [
        ("existing", "acme-x7k2q", true),
        ("missing", "never-x1y2z", false),
        ("deleted", deleted.as_str(), false),
    ] {
        let mut reads = Vec::new();
        for (kind, token) in tokens(tenant) {
            let read = request(
                port,
                "GET",
                &format!("/users/u1.json?ns={ns}&auth={token}"),
                &[],
                "",
            )
            .0;
            let write = request(
                port,
                "PUT",
                &format!("/box.json?ns={ns}&auth={token}"),
                &[],
                &format!(r#""{kind}-{state}""#),
            )
            .0;
            let stored = request(port, "GET", &format!("/box.json?ns={ns}"), &[], "").1;
            let socket = websocket_auth(port, ns, &token);
            // A refused token is nobody: the read of the user's node and the write fail, the
            // write leaves the data as it was, and the WebSocket does not accept the token.
            if exists {
                assert_eq!((read, write), (200, 200), "{kind} {state}");
                assert_eq!(stored, format!(r#""{kind}-{state}""#), "{kind} {state}");
                assert_eq!(socket, "ok", "{kind} {state}");
            } else {
                assert_eq!((read, write), (401, 401), "{kind} {state}");
                assert_ne!(stored, format!(r#""{kind}-{state}""#), "{kind} {state}");
                assert_eq!(socket, "invalid_token", "{kind} {state}");
            }
            reads.push((read, write, socket));
        }
        // A forged token is routed exactly as the unsigned one is.
        assert!(reads.iter().all(|r| *r == reads[0]), "{state}: {reads:?}");
    }
}

/// A daemon serving the database (and Auth) of `PROJECT` with `config`, and rules that let a user
/// read their own node.
fn guard_daemon(dir: &Scratch, name: &str, config: &str) -> Daemon {
    let firebase_json = dir.join(format!("{name}.firebase.json"));
    std::fs::write(
        &firebase_json,
        r#"{"database":[{"instance":"demo-rtdb-default-rtdb","rules":"database.rules.json"}]}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("database.rules.json"),
        r#"{"rules":{"users":{"$uid":{".read":"auth != null && auth.uid === $uid"}}}}"#,
    )
    .unwrap();
    let config_path = dir.join(format!("{name}.json"));
    std::fs::write(&config_path, config).unwrap();
    Daemon::start(&[
        "--firebase-json",
        firebase_json.to_str().unwrap(),
        "--config",
        config_path.to_str().unwrap(),
        "--only",
        "database,auth",
        "--database-port",
        "0",
    ])
}

/// What a token is on a daemon: the status of the read of `/users/u1` (a user's own node) and the
/// status of a WebSocket `auth` message.
fn token_on(daemon: &Daemon, token: &str) -> (u16, String) {
    let ns = "demo-rtdb-default-rtdb";
    let port = daemon.database_port();
    let read = request(
        port,
        "GET",
        &format!("/users/u1.json?ns={ns}&auth={token}"),
        &[],
        "",
    )
    .0;
    (read, websocket_auth(port, ns, token))
}

/// The fallback that reads a signed token's claims unverified (G10 rows auth-rs256 and
/// auth-hs256) is guarded by two conditions of its own: unsigned tokens are admitted, and no
/// session signer is installed. Each is pinned here on the emulator profile, where strict does not
/// block the fallback by itself. HS256 is the sensitive case of the signer condition (an RS256
/// token is refused earlier by a signer's key check).
#[test]
fn the_unverified_claims_of_a_signed_token_need_unsigned_admission_and_no_signer() {
    let dir = Scratch::new("database", "fallback-guards");
    let claims = format!(r#"{{"aud":"{PROJECT}","sub":"u1","iat":1,"exp":9999999999}}"#);
    let tokens = [
        ("RS256", jwt("RS256", "c2ln", &claims)),
        ("HS256", jwt("HS256", "c2ln", &claims)),
    ];
    // The control: the default emulator profile admits both.
    let control = guard_daemon(
        &dir,
        "control",
        r#"{"schemaVersion":1,"profile":"emulator"}"#,
    );
    for (alg, token) in &tokens {
        assert_eq!(
            token_on(&control, token),
            (200, "ok".to_owned()),
            "control {alg}"
        );
    }
    drop(control);
    // (a) Unsigned tokens are not admitted: the emulator profile admits no forged token either.
    let refused = guard_daemon(
        &dir,
        "no-unsigned",
        r#"{"schemaVersion":1,"profile":"emulator","auth":{"allowUnsignedIdTokens":false}}"#,
    );
    for (alg, token) in &tokens {
        assert_eq!(
            token_on(&refused, token),
            (401, "invalid_token".to_owned()),
            "unsigned admission off {alg}"
        );
    }
    drop(refused);
    // (b) A session signer is installed: a token with another algorithm is not a user.
    let signing = guard_daemon(
        &dir,
        "signer",
        r#"{"schemaVersion":1,"profile":"emulator","auth":{"idTokenSigning":"session-rsa","allowUnsignedIdTokens":true}}"#,
    );
    for (alg, token) in &tokens {
        assert_eq!(
            token_on(&signing, token),
            (401, "invalid_token".to_owned()),
            "session signer {alg}"
        );
    }
}

/// The claims of a forged token go through the parser, and its depth budget, that an unsigned
/// token's claims go through: the same nesting is a user for both or for neither, over REST and a
/// WebSocket `auth` message.
#[test]
fn forged_and_unsigned_claims_share_the_depth_budget() {
    let dir = Scratch::new("database", "claims-depth");
    let daemon = guard_daemon(&dir, "depth", r#"{"schemaVersion":1,"profile":"emulator"}"#);
    let nested = |depth: usize| {
        format!(
            r#"{{"aud":"{PROJECT}","sub":"u1","iat":1,"exp":9999999999,"x":{}0{}}}"#,
            "[".repeat(depth),
            "]".repeat(depth)
        )
    };
    for (depth, expected) in [
        (1, (200, "ok")),
        (60, (200, "ok")),
        (65, (401, "invalid_token")),
        (200, (401, "invalid_token")),
    ] {
        for (kind, token) in [
            ("unsigned", jwt("none", "", &nested(depth))),
            ("RS256", jwt("RS256", "c2ln", &nested(depth))),
            ("HS256", jwt("HS256", "c2ln", &nested(depth))),
        ] {
            assert_eq!(
                token_on(&daemon, &token),
                (expected.0, expected.1.to_owned()),
                "{kind} nested {depth}"
            );
        }
    }
}
