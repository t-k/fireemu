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

#[test]
fn the_banner_says_rules_are_not_evaluated_and_what_access_is_in_effect() {
    let dir = Scratch::new("database", "rules-banner");
    let open = Daemon::start(&["--only", "database", "--database-port", "0"]);
    let line = open.rules_line();
    assert!(line.contains("not evaluated"), "{line}");
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
fn declared_rules_that_are_not_enforced_are_a_warning_when_the_database_is_served() {
    let dir = Scratch::new("database", "rules-warning");
    let firebase_json = dir.join("firebase.json");
    std::fs::write(
        &firebase_json,
        r#"{"database":{"rules":"database.rules.json"}}"#,
    )
    .unwrap();
    let run = |only: &str| {
        let output = Command::new(env!("CARGO_BIN_EXE_fireemu"))
            .args(["exec", "--no-config-discovery", "--project", PROJECT])
            .args(["--firebase-json", firebase_json.to_str().unwrap()])
            .args(["--only", only, "--database-port", "0", "--http-port", "0"])
            .args(["--hub-port", "0", "--log-verbosity", "quiet", "--", "true"])
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stderr).unwrap()
    };
    let stderr = run("database");
    assert!(
        stderr.contains("warning: database: the rules in database.rules.json are not enforced"),
        "{stderr}"
    );
    assert!(
        stderr.contains("database.defaultAccess = open, default"),
        "{stderr}"
    );
    let stderr = run("auth");
    assert!(!stderr.contains("database.rules.json"), "{stderr}");
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
            .args(["--", "sh", "-c", script])
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
