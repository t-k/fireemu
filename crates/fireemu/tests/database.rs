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

#[test]
fn an_export_with_the_database_served_warns_that_its_data_is_not_exported() {
    let dir = Scratch::new("database", "export-warning");
    let run = |only: &str| {
        let export = dir.join(format!("export-{only}"));
        let output = Command::new(env!("CARGO_BIN_EXE_fireemu"))
            .args(["exec", "--no-config-discovery", "--project", PROJECT])
            .args(["--only", only, "--database-port", "0", "--http-port", "0"])
            .args(["--firestore-port", "0", "--hub-port", "0"])
            .arg("--export-on-exit")
            .arg(&export)
            .args(["--", "true"])
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
    let stderr = run("database,firestore");
    assert!(
        stderr.contains("warning: Realtime Database data is not exported"),
        "{stderr}"
    );
    let stderr = run("firestore");
    assert!(!stderr.contains("Realtime Database"), "{stderr}");
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

#[test]
fn emulators_export_prints_the_database_warning_the_hub_answers() {
    let dir = Scratch::new("database", "hub-export-warning");
    let export = dir.join("export");
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
    // Once from the suite's own log, once from the command that asked, which read it from
    // the Hub's answer.
    assert_eq!(
        stderr
            .matches("warning: Realtime Database data is not exported")
            .count(),
        2,
        "{stderr}"
    );
}

/// The unsigned ID token `@firebase/rules-unit-testing` mints for `uid` of the test project
/// (the SDK's `mockUserToken` shape).
fn mock_token(uid: &str) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let claims = format!(
        r#"{{"iss":"https://securetoken.google.com/{PROJECT}","aud":"{PROJECT}","iat":{now},"exp":{},"auth_time":{now},"sub":"{uid}","user_id":"{uid}","firebase":{{"sign_in_provider":"custom","identities":{{}}}}}}"#,
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
        // project, and nobody on another project's instance.
        assert_eq!(read(default, &own, &auth(&signed), &[]), 200, "{name}");
        assert_eq!(read(named, &own, &auth(&signed), &[]), 200, "{name}");
        assert_eq!(read(other, &own, &auth(&signed), &[]), 401, "{name}");
        assert_eq!(read(other, "/anon", &auth(&signed), &[]), nobody, "{name}");
        // So is a tenant's token.
        let tenant_own = format!("/users/{tenant_uid}");
        assert_eq!(
            read(default, &tenant_own, &auth(&tenant_token), &[]),
            200,
            "{name}"
        );
        // The SDK's mock token is its user on its project's instances while unsigned tokens
        // are admitted (not under productionExact), and nobody elsewhere.
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
        assert_eq!(read(other, "/users/u1", &auth(&mock), &[]), 401, "{name}");
        assert_eq!(read(other, "/anon", &auth(&mock), &[]), nobody, "{name}");
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
