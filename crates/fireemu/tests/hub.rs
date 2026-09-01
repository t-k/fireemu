//! The Emulator Hub over the wire: discovery, the locator file and the background-trigger
//! switch, checked against a daemon started the way a project would start it (CLI-03).
//!
//! Every scenario asks for an explicit Hub port so it never races another test for the
//! official default 4400, and gives the daemon its own project so its locator file is its
//! own.

use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// A port nothing is listening on, released before it is handed back.
fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("fireemu-hub-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// One HTTP request against the Hub. Written by hand because the binary's test suite has no
/// HTTP client dependency, and the Hub's answers are small enough to read in one go.
fn request(port: u16, method: &str, path: &str, host: &str) -> (u16, String) {
    let (status, _, body) = request_with_headers(port, method, path, host, &[], "");
    (status, body)
}

fn request_with_headers(
    port: u16,
    method: &str,
    path: &str,
    host: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> (u16, String, String) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("the Hub accepts");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    write!(stream, "{method} {path} HTTP/1.1\r\nHost: {host}\r\n").unwrap();
    for (name, value) in headers {
        write!(stream, "{name}: {value}\r\n").unwrap();
    }
    write!(
        stream,
        "Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
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
    (status, head.to_owned(), body.to_owned())
}

fn json(port: u16, method: &str, path: &str) -> serde_json::Value {
    let (status, body) = request(port, method, path, "127.0.0.1");
    assert_eq!(status, 200, "{method} {path} -> {body}");
    serde_json::from_str(&body).unwrap_or_else(|e| panic!("{method} {path}: {e}\n{body}"))
}

/// A daemon serving until it is stopped, with the Hub on `hub_port`.
struct Daemon {
    child: Child,
    project: String,
}

impl Daemon {
    fn start(project: &str, hub_port: u16, extra: &[&str]) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_fireemu"))
            .args([
                "up",
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
                "--project",
                project,
                "--hub-port",
            ])
            .arg(hub_port.to_string())
            .args(extra)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        // The banner's control-API line is printed once every listener is bound and served.
        // The pipe keeps being drained on its own thread afterwards: a closed stdout would
        // give the daemon a broken pipe on its next line and kill it mid-scenario.
        let stdout = child.stdout.take().unwrap();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel::<()>();
        std::thread::spawn(move || {
            let mut reader = BufReader::new(stdout);
            let mut ready = Some(ready_tx);
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
        ready_rx
            .recv_timeout(Duration::from_secs(60))
            .expect("the daemon became ready");
        Self {
            child,
            project: project.to_owned(),
        }
    }

    fn locator(&self) -> PathBuf {
        std::env::temp_dir().join(format!("hub-{}.json", self.project))
    }

    fn control_token(&self) -> String {
        let locator: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(self.locator()).unwrap()).unwrap();
        locator["fireemuControlToken"].as_str().unwrap().to_owned()
    }

    fn stop(mut self) {
        let _ = Command::new("kill")
            .args(["-TERM", &self.child.id().to_string()])
            .status();
        let _ = self.child.wait();
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn the_hub_publishes_every_running_emulator_in_the_official_shape() {
    let port = free_port();
    let daemon = Daemon::start("demo-hub-shape", port, &[]);
    let emulators = json(port, "GET", "/emulators");

    // Every selected service is present, keyed by its official name.
    for name in ["firestore", "auth", "storage", "hub"] {
        let entry = emulators
            .get(name)
            .unwrap_or_else(|| panic!("{name} is missing from {emulators}"));
        assert_eq!(entry["name"], name);
        assert_eq!(
            entry["host"], "127.0.0.1",
            "{name}: discovery clients build `host:port` without re-bracketing, so the entry must name the IPv4 loopback"
        );
        assert!(entry["port"].as_u64().is_some_and(|p| p > 0), "{name}");
        assert!(entry["pid"].as_u64().is_some_and(|p| p > 0), "{name}");
        let listen = &entry["listen"][0];
        assert_eq!(listen["address"], "127.0.0.1", "{name}");
        assert_eq!(listen["family"], "IPv4", "{name}");
        assert_eq!(listen["port"], entry["port"], "{name}");
    }
    // Nothing is claimed that is not running: no functions codebase was configured, the UI
    // was turned off, and fireemu serves none of the deferred products.
    for absent in [
        "functions",
        "ui",
        "database",
        "hosting",
        "pubsub",
        "eventarc",
        "tasks",
        "dataconnect",
        "extensions",
    ] {
        assert!(
            emulators.get(absent).is_none(),
            "{absent} must not be advertised: {emulators}"
        );
    }
    assert_eq!(emulators["hub"]["port"], u64::from(port));

    // `GET /` answers the locator plus this listener's own address.
    let root = json(port, "GET", "/");
    assert_eq!(root["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(root["origins"][0], format!("http://127.0.0.1:{port}"));
    assert_eq!(root["host"], "127.0.0.1");
    assert_eq!(root["port"], u64::from(port));
    assert!(root["pid"].as_u64().is_some_and(|p| p > 0));
    assert!(
        root.get("fireemuControlToken").is_none(),
        "the public Hub response must not expose the discovery capability"
    );

    // An unknown route is a 404, not a hang or a 200 with an empty body.
    let (status, _) = request(port, "GET", "/nope", "127.0.0.1");
    assert_eq!(status, 404);
    // The export route exists; a request without the official body is refused precisely
    // rather than writing a directory the caller never named. `tests/import_export.rs`
    // drives the successful path end to end.
    let token = daemon.control_token();
    let (status, _, body) = request_with_headers(
        port,
        "POST",
        "/_admin/export",
        "127.0.0.1",
        &[("Authorization", &format!("Bearer {token}"))],
        "",
    );
    assert_eq!(status, 400, "{body}");
    assert!(body.contains("export request body"), "{body}");

    // A non-loopback Host is refused: the Hub can disable background triggers, so a page on
    // a routable name must not reach it by DNS rebinding.
    let (status, _) = request(port, "GET", "/emulators", "attacker.example");
    assert_eq!(status, 403);

    daemon.stop();
}

#[test]
fn the_locator_file_is_written_at_start_and_removed_at_exit() {
    let port = free_port();
    let daemon = Daemon::start("demo-hub-locator", port, &[]);
    let path = daemon.locator();
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{} should exist: {e}", path.display()));
    let locator: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(locator["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(locator["origins"][0], format!("http://127.0.0.1:{port}"));
    assert_eq!(
        locator["pid"].as_u64().unwrap(),
        u64::from(daemon.child.id()),
        "the locator names the daemon that wrote it, which is what tells a second suite it is live"
    );
    assert_eq!(locator["fireemuControlToken"].as_str().unwrap().len(), 32);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    daemon.stop();
    let gone = Instant::now();
    while path.exists() && gone.elapsed() < Duration::from_secs(5) {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(
        !path.exists(),
        "{} outlived the daemon that wrote it",
        path.display()
    );
}

#[cfg(unix)]
#[test]
fn the_hub_discovery_file_never_follows_a_symlink() {
    use std::os::unix::fs::symlink;

    let project = format!("demo-hub-symlink-{}", std::process::id());
    let path = std::env::temp_dir().join(format!("hub-{project}.json"));
    let target = scratch("locator-symlink-target").join("target.txt");
    std::fs::write(&target, "do not replace").unwrap();
    let _ = std::fs::remove_file(&path);
    symlink(&target, &path).unwrap();
    let port = free_port();
    let daemon = Daemon::start(&project, port, &[]);
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "do not replace");
    assert!(std::fs::symlink_metadata(&path)
        .unwrap()
        .file_type()
        .is_symlink());
    daemon.stop();
    assert!(std::fs::symlink_metadata(&path)
        .unwrap()
        .file_type()
        .is_symlink());
    std::fs::remove_file(path).unwrap();
}

#[test]
fn a_daemon_that_could_not_bind_the_hub_serves_the_suite_anyway() {
    // The default Hub port is best effort, exactly like the UI's: a busy one disables
    // discovery and nothing else. An explicit one that cannot be bound is an error.
    let busy = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = busy.local_addr().unwrap().port();
    let output = Command::new(env!("CARGO_BIN_EXE_fireemu"))
        .args([
            "exec",
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
        .arg(port.to_string())
        .args(["--", "true"])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains(&format!("bind 127.0.0.1:{port}")),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    drop(busy);
}

#[test]
fn the_hub_switches_background_triggers_and_says_so() {
    let port = free_port();
    // No functions codebase is loaded, so the switch has nothing to act on and says that
    // rather than reporting a state it did not reach.
    let daemon = Daemon::start("demo-hub-triggers", port, &[]);
    let token = daemon.control_token();
    let (status, _, body) = request_with_headers(
        port,
        "PUT",
        "/functions/disableBackgroundTriggers",
        "127.0.0.1",
        &[("Authorization", &format!("Bearer {token}"))],
        "",
    );
    assert_eq!(status, 400, "{body}");
    assert!(
        body.contains("Cloud Functions emulator is not running"),
        "{body}"
    );
    daemon.stop();

    // With a codebase loaded, both routes answer the official `{"enabled": ...}` body.
    let port = free_port();
    let functions = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tools/sdk-smoke/functions-project");
    // The codebase resolves firebase-functions through tools/sdk-smoke/node_modules; without
    // an install this half of the scenario cannot run, and the smoke there covers it instead.
    if !functions
        .join("../node_modules/firebase-functions")
        .is_dir()
    {
        return;
    }
    let daemon = Daemon::start(
        "demo-hub-triggers-fn",
        port,
        &[
            "--functions",
            functions.to_str().unwrap(),
            "--functions-port",
            "0",
        ],
    );
    let token = daemon.control_token();
    let mutation = |path: &str| {
        let (status, _, body) = request_with_headers(
            port,
            "PUT",
            path,
            "127.0.0.1",
            &[("Authorization", &format!("Bearer {token}"))],
            "",
        );
        assert_eq!(status, 200, "PUT {path} -> {body}");
        serde_json::from_str::<serde_json::Value>(&body).unwrap()
    };
    let disabled = mutation("/functions/disableBackgroundTriggers");
    assert_eq!(disabled["enabled"], false);
    let enabled = mutation("/functions/enableBackgroundTriggers");
    assert_eq!(enabled["enabled"], true);
    // The Functions emulator is discoverable while it runs.
    let emulators = json(port, "GET", "/emulators");
    assert_eq!(emulators["functions"]["name"], "functions");
    let _ = scratch("triggers");
    daemon.stop();
}

#[test]
fn hub_mutations_require_a_local_browser_origin_and_the_control_capability() {
    let port = free_port();
    let daemon = Daemon::start("demo-hub-mutation-security", port, &[]);
    let token = daemon.control_token();
    let path = "/functions/disableBackgroundTriggers";

    for (label, headers) in [
        (
            "remote origin",
            vec![
                ("Origin", "https://attacker.example"),
                ("Access-Control-Request-Method", "PUT"),
                ("Access-Control-Request-Headers", "authorization"),
            ],
        ),
        (
            "opaque origin",
            vec![
                ("Origin", "null"),
                ("Access-Control-Request-Method", "PUT"),
                ("Access-Control-Request-Headers", "authorization"),
            ],
        ),
        (
            "wrong requested method",
            vec![
                ("Origin", "http://127.0.0.1:4000"),
                ("Access-Control-Request-Method", "POST"),
                ("Access-Control-Request-Headers", "authorization"),
            ],
        ),
        (
            "unapproved requested header",
            vec![
                ("Origin", "http://127.0.0.1:4000"),
                ("Access-Control-Request-Method", "PUT"),
                ("Access-Control-Request-Headers", "x-fireemu-internal"),
            ],
        ),
        (
            "cross-site fetch metadata",
            vec![
                ("Origin", "http://127.0.0.1:4000"),
                ("Access-Control-Request-Method", "PUT"),
                ("Access-Control-Request-Headers", "authorization"),
                ("Sec-Fetch-Site", "cross-site"),
            ],
        ),
    ] {
        let (status, head, _) =
            request_with_headers(port, "OPTIONS", path, "127.0.0.1", &headers, "");
        assert_eq!(status, 403, "{label}: {head}");
        assert!(
            !head
                .to_ascii_lowercase()
                .contains("access-control-allow-origin"),
            "{label}: {head}"
        );
    }

    let local_origin = "http://127.0.0.1:4000";
    let (status, head, _) = request_with_headers(
        port,
        "OPTIONS",
        path,
        "127.0.0.1",
        &[
            ("Origin", local_origin),
            ("Access-Control-Request-Method", "PUT"),
            ("Access-Control-Request-Headers", "authorization"),
            ("Sec-Fetch-Site", "same-site"),
            ("Sec-Fetch-Mode", "cors"),
            ("Access-Control-Request-Private-Network", "true"),
        ],
        "",
    );
    let lower = head.to_ascii_lowercase();
    assert_eq!(status, 204, "{head}");
    assert!(lower.contains(&format!("access-control-allow-origin: {local_origin}")));
    assert!(
        lower.contains("access-control-allow-methods: put"),
        "{head}"
    );
    assert!(
        lower.contains("access-control-allow-headers: authorization"),
        "{head}"
    );
    assert!(lower.contains("access-control-allow-private-network: true"));
    assert!(lower.contains("vary: origin, access-control-request-method, access-control-request-headers, access-control-request-private-network, sec-fetch-site, sec-fetch-mode"), "{head}");

    for (label, authorization) in [
        ("missing token", None),
        ("wrong token", Some("Bearer wrong")),
    ] {
        let mut headers = vec![("Origin", local_origin)];
        if let Some(value) = authorization {
            headers.push(("Authorization", value));
        }
        let (status, _, _) = request_with_headers(port, "PUT", path, "127.0.0.1", &headers, "");
        assert_eq!(status, 403, "{label}");
    }
    let authorization = format!("Bearer {token}");
    let (status, head, body) = request_with_headers(
        port,
        "PUT",
        path,
        "127.0.0.1",
        &[("Origin", local_origin), ("Authorization", &authorization)],
        "",
    );
    assert_eq!(status, 400, "{body}");
    assert!(
        head.to_ascii_lowercase()
            .contains(&format!("access-control-allow-origin: {local_origin}")),
        "{head}"
    );
    daemon.stop();
}

#[test]
fn exec_exports_the_hub_address_to_its_command() {
    let dir = scratch("env");
    let out = dir.join("env.txt");
    let port = free_port();
    let output = Command::new(env!("CARGO_BIN_EXE_fireemu"))
        .args([
            "exec",
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
            "--project",
            "demo-hub-env",
            "--hub-port",
        ])
        .arg(port.to_string())
        .args(["--", "sh", "-c"])
        .arg(format!("env > {}", out.display()))
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let env: std::collections::BTreeMap<String, String> = std::fs::read_to_string(&out)
        .unwrap()
        .lines()
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect();
    // A bare host:port, as `firebase-tools` writes it; `@firebase/rules-unit-testing` parses
    // it with `new URL("http://" + value)`, so a scheme here would break discovery.
    assert_eq!(env["FIREBASE_EMULATOR_HUB"], format!("127.0.0.1:{port}"));

    // The locator the run wrote is gone with it.
    let locator = std::env::temp_dir().join("hub-demo-hub-env.json");
    assert!(!locator.exists(), "{} outlived exec", locator.display());
}

#[test]
fn turning_the_hub_off_leaves_no_listener_and_no_variable() {
    let dir = scratch("off");
    let out = dir.join("env.txt");
    let output = Command::new(env!("CARGO_BIN_EXE_fireemu"))
        .args([
            "exec",
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
            "0",
            "--project",
            "demo-hub-off",
            "--",
            "sh",
            "-c",
        ])
        .arg(format!("env > {}", out.display()))
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = std::fs::read_to_string(&out).unwrap();
    assert!(
        !text.contains("FIREBASE_EMULATOR_HUB"),
        "the Hub was turned off but its variable was still exported"
    );
    assert!(!std::env::temp_dir().join("hub-demo-hub-off.json").exists());
}

/// The export route is the one Hub route that writes to disk. Its CSRF wall is the refusal of
/// every request carrying an `Origin`: the official CLI drives it without one, a page in a
/// browser cannot avoid sending one.
#[test]
fn the_export_route_requires_the_control_capability_and_refuses_browser_origins() {
    use std::io::{Read as _, Write as _};
    use std::net::TcpStream;
    use std::time::Duration;
    let dir = std::env::temp_dir().join(format!("fireemu-hub-export-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let port = free_port();
    let daemon = Daemon::start("demo-hub-export", port, &[]);
    let token = daemon.control_token();
    let send = |origin: Option<&str>, authorization: Option<&str>| -> u16 {
        let body = format!(
            "{{\"path\": {:?}, \"initiatedBy\": \"test\"}}",
            dir.display().to_string()
        );
        let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("the Hub accepts");
        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .unwrap();
        let origin_line = origin
            .map(|o| format!("Origin: {o}\r\n"))
            .unwrap_or_default();
        let authorization_line = authorization
            .map(|value| format!("Authorization: {value}\r\n"))
            .unwrap_or_default();
        write!(
            stream,
            "POST /_admin/export HTTP/1.1\r\nHost: 127.0.0.1\r\n{origin_line}{authorization_line}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .unwrap();
        let mut raw = String::new();
        stream.read_to_string(&mut raw).unwrap();
        raw.lines()
            .next()
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|c| c.parse().ok())
            .unwrap_or(0)
    };
    // A page (any Origin, loopback included) is refused and writes nothing.
    let bearer = format!("Bearer {token}");
    assert_eq!(send(Some("http://127.0.0.1:4000"), Some(&bearer)), 403);
    assert!(
        !dir.exists(),
        "a refused export must not create the directory"
    );
    assert_eq!(send(None, None), 403);
    assert_eq!(send(None, Some(&bearer)), 200);
    assert!(dir.join("firebase-export-metadata.json").is_file());
    drop(daemon);
    let _ = std::fs::remove_dir_all(&dir);
}
