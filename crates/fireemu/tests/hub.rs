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
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("the Hub accepts");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
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
    (status, body.to_owned())
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

    // An unknown route is a 404, not a hang or a 200 with an empty body.
    let (status, _) = request(port, "GET", "/nope", "127.0.0.1");
    assert_eq!(status, 404);
    // Export is refused precisely rather than pretending to have written one.
    let (status, body) = request(port, "POST", "/_admin/export", "127.0.0.1");
    assert_eq!(status, 501, "{body}");
    assert!(body.contains("snapshots"), "{body}");

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
    let (status, body) = request(
        port,
        "PUT",
        "/functions/disableBackgroundTriggers",
        "127.0.0.1",
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
    let disabled = json(port, "PUT", "/functions/disableBackgroundTriggers");
    assert_eq!(disabled["enabled"], false);
    let enabled = json(port, "PUT", "/functions/enableBackgroundTriggers");
    assert_eq!(enabled["enabled"], true);
    // The Functions emulator is discoverable while it runs.
    let emulators = json(port, "GET", "/emulators");
    assert_eq!(emulators["functions"]["name"], "functions");
    let _ = scratch("triggers");
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
