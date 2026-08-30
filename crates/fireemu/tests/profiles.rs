//! The compatibility profile as a runtime switch, against a daemon started the way a project
//! starts it (`CLAIM-01`, `CLAIM-03`).
//!
//! The scenario the compatibility contract asks for is one official limitation run under both
//! profiles: the pinned official Firestore emulator does not check composite indexes at all,
//! so a query whose index is not configured is served there. The `firebase` profile has to
//! serve it too -- that profile may add no rejection the official emulator does not make --
//! and only `strict` may refuse it, with the `firestore.indexes.json` fragment production
//! would need.

use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// A port nothing is listening on, released before it is handed back.
fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("fireemu-profiles-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// One HTTP request, written by hand: the binary's test suite has no HTTP client dependency
/// and the answers here are small enough to read in one go.
fn http(port: u16, method: &str, path: &str, body: Option<&str>) -> (u16, String) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("the daemon accepts");
    stream
        .set_read_timeout(Some(Duration::from_secs(20)))
        .unwrap();
    let body = body.unwrap_or("");
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
    (status, body.to_owned())
}

/// A daemon under one compatibility profile, with its Hub on `hub_port` so the test can ask
/// it which port Firestore ended up on.
struct Daemon {
    child: Child,
    banner: Arc<Mutex<String>>,
    hub_port: u16,
}

impl Daemon {
    fn start(profile: &str) -> Self {
        let dir = scratch(profile);
        let config = dir.join("fireemu.json");
        std::fs::write(
            &config,
            format!(
                r#"{{"schemaVersion": 1, "profile": "{profile}", "firestore": {{"edition": "standard", "apiMode": "native"}}}}"#
            ),
        )
        .unwrap();
        let hub_port = free_port();
        let mut child = Command::new(env!("CARGO_BIN_EXE_fireemu"))
            .args([
                "up",
                "--config",
                config.to_str().unwrap(),
                "--project",
                &format!("demo-profile-{profile}"),
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
            .arg(hub_port.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        // The banner's control-API line is printed once every listener is bound; the pipe
        // keeps being drained afterwards so the daemon never hits a broken pipe mid-run, and
        // every line it ever prints stays readable, whatever order the banner puts them in.
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
            banner,
            hub_port,
        }
    }

    /// Everything the daemon has printed so far.
    fn banner(&self) -> String {
        self.banner.lock().unwrap().clone()
    }

    /// The Firestore port, discovered the way a client discovers it.
    fn firestore_port(&self) -> u16 {
        let (status, body) = http(self.hub_port, "GET", "/emulators", None);
        assert_eq!(status, 200, "{body}");
        let emulators: serde_json::Value = serde_json::from_str(&body).unwrap();
        u16::try_from(emulators["firestore"]["port"].as_u64().unwrap()).unwrap()
    }

    /// A query that needs a composite index nothing configured: an equality filter and an
    /// order by another field.
    fn unindexed_query(&self) -> (u16, String) {
        http(
            self.firestore_port(),
            "POST",
            "/v1/projects/demo-profile/databases/(default)/documents:runQuery",
            Some(
                r#"{"structuredQuery": {"from": [{"collectionId": "notes"}], "where": {"fieldFilter": {"field": {"fieldPath": "owner"}, "op": "EQUAL", "value": {"stringValue": "a"}}}, "orderBy": [{"field": {"fieldPath": "created"}, "direction": "ASCENDING"}]}}"#,
            ),
        )
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
fn the_same_official_limitation_is_served_under_firebase_and_refused_under_strict() {
    let firebase = Daemon::start("firebase");
    let (status, body) = firebase.unindexed_query();
    assert_eq!(
        status, 200,
        "the pinned official Firestore emulator serves this query, so the firebase profile must: {body}"
    );
    assert!(
        firebase.banner().contains("profile: firebase"),
        "the banner names the profile the run is under:\n{}",
        firebase.banner()
    );
    firebase.stop();

    let strict = Daemon::start("strict");
    let (status, body) = strict.unindexed_query();
    assert_eq!(status, 400, "{body}");
    assert!(body.contains("FAILED_PRECONDITION"), "{body}");
    assert!(
        body.contains("firestore.indexes.json"),
        "the refusal carries the fragment production would need: {body}"
    );
    assert!(
        strict.banner().contains("profile: strict"),
        "{}",
        strict.banner()
    );
    strict.stop();
}

#[test]
fn the_capabilities_command_reports_the_profile_it_would_run_under() {
    let dir = scratch("capabilities");
    for profile in ["firebase", "strict"] {
        let config = dir.join(format!("{profile}.json"));
        std::fs::write(
            &config,
            format!(
                r#"{{"schemaVersion": 1, "profile": "{profile}", "firestore": {{"edition": "standard", "apiMode": "native"}}}}"#
            ),
        )
        .unwrap();
        let out = Command::new(env!("CARGO_BIN_EXE_fireemu"))
            .args(["capabilities", "--config", config.to_str().unwrap()])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let manifest: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(manifest["profile"], profile);
        assert!(manifest["capabilities"]["FS-GW-1"].is_object());
    }
    // Without a configuration the command reports the default, which is the profile the
    // public compatibility claim is made under.
    let out = Command::new(env!("CARGO_BIN_EXE_fireemu"))
        .arg("capabilities")
        .output()
        .unwrap();
    let manifest: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(manifest["profile"], "firebase");
}
