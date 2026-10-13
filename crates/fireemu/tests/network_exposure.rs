//! `network.allowNonLoopbackHosts`: the product emulators may listen on every interface (a
//! container that publishes its ports), while the control API keeps answering loopback peers
//! only (owner decision 2026-10-13).
//!
//! The daemon is started with Firestore and Auth on `0.0.0.0` and reached twice: through
//! loopback and through this host's own non-loopback address, which the kernel delivers
//! with that address as the peer. A host with no such address (a sandbox without a network)
//! skips the off-loopback half and says so.

#![cfg(unix)]

#[path = "../../../tests/support/trusted_temp.rs"]
mod trusted_temp;

use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::net::{IpAddr, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

use serde_json::Value;
use trusted_temp::TrustedTempDir;

const PROJECT: &str = "demo-network";

fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

fn http(host: IpAddr, port: u16, method: &str, path: &str, body: &str) -> (u16, String) {
    http_as("owner", host, port, method, path, body)
}

/// [`http`] with `Authorization: Bearer <bearer>`.
fn http_as(
    bearer: &str,
    host: IpAddr,
    port: u16,
    method: &str,
    path: &str,
    body: &str,
) -> (u16, String) {
    try_http_as(
        bearer,
        host,
        port,
        method,
        path,
        body,
        Duration::from_secs(20),
    )
    .unwrap_or_else(|e| panic!("{method} {host}:{port}{path}: {e}"))
}

fn try_http(
    host: IpAddr,
    port: u16,
    method: &str,
    path: &str,
    body: &str,
    timeout: Duration,
) -> std::io::Result<(u16, String)> {
    try_http_as("owner", host, port, method, path, body, timeout)
}

fn try_http_as(
    bearer: &str,
    host: IpAddr,
    port: u16,
    method: &str,
    path: &str,
    body: &str,
    timeout: Duration,
) -> std::io::Result<(u16, String)> {
    let mut stream = TcpStream::connect_timeout(&(host, port).into(), timeout)?;
    stream.set_read_timeout(Some(timeout))?;
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nHost: {host}:{port}\r\nAuthorization: Bearer {bearer}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )?;
    stream.flush()?;
    let mut raw = String::new();
    stream.read_to_string(&mut raw)?;
    let (head, body) = raw.split_once("\r\n\r\n").unwrap_or((raw.as_str(), ""));
    let status = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    Ok((status, body.to_owned()))
}

/// This host's address on the interface of its default route, found without sending a packet
/// (a UDP `connect` only selects the route). `None` without a non-loopback route.
fn own_non_loopback_address() -> Option<IpAddr> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("192.0.2.1:9").ok()?;
    let ip = socket.local_addr().ok()?.ip();
    (!ip.is_loopback() && !ip.is_unspecified()).then_some(ip)
}

struct Daemon {
    child: Child,
    hub_port: u16,
    transcript: Arc<Mutex<String>>,
    dir: TrustedTempDir,
}

impl Daemon {
    fn start(allow: bool) -> Result<Self, String> {
        let dir = TrustedTempDir::new("network-exposure");
        let firebase_json = dir.join("firebase.json");
        std::fs::write(
            &firebase_json,
            serde_json::json!({"emulators": {
                "firestore": {"host": "0.0.0.0", "port": 0},
                "auth": {"host": "0.0.0.0", "port": 0},
            }})
            .to_string(),
        )
        .unwrap();
        let config = dir.join("fireemu.json");
        std::fs::write(
            &config,
            serde_json::json!({
                "schemaVersion": 1,
                "network": {"allowNonLoopbackHosts": allow},
            })
            .to_string(),
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
                "firestore,auth",
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
        let transcript = Arc::new(Mutex::new(String::new()));
        let mut daemon = Self {
            child,
            hub_port,
            transcript: Arc::clone(&transcript),
            dir,
        };
        let (tx, rx) = mpsc::channel::<()>();
        let collected = Arc::clone(&transcript);
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
        let started = rx.recv_timeout(Duration::from_secs(60)).is_ok();
        if !started {
            let _ = daemon.child.wait();
            // Let the reader threads drain what the exited child wrote.
            std::thread::sleep(Duration::from_millis(200));
            return Err(daemon.transcript());
        }
        Ok(daemon)
    }

    fn transcript(&self) -> String {
        self.transcript.lock().unwrap().clone()
    }

    /// The transcript once it holds every needle. The startup warnings go to stderr, which
    /// another thread reads, so they can arrive after the `control API:` line on stdout.
    fn transcript_with(&self, needles: &[&str]) -> String {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            let transcript = self.transcript();
            if needles.iter().all(|needle| transcript.contains(needle))
                || std::time::Instant::now() >= deadline
            {
                return transcript;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn emulator(&self, name: &str) -> (String, u16) {
        let loopback = IpAddr::from([127, 0, 0, 1]);
        let (status, body) = http(loopback, self.hub_port, "GET", "/emulators", "");
        assert_eq!(status, 200, "{body}");
        let emulators: Value = serde_json::from_str(&body).unwrap();
        (
            emulators[name]["host"].as_str().unwrap().to_owned(),
            u16::try_from(emulators[name]["port"].as_u64().unwrap()).unwrap(),
        )
    }
}

impl Daemon {
    /// The run's control token, from the Hub locator in the daemon's `TMPDIR`.
    fn control_token(&self) -> String {
        let locator = self.dir.join(format!("hub-{PROJECT}.json"));
        let locator: Value =
            serde_json::from_str(&std::fs::read_to_string(locator).unwrap()).unwrap();
        locator["fireemuControlToken"].as_str().unwrap().to_owned()
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn a_host_on_every_interface_is_refused_without_the_opt_in() {
    let Err(transcript) = Daemon::start(false) else {
        panic!("the daemon started with 0.0.0.0 and no opt-in");
    };
    assert!(
        transcript.contains("emulators.firestore.host")
            || transcript.contains("emulators.auth.host"),
        "{transcript}"
    );
    assert!(
        transcript.contains("network.allowNonLoopbackHosts"),
        "{transcript}"
    );
}

#[test]
fn the_emulators_answer_other_hosts_and_the_control_api_answers_loopback_only() {
    let daemon = Daemon::start(true).unwrap_or_else(|transcript| panic!("{transcript}"));
    let transcript = daemon.transcript_with(&[
        "warning: firestore listens on 0.0.0.0:",
        "warning: auth listens on 0.0.0.0:",
    ]);
    assert!(
        transcript.contains("warning: firestore listens on 0.0.0.0:"),
        "{transcript}"
    );
    assert!(
        transcript.contains("warning: auth listens on 0.0.0.0:"),
        "{transcript}"
    );

    // The Hub advertises the connectable loopback address, not 0.0.0.0.
    let (firestore_host, firestore_port) = daemon.emulator("firestore");
    let (auth_host, auth_port) = daemon.emulator("auth");
    assert_eq!(firestore_host, "127.0.0.1");
    assert_eq!(auth_host, "127.0.0.1");

    let loopback = IpAddr::from([127, 0, 0, 1]);
    let document = format!("/v1/projects/{PROJECT}/databases/(default)/documents/things/one");
    let (status, body) = http(
        loopback,
        firestore_port,
        "PATCH",
        &document,
        r#"{"fields": {"a": {"stringValue": "x"}}}"#,
    );
    assert_eq!(status, 200, "{body}");
    let (status, body) = http(loopback, auth_port, "GET", "/health/live", "");
    assert_eq!(status, 200, "loopback reaches the health check: {body}");
    // Exposed, the control API needs the token even from loopback: a forwarder in the
    // namespace would connect from there.
    let (status, body) = http(loopback, auth_port, "GET", "/v1/sessions", "");
    assert_eq!(status, 403, "{body}");
    assert!(body.contains("CONTROL_TOKEN_REQUIRED"), "{body}");
    let token = daemon.control_token();
    let (status, body) = http_as(&token, loopback, auth_port, "GET", "/v1/sessions", "");
    assert_eq!(status, 200, "{body}");

    let Some(remote) = own_non_loopback_address() else {
        eprintln!("skipped: this host has no non-loopback address to connect from");
        return;
    };
    // The macOS application firewall drops the traffic of an unsigned binary it has not been
    // told about (the connection opens, nothing comes back), so a fresh test build cannot be
    // reached off loopback there.
    let Ok((status, body)) = try_http(
        remote,
        firestore_port,
        "GET",
        &document,
        "",
        Duration::from_secs(3),
    ) else {
        eprintln!("skipped: {remote} does not reach the daemon (a host firewall)");
        return;
    };
    assert_eq!(status, 200, "Firestore answers {remote}: {body}");
    assert!(
        body.contains("\"stringValue\": \"x\"") || body.contains("\"stringValue\":\"x\""),
        "{body}"
    );
    let (status, body) = http(
        remote,
        auth_port,
        "POST",
        "/identitytoolkit.googleapis.com/v1/accounts:signUp?key=fake",
        "{}",
    );
    assert_eq!(status, 200, "Auth answers {remote}: {body}");
    for path in ["/health/live", "/v1/sessions", "/v1/sessions/default/reset"] {
        let (status, body) = http_as(&token, remote, auth_port, "POST", path, "{}");
        assert_eq!(status, 403, "{path} from {remote}: {body}");
        assert!(body.contains("loopback peers only"), "{body}");
    }
    // Neither the rules route nor the data clear is the emulators' to expose.
    for (method, path) in [
        (
            "PUT",
            format!("/emulator/v1/projects/{PROJECT}:securityRules"),
        ),
        (
            "DELETE",
            format!("/emulator/v1/projects/{PROJECT}/databases/(default)/documents"),
        ),
    ] {
        let (status, body) = http(remote, firestore_port, method, &path, "{}");
        assert_eq!(status, 403, "{method} {path} from {remote}: {body}");
    }
    let (status, _) = http(remote, firestore_port, "GET", &document, "");
    assert_eq!(status, 200, "the data was not cleared");
}
