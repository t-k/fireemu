//! A refusal sent from the request head alone reaches a client that is still sending its body, on
//! every keep-alive listener of a daemon started the way a project starts it.
//!
//! The listeners answer a refused request (a page on another site, a body over the limit) without
//! reading its body and then end the connection. Closing a TCP connection that still has unread
//! request bytes makes the kernel answer them with a reset, which can discard the response before the
//! client has read it. A client that sends its head, waits a moment and then sends its body (the
//! shape of every upload) would see a reset instead of the refusal. The listeners therefore announce
//! the end of the response first and read and discard what the client still sends, within bounds
//! (`fireemu_adapter_support::connection`); the response bytes are unchanged.

#![cfg(unix)]

#[path = "../../../tests/support/trusted_temp.rs"]
mod trusted_temp;

use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

use trusted_temp::TrustedTempDir;

const PROJECT: &str = "demo-refused-body";
const ROUNDS: usize = 12;
/// How long the client waits after its head before it sends the body, so the refusal is already
/// written, and the connection already ended on the server side, when the body arrives.
const LATE_BODY_DELAY: Duration = Duration::from_millis(100);

fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

struct Ports {
    http: u16,
    firestore: u16,
    storage: u16,
    ui: u16,
    hub: u16,
}

struct Daemon {
    child: Child,
    ports: Ports,
    _dir: TrustedTempDir,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Daemon {
    fn start() -> Self {
        let dir = TrustedTempDir::new("refused-body");
        let firebase_json = dir.join("firebase.json");
        std::fs::write(&firebase_json, "{}").unwrap();
        let config = dir.join("fireemu.json");
        std::fs::write(&config, r#"{"schemaVersion": 1}"#).unwrap();
        let ports = Ports {
            http: free_port(),
            firestore: free_port(),
            storage: free_port(),
            ui: free_port(),
            hub: free_port(),
        };
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
                "auth,firestore,storage",
                "--functions-port",
                "0",
                "--pubsub-port",
                "0",
                "--logging-port",
                "0",
            ])
            .args(["--http-port", &ports.http.to_string()])
            .args(["--firestore-port", &ports.firestore.to_string()])
            .args(["--storage-port", &ports.storage.to_string()])
            .args(["--ui-port", &ports.ui.to_string()])
            .args(["--hub-port", &ports.hub.to_string()])
            .env("TMPDIR", dir.path())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let stderr = child.stderr.take().unwrap();
        // The child is owned (and killed on drop) before anything below can panic.
        let daemon = Self {
            child,
            ports,
            _dir: dir,
        };
        let transcript = Arc::new(Mutex::new(String::new()));
        let collected = Arc::clone(&transcript);
        let (tx, rx) = mpsc::channel::<()>();
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
        assert!(
            rx.recv_timeout(Duration::from_secs(60)).is_ok(),
            "the daemon did not become ready:\n{}",
            transcript.lock().unwrap()
        );
        daemon
    }
}

/// What a client that sends its head, waits, then sends `body_len` bytes of body sees: the status
/// line of the answer and whether the connection then ended cleanly (a reset after the answer is what
/// discards it on a client that has not read it yet, and ends a client that reads on in an error), or
/// why there was no answer.
fn late_body_exchange(port: u16, path: &str, extra_headers: &str, body_len: usize) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("the daemon accepts");
    stream
        .set_read_timeout(Some(Duration::from_secs(20)))
        .unwrap();
    let head = format!(
        "POST {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n{extra_headers}Content-Type: application/json\r\nContent-Length: {body_len}\r\nConnection: close\r\n\r\n"
    );
    if let Err(error) = stream.write_all(head.as_bytes()) {
        return format!("head not sent: {error}");
    }
    std::thread::sleep(LATE_BODY_DELAY);
    // A reset can arrive while the body is being sent; the client then still reads whatever
    // arrived before it, which is what a real client does, and the way the connection ends is part
    // of what it sees.
    let chunk = vec![b'x'; 16 * 1024];
    let mut sent = 0;
    while sent < body_len {
        let n = chunk.len().min(body_len - sent);
        if stream.write_all(&chunk[..n]).is_err() {
            break;
        }
        sent += n;
    }
    let mut raw = Vec::new();
    let read = stream.read_to_end(&mut raw);
    let text = String::from_utf8_lossy(&raw);
    let Some(status) = text.lines().next().filter(|line| !line.is_empty()) else {
        return format!("no answer ({read:?})");
    };
    match read {
        Ok(_) => format!("{status} (clean end)"),
        Err(error) => format!("{status} + {:?} after it", error.kind()),
    }
}

/// What went wrong for `listener`, if anything: the rounds whose refusal did not reach the client.
fn refusal_losses(
    listener: &str,
    port: u16,
    path: &str,
    extra_headers: &str,
    body_len: usize,
    expected_status: &str,
) -> Option<String> {
    let expected = format!("{expected_status} (clean end)");
    let lost: Vec<String> = (0..ROUNDS)
        .map(|_| late_body_exchange(port, path, extra_headers, body_len))
        .filter(|outcome| *outcome != expected)
        .collect();
    (!lost.is_empty()).then(|| {
        format!(
            "{listener}: {} of {ROUNDS} refusals did not reach a client that sends {body_len} body bytes late (expected {expected:?}): {lost:?}",
            lost.len()
        )
    })
}

const OTHER_SITE: &str = "Origin: https://other-site.example\r\n";

#[test]
fn every_keep_alive_listener_delivers_its_refusal_to_a_client_that_sends_its_body_late() {
    let daemon = Daemon::start();
    let ports = &daemon.ports;
    let mut losses = Vec::new();
    // A page on another site is refused from the head alone; the bodies are both below and well
    // above what a listener reads for a legitimate request.
    for body_len in [64 * 1024, 512 * 1024] {
        let cases = [
            (
                "auth (http)",
                ports.http,
                "/identitytoolkit.googleapis.com/v1/accounts:signUp?key=x",
                "HTTP/1.1 403 Forbidden",
            ),
            (
                "firestore REST (grpc listener)",
                ports.firestore,
                "/v1/projects/demo-refused-body/databases/(default)/documents/things",
                "HTTP/1.1 403 Forbidden",
            ),
            (
                "storage",
                ports.storage,
                "/v0/b/demo-refused-body.appspot.com/o",
                "HTTP/1.1 403 Forbidden",
            ),
            ("hub", ports.hub, "/emulators", "HTTP/1.1 404 Not Found"),
        ];
        for (listener, port, path, status) in cases {
            losses.extend(refusal_losses(
                listener, port, path, OTHER_SITE, body_len, status,
            ));
        }
    }
    // The UI reads a body up to its limit (256 KiB outside the storage routes) before it refuses a
    // larger one, so the body is several times that limit: a substantial remainder is unread at
    // the refusal.
    losses.extend(refusal_losses(
        "ui",
        ports.ui,
        "/api/anything",
        OTHER_SITE,
        4 * 1024 * 1024,
        "HTTP/1.1 413 Payload Too Large",
    ));
    assert!(losses.is_empty(), "{}", losses.join("\n"));
}
