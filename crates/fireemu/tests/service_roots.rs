//! Auth and Firestore expose exact readiness roots to process-level pollers.

use std::io::{Read as _, Write as _};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

fn request(port: u16, method: &str, path: &str, origin: Option<&str>) -> Option<(u16, String)> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\n{}Connection: close\r\n\r\n",
        origin.map_or(String::new(), |value| format!("Origin: {value}\r\n"))
    )
    .ok()?;
    stream.flush().ok()?;
    let mut raw = String::new();
    stream.read_to_string(&mut raw).ok()?;
    let (head, body) = raw.split_once("\r\n\r\n").unwrap_or((&raw, ""));
    let status = head
        .lines()
        .next()?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()?;
    Some((status, body.to_owned()))
}

struct Daemon(Child);

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn auth_and_firestore_roots_are_ready_without_widening_routes() {
    let hub_port = free_port();
    let child = Command::new(env!("CARGO_BIN_EXE_fireemu"))
        .args([
            "up",
            "--project",
            "demo-readiness",
            "--only",
            "auth,firestore",
            "--http-port",
            "0",
            "--firestore-port",
            "0",
            "--storage-port",
            "0",
            "--functions-port",
            "0",
            "--pubsub-port",
            "0",
            "--ui-port",
            "0",
            "--logging-port",
            "0",
            "--hub-port",
        ])
        .arg(hub_port.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let _daemon = Daemon(child);

    let deadline = Instant::now() + Duration::from_secs(30);
    let emulators = loop {
        if let Some((200, body)) = request(hub_port, "GET", "/emulators", None) {
            break serde_json::from_str::<serde_json::Value>(&body).unwrap();
        }
        assert!(Instant::now() < deadline, "the emulator hub became ready");
        std::thread::sleep(Duration::from_millis(50));
    };
    let auth = u16::try_from(emulators["auth"]["port"].as_u64().unwrap()).unwrap();
    let firestore = u16::try_from(emulators["firestore"]["port"].as_u64().unwrap()).unwrap();

    for port in [auth, firestore] {
        let (status, body) = request(port, "GET", "/", None).unwrap();
        assert_eq!(status, 200, "{body}");
        assert_eq!(request(port, "GET", "/unknown", None).unwrap().0, 404);
        assert_ne!(request(port, "POST", "/", None).unwrap().0, 200);
        assert_eq!(
            request(port, "GET", "/", Some("https://example.test"))
                .unwrap()
                .0,
            403
        );
    }
}
