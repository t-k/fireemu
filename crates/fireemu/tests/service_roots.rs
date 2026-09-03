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

fn json_request(port: u16, method: &str, path: &str, body: &str) -> Option<(u16, String)> {
    read_response(write_json_request(port, method, path, body)?)
}

fn write_json_request(port: u16, method: &str, path: &str, body: &str) -> Option<TcpStream> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).ok()?;
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .ok()?;
    stream
        .set_write_timeout(Some(Duration::from_secs(30)))
        .ok()?;
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer owner\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .ok()?;
    stream.flush().ok()?;
    Some(stream)
}

fn read_response(mut stream: TcpStream) -> Option<(u16, String)> {
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

fn discover(hub_port: u16) -> serde_json::Value {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some((200, body)) = request(hub_port, "GET", "/emulators", None) {
            return serde_json::from_str(&body).unwrap();
        }
        assert!(Instant::now() < deadline, "the emulator hub became ready");
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn seed_large_collection(firestore: u16) {
    let payload = "x".repeat(8 * 1024);
    let writes: Vec<_> = (0..1_000)
        .map(|index| {
            serde_json::json!({"update": {
                "name": format!("projects/demo-saturation/databases/(default)/documents/items/{index:04}"),
                "fields": {"payload": {"stringValue": payload}}
            }})
        })
        .collect();
    let commit = serde_json::to_string(&serde_json::json!({"writes": writes})).unwrap();
    let path = "/v1/projects/demo-saturation/databases/(default)/documents:commit";
    assert_eq!(
        json_request(firestore, "POST", path, &commit).unwrap().0,
        200
    );
}

fn start_large_queries(firestore: u16) -> Vec<std::thread::JoinHandle<u16>> {
    let query = serde_json::json!({"structuredQuery": {
        "from": [{"collectionId": "items"}],
        "orderBy": [{"field": {"fieldPath": "__name__"}, "direction": "ASCENDING"}]
    }})
    .to_string();
    let (admitted_tx, admitted_rx) = std::sync::mpsc::channel();
    let release = std::sync::Arc::new(std::sync::Barrier::new(9));
    let completed = std::sync::Arc::new(
        (0..8)
            .map(|_| std::sync::atomic::AtomicBool::new(false))
            .collect::<Vec<_>>(),
    );
    let readers: Vec<_> = (0..8)
        .map(|index| {
            let admitted_tx = admitted_tx.clone();
            let completed = completed.clone();
            let query = query.clone();
            let release = release.clone();
            std::thread::spawn(move || {
                let path = "/v1/projects/demo-saturation/databases/(default)/documents:runQuery";
                release.wait();
                let stream = write_json_request(firestore, "POST", path, &query)
                    .expect("write query request");
                admitted_tx.send(()).unwrap();
                let status = read_response(stream).expect("query response").0;
                completed[index].store(true, std::sync::atomic::Ordering::Release);
                status
            })
        })
        .collect();
    drop(admitted_tx);
    release.wait();
    for _ in 0..readers.len() {
        admitted_rx
            .recv_timeout(Duration::from_secs(30))
            .expect("query request admitted");
    }
    assert!(
        completed
            .iter()
            .all(|done| !done.load(std::sync::atomic::Ordering::Acquire)),
        "all large queries must still be active before the responsiveness probes"
    );
    readers
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

    let emulators = discover(hub_port);
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

#[test]
fn large_firestore_queries_do_not_stall_auth_or_another_database() {
    let hub_port = free_port();
    let child = Command::new(env!("CARGO_BIN_EXE_fireemu"))
        .env("FIREEMU_WORKER_THREADS", "2")
        .env("FIREEMU_MAX_BLOCKING_THREADS", "16")
        .args([
            "up",
            "--project",
            "demo-saturation",
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
    let emulators = discover(hub_port);
    let auth = u16::try_from(emulators["auth"]["port"].as_u64().unwrap()).unwrap();
    let firestore = u16::try_from(emulators["firestore"]["port"].as_u64().unwrap()).unwrap();

    seed_large_collection(firestore);
    let readers = start_large_queries(firestore);

    let auth_started = Instant::now();
    assert_eq!(request(auth, "GET", "/", None).unwrap().0, 200);
    assert!(auth_started.elapsed() < Duration::from_secs(2));
    let other = "/v1/projects/demo-saturation/databases/other/documents/items/missing";
    let firestore_started = Instant::now();
    assert_eq!(json_request(firestore, "GET", other, "").unwrap().0, 404);
    assert!(firestore_started.elapsed() < Duration::from_secs(2));

    for reader in readers {
        assert_eq!(reader.join().unwrap(), 200);
    }
}
