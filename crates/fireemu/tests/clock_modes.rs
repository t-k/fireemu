//! The daemon's clock under `daemon.clock`: no request moves it on its own account, a rewind
//! sticks, and a following clock runs on from where it was put.

#![cfg(unix)]

mod census;
#[path = "../../../tests/support/trusted_temp.rs"]
mod trusted_temp;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

use fireemu_core_types::time::LogicalInstant;
use serde_json::{json, Value};
use trusted_temp::TrustedTempDir;

const PROJECT: &str = "demo-clock-modes";

fn http(port: u16, method: &str, path: &str, body: &Value) -> (u16, Value) {
    http_as(port, method, path, "", body)
}

fn http_as(port: u16, method: &str, path: &str, headers: &str, body: &Value) -> (u16, Value) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("the daemon accepts");
    stream
        .set_read_timeout(Some(Duration::from_secs(20)))
        .unwrap();
    let body = body.to_string();
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
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
    (status, serde_json::from_str(body).unwrap_or(Value::Null))
}

struct Daemon {
    child: Child,
    banner: Arc<Mutex<String>>,
    _dir: TrustedTempDir,
}

impl Daemon {
    /// An unpinned daemon whose `daemon` section is `daemon` (`{}` for the default).
    fn start(name: &str, daemon: &Value) -> Self {
        let dir = TrustedTempDir::new(&format!("clock-modes-{name}"));
        let config = dir.join("fireemu.json");
        std::fs::write(
            &config,
            json!({"schemaVersion": 1, "profile": "emulator", "daemon": daemon}).to_string(),
        )
        .unwrap();
        let mut child = Command::new(env!("CARGO_BIN_EXE_fireemu"))
            .args([
                "up",
                "--config",
                config.to_str().unwrap(),
                "--project",
                PROJECT,
            ])
            .args(["--firestore-port", "0", "--http-port", "0"])
            .args([
                "--storage-port",
                "0",
                "--functions-port",
                "0",
                "--logging-port",
                "0",
            ])
            .args(["--ui-port", "0", "--hub-port", "0"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let daemon = Self {
            child,
            banner: Arc::new(Mutex::new(String::new())),
            _dir: dir,
        };
        let collected = Arc::clone(&daemon.banner);
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
        rx.recv_timeout(Duration::from_secs(60))
            .expect("the daemon became ready");
        daemon
    }

    fn banner_port(&self, label: &str) -> u16 {
        let banner = self.banner.lock().unwrap().clone();
        banner
            .lines()
            .find(|line| line.trim_start().starts_with(label))
            .and_then(|line| line.split("127.0.0.1:").nth(1))
            .and_then(|rest| rest.split(|c: char| !c.is_ascii_digit()).next())
            .and_then(|digits| digits.parse().ok())
            .unwrap_or_else(|| panic!("the banner names no {label}: {banner}"))
    }

    /// The daemon's clock, from the control API.
    fn clock(&self) -> LogicalInstant {
        let (status, body) = http(
            self.banner_port("control API:"),
            "GET",
            "/v1/sessions/default",
            &json!({}),
        );
        assert_eq!(status, 200, "{body}");
        LogicalInstant::parse_rfc3339(body["clock"]["clock"].as_str().expect("a clock")).unwrap()
    }

    fn rewind_to(&self, instant: &str) {
        let (status, body) = http(
            self.banner_port("control API:"),
            "POST",
            "/v1/sessions/default/clock:set",
            &json!({"instant": instant, "allowBackwards": true}),
        );
        assert_eq!(status, 200, "{body}");
    }

    /// The update time of a document written now: Firestore stamps writes with the clock.
    fn write_time(&self) -> LogicalInstant {
        let (status, body) = http_as(
            self.banner_port("firestore (gRPC + REST):"),
            "PATCH",
            &format!("/v1/projects/{PROJECT}/databases/(default)/documents/clock/doc"),
            "Authorization: Bearer owner\r\n",
            &json!({"fields": {"v": {"integerValue": "1"}}}),
        );
        assert_eq!(status, 200, "{body}");
        LogicalInstant::parse_rfc3339(body["updateTime"].as_str().expect("an update time")).unwrap()
    }

    /// An Auth request, which reads the clock to stamp what it issues.
    fn sign_up(&self) {
        let (status, body) = http(
            self.banner_port("auth (REST):"),
            "POST",
            "/identitytoolkit.googleapis.com/v1/accounts:signUp?key=any",
            &json!({"returnSecureToken": true}),
        );
        assert_eq!(status, 200, "{body}");
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

const REWOUND: &str = "2020-01-01T00:00:00Z";

fn nanos_since_rewind(clock: LogicalInstant) -> i128 {
    clock.as_nanos() - LogicalInstant::parse_rfc3339(REWOUND).unwrap().as_nanos()
}

#[test]
fn a_frozen_unpinned_clock_stands_still_and_a_rewind_sticks_through_requests() {
    let daemon = Daemon::start("frozen", &json!({"clock": "frozen"}));
    let start = daemon.clock();
    std::thread::sleep(Duration::from_millis(300));
    daemon.sign_up();
    assert_eq!(daemon.clock(), start, "no request moves a frozen clock");
    daemon.rewind_to(REWOUND);
    daemon.sign_up();
    std::thread::sleep(Duration::from_millis(300));
    daemon.sign_up();
    assert_eq!(nanos_since_rewind(daemon.clock()), 0, "the rewind sticks");
    assert_eq!(
        nanos_since_rewind(daemon.write_time()),
        0,
        "a write is stamped with the frozen clock, not the wall"
    );
}

#[test]
fn a_following_clock_runs_on_from_a_rewind_and_requests_do_not_pull_it_back() {
    let daemon = Daemon::start("following", &json!({}));
    // From its first reading the clock agrees with the wall clock, however long start-up took.
    let wall = || {
        i128::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        )
        .unwrap()
    };
    let before = wall();
    let first = daemon.clock();
    let after = wall();
    assert!(
        (before..=after).contains(&first.as_nanos()),
        "{before} <= {} <= {after}",
        first.as_nanos()
    );
    std::thread::sleep(Duration::from_millis(300));
    daemon.sign_up();
    assert!(daemon.clock().as_nanos() - first.as_nanos() >= 300_000_000);
    daemon.rewind_to(REWOUND);
    daemon.sign_up();
    std::thread::sleep(Duration::from_millis(300));
    daemon.sign_up();
    let after = nanos_since_rewind(daemon.clock());
    assert!(
        (300_000_000..30_000_000_000).contains(&after),
        "it runs on from the rewind, not from the wall: {after}"
    );
    let written = nanos_since_rewind(daemon.write_time());
    assert!(
        (after..30_000_000_000).contains(&written),
        "a write is stamped with the clock's offset time: {written}"
    );
}
