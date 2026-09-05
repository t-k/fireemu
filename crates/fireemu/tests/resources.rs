//! `GET /v1/sessions/{s}/resources` and `POST .../resources:assertQuiescent` as the shipped
//! daemon serves them: every configured service reports in the shared schema, the route is
//! privileged for pages, and a fresh daemon is quiescent.

mod census;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use serde_json::Value;

struct Daemon {
    child: Child,
    control_port: u16,
    _banner: BufReader<std::process::ChildStdout>,
}

impl Daemon {
    fn start() -> Self {
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
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("the daemon binary starts");
        let stdout = child.stdout.take().expect("stdout is piped");
        let mut reader = BufReader::new(stdout);
        let mut banner = String::new();
        let mut port = None;
        for _ in 0..40 {
            let mut line = String::new();
            if reader.read_line(&mut line).unwrap_or(0) == 0 {
                break;
            }
            banner.push_str(&line);
            if line.trim_start().starts_with("control API:") {
                port = line
                    .split("http://127.0.0.1:")
                    .nth(1)
                    .and_then(|rest| rest.split(|c: char| !c.is_ascii_digit()).next())
                    .and_then(|digits| digits.parse::<u16>().ok());
                break;
            }
        }
        let Some(control_port) = port else {
            let _ = child.kill();
            let _ = child.wait();
            panic!("the daemon printed no control API line:\n{banner}");
        };
        Self {
            child,
            control_port,
            _banner: reader,
        }
    }

    /// One request over a fresh connection; `origin` marks a browser page.
    fn request(&self, method: &str, path: &str, origin: Option<&str>, body: &str) -> (u16, Value) {
        let mut socket = TcpStream::connect(("127.0.0.1", self.control_port))
            .expect("the control listener accepts");
        socket
            .set_read_timeout(Some(Duration::from_secs(20)))
            .expect("the read timeout is set");
        let origin = origin.map_or(String::new(), |o| format!("Origin: {o}\r\n"));
        write!(
            socket,
            "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n{origin}Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
        .expect("the request is written");
        let mut response = String::new();
        socket
            .read_to_string(&mut response)
            .expect("the response is read");
        let (head, body) = response
            .split_once("\r\n\r\n")
            .expect("the response has a header block");
        let status = head
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .expect("a status line");
        let body = body.trim();
        let value = if body.is_empty() {
            Value::Null
        } else {
            serde_json::from_str(body).unwrap_or_else(|_| Value::String(body.to_owned()))
        };
        (status, value)
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn the_daemon_reports_every_service_and_a_fresh_session_is_quiescent() {
    let daemon = Daemon::start();
    let (status, report) = daemon.request("GET", "/v1/sessions/default/resources", None, "");
    assert_eq!(status, 200, "{report}");
    assert_eq!(report["schemaVersion"], 1);
    assert_eq!(report["complete"], true, "{report}");
    let services: Vec<&str> = report["services"]
        .as_array()
        .expect("services")
        .iter()
        .map(|s| s["service"].as_str().unwrap())
        .collect();
    for expected in ["snapshots", "firestore", "storage", "auth", "pubsub"] {
        assert!(services.contains(&expected), "{services:?}");
    }
    for service in report["services"].as_array().unwrap() {
        for gauge in service["gauges"].as_array().unwrap() {
            assert!(
                matches!(
                    gauge["measure"].as_str(),
                    Some("logical" | "estimate" | "process")
                ),
                "{gauge}"
            );
            assert!(
                matches!(gauge["unit"].as_str(), Some("bytes" | "count")),
                "{gauge}"
            );
        }
        assert_eq!(service["roots"]["truncated"], false, "{service}");
    }

    // A page needs the token even to read the report; a CLI client on loopback does not.
    let (status, body) = daemon.request(
        "GET",
        "/v1/sessions/default/resources",
        Some("http://localhost:5173"),
        "",
    );
    assert_eq!(status, 403, "{body}");

    let (status, body) = daemon.request(
        "POST",
        "/v1/sessions/default/resources:assertQuiescent",
        None,
        "{}",
    );
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["quiescent"], true);

    let (status, body) = daemon.request(
        "POST",
        "/v1/sessions/default/resources:assertQuiescent",
        None,
        r#"{"allow": [{"service": "firestore", "kind": "transactions", "id": "demo/(default)", "reason": "nothing holds it"}]}"#,
    );
    assert_eq!(status, 409, "{body}");
    assert_eq!(body["staleAllowances"].as_array().unwrap().len(), 1);
    assert_eq!(body["leaks"].as_array().unwrap().len(), 0);

    drop(daemon);
    census::assert_no_owned_descendants("the resources daemon", Duration::from_secs(10));
}
