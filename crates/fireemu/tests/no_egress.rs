//! No-egress observation (XINT-D3): while a daemon serves a workload, every socket it holds
//! is observed with `lsof`, and every established connection must have a loopback peer. The
//! observation is written as an artifact so a reviewer can read what was seen rather than
//! trust the assertion, and a machine without `lsof` skips with that reason instead of
//! passing on nothing.

mod census;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

struct Daemon {
    child: Child,
    control: u16,
    firestore: u16,
    _banner: BufReader<std::process::ChildStdout>,
}

fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

impl Daemon {
    fn start() -> Self {
        let firestore = free_port();
        let mut child = Command::new(env!("CARGO_BIN_EXE_fireemu"))
            .args([
                "up",
                "--project",
                "demo-egress",
                "--only",
                "auth,firestore,storage",
                "--firestore-port",
                &firestore.to_string(),
                "--http-port",
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
                "0",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("the daemon binary starts");
        let mut reader = BufReader::new(child.stdout.take().expect("stdout is piped"));
        let mut control = None;
        for _ in 0..60 {
            let mut line = String::new();
            if reader.read_line(&mut line).unwrap_or(0) == 0 {
                break;
            }
            if line.trim_start().starts_with("control API:") {
                control = line
                    .split("http://127.0.0.1:")
                    .nth(1)
                    .and_then(|rest| rest.split(|c: char| !c.is_ascii_digit()).next())
                    .and_then(|digits| digits.parse::<u16>().ok());
                break;
            }
        }
        let Some(control) = control else {
            let _ = child.kill();
            let _ = child.wait();
            panic!("the daemon printed no control API line");
        };
        Self {
            child,
            control,
            firestore,
            _banner: reader,
        }
    }
    fn pid(&self) -> i32 {
        i32::try_from(self.child.id()).expect("pid fits i32")
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn http(port: u16, method: &str, path: &str, body: &str) -> u16 {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer owner\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .unwrap();
    let mut raw = String::new();
    stream.read_to_string(&mut raw).unwrap();
    raw.split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

/// One `lsof -nP -i -a -p <pid>` line: protocol, local and peer address, state.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Socket {
    protocol: String,
    name: String,
    state: String,
}

fn observe(pid: i32) -> Option<Vec<Socket>> {
    let output = Command::new("lsof")
        .args(["-nP", "-i", "-a", "-p", &pid.to_string()])
        .stderr(Stdio::null())
        .output()
        .ok()?;
    // `lsof` exits 1 when the process has no network files at all; that is an empty list.
    let text = String::from_utf8_lossy(&output.stdout);
    Some(
        text.lines()
            .skip(1)
            .filter_map(|line| {
                let fields: Vec<&str> = line.split_whitespace().collect();
                // COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME [(STATE)]
                let node = fields.get(7)?;
                let name = fields.get(8)?;
                let state = fields.get(9).map_or("", |s| s.trim_matches(['(', ')']));
                Some(Socket {
                    protocol: (*node).to_owned(),
                    name: (*name).to_owned(),
                    state: state.to_owned(),
                })
            })
            .collect(),
    )
}

/// Whether an address `lsof` printed (`127.0.0.1:1234`, `[::1]:1234`, `localhost:1234`, `*:1234`)
/// is a loopback address. `*` is a wildcard bind and is not loopback.
fn is_loopback(address: &str) -> bool {
    let host = address.rsplit_once(':').map_or(address, |(host, _)| host);
    matches!(host, "127.0.0.1" | "[::1]" | "localhost") || host.starts_with("127.")
}

#[test]
fn a_serving_daemon_holds_only_loopback_sockets() {
    if Command::new("lsof").arg("-v").output().is_err() {
        eprintln!("skipped: lsof is not available, no socket observation is possible here");
        return;
    }
    let daemon = Daemon::start();
    let pid = daemon.pid();
    let docs = "/v1/projects/demo-egress/databases/(default)/documents";
    let mut samples: Vec<Value> = Vec::new();
    let mut peers = std::collections::BTreeSet::new();
    let mut listeners = std::collections::BTreeSet::new();
    let started = Instant::now();
    // A workload that touches Firestore and the control API while sockets are sampled between
    // requests, so the observation covers request handling and not only an idle daemon.
    for round in 0..6 {
        assert_eq!(
            http(
                daemon.firestore,
                "PATCH",
                &format!("{docs}/egress/doc-{round}"),
                r#"{"fields":{"v":{"integerValue":"1"}}}"#
            ),
            200
        );
        assert_eq!(
            http(
                daemon.firestore,
                "GET",
                &format!("{docs}/egress/doc-{round}"),
                ""
            ),
            200
        );
        if round == 3 {
            assert_eq!(
                http(daemon.control, "POST", "/v1/sessions/default/reset", "{}"),
                200
            );
        }
        // A request held open while sampling, so the observation includes an established
        // connection and not only the listeners between requests.
        let mut held = TcpStream::connect(("127.0.0.1", daemon.firestore)).expect("connect");
        write!(
            held,
            "GET {docs}/egress/doc-{round} HTTP/1.1\r\nHost: 127.0.0.1\r\n"
        )
        .unwrap();
        held.flush().unwrap();
        let sockets = observe(pid).expect("lsof ran");
        drop(held);
        for socket in &sockets {
            if socket.state == "LISTEN" {
                listeners.insert(socket.name.clone());
            } else if let Some((_, peer)) = socket.name.split_once("->") {
                peers.insert(peer.to_owned());
            }
        }
        samples.push(json!({
            "round": round,
            "elapsedMs": started.elapsed().as_millis(),
            "sockets": sockets.iter().map(|s| json!({"protocol": s.protocol, "name": s.name, "state": s.state})).collect::<Vec<_>>(),
        }));
    }
    drop(daemon);
    let artifact = json!({
        "schemaVersion": 1,
        "kind": "no-egress-observation",
        "os": std::env::consts::OS,
        "tool": "lsof -nP -i -a -p <pid>",
        "listeners": listeners,
        "peers": peers,
        "samples": samples,
    });
    let path = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("no-egress-observation.json");
    std::fs::write(&path, serde_json::to_string_pretty(&artifact).unwrap()).unwrap();
    eprintln!("no-egress observation: {}", path.display());

    let foreign: Vec<&String> = peers.iter().filter(|peer| !is_loopback(peer)).collect();
    assert!(
        foreign.is_empty(),
        "connections to non-loopback peers: {foreign:?}"
    );
    assert!(
        !listeners.is_empty(),
        "the daemon listened on nothing: {artifact}"
    );
    for listener in &listeners {
        assert!(
            is_loopback(listener),
            "a listener is not bound to loopback: {listener} (all: {listeners:?})"
        );
    }
    assert!(
        !peers.is_empty(),
        "no established connection was observed while requests were served: {artifact}"
    );
    census::assert_no_owned_descendants("the no-egress daemon", Duration::from_secs(10));
}
