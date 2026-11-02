//! ACCEPT-1: a daemon that runs out of file descriptors keeps serving.
//!
//! The daemon is started with a low `RLIMIT_NOFILE` and the Hub is sent idle connections until
//! accepting one more fails with `EMFILE`. The daemon must neither stop nor take the suite down;
//! once the connections are closed, the control API's `/health/live` and the Hub answer again.
#![cfg(target_os = "linux")]

use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

#[path = "../../../tests/support/trusted_temp.rs"]
mod trusted_temp;

use trusted_temp::TrustedTempDir;

/// The descriptor limit the daemon runs under: room for its own listeners and runtime, far
/// fewer than the connections the test opens.
const DAEMON_NOFILE: u32 = 64;
/// How many idle connections are sent to the Hub; well above [`DAEMON_NOFILE`].
const IDLE_CONNECTIONS: usize = 160;

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

struct Daemon {
    child: Child,
    _namespace: TrustedTempDir,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Starts `fireemu up` under `ulimit -n DAEMON_NOFILE`, returning it with its control port.
fn start(hub_port: u16) -> (Daemon, u16) {
    let namespace = TrustedTempDir::new("accept-backoff");
    let mut child = Command::new("/bin/sh")
        .arg("-c")
        .arg(format!("ulimit -n {DAEMON_NOFILE} && exec \"$0\" \"$@\""))
        .arg(env!("CARGO_BIN_EXE_fireemu"))
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
            "demo-accept-backoff",
            "--hub-port",
        ])
        .arg(hub_port.to_string())
        .env("TMPDIR", namespace.path())
        .current_dir(namespace.path())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    // Keeps draining stdout after readiness so the daemon never writes into a closed pipe.
    std::thread::spawn(move || {
        let mut tx = Some(tx);
        for line in BufReader::new(stdout).lines() {
            let Ok(line) = line else { return };
            if let Some(rest) = line.split("control API:").nth(1) {
                let port = rest
                    .trim()
                    .trim_start_matches("http://")
                    .split('/')
                    .next()
                    .and_then(|addr| addr.rsplit(':').next())
                    .and_then(|port| port.parse::<u16>().ok());
                if let (Some(tx), Some(port)) = (tx.take(), port) {
                    let _ = tx.send(port);
                }
            }
        }
    });
    let daemon = Daemon {
        child,
        _namespace: namespace,
    };
    let control = rx
        .recv_timeout(Duration::from_secs(60))
        .expect("the daemon reports its control API");
    (daemon, control)
}

/// One `GET` with `Connection: close`, returning the status code (0 when nothing answers).
fn get(port: u16, path: &str) -> u16 {
    let Ok(mut stream) = TcpStream::connect(("127.0.0.1", port)) else {
        return 0;
    };
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut raw = String::new();
    let _ = stream.read_to_string(&mut raw);
    raw.split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or(0)
}

#[test]
fn a_daemon_out_of_descriptors_keeps_serving_once_they_are_free() {
    let hub_port = free_port();
    let (mut daemon, control) = start(hub_port);
    assert_eq!(get(control, "/health/live"), 200);

    // Idle connections the Hub accepts and keeps open, each holding one of its descriptors,
    // until accepting fails with EMFILE; the rest wait in the backlog. A refused connect means
    // the Hub is gone, which the check below reports.
    let idle: Vec<TcpStream> = (0..IDLE_CONNECTIONS)
        .map_while(|_| TcpStream::connect(("127.0.0.1", hub_port)).ok())
        .collect();

    std::thread::sleep(Duration::from_secs(2));

    drop(idle);
    let deadline = Instant::now() + Duration::from_secs(10);
    while get(control, "/health/live") != 200 {
        if let Some(status) = daemon.child.try_wait().unwrap() {
            panic!("the daemon stopped after running out of descriptors: {status}");
        }
        assert!(Instant::now() < deadline, "/health/live never answered");
        std::thread::sleep(Duration::from_millis(100));
    }
    assert_eq!(get(hub_port, "/emulators"), 200);
    assert!(
        daemon.child.try_wait().unwrap().is_none(),
        "the daemon is still running"
    );
}
