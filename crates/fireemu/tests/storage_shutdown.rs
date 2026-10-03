//! Native daemon signals and exec completion close Storage's listeners and pending requests.

#![cfg(unix)]

#[path = "../../../tests/support/trusted_temp.rs"]
mod trusted_temp;

use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use trusted_temp::TrustedTempDir;

const PROJECT: &str = "demo-storage-shutdown";

struct Daemon {
    child: Child,
    readers: Vec<std::thread::JoinHandle<()>>,
    log: Arc<Mutex<String>>,
    port: u16,
    dir: TrustedTempDir,
}

impl Daemon {
    fn start(exec: Option<&[&str]>) -> Self {
        let dir = TrustedTempDir::new("storage-shutdown");
        let config = dir.join("fireemu.json");
        std::fs::write(&config, r#"{"schemaVersion":1,"profile":"strict"}"#).unwrap();
        let port = std::env::var("PORT")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or_else(|| {
                TcpListener::bind("127.0.0.1:0")
                    .unwrap()
                    .local_addr()
                    .unwrap()
                    .port()
            });
        let mut command = Command::new(env!("CARGO_BIN_EXE_fireemu"));
        command
            .args([if exec.is_some() { "exec" } else { "up" }, "--config"])
            .arg(&config)
            .args([
                "--only",
                "storage",
                "--project",
                PROJECT,
                "--firestore-port",
                "0",
                "--http-port",
                "0",
                "--logging-port",
                "0",
                "--ui-port",
                "0",
                "--hub-port",
                "0",
                "--storage-port",
            ])
            .arg(port.to_string())
            .env("TMPDIR", dir.path())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(exec) = exec {
            command.arg("--").args(exec);
        }
        let mut child = command.spawn().unwrap();
        let stdout = child.stdout.take().unwrap();
        let stderr = child.stderr.take().unwrap();
        let log = Arc::new(Mutex::new(String::new()));
        let mut daemon = Self {
            child,
            readers: Vec::new(),
            log: log.clone(),
            port,
            dir,
        };
        for pipe in [
            Box::new(stdout) as Box<dyn std::io::Read + Send>,
            Box::new(stderr),
        ] {
            let log = log.clone();
            daemon.readers.push(std::thread::spawn(move || {
                for line in BufReader::new(pipe).lines() {
                    let Ok(line) = line else { break };
                    let mut text = log.lock().unwrap();
                    text.push_str(&line);
                    text.push('\n');
                }
            }));
        }
        daemon
    }

    fn verify_pid(&self) -> bool {
        let output = Command::new("ps")
            .args([
                "-p",
                &self.child.id().to_string(),
                "-o",
                "comm=",
                "-o",
                "args=",
            ])
            .output();
        let Ok(output) = output else { return false };
        let value = String::from_utf8_lossy(&output.stdout);
        output.status.success()
            && value.contains("fireemu")
            && value.contains(self.dir.path().to_str().unwrap())
    }

    fn signal(&self, signal: &str) {
        assert!(
            self.verify_pid(),
            "the signal belongs to this test's daemon"
        );
        assert!(Command::new("kill")
            .args([signal, &self.child.id().to_string()])
            .status()
            .unwrap()
            .success());
    }

    fn ready(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            if self.log.lock().unwrap().contains("control API:") {
                return;
            }
            assert!(
                self.child.try_wait().unwrap().is_none(),
                "{}",
                self.log.lock().unwrap()
            );
            assert!(Instant::now() < deadline, "{}", self.log.lock().unwrap());
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn wait(&mut self) -> ExitStatus {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                for reader in self.readers.drain(..) {
                    reader.join().unwrap();
                }
                return status;
            }
            assert!(
                Instant::now() < deadline,
                "daemon did not terminate: {}",
                self.log.lock().unwrap()
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn exchange(&self, method: &str, path: &str, body: &[u8]) -> Vec<u8> {
        let mut stream = TcpStream::connect(("127.0.0.1", self.port)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        write!(stream, "{method} {path} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer owner\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).unwrap();
        stream.write_all(body).unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).unwrap();
        response
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        if matches!(self.child.try_wait(), Ok(None)) && self.verify_pid() {
            let _ = Command::new("kill")
                .args(["-TERM", &self.child.id().to_string()])
                .status();
            let deadline = Instant::now() + Duration::from_secs(2);
            while matches!(self.child.try_wait(), Ok(None)) && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(10));
            }
            if matches!(self.child.try_wait(), Ok(None)) && self.verify_pid() {
                let _ = self.child.kill();
            }
        }
        let _ = self.child.wait();
        for reader in self.readers.drain(..) {
            let _ = reader.join();
        }
    }
}

fn native_storage_signals_cancel_pending_globs_and_close_listeners() {
    for signal in ["-INT", "-TERM"] {
        let mut daemon = Daemon::start(None);
        daemon.ready();
        let bucket = format!("{PROJECT}.appspot.com");
        for number in 0..16 {
            let name = format!("{number:03}{}", "x".repeat(990));
            let response = daemon.exchange(
                "POST",
                &format!("/upload/storage/v1/b/{bucket}/o?uploadType=media&name={name}"),
                b"x",
            );
            assert!(
                response.starts_with(b"HTTP/1.1 200"),
                "{}",
                String::from_utf8_lossy(&response)
            );
        }
        let pattern = format!("{}z", "*{,}".repeat(15_000));
        let mut pending = Vec::new();
        for _ in 0..24 {
            let mut stream = TcpStream::connect(("127.0.0.1", daemon.port)).unwrap();
            write!(stream, "GET /storage/v1/b/{bucket}/o?matchGlob={pattern} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer owner\r\n\r\n").unwrap();
            pending.push(stream);
        }
        assert!(daemon
            .exchange(
                "GET",
                &format!("/storage/v1/b/{bucket}/o?maxResults=1"),
                b""
            )
            .starts_with(b"HTTP/1.1 200"));
        for stream in pending.iter().take(2) {
            stream.set_nonblocking(true).unwrap();
            let mut byte = [0];
            assert_eq!(
                stream.peek(&mut byte).unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock,
                "the first two heavy requests must still be pending at the signal"
            );
            stream.set_nonblocking(false).unwrap();
        }
        daemon.signal(signal);
        assert!(daemon.wait().success(), "{}", daemon.log.lock().unwrap());
        for mut stream in pending {
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut remaining = Vec::new();
            let result = stream.read_to_end(&mut remaining);
            assert!(
                result.is_ok() || result.unwrap_err().kind() == std::io::ErrorKind::ConnectionReset
            );
        }
        let listener = TcpListener::bind(("127.0.0.1", daemon.port)).unwrap();
        drop(listener);
        eprintln!("native signal={signal} pending=24 successfulExit=true portRebound=true");
    }
}

fn native_storage_exec_exit_and_spawn_failure_close_listeners() {
    for (command, success) in [
        (&["/bin/sh", "-c", "exit 0"][..], true),
        (&["/fireemu-test-command-does-not-exist"][..], false),
    ] {
        let mut daemon = Daemon::start(Some(command));
        let status = daemon.wait();
        assert_eq!(status.success(), success, "{}", daemon.log.lock().unwrap());
        let listener = TcpListener::bind(("127.0.0.1", daemon.port)).unwrap();
        drop(listener);
        eprintln!("native exec success={success} portRebound=true");
    }
}

#[test]
fn native_storage_signal_and_exec_shutdown() {
    native_storage_signals_cancel_pending_globs_and_close_listeners();
    native_storage_exec_exit_and_spawn_failure_close_listeners();
}
