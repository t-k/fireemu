//! A clean interrupt removes the daemon's spill directory.
//!
//! The daemon is started with `storage.spillObjectBytes` set and its temporary directory in a
//! private namespace. Its per-process spill directory must exist while it runs and must be gone
//! after SIGINT, at the shutdown hook, not only when a destructor happens to run.
#![cfg(unix)]

use std::io::{BufRead as _, BufReader};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

#[path = "../../../tests/support/trusted_temp.rs"]
mod trusted_temp;

use trusted_temp::TrustedTempDir;

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Starts `fireemu up` with spilling on, returning the child and the namespace it uses.
fn start(namespace: &TrustedTempDir) -> Child {
    let config = namespace.path().join("config.json");
    std::fs::write(
        &config,
        r#"{"schemaVersion":1,"storage":{"spillObjectBytes":1}}"#,
    )
    .unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_fireemu"))
        .args(["up", "--no-config-discovery", "--config"])
        .arg(&config)
        .args([
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
            "demo-spill-shutdown",
            "--hub-port",
        ])
        .arg(free_port().to_string())
        .env("TMPDIR", namespace.path())
        .current_dir(namespace.path())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    // Drains stdout for the whole run so the daemon never writes into a closed pipe.
    std::thread::spawn(move || {
        let mut tx = Some(tx);
        for line in BufReader::new(stdout).lines() {
            let Ok(line) = line else { return };
            if line.contains("control API:") {
                if let Some(tx) = tx.take() {
                    let _ = tx.send(());
                }
            }
        }
    });
    rx.recv_timeout(Duration::from_secs(120))
        .expect("the daemon reports its control API");
    child
}

#[test]
fn a_clean_interrupt_removes_the_spill_directory() {
    let namespace = TrustedTempDir::new("spill-shutdown");
    let mut child = start(&namespace);
    let spill_dir = namespace
        .path()
        .join("fireemu")
        .join(format!("fireemu-spill-{}", child.id()));
    assert!(
        spill_dir.is_dir(),
        "the running daemon owns {}",
        spill_dir.display()
    );
    // Interrupt the daemon this test started, by its own pid, as Ctrl-C would.
    let status = Command::new("kill")
        .arg("-INT")
        .arg(child.id().to_string())
        .status()
        .unwrap();
    assert!(status.success(), "sending SIGINT failed");
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        if child.try_wait().unwrap().is_some() {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the daemon did not stop after SIGINT"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(
        !spill_dir.exists(),
        "a clean shutdown must remove {}",
        spill_dir.display()
    );
}
