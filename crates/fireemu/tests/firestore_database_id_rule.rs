//! A named database that `firebase.json` declares must have an id production could create:
//! 4-63 characters of `[a-z0-9-]`, starting with a letter and not ending with a hyphen
//! (`databases.create`: "`database_id` should be 4-63 characters, and valid characters
//! are /[a-z][0-9]-/"). Under `strict` a declaration with any other id stops the daemon; the
//! `emulator` profile, whose official emulator accepts any name, still starts.

mod scratch;

use scratch::Scratch;

use std::io::{BufRead as _, BufReader};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

fn command(name: &str, profile: &str, database: &str) -> (Command, Scratch) {
    let dir = Scratch::new("database-id", name);
    std::fs::write(
        dir.join("firebase.json"),
        format!(r#"{{"firestore": [{{"database": "(default)"}}, {{"database": "{database}"}}]}}"#),
    )
    .unwrap();
    let config = dir.join("fireemu.json");
    std::fs::write(
        &config,
        format!(
            r#"{{"schemaVersion": 1, "profile": "{profile}", "firebaseJson": "firebase.json", "firestore": {{"edition": "standard", "apiMode": "native"}}}}"#
        ),
    )
    .unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_fireemu"));
    command
        .args(["up", "--config", config.to_str().unwrap()])
        .args(["--project", "demo-database-id"])
        .args([
            "--firestore-port",
            "0",
            "--http-port",
            "0",
            "--storage-port",
            "0",
        ])
        .args(["--logging-port", "0", "--ui-port", "0", "--hub-port", "0"])
        .stdin(Stdio::null());
    (command, dir)
}

struct Running(Child);

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
        scratch::remove_killed_daemon_locator("demo-database-id", self.0.id());
    }
}

fn starts(name: &str, profile: &str, database: &str) -> bool {
    let (mut command, _dir) = command(name, profile, database);
    let mut child = Running(
        command
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let stdout = child.0.stdout.take().unwrap();
    let (tx, rx) = std::sync::mpsc::channel::<()>();
    std::thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line).unwrap_or(0) == 0 {
                return;
            }
            if line.contains("control API:") {
                let _ = tx.send(());
                return;
            }
        }
    });
    rx.recv_timeout(Duration::from_secs(60)).is_ok()
}

#[test]
fn strict_refuses_a_database_id_production_could_not_create() {
    for (name, database) in [
        ("short", "db"),
        ("three", "abc"),
        ("digit-first", "1abc"),
        ("upper", "Reports"),
        ("underscore", "re_ports"),
        ("hyphen-last", "reports-"),
        ("long", &"a".repeat(64)),
    ] {
        let (mut command, _dir) = command(name, "strict", database);
        let mut child = command
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if std::time::Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                scratch::remove_killed_daemon_locator("demo-database-id", child.id());
                panic!("{database}: the daemon started instead of refusing the id");
            }
            std::thread::sleep(Duration::from_millis(50));
        };
        assert!(
            !status.success(),
            "{database}: the daemon exited successfully"
        );
        let output = child.wait_with_output().unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("database_id should be 4-63 characters")
                && stderr.contains("firebase.json"),
            "{database}: {stderr}"
        );
    }
}

#[test]
fn strict_starts_with_ids_production_can_create() {
    for (name, database) in [
        ("four", "abcd"),
        ("hyphen", "re-ports"),
        ("digits", "a123"),
        ("longest", &"a".repeat(63)),
    ] {
        assert!(starts(name, "strict", database), "{database}");
    }
}

#[test]
fn the_emulator_profile_accepts_any_database_name() {
    assert!(starts("emulator-short", "emulator", "db"));
}
