//! `firestore.indexes.json` is checked as `firebase deploy` checks it under `strict`: a daemon
//! started with a file production's deploy refuses stops with a message that names the entry,
//! and the `emulator` profile, whose official emulator never reads the file, still starts.

mod scratch;

use scratch::Scratch;

use std::io::{BufRead as _, BufReader};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

const SINGLE_FIELD_GROUP_INDEX: &str = r#"{"indexes": [
  {"collectionGroup": "posts", "queryScope": "COLLECTION",
   "fields": [{"fieldPath": "a", "order": "ASCENDING"}, {"fieldPath": "b", "order": "ASCENDING"}]},
  {"collectionGroup": "g", "queryScope": "COLLECTION_GROUP",
   "fields": [{"fieldPath": "n", "order": "ASCENDING"}]}
], "fieldOverrides": []}"#;

const MISSPELLED_FIELDS: &str = r#"{"indexes": [
  {"collectionGroup": "posts", "queryScope": "COLLECTION",
   "feilds": [{"fieldPath": "a", "order": "ASCENDING"}, {"fieldPath": "b", "order": "ASCENDING"}]}
], "fieldOverrides": []}"#;

fn command(name: &str, profile: &str, indexes: &str) -> (Command, Scratch) {
    let dir = Scratch::new("indexes-deploy", name);
    let indexes_path = dir.join("firestore.indexes.json");
    std::fs::write(&indexes_path, indexes).unwrap();
    let config = dir.join("fireemu.json");
    std::fs::write(
        &config,
        format!(
            r#"{{"schemaVersion": 1, "profile": "{profile}", "firestore": {{"indexFile": {}, "edition": "standard", "apiMode": "native"}}}}"#,
            serde_json::Value::String(indexes_path.display().to_string())
        ),
    )
    .unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_fireemu"));
    command
        .args(["up", "--config", config.to_str().unwrap()])
        .args(["--project", "demo-indexes-deploy"])
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

fn refused(name: &str, indexes: &str) -> String {
    let (mut command, _dir) = command(name, "strict", indexes);
    let output = command
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    assert!(!output.status.success(), "the daemon started");
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn strict_refuses_a_single_field_composite_index_at_start() {
    let stderr = refused("single-field", SINGLE_FIELD_GROUP_INDEX);
    assert!(
        stderr.contains("indexes[1]")
            && stderr.contains("collection group g")
            && stderr.contains("this index is not necessary"),
        "{stderr}"
    );
}

#[test]
fn strict_refuses_an_entry_with_a_misspelled_fields_key_at_start() {
    let stderr = refused("misspelled", MISSPELLED_FIELDS);
    assert!(
        stderr.contains("indexes[0]") && stderr.contains("Must contain \"fields\""),
        "{stderr}"
    );
}

struct Running(Child);

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
        scratch::remove_killed_daemon_locator("demo-indexes-deploy", self.0.id());
    }
}

#[test]
fn the_emulator_profile_still_starts_with_those_files() {
    for (name, indexes) in [
        ("emulator-single", SINGLE_FIELD_GROUP_INDEX),
        ("emulator-misspelled", MISSPELLED_FIELDS),
    ] {
        let (mut command, _dir) = command(name, "emulator", indexes);
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
        rx.recv_timeout(Duration::from_secs(60))
            .unwrap_or_else(|_| panic!("{name}: the emulator profile did not start"));
    }
}
