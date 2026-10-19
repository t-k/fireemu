//! A `firestore.indexes.json` with a search index (`searchConfig`), as a production project
//! with Enterprise text or geo search has, starts `fireemu up --firebase-json` under both
//! profiles: the search index is checked, left out of query planning and reported in one note.
//! A malformed `searchConfig` still stops the daemon with a message that names the field.

mod scratch;

use scratch::Scratch;

use std::io::{BufRead as _, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

const PROJECT: &str = "demo-search-indexes";

const SEARCH_INDEXES: &str = r#"{"indexes": [
  {"collectionGroup": "posts", "queryScope": "COLLECTION",
   "fields": [{"fieldPath": "a", "order": "ASCENDING"}, {"fieldPath": "b", "order": "ASCENDING"}]},
  {"collectionGroup": "posts", "queryScope": "COLLECTION_GROUP",
   "fields": [{"fieldPath": "body", "searchConfig": {"textSpec": {"indexSpecs": [
     {"indexType": "TOKENIZED", "matchType": "MATCH_GLOBALLY"}]}}}]},
  {"collectionGroup": "places", "queryScope": "COLLECTION_GROUP",
   "fields": [{"fieldPath": "location", "searchConfig": {"geoSpec": {"geoJsonIndexingDisabled": false}}}]}
], "fieldOverrides": []}"#;

const MALFORMED_SEARCH_CONFIG: &str = r#"{"indexes": [
  {"collectionGroup": "posts", "queryScope": "COLLECTION_GROUP",
   "fields": [{"fieldPath": "body", "searchConfig": {"textSpec": {"indexSpecs": [
     {"indexType": "NGRAM", "matchType": "MATCH_GLOBALLY"}]}}}]}
], "fieldOverrides": []}"#;

/// `fireemu up --config fireemu.json --firebase-json firebase.json`, where `firebase.json` names
/// the index file the way a Firebase project does.
fn command(name: &str, profile: &str, indexes: &str) -> (Command, Scratch) {
    let dir = Scratch::new("search-indexes", name);
    std::fs::write(dir.join("firestore.indexes.json"), indexes).unwrap();
    let firebase_json = dir.join("firebase.json");
    std::fs::write(
        &firebase_json,
        r#"{"firestore": {"indexes": "firestore.indexes.json"}}"#,
    )
    .unwrap();
    let config = dir.join("fireemu.json");
    std::fs::write(
        &config,
        format!(r#"{{"schemaVersion": 1, "profile": "{profile}"}}"#),
    )
    .unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_fireemu"));
    command
        .args(["up", "--config", config.to_str().unwrap()])
        .args(["--firebase-json", firebase_json.to_str().unwrap()])
        .args(["--project", PROJECT])
        .args([
            "--firestore-port",
            "0",
            "--http-port",
            "0",
            "--storage-port",
            "0",
        ])
        .args(["--logging-port", "0", "--ui-port", "0", "--hub-port", "0"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    (command, dir)
}

struct Running(Child);

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
        scratch::remove_killed_daemon_locator(PROJECT, self.0.id());
    }
}

enum Line {
    Out(String),
    Err(String),
}

/// Forwards the daemon's output, line by line, to one channel.
fn lines(child: &mut Child) -> mpsc::Receiver<Line> {
    let (tx, rx) = mpsc::channel();
    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();
    let out = tx.clone();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if out.send(Line::Out(line)).is_err() {
                return;
            }
        }
    });
    std::thread::spawn(move || {
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            if tx.send(Line::Err(line)).is_err() {
                return;
            }
        }
    });
    rx
}

#[test]
fn a_search_index_file_starts_under_both_profiles_with_one_note() {
    for profile in ["strict", "emulator"] {
        let (mut command, _dir) = command(&format!("start-{profile}"), profile, SEARCH_INDEXES);
        let mut child = Running(command.spawn().unwrap());
        let rx = lines(&mut child.0);
        let deadline = Instant::now() + Duration::from_secs(60);
        let (mut started, mut notes) = (false, Vec::new());
        while !started {
            let left = deadline.saturating_duration_since(Instant::now());
            match rx.recv_timeout(left) {
                Ok(Line::Out(line)) => started = line.contains("control API:"),
                Ok(Line::Err(line)) => {
                    if line.contains("searchConfig") {
                        notes.push(line);
                    }
                }
                Err(error) => {
                    panic!("{profile}: the daemon did not start ({error}); notes so far: {notes:?}")
                }
            }
        }
        assert_eq!(notes.len(), 1, "{profile}: {notes:?}");
        assert!(
            notes[0].starts_with("note: ")
                && notes[0].contains("firestore.indexes.json")
                && notes[0].contains("2 search indexes"),
            "{profile}: {}",
            notes[0]
        );
    }
}

#[test]
fn a_malformed_search_config_stops_the_daemon_under_both_profiles() {
    for profile in ["strict", "emulator"] {
        let (mut command, _dir) = command(
            &format!("malformed-{profile}"),
            profile,
            MALFORMED_SEARCH_CONFIG,
        );
        let mut child = Running(command.spawn().unwrap());
        let rx = lines(&mut child.0);
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut stderr = String::new();
        let status = loop {
            while let Ok(line) = rx.try_recv() {
                match line {
                    Line::Out(line) => assert!(
                        !line.contains("control API:"),
                        "{profile}: the daemon started with a malformed searchConfig"
                    ),
                    Line::Err(line) => {
                        stderr.push_str(&line);
                        stderr.push('\n');
                    }
                }
            }
            if let Some(status) = child.0.try_wait().unwrap() {
                break status;
            }
            assert!(
                Instant::now() < deadline,
                "{profile}: the daemon neither stopped nor started: {stderr}"
            );
            std::thread::sleep(Duration::from_millis(20));
        };
        assert!(
            !status.success(),
            "{profile}: the daemon exited successfully"
        );
        // Drain what the reader threads still hold once the process has gone.
        while let Ok(line) = rx.recv_timeout(Duration::from_secs(5)) {
            if let Line::Err(line) = line {
                stderr.push_str(&line);
                stderr.push('\n');
            }
        }
        assert!(
            stderr.contains("index field body") && stderr.contains("indexType"),
            "{profile}: {stderr}"
        );
    }
}
