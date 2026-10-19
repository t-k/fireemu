//! A `firestore.indexes.json` with a search index (`searchConfig`), as a production project
//! with Enterprise text or geo search has, starts `fireemu up --firebase-json` under both
//! profiles: the search index is checked, left out of query planning and reported in one note.
//! A malformed `searchConfig` still stops the daemon with a message that names the field, and a
//! named database's ordinary query gets the same missing-index answer with or without a search
//! index in its file.

mod scratch;

use scratch::Scratch;

use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::net::TcpStream;
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

/// A `firebase.json` whose default database reads the index file.
const DEFAULT_DATABASE: &str = r#"{"firestore": {"indexes": "firestore.indexes.json"}}"#;

/// A `firebase.json` whose named database `staging` reads the index file.
const NAMED_DATABASE: &str = r#"{"firestore": [{"database": "(default)"}, {"database": "staging", "indexes": "firestore.indexes.json"}]}"#;

/// `fireemu up --config fireemu.json --firebase-json firebase.json`, where `firebase.json` names
/// the index file the way a Firebase project does.
fn command(name: &str, profile: &str, indexes: &str) -> (Command, Scratch) {
    command_with(name, profile, indexes, DEFAULT_DATABASE, 0)
}

fn command_with(
    name: &str,
    profile: &str,
    indexes: &str,
    firebase: &str,
    hub_port: u16,
) -> (Command, Scratch) {
    let dir = Scratch::new("search-indexes", name);
    std::fs::write(dir.join("firestore.indexes.json"), indexes).unwrap();
    let firebase_json = dir.join("firebase.json");
    std::fs::write(&firebase_json, firebase).unwrap();
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
        .args(["--logging-port", "0", "--ui-port", "0", "--hub-port"])
        .arg(hub_port.to_string())
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

fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

fn http_as_owner(port: u16, method: &str, path: &str, body: &str) -> (u16, serde_json::Value) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("the daemon accepts");
    stream
        .set_read_timeout(Some(Duration::from_secs(20)))
        .unwrap();
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer owner\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
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
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .unwrap_or(0);
    (status, serde_json::from_str(body).unwrap_or_default())
}

/// The ordinary composite index of both files, and a search index whose fields, read as
/// ordinary ascending fields, would serve the query below.
const NAMED_WITH_SEARCH: &str = r#"{"indexes": [
  {"collectionGroup": "posts", "queryScope": "COLLECTION",
   "fields": [{"fieldPath": "a", "order": "ASCENDING"}, {"fieldPath": "b", "order": "ASCENDING"}]},
  {"collectionGroup": "posts", "queryScope": "COLLECTION",
   "fields": [{"fieldPath": "a", "order": "ASCENDING"}, {"fieldPath": "body", "searchConfig": {"textSpec": {"indexSpecs": [
     {"indexType": "TOKENIZED", "matchType": "MATCH_GLOBALLY"}]}}}]}
], "fieldOverrides": []}"#;

const NAMED_WITHOUT_SEARCH: &str = r#"{"indexes": [
  {"collectionGroup": "posts", "queryScope": "COLLECTION",
   "fields": [{"fieldPath": "a", "order": "ASCENDING"}, {"fieldPath": "b", "order": "ASCENDING"}]}
], "fieldOverrides": []}"#;

/// Starts a strict daemon whose `staging` database reads `indexes`, and answers its startup
/// notes about search indexes and the answer to `where a == 1 order by body` on `staging`.
fn staging_query(name: &str, indexes: &str) -> (Vec<String>, u16, serde_json::Value) {
    let hub_port = free_port();
    let (mut command, _dir) = command_with(name, "strict", indexes, NAMED_DATABASE, hub_port);
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
            Err(error) => panic!("{name}: the daemon did not start ({error})"),
        }
    }
    let (status, emulators) = http_as_owner(hub_port, "GET", "/emulators", "");
    assert_eq!(status, 200, "{emulators}");
    let port = u16::try_from(emulators["firestore"]["port"].as_u64().unwrap()).unwrap();
    let query = serde_json::json!({"structuredQuery": {
        "from": [{"collectionId": "posts"}],
        "where": {"fieldFilter": {"field": {"fieldPath": "a"}, "op": "EQUAL", "value": {"integerValue": "1"}}},
        "orderBy": [{"field": {"fieldPath": "body"}, "direction": "ASCENDING"}],
    }});
    let (status, body) = http_as_owner(
        port,
        "POST",
        &format!("/v1/projects/{PROJECT}/databases/staging/documents:runQuery"),
        &query.to_string(),
    );
    (notes, status, body)
}

#[test]
fn a_named_databases_search_index_is_noted_and_leaves_its_missing_index_answer_alone() {
    let (notes, status, with_search) = staging_query("named-with", NAMED_WITH_SEARCH);
    assert_eq!(notes.len(), 1, "{notes:?}");
    assert!(notes[0].contains("1 search index "), "{}", notes[0]);
    assert_eq!(status, 400, "{with_search}");
    assert!(
        with_search.to_string().contains("FAILED_PRECONDITION"),
        "{with_search}"
    );
    let (notes, plain_status, without_search) =
        staging_query("named-without", NAMED_WITHOUT_SEARCH);
    assert!(notes.is_empty(), "{notes:?}");
    assert_eq!((status, with_search), (plain_status, without_search));
}

/// A hot reload that brings a search index prints the note after the new indexes are in force,
/// that is after the reload line.
#[test]
fn a_hot_reload_notes_the_search_indexes_after_it_takes_effect() {
    let (mut command, dir) = command("reload", "strict", NAMED_WITHOUT_SEARCH);
    let mut child = Running(command.spawn().unwrap());
    let rx = lines(&mut child.0);
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        match rx.recv_timeout(left) {
            Ok(Line::Out(line)) if line.contains("control API:") => break,
            Ok(Line::Err(line)) => assert!(!line.contains("searchConfig"), "{line}"),
            Ok(Line::Out(_)) => {}
            Err(error) => panic!("the daemon did not start ({error})"),
        }
    }
    std::fs::write(dir.join("firestore.indexes.json"), SEARCH_INDEXES).unwrap();
    let mut seen = Vec::new();
    while !seen
        .iter()
        .any(|line: &String| line.contains("searchConfig"))
    {
        let left = deadline.saturating_duration_since(Instant::now());
        match rx.recv_timeout(left) {
            Ok(Line::Err(line)) if line.starts_with("note: ") => seen.push(line),
            Ok(_) => {}
            Err(error) => panic!("no search note after the reload ({error}): {seen:?}"),
        }
    }
    let reloaded = seen
        .iter()
        .position(|line| line.contains("reloaded Firestore indexes"))
        .unwrap_or_else(|| panic!("{seen:?}"));
    let noted = seen
        .iter()
        .position(|line| line.contains("2 search indexes"))
        .unwrap_or_else(|| panic!("{seen:?}"));
    assert!(reloaded < noted, "{seen:?}");
}
