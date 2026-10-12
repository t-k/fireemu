//! `fireemu up` / `exec` without `--config` or `--firebase-json`: the working directory's
//! `fireemu.json`, else the nearest `firebase.json` (the working directory or a parent, as
//! firebase-tools finds it), and the start banner says which files were loaded and, per
//! service, when no Security Rules are loaded.

mod scratch;

use std::path::Path;
use std::process::{Command, Output, Stdio};

use scratch::Scratch;

const FIRESTORE_RULES: &str = "rules_version = '2';\nservice cloud.firestore {\n  match /databases/{database}/documents {\n    match /{document=**} {\n      allow read, write: if false;\n    }\n  }\n}\n";
const STORAGE_RULES: &str = "rules_version = '2';\nservice firebase.storage {\n  match /b/{bucket}/o {\n    match /{allPaths=**} {\n      allow read, write: if false;\n    }\n  }\n}\n";
const FIREBASE_JSON: &str =
    r#"{"firestore": {"rules": "firestore.rules"}, "storage": {"rules": "storage.rules"}}"#;

fn scratch(name: &str) -> Scratch {
    Scratch::new("config-discovery", name)
}

/// A Firebase project directory: `firebase.json` naming both rules files.
fn firebase_project(dir: &Path) {
    std::fs::write(dir.join("firebase.json"), FIREBASE_JSON).unwrap();
    std::fs::write(dir.join("firestore.rules"), FIRESTORE_RULES).unwrap();
    std::fs::write(dir.join("storage.rules"), STORAGE_RULES).unwrap();
}

/// `fireemu exec` in `cwd` with `extra` options, running a command that writes the project ID
/// it was given to `project.txt` in `cwd`.
fn exec_in(cwd: &Path, extra: &[&str]) -> (Output, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_fireemu"))
        .current_dir(cwd)
        .args(["exec", "--only", "firestore,storage"])
        .args(extra)
        .args([
            "--firestore-port",
            "0",
            "--http-port",
            "0",
            "--storage-port",
            "0",
            "--hub-port",
            "0",
            "--",
            "/bin/sh",
            "-c",
            "printf %s \"$GCLOUD_PROJECT\" > project.txt",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let project = std::fs::read_to_string(cwd.join("project.txt")).unwrap();
    (output, project)
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// The banner line that starts with `prefix` (after its indentation).
fn line<'a>(banner: &'a str, prefix: &str) -> &'a str {
    banner
        .lines()
        .find(|l| l.trim_start().starts_with(prefix))
        .unwrap_or_else(|| panic!("no {prefix:?} line in:\n{banner}"))
}

#[test]
fn a_firebase_json_in_the_working_directory_is_loaded() {
    let dir = scratch("cwd-firebase");
    firebase_project(&dir);
    let (output, _) = exec_in(&dir, &[]);
    let banner = stdout(&output);
    let config = line(&banner, "config:");
    assert!(config.contains("firebase.json"), "{config}");
    assert!(
        config.contains("found in the working directory"),
        "{config}"
    );
    let rules = line(&banner, "firestore rules:");
    assert!(
        rules.contains("enforced from") && rules.contains("firestore.rules"),
        "{rules}"
    );
    assert!(
        !banner.contains("storage rules:    none loaded"),
        "storage.rules was loaded:\n{banner}"
    );
}

#[test]
fn a_firebase_json_in_a_parent_is_loaded_with_the_firebaserc_beside_it() {
    let dir = scratch("parent-firebase");
    firebase_project(&dir);
    std::fs::write(
        dir.join(".firebaserc"),
        r#"{"projects": {"default": "demo-discovered-parent"}}"#,
    )
    .unwrap();
    let sub = dir.join("functions").join("test");
    std::fs::create_dir_all(&sub).unwrap();
    let (output, project) = exec_in(&sub, &[]);
    assert_eq!(project, "demo-discovered-parent");
    let banner = stdout(&output);
    let config = line(&banner, "config:");
    assert!(config.contains("found in a parent"), "{config}");
    let rules = line(&banner, "firestore rules:");
    assert!(rules.contains("enforced from"), "{rules}");
}

#[test]
fn a_fireemu_json_in_the_working_directory_is_loaded_with_its_firebase_json_reference() {
    let dir = scratch("cwd-canonical");
    firebase_project(&dir);
    std::fs::write(
        dir.join("fireemu.json"),
        r#"{"schemaVersion": 1, "profile": "emulator", "firebaseJson": "firebase.json"}"#,
    )
    .unwrap();
    let (output, _) = exec_in(&dir, &[]);
    let banner = stdout(&output);
    let config = line(&banner, "config:");
    assert!(config.contains("fireemu.json"), "{config}");
    assert!(config.contains("firebaseJson"), "{config}");
    assert!(banner.contains("profile: emulator"), "{banner}");
    let rules = line(&banner, "firestore rules:");
    assert!(rules.contains("enforced from"), "{rules}");
}

#[test]
fn a_fireemu_json_without_a_reference_leaves_the_firebase_json_beside_it_unused_and_says_so() {
    let dir = scratch("cwd-canonical-alone");
    firebase_project(&dir);
    std::fs::write(dir.join("fireemu.json"), r#"{"schemaVersion": 1}"#).unwrap();
    let (output, _) = exec_in(&dir, &[]);
    let banner = stdout(&output);
    let config = line(&banner, "config:");
    assert!(config.contains("fireemu.json"), "{config}");
    assert!(
        config.contains("firebase.json beside it is not loaded"),
        "{config}"
    );
    let rules = line(&banner, "firestore rules:");
    assert!(rules.contains("none loaded"), "{rules}");
}

#[test]
fn a_fireemu_json_in_a_parent_is_not_used() {
    let dir = scratch("parent-canonical");
    std::fs::write(
        dir.join("fireemu.json"),
        r#"{"schemaVersion": 1, "profile": "emulator"}"#,
    )
    .unwrap();
    let sub = dir.join("sub");
    std::fs::create_dir_all(&sub).unwrap();
    let (output, _) = exec_in(&sub, &[]);
    let banner = stdout(&output);
    assert!(banner.contains("profile: strict"), "{banner}");
    assert!(line(&banner, "config:").contains("none found"), "{banner}");
}

#[test]
fn an_explicit_config_turns_discovery_off() {
    let dir = scratch("explicit");
    firebase_project(&dir);
    std::fs::write(
        dir.join("other.json"),
        r#"{"schemaVersion": 1, "profile": "emulator"}"#,
    )
    .unwrap();
    let (output, _) = exec_in(&dir, &["--config", "other.json"]);
    let banner = stdout(&output);
    let config = line(&banner, "config:");
    assert!(config.contains("other.json (--config)"), "{config}");
    // other.json selects the emulator profile, which allows every request without rules.
    let rules = line(&banner, "firestore rules:");
    assert!(
        rules.contains("none loaded, so every request is allowed"),
        "{rules}"
    );
    // An explicit --firebase-json wins as well.
    std::fs::write(dir.join("fireemu.json"), r#"{"schemaVersion": 1}"#).unwrap();
    std::fs::write(dir.join("empty.json"), "{}").unwrap();
    let (output, _) = exec_in(&dir, &["--firebase-json", "empty.json"]);
    let banner = stdout(&output);
    let config = line(&banner, "config:");
    assert!(config.contains("empty.json (--firebase-json)"), "{config}");
    assert!(
        line(&banner, "firestore rules:").contains("none loaded"),
        "{banner}"
    );
}

#[test]
fn no_config_discovery_starts_with_the_built_in_defaults() {
    let dir = scratch("opt-out");
    firebase_project(&dir);
    let (output, _) = exec_in(&dir, &["--no-config-discovery"]);
    let banner = stdout(&output);
    let config = line(&banner, "config:");
    assert!(config.contains("--no-config-discovery"), "{config}");
    assert!(
        line(&banner, "firestore rules:").contains("none loaded"),
        "{banner}"
    );
}

#[test]
fn strict_without_rules_warns_for_firestore_and_for_storage() {
    let dir = scratch("nothing");
    let (output, _) = exec_in(&dir, &[]);
    let banner = stdout(&output);
    assert!(line(&banner, "config:").contains("none found"), "{banner}");
    let firestore = line(&banner, "firestore rules:");
    assert!(
        firestore.contains("none loaded") && firestore.contains("every client request is refused"),
        "{firestore}"
    );
    assert!(firestore.contains("firebase.json"), "{firestore}");
    let storage = line(&banner, "storage rules:");
    assert!(
        storage.contains("none loaded") && storage.contains("refused with production's 400"),
        "{storage}"
    );
}

fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

/// The status of an anonymous HTTP/1.1 request.
fn anonymous_status(port: u16, method: &str, path: &str) -> u16 {
    use std::io::{Read, Write};
    let mut stream = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(20)))
        .unwrap();
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut raw = String::new();
    stream.read_to_string(&mut raw).unwrap();
    raw.split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or(0)
}

/// The client answers keep production's bytes, so the first refusal for want of rules is
/// explained on standard error, once per database and bucket; `--log-verbosity quiet` keeps it
/// silent.
#[test]
fn the_first_refusal_without_rules_is_explained_on_standard_error_once() {
    use std::io::{BufRead, BufReader, Read};
    for quiet in [false, true] {
        let dir = scratch(if quiet { "warn-quiet" } else { "warn" });
        let (firestore, storage) = (free_port(), free_port());
        let mut command = Command::new(env!("CARGO_BIN_EXE_fireemu"));
        command
            .current_dir(&dir)
            .args([
                "up",
                "--only",
                "firestore,storage",
                "--project",
                "demo-warn",
            ])
            .args(["--firestore-port", &firestore.to_string()])
            .args(["--storage-port", &storage.to_string()])
            .args(["--http-port", "0", "--hub-port", "0", "--ui-port", "0"])
            .args(["--logging-port", "0", "--ready-file", "ready.json"])
            .args(if quiet {
                &["--log-verbosity", "quiet"][..]
            } else {
                &[][..]
            })
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().unwrap();
        let ready = dir.join("ready.json");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
        while !ready.exists() {
            assert!(
                std::time::Instant::now() < deadline,
                "the daemon never became ready"
            );
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        let document = "/v1/projects/demo-warn/databases/(default)/documents/notes/n1";
        let object = "/v0/b/demo-warn.appspot.com/o/a.txt";
        for _ in 0..2 {
            assert_eq!(anonymous_status(firestore, "GET", document), 403);
            assert_eq!(anonymous_status(storage, "GET", object), 400);
        }
        let _ = Command::new("kill")
            .args(["-TERM", &child.id().to_string()])
            .status();
        let mut stderr = String::new();
        child
            .stderr
            .take()
            .unwrap()
            .read_to_string(&mut stderr)
            .unwrap();
        let _ = BufReader::new(child.stdout.take().unwrap()).lines().count();
        child.wait().unwrap();
        let firestore_warnings = stderr
            .lines()
            .filter(|l| l.starts_with("warning: firestore:"))
            .collect::<Vec<_>>();
        let storage_warnings = stderr
            .lines()
            .filter(|l| l.starts_with("warning: storage:"))
            .collect::<Vec<_>>();
        if quiet {
            assert!(
                firestore_warnings.is_empty() && storage_warnings.is_empty(),
                "{stderr}"
            );
            continue;
        }
        assert_eq!(firestore_warnings.len(), 1, "{stderr}");
        assert!(
            firestore_warnings[0].contains("\"(default)\"")
                && firestore_warnings[0].contains("no Security Rules are loaded")
                && firestore_warnings[0].contains("firestore.rules in firebase.json"),
            "{stderr}"
        );
        assert_eq!(storage_warnings.len(), 1, "{stderr}");
        assert!(
            storage_warnings[0].contains("\"demo-warn.appspot.com\"")
                && storage_warnings[0].contains("no Storage Rules are loaded")
                && storage_warnings[0].contains("storage.rules in firebase.json"),
            "{stderr}"
        );
    }
}

/// The Firestore rules line belongs to a run that serves Firestore.
#[test]
fn the_firestore_rules_line_is_printed_only_when_firestore_is_selected() {
    let dir = scratch("storage-only");
    let output = Command::new(env!("CARGO_BIN_EXE_fireemu"))
        .current_dir(&dir)
        .args(["exec", "--only", "storage", "--http-port", "0"])
        .args(["--storage-port", "0", "--hub-port", "0", "--", "true"])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(output.status.success());
    let banner = stdout(&output);
    assert!(!banner.contains("firestore rules:"), "{banner}");
    assert!(banner.contains("storage rules:"), "{banner}");
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[cfg(unix)]
fn chmod(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

/// Unlike firebase-tools, discovery loads only files the user controls: a candidate in a
/// directory anyone can write, or one its group can write, is skipped and named, and the run
/// goes on with the built-in defaults.
#[cfg(unix)]
#[test]
fn a_candidate_others_can_write_is_skipped_with_a_warning() {
    // The working directory can be written by anyone.
    let dir = scratch("world-writable-cwd");
    firebase_project(&dir);
    chmod(&dir, 0o777);
    let (output, _) = exec_in(&dir, &[]);
    let warning = stderr(&output);
    assert!(
        warning.contains("warning: config discovery skipped firebase.json: is in ")
            && warning.contains("which can be written by any user"),
        "{warning}"
    );
    let banner = stdout(&output);
    assert!(
        line(&banner, "config:").contains("none loaded: firebase.json was skipped"),
        "{banner}"
    );
    assert!(
        line(&banner, "firestore rules:").contains("none loaded"),
        "{banner}"
    );
    chmod(&dir, 0o755);

    // The file can be written by its group.
    let dir = scratch("group-writable-file");
    firebase_project(&dir);
    chmod(&dir.join("firebase.json"), 0o664);
    let (output, _) = exec_in(&dir, &[]);
    assert!(
        stderr(&output).contains("can be written by its group or by any user"),
        "{}",
        stderr(&output)
    );
    assert!(line(&stdout(&output), "firestore rules:").contains("none loaded"));
    // Naming it explicitly still loads it.
    let (output, _) = exec_in(&dir, &["--firebase-json", "firebase.json"]);
    assert!(!stderr(&output).contains("config discovery skipped"));
    assert!(line(&stdout(&output), "firestore rules:").contains("enforced from"));
}

/// A shared parent such as `/tmp` (sticky, anyone can write) ends the walk: a firebase.json
/// another user may have put there is never loaded.
#[cfg(unix)]
#[test]
fn the_walk_stops_at_a_sticky_shared_parent() {
    let dir = scratch("sticky-parent");
    let shared = dir.join("shared");
    let project = shared.join("project");
    std::fs::create_dir_all(&project).unwrap();
    firebase_project(&shared);
    chmod(&shared, 0o1777);
    let (output, _) = exec_in(&project, &[]);
    let warning = stderr(&output);
    assert!(
        warning.contains("config discovery skipped")
            && warning.contains("shared/firebase.json")
            && warning.contains("which can be written by any user"),
        "{warning}"
    );
    assert!(line(&stdout(&output), "firestore rules:").contains("none loaded"));
    chmod(&shared, 0o755);
}

/// The `.firebaserc` beside a discovered firebase.json follows the same rule.
#[cfg(unix)]
#[test]
fn a_firebaserc_others_can_write_is_not_used_for_the_project() {
    let dir = scratch("writable-firebaserc");
    firebase_project(&dir);
    let rc = dir.join(".firebaserc");
    std::fs::write(&rc, r#"{"projects": {"default": "demo-planted"}}"#).unwrap();
    chmod(&rc, 0o666);
    let (output, project) = exec_in(&dir, &[]);
    assert_ne!(project, "demo-planted");
    assert!(
        stderr(&output).contains("config discovery skipped")
            && stderr(&output).contains(".firebaserc"),
        "{}",
        stderr(&output)
    );
    // The firebase.json itself is the user's, so its rules still load.
    assert!(line(&stdout(&output), "firestore rules:").contains("enforced from"));
}

/// A broken file the search found says so, and how to choose another or none.
#[test]
fn an_error_in_a_discovered_file_says_it_was_discovered() {
    let dir = scratch("broken");
    std::fs::write(dir.join("firebase.json"), "{not json").unwrap();
    let sub = dir.join("sub");
    std::fs::create_dir_all(&sub).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_fireemu"))
        .current_dir(&sub)
        .args(["exec", "--only", "firestore", "--firestore-port", "0"])
        .args(["--http-port", "0", "--hub-port", "0", "--", "true"])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let error = stderr(&output);
    assert!(
        error.contains("does not parse")
            && error.contains("found by searching from the working directory")
            && error.contains("--no-config-discovery"),
        "{error}"
    );
    // The same file named explicitly gets no such hint.
    let output = Command::new(env!("CARGO_BIN_EXE_fireemu"))
        .current_dir(&sub)
        .args(["exec", "--firebase-json", "../firebase.json", "--", "true"])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(!stderr(&output).contains("found by searching"));
}

/// `init` in a subdirectory of a Firebase project writes a fireemu.json without a firebaseJson
/// entry; the banner says that the parent's firebase.json is not loaded.
#[test]
fn a_parent_firebase_json_shadowed_by_a_canonical_file_is_named() {
    let dir = scratch("shadowed-parent");
    firebase_project(&dir);
    let sub = dir.join("web");
    std::fs::create_dir_all(&sub).unwrap();
    std::fs::write(sub.join("fireemu.json"), r#"{"schemaVersion": 1}"#).unwrap();
    let (output, _) = exec_in(&sub, &[]);
    let config = stdout(&output);
    let config = line(&config, "config:");
    assert!(
        config.contains("firebase.json in a parent directory is not loaded"),
        "{config}"
    );
}

/// `emulators:export` looks for the suite of the project `up` would take from here, the one in
/// the `.firebaserc` beside the discovered firebase.json.
#[test]
fn export_resolves_the_project_the_way_up_does() {
    let dir = scratch("export-project");
    firebase_project(&dir);
    std::fs::write(
        dir.join(".firebaserc"),
        r#"{"projects": {"default": "demo-export-discovered"}}"#,
    )
    .unwrap();
    let sub = dir.join("functions");
    std::fs::create_dir_all(&sub).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_fireemu"))
        .current_dir(&sub)
        .args(["emulators:export", "out"])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr(&output).contains("no running fireemu suite for demo-export-discovered"),
        "{}",
        stderr(&output)
    );
}

/// `capabilities` reports the profile of the configuration `up` would load.
#[test]
fn capabilities_follow_discovery() {
    let dir = scratch("capabilities");
    std::fs::write(
        dir.join("fireemu.json"),
        r#"{"schemaVersion": 1, "profile": "emulator"}"#,
    )
    .unwrap();
    let profile = |extra: &[&str]| {
        let output = Command::new(env!("CARGO_BIN_EXE_fireemu"))
            .current_dir(&dir)
            .arg("capabilities")
            .args(extra)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert!(output.status.success(), "{}", stderr(&output));
        let manifest: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        manifest["profile"].as_str().unwrap().to_owned()
    };
    assert_eq!(profile(&[]), "emulator");
    assert_eq!(profile(&["--no-config-discovery"]), "strict");
}
