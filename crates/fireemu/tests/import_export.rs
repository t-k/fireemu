//! Official import and export over the command line (`DATA-01` .. `DATA-05`).
//!
//! Every scenario runs the real binary against the export directories the official Local
//! Emulator Suite wrote, recorded under `tests/fixtures/export/` by
//! `conformance/src/record-export.mjs`.

mod census;

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/export")
        .join(name)
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "fireemu-import-export-{name}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A copy of a recorded fixture that a scenario may damage.
fn copy_fixture(name: &str, into: &Path) -> PathBuf {
    let target = into.join("export");
    copy_tree(&fixture(name), &target);
    target
}

fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), &target).unwrap();
        }
    }
}

fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

/// `fireemu exec` with every listener on an ephemeral port and the Hub off.
fn exec() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_fireemu"));
    cmd.args([
        "exec",
        "--firestore-port",
        "0",
        "--http-port",
        "0",
        "--storage-port",
        "0",
        "--ui-port",
        "0",
        "--hub-port",
        "0",
        "--project",
        "demo-export",
    ])
    .stdin(Stdio::null())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped());
    cmd
}

fn text(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn files(dir: &Path) -> Vec<String> {
    let mut out = Vec::new();
    walk(dir, dir, &mut out);
    out.sort();
    out
}

fn walk(root: &Path, at: &Path, out: &mut Vec<String>) {
    let Ok(entries) = std::fs::read_dir(at) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk(root, &path, out);
        } else if let Ok(relative) = path.strip_prefix(root) {
            out.push(relative.to_string_lossy().replace('\\', "/"));
        }
    }
}

#[cfg(unix)]
fn mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

// --------------------------------------------------------------------------------------
// DATA-01: an official export imports without silent loss
// --------------------------------------------------------------------------------------

#[test]
fn an_official_multi_product_export_is_imported_whole() {
    let output = exec()
        .args(["--import"])
        .arg(fixture("official-multiproduct"))
        .args(["--", "true"])
        .output()
        .unwrap();
    let log = text(&output);
    assert!(output.status.success(), "{log}");
    assert!(
        log.contains("firestore: 30 document(s) in 1 database(s)"),
        "{log}"
    );
    assert!(log.contains("auth: 5 account(s)"), "{log}");
    assert!(log.contains("storage: 3 object(s) in 1 bucket(s)"), "{log}");
}

#[test]
fn the_recorded_value_corpus_is_imported_whole() {
    let output = Command::new(env!("CARGO_BIN_EXE_fireemu"))
        .args([
            "exec",
            "--firestore-port",
            "0",
            "--http-port",
            "0",
            "--storage-port",
            "0",
            "--ui-port",
            "0",
            "--hub-port",
            "0",
            "--project",
            "demo-edge",
            "--only",
            "firestore",
            "--import",
        ])
        .arg(fixture("official-firestore-values"))
        .args(["--", "true"])
        .output()
        .unwrap();
    let log = text(&output);
    assert!(output.status.success(), "{log}");
    assert!(log.contains("firestore: 10 document(s)"), "{log}");
}

#[test]
fn a_section_of_an_unselected_product_is_skipped_with_a_notice() {
    let output = exec()
        .args(["--only", "auth", "--import"])
        .arg(fixture("official-multiproduct"))
        .args(["--", "true"])
        .output()
        .unwrap();
    let log = text(&output);
    assert!(output.status.success(), "{log}");
    assert!(
        log.contains("firestore section; --only did not select that product"),
        "{log}"
    );
    assert!(log.contains("auth: 5 account(s)"), "{log}");
    assert!(!log.contains("firestore: 30 document(s)"), "{log}");
}

#[test]
fn a_named_firestore_database_and_a_second_bucket_survive_the_round_trip() {
    let dir = scratch("named-database");
    let export = copy_fixture("official-multiproduct", &dir);

    // A second Firestore database, in the `fireemu` manifest member the official CLI
    // ignores: a copy of the default section under its own directory.
    copy_tree(
        &export.join("firestore_export"),
        &export.join("firestore_export_analytics"),
    );
    let manifest = export.join("firebase-export-metadata.json");
    let manifest_text = std::fs::read_to_string(&manifest).unwrap();
    let with_extension = manifest_text.trim_end().trim_end_matches('}').to_owned()
        + r#",
  "fireemu": {
    "version": "0.1.0",
    "firestoreDatabases": [
      {
        "database": "analytics",
        "path": "firestore_export_analytics",
        "metadata_file": "firestore_export_analytics/firestore_export.overall_export_metadata"
      }
    ]
  }
}
"#;
    std::fs::write(&manifest, with_extension).unwrap();

    // A second bucket, holding a copy of an object of the first.
    let metadata_dir = export.join("storage_export/metadata");
    let source = std::fs::read_dir(&metadata_dir)
        .unwrap()
        .flatten()
        .next()
        .unwrap()
        .path();
    let source_id = source.file_stem().unwrap().to_string_lossy().into_owned();
    let document = std::fs::read_to_string(&source)
        .unwrap()
        .replace("demo-export.appspot.com", "second.appspot.com");
    std::fs::write(
        metadata_dir.join("copied-into-second-bucket.json"),
        document,
    )
    .unwrap();
    std::fs::copy(
        export.join("storage_export/blobs").join(&source_id),
        export.join("storage_export/blobs/copied-into-second-bucket"),
    )
    .unwrap();
    let buckets = export.join("storage_export/buckets.json");
    std::fs::write(
        &buckets,
        r#"{"buckets":[{"id":"demo-export.appspot.com"},{"id":"second.appspot.com"}]}"#,
    )
    .unwrap();

    let out = dir.join("out");
    let output = exec()
        .args(["--import"])
        .arg(&export)
        .arg("--export-on-exit")
        .arg(&out)
        .args(["--", "true"])
        .output()
        .unwrap();
    let log = text(&output);
    assert!(output.status.success(), "{log}");
    assert!(
        log.contains("firestore: 60 document(s) in 2 database(s)"),
        "both databases are imported: {log}"
    );
    assert!(
        log.contains("storage: 4 object(s) in 2 bucket(s)"),
        "both buckets are imported: {log}"
    );

    // The export writes the named database back under its own section, and the manifest's
    // official Firestore section still names only the default one.
    let written = files(&out);
    assert!(
        written
            .iter()
            .any(|f| f.starts_with("firestore_export_analytics/")),
        "{written:?}"
    );
    let manifest = std::fs::read_to_string(out.join("firebase-export-metadata.json")).unwrap();
    assert!(manifest.contains("\"fireemu\""), "{manifest}");
    assert!(
        manifest.contains("\"database\": \"analytics\""),
        "{manifest}"
    );
    assert!(
        std::fs::read_to_string(out.join("storage_export/buckets.json"))
            .unwrap()
            .contains("second.appspot.com")
    );

    // And it imports again with the same shape.
    let second = exec()
        .args(["--import"])
        .arg(&out)
        .args(["--", "true"])
        .output()
        .unwrap();
    let log = text(&second);
    assert!(second.status.success(), "{log}");
    assert!(
        log.contains("firestore: 60 document(s) in 2 database(s)"),
        "{log}"
    );
    assert!(log.contains("storage: 4 object(s) in 2 bucket(s)"), "{log}");
}

// --------------------------------------------------------------------------------------
// DATA-03: a cross-product import is atomic
// --------------------------------------------------------------------------------------

/// The daemon must not start at all when a section is malformed: nothing bound, nothing
/// imported, the command never ran, exit code 1 naming the product and the path.
fn assert_refused(output: &Output, product: &str, fragment: &str) {
    let log = text(output);
    assert_eq!(output.status.code(), Some(1), "{log}");
    assert!(
        log.contains(product),
        "the failure names the product: {log}"
    );
    assert!(log.contains(fragment), "the failure names the path: {log}");
    assert!(
        !log.contains("running: "),
        "the command must never have started: {log}"
    );
    assert!(
        !log.contains("imported: "),
        "nothing may be reported as imported: {log}"
    );
}

#[test]
fn a_corrupt_firestore_section_refuses_the_whole_import() {
    let dir = scratch("corrupt-firestore");
    let export = copy_fixture("official-multiproduct", &dir);
    let output_file = export.join("firestore_export/all_namespaces/all_kinds/output-0");
    let mut bytes = std::fs::read(&output_file).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0xff;
    std::fs::write(&output_file, bytes).unwrap();

    let output = exec()
        .args(["--import"])
        .arg(&export)
        .args(["--", "true"])
        .output()
        .unwrap();
    assert_refused(&output, "firestore", "output-0");
}

#[test]
fn a_malformed_auth_section_refuses_the_whole_import() {
    let dir = scratch("corrupt-auth");
    let export = copy_fixture("official-multiproduct", &dir);
    std::fs::write(
        export.join("auth_export/accounts.json"),
        "{\"users\": [{}]}",
    )
    .unwrap();

    let output = exec()
        .args(["--import"])
        .arg(&export)
        .args(["--", "true"])
        .output()
        .unwrap();
    assert_refused(&output, "auth", "accounts.json");
}

#[test]
fn a_storage_blob_that_does_not_match_its_metadata_refuses_the_whole_import() {
    let dir = scratch("corrupt-storage");
    let export = copy_fixture("official-multiproduct", &dir);
    let blobs = export.join("storage_export/blobs");
    let first = std::fs::read_dir(&blobs)
        .unwrap()
        .flatten()
        .next()
        .unwrap()
        .path();
    std::fs::write(&first, b"these are not the recorded bytes").unwrap();

    let output = exec()
        .args(["--import"])
        .arg(&export)
        .args(["--", "true"])
        .output()
        .unwrap();
    // The mismatch is caught while applying, after every section parsed; the run still
    // never reaches the command.
    let log = text(&output);
    assert_eq!(output.status.code(), Some(1), "{log}");
    assert!(log.contains("storage"), "{log}");
    assert!(!log.contains("running: "), "{log}");
}

#[test]
fn a_missing_blob_refuses_the_whole_import() {
    let dir = scratch("missing-blob");
    let export = copy_fixture("official-multiproduct", &dir);
    let blobs = export.join("storage_export/blobs");
    let first = std::fs::read_dir(&blobs)
        .unwrap()
        .flatten()
        .next()
        .unwrap()
        .path();
    std::fs::remove_file(&first).unwrap();

    let output = exec()
        .args(["--import"])
        .arg(&export)
        .args(["--", "true"])
        .output()
        .unwrap();
    assert_refused(&output, "storage", "blobs");
}

#[test]
fn a_realtime_database_section_is_refused_with_the_deferred_status() {
    let dir = scratch("rtdb");
    let export = dir.join("export");
    std::fs::create_dir_all(export.join("database_export")).unwrap();
    std::fs::write(
        export.join("firebase-export-metadata.json"),
        r#"{"version":"15.28.2","database":{"version":"4.11.2","path":"database_export"}}"#,
    )
    .unwrap();
    std::fs::write(export.join("database_export/demo-export.json"), "{}").unwrap();

    let output = exec()
        .args(["--import"])
        .arg(&export)
        .args(["--", "true"])
        .output()
        .unwrap();
    let log = text(&output);
    assert_eq!(output.status.code(), Some(1), "{log}");
    assert!(log.contains("Realtime Database"), "{log}");
    assert!(log.contains("deferred"), "{log}");
    assert!(!log.contains("running: "), "{log}");
}

#[test]
fn a_data_connect_section_is_refused_with_the_deferred_status() {
    let dir = scratch("dataconnect");
    let export = dir.join("export");
    std::fs::create_dir_all(export.join("dataconnect_export")).unwrap();
    std::fs::write(
        export.join("firebase-export-metadata.json"),
        r#"{"version":"15.28.2","dataconnect":{"version":"15.28.2","path":"dataconnect_export"}}"#,
    )
    .unwrap();

    let output = exec()
        .args(["--import"])
        .arg(&export)
        .args(["--", "true"])
        .output()
        .unwrap();
    let log = text(&output);
    assert_eq!(output.status.code(), Some(1), "{log}");
    assert!(log.contains("SQL Connect"), "{log}");
    assert!(!log.contains("running: "), "{log}");
}

#[test]
fn an_import_directory_that_does_not_exist_is_refused_before_anything_binds() {
    let output = exec()
        .args(["--import", "/nonexistent/fireemu/export", "--", "true"])
        .output()
        .unwrap();
    let log = text(&output);
    assert_eq!(output.status.code(), Some(1), "{log}");
    assert!(log.contains("no such directory"), "{log}");
}

// --------------------------------------------------------------------------------------
// DATA-02 and DATA-04: the shutdown export
// --------------------------------------------------------------------------------------

#[test]
fn an_export_on_exit_reimports_into_the_same_state() {
    let dir = scratch("round-trip");
    let out = dir.join("out");
    let output = exec()
        .args(["--import"])
        .arg(fixture("official-multiproduct"))
        .arg("--export-on-exit")
        .arg(&out)
        .args(["--", "true"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", text(&output));
    let written = files(&out);
    for expected in [
        "auth_export/accounts.json",
        "auth_export/config.json",
        "firebase-export-metadata.json",
        "firestore_export/all_namespaces/all_kinds/all_namespaces_all_kinds.export_metadata",
        "firestore_export/all_namespaces/all_kinds/output-0",
        "firestore_export/firestore_export.overall_export_metadata",
        "storage_export/buckets.json",
    ] {
        assert!(
            written.iter().any(|f| f == expected),
            "the export holds {expected}: {written:?}"
        );
    }
    assert_eq!(
        written
            .iter()
            .filter(|f| f.starts_with("storage_export/blobs/"))
            .count(),
        3
    );

    // The export fireemu wrote imports back with the same shape.
    let again = dir.join("again");
    let second = exec()
        .args(["--import"])
        .arg(&out)
        .arg("--export-on-exit")
        .arg(&again)
        .args(["--", "true"])
        .output()
        .unwrap();
    let log = text(&second);
    assert!(second.status.success(), "{log}");
    assert!(
        log.contains("firestore: 30 document(s) in 1 database(s)"),
        "{log}"
    );
    assert!(log.contains("auth: 5 account(s)"), "{log}");
    assert!(log.contains("storage: 3 object(s)"), "{log}");
    // The blob ids are derived from the object, not drawn at random, so a second export of
    // the same state writes the same file names.
    assert_eq!(
        files(&out)
            .into_iter()
            .filter(|f| f.starts_with("storage_export/blobs/"))
            .collect::<Vec<String>>(),
        files(&again)
            .into_iter()
            .filter(|f| f.starts_with("storage_export/blobs/"))
            .collect::<Vec<String>>()
    );
}

#[test]
fn an_export_covers_exactly_the_products_only_selected() {
    let dir = scratch("only-export");
    let out = dir.join("out");
    let output = exec()
        .args(["--only", "auth", "--import"])
        .arg(fixture("official-multiproduct"))
        .arg("--export-on-exit")
        .arg(&out)
        .args(["--", "true"])
        .output()
        .unwrap();
    let log = text(&output);
    assert!(output.status.success(), "{log}");
    let written = files(&out);
    assert!(
        written.iter().any(|f| f == "auth_export/accounts.json"),
        "{written:?}"
    );
    assert!(
        !written.iter().any(|f| f.starts_with("firestore_export")),
        "an unselected product gets no section: {written:?}"
    );
    assert!(
        !written.iter().any(|f| f.starts_with("storage_export")),
        "an unselected product gets no section: {written:?}"
    );
    let manifest = std::fs::read_to_string(out.join("firebase-export-metadata.json")).unwrap();
    assert!(manifest.contains("\"auth\""), "{manifest}");
    assert!(!manifest.contains("\"firestore\""), "{manifest}");
    assert!(!manifest.contains("\"storage\""), "{manifest}");
}

#[test]
fn the_export_runs_when_the_command_fails() {
    let dir = scratch("child-failure");
    let out = dir.join("out");
    let output = exec()
        .args(["--import"])
        .arg(fixture("official-multiproduct"))
        .arg("--export-on-exit")
        .arg(&out)
        .args(["--", "false"])
        .output()
        .unwrap();
    let log = text(&output);
    assert_eq!(output.status.code(), Some(1), "{log}");
    assert!(
        out.join("firebase-export-metadata.json").is_file(),
        "the export still ran: {log}"
    );
    assert!(files(&out).iter().any(|f| f.starts_with("auth_export/")));
}

#[test]
fn the_export_runs_when_the_daemon_is_interrupted() {
    let dir = scratch("sigint");
    let out = dir.join("out");
    let ready = dir.join("ready");
    let supervisor = exec()
        .args(["--import"])
        .arg(fixture("official-multiproduct"))
        .arg("--export-on-exit")
        .arg(&out)
        .args(["--", "sh", "-c"])
        .arg(format!("touch {}; exec sleep 60", ready.display()))
        .spawn()
        .unwrap();
    let started = Instant::now();
    while !ready.exists() && started.elapsed() < Duration::from_secs(60) {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(ready.exists(), "the command started");
    assert!(Command::new("kill")
        .args(["-INT", &supervisor.id().to_string()])
        .status()
        .unwrap()
        .success());
    let output = supervisor.wait_with_output().unwrap();
    let log = text(&output);
    assert!(
        out.join("firebase-export-metadata.json").is_file(),
        "SIGINT still wrote the export: {log}"
    );
    census::assert_no_owned_descendants("after the interrupted export", Duration::from_secs(10));
}

#[test]
fn the_export_runs_when_the_daemon_is_terminated() {
    let dir = scratch("sigterm");
    let out = dir.join("out");
    let ready = dir.join("ready");
    let supervisor = exec()
        .args(["--import"])
        .arg(fixture("official-multiproduct"))
        .arg("--export-on-exit")
        .arg(&out)
        .args(["--", "sh", "-c"])
        .arg(format!("touch {}; exec sleep 60", ready.display()))
        .spawn()
        .unwrap();
    let started = Instant::now();
    while !ready.exists() && started.elapsed() < Duration::from_secs(60) {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(ready.exists(), "the command started");
    assert!(Command::new("kill")
        .args(["-TERM", &supervisor.id().to_string()])
        .status()
        .unwrap()
        .success());
    let output = supervisor.wait_with_output().unwrap();
    let log = text(&output);
    assert!(
        out.join("firebase-export-metadata.json").is_file(),
        "SIGTERM still wrote the export: {log}"
    );
    census::assert_no_owned_descendants("after the terminated export", Duration::from_secs(10));
}

#[test]
fn a_startup_failure_writes_no_export_at_all() {
    let dir = scratch("startup-failure");
    let out = dir.join("out");
    let export = copy_fixture("official-multiproduct", &dir);
    std::fs::write(export.join("auth_export/accounts.json"), "not json").unwrap();
    let output = exec()
        .args(["--import"])
        .arg(&export)
        .arg("--export-on-exit")
        .arg(&out)
        .args(["--", "true"])
        .output()
        .unwrap();
    let log = text(&output);
    assert_eq!(output.status.code(), Some(1), "{log}");
    assert!(
        !out.join("firebase-export-metadata.json").exists(),
        "a run that never started writes nothing: {log}"
    );
}

#[test]
fn export_on_exit_without_a_directory_uses_the_import_one() {
    let dir = scratch("same-directory");
    let export = copy_fixture("official-multiproduct", &dir);
    let before = std::fs::read_to_string(export.join("auth_export/accounts.json")).unwrap();
    let output = exec()
        .args(["--import"])
        .arg(&export)
        .arg("--export-on-exit")
        .args(["--", "true"])
        .output()
        .unwrap();
    let log = text(&output);
    assert!(output.status.success(), "{log}");
    let after = std::fs::read_to_string(export.join("auth_export/accounts.json")).unwrap();
    assert_ne!(before, after, "the directory was rewritten in place");
    assert!(after.contains("user-password"), "{after}");
}

// --------------------------------------------------------------------------------------
// DATA-05: the artifacts carry credentials, so the directory is owner-only
// --------------------------------------------------------------------------------------

#[cfg(unix)]
#[test]
fn every_exported_directory_and_file_is_owner_only() {
    let dir = scratch("permissions");
    let out = dir.join("out");
    let output = exec()
        .args(["--import"])
        .arg(fixture("official-multiproduct"))
        .arg("--export-on-exit")
        .arg(&out)
        .args(["--", "true"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", text(&output));
    assert_eq!(mode(&out), 0o700, "{}", out.display());
    for relative in files(&out) {
        let path = out.join(&relative);
        assert_eq!(mode(&path), 0o600, "{relative} is group or world readable");
        if let Some(parent) = path.parent() {
            assert_eq!(mode(parent), 0o700, "{relative}'s directory is not private");
        }
    }
}

#[test]
fn no_app_check_secret_or_fireemu_snapshot_reaches_an_export() {
    let dir = scratch("no-secrets");
    let out = dir.join("out");
    let output = exec()
        .args(["--import"])
        .arg(fixture("official-multiproduct"))
        .arg("--export-on-exit")
        .arg(&out)
        .args(["--", "true"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", text(&output));
    let names = files(&out);
    assert!(
        names.iter().all(|f| {
            f.starts_with("auth_export/")
                || f.starts_with("firestore_export")
                || f.starts_with("storage_export/")
                || f == "firebase-export-metadata.json"
        }),
        "an export holds only the official sections: {names:?}"
    );
    for relative in &names {
        let bytes = std::fs::read(out.join(relative)).unwrap();
        let text = String::from_utf8_lossy(&bytes);
        for forbidden in ["appCheck", "app_check", "debugToken", "epoch", "snapshot"] {
            assert!(
                !text.contains(forbidden),
                "{relative} mentions {forbidden}, which belongs to fireemu's own session state"
            );
        }
    }
}

// --------------------------------------------------------------------------------------
// Overwrite protection and `emulators:export`
// --------------------------------------------------------------------------------------

#[test]
fn an_occupied_directory_that_is_not_an_export_is_never_overwritten() {
    let dir = scratch("occupied");
    let out = dir.join("documents");
    std::fs::create_dir_all(&out).unwrap();
    std::fs::write(out.join("notes.txt"), "keep me").unwrap();

    let output = exec()
        .args(["--import"])
        .arg(fixture("official-multiproduct"))
        .arg("--export-on-exit")
        .arg(&out)
        .args(["--", "true"])
        .output()
        .unwrap();
    let log = text(&output);
    assert_eq!(output.status.code(), Some(1), "{log}");
    assert!(log.contains("not an export directory"), "{log}");
    assert_eq!(
        std::fs::read_to_string(out.join("notes.txt")).unwrap(),
        "keep me"
    );
}

#[test]
fn export_on_exit_refuses_the_working_directory() {
    let dir = scratch("cwd");
    let output = exec()
        .current_dir(&dir)
        .arg("--export-on-exit")
        .arg(&dir)
        .args(["--", "true"])
        .output()
        .unwrap();
    let log = text(&output);
    assert_eq!(output.status.code(), Some(1), "{log}");
    assert!(log.contains("working directory"), "{log}");
}

#[test]
fn emulators_export_drives_a_running_suite_through_its_hub() {
    let dir = scratch("hub-export");
    let out = dir.join("out");
    let hub_port = free_port();
    let ready = dir.join("ready");
    let mut supervisor = Command::new(env!("CARGO_BIN_EXE_fireemu"))
        .args([
            "up",
            "--firestore-port",
            "0",
            "--http-port",
            "0",
            "--storage-port",
            "0",
            "--ui-port",
            "0",
            "--project",
            "demo-export-hub",
            "--hub-port",
            &hub_port.to_string(),
            "--import",
        ])
        .arg(fixture("official-multiproduct"))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // The Hub is up once its port accepts.
    let started = Instant::now();
    while std::net::TcpStream::connect(("127.0.0.1", hub_port)).is_err()
        && started.elapsed() < Duration::from_secs(60)
    {
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = std::fs::write(&ready, "");

    let export = Command::new(env!("CARGO_BIN_EXE_fireemu"))
        .args(["emulators:export"])
        .arg(&out)
        .args(["--project", "demo-export-hub"])
        .output()
        .unwrap();
    let log = text(&export);
    assert!(export.status.success(), "{log}");
    assert!(log.contains("exported demo-export-hub"), "{log}");
    assert!(out.join("firebase-export-metadata.json").is_file(), "{log}");
    assert!(out.join("auth_export/accounts.json").is_file(), "{log}");

    let _ = Command::new("kill")
        .args(["-TERM", &supervisor.id().to_string()])
        .status();
    let _ = supervisor.wait();
}

#[test]
fn emulators_export_without_a_running_suite_says_so() {
    let dir = scratch("no-suite");
    let output = Command::new(env!("CARGO_BIN_EXE_fireemu"))
        .args(["emulators:export"])
        .arg(dir.join("out"))
        .args(["--project", "demo-nothing-running-here"])
        .output()
        .unwrap();
    let log = text(&output);
    assert_eq!(output.status.code(), Some(1), "{log}");
    assert!(log.contains("no running fireemu suite"), "{log}");
}

#[test]
fn emulators_export_needs_a_directory() {
    let output = Command::new(env!("CARGO_BIN_EXE_fireemu"))
        .args(["emulators:export"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2), "{}", text(&output));
}
