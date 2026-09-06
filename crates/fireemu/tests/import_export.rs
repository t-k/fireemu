//! Official import and export over the command line (`DATA-01` .. `DATA-05`).
//!
//! Every scenario runs the real binary against the export directories the official Local
//! Emulator Suite wrote, recorded under `tests/fixtures/export/` by
//! `conformance/src/record-export.mjs`.

mod census;

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

#[cfg(unix)]
#[path = "../../../tests/support/trusted_temp.rs"]
mod trusted_temp;

#[cfg(unix)]
use trusted_temp::TrustedTempDir;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/export")
        .join(name)
}

#[cfg(unix)]
fn scratch(name: &str) -> TrustedTempDir {
    TrustedTempDir::new(&format!("import-export-{name}"))
}

#[cfg(not(unix))]
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
        "--logging-port",
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

struct ChildGuard(Option<Child>);

impl ChildGuard {
    fn new(child: Child) -> Self {
        Self(Some(child))
    }

    fn id(&self) -> u32 {
        self.0.as_ref().expect("child is present").id()
    }

    fn wait_with_output(mut self) -> std::io::Result<Output> {
        self.0.take().expect("child is present").wait_with_output()
    }

    fn terminate_and_wait(mut self) {
        let mut child = self.0.take().expect("child is present");
        let _ = Command::new("kill")
            .args(["-TERM", &child.id().to_string()])
            .status();
        let _ = child.wait();
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = Command::new("kill")
                .args(["-TERM", &child.id().to_string()])
                .status();
            let _ = child.wait();
        }
    }
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

#[cfg(all(target_os = "macos", not(debug_assertions)))]
fn write_document_artifact(root: &Path, count: usize, payload_len: usize) -> u64 {
    use std::collections::BTreeMap;
    use std::io::Write as _;

    use fireemu_core_export::firestore::{
        write_output_to, ExportDocument, OverallMetadata, PartitionMetadata, EXPORT_NAME,
        OUTPUT_FILE, PARTITION_DIR, PARTITION_METADATA,
    };
    use fireemu_core_export::metadata::{
        ExportMetadata, Product, Section, FIRESTORE_OVERALL_METADATA, FIRESTORE_PATH,
        METADATA_FILE_NAME,
    };
    use fireemu_core_firestore::value::Value;

    let partition = root.join(FIRESTORE_PATH).join(PARTITION_DIR);
    std::fs::create_dir_all(&partition).unwrap();
    let documents: Vec<_> = (0..count)
        .map(|index| {
            let mut fields = BTreeMap::new();
            fields.insert(
                "payload".to_owned(),
                Value::Bytes(vec![u8::try_from(index % 251).unwrap(); payload_len]),
            );
            ExportDocument {
                project: "demo-import-rss".to_owned(),
                path: vec![("payloads".to_owned(), format!("doc-{index:06}"))],
                fields,
            }
        })
        .collect();
    let mut output =
        std::io::BufWriter::new(std::fs::File::create(partition.join(OUTPUT_FILE)).unwrap());
    let artifact_bytes = write_output_to(&documents, &mut output).unwrap();
    output.flush().unwrap();
    std::fs::write(
        partition.join(PARTITION_METADATA),
        PartitionMetadata {
            export_name: EXPORT_NAME.to_owned(),
            start_micros: 0,
            end_micros: 0,
            output_files: vec![OUTPUT_FILE.to_owned()],
        }
        .to_bytes(),
    )
    .unwrap();
    std::fs::write(
        root.join(FIRESTORE_PATH).join(FIRESTORE_OVERALL_METADATA),
        OverallMetadata {
            metadata_file: format!("{PARTITION_DIR}/{PARTITION_METADATA}"),
            entity_count: count as u64,
            byte_count: artifact_bytes,
        }
        .to_bytes(),
    )
    .unwrap();
    let mut manifest = ExportMetadata::new("15.28.2");
    manifest.set(
        Product::Firestore,
        Section {
            version: "1.22.0".to_owned(),
            path: FIRESTORE_PATH.to_owned(),
            metadata_file: Some(format!("{FIRESTORE_PATH}/{FIRESTORE_OVERALL_METADATA}")),
        },
    );
    std::fs::write(root.join(METADATA_FILE_NAME), manifest.to_json()).unwrap();
    artifact_bytes
}

#[cfg(all(target_os = "macos", not(debug_assertions)))]
fn timed_import_max_rss(dir: &Path) -> u64 {
    let output = Command::new("/usr/bin/time")
        .env("LC_ALL", "C")
        .arg("-l")
        .arg(env!("CARGO_BIN_EXE_fireemu"))
        .args([
            "exec",
            "--only",
            "firestore",
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
            "--hub-port",
            "0",
            "--log-verbosity",
            "quiet",
            "--project",
            "demo-import-rss",
            "--import",
        ])
        .arg(dir)
        .args(["--", "true"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", text(&output));
    let stderr = String::from_utf8_lossy(&output.stderr);
    let matches: Vec<_> = stderr
        .lines()
        .filter(|line| line.trim_end().ends_with("maximum resident set size"))
        .collect();
    assert_eq!(matches.len(), 1, "{stderr}");
    matches[0]
        .split_whitespace()
        .next()
        .unwrap()
        .parse()
        .unwrap()
}

#[cfg(all(target_os = "macos", not(debug_assertions)))]
fn median_three(mut measure: impl FnMut() -> u64) -> u64 {
    let mut values = [measure(), measure(), measure()];
    values.sort_unstable();
    values[1]
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
            "--logging-port",
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
fn a_firestore_output_truncated_at_a_record_boundary_is_refused() {
    let dir = scratch("short-firestore");
    let export = copy_fixture("official-multiproduct", &dir);
    let output_file = export.join("firestore_export/all_namespaces/all_kinds/output-0");
    std::fs::write(&output_file, []).unwrap();

    let output = exec()
        .args(["--import"])
        .arg(&export)
        .args(["--", "true"])
        .output()
        .unwrap();

    assert_refused(&output, "firestore", "entity count");
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

#[cfg(unix)]
#[test]
fn symlinked_manifest_and_optional_auth_config_are_never_followed() {
    use std::os::unix::fs::symlink;

    for leaf in ["firebase-export-metadata.json", "auth_export/config.json"] {
        let dir = scratch(&format!("symlink-{}", leaf.replace('/', "-")));
        let export = dir.join("export");
        copy_tree(&fixture("official-multiproduct"), &export);
        let link = export.join(leaf);
        let outside = dir.join("outside.json");
        std::fs::copy(&link, &outside).unwrap();
        std::fs::remove_file(&link).unwrap();
        symlink(&outside, &link).unwrap();

        let output = exec()
            .args(["--import"])
            .arg(&export)
            .args(["--", "true"])
            .output()
            .unwrap();
        let log = text(&output);
        assert_eq!(output.status.code(), Some(1), "{leaf}: {log}");
        assert!(log.contains("symlink"), "{leaf}: {log}");
    }
}

#[test]
fn a_missing_optional_auth_config_still_imports_accounts() {
    let dir = scratch("missing-auth-config");
    let export = copy_fixture("official-multiproduct", &dir);
    std::fs::remove_file(export.join("auth_export/config.json")).unwrap();

    let output = exec()
        .args(["--only", "auth", "--import"])
        .arg(&export)
        .args(["--", "true"])
        .output()
        .unwrap();
    let log = text(&output);
    assert!(output.status.success(), "{log}");
    assert!(log.contains("auth: 5 account(s)"), "{log}");
}

/// An artifact that does not declare `enableImprovedEmailPrivacy` leaves the running setting
/// (production's default, on) in place; one that declares it off switches it off.
#[test]
fn an_import_keeps_email_enumeration_protection_unless_the_artifact_declares_it() {
    let probe = r#"curl -s -X POST "http://$FIREBASE_AUTH_EMULATOR_HOST/identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=fake-api-key" -H 'Content-Type: application/json' -d '{"email":"nobody@example.com","password":"hunter22","returnSecureToken":true}'"#;
    for (declared, expected) in [
        (None, "INVALID_LOGIN_CREDENTIALS"),
        (Some(false), "EMAIL_NOT_FOUND"),
        (Some(true), "INVALID_LOGIN_CREDENTIALS"),
    ] {
        let dir = scratch(&format!("auth-config-{declared:?}"));
        let export = copy_fixture("official-multiproduct", &dir);
        let config = match declared {
            None => r#"{"signIn":{"allowDuplicateEmails":false}}"#.to_owned(),
            Some(value) => format!(
                r#"{{"signIn":{{"allowDuplicateEmails":false}},"emailPrivacyConfig":{{"enableImprovedEmailPrivacy":{value}}}}}"#
            ),
        };
        std::fs::write(export.join("auth_export/config.json"), config).unwrap();
        let output = exec()
            .args(["--only", "auth", "--import"])
            .arg(&export)
            .args(["--", "sh", "-c", probe])
            .output()
            .unwrap();
        let log = text(&output);
        assert!(output.status.success(), "{declared:?}: {log}");
        assert!(
            log.contains(expected),
            "{declared:?}: expected {expected} in {log}"
        );
    }
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
fn a_storage_resource_limit_refuses_a_mixed_import_before_the_command_starts() {
    let dir = scratch("storage-import-limit");
    let export = copy_fixture("official-multiproduct", &dir);
    let sparse = export.join("storage_export/blobs/over-budget");
    std::fs::File::create(&sparse)
        .unwrap()
        .set_len(1024 * 1024 * 1024 + 1)
        .unwrap();
    let marker = dir.join("command-ran");

    let output = exec()
        .args(["--import"])
        .arg(&export)
        .args(["--", "sh", "-c"])
        .arg(format!("touch {}", marker.display()))
        .output()
        .unwrap();
    let log = text(&output);
    assert_eq!(output.status.code(), Some(1), "{log}");
    assert!(
        log.contains("1073741824 byte cumulative import limit"),
        "{log}"
    );
    assert!(!log.contains("running: "), "{log}");
    assert!(
        !marker.exists(),
        "the command must not run after preparation fails"
    );
}

#[test]
fn a_sparse_firestore_output_is_refused_before_allocation_or_command_start() {
    let dir = scratch("firestore-import-limit");
    let export = copy_fixture("official-multiproduct", &dir);
    let sparse = export.join("firestore_export/all_namespaces/all_kinds/output-0");
    std::fs::File::options()
        .write(true)
        .open(&sparse)
        .unwrap()
        .set_len(1024 * 1024 * 1024 + 1)
        .unwrap();
    let marker = dir.join("command-ran");

    let output = exec()
        .args(["--import"])
        .arg(&export)
        .args(["--", "sh", "-c"])
        .arg(format!("touch {}", marker.display()))
        .output()
        .unwrap();

    let log = text(&output);
    assert_eq!(output.status.code(), Some(1), "{log}");
    assert!(
        log.contains("output files exceed the 1073741824 byte cumulative import limit"),
        "{log}"
    );
    assert!(!log.contains("running: "), "{log}");
    assert!(!marker.exists());
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
fn tenant_accounts_import_and_export_in_isolated_files() {
    let dir = scratch("tenant-auth-round-trip");
    let source = copy_fixture("official-multiproduct", &dir);
    std::fs::write(
        source.join("auth_export/accounts-customer-a.json"),
        r#"{"kind":"identitytoolkit#DownloadAccountResponse","users":[{"localId":"tenant-user","email":"tenant@example.com","emailVerified":true,"createdAt":"1788105513122"}]}"#,
    )
    .unwrap();
    let out = dir.join("out");
    let output = exec()
        .args(["--import"])
        .arg(&source)
        .arg("--export-on-exit")
        .arg(&out)
        .args(["--", "true"])
        .output()
        .unwrap();
    let log = text(&output);
    assert!(output.status.success(), "{log}");
    assert!(log.contains("auth: 6 account(s) in 1 tenant(s)"), "{log}");
    let tenant = std::fs::read_to_string(out.join("auth_export/accounts-customer-a.json"))
        .expect("the tenant has its own export file");
    let tenant: serde_json::Value = serde_json::from_str(&tenant).unwrap();
    assert_eq!(tenant["users"][0]["localId"], "tenant-user");
    assert_eq!(tenant["users"][0]["tenantId"], "customer-a");
    let default = std::fs::read_to_string(out.join("auth_export/accounts.json")).unwrap();
    assert!(!default.contains("tenant-user"));
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
    let child_pid_path = dir.join("child-pid");
    let supervisor = ChildGuard::new(
        exec()
            .args(["--import"])
            .arg(fixture("official-multiproduct"))
            .arg("--export-on-exit")
            .arg(&out)
            .args(["--", "sh", "-c"])
            .arg(format!(
                "printf '%s' $$ > {}; touch {}; exec sleep 60",
                child_pid_path.display(),
                ready.display()
            ))
            .spawn()
            .unwrap(),
    );
    let started = Instant::now();
    while !ready.exists() && started.elapsed() < Duration::from_secs(60) {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(ready.exists(), "the command started");
    let command_group = std::fs::read_to_string(&child_pid_path)
        .unwrap()
        .parse::<i32>()
        .unwrap();
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
    census::assert_process_group_empty(
        command_group,
        "after the interrupted export",
        Duration::from_secs(10),
    );
}

#[test]
fn the_export_runs_when_the_daemon_is_terminated() {
    let dir = scratch("sigterm");
    let out = dir.join("out");
    let ready = dir.join("ready");
    let child_pid_path = dir.join("child-pid");
    let supervisor = ChildGuard::new(
        exec()
            .args(["--import"])
            .arg(fixture("official-multiproduct"))
            .arg("--export-on-exit")
            .arg(&out)
            .args(["--", "sh", "-c"])
            .arg(format!(
                "printf '%s' $$ > {}; touch {}; exec sleep 60",
                child_pid_path.display(),
                ready.display()
            ))
            .spawn()
            .unwrap(),
    );
    let started = Instant::now();
    while !ready.exists() && started.elapsed() < Duration::from_secs(60) {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(ready.exists(), "the command started");
    let command_group = std::fs::read_to_string(&child_pid_path)
        .unwrap()
        .parse::<i32>()
        .unwrap();
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
    census::assert_process_group_empty(
        command_group,
        "after the terminated export",
        Duration::from_secs(10),
    );
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
    let accounts: serde_json::Value = serde_json::from_str(&after).unwrap();
    let user = accounts["users"]
        .as_array()
        .unwrap()
        .iter()
        .find(|user| user["localId"] == "user-password")
        .unwrap();
    let phone = user["providerUserInfo"]
        .as_array()
        .unwrap()
        .iter()
        .find(|provider| provider["providerId"] == "phone")
        .unwrap();
    assert_eq!(phone["rawId"], "+15555550100");
    assert_eq!(phone["phoneNumber"], "+15555550100");
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
fn replacing_an_export_preserves_unmanaged_regular_entries() {
    let dir = scratch("preserve-unmanaged");
    let out = copy_fixture("official-multiproduct", &dir);
    std::fs::write(out.join("README.txt"), "keep me").unwrap();
    std::fs::create_dir(out.join("notes")).unwrap();
    std::fs::write(out.join("notes/local.txt"), "also keep me").unwrap();

    let output = exec()
        .args(["--import"])
        .arg(fixture("official-multiproduct"))
        .arg("--export-on-exit")
        .arg(&out)
        .args(["--", "true"])
        .output()
        .unwrap();
    let log = text(&output);
    assert!(output.status.success(), "{log}");
    assert_eq!(
        std::fs::read_to_string(out.join("README.txt")).unwrap(),
        "keep me"
    );
    assert_eq!(
        std::fs::read_to_string(out.join("notes/local.txt")).unwrap(),
        "also keep me"
    );
}

#[test]
fn an_over_budget_unmanaged_entry_leaves_the_existing_export_unchanged() {
    let dir = scratch("over-budget-unmanaged");
    let out = copy_fixture("official-multiproduct", &dir);
    let manifest = out.join("firebase-export-metadata.json");
    let original_manifest = std::fs::read(&manifest).unwrap();
    let sparse = out.join("large-local-note");
    std::fs::File::create(&sparse)
        .unwrap()
        .set_len(1024 * 1024 * 1024 + 1)
        .unwrap();

    let output = exec()
        .args(["--import"])
        .arg(fixture("official-multiproduct"))
        .arg("--export-on-exit")
        .arg(&out)
        .args(["--", "true"])
        .output()
        .unwrap();

    let log = text(&output);
    assert!(
        output.status.success(),
        "the command's exit code is preserved: {log}"
    );
    assert!(
        log.contains("1073741824 byte cumulative copy limit"),
        "{log}"
    );
    assert_eq!(std::fs::read(&manifest).unwrap(), original_manifest);
    assert_eq!(
        std::fs::metadata(&sparse).unwrap().len(),
        1024 * 1024 * 1024 + 1
    );
}

#[cfg(unix)]
#[test]
fn a_failed_staged_export_leaves_the_existing_export_unchanged() {
    use std::os::unix::fs::symlink;

    let dir = scratch("failed-stage");
    let out = copy_fixture("official-multiproduct", &dir);
    let manifest = out.join("firebase-export-metadata.json");
    let original_manifest = std::fs::read(&manifest).unwrap();
    let outside = dir.join("outside.txt");
    std::fs::write(&outside, "outside").unwrap();
    symlink(&outside, out.join("unmanaged-link")).unwrap();

    let output = exec()
        .args(["--import"])
        .arg(fixture("official-multiproduct"))
        .arg("--export-on-exit")
        .arg(&out)
        .args(["--", "true"])
        .output()
        .unwrap();
    let log = text(&output);
    assert!(
        output.status.success(),
        "the command's exit code is preserved: {log}"
    );
    assert!(log.contains("not a regular file or directory"), "{log}");
    assert_eq!(std::fs::read(&manifest).unwrap(), original_manifest);
    assert_eq!(std::fs::read_to_string(&outside).unwrap(), "outside");
    assert!(std::fs::symlink_metadata(out.join("unmanaged-link"))
        .unwrap()
        .file_type()
        .is_symlink());
    let stage_prefix = format!(
        ".{}.fireemu-stage-",
        out.file_name().unwrap().to_string_lossy()
    );
    assert!(
        std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .all(|entry| !entry
                .file_name()
                .to_string_lossy()
                .starts_with(&stage_prefix)),
        "a failed export must remove its private stage"
    );
}

#[cfg(unix)]
#[test]
fn a_hard_linked_unmanaged_file_leaves_the_existing_export_unchanged() {
    let dir = scratch("hard-linked-unmanaged");
    let out = copy_fixture("official-multiproduct", &dir);
    let manifest = out.join("firebase-export-metadata.json");
    let original_manifest = std::fs::read(&manifest).unwrap();
    let outside = dir.join("outside.txt");
    std::fs::write(&outside, "outside").unwrap();
    std::fs::hard_link(&outside, out.join("unmanaged-hard-link")).unwrap();

    let output = exec()
        .args(["--import"])
        .arg(fixture("official-multiproduct"))
        .arg("--export-on-exit")
        .arg(&out)
        .args(["--", "true"])
        .output()
        .unwrap();
    let log = text(&output);

    assert!(
        output.status.success(),
        "the command's exit code is preserved: {log}"
    );
    assert!(log.contains("multiple hard links"), "{log}");
    assert_eq!(std::fs::read(&manifest).unwrap(), original_manifest);
    assert_eq!(std::fs::read_to_string(&outside).unwrap(), "outside");
    assert_eq!(
        std::fs::read_to_string(out.join("unmanaged-hard-link")).unwrap(),
        "outside"
    );
}

#[cfg(unix)]
#[test]
fn a_symlinked_export_root_is_refused_without_touching_its_target() {
    use std::os::unix::fs::symlink;

    let dir = scratch("symlink-export-root");
    let target = dir.join("target");
    std::fs::create_dir_all(&target).unwrap();
    std::fs::write(target.join("marker.txt"), "unchanged").unwrap();
    let out = dir.join("out");
    symlink(&target, &out).unwrap();

    let output = exec()
        .args(["--export-on-exit"])
        .arg(&out)
        .args(["--", "true"])
        .output()
        .unwrap();
    let log = text(&output);
    assert_eq!(output.status.code(), Some(1), "{log}");
    assert!(log.contains("symlink"), "{log}");
    assert_eq!(
        std::fs::read_to_string(target.join("marker.txt")).unwrap(),
        "unchanged"
    );
    assert_eq!(std::fs::read_dir(&target).unwrap().count(), 1);
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
    let hub_port_text = hub_port.to_string();
    let project = format!("demo-export-hub-{}", std::process::id());
    let locator = std::env::temp_dir().join(format!("hub-{project}.json"));
    let supervisor = ChildGuard::new(
        Command::new(env!("CARGO_BIN_EXE_fireemu"))
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
                project.as_str(),
                "--hub-port",
                hub_port_text.as_str(),
                "--import",
            ])
            .arg(fixture("official-multiproduct"))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    // Binding the Hub socket happens before import and locator publication. Wait for the
    // locator that proves this exact daemon has completed startup instead of only connecting.
    let started = Instant::now();
    let mut locator_ready = false;
    while started.elapsed() < Duration::from_secs(60) {
        locator_ready = std::fs::read_to_string(&locator)
            .ok()
            .and_then(|text| serde_json::from_str::<serde_json::Value>(&text).ok())
            .is_some_and(|document| {
                document["pid"].as_u64() == Some(u64::from(supervisor.id()))
                    && document["origins"][0].as_str()
                        == Some(format!("http://127.0.0.1:{hub_port}").as_str())
            });
        if locator_ready {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(locator_ready, "the exact Hub locator was published");

    let export = Command::new(env!("CARGO_BIN_EXE_fireemu"))
        .args(["emulators:export"])
        .arg(&out)
        .args(["--project", project.as_str()])
        .output()
        .unwrap();
    let log = text(&export);
    assert!(export.status.success(), "{log}");
    assert!(log.contains(&format!("exported {project}")), "{log}");
    assert!(out.join("firebase-export-metadata.json").is_file(), "{log}");
    assert!(out.join("auth_export/accounts.json").is_file(), "{log}");

    supervisor.terminate_and_wait();
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

#[cfg(all(target_os = "macos", not(debug_assertions)))]
#[test]
#[ignore = "release-only RSS qualification; writes and imports about 192 MiB three times"]
fn document_only_import_peak_rss_is_within_one_point_two_times_the_artifact() {
    let root = scratch("import-rss");
    let empty = root.join("empty");
    let loaded = root.join("loaded");
    let _ = write_document_artifact(&empty, 0, 0);
    let artifact_bytes = write_document_artifact(&loaded, 256, 768 * 1024);
    assert!(artifact_bytes >= 192 * 1024 * 1024);

    let baseline = median_three(|| timed_import_max_rss(&empty));
    let loaded_rss = median_three(|| timed_import_max_rss(&loaded));
    let incremental = loaded_rss
        .checked_sub(baseline)
        .expect("the payload import must exceed the empty baseline");
    eprintln!(
        "import RSS baseline={baseline}, loaded={loaded_rss}, incremental={incremental}, artifact={artifact_bytes}"
    );

    assert!(
        u128::from(incremental) * 10 <= u128::from(artifact_bytes) * 12,
        "baseline={baseline}, loaded={loaded_rss}, incremental={incremental}, artifact={artifact_bytes}"
    );
}
