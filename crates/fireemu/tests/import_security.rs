//! A crafted export must never make an import read outside its directory.

use std::path::Path;
use std::process::{Command, Stdio};

fn scratch(name: &str) -> std::path::PathBuf {
    let dir =
        std::env::temp_dir().join(format!("fireemu-import-sec-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn import(dir: &Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_fireemu"))
        .args([
            "exec",
            "--project",
            "demo-app",
            "--firestore-port",
            "0",
            "--http-port",
            "0",
            "--storage-port",
            "0",
            "--hub-port",
            "0",
            "--logging-port",
            "0",
            "--ui-port",
            "0",
            "--import",
        ])
        .arg(dir)
        .args(["--", "true"])
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

#[cfg(unix)]
#[test]
fn a_storage_blob_that_is_a_symlink_is_refused_without_reading_its_target() {
    let dir = scratch("symlink");
    let secret = dir.join("secret-outside.txt");
    std::fs::write(&secret, b"private key material").unwrap();
    let export = dir.join("export");
    std::fs::create_dir_all(export.join("storage_export/blobs")).unwrap();
    std::fs::create_dir_all(export.join("storage_export/metadata")).unwrap();
    std::fs::write(
        export.join("firebase-export-metadata.json"),
        r#"{"version":"15.28.2","storage":{"version":"15.28.2","path":"storage_export"}}"#,
    )
    .unwrap();
    std::fs::write(
        export.join("storage_export/buckets.json"),
        r#"{"buckets":[{"id":"demo-app.appspot.com"}]}"#,
    )
    .unwrap();
    std::fs::write(
        export.join("storage_export/metadata/leak.json"),
        format!(
            r#"{{"name":"leak","bucket":"demo-app.appspot.com","generation":1,"metageneration":1,"size":{},"contentType":"text/plain"}}"#,
            b"private key material".len()
        ),
    )
    .unwrap();
    std::os::unix::fs::symlink(&secret, export.join("storage_export/blobs/leak")).unwrap();
    let output = import(&export);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "{stderr}");
    assert!(stderr.contains("symlink"), "{stderr}");
    assert!(!stderr.contains("private key"), "{stderr}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_blob_whose_size_disagrees_with_its_metadata_is_refused_without_naming_the_real_size() {
    let dir = scratch("size");
    let export = dir.join("export");
    std::fs::create_dir_all(export.join("storage_export/blobs")).unwrap();
    std::fs::create_dir_all(export.join("storage_export/metadata")).unwrap();
    std::fs::write(
        export.join("firebase-export-metadata.json"),
        r#"{"version":"15.28.2","storage":{"version":"15.28.2","path":"storage_export"}}"#,
    )
    .unwrap();
    std::fs::write(
        export.join("storage_export/buckets.json"),
        r#"{"buckets":[{"id":"demo-app.appspot.com"}]}"#,
    )
    .unwrap();
    std::fs::write(
        export.join("storage_export/metadata/obj.json"),
        r#"{"name":"obj","bucket":"demo-app.appspot.com","generation":1,"metageneration":1,"size":1,"contentType":"text/plain"}"#,
    )
    .unwrap();
    std::fs::write(
        export.join("storage_export/blobs/obj"),
        b"four hundred eleven bytes? no, fewer",
    )
    .unwrap();
    let output = import(&export);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "{stderr}");
    assert!(stderr.contains("does not have the size"), "{stderr}");
    assert!(
        !stderr.contains(" 36 "),
        "the real size must not be reported: {stderr}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
