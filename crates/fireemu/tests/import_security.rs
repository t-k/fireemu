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

fn storage_export_with_identity(
    name: &str,
    generation: i64,
    metageneration: i64,
) -> std::path::PathBuf {
    let dir = scratch(name);
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
        format!(
            r#"{{"name":"obj","bucket":"demo-app.appspot.com","generation":{generation},"metageneration":{metageneration},"size":1,"contentType":"text/plain"}}"#
        ),
    )
    .unwrap();
    std::fs::write(export.join("storage_export/blobs/obj"), b"x").unwrap();
    export
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

#[test]
fn zero_or_negative_storage_identity_is_refused_instead_of_becoming_generation_one() {
    for (name, generation, metageneration, field) in [
        ("zero-generation", 0, 1, "generation"),
        ("negative-metageneration", 1, -1, "metageneration"),
    ] {
        let export = storage_export_with_identity(name, generation, metageneration);
        let output = import(&export);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(1), "{stderr}");
        assert!(stderr.contains(field), "{stderr}");
        assert!(stderr.contains("at least 1"), "{stderr}");
        let _ = std::fs::remove_dir_all(export.parent().unwrap());
    }
}

#[test]
fn duplicate_storage_object_identities_are_refused_instead_of_replacing_bytes() {
    let export = storage_export_with_identity("duplicate-identity", 7, 1);
    std::fs::write(
        export.join("storage_export/metadata/duplicate.json"),
        r#"{"name":"obj","bucket":"demo-app.appspot.com","generation":7,"metageneration":1,"size":1,"contentType":"text/plain"}"#,
    )
    .unwrap();
    std::fs::write(export.join("storage_export/blobs/duplicate"), b"y").unwrap();

    let output = import(&export);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "{stderr}");
    assert!(stderr.contains("duplicate storage object"), "{stderr}");
    let _ = std::fs::remove_dir_all(export.parent().unwrap());
}

/// SIMP-1: object metadata from an artifact reaches response headers, re-export and the
/// Rules `resource`, so the import boundary refuses the control characters an upload
/// refuses. The refusal names the field and never echoes the value.
#[test]
fn storage_metadata_with_control_characters_is_refused_naming_the_field_only() {
    const BASE: &str = r#""name":"obj","bucket":"demo-app.appspot.com","generation":1,"metageneration":1,"size":1"#;
    let crlf = "\\r\\n";
    let nul = "\\u0000";
    // C1 (U+0080..U+009F): a control character that is multi-byte in UTF-8, so a byte-wise
    // test would miss it while the value still reaches a response header and a log line.
    let c1 = "\\u0085";
    for (label, tail, field) in [
        (
            "content-type-crlf",
            format!(r#""contentType":"text/plain{crlf}X-Injected: marker-secret""#),
            "contentType",
        ),
        (
            "cache-control-nul",
            format!(r#""contentType":"text/plain","cacheControl":"public{nul}marker-secret""#),
            "cacheControl",
        ),
        (
            "custom-key-nul",
            format!(r#""contentType":"text/plain","customMetadata":{{"k{nul}marker-secret":"v"}}"#),
            "metadata key",
        ),
        (
            "custom-value-crlf",
            format!(
                r#""contentType":"text/plain","customMetadata":{{"k":"v{crlf}marker-secret"}}"#
            ),
            "metadata",
        ),
        (
            "download-token-nul",
            format!(r#""contentType":"text/plain","downloadTokens":["tok{nul}marker-secret"]"#),
            "downloadTokens",
        ),
        (
            "content-type-c1",
            format!(r#""contentType":"text/plain{c1}marker-secret""#),
            "contentType",
        ),
    ] {
        let dir = scratch(label);
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
            format!("{{{BASE},{tail}}}"),
        )
        .unwrap();
        std::fs::write(export.join("storage_export/blobs/obj"), b"x").unwrap();

        let output = import(&export);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(1), "{label}: {stderr}");
        assert!(stderr.contains(field), "{label}: {stderr}");
        assert!(stderr.contains("control character"), "{label}: {stderr}");
        assert!(
            !stderr.contains("marker-secret"),
            "{label}: the refusal must not echo the value: {stderr}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// The Auth half of the same input boundary: an account from an artifact carries strings that
/// are rendered into responses, logs and a re-export, so the fields the store checks for
/// control characters (local id, email, display name, photo URL, phone number) must be checked
/// on the fields it does not see either -- federated identities and enrolled second factors.
/// The refusal names the field and never echoes the value.
#[test]
fn auth_metadata_with_control_characters_is_refused_naming_the_field_only() {
    let crlf = "\\r\\n";
    let nul = "\\u0000";
    // C1 (U+0080..U+009F): a control character that is multi-byte in UTF-8.
    let c1 = "\\u0085";
    for (label, account, field) in [
        (
            "federated-display-name",
            format!(
                r#"{{"localId":"u","providerUserInfo":[{{"providerId":"google.com","rawId":"g-1","displayName":"Carol{crlf}marker-secret"}}]}}"#
            ),
            "providerUserInfo.displayName",
        ),
        (
            "federated-raw-id",
            format!(
                r#"{{"localId":"u","providerUserInfo":[{{"providerId":"google.com","rawId":"g{nul}marker-secret"}}]}}"#
            ),
            "providerUserInfo.rawId",
        ),
        (
            "federated-provider-id",
            format!(
                r#"{{"localId":"u","providerUserInfo":[{{"providerId":"google{nul}marker-secret","rawId":"g-1"}}]}}"#
            ),
            "providerUserInfo.providerId",
        ),
        (
            "federated-email",
            format!(
                r#"{{"localId":"u","providerUserInfo":[{{"providerId":"google.com","rawId":"g-1","email":"c@example.com{crlf}marker-secret"}}]}}"#
            ),
            "providerUserInfo.email",
        ),
        (
            "federated-photo-url",
            format!(
                r#"{{"localId":"u","providerUserInfo":[{{"providerId":"google.com","rawId":"g-1","photoUrl":"http://x/{nul}marker-secret"}}]}}"#
            ),
            "providerUserInfo.photoUrl",
        ),
        (
            "phone-factor-number",
            format!(
                r#"{{"localId":"u","mfaInfo":[{{"mfaEnrollmentId":"f1","phoneInfo":"+15551234567{nul}marker-secret"}}]}}"#
            ),
            "mfaInfo.phoneInfo",
        ),
        (
            "phone-factor-display-name",
            format!(
                r#"{{"localId":"u","mfaInfo":[{{"mfaEnrollmentId":"f1","phoneInfo":"+15551234567","displayName":"phone{crlf}marker-secret"}}]}}"#
            ),
            "mfaInfo.displayName",
        ),
        (
            "enrollment-id",
            format!(
                r#"{{"localId":"u","mfaInfo":[{{"mfaEnrollmentId":"f{nul}marker-secret","phoneInfo":"+15551234567"}}]}}"#
            ),
            "mfaInfo.mfaEnrollmentId",
        ),
        (
            "federated-display-name-c1",
            format!(
                r#"{{"localId":"u","providerUserInfo":[{{"providerId":"google.com","rawId":"g-1","displayName":"Carol{c1}marker-secret"}}]}}"#
            ),
            "providerUserInfo.displayName",
        ),
    ] {
        let dir = scratch(label);
        let export = dir.join("export");
        std::fs::create_dir_all(export.join("auth_export")).unwrap();
        std::fs::write(
            export.join("firebase-export-metadata.json"),
            r#"{"version":"15.28.2","auth":{"version":"15.28.2","path":"auth_export"}}"#,
        )
        .unwrap();
        std::fs::write(
            export.join("auth_export/config.json"),
            r#"{"signIn":{"allowDuplicateEmails":false},"emailPrivacyConfig":{"enableImprovedEmailPrivacy":false}}"#,
        )
        .unwrap();
        std::fs::write(
            export.join("auth_export/accounts.json"),
            format!(r#"{{"kind":"identitytoolkit#DownloadAccountResponse","users":[{account}]}}"#),
        )
        .unwrap();

        let output = import(&export);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(1), "{label}: {stderr}");
        assert!(stderr.contains(field), "{label}: {stderr}");
        assert!(stderr.contains("control character"), "{label}: {stderr}");
        assert!(
            !stderr.contains("marker-secret"),
            "{label}: the refusal must not echo the value: {stderr}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
