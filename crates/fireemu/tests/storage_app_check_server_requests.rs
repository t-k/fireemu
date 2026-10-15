//! `appCheck.storageServerRequests` reaches the daemon's Storage emulator through `fireemu
//! exec` (owner ledger 1431): under Storage App Check `enforced`, the default `loopback` admits
//! a credential-less Cloud Storage JSON API request from the child process, `capability` admits
//! only the credentialed `STORAGE_EMULATOR_HOST` the child inherits, and in both a browser-shaped
//! request or the Firebase Storage API still needs a token.

#![cfg(unix)]

use std::process::{Command, Stdio};

const BUCKET: &str = "demo-exec.appspot.com";

/// The status code of each probe, one `<label> <code>` line each.
fn run(name: &str, server_requests: Option<&str>) -> String {
    let dir = std::env::temp_dir().join(format!(
        "fireemu-storage-server-requests-{name}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let config = dir.join("fireemu.json");
    let setting = server_requests.map_or_else(String::new, |value| {
        format!(r#""storageServerRequests": "{value}","#)
    });
    std::fs::write(
        &config,
        format!(
            r#"{{"schemaVersion": 1, "profile": "strict", "firestore": {{"edition": "standard", "apiMode": "native"}}, "appCheck": {{"enabled": true, {setting} "apps": [{{"projectId": "demo-exec", "projectNumber": "1234567890", "appId": "1:1234567890:web:local-test-app"}}], "services": {{"storage": "enforced"}}}}}}"#
        ),
    )
    .unwrap();
    let probe = format!(
        r#"list="/storage/v1/b/{BUCKET}/o"
code() {{ curl -s -o /dev/null -w "$1 %{{http_code}}\n" "${{@:2}}"; }}
code plain "http://$FIREBASE_STORAGE_EMULATOR_HOST$list"
code origin -H 'Origin: http://localhost:5173' "http://$FIREBASE_STORAGE_EMULATOR_HOST$list"
code fetch-metadata -H 'Sec-Fetch-Site: same-origin' "http://$FIREBASE_STORAGE_EMULATOR_HOST$list"
code firebase-api "http://$FIREBASE_STORAGE_EMULATOR_HOST/v0/b/{BUCKET}/o"
code exported-endpoint "$STORAGE_EMULATOR_HOST$list"
if [[ "$STORAGE_EMULATOR_HOST" == *@* ]]; then echo endpoint-has-userinfo yes; else echo endpoint-has-userinfo no; fi
"#
    );
    let output = Command::new(env!("CARGO_BIN_EXE_fireemu"))
        .args(["exec", "--config"])
        .arg(&config)
        .args([
            "--only",
            "storage",
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
            "demo-exec",
            "--",
            "/bin/bash",
            "-c",
            &probe,
        ])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    let log = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.status.success(), "{log}");
    log
}

#[test]
fn loopback_admits_the_credential_less_json_api_request_and_nothing_browser_shaped() {
    for (name, setting) in [("default", None), ("explicit", Some("loopback"))] {
        let log = run(name, setting);
        assert!(log.contains("plain 200"), "{name}: {log}");
        assert!(log.contains("origin 403"), "{name}: {log}");
        assert!(log.contains("fetch-metadata 403"), "{name}: {log}");
        assert!(log.contains("firebase-api 403"), "{name}: {log}");
        assert!(log.contains("exported-endpoint 200"), "{name}: {log}");
        assert!(log.contains("endpoint-has-userinfo no"), "{name}: {log}");
    }
}

#[test]
fn capability_admits_only_the_exported_credentialed_endpoint() {
    let log = run("capability", Some("capability"));
    assert!(log.contains("plain 403"), "{log}");
    assert!(log.contains("origin 403"), "{log}");
    assert!(log.contains("fetch-metadata 403"), "{log}");
    assert!(log.contains("firebase-api 403"), "{log}");
    assert!(log.contains("exported-endpoint 200"), "{log}");
    assert!(log.contains("endpoint-has-userinfo yes"), "{log}");
}
