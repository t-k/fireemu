//! `storage.maxStoredBytes` in the canonical configuration reaches the daemon's Storage
//! emulator: a write past it answers 402 (owner ledgers 759 and 788), and without it nothing is bounded.

#![cfg(unix)]

use std::process::{Command, Stdio};

fn run(name: &str, storage: &str) -> String {
    let dir = std::env::temp_dir().join(format!(
        "fireemu-storage-limits-{name}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let config = dir.join("fireemu.json");
    std::fs::write(
        &config,
        format!(
            r#"{{"schemaVersion": 1, "profile": "emulator", "firestore": {{"edition": "standard", "apiMode": "native"}}, "storage": {{{storage}}}}}"#
        ),
    )
    .unwrap();
    // Two 6-byte objects against a 10-byte bound: the second is refused.
    let probe = r#"for object in a b; do
curl -s -o /dev/null -w "$object %{http_code}\n" -X POST -H 'Authorization: Bearer owner' --data-binary '123456' "http://$FIREBASE_STORAGE_EMULATOR_HOST/v0/b/demo-storage-limits.appspot.com/o?name=$object"
done"#;
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
            "demo-storage-limits",
            "--",
            "/bin/sh",
            "-c",
            probe,
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
fn a_configured_stored_byte_limit_refuses_the_write_that_crosses_it() {
    let log = run("bounded", r#""maxStoredBytes": 10"#);
    assert!(log.contains("a 200"), "{log}");
    assert!(log.contains("b 402"), "{log}");

    let log = run("unbounded", "");
    assert!(log.contains("a 200"), "{log}");
    assert!(log.contains("b 200"), "{log}");
}
