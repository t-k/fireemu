//! Process-boundary coverage for the Auth session RSA cache.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

fn scratch(name: &str) -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let sequence = NEXT.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "fireemu-session-rsa-process-{name}-{}-{sequence}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir(&root).unwrap();
    root
}

fn cache_base(root: &Path) -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        let base = root.join("home/Library/Caches");
        std::fs::create_dir_all(&base).unwrap();
        base
    }
    #[cfg(not(target_os = "macos"))]
    {
        let base = root.join("cache");
        std::fs::create_dir_all(&base).unwrap();
        base
    }
}

fn command(root: &Path, config: &Path, only: &str) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_fireemu"));
    command
        .args([
            "exec",
            "--config",
            config.to_str().unwrap(),
            "--only",
            only,
            "--firestore-port",
            "0",
            "--http-port",
            "0",
            "--storage-port",
            "0",
            "--functions-port",
            "0",
            "--pubsub-port",
            "0",
            "--ui-port",
            "0",
            "--hub-port",
            "0",
            "--logging-port",
            "0",
            "--",
            "true",
        ])
        .env("HOME", root.join("home"))
        .env_remove("XDG_CACHE_HOME")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(not(target_os = "macos"))]
    command.env("XDG_CACHE_HOME", root.join("cache"));
    command
}

fn run(root: &Path, config: &Path, only: &str) -> Output {
    command(root, config, only).output().unwrap()
}

fn output_text(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn kid_after<'a>(text: &'a str, prefix: &str) -> &'a str {
    let suffix = text
        .split_once(prefix)
        .unwrap_or_else(|| panic!("missing {prefix}: {text}"));
    suffix
        .1
        .split(|character: char| character == ')' || character.is_whitespace())
        .next()
        .filter(|kid| !kid.is_empty())
        .unwrap_or_else(|| panic!("missing key id after {prefix}: {text}"))
}

fn write_config(root: &Path, app_check: bool) -> PathBuf {
    let app_check = if app_check {
        r#",
  "appCheck": {
    "enabled": true,
    "tokenSigning": "instance-rsa",
    "apps": [{
      "projectId": "demo-session-rsa-cache",
      "projectNumber": "1234567890",
      "appId": "1:1234567890:web:session-rsa-cache",
      "debugTokenSha256": []
    }]
  }"#
    } else {
        ""
    };
    let config = root.join("fireemu.json");
    std::fs::write(
        &config,
        format!(
            r#"{{
  "schemaVersion": 1,
  "daemon": {{"seed": 246813579, "authProject": "demo-session-rsa-cache"}},
  "auth": {{"idTokenSigning": "session-rsa"}}{app_check}
}}
"#
        ),
    )
    .unwrap();
    config
}

fn cache_entries(base: &Path) -> Vec<std::fs::DirEntry> {
    let directory = base.join("fireemu/session-rsa/v1");
    std::fs::read_dir(directory)
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
}

#[test]
fn concurrent_processes_publish_one_complete_entry_and_later_processes_reuse_it() {
    use std::os::unix::fs::PermissionsExt as _;

    let root = scratch("concurrent");
    let base = cache_base(&root);
    let config = write_config(&root, false);
    let children = (0..4)
        .map(|_| command(&root, &config, "auth").spawn().unwrap())
        .collect::<Vec<_>>();
    let outputs = children
        .into_iter()
        .map(|child| child.wait_with_output().unwrap())
        .collect::<Vec<_>>();
    for output in &outputs {
        assert!(output.status.success(), "{}", output_text(output));
    }
    let kids = outputs
        .iter()
        .map(|output| kid_after(&output_text(output), "RS256 (kid ").to_owned())
        .collect::<Vec<_>>();
    assert!(kids.windows(2).all(|pair| pair[0] == pair[1]));

    let entries = cache_entries(&base);
    assert_eq!(entries.len(), 1);
    let entry = entries[0].path();
    let before = std::fs::read(&entry).unwrap();
    let before_metadata = std::fs::metadata(&entry).unwrap();
    assert!(before_metadata.file_type().is_file());
    assert_eq!(before_metadata.permissions().mode() & 0o7777, 0o600);

    let next = run(&root, &config, "auth");
    assert!(next.status.success(), "{}", output_text(&next));
    assert_eq!(kid_after(&output_text(&next), "RS256 (kid "), kids[0]);
    assert_eq!(std::fs::read(&entry).unwrap(), before);
    assert_eq!(
        std::fs::metadata(&entry).unwrap().len(),
        before_metadata.len()
    );
    assert_eq!(cache_entries(&base).len(), 1);

    for service in ["firestore", "storage"] {
        let output = run(&root, &config, service);
        assert!(
            output.status.success(),
            "{service}: {}",
            output_text(&output)
        );
        assert_eq!(
            kid_after(&output_text(&output), "RS256 (kid "),
            kids[0],
            "{service} must install the configured Auth signer for token verification"
        );
    }

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn app_check_keys_remain_per_process_and_app_check_only_never_creates_an_auth_cache() {
    let root = scratch("key-separation");
    let base = cache_base(&root);
    let config = write_config(&root, true);
    let first = run(&root, &config, "auth,appcheck");
    let second = run(&root, &config, "auth,appcheck");
    assert!(first.status.success(), "{}", output_text(&first));
    assert!(second.status.success(), "{}", output_text(&second));
    let first_text = output_text(&first);
    let second_text = output_text(&second);
    assert_eq!(
        kid_after(&first_text, "RS256 (kid "),
        kid_after(&second_text, "RS256 (kid ")
    );
    assert_ne!(
        kid_after(&first_text, "/v1/jwks (kid "),
        kid_after(&second_text, "/v1/jwks (kid ")
    );
    assert_eq!(cache_entries(&base).len(), 1);

    let app_check_root = scratch("app-check-only");
    let app_check_base = cache_base(&app_check_root);
    let app_check_config = write_config(&app_check_root, true);
    let output = run(&app_check_root, &app_check_config, "appcheck");
    assert!(output.status.success(), "{}", output_text(&output));
    assert!(!app_check_base.join("fireemu").exists());

    let _ = std::fs::remove_dir_all(root);
    let _ = std::fs::remove_dir_all(app_check_root);
}
