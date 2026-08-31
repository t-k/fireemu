//! Discovery parity (FN-01): what the daemon does with an export it cannot serve.
//!
//! The pinned official emulator never drops one in silence and never fails on one: an
//! unsupported trigger service is logged (`Unsupported trigger: <json>`, DEBUG) and an
//! unrecognised shape is logged (`Unsupported function type on <name>. Expected either an
//! httpsTrigger, eventTrigger, or blockingTrigger.`, WARN), and in both cases the definition
//! stays in the inventory with `ignored: true` and prints
//! `functions[<region>-<name>]: function ignored because the <service> emulator does not
//! exist or is not running.` (firebase-tools 15.28.2 `lib/emulator/functionsEmulator.js:488`,
//! `:497`, `:501`).
//!
//! fireemu keeps the inventory and names every ignored export the same way, and parts company
//! on one point it publishes: a trigger family that belongs to a product fireemu does not
//! serve at all fails discovery by default, because carrying on would let a project believe a
//! handler runs that never can. `functions.unservedTriggers = "report"` asks for the official
//! carry-on instead.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

/// The fixture codebases live beside the smoke's functions project so that Node resolves
/// `firebase-functions` through `tools/sdk-smoke/node_modules`.
fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tools/sdk-smoke/functions-project/fixtures")
        .join(name)
}

/// Whether the smoke's `node_modules` is installed; without it there is no codebase to load
/// and the scenario has nothing to say.
fn have_sdk() -> bool {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tools/sdk-smoke/node_modules/firebase-functions")
        .exists()
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("fireemu-fn-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn exec(source: &Path, config: Option<&Path>) -> Output {
    let mut args: Vec<String> = vec!["exec".into()];
    for a in [
        "--firestore-port",
        "0",
        "--http-port",
        "0",
        "--storage-port",
        "0",
        "--functions-port",
        "0",
        "--logging-port",
        "0",
        "--ui-port",
        "0",
        "--hub-port",
        "0",
    ] {
        args.push(a.into());
    }
    if let Some(config) = config {
        args.push("--config".into());
        args.push(config.display().to_string());
    }
    args.push("--functions".into());
    args.push(source.display().to_string());
    args.push("--".into());
    args.push("true".into());
    Command::new(env!("CARGO_BIN_EXE_fireemu"))
        .args(&args)
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// Functions scenario 5: an export whose product fireemu does not serve is named, not
/// dropped -- and by default it stops the run rather than pretending the trigger is live.
#[test]
fn a_trigger_of_a_product_the_daemon_does_not_serve_fails_discovery_by_name() {
    if !have_sdk() {
        return;
    }
    let out = exec(&fixture("unserved-triggers"), None);
    let err = stderr(&out);
    assert_eq!(out.status.code(), Some(1), "{err}");
    for name in ["fxOnValueWritten", "fxV1DatabaseWrite", "fxOnConfigUpdated"] {
        assert!(err.contains(name), "{name} is not named:\n{err}");
    }
    assert!(
        err.contains("the Realtime Database emulator is not in the active supported surface"),
        "{err}"
    );
    assert!(
        err.contains("Remote Config has no emulator in the active supported surface"),
        "{err}"
    );
    // The served export is not the reason the run failed, and is not named as unserved.
    assert!(!err.contains("fxHealth ("), "{err}");
}

/// `functions.unservedTriggers = "report"` is the official emulator's carry-on: every ignored
/// export gets a line naming it and the rest of the codebase runs.
#[test]
fn the_report_policy_names_every_ignored_export_and_serves_the_rest() {
    if !have_sdk() {
        return;
    }
    let dir = scratch("report");
    let config = dir.join("fireemu.json");
    std::fs::write(
        &config,
        r#"{"schemaVersion": 1, "functions": {"unservedTriggers": "report"}}"#,
    )
    .unwrap();
    let out = exec(&fixture("unserved-triggers"), Some(&config));
    let err = stderr(&out);
    assert_eq!(out.status.code(), Some(0), "{err}");
    for name in ["fxOnValueWritten", "fxV1DatabaseWrite", "fxOnConfigUpdated"] {
        assert!(
            err.contains(&format!("functions[us-central1-{name}]: function ignored")),
            "{name} has no ignored line:\n{err}"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// An export whose describing throws -- the shape the v1 SDK's lazily-computed endpoints can
/// take -- is one malformed function, not a dead runner.
#[test]
fn an_export_that_cannot_describe_itself_is_reported_rather_than_killing_the_runner() {
    if !have_sdk() {
        return;
    }
    let dir = scratch("malformed");
    let config = dir.join("fireemu.json");
    std::fs::write(
        &config,
        r#"{"schemaVersion": 1, "functions": {"unservedTriggers": "report"}}"#,
    )
    .unwrap();
    let out = exec(&fixture("malformed-export"), Some(&config));
    let err = stderr(&out);
    assert_eq!(out.status.code(), Some(0), "{err}");
    assert!(
        err.contains("functions[us-central1-fxThrows]: function ignored"),
        "{err}"
    );
    assert!(err.contains("could not be described"), "{err}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// beforeUserCreated and beforeUserSignedIn are served synchronous triggers, not ignored
/// inventory entries.
#[test]
fn blocking_identity_exports_are_discovered_as_served_triggers() {
    if !have_sdk() {
        return;
    }
    let out = exec(&fixture("blocking-auth"), None);
    let err = stderr(&out);
    assert_eq!(out.status.code(), Some(0), "{err}");
    assert!(!err.contains("function ignored"), "{err}");
    assert!(!err.contains("blocking identity event"), "{err}");
}
