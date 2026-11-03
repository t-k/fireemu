//! Python Functions codebases through the real daemon, the real Python runner and the real
//! `firebase-functions` SDK (the hash-locked fixture `tools/sdk-smoke-functions-python`).
//!
//! These tests need the fixture's virtual environment (`README.md` there); CI creates it and runs
//! them with `--ignored`, so a missing environment is a failure there and not a skip.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::Duration;

use fireemu_adapter_functions::manifest_json::parse_manifest;
use fireemu_adapter_functions::runner::{InvokeOutcome, Runner, SpawnSpec};

fn fixture() -> PathBuf {
    std::fs::canonicalize(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tools/sdk-smoke-functions-python"),
    )
    .unwrap()
}

fn interpreter() -> PathBuf {
    fixture().join("venv/bin/python")
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("fireemu-py-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn runner_script() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tools/runner-python/runner.py")
}

/// `firebase.json` with one Python codebase at `source`, with `runtime` when given.
fn firebase_json(dir: &Path, source: &Path, runtime: Option<&str>) -> PathBuf {
    let mut entry = serde_json::json!({
        "codebase": "py",
        "source": source.display().to_string(),
    });
    if let Some(runtime) = runtime {
        entry["runtime"] = runtime.into();
    }
    let path = dir.join("firebase.json");
    std::fs::write(
        &path,
        serde_json::to_string(&serde_json::json!({ "functions": [entry] })).unwrap(),
    )
    .unwrap();
    path
}

fn exec(config: &Path, extra: &[&str], command: &[&str]) -> Output {
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
        "--eventarc-port",
        "0",
        "--tasks-port",
        "0",
        "--logging-port",
        "0",
        "--ui-port",
        "0",
        "--hub-port",
        "0",
        "--project",
        "demo-py",
        "--firebase-json",
    ] {
        args.push(a.into());
    }
    args.push(config.display().to_string());
    args.extend(extra.iter().map(|s| (*s).to_owned()));
    args.push("--".into());
    args.extend(command.iter().map(|s| (*s).to_owned()));
    Command::new(env!("CARGO_BIN_EXE_fireemu"))
        .args(&args)
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

#[tokio::test]
#[ignore = "requires the fixture virtual environment; CI creates it"]
async fn the_daemons_runner_class_drives_the_real_python_runner() {
    let source = fixture();
    let runner = Runner::spawn_spec(&SpawnSpec {
        command: vec![
            interpreter().display().to_string(),
            runner_script().display().to_string(),
            "--source".to_owned(),
            source.display().to_string(),
            "--codebase".to_owned(),
            "py".to_owned(),
        ],
        cwd: Some(source.display().to_string()),
        env: vec![
            ("GCLOUD_PROJECT".to_owned(), "demo-py".to_owned()),
            (
                "FIRESTORE_EMULATOR_HOST".to_owned(),
                "127.0.0.1:9".to_owned(),
            ),
            (
                "FIREBASE_AUTH_EMULATOR_HOST".to_owned(),
                "127.0.0.1:9".to_owned(),
            ),
        ],
        hello_timeout: Duration::from_secs(60),
    })
    .await
    .unwrap();
    let hello = runner.hello();
    assert_eq!(hello.runner, "python");
    assert!(hello.http_port.is_some());
    assert!(hello.clock.is_none() && hello.app_check.is_none() && hello.inspector_port.is_none());
    // The daemon's own parser accepts exactly what the runner announced.
    let manifest = parse_manifest(hello.manifest.as_ref().expect("a manifest")).unwrap();
    let names: Vec<&str> = manifest.functions.iter().map(|f| f.name.as_str()).collect();
    for expected in ["hello", "add", "fs_created", "fs_literal", "fs_options"] {
        assert!(names.contains(&expected), "{expected} in {names:?}");
    }
    assert!(manifest.ignored.is_empty(), "{:?}", manifest.ignored);

    let event = serde_json::json!({
        "specversion": "1.0",
        "id": "0a1b2c3d-0000-4000-8000-000000000001",
        "source": "//firestore.googleapis.com/projects/demo-py/databases/(default)",
        "subject": "documents/items/a",
        "type": "google.cloud.firestore.document.v1.created",
        "time": "2026-01-01T00:00:02.25Z",
        "datacontenttype": "application/json",
        "data": {"value": {
            "name": "projects/demo-py/databases/(default)/documents/items/a",
            "fields": {"n": {"integerValue": "1"}},
            "createTime": "2026-01-01T00:00:00Z",
            "updateTime": "2026-01-01T00:00:00Z"
        }},
        "location": "nam5", "project": "demo-py", "namespace": "(default)",
        "document": "items/a", "database": "(default)"
    });
    let request = |function: &str, trigger: &str, id: &str| {
        serde_json::json!({
            "type": "invoke", "invocationId": id, "function": function,
            "entryPoint": function, "trigger": trigger, "event": event,
        })
    };
    let ok = runner
        .invoke(
            request("fs_created", "firestore", "ok-1"),
            Duration::from_secs(20),
        )
        .await;
    assert_eq!(ok.outcome, InvokeOutcome::Ok);
    let wrong_trigger = runner
        .invoke(
            request("fs_created", "pubsub", "bad-1"),
            Duration::from_secs(20),
        )
        .await;
    assert!(
        matches!(wrong_trigger.outcome, InvokeOutcome::Failed(_)),
        "{:?}",
        wrong_trigger.outcome
    );
    runner.shutdown().await;
}

#[test]
#[ignore = "requires the fixture virtual environment; CI creates it"]
fn a_python_codebase_serves_http_callables_and_firestore_triggers_in_both_profiles() {
    for (profile, config) in [
        ("emulator", None),
        ("strict", Some(r#"{"schemaVersion":1,"profile":"strict"}"#)),
    ] {
        let dir = scratch(profile);
        let firebase = firebase_json(&dir, &fixture(), None);
        let mut extra: Vec<String> = Vec::new();
        if let Some(text) = config {
            let path = dir.join("fireemu.json");
            std::fs::write(&path, text).unwrap();
            extra.push("--config".to_owned());
            extra.push(path.display().to_string());
        }
        let extra: Vec<&str> = extra.iter().map(String::as_str).collect();
        let script = fixture().join("e2e.py");
        let python = interpreter().display().to_string();
        let script = script.display().to_string();
        let profile_setting = format!("E2E_PROFILE={profile}");
        let out = exec(
            &firebase,
            &extra,
            &["env", &profile_setting, &python, &script],
        );
        let err = String::from_utf8_lossy(&out.stderr).into_owned();
        assert_eq!(out.status.code(), Some(0), "{profile}: {err}");
        assert!(
            String::from_utf8_lossy(&out.stdout).contains("\"ok\": true"),
            "{profile}: {} {err}",
            String::from_utf8_lossy(&out.stdout)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[test]
fn a_python_codebase_without_a_virtual_environment_stops_before_anything_starts() {
    let dir = scratch("novenv");
    let source = dir.join("code");
    std::fs::create_dir_all(&source).unwrap();
    std::fs::write(source.join("requirements.txt"), "firebase-functions\n").unwrap();
    std::fs::write(source.join("main.py"), "").unwrap();
    for (runtime, bin) in [(Some("python312"), "python3.12"), (None, "python3")] {
        let firebase = firebase_json(&dir, &source, runtime);
        let out = exec(&firebase, &[], &["true"]);
        let err = String::from_utf8_lossy(&out.stderr).into_owned();
        assert_eq!(out.status.code(), Some(1), "{err}");
        assert!(err.contains("the Functions codebase \"py\""), "{err}");
        assert!(
            err.contains(&format!(
                "Missing virtual environment at venv directory. Did you forget to run '{bin} -m venv venv'?"
            )),
            "{err}"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
#[ignore = "requires the fixture virtual environment; CI creates it"]
fn a_declared_runtime_that_does_not_match_the_interpreter_is_refused_naming_both() {
    let dir = scratch("mismatch");
    // The fixture's venv is whatever minor the machine built it with; declare another one.
    let output = Command::new(interpreter())
        .args(["-c", "import sys; print(sys.version_info[1])"])
        .output()
        .unwrap();
    let minor: u32 = String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse()
        .unwrap();
    let other = if minor == 12 { 13 } else { 12 };
    let firebase = firebase_json(&dir, &fixture(), Some(&format!("python3{other}")));
    let out = exec(&firebase, &[], &["true"]);
    let err = String::from_utf8_lossy(&out.stderr).into_owned();
    assert_eq!(out.status.code(), Some(1), "{err}");
    assert!(err.contains(&format!("runs Python 3.{minor}")), "{err}");
    assert!(err.contains(&format!("needs Python 3.{other}")), "{err}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
#[ignore = "requires the fixture virtual environment; CI creates it"]
fn a_python_trigger_family_that_is_planned_fails_discovery_naming_the_function() {
    let dir = scratch("planned");
    let source = dir.join("code");
    std::fs::create_dir_all(&source).unwrap();
    std::fs::write(source.join("requirements.txt"), "firebase-functions\n").unwrap();
    std::os::unix::fs::symlink(fixture().join("venv"), source.join("venv")).unwrap();
    std::fs::write(
        source.join("main.py"),
        "from firebase_admin import initialize_app\n\
         from firebase_functions import pubsub_fn\n\
         initialize_app()\n\
         @pubsub_fn.on_message_published(topic='jobs')\n\
         def later(event):\n    pass\n",
    )
    .unwrap();
    let firebase = firebase_json(&dir, &source, None);
    let out = exec(&firebase, &[], &["true"]);
    let err = String::from_utf8_lossy(&out.stderr).into_owned();
    assert_eq!(out.status.code(), Some(1), "{err}");
    assert!(err.contains("later (pubsub)"), "{err}");
    assert!(err.contains("planned"), "{err}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
#[ignore = "requires the fixture virtual environment; CI creates it"]
fn a_virtual_clock_for_the_functions_runner_is_refused_for_a_python_codebase() {
    let dir = scratch("clock");
    let firebase = firebase_json(&dir, &fixture(), None);
    let config = dir.join("fireemu.json");
    std::fs::write(
        &config,
        r#"{"schemaVersion":1,"daemon":{"clockStart":"2026-01-01T00:00:00Z"},"functions":{"clock":{"date":"virtual"}}}"#,
    )
    .unwrap();
    let config = config.display().to_string();
    let out = exec(&firebase, &["--config", &config], &["true"]);
    let err = String::from_utf8_lossy(&out.stderr).into_owned();
    assert_eq!(out.status.code(), Some(1), "{err}");
    assert!(
        err.contains(
            "does not support the requested virtual clock (Python code runs on real time)"
        ),
        "{err}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
