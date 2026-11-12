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
    exec_with_env(config, extra, command, &[])
}

fn exec_with_env(config: &Path, extra: &[&str], command: &[&str], env: &[(&str, &Path)]) -> Output {
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
        "--pubsub-port",
        "0",
        "--database-port",
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
        .envs(env.iter().copied())
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

/// The structured event the daemon sends for a created Firestore document.
fn created_event() -> serde_json::Value {
    serde_json::json!({
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
    })
}

/// The structured event the daemon sends for a Pub/Sub message with an ordering key.
fn published_event() -> serde_json::Value {
    serde_json::json!({
        "specversion": "1.0", "id": "m-1",
        "source": "//pubsub.googleapis.com/projects/demo-py/topics/orders",
        "type": "google.cloud.pubsub.topic.v1.messagePublished",
        "time": "2026-01-01T00:00:02.250Z",
        "data": {
            "message": {"messageId": "m-1", "data": "aGk=", "attributes": {}, "publishTime": "2026-01-01T00:00:02.250Z", "orderingKey": "k"},
            "subscription": "projects/demo-py/subscriptions/s"
        }
    })
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
            // The daemon exports it; a Storage function with no bucket reads its default from it.
            (
                "FIREBASE_CONFIG".to_owned(),
                r#"{"storageBucket":"demo-py.appspot.com"}"#.to_owned(),
            ),
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
    for expected in [
        "hello",
        "add",
        "fs_created",
        "fs_literal",
        "fs_options",
        "ps_orders",
        "ps_retried",
        "st_finalized",
        "st_default_bucket",
        "ea_plain",
        "ea_filtered",
        "db_created",
        "db_literal_glob",
        "sch_ok",
        "sch_retry",
        "tk_echo",
        "bc_user",
        "bs_user",
        "reads_key",
    ] {
        assert!(names.contains(&expected), "{expected} in {names:?}");
    }
    assert!(manifest.ignored.is_empty(), "{:?}", manifest.ignored);

    let event = created_event();
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
    // A Pub/Sub frame the runner turns into the SDK's event (the message ids are the SDK's snake_case keys).
    let pubsub = runner
        .invoke(
            serde_json::json!({
                "type": "invoke", "invocationId": "ps-1", "function": "ps_orders",
                "entryPoint": "ps_orders", "trigger": "pubsub", "event": published_event(),
            }),
            Duration::from_secs(20),
        )
        .await;
    assert_eq!(pubsub.outcome, InvokeOutcome::Ok);
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
fn a_python_codebase_serves_http_callables_and_event_triggers_in_both_profiles() {
    for (profile, config) in [
        (
            "emulator",
            Some(r#"{"schemaVersion":1,"profile":"emulator"}"#),
        ),
        ("strict", None),
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
fn a_python_trigger_family_that_is_deferred_fails_discovery_naming_the_function() {
    let dir = scratch("deferred");
    let source = dir.join("code");
    std::fs::create_dir_all(&source).unwrap();
    std::fs::write(source.join("requirements.txt"), "firebase-functions\n").unwrap();
    std::os::unix::fs::symlink(fixture().join("venv"), source.join("venv")).unwrap();
    std::fs::write(
        source.join("main.py"),
        "from firebase_admin import initialize_app\n\
         from firebase_functions import remote_config_fn\n\
         initialize_app()\n\
         @remote_config_fn.on_config_updated()\n\
         def later(event):\n    pass\n",
    )
    .unwrap();
    let firebase = firebase_json(&dir, &source, None);
    let out = exec(&firebase, &[], &["true"]);
    let err = String::from_utf8_lossy(&out.stderr).into_owned();
    assert_eq!(out.status.code(), Some(1), "{err}");
    assert!(err.contains("later (remoteConfig)"), "{err}");
    assert!(err.contains("deferred"), "{err}");
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

#[test]
#[ignore = "requires the fixture virtual environment; CI creates it"]
fn production_exact_reproduces_the_python_sdks_audience_refusal_of_an_auth_blocking_token() {
    let script = r#"import os, urllib.request, urllib.error
url = 'http://' + os.environ['FIREBASE_AUTH_EMULATOR_HOST'] + '/identitytoolkit.googleapis.com/v1/accounts:signUp?key=fake'
request = urllib.request.Request(url, data=b'{"email":"plain@example.com","password":"secret1","returnSecureToken":true}', headers={'Content-Type': 'application/json'})
try:
    response = urllib.request.urlopen(request, timeout=20)
except urllib.error.HTTPError as error:
    response = error
print('STATUS', response.code)
print(response.read().decode())
if response.code == 200:
    seen = urllib.request.urlopen('http://' + os.environ['FIREEMU_FUNCTIONS_HOST'] + '/demo-py/us-central1/seen', timeout=20).read().decode()
    assert '"function":"bc_user"' in seen.replace(' ', ''), seen
"#;
    for (name, config, status, note) in [
        ("default", None, 200, 1),
        (
            "production",
            Some(r#"{"schemaVersion":1,"productionExact":true}"#),
            503,
            0,
        ),
        // `seen` reads what `bc_user` recorded in the same process, so this case keeps the shared runner
        // that productionExact would otherwise replace by one process per function.
        (
            "override",
            Some(
                r#"{"schemaVersion":1,"productionExact":true,"functions":{"authBlockingToken":"emulated","isolation":"codebase"}}"#,
            ),
            200,
            1,
        ),
    ] {
        let dir = scratch(name);
        let firebase = firebase_json(&dir, &fixture(), None);
        let config_path = dir.join("fireemu.json");
        let config_string = config_path.display().to_string();
        let extra = if let Some(config) = config {
            std::fs::write(&config_path, config).unwrap();
            vec!["--config", config_string.as_str()]
        } else {
            vec![]
        };
        let python = interpreter().display().to_string();
        let cache = dir.join("cache");
        std::fs::create_dir_all(cache.join("Library/Caches")).unwrap();
        std::fs::create_dir_all(cache.join(".cache")).unwrap();
        let out = exec_with_env(
            &firebase,
            &extra,
            &[&python, "-c", script],
            &[("HOME", &cache), ("XDG_CACHE_HOME", &cache)],
        );
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(out.status.success(), "{name}: {stdout}\n{stderr}");
        assert!(
            stdout.contains(&format!("STATUS {status}")),
            "{name}: {stdout}\n{stderr}"
        );
        if status == 503 {
            assert!(
                stdout.contains("Error code: 47") && stdout.contains("backendError"),
                "{stdout}"
            );
            assert!(stderr.contains("incorrect \"aud\""), "{stderr}");
            // The blocking key signs blocking tokens only: ID tokens stay unsigned-emulator.
            assert!(
                stdout.contains("blocking tokens:  production (RS256 kid "),
                "{stdout}"
            );
            assert!(!stdout.contains("id tokens:"), "{stdout}");
            assert!(!cache.join("Library/Caches/fireemu/session-rsa").exists());
            assert!(!cache.join(".cache/fireemu/session-rsa").exists());
            assert!(!cache.join("fireemu/session-rsa").exists());
            assert!(!cache.join("session-rsa").exists());
        } else {
            assert!(!stdout.contains("blocking tokens:"), "{name}: {stdout}");
        }
        assert_eq!(
            stderr.matches("functions.authBlockingToken").count(),
            note,
            "{name}: {stderr}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[test]
fn the_emulator_profile_refuses_the_production_blocking_token() {
    let dir = scratch("blocking-profile");
    let firebase = firebase_json(&dir, &fixture(), None);
    let config = dir.join("fireemu.json");
    std::fs::write(&config, r#"{"schemaVersion":1,"profile":"emulator","functions":{"authBlockingToken":"production"}}"#).unwrap();
    let config = config.display().to_string();
    let out = exec(&firebase, &["--config", &config], &["true"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "{stderr}");
    assert!(
        stderr.contains("functions.authBlockingToken \"production\" requires the strict profile"),
        "{stderr}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
#[ignore = "requires the fixture virtual environment; CI creates it"]
fn a_token_signed_with_the_daemons_key_verifies_in_the_python_runner() {
    use fireemu_adapter_http::signing::RsaSigner;
    use fireemu_core_auth::jwt::{base64url_decode, base64url_encode, encode_payload_with};
    let signer = RsaSigner::from_seed(7).unwrap();
    let other = RsaSigner::from_seed(8).unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let claims = serde_json::json!({"aud":"https://pcblock-abc123-uc.a.run.app", "iss":"https://securetoken.google.com/demo-py", "sub":"interop-user", "iat":now, "exp":now + 300});
    let token = encode_payload_with(&claims.to_string(), Some(signer.as_ref()));
    let parts: Vec<_> = token.split('.').collect();
    let mut payload = base64url_decode(parts[1]).unwrap();
    // Flip one bit of the subject so the payload stays valid JSON and only the signature check can refuse it.
    let position = payload
        .windows(b"interop-user".len())
        .position(|window| window == b"interop-user")
        .unwrap();
    payload[position] ^= 1;
    let tampered = format!("{}.{}.{}", parts[0], base64url_encode(&payload), parts[2]);
    let wrong_key = encode_payload_with(&claims.to_string(), Some(other.as_ref()));
    let script = r#"import os, sys
from fireemu_runner.blocking import install_from_environment
install_from_environment(os.environ)
from firebase_functions.private.token_verifier import verify_auth_blocking_token
import firebase_admin
firebase_admin.initialize_app(options={"projectId": "demo-py"})
try:
    print(verify_auth_blocking_token(sys.argv[1])['uid'])
except Exception as error:
    print(type(error).__name__)
"#;
    for (candidate, expected) in [
        (token, "interop-user"),
        (tampered, "InvalidAuthBlockingTokenError"),
        (wrong_key, "InvalidAuthBlockingTokenError"),
    ] {
        let out = Command::new(interpreter())
            .args(["-c", script, &candidate])
            .env(
                "PYTHONPATH",
                Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tools/runner-python"),
            )
            .env("FIREEMU_AUTH_BLOCKING_JWKS", signer.jwks().to_string())
            .env("GCLOUD_PROJECT", "demo-py")
            .env("FIREBASE_AUTH_EMULATOR_HOST", "127.0.0.1:9")
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), expected);
    }
}

#[test]
#[ignore = "requires the fixture virtual environment; CI creates it"]
fn the_blocking_key_is_not_the_id_token_key() {
    let dir = scratch("blocking-key-separate");
    let firebase = firebase_json(&dir, &fixture(), None);
    let config = dir.join("fireemu.json");
    std::fs::write(
        &config,
        r#"{"schemaVersion":1,"productionExact":true,"auth":{"idTokenSigning":"session-rsa"}}"#,
    )
    .unwrap();
    let cache = dir.join("cache");
    std::fs::create_dir_all(&cache).unwrap();
    let config = config.display().to_string();
    let out = exec_with_env(
        &firebase,
        &["--config", &config],
        &["true"],
        &[("HOME", &cache), ("XDG_CACHE_HOME", &cache)],
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "{stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let kid_after = |prefix: &str| {
        let rest = stdout
            .split(prefix)
            .nth(1)
            .unwrap_or_else(|| panic!("{prefix} missing in {stdout}"));
        rest.split(|c: char| !c.is_ascii_alphanumeric())
            .next()
            .unwrap()
            .to_owned()
    };
    let id_kid = kid_after("id tokens:        RS256 (kid ");
    let blocking_kid = kid_after("blocking tokens:  production (RS256 kid ");
    assert!(!id_kid.is_empty() && !blocking_kid.is_empty());
    assert_ne!(id_kid, blocking_kid, "{stdout}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// `functions.isolation = "function"`: each Python function is served by its own runner process, with
/// its own identity from the start (the shared runner names the call that started last).
#[test]
#[ignore = "requires the fixture virtual environment; CI creates it"]
fn function_isolation_gives_each_python_function_its_own_process_and_identity() {
    let dir = scratch("isolation");
    let source = dir.join("code");
    std::fs::create_dir_all(&source).unwrap();
    std::fs::write(source.join("requirements.txt"), "firebase-functions\n").unwrap();
    std::os::unix::fs::symlink(fixture().join("venv"), source.join("venv")).unwrap();
    std::fs::write(
        source.join("main.py"),
        "import os\n\
         from firebase_admin import initialize_app\n\
         from firebase_functions import https_fn\n\
         initialize_app()\n\
         CACHE = {}\n\
         def answer(name, request):\n    \
             CACHE[name] = True\n    \
             return {'service': os.environ.get('K_SERVICE'), 'target': os.environ.get('FUNCTION_TARGET'), \
         'signature': os.environ.get('FUNCTION_SIGNATURE_TYPE'), 'pid': os.getpid(), 'cached': sorted(CACHE)}\n\
         @https_fn.on_request()\n\
         def one(request):\n    return answer('one', request)\n\
         @https_fn.on_request()\n\
         def two(request):\n    return answer('two', request)\n",
    )
    .unwrap();
    let firebase = firebase_json(&dir, &source, None);
    let config = dir.join("fireemu.json");
    std::fs::write(
        &config,
        r#"{"schemaVersion":1,"functions":{"isolation":"function"}}"#,
    )
    .unwrap();
    let out = exec(
        &firebase,
        &["--config", &config.display().to_string()],
        &[
            "/bin/sh",
            "-c",
            "curl -sS http://$FIREEMU_FUNCTIONS_HOST/demo-py/us-central1/one; echo; \
             curl -sS http://$FIREEMU_FUNCTIONS_HOST/demo-py/us-central1/two; echo",
        ],
    );
    let err = String::from_utf8_lossy(&out.stderr).into_owned();
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    assert_eq!(out.status.code(), Some(0), "{err}");
    let answers: Vec<serde_json::Value> = stdout
        .lines()
        .filter_map(|line| serde_json::from_str(line.trim()).ok())
        .collect();
    assert_eq!(answers.len(), 2, "stdout was:\n{stdout}\nstderr:\n{err}");
    for (answer, name) in answers.iter().zip(["one", "two"]) {
        assert_eq!(answer["service"], name);
        assert_eq!(answer["target"], name);
        assert_eq!(answer["signature"], "http");
        // Module state is per process: the other function's call left nothing here.
        assert_eq!(answer["cached"], serde_json::json!([name]));
    }
    assert_ne!(answers[0]["pid"], answers[1]["pid"]);
    let _ = std::fs::remove_dir_all(&dir);
}
