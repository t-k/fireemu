//! Multi-codebase discovery (FN-01): `functions` as an array in `firebase.json`.
//!
//! The official emulator gives each `EmulatableBackend` its own runtime worker pool, keyed by
//! `backend.codebase` (`functionsEmulator.js` `this.workerPools[backend.codebase]`), and
//! serves them all behind one functions port. fireemu does the same with one runner process
//! per codebase behind one runtime, so every trigger match, schedule and retry is still
//! decided once while each function runs in the process of the codebase that exported it.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

fn sdk_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tools/sdk-smoke")
}

fn have_sdk() -> bool {
    sdk_root().join("node_modules/firebase-functions").exists()
}

fn fixtures() -> PathBuf {
    std::fs::canonicalize(sdk_root().join("functions-project/fixtures")).unwrap()
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("fireemu-cb-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A `firebase.json` declaring `codebases` as a `functions` array, written into `dir`.
fn firebase_json(dir: &Path, codebases: &[(&str, &str)]) -> PathBuf {
    let entries: Vec<serde_json::Value> = codebases
        .iter()
        .map(|(name, source)| {
            serde_json::json!({
                "codebase": name,
                "source": fixtures().join(source).display().to_string(),
                "ignore": ["node_modules", ".git"],
            })
        })
        .collect();
    let path = dir.join("firebase.json");
    std::fs::write(
        &path,
        serde_json::to_string_pretty(&serde_json::json!({ "functions": entries })).unwrap(),
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
        "--logging-port",
        "0",
        "--ui-port",
        "0",
        "--hub-port",
        "0",
        "--project",
        "demo-multi",
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

/// Functions scenario 4: several codebases, each on its own runner, routed by region and
/// name behind one functions port.
#[test]
fn every_declared_codebase_is_loaded_on_its_own_runner_and_routed_by_region() {
    if !have_sdk() {
        return;
    }
    let dir = scratch("both");
    let config = firebase_json(&dir, &[("alpha", "codebase-a"), ("beta", "codebase-b")]);
    let out = exec(
        &config,
        &[],
        &[
            "sh",
            "-c",
            "curl -sS http://$FIREEMU_FUNCTIONS_HOST/demo-multi/us-central1/fxAlpha; echo; \
             curl -sS http://$FIREEMU_FUNCTIONS_HOST/demo-multi/europe-west1/fxBeta",
        ],
    );
    let err = String::from_utf8_lossy(&out.stderr).into_owned();
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    assert_eq!(out.status.code(), Some(0), "{err}");

    let answers: Vec<serde_json::Value> = stdout
        .lines()
        .filter_map(|l| serde_json::from_str(l.trim()).ok())
        .collect();
    assert_eq!(answers.len(), 2, "stdout was:\n{stdout}\nstderr:\n{err}");
    assert_eq!(answers[0]["codebase"], "alpha");
    assert_eq!(answers[1]["codebase"], "beta");
    let advertised: Vec<&str> = stdout
        .lines()
        .filter(|line| line.starts_with("  function URL: http://"))
        .collect();
    assert_eq!(advertised.len(), 2, "unexpected banner:\n{stdout}");
    assert!(
        advertised[0].ends_with("/demo-multi/us-central1/fxAlpha"),
        "the banner did not print the first routable function URL:\n{stdout}"
    );
    assert!(
        advertised[1].ends_with("/demo-multi/europe-west1/fxBeta"),
        "the banner did not print the second routable function URL:\n{stdout}"
    );
    // One runner process per codebase, which is the point: the two answers come from
    // different processes.
    assert_ne!(
        answers[0]["pid"], answers[1]["pid"],
        "both codebases answered from the same process"
    );
    assert!(
        err.contains("2 codebases are loaded (alpha, beta), one runner process each"),
        "{err}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// `--only functions:<codebase>` loads exactly one of them, as the official CLI spells it.
#[test]
fn only_functions_with_a_codebase_name_loads_that_one_alone() {
    if !have_sdk() {
        return;
    }
    let dir = scratch("one");
    let config = firebase_json(&dir, &[("alpha", "codebase-a"), ("beta", "codebase-b")]);
    let out = exec(
        &config,
        &["--only", "functions:beta"],
        &[
            "sh",
            "-c",
            "curl -sS -o /dev/null -w '%{http_code}\\n' \
             http://$FIREEMU_FUNCTIONS_HOST/demo-multi/us-central1/fxAlpha; \
             curl -sS http://$FIREEMU_FUNCTIONS_HOST/demo-multi/europe-west1/fxBeta",
        ],
    );
    let err = String::from_utf8_lossy(&out.stderr).into_owned();
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    assert_eq!(out.status.code(), Some(0), "{err}");
    assert!(
        stdout.contains("404"),
        "alpha should not be served:\n{stdout}"
    );
    assert!(stdout.contains("\"codebase\":\"beta\""), "{stdout}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// A function name two codebases both export is refused, naming both: the emulator serves one
/// URL per region and name, so whichever loaded second would silently take it.
#[test]
fn a_function_name_two_codebases_export_is_refused_naming_both() {
    if !have_sdk() {
        return;
    }
    let dir = scratch("clash");
    let config = firebase_json(
        &dir,
        &[("alpha", "codebase-a"), ("clash", "codebase-clash")],
    );
    let out = exec(&config, &[], &["true"]);
    let err = String::from_utf8_lossy(&out.stderr).into_owned();
    assert_eq!(out.status.code(), Some(1), "{err}");
    assert!(err.contains("fxAlpha"), "{err}");
    assert!(err.contains("alpha"), "{err}");
    assert!(err.contains("clash"), "{err}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// A codebase whose declared runtime is not Node is refused by name. fireemu ships one
/// loader; handing a Python codebase to `node` would fail later, from a file the project never
/// meant Node to read.
#[test]
fn a_python_or_dart_codebase_is_refused_with_the_language_named() {
    for (runtime, language) in [("python312", "Python"), ("dart3", "Dart")] {
        let dir = scratch("runtime");
        let path = dir.join("firebase.json");
        std::fs::write(
            &path,
            serde_json::to_string(&serde_json::json!({
                "functions": [{
                    "codebase": "backend",
                    "source": fixtures().join("codebase-a").display().to_string(),
                    "runtime": runtime,
                }]
            }))
            .unwrap(),
        )
        .unwrap();
        let out = exec(&path, &[], &["true"]);
        let err = String::from_utf8_lossy(&out.stderr).into_owned();
        assert_eq!(out.status.code(), Some(1), "{err}");
        assert!(err.contains("\"backend\""), "{err}");
        assert!(err.contains(runtime), "{err}");
        assert!(err.contains(language), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
