//! Environment and configuration parity (FN-04): the dotenv chain, `.secret.local`, the
//! legacy runtime configuration and the variables the runtime is started with.
//!
//! The order and the dialect are `firebase-tools@15.28.2` `lib/functions/env.js`
//! (`findEnvfiles`, `loadUserEnvs`, `parseStrict`); the variables are
//! `lib/emulator/functionsEmulator.js` `getRuntimeEnvs` -- the user environment first, then
//! the system and emulator variables over it, then `FIREBASE_CONFIG`, then `.secret.local`
//! over everything (`startRuntime`, `:1195`).
//!
//! The dotenv files are written into a scratch codebase rather than committed: a repository
//! that carries a file called `.secret.local` is a repository whose secret scanners cry wolf.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

fn sdk_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tools/sdk-smoke")
}

fn have_sdk() -> bool {
    sdk_root().join("node_modules/firebase-functions").exists()
}

/// A codebase in a scratch directory, with `node_modules` linked to the smoke's so that Node
/// resolves `firebase-functions` from it.
fn scratch_codebase(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("fireemu-env-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let source = sdk_root().join("functions-project/fixtures/env-params");
    for file in ["index.js", "package.json"] {
        std::fs::copy(source.join(file), dir.join(file)).unwrap();
    }
    #[cfg(unix)]
    std::os::unix::fs::symlink(
        std::fs::canonicalize(sdk_root().join("node_modules")).unwrap(),
        dir.join("node_modules"),
    )
    .unwrap();
    dir
}

fn write(dir: &Path, name: &str, body: &str) {
    std::fs::write(dir.join(name), body).unwrap();
}

fn fireemu_exec(source: &Path, project: &str) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_fireemu"));
    command.args([
        "exec",
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
        project,
        "--functions",
        &source.display().to_string(),
    ]);
    command
}

fn exec(source: &Path, project: &str) -> Output {
    fireemu_exec(source, project)
        .args(["--", "true"])
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

fn exec_script(source: &Path, project: &str, script: &str) -> Output {
    fireemu_exec(source, project)
        .args(["--", "sh", "-c", script])
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

fn exec_script_with_arg(source: &Path, project: &str, script: &str, arg: &Path) -> Output {
    fireemu_exec(source, project)
        .args([
            "--",
            "sh",
            "-c",
            script,
            "functions-reload-test",
            arg.to_str().unwrap(),
        ])
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

fn exec_with_profile(source: &Path, project: &str, profile: &str) -> Output {
    let config = source.join(format!("fireemu-{profile}.json"));
    write(
        source,
        config.file_name().unwrap().to_str().unwrap(),
        &format!(
            r#"{{"schemaVersion":1,"profile":"{profile}","firestore":{{"edition":"standard","apiMode":"native"}}}}"#
        ),
    );
    fireemu_exec(source, project)
        .args(["--config", config.to_str().unwrap(), "--", "true"])
        .env("FX_FROM_PARENT", "inherited parent value")
        .env(
            "GOOGLE_APPLICATION_CREDENTIALS",
            "/must/not/reach-functions.json",
        )
        .env("CLOUDSDK_CONFIG", "/must/not/reach-gcloud")
        .env("FIREBASE_DEBUG_MODE", "must-not-reach")
        .env("FIREBASE_DEBUG_FEATURES", "must-not-reach")
        .env("FIREEMU_RUNNER_SECRET", "must-not-reach")
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

#[test]
fn a_same_size_rewrite_reloads_and_an_invalid_generation_keeps_the_last_good_one() {
    if !have_sdk() {
        return;
    }
    let dir = scratch_codebase("same-size-reload");
    write(
        &dir,
        "index.js",
        "const { onRequest } = require('firebase-functions/v2/https');\nconst marker = \"before\";\nexports.fxReload = onRequest((_request, response) => response.status(200).send(marker));\n",
    );
    write(
        &dir,
        "package.json",
        r#"{"name":"same-size-reload","private":true,"main":"index.js","engines":{"node":"20"}}"#,
    );
    let source = dir.join("index.js");
    let output = exec_script_with_arg(
        &dir,
        "demo-same-size-reload",
        r#"
set -eu
endpoint="$FIREEMU_FUNCTIONS_HOST/demo-same-size-reload/us-central1/fxReload"
first=$(curl -fsS "$endpoint")
node -e 'const fs=require("fs"); const p=process.argv[1]; const s=fs.readFileSync(p,"utf8"); fs.writeFileSync(p,s.replace("\"before\"", "missing!"));' "$1"
sleep 3
last_good=$(curl -fsS "$endpoint")
node -e 'const fs=require("fs"); const p=process.argv[1]; const s=fs.readFileSync(p,"utf8"); fs.writeFileSync(p,s.replace("missing!", "\"after!\""));' "$1"
latest=""
for _attempt in 1 2 3 4 5 6 7 8 9 10; do
  sleep 1
  latest=$(curl -fsS "$endpoint")
  if [ "$latest" = "after!" ]; then
    break
  fi
done
printf '%s\n%s\n%s\n' "$first" "$last_good" "$latest"
test "$first" = "before"
test "$last_good" = "before"
test "$latest" = "after!"
"#,
        &source,
    );
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(output.status.code(), Some(0), "{stderr}");
    assert!(
        stderr.contains("keeping the last-known-good generation"),
        "{stderr}"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let observations = stdout.lines().rev().take(3).collect::<Vec<_>>();
    assert_eq!(observations, ["after!", "before", "before"], "{stdout}");
    let _ = std::fs::remove_dir_all(dir);
}

/// The one line the fixture prints at load, parsed.
fn observed(out: &Output) -> serde_json::Value {
    let err = String::from_utf8_lossy(&out.stderr).into_owned();
    let line = err
        .lines()
        .find_map(|l| l.split_once("FIXTURE_ENV "))
        .unwrap_or_else(|| panic!("the fixture printed no environment:\n{err}"))
        .1;
    serde_json::from_str(line).unwrap_or_else(|e| panic!("{e}: {line}"))
}

#[test]
fn the_firebase_profile_inherits_the_parent_environment_but_strict_stays_isolated() {
    if !have_sdk() {
        return;
    }
    let dir = scratch_codebase("parent-env");
    write(
        &dir,
        ".env",
        "FX_FROM_DOTENV=fixture\nFX_INT=1\nFX_BOOL=true\nFX_LIST=[\"fixture\"]\n",
    );

    let firebase = exec_with_profile(&dir, "demo-parent-env", "firebase");
    assert_eq!(
        firebase.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&firebase.stderr)
    );
    assert_eq!(observed(&firebase)["fromParent"], "inherited parent value");
    assert_ne!(
        observed(&firebase)["googleCredentials"],
        "/must/not/reach-functions.json"
    );
    for field in [
        "cloudSdkConfigIsParent",
        "debugModeIsParent",
        "debugFeaturesIsParent",
        "runnerSecretIsParent",
    ] {
        assert_eq!(observed(&firebase)[field], false, "{field}");
    }

    let strict = exec_with_profile(&dir, "demo-parent-env", "strict");
    assert_eq!(
        strict.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&strict.stderr)
    );
    assert_eq!(observed(&strict)["fromParent"], serde_json::Value::Null);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Functions scenario 4: the chain is applied in the official order, the emulator-only file
/// wins, and `.secret.local` and `.runtimeconfig.json` reach the runtime the way they do
/// under the Firebase CLI.
#[test]
fn the_dotenv_chain_secret_overrides_and_runtime_config_reach_the_runtime() {
    if !have_sdk() {
        return;
    }
    let dir = scratch_codebase("chain");
    write(
        &dir,
        ".env",
        "# every file in the chain sets these; the last one to set a key wins\n\
         FX_FROM_DOTENV=from .env\n\
         FX_OVERRIDDEN_BY_PROJECT=from .env\n\
         FX_OVERRIDDEN_BY_LOCAL=from .env\n\
         FX_QUOTED=\"first\\nsecond\"\n\
         FX_INT=41\n\
         FX_BOOL=false\n\
         FX_LIST=[\"a\",\"b\"]\n\
         FX_SECRET=must not bypass the secret binding\n",
    );
    write(
        &dir,
        ".env.demo-envchain",
        "FX_OVERRIDDEN_BY_PROJECT=from .env.<projectId>\n\
         FX_OVERRIDDEN_BY_LOCAL=from .env.<projectId>\n\
         FX_INT=42\n",
    );
    write(
        &dir,
        ".env.local",
        "FX_OVERRIDDEN_BY_LOCAL=from .env.local\nFX_BOOL=true\n",
    );
    write(&dir, ".secret.local", "FX_SECRET=a local secret value\n");
    write(
        &dir,
        ".runtimeconfig.json",
        r#"{"someservice": {"key": "legacy"}}"#,
    );

    let out = exec(&dir, "demo-envchain");
    let err = String::from_utf8_lossy(&out.stderr).into_owned();
    assert_eq!(out.status.code(), Some(0), "{err}");
    let seen = observed(&out);

    assert_eq!(seen["fromDotEnv"], "from .env");
    assert_eq!(seen["overriddenByProject"], "from .env.<projectId>");
    assert_eq!(seen["overriddenByLocal"], "from .env.local");
    // A double-quoted value expands its escapes; a single-quoted one would not.
    assert_eq!(seen["quoted"], "first\nsecond");

    // Parameters read the same variables, with the types the SDK gives them.
    assert_eq!(seen["paramString"], "from .env");
    assert_eq!(seen["paramInt"], 42);
    assert_eq!(seen["paramBoolean"], true);
    assert_eq!(seen["paramList"], serde_json::json!(["a", "b"]));
    // The official missing-parameter behaviour: an empty string, and a `default` is a
    // deploy-time value the runtime never sees. Neither prompts and neither fails.
    assert_eq!(seen["paramMissing"], "");
    assert_eq!(seen["paramMissingWithDefault"], "");
    assert_eq!(seen["paramSecret"], "");
    // Legacy functions.config(), through CLOUD_RUNTIME_CONFIG.
    assert_eq!(seen["legacyConfig"], serde_json::json!({"key": "legacy"}));

    // The system and emulator variables the official emulator sets.
    assert_eq!(seen["kRevision"], "1");
    assert_eq!(seen["tz"], "UTC");
    assert_eq!(seen["quotaProject"], "demo-envchain");
    assert_eq!(seen["functionsEmulator"], "true");
    assert_eq!(
        seen["firebaseConfigKeys"],
        serde_json::json!(["databaseURL", "projectId", "storageBucket"])
    );

    assert!(
        err.contains("loaded environment variables from .env, .env.demo-envchain, .env.local"),
        "{err}"
    );

    let invoked = exec_script(
        &dir,
        "demo-envchain",
        "curl -sS http://$FIREEMU_FUNCTIONS_HOST/demo-envchain/us-central1/fxEnvEcho; printf '\\n'; curl -sS http://$FIREEMU_FUNCTIONS_HOST/demo-envchain/us-central1/fxEnvNoSecret; printf '\\n'; curl -sS http://$FIREEMU_FUNCTIONS_HOST/demo-envchain/us-central1/fxEnvLegacySecret",
    );
    let invoked_err = String::from_utf8_lossy(&invoked.stderr);
    assert_eq!(invoked.status.code(), Some(0), "{invoked_err}");
    let responses: Vec<serde_json::Value> = String::from_utf8_lossy(&invoked.stdout)
        .lines()
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect();
    assert_eq!(
        responses.len(),
        3,
        "{}",
        String::from_utf8_lossy(&invoked.stdout)
    );
    assert_eq!(responses[0]["paramSecret"], "a local secret value");
    assert_eq!(responses[1]["paramSecret"], serde_json::Value::Null);
    assert_eq!(responses[2]["paramSecret"], "a local secret value");
    let _ = std::fs::remove_dir_all(&dir);
}

/// A dotenv file the official CLI refuses is refused here with the same sentence, before
/// anything starts: a reserved key would otherwise be silently overwritten by the emulator's
/// own value, and a malformed line silently lose an assignment.
#[test]
fn a_dotenv_file_the_official_parser_refuses_stops_the_run_with_its_message() {
    if !have_sdk() {
        return;
    }
    for (body, expected) in [
        (
            "FUNCTION_TARGET=mine\n",
            "Key FUNCTION_TARGET is reserved for internal use.",
        ),
        (
            "lower_case=1\n",
            "Failed to validate key lower_case: Key lower_case must start with an uppercase",
        ),
        (
            "FIREBASE_THING=1\n",
            "starts with a reserved prefix (X_GOOGLE_ FIREBASE_ EXT_ KIT_)",
        ),
        (
            "GOOD=1\nthis is not an assignment\n",
            "Invalid dotenv file, error on lines: this is not an assignment",
        ),
    ] {
        let dir = scratch_codebase("refuse");
        write(&dir, ".env", body);
        let out = exec(&dir, "demo-envrefuse");
        let err = String::from_utf8_lossy(&out.stderr).into_owned();
        assert_eq!(out.status.code(), Some(1), "{body}\n{err}");
        assert!(
            err.contains(expected),
            "{body}\nwanted {expected}\ngot {err}"
        );
        assert!(
            err.contains("Failed to load environment variables from .env."),
            "{err}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
