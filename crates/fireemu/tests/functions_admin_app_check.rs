//! HTTP Functions that verify the App Check header with the real `firebase-admin` SDK.
//!
//! `getAppCheck().verifyToken()` inside an `onRequest` function is answered by the daemon
//! (version-bounded instrumentation, `tools/runner-node/admin-app-check.mjs`): it honours the
//! project's current session epoch and the virtual clock, rejects what the callable boundary
//! rejects, refuses `consume: true` without any request to Google, and keeps working in the
//! runner that replaces the one a session reset retires.
//!
//! Run against every `firebase-admin` copy installed under `tools/sdk-smoke` and
//! `conformance` (13.x and 14.x); the SDK workflow installs 14.x in both.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// `node_modules` directories that hold both `firebase-functions` and `firebase-admin`. The SDK
/// workflow installs 14.x in two of them; `FIREEMU_ADMIN_SDK_MODULES` adds more (a 13.x copy,
/// say), separated by the platform path delimiter.
fn sdk_roots() -> Vec<PathBuf> {
    let extra = std::env::var_os("FIREEMU_ADMIN_SDK_MODULES")
        .map(|paths| std::env::split_paths(&paths).collect::<Vec<_>>())
        .unwrap_or_default();
    ["tools/sdk-smoke/node_modules", "conformance/node_modules"]
        .iter()
        .map(|p| repo().join(p))
        .chain(extra)
        .filter(|root| {
            root.join("firebase-functions").exists()
                && root.join("firebase-admin/package.json").exists()
                && root.join("express").exists()
        })
        .collect()
}

fn scratch_codebase(label: usize, node_modules: &Path) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "fireemu-admin-app-check-{label}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let source = repo().join("tools/sdk-smoke/functions-project/fixtures/admin-app-check");
    for file in ["index.js", "package.json"] {
        std::fs::copy(source.join(file), dir.join(file)).unwrap();
    }
    #[cfg(unix)]
    std::os::unix::fs::symlink(
        std::fs::canonicalize(node_modules).unwrap(),
        dir.join("node_modules"),
    )
    .unwrap();
    dir
}

const SCRIPT: &str = r"
const crypto = require('node:crypto');
const appId = '1:123456789:web:local-test-app';
const auth = { authorization: `Bearer ${process.env.FIREEMU_CONTROL_TOKEN}`, 'content-type': 'application/json' };
const verify = async (token, query = '') => {
  const headers = token === undefined ? {} : { 'x-firebase-appcheck': token };
  const r = await fetch(`http://${process.env.FIREEMU_FUNCTIONS_HOST}/demo-adminac/us-central1/verify${query}`, { headers });
  return r.json();
};
const exchange = async () => {
  const r = await fetch(`http://${process.env.FIREEMU_APP_CHECK_EMULATOR_HOST}/v1/projects/demo-adminac/apps/${appId}:exchangeDebugToken`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ debugToken: crypto.randomUUID() }) });
  return (await r.json()).token;
};
const control = (path, body) => fetch(`${process.env.FIREEMU_CONTROL_URL}${path}`, { method: 'POST', headers: auth, body: JSON.stringify(body ?? {}) }).then((r) => r.status);
(async () => {
  const out = {};
  const first = await exchange();
  out.valid = await verify(first);
  out.consume = await verify(first, '?consume=1');
  out.garbage = await verify('not-a-token');
  out.missing = await verify(undefined);
  out.resetStatus = await control('sessions/default/reset');
  out.afterReset = await verify(first);
  const second = await exchange();
  out.fresh = await verify(second);
  out.advance = await control('sessions/default/clock:advance', { seconds: 4000 });
  out.expired = await verify(second);
  console.log('RESULT ' + JSON.stringify(out));
})().catch((e) => { console.error(e); process.exit(1); });
";

#[test]
#[ignore = "requires tools/sdk-smoke or conformance dependencies; the SDK workflow runs this test"]
fn verify_token_in_an_http_function_follows_the_daemon_across_a_reset() {
    let roots = sdk_roots();
    assert!(
        !roots.is_empty(),
        "install tools/sdk-smoke (npm ci) or conformance (pnpm install) first"
    );
    for (label, node_modules) in roots.iter().enumerate() {
        let version =
            std::fs::read_to_string(node_modules.join("firebase-admin/package.json")).unwrap();
        let version: serde_json::Value = serde_json::from_str(&version).unwrap();
        let version = version["version"].as_str().unwrap().to_owned();
        let dir = scratch_codebase(label, node_modules);
        let out = Command::new(env!("CARGO_BIN_EXE_fireemu"))
            .args([
                "exec",
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
                "demo-adminac",
                "--functions",
            ])
            .arg(&dir)
            .args(["--", "node", "-e", SCRIPT])
            .stdin(Stdio::null())
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        let line = stdout
            .lines()
            .find_map(|l| l.strip_prefix("RESULT "))
            .unwrap_or_else(|| panic!("firebase-admin {version}: no result\n{stdout}\n{stderr}"));
        let seen: serde_json::Value = serde_json::from_str(line).unwrap();
        let context = format!("firebase-admin {version}: {seen}\n{stderr}");
        println!("verified through firebase-admin {version}");

        assert_eq!(seen["valid"]["ok"], true, "{context}");
        assert_eq!(
            seen["valid"]["appId"], "1:123456789:web:local-test-app",
            "{context}"
        );
        // consume:true is refused locally, with the instrumentation's own error.
        assert_eq!(seen["consume"]["ok"], false, "{context}");
        assert_eq!(
            seen["consume"]["code"], "app-check/unimplemented",
            "{context}"
        );
        // The SDK's own decode and input checks.
        assert_eq!(
            seen["garbage"]["code"], "app-check/invalid-argument",
            "{context}"
        );
        assert!(
            seen["garbage"]["message"]
                .as_str()
                .unwrap()
                .starts_with("Decoding App Check token failed."),
            "{context}"
        );
        assert_eq!(
            seen["missing"]["message"], "App check token must be a non-null string.",
            "{context}"
        );
        // A reset retires every token minted before it, and the runner that replaces the
        // retired one keeps verifying.
        assert_eq!(seen["resetStatus"], 200, "{context}");
        assert_eq!(seen["afterReset"]["ok"], false, "{context}");
        assert_eq!(
            seen["afterReset"]["code"], "app-check/invalid-argument",
            "{context}"
        );
        assert!(
            seen["afterReset"]["message"]
                .as_str()
                .unwrap()
                .contains("does not correspond to a known public key"),
            "{context}"
        );
        assert_eq!(seen["fresh"]["ok"], true, "{context}");
        // The virtual clock, not the runner's, decides expiry.
        assert_eq!(seen["advance"], 200, "{context}");
        assert_eq!(seen["expired"]["ok"], false, "{context}");
        assert_eq!(
            seen["expired"]["code"], "app-check/app-check-token-expired",
            "{context}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// A verifier that answers every question the same way, to observe the runner's own report.
#[derive(Debug)]
struct Refusing;

impl fireemu_adapter_functions::admin_app_check::AdminAppCheckVerifier for Refusing {
    fn verify(
        &self,
        _project_id: &str,
        _token: &str,
    ) -> fireemu_adapter_functions::admin_app_check::Reply {
        fireemu_adapter_functions::admin_app_check::Reply::Verdict(
            fireemu_core_app_check::admin::AdminVerdict::Reject(
                fireemu_core_app_check::admin::AdminRejection::NoMatchingKid,
            ),
        )
    }
}

/// The hello of a real runner says whether `getAppCheck().verifyToken` is answered by the daemon.
#[tokio::test]
#[ignore = "requires tools/sdk-smoke or conformance dependencies; the SDK workflow runs this test"]
async fn the_runner_hello_reports_the_admin_instrumentation() {
    use fireemu_adapter_functions::admin_app_check::AdminAppCheckVerifier;
    use fireemu_adapter_functions::runner::{Runner, SpawnSpec};
    use std::sync::Arc;
    use std::time::Duration;

    let roots = sdk_roots();
    let node_modules = roots.first().expect("install the SDK dependencies first");
    let script = repo().join("tools/runner-node/index.mjs");
    let spec_for = |dir: &Path, admin: bool| SpawnSpec {
        command: vec![
            "node".to_owned(),
            script.display().to_string(),
            "--source".to_owned(),
            dir.display().to_string(),
            "--codebase".to_owned(),
            "default".to_owned(),
        ],
        cwd: None,
        env: {
            let mut env = vec![
                ("GCLOUD_PROJECT".to_owned(), "demo-adminac".to_owned()),
                ("FIREEMU_RUNNER_SECRET".to_owned(), "test-secret".to_owned()),
            ];
            if admin {
                env.push(("FIREEMU_APP_CHECK_ADMIN".to_owned(), "1".to_owned()));
            }
            env
        },
        hello_timeout: Duration::from_secs(60),
    };
    let report = |runner: &Runner| runner.hello().admin_app_check.clone().expect("a report");
    let dir = scratch_codebase(90, node_modules);
    let verifier: Arc<dyn AdminAppCheckVerifier> = Arc::new(Refusing);

    // Asked for and in place: the self-test reached the daemon, which answered.
    let runner = Runner::spawn_spec_with(&spec_for(&dir, true), Some(verifier.clone()))
        .await
        .unwrap();
    assert_eq!(
        report(&runner)["instrumentation"],
        "ok",
        "{}",
        report(&runner)
    );
    assert!(report(&runner)["firebaseAdminVersion"].is_string());
    runner.shutdown().await;

    // Not asked for: nothing is patched.
    let runner = Runner::spawn_spec_with(&spec_for(&dir, false), Some(verifier.clone()))
        .await
        .unwrap();
    assert_eq!(report(&runner)["instrumentation"], "disabled");
    runner.shutdown().await;

    // Asked for, but the daemon has no verifier: still patched and failing closed, and it says so.
    let runner = Runner::spawn_spec(&spec_for(&dir, true)).await.unwrap();
    assert_eq!(report(&runner)["instrumentation"], "daemon-unavailable");
    runner.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);

    // A codebase with a firebase-admin outside the supported majors is left alone.
    let unsupported = std::env::temp_dir().join(format!(
        "fireemu-admin-app-check-unsupported-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&unsupported);
    std::fs::create_dir_all(unsupported.join("node_modules/firebase-admin")).unwrap();
    std::fs::write(
        unsupported.join("package.json"),
        r#"{"name":"f","private":true,"main":"index.js"}"#,
    )
    .unwrap();
    std::fs::write(unsupported.join("index.js"), "").unwrap();
    std::fs::write(
        unsupported.join("node_modules/firebase-admin/package.json"),
        r#"{"name":"firebase-admin","version":"15.0.0","main":"index.js"}"#,
    )
    .unwrap();
    std::fs::write(unsupported.join("node_modules/firebase-admin/index.js"), "").unwrap();
    let runner = Runner::spawn_spec_with(&spec_for(&unsupported, true), Some(verifier))
        .await
        .unwrap();
    let reported = report(&runner);
    assert!(
        reported["instrumentation"]
            .as_str()
            .unwrap()
            .contains("outside the supported range"),
        "{reported}"
    );
    assert_eq!(reported["firebaseAdminVersion"], "15.0.0");
    runner.shutdown().await;
    let _ = std::fs::remove_dir_all(&unsupported);
}
