//! `eventarc.authentication` through the real CLI and the real Admin SDK (owner decision 1396).
//!
//! `getEventarc().channel().publish()` always sends `Authorization: Bearer <token of the app's
//! credential>`; in CI there is no Google credential, so a test gives the app a fake one (the
//! emulators' usual `owner`). The strict listener's development default admits it, as the official
//! emulator admits any credential; `productionExact` restores production's 401.
//!
//! The SDKs come from the pinned conformance install, which the CI test job installs
//! (`pnpm -C conformance install --frozen-lockfile`).

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn sdk_modules() -> PathBuf {
    let modules = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../conformance/node_modules");
    for package in ["firebase-admin", "firebase-functions"] {
        assert!(
            modules.join(package).join("package.json").exists(),
            "the pinned conformance install is required (pnpm -C conformance install --frozen-lockfile): {package}"
        );
    }
    std::fs::canonicalize(modules).unwrap()
}

/// A handler that counts the custom events it receives, and an HTTPS function that reports the count.
const CODEBASE: &str = r"
const { onCustomEventPublished } = require('firebase-functions/v2/eventarc');
const { onRequest } = require('firebase-functions/v2/https');
let received = 0;
exports.onThingDone = onCustomEventPublished('com.example.thing.done', () => { received += 1; });
exports.received = onRequest((_request, response) => response.json({ received }));
";

/// Publishes once through the Admin SDK with the fake `owner` credential and once with no credential
/// at all, then reads how many events the handler received. `expect` is `delivered` or `refused`.
const PROBE: &str = r"
const assert = require('node:assert/strict');
const path = require('node:path');
const [modules, project, expect] = process.argv.slice(1);
const { initializeApp } = require(path.join(modules, 'firebase-admin/lib/app/index.js'));
const { getEventarc } = require(path.join(modules, 'firebase-admin/lib/eventarc/index.js'));
(async () => {
  const host = process.env.CLOUD_EVENTARC_EMULATOR_HOST;
  assert.ok(host, 'Eventarc must be started');
  const credential = { getAccessToken: async () => ({ access_token: 'owner', expires_in: 3600 }) };
  const app = initializeApp({ projectId: project, credential });
  const event = { type: 'com.example.thing.done', source: 'https://example.com/things', data: { n: 1 } };
  let sdk = 'published';
  try {
    await getEventarc(app).channel('locations/us-central1/channels/firebase').publish(event);
  } catch (error) {
    sdk = String(error.message);
  }
  const bare = await fetch(`${host}/projects/${project}/locations/us-central1/channels/firebase:publishEvents`, {
    method: 'POST',
    body: JSON.stringify({ events: [{ '@type': 'type.googleapis.com/io.cloudevents.v1.CloudEvent', id: 'bare', source: 's', specVersion: '1.0', type: 'com.example.thing.done', attributes: { time: { ceTimestamp: new Date().toISOString() }, datacontenttype: { ceString: 'application/json' } }, textData: '{}' }] }),
  });
  const bareText = await bare.text();
  const count = async () => (await (await fetch(`http://${process.env.FIREEMU_FUNCTIONS_HOST}/${project}/us-central1/received`)).json()).received;
  if (expect === 'delivered') {
    assert.equal(sdk, 'published');
    assert.equal(bare.status, 200, bareText);
    const deadline = Date.now() + 30000;
    while ((await count()) < 2) {
      assert.ok(Date.now() < deadline, 'both publications must be delivered');
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    assert.equal(await count(), 2);
  } else {
    assert.match(sdk, /status: 401/);
    assert.equal(bare.status, 401);
    assert.equal(JSON.parse(bareText).error.details[0].reason, 'CREDENTIALS_MISSING');
    await new Promise((resolve) => setTimeout(resolve, 1000));
    assert.equal(await count(), 0);
  }
})().catch((error) => { console.error(error); process.exitCode = 1; });
";

#[test]
fn the_admin_sdk_publishes_without_a_google_credential_unless_production_exact() {
    let modules = sdk_modules();
    let dir = std::env::temp_dir().join(format!("fireemu-eventarc-auth-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("index.js"), CODEBASE).unwrap();
    std::fs::write(
        dir.join("package.json"),
        r#"{"name":"eventarc-authentication","private":true,"main":"index.js"}"#,
    )
    .unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(&modules, dir.join("node_modules")).unwrap();
    let project = "demo-eventarc-auth";
    for (name, config, expect) in [
        ("strict-default", r#""profile":"strict""#, "delivered"),
        (
            "strict-production-exact",
            r#""profile":"strict","productionExact":true"#,
            "refused",
        ),
        (
            "strict-explicit-production",
            r#""profile":"strict","eventarc":{"authentication":"production"}"#,
            "refused",
        ),
        (
            "strict-explicit-permissive",
            r#""profile":"strict","productionExact":true,"eventarc":{"authentication":"permissive"}"#,
            "delivered",
        ),
        ("emulator", r#""profile":"emulator""#, "delivered"),
    ] {
        let path = dir.join(format!("{name}.json"));
        std::fs::write(
            &path,
            format!(
                r#"{{"schemaVersion":1,{config},"firestore":{{"edition":"standard","apiMode":"native"}}}}"#
            ),
        )
        .unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_fireemu"))
            .args(["exec", "--config", path.to_str().unwrap()])
            .args(["--only", "functions,eventarc", "--project", project])
            .args(["--functions", dir.to_str().unwrap()])
            .args([
                "--http-port",
                "0",
                "--functions-port",
                "0",
                "--eventarc-port",
                "0",
            ])
            .args([
                "--tasks-port",
                "0",
                "--logging-port",
                "0",
                "--hub-port",
                "0",
            ])
            .args(["--ui-port", "0", "--", "node", "-e", PROBE])
            .args([modules.to_str().unwrap(), project, expect])
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{name}\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    std::fs::remove_dir_all(dir).unwrap();
}
