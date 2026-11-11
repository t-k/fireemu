//! `functions.isolation`: one runner process serves a codebase (`codebase`, the default) or one
//! dedicated runner process serves each function (`function`).
//!
//! Production runs every function in its own instance: the function's identity and secrets are in
//! its environment from the start, its module graph is its own, and a call to another function
//! cannot change what it sees or make it wait. The same fixture runs in both modes. Where the
//! shared runner shows the limit of sharing one process (the identity of the call that started
//! last, a module cache both functions use, a secret-using call that runs alone), the dedicated
//! runners show what production shows.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

/// The smoke's dependencies. `FIREEMU_TEST_SDK_ROOT` names them for a copy of the tree that does not
/// carry the ignored `node_modules` (a mutation work copy).
fn sdk_root() -> PathBuf {
    std::env::var_os("FIREEMU_TEST_SDK_ROOT").map_or_else(
        || Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tools/sdk-smoke"),
        PathBuf::from,
    )
}

/// The real Node binary, resolved once from the unmodified environment, so the scenario never runs
/// through the Volta shim (which forks when its environment is changed).
fn real_node() -> PathBuf {
    static NODE: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    NODE.get_or_init(|| {
        let out = Command::new("node")
            .args(["-p", "process.execPath"])
            .output()
            .expect("node is on PATH");
        PathBuf::from(String::from_utf8_lossy(&out.stdout).trim())
    })
    .clone()
}

fn have_sdk() -> bool {
    sdk_root().join("node_modules/firebase-functions").exists()
}

fn scratch_codebase(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("fireemu-iso-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    // The runners are started with the canonical path, and the scenario finds them by it.
    let dir = std::fs::canonicalize(&dir).unwrap();
    std::os::unix::fs::symlink(
        std::fs::canonicalize(sdk_root().join("node_modules")).unwrap(),
        dir.join("node_modules"),
    )
    .unwrap();
    std::fs::write(
        dir.join("package.json"),
        r#"{"name":"isolation-fixture","main":"index.js","engines":{"node":">=18"}}"#,
    )
    .unwrap();
    std::fs::write(dir.join("shared.js"), "exports.cache = new Map();\n").unwrap();
    std::fs::write(
        dir.join(".secret.local"),
        "FX_TOKEN=token-for-alpha\nFX_OTHER=nobody-declares-this\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("index.js"),
        r"
const { onRequest } = require('firebase-functions/v2/https');
const { defineSecret } = require('firebase-functions/params');
const shared = require('./shared');
const token = defineSecret('FX_TOKEN');
const atImport = { service: process.env.K_SERVICE ?? null, token: process.env.FX_TOKEN ?? null };
const snapshot = () => ({
  pid: process.pid, service: process.env.K_SERVICE, target: process.env.FUNCTION_TARGET,
  signature: process.env.FUNCTION_SIGNATURE_TYPE, token: process.env.FX_TOKEN ?? null,
  other: process.env.FX_OTHER ?? null, cached: shared.cache.get('writer') ?? null,
});
const handler = name => async (req, res) => {
  const startedAt = Date.now();
  if (req.query.remember) shared.cache.set('writer', name);
  const before = snapshot();
  await new Promise(resolve => setTimeout(resolve, Number(req.query.wait ?? 0)));
  res.json({ name, before, after: snapshot(), atImport, startedAt, endedAt: Date.now() });
};
exports.alpha = onRequest({ secrets: [token] }, handler('alpha'));
exports.beta = onRequest(handler('beta'));
exports.gamma = onRequest(handler('gamma'));
exports.crasher = onRequest((req, res) => {
  res.json({ pid: process.pid });
  setTimeout(() => process.exit(3), 100);
});
",
    )
    .unwrap();
    dir
}

/// The scenario, run by Node inside `fireemu exec` against the codebase, printing one JSON object.
const SCENARIO: &str = r"
const { execFileSync } = require('node:child_process');
// Other processes on a shared machine can have very long command lines.
const PS_LIMIT = { maxBuffer: 1 << 28 };
const base = `http://${process.env.FIREEMU_FUNCTIONS_HOST}/demo-isolation/us-central1/`;
const get = async path => { const r = await fetch(base + path); if (r.status !== 200) throw new Error(path + ' ' + r.status); return r.json(); };
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const runnerLines = () => execFileSync('ps', ['-ax', '-o', 'ucomm=,args='], PS_LIMIT).toString().split('\n').map(line => line.trim())
  .filter(line => line.startsWith('node ') && line.includes(' --source ' + process.argv[1]));
(async () => {
  const out = {};
  out.runnersAtStart = runnerLines().map(line => line.includes(' --function ') ? line.split(' --function ')[1].trim() : '(codebase)').sort();
  // An await in one function while another function of the codebase is called.
  const slow = get('beta?wait=2000');
  await sleep(400);
  const other = get('gamma?remember=1');
  [out.slowBeta, out.gamma] = await Promise.all([slow, other]);
  // A function that declares a local secret runs while a plain function is called.
  const holding = get('alpha?wait=2000');
  await sleep(400);
  const plain = get('beta');
  [out.alpha, out.plainBeta] = await Promise.all([holding, plain]);
  out.runnersAfterCalls = runnerLines().map(line => line.includes(' --function ') ? line.split(' --function ')[1].trim() : '(codebase)').sort();
  // Another function's process dies; the others keep theirs.
  const before = { alpha: (await get('alpha')).after.pid, beta: (await get('beta')).after.pid };
  out.crashedPid = (await get('crasher')).pid;
  await sleep(600);
  out.afterCrash = { alpha: (await get('alpha')).after.pid, beta: (await get('beta')).after.pid };
  out.before = before;
  let again;
  for (let attempt = 0; attempt < 40 && !again; attempt += 1) {
    try { again = (await get('crasher')).pid; } catch { await sleep(250); }
  }
  out.restartedPid = again;
  out.runnersAfter = runnerLines().map(line => line.includes(' --function ') ? line.split(' --function ')[1].trim() : '(codebase)').sort();
  console.log('RESULT ' + JSON.stringify(out));
})().catch(error => { console.error(error); process.exitCode = 1; });
";

fn run(dir: &Path, isolation: &str) -> (Output, serde_json::Value) {
    let config = dir.join("fireemu.json");
    std::fs::write(
        &config,
        format!(r#"{{"schemaVersion":1,"functions":{{"isolation":"{isolation}"}}}}"#),
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_fireemu"))
        .args([
            "exec",
            "--project",
            "demo-isolation",
            "--only",
            "functions",
            "--http-port",
            "0",
            "--functions-port",
            "0",
            "--logging-port",
            "0",
            "--hub-port",
            "0",
            "--ui-port",
            "0",
            "--config",
        ])
        .arg(&config)
        .args(["--functions"])
        .arg(dir)
        .arg("--")
        .arg(real_node())
        .args(["-e", SCENARIO])
        .arg(dir)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let line = stdout
        .lines()
        .find_map(|line| line.strip_prefix("RESULT "))
        .unwrap_or_else(|| panic!("no result; stdout:\n{stdout}\nstderr:\n{stderr}"));
    let result = serde_json::from_str(line).unwrap();
    (output, result)
}

/// No process whose command line names the scratch source is left once `fireemu exec` returned.
fn assert_no_orphans(dir: &Path) {
    assert_no_orphans_of(&dir.display().to_string());
}

fn assert_no_orphans_of(needle: &str) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let table = Command::new("ps")
            .args(["-ax", "-o", "pid=,args="])
            .output()
            .unwrap();
        let left: Vec<String> = String::from_utf8_lossy(&table.stdout)
            .lines()
            .filter(|line| line.contains(needle) && line.contains("--source"))
            .map(str::to_owned)
            .collect();
        if left.is_empty() {
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "orphan runner processes:\n{}",
            left.join("\n")
        );
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

fn text<'a>(value: &'a serde_json::Value, path: &[&str]) -> &'a str {
    let mut node = value;
    for key in path {
        node = &node[*key];
    }
    node.as_str()
        .unwrap_or_else(|| panic!("{path:?} is not text in {value}"))
}

#[test]
#[ignore = "requires tools/sdk-smoke dependencies; CI runs this test after npm ci"]
fn the_shared_runner_shows_what_one_process_for_a_codebase_means() {
    assert!(
        have_sdk(),
        "install tools/sdk-smoke dependencies before running this test"
    );
    let dir = scratch_codebase("codebase");
    let (output, result) = run(&dir, "codebase");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        result["runnersAtStart"],
        serde_json::json!(["(codebase)"]),
        "one process serves the codebase"
    );
    // The identity and the module cache are those of the call that started last.
    assert_eq!(text(&result, &["slowBeta", "before", "service"]), "beta");
    assert_eq!(text(&result, &["slowBeta", "after", "service"]), "gamma");
    assert_eq!(text(&result, &["slowBeta", "after", "cached"]), "gamma");
    assert_eq!(
        result["slowBeta"]["after"]["pid"],
        result["gamma"]["after"]["pid"]
    );
    // A call that uses a local secret runs alone, so a plain call waits for it.
    let alpha_end = result["alpha"]["endedAt"].as_i64().unwrap();
    let beta_start = result["plainBeta"]["startedAt"].as_i64().unwrap();
    assert!(
        beta_start >= alpha_end - 5,
        "beta started at {beta_start}, alpha ended at {alpha_end}"
    );
    // The secret is hidden while user code loads.
    assert!(result["alpha"]["atImport"]["token"].is_null());
    assert_eq!(
        text(&result, &["alpha", "before", "token"]),
        "token-for-alpha"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
#[ignore = "requires tools/sdk-smoke dependencies; CI runs this test after npm ci"]
fn dedicated_runners_keep_identity_module_graph_secrets_and_lifecycle_per_function() {
    assert!(
        have_sdk(),
        "install tools/sdk-smoke dependencies before running this test"
    );
    let dir = scratch_codebase("function");
    let (output, result) = run(&dir, "function");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    // The discovery process is gone and no function process exists until the function is first called;
    // then there is one per function that was called (the crasher has not been called yet).
    assert_eq!(result["runnersAtStart"], serde_json::json!([]));
    assert_eq!(
        result["runnersAfterCalls"],
        serde_json::json!(["alpha", "beta", "gamma"])
    );
    // Identity: fixed from the start, whatever else runs meanwhile.
    for path in ["before", "after"] {
        assert_eq!(text(&result, &["slowBeta", path, "service"]), "beta");
        assert_eq!(text(&result, &["slowBeta", path, "target"]), "beta");
        assert_eq!(text(&result, &["slowBeta", path, "signature"]), "http");
    }
    assert_eq!(
        text(&result, &["slowBeta", "atImport", "service"]),
        "beta",
        "set before user code loaded"
    );
    // Module graph: what gamma cached is not in beta's process.
    assert!(result["slowBeta"]["after"]["cached"].is_null());
    assert_eq!(text(&result, &["gamma", "after", "cached"]), "gamma");
    assert_ne!(
        result["slowBeta"]["after"]["pid"],
        result["gamma"]["after"]["pid"]
    );
    // Concurrency: a plain function is not held back by a function that declares a secret.
    let alpha_end = result["alpha"]["endedAt"].as_i64().unwrap();
    let beta_start = result["plainBeta"]["startedAt"].as_i64().unwrap();
    assert!(
        beta_start < alpha_end - 500,
        "beta started at {beta_start}, alpha ended at {alpha_end}"
    );
    // Secrets: declared and present from the first line of user code; nobody else gets them.
    assert_eq!(
        text(&result, &["alpha", "atImport", "token"]),
        "token-for-alpha"
    );
    assert_eq!(
        text(&result, &["alpha", "before", "token"]),
        "token-for-alpha"
    );
    assert!(result["alpha"]["before"]["other"].is_null());
    assert!(result["plainBeta"]["before"]["token"].is_null());
    assert!(result["plainBeta"]["before"]["other"].is_null());
    // Lifecycle: one function's process dying changes no other function's process.
    assert_eq!(result["before"], result["afterCrash"]);
    let crashed = result["crashedPid"].as_i64().unwrap();
    let restarted = result["restartedPid"]
        .as_i64()
        .expect("the crashed function came back");
    assert_ne!(crashed, restarted);
    // The crasher exits after every answer, so it may or may not be up again; the others are.
    let after: Vec<&str> = result["runnersAfter"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    for name in ["alpha", "beta", "gamma"] {
        assert!(after.contains(&name), "{name} is still running: {after:?}");
    }
    // Cleanup: every runner process is gone once the run ended.
    assert_no_orphans(&dir);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Run by Node inside `fireemu exec` against a function-isolated codebase whose source it rewrites.
const RELOAD_SCENARIO: &str = r#"
const fs = require('node:fs');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
// Other processes on a shared machine can have very long command lines.
const PS_LIMIT = { maxBuffer: 1 << 28 };
const dir = process.argv[1];
const base = `http://${process.env.FIREEMU_FUNCTIONS_HOST}/demo-isolation/us-central1/`;
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const get = async name => { const r = await fetch(base + name); return { status: r.status, body: r.status === 200 ? await r.json() : null }; };
const ancestors = () => {
  const parent = new Map(execFileSync('ps', ['-ax', '-o', 'pid=,ppid='], PS_LIMIT).toString().trim().split('\n')
    .map(row => row.trim().split(/\s+/).map(Number)));
  const chain = [];
  for (let pid = process.pid; pid > 1 && parent.has(pid); pid = parent.get(pid)) chain.push(pid);
  return chain;
};
const runners = () => {
  const chain = ancestors();
  return execFileSync('ps', ['-ax', '-o', 'ucomm=,args='], PS_LIMIT).toString().split('\n').map(line => line.trim())
    .filter(line => line.startsWith('node ') && line.includes(' --source ') &&
      (line.includes(' --source ' + dir) || chain.some(pid => line.includes('/fireemu-functions-' + pid + '-'))))
    .map(line => line.includes(' --function ') ? line.split(' --function ')[1].trim() : '(codebase)').sort();
};
const until = async (check, what) => {
  for (let attempt = 0; attempt < 200; attempt += 1) { const value = await check(); if (value) return value; await sleep(100); }
  throw new Error('timed out waiting for ' + what);
};
(async () => {
  const out = { runnersAtStart: runners(), ancestors: ancestors() };
  out.first = { alpha: (await get('alpha')).body, beta: (await get('beta')).body };
  out.runnersBefore = runners();
  const index = path.join(dir, 'index.js');
  fs.writeFileSync(index, fs.readFileSync(index, 'utf8').replace(/'before'/g, "'after'"));
  out.reloaded = await until(async () => {
    const alpha = (await get('alpha')).body; const beta = (await get('beta')).body;
    return alpha && beta && alpha.marker === 'after' && beta.marker === 'after' ? { alpha, beta } : null;
  }, 'the reloaded generation');
  out.runnersAfterReload = runners();
  // A new export changes the trigger manifest: the reload is rejected and the last good processes stay.
  fs.writeFileSync(index, fs.readFileSync(index, 'utf8').replace(/'after'/g, "'third'") + '\nexports.gamma = onRequest((req, res) => res.json({ marker: "third" }));\n');
  await sleep(10000);
  out.afterChange = { alpha: (await get('alpha')).body, gamma: (await get('gamma')).status };
  // The staged processes (the discovery process and one per function of the changed set) are stopped again.
  out.runnersAfterChange = await until(async () => { const now = runners(); return now.length === 2 ? now : null; }, 'the refused generation to stop');
  console.log('RESULT ' + JSON.stringify(out));
})().catch(error => { console.error(error); process.exitCode = 1; });
"#;

#[test]
#[ignore = "requires tools/sdk-smoke dependencies; CI runs this test after npm ci"]
fn a_reload_replaces_every_function_runner_together_and_a_changed_function_set_is_refused() {
    assert!(
        have_sdk(),
        "install tools/sdk-smoke dependencies before running this test"
    );
    let dir = scratch_codebase("reload");
    std::fs::write(
        dir.join("index.js"),
        r"
const { onRequest } = require('firebase-functions/v2/https');
const marker = 'before';
exports.alpha = onRequest((req, res) => res.json({ marker, pid: process.pid }));
exports.beta = onRequest((req, res) => res.json({ marker, pid: process.pid }));
",
    )
    .unwrap();
    let config = dir.join("fireemu.json");
    std::fs::write(
        &config,
        r#"{"schemaVersion":1,"functions":{"isolation":"function"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("firebase.json"),
        r#"{"functions":{"source":".","ignore":["node_modules",".git","firebase-debug.log","firebase-debug.*.log","*.local"]}}"#,
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_fireemu"))
        .args([
            "exec",
            "--project",
            "demo-isolation",
            "--only",
            "functions",
            "--http-port",
            "0",
            "--functions-port",
            "0",
            "--logging-port",
            "0",
            "--hub-port",
            "0",
            "--ui-port",
            "0",
            "--config",
        ])
        .arg(&config)
        .arg("--firebase-json")
        .arg(dir.join("firebase.json"))
        .arg("--")
        .arg(real_node())
        .args(["-e", RELOAD_SCENARIO])
        .arg(&dir)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(output.status.success(), "{stderr}");
    let line = stdout
        .lines()
        .find_map(|line| line.strip_prefix("RESULT "))
        .unwrap_or_else(|| panic!("no result; stdout:\n{stdout}\nstderr:\n{stderr}"));
    let result: serde_json::Value = serde_json::from_str(line).unwrap();
    assert_eq!(result["runnersAtStart"], serde_json::json!([]));
    assert_eq!(
        result["runnersBefore"],
        serde_json::json!(["alpha", "beta"])
    );
    // Both functions moved to new processes with the new source.
    for name in ["alpha", "beta"] {
        assert_eq!(text(&result, &["first", name, "marker"]), "before");
        assert_eq!(text(&result, &["reloaded", name, "marker"]), "after");
        assert_ne!(
            result["first"][name]["pid"], result["reloaded"][name]["pid"],
            "{name} runs in a new process"
        );
    }
    assert_eq!(
        result["runnersAfterReload"],
        serde_json::json!(["alpha", "beta"]),
        "the replaced processes are gone"
    );
    // A changed function set is refused as a whole: nothing was replaced, nothing was left behind.
    assert_eq!(text(&result, &["afterChange", "alpha", "marker"]), "after");
    assert_eq!(
        result["afterChange"]["alpha"]["pid"],
        result["reloaded"]["alpha"]["pid"]
    );
    assert_eq!(result["afterChange"]["gamma"], 404);
    assert_eq!(
        result["runnersAfterChange"],
        serde_json::json!(["alpha", "beta"])
    );
    assert!(stderr.contains("changed its trigger manifest"), "{stderr}");
    assert_no_orphans(&dir);
    // The reload snapshots the runners started from are removed with their processes.
    for pid in result["ancestors"].as_array().unwrap() {
        assert_no_orphans_of(&format!("/fireemu-functions-{pid}-"));
    }
    let _ = std::fs::remove_dir_all(&dir);
}

fn exec_with_inspector(dir: &Path, isolation: &str, inspect: &[&str]) -> Output {
    let config = dir.join("fireemu-inspect.json");
    std::fs::write(
        &config,
        format!(r#"{{"schemaVersion":1,"functions":{{"isolation":"{isolation}"}}}}"#),
    )
    .unwrap();
    Command::new(env!("CARGO_BIN_EXE_fireemu"))
        .args([
            "exec",
            "--project",
            "demo-isolation",
            "--only",
            "functions",
            "--http-port",
            "0",
            "--functions-port",
            "0",
            "--logging-port",
            "0",
            "--hub-port",
            "0",
            "--ui-port",
            "0",
            "--config",
        ])
        .arg(&config)
        .arg("--functions")
        .arg(dir)
        .args(inspect)
        .args(["--", "true"])
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

#[test]
fn a_fixed_debugger_port_cannot_be_shared_by_the_runners_of_one_codebase() {
    let dir = std::env::temp_dir().join(format!("fireemu-iso-port-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("index.js"), "exports.alpha = () => {};\n").unwrap();
    let output = exec_with_inspector(&dir, "function", &["--inspect-functions", "9330"]);
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(!output.status.success(), "{stderr}");
    assert!(
        stderr.contains("cannot share one fixed debugger port"),
        "{stderr}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
#[ignore = "requires tools/sdk-smoke dependencies; CI runs this test after npm ci"]
fn a_dynamic_debugger_port_is_assigned_to_each_function_runner() {
    assert!(
        have_sdk(),
        "install tools/sdk-smoke dependencies before running this test"
    );
    let dir = scratch_codebase("inspect");
    let output = exec_with_inspector(&dir, "function", &["--inspect-functions"]);
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(output.status.success(), "{stderr}");
    let ports: std::collections::BTreeSet<&str> = stderr
        .lines()
        .filter_map(|line| line.split("using debug port ").nth(1))
        .collect();
    // The discovery runner and the four function runners each own a port.
    assert_eq!(ports.len(), 5, "{stderr}");
    let _ = std::fs::remove_dir_all(&dir);
}
