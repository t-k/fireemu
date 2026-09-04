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

mod census;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use fireemu_adapter_functions::manifest_json::parse_manifest;
use fireemu_adapter_functions::runner::{Runner, SpawnSpec};

#[tokio::test]
#[ignore = "requires tools/sdk-smoke dependencies; CI runs this test after npm ci"]
async fn concurrent_real_sdk_logs_keep_their_function_identity() {
    let runner_script =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tools/runner-node/index.mjs");
    let source = fixture("log-metadata");
    let runner = Runner::spawn_spec(&SpawnSpec {
        command: vec![
            "node".to_owned(),
            runner_script.display().to_string(),
            "--source".to_owned(),
            source.display().to_string(),
            "--codebase".to_owned(),
            "default".to_owned(),
        ],
        cwd: None,
        env: vec![("GCLOUD_PROJECT".to_owned(), "demo-logs".to_owned())],
        hello_timeout: Duration::from_secs(20),
    })
    .await
    .unwrap();
    let request = |function: &str, invocation_id: &str| {
        serde_json::json!({
            "type": "invoke",
            "invocationId": invocation_id,
            "function": function,
            "entryPoint": function,
            "trigger": "schedule",
            "event": {"data": {}}
        })
    };

    let (alpha, beta) = tokio::join!(
        runner.invoke(request("alpha", "alpha-1"), Duration::from_secs(5)),
        runner.invoke(request("beta", "beta-1"), Duration::from_secs(5)),
    );
    assert_eq!(
        alpha.outcome,
        fireemu_adapter_functions::runner::InvokeOutcome::Ok
    );
    assert_eq!(
        beta.outcome,
        fireemu_adapter_functions::runner::InvokeOutcome::Ok
    );
    let oversized = runner
        .invoke(request("oversized", "oversized-1"), Duration::from_secs(5))
        .await;
    assert_eq!(
        oversized.outcome,
        fireemu_adapter_functions::runner::InvokeOutcome::Ok
    );
    let after_oversized = runner
        .invoke(request("beta", "beta-2"), Duration::from_secs(5))
        .await;
    assert_eq!(
        after_oversized.outcome,
        fireemu_adapter_functions::runner::InvokeOutcome::Ok
    );
    let logs = runner.logs_since(None);
    for (message, function, level, user) in [
        ("alpha start", "alpha", "info", true),
        ("alpha structured", "alpha", "warning", true),
        ("alpha done", "alpha", "error", true),
        ("beta start", "beta", "info", true),
        ("beta done", "beta", "info", true),
    ] {
        let line = logs
            .lines
            .iter()
            .find(|line| line.message().contains(message))
            .unwrap_or_else(|| panic!("missing log {message:?}"));
        assert_eq!(line.function(), Some(function), "{message}");
        assert_eq!(line.level(), level, "{message}");
        assert_eq!(line.is_user(), user, "{message}");
    }
    let bounded = logs
        .lines
        .iter()
        .find(|line| line.display().starts_with("info oversized-1"))
        .expect("the oversized log is retained without stopping the runner");
    assert!(bounded.message().ends_with("... [truncated]"));
    assert!(bounded.message().len() <= 256 * 1024);
    assert!(logs
        .lines
        .iter()
        .any(|line| line.display() == "info beta-2 beta start"));
    runner.shutdown().await;
}

#[tokio::test]
#[ignore = "requires tools/sdk-smoke dependencies; CI runs this test after npm ci"]
async fn a_dynamic_inspector_port_is_reported_active_and_released_on_shutdown() {
    let runner_script =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tools/runner-node/index.mjs");
    let source = fixture("inspect-sequential");
    let runner = Runner::spawn_spec(&SpawnSpec {
        command: vec![
            "node".to_owned(),
            "--inspect=127.0.0.1:0".to_owned(),
            "--inspect-publish-uid=http".to_owned(),
            runner_script.display().to_string(),
            "--source".to_owned(),
            source.display().to_string(),
            "--codebase".to_owned(),
            "default".to_owned(),
        ],
        cwd: None,
        env: vec![("GCLOUD_PROJECT".to_owned(), "demo-inspect".to_owned())],
        hello_timeout: Duration::from_secs(20),
    })
    .await
    .unwrap();
    let port = runner
        .hello()
        .inspector_port
        .expect("the runner reports Node's active dynamic inspector port");
    TcpStream::connect(("127.0.0.1", port)).expect("the reported inspector port accepts traffic");
    runner.shutdown().await;
    std::net::TcpListener::bind(("127.0.0.1", port))
        .unwrap_or_else(|cause| panic!("dynamic inspector port remained open: {cause}"));
}

/// The fixture codebases live beside the smoke's functions project so that Node resolves
/// `firebase-functions` through `tools/sdk-smoke/node_modules`.
fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tools/sdk-smoke/functions-project/fixtures")
        .join(name)
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("fireemu-fn-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

struct ChildGuard(Option<Child>);

impl ChildGuard {
    fn new(child: Child) -> Self {
        Self(Some(child))
    }

    fn id(&self) -> u32 {
        self.0.as_ref().expect("the child remains owned").id()
    }

    fn wait_with_output(mut self) -> std::io::Result<Output> {
        self.0
            .take()
            .expect("the child remains owned")
            .wait_with_output()
    }
}

struct ProcessGroupGuard(Option<i32>);

impl ProcessGroupGuard {
    fn new(pgid: i32) -> Self {
        assert!(pgid > 1, "refusing to guard an unsafe process group");
        let own_pgid = census::own_process_group().expect("the test process is visible");
        assert_ne!(pgid, own_pgid, "refusing to guard the test process group");
        Self(Some(pgid))
    }

    fn disarm(&mut self) {
        self.0 = None;
    }
}

impl Drop for ProcessGroupGuard {
    fn drop(&mut self) {
        if let Some(pgid) = self.0.take() {
            census::kill_process_group_with_grace(pgid, Duration::from_secs(2));
        }
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let Some(child) = self.0.as_mut() else {
            return;
        };
        let _ = Command::new("kill")
            .args(["-TERM", &child.id().to_string()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            if child.try_wait().is_ok_and(|status| status.is_some()) {
                return;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        let _ = child.kill();
        let _ = child.wait();
    }
}

fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

fn arm_shutdown_fixture(port: u16, project: &str, marker: &Path) -> serde_json::Value {
    let body = serde_json::json!({"marker": marker}).to_string();
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        match TcpStream::connect(("127.0.0.1", port)) {
            Ok(mut stream) => {
                write!(
                    stream,
                    "POST /{project}/us-central1/arm HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}",
                    body.len()
                )
                .unwrap();
                let mut raw = Vec::new();
                stream.read_to_end(&mut raw).unwrap();
                let response = fireemu_adapter_functions::http::parse_response(&raw, "POST")
                    .expect("the Functions response is valid HTTP");
                assert_eq!(response.status, 200, "{}", String::from_utf8_lossy(&raw));
                return serde_json::from_slice(&response.body).unwrap();
            }
            Err(_) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(error) => panic!("the Functions listener did not start: {error}"),
        }
    }
}

fn assert_listener_closed(port: u16, label: &str, signal: &str) {
    assert!(
        TcpStream::connect(("127.0.0.1", port)).is_err(),
        "the {label} listener survived {signal}"
    );
}

fn exec(source: &Path, config: Option<&Path>) -> Output {
    exec_command(source, config, &["true"])
}

fn exec_command(source: &Path, config: Option<&Path>, command: &[&str]) -> Output {
    exec_command_with_logging_port(source, config, command, 0)
}

fn exec_command_with_logging_port(
    source: &Path,
    config: Option<&Path>,
    command: &[&str],
    logging_port: u16,
) -> Output {
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
        "--ui-port",
        "0",
        "--hub-port",
        "0",
    ] {
        args.push(a.into());
    }
    args.push("--logging-port".into());
    args.push(logging_port.to_string());
    if let Some(config) = config {
        args.push("--config".into());
        args.push(config.display().to_string());
    }
    args.push("--functions".into());
    args.push(source.display().to_string());
    args.push("--".into());
    args.extend(command.iter().map(|argument| (*argument).to_owned()));
    Command::new(env!("CARGO_BIN_EXE_fireemu"))
        .args(&args)
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

fn exec_command_with_inspector_port(
    source: &Path,
    command: &[&str],
    inspector_port: u16,
    logging_port: u16,
) -> Output {
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
        "--ui-port",
        "0",
        "--hub-port",
        "0",
    ] {
        args.push(a.into());
    }
    args.push("--logging-port".into());
    args.push(logging_port.to_string());
    args.push("--inspect-functions".into());
    args.push(inspector_port.to_string());
    args.push("--functions".into());
    args.push(source.display().to_string());
    args.push("--".into());
    args.extend(command.iter().map(|argument| (*argument).to_owned()));
    Command::new(env!("CARGO_BIN_EXE_fireemu"))
        .args(&args)
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[test]
#[ignore = "requires tools/sdk-smoke dependencies; CI runs this test after npm ci"]
fn functions_starts_eventarc_and_tasks_on_dedicated_ports() {
    let source =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tools/sdk-smoke/functions-project");
    let dir = scratch("support-services");
    let env_path = dir.join("env.txt");
    let script = format!("env > {}", env_path.display());
    let output = exec_command(&source, None, &["sh", "-c", &script]);
    assert!(output.status.success(), "{}", stderr(&output));

    let env: std::collections::BTreeMap<String, String> = std::fs::read_to_string(&env_path)
        .unwrap()
        .lines()
        .filter_map(|line| line.split_once('='))
        .map(|(key, value)| (key.to_owned(), value.to_owned()))
        .collect();
    let functions = &env["FIREEMU_FUNCTIONS_HOST"];
    let eventarc = env["CLOUD_EVENTARC_EMULATOR_HOST"]
        .strip_prefix("http://")
        .expect("Eventarc uses the official URL spelling");
    let tasks = &env["CLOUD_TASKS_EMULATOR_HOST"];
    assert_ne!(eventarc, functions);
    assert_ne!(tasks, functions);
    assert_ne!(eventarc, tasks);
    for (service, address) in [
        ("functions", functions.as_str()),
        ("eventarc", eventarc),
        ("tasks", tasks.as_str()),
    ] {
        assert!(
            TcpStream::connect(address).is_err(),
            "{service} listener {address} survived exec"
        );
    }
}

#[test]
#[ignore = "requires tools/sdk-smoke dependencies; CI runs this test after npm ci"]
fn a_real_node_invocation_reaches_the_logging_websocket_with_function_metadata() {
    let probe = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tools/sdk-smoke/functions-project/logging-e2e.mjs");
    let probe = probe.display().to_string();
    for attempt in 0..3 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let logging_port = listener.local_addr().unwrap().port();
        drop(listener);
        let out = exec_command_with_logging_port(
            &fixture("log-metadata"),
            None,
            &["node", &probe],
            logging_port,
        );
        if out.status.success() {
            return;
        }
        let error = stderr(&out);
        let bind_collision = error.contains(&format!(
            "error: bind 127.0.0.1:{logging_port}: Address already in use"
        ));
        if bind_collision && attempt < 2 {
            continue;
        }
        panic!(
            "stdout:\n{}\nstderr:\n{error}",
            String::from_utf8_lossy(&out.stdout)
        );
    }
    unreachable!("the final failed attempt panics");
}

#[test]
#[ignore = "requires tools/sdk-smoke dependencies; CI runs this test after npm ci"]
fn real_node_streaming_callables_deliver_progressively_and_observe_disconnects() {
    let probe = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tools/sdk-smoke/functions-project/streaming-e2e.mjs");
    let probe = probe.display().to_string();
    let out = exec_command(&fixture("streaming-callable"), None, &["node", &probe]);
    assert!(
        out.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        stderr(&out)
    );
}

#[test]
#[ignore = "requires tools/sdk-smoke dependencies; CI runs this test after npm ci"]
fn inspect_functions_opens_the_requested_port_and_serialises_all_handler_kinds() {
    let probe = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tools/sdk-smoke/functions-project/inspector-e2e.mjs");
    let probe = probe.display().to_string();
    for attempt in 0..3 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let inspector_port = listener.local_addr().unwrap().port();
        drop(listener);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let logging_port = listener.local_addr().unwrap().port();
        drop(listener);
        let port = inspector_port.to_string();
        let out = exec_command_with_inspector_port(
            &fixture("inspect-sequential"),
            &["node", &probe, &port],
            inspector_port,
            logging_port,
        );
        let error = stderr(&out);
        if !out.status.success()
            && error.contains(&format!(
                "Address already in use: 127.0.0.1:{inspector_port}"
            ))
            && attempt < 2
        {
            continue;
        }
        assert!(
            out.status.success(),
            "stdout:\n{}\nstderr:\n{error}",
            String::from_utf8_lossy(&out.stdout)
        );
        for name in ["alpha", "beta", "http", "slowHttp"] {
            assert!(error.contains(&format!("{name} active=1")), "{error}");
        }
        assert!(!error.contains("active=2"), "{error}");
        assert!(!error.contains("active=3"), "{error}");
        assert!(!error.contains("Debugger listening on ws://"), "{error}");
        std::net::TcpListener::bind(("127.0.0.1", inspector_port))
            .unwrap_or_else(|cause| panic!("inspector port remained open: {cause}"));
        return;
    }
    unreachable!("the final failed attempt asserts");
}

#[test]
#[ignore = "requires tools/sdk-smoke dependencies; CI runs this test after npm ci"]
fn inspect_functions_refuses_to_start_when_the_requested_port_is_occupied() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let inspector_port = listener.local_addr().unwrap().port();
    let out = exec_command_with_inspector_port(
        &fixture("inspect-sequential"),
        &["true"],
        inspector_port,
        0,
    );
    let error = stderr(&out);
    assert_eq!(out.status.code(), Some(1), "{error}");
    assert!(
        error.contains(&format!(
            "requested debugger port {inspector_port} is not active"
        )),
        "{error}"
    );
    drop(listener);
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match std::net::TcpListener::bind(("127.0.0.1", inspector_port)) {
            Ok(rebound) => {
                drop(rebound);
                break;
            }
            Err(cause)
                if cause.kind() == std::io::ErrorKind::AddrInUse && Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(cause) => panic!("runner retained the occupied inspector port: {cause}"),
        }
    }
}

#[test]
#[ignore = "requires tools/sdk-smoke dependencies; CI runs this test after npm ci"]
fn inspect_functions_refuses_a_listener_closed_during_module_loading() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let inspector_port = listener.local_addr().unwrap().port();
    drop(listener);
    let out =
        exec_command_with_inspector_port(&fixture("inspect-closed"), &["true"], inspector_port, 0);
    let error = stderr(&out);
    assert_eq!(out.status.code(), Some(1), "{error}");
    assert!(
        error.contains(&format!(
            "requested debugger port {inspector_port} is not active"
        )),
        "{error}"
    );
    std::net::TcpListener::bind(("127.0.0.1", inspector_port))
        .unwrap_or_else(|cause| panic!("closed inspector port remained open: {cause}"));
}

#[cfg(unix)]
fn assert_signal_shutdown(signal: &str, label: &str) {
    let unrelated = ChildGuard::new(
        Command::new("sleep")
            .arg("30")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let dir = scratch(&format!("signal-{label}"));
    let marker = dir.join("runner-exit.txt");
    let project = format!("demo-functions-shutdown-{label}-{}", std::process::id());
    let locator = std::env::temp_dir().join(format!("hub-{project}.json"));
    let functions_port = free_port();
    let hub_port = free_port();
    let functions_port_text = functions_port.to_string();
    let hub_port_text = hub_port.to_string();
    let source = fixture("shutdown-signal");
    let daemon = ChildGuard::new(
        Command::new(env!("CARGO_BIN_EXE_fireemu"))
            .args([
                "up",
                "--project",
                &project,
                "--firestore-port",
                "0",
                "--http-port",
                "0",
                "--storage-port",
                "0",
                "--functions-port",
                &functions_port_text,
                "--eventarc-port",
                "0",
                "--tasks-port",
                "0",
                "--pubsub-port",
                "0",
                "--ui-port",
                "0",
                "--hub-port",
                &hub_port_text,
                "--logging-port",
                "0",
                "--functions",
                source.to_str().unwrap(),
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let daemon_pid = daemon.id();
    let armed = arm_shutdown_fixture(functions_port, &project, &marker);
    let runner_pid = i32::try_from(armed["runnerPid"].as_i64().unwrap()).unwrap();
    let child_pid = i32::try_from(armed["childPid"].as_i64().unwrap()).unwrap();
    let runner = census::find(runner_pid).expect("the Node runner is visible");
    let mut runner_group = ProcessGroupGuard::new(runner.pgid);
    assert_eq!(
        runner.pgid, runner_pid,
        "the runner leads its owned process group"
    );
    assert_eq!(
        census::find(child_pid)
            .expect("the fixture child is visible")
            .pgid,
        runner.pgid
    );
    assert!(
        locator.exists(),
        "the exact daemon locator was not published"
    );
    assert!(Command::new("kill")
        .args([signal, &daemon_pid.to_string()])
        .status()
        .unwrap()
        .success());
    let output = daemon.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(std::fs::read_to_string(&marker).unwrap(), "graceful\n");
    census::assert_process_group_empty(
        runner.pgid,
        "Functions runner signal shutdown",
        Duration::from_secs(5),
    );
    runner_group.disarm();
    assert_listener_closed(functions_port, "Functions", signal);
    assert_listener_closed(hub_port, "Hub", signal);
    assert!(!locator.exists(), "the Hub locator survived {signal}");
    assert!(
        census::alive(i32::try_from(unrelated.id()).unwrap()),
        "signal cleanup stopped an unrelated process"
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[cfg(unix)]
#[test]
#[ignore = "requires tools/sdk-smoke dependencies; CI runs this test after npm ci"]
fn sigterm_and_sigint_gracefully_shutdown_real_node_runners_and_their_children() {
    for (signal, label) in [("-TERM", "term"), ("-INT", "int")] {
        assert_signal_shutdown(signal, label);
    }
}

fn invoke_blocking_runner(port: u16, function: &str, body: &str) -> (u16, serde_json::Value) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    write!(
        stream,
        "POST /demo-blocking/us-central1/{function} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nX-Fireemu-Runner-Secret: test-secret\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    )
    .unwrap();
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).unwrap();
    let response = fireemu_adapter_functions::http::parse_response(&raw, "POST").unwrap();
    let body = serde_json::from_slice(&response.body).unwrap();
    (response.status, body)
}

fn assert_blocking_sign_in_contract(port: u16, before_create_body: &str) {
    let sign_in_body = before_create_body.replace(
        "providers/cloud.auth/eventTypes/user.beforeCreate",
        "providers/cloud.auth/eventTypes/user.beforeSignIn:oidc.corp",
    );
    let (status, response) = invoke_blocking_runner(port, "fxBeforeSignInContext", &sign_in_body);
    assert_eq!(status, 200, "{response}");
    assert_eq!(
        response["userRecord"]["sessionClaims"]["contextObserved"],
        true
    );
    for method in [
        "password",
        "anonymous",
        "custom",
        "emailLink",
        "phone",
        "oidc.corp",
        "saml.corp",
    ] {
        let method_body = before_create_body.replace(
            "providers/cloud.auth/eventTypes/user.beforeCreate",
            &format!("providers/cloud.auth/eventTypes/user.beforeSignIn:{method}"),
        );
        let (status, response) = invoke_blocking_runner(port, "fxBeforeSignInMethod", &method_body);
        assert_eq!(status, 200, "{method}: {response}");
        assert_eq!(
            response["userRecord"]["sessionClaims"]["observedEventType"],
            format!("providers/cloud.auth/eventTypes/user.beforeSignIn:{method}")
        );
    }
    let (status, response) = invoke_blocking_runner(port, "fxSessionClaimsAtLimit", &sign_in_body);
    assert_eq!(status, 200, "{response}");
    assert_eq!(
        response["userRecord"]["sessionClaims"]
            .to_string()
            .encode_utf16()
            .count(),
        1000
    );
    for function in ["fxSessionClaimsOverLimit", "fxCombinedClaimsOverLimit"] {
        let (status, response) = invoke_blocking_runner(port, function, &sign_in_body);
        assert_eq!(status, 400, "{function}: {response}");
        assert_eq!(
            response["error"]["status"], "INVALID_ARGUMENT",
            "{function}"
        );
    }
}

/// Functions scenario 5: an export whose product fireemu does not serve is named, not
/// dropped -- and by default it stops the run rather than pretending the trigger is live.
#[test]
#[ignore = "requires tools/sdk-smoke dependencies; CI runs this test after npm ci"]
fn a_trigger_of_a_product_the_daemon_does_not_serve_fails_discovery_by_name() {
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
#[ignore = "requires tools/sdk-smoke dependencies; CI runs this test after npm ci"]
fn the_report_policy_names_every_ignored_export_and_serves_the_rest() {
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
#[ignore = "requires tools/sdk-smoke dependencies; CI runs this test after npm ci"]
fn an_export_that_cannot_describe_itself_is_reported_rather_than_killing_the_runner() {
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
#[ignore = "requires tools/sdk-smoke dependencies; CI runs this test after npm ci"]
fn blocking_identity_exports_are_discovered_as_served_triggers() {
    let out = exec(&fixture("blocking-auth"), None);
    let err = stderr(&out);
    assert_eq!(out.status.code(), Some(0), "{err}");
    assert!(!err.contains("function ignored"), "{err}");
    assert!(!err.contains("blocking identity event"), "{err}");
}

#[test]
#[ignore = "requires tools/sdk-smoke dependencies; CI runs this test after npm ci"]
fn a_disconnected_never_settling_handler_is_destroyed_with_its_runner() {
    let script = r#"
set -eu
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
pid_url="http://$FIREEMU_FUNCTIONS_HOST/$GOOGLE_CLOUD_PROJECT/us-central1/fxPid"
signup_url="http://$FIREBASE_AUTH_EMULATOR_HOST/identitytoolkit.googleapis.com/v1/accounts:signUp?key=fake-api-key"
before=$(curl -fsS "$pid_url")
if curl -sS --max-time 0.2 -o /dev/null \
  -H 'content-type: application/json' \
  -d '{"email":"disconnected@example.test","password":"hunter22"}' \
  "$signup_url"; then
  echo 'the never-settling request unexpectedly completed' >&2
  exit 1
else
  test "$?" = 28
fi
status=$(curl -sS --max-time 2 -o "$scratch/response.json" -w '%{http_code}' \
  -H 'content-type: application/json' \
  -d '{"email":"overloaded@example.test","password":"hunter22"}' \
  "$signup_url")
printf 'blocking-status=%s blocking-body=' "$status"
cat "$scratch/response.json"
printf '\n'
test "$status" = 503
grep -q 'BLOCKING_FUNCTION_ERROR_RESPONSE' "$scratch/response.json"
after=""
attempt=0
while [ "$attempt" -lt 100 ]; do
  attempt=$((attempt + 1))
  after=$(curl -fsS "$pid_url" 2>/dev/null || true)
  if [ -n "$after" ] && [ "$after" != "$before" ]; then
    break
  fi
  sleep 0.1
done
printf 'runner-before=%s\nrunner-after=%s\n' "$before" "$after"
test -n "$after"
test "$after" != "$before"
"#;
    let source = fixture("blocking-auth-never-settles");
    let config = source.join("fireemu.json");
    let out = exec_command(&source, Some(&config), &["sh", "-c", script]);
    let err = stderr(&out);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        out.status.code(),
        Some(0),
        "stdout was:\n{stdout}\nstderr:\n{err}"
    );
    let pids = stdout
        .lines()
        .filter_map(|line| {
            line.strip_prefix("runner-before=")
                .or_else(|| line.strip_prefix("runner-after="))
        })
        .collect::<Vec<_>>();
    assert_eq!(pids.len(), 2, "stdout was:\n{stdout}\nstderr:\n{err}");
    assert_ne!(
        pids[0], pids[1],
        "the disconnected SDK Promise survived in the original runner"
    );
}

#[tokio::test]
#[ignore = "requires tools/sdk-smoke dependencies; CI runs this test after npm ci"]
async fn blocking_identity_exports_have_a_synchronous_runner_endpoint() {
    let runner_script =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tools/runner-node/index.mjs");
    let source = fixture("blocking-auth");
    let spec = SpawnSpec {
        command: vec![
            "node".to_owned(),
            runner_script.display().to_string(),
            "--source".to_owned(),
            source.display().to_string(),
            "--codebase".to_owned(),
            "default".to_owned(),
        ],
        cwd: None,
        env: vec![
            ("GCLOUD_PROJECT".to_owned(), "demo-blocking".to_owned()),
            ("FIREEMU_RUNNER_SECRET".to_owned(), "test-secret".to_owned()),
        ],
        hello_timeout: Duration::from_secs(20),
    };
    let runner = Runner::spawn_spec(&spec).await.unwrap();
    let port = runner
        .hello()
        .http_port
        .expect("blocking triggers need HTTP");
    let body = serde_json::json!({
        "data": {
            "user": {
                "uid": "user-1",
                "email": "a@example.com",
                "emailVerified": true,
                "displayName": "Input name",
                "photoURL": "https://example.test/input.png",
                "phoneNumber": "+15555550123",
                "disabled": false,
                "customClaims": {"role": "tester"},
                "metadata": {
                    "creationTime": "2026-08-29T12:01:00Z",
                    "lastSignInTime": "2026-08-30T12:01:00Z"
                },
                "providerData": [{
                    "uid": "provider-user",
                    "displayName": "Provider name",
                    "email": "provider@example.com",
                    "photoURL": "https://example.test/provider.png",
                    "providerId": "example.com",
                    "phoneNumber": null
                }]
            },
            "context": {"eventType": "providers/cloud.auth/eventTypes/user.beforeCreate"}
        }
    })
    .to_string();
    for function in ["fxBeforeCreate", "fxLegacyBeforeCreate"] {
        let (status, response) = invoke_blocking_runner(port, function, &body);
        assert_eq!(status, 200, "{function}");
        assert_eq!(
            response["userRecord"]["displayName"], "observed:Input name",
            "{function}"
        );
        assert_eq!(response["userRecord"]["updateMask"], "displayName");
    }
    assert_blocking_sign_in_contract(port, &body);
    for (function, status, canonical, message) in [
        (
            "fxPermissionDenied",
            403,
            "PERMISSION_DENIED",
            "fixture rejected",
        ),
        (
            "fxExplicitDeadline",
            504,
            "DEADLINE_EXCEEDED",
            "fixture deadline",
        ),
        (
            "fxEsmPermissionDenied",
            403,
            "PERMISSION_DENIED",
            "ESM fixture rejected",
        ),
        (
            "fxUnhandled",
            503,
            "UNAVAILABLE",
            "An unexpected error occurred.",
        ),
    ] {
        let (actual_status, response) = invoke_blocking_runner(port, function, &body);
        assert_eq!(actual_status, status, "{function}");
        assert_eq!(response["error"]["status"], canonical, "{function}");
        assert_eq!(response["error"]["message"], message, "{function}");
        assert!(!response.to_string().contains("private fixture marker"));
    }
    runner.shutdown().await;
}

/// `GlobalOptions` with local runtime meaning and every `ScheduleOptions` retry field survive
/// real SDK discovery; `omit` deliberately removes an export from emulation.
#[tokio::test]
#[ignore = "requires tools/sdk-smoke dependencies; CI runs this test after npm ci"]
async fn global_and_schedule_options_reach_the_runtime_manifest() {
    let runner_script =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tools/runner-node/index.mjs");
    let source = fixture("function-options");
    let spec = SpawnSpec {
        command: vec![
            "node".to_owned(),
            runner_script.display().to_string(),
            "--source".to_owned(),
            source.display().to_string(),
            "--codebase".to_owned(),
            "default".to_owned(),
        ],
        cwd: None,
        env: vec![
            ("GCLOUD_PROJECT".to_owned(), "demo-options".to_owned()),
            ("FIREEMU_RUNNER_SECRET".to_owned(), "test-secret".to_owned()),
            ("GLOBAL_CONCURRENCY".to_owned(), "3".to_owned()),
        ],
        hello_timeout: Duration::from_secs(20),
    };
    let runner = Runner::spawn_spec(&spec).await.unwrap();
    let manifest = runner.hello().manifest.as_ref().unwrap();
    let functions = manifest["functions"].as_array().unwrap();
    assert!(functions
        .iter()
        .all(|function| function["name"] != "fxOmitted"));
    let callable = functions
        .iter()
        .find(|function| function["name"] == "fxCallable")
        .unwrap();
    assert_eq!(callable["region"], "asia-northeast1");
    assert_eq!(callable["timeoutSeconds"], 17);
    assert_eq!(callable["concurrency"], 3);
    assert_eq!(callable["trigger"]["enforceAppCheck"], true);
    assert_eq!(callable["platformOptions"]["availableMemoryMb"], 512);
    assert_eq!(callable["platformOptions"]["cpu"], "1");
    assert_eq!(callable["platformOptions"]["minInstances"], 1);
    assert_eq!(callable["platformOptions"]["maxInstances"], 4);
    assert_eq!(callable["platformOptions"]["preserveExternalChanges"], true);
    assert_eq!(
        callable["platformOptions"]["ingressSettings"],
        "ALLOW_INTERNAL_ONLY"
    );
    assert_eq!(
        callable["platformOptions"]["serviceAccountEmail"],
        "runner@example.iam.gserviceaccount.com"
    );
    assert_eq!(
        callable["platformOptions"]["vpcConnector"],
        "projects/demo-options/locations/us-central1/connectors/default"
    );
    assert_eq!(
        callable["platformOptions"]["vpcEgressSettings"],
        "PRIVATE_RANGES_ONLY"
    );
    assert_eq!(
        callable["platformOptions"]["labels"],
        serde_json::json!({"fixture": "options"})
    );
    assert_eq!(
        callable["platformOptions"]["secrets"],
        serde_json::json!(["API_KEY"])
    );
    let http = functions
        .iter()
        .find(|function| function["name"] == "fxHttp")
        .unwrap();
    assert_eq!(
        http["platformOptions"]["invoker"],
        serde_json::json!(["public"])
    );
    let schedule = functions
        .iter()
        .find(|function| function["name"] == "fxSchedule")
        .unwrap();
    assert_eq!(schedule["region"], "europe-west1");
    assert_eq!(schedule["timeoutSeconds"], 23);
    assert_eq!(schedule["concurrency"], 2);
    assert_eq!(schedule["trigger"]["timeZone"], "America/New_York");
    assert_eq!(schedule["trigger"]["retryConfig"]["retryCount"], 4);
    assert_eq!(schedule["trigger"]["retryConfig"]["maxRetrySeconds"], 90);
    assert_eq!(schedule["trigger"]["retryConfig"]["minBackoffSeconds"], 3);
    assert_eq!(schedule["trigger"]["retryConfig"]["maxBackoffSeconds"], 30);
    assert_eq!(schedule["trigger"]["retryConfig"]["maxDoublings"], 2);
    runner.shutdown().await;
}

#[tokio::test]
#[ignore = "requires tools/sdk-smoke dependencies; CI runs this test after npm ci"]
async fn second_generation_omitted_concurrency_remains_defaultable() {
    let runner_script =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tools/runner-node/index.mjs");
    let source = fixture("omitted-concurrency");
    let runner = Runner::spawn_spec(&SpawnSpec {
        command: vec![
            "node".to_owned(),
            runner_script.display().to_string(),
            "--source".to_owned(),
            source.display().to_string(),
            "--codebase".to_owned(),
            "default".to_owned(),
        ],
        cwd: None,
        env: vec![
            ("GCLOUD_PROJECT".to_owned(), "demo-options".to_owned()),
            ("FIREEMU_RUNNER_SECRET".to_owned(), "test-secret".to_owned()),
        ],
        hello_timeout: Duration::from_secs(20),
    })
    .await
    .unwrap();
    let discovered_json = runner.hello().manifest.as_ref().unwrap().clone();
    runner.shutdown().await;
    let function = &discovered_json["functions"][0];
    assert_eq!(function["generation"], 2);
    assert!(function["concurrency"].is_null());
    assert_eq!(function["platformOptions"]["availableMemoryMb"], 2048);

    let discovered = parse_manifest(&discovered_json).unwrap();
    let configured = parse_manifest(&serde_json::json!({"functions": [{
        "name": function["name"],
        "generation": 2,
        "trigger": {"type": "http"},
        "platformOptions": {"availableMemoryMb": 2048}
    }]}))
    .unwrap();
    assert_eq!(
        discovered.functions[0].effective_concurrency(),
        configured.functions[0].effective_concurrency()
    );
    assert_eq!(
        discovered.functions[0].http_capacity(100),
        configured.functions[0].http_capacity(100)
    );
}

#[tokio::test]
#[ignore = "requires tools/sdk-smoke dependencies; CI runs this test after npm ci"]
async fn first_generation_capacity_matches_an_equivalent_configured_manifest() {
    let runner_script =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tools/runner-node/index.mjs");
    let source = fixture("gen1-options");
    let runner = Runner::spawn_spec(&SpawnSpec {
        command: vec![
            "node".to_owned(),
            runner_script.display().to_string(),
            "--source".to_owned(),
            source.display().to_string(),
            "--codebase".to_owned(),
            "default".to_owned(),
        ],
        cwd: None,
        env: vec![
            ("GCLOUD_PROJECT".to_owned(), "demo-options".to_owned()),
            ("FIREEMU_RUNNER_SECRET".to_owned(), "test-secret".to_owned()),
            ("GEN1_MEMORY_MB".to_owned(), "512".to_owned()),
            ("GEN1_MIN_INSTANCES".to_owned(), "1".to_owned()),
            ("GEN1_MAX_INSTANCES".to_owned(), "3".to_owned()),
        ],
        hello_timeout: Duration::from_secs(20),
    })
    .await
    .unwrap();
    let discovered_json = runner.hello().manifest.as_ref().unwrap().clone();
    runner.shutdown().await;

    let discovered = parse_manifest(&discovered_json).unwrap();
    let configured = parse_manifest(&serde_json::json!({"functions": [{
        "name": "fxV1",
        "generation": 1,
        "trigger": {"type": "http"},
        "platformOptions": {
            "availableMemoryMb": 512,
            "minInstances": 1,
            "maxInstances": 3,
            "ingressSettings": "ALLOW_INTERNAL_ONLY",
            "serviceAccountEmail": "runner@example.iam.gserviceaccount.com",
            "vpcConnector": "projects/demo-options/locations/us-central1/connectors/default",
            "vpcEgressSettings": "PRIVATE_RANGES_ONLY",
            "labels": {"fixture": "gen1"},
            "secrets": ["API_KEY"]
        }
    }]}))
    .unwrap();
    let discovered = &discovered.functions[0];
    let configured = &configured.functions[0];
    assert_eq!(
        discovered.generation,
        fireemu_core_functions::manifest::FunctionGeneration::First
    );
    assert!(discovered.concurrency.is_none());
    assert_eq!(discovered.platform_options, configured.platform_options);
    assert_eq!(
        discovered.effective_concurrency(),
        configured.effective_concurrency()
    );
    assert_eq!(discovered.http_capacity(100), configured.http_capacity(100));
    assert_eq!(discovered.http_capacity(100), 3);
}

#[tokio::test]
#[ignore = "requires tools/sdk-smoke dependencies; CI runs this test after npm ci"]
async fn esm_callable_app_check_options_are_observed_by_the_loaded_module_graph() {
    let runner_script =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tools/runner-node/index.mjs");
    let source = fixture("app-check-esm");
    let spec = SpawnSpec {
        command: vec![
            "node".to_owned(),
            runner_script.display().to_string(),
            "--source".to_owned(),
            source.display().to_string(),
            "--codebase".to_owned(),
            "default".to_owned(),
        ],
        cwd: None,
        env: vec![
            ("GCLOUD_PROJECT".to_owned(), "demo-app-check-esm".to_owned()),
            ("FIREEMU_RUNNER_SECRET".to_owned(), "test-secret".to_owned()),
            ("FIREBASE_DEBUG_MODE".to_owned(), "true".to_owned()),
            (
                "FIREBASE_DEBUG_FEATURES".to_owned(),
                r#"{"skipTokenVerification":true}"#.to_owned(),
            ),
        ],
        hello_timeout: Duration::from_secs(20),
    };
    let runner = Runner::spawn_spec(&spec).await.unwrap();
    let manifest = runner.hello().manifest.as_ref().unwrap();
    let functions = manifest["functions"].as_array().unwrap();
    let guarded = functions
        .iter()
        .find(|function| function["name"] == "guarded")
        .unwrap();
    assert_eq!(guarded["trigger"]["enforceAppCheck"], true);
    assert_eq!(guarded["trigger"]["consumeAppCheckToken"], "disabled");
    let replay = functions
        .iter()
        .find(|function| function["name"] == "replayProtected")
        .unwrap();
    assert_eq!(replay["trigger"]["consumeAppCheckToken"], "enabled");
    let report = runner.hello().app_check.as_ref().unwrap();
    assert_eq!(report["instrumentation"], "ok");
    assert_eq!(report["graphs"]["commonjs"], "instrumented");
    assert_eq!(report["graphs"]["esm"], "instrumented");
    runner.shutdown().await;
}
