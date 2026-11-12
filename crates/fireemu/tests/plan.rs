//! `fireemu up --plan` and `fireemu exec --plan -- <command>`: what a run would do, resolved by
//! the code start-up uses, without starting anything; and the inherited-emulator-environment
//! policy of `up` and `exec`.
//!
//! Every process runs with a cleared environment, an empty `HOME` and no credentials, so
//! nothing here can reach a Google service.

mod scratch;

use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use scratch::Scratch;
use serde_json::Value;

/// Runs `fireemu` in `cwd` with a cleared environment plus `env`, and kills it when it has not
/// finished in `limit`: a `--plan` that started a daemon would otherwise hang the test.
fn run(cwd: &Path, args: &[&str], env: &[(&str, &str)]) -> Output {
    let home = cwd.join(".home");
    std::fs::create_dir_all(&home).unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_fireemu"));
    command
        .current_dir(cwd)
        .args(args)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", &home)
        .envs(env.iter().copied())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let child = command.spawn().unwrap();
    let pid = child.id();
    let (sender, receiver) = std::sync::mpsc::channel();
    let waiter = std::thread::spawn(move || {
        let _ = sender.send(child.wait_with_output());
    });
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if let Ok(output) = receiver.recv_timeout(Duration::from_millis(100)) {
            waiter.join().unwrap();
            return output.unwrap();
        }
        if Instant::now() > deadline {
            // `pid` is the child this function spawned.
            #[cfg(unix)]
            let _ = Command::new("/bin/kill")
                .args(["-KILL", &pid.to_string()])
                .status();
            panic!("fireemu {args:?} did not finish: a plan must not start the emulators");
        }
    }
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn project(name: &str) -> Scratch {
    Scratch::new("plan", name)
}

fn write(dir: &Path, name: &str, text: &str) {
    let path = dir.join(name);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

fn json_plan(cwd: &Path, args: &[&str], env: &[(&str, &str)]) -> Value {
    let output = run(cwd, args, env);
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "not JSON ({error}); status {:?}\nstdout: {}\nstderr: {}",
            output.status,
            stdout(&output),
            stderr(&output)
        )
    })
}

fn service<'a>(plan: &'a Value, name: &str) -> &'a Value {
    plan["services"]
        .as_array()
        .unwrap()
        .iter()
        .find(|service| service["name"] == name)
        .unwrap_or_else(|| panic!("no {name} in {}", plan["services"]))
}

const FIREBASE_JSON: &str = r#"{
  "firestore": {"rules": "firestore.rules", "indexes": "firestore.indexes.json"},
  "emulators": {"firestore": {"port": 8181}, "auth": {"port": 9199}}
}"#;

#[test]
fn up_plan_reports_the_project_services_and_ports_without_starting_anything() {
    let dir = project("basic");
    write(&dir, "firebase.json", FIREBASE_JSON);
    write(
        &dir,
        ".firebaserc",
        r#"{"projects": {"default": "rc-project"}}"#,
    );
    let output = run(&dir, &["up", "--plan", "--hub-port", "0"], &[]);
    assert!(output.status.success(), "{}", stderr(&output));
    let text = stdout(&output);
    assert!(text.contains("rc-project"), "{text}");
    assert!(text.contains(".firebaserc"), "{text}");
    assert!(text.contains("127.0.0.1:8181"), "{text}");
    assert!(text.contains("firestore"), "{text}");
}

/// The text form up to the development defaults, with the working directory line removed.
fn text_head(output: &Output) -> String {
    let text = stdout(output);
    let head = text
        .split("\ndevelopment defaults")
        .next()
        .unwrap()
        .to_owned();
    head.lines()
        .filter(|line| !line.starts_with("working dir:"))
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn the_text_plan_reads_as_documented() {
    let dir = project("text");
    let output = run(
        &dir,
        &[
            "exec",
            "--plan",
            "--only",
            "firestore,auth",
            "--hub-port",
            "0",
            "--",
            "echo",
            "hi",
        ],
        &[("PUBSUB_EMULATOR_HOST", "localhost:8085")],
    );
    assert!(output.status.success(), "{}", stderr(&output));
    let expected = "\
fireemu plan (exec)
project:         demo-app (built-in default)
profile:         strict
configuration:   none found (no fireemu.toml or fireemu.json in the working directory, no firebase.json in it or the parents the search may enter); built-in defaults apply, so no Security Rules are loaded
override:        --only firestore,auth
override:        --hub-port 0
command:         echo hi

services
  firestore  start 127.0.0.1:8080
  auth       start 127.0.0.1:9099
  storage    off   not in --only
  functions  off   not in --only
  hosting    off   not in --only
  eventarc   off   starts only with a loaded Functions codebase
  tasks      off   starts only with a loaded Functions codebase
  pubsub     off   not in --only
  database   off   not in --only
  appcheck   off   not in --only
  hub        off   --hub-port 0 turns it off
  ui         off   off (exec starts it only with --ui; --ui-port 0 and emulators.ui.port 0 turn it off)
  logging    start 127.0.0.1:4500 (best effort unless the port was asked for)

environment
  sets FIRESTORE_EMULATOR_HOST, FIREBASE_FIRESTORE_EMULATOR_ADDRESS = 127.0.0.1:8080
  sets FIREBASE_AUTH_EMULATOR_HOST = 127.0.0.1:9099
  sets FIREBASE_LOGGING_EMULATOR_HOST = 127.0.0.1:4500
  PUBSUB_EMULATOR_HOST=localhost:8085 (inherited, kept: this run does not start the service)
  inherited emulator variables of services this run does not start: warn
";
    assert_eq!(text_head(&output), expected.trim_end());
}

#[test]
fn the_auxiliary_listeners_and_port_notes_follow_the_options() {
    let dir = project("aux");
    let plan = json_plan(
        &dir,
        &[
            "exec",
            "--plan",
            "--json",
            "--ui",
            "--ui-port",
            "auto",
            "--hub-port",
            "auto",
            "--logging-port",
            "0",
            "--firestore-port",
            "0",
            "--",
            "true",
        ],
        &[],
    );
    assert_eq!(service(&plan, "ui")["start"], true);
    assert_eq!(service(&plan, "hub")["start"], true);
    assert_eq!(service(&plan, "hub")["address"], "127.0.0.1:0");
    assert_eq!(service(&plan, "logging")["start"], false);
    assert!(service(&plan, "logging")["address"].is_null());
    assert_eq!(
        service(&plan, "firestore")["note"],
        "a free port is chosen at start"
    );
    assert!(service(&plan, "auth")["note"].is_null());
    assert_eq!(service(&plan, "ui")["auxiliary"], true);
    assert_eq!(service(&plan, "firestore")["auxiliary"], false);

    let up = json_plan(&dir, &["up", "--plan", "--json"], &[]);
    assert_eq!(service(&up, "ui")["start"], true);
    assert_eq!(service(&up, "hub")["start"], true);
    assert_eq!(service(&up, "hub")["address"], "127.0.0.1:4400");
    assert!(service(&up, "hub")["note"]
        .as_str()
        .unwrap()
        .contains("best effort"));
    assert_eq!(service(&up, "logging")["start"], true);

    let only = json_plan(
        &dir,
        &["up", "--plan", "--json", "--only", "firestore"],
        &[],
    );
    assert_eq!(service(&only, "appcheck")["start"], false);
    assert!(service(&only, "appcheck")["reason"]
        .as_str()
        .unwrap()
        .contains("--only"));
    assert!(service(&only, "appcheck")["address"].is_null());
    let all = json_plan(&dir, &["up", "--plan", "--json"], &[]);
    assert_eq!(service(&all, "appcheck")["start"], true);
    assert_eq!(service(&all, "appcheck")["address"], "127.0.0.1:9099");
    let without_auth = json_plan(
        &dir,
        &["up", "--plan", "--json", "--only", "appcheck,firestore"],
        &[],
    );
    assert_eq!(service(&without_auth, "appcheck")["start"], true);
    assert!(service(&without_auth, "appcheck")["address"]
        .as_str()
        .unwrap()
        .contains("control listener"));
}

#[test]
fn a_listener_that_is_off_has_a_reason_and_one_that_starts_has_none() {
    let dir = project("reasons");
    // Hub off, Logging off; the Hub on a port that was asked for has no best-effort note.
    let off = json_plan(
        &dir,
        &[
            "up",
            "--plan",
            "--json",
            "--hub-port",
            "0",
            "--logging-port",
            "0",
        ],
        &[],
    );
    for name in ["hub", "logging"] {
        assert_eq!(service(&off, name)["start"], false, "{name}");
        assert!(service(&off, name)["reason"].is_string(), "{name}: {off}");
        assert!(service(&off, name)["note"].is_null(), "{name}");
    }
    let on = json_plan(&dir, &["up", "--plan", "--json", "--hub-port", "4411"], &[]);
    assert_eq!(service(&on, "hub")["start"], true);
    assert_eq!(service(&on, "hub")["address"], "127.0.0.1:4411");
    assert!(
        service(&on, "hub")["note"].is_null(),
        "asked for: not best effort"
    );
    assert!(service(&on, "hub")["reason"].is_null());
    assert_eq!(service(&on, "logging")["start"], true);
    assert!(service(&on, "logging")["reason"].is_null(), "{on}");
}

#[test]
fn a_named_database_that_shares_the_default_files_still_has_its_own_rows() {
    let dir = project("shared-files");
    write(
        &dir,
        "firebase.json",
        r#"{"firestore": [
            {"database": "(default)", "rules": "same.rules", "indexes": "same.json"},
            {"database": "other", "rules": "same.rules", "indexes": "same.json"}
        ]}"#,
    );
    let plan = json_plan(&dir, &["up", "--plan", "--json"], &[]);
    let settings: Vec<&str> = plan["paths"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["setting"].as_str().unwrap())
        .collect();
    assert!(settings.contains(&"firestore[other].rules"), "{settings:?}");
    assert!(
        settings.contains(&"firestore[other].indexes"),
        "{settings:?}"
    );
    assert!(
        !settings
            .iter()
            .any(|setting| setting.starts_with("firestore[(default)]")),
        "{settings:?}"
    );
}

#[test]
fn hosting_and_the_support_emulators_say_when_and_how_they_start() {
    let dir = project("hosting");
    write(
        &dir,
        "firebase.json",
        r#"{"hosting": {"public": "pub"}, "emulators": {"eventarc": {"port": 9399}}}"#,
    );
    std::fs::create_dir_all(dir.join("pub")).unwrap();
    let plan = json_plan(&dir, &["up", "--plan", "--json"], &[]);
    assert_eq!(service(&plan, "hosting")["start"], true);
    assert_eq!(
        service(&plan, "hosting")["note"],
        "moves up to the next free port when busy"
    );
    assert_eq!(
        service(&plan, "eventarc")["start"],
        false,
        "no Functions codebase"
    );
    let fixed = json_plan(
        &dir,
        &["up", "--plan", "--json", "--hosting-port", "5050"],
        &[],
    );
    assert!(service(&fixed, "hosting")["note"].is_null());
    assert_eq!(service(&fixed, "hosting")["address"], "127.0.0.1:5050");
    let rows = fixed["paths"].as_array().unwrap();
    let public = rows
        .iter()
        .find(|row| row["setting"] == "hosting.public")
        .unwrap();
    assert_eq!(public["written"], "pub");
    assert_eq!(public["base"], "firebase.json directory");
    let off = run(
        &dir,
        &["up", "--plan", "--only", "hosting", "--no-config-discovery"],
        &[],
    );
    assert_eq!(
        off.status.code(),
        Some(1),
        "--only hosting without hosting.public is refused like start-up"
    );
    assert!(
        stderr(&off).contains("--only hosting requires hosting.public"),
        "{}",
        stderr(&off)
    );
}

#[test]
fn the_json_plan_names_the_project_and_where_it_came_from() {
    let dir = project("json");
    write(&dir, "firebase.json", FIREBASE_JSON);
    write(
        &dir,
        ".firebaserc",
        r#"{"projects": {"default": "rc-project", "staging": "stage-1"}}"#,
    );
    let plan = json_plan(&dir, &["up", "--plan", "--json"], &[]);
    assert_eq!(plan["planVersion"], 1);
    assert_eq!(plan["command"], "up");
    assert_eq!(plan["project"]["id"], "rc-project");
    assert_eq!(plan["project"]["source"], ".firebaserc default");

    let plan = json_plan(
        &dir,
        &["up", "--plan", "--json", "--project", "staging"],
        &[],
    );
    assert_eq!(plan["project"]["id"], "stage-1");
    assert_eq!(plan["project"]["source"], "--project alias in .firebaserc");

    let plan = json_plan(&dir, &["up", "--plan", "--json", "-P", "demo-direct"], &[]);
    assert_eq!(plan["project"]["id"], "demo-direct");
    assert_eq!(plan["project"]["source"], "--project");

    let bare = project("json-bare");
    let plan = json_plan(&bare, &["up", "--plan", "--json"], &[]);
    assert_eq!(plan["project"]["id"], "demo-app");
    assert_eq!(plan["project"]["source"], "built-in default");

    write(
        &bare,
        "fireemu.toml",
        "schemaVersion = 1\n[daemon]\nauthProject = \"demo-cfg\"\n",
    );
    let plan = json_plan(&bare, &["up", "--plan", "--json"], &[]);
    assert_eq!(plan["project"]["id"], "demo-cfg");
    assert_eq!(
        plan["project"]["source"],
        "daemon.authProject in fireemu.toml"
    );
}

#[test]
fn command_line_overrides_are_part_of_the_plan() {
    let dir = project("overrides");
    write(&dir, "firebase.json", FIREBASE_JSON);
    let plan = json_plan(
        &dir,
        &[
            "up",
            "--plan",
            "--json",
            "--only",
            "firestore,auth",
            "--firestore-port",
            "9100",
            "--hub-port",
            "0",
        ],
        &[],
    );
    let firestore = service(&plan, "firestore");
    assert_eq!(firestore["start"], true);
    assert_eq!(firestore["address"], "127.0.0.1:9100");
    assert_eq!(service(&plan, "storage")["start"], false);
    assert_eq!(service(&plan, "pubsub")["start"], false);
    let overrides: Vec<String> = plan["overrides"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| {
            format!(
                "{} {}",
                entry["flag"].as_str().unwrap(),
                entry["value"].as_str().unwrap()
            )
        })
        .collect();
    assert!(
        overrides.contains(&"--only firestore,auth".to_owned()),
        "{overrides:?}"
    );
    assert!(
        overrides.contains(&"--firestore-port 9100".to_owned()),
        "{overrides:?}"
    );
}

#[test]
fn an_unselected_service_says_why_it_does_not_start() {
    let dir = project("why");
    let plan = json_plan(
        &dir,
        &["up", "--plan", "--json", "--only", "firestore"],
        &[],
    );
    assert_eq!(service(&plan, "auth")["start"], false);
    assert!(
        service(&plan, "auth")["reason"]
            .as_str()
            .unwrap()
            .contains("--only"),
        "{plan}"
    );
    let plan = json_plan(&dir, &["up", "--plan", "--json"], &[]);
    assert_eq!(service(&plan, "functions")["start"], false);
    assert!(
        service(&plan, "functions")["reason"]
            .as_str()
            .unwrap()
            .contains("codebase"),
        "{plan}"
    );
    assert_eq!(service(&plan, "pubsub")["start"], false);
    assert_eq!(service(&plan, "firestore")["start"], true);
}

#[test]
fn exec_plan_shows_the_command_and_the_environment_it_would_receive() {
    let dir = project("exec");
    let plan = json_plan(
        &dir,
        &[
            "exec",
            "--plan",
            "--json",
            "--firestore-port",
            "8090",
            "--",
            "npm",
            "test",
        ],
        &[],
    );
    assert_eq!(plan["command"], "exec");
    assert_eq!(plan["exec"]["argv"], serde_json::json!(["npm", "test"]));
    let set: Vec<&str> = plan["environment"]["set"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|entry| entry["names"].as_array().unwrap())
        .map(|name| name.as_str().unwrap())
        .collect();
    assert!(set.contains(&"FIRESTORE_EMULATOR_HOST"), "{set:?}");
    assert!(set.contains(&"FIREBASE_AUTH_EMULATOR_HOST"), "{set:?}");
    assert!(!set.contains(&"PUBSUB_EMULATOR_HOST"), "{set:?}");

    let script = json_plan(
        &dir,
        &["exec", "--plan", "--json", "echo $FIRESTORE_EMULATOR_HOST"],
        &[],
    );
    assert_eq!(script["exec"]["script"], "echo $FIRESTORE_EMULATOR_HOST");
}

#[test]
fn a_parent_variable_for_a_service_this_run_does_not_start_is_reported_and_warned() {
    let dir = project("stale");
    let env = [
        ("PUBSUB_EMULATOR_HOST", "localhost:8085"),
        ("FIRESTORE_EMULATOR_HOST", "localhost:1234"),
    ];
    let plan = json_plan(
        &dir,
        &[
            "exec",
            "--plan",
            "--json",
            "--only",
            "firestore",
            "--",
            "true",
        ],
        &env,
    );
    let inherited = plan["environment"]["inherited"].as_array().unwrap();
    let find = |name: &str| {
        inherited
            .iter()
            .find(|entry| entry["name"] == name)
            .unwrap_or_else(|| panic!("{name} missing from {inherited:?}"))
    };
    assert_eq!(
        find("PUBSUB_EMULATOR_HOST")["disposition"],
        "kept-service-not-started"
    );
    assert_eq!(find("PUBSUB_EMULATOR_HOST")["service"], "pubsub");
    assert_eq!(find("FIRESTORE_EMULATOR_HOST")["disposition"], "overridden");
    assert_eq!(plan["environment"]["policy"], "warn");
    assert!(
        plan["warnings"]
            .to_string()
            .contains("PUBSUB_EMULATOR_HOST"),
        "{}",
        plan["warnings"]
    );
}

#[test]
fn credentials_in_an_inherited_storage_endpoint_are_not_printed() {
    let dir = project("redact");
    let env = [(
        "STORAGE_EMULATOR_HOST",
        "http://fireemu:s3cretcapability@127.0.0.1:9199",
    )];
    let output = run(
        &dir,
        &["exec", "--plan", "--only", "firestore", "--", "true"],
        &env,
    );
    let all = format!("{}{}", stdout(&output), stderr(&output));
    assert!(all.contains("STORAGE_EMULATOR_HOST"), "{all}");
    assert!(!all.contains("s3cretcapability"), "{all}");
}

#[test]
fn deny_inherited_emulator_env_fails_before_anything_starts() {
    let dir = project("deny");
    let env = [("PUBSUB_EMULATOR_HOST", "localhost:8085")];
    let output = run(
        &dir,
        &[
            "exec",
            "--deny-inherited-emulator-env",
            "--only",
            "firestore",
            "--firestore-port",
            "0",
            "--hub-port",
            "0",
            "--",
            "true",
        ],
        &env,
    );
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    let error = stderr(&output);
    assert!(error.contains("PUBSUB_EMULATOR_HOST"), "{error}");
    assert!(error.contains("--allow-inherited-emulator-env"), "{error}");
    assert!(
        !error.contains("firestore:"),
        "nothing was started: {error}"
    );
}

/// `exec` with every listener on a free port, so a real start is cheap.
const QUICK_EXEC: [&str; 11] = [
    "exec",
    "--only",
    "firestore",
    "--firestore-port",
    "0",
    "--hub-port",
    "0",
    "--ui-port",
    "0",
    "--logging-port",
    "0",
];

#[test]
fn by_default_a_stale_variable_is_warned_about_kept_and_the_command_runs() {
    let dir = project("warn-run");
    let env = [("PUBSUB_EMULATOR_HOST", "localhost:8085")];
    let mut args = QUICK_EXEC.to_vec();
    args.extend(["--", "/bin/sh", "-c", "echo seen=$PUBSUB_EMULATOR_HOST"]);
    let output = run(&dir, &args, &env);
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(
        stdout(&output).contains("seen=localhost:8085"),
        "the variable is kept: {}",
        stdout(&output)
    );
    let error = stderr(&output);
    assert!(
        error.contains("warning: PUBSUB_EMULATOR_HOST=localhost:8085"),
        "{error}"
    );
    assert!(error.contains("does not start pubsub"), "{error}");
}

#[test]
fn an_allowed_variable_is_neither_warned_about_nor_refused_and_quiet_prints_nothing() {
    let dir = project("allow-run");
    let env = [("PUBSUB_EMULATOR_HOST", "localhost:8085")];
    let mut args = QUICK_EXEC.to_vec();
    args.extend([
        "--deny-inherited-emulator-env",
        "--allow-inherited-emulator-env",
        "PUBSUB_EMULATOR_HOST",
        "--",
        "true",
    ]);
    let output = run(&dir, &args, &env);
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(
        !stderr(&output).contains("PUBSUB_EMULATOR_HOST"),
        "{}",
        stderr(&output)
    );

    let mut quiet = QUICK_EXEC.to_vec();
    quiet.extend(["--log-verbosity", "quiet", "--", "true"]);
    let output = run(&dir, &quiet, &env);
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(
        !stderr(&output).contains("PUBSUB_EMULATOR_HOST"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn a_started_services_variable_is_replaced_by_the_run_and_never_warned_about() {
    let dir = project("replaced-run");
    let env = [("FIRESTORE_EMULATOR_HOST", "localhost:1234")];
    let mut args = QUICK_EXEC.to_vec();
    args.extend([
        "--deny-inherited-emulator-env",
        "--",
        "/bin/sh",
        "-c",
        "echo seen=$FIRESTORE_EMULATOR_HOST",
    ]);
    let output = run(&dir, &args, &env);
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(
        stdout(&output).contains("seen=127.0.0.1:"),
        "{}",
        stdout(&output)
    );
    assert!(
        !stderr(&output).contains("FIRESTORE_EMULATOR_HOST"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn deny_applies_to_up_as_well() {
    let dir = project("deny-up");
    let env = [("FIREBASE_DATABASE_EMULATOR_HOST", "localhost:9000")];
    let output = run(
        &dir,
        &[
            "up",
            "--deny-inherited-emulator-env",
            "--only",
            "firestore",
            "--hub-port",
            "0",
        ],
        &env,
    );
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    assert!(stderr(&output).contains("FIREBASE_DATABASE_EMULATOR_HOST"));
}

#[test]
fn the_plan_applies_the_deny_policy_and_exits_nonzero() {
    let dir = project("deny-plan");
    let env = [("PUBSUB_EMULATOR_HOST", "localhost:8085")];
    let args = [
        "up",
        "--plan",
        "--json",
        "--deny-inherited-emulator-env",
        "--only",
        "firestore",
    ];
    let output = run(&dir, &args, &env);
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    let plan: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(plan["environment"]["policy"], "deny");
    assert_eq!(
        plan["environment"]["denied"],
        serde_json::json!(["PUBSUB_EMULATOR_HOST"])
    );
    assert!(stderr(&output).contains("PUBSUB_EMULATOR_HOST"));
}

#[test]
fn an_allowed_variable_does_not_fail_the_deny_policy() {
    let dir = project("allow");
    let env = [("PUBSUB_EMULATOR_HOST", "localhost:8085")];
    let output = run(
        &dir,
        &[
            "up",
            "--plan",
            "--json",
            "--deny-inherited-emulator-env",
            "--allow-inherited-emulator-env",
            "PUBSUB_EMULATOR_HOST",
            "--only",
            "firestore",
        ],
        &env,
    );
    assert!(output.status.success(), "{}", stderr(&output));
    let plan: Value = serde_json::from_slice(&output.stdout).unwrap();
    let entry = &plan["environment"]["inherited"][0];
    assert_eq!(entry["name"], "PUBSUB_EMULATOR_HOST");
    assert_eq!(entry["disposition"], "kept-allowed");
    assert_eq!(plan["environment"]["denied"], serde_json::json!([]));
    assert!(plan["warnings"]
        .to_string()
        .find("PUBSUB_EMULATOR_HOST")
        .is_none());
}

#[test]
fn a_variable_for_a_started_service_is_overridden_and_never_denied() {
    let dir = project("started");
    let env = [("FIRESTORE_EMULATOR_HOST", "localhost:1234")];
    let output = run(
        &dir,
        &[
            "up",
            "--plan",
            "--json",
            "--deny-inherited-emulator-env",
            "--only",
            "firestore",
        ],
        &env,
    );
    assert!(output.status.success(), "{}", stderr(&output));
}

#[test]
fn an_unknown_allowed_name_is_a_usage_error() {
    let dir = project("allow-typo");
    let output = run(
        &dir,
        &[
            "up",
            "--plan",
            "--allow-inherited-emulator-env",
            "PUBSUB_EMULATOR_HOSTT",
        ],
        &[],
    );
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    let error = stderr(&output);
    assert!(error.contains("PUBSUB_EMULATOR_HOSTT"), "{error}");
    assert!(
        error.contains("PUBSUB_EMULATOR_HOST"),
        "the message lists the names: {error}"
    );
}

#[test]
fn json_needs_plan() {
    let dir = project("json-alone");
    let output = run(&dir, &["up", "--json"], &[]);
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    assert!(stderr(&output).contains("--plan"));
}

#[test]
fn paths_name_their_base_and_a_different_working_directory_is_warned() {
    let dir = project("paths");
    write(
        &dir,
        "firebase.json",
        r#"{"firestore": {"rules": "from-firebase.rules"}}"#,
    );
    write(&dir, "sub/fireemu.toml", "schemaVersion = 1\n[rules]\nsource = \"canonical.rules\"\n[firestore]\nindexFile = \"idx.json\"\n");
    // Canonical-configuration paths resolve against the working directory.
    let plan = json_plan(
        &dir,
        &[
            "up",
            "--plan",
            "--json",
            "--config",
            "sub/fireemu.toml",
            "--no-config-discovery",
        ],
        &[],
    );
    let paths = plan["paths"].as_array().unwrap();
    let rules = paths
        .iter()
        .find(|p| p["setting"] == "rules.source")
        .unwrap();
    assert_eq!(rules["written"], "canonical.rules");
    assert_eq!(rules["base"], "working directory");
    assert!(rules["resolved"]
        .as_str()
        .unwrap()
        .ends_with("/canonical.rules"));
    assert!(
        !rules["resolved"].as_str().unwrap().contains("/sub/"),
        "{rules}"
    );
    let warnings = plan["warnings"].to_string();
    assert!(warnings.contains("canonical.rules"), "{warnings}");
    assert!(warnings.contains("working directory"), "{warnings}");

    // Run from the configuration's own directory, the same file resolves elsewhere.
    let from_sub = json_plan(
        &dir.join("sub"),
        &[
            "up",
            "--plan",
            "--json",
            "--config",
            "fireemu.toml",
            "--no-config-discovery",
        ],
        &[],
    );
    let rules = from_sub["paths"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["setting"] == "rules.source")
        .unwrap()
        .clone();
    assert!(
        rules["resolved"]
            .as_str()
            .unwrap()
            .contains("/sub/canonical.rules"),
        "{rules}"
    );
    assert!(
        !from_sub["warnings"].to_string().contains("canonical.rules"),
        "{}",
        from_sub["warnings"]
    );

    // firebase.json paths resolve against the directory of firebase.json.
    let plan = json_plan(
        &dir,
        &["up", "--plan", "--json", "--firebase-json", "firebase.json"],
        &[],
    );
    let rules = plan["paths"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["setting"] == "rules.source")
        .unwrap()
        .clone();
    assert_eq!(rules["written"], "from-firebase.rules");
    assert_eq!(rules["base"], "firebase.json directory");
    assert!(rules["resolved"]
        .as_str()
        .unwrap()
        .ends_with("/from-firebase.rules"));
}

#[test]
fn ineffective_settings_and_development_defaults_come_from_the_shared_sources() {
    let dir = project("lint");
    write(
        &dir,
        "fireemu.toml",
        "schemaVersion = 1\n[trace]\nenabled = true\n",
    );
    let plan = json_plan(&dir, &["up", "--plan", "--json"], &[]);
    let ineffective: Vec<&str> = plan["ineffective"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["key"].as_str().unwrap())
        .collect();
    assert_eq!(ineffective, ["trace.enabled"]);

    let defaults = plan["developmentDefaults"].as_array().unwrap();
    assert!(!defaults.is_empty());
    let relaxed = defaults
        .iter()
        .filter(|entry| entry["relaxed"] == true)
        .count();
    assert!(relaxed > 0, "{defaults:?}");

    write(
        &dir,
        "fireemu.toml",
        "schemaVersion = 1\nprofile = \"strict\"\nproductionExact = true\n",
    );
    let exact = json_plan(&dir, &["up", "--plan", "--json"], &[]);
    assert_eq!(exact["productionExact"], true);
    assert!(exact["developmentDefaults"]
        .as_array()
        .unwrap()
        .iter()
        .all(|entry| entry["relaxed"] == false));
}

#[test]
fn a_configuration_the_daemon_refuses_fails_the_plan_with_the_same_message() {
    let dir = project("refused");
    write(&dir, "fireemu.toml", "schemaVersion = 1\nbogus = 1\n");
    let plan = run(&dir, &["up", "--plan"], &[]);
    let start = run(&dir, &["up"], &[]);
    assert_eq!(plan.status.code(), start.status.code());
    assert_eq!(stderr(&plan), stderr(&start));
    assert_ne!(plan.status.code(), Some(0));
}

#[test]
fn the_refusal_names_every_stale_variable_and_agrees_in_number() {
    let dir = project("denial");
    let one = run(
        &dir,
        &[
            "up",
            "--plan",
            "--deny-inherited-emulator-env",
            "--only",
            "firestore",
        ],
        &[("PUBSUB_EMULATOR_HOST", "localhost:8085")],
    );
    let error = stderr(&one);
    assert!(error.contains("PUBSUB_EMULATOR_HOST is set in the environment for a service this run does not start (pubsub)"), "{error}");
    assert!(
        error.contains("unset it, start the service, or keep it with"),
        "{error}"
    );

    let two = run(
        &dir,
        &[
            "up",
            "--plan",
            "--deny-inherited-emulator-env",
            "--only",
            "firestore",
        ],
        &[
            ("PUBSUB_EMULATOR_HOST", "localhost:8085"),
            ("CLOUD_TASKS_EMULATOR_HOST", "localhost:9499"),
            ("FIREBASE_DATABASE_EMULATOR_HOST", "localhost:9000"),
        ],
    );
    let error = stderr(&two);
    assert!(error.contains("CLOUD_TASKS_EMULATOR_HOST, PUBSUB_EMULATOR_HOST, FIREBASE_DATABASE_EMULATOR_HOST are set in the environment"), "{error}");
    assert!(
        error.contains("(database, pubsub, tasks)"),
        "services are listed once, sorted: {error}"
    );
    assert!(
        error.contains("unset them, start the service, or keep them with"),
        "{error}"
    );
}

#[test]
fn the_named_databases_have_their_own_rows_and_the_default_one_is_not_listed_twice() {
    let dir = project("databases");
    write(
        &dir,
        "firebase.json",
        r#"{"firestore": [
            {"database": "(default)", "rules": "default.rules", "indexes": "default.json"},
            {"database": "other", "rules": "other.rules", "indexes": "other.json"}
        ]}"#,
    );
    let plan = json_plan(&dir, &["up", "--plan", "--json"], &[]);
    let settings: Vec<&str> = plan["paths"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["setting"].as_str().unwrap())
        .collect();
    assert!(settings.contains(&"rules.source"), "{settings:?}");
    assert!(settings.contains(&"firestore.indexFile"), "{settings:?}");
    assert!(settings.contains(&"firestore[other].rules"), "{settings:?}");
    assert!(
        settings.contains(&"firestore[other].indexes"),
        "{settings:?}"
    );
    assert!(
        !settings
            .iter()
            .any(|setting| setting.starts_with("firestore[(default)]")),
        "{settings:?}"
    );
}

#[test]
fn a_python_codebase_is_refused_the_app_check_trust_only_when_the_run_enables_it() {
    let dir = project("python-app-check");
    write(
        &dir,
        "firebase.json",
        r#"{"functions": {"source": "py", "runtime": "python312"}}"#,
    );
    write(&dir, "py/requirements.txt", "firebase-functions\n");
    // The development default serves App Check without asking for it: the Python codebase gets
    // as far as the missing virtual environment.
    let implicit = json_plan(&dir, &["up", "--plan", "--json", "--hub-port", "0"], &[]);
    let error = implicit["functions"][0]["error"].as_str().unwrap();
    assert!(error.contains("Missing virtual environment"), "{error}");
    assert_eq!(implicit["functions"][0]["language"], "python");

    // An App Check the configuration asks for is refused for Python before anything runs.
    write(
        &dir,
        "fireemu.toml",
        "schemaVersion = 1\nfirebaseJson = \"firebase.json\"\n[appCheck]\nenabled = true\n",
    );
    let explicit = json_plan(&dir, &["up", "--plan", "--json", "--hub-port", "0"], &[]);
    let error = explicit["functions"][0]["error"].as_str().unwrap();
    assert!(
        error.contains("App Check for Python callables is not available yet"),
        "{error}"
    );
    assert!(explicit["functions"][0]["runner"]["command"].is_null());
}

#[test]
fn the_text_plan_reports_inherited_variables_paths_defaults_and_ineffective_settings() {
    let dir = project("text-rich");
    write(
        &dir,
        "firebase.json",
        r#"{"firestore": {"rules": "fs.rules"}}"#,
    );
    write(
        &dir,
        "fireemu.toml",
        "schemaVersion = 1\nprofile = \"strict\"\nproductionExact = true\nfirebaseJson = \"firebase.json\"\n[trace]\nenabled = true\n",
    );
    let output = run(
        &dir,
        &[
            "up",
            "--plan",
            "--only",
            "firestore",
            "--allow-inherited-emulator-env",
            "PUBSUB_EMULATOR_HOST",
        ],
        &[
            ("FIRESTORE_EMULATOR_HOST", "localhost:1234"),
            ("PUBSUB_EMULATOR_HOST", "localhost:8085"),
            ("CLOUD_TASKS_EMULATOR_HOST", "localhost:9499"),
        ],
    );
    assert!(output.status.success(), "{}", stderr(&output));
    let text = stdout(&output);
    for line in [
        "fireemu plan (up)",
        "profile:         strict, productionExact",
        "  FIRESTORE_EMULATOR_HOST=localhost:1234 (inherited, replaced by this run's value)",
        "  PUBSUB_EMULATOR_HOST=localhost:8085 (inherited, kept (allowed))",
        "  CLOUD_TASKS_EMULATOR_HOST=localhost:9499 (inherited, kept: this run does not start the service)",
        "  inherited emulator variables of services this run does not start: warn",
        "paths (resolved as the run opens them)",
        "development defaults in effect (productionExact switches the relaxed ones to production's value)",
        "  auth.allowUnsignedIdTokens = false (productionExact)",
        "settings accepted but with no effect",
        "  trace.enabled is accepted for forward compatibility and currently has no effect",
        "No port was probed and nothing was started; the run binds its ports when it starts.",
    ] {
        assert!(text.lines().any(|candidate| candidate == line), "missing line {line:?} in:\n{text}");
    }
    let path_line = text
        .lines()
        .find(|line| line.starts_with("  rules.source: "))
        .expect("a rules.source path");
    assert!(
        path_line.contains("(written fs.rules, relative to the firebase.json directory "),
        "{path_line}"
    );
    let reference = text
        .lines()
        .find(|line| line.starts_with("  firebaseJson: "))
        .expect("a firebaseJson path");
    assert!(
        reference.contains("relative to the configuration file directory"),
        "{reference}"
    );
    assert!(
        text.contains("\nwarning: CLOUD_TASKS_EMULATOR_HOST=localhost:9499 is inherited from the environment, but this run does not start tasks;"),
        "{text}"
    );
    assert!(
        !text.lines().any(|line| line.ends_with(" relaxed")),
        "productionExact leaves nothing relaxed:\n{text}"
    );

    // An error of the plan is printed in the text and again on standard error.
    let denied = run(
        &dir,
        &[
            "up",
            "--plan",
            "--only",
            "firestore",
            "--deny-inherited-emulator-env",
        ],
        &[("CLOUD_TASKS_EMULATOR_HOST", "localhost:9499")],
    );
    assert_eq!(denied.status.code(), Some(1));
    assert!(
        stdout(&denied).contains("\nerror: CLOUD_TASKS_EMULATOR_HOST is set in the environment"),
        "{}",
        stdout(&denied)
    );
    assert!(
        stderr(&denied).contains("\nerror: CLOUD_TASKS_EMULATOR_HOST is set"),
        "{}",
        stderr(&denied)
    );
}

#[cfg(unix)]
mod functions {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn fake_node(path: &Path, version: &str) {
        fake_node_with(path, version, true);
    }

    /// A `node` that answers `--version` and the loader-feature probe, nothing else.
    fn fake_node_with(path: &Path, version: &str, require_module: bool) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(
            path,
            format!("#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then echo '{version}'; exit 0; fi\necho {require_module}\n"),
        )
        .unwrap();
        let mut permissions = std::fs::metadata(path).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(path, permissions).unwrap();
    }

    fn codebase(dir: &Path) {
        write(
            dir,
            "firebase.json",
            r#"{"functions": {"source": "functions", "runtime": "nodejs20"}}"#,
        );
        write(
            dir,
            "functions/package.json",
            r#"{"name": "f", "engines": {"node": "20"}}"#,
        );
        write(
            dir,
            "functions/node_modules/firebase-functions/package.json",
            r#"{"name": "firebase-functions", "version": "6.1.0"}"#,
        );
        write(
            dir,
            "functions/node_modules/firebase-admin/package.json",
            r#"{"name": "firebase-admin", "version": "13.0.1"}"#,
        );
    }

    #[test]
    fn the_plan_names_the_node_the_runner_would_select_and_the_sdk_versions() {
        let dir = project("node");
        codebase(&dir);
        let explicit = dir.join("tools/node-explicit/bin/node");
        let on_path = dir.join("tools/node-path/node");
        fake_node(&explicit, "v22.11.0");
        fake_node(&on_path, "v18.20.0");
        let path = format!("{}:/usr/bin:/bin", on_path.parent().unwrap().display());
        let plan = json_plan(
            &dir,
            &["up", "--plan", "--json", "--hub-port", "0"],
            &[
                ("FIREEMU_NODE", explicit.to_str().unwrap()),
                ("PATH", &path),
            ],
        );
        assert_eq!(service(&plan, "functions")["start"], true);
        let codebase = &plan["functions"][0];
        assert_eq!(codebase["codebase"], "default");
        assert_eq!(codebase["language"], "node");
        assert_eq!(
            codebase["runner"]["interpreter"],
            explicit.to_str().unwrap()
        );
        assert_eq!(codebase["runner"]["version"], "22.11.0");
        assert_eq!(codebase["sdk"]["firebase-functions"], "6.1.0");
        assert_eq!(codebase["sdk"]["firebase-admin"], "13.0.1");
        assert!(codebase["source"].as_str().unwrap().ends_with("/functions"));
        assert!(codebase["error"].is_null(), "{codebase}");

        // Without FIREEMU_NODE the PATH one is selected.
        let plan = json_plan(
            &dir,
            &["up", "--plan", "--json", "--hub-port", "0"],
            &[("PATH", &path)],
        );
        assert_eq!(
            plan["functions"][0]["runner"]["interpreter"],
            on_path.to_str().unwrap()
        );
        assert_eq!(plan["functions"][0]["runner"]["version"], "18.20.0");
    }

    #[test]
    fn doctor_reports_the_node_the_functions_runner_selects_not_the_first_on_path() {
        let dir = project("doctor");
        let explicit = dir.join("tools/node-explicit/bin/node");
        let on_path = dir.join("tools/node-path/node");
        fake_node(&explicit, "v22.11.0");
        fake_node(&on_path, "v18.20.0");
        let path = format!("{}:/usr/bin:/bin", on_path.parent().unwrap().display());
        let output = run(
            &dir,
            &["doctor"],
            &[
                ("FIREEMU_NODE", explicit.to_str().unwrap()),
                ("PATH", &path),
            ],
        );
        let text = stdout(&output);
        let node_line = text
            .lines()
            .find(|line| line.contains(" node "))
            .unwrap_or_else(|| panic!("{text}"));
        assert!(node_line.contains("v22.11.0"), "{node_line}");
        assert!(
            node_line.contains(explicit.to_str().unwrap()),
            "{node_line}"
        );
        assert!(node_line.contains("FIREEMU_NODE"), "{node_line}");
    }

    #[test]
    fn doctor_names_a_node_override_that_cannot_run_instead_of_reporting_the_path_one() {
        let dir = project("doctor-bad");
        let on_path = dir.join("tools/node-path/node");
        fake_node(&on_path, "v18.20.0");
        let path = format!("{}:/usr/bin:/bin", on_path.parent().unwrap().display());
        let output = run(
            &dir,
            &["doctor"],
            &[("FIREEMU_NODE", "/nonexistent/node"), ("PATH", &path)],
        );
        let text = stdout(&output);
        assert!(text.contains("FIREEMU_NODE"), "{text}");
        assert!(!text.contains("v18.20.0"), "{text}");
    }

    #[test]
    fn a_plan_with_no_usable_node_reports_the_error_and_fails() {
        let dir = project("no-node");
        codebase(&dir);
        let output = run(
            &dir,
            &["up", "--plan", "--json", "--hub-port", "0"],
            &[("FIREEMU_NODE", "/nonexistent/node")],
        );
        assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
        let plan: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert!(
            plan["functions"][0]["error"]
                .as_str()
                .unwrap()
                .contains("FIREEMU_NODE"),
            "{plan}"
        );
    }

    /// The notes of the plan are the `note:` lines start-up prints for the same choice.
    fn plan_notes(
        name: &str,
        runtime: Option<&str>,
        engines: Option<&str>,
        require_module: bool,
    ) -> Vec<String> {
        let dir = project(name);
        let runtime = runtime.map_or(String::new(), |runtime| {
            format!(", \"runtime\": \"{runtime}\"")
        });
        write(
            &dir,
            "firebase.json",
            &format!(r#"{{"functions": {{"source": "functions"{runtime}}}}}"#),
        );
        let engines = engines.map_or(String::new(), |engines| {
            format!(", \"engines\": {{\"node\": \"{engines}\"}}")
        });
        write(
            &dir,
            "functions/package.json",
            &format!(r#"{{"name": "f"{engines}}}"#),
        );
        let node = dir.join("tools/node/bin/node");
        fake_node_with(&node, "v22.11.0", require_module);
        let plan = json_plan(
            &dir,
            &["up", "--plan", "--json", "--hub-port", "0"],
            &[("FIREEMU_NODE", node.to_str().unwrap())],
        );
        plan["functions"][0]["notes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|note| note.as_str().unwrap().to_owned())
            .collect()
    }

    #[test]
    fn the_plan_carries_the_notes_start_up_prints_about_the_node_choice() {
        let notes = plan_notes("notes-engine", None, Some(">=20"), true);
        assert_eq!(
            notes,
            ["note: functions[default]: selected Node v22.11.0 for package.json engines.node \">=20\""]
        );
        let notes = plan_notes("notes-engine-runtime", Some("nodejs20"), Some(">=20"), true);
        assert_eq!(
            notes,
            ["note: functions[default]: selected Node v22.11.0 for package.json engines.node \">=20\" (firebase runtime nodejs20 is deployment metadata)"]
        );
        let notes = plan_notes("notes-fallback", None, Some("18"), true);
        assert_eq!(
            notes,
            ["note: functions[default]: selected Node v22.11.0 as a loader-capable local fallback; package.json engines.node \"18\" does not include it"]
        );
        let notes = plan_notes("notes-runtime", Some("nodejs18"), None, true);
        assert_eq!(
            notes,
            ["note: functions[default]: firebase runtime nodejs18 differs from local Node v22.11.0; the local emulator uses the first usable Node on PATH"]
        );
        assert_eq!(
            plan_notes("notes-same", Some("nodejs22"), None, true),
            Vec::<String>::new()
        );
        assert_eq!(
            plan_notes("notes-none", None, None, true),
            Vec::<String>::new()
        );
        let notes = plan_notes("notes-no-require", Some("nodejs22"), None, false);
        assert_eq!(
            notes,
            ["note: functions[default]: Node v22.11.0 cannot synchronously require ES modules from CommonJS; install Node 20.19+, Node 22.12+, or a newer release if module loading fails"]
        );
    }

    #[test]
    fn a_functions_runner_override_is_reported_as_such_and_no_node_is_probed() {
        let dir = project("override");
        write(
            &dir,
            "firebase.json",
            r#"{"functions": {"source": "functions"}}"#,
        );
        write(&dir, "functions/package.json", r#"{"name": "f"}"#);
        write(&dir, "fireemu.toml", "schemaVersion = 1\n[functions]\nrunner = [\"/bin/echo\", \"x\"]\nsource = \"functions\"\n");
        let plan = json_plan(
            &dir,
            &["up", "--plan", "--json", "--hub-port", "0"],
            &[("FIREEMU_NODE", "/nonexistent/node")],
        );
        let runner = &plan["functions"][0]["runner"];
        assert_eq!(runner["override"], true, "{plan}");
        assert_eq!(
            runner["command"],
            serde_json::json!(["/bin/echo", "[redacted]"])
        );
        assert!(runner["interpreter"].is_null());
        assert!(plan["functions"][0]["error"].is_null(), "{plan}");
    }

    #[test]
    fn a_codebase_whose_source_is_missing_reports_the_start_up_refusal() {
        let dir = project("missing-source");
        write(
            &dir,
            "firebase.json",
            r#"{"functions": {"source": "nowhere"}}"#,
        );
        let output = run(&dir, &["up", "--plan", "--json", "--hub-port", "0"], &[]);
        assert_eq!(output.status.code(), Some(1));
        let plan: Value = serde_json::from_slice(&output.stdout).unwrap();
        let error = plan["functions"][0]["error"].as_str().unwrap();
        assert!(error.contains("is not a directory"), "{error}");
        assert!(plan["functions"][0]["source"].is_null());
    }

    #[test]
    fn the_text_plan_names_the_interpreter_sdk_versions_and_the_error_of_each_codebase() {
        let dir = project("text-functions");
        codebase(&dir);
        let node = dir.join("tools/node/bin/node");
        fake_node(&node, "v22.11.0");
        let output = run(
            &dir,
            &["up", "--plan", "--hub-port", "0"],
            &[("FIREEMU_NODE", node.to_str().unwrap())],
        );
        assert!(output.status.success(), "{}", stderr(&output));
        let text = stdout(&output);
        assert!(text.contains("\nfunctions\n  default: "), "{text}");
        assert!(
            text.contains(&format!(" on node 22.11.0 ({})", node.display())),
            "{text}"
        );
        assert!(
            text.contains("\n      firebase-admin 13.0.1\n      firebase-functions 6.1.0\n"),
            "{text}"
        );
        assert!(text.contains("\n      note: functions[default]: selected Node v22.11.0 as a loader-capable local fallback;") || text.contains("selected Node v22.11.0 for package.json engines.node"), "{text}");

        write(&dir, "fireemu.toml", "schemaVersion = 1\nfirebaseJson = \"firebase.json\"\n[functions]\nrunner = [\"/bin/echo\", \"x\"]\n");
        let overridden = run(&dir, &["up", "--plan", "--hub-port", "0"], &[]);
        assert!(
            stdout(&overridden).contains(" on functions.runner override"),
            "{}",
            stdout(&overridden)
        );

        let missing = project("text-functions-missing");
        write(
            &missing,
            "firebase.json",
            r#"{"functions": {"source": "nowhere"}}"#,
        );
        let output = run(&missing, &["up", "--plan", "--hub-port", "0"], &[]);
        assert_eq!(output.status.code(), Some(1));
        assert!(stdout(&output).contains("      cannot start: the Functions codebase \"default\": source \"./nowhere\" is not a directory"), "{}", stdout(&output));
    }

    fn doctor_node_line(dir: &Path, env: &[(&str, &str)]) -> (String, Option<i32>) {
        let output = run(dir, &["doctor"], env);
        let text = stdout(&output);
        let line = text
            .lines()
            .find(|line| line.contains(" node "))
            .unwrap_or_else(|| panic!("{text}"))
            .to_owned();
        (line, output.status.code())
    }

    #[test]
    fn doctor_reports_where_the_node_came_from_and_when_there_is_none() {
        // The first node on PATH.
        let dir = project("doctor-sources");
        let on_path = dir.join("tools/path/node");
        fake_node(&on_path, "v20.19.5");
        let path = on_path.parent().unwrap().to_str().unwrap().to_owned();
        let (line, code) = doctor_node_line(&dir, &[("PATH", &path)]);
        assert!(line.starts_with("ok "), "{line}");
        assert!(
            line.contains("v20.19.5") && line.contains("selected by first node on PATH"),
            "{line}"
        );
        assert_eq!(code, Some(0));

        // VOLTA_HOME, when PATH has none.
        let volta = dir.join("volta");
        fake_node(&volta.join("tools/image/node/22.11.0/bin/node"), "v22.11.0");
        let empty = dir.join("empty");
        std::fs::create_dir_all(&empty).unwrap();
        let (line, _) = doctor_node_line(
            &dir,
            &[
                ("PATH", empty.to_str().unwrap()),
                ("VOLTA_HOME", volta.to_str().unwrap()),
            ],
        );
        assert!(
            line.contains("v22.11.0") && line.contains("selected by VOLTA_HOME"),
            "{line}"
        );

        // No Node at all is an absent optional component, not a failure.
        let (line, code) = doctor_node_line(&dir, &[("PATH", empty.to_str().unwrap())]);
        assert!(line.starts_with("-- "), "{line}");
        assert!(line.contains("not found on PATH"), "{line}");
        assert_eq!(code, Some(0));

        // A node that cannot answer --version is a problem, and the command fails.
        let broken = dir.join("tools/broken/node");
        std::fs::create_dir_all(broken.parent().unwrap()).unwrap();
        std::fs::write(&broken, "#!/bin/sh\nexit 126\n").unwrap();
        let mut permissions = std::fs::metadata(&broken).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&broken, permissions).unwrap();
        let (line, code) = doctor_node_line(
            &dir,
            &[("PATH", broken.parent().unwrap().to_str().unwrap())],
        );
        assert!(line.starts_with("!! "), "{line}");
        assert!(line.contains("unusable"), "{line}");
        assert_eq!(code, Some(1));

        // FIREEMU_NODE that cannot run is a problem too, whatever PATH holds.
        let (line, code) = doctor_node_line(
            &dir,
            &[("FIREEMU_NODE", "/nonexistent/node"), ("PATH", &path)],
        );
        assert!(
            line.starts_with("!! ") && line.contains("FIREEMU_NODE"),
            "{line}"
        );
        assert_eq!(code, Some(1));
    }
}

#[cfg(unix)]
#[test]
fn runner_override_arguments_are_never_printed() {
    let dir = project("runner-secrets");
    write(
        &dir,
        "firebase.json",
        r#"{"functions":{"source":"functions"}}"#,
    );
    write(&dir, "functions/package.json", r#"{"name":"fixture"}"#);
    write(&dir, "fireemu.toml", "schemaVersion = 1\nfirebaseJson = \"firebase.json\"\n[functions]\nrunner = [\"/bin/echo\", \"--token=review-sentinel-secret\", \"second-secret\"]\n");
    for args in [&["up", "--plan", "--json"][..], &["up", "--plan"][..]] {
        let output = run(&dir, args, &[]);
        assert!(output.status.success(), "{}", stderr(&output));
        let text = format!("{}{}", stdout(&output), stderr(&output));
        assert!(!text.contains("review-sentinel-secret") && !text.contains("second-secret"));
        if args.contains(&"--json") {
            let plan: Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(
                plan["functions"][0]["runner"]["command"],
                serde_json::json!(["/bin/echo", "[redacted]", "[redacted]"])
            );
        }
    }
}

#[test]
fn configured_secrets_are_not_printed_in_plans() {
    let dir = project("config-secrets");
    let digest = "cd".repeat(32);
    let config = format!("schemaVersion = 1\n[pubsub.authentication]\nlocalBearerToken = \"sentinel-bearer-0001\"\n[auth]\napiKeys = [\"sentinel-api-key-0002\"]\n[auth.customTokenSigners.\"signer@demo-app.iam.gserviceaccount.com\"]\nkeys = [{{ kty = \"RSA\", alg = \"RS256\", kid = \"sentinel-signer-0004\", n = \"0lwNtQWMVy0QqgEvrBmoFqwky_dcMx8CgS-o2rTesEV7QbG4cvNigTcDV7b_u0twRkJdonkMPjbUs0b8NKe_0_UOZ5vE_kILFG4TtPdeZWub8xnqhETc7WifXhEfqcB8xFbRyIxU9V0d_epsuNnQ-Nd7NlnFsH-aaq6f1HKp55_BVNxudwmHwT49P6JhNDDh7FWyoYBBBFtQ0St8dky4MFQTd2swZP4pEA8xGp-q-1mxbn0g9gfbq5voYWtOaDW9a2lsC_S_d6DecsrNWn4YYJ7Qc5xcx4pI70a23zftkVBj_I-Eip2hcvNUEsZJA4LlR4BgDLsNWu3ZWQxe08fOew\", e = \"AQAB\" }}]\n[[auth.providers.oidc]]\nname = \"oidc.fixture\"\nenabled = true\nclientId = \"visible-client-id\"\nissuer = \"https://issuer.test\"\nclientSecret = \"sentinel-oidc-secret-0003\"\n[appCheck]\nenabled = true\n[[appCheck.apps]]\nprojectId = \"demo-app\"\nprojectNumber = \"1234567890\"\nappId = \"1:1234567890:web:abc\"\ndebugTokenSha256 = [\"{digest}\"]\n");
    write(&dir, "fireemu.toml", &config);
    for args in [&["up", "--plan", "--json"][..], &["up", "--plan"][..]] {
        let output = run(&dir, args, &[]);
        assert!(output.status.success(), "{}", stderr(&output));
        let text = format!("{}{}", stdout(&output), stderr(&output));
        for secret in [
            "sentinel-bearer-0001",
            "sentinel-api-key-0002",
            "sentinel-oidc-secret-0003",
            "sentinel-signer-0004",
            &digest,
        ] {
            assert!(!text.contains(secret));
        }
    }
}

#[test]
fn data_connect_inherited_environment_is_denied_or_allowed() {
    let dir = project("data-connect-env");
    let env = [("DATA_CONNECT_EMULATOR_HOST", "127.0.0.1:9399")];
    let args = [
        "up",
        "--plan",
        "--json",
        "--only",
        "firestore",
        "--deny-inherited-emulator-env",
    ];
    let output = run(&dir, &args, &env);
    assert_eq!(output.status.code(), Some(1));
    let plan: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        plan["environment"]["denied"],
        serde_json::json!(["DATA_CONNECT_EMULATOR_HOST"])
    );
    let output = run(
        &dir,
        &[
            "up",
            "--plan",
            "--json",
            "--only",
            "firestore",
            "--deny-inherited-emulator-env",
            "--allow-inherited-emulator-env",
            "DATA_CONNECT_EMULATOR_HOST",
        ],
        &env,
    );
    assert!(output.status.success());
    let plan: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        plan["environment"]["inherited"][0]["disposition"],
        "kept-allowed"
    );
}

#[test]
fn ui_plan_reflects_firebase_json_selection() {
    let dir = project("ui-config");
    for (config, enabled, address) in [
        (r#"{"emulators":{"ui":{"port":0}}}"#, false, None),
        (
            r#"{"emulators":{"ui":{"port":4123}}}"#,
            true,
            Some("127.0.0.1:4123"),
        ),
        (r#"{"emulators":{"ui":{"enabled":false}}}"#, false, None),
    ] {
        write(&dir, "firebase.json", config);
        let plan = json_plan(&dir, &["up", "--plan", "--json"], &[]);
        let row = service(&plan, "ui");
        assert_eq!(row["start"], enabled);
        assert_eq!(row["address"].as_str(), address);
    }
}

#[cfg(unix)]
#[test]
fn unbound_logging_listener_is_checked_against_inherited_environment() {
    let dir = project("logging-inherited");
    let _listener = std::net::TcpListener::bind("127.0.0.1:4500").ok();
    let env = [("FIREBASE_LOGGING_EMULATOR_HOST", "127.0.0.1:1")];
    let common = [
        "--only",
        "firestore",
        "--firestore-port",
        "0",
        "--hub-port",
        "0",
        "--ui-port",
        "0",
        "--",
        "true",
    ];
    let mut denied = vec!["exec", "--deny-inherited-emulator-env"];
    denied.extend(common);
    let output = run(&dir, &denied, &env);
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).contains("FIREBASE_LOGGING_EMULATOR_HOST"));
    let mut warned = vec!["exec"];
    warned.extend(common);
    let output = run(&dir, &warned, &env);
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(stderr(&output)
        .lines()
        .any(|line| line.contains("warning:") && line.contains("FIREBASE_LOGGING_EMULATOR_HOST")));
}
