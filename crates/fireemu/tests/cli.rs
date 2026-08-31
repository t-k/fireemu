//! The command surface: the official command and flag spellings, the exit codes they
//! produce, and how a real `firebase.json` / `.firebaserc` pair reaches the daemon
//! (CLI-01, CLI-04).
//!
//! Every scenario runs the shipped binary, so what is asserted is what a project invoking
//! `fireemu` actually gets rather than what the parser returns internally.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("fireemu-cli-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn write(dir: &Path, name: &str, body: &str) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, body).unwrap();
    path
}

/// Runs the binary with ephemeral service ports and the Hub off, so a scenario is about the
/// arguments and never about which port was free.
fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_fireemu"))
        .args(args)
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

fn run_in(dir: &Path, args: &[&str], input: Option<&str>) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_fireemu"));
    command
        .current_dir(dir)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    match input {
        None => command.stdin(Stdio::null()).output().unwrap(),
        Some(input) => {
            use std::io::Write as _;

            let mut child = command.stdin(Stdio::piped()).spawn().unwrap();
            child
                .stdin
                .take()
                .unwrap()
                .write_all(input.as_bytes())
                .unwrap();
            child.wait_with_output().unwrap()
        }
    }
}

/// The port arguments every successful scenario needs.
const PORTS: [&str; 14] = [
    "--firestore-port",
    "0",
    "--http-port",
    "0",
    "--storage-port",
    "0",
    "--pubsub-port",
    "0",
    "--ui-port",
    "0",
    "--hub-port",
    "0",
    "--logging-port",
    "0",
];

fn exec_with(extra: &[&str], command: &[&str]) -> Output {
    let mut args: Vec<&str> = vec!["exec"];
    args.extend_from_slice(&PORTS);
    args.extend_from_slice(extra);
    args.push("--");
    args.extend_from_slice(command);
    run(&args)
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

// --------------------------------------------------------------------------------------
// Command names and exit codes
// --------------------------------------------------------------------------------------

#[test]
fn the_official_command_names_are_aliases_of_the_short_ones() {
    // `emulators:exec` runs a command and propagates its status, exactly as `exec` does.
    let out = exec_with(&[], &["sh", "-c", "exit 7"]);
    assert_eq!(out.status.code(), Some(7));
    let mut args: Vec<&str> = vec!["emulators:exec"];
    args.extend_from_slice(&PORTS);
    args.extend_from_slice(&["--", "sh", "-c", "exit 7"]);
    assert_eq!(run(&args).status.code(), Some(7));

    // `emulators:start` is `up`; both refuse the same unknown argument the same way.
    for verb in ["up", "emulators:start"] {
        let out = run(&[verb, "--nope"]);
        assert_eq!(out.status.code(), Some(2), "{verb}");
        assert!(stderr(&out).contains("unknown argument --nope"), "{verb}");
    }

    // An unknown verb prints the usage and exits 2.
    let out = run(&["emulators:frobnicate"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(stderr(&out).contains("usage: fireemu"));
}

#[test]
fn init_noninteractive_defaults_to_strict_and_detects_firebase_json() {
    let dir = scratch("init-default");
    write(&dir, "firebase.json", "{}\n");

    let out = run_in(&dir, &["init", "--yes"], None);
    assert!(out.status.success(), "{}", stderr(&out));
    let path = dir.join("fireemu.json");
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(text.ends_with('\n'));
    let generated: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(generated["$schema"], config_schema_url());
    assert_eq!(generated["schemaVersion"], 1);
    assert_eq!(generated["profile"], "strict");
    assert_eq!(generated["firebaseJson"], "firebase.json");
    assert_eq!(generated["firestore"]["edition"], "standard");
    assert_eq!(generated["firestore"]["apiMode"], "native");
    assert!(String::from_utf8_lossy(&out.stdout).contains("fireemu up --config fireemu.json"));

    let before = std::fs::read(&path).unwrap();
    let out = run_in(&dir, &["init", "--yes"], None);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("already exists"));
    assert_eq!(std::fs::read(path).unwrap(), before);
}

#[test]
fn init_wizard_explains_profiles_and_the_live_firebase_reference() {
    let dir = scratch("init-wizard");
    write(&dir, "firebase.json", "{}\n");

    let out = run_in(&dir, &["init", "--interactive"], Some("\n\ny\n"));
    assert!(out.status.success(), "{}", stderr(&out));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("strict (recommended)"), "{stdout}");
    assert!(
        stdout.contains("additional validation and production limit checks"),
        "{stdout}"
    );
    assert!(
        stdout.contains("firebase reproduces the pinned official emulator behavior"),
        "{stdout}"
    );
    assert!(
        stdout.contains("loaded again on every fireemu start"),
        "{stdout}"
    );
    assert!(stdout.contains("Create fireemu.json? [Y/n]"), "{stdout}");
    let generated: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(dir.join("fireemu.json")).unwrap()).unwrap();
    assert_eq!(generated["profile"], "strict");
    assert_eq!(generated["firebaseJson"], "firebase.json");
}

#[test]
fn init_options_select_values_and_non_tty_input_never_opens_the_wizard() {
    let explicit = scratch("init-explicit");
    write(&explicit, "project.json", "{}\n");
    let out = run_in(
        &explicit,
        &[
            "init",
            "--yes",
            "--profile",
            "firebase",
            "--firebase-json",
            "project.json",
        ],
        None,
    );
    assert!(out.status.success(), "{}", stderr(&out));
    let generated: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(explicit.join("fireemu.json")).unwrap())
            .unwrap();
    assert_eq!(generated["profile"], "firebase");
    assert_eq!(generated["firebaseJson"], "project.json");
    assert!(!String::from_utf8_lossy(&out.stdout).contains("Profiles:"));

    let redirected = scratch("init-redirected");
    let out = run_in(&redirected, &["init"], Some("firebase\nmissing.json\nn\n"));
    assert!(out.status.success(), "{}", stderr(&out));
    let generated: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(redirected.join("fireemu.json")).unwrap())
            .unwrap();
    assert_eq!(generated["profile"], "strict");
    assert!(generated.get("firebaseJson").is_none());
    assert!(!String::from_utf8_lossy(&out.stdout).contains("Profiles:"));
}

#[test]
fn init_option_conflicts_duplicates_and_missing_values_are_usage_errors() {
    for (label, args) in [
        ("conflicting modes", vec!["init", "--interactive", "--yes"]),
        (
            "duplicate profile",
            vec!["init", "--profile", "strict", "--profile", "firebase"],
        ),
        (
            "duplicate source",
            vec![
                "init",
                "--firebase-json",
                "a.json",
                "--firebase-json",
                "b.json",
            ],
        ),
        ("bad profile", vec!["init", "--profile", "production"]),
        ("missing profile", vec!["init", "--profile"]),
        ("missing source", vec!["init", "--firebase-json"]),
    ] {
        let dir = scratch(&format!("init-usage-{}", label.replace(' ', "-")));
        let out = run_in(&dir, &args, None);
        assert_eq!(out.status.code(), Some(2), "{label}: {}", stderr(&out));
        assert!(!dir.join("fireemu.json").exists(), "{label}");
    }
}

#[test]
fn init_force_validates_the_firebase_source_before_replacing_a_regular_file() {
    let dir = scratch("init-force-validation");
    let destination = write(&dir, "fireemu.json", "keep this exact content\n");
    write(&dir, "malformed.json", "{ nope\n");

    let out = run_in(
        &dir,
        &[
            "init",
            "--yes",
            "--force",
            "--firebase-json",
            "malformed.json",
        ],
        None,
    );
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("malformed.json does not parse"));
    assert_eq!(
        std::fs::read_to_string(&destination).unwrap(),
        "keep this exact content\n"
    );

    write(&dir, "valid.json", "{}\n");
    let out = run_in(
        &dir,
        &["init", "--yes", "--force", "--firebase-json", "valid.json"],
        None,
    );
    assert!(out.status.success(), "{}", stderr(&out));
    let generated: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(destination).unwrap()).unwrap();
    assert_eq!(generated["firebaseJson"], "valid.json");
}

#[test]
fn init_force_refuses_missing_canonical_and_directory_sources_or_destinations() {
    for (label, source, body, fragment) in [
        ("missing", "missing.json", None, "cannot read"),
        (
            "canonical",
            "other-fireemu.json",
            Some(r#"{"schemaVersion":1}"#),
            "not a firebase.json",
        ),
    ] {
        let dir = scratch(&format!("init-source-{label}"));
        if let Some(body) = body {
            write(&dir, source, body);
        }
        let out = run_in(&dir, &["init", "--yes", "--firebase-json", source], None);
        assert_eq!(out.status.code(), Some(1), "{label}: {}", stderr(&out));
        assert!(stderr(&out).contains(fragment), "{label}: {}", stderr(&out));
        assert!(!dir.join("fireemu.json").exists());
    }

    let dir = scratch("init-directory-destination");
    std::fs::create_dir(dir.join("fireemu.json")).unwrap();
    let out = run_in(&dir, &["init", "--yes", "--force"], None);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("not a regular file"));
    assert!(dir.join("fireemu.json").is_dir());
}

#[cfg(unix)]
#[test]
fn init_force_refuses_a_symlink_destination_without_touching_its_target() {
    use std::os::unix::fs::symlink;

    let dir = scratch("init-symlink");
    let target = write(&dir, "target.json", "keep\n");
    let destination = dir.join("fireemu.json");
    symlink(&target, &destination).unwrap();

    let out = run_in(&dir, &["init", "--yes", "--force"], None);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("symbolic link"));
    assert_eq!(std::fs::read_to_string(target).unwrap(), "keep\n");
    assert!(std::fs::symlink_metadata(destination)
        .unwrap()
        .file_type()
        .is_symlink());
}

fn config_schema_url() -> &'static str {
    "https://fireemu.dev/spec/config/fireemu.schema.json"
}

#[test]
fn export_without_a_running_suite_says_which_suite_it_looked_for() {
    let dir = scratch("export-no-suite");
    let out = run(&[
        "emulators:export",
        dir.join("out").to_str().unwrap(),
        "--project",
        "demo-nothing-runs-here",
    ]);
    assert_eq!(
        out.status.code(),
        Some(1),
        "a command that needs a running suite and finds none is a refusal, not a usage error"
    );
    let text = stderr(&out);
    assert!(text.contains("no running fireemu suite"), "{text}");
    assert!(
        text.contains("demo-nothing-runs-here"),
        "{text}: it must name the project it looked for"
    );
}

#[test]
fn a_bad_import_or_export_target_fails_before_anything_starts() {
    let dir = scratch("import");
    let marker = dir.join("ran");
    let occupied = dir.join("occupied");
    std::fs::create_dir_all(&occupied).unwrap();
    std::fs::write(occupied.join("notes.txt"), "keep me").unwrap();
    for (label, extra, fragment) in [
        (
            "a directory that does not exist",
            vec!["--import", "./no-such-export"],
            "no such directory",
        ),
        (
            "a target that is not an export directory",
            vec!["--export-on-exit", occupied.to_str().unwrap()],
            "not an export directory",
        ),
        (
            "--export-on-exit with nothing to resolve it against",
            vec!["--export-on-exit"],
            "must be used with --import",
        ),
    ] {
        let out = exec_with(&extra, &["touch", marker.to_str().unwrap()]);
        let text = stderr(&out);
        assert!(matches!(out.status.code(), Some(1 | 2)), "{label}: {text}");
        assert!(text.contains(fragment), "{label}: {text}");
        assert!(!marker.exists(), "{label}: the command ran anyway");
    }
}

#[test]
fn log_verbosity_decides_whether_the_banner_is_printed() {
    for (level, banner) in [("quiet", false), ("info", true), ("DEBUG", true)] {
        let out = exec_with(&["--log-verbosity", level], &["true"]);
        assert!(out.status.success(), "{level}: {}", stderr(&out));
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert_eq!(
            stdout.contains("control API:"),
            banner,
            "{level} printed: {stdout}"
        );
    }
    // `debug` adds the resolved configuration on top of everything `info` prints.
    let out = exec_with(&["--log-verbosity", "debug"], &["true"]);
    assert!(String::from_utf8_lossy(&out.stdout).contains("resolved config:"));
    // An unknown level is a usage error, not a silent fallback.
    let out = exec_with(&["--log-verbosity", "loud"], &["true"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(stderr(&out).contains("quiet, info, debug"));
}

#[test]
fn inspect_functions_passes_the_node_inspector_through_to_the_runner() {
    let dir = scratch("inspect");
    // With no codebase there is no runner to start, so the flag only has to be accepted.
    let out = exec_with(&["--inspect-functions"], &["true"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let out = exec_with(&["--inspect-functions", "9330"], &["true"]);
    assert!(out.status.success(), "{}", stderr(&out));

    // A configured runner that is not Node cannot take `--inspect`, and says so instead of
    // starting without the inspector the caller asked for.
    let config = write(
        &dir,
        "fireemu.json",
        r#"{
  "schemaVersion": 1,
  "profile": "strict",
  "firestore": { "edition": "standard", "apiMode": "native" },
  "functions": { "runner": ["python3", "runner.py"] }
}
"#,
    );
    let out = exec_with(
        &["--config", config.to_str().unwrap(), "--inspect-functions"],
        &["true"],
    );
    assert_eq!(out.status.code(), Some(1));
    let text = stderr(&out);
    assert!(text.contains("--inspect-functions"), "{text}");
    assert!(text.contains("not node"), "{text}");
}

// --------------------------------------------------------------------------------------
// firebase.json and .firebaserc
// --------------------------------------------------------------------------------------

/// Reports the child's environment from a run configured by `firebase.json`.
fn env_of(dir: &Path, extra: &[&str]) -> std::collections::BTreeMap<String, String> {
    let out_file = dir.join("env.txt");
    let script = format!("env > {}", out_file.display());
    let mut args: Vec<&str> = vec!["exec"];
    args.extend_from_slice(&PORTS);
    args.extend_from_slice(extra);
    args.extend_from_slice(&["--", "sh", "-c", &script]);
    let out = run(&args);
    assert!(out.status.success(), "{}", stderr(&out));
    std::fs::read_to_string(&out_file)
        .unwrap()
        .lines()
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect()
}

#[test]
fn a_project_alias_from_firebaserc_resolves_the_project() {
    let dir = scratch("firebaserc");
    write(&dir, "firebase.json", "{}");
    write(
        &dir,
        ".firebaserc",
        r#"{"projects": {"default": "demo-default-app", "staging": "demo-staging-app"}}"#,
    );
    let firebase = dir.join("firebase.json");
    let firebase = firebase.to_str().unwrap();

    // No --project: the `default` alias.
    let env = env_of(&dir, &["--firebase-json", firebase]);
    assert_eq!(env["GCLOUD_PROJECT"], "demo-default-app");

    // A named alias resolves to its project ID.
    let env = env_of(&dir, &["--firebase-json", firebase, "--project", "staging"]);
    assert_eq!(env["GCLOUD_PROJECT"], "demo-staging-app");

    // A value that is not an alias is taken as a project ID, as `firebase --project` does.
    let env = env_of(
        &dir,
        &["--firebase-json", firebase, "--project", "demo-literal"],
    );
    assert_eq!(env["GCLOUD_PROJECT"], "demo-literal");
}

#[test]
fn config_accepts_a_firebase_json_as_well_as_the_canonical_configuration() {
    let dir = scratch("config-kind");
    write(
        &dir,
        "firebase.json",
        r#"{"emulators": {"singleProjectMode": true}}"#,
    );
    write(
        &dir,
        ".firebaserc",
        r#"{"projects": {"default": "demo-cfg"}}"#,
    );
    // `firebase emulators:exec --config firebase.json` works verbatim: a file without
    // `schemaVersion` is a firebase.json.
    let env = env_of(
        &dir,
        &["--config", dir.join("firebase.json").to_str().unwrap()],
    );
    assert_eq!(env["GCLOUD_PROJECT"], "demo-cfg");

    // A canonical configuration through --config still loads, and passing one to
    // --firebase-json is refused with the flag to use instead.
    let canonical = write(
        &dir,
        "fireemu.json",
        r#"{
  "schemaVersion": 1,
  "profile": "strict",
  "firestore": { "edition": "standard", "apiMode": "native" },
  "daemon": { "authProject": "demo-canonical" }
}
"#,
    );
    let env = env_of(&dir, &["--config", canonical.to_str().unwrap()]);
    assert_eq!(env["GCLOUD_PROJECT"], "demo-canonical");
    let out = exec_with(&["--firebase-json", canonical.to_str().unwrap()], &["true"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).contains("pass it with --config"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn a_canonical_config_live_loads_its_relative_firebase_json_reference() {
    let dir = scratch("embedded-firebase-json");
    let alternate = dir.join("alternate");
    std::fs::create_dir_all(&alternate).unwrap();
    let canonical = write(
        &dir,
        "fireemu.json",
        r#"{
  "$schema": "https://fireemu.dev/spec/config/fireemu.schema.json",
  "schemaVersion": 1,
  "profile": "strict",
  "firebaseJson": "firebase.json",
  "firestore": { "edition": "standard", "apiMode": "native" }
}
"#,
    );
    write(&dir, "firebase.json", r#"{"emulators": {}}"#);
    write(
        &dir,
        ".firebaserc",
        r#"{"projects": {"default": "demo-embedded"}}"#,
    );
    let alternate_firebase = write(&alternate, "firebase.json", r#"{"emulators": {}}"#);
    write(
        &alternate,
        ".firebaserc",
        r#"{"projects": {"default": "demo-explicit"}}"#,
    );

    let env = env_of(&dir, &["--config", canonical.to_str().unwrap()]);
    assert_eq!(env["GCLOUD_PROJECT"], "demo-embedded");

    let env = env_of(
        &dir,
        &[
            "--config",
            canonical.to_str().unwrap(),
            "--firebase-json",
            alternate_firebase.to_str().unwrap(),
        ],
    );
    assert_eq!(env["GCLOUD_PROJECT"], "demo-explicit");
}

#[test]
fn a_deferred_emulator_entry_is_a_notice_unless_only_asks_for_it() {
    let dir = scratch("deferred");
    let firebase = write(
        &dir,
        "firebase.json",
        r#"{
  "database": {"rules": "database.rules.json"},
  "emulators": {
    "firestore": {"port": 8080},
    "database": {"port": 9000},
    "pubsub": {"port": 8085},
    "logging": {"port": 4500}
  }
}
"#,
    );
    let firebase = firebase.to_str().unwrap();
    // Without --only naming them, they are notices and the run proceeds.
    let out = exec_with(&["--firebase-json", firebase], &["true"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let text = stderr(&out);
    assert!(text.contains("emulators.database"), "{text}");
    assert!(text.contains("deferred"), "{text}");
    // Pub/Sub is now a served service: its firebase.json entry is applied, not a notice.
    assert!(
        !text.contains("emulators.pubsub"),
        "pubsub is served and must not be reported as unserved: {text}"
    );
    // The Logging emulator is now served: its firebase.json entry is applied, not a notice.
    assert!(
        !text.contains("emulators.logging"),
        "logging is served and must not be reported as unserved: {text}"
    );

    // Naming one in --only is refused before anything binds; the message names the product.
    let out = exec_with(
        &["--firebase-json", firebase, "--only", "database"],
        &["true"],
    );
    assert_eq!(out.status.code(), Some(2));
    assert!(stderr(&out).contains("database"), "{}", stderr(&out));
}

#[test]
fn a_multi_codebase_functions_section_names_the_codebase_to_load() {
    let dir = scratch("codebases");
    std::fs::create_dir_all(dir.join("fn-a")).unwrap();
    std::fs::create_dir_all(dir.join("fn-b")).unwrap();
    let firebase = write(
        &dir,
        "firebase.json",
        r#"{
  "functions": [
    {"source": "fn-a", "codebase": "alpha", "runtime": "nodejs20", "ignore": ["node_modules"]},
    {"source": "fn-b", "codebase": "beta"}
  ]
}
"#,
    );
    let firebase = firebase.to_str().unwrap();

    // Every declared codebase is loaded, one runner process each, and the run says so. The
    // two directories here are empty, so the runners fail on the codebases themselves --
    // which is the point: both were loaded rather than one of them silently skipped.
    let out = exec_with(&["--firebase-json", firebase], &["true"]);
    assert_eq!(out.status.code(), Some(1));
    let text = stderr(&out);
    assert!(
        text.contains("2 codebases are loaded (alpha, beta)"),
        "{text}"
    );

    // Naming one selects it; the directory is empty, so the runner fails on the codebase
    // itself rather than on the configuration -- which is the point: it was loaded.
    let out = exec_with(
        &["--firebase-json", firebase, "--only", "functions:alpha"],
        &["true"],
    );
    let text = stderr(&out);
    assert!(
        !text.contains("--only functions:<codebase>"),
        "a named codebase must not be ambiguous: {text}"
    );

    // An unknown codebase names the ones that exist.
    let out = exec_with(
        &["--firebase-json", firebase, "--only", "functions:gamma"],
        &["true"],
    );
    assert_eq!(out.status.code(), Some(1));
    let text = stderr(&out);
    assert!(text.contains("no such codebase"), "{text}");
    assert!(text.contains("alpha, beta"), "{text}");

    // Not selecting functions at all leaves the ambiguity moot.
    let out = exec_with(
        &["--firebase-json", firebase, "--only", "firestore"],
        &["true"],
    );
    assert!(out.status.success(), "{}", stderr(&out));
}

#[test]
fn a_named_firestore_database_is_reported_rather_than_folded_into_the_default_one() {
    let dir = scratch("databases");
    write(&dir, "firestore.rules", "rules_version = '2';\nservice cloud.firestore {\n  match /databases/{db}/documents {\n    match /{d=**} { allow read, write: if true; }\n  }\n}\n");
    write(&dir, "reports.rules", "rules_version = '2';\nservice cloud.firestore {\n  match /databases/{db}/documents {\n    match /{d=**} { allow read, write: if false; }\n  }\n}\n");
    let firebase = write(
        &dir,
        "firebase.json",
        r#"{
  "firestore": [
    {"database": "(default)", "rules": "firestore.rules"},
    {"database": "reports", "rules": "reports.rules"}
  ]
}
"#,
    );
    let out = exec_with(&["--firebase-json", firebase.to_str().unwrap()], &["true"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("firestore.rules"), "{text}");
    assert!(text.contains("rules [reports]: enforced from "), "{text}");
    assert!(text.contains("reports.rules"), "{text}");
    assert!(!stderr(&out).contains("not loaded"), "{}", stderr(&out));
}

#[test]
fn a_routable_emulator_host_is_refused() {
    // firebase-tools 15.28.2 binds each of these as given; fireemu publishes the refusal as a
    // divergence of the CLI lifecycle claim, so the exit code and the message are contract.
    for host in ["0.0.0.0", "::", "192.168.1.10"] {
        let dir = scratch("host");
        let firebase = write(
            &dir,
            "firebase.json",
            &format!(r#"{{"emulators": {{"firestore": {{"host": "{host}", "port": 8080}}}}}}"#),
        );
        let out = exec_with(&["--firebase-json", firebase.to_str().unwrap()], &["true"]);
        assert_eq!(out.status.code(), Some(1), "host {host:?}");
        let text = stderr(&out);
        assert!(text.contains("emulators.firestore.host"), "{text}");
        assert!(text.contains("only loopback hosts are accepted"), "{text}");
    }
}

#[test]
fn a_command_line_port_overrides_the_one_in_firebase_json() {
    let dir = scratch("override");
    write(
        &dir,
        ".firebaserc",
        r#"{"projects": {"default": "demo-ports"}}"#,
    );
    let firebase = write(
        &dir,
        "firebase.json",
        r#"{"emulators": {"firestore": {"port": 8123}, "auth": {"host": "localhost", "port": 9123}}}"#,
    );
    // The ports of `PORTS` are all 0 (ephemeral), so nothing lands on 8123 or 9123.
    let env = env_of(&dir, &["--firebase-json", firebase.to_str().unwrap()]);
    assert!(!env["FIRESTORE_EMULATOR_HOST"].ends_with(":8123"));
    assert!(!env["FIREBASE_AUTH_EMULATOR_HOST"].ends_with(":9123"));
    assert_eq!(env["GCLOUD_PROJECT"], "demo-ports");
}
