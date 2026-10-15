//! The command surface: the official command and flag spellings, the exit codes they
//! produce, and how a real `firebase.json` / `.firebaserc` pair reaches the daemon
//! (CLI-01, CLI-04).
//!
//! Every scenario runs the shipped binary, so what is asserted is what a project invoking
//! `fireemu` actually gets rather than what the parser returns internally.

mod scratch;

use scratch::Scratch;

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

fn scratch(name: &str) -> Scratch {
    Scratch::new("cli", name)
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

#[test]
fn toml_and_json_configs_have_identical_effective_values() {
    let dir = scratch("toml-twins");
    for (toml, json) in [
        ("schemaVersion = 1\nprofile = 'emulator'\n[firestore]\nedition = 'standard'\napiMode = 'native'\n", r#"{"schemaVersion":1,"profile":"emulator","firestore":{"edition":"standard","apiMode":"native"}}"#),
        ("schemaVersion = 1\nproductionExact = true\nauth.allowUnsignedIdTokens = true\n[auth.idpSigners]\n[eventarc.oauthCredentials]\n", r#"{"schemaVersion":1,"productionExact":true,"auth":{"allowUnsignedIdTokens":true,"idpSigners":{}},"eventarc":{"oauthCredentials":{}}}"#),
        ("schemaVersion = 1\n[[auth.tenants]]\ntenantId = 'tenant-a'\ndisplayName = 'First'\n[[auth.tenants]]\ntenantId = 'tenant-b'\ndisplayName = 'Second'\n", r#"{"schemaVersion":1,"auth":{"tenants":[{"tenantId":"tenant-a","displayName":"First"},{"tenantId":"tenant-b","displayName":"Second"}]}}"#),
    ] {
        write(&dir, "foo.toml", toml);
        write(&dir, "foo.json", json);
        write(&dir, "foo.conf", json);
        let mut outputs = Vec::new();
        for path in ["foo.toml", "foo.json", "foo.conf"] {
            let out = run_in(&dir, &["config", "show", "--json", "--config", path], None);
            assert!(out.status.success(), "{path}: {}", stderr(&out));
            outputs.push(out.stdout);
        }
        assert_eq!(outputs[0], outputs[1]);
        assert_eq!(outputs[1], outputs[2]);
    }
}

#[test]
fn toml_rules_source_reloads_after_an_edit() {
    let dir = scratch("toml-rules-reload");
    write(
        &dir,
        "fireemu.toml",
        "schemaVersion = 1\nrules.source = 'firestore.rules'\n",
    );
    write(&dir, "firestore.rules", "rules_version = '2'; service cloud.firestore { match /databases/{db}/documents/{doc=**} { allow read: if true; } }");
    let script = r#"
const fs = require('node:fs');
(async () => {
  const host = process.env.FIRESTORE_EMULATOR_HOST;
  if (!host.startsWith('127.0.0.1:')) throw new Error('expected a local emulator');
  const url = `http://${host}/v1/projects/demo-toml-reload/databases/(default)/documents/items/one`;
  const initial = await fetch(url);
  await initial.text();
  if (initial.status !== 404) throw new Error(`initial read: ${initial.status}`);
  fs.writeFileSync('firestore.rules', "rules_version = '2'; service cloud.firestore { match /databases/{db}/documents/{doc=**} { allow read: if false; } }");
  const deadline = Date.now() + 5000;
  while (Date.now() < deadline) {
    const response = await fetch(url);
    await response.text();
    if (response.status === 403) return;
    await new Promise(resolve => setTimeout(resolve, 50));
  }
  throw new Error('edited TOML rules.source was not reloaded');
})().catch(error => { console.error(error); process.exitCode = 1; });
"#;
    let mut args = vec!["exec"];
    args.extend_from_slice(&PORTS);
    args.extend([
        "--only",
        "firestore",
        "--project",
        "demo-toml-reload",
        "--",
        "node",
        "-e",
        script,
    ]);
    let out = run_in(&dir, &args, None);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("reloaded Firestore rules"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn toml_without_schema_version_is_refused_by_up_exec_and_config_show() {
    let dir = scratch("toml-version-parity");
    for body in [
        "[emulators.firestore]\nport = 0\n[firestore]\nrules = 'missing.rules'\n",
        "profile = 'emulator'\n",
    ] {
        for file in ["fireemu.toml", "explicit.toml"] {
            write(&dir, file, body);
            let expected = format!("{file}: a TOML configuration must set schemaVersion = 1 (firebase.json is JSON only)");
            let mut errors = Vec::new();
            for command in [vec!["up"], vec!["exec"], vec!["config", "show"]] {
                let mut args = command.clone();
                if file != "fireemu.toml" {
                    args.extend(["--config", file]);
                }
                if command[0] != "config" {
                    args.extend(["--only", "firestore"]);
                }
                if command[0] == "exec" {
                    args.extend(["--", "true"]);
                }
                let out = run_in(&dir, &args, None);
                assert_eq!(out.status.code(), Some(1), "{args:?}: {}", stderr(&out));
                let error = stderr(&out);
                assert!(
                    error.starts_with(&format!("error: {expected}")),
                    "{args:?}: {error}"
                );
                assert!(!error.contains("add \"schemaVersion\": 1"), "{error}");
                errors.push(error);
            }
            assert_eq!(errors[0], errors[1]);
            assert_eq!(errors[1], errors[2]);
        }
    }
}

#[test]
fn toml_diagnostic_key_paths_escape_controls_and_quote_dots() {
    let dir = scratch("toml-diagnostic-keys");
    for (value, message) in [
        (
            "1979-05-27",
            "TOML datetime values are not supported; use a quoted string",
        ),
        ("inf", "non-finite TOML numbers are not supported"),
    ] {
        for (key, expected) in [
            (r#""b.c""#, r#"a."b.c""#),
            (r#""x\"y""#, r#"a.'x"y'"#),
            (r#""\u001b[31mRED""#, r#"a."\u001B[31mRED""#),
            (r#""b.c"."d.e""#, r#"a."b.c"."d.e""#),
        ] {
            write(
                &dir,
                "keys.toml",
                &format!("schemaVersion = 1\n[a]\n{key} = {value}\n"),
            );
            let out = run_in(&dir, &["config", "show", "--config", "keys.toml"], None);
            assert_eq!(out.status.code(), Some(1));
            let error = stderr(&out);
            assert!(!error.contains('\u{1b}'), "raw terminal escape");
            assert_eq!(error, format!("error: keys.toml: {expected}: {message}\n"));
        }
    }
}

#[test]
fn toml_parser_messages_preserve_quotes() {
    let dir = scratch("toml-parser-quotes");
    write(
        &dir,
        "broken.toml",
        "schemaVersion = 1\nprofile = \"\\q\"\n",
    );
    let out = run_in(&dir, &["config", "show", "--config", "broken.toml"], None);
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(stderr(&out), "error: broken.toml:2:13: missing escaped value, expected `b`, `e`, `f`, `n`, `r`, `\\`, `\"`, `x`, `u`, `U`\n");
}

#[test]
fn toml_extension_is_case_insensitive() {
    let dir = scratch("toml-extension-case");
    for file in ["config.TOML", "config.ToMl"] {
        write(&dir, file, "schemaVersion = 1\nprofile = 'emulator'\n");
        let out = run_in(&dir, &["config", "show", "--config", file], None);
        assert!(out.status.success(), "{}", stderr(&out));
        assert!(String::from_utf8_lossy(&out.stdout).contains("profile = \"emulator\" (explicit)"));
    }
}

#[test]
fn toml_errors_name_the_path_position_and_datetime_key() {
    let dir = scratch("toml-errors");
    write(&dir, "broken.toml", "schemaVersion = 1\nprofile = [\n");
    let out = run_in(&dir, &["config", "show", "--config", "broken.toml"], None);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).contains("broken.toml:2:12"),
        "{}",
        stderr(&out)
    );
    for value in [
        "1979-05-27T07:32:00Z",
        "1979-05-27T07:32:00",
        "1979-05-27",
        "07:32:00",
    ] {
        write(
            &dir,
            "date.toml",
            &format!("schemaVersion = 1\n[time]\nstart = {value}\n"),
        );
        let out = run_in(&dir, &["config", "show", "--config", "date.toml"], None);
        assert_eq!(out.status.code(), Some(1));
        let error = stderr(&out);
        assert!(
            error.contains("date.toml")
                && error.contains("time.start")
                && error.contains("datetime"),
            "{error}"
        );
    }
    write(
        &dir,
        "quoted.toml",
        "schemaVersion = 1\n[daemon]\nclockStart = '1979-05-27T07:32:00Z'\n",
    );
    let out = run_in(&dir, &["config", "show", "--config", "quoted.toml"], None);
    assert!(out.status.success(), "{}", stderr(&out));
    write(
        &dir,
        "nested.toml",
        "schemaVersion = 1\n[[auth.tenants]]\ntenantId = 'tenant-a'\ncreatedAt = 1979-05-27\n",
    );
    let out = run_in(&dir, &["config", "show", "--config", "nested.toml"], None);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).contains("auth.tenants[0].createdAt"),
        "{}",
        stderr(&out)
    );
    for value in ["nan", "inf", "-inf"] {
        write(
            &dir,
            "number.toml",
            &format!("schemaVersion = 1\n[limits]\nqueryCatalog = {value}\n"),
        );
        let out = run_in(&dir, &["config", "show", "--config", "number.toml"], None);
        assert_eq!(out.status.code(), Some(1));
        assert!(
            stderr(&out).contains("limits.queryCatalog: non-finite"),
            "{}",
            stderr(&out)
        );
    }
}

#[test]
fn discovery_loads_toml_and_refuses_both_canonical_files() {
    let dir = scratch("toml-discovery");
    write(
        &dir,
        "fireemu.toml",
        "schemaVersion = 1\nprofile = 'emulator'\nbind = '127.0.0.1'\n",
    );
    let out = run_in(&dir, &["config", "show"], None);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(String::from_utf8_lossy(&out.stdout).contains("profile = \"emulator\" (explicit)"));
    assert!(
        stderr(&out).contains("fireemu.toml: bind"),
        "{}",
        stderr(&out)
    );
    write(&dir, "fireemu.json", r#"{"schemaVersion":1}"#);
    let out = run_in(&dir, &["config", "show"], None);
    assert_eq!(out.status.code(), Some(1));
    let error = stderr(&out);
    assert_eq!(error, "error: both fireemu.toml and fireemu.json exist; remove one or select a file with --config\n");
    let out = run_in(&dir, &["config", "show", "--config", "fireemu.toml"], None);
    assert!(out.status.success(), "{}", stderr(&out));
}

#[test]
fn discovery_skips_non_regular_toml_beside_json() {
    let dir = scratch("toml-non-regular");
    write(
        &dir,
        "fireemu.json",
        r#"{"schemaVersion":1,"profile":"emulator"}"#,
    );
    let toml = dir.join("fireemu.toml");
    std::fs::create_dir(&toml).unwrap();
    let out = run_in(&dir, &["config", "show"], None);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(String::from_utf8_lossy(&out.stdout).contains("profile = \"emulator\" (explicit)"));
    #[cfg(unix)]
    {
        std::fs::remove_dir(&toml).unwrap();
        std::os::unix::fs::symlink("missing.toml", &toml).unwrap();
        let out = run_in(&dir, &["config", "show"], None);
        assert!(out.status.success(), "{}", stderr(&out));
        assert!(String::from_utf8_lossy(&out.stdout).contains("profile = \"emulator\" (explicit)"));
    }
}

#[test]
fn firebase_json_flags_keep_json_parsing_for_toml_named_files() {
    let dir = scratch("firebase-json-extension");
    write(
        &dir,
        "firebase.toml",
        r#"{"emulators":{"firestore":{"port":8123}}}"#,
    );
    let out = run_in(
        &dir,
        &[
            "config",
            "show",
            "--firebase-json",
            "firebase.toml",
            "--json",
        ],
        None,
    );
    assert!(out.status.success(), "{}", stderr(&out));
    let rows: Vec<serde_json::Value> = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(
        rows.iter()
            .find(|row| row["key"] == "daemon.firestorePort")
            .unwrap()["value"],
        8123
    );
    write(
        &dir,
        "fireemu.toml",
        "schemaVersion = 1\nfirebaseJson = 'firebase.toml'\n",
    );
    let out = run_in(&dir, &["config", "show", "--json"], None);
    assert!(out.status.success(), "{}", stderr(&out));
}

#[test]
fn init_with_existing_json_does_not_create_toml_even_with_force() {
    let dir = scratch("init-existing-json");
    let original = r#"{"schemaVersion":1,"profile":"emulator"}"#;
    write(&dir, "fireemu.json", original);
    for args in [vec!["init", "--yes"], vec!["init", "--yes", "--force"]] {
        let out = run_in(&dir, &args, None);
        assert_eq!(out.status.code(), Some(1));
        assert!(stderr(&out).contains("fireemu.json"), "{}", stderr(&out));
        assert!(!dir.join("fireemu.toml").exists());
        assert_eq!(
            std::fs::read_to_string(dir.join("fireemu.json")).unwrap(),
            original
        );
    }
    let out = run_in(&dir, &["init", "--reference", "--yes"], None);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        format!(
            "created {}\nnext: fireemu up (fireemu.json in this directory is loaded automatically)\n",
            dir.canonicalize().unwrap().join("fireemu.reference.jsonc").display(),
        )
    );
    let reference = std::fs::read_to_string(dir.join("fireemu.reference.jsonc")).unwrap();
    assert!(reference.contains("Edit fireemu.json to configure it."));
    assert!(reference.contains("Do not create fireemu.toml beside fireemu.json."));
    assert!(reference.contains("Copying a key into fireemu.json makes it explicit"));
    let active = reference
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    let parsed: serde_json::Value = serde_json::from_str(&active).unwrap();
    assert!(reference.contains("\"schemaVersion\": 1"));
    assert_eq!(parsed["network"]["allowNonLoopbackHosts"], false);
    assert!(parsed.pointer("/auth/allowUnsignedIdTokens").is_none());
    assert!(!dir.join("fireemu.reference.toml").exists());
    assert!(!dir.join("fireemu.toml").exists());
}

#[test]
fn config_show_reports_effective_values_sources_and_schema_order() {
    let dir = scratch("config-show");
    write(
        &dir,
        "fireemu.json",
        r#"{"schemaVersion":1,"productionExact":true,"auth":{"allowUnsignedIdTokens":true,"idpSigners":{}},"eventarc":{"oauthCredentials":{}}}"#,
    );
    let out = run_in(&dir, &["config", "show", "--json"], None);
    assert!(out.status.success(), "{}", stderr(&out));
    let rows: Vec<serde_json::Value> = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(rows[0]["key"], "$schema");
    assert_eq!(rows[1]["key"], "eventarc.authentication");
    for (key, value, source) in [
        (
            "auth.allowUnsignedIdTokens",
            serde_json::json!(true),
            "explicit",
        ),
        (
            "auth.allowUnsignedCustomTokens",
            serde_json::json!(false),
            "productionExact",
        ),
        (
            "auth.idpAssertions",
            serde_json::json!("signed"),
            "derived from auth.idpSigners",
        ),
        (
            "eventarc.authentication",
            serde_json::json!("production"),
            "derived from eventarc.oauthCredentials",
        ),
        ("daemon.firestorePort", serde_json::json!(8080), "default"),
        (
            "firestore.enforceLimits",
            serde_json::json!(true),
            "derived from profile",
        ),
        ("functions.source", serde_json::Value::Null, "unset"),
    ] {
        let row = rows.iter().find(|row| row["key"] == key).unwrap();
        assert_eq!(row["value"], value, "{key}");
        assert_eq!(row["source"], source, "{key}");
        assert!(row["description"].is_string());
    }
    let out = run_in(&dir, &["config", "show"], None);
    assert!(out.status.success(), "{}", stderr(&out));
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.contains("auth.idpAssertions = \"signed\" (derived from auth.idpSigners)\n"));
    assert!(text.contains("functions.source = (unset) (unset)\n"));
}

#[test]
fn config_show_marks_keys_without_effect_and_loading_one_prints_a_note() {
    let dir = scratch("config-show-no-effect");
    write(
        &dir,
        "fireemu.json",
        r#"{"schemaVersion":1,"bind":"127.0.0.1","trace":{"enabled":true},"firestore":{"textSearch":{"fidelity":"deterministic-basic"}}}"#,
    );
    let out = run_in(&dir, &["config", "show", "--json"], None);
    assert!(out.status.success(), "{}", stderr(&out));
    // The notes go to standard error only; standard output stays one JSON document.
    assert!(!String::from_utf8_lossy(&out.stdout).contains("note:"));
    assert!(stderr(&out).contains("note: "), "{}", stderr(&out));
    let rows: Vec<serde_json::Value> = serde_json::from_slice(&out.stdout).unwrap();
    for (key, value) in [
        ("bind", serde_json::json!("127.0.0.1")),
        ("trace.enabled", serde_json::json!(true)),
        ("trace.canonical", serde_json::Value::Null),
        (
            "firestore.textSearch.fidelity",
            serde_json::json!("deterministic-basic"),
        ),
    ] {
        let row = rows.iter().find(|row| row["key"] == key).unwrap();
        assert_eq!(row["value"], value, "{key}");
        assert_eq!(row["source"], "accepted, no effect", "{key}");
    }
    // One note per key the file sets, none for the keys it leaves out.
    let notes = stderr(&out);
    for key in ["bind", "trace.enabled", "firestore.textSearch.fidelity"] {
        assert!(
            notes.contains(&format!(
                "fireemu.json: {key} is accepted for forward compatibility and currently has no effect\n"
            )),
            "{notes}"
        );
    }
    assert_eq!(notes.matches("note: ").count(), 3, "{notes}");
    assert!(!notes.contains("trace.canonical"), "{notes}");
    let out = run_in(&dir, &["config", "show"], None);
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(
        text.contains("trace.enabled = true (accepted, no effect)\n"),
        "{text}"
    );
    assert!(
        text.contains("trace.canonical = (unset) (accepted, no effect)\n"),
        "{text}"
    );
}

#[test]
fn config_show_names_the_firebase_json_that_is_actually_selected() {
    let dir = scratch("config-show-firebase-json");
    write(&dir, "other.json", "{}");
    write(
        &dir,
        "firebase.json",
        r#"{"emulators":{"firestore":{"port":8124}}}"#,
    );
    let show = |args: &[&str]| -> serde_json::Value {
        let mut all = vec!["config", "show", "--json"];
        all.extend_from_slice(args);
        let out = run_in(&dir, &all, None);
        assert!(out.status.success(), "{args:?}: {}", stderr(&out));
        let rows: Vec<serde_json::Value> = serde_json::from_slice(&out.stdout).unwrap();
        rows.into_iter()
            .find(|row| row["key"] == "firebaseJson")
            .unwrap()
    };
    // Found by the search in the working directory.
    let row = show(&[]);
    assert!(
        row["value"].as_str().unwrap().ends_with("firebase.json"),
        "{row}"
    );
    assert_eq!(row["source"], "discovered");
    // Named on the command line, or as the --config file.
    let row = show(&["--firebase-json", "other.json"]);
    assert!(
        row["value"].as_str().unwrap().ends_with("other.json"),
        "{row}"
    );
    assert_eq!(row["source"], "explicit (--firebase-json)");
    let row = show(&["--config", "firebase.json"]);
    assert!(
        row["value"].as_str().unwrap().ends_with("firebase.json"),
        "{row}"
    );
    assert_eq!(row["source"], "explicit (--config)");
    // Named by the canonical configuration, unless a flag chose another file.
    write(
        &dir,
        "chosen.json",
        r#"{"schemaVersion":1,"firebaseJson":"other.json"}"#,
    );
    let row = show(&["--config", "chosen.json"]);
    assert!(
        row["value"].as_str().unwrap().ends_with("other.json"),
        "{row}"
    );
    assert_eq!(row["source"], "explicit");
    let row = show(&[
        "--config",
        "chosen.json",
        "--firebase-json",
        "firebase.json",
    ]);
    assert!(
        row["value"].as_str().unwrap().ends_with("firebase.json"),
        "{row}"
    );
    assert_eq!(row["source"], "explicit (--firebase-json)");
    // No Firebase configuration at all.
    let bare = scratch("config-show-no-firebase-json");
    write(&bare, "fireemu.json", r#"{"schemaVersion":1}"#);
    let out = run_in(&bare, &["config", "show", "--json"], None);
    let rows: Vec<serde_json::Value> = serde_json::from_slice(&out.stdout).unwrap();
    let row = rows
        .iter()
        .find(|row| row["key"] == "firebaseJson")
        .unwrap();
    assert_eq!(row["value"], serde_json::Value::Null);
    assert_eq!(row["source"], "unset");
}

#[test]
fn log_verbosity_quiet_keeps_the_notes_about_keys_without_effect_off_standard_error() {
    let dir = scratch("no-effect-note-verbosity");
    let config = write(
        &dir,
        "fireemu.json",
        r#"{"schemaVersion":1,"trace":{"enabled":true}}"#,
    );
    let config = config.to_str().unwrap();
    for (level, shown) in [("quiet", false), ("info", true)] {
        let out = exec_with(&["--config", config, "--log-verbosity", level], &["true"]);
        assert!(out.status.success(), "{level}: {}", stderr(&out));
        assert_eq!(
            stderr(&out).contains("trace.enabled is accepted for forward compatibility"),
            shown,
            "{level}: {}",
            stderr(&out)
        );
    }
}

#[test]
fn config_show_defaults_cover_every_schema_leaf_without_loading_the_reference() {
    let dir = scratch("config-show-defaults");
    write(&dir, "fireemu.reference.toml", "not a configuration");
    let out = run_in(&dir, &["config", "show", "--json"], None);
    assert!(out.status.success(), "{}", stderr(&out));
    let rows: Vec<serde_json::Value> = serde_json::from_slice(&out.stdout).unwrap();
    let schema: serde_json::Value =
        serde_json::from_str(include_str!("../../../spec/config/fireemu.schema.json")).unwrap();
    let mut pending = vec![(String::new(), &schema)];
    let mut leaves = std::collections::BTreeSet::new();
    while let Some((path, node)) = pending.pop() {
        if let Some(properties) = node["properties"].as_object() {
            for (name, node) in properties {
                pending.push((
                    if path.is_empty() {
                        name.clone()
                    } else {
                        format!("{path}.{name}")
                    },
                    node,
                ));
            }
        } else {
            let row = rows.iter().find(|row| row["key"] == path).unwrap();
            assert_eq!(
                row["description"],
                node["description"].as_str().unwrap_or("")
            );
            if path == "bind" {
                // Accepted but never read: the schema default is not shown as if in effect.
                assert_eq!(row["value"], serde_json::Value::Null);
                assert_eq!(row["source"], "accepted, no effect");
            } else if let Some(default) = node.get("default") {
                assert_eq!(&row["value"], default, "{path}");
                assert_eq!(
                    row["source"],
                    match path.as_str() {
                        "firestore.history.maxBytes"
                        | "firestore.deletedDatabaseIdCooldownSeconds" => "default (schema)",
                        "firestore.missingIndexes" => "derived from profile",
                        _ => "default",
                    },
                    "{path}"
                );
            }
            leaves.insert(path);
        }
    }
    assert_eq!(rows.len(), leaves.len());
    assert_eq!(
        rows.iter()
            .map(|row| row["key"].as_str().unwrap().to_owned())
            .collect::<std::collections::BTreeSet<_>>(),
        leaves
    );
    for (key, value) in [
        ("firestore.edition", serde_json::json!("standard")),
        ("firestore.apiMode", serde_json::json!("native")),
        ("daemon.seed", serde_json::json!(42)),
        ("daemon.authProject", serde_json::json!("demo-app")),
        ("daemon.httpPort", serde_json::json!(9099)),
        ("daemon.storagePort", serde_json::json!(9199)),
        ("daemon.functionsPort", serde_json::json!(5001)),
        ("daemon.eventarcPort", serde_json::json!(9299)),
        ("daemon.tasksPort", serde_json::json!(9499)),
        ("daemon.pubsubPort", serde_json::json!(8085)),
        ("daemon.loggingPort", serde_json::json!(4500)),
        (
            "auth.idTokenSigning",
            serde_json::json!("unsigned-emulator"),
        ),
        ("auth.apiKeys", serde_json::json!([])),
        ("auth.logActionCodes", serde_json::json!(true)),
        ("auth.forwardInboundCredentials", serde_json::json!(false)),
        ("events.maxAttempts", serde_json::json!(4)),
        ("functions.maxGlobalConcurrency", serde_json::json!(8)),
        ("functions.unservedTriggers", serde_json::json!("refuse")),
        ("scheduler.catchUp", serde_json::json!("all")),
        ("scheduler.maxCatchUpRuns", serde_json::json!(1000)),
        ("appCheck.services.auth", serde_json::json!("off")),
        ("appCheck.services.firestore", serde_json::json!("off")),
        ("appCheck.services.storage", serde_json::json!("off")),
    ] {
        let row = rows.iter().find(|row| row["key"] == key).unwrap();
        assert_eq!(row["value"], value, "{key}");
        assert_eq!(row["source"], "default", "{key}");
    }
}

#[test]
fn init_reference_is_complete_valid_toml_and_preserves_the_minimal_config() {
    let dir = scratch("init-reference");
    let out = run_in(&dir, &["init", "--yes", "--reference"], None);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        format!(
            "created {}\ncreated {}\nnext: fireemu up (fireemu.toml in this directory is loaded automatically)\n",
            dir.canonicalize().unwrap().join("fireemu.reference.toml").display(),
            dir.canonicalize().unwrap().join("fireemu.toml").display(),
        )
    );
    let minimal = std::fs::read(dir.join("fireemu.toml")).unwrap();
    let config: serde_json::Value = toml::from_str(std::str::from_utf8(&minimal).unwrap()).unwrap();
    assert_eq!(config.as_object().unwrap().len(), 4);
    let reference = std::fs::read_to_string(dir.join("fireemu.reference.toml")).unwrap();
    assert!(reference.contains("not loaded by fireemu"));
    assert!(reference.starts_with(&format!("#:schema {}\n", config_schema_url())));
    assert!(reference.contains("makes it explicit"));
    assert!(reference.contains("Edit fireemu.toml to configure it."));
    let keys: Vec<_> = reference
        .lines()
        .filter(|line| line.starts_with("# ") && line.ends_with(':'))
        .take(2)
        .collect();
    assert_eq!(keys, ["# schemaVersion:", "# profile:"]);

    assert!(std::str::from_utf8(&minimal)
        .unwrap()
        .lines()
        .skip(1)
        .take(2)
        .eq(["schemaVersion = 1", "profile = \"strict\""]));
    let active = reference
        .lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n");
    let parsed: serde_json::Value = toml::from_str(&active).unwrap();
    assert!(parsed.pointer("/auth/allowUnsignedIdTokens").is_none());
    assert!(parsed.pointer("/auth/idpSigners").is_none());
    assert!(parsed.pointer("/eventarc/oauthCredentials").is_none());
    assert!(parsed.pointer("/auth/totp").is_none());
    let schema: serde_json::Value =
        serde_json::from_str(include_str!("../../../spec/config/fireemu.schema.json")).unwrap();
    let mut pending = vec![(String::new(), &schema)];
    while let Some((prefix, node)) = pending.pop() {
        if let Some(properties) = node["properties"].as_object() {
            for (key, node) in properties {
                let path = if prefix.is_empty() {
                    key.clone()
                } else {
                    format!("{prefix}.{key}")
                };
                pending.push((path, node));
            }
        } else {
            assert!(
                reference.contains(&format!("# {prefix}:")),
                "missing {prefix}"
            );
            let (_, section) = reference.split_once(&format!("# {prefix}:\n")).unwrap();
            assert!(
                section.lines().any(|line| line
                    .trim_start()
                    .trim_start_matches("# ")
                    .trim_start_matches('"')
                    .starts_with(&prefix)),
                "missing property {prefix}"
            );
            if let Some(value) = parsed.pointer(&format!("/{}", prefix.replace('.', "/"))) {
                assert_eq!(Some(value), node.get("default"), "{prefix}");
            }
        }
    }
    let out = run_in(&dir, &["init", "--reference"], None);
    assert!(!out.status.success());
    assert_eq!(std::fs::read(dir.join("fireemu.toml")).unwrap(), minimal);
    std::fs::remove_file(dir.join("fireemu.reference.toml")).unwrap();
    let out = run_in(&dir, &["init", "--reference"], None);
    assert!(out.status.success(), "{}", stderr(&out));
    let out = run_in(&dir, &["init", "--reference", "--force"], None);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(std::fs::read(dir.join("fireemu.toml")).unwrap(), minimal);
}

#[test]
#[allow(clippy::too_many_lines)]
fn config_show_uses_selected_files_and_runtime_normalization() {
    let dir = scratch("config-show-files");
    write(&dir, "fireemu.json", "invalid discovered configuration");
    write(
        &dir,
        "chosen.json",
        r#"{"schemaVersion":1,"profile":"emulator","firebaseJson":"missing.json","events":{"maxAttempts":7},"auth":{"authorizedDomains":[42,true,null],"totp":{},"providers":{"oidc":[{"name":"oidc.test","issuer":"https://issuer.example","clientId":"client","enabled":false}]},"quota":{"signUpQuotaConfig":{"quota":"1","startTime":"2026-01-01T00:00:00Z","quotaDuration":"0.5s"}}},"limits":{"enforcement":"observe"}}"#,
    );
    write(
        &dir,
        "selected.json",
        r#"{"emulators":{"firestore":{"port":8123},"auth":{"port":9123},"storage":{"port":9223},"functions":{"port":5023},"eventarc":{"port":9323},"tasks":{"port":9523},"pubsub":{"port":8223},"logging":{"port":4523}},"firestore":{"rules":"test.rules"},"storage":{"rules":"storage.rules"},"functions":{"source":"functions"}}"#,
    );
    std::fs::create_dir(dir.join("functions")).unwrap();
    write(
        &dir,
        ".firebaserc",
        r#"{"projects":{"default":"demo-selected"}}"#,
    );
    let out = run_in(
        &dir,
        &[
            "config",
            "show",
            "--config",
            "chosen.json",
            "--firebase-json",
            "selected.json",
            "--json",
        ],
        None,
    );
    assert!(out.status.success(), "{}", stderr(&out));
    let rows: Vec<serde_json::Value> = serde_json::from_slice(&out.stdout).unwrap();
    for (key, value, source) in [
        ("profile", serde_json::json!("emulator"), "explicit"),
        ("daemon.firestorePort", serde_json::json!(8123), "explicit"),
        ("daemon.httpPort", serde_json::json!(9123), "explicit"),
        ("daemon.storagePort", serde_json::json!(9223), "explicit"),
        ("daemon.functionsPort", serde_json::json!(5023), "explicit"),
        ("daemon.eventarcPort", serde_json::json!(9323), "explicit"),
        ("daemon.tasksPort", serde_json::json!(9523), "explicit"),
        ("daemon.pubsubPort", serde_json::json!(8223), "explicit"),
        ("daemon.loggingPort", serde_json::json!(4523), "explicit"),
        (
            "daemon.authProject",
            serde_json::json!("demo-selected"),
            ".firebaserc",
        ),
        ("events.maxAttempts", serde_json::json!(7), "explicit"),
        (
            "auth.authorizedDomains",
            serde_json::json!(["42", "true"]),
            "explicit",
        ),
        (
            "auth.improvedEmailPrivacy",
            serde_json::json!(false),
            "derived from profile",
        ),
        ("auth.totp.periodSeconds", serde_json::json!(30), "default"),
        (
            "limits.enforcement",
            serde_json::json!("observe"),
            "accepted, no effect",
        ),
        (
            "firestore.history.maxBytes",
            serde_json::json!(1_073_741_824_u64),
            "default (schema)",
        ),
    ] {
        let row = rows.iter().find(|row| row["key"] == key).unwrap();
        assert_eq!(row["value"], value, "{key}");
        assert_eq!(row["source"], source, "{key}");
    }
    // chosen.json names missing.json, but --firebase-json selected.json is the file in use.
    let firebase_json = rows
        .iter()
        .find(|row| row["key"] == "firebaseJson")
        .unwrap();
    assert!(
        firebase_json["value"]
            .as_str()
            .unwrap()
            .ends_with("selected.json"),
        "{firebase_json}"
    );
    assert_eq!(firebase_json["source"], "explicit (--firebase-json)");
    let rules = rows
        .iter()
        .find(|row| row["key"] == "rules.source")
        .unwrap();
    assert!(rules["value"].as_str().unwrap().ends_with("test.rules"));
    assert_eq!(rules["source"], "explicit");
    for (key, suffix) in [
        ("storage.rules", "storage.rules"),
        ("functions.source", "functions"),
    ] {
        let row = rows.iter().find(|row| row["key"] == key).unwrap();
        assert!(row["value"].as_str().unwrap().ends_with(suffix));
        assert_eq!(row["source"], "explicit");
    }
    let providers = rows
        .iter()
        .find(|row| row["key"] == "auth.providers.oidc")
        .unwrap();
    assert_eq!(providers["value"][0]["name"], "oidc.test");
    let quota = rows.iter().find(|row| row["key"] == "auth.quota").unwrap();
    assert_eq!(
        quota["value"]["signUpQuotaConfig"]["quotaDuration"],
        "0.500000000s"
    );
    let out = run_in(
        &dir,
        &[
            "config",
            "show",
            "--firebase-json",
            "selected.json",
            "--json",
        ],
        None,
    );
    assert!(out.status.success(), "{}", stderr(&out));
    let out = run_in(&dir, &["config", "show"], None);
    assert!(!out.status.success());
    assert!(out.stdout.is_empty());
    for args in [
        vec!["config"],
        vec!["config", "other"],
        vec!["config", "show", "--config"],
        vec!["config", "show", "--firebase-json"],
        vec!["config", "show", "--nope"],
    ] {
        assert_eq!(run_in(&dir, &args, None).status.code(), Some(2), "{args:?}");
    }
}

#[test]
fn init_reference_combines_flags_and_refuses_unsafe_replacement() {
    let dir = scratch("init-reference-options");
    write(&dir, "project.json", "{}");
    let out = run_in(
        &dir,
        &[
            "init",
            "--reference",
            "--profile",
            "emulator",
            "--firebase-json",
            "project.json",
            "--yes",
        ],
        None,
    );
    assert!(out.status.success(), "{}", stderr(&out));
    let config: serde_json::Value =
        toml::from_str(&std::fs::read_to_string(dir.join("fireemu.toml")).unwrap()).unwrap();
    assert_eq!(config["profile"], "emulator");
    assert_eq!(config["firebaseJson"], "project.json");
    let out = run_in(&dir, &["init", "--reference", "--reference"], None);
    assert_eq!(out.status.code(), Some(2));
    std::fs::remove_file(dir.join("fireemu.reference.toml")).unwrap();
    std::fs::create_dir(dir.join("fireemu.reference.toml")).unwrap();
    let out = run_in(&dir, &["init", "--reference", "--force"], None);
    assert!(!out.status.success());
    #[cfg(unix)]
    {
        std::fs::remove_dir(dir.join("fireemu.reference.toml")).unwrap();
        write(&dir, "keep.json", "keep");
        std::os::unix::fs::symlink(dir.join("keep.json"), dir.join("fireemu.reference.toml"))
            .unwrap();
        let out = run_in(&dir, &["init", "--reference", "--force"], None);
        assert!(!out.status.success());
        assert_eq!(
            std::fs::read_to_string(dir.join("keep.json")).unwrap(),
            "keep"
        );
    }
}

type Obstacle = fn(&Path);

/// A refused `init --reference` leaves nothing behind: the reference destination is checked
/// before `fireemu.toml` is written, with and without `--force`, for each kind of obstacle.
#[test]
fn init_reference_refusal_leaves_no_fireemu_toml_behind() {
    let init = ["init", "--reference", "--profile", "strict", "--yes"];
    let with_force = [
        "init",
        "--reference",
        "--profile",
        "strict",
        "--yes",
        "--force",
    ];
    let mut obstacles: Vec<(&str, Obstacle)> = vec![
        ("an existing file", |p| std::fs::write(p, "keep").unwrap()),
        ("a directory", |p| std::fs::create_dir(p).unwrap()),
    ];
    #[cfg(unix)]
    obstacles.push(("a symbolic link", |p| {
        std::os::unix::fs::symlink(p.with_file_name("elsewhere"), p).unwrap();
    }));
    for (label, make) in obstacles {
        // Without --force every obstacle refuses, a regular file included.
        // With --force only a regular file may be replaced.
        for (force, args) in [(false, &init[..]), (true, &with_force[..])] {
            let refused = !(force && label == "an existing file");
            let dir = scratch(&format!(
                "init-reference-atomic-{}-{force}",
                label.replace(' ', "-")
            ));
            let reference = dir.join("fireemu.reference.toml");
            make(&reference);
            let out = run_in(&dir, args, None);
            assert_eq!(
                !out.status.success(),
                refused,
                "{label}, force={force}: {}",
                stderr(&out)
            );
            assert_eq!(
                dir.join("fireemu.toml").exists(),
                !refused,
                "{label}, force={force}: fireemu.toml must exist only if the command succeeded"
            );
        }
    }
    // An existing fireemu.toml is left alone when the reference is what is refused.
    let dir = scratch("init-reference-atomic-existing-config");
    write(&dir, "fireemu.toml", "keep me");
    std::fs::create_dir(dir.join("fireemu.reference.toml")).unwrap();
    let out = run_in(
        &dir,
        &[
            "init",
            "--reference",
            "--profile",
            "strict",
            "--yes",
            "--force",
        ],
        None,
    );
    assert!(!out.status.success());
    assert_eq!(
        std::fs::read_to_string(dir.join("fireemu.toml")).unwrap(),
        "keep me"
    );
}

/// The port arguments every successful scenario needs.
const PORTS: [&str; 18] = [
    "--firestore-port",
    "0",
    "--http-port",
    "0",
    "--storage-port",
    "0",
    "--pubsub-port",
    "0",
    "--eventarc-port",
    "0",
    "--tasks-port",
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
    let out = exec_with(&[], &["/bin/sh", "-c", "exit 7"]);
    assert_eq!(out.status.code(), Some(7));
    let mut args: Vec<&str> = vec!["emulators:exec"];
    args.extend_from_slice(&PORTS);
    args.extend_from_slice(&["--", "/bin/sh", "-c", "exit 7"]);
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

#[cfg(unix)]
#[test]
fn emulators_exec_accepts_the_official_positional_shell_script() {
    let mut args: Vec<&str> = vec!["emulators:exec"];
    args.extend_from_slice(&PORTS);
    args.push("exit 7");

    let out = run(&args);

    assert_eq!(out.status.code(), Some(7), "{}", stderr(&out));

    let mut args: Vec<&str> = vec!["emulators:exec", "exit 7"];
    args.extend_from_slice(&PORTS);

    let out = run(&args);

    assert_eq!(out.status.code(), Some(7), "{}", stderr(&out));
}

#[cfg(unix)]
#[test]
fn explicit_exec_argv_does_not_shell_expand_metacharacters() {
    let out = exec_with(
        &[],
        &[
            "/bin/sh",
            "-c",
            "test \"$1\" = '$HOME;*'",
            "fireemu",
            "$HOME;*",
        ],
    );

    assert!(out.status.success(), "{}", stderr(&out));
}

#[cfg(unix)]
#[test]
fn exec_does_not_copy_command_secrets_or_control_text_into_its_log() {
    const SECRET: &str = "FIREEMU_EXEC_INLINE_SECRET_7bf32d";

    let mut args: Vec<&str> = vec![
        "emulators:exec",
        "true # FIREEMU_EXEC_INLINE_SECRET_7bf32d\n# forged-log-line",
    ];
    args.extend_from_slice(&PORTS);
    let positional = run(&args);
    assert!(positional.status.success(), "{}", stderr(&positional));
    assert!(!String::from_utf8_lossy(&positional.stdout).contains(SECRET));
    assert!(!stderr(&positional).contains(SECRET));
    assert!(!String::from_utf8_lossy(&positional.stdout).contains("forged-log-line"));

    let explicit = exec_with(
        &[],
        &[
            "/bin/sh",
            "-c",
            "test \"$1\" = \"$2\"",
            "fireemu",
            SECRET,
            SECRET,
        ],
    );
    assert!(explicit.status.success(), "{}", stderr(&explicit));
    assert!(!String::from_utf8_lossy(&explicit.stdout).contains(SECRET));
    assert!(!stderr(&explicit).contains(SECRET));
}

#[test]
fn init_noninteractive_defaults_to_strict_and_detects_firebase_json() {
    let dir = scratch("init-default");
    write(&dir, "firebase.json", "{}\n");

    let out = run_in(&dir, &["init", "--yes"], None);
    assert!(out.status.success(), "{}", stderr(&out));
    let path = dir.join("fireemu.toml");
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(text.ends_with('\n'));
    assert!(text.starts_with(&format!("#:schema {}\n", config_schema_url())));
    let generated: serde_json::Value = toml::from_str(&text).unwrap();
    assert_eq!(generated["$schema"], config_schema_url());
    assert_eq!(generated["schemaVersion"], 1);
    assert_eq!(generated["profile"], "strict");
    assert_eq!(generated["firebaseJson"], "firebase.json");
    assert_eq!(generated["firestore"]["edition"], "standard");
    assert_eq!(generated["firestore"]["apiMode"], "native");
    assert!(String::from_utf8_lossy(&out.stdout)
        .contains("next: fireemu up (fireemu.toml in this directory is loaded automatically)"));

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
        stdout.contains("behaves like production Firebase, including index and limit checks"),
        "{stdout}"
    );
    assert!(
        stdout.contains("emulator: reproduces the pinned official emulator behavior"),
        "{stdout}"
    );
    assert!(
        stdout.contains("Use it when migrating from the official emulator too."),
        "{stdout}"
    );
    assert!(
        stdout.contains(
            "Only for checking alignment with the official emulator; not needed when migrating."
        ),
        "{stdout}"
    );
    assert!(
        stdout.contains("loaded again on every fireemu start"),
        "{stdout}"
    );
    assert!(stdout.contains("Create fireemu.toml? [Y/n]"), "{stdout}");
    let generated: serde_json::Value =
        toml::from_str(&std::fs::read_to_string(dir.join("fireemu.toml")).unwrap()).unwrap();
    assert_eq!(generated["profile"], "strict");
    assert_eq!(generated["firebaseJson"], "firebase.json");

    let dir = scratch("init-wizard-emulator-without-detected-config");
    let out = run_in(&dir, &["init", "--interactive"], Some("emulator\n\ny\n"));
    assert!(out.status.success(), "{}", stderr(&out));
    let generated: serde_json::Value =
        toml::from_str(&std::fs::read_to_string(dir.join("fireemu.toml")).unwrap()).unwrap();
    assert_eq!(generated["profile"], "emulator");
    assert!(generated.get("firebaseJson").is_none());
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
            "emulator",
            "--firebase-json",
            "project.json",
        ],
        None,
    );
    assert!(out.status.success(), "{}", stderr(&out));
    let generated: serde_json::Value =
        toml::from_str(&std::fs::read_to_string(explicit.join("fireemu.toml")).unwrap()).unwrap();
    assert_eq!(generated["profile"], "emulator");
    assert_eq!(generated["firebaseJson"], "project.json");
    assert!(!String::from_utf8_lossy(&out.stdout).contains("Profiles:"));

    let strict = scratch("init-explicit-strict");
    let out = run_in(&strict, &["init", "--yes", "--profile", "strict"], None);
    assert!(out.status.success(), "{}", stderr(&out));
    let generated: serde_json::Value =
        toml::from_str(&std::fs::read_to_string(strict.join("fireemu.toml")).unwrap()).unwrap();
    assert_eq!(generated["profile"], "strict");

    let redirected = scratch("init-redirected");
    let out = run_in(&redirected, &["init"], Some("emulator\nmissing.json\nn\n"));
    assert!(out.status.success(), "{}", stderr(&out));
    let generated: serde_json::Value =
        toml::from_str(&std::fs::read_to_string(redirected.join("fireemu.toml")).unwrap()).unwrap();
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
            vec!["init", "--profile", "strict", "--profile", "emulator"],
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
        assert!(!dir.join("fireemu.toml").exists(), "{label}");
    }

    let dir = scratch("init-usage-control-character");
    let out = run_in(&dir, &["init", "--bad-\u{1b}[31m"], None);
    assert_eq!(out.status.code(), Some(2));
    assert!(!stderr(&out).contains('\u{1b}'), "{}", stderr(&out));
    assert!(stderr(&out).contains("\\u{1b}"), "{}", stderr(&out));
}

#[test]
fn init_force_validates_the_firebase_source_before_replacing_a_regular_file() {
    let dir = scratch("init-force-validation");
    let destination = write(&dir, "fireemu.toml", "keep this exact content\n");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        std::fs::set_permissions(&destination, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
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
        toml::from_str(&std::fs::read_to_string(destination).unwrap()).unwrap();
    assert_eq!(generated["firebaseJson"], "valid.json");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        assert_eq!(
            std::fs::metadata(dir.join("fireemu.toml"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    let absent = scratch("init-force-absent-destination");
    write(&absent, "valid.json", "{}\n");
    let out = run_in(
        &absent,
        &["init", "--yes", "--force", "--firebase-json", "valid.json"],
        None,
    );
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(absent.join("fireemu.toml").is_file());
}

#[test]
fn init_force_refuses_missing_canonical_and_directory_sources_or_destinations() {
    for (label, source, body, fragment) in [
        ("missing", "missing.json", None, "cannot read"),
        (
            "canonical",
            "other-fireemu.toml",
            Some(r#"{"schemaVersion":1}"#),
            "not a firebase.json",
        ),
        ("non-object", "array.json", Some("[]"), "must be an object"),
    ] {
        let dir = scratch(&format!("init-source-{label}"));
        if let Some(body) = body {
            write(&dir, source, body);
        }
        let out = run_in(&dir, &["init", "--yes", "--firebase-json", source], None);
        assert_eq!(out.status.code(), Some(1), "{label}: {}", stderr(&out));
        assert!(stderr(&out).contains(fragment), "{label}: {}", stderr(&out));
        assert!(!dir.join("fireemu.toml").exists());
    }

    let dir = scratch("init-control-character-source");
    let source = "missing-\u{1b}[31m.json";
    let out = run_in(&dir, &["init", "--yes", "--firebase-json", source], None);
    assert_eq!(out.status.code(), Some(1));
    assert!(!stderr(&out).contains('\u{1b}'), "{}", stderr(&out));
    assert!(stderr(&out).contains("\\u{1b}"), "{}", stderr(&out));

    let dir = scratch("init-directory-destination");
    std::fs::create_dir(dir.join("fireemu.toml")).unwrap();
    let out = run_in(&dir, &["init", "--yes", "--force"], None);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("not a regular file"));
    assert!(dir.join("fireemu.toml").is_dir());
}

#[cfg(unix)]
#[test]
fn init_force_refuses_a_symlink_destination_without_touching_its_target() {
    use std::os::unix::fs::symlink;

    let dir = scratch("init-symlink");
    let target = write(&dir, "target.json", "keep\n");
    let destination = dir.join("fireemu.toml");
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
    for (level, banner) in [
        ("quiet", false),
        ("SILENT", false),
        ("info", true),
        ("DEBUG", true),
    ] {
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
    assert!(stderr(&out).contains("quiet, silent, info, debug"));
}

#[test]
fn ui_is_an_exec_only_official_flag() {
    let out = run(&["up", "--ui"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(stderr(&out).contains("unknown argument --ui"));
}

#[test]
fn debug_logging_redacts_seed_project_and_app_check_digests() {
    let dir = scratch("debug-redaction");
    let config = write(
        &dir,
        "fireemu.json",
        r#"{
  "schemaVersion": 1,
  "daemon": {"seed": 918273645, "authProject": "demo-sensitive-project"},
  "appCheck": {
    "enabled": true,
    "apps": [{
      "projectId": "demo-sensitive-project",
      "projectNumber": "1234567890",
      "appId": "1:1234567890:web:redaction",
      "debugTokenSha256": ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]
    }]
  }
}"#,
    );
    let output = exec_with(
        &[
            "--config",
            config.to_str().unwrap(),
            "--only",
            "auth",
            "--log-verbosity",
            "debug",
        ],
        &["true"],
    );
    let logs = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(output.status.success(), "{logs}");
    for sensitive in [
        "918273645",
        "demo-sensitive-project",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    ] {
        assert!(
            !logs.contains(sensitive),
            "debug logs exposed {sensitive}: {logs}"
        );
    }
    assert!(logs.contains("resolved config:"));
    assert!(logs.contains("[redacted]"));
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn inspect_functions_passes_the_node_inspector_through_to_the_runner() {
    let dir = scratch("inspect");
    // With no codebase there is no runner to start, so the flag only has to be accepted.
    let out = exec_with(&["--inspect-functions"], &["true"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let out = exec_with(&["--inspect-functions", "true"], &["true"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let out = exec_with(&["--inspect-functions", "9330"], &["true"]);
    assert!(out.status.success(), "{}", stderr(&out));
    for port in ["1024", "65535"] {
        let out = exec_with(&["--inspect-functions", port], &["true"]);
        assert!(out.status.success(), "{port}: {}", stderr(&out));
    }

    for port in ["0", "1023", "65536"] {
        let out = exec_with(&["--inspect-functions", port], &["true"]);
        assert_eq!(out.status.code(), Some(2), "{port}: {}", stderr(&out));
        assert!(
            stderr(&out).contains(&format!(
                "{port:?} is not a valid port for debugging, please pass an integer between 1024 and 65535 or true for a dynamic port."
            )),
            "{port}: {}",
            stderr(&out)
        );
    }

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
    args.extend_from_slice(&["--", "/bin/sh", "-c", &script]);
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
fn storage_target_rules_are_resolved_before_the_emulator_starts() {
    let dir = scratch("storage-targets");
    let rules = "rules_version = '2'; service firebase.storage { match /b/{bucket}/o { match /{path=**} { allow read, write: if false; } } }";
    write(&dir, "public.rules", rules);
    write(&dir, "private.rules", rules);
    let firebase = write(
        &dir,
        "firebase.json",
        r#"{"storage":[{"target":"public","rules":"public.rules"},{"target":"private","rules":"private.rules"}]}"#,
    );
    write(
        &dir,
        ".firebaserc",
        r#"{"projects":{"default":"demo-targets"},"targets":{"demo-targets":{"storage":{"public":["demo-targets.appspot.com"],"private":["private.example.test"]}}}}"#,
    );

    let out = exec_with(
        &[
            "--firebase-json",
            firebase.to_str().unwrap(),
            "--only",
            "storage:public",
        ],
        &["true"],
    );
    assert!(out.status.success(), "{}", stderr(&out));

    write(
        &dir,
        ".firebaserc",
        r#"{"projects":{"default":"demo-targets"},"targets":{"demo-targets":{"storage":{"public":["demo-targets.appspot.com"]}}}}"#,
    );
    let out = exec_with(
        &[
            "--firebase-json",
            firebase.to_str().unwrap(),
            "--only",
            "storage",
        ],
        &["true"],
    );
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).contains("targets.demo-targets.storage.private"),
        "{}",
        stderr(&out)
    );
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

    std::fs::remove_file(dir.join("firebase.json")).unwrap();
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

    let invalid = write(
        &dir,
        "invalid-fireemu.json",
        r#"{
  "schemaVersion": 1,
  "profile": "strict",
  "firebaseJson": "missing.json",
  "unknown": true,
  "firestore": { "edition": "standard", "apiMode": "native" }
}
"#,
    );
    let out = exec_with(&["--config", invalid.to_str().unwrap()], &["true"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).contains("unknown config key"),
        "{}",
        stderr(&out)
    );
    assert!(!stderr(&out).contains("cannot read"), "{}", stderr(&out));
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

    let out = exec_with(
        &["--firebase-json", firebase, "--inspect-functions", "9330"],
        &["true"],
    );
    let text = stderr(&out);
    assert_eq!(out.status.code(), Some(1), "{text}");
    assert!(
        text.contains("Cannot debug on a single port with multiple codebases"),
        "{text}"
    );

    let out = exec_with(
        &["--firebase-json", firebase, "--inspect-functions"],
        &["true"],
    );
    let text = stderr(&out);
    assert_eq!(out.status.code(), Some(1), "{text}");
    assert!(
        !text.contains("Cannot debug on a single port with multiple codebases"),
        "dynamic inspector ports must permit multiple codebases: {text}"
    );

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
fn a_referenced_rules_file_accepts_firebase_compatible_delimiters() {
    let dir = scratch("firebase-rules-delimiters");
    write(
        &dir,
        "firestore.rules",
        r#"rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    function allowedValues() {
      return [
        "one",
        "two",
      ]
    }

    match /items/{itemId} {
      allow read: if allowedValues().hasAny(["one"]);
    }
  }
}
"#,
    );
    let firebase = write(
        &dir,
        "firebase.json",
        r#"{"firestore": {"rules": "firestore.rules"}}"#,
    );

    let out = exec_with(
        &[
            "--firebase-json",
            firebase.to_str().unwrap(),
            "--only",
            "firestore",
        ],
        &["true"],
    );

    assert!(out.status.success(), "{}", stderr(&out));
}

#[test]
fn a_referenced_rules_file_accepts_firebase_null_escape() {
    let dir = scratch("firebase-rules-null-escape");
    write(
        &dir,
        "firestore.rules",
        r#"rules_version = '2';
service cloud.firestore {
  function isValidString(data) {
    return data.matches(".*(\r|\n|\\0|\u0000|\x00)+.*") == false;
  }
  match /databases/{database}/documents {
    match /items/{itemId} {
      allow read: if isValidString(itemId);
    }
  }
}
"#,
    );
    write(
        &dir,
        "storage.rules",
        r"rules_version = '2';
service firebase.storage {
  match /b/{bucket}/o {
    match /{path=**} {
      allow read: if false;
    }
  }
}
",
    );
    let firebase = write(
        &dir,
        "firebase.json",
        r#"{
  "firestore": {"rules": "firestore.rules"},
  "storage": {"rules": "storage.rules"},
  "emulators": {"auth": {}, "firestore": {}, "storage": {}}
}
"#,
    );

    let out = exec_with(
        &[
            "--firebase-json",
            firebase.to_str().unwrap(),
            "--only",
            "auth,firestore,storage",
        ],
        &["true"],
    );

    assert!(out.status.success(), "{}", stderr(&out));
}

#[test]
fn a_rules_parse_error_escapes_decoded_control_characters() {
    let dir = scratch("firebase-rules-control-diagnostic");
    write(
        &dir,
        "firestore.rules",
        r#"rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /items/{itemId} {
      allow read: if itemId.matches("\u0000(?=x)");
    }
  }
}
"#,
    );
    let firebase = write(
        &dir,
        "firebase.json",
        r#"{"firestore": {"rules": "firestore.rules"}}"#,
    );

    let out = exec_with(
        &[
            "--firebase-json",
            firebase.to_str().unwrap(),
            "--only",
            "firestore",
        ],
        &["true"],
    );

    assert_eq!(out.status.code(), Some(1));
    let text = stderr(&out);
    let diagnostic = text.strip_suffix('\n').unwrap_or(&text);
    assert!(
        diagnostic.chars().all(|character| !character.is_control()),
        "{text:?}"
    );
    assert!(diagnostic.contains("\\0"), "{text:?}");
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
