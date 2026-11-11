//! `fireemu config lint`: reports the settings a configuration sets that the daemon accepts and
//! never reads, and with `--deny-ineffective` fails when any is not on the allow list.

mod scratch;

use std::path::Path;
use std::process::{Command, Output, Stdio};

use scratch::Scratch;

fn fireemu(cwd: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_fireemu"))
        .current_dir(cwd)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

const TOML: &str = "schemaVersion = 1\nbind = \"127.0.0.1\"\n[trace]\nenabled = true\n[firestore.textSearch]\nfidelity = \"deterministic-basic\"\n";

fn project(name: &str, file: &str, text: &str) -> Scratch {
    let dir = Scratch::new("config-lint", name);
    std::fs::write(dir.join(file), text).unwrap();
    dir
}

#[test]
fn a_configuration_without_ineffective_settings_passes_even_when_denied() {
    let dir = project(
        "clean",
        "fireemu.toml",
        "schemaVersion = 1\nprofile = \"strict\"\n",
    );
    let output = fireemu(
        &dir,
        &[
            "config",
            "lint",
            "--config",
            "fireemu.toml",
            "--deny-ineffective",
        ],
    );
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(
        stdout(&output).contains("no ineffective settings"),
        "{}",
        stdout(&output)
    );
    assert_eq!(stderr(&output), "");
}

#[test]
fn deny_ineffective_fails_naming_every_setting_and_the_remedy() {
    let dir = project("denied", "fireemu.toml", TOML);
    let output = fireemu(
        &dir,
        &[
            "config",
            "lint",
            "--config",
            "fireemu.toml",
            "--deny-ineffective",
        ],
    );
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    let report = stdout(&output);
    for key in ["bind", "trace.enabled", "firestore.textSearch.fidelity"] {
        assert!(
            report.contains(&format!(
                "{key} is accepted for forward compatibility and currently has no effect"
            )),
            "{key}: {report}"
        );
    }
    let message = stderr(&output);
    assert!(message.starts_with("error: "), "{message}");
    assert!(message.contains("fireemu.toml"), "{message}");
    assert!(message.contains("3 settings"), "{message}");
    assert!(message.contains("--allow"), "{message}");
}

#[test]
fn without_deny_ineffective_the_report_is_informational() {
    let dir = project("informational", "fireemu.toml", TOML);
    let output = fireemu(&dir, &["config", "lint", "--config", "fireemu.toml"]);
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(
        stdout(&output).contains("bind is accepted"),
        "{}",
        stdout(&output)
    );
    assert_eq!(stderr(&output), "");
}

#[test]
fn allowed_keys_and_prefixes_are_reported_but_do_not_fail() {
    let dir = project("allowed", "fireemu.toml", TOML);
    let output = fireemu(
        &dir,
        &[
            "config",
            "lint",
            "--config",
            "fireemu.toml",
            "--deny-ineffective",
            "--allow",
            "bind",
            "--allow",
            "trace.enabled",
            "--allow",
            "firestore.textSearch.*",
        ],
    );
    assert!(output.status.success(), "{}", stderr(&output));
    let report = stdout(&output);
    assert!(report.contains("allowed: bind is accepted"), "{report}");
    assert!(
        report.contains("allowed: firestore.textSearch.fidelity is accepted"),
        "{report}"
    );
    assert!(!report.contains("ineffective: "), "{report}");
}

#[test]
fn one_setting_off_the_allow_list_still_fails() {
    let dir = project("near-miss", "fireemu.toml", TOML);
    let output = fireemu(
        &dir,
        &[
            "config",
            "lint",
            "--config",
            "fireemu.toml",
            "--deny-ineffective",
            "--allow",
            "bind",
            // Not the same key, and not a prefix of it.
            "--allow",
            "trace.canonical",
            "--allow",
            "firestore.textSearch.*",
        ],
    );
    assert_eq!(output.status.code(), Some(1));
    let message = stderr(&output);
    assert!(message.contains("1 setting "), "{message}");
    assert!(message.contains("trace.enabled"), "{message}");
    assert!(!message.contains("bind"), "{message}");
}

#[test]
fn an_allow_file_lists_keys_with_comments_and_blank_lines() {
    let dir = project("allow-file", "fireemu.toml", TOML);
    std::fs::write(
        dir.join("allow.txt"),
        "# future use\nbind\n\n  trace.*  \nfirestore.textSearch.fidelity # a comment\n",
    )
    .unwrap();
    let output = fireemu(
        &dir,
        &[
            "config",
            "lint",
            "--config",
            "fireemu.toml",
            "--deny-ineffective",
            "--allow-file",
            "allow.txt",
        ],
    );
    assert!(output.status.success(), "{}", stderr(&output));
}

#[test]
fn an_allow_entry_that_names_no_configuration_key_is_a_usage_error() {
    let dir = project("typo", "fireemu.toml", TOML);
    for entry in ["bnd", "trace", "nothing.*", ""] {
        let output = fireemu(
            &dir,
            &[
                "config",
                "lint",
                "--config",
                "fireemu.toml",
                "--deny-ineffective",
                "--allow",
                entry,
            ],
        );
        assert_eq!(
            output.status.code(),
            Some(2),
            "{entry:?}: {}",
            stderr(&output)
        );
        assert!(
            stderr(&output).contains("--allow"),
            "{entry:?}: {}",
            stderr(&output)
        );
    }
    let output = fireemu(
        &dir,
        &[
            "config",
            "lint",
            "--config",
            "fireemu.toml",
            "--allow-file",
            "missing.txt",
        ],
    );
    assert_eq!(output.status.code(), Some(2));
    assert!(
        stderr(&output).contains("missing.txt"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn json_output_lists_each_setting_with_its_allowed_state() {
    let dir = project(
        "json",
        "fireemu.json",
        r#"{"schemaVersion":1,"bind":"127.0.0.1","trace":{"enabled":false}}"#,
    );
    let output = fireemu(
        &dir,
        &[
            "config",
            "lint",
            "--config",
            "fireemu.json",
            "--json",
            "--deny-ineffective",
            "--allow",
            "bind",
        ],
    );
    assert_eq!(output.status.code(), Some(1));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["config"], "fireemu.json");
    assert_eq!(report["denied"], serde_json::json!(["trace.enabled"]));
    let settings = report["ineffective"].as_array().unwrap();
    assert_eq!(settings.len(), 2);
    assert_eq!(settings[0]["key"], "bind");
    assert_eq!(settings[0]["allowed"], true);
    assert_eq!(settings[1]["key"], "trace.enabled");
    assert_eq!(settings[1]["allowed"], false);
    assert!(settings[1]["note"]
        .as_str()
        .unwrap()
        .starts_with("trace.enabled is accepted"));
}

#[test]
fn a_configuration_the_daemon_refuses_fails_the_lint_with_the_same_message() {
    let dir = project(
        "refused",
        "fireemu.toml",
        "schemaVersion = 1\n[firestore]\nprot = 8080\n",
    );
    let output = fireemu(&dir, &["config", "lint", "--config", "fireemu.toml"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr(&output).contains("unknown config key firestore.prot"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn no_canonical_configuration_means_nothing_to_lint() {
    let dir = Scratch::new("config-lint", "nothing");
    let output = fireemu(&dir, &["config", "lint", "--deny-ineffective"]);
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(
        stdout(&output).contains("no fireemu.toml or fireemu.json"),
        "{}",
        stdout(&output)
    );
}

#[test]
fn the_configuration_is_found_by_discovery_like_the_other_commands() {
    let dir = project("discovered", "fireemu.toml", TOML);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&*dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::set_permissions(
            dir.join("fireemu.toml"),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
    }
    let output = fireemu(&dir, &["config", "lint", "--deny-ineffective"]);
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
}

#[test]
fn the_flags_belong_to_lint_only() {
    let dir = project("show", "fireemu.toml", TOML);
    let output = fireemu(
        &dir,
        &[
            "config",
            "show",
            "--config",
            "fireemu.toml",
            "--deny-ineffective",
        ],
    );
    assert_eq!(output.status.code(), Some(2));
    assert!(
        stderr(&output).contains("unknown argument --deny-ineffective"),
        "{}",
        stderr(&output)
    );
    let output = fireemu(&dir, &["config", "check"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(stderr(&output).contains("lint"), "{}", stderr(&output));
}

#[test]
fn the_allow_flags_belong_to_lint_only() {
    let dir = project("show-allow", "fireemu.toml", TOML);
    std::fs::write(dir.join("allow.txt"), "bind\n").unwrap();
    for flag in [["--allow", "bind"], ["--allow-file", "allow.txt"]] {
        let output = fireemu(
            &dir,
            &[
                "config",
                "show",
                "--config",
                "fireemu.toml",
                flag[0],
                flag[1],
            ],
        );
        assert_eq!(output.status.code(), Some(2), "{flag:?}");
        assert!(
            stderr(&output).contains(&format!("unknown argument {}", flag[0])),
            "{flag:?}: {}",
            stderr(&output)
        );
    }
}

#[test]
fn every_flag_is_read_wherever_it_stands_among_the_others() {
    let dir = project("order", "fireemu.toml", TOML);
    std::fs::write(dir.join("allow.txt"), "bind\n").unwrap();
    // `--allow-file` and `--allow` each consume their value and nothing else: the flag after
    // them still counts.
    for args in [
        vec![
            "config",
            "lint",
            "--allow-file",
            "allow.txt",
            "--deny-ineffective",
            "--config",
            "fireemu.toml",
        ],
        vec![
            "config",
            "lint",
            "--allow",
            "bind",
            "--deny-ineffective",
            "--config",
            "fireemu.toml",
        ],
        vec![
            "config",
            "lint",
            "--deny-ineffective",
            "--allow",
            "bind",
            "--config",
            "fireemu.toml",
        ],
    ] {
        let output = fireemu(&dir, &args);
        assert_eq!(
            output.status.code(),
            Some(1),
            "{args:?}: {}",
            stderr(&output)
        );
        assert!(
            stderr(&output).contains("trace.enabled"),
            "{args:?}: {}",
            stderr(&output)
        );
    }
}
