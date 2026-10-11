//! `fireemu --help`, `fireemu <command> --help` and `fireemu help <command>`.
//!
//! Every scenario runs the shipped binary: what is asserted is what a user who types
//! `fireemu exec --help` actually gets (stdout, stderr and the exit code), including the rule
//! that `--help` after `--` belongs to the child command.

mod scratch;

use scratch::Scratch;

use std::process::{Command, Output, Stdio};

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_fireemu"))
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("fireemu runs")
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// Help is documentation: stdout only, exit 0, nothing on stderr.
fn assert_help(out: &Output, label: &str) -> String {
    assert_eq!(out.status.code(), Some(0), "{label}: {out:?}");
    assert!(out.stderr.is_empty(), "{label}: stderr {}", stderr(out));
    let text = stdout(out);
    assert!(text.starts_with("fireemu"), "{label}: {text}");
    text
}

const COMMANDS: [&str; 6] = [
    "init",
    "up",
    "exec",
    "emulators:export",
    "doctor",
    "capabilities",
];

/// Every spelling of a command and the canonical command whose help it must print.
const SPELLINGS: [(&str, &str); 8] = [
    ("init", "init"),
    ("up", "up"),
    ("emulators:start", "up"),
    ("exec", "exec"),
    ("emulators:exec", "exec"),
    ("emulators:export", "emulators:export"),
    ("doctor", "doctor"),
    ("capabilities", "capabilities"),
];

#[test]
fn the_overall_help_lists_every_command_and_points_to_the_command_help() {
    let mut seen = Vec::new();
    for args in [&["--help"][..], &["-h"], &["help"], &["help", "--help"]] {
        let text = assert_help(&run(args), &args.join(" "));
        for command in COMMANDS {
            assert!(
                text.contains(&format!("\n  {command} ")),
                "{args:?}: {command}"
            );
        }
        for alias in ["emulators:start", "emulators:exec"] {
            assert!(text.contains(alias), "{args:?}: {alias}");
        }
        assert!(text.contains("fireemu help <command>"), "{args:?}");
        assert!(text.contains("fireemu <command> --help"), "{args:?}");
        assert!(text.contains("--version"), "{args:?}");
        seen.push(text);
    }
    assert!(seen.windows(2).all(|pair| pair[0] == pair[1]));
}

#[test]
fn every_command_prints_the_same_help_through_all_three_spellings() {
    for (spelling, canonical) in SPELLINGS {
        let long = assert_help(&run(&[spelling, "--help"]), &format!("{spelling} --help"));
        let short = assert_help(&run(&[spelling, "-h"]), &format!("{spelling} -h"));
        let word = assert_help(&run(&["help", spelling]), &format!("help {spelling}"));
        let canonical_text = assert_help(&run(&["help", canonical]), &format!("help {canonical}"));
        assert_eq!(long, short, "{spelling}");
        assert_eq!(long, word, "{spelling}");
        assert_eq!(
            long, canonical_text,
            "{spelling}: aliases print their command's help"
        );
        assert!(long.contains("usage:"), "{spelling}");
        assert!(
            long.contains(&format!("fireemu {canonical}")),
            "{spelling}: {long}"
        );
    }
}

#[test]
fn help_for_different_commands_is_different() {
    let texts: Vec<String> = COMMANDS
        .iter()
        .map(|command| assert_help(&run(&["help", command]), command))
        .collect();
    for (i, a) in texts.iter().enumerate() {
        for b in &texts[i + 1..] {
            assert_ne!(a, b);
        }
    }
}

#[test]
fn the_exec_help_explains_the_double_dash_form_and_the_exit_status() {
    let text = assert_help(&run(&["exec", "--help"]), "exec --help");
    assert!(
        text.contains("fireemu exec [options] -- <command...>"),
        "{text}"
    );
    assert!(text.contains("\"shell script\""), "{text}");
    assert!(text.contains("--ui"), "{text}");
    assert!(text.contains("after `--`"), "{text}");
    assert!(text.contains("exit"), "{text}");
}

#[test]
fn the_up_help_does_not_offer_the_exec_only_ui_flag_as_an_option() {
    let up = assert_help(&run(&["up", "--help"]), "up --help");
    assert!(!up.contains("\n  --ui "), "{up}");
    assert!(up.contains("--ui-port"), "{up}");
}

#[test]
fn help_wins_over_other_options_wherever_it_stands() {
    for args in [
        &["up", "--only", "bogus", "--help"][..],
        &["up", "--help", "--only", "bogus"],
        &["up", "--firestore-port", "nope", "-h"],
        &["exec", "--help", "echo hi"],
        &["exec", "echo hi", "--help"],
        &["exec", "--project", "demo-x", "--help"],
        &["capabilities", "--help"],
        &["emulators:export", "./dir", "--help"],
        &["doctor", "--help"],
        &["init", "--yes", "--help"],
    ] {
        let text = assert_help(&run(args), &args.join(" "));
        assert!(text.contains("usage:"), "{args:?}");
    }
}

#[test]
fn a_value_taking_option_consumes_help_as_its_value() {
    // `--config --help` names a file called `--help`; it is a refusal, not a help request.
    let out = run(&["up", "--config", "--help"]);
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    assert!(!stdout(&out).contains("usage:"));
    let out = run(&["init", "--profile", "--help"]);
    assert_eq!(out.status.code(), Some(2), "{out:?}");
    assert!(!stdout(&out).contains("usage:"));
}

#[test]
fn help_does_not_start_anything_or_write_anything() {
    let dir = Scratch::new("help", "init-writes-nothing");
    let out = Command::new(env!("CARGO_BIN_EXE_fireemu"))
        .current_dir(&dir)
        .args(["init", "--help"])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
}

#[test]
fn an_unknown_command_in_help_is_a_usage_error_that_lists_the_commands() {
    let out = run(&["help", "frobnicate"]);
    assert_eq!(out.status.code(), Some(2), "{out:?}");
    assert!(out.stdout.is_empty());
    let message = stderr(&out);
    assert!(message.contains("unknown command frobnicate"), "{message}");
    for command in COMMANDS {
        assert!(message.contains(command), "{message}");
    }
}

#[test]
fn help_with_extra_arguments_is_a_usage_error() {
    let out = run(&["help", "up", "exec"]);
    assert_eq!(out.status.code(), Some(2), "{out:?}");
    assert!(out.stdout.is_empty());
}

#[test]
fn the_bare_usage_keeps_exit_two_and_points_to_help() {
    for args in [&[][..], &["emulators:frobnicate"]] {
        let out = run(args);
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        assert!(out.stdout.is_empty(), "{args:?}");
        let message = stderr(&out);
        assert!(message.contains("usage: fireemu"), "{message}");
        assert!(message.contains("fireemu --help"), "{message}");
    }
}

#[test]
fn an_unknown_argument_points_to_the_command_help() {
    for (args, command) in [
        (&["up", "--nope"][..], "up"),
        (&["emulators:start", "--nope"], "emulators:start"),
        (&["exec", "--nope"], "exec"),
        (&["emulators:exec", "--nope"], "emulators:exec"),
        (&["capabilities", "--nope"], "capabilities"),
        (&["emulators:export", "--nope"], "emulators:export"),
        (&["init", "--nope"], "init"),
    ] {
        let out = run(args);
        assert_eq!(out.status.code(), Some(2), "{args:?}: {out:?}");
        let message = stderr(&out);
        assert!(message.contains("unknown"), "{args:?}: {message}");
        assert!(
            message.contains(&format!("run `fireemu {command} --help` for the options")),
            "{args:?}: {message}"
        );
    }
}

#[test]
fn other_usage_errors_do_not_claim_an_unknown_argument() {
    let out = run(&["up", "--only"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(
        !stderr(&out).contains("for the options"),
        "{}",
        stderr(&out)
    );
}

#[cfg(unix)]
mod exec_passthrough {
    use super::*;

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

    fn exec(tail: &[&str]) -> Output {
        let mut args = vec!["exec"];
        args.extend_from_slice(&PORTS);
        args.extend_from_slice(tail);
        run(&args)
    }

    #[test]
    fn help_after_the_double_dash_belongs_to_the_child() {
        for flag in ["--help", "-h"] {
            let out = exec(&[
                "--",
                "/bin/sh",
                "-c",
                "echo \"child-arg:$1\"",
                "/bin/sh",
                flag,
            ]);
            assert_eq!(out.status.code(), Some(0), "{flag}: {out:?}");
            let text = stdout(&out);
            assert!(
                text.contains(&format!("child-arg:{flag}")),
                "{flag}: {text}"
            );
            assert!(!text.contains("usage:"), "{flag}: {text}");
        }
    }

    #[test]
    fn help_before_the_double_dash_is_still_help() {
        let out = exec(&["--help", "--", "/bin/sh", "-c", "echo ran"]);
        let text = assert_help(&out, "exec ... --help -- cmd");
        assert!(!text.contains("ran"));
    }

    #[test]
    fn help_inside_the_positional_shell_script_is_script_text() {
        let out = exec(&["echo script-text --help"]);
        assert_eq!(out.status.code(), Some(0), "{out:?}");
        let text = stdout(&out);
        assert!(text.contains("script-text --help"), "{text}");
        assert!(!text.contains("usage:"), "{text}");
    }

    #[test]
    fn a_standalone_help_option_next_to_a_script_is_help_and_runs_nothing() {
        let out = exec(&["echo should-not-run", "--help"]);
        let text = assert_help(&out, "exec script --help");
        assert!(!text.contains("should-not-run"));
    }
}

/// The documents an agent reads when it migrates a project must all recommend `strict`.
#[test]
fn the_profile_documentation_recommends_strict_including_for_migrations() {
    let schema: serde_json::Value =
        serde_json::from_str(include_str!("../../../spec/config/fireemu.schema.json")).unwrap();
    let description = schema["properties"]["profile"]["description"]
        .as_str()
        .unwrap();
    assert!(
        description.contains("strict is recommended, including when migrating"),
        "{description}"
    );
    assert!(
        description.contains("emulator is only for checking alignment"),
        "{description}"
    );
    let readme = include_str!("../../../README.md");
    assert!(readme.contains("Recommended, including when migrating from the official emulator"));
    assert!(readme.contains("### Migrating from the Firebase Local Emulator Suite"));
    assert!(readme.contains("it is not needed for a migration"));
    // The settings the README names as single-behavior relaxations exist in the schema.
    for (section, key) in [
        ("firestore", "enforceLimits"),
        ("auth", "improvedEmailPrivacy"),
        ("auth", "mfa"),
    ] {
        assert!(
            schema["properties"][section]["properties"][key].is_object(),
            "{section}.{key}"
        );
        assert!(
            readme.contains(&format!("`{section}.{key}`")),
            "{section}.{key}"
        );
    }
}

#[test]
fn doctor_arguments_are_checked_and_an_unknown_one_points_to_the_help() {
    // An unreachable control URL is attempted (not a usage error); a surplus argument is.
    let attempted = run(&["doctor", "--connect", "http://127.0.0.1:9"]);
    assert!(
        !stderr(&attempted).contains("usage: fireemu doctor"),
        "{}",
        stderr(&attempted)
    );
    for args in [
        &["doctor", "--connect", "http://127.0.0.1:9", "extra"][..],
        &["doctor", "--connect"],
        &["doctor", "--nope"],
    ] {
        let out = run(args);
        assert_eq!(out.status.code(), Some(2), "{args:?}: {out:?}");
        let message = stderr(&out);
        assert!(
            message.contains("usage: fireemu doctor"),
            "{args:?}: {message}"
        );
        assert!(
            message.contains("run `fireemu doctor --help` for the options"),
            "{args:?}: {message}"
        );
    }
}
