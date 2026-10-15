//! A canonical configuration file is checked against the schema: an unknown key or a value of
//! the wrong type is refused naming the file, the key's path and the type it should have had,
//! the same way for `fireemu.toml` and `fireemu.json` and for `up`, `exec` and `config show`.

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

/// The same refused document in both formats, with the path and the type its diagnostic names.
const REFUSED: [(&str, &str, &str); 4] = [
    (
        "fireemu.json",
        r#"{"schemaVersion": 1, "firestore": {"prot": 8080}}"#,
        "unknown config key firestore.prot",
    ),
    (
        "fireemu.toml",
        "schemaVersion = 1\n[firestore]\nprot = 8080\n",
        "unknown config key firestore.prot",
    ),
    (
        "fireemu.json",
        r#"{"schemaVersion": 1, "daemon": {"firestorePort": "8080"}}"#,
        "daemon.firestorePort must be an integer, found a string",
    ),
    (
        "fireemu.toml",
        "schemaVersion = 1\n[daemon]\nfirestorePort = \"8080\"\n",
        "daemon.firestorePort must be an integer, found a string",
    ),
];

#[test]
fn every_command_refuses_a_misspelt_key_or_a_wrong_type_naming_the_file_the_key_and_the_type() {
    for (file, text, expected) in REFUSED {
        let dir = Scratch::new("config-strict", "refused");
        std::fs::write(dir.join(file), text).unwrap();
        for args in [
            vec!["config", "show", "--config", file],
            vec!["up", "--config", file],
            vec!["exec", "--config", file, "--", "true"],
        ] {
            let output = fireemu(&dir, &args);
            assert!(!output.status.success(), "{file} {args:?}");
            let message = stderr(&output);
            assert!(
                message.contains(file) && message.contains(expected),
                "{file} {args:?}: {message}"
            );
        }
    }
}

/// Gives `path` an explicit mode, so that discovery's ownership and write-permission checks do
/// not depend on the umask of whoever runs the test.
#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) {}

#[test]
fn a_discovered_file_with_a_wrong_type_is_refused_too() {
    let dir = Scratch::new("config-strict", "discovered");
    set_mode(&dir, 0o755);
    std::fs::write(
        dir.join("fireemu.toml"),
        "schemaVersion = 1\n[projects]\nrequireDemoPrefix = \"yes\"\n",
    )
    .unwrap();
    set_mode(&dir.join("fireemu.toml"), 0o644);
    let output = fireemu(&dir, &["config", "show"]);
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("projects.requireDemoPrefix must be a boolean, found a string"),
        "{}",
        stderr(&output)
    );
}

/// The `config show --json` value of one key.
fn shown(output: &Output, key: &str) -> serde_json::Value {
    let rows: serde_json::Value = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|e| panic!("{e}: {}", stdout(output)));
    rows.as_array()
        .and_then(|rows| rows.iter().find(|row| row["key"] == key))
        .unwrap_or_else(|| panic!("no {key} row in {rows}"))["value"]
        .clone()
}

#[test]
fn a_referenced_firebase_json_without_sections_does_not_drop_the_canonical_files() {
    let dir = Scratch::new("config-strict", "layering");
    std::fs::write(
        dir.join("firebase.json"),
        r#"{"emulators": {"ui": {"enabled": false}}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("fireemu.json"),
        r#"{"schemaVersion": 1, "firebaseJson": "firebase.json", "rules": {"source": "firestore.rules"}, "storage": {"rules": "storage.rules"}, "functions": {"source": "fns"}}"#,
    )
    .unwrap();
    let output = fireemu(
        &dir,
        &["config", "show", "--json", "--config", "fireemu.json"],
    );
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(shown(&output, "rules.source"), "firestore.rules");
    assert_eq!(shown(&output, "storage.rules"), "storage.rules");
    assert_eq!(shown(&output, "functions.source"), "fns");
}

#[test]
fn the_notes_about_a_configuration_file_are_not_printed_when_the_log_is_quiet() {
    let dir = Scratch::new("config-strict", "quiet");
    std::fs::write(
        dir.join("fireemu.json"),
        r#"{"schemaVersion": 1, "firestore": {"rules": "unused.rules"}}"#,
    )
    .unwrap();
    let args = [
        "exec",
        "--only",
        "firestore",
        "--config",
        "fireemu.json",
        "--firestore-port",
        "0",
        "--http-port",
        "0",
        "--hub-port",
        "0",
        "--ui-port",
        "0",
    ];
    let run = |extra: &[&str]| {
        let mut all = args.to_vec();
        all.extend(extra);
        all.extend(["--", "true"]);
        fireemu(&dir, &all)
    };
    let loud = run(&[]);
    assert!(loud.status.success(), "{}", stderr(&loud));
    assert!(
        stderr(&loud).contains("firestore.rules is accepted but never read"),
        "{}",
        stderr(&loud)
    );
    let quiet = run(&["--log-verbosity", "quiet"]);
    assert!(quiet.status.success(), "{}", stderr(&quiet));
    assert!(
        !stderr(&quiet).contains("note:"),
        "quiet means no notes: {}",
        stderr(&quiet)
    );
}

/// The base of a canonical file's relative paths is the working directory, whichever directory
/// the file is in (`firebaseJson` is the exception: it is read from the file's directory).
#[test]
fn relative_paths_in_a_canonical_file_are_read_from_the_working_directory() {
    let dir = Scratch::new("config-strict", "cwd-base");
    std::fs::create_dir_all(dir.join("sub")).unwrap();
    std::fs::write(
        dir.join("sub").join("fireemu.json"),
        r#"{"schemaVersion": 1, "rules": {"source": "firestore.rules"}, "storage": {"rules": "storage.rules"}}"#,
    )
    .unwrap();
    let output = fireemu(
        &dir,
        &["config", "show", "--json", "--config", "sub/fireemu.json"],
    );
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(shown(&output, "rules.source"), "firestore.rules");
    assert_eq!(shown(&output, "storage.rules"), "storage.rules");
}
