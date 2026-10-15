//! A canonical configuration file is checked against the schema: an unknown key or a value of
//! the wrong type is refused naming the file, the key's path and the type it should have had,
//! the same way for `fireemu.toml` and `fireemu.json` and for `up`, `exec` and `config show`.
//! Its relative paths are read from the directory the file is in.

mod scratch;

use std::path::Path;
use std::process::{Command, Output, Stdio};

use scratch::Scratch;

const RULES: &str = "rules_version = '2';\nservice cloud.firestore {\n  match /databases/{database}/documents {\n    match /{document=**} {\n      allow read, write: if false;\n    }\n  }\n}\n";

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

#[test]
fn a_discovered_file_with_a_wrong_type_is_refused_too() {
    let dir = Scratch::new("config-strict", "discovered");
    std::fs::write(
        dir.join("fireemu.toml"),
        "schemaVersion = 1\n[projects]\nrequireDemoPrefix = \"yes\"\n",
    )
    .unwrap();
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
fn relative_paths_are_read_from_the_directory_of_the_configuration_file() {
    for (file, text) in [
        (
            "fireemu.json",
            r#"{"schemaVersion": 1, "rules": {"source": "firestore.rules"}, "storage": {"rules": "storage.rules"}, "firestore": {"indexFile": "indexes.json"}, "functions": {"source": "fns"}}"#,
        ),
        (
            "fireemu.toml",
            "schemaVersion = 1\n[rules]\nsource = \"firestore.rules\"\n[storage]\nrules = \"storage.rules\"\n[firestore]\nindexFile = \"indexes.json\"\n[functions]\nsource = \"fns\"\n",
        ),
    ] {
        let dir = Scratch::new("config-strict", "relative");
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        std::fs::write(dir.join("sub").join(file), text).unwrap();
        let config = format!("sub/{file}");
        let output = fireemu(&dir, &["config", "show", "--json", "--config", &config]);
        assert!(output.status.success(), "{}", stderr(&output));
        assert_eq!(shown(&output, "rules.source"), "sub/firestore.rules", "{file}");
        assert_eq!(shown(&output, "storage.rules"), "sub/storage.rules", "{file}");
        assert_eq!(shown(&output, "firestore.indexFile"), "sub/indexes.json", "{file}");
        assert_eq!(shown(&output, "functions.source"), "sub/fns", "{file}");
    }
}

#[test]
fn an_absolute_path_and_a_file_in_the_working_directory_keep_their_paths() {
    let dir = Scratch::new("config-strict", "absolute");
    let absolute = dir.join("elsewhere.rules");
    std::fs::write(
        dir.join("fireemu.json"),
        format!(
            r#"{{"schemaVersion": 1, "rules": {{"source": {}}}, "storage": {{"rules": "storage.rules"}}}}"#,
            serde_json::to_string(&absolute).unwrap()
        ),
    )
    .unwrap();
    let output = fireemu(
        &dir,
        &["config", "show", "--json", "--config", "fireemu.json"],
    );
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(shown(&output, "rules.source"), absolute.to_str().unwrap());
    assert_eq!(shown(&output, "storage.rules"), "storage.rules");
}

#[test]
fn exec_loads_rules_beside_a_configuration_file_named_from_another_directory() {
    let dir = Scratch::new("config-strict", "exec");
    std::fs::create_dir_all(dir.join("sub")).unwrap();
    std::fs::write(dir.join("sub").join("firestore.rules"), RULES).unwrap();
    std::fs::write(
        dir.join("sub").join("fireemu.toml"),
        "schemaVersion = 1\n[rules]\nsource = \"firestore.rules\"\n",
    )
    .unwrap();
    let output = fireemu(
        &dir,
        &[
            "exec",
            "--only",
            "firestore",
            "--config",
            "sub/fireemu.toml",
            "--firestore-port",
            "0",
            "--http-port",
            "0",
            "--hub-port",
            "0",
            "--ui-port",
            "0",
            "--",
            "true",
        ],
    );
    assert!(
        output.status.success(),
        "{}\n{}",
        stdout(&output),
        stderr(&output)
    );
    assert!(
        stdout(&output).contains("enforced from"),
        "the rules file beside the configuration was not loaded:\n{}",
        stdout(&output)
    );
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
fn a_relative_path_that_only_the_working_directory_has_still_loads_with_a_note() {
    let dir = Scratch::new("config-strict", "fallback");
    std::fs::create_dir_all(dir.join("sub")).unwrap();
    std::fs::write(dir.join("here.rules"), RULES).unwrap();
    std::fs::write(dir.join("both.rules"), RULES).unwrap();
    std::fs::write(dir.join("sub").join("both.rules"), RULES).unwrap();
    std::fs::write(
        dir.join("sub").join("fireemu.json"),
        r#"{"schemaVersion": 1, "rules": {"source": "here.rules"}, "storage": {"rules": "both.rules"}}"#,
    )
    .unwrap();
    let output = fireemu(
        &dir,
        &["config", "show", "--json", "--config", "sub/fireemu.json"],
    );
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(shown(&output, "rules.source"), "here.rules");
    assert_eq!(shown(&output, "storage.rules"), "sub/both.rules");
    let notes = stderr(&output);
    assert!(
        notes.contains("rules.source \"here.rules\" is not beside the configuration file")
            && !notes.contains("storage.rules \"both.rules\" is not beside"),
        "{notes}"
    );
}

#[test]
fn the_notes_about_a_configuration_file_are_not_printed_when_the_log_is_quiet() {
    let dir = Scratch::new("config-strict", "quiet");
    std::fs::create_dir_all(dir.join("sub")).unwrap();
    std::fs::write(dir.join("here.rules"), RULES).unwrap();
    std::fs::write(
        dir.join("sub").join("fireemu.json"),
        r#"{"schemaVersion": 1, "rules": {"source": "here.rules"}, "firestore": {"rules": "unused.rules"}}"#,
    )
    .unwrap();
    let args = [
        "exec",
        "--only",
        "firestore",
        "--config",
        "sub/fireemu.json",
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
    let loud = stderr(&loud);
    assert!(
        loud.contains("is not beside the configuration file")
            && loud.contains("firestore.rules is accepted but never read"),
        "{loud}"
    );
    let quiet = run(&["--log-verbosity", "quiet"]);
    assert!(quiet.status.success(), "{}", stderr(&quiet));
    assert!(
        !stderr(&quiet).contains("note:"),
        "quiet means no notes: {}",
        stderr(&quiet)
    );
}
