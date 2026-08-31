//! Process-level tests for exact TLA+ mutation execution.

#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use tla_verification::{run_mutations, MutationOutcome, RunOptions};

struct Fixture {
    root: PathBuf,
}

impl Fixture {
    fn new(name: &str) -> Self {
        let root = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("runner-{name}"));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).expect("create fixture");
        Self { root }
    }

    fn write(&self, name: &str, contents: &str) -> PathBuf {
        let path = self.root.join(name);
        fs::write(&path, contents).expect("write fixture");
        path
    }

    fn executable(&self, name: &str, script: &str) -> PathBuf {
        let path = self.write(name, script);
        let mut permissions = fs::metadata(&path).expect("metadata").permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&path, permissions).expect("executable fixture");
        path
    }

    fn options(&self, java: PathBuf, timeout: Duration) -> RunOptions {
        RunOptions {
            module: self.root.join("Model.tla"),
            config: self.root.join("Model.cfg"),
            manifest: self.root.join("Model.json"),
            jar: self.root.join("tla2tools.jar"),
            evidence: self.root.join("evidence.json"),
            java_bin: java,
            timeout,
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn prepare(name: &str) -> Fixture {
    let fixture = Fixture::new(name);
    fixture.write(
        "Model.tla",
        "---- MODULE Model ----\nSafe == state = 0\n====\n",
    );
    fixture.write("Model.cfg", "INIT Init\nNEXT Next\nINVARIANT Safe\n");
    fixture.write(
        "Model.json",
        r#"{
            "schemaVersion": 1,
            "model": "Model",
            "mutations": [{
                "id": "M-MODEL-001",
                "property": "Safe",
                "operator": "invert-safe",
                "from": "state = 0",
                "to": "state # 0"
            }]
        }"#,
    );
    fixture.write("tla2tools.jar", "pinned jar bytes");
    fixture
}

#[test]
fn the_runner_uses_a_mutated_copy_and_an_unchanged_config() {
    let fixture = prepare("copy");
    let original_module = fs::read(fixture.root.join("Model.tla")).expect("module before");
    let original_config = fs::read(fixture.root.join("Model.cfg")).expect("config before");
    let java = fixture.executable(
        "fake-java",
        r"#!/bin/sh
grep -q 'state # 0' Model.tla || exit 90
grep -q '^INVARIANT Safe$' Model.cfg || exit 91
printf '%s\n' 'Error: Invariant Safe is violated.'
exit 12
",
    );

    let evidence =
        run_mutations(&fixture.options(java, Duration::from_secs(2))).expect("mutation execution");

    assert_eq!(evidence.results[0].outcome, MutationOutcome::KilledSafety);
    assert_eq!(
        fs::read(fixture.root.join("Model.tla")).expect("module after"),
        original_module
    );
    assert_eq!(
        fs::read(fixture.root.join("Model.cfg")).expect("config after"),
        original_config
    );
}

#[test]
fn temporal_counterexamples_and_clean_runs_are_classified_distinctly() {
    let temporal = prepare("temporal");
    let temporal_java = temporal.executable(
        "fake-java",
        "#!/bin/sh\nprintf '%s\\n' 'Error: Temporal properties were violated.'\nexit 12\n",
    );
    let temporal_evidence = run_mutations(&temporal.options(temporal_java, Duration::from_secs(2)))
        .expect("temporal execution");
    assert_eq!(
        temporal_evidence.results[0].outcome,
        MutationOutcome::KilledTemporal
    );

    let survived = prepare("survived");
    let survived_java = survived.executable(
        "fake-java",
        "#!/bin/sh\nprintf '%s\\n' 'Model checking completed. No error has been found.'\nexit 0\n",
    );
    let survived_evidence = run_mutations(&survived.options(survived_java, Duration::from_secs(2)))
        .expect("survived execution");
    assert_eq!(
        survived_evidence.results[0].outcome,
        MutationOutcome::Survived
    );
}

#[test]
fn timeout_and_launch_failure_never_count_as_killed() {
    let timeout = prepare("timeout");
    let slow_java = timeout.executable("fake-java", "#!/bin/sh\nwhile :; do :; done\n");
    let timeout_evidence = run_mutations(&timeout.options(slow_java, Duration::from_millis(20)))
        .expect("timeout is evidence, not a runner failure");
    assert_eq!(
        timeout_evidence.results[0].outcome,
        MutationOutcome::Timeout
    );

    let launch = prepare("launch");
    let launch_evidence =
        run_mutations(&launch.options(launch.root.join("missing-java"), Duration::from_secs(1)))
            .expect("launch failure is evidence, not a runner failure");
    assert_eq!(
        launch_evidence.results[0].outcome,
        MutationOutcome::ToolError
    );
}

#[test]
fn evidence_is_written_without_leaving_a_temporary_sibling() {
    let fixture = prepare("atomic");
    let java = fixture.executable("fake-java", "#!/bin/sh\nexit 0\n");

    run_mutations(&fixture.options(java, Duration::from_secs(2))).expect("run");

    assert!(fixture.root.join("evidence.json").is_file());
    let siblings = fs::read_dir(&fixture.root)
        .expect("read fixture")
        .map(|entry| entry.expect("entry").file_name())
        .collect::<Vec<_>>();
    assert!(!siblings
        .iter()
        .any(|name| name.to_string_lossy().contains("evidence.json.tmp")));
}
