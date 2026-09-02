//! Contracts for the pinned, bounded Quint command.

use std::fs;
#[cfg(unix)]
use std::path::Path;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

fn wrapper_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("bin/quint")
}

fn process_group_launcher_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("bin/process-group")
}

fn package_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("package.json")
}

fn pinned_quint_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("node_modules/.bin/quint")
}

fn event_delivery_spec_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("specs/EventDelivery.qnt")
}

fn authority_script_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("run-verification.sh")
}

fn readme_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("README.md")
}

fn repository_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .expect("verification/quint must have a repository parent")
        .to_path_buf()
}

fn path_with_pinned_quint() -> std::ffi::OsString {
    let mut paths = vec![pinned_quint_path()
        .parent()
        .expect("pinned Quint must have a bin directory")
        .to_path_buf()];
    paths.extend(std::env::split_paths(
        &std::env::var_os("PATH").unwrap_or_default(),
    ));
    std::env::join_paths(paths).expect("test PATH must be joinable")
}

fn run_wrapper(configure: impl FnOnce(&mut Command)) -> Output {
    let mut command = Command::new(wrapper_path());
    command.env_remove("QUINT_REAL_BIN");
    command.env_remove("QUINT_TIMEOUT_SECONDS");
    configure(&mut command);
    command.output().expect("guarded Quint wrapper must launch")
}

#[cfg(unix)]
fn process_exists(pid: u32) -> bool {
    Command::new("/bin/kill")
        .args(["-0", &pid.to_string()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

#[cfg(unix)]
fn wait_until(timeout: Duration, mut condition: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if condition() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    condition()
}

#[cfg(unix)]
fn make_executable(paths: &[&Path]) {
    use std::os::unix::fs::PermissionsExt;

    for path in paths {
        let mut permissions = fs::metadata(path)
            .expect("script metadata must exist")
            .permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(path, permissions).expect("script must be executable");
    }
}

#[cfg(unix)]
struct OwnedTestDirectory(PathBuf);

#[cfg(unix)]
impl OwnedTestDirectory {
    fn create(label: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock must follow the Unix epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "fireemu-quint-{label}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("owned test directory must be created");
        Self(path)
    }
}

#[cfg(unix)]
impl Drop for OwnedTestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn guarded_quint_wrapper_is_present_and_executable() {
    let path = wrapper_path();
    let metadata = fs::metadata(&path).unwrap_or_else(|error| {
        panic!(
            "guarded Quint wrapper is missing at {}: {error}",
            path.display()
        )
    });
    assert!(metadata.is_file(), "guarded Quint wrapper must be a file");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        assert_ne!(
            metadata.permissions().mode() & 0o111,
            0,
            "guarded Quint wrapper must be executable"
        );
    }
}

#[test]
fn guarded_quint_wrapper_requires_an_absolute_real_binary() {
    let missing = run_wrapper(|_| {});
    assert!(!missing.status.success());
    assert!(
        String::from_utf8_lossy(&missing.stderr).contains("QUINT_REAL_BIN"),
        "missing binary diagnostic must name QUINT_REAL_BIN"
    );

    let relative = run_wrapper(|command| {
        command.env("QUINT_REAL_BIN", "quint");
    });
    assert_eq!(relative.status.code(), Some(126));
    assert!(
        String::from_utf8_lossy(&relative.stderr).contains("must be absolute"),
        "relative binary diagnostic must explain the absolute-path contract"
    );
}

#[test]
fn guarded_quint_wrapper_rejects_invalid_timeout_values() {
    for timeout in ["0", "not-a-number"] {
        let output = run_wrapper(|command| {
            command.env("QUINT_REAL_BIN", "/bin/sh");
            command.env("QUINT_TIMEOUT_SECONDS", timeout);
        });
        assert_eq!(output.status.code(), Some(126), "timeout {timeout:?}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("must be a positive integer"),
            "timeout {timeout:?} must have a bounded validation diagnostic"
        );
    }
}

#[test]
fn guarded_quint_wrapper_declares_nested_group_signal_forwarding() {
    let wrapper = fs::read_to_string(wrapper_path()).expect("guarded wrapper must be readable");
    assert!(wrapper.contains("exec \"$group_supervisor\" --map-exit 137=124 -- timeout"));
}

#[cfg(unix)]
#[test]
fn process_group_supervisor_escalates_and_reaps_term_resistant_descendants() {
    use std::os::unix::fs::PermissionsExt;

    for (signal_name, expected_status) in [("HUP", 129), ("INT", 130), ("TERM", 143)] {
        let temporary = OwnedTestDirectory::create("group-supervisor");
        let fixture = temporary.0.join("signal-resistant");
        let pid_file = temporary.0.join("descendants.pid");
        fs::write(
            &fixture,
            "#!/bin/sh\ntrap '' HUP INT TERM\n/bin/sh -c 'trap \"\" HUP INT TERM; while :; do sleep 1; done' &\nchild=$!\nprintf '%s %s\\n' \"$$\" \"$child\" > \"$SUPERVISOR_PID_FILE\"\nwait \"$child\"\n",
        )
        .expect("signal-resistant fixture must be written");
        let mut permissions = fs::metadata(&fixture)
            .expect("fixture metadata must exist")
            .permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&fixture, permissions).expect("fixture must be executable");

        let mut supervisor = Command::new(process_group_launcher_path())
            .arg(&fixture)
            .env("SUPERVISOR_PID_FILE", &pid_file)
            .spawn()
            .expect("process-group supervisor must launch");
        assert!(
            wait_until(Duration::from_secs(30), || pid_file.exists()),
            "supervised descendants must become ready"
        );
        let pids = fs::read_to_string(&pid_file).expect("supervised pid file must be readable");
        let pids = pids
            .split_whitespace()
            .map(|pid| pid.parse::<u32>().expect("supervised pid must be numeric"))
            .collect::<Vec<_>>();
        assert_eq!(pids.len(), 2);

        let signal = Command::new("/bin/kill")
            .args([format!("-{signal_name}"), supervisor.id().to_string()])
            .status()
            .expect("signal command must launch");
        assert!(signal.success());
        let exited = wait_until(Duration::from_secs(6), || {
            supervisor
                .try_wait()
                .expect("supervisor wait must succeed")
                .is_some()
        });
        if !exited {
            let _ = Command::new("/bin/kill")
                .args(["-KILL", &format!("-{}", supervisor.id())])
                .status();
            let _ = supervisor.wait();
            panic!("supervisor must escalate {signal_name}-resistant descendants");
        }
        let status = supervisor.wait().expect("supervisor must be reaped");
        assert_eq!(status.code(), Some(expected_status), "signal {signal_name}");
        assert!(
            pids.iter().all(|pid| !process_exists(*pid)),
            "supervisor must not return before its group disappears after {signal_name}: {pids:?}"
        );
    }
}

#[cfg(unix)]
#[test]
fn process_group_supervisor_does_not_leak_during_the_launch_window() {
    use std::os::unix::fs::PermissionsExt;

    let temporary = OwnedTestDirectory::create("group-launch-window");
    let fixture = temporary.0.join("launch-window-child");
    fs::write(
        &fixture,
        "#!/bin/sh\nsleep 30 &\nchild=$!\nprintf '%s %s\\n' \"$$\" \"$child\" > \"$SUPERVISOR_PID_FILE\"\nwait \"$child\"\n",
    )
    .expect("launch-window fixture must be written");
    let mut permissions = fs::metadata(&fixture)
        .expect("fixture metadata must exist")
        .permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&fixture, permissions).expect("fixture must be executable");

    for iteration in 0..50 {
        let pid_file = temporary.0.join(format!("launch-{iteration}.pid"));
        let mut supervisor = Command::new(process_group_launcher_path())
            .arg(&fixture)
            .env("SUPERVISOR_PID_FILE", &pid_file)
            .spawn()
            .expect("process-group supervisor must launch");
        let signal = Command::new("/bin/kill")
            .args(["-TERM", &supervisor.id().to_string()])
            .status()
            .expect("TERM command must launch");
        assert!(signal.success());
        assert!(
            wait_until(Duration::from_secs(6), || supervisor
                .try_wait()
                .expect("launch-window wait must succeed")
                .is_some()),
            "launch-window supervisor {iteration} must terminate"
        );
        let status = supervisor
            .wait()
            .expect("launch-window supervisor must be reaped");
        assert!(
            !status.success(),
            "launch-window signal must stop the command"
        );
        if pid_file.exists() {
            let pids = fs::read_to_string(&pid_file).expect("launch-window pids must be readable");
            for pid in pids.split_whitespace() {
                let pid = pid
                    .parse::<u32>()
                    .expect("launch-window pid must be numeric");
                assert!(
                    !process_exists(pid),
                    "launch-window iteration {iteration} leaked process {pid}"
                );
            }
        }
    }
}

#[test]
fn package_manifest_pins_quint_and_pnpm_exactly() {
    let path = package_path();
    let json = fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
    let manifest: serde_json::Value =
        serde_json::from_str(&json).expect("package.json must be valid JSON");

    assert_eq!(manifest["private"], true);
    assert_eq!(manifest["packageManager"], "pnpm@10.32.1");
    assert_eq!(
        manifest["devDependencies"]["@informalsystems/quint"],
        "0.32.0"
    );
}

#[test]
#[ignore = "requires the pinned local Quint CLI"]
fn pinned_quint_version_is_exact() {
    let path = pinned_quint_path();
    let output = Command::new(&path)
        .arg("--version")
        .output()
        .unwrap_or_else(|error| panic!("cannot launch {}: {error}", path.display()));
    assert!(output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "0.32.0");
}

#[test]
#[ignore = "requires the pinned local Quint CLI"]
fn event_delivery_model_typechecks() {
    let spec = event_delivery_spec_path();
    let output = Command::new(pinned_quint_path())
        .args(["typecheck", spec.to_str().expect("spec path must be UTF-8")])
        .output()
        .expect("pinned Quint must launch");
    assert!(
        output.status.success(),
        "Quint typecheck failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
#[ignore = "requires the pinned local Quint CLI"]
fn event_delivery_named_scenarios_pass() {
    let spec = event_delivery_spec_path();
    let output = Command::new(pinned_quint_path())
        .args([
            "test",
            spec.to_str().expect("spec path must be UTF-8"),
            "--main",
            "EventDeliveryScenarios",
            "--match",
            "^(success|retryTiming|interrupt|staleDiscard|cancel)$",
            "--max-samples",
            "1",
            "--seed",
            "0x1",
        ])
        .output()
        .expect("pinned Quint must launch");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "Quint scenarios failed:\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    for scenario in [
        "success",
        "retryTiming",
        "interrupt",
        "staleDiscard",
        "cancel",
    ] {
        assert!(
            stdout.contains(scenario),
            "Quint output did not execute {scenario}:\n{stdout}\n{stderr}"
        );
    }
}

#[test]
fn cli_declares_verify_model_command() {
    let output = Command::new(env!("CARGO_BIN_EXE_fireemu-verification-quint"))
        .arg("--help")
        .output()
        .expect("authority CLI must launch");
    assert!(output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("verify-model --model MODEL [--root PATH]"),
        "help must declare the verify-model contract"
    );
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("mutate-model --model MODEL [--root PATH] [--evidence PATH]"),
        "help must declare the mutation contract"
    );
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("verify-evidence --model MODEL [--root PATH] [--evidence PATH]"),
        "help must declare the evidence contract"
    );
}

#[test]
fn cli_rejects_an_unknown_model_before_launching_a_checker() {
    let output = Command::new(env!("CARGO_BIN_EXE_fireemu-verification-quint"))
        .args(["verify-model", "--model", "UnknownModel"])
        .env("PATH", "")
        .output()
        .expect("verification CLI must launch");
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("unknown Quint model UnknownModel"));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("failed to launch"));
}

#[test]
fn authority_script_declares_all_models_and_ordered_gates() {
    let script = fs::read_to_string(authority_script_path()).expect("authority script must exist");
    for model in [
        "AtomicCommitOutbox",
        "AtomicExportPublication",
        "AuthTotp",
        "AwaitIdle",
        "EventDelivery",
        "RegexAuthorization",
        "RulesetActivation",
        "SessionEpoch",
        "StorageGeneration",
    ] {
        assert!(script.contains(model), "missing authority model {model}");
    }
    let gates = [
        "verify-model --model \"$model\"",
        "cargo test -p fireemu-verification-quint --test \"$test_target\"",
        "mutate-model --model \"$model\"",
        "verify-evidence --model \"$model\" --evidence \"$mutation_evidence\"",
        "cargo run -p traceability-check",
    ];
    let mut offset = 0;
    for gate in gates {
        let found = script[offset..]
            .find(gate)
            .unwrap_or_else(|| panic!("missing or out-of-order gate {gate}"));
        offset += found + gate.len();
    }
    assert!(script.contains("VERIFICATION_PASSES:-1"));
    assert!(script.contains("mktemp -d"));
    assert!(script.contains("trap cleanup"));
    let launch_contract = [
        "launching=1",
        "\"$group_launcher\" \"$@\" &",
        "active_pid=$!",
        "launching=0",
        "if [ -n \"$pending_signal\" ]",
    ];
    let mut launch_offset = 0;
    for statement in launch_contract {
        let found = script[launch_offset..]
            .find(statement)
            .unwrap_or_else(|| panic!("missing or out-of-order launch contract {statement}"));
        launch_offset += found + statement.len();
    }
}

#[test]
fn readme_declares_the_nine_model_authority_and_generated_conformance() {
    let readme = fs::read_to_string(readme_path()).expect("authority README must exist");
    assert!(readme.contains("repository's formal verification authority"));
    assert!(readme.contains("`AwaitIdle`"));
    assert!(readme.contains("`StorageGeneration`"));
    assert!(readme.contains("Generated conformance campaigns"));
}

#[cfg(unix)]
#[test]
fn authority_term_signal_stops_and_waits_for_the_active_gate_group() {
    let temporary = OwnedTestDirectory::create("authority-signal");
    let quint_dir = temporary.0.join("verification/quint");
    fs::create_dir_all(&quint_dir).expect("temporary Quint directory must be created");

    let authority = quint_dir.join("run-verification.sh");
    fs::copy(authority_script_path(), &authority).expect("authority script must be copied");
    let launcher = quint_dir.join("bin/process-group");
    fs::create_dir_all(launcher.parent().expect("launcher must have a parent"))
        .expect("temporary launcher directory must be created");
    fs::copy(process_group_launcher_path(), &launcher).expect("group launcher must be copied");
    let fake_bin = temporary.0.join("bin");
    fs::create_dir_all(&fake_bin).expect("temporary bin directory must be created");
    let gate = fake_bin.join("cargo");
    fs::write(
        &gate,
        "#!/bin/sh\nsleep 30 &\nchild=$!\nprintf '%s %s\\n' \"$$\" \"$child\" > \"$AUTHORITY_CHILD_PID_FILE\"\nwait \"$child\"\n",
    )
    .expect("cargo fixture must be written");
    make_executable(&[&authority, &launcher, &gate]);

    let pid_file = temporary.0.join("children.pid");
    let authority_log = temporary.0.join("authority.log");
    let stdout = fs::File::create(&authority_log).expect("authority log must be created");
    let stderr = stdout
        .try_clone()
        .expect("authority log handle must be cloned");
    let mut child = Command::new(&authority)
        .current_dir(&temporary.0)
        .env("AUTHORITY_CHILD_PID_FILE", &pid_file)
        .env("QUINT_REAL_BIN", "/bin/sh")
        .env(
            "PATH",
            std::env::join_paths(std::iter::once(fake_bin).chain(std::env::split_paths(
                &std::env::var_os("PATH").unwrap_or_default(),
            )))
            .expect("fixture PATH must be joinable"),
        )
        .stdout(stdout)
        .stderr(stderr)
        .spawn()
        .expect("authority must launch");
    let mut early_status = None;
    let ready = wait_until(Duration::from_secs(30), || {
        if pid_file.exists() {
            return true;
        }
        early_status = child
            .try_wait()
            .expect("authority readiness wait must succeed");
        early_status.is_some()
    });
    if let Some(status) = early_status {
        let log = fs::read_to_string(&authority_log).unwrap_or_default();
        panic!("authority exited before the active gate was ready ({status}):\n{log}");
    }
    if !ready {
        let _ = Command::new("/bin/kill")
            .args(["-TERM", &child.id().to_string()])
            .status();
        let _ = child.wait();
        let log = fs::read_to_string(&authority_log).unwrap_or_default();
        panic!("active gate did not become ready within 30 seconds:\n{log}");
    }
    let pids = fs::read_to_string(&pid_file).expect("child pid file must be readable");
    let pids = pids
        .split_whitespace()
        .map(|pid| pid.parse::<u32>().expect("child pid must be numeric"))
        .collect::<Vec<_>>();
    assert_eq!(pids.len(), 2);

    let signal = Command::new("/bin/kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .expect("TERM command must launch");
    assert!(signal.success());
    let exited = wait_until(Duration::from_secs(4), || {
        child
            .try_wait()
            .expect("authority wait must succeed")
            .is_some()
    });
    if !exited {
        let _ = child.kill();
        for pid in &pids {
            let _ = Command::new("/bin/kill")
                .args(["-TERM", &pid.to_string()])
                .status();
        }
        panic!("TERM must stop the authority promptly");
    }
    let status = child.wait().expect("authority must be reaped");
    assert_eq!(status.code(), Some(143));
    assert!(
        wait_until(Duration::from_secs(2), || pids
            .iter()
            .all(|pid| !process_exists(*pid))),
        "TERM must remove every recorded active-gate process: {pids:?}"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn authority_term_signal_reaches_the_nested_guarded_quint_group() {
    let temporary = OwnedTestDirectory::create("authority-nested-signal");
    let quint_dir = temporary.0.join("verification/quint");
    fs::create_dir_all(quint_dir.join("bin")).expect("temporary Quint bin must be created");

    let authority = quint_dir.join("run-verification.sh");
    let launcher = quint_dir.join("bin/process-group");
    let wrapper = quint_dir.join("bin/quint");
    fs::copy(authority_script_path(), &authority).expect("authority script must be copied");
    fs::copy(process_group_launcher_path(), &launcher).expect("group launcher must be copied");
    fs::copy(wrapper_path(), &wrapper).expect("guarded wrapper must be copied");

    let real_quint = temporary.0.join("fake-quint");
    fs::write(
        &real_quint,
        "#!/bin/sh\nsleep 30 &\nchild=$!\ntimeout_pid=$(ps -o ppid= -p \"$$\" | tr -d ' ')\nprintf '%s %s %s\\n' \"$timeout_pid\" \"$$\" \"$child\" > \"$NESTED_PID_FILE\"\nwait \"$child\"\n",
    )
    .expect("fake Quint must be written");
    let fake_bin = temporary.0.join("fixture-bin");
    fs::create_dir_all(&fake_bin).expect("temporary fixture bin must be created");
    let gate = fake_bin.join("cargo");
    fs::write(
        &gate,
        "#!/bin/sh\nexec \"$AUTHORITY_QUINT_WRAPPER\" \"$@\"\n",
    )
    .expect("wrapper gate must be written");
    make_executable(&[&authority, &launcher, &wrapper, &real_quint, &gate]);

    let pid_file = temporary.0.join("nested.pid");
    let authority_log = temporary.0.join("authority.log");
    let stdout = fs::File::create(&authority_log).expect("authority log must be created");
    let stderr = stdout
        .try_clone()
        .expect("authority log handle must be cloned");
    let mut child = Command::new(&authority)
        .current_dir(&temporary.0)
        .env("NESTED_PID_FILE", &pid_file)
        .env("AUTHORITY_QUINT_WRAPPER", &wrapper)
        .env("QUINT_REAL_BIN", &real_quint)
        .env("QUINT_TIMEOUT_SECONDS", "30")
        .env(
            "PATH",
            std::env::join_paths(std::iter::once(fake_bin).chain(std::env::split_paths(
                &std::env::var_os("PATH").unwrap_or_default(),
            )))
            .expect("fixture PATH must be joinable"),
        )
        .stdout(stdout)
        .stderr(stderr)
        .spawn()
        .expect("nested authority must launch");
    let mut early_status = None;
    let ready = wait_until(Duration::from_secs(30), || {
        if pid_file.exists() {
            return true;
        }
        early_status = child
            .try_wait()
            .expect("nested authority readiness wait must succeed");
        early_status.is_some()
    });
    if let Some(status) = early_status {
        let log = fs::read_to_string(&authority_log).unwrap_or_default();
        panic!("nested authority exited before readiness ({status}):\n{log}");
    }
    if !ready {
        let _ = Command::new("/bin/kill")
            .args(["-TERM", &child.id().to_string()])
            .status();
        let _ = child.wait();
        let log = fs::read_to_string(&authority_log).unwrap_or_default();
        panic!("nested Quint group did not become ready:\n{log}");
    }
    let pids = fs::read_to_string(&pid_file).expect("nested pid file must be readable");
    let pids = pids
        .split_whitespace()
        .map(|pid| pid.parse::<u32>().expect("nested pid must be numeric"))
        .collect::<Vec<_>>();
    assert_eq!(pids.len(), 3);

    let signal = Command::new("/bin/kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .expect("TERM command must launch");
    assert!(signal.success());
    let exited = wait_until(Duration::from_secs(6), || {
        child
            .try_wait()
            .expect("nested authority wait must succeed")
            .is_some()
    });
    if !exited {
        let _ = child.kill();
        for pid in &pids {
            let _ = Command::new("/bin/kill")
                .args(["-TERM", &pid.to_string()])
                .status();
        }
        panic!("TERM must stop the nested authority promptly");
    }
    let status = child.wait().expect("nested authority must be reaped");
    assert_eq!(status.code(), Some(143));
    assert!(
        wait_until(Duration::from_secs(2), || pids
            .iter()
            .all(|pid| !process_exists(*pid))),
        "TERM must remove timeout, Quint, and descendant processes: {pids:?}"
    );
}

#[test]
#[ignore = "requires Java and the pinned local Quint CLI"]
fn verify_model_cli_checks_event_delivery_with_tlc() {
    let output = Command::new(env!("CARGO_BIN_EXE_fireemu-verification-quint"))
        .args([
            "verify-model",
            "--model",
            "EventDelivery",
            "--root",
            repository_root()
                .to_str()
                .expect("repository path must be UTF-8"),
        ])
        .env("PATH", path_with_pinned_quint())
        .output()
        .expect("authority CLI must launch");
    assert!(
        output.status.success(),
        "verify-model failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "EventDelivery Quint/TLC model: ok"
    );
    assert!(
        !repository_root()
            .join("verification/quint/_apalache-out")
            .exists(),
        "verify-model must remove the checker output it owns"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn guarded_quint_wrapper_propagates_exit_status() {
    let output = run_wrapper(|command| {
        command.env("QUINT_REAL_BIN", "/bin/sh");
        command.args(["-c", "exit 23"]);
    });
    assert_eq!(output.status.code(), Some(23));
}

#[cfg(target_os = "linux")]
#[test]
fn guarded_quint_wrapper_times_out_its_process_group() {
    let temporary = OwnedTestDirectory::create("wrapper-timeout");
    let pid_file = temporary.0.join("descendant.pid");
    let output = run_wrapper(|command| {
        command.env("QUINT_REAL_BIN", "/bin/sh");
        command.env("QUINT_TIMEOUT_SECONDS", "1");
        command.env("WRAPPER_CHILD_PID_FILE", &pid_file);
        command.args([
            "-c",
            "sleep 30 & child=$!; printf '%s\\n' \"$child\" > \"$WRAPPER_CHILD_PID_FILE\"; wait \"$child\"",
        ]);
    });
    assert_eq!(output.status.code(), Some(124));
    let pid = fs::read_to_string(&pid_file)
        .expect("wrapper descendant pid must be recorded")
        .trim()
        .parse::<u32>()
        .expect("wrapper descendant pid must be numeric");
    assert!(
        wait_until(Duration::from_secs(2), || !process_exists(pid)),
        "timeout must remove the wrapper descendant {pid}"
    );
}
