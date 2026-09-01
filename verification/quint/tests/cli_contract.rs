//! Contracts for the pinned, bounded Quint command.

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};

fn wrapper_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("bin/quint")
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

fn run_wrapper(configure: impl FnOnce(&mut Command)) -> Output {
    let mut command = Command::new(wrapper_path());
    command.env_remove("QUINT_REAL_BIN");
    command.env_remove("QUINT_TIMEOUT_SECONDS");
    configure(&mut command);
    command.output().expect("guarded Quint wrapper must launch")
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
            "^(success|retryExhaustion|staleDiscard|cancel)$",
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
    for scenario in ["success", "retryExhaustion", "staleDiscard", "cancel"] {
        assert!(
            stdout.contains(scenario),
            "Quint output did not execute {scenario}:\n{stdout}\n{stderr}"
        );
    }
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
    let output = run_wrapper(|command| {
        command.env("QUINT_REAL_BIN", "/bin/sh");
        command.env("QUINT_TIMEOUT_SECONDS", "1");
        command.args(["-c", "sleep 30 & wait"]);
    });
    assert_eq!(output.status.code(), Some(124));
}
