//! Contracts for the pinned, bounded Quint command.

use std::fs;
#[cfg(unix)]
use std::net::TcpListener;
#[cfg(unix)]
use std::path::Path;
use std::path::PathBuf;
#[cfg(unix)]
use std::process::{Child, ExitStatus};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

#[cfg(unix)]
#[path = "../../../tests/support/trusted_temp.rs"]
mod trusted_temp;

#[cfg(unix)]
use trusted_temp::TrustedTempDir;

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

fn apalache_lock_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("apalache.lock.json")
}

fn apalache_installer_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("bin/install-apalache")
}

fn loopback_agent_source_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("java/io/fireemu/verification/LoopbackServerProviderAgent.java")
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
fn read_complete_pid_record(path: &Path, expected: usize) -> Option<Vec<u32>> {
    let text = fs::read_to_string(path).ok()?;
    let pids = text
        .split_whitespace()
        .map(str::parse::<u32>)
        .collect::<Result<Vec<_>, _>>()
        .ok()?;
    (pids.len() == expected && pids.iter().all(|pid| *pid > 0)).then_some(pids)
}

#[cfg(unix)]
struct AuthorityChild {
    child: Option<Child>,
}

#[cfg(unix)]
impl AuthorityChild {
    fn new(child: Child) -> Self {
        Self { child: Some(child) }
    }

    fn child_mut(&mut self) -> &mut Child {
        self.child.as_mut().expect("authority child is present")
    }

    fn terminate_and_wait(mut self, timeout: Duration) -> ExitStatus {
        self.terminate(timeout)
            .expect("authority child must produce an exit status")
    }

    fn terminate(&mut self, timeout: Duration) -> Option<ExitStatus> {
        let child = self.child.as_mut()?;
        let pid = child.id();
        let mut status = child.try_wait().ok().flatten();
        if status.is_none() {
            let _ = Command::new("/bin/kill")
                .args(["-TERM", &pid.to_string()])
                .status();
            let deadline = Instant::now() + timeout;
            while Instant::now() < deadline {
                if let Ok(Some(exited)) = child.try_wait() {
                    status = Some(exited);
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        if status.is_none() {
            let _ = child.kill();
            status = child.wait().ok();
        }
        self.child.take();
        status
    }
}

#[cfg(unix)]
impl Drop for AuthorityChild {
    fn drop(&mut self) {
        let _ = self.terminate(Duration::from_secs(4));
    }
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
#[allow(clippy::too_many_lines)]
fn prepare_authority_backend_fixture(
    temporary: &Path,
    quint_dir: &Path,
    fake_bin: &Path,
) -> PathBuf {
    fs::create_dir_all(quint_dir.join("bin")).expect("temporary Quint bin must be created");
    fs::create_dir_all(quint_dir.join("evidence"))
        .expect("temporary evidence target must be created");
    fs::create_dir_all(fake_bin).expect("temporary fixture bin must be created");
    let agent_source =
        quint_dir.join("java/io/fireemu/verification/LoopbackServerProviderAgent.java");
    fs::create_dir_all(
        agent_source
            .parent()
            .expect("loopback agent source must have a parent"),
    )
    .expect("loopback agent source directory must be created");
    fs::copy(loopback_agent_source_path(), &agent_source)
        .expect("loopback agent source must be copied");
    let installer = quint_dir.join("bin/install-apalache");
    fs::write(&installer, "#!/bin/sh\nexit 0\n").expect("installer fixture must be written");
    let quint_home = temporary.join("quint-home");
    let apalache_lib = quint_home.join("apalache-dist-0.56.1/apalache/lib");
    fs::create_dir_all(&apalache_lib).expect("Apalache fixture directory must be created");
    let stub_sources = temporary.join("grpc-stubs");
    let stub_classes = temporary.join("grpc-stub-classes");
    for (relative, source) in [
        (
            "io/grpc/ServerBuilder.java",
            "package io.grpc; public abstract class ServerBuilder<T extends ServerBuilder<T>> {}\n",
        ),
        (
            "io/grpc/ServerProvider.java",
            "package io.grpc; public abstract class ServerProvider { protected abstract boolean isAvailable(); protected abstract int priority(); protected abstract ServerBuilder<?> builderForPort(int port); }\n",
        ),
        (
            "io/grpc/ServerRegistry.java",
            "package io.grpc; public final class ServerRegistry { private static final ServerRegistry INSTANCE = new ServerRegistry(); public static ServerRegistry getDefaultRegistry() { return INSTANCE; } public void register(ServerProvider provider) {} }\n",
        ),
        (
            "io/grpc/netty/NettyServerBuilder.java",
            "package io.grpc.netty; import io.grpc.ServerBuilder; import java.net.SocketAddress; public final class NettyServerBuilder extends ServerBuilder<NettyServerBuilder> { public static NettyServerBuilder forAddress(SocketAddress address) { return new NettyServerBuilder(); } }\n",
        ),
    ] {
        let path = stub_sources.join(relative);
        fs::create_dir_all(path.parent().expect("stub source must have a parent"))
            .expect("stub source directory must be created");
        fs::write(path, source).expect("stub source must be written");
    }
    fs::create_dir(&stub_classes).expect("stub classes directory must be created");
    let mut javac = Command::new("javac");
    javac.arg("-d").arg(&stub_classes);
    for relative in [
        "io/grpc/ServerBuilder.java",
        "io/grpc/ServerProvider.java",
        "io/grpc/ServerRegistry.java",
        "io/grpc/netty/NettyServerBuilder.java",
    ] {
        javac.arg(stub_sources.join(relative));
    }
    let status = javac
        .status()
        .expect("javac must build authority fixture stubs");
    assert!(status.success(), "authority fixture stubs must compile");
    let fixture_jar = apalache_lib.join("apalache.jar");
    let status = Command::new("jar")
        .args(["cf"])
        .arg(&fixture_jar)
        .arg("-C")
        .arg(&stub_classes)
        .arg(".")
        .status()
        .expect("jar must package authority fixture stubs");
    assert!(status.success(), "authority fixture JAR must be packaged");
    let apalache_launcher = quint_home.join("apalache-dist-0.56.1/apalache/bin/apalache-mc");
    fs::create_dir_all(
        apalache_launcher
            .parent()
            .expect("Apalache launcher must have a parent"),
    )
    .expect("Apalache fixture bin must be created");
    fs::write(
        &apalache_launcher,
        r#"#!/usr/bin/env python3
import os
import signal
import socket

if __import__("sys").argv[1:] != ["server", "--port=0"]:
    raise SystemExit("unexpected fake Apalache arguments")

environment_file = os.environ.get("APALACHE_SERVER_ENV_FILE")
if environment_file:
    with open(environment_file, "w", encoding="utf-8") as handle:
        for name in (
            "APALACHE_JAR",
            "JVM_ARGS",
            "JVM_GC_ARGS",
            "JAVA_TOOL_OPTIONS",
            "_JAVA_OPTIONS",
            "JDK_JAVA_OPTIONS",
            "CLASSPATH",
            "BASH_ENV",
            "ENV",
            "LD_PRELOAD",
            "LD_LIBRARY_PATH",
            "LD_AUDIT",
            "DYLD_INSERT_LIBRARIES",
            "DYLD_LIBRARY_PATH",
            "DYLD_FRAMEWORK_PATH",
        ):
            handle.write(f"{name}={os.environ.get(name, '')}\n")

listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listener.bind(("127.0.0.1", 0))
listener.listen()
pid_file = os.environ.get("APALACHE_SERVER_PID_FILE")
if pid_file:
    temporary = f"{pid_file}.tmp.{os.getpid()}"
    with open(temporary, "w", encoding="utf-8") as handle:
        handle.write(f"{os.getpid()} {listener.getsockname()[1]}\n")
    os.replace(temporary, pid_file)

def stop(_signal, _frame):
    raise SystemExit(0)

signal.signal(signal.SIGTERM, stop)
signal.signal(signal.SIGINT, stop)
while True:
    connection, _address = listener.accept()
    connection.close()
"#,
    )
    .expect("Apalache fixture launcher must be written");
    let shasum = fake_bin.join("shasum");
    fs::write(&shasum, "#!/bin/sh\nexit 0\n").expect("shasum fixture must be written");
    make_executable(&[&installer, &apalache_launcher, &shasum]);
    quint_home
}

#[cfg(unix)]
struct OwnedTestDirectory(TrustedTempDir);

#[cfg(unix)]
impl OwnedTestDirectory {
    fn create(label: &str) -> Self {
        Self(TrustedTempDir::new(&format!("quint-{label}")))
    }
}

#[cfg(unix)]
#[test]
fn incomplete_pid_records_are_not_ready() {
    let temporary = OwnedTestDirectory::create("pid-record");
    let path = temporary.0.join("children.pid");

    for content in ["", "101", "101 partial", "0 102", "101 102 103"] {
        fs::write(&path, content).expect("partial PID record must be writable");
        assert_eq!(read_complete_pid_record(&path, 2), None, "{content:?}");
    }

    fs::write(&path, "101 102\n").expect("complete PID record must be writable");
    assert_eq!(read_complete_pid_record(&path, 2), Some(vec![101, 102]));
}

#[cfg(unix)]
#[test]
fn authority_child_cleanup_survives_panic_unwinding() {
    let temporary = OwnedTestDirectory::create("authority-panic-cleanup");
    let pid_file = temporary.0.join("children.pid");
    let observed = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let capture = std::sync::Arc::clone(&observed);
    let pid_path = pid_file.clone();

    let result = std::panic::catch_unwind(move || {
        let child = Command::new(process_group_launcher_path())
            .args([
                "/bin/sh",
                "-c",
                "sleep 30 & child=$!; pid_tmp=\"${PID_FILE}.tmp.$$\"; printf '%s %s\\n' \"$$\" \"$child\" > \"$pid_tmp\"; mv \"$pid_tmp\" \"$PID_FILE\"; wait \"$child\"",
            ])
            .env("PID_FILE", &pid_path)
            .spawn()
            .expect("panic fixture must launch");
        let guard = AuthorityChild::new(child);
        let mut pids = None;
        assert!(wait_until(Duration::from_secs(3), || {
            pids = read_complete_pid_record(&pid_path, 2);
            pids.is_some()
        }));
        *capture.lock().unwrap() = pids.unwrap();
        let _guard = guard;
        panic!("exercise authority cleanup during unwinding");
    });
    assert!(result.is_err());
    let pids = observed.lock().unwrap();
    assert_eq!(pids.len(), 2, "panic fixture never became ready");
    assert!(
        pids.iter().all(|pid| !process_exists(*pid)),
        "fixture descendants survived panic cleanup: {pids:?}"
    );
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
            "#!/bin/sh\ntrap '' HUP INT TERM\n/bin/sh -c 'trap \"\" HUP INT TERM; while :; do sleep 1; done' &\nchild=$!\npid_tmp=\"${SUPERVISOR_PID_FILE}.tmp.$$\"\nprintf '%s %s\\n' \"$$\" \"$child\" > \"$pid_tmp\"\nmv \"$pid_tmp\" \"$SUPERVISOR_PID_FILE\"\nwait \"$child\"\n",
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
        let mut pids = None;
        assert!(
            wait_until(Duration::from_secs(30), || {
                pids = read_complete_pid_record(&pid_file, 2);
                pids.is_some()
            }),
            "supervised descendants must become ready"
        );
        let pids = pids.expect("supervised PID record must be complete");

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
fn apalache_lock_binds_the_reviewed_distribution() {
    let json = fs::read_to_string(apalache_lock_path()).expect("Apalache lock must be readable");
    let lock: serde_json::Value = serde_json::from_str(&json).expect("valid Apalache lock JSON");
    assert_eq!(lock["version"], "0.56.1");
    assert_eq!(
        lock["archiveSha256"],
        "91125e5a3646b9c9d3a7d921d3323f321fac5071909f72b3960c66ff2f998ee1"
    );
    assert_eq!(
        lock["launcherSha256"],
        "bda52d2dbdbc7f6e95289a69dfe7ddeb162493ddd3501898d33ea7d1da3a8cd7"
    );
    assert_eq!(
        lock["jarSha256"],
        "4753c0ebb2cbb266e2c6ac19ab5ca3827d726cc80fd1fc5d7c1eeb64736cd60b"
    );
}

#[cfg(unix)]
#[test]
fn apalache_installer_is_executable_and_rejects_a_corrupt_cache() {
    use std::os::unix::fs::PermissionsExt;

    let installer = apalache_installer_path();
    let metadata = fs::metadata(&installer).expect("Apalache installer must exist");
    assert!(metadata.is_file());
    assert_ne!(metadata.permissions().mode() & 0o111, 0);

    let temporary = OwnedTestDirectory::create("apalache-corrupt-cache");
    let jar = temporary
        .0
        .join("apalache-dist-0.56.1/apalache/lib/apalache.jar");
    let launcher = temporary
        .0
        .join("apalache-dist-0.56.1/apalache/bin/apalache-mc");
    fs::create_dir_all(jar.parent().expect("JAR parent")).expect("create corrupt cache");
    fs::create_dir_all(launcher.parent().expect("launcher parent"))
        .expect("create corrupt launcher cache");
    fs::write(&jar, b"not the pinned JAR").expect("write corrupt JAR");
    fs::write(&launcher, b"not the pinned launcher").expect("write corrupt launcher");
    let mut permissions = fs::metadata(&launcher)
        .expect("corrupt launcher metadata")
        .permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&launcher, permissions).expect("make corrupt launcher executable");
    let output = Command::new(installer)
        .arg("--verify-only")
        .env("QUINT_HOME", &temporary.0)
        .output()
        .expect("installer must launch");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("digest mismatch"));
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
        String::from_utf8_lossy(&output.stdout).contains(
            "mutate-model --model MODEL [--root PATH] [--evidence PATH] [--cargo-authority PATH]"
        ),
        "help must declare the mutation contract"
    );
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("verify-evidence --model MODEL [--root PATH] [--evidence PATH] [--cargo-authority PATH]"),
        "help must declare the evidence contract"
    );
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("publish-evidence --source PATH --target PATH"),
        "help must declare the atomic publication contract"
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

#[cfg(unix)]
#[test]
fn cli_rejects_external_server_selection() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("fixture listener must bind");
    let endpoint = listener
        .local_addr()
        .expect("fixture listener must have an address")
        .to_string();
    let owner = Command::new("sleep")
        .arg("30")
        .spawn()
        .expect("non-owner process must launch");
    let owner_pid = owner.id().to_string();
    let _owner = AuthorityChild::new(owner);

    let output = Command::new(env!("CARGO_BIN_EXE_fireemu-verification-quint"))
        .args([
            "verify-model",
            "--model",
            "EventDelivery",
            "--server-endpoint",
            &endpoint,
            "--server-owner-pid",
            &owner_pid,
        ])
        .env("FIREEMU_QUINT_APALACHE_ENDPOINT", &endpoint)
        .env("FIREEMU_QUINT_APALACHE_OWNER_PID", &owner_pid)
        .env("PATH", "")
        .output()
        .expect("verification CLI must launch");
    assert_eq!(output.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("unknown flag \"--server-endpoint\""),
        "unexpected diagnostic: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn authority_script_declares_all_models_and_ordered_gates() {
    let script = fs::read_to_string(authority_script_path()).expect("authority script must exist");
    for model in [
        "AtomicCommitOutbox",
        "AtomicExportPublication",
        "AuthTotp",
        "AwaitIdle",
        "CompatibilitySelection",
        "EventDelivery",
        "FirestoreListenRefresh",
        "RegexAuthorization",
        "RegexEvaluationCache",
        "RegexLinearRepeat",
        "RulesetActivation",
        "SessionEpoch",
        "StorageGeneration",
        "TransactionConditionalLock",
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
    assert!(!script.contains("_apalache-out"));
    assert!(script.contains("--refresh"));
    assert!(script.contains("cargo-authority --write"));
    assert!(script.contains("--quint-evidence-dir"));
    assert!(script.contains("publish-evidence --source"));
    assert!(script.contains("--cargo-authority \"$staged_evidence/cargo-authority.json\""));
    assert!(!script.contains("authority_backup"));
    assert!(!script.contains("authority_installed"));
    assert!(!script.contains("refresh_committed"));
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
fn authority_script_rejects_unknown_refresh_arguments_before_tool_setup() {
    let output = Command::new(authority_script_path())
        .arg("--unknown")
        .env_remove("QUINT_REAL_BIN")
        .env_remove("QUINT_HOME")
        .output()
        .expect("authority script must launch");
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("unknown argument: --unknown"));
}

#[test]
fn authority_script_owns_a_dynamic_backend_and_checks_its_digest() {
    let script = fs::read_to_string(authority_script_path()).expect("authority script must exist");
    assert!(!script.contains("bin/authority-lock"));
    assert!(!script.contains("FIREEMU_QUINT_AUTHORITY_LOCK_FD"));
    assert!(!script.contains("bin/authority-server"));
    assert!(!script.contains("--server-endpoint"));
    assert!(!script.contains("--server-owner-pid"));
    assert!(!script.contains("127.0.0.1:8822"));
    assert!(!script.contains("FIREEMU_QUINT_AUTHORITY_LOCK_HELD"));
    assert!(!script.contains("FIREEMU_QUINT_AUTHORITY_LOCK:-"));
    assert!(script.contains("APALACHE_JAR_SHA256"));
    assert!(script.contains("shasum -a 256"));
}

#[test]
fn rust_authority_embeds_the_loopback_provider() {
    let source = fs::read_to_string(loopback_agent_source_path())
        .expect("loopback server provider agent source must exist");
    assert!(source.contains("ServerRegistry.getDefaultRegistry().register"));
    assert!(source.contains("InetAddress.getByAddress(new byte[] {127, 0, 0, 1})"));
    assert!(source.contains("NettyServerBuilder.forAddress"));

    let server =
        fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/server.rs"))
            .expect("Rust authority server source must exist");
    assert!(server.contains("include_bytes!"));
    assert!(server.contains("-javaagent:"));
    assert!(server.contains("env_clear"));
    assert!(server.contains("server\", \"--port=0"));
}

#[cfg(unix)]
#[test]
#[allow(clippy::too_many_lines)]
fn authority_pass_owns_a_dynamic_loopback_endpoint_when_legacy_8822_is_occupied() {
    let legacy_listener = match TcpListener::bind(("127.0.0.1", 8822)) {
        Ok(listener) => Some(listener),
        Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => None,
        Err(error) => panic!("legacy endpoint fixture must bind: {error}"),
    };
    let temporary = OwnedTestDirectory::create("authority-owned-endpoint");
    let quint_dir = temporary.0.join("verification/quint");
    let fake_bin = temporary.0.join("bin");
    let quint_home = prepare_authority_backend_fixture(&temporary.0, &quint_dir, &fake_bin);

    let authority = quint_dir.join("run-verification.sh");
    fs::copy(authority_script_path(), &authority).expect("authority script must be copied");
    let group_launcher = quint_dir.join("bin/process-group");
    fs::copy(process_group_launcher_path(), &group_launcher)
        .expect("group launcher must be copied");
    let evidence_dir = quint_dir.join("evidence");
    fs::create_dir_all(&evidence_dir).expect("authority evidence directory must be created");
    fs::write(evidence_dir.join("cargo-authority.json"), "{}\n")
        .expect("authority fixture must be written");

    let invocation_log = temporary.0.join("invocations.log");
    let server_pid_file = temporary.0.join("server.pid");
    let server_environment_file = temporary.0.join("server.env");
    let cargo = fake_bin.join("cargo");
    fs::write(
        &cargo,
        "#!/bin/sh\nprintf '%s\\t%s\\t%s\\n' \"${FIREEMU_QUINT_APALACHE_ENDPOINT:-}\" \"${FIREEMU_QUINT_APALACHE_OWNER_PID:-}\" \"$*\" >> \"$AUTHORITY_INVOCATION_LOG\"\n",
    )
    .expect("cargo fixture must be written");
    make_executable(&[&authority, &group_launcher, &cargo]);

    let output = Command::new(&authority)
        .current_dir(&temporary.0)
        .env("APALACHE_SERVER_PID_FILE", &server_pid_file)
        .env("APALACHE_SERVER_ENV_FILE", &server_environment_file)
        .env("AUTHORITY_INVOCATION_LOG", &invocation_log)
        .env(
            "FIREEMU_QUINT_AUTHORITY_LOCK",
            temporary.0.join("authority.lock"),
        )
        .env("QUINT_HOME", &quint_home)
        .env("QUINT_REAL_BIN", "/bin/sh")
        .env("FIREEMU_QUINT_APALACHE_ENDPOINT", "192.0.2.1:1")
        .env("FIREEMU_QUINT_APALACHE_OWNER_PID", "1")
        .env("APALACHE_JAR", "/tmp/unreviewed-apalache.jar")
        .env("JVM_ARGS", "-javaagent:/tmp/unreviewed-agent.jar")
        .env("JAVA_TOOL_OPTIONS", "-javaagent:/tmp/unreviewed-agent.jar")
        .env("_JAVA_OPTIONS", "-javaagent:/tmp/unreviewed-agent.jar")
        .env("JDK_JAVA_OPTIONS", "-javaagent:/tmp/unreviewed-agent.jar")
        .env("CLASSPATH", "/tmp/unreviewed-classes")
        .env("BASH_ENV", "/tmp/unreviewed-bash-env")
        .env("ENV", "/tmp/unreviewed-shell-env")
        .env("LD_PRELOAD", "/tmp/unreviewed-native.so")
        .env("LD_LIBRARY_PATH", "/tmp/unreviewed-native-libraries")
        .env("LD_AUDIT", "/tmp/unreviewed-audit.so")
        .env("DYLD_INSERT_LIBRARIES", "/tmp/unreviewed-native.dylib")
        .env("DYLD_LIBRARY_PATH", "/tmp/unreviewed-native-libraries")
        .env("DYLD_FRAMEWORK_PATH", "/tmp/unreviewed-frameworks")
        .env(
            "PATH",
            std::env::join_paths(std::iter::once(fake_bin).chain(std::env::split_paths(
                &std::env::var_os("PATH").unwrap_or_default(),
            )))
            .expect("fixture PATH must be joinable"),
        )
        .output()
        .expect("authority must launch");
    drop(legacy_listener);
    assert!(
        output.status.success(),
        "authority failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let invocations =
        fs::read_to_string(&invocation_log).expect("authority invocations must be recorded");
    assert!(
        invocations.lines().all(|line| line.starts_with("\t\t")),
        "legacy endpoint metadata reached a Rust command: {invocations}"
    );
    assert!(invocations.contains("verify-model --model AtomicCommitOutbox"));
    assert!(invocations.contains("mutate-model --model AtomicCommitOutbox"));
    assert!(!invocations.contains("--server-endpoint"));
    assert!(!invocations.contains("--server-owner-pid"));
    assert!(!quint_dir.join("_apalache-out").exists());
}

#[test]
fn readme_declares_the_fourteen_model_authority_and_generated_conformance() {
    let readme = fs::read_to_string(readme_path()).expect("authority README must exist");
    assert!(readme.contains("repository's formal verification authority"));
    assert!(readme.contains("`AwaitIdle`"));
    assert!(readme.contains("`CompatibilitySelection`"));
    assert!(readme.contains("`FirestoreListenRefresh`"));
    assert!(readme.contains("`RegexEvaluationCache`"));
    assert!(readme.contains("`RegexLinearRepeat`"));
    assert!(readme.contains("`StorageGeneration`"));
    assert!(readme.contains("`TransactionConditionalLock`"));
    assert!(readme.contains("Generated conformance campaigns"));
}

#[cfg(unix)]
#[test]
fn authority_term_signal_stops_and_waits_for_the_active_gate_group() {
    let temporary = OwnedTestDirectory::create("authority-signal");
    let quint_dir = temporary.0.join("verification/quint");
    let fake_bin = temporary.0.join("bin");
    let quint_home = prepare_authority_backend_fixture(&temporary.0, &quint_dir, &fake_bin);

    let authority = quint_dir.join("run-verification.sh");
    fs::copy(authority_script_path(), &authority).expect("authority script must be copied");
    let launcher = quint_dir.join("bin/process-group");
    fs::create_dir_all(launcher.parent().expect("launcher must have a parent"))
        .expect("temporary launcher directory must be created");
    fs::copy(process_group_launcher_path(), &launcher).expect("group launcher must be copied");
    let gate = fake_bin.join("cargo");
    fs::write(
        &gate,
        "#!/bin/sh\nsleep 30 &\nchild=$!\npid_tmp=\"${AUTHORITY_CHILD_PID_FILE}.tmp.$$\"\nprintf '%s %s\\n' \"$$\" \"$child\" > \"$pid_tmp\"\nmv \"$pid_tmp\" \"$AUTHORITY_CHILD_PID_FILE\"\nwait \"$child\"\n",
    )
    .expect("cargo fixture must be written");
    make_executable(&[&authority, &launcher, &gate]);

    let pid_file = temporary.0.join("children.pid");
    let server_pid_file = temporary.0.join("server.pid");
    let authority_log = temporary.0.join("authority.log");
    let stdout = fs::File::create(&authority_log).expect("authority log must be created");
    let stderr = stdout
        .try_clone()
        .expect("authority log handle must be cloned");
    let child = Command::new(process_group_launcher_path())
        .arg(&authority)
        .current_dir(&temporary.0)
        .env("AUTHORITY_CHILD_PID_FILE", &pid_file)
        .env("APALACHE_SERVER_PID_FILE", &server_pid_file)
        .env(
            "FIREEMU_QUINT_AUTHORITY_LOCK",
            temporary.0.join("authority.lock"),
        )
        .env("QUINT_HOME", &quint_home)
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
    let mut child = AuthorityChild::new(child);
    let mut early_status = None;
    let mut pids = None;
    let ready = wait_until(Duration::from_secs(30), || {
        pids = read_complete_pid_record(&pid_file, 2);
        if pids.is_some() {
            return true;
        }
        early_status = child
            .child_mut()
            .try_wait()
            .expect("authority readiness wait must succeed");
        early_status.is_some()
    });
    if let Some(status) = early_status {
        let log = fs::read_to_string(&authority_log).unwrap_or_default();
        panic!("authority exited before the active gate was ready ({status}):\n{log}");
    }
    if !ready {
        let log = fs::read_to_string(&authority_log).unwrap_or_default();
        panic!("active gate did not become ready within 30 seconds:\n{log}");
    }
    let pids = pids.expect("child PID record must be complete");
    let status = child.terminate_and_wait(Duration::from_secs(4));
    assert_eq!(status.code(), Some(143));
    assert!(
        wait_until(Duration::from_secs(2), || pids
            .iter()
            .all(|pid| !process_exists(*pid))),
        "TERM must remove every recorded active-gate process: {pids:?}"
    );
    assert!(!server_pid_file.exists());
}

#[cfg(target_os = "linux")]
#[test]
fn authority_term_signal_reaches_the_nested_guarded_quint_group() {
    let temporary = OwnedTestDirectory::create("authority-nested-signal");
    let quint_dir = temporary.0.join("verification/quint");
    let fake_bin = temporary.0.join("fixture-bin");
    let quint_home = prepare_authority_backend_fixture(&temporary.0, &quint_dir, &fake_bin);

    let authority = quint_dir.join("run-verification.sh");
    let launcher = quint_dir.join("bin/process-group");
    let wrapper = quint_dir.join("bin/quint");
    fs::copy(authority_script_path(), &authority).expect("authority script must be copied");
    fs::copy(process_group_launcher_path(), &launcher).expect("group launcher must be copied");
    fs::copy(wrapper_path(), &wrapper).expect("guarded wrapper must be copied");

    let real_quint = temporary.0.join("fake-quint");
    fs::write(
        &real_quint,
        "#!/bin/sh\nsleep 30 &\nchild=$!\ntimeout_pid=$(ps -o ppid= -p \"$$\" | tr -d ' ')\npid_tmp=\"${NESTED_PID_FILE}.tmp.$$\"\nprintf '%s %s %s\\n' \"$timeout_pid\" \"$$\" \"$child\" > \"$pid_tmp\"\nmv \"$pid_tmp\" \"$NESTED_PID_FILE\"\nwait \"$child\"\n",
    )
    .expect("fake Quint must be written");
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
    let child = Command::new(process_group_launcher_path())
        .arg(&authority)
        .current_dir(&temporary.0)
        .env("NESTED_PID_FILE", &pid_file)
        .env("AUTHORITY_QUINT_WRAPPER", &wrapper)
        .env(
            "FIREEMU_QUINT_AUTHORITY_LOCK",
            temporary.0.join("authority.lock"),
        )
        .env("QUINT_HOME", &quint_home)
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
    let mut child = AuthorityChild::new(child);
    let mut early_status = None;
    let mut pids = None;
    let ready = wait_until(Duration::from_secs(30), || {
        pids = read_complete_pid_record(&pid_file, 3);
        if pids.is_some() {
            return true;
        }
        early_status = child
            .child_mut()
            .try_wait()
            .expect("nested authority readiness wait must succeed");
        early_status.is_some()
    });
    if let Some(status) = early_status {
        let log = fs::read_to_string(&authority_log).unwrap_or_default();
        panic!("nested authority exited before readiness ({status}):\n{log}");
    }
    if !ready {
        let log = fs::read_to_string(&authority_log).unwrap_or_default();
        panic!("nested Quint group did not become ready:\n{log}");
    }
    let pids = pids.expect("nested PID record must be complete");
    let status = child.terminate_and_wait(Duration::from_secs(6));
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
    let legacy_listener = TcpListener::bind(("127.0.0.1", 8822)).ok();
    let output = Command::new(env!("CARGO_BIN_EXE_fireemu-verification-quint"))
        .args(["verify-model", "--model", "EventDelivery", "--root"])
        .arg(repository_root())
        .env(
            "QUINT_HOME",
            std::env::var_os("QUINT_HOME").unwrap_or_else(|| {
                PathBuf::from(std::env::var_os("HOME").expect("HOME must exist"))
                    .join(".quint")
                    .into_os_string()
            }),
        )
        .env("PATH", path_with_pinned_quint())
        .env("FIREEMU_QUINT_APALACHE_ENDPOINT", "192.0.2.1:1")
        .env("FIREEMU_QUINT_APALACHE_OWNER_PID", "1")
        .output()
        .expect("authority CLI must launch");
    drop(legacy_listener);
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
