//! `firebase-testd exec`: the `firebase emulators:exec` equivalent. Every scenario starts a
//! daemon on ephemeral ports (`--*-port 0`) and checks the command's environment, the exit
//! status, and that nothing keeps listening or running afterwards.

mod census;

use std::collections::BTreeMap;
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn daemon() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_firebase-testd"));
    cmd.args([
        "exec",
        "--firestore-port",
        "0",
        "--http-port",
        "0",
        "--storage-port",
        "0",
    ])
    .stdin(Stdio::null())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped());
    cmd
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ftd-exec-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn env_file(path: &Path) -> BTreeMap<String, String> {
    std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect()
}

fn refused(addr: &str) -> bool {
    TcpStream::connect_timeout(&addr.parse().unwrap(), Duration::from_millis(500)).is_err()
}

fn alive(pid: &str) -> bool {
    Command::new("kill")
        .args(["-0", pid])
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[test]
fn the_command_gets_the_emulator_hosts_and_the_services_stop_with_it() {
    let dir = scratch("env");
    let out = dir.join("env.txt");
    let output = daemon()
        .args(["--project", "demo-exec", "--", "sh", "-c"])
        .arg(format!("env > {}", out.display()))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let env = env_file(&out);
    assert_eq!(env["GOOGLE_CLOUD_PROJECT"], "demo-exec");
    assert_eq!(env["GCLOUD_PROJECT"], "demo-exec");
    assert_eq!(env["FTD_CONTROL_TOKEN"].len(), 32);
    assert!(env["FTD_CONTROL_URL"].starts_with("http://127.0.0.1:"));
    assert!(env["STORAGE_EMULATOR_HOST"].starts_with("http://127.0.0.1:"));
    for key in [
        "FIRESTORE_EMULATOR_HOST",
        "FIREBASE_AUTH_EMULATOR_HOST",
        "FIREBASE_STORAGE_EMULATOR_HOST",
    ] {
        let addr = &env[key];
        assert!(addr.starts_with("127.0.0.1:"), "{key}={addr}");
        assert!(refused(addr), "{key}={addr} still listens after exec");
    }
    assert!(!env.contains_key("FTD_FUNCTIONS_HOST"));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.starts_with("firebase-testd exec\n"), "{stdout}");
}

#[test]
fn only_selects_the_variables_the_command_receives() {
    let dir = scratch("only");
    let out = dir.join("env.txt");
    let output = daemon()
        .args(["--only", "auth,firestore", "--", "sh", "-c"])
        .arg(format!("env > {}", out.display()))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let env = env_file(&out);
    assert!(env.contains_key("FIRESTORE_EMULATOR_HOST"));
    assert!(env.contains_key("FIREBASE_AUTH_EMULATOR_HOST"));
    assert!(!env.contains_key("FIREBASE_STORAGE_EMULATOR_HOST"));
    assert!(!env.contains_key("STORAGE_EMULATOR_HOST"));
}

#[test]
fn the_exit_status_of_the_command_is_propagated() {
    let output = daemon()
        .args(["--", "sh", "-c", "exit 3"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(3));
}

#[test]
fn a_startup_failure_never_runs_the_command() {
    let dir = scratch("busy");
    let marker = dir.join("ran");
    // Something else owns the Firestore port.
    let busy = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = busy.local_addr().unwrap().port();
    let output = Command::new(env!("CARGO_BIN_EXE_firebase-testd"))
        .args([
            "exec",
            "--firestore-port",
            &port.to_string(),
            "--http-port",
            "0",
            "--storage-port",
            "0",
            "--",
            "touch",
        ])
        .arg(&marker)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("bind 127.0.0.1:"), "{stderr}");
    assert!(
        !marker.exists(),
        "the command ran although the services failed to start"
    );
    drop(busy);
}

#[test]
fn sigterm_stops_the_command_and_the_services_without_leaving_processes() {
    let dir = scratch("term");
    let pidfile = dir.join("pid");
    let out = dir.join("env.txt");
    let supervisor = daemon()
        .args(["--", "sh", "-c"])
        .arg(format!(
            "env > {}; echo $$ > {}; exec sleep 30",
            out.display(),
            pidfile.display()
        ))
        .spawn()
        .unwrap();
    let started = Instant::now();
    while !pidfile.exists() && started.elapsed() < Duration::from_secs(20) {
        std::thread::sleep(Duration::from_millis(50));
    }
    let child_pid = std::fs::read_to_string(&pidfile).unwrap().trim().to_owned();
    assert!(alive(&child_pid));
    let env = env_file(&out);
    let firestore = env["FIRESTORE_EMULATOR_HOST"].clone();
    assert!(
        !refused(&firestore),
        "the daemon should be serving while the command runs"
    );
    let status = Command::new("kill")
        .args(["-TERM", &supervisor.id().to_string()])
        .status()
        .unwrap();
    assert!(status.success());
    let output = supervisor.wait_with_output().unwrap();
    assert!(
        started.elapsed() < Duration::from_secs(20),
        "the supervisor did not stop promptly"
    );
    // `sleep` was ended by the forwarded SIGTERM: 128 + 15.
    assert_eq!(
        output.status.code(),
        Some(143),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let gone = Instant::now();
    while alive(&child_pid) && gone.elapsed() < Duration::from_secs(5) {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(!alive(&child_pid), "the command outlived the supervisor");
    assert!(refused(&firestore), "the daemon kept listening");
    // Nextest only sees processes still holding this test's captured output; the census also
    // covers descendants that closed or redirected it.
    census::assert_no_owned_descendants(
        "sigterm_stops_the_command_and_the_services_without_leaving_processes",
        Duration::from_secs(5),
    );
}

#[test]
fn exec_needs_a_command() {
    let output = Command::new(env!("CARGO_BIN_EXE_firebase-testd"))
        .args(["exec", "--http-port", "0"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("-- <command...>"));
}

#[test]
fn a_background_job_the_command_leaves_behind_is_swept() {
    // Off a terminal the command leads its own process group; the group is killed once
    // the command has exited, so `sleep` does not outlive the supervisor.
    let dir = scratch("orphan");
    let pidfile = dir.join("pid");
    let output = daemon()
        .args(["--", "sh", "-c"])
        .arg(format!(
            "sleep 300 & echo $! > {}; exit 0",
            pidfile.display()
        ))
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0));
    let sleeper = std::fs::read_to_string(&pidfile).unwrap().trim().to_owned();
    let gone = Instant::now();
    while alive(&sleeper) && gone.elapsed() < Duration::from_secs(5) {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(
        !alive(&sleeper),
        "the background job survived the supervisor"
    );
    census::assert_no_owned_descendants(
        "a_background_job_the_command_leaves_behind_is_swept",
        Duration::from_secs(5),
    );
}

#[test]
fn inherited_emulator_variables_do_not_reach_the_command_unless_selected() {
    let dir = scratch("scrub");
    let out = dir.join("env.txt");
    let output = daemon()
        .env("FIRESTORE_EMULATOR_HOST", "leaked.example:1")
        .env("STORAGE_EMULATOR_HOST", "http://leaked.example:2")
        .env("FTD_FUNCTIONS_HOST", "leaked.example:3")
        .args(["--only", "auth", "--", "sh", "-c"])
        .arg(format!("env > {}", out.display()))
        .output()
        .unwrap();
    assert!(output.status.success());
    let env = env_file(&out);
    assert!(env.contains_key("FIREBASE_AUTH_EMULATOR_HOST"));
    for key in [
        "FIRESTORE_EMULATOR_HOST",
        "STORAGE_EMULATOR_HOST",
        "FIREBASE_STORAGE_EMULATOR_HOST",
        "FTD_FUNCTIONS_HOST",
    ] {
        assert!(!env.contains_key(key), "{key} leaked into the command");
    }
}

#[test]
fn sigint_keeps_its_identity_when_forwarded() {
    let dir = scratch("int");
    let pidfile = dir.join("pid");
    let supervisor = daemon()
        .args(["--", "sh", "-c"])
        .arg(format!("echo $$ > {}; exec sleep 30", pidfile.display()))
        .spawn()
        .unwrap();
    let started = Instant::now();
    while !pidfile.exists() && started.elapsed() < Duration::from_secs(20) {
        std::thread::sleep(Duration::from_millis(50));
    }
    let child_pid = std::fs::read_to_string(&pidfile).unwrap().trim().to_owned();
    assert!(alive(&child_pid));
    assert!(Command::new("kill")
        .args(["-INT", &supervisor.id().to_string()])
        .status()
        .unwrap()
        .success());
    let output = supervisor.wait_with_output().unwrap();
    // `sleep` ended by SIGINT: 128 + 2.
    assert_eq!(
        output.status.code(),
        Some(130),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(!alive(&child_pid));
}
