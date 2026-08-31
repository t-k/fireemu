//! `fireemu exec`: the `firebase emulators:exec` equivalent. Every scenario starts a
//! daemon on ephemeral ports (`--*-port 0`) and checks the command's environment, the exit
//! status, and that nothing keeps listening or running afterwards.

mod census;

use std::collections::BTreeMap;
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn daemon() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_fireemu"));
    // `--hub-port 0` turns the Emulator Hub off: these scenarios are about the service
    // listeners and the child environment, and a shared default Hub port would make them
    // depend on which test won the race for it. `tests/hub.rs` covers the Hub itself.
    cmd.args([
        "exec",
        "--firestore-port",
        "0",
        "--http-port",
        "0",
        "--storage-port",
        "0",
        "--hub-port",
        "0",
    ])
    .stdin(Stdio::null())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped());
    cmd
}

/// A port nothing is listening on: bound, read back and released. A later bind can lose a
/// race for it, which every caller treats as a failure to bind rather than a wrong answer.
fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("fireemu-exec-{name}-{}", std::process::id()));
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
    assert_eq!(env["FIREEMU_CONTROL_TOKEN"].len(), 32);
    assert!(env["FIREEMU_CONTROL_URL"].starts_with("http://127.0.0.1:"));
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
    assert!(!env.contains_key("FIREEMU_FUNCTIONS_HOST"));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.starts_with("fireemu exec\n"), "{stdout}");
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

/// A canonical configuration with App Check enabled for one app of `demo-exec`.
fn app_check_config(dir: &Path) -> PathBuf {
    let path = dir.join("fireemu.json");
    std::fs::write(
        &path,
        r#"{
  "schemaVersion": 1,
  "profile": "strict",
  "firestore": { "edition": "standard", "apiMode": "native" },
  "appCheck": {
    "enabled": true,
    "tokenSigning": "instance-rsa",
    "apps": [
      {
        "projectId": "demo-exec",
        "projectNumber": "1234567890",
        "appId": "1:1234567890:web:local-test-app",
        "debugTokenSha256": [
          "db8055e0e0307d5a016bec4dc338d69875eb0fb7e614a8b125b08fb082095d98"
        ]
      }
    ]
  }
}
"#,
    )
    .unwrap();
    path
}

#[test]
fn app_check_variables_are_exported_only_when_the_service_is_selected() {
    let dir = scratch("appcheck");
    let config = app_check_config(&dir);
    let out = dir.join("env.txt");
    let output = daemon()
        .args(["--config"])
        .arg(&config)
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
    let host = &env["FIREEMU_APP_CHECK_EMULATOR_HOST"];
    assert!(host.starts_with("127.0.0.1:"), "{host}");
    // App Check shares the Auth/control listener.
    assert_eq!(host, &env["FIREBASE_AUTH_EMULATOR_HOST"]);
    assert_eq!(
        env["FIREEMU_APP_CHECK_JWKS_URL"],
        format!("http://{host}/v1/jwks")
    );
    // No raw debug secret is generated or exported implicitly.
    assert!(env.keys().all(|k| !k.contains("DEBUG_TOKEN")));

    // Neither `appcheck` nor `functions` selected: the routes and the variables are gone.
    let out = dir.join("env-unselected.txt");
    let output = daemon()
        .args(["--config"])
        .arg(&config)
        .args([
            "--project",
            "demo-exec",
            "--only",
            "auth,firestore",
            "--",
            "sh",
            "-c",
        ])
        .arg(format!("env > {}", out.display()))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let env = env_file(&out);
    assert!(!env.contains_key("FIREEMU_APP_CHECK_EMULATOR_HOST"));
    assert!(!env.contains_key("FIREEMU_APP_CHECK_JWKS_URL"));
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
    let output = Command::new(env!("CARGO_BIN_EXE_fireemu"))
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
    let output = Command::new(env!("CARGO_BIN_EXE_fireemu"))
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
        .env("FIREEMU_FUNCTIONS_HOST", "leaked.example:3")
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
        "FIREEMU_FUNCTIONS_HOST",
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

// --------------------------------------------------------------------------------------
// `--only` decides the lifecycle, not only the environment (CLI-02)
// --------------------------------------------------------------------------------------

/// Runs `exec` with the given extra arguments, dumping the child's environment to a file.
fn run_selection(name: &str, ports: [u16; 3], extra: &[&str]) -> BTreeMap<String, String> {
    let dir = scratch(name);
    let out = dir.join("env.txt");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_fireemu"));
    cmd.args(["exec", "--hub-port", "0"])
        .args(["--firestore-port", &ports[0].to_string()])
        .args(["--http-port", &ports[1].to_string()])
        .args(["--storage-port", &ports[2].to_string()])
        .args(extra)
        .args(["--", "sh", "-c"])
        .arg(format!("env > {}", out.display()))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let output = cmd.output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    env_file(&out)
}

#[test]
fn an_unselected_service_binds_no_listener_at_all() {
    // Fixed ports: whatever `--only` leaves out has to stay free while the daemon serves,
    // which is what "the service is not started" has to mean.
    for (label, only, want) in [
        ("firestore-only", "firestore", [true, false, false]),
        ("auth-only", "auth", [false, true, false]),
        ("storage-only", "storage", [false, false, true]),
        ("auth-storage", "auth,storage", [false, true, true]),
        (
            "firestore-storage",
            "firestore,storage",
            [true, false, true],
        ),
    ] {
        let ports = [free_port(), free_port(), free_port()];
        let dir = scratch(&format!("lifecycle-{label}"));
        let probe = dir.join("probe.txt");
        // The command probes each port from inside the run, while the daemon is serving.
        let script = format!(
            "for p in {} {} {}; do (exec 3<>/dev/tcp/127.0.0.1/$p) 2>/dev/null && echo \"$p open\" || echo \"$p closed\"; done > {}",
            ports[0],
            ports[1],
            ports[2],
            probe.display()
        );
        let output = Command::new(env!("CARGO_BIN_EXE_fireemu"))
            .args(["exec", "--hub-port", "0", "--only", only])
            .args(["--firestore-port", &ports[0].to_string()])
            .args(["--http-port", &ports[1].to_string()])
            .args(["--storage-port", &ports[2].to_string()])
            .args(["--", "bash", "-c"])
            .arg(&script)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{label}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let probed = std::fs::read_to_string(&probe).unwrap();
        for (i, service) in ["firestore", "auth", "storage"].into_iter().enumerate() {
            let expected = if want[i] { "open" } else { "closed" };
            assert!(
                probed.contains(&format!("{} {expected}", ports[i])),
                "{label}: {service} on {} should be {expected}\n{probed}",
                ports[i]
            );
        }
    }
}

#[test]
fn every_selection_exports_exactly_the_canonical_variables_of_its_services() {
    // The official `firebase emulators:exec` names, and only those: no
    // FIREBASE_DATABASE_EMULATOR_HOST (fireemu serves no Realtime Database) and no
    // variable for a service `--only` left out.
    let firestore = [
        "FIRESTORE_EMULATOR_HOST",
        "FIREBASE_FIRESTORE_EMULATOR_ADDRESS",
    ];
    let auth = ["FIREBASE_AUTH_EMULATOR_HOST"];
    let storage = ["FIREBASE_STORAGE_EMULATOR_HOST", "STORAGE_EMULATOR_HOST"];
    for (label, only, want_fs, want_auth, want_st) in [
        ("firestore", "firestore", true, false, false),
        ("auth", "auth", false, true, false),
        ("storage", "storage", false, false, true),
        ("all-three", "firestore,auth,storage", true, true, true),
        ("appcheck-only", "appcheck", false, false, false),
    ] {
        let ports = [free_port(), free_port(), free_port()];
        let env = run_selection(&format!("vars-{label}"), ports, &["--only", only]);
        for (keys, wanted) in [
            (&firestore[..], want_fs),
            (&auth[..], want_auth),
            (&storage[..], want_st),
        ] {
            for key in keys {
                assert_eq!(
                    env.contains_key(*key),
                    wanted,
                    "{label}: {key} should{} be exported",
                    if wanted { "" } else { " not" }
                );
            }
        }
        // The formats are the official ones: bare host:port everywhere but
        // STORAGE_EMULATOR_HOST, which carries the scheme.
        if want_fs {
            assert!(env["FIRESTORE_EMULATOR_HOST"].starts_with("127.0.0.1:"));
            assert_eq!(
                env["FIREBASE_FIRESTORE_EMULATOR_ADDRESS"], env["FIRESTORE_EMULATOR_HOST"],
                "{label}"
            );
        }
        if want_st {
            assert!(env["FIREBASE_STORAGE_EMULATOR_HOST"].starts_with("127.0.0.1:"));
            assert_eq!(
                env["STORAGE_EMULATOR_HOST"],
                format!("http://{}", env["FIREBASE_STORAGE_EMULATOR_HOST"]),
                "{label}"
            );
        }
        assert!(
            !env.contains_key("FIREBASE_DATABASE_EMULATOR_HOST"),
            "{label}: fireemu has no Realtime Database to point that variable at"
        );
        // The control plane is always reachable: it is fireemu's own surface, not a product.
        assert!(env["FIREEMU_CONTROL_URL"].starts_with("http://127.0.0.1:"));
        assert_eq!(env["GCLOUD_PROJECT"], env["GOOGLE_CLOUD_PROJECT"]);
    }
}

#[test]
fn the_control_plane_leaves_the_auth_port_free_when_auth_is_not_selected() {
    let ports = [free_port(), free_port(), free_port()];
    let env = run_selection("control-plane", ports, &["--only", "firestore"]);
    let control = env["FIREEMU_CONTROL_URL"].clone();
    assert!(
        !control.contains(&format!(":{}/", ports[1])),
        "the control API took the Auth port although auth was not selected: {control}"
    );
    assert!(!env.contains_key("FIREBASE_AUTH_EMULATOR_HOST"));
}

#[test]
fn an_official_service_fireemu_does_not_serve_is_refused_with_its_status() {
    for (service, fragment) in [
        ("database", "deferred"),
        ("hosting", "deferred"),
        ("apphosting", "deferred"),
        ("eventarc", "planned"),
        ("tasks", "planned"),
        ("dataconnect", "deferred"),
        ("extensions", "not planned"),
    ] {
        let dir = scratch(&format!("unsupported-{service}"));
        let marker = dir.join("ran");
        let output = Command::new(env!("CARGO_BIN_EXE_fireemu"))
            .args([
                "exec",
                "--firestore-port",
                "0",
                "--http-port",
                "0",
                "--storage-port",
                "0",
                "--hub-port",
                "0",
                "--only",
            ])
            .arg(format!("firestore,{service}"))
            .args(["--", "touch"])
            .arg(&marker)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2), "{service}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains(service), "{service}: {stderr}");
        assert!(stderr.contains(fragment), "{service}: {stderr}");
        assert!(
            !marker.exists(),
            "{service}: the command ran although the selection was refused"
        );
    }
    // `hub`, `ui` and `logging` are emulators, but not selectable services.
    for name in ["hub", "ui", "logging"] {
        let output = Command::new(env!("CARGO_BIN_EXE_fireemu"))
            .args(["exec", "--http-port", "0", "--only", name, "--", "true"])
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2), "{name}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("not a service emulator"),
            "{name}"
        );
    }
}

#[test]
fn an_occupied_port_of_a_selected_service_fails_before_the_command_runs() {
    for (label, flag) in [
        ("firestore", "--firestore-port"),
        ("auth", "--http-port"),
        ("storage", "--storage-port"),
    ] {
        let dir = scratch(&format!("busy-{label}"));
        let marker = dir.join("ran");
        let busy = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = busy.local_addr().unwrap().port();
        let output = Command::new(env!("CARGO_BIN_EXE_fireemu"))
            .args([
                "exec",
                "--firestore-port",
                "0",
                "--http-port",
                "0",
                "--storage-port",
                "0",
                "--hub-port",
                "0",
                "--only",
                "firestore,auth,storage",
            ])
            .args([flag, &port.to_string()])
            .args(["--", "touch"])
            .arg(&marker)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1), "{label}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains(&format!("bind 127.0.0.1:{port}")),
            "{stderr}"
        );
        assert!(!marker.exists(), "{label}: the command ran anyway");
        drop(busy);
    }
    // The same port is free to use while the service that would have taken it is not
    // selected: nothing binds it, so the run succeeds.
    let busy = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = busy.local_addr().unwrap().port();
    let output = Command::new(env!("CARGO_BIN_EXE_fireemu"))
        .args([
            "exec",
            "--http-port",
            "0",
            "--hub-port",
            "0",
            "--only",
            "auth",
            "--firestore-port",
        ])
        .arg(port.to_string())
        .args(["--", "true"])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "an unselected service must not fail on a busy port: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    drop(busy);
}
