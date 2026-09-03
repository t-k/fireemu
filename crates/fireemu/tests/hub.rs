//! The Emulator Hub over the wire: discovery, the locator file and the background-trigger
//! switch, checked against a daemon started the way a project would start it (CLI-03).
//!
//! Every scenario asks for an explicit Hub port so it never races another test for the
//! official default 4400, and gives the daemon its own project so its locator file is its
//! own.

use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[cfg(unix)]
#[path = "../../../tests/support/trusted_temp.rs"]
mod trusted_temp;

#[cfg(unix)]
use trusted_temp::TrustedTempDir;

const STARTUP_TRANSCRIPT_LIMIT: usize = 32 * 1024;

fn append_startup_output(transcript: &Mutex<String>, text: &str) {
    let mut transcript = transcript.lock().unwrap();
    let remaining = STARTUP_TRANSCRIPT_LIMIT.saturating_sub(transcript.len());
    let mut end = text.len().min(remaining);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    transcript.push_str(&text[..end]);
}

fn drain_startup_pipe<R: std::io::BufRead>(reader: R, transcript: &Mutex<String>) {
    for line in reader.lines() {
        match line {
            Ok(line) => append_startup_output(transcript, &format!("{line}\n")),
            Err(error) => {
                append_startup_output(transcript, &format!("<read error: {error}>\n"));
                return;
            }
        }
    }
}

/// A port nothing is listening on at the time of the probe.
fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("fireemu-hub-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// One HTTP request against the Hub. Written by hand because the binary's test suite has no
/// HTTP client dependency, and the Hub's answers are small enough to read in one go.
fn request(port: u16, method: &str, path: &str, host: &str) -> (u16, String) {
    let (status, _, body) = request_with_headers(port, method, path, host, &[], "");
    (status, body)
}

fn request_with_headers(
    port: u16,
    method: &str,
    path: &str,
    host: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> (u16, String, String) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("the Hub accepts");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    write!(stream, "{method} {path} HTTP/1.1\r\nHost: {host}\r\n").unwrap();
    for (name, value) in headers {
        write!(stream, "{name}: {value}\r\n").unwrap();
    }
    write!(
        stream,
        "Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .unwrap();
    stream.flush().unwrap();
    let mut raw = String::new();
    stream.read_to_string(&mut raw).unwrap();
    let (head, body) = raw.split_once("\r\n\r\n").unwrap_or((raw.as_str(), ""));
    let status = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    (status, head.to_owned(), body.to_owned())
}

fn complete_http_response(raw: &str) -> bool {
    let Some((head, body)) = raw.split_once("\r\n\r\n") else {
        return false;
    };
    let content_length = head.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("content-length")
            .then(|| value.trim().parse::<usize>().ok())
            .flatten()
    });
    content_length.is_some_and(|length| body.len() >= length)
}

fn json(port: u16, method: &str, path: &str) -> serde_json::Value {
    let (status, body) = request(port, method, path, "127.0.0.1");
    assert_eq!(status, 200, "{method} {path} -> {body}");
    serde_json::from_str(&body).unwrap_or_else(|e| panic!("{method} {path}: {e}\n{body}"))
}

/// A daemon serving until it is stopped, with the Hub on `hub_port`.
struct Daemon {
    child: Child,
    project: String,
    hub_port: u16,
    stopped: bool,
    namespace: DaemonNamespace,
}

struct DaemonNamespace {
    #[cfg(unix)]
    trusted: TrustedTempDir,
}

impl DaemonNamespace {
    fn new(label: &str) -> Self {
        Self {
            #[cfg(unix)]
            trusted: TrustedTempDir::new(label),
        }
    }

    fn path(&self) -> PathBuf {
        #[cfg(unix)]
        {
            self.trusted.path().to_path_buf()
        }
        #[cfg(not(unix))]
        {
            std::env::temp_dir()
        }
    }
}

struct StartupFailure {
    reason: String,
    pid: u32,
    status: Option<ExitStatus>,
    stdout: String,
    stderr: String,
}

impl StartupFailure {
    fn is_address_in_use(&self) -> bool {
        self.stderr.contains("Address already in use")
    }

    fn report(&self) -> String {
        let Self {
            reason,
            pid,
            status,
            stdout,
            stderr,
        } = self;
        format!(
            "the daemon became ready: {reason}; pid={pid}; status={status:?}\nstdout:\n{stdout}\nstderr:\n{stderr}"
        )
    }
}

impl Daemon {
    fn start(project: &str, extra: &[&str]) -> Self {
        const MAX_BIND_ATTEMPTS: usize = 8;

        let mut last_collision = None;
        for attempt in 0..MAX_BIND_ATTEMPTS {
            let hub_port = free_port();
            let namespace = DaemonNamespace::new("hub-daemon");
            match Self::start_once(project, hub_port, extra, namespace) {
                Ok(daemon) => return daemon,
                Err(failure) if failure.is_address_in_use() && attempt + 1 < MAX_BIND_ATTEMPTS => {
                    last_collision = Some(failure);
                }
                Err(failure) => panic!("{}", failure.report()),
            }
        }
        panic!(
            "{}",
            last_collision
                .expect("a failed bind attempt was recorded")
                .report()
        );
    }

    #[cfg(unix)]
    fn start_in_namespace(project: &str, extra: &[&str], namespace: DaemonNamespace) -> Self {
        Self::start_once(project, free_port(), extra, namespace)
            .unwrap_or_else(|failure| panic!("{}", failure.report()))
    }

    fn start_once(
        project: &str,
        hub_port: u16,
        extra: &[&str],
        namespace: DaemonNamespace,
    ) -> Result<Self, StartupFailure> {
        let mut command = Command::new(env!("CARGO_BIN_EXE_fireemu"));
        command
            .args([
                "up",
                "--firestore-port",
                "0",
                "--http-port",
                "0",
                "--storage-port",
                "0",
                "--logging-port",
                "0",
                "--ui-port",
                "0",
                "--project",
                project,
                "--hub-port",
            ])
            .arg(hub_port.to_string())
            .args(extra)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        #[cfg(unix)]
        command.env("TMPDIR", namespace.path());
        let mut child = command.spawn().unwrap();
        // The banner's control-API line is printed once every listener is bound and served.
        // The pipe keeps being drained on its own thread afterwards: a closed stdout would
        // give the daemon a broken pipe on its next line and kill it mid-scenario.
        let stdout = child.stdout.take().unwrap();
        let stderr = child.stderr.take().unwrap();
        let stdout_transcript = Arc::new(Mutex::new(String::new()));
        let stderr_transcript = Arc::new(Mutex::new(String::new()));
        let stdout_capture = Arc::clone(&stdout_transcript);
        let stderr_capture = Arc::clone(&stderr_transcript);
        let (ready_tx, ready_rx) = std::sync::mpsc::channel::<Result<(), String>>();
        let stdout_thread = std::thread::spawn(move || {
            let mut reader = BufReader::new(stdout);
            let mut ready = Some(ready_tx);
            loop {
                let mut line = String::new();
                match reader.read_line(&mut line) {
                    Ok(0) => {
                        if let Some(tx) = ready.take() {
                            let _ = tx.send(Err("stdout reached EOF before readiness".to_owned()));
                        }
                        return;
                    }
                    Ok(_) => append_startup_output(&stdout_capture, &line),
                    Err(error) => {
                        if let Some(tx) = ready.take() {
                            let _ = tx.send(Err(format!("could not read stdout: {error}")));
                        }
                        return;
                    }
                }
                if line.contains("control API:") {
                    if let Some(tx) = ready.take() {
                        let _ = tx.send(Ok(()));
                    }
                }
            }
        });
        let stderr_thread =
            std::thread::spawn(move || drain_startup_pipe(BufReader::new(stderr), &stderr_capture));
        let readiness = ready_rx
            .recv_timeout(Duration::from_secs(60))
            .unwrap_or_else(|error| Err(format!("readiness channel failed: {error}")));
        if let Err(reason) = readiness {
            let pid = child.id();
            let status = match child.try_wait() {
                Ok(Some(status)) => Some(status),
                Ok(None) => {
                    let _ = child.kill();
                    child.wait().ok()
                }
                Err(_) => None,
            };
            let _ = stdout_thread.join();
            let _ = stderr_thread.join();
            let stdout = stdout_transcript.lock().unwrap().clone();
            let stderr = stderr_transcript.lock().unwrap().clone();
            return Err(StartupFailure {
                reason,
                pid,
                status,
                stdout,
                stderr,
            });
        }
        Ok(Self {
            child,
            project: project.to_owned(),
            hub_port,
            stopped: false,
            namespace,
        })
    }

    fn hub_port(&self) -> u16 {
        self.hub_port
    }

    fn locator(&self) -> PathBuf {
        self.namespace
            .path()
            .join(format!("hub-{}.json", self.project))
    }

    fn control_token(&self) -> String {
        let locator: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(self.locator()).unwrap()).unwrap();
        locator["fireemuControlToken"].as_str().unwrap().to_owned()
    }

    fn cleanup(&mut self) -> bool {
        if self.stopped {
            return false;
        }
        let pid = self.child.id();
        let owned_locator = std::fs::symlink_metadata(self.locator())
            .is_ok_and(|metadata| metadata.file_type().is_file());
        let mut exited = self.child.try_wait().is_ok_and(|status| status.is_some());
        if !exited {
            let _ = Command::new("kill")
                .args(["-TERM", &pid.to_string()])
                .status();
            let deadline = Instant::now() + Duration::from_secs(5);
            while Instant::now() < deadline {
                if self.child.try_wait().is_ok_and(|status| status.is_some()) {
                    exited = true;
                    break;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        }
        let graceful = exited;
        if !exited {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
        self.stopped = true;
        graceful && owned_locator
    }

    fn stop(mut self) {
        let graceful = self.cleanup();
        assert!(
            self.child.try_wait().is_ok_and(|status| status.is_some()),
            "daemon {} survived explicit cleanup",
            self.child.id()
        );
        if graceful {
            assert!(
                !self.locator().exists(),
                "{} survived explicit cleanup",
                self.locator().display()
            );
        }
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
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
#[test]
fn implicit_daemon_cleanup_reaps_the_process_and_removes_its_locator() {
    let (pid, locator) = {
        let daemon = Daemon::start("demo-hub-implicit-cleanup", &[]);
        (daemon.child.id(), daemon.locator())
    };

    assert!(!process_exists(pid), "daemon {pid} survived its guard");
    assert!(
        !locator.exists(),
        "{} survived its daemon",
        locator.display()
    );
}

#[cfg(unix)]
#[test]
fn unwinding_daemon_cleanup_reaps_the_process_and_removes_its_locator() {
    let observed = Arc::new(Mutex::new(None));
    let capture = Arc::clone(&observed);
    let result = std::panic::catch_unwind(move || {
        let daemon = Daemon::start("demo-hub-unwind-cleanup", &[]);
        *capture.lock().unwrap() = Some((daemon.child.id(), daemon.locator()));
        panic!("exercise daemon cleanup during unwinding");
    });
    assert!(result.is_err());

    let (pid, locator) = observed.lock().unwrap().clone().unwrap();
    assert!(!process_exists(pid), "daemon {pid} survived unwinding");
    assert!(
        !locator.exists(),
        "{} survived unwinding",
        locator.display()
    );
}

#[test]
fn the_hub_publishes_every_running_emulator_in_the_official_shape() {
    let daemon = Daemon::start("demo-hub-shape", &[]);
    let port = daemon.hub_port();
    let emulators = json(port, "GET", "/emulators");

    // Every selected service is present, keyed by its official name.
    for name in ["firestore", "auth", "storage", "hub"] {
        let entry = emulators
            .get(name)
            .unwrap_or_else(|| panic!("{name} is missing from {emulators}"));
        assert_eq!(entry["name"], name);
        assert_eq!(
            entry["host"], "127.0.0.1",
            "{name}: discovery clients build `host:port` without re-bracketing, so the entry must name the IPv4 loopback"
        );
        assert!(entry["port"].as_u64().is_some_and(|p| p > 0), "{name}");
        assert!(entry["pid"].as_u64().is_some_and(|p| p > 0), "{name}");
        let listen = &entry["listen"][0];
        assert_eq!(listen["address"], "127.0.0.1", "{name}");
        assert_eq!(listen["family"], "IPv4", "{name}");
        assert_eq!(listen["port"], entry["port"], "{name}");
    }
    // Nothing is claimed that is not running: no functions codebase was configured, the UI
    // was turned off, and fireemu serves none of the deferred products.
    for absent in [
        "functions",
        "ui",
        "database",
        "hosting",
        "pubsub",
        "eventarc",
        "tasks",
        "dataconnect",
        "extensions",
    ] {
        assert!(
            emulators.get(absent).is_none(),
            "{absent} must not be advertised: {emulators}"
        );
    }
    assert_eq!(emulators["hub"]["port"], u64::from(port));

    // `GET /` answers the locator plus this listener's own address.
    let root = json(port, "GET", "/");
    assert_eq!(root["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(root["origins"][0], format!("http://127.0.0.1:{port}"));
    assert_eq!(root["host"], "127.0.0.1");
    assert_eq!(root["port"], u64::from(port));
    assert!(root["pid"].as_u64().is_some_and(|p| p > 0));
    assert!(
        root.get("fireemuControlToken").is_none(),
        "the public Hub response must not expose the discovery capability"
    );

    // An unknown route is a 404, not a hang or a 200 with an empty body.
    let (status, _) = request(port, "GET", "/nope", "127.0.0.1");
    assert_eq!(status, 404);
    // The export route exists; a request without the official body is refused precisely
    // rather than writing a directory the caller never named. `tests/import_export.rs`
    // drives the successful path end to end.
    let token = daemon.control_token();
    let (status, _, body) = request_with_headers(
        port,
        "POST",
        "/_admin/export",
        "127.0.0.1",
        &[("Authorization", &format!("Bearer {token}"))],
        "",
    );
    assert_eq!(status, 400, "{body}");
    assert!(body.contains("export request body"), "{body}");

    // A non-loopback Host is refused: the Hub can disable background triggers, so a page on
    // a routable name must not reach it by DNS rebinding.
    let (status, _) = request(port, "GET", "/emulators", "attacker.example");
    assert_eq!(status, 403);
    let (status, _) = request(port, "GET", "/emulators", "127.attacker.example");
    assert_eq!(status, 403);

    daemon.stop();
}

#[test]
fn the_locator_file_is_written_at_start_and_removed_at_exit() {
    let daemon = Daemon::start("demo-hub-locator", &[]);
    let port = daemon.hub_port();
    let path = daemon.locator();
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{} should exist: {e}", path.display()));
    let locator: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(locator["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(locator["origins"][0], format!("http://127.0.0.1:{port}"));
    assert_eq!(
        locator["pid"].as_u64().unwrap(),
        u64::from(daemon.child.id()),
        "the locator names the daemon that wrote it, which is what tells a second suite it is live"
    );
    assert_eq!(locator["fireemuControlToken"].as_str().unwrap().len(), 32);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    daemon.stop();
    let gone = Instant::now();
    while path.exists() && gone.elapsed() < Duration::from_secs(5) {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(
        !path.exists(),
        "{} outlived the daemon that wrote it",
        path.display()
    );
}

#[cfg(unix)]
#[test]
fn the_hub_discovery_file_never_follows_a_symlink() {
    use std::os::unix::fs::symlink;

    let project = format!("demo-hub-symlink-{}", std::process::id());
    let namespace = DaemonNamespace::new("hub-symlink-locator");
    let path = namespace.path().join(format!("hub-{project}.json"));
    let target_namespace = TrustedTempDir::new("hub-symlink-target");
    let target = target_namespace.join("target.txt");
    std::fs::write(&target, "do not replace").unwrap();
    symlink(&target, &path).unwrap();
    let daemon = Daemon::start_in_namespace(&project, &[], namespace);
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "do not replace");
    assert!(std::fs::symlink_metadata(&path)
        .unwrap()
        .file_type()
        .is_symlink());
    daemon.stop();
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "do not replace");
}

#[test]
fn a_daemon_that_could_not_bind_the_hub_serves_the_suite_anyway() {
    // The default Hub port is best effort, exactly like the UI's: a busy one disables
    // discovery and nothing else. An explicit one that cannot be bound is an error.
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
            "--logging-port",
            "0",
            "--ui-port",
            "0",
            "--hub-port",
        ])
        .arg(port.to_string())
        .args(["--", "true"])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains(&format!("bind 127.0.0.1:{port}")),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    drop(busy);
}

#[test]
fn the_hub_switches_background_triggers_and_says_so() {
    // No functions codebase is loaded, so the switch has nothing to act on and says that
    // rather than reporting a state it did not reach.
    let daemon = Daemon::start("demo-hub-triggers", &[]);
    let port = daemon.hub_port();
    let token = daemon.control_token();
    let (status, _, body) = request_with_headers(
        port,
        "PUT",
        "/functions/disableBackgroundTriggers",
        "127.0.0.1",
        &[("Authorization", &format!("Bearer {token}"))],
        "",
    );
    assert_eq!(status, 400, "{body}");
    assert!(
        body.contains("Cloud Functions emulator is not running"),
        "{body}"
    );
    daemon.stop();

    // With a codebase loaded, both routes answer the official `{"enabled": ...}` body.
    let functions = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tools/sdk-smoke/functions-project");
    // The codebase resolves firebase-functions through tools/sdk-smoke/node_modules; without
    // an install this half of the scenario cannot run, and the smoke there covers it instead.
    if !functions
        .join("../node_modules/firebase-functions")
        .is_dir()
    {
        return;
    }
    let daemon = Daemon::start(
        "demo-hub-triggers-fn",
        &[
            "--functions",
            functions.to_str().unwrap(),
            "--functions-port",
            "0",
        ],
    );
    let port = daemon.hub_port();
    let token = daemon.control_token();
    let mutation = |path: &str| {
        let (status, _, body) = request_with_headers(
            port,
            "PUT",
            path,
            "127.0.0.1",
            &[("Authorization", &format!("Bearer {token}"))],
            "",
        );
        assert_eq!(status, 200, "PUT {path} -> {body}");
        serde_json::from_str::<serde_json::Value>(&body).unwrap()
    };
    let disabled = mutation("/functions/disableBackgroundTriggers");
    assert_eq!(disabled["enabled"], false);
    let enabled = mutation("/functions/enableBackgroundTriggers");
    assert_eq!(enabled["enabled"], true);
    // The Functions emulator is discoverable while it runs.
    let emulators = json(port, "GET", "/emulators");
    assert_eq!(emulators["functions"]["name"], "functions");
    let _ = scratch("triggers");
    daemon.stop();
}

fn assert_hub_preflight_refused(port: u16, path: &str, label: &str, headers: &[(&str, &str)]) {
    let (status, head, _) = request_with_headers(port, "OPTIONS", path, "127.0.0.1", headers, "");
    assert_eq!(status, 403, "{label}: {head}");
    assert!(
        !head
            .to_ascii_lowercase()
            .contains("access-control-allow-origin"),
        "{label}: {head}"
    );
}

fn assert_hub_preflight_admitted(port: u16, path: &str, local_origin: &str) {
    let (status, head, _) = request_with_headers(
        port,
        "OPTIONS",
        path,
        "127.0.0.1",
        &[
            ("Origin", local_origin),
            ("Access-Control-Request-Method", "PUT"),
            ("Access-Control-Request-Headers", "authorization"),
            ("Sec-Fetch-Site", "same-site"),
            ("Sec-Fetch-Mode", "cors"),
            ("Access-Control-Request-Private-Network", "true"),
        ],
        "",
    );
    let lower = head.to_ascii_lowercase();
    assert_eq!(status, 204, "{head}");
    assert!(lower.contains(&format!("access-control-allow-origin: {local_origin}")));
    assert!(
        lower.contains("access-control-allow-methods: put"),
        "{head}"
    );
    assert!(
        lower.contains("access-control-allow-headers: authorization"),
        "{head}"
    );
    assert!(lower.contains("access-control-allow-private-network: true"));
    assert!(lower.contains("vary: origin, access-control-request-method, access-control-request-headers, access-control-request-private-network, sec-fetch-site, sec-fetch-mode"), "{head}");
}

#[test]
fn hub_mutations_require_a_local_browser_origin_and_the_control_capability() {
    let daemon = Daemon::start("demo-hub-mutation-security", &[]);
    let port = daemon.hub_port();
    let token = daemon.control_token();
    let path = "/functions/disableBackgroundTriggers";

    for (label, headers) in [
        (
            "remote origin",
            vec![
                ("Origin", "https://attacker.example"),
                ("Access-Control-Request-Method", "PUT"),
                ("Access-Control-Request-Headers", "authorization"),
            ],
        ),
        (
            "opaque origin",
            vec![
                ("Origin", "null"),
                ("Access-Control-Request-Method", "PUT"),
                ("Access-Control-Request-Headers", "authorization"),
            ],
        ),
        (
            "rebinding origin",
            vec![
                ("Origin", "http://127.0.0.1.attacker.example"),
                ("Access-Control-Request-Method", "PUT"),
                ("Access-Control-Request-Headers", "authorization"),
            ],
        ),
        (
            "userinfo origin",
            vec![
                ("Origin", "http://user@localhost"),
                ("Access-Control-Request-Method", "PUT"),
                ("Access-Control-Request-Headers", "authorization"),
            ],
        ),
        (
            "wrong requested method",
            vec![
                ("Origin", "http://127.0.0.1:4000"),
                ("Access-Control-Request-Method", "POST"),
                ("Access-Control-Request-Headers", "authorization"),
            ],
        ),
        (
            "unapproved requested header",
            vec![
                ("Origin", "http://127.0.0.1:4000"),
                ("Access-Control-Request-Method", "PUT"),
                ("Access-Control-Request-Headers", "x-fireemu-internal"),
            ],
        ),
        (
            "cross-site fetch metadata",
            vec![
                ("Origin", "http://127.0.0.1:4000"),
                ("Access-Control-Request-Method", "PUT"),
                ("Access-Control-Request-Headers", "authorization"),
                ("Sec-Fetch-Site", "cross-site"),
            ],
        ),
    ] {
        assert_hub_preflight_refused(port, path, label, &headers);
    }

    let local_origin = "http://127.0.0.1:4000";
    assert_hub_preflight_admitted(port, path, local_origin);

    for (label, authorization) in [
        ("missing token", None),
        ("wrong token", Some("Bearer wrong")),
    ] {
        let mut headers = vec![("Origin", local_origin)];
        if let Some(value) = authorization {
            headers.push(("Authorization", value));
        }
        let (status, _, _) = request_with_headers(port, "PUT", path, "127.0.0.1", &headers, "");
        assert_eq!(status, 403, "{label}");
    }
    let authorization = format!("Bearer {token}");
    let (status, head, body) = request_with_headers(
        port,
        "PUT",
        path,
        "127.0.0.1",
        &[("Origin", local_origin), ("Authorization", &authorization)],
        "",
    );
    assert_eq!(status, 400, "{body}");
    assert!(
        head.to_ascii_lowercase()
            .contains(&format!("access-control-allow-origin: {local_origin}")),
        "{head}"
    );
    daemon.stop();
}

#[test]
fn exec_exports_the_hub_address_to_its_command() {
    let dir = scratch("env");
    let out = dir.join("env.txt");
    let (port, output) = (0..8)
        .find_map(|attempt| {
            let port = free_port();
            let output = Command::new(env!("CARGO_BIN_EXE_fireemu"))
                .args([
                    "exec",
                    "--firestore-port",
                    "0",
                    "--http-port",
                    "0",
                    "--storage-port",
                    "0",
                    "--logging-port",
                    "0",
                    "--ui-port",
                    "0",
                    "--project",
                    "demo-hub-env",
                    "--hub-port",
                ])
                .arg(port.to_string())
                .args(["--", "sh", "-c"])
                .arg(format!("env > {}", out.display()))
                .stdin(Stdio::null())
                .output()
                .unwrap();
            let collision =
                String::from_utf8_lossy(&output.stderr).contains("Address already in use");
            (output.status.success() || !collision || attempt == 7).then_some((port, output))
        })
        .expect("one bounded Hub bind attempt completes");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let env: std::collections::BTreeMap<String, String> = std::fs::read_to_string(&out)
        .unwrap()
        .lines()
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect();
    // A bare host:port, as `firebase-tools` writes it; `@firebase/rules-unit-testing` parses
    // it with `new URL("http://" + value)`, so a scheme here would break discovery.
    assert_eq!(env["FIREBASE_EMULATOR_HUB"], format!("127.0.0.1:{port}"));

    // The locator the run wrote is gone with it.
    let locator = std::env::temp_dir().join("hub-demo-hub-env.json");
    assert!(!locator.exists(), "{} outlived exec", locator.display());
}

#[test]
fn turning_the_hub_off_leaves_no_listener_and_no_variable() {
    let dir = scratch("off");
    let out = dir.join("env.txt");
    let output = Command::new(env!("CARGO_BIN_EXE_fireemu"))
        .args([
            "exec",
            "--firestore-port",
            "0",
            "--http-port",
            "0",
            "--storage-port",
            "0",
            "--logging-port",
            "0",
            "--ui-port",
            "0",
            "--hub-port",
            "0",
            "--project",
            "demo-hub-off",
            "--",
            "sh",
            "-c",
        ])
        .arg(format!("env > {}", out.display()))
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = std::fs::read_to_string(&out).unwrap();
    assert!(
        !text.contains("FIREBASE_EMULATOR_HUB"),
        "the Hub was turned off but its variable was still exported"
    );
    assert!(!std::env::temp_dir().join("hub-demo-hub-off.json").exists());
}

/// The export route is the one Hub route that writes to disk. Its CSRF wall is the refusal of
/// every request carrying an `Origin`: the official CLI drives it without one, a page in a
/// browser cannot avoid sending one.
#[test]
fn the_export_route_requires_the_control_capability_and_refuses_browser_origins() {
    use std::io::{Read as _, Write as _};
    use std::net::TcpStream;
    use std::time::Duration;

    #[cfg(unix)]
    let trusted = TrustedTempDir::new("hub-export");
    #[cfg(unix)]
    let dir = trusted.join("export");
    #[cfg(not(unix))]
    let dir = std::env::temp_dir().join(format!("fireemu-hub-export-{}", std::process::id()));
    #[cfg(not(unix))]
    let _ = std::fs::remove_dir_all(&dir);
    let daemon = Daemon::start("demo-hub-export", &[]);
    let port = daemon.hub_port();
    let token = daemon.control_token();
    let send = |origin: Option<&str>, authorization: Option<&str>| -> u16 {
        let body = format!(
            "{{\"path\": {:?}, \"initiatedBy\": \"test\"}}",
            dir.display().to_string()
        );
        let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("the Hub accepts");
        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .unwrap();
        let origin_line = origin
            .map(|o| format!("Origin: {o}\r\n"))
            .unwrap_or_default();
        let authorization_line = authorization
            .map(|value| format!("Authorization: {value}\r\n"))
            .unwrap_or_default();
        write!(
            stream,
            "POST /_admin/export HTTP/1.1\r\nHost: 127.0.0.1\r\n{origin_line}{authorization_line}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .unwrap();
        let mut raw = String::new();
        let read = stream.read_to_string(&mut raw);
        let status = raw
            .lines()
            .next()
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|c| c.parse().ok())
            .unwrap_or(0);
        if let Err(error) = read {
            assert!(
                error.kind() == std::io::ErrorKind::ConnectionReset
                    && status != 0
                    && complete_http_response(&raw),
                "the Hub response failed before it was complete: {error}; {raw}"
            );
        }
        status
    };
    // A page (any Origin, loopback included) is refused and writes nothing.
    let bearer = format!("Bearer {token}");
    assert_eq!(send(Some("http://127.0.0.1:4000"), Some(&bearer)), 403);
    assert!(
        !dir.exists(),
        "a refused export must not create the directory"
    );
    assert_eq!(send(None, None), 403);
    assert!(
        !dir.exists(),
        "an export without the control capability must not create the directory"
    );
    assert_eq!(send(None, Some(&bearer)), 200);
    assert!(dir.join("firebase-export-metadata.json").is_file());
    drop(daemon);
    #[cfg(not(unix))]
    let _ = std::fs::remove_dir_all(dir);
}
