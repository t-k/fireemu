//! The official Auth emulator prints every email action link and SMS code to its console
//! instead of sending it. A daemon does the same on standard output, once per issued code,
//! unless `auth.logActionCodes` is false or `--log-verbosity quiet` is given; the codes stay
//! readable from the emulator inspection routes either way.

#![cfg(unix)]

mod census;
#[path = "../../../tests/support/trusted_temp.rs"]
mod trusted_temp;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use trusted_temp::TrustedTempDir;

fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

fn http(port: u16, method: &str, path: &str, body: &Value) -> (u16, Value) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("the daemon accepts");
    stream
        .set_read_timeout(Some(Duration::from_secs(20)))
        .unwrap();
    let body = body.to_string();
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
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
    (status, serde_json::from_str(body).unwrap_or(Value::Null))
}

struct Daemon {
    child: Child,
    stdout: Arc<Mutex<String>>,
    hub_port: u16,
    /// Owned for the daemon's lifetime; removed when the test ends.
    _dir: TrustedTempDir,
}

impl Daemon {
    fn start(name: &str, auth: &Value, verbosity: &str) -> Self {
        let dir = TrustedTempDir::new(&format!("auth-code-log-{name}"));
        let config = dir.join("fireemu.json");
        std::fs::write(
            &config,
            json!({"schemaVersion": 1, "profile": "firebase", "auth": auth}).to_string(),
        )
        .unwrap();
        let hub_port = free_port();
        let mut child = Command::new(env!("CARGO_BIN_EXE_fireemu"))
            .args([
                "up",
                "--config",
                config.to_str().unwrap(),
                "--project",
                &format!("demo-{name}"),
                "--only",
                "auth",
                "--firestore-port",
                "0",
                "--http-port",
                "0",
                "--storage-port",
                "0",
                "--functions-port",
                "0",
                "--pubsub-port",
                "0",
                "--logging-port",
                "0",
                "--ui-port",
                "0",
                "--log-verbosity",
                verbosity,
                "--hub-port",
            ])
            .arg(hub_port.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        // The child is owned (and killed on drop) before anything below can panic.
        let daemon = Self {
            child,
            stdout: Arc::new(Mutex::new(String::new())),
            hub_port,
            _dir: dir,
        };
        let collected = Arc::clone(&daemon.stdout);
        let (tx, rx) = mpsc::channel::<()>();
        std::thread::spawn(move || {
            let mut reader = BufReader::new(stdout);
            let mut ready = Some(tx);
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or(0) == 0 {
                    return;
                }
                collected.lock().unwrap().push_str(&line);
                if line.contains("control API:") {
                    if let Some(tx) = ready.take() {
                        let _ = tx.send(());
                    }
                }
            }
        });
        if verbosity == "quiet" {
            // Nothing is printed: wait for the hub instead.
            let deadline = Instant::now() + Duration::from_secs(60);
            while TcpStream::connect(("127.0.0.1", hub_port)).is_err() {
                assert!(Instant::now() < deadline, "the daemon became ready");
                std::thread::sleep(Duration::from_millis(50));
            }
        } else {
            rx.recv_timeout(Duration::from_secs(60))
                .expect("the daemon became ready");
        }
        daemon
    }

    fn auth_port(&self) -> u16 {
        let (status, emulators) = http(self.hub_port, "GET", "/emulators", &Value::Null);
        assert_eq!(status, 200, "{emulators}");
        u16::try_from(emulators["auth"]["port"].as_u64().unwrap()).unwrap()
    }

    /// Standard output so far, once `needle` has appeared or two seconds passed.
    fn stdout_after(&self, needle: &str) -> String {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let text = self.stdout.lock().unwrap().clone();
            if text.contains(needle) || Instant::now() > deadline {
                return text;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

const V1: &str = "/identitytoolkit.googleapis.com/v1";

/// Signs one account up, asks for an email verification link and a phone code, and reports
/// the daemon's standard output together with the code the inspection routes hold.
fn issue(daemon: &Daemon, project: &str) -> (String, String, String) {
    let port = daemon.auth_port();
    let (status, user) = http(
        port,
        "POST",
        &format!("{V1}/accounts:signUp?key=fake-api-key"),
        &json!({"email": "codes@example.com", "password": "hunter22", "returnSecureToken": true}),
    );
    assert_eq!(status, 200, "{user}");
    let (status, sent) = http(
        port,
        "POST",
        &format!("{V1}/accounts:sendOobCode?key=fake-api-key"),
        &json!({"requestType": "VERIFY_EMAIL", "idToken": user["idToken"]}),
    );
    assert_eq!(status, 200, "{sent}");
    let (status, sent) = http(
        port,
        "POST",
        &format!("{V1}/accounts:sendVerificationCode?key=fake-api-key"),
        &json!({"phoneNumber": "+15550001", "recaptchaToken": "x"}),
    );
    assert_eq!(status, 200, "{sent}");
    let (_, oob) = http(
        port,
        "GET",
        &format!("/emulator/v1/projects/{project}/oobCodes"),
        &Value::Null,
    );
    let (_, sms) = http(
        port,
        "GET",
        &format!("/emulator/v1/projects/{project}/verificationCodes"),
        &Value::Null,
    );
    let oob_code = oob["oobCodes"][0]["oobCode"].as_str().unwrap().to_owned();
    let sms_code = sms["verificationCodes"][0]["code"]
        .as_str()
        .unwrap()
        .to_owned();
    let text = daemon.stdout_after(&sms_code);
    (text, oob_code, sms_code)
}

#[test]
fn action_links_and_sms_codes_are_printed_once_like_the_official_emulator() {
    let daemon = Daemon::start("default", &json!({}), "info");
    let port = daemon.auth_port();
    let (text, oob_code, sms_code) = issue(&daemon, "demo-default");
    assert!(
        text.contains("  auth codes:       email action links and SMS codes are printed here"),
        "the banner says what is printed:\n{text}"
    );
    let link = format!(
        "  auth: To verify the email address codes@example.com, follow this link: http://127.0.0.1:{port}/emulator/action?mode=verifyEmail&lang=en&oobCode={oob_code}&apiKey=fake-api-key\n"
    );
    assert_eq!(text.matches(&link).count(), 1, "{text}");
    let sms = format!("  auth: To verify the phone number +15550001, use the code {sms_code}.\n");
    assert_eq!(text.matches(&sms).count(), 1, "{text}");
    // Reading the inspection routes again prints nothing more.
    let _ = http(
        port,
        "GET",
        "/emulator/v1/projects/demo-default/oobCodes",
        &Value::Null,
    );
    std::thread::sleep(Duration::from_millis(200));
    let again = daemon.stdout.lock().unwrap().clone();
    assert_eq!(again.matches("  auth: To ").count(), 2, "{again}");
}

#[test]
fn action_code_logging_can_be_switched_off_and_is_quiet_under_quiet_verbosity() {
    let off = Daemon::start("off", &json!({"logActionCodes": false}), "info");
    let (text, oob_code, sms_code) = issue(&off, "demo-off");
    assert!(
        text.contains("  auth codes:       not printed (auth.logActionCodes = false)"),
        "{text}"
    );
    assert!(!text.contains(&oob_code), "{text}");
    assert!(!text.contains(&sms_code), "{text}");
    assert!(!text.contains("  auth: To "), "{text}");
    drop(off);

    let quiet = Daemon::start("quiet", &json!({}), "quiet");
    let (text, oob_code, sms_code) = issue(&quiet, "demo-quiet");
    assert!(!text.contains(&oob_code), "{text}");
    assert!(!text.contains(&sms_code), "{text}");
    assert!(!text.contains("auth: To "), "{text}");
}
