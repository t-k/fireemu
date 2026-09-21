//! The browser policy of the privileged emulator routes, through the real listeners of a
//! daemon started the way a project starts it: `DELETE .../databases/(default)/documents`
//! (`clearFirestore()`), `PUT .../{project}:securityRules` (`loadFirestoreRules`) and the
//! Storage `PUT /internal/setRules` (`loadStorageRules`).
//!
//! The clients of these routes are processes: `@firebase/rules-unit-testing` 5.0.2 calls all
//! three through Node's built-in `fetch`. Node 18 and later ship undici, which attaches
//! `sec-fetch-mode: cors` to every request (a forbidden header name the script cannot remove)
//! and nothing else a browser would attach. The exact header set Node 24 sends for a request
//! with no headers of its own, probed against a loopback listener on 2026-09-21, is `host`,
//! `connection`, `accept`, `accept-language`, `sec-fetch-mode`, `user-agent`,
//! `accept-encoding`. That request must be admitted unauthenticated; a page-issued request
//! (`sec-fetch-site`, `sec-fetch-dest`, `origin`) must still present the run's control token.

#![cfg(unix)]

#[path = "../../../tests/support/trusted_temp.rs"]
mod trusted_temp;

use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

use serde_json::Value;
use trusted_temp::TrustedTempDir;

const PROJECT: &str = "demo-browser-guard";

fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

/// One HTTP request written by hand, so the test controls every header on the wire: the
/// binary's test suite has no HTTP client dependency, and one would attach headers of its own.
fn http(
    port: u16,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> (u16, String) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("the daemon accepts");
    stream
        .set_read_timeout(Some(Duration::from_secs(20)))
        .unwrap();
    write!(stream, "{method} {path} HTTP/1.1\r\n").unwrap();
    if !headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("host"))
    {
        write!(stream, "Host: 127.0.0.1:{port}\r\n").unwrap();
    }
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
    (status, body.to_owned())
}

/// The header set Node 24's built-in `fetch` attaches to a request a script issues with no
/// headers of its own, `Host` aside (the test writes that one). `sec-fetch-mode` is the only
/// field of it that any browser-metadata list could contain.
fn undici_headers(port: u16) -> Vec<(String, String)> {
    vec![
        ("host".to_owned(), format!("127.0.0.1:{port}")),
        ("connection".to_owned(), "keep-alive".to_owned()),
        ("accept".to_owned(), "*/*".to_owned()),
        ("accept-language".to_owned(), "*".to_owned()),
        ("sec-fetch-mode".to_owned(), "cors".to_owned()),
        ("user-agent".to_owned(), "node".to_owned()),
        ("accept-encoding".to_owned(), "gzip, deflate".to_owned()),
    ]
}

/// The same request as a page on another loopback port would issue it: every current browser
/// attaches `sec-fetch-site` and `sec-fetch-dest` alongside `sec-fetch-mode`, and `origin`
/// on a cross-origin fetch.
fn browser_headers(port: u16) -> Vec<(String, String)> {
    let mut headers = undici_headers(port);
    headers.push(("sec-fetch-site".to_owned(), "same-site".to_owned()));
    headers.push(("sec-fetch-dest".to_owned(), "empty".to_owned()));
    headers.push(("origin".to_owned(), "http://127.0.0.1:5173".to_owned()));
    headers
}

fn borrowed(headers: &[(String, String)]) -> Vec<(&str, &str)> {
    headers
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect()
}

/// A strict-profile daemon with Firestore Security Rules, its Hub on `hub_port` so the test
/// can discover the ports and the control token the way a client does.
struct Daemon {
    child: Child,
    hub_port: u16,
    dir: TrustedTempDir,
}

impl Daemon {
    fn start() -> Self {
        let dir = TrustedTempDir::new("browser-guard");
        let rules = dir.join("firestore.rules");
        std::fs::write(
            &rules,
            "rules_version = '2';\nservice cloud.firestore {\n  match /databases/{database}/documents {\n    match /{document=**} {\n      allow read, write: if true;\n    }\n  }\n}\n",
        )
        .unwrap();
        let firebase_json = dir.join("firebase.json");
        std::fs::write(
            &firebase_json,
            serde_json::json!({"firestore": {"rules": "firestore.rules"}}).to_string(),
        )
        .unwrap();
        let config = dir.join("fireemu.json");
        std::fs::write(
            &config,
            serde_json::json!({"schemaVersion": 1, "profile": "strict"}).to_string(),
        )
        .unwrap();
        let hub_port = free_port();
        let mut child = Command::new(env!("CARGO_BIN_EXE_fireemu"))
            .args([
                "up",
                "--config",
                config.to_str().unwrap(),
                "--firebase-json",
                firebase_json.to_str().unwrap(),
                "--project",
                PROJECT,
                "--only",
                "firestore,storage",
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
                "--hub-port",
            ])
            .arg(hub_port.to_string())
            .env("TMPDIR", dir.path())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let stderr = child.stderr.take().unwrap();
        // The child is owned (and killed on drop) before anything below can panic.
        let daemon = Self {
            child,
            hub_port,
            dir,
        };
        let transcript = Arc::new(Mutex::new(String::new()));
        let collected = Arc::clone(&transcript);
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
        let errors = Arc::clone(&transcript);
        std::thread::spawn(move || {
            let mut reader = BufReader::new(stderr);
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or(0) == 0 {
                    return;
                }
                errors.lock().unwrap().push_str(&line);
            }
        });
        assert!(
            rx.recv_timeout(Duration::from_secs(60)).is_ok(),
            "the daemon did not become ready:\n{}",
            transcript.lock().unwrap()
        );
        daemon
    }

    fn emulator_port(&self, name: &str) -> u16 {
        let (status, body) = http(self.hub_port, "GET", "/emulators", &[], "");
        assert_eq!(status, 200, "{body}");
        let emulators: Value = serde_json::from_str(&body).unwrap();
        u16::try_from(emulators[name]["port"].as_u64().unwrap()).unwrap()
    }

    fn control_token(&self) -> String {
        let locator = self.dir.join(format!("hub-{PROJECT}.json"));
        let locator: Value =
            serde_json::from_str(&std::fs::read_to_string(locator).unwrap()).unwrap();
        locator["fireemuControlToken"].as_str().unwrap().to_owned()
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn documents(path: &str) -> String {
    format!("/v1/projects/{PROJECT}/databases/(default)/documents{path}")
}

fn seed(port: u16, id: &str) {
    let (status, body) = http(
        port,
        "POST",
        &format!("{}?documentId={id}", documents("/things")),
        &[
            ("Authorization", "Bearer owner"),
            ("Content-Type", "application/json"),
        ],
        r#"{"fields": {"a": {"stringValue": "x"}}}"#,
    );
    assert_eq!(status, 200, "seed {id}: {body}");
}

fn present(port: u16, id: &str) -> bool {
    let (status, body) = http(
        port,
        "GET",
        &documents(&format!("/things/{id}")),
        &[("Authorization", "Bearer owner")],
        "",
    );
    assert!(status == 200 || status == 404, "{status}: {body}");
    status == 200
}

#[test]
fn clear_firestore_admits_the_node_fetch_shape_and_holds_a_page_to_the_control_token() {
    let daemon = Daemon::start();
    let port = daemon.emulator_port("firestore");
    let token = daemon.control_token();
    let clear = format!("/emulator/v1/projects/{PROJECT}/databases/(default)/documents");

    // Exactly what `clearFirestore()` sends from Node 24: admitted, and the project is wiped.
    seed(port, "undici");
    let (status, body) = http(port, "DELETE", &clear, &borrowed(&undici_headers(port)), "");
    assert_eq!(status, 200, "undici shape: {body}");
    assert!(
        !present(port, "undici"),
        "the clear must have wiped the project"
    );

    // The same request from a page on another loopback port, without a token: refused, and
    // nothing is wiped.
    seed(port, "page");
    let (status, body) = http(
        port,
        "DELETE",
        &clear,
        &borrowed(&browser_headers(port)),
        "",
    );
    assert_eq!(status, 403, "browser shape without a token: {body}");
    assert!(body.contains("CONTROL_TOKEN_REQUIRED"), "{body}");
    assert!(
        present(port, "page"),
        "the refused clear must keep the data"
    );

    // The wrong token is the same refusal.
    let mut wrong = browser_headers(port);
    wrong.push((
        "authorization".to_owned(),
        "Bearer not-the-control-token".to_owned(),
    ));
    let (status, body) = http(port, "DELETE", &clear, &borrowed(&wrong), "");
    assert_eq!(status, 403, "browser shape with the wrong token: {body}");
    assert!(body.contains("CONTROL_TOKEN_REQUIRED"), "{body}");
    assert!(present(port, "page"));

    // A page that presents the run's control token clears.
    let mut with_token = browser_headers(port);
    with_token.push(("authorization".to_owned(), format!("Bearer {token}")));
    let (status, body) = http(port, "DELETE", &clear, &borrowed(&with_token), "");
    assert_eq!(status, 200, "browser shape with the control token: {body}");
    assert!(!present(port, "page"));

    drop(daemon);
}

#[test]
fn security_rules_admit_the_node_fetch_shape_and_hold_a_page_to_the_control_token() {
    let daemon = Daemon::start();
    let port = daemon.emulator_port("firestore");
    let token = daemon.control_token();
    let route = format!("/emulator/v1/projects/{PROJECT}:securityRules");
    let deny_all = serde_json::json!({"rules": {"files": [{"name": "firestore.rules", "content": "rules_version = '2';\nservice cloud.firestore {\n  match /databases/{database}/documents {\n    match /{document=**} {\n      allow read, write: if false;\n    }\n  }\n}\n"}]}}).to_string();
    let allow_all = serde_json::json!({"rules": {"files": [{"name": "firestore.rules", "content": "rules_version = '2';\nservice cloud.firestore {\n  match /databases/{database}/documents {\n    match /{document=**} {\n      allow read, write: if true;\n    }\n  }\n}\n"}]}}).to_string();

    // A rules-bound read: `Bearer owner` bypasses rules, an unauthenticated read is judged by
    // them, so it tells which ruleset is live.
    seed(port, "probe");
    let anonymous_read = || http(port, "GET", &documents("/things/probe"), &[], "").0;
    assert_eq!(anonymous_read(), 200, "the run starts with allow-all rules");

    // Exactly what `loadFirestoreRules` sends from Node 24 (undici adds `content-type` for a
    // string body; the library sets none): admitted, and the ruleset is replaced.
    let (status, body) = http(
        port,
        "PUT",
        &route,
        &borrowed(&undici_headers(port)),
        &deny_all,
    );
    assert_eq!(status, 200, "undici shape: {body}");
    assert_eq!(anonymous_read(), 403, "the deny-all ruleset must be live");

    // A page without the token cannot put the allow-all ruleset back.
    let (status, body) = http(
        port,
        "PUT",
        &route,
        &borrowed(&browser_headers(port)),
        &allow_all,
    );
    assert_eq!(status, 403, "browser shape without a token: {body}");
    assert!(body.contains("CONTROL_TOKEN_REQUIRED"), "{body}");
    assert_eq!(
        anonymous_read(),
        403,
        "the refused load must keep the ruleset"
    );

    // A page with the run's control token can.
    let mut with_token = browser_headers(port);
    with_token.push(("authorization".to_owned(), format!("Bearer {token}")));
    let (status, body) = http(port, "PUT", &route, &borrowed(&with_token), &allow_all);
    assert_eq!(status, 200, "browser shape with the control token: {body}");
    assert_eq!(anonymous_read(), 200);

    drop(daemon);
}

#[test]
fn storage_set_rules_admits_the_node_fetch_shape_and_holds_a_page_to_the_control_token() {
    let daemon = Daemon::start();
    let port = daemon.emulator_port("storage");
    let token = daemon.control_token();
    let rules = |allow: bool| {
        serde_json::json!({"rules": {"files": [{"name": "storage.rules", "content": format!(
            "rules_version = '2';\nservice firebase.storage {{\n  match /b/{{bucket}}/o {{\n    match /{{allPaths=**}} {{\n      allow read, write: if {allow};\n    }}\n  }}\n}}\n"
        )}]}})
        .to_string()
    };
    // `loadStorageRules` sets `Content-Type: application/json` itself; the rest is undici's.
    let mut undici = undici_headers(port);
    undici.push(("content-type".to_owned(), "application/json".to_owned()));
    let mut browser = browser_headers(port);
    browser.push(("content-type".to_owned(), "application/json".to_owned()));

    // A rules-bound anonymous read of a missing object answers 404 under allow-all rules and
    // 403 under deny-all, so it tells which ruleset is live.
    let anonymous_read = || {
        http(
            port,
            "GET",
            &format!("/v0/b/{PROJECT}.appspot.com/o/probe.txt?alt=media"),
            &[],
            "",
        )
        .0
    };

    let (status, body) = http(
        port,
        "PUT",
        "/internal/setRules",
        &borrowed(&undici),
        &rules(false),
    );
    assert_eq!(status, 200, "undici shape: {body}");
    assert_eq!(anonymous_read(), 403, "the deny-all ruleset must be live");

    let (status, body) = http(
        port,
        "PUT",
        "/internal/setRules",
        &borrowed(&browser),
        &rules(true),
    );
    assert_eq!(status, 403, "browser shape without a token: {body}");
    assert!(body.contains("CONTROL_TOKEN_REQUIRED"), "{body}");
    assert_eq!(
        anonymous_read(),
        403,
        "the refused load must keep the ruleset"
    );

    let mut with_token = browser.clone();
    with_token.push(("authorization".to_owned(), format!("Bearer {token}")));
    let (status, body) = http(
        port,
        "PUT",
        "/internal/setRules",
        &borrowed(&with_token),
        &rules(true),
    );
    assert_eq!(status, 200, "browser shape with the control token: {body}");
    assert_eq!(anonymous_read(), 404, "the allow-all ruleset must be live");

    drop(daemon);
}
