//! The compatibility profile as a runtime switch, against a daemon started the way a project
//! starts it (`CLAIM-01`, `CLAIM-03`).
//!
//! The scenario the compatibility contract asks for is one official limitation run under both
//! profiles: the pinned official Firestore emulator does not check composite indexes at all,
//! so a query whose index is not configured is served there. The `emulator` profile has to
//! serve it too -- that profile may add no rejection the official emulator does not make --
//! and only `strict` may refuse it, with the `firestore.indexes.json` fragment production
//! would need.

use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// A port nothing is listening on, released before it is handed back.
fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("fireemu-profiles-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// One HTTP request, written by hand: the binary's test suite has no HTTP client dependency
/// and the answers here are small enough to read in one go.
fn http(port: u16, method: &str, path: &str, body: Option<&str>) -> (u16, String) {
    http_with(port, method, path, body, "")
}

/// An owner (administrator) request, which Security Rules never judge.
fn http_as_owner(port: u16, method: &str, path: &str, body: Option<&str>) -> (u16, String) {
    http_with(port, method, path, body, "Authorization: Bearer owner\r\n")
}

fn http_with(
    port: u16,
    method: &str,
    path: &str,
    body: Option<&str>,
    headers: &str,
) -> (u16, String) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("the daemon accepts");
    stream
        .set_read_timeout(Some(Duration::from_secs(20)))
        .unwrap();
    let body = body.unwrap_or("");
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
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

/// A daemon under one compatibility profile, with its Hub on `hub_port` so the test can ask
/// it which port Firestore ended up on.
struct Daemon {
    child: Child,
    banner: Arc<Mutex<String>>,
    hub_port: u16,
}

impl Daemon {
    fn start(profile: &str) -> Self {
        Self::start_with(profile, profile, "")
    }

    /// A daemon whose `firestore` configuration carries `firestore_extra` (`"key": value, `
    /// pairs) besides the edition and the API mode.
    fn start_with(name: &str, profile: &str, firestore_extra: &str) -> Self {
        let (mut command, hub_port) = Self::command(name, profile, firestore_extra);
        let mut child = command
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        Self::ready(child.stdout.take().unwrap(), child, hub_port)
    }

    /// The `fireemu up` command of a daemon, and the Hub port it will listen on.
    fn command(name: &str, profile: &str, firestore_extra: &str) -> (Command, u16) {
        let dir = scratch(name);
        let config = dir.join("fireemu.json");
        std::fs::write(
            &config,
            format!(
                r#"{{"schemaVersion": 1, "profile": "{profile}", "firestore": {{{firestore_extra}"edition": "standard", "apiMode": "native"}}}}"#
            ),
        )
        .unwrap();
        let hub_port = free_port();
        let mut command = Command::new(env!("CARGO_BIN_EXE_fireemu"));
        command
            .args([
                "up",
                "--config",
                config.to_str().unwrap(),
                "--project",
                &format!("demo-profile-{name}"),
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
            .arg(hub_port.to_string())
            .stdin(Stdio::null());
        (command, hub_port)
    }

    fn ready(stdout: std::process::ChildStdout, child: Child, hub_port: u16) -> Self {
        // The banner's control-API line is printed once every listener is bound; the pipe
        // keeps being drained afterwards so the daemon never hits a broken pipe mid-run, and
        // every line it ever prints stays readable, whatever order the banner puts them in.
        let banner = Arc::new(Mutex::new(String::new()));
        let collected = Arc::clone(&banner);
        let (tx, rx) = std::sync::mpsc::channel::<()>();
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
        rx.recv_timeout(Duration::from_secs(60))
            .expect("the daemon became ready");
        Self {
            child,
            banner,
            hub_port,
        }
    }

    /// Everything the daemon has printed so far.
    fn banner(&self) -> String {
        self.banner.lock().unwrap().clone()
    }

    /// The Firestore port, discovered the way a client discovers it.
    fn firestore_port(&self) -> u16 {
        let (status, body) = http(self.hub_port, "GET", "/emulators", None);
        assert_eq!(status, 200, "{body}");
        let emulators: serde_json::Value = serde_json::from_str(&body).unwrap();
        u16::try_from(emulators["firestore"]["port"].as_u64().unwrap()).unwrap()
    }

    /// A query that needs a composite index nothing configured: an equality filter and an
    /// order by another field.
    fn unindexed_query(&self) -> (u16, String) {
        http(
            self.firestore_port(),
            "POST",
            "/v1/projects/demo-profile/databases/(default)/documents:runQuery",
            Some(
                r#"{"structuredQuery": {"from": [{"collectionId": "notes"}], "where": {"fieldFilter": {"field": {"fieldPath": "owner"}, "op": "EQUAL", "value": {"stringValue": "a"}}}, "orderBy": [{"field": {"fieldPath": "created"}, "direction": "ASCENDING"}]}}"#,
            ),
        )
    }

    fn stop(mut self) {
        let _ = Command::new("kill")
            .args(["-TERM", &self.child.id().to_string()])
            .status();
        let _ = self.child.wait();
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn the_same_official_limitation_is_served_under_emulator_and_refused_under_strict() {
    let emulator = Daemon::start("emulator");
    let (status, body) = emulator.unindexed_query();
    assert_eq!(
        status, 200,
        "the pinned official Firestore emulator serves this query, so the emulator profile must: {body}"
    );
    assert!(
        emulator.banner().contains("profile: emulator"),
        "the banner names the profile the run is under:\n{}",
        emulator.banner()
    );
    emulator.stop();

    let strict = Daemon::start("strict");
    let (status, body) = strict.unindexed_query();
    assert_eq!(status, 400, "{body}");
    assert!(body.contains("FAILED_PRECONDITION"), "{body}");
    assert!(
        body.contains("The query requires an index. You can create it here: https://console.firebase.google.com/v1/r/project/demo-profile/firestore/indexes?create_composite="),
        "the refusal carries production's console link to the index it needs: {body}"
    );
    assert!(
        strict.banner().contains("profile: strict"),
        "{}",
        strict.banner()
    );
    strict.stop();
}

#[test]
fn the_capabilities_command_reports_the_profile_it_would_run_under() {
    let dir = scratch("capabilities");
    for profile in ["emulator", "strict"] {
        let config = dir.join(format!("{profile}.json"));
        std::fs::write(
            &config,
            format!(
                r#"{{"schemaVersion": 1, "profile": "{profile}", "firestore": {{"edition": "standard", "apiMode": "native"}}}}"#
            ),
        )
        .unwrap();
        let out = Command::new(env!("CARGO_BIN_EXE_fireemu"))
            .args(["capabilities", "--config", config.to_str().unwrap()])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let manifest: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(manifest["profile"], profile);
        assert!(manifest["capabilities"]["FS-GW-1"].is_object());
    }
    // Without a configuration the command reports the default, which is the strict profile
    // `fireemu init` recommends.
    let out = Command::new(env!("CARGO_BIN_EXE_fireemu"))
        .arg("capabilities")
        .output()
        .unwrap();
    let manifest: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(manifest["profile"], "strict");
}

/// `firestore.databaseCreateTime` stands in for a production database's age: a read time
/// inside the retention hour but before the daemon started is served, one past the hour is
/// too old, and a creation time after the clock start is refused at start-up
/// (FS-QUERY-INDEX read-time/snapshots).
#[test]
fn a_configured_database_creation_time_bounds_read_times() {
    let rfc3339 = |seconds_ago: u64| {
        let at = std::time::SystemTime::now() - Duration::from_secs(seconds_ago);
        let seconds = at.duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        let days = seconds / 86_400;
        // Civil date from days since the epoch (Howard Hinnant's algorithm).
        let z = i64::try_from(days).unwrap() + 719_468;
        let era = z.div_euclid(146_097);
        let doe = z - era * 146_097;
        let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let day = doy - (153 * mp + 2) / 5 + 1;
        let month = if mp < 10 { mp + 3 } else { mp - 9 };
        let year = yoe + era * 400 + i64::from(month <= 2);
        let rest = seconds % 86_400;
        format!(
            "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
            rest / 3600,
            rest / 60 % 60,
            rest % 60
        )
    };
    let daemon = Daemon::start_with(
        "created",
        "strict",
        r#""databaseCreateTime": "2020-01-01T00:00:00Z", "#,
    );
    let port = daemon.firestore_port();
    let query = |read_time: &str| {
        // As the owner: the daemon has no ruleset, which the strict profile answers for a
        // client request with production's refusal.
        http_as_owner(
            port,
            "POST",
            "/v1/projects/demo-profile-created/databases/(default)/documents:runQuery",
            Some(&format!(
                r#"{{"structuredQuery": {{"from": [{{"collectionId": "notes"}}]}}, "readTime": "{read_time}"}}"#
            )),
        )
    };
    let (status, body) = query(&rfc3339(3540));
    assert_eq!(status, 200, "{body}");
    let (status, body) = query(&rfc3339(3660));
    assert_eq!(status, 400, "{body}");
    assert!(
        body.contains("The requested 'read_time' is too old."),
        "{body}"
    );
    daemon.stop();

    let (mut command, _) = Daemon::command(
        "created-later",
        "strict",
        r#""databaseCreateTime": "2999-01-01T00:00:00Z", "#,
    );
    let output = command.output().unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr
            .contains("firestore.databaseCreateTime 2999-01-01T00:00:00Z is after the clock start"),
        "{stderr}"
    );
}

/// The resident memory of a process in KiB, from `ps`.
/// `firestore.history.maxVersionsPerPath` bounds a document's retained versions on the
/// wall clock, where the default keeps every version of the last hour as production does.
#[test]
fn a_configured_per_path_history_cap_refuses_an_evicted_read_time() {
    for (name, history) in [
        ("history-default", ""),
        (
            "history-capped",
            r#""history": {"maxVersionsPerPath": 2}, "#,
        ),
    ] {
        let daemon = Daemon::start_with(name, "emulator", history);
        let port = daemon.firestore_port();
        let document =
            format!("/v1/projects/demo-profile-{name}/databases/(default)/documents/notes/n1");
        let mut first_update_time = None;
        for round in 0..4 {
            let (status, body) = http_as_owner(
                port,
                "PATCH",
                &document,
                Some(&format!(
                    r#"{{"fields": {{"v": {{"integerValue": "{round}"}}}}}}"#
                )),
            );
            assert_eq!(status, 200, "{body}");
            let written: serde_json::Value = serde_json::from_str(&body).unwrap();
            first_update_time
                .get_or_insert_with(|| written["updateTime"].as_str().unwrap().to_owned());
        }
        let read_time = first_update_time.unwrap();
        let (status, body) = http_as_owner(
            port,
            "GET",
            &format!("{document}?readTime={read_time}"),
            None,
        );
        if history.is_empty() {
            assert_eq!(status, 200, "{body}");
            assert!(body.contains(r#""integerValue":"0""#), "{body}");
        } else {
            assert_eq!(status, 400, "{body}");
            assert!(
                body.contains("The requested 'read_time' is no longer retained by this database."),
                "{body}"
            );
        }
        let (status, body) = http_as_owner(port, "GET", &document, None);
        assert_eq!(status, 200, "{body}");
        assert!(body.contains(r#""integerValue":"3""#), "{body}");
        daemon.stop();
    }
}

/// `firestore.history.maxBytes` lowers the logical history one database retains; a write that
/// would cross it is refused whole with `RESOURCE_EXHAUSTED`.
#[test]
fn a_configured_history_byte_limit_refuses_growth() {
    let daemon = Daemon::start_with(
        "history-bytes",
        "emulator",
        r#""history": {"maxBytes": 1048576}, "#,
    );
    let port = daemon.firestore_port();
    let document = "/v1/projects/demo-profile-history-bytes/databases/(default)/documents/notes/n1";
    let payload = "x".repeat(64 * 1024);
    let mut accepted = 0;
    let (status, body) = loop {
        let (status, body) = http_as_owner(
            port,
            "PATCH",
            document,
            Some(&format!(
                r#"{{"fields": {{"v": {{"stringValue": "{accepted} {payload}"}}}}}}"#
            )),
        );
        if status != 200 {
            break (status, body);
        }
        accepted += 1;
        assert!(
            accepted < 64,
            "1 MiB of history holds fewer than 64 versions of 64 KiB"
        );
    };
    assert_eq!(status, 429, "{body}");
    assert!(
        body.contains("Firestore retained history capacity is exhausted"),
        "{body}"
    );
    assert!(accepted > 0);
    let (status, body) = http_as_owner(port, "GET", document, None);
    assert_eq!(status, 200, "{body}");
    assert!(
        body.contains(&format!(r#""stringValue":"{} x"#, accepted - 1)),
        "the refused write left the document as it was"
    );
    daemon.stop();
}

fn resident_kib(pid: u32) -> u64 {
    sampled_resident_kib(pid).unwrap()
}

/// The resident set of `pid` in KiB, or `None` when `ps` could not tell (a sampler skips it).
fn sampled_resident_kib(pid: u32) -> Option<u64> {
    let output = Command::new("ps")
        .args(["-o", "rss=", "-p", &pid.to_string()])
        .output()
        .ok()?;
    String::from_utf8_lossy(&output.stdout).trim().parse().ok()
}

/// A refusal echoes at most 1 KiB of what it names, in both profiles: a 9 MiB property path of
/// control characters, refused before authorization, answers in a few KiB and does not grow
/// the daemon by many times its size (promotion review Security Should 1; the bound is local,
/// see `spec/compatibility/contract.json`).
#[test]
fn a_refusal_does_not_echo_a_large_request() {
    for profile in ["strict", "emulator"] {
        let daemon = Daemon::start_with(&format!("echo-{profile}"), profile, "");
        let port = daemon.firestore_port();
        let path = format!("~{}", "\u{1}".repeat(9 << 20));
        let body = format!(
            r#"{{"structuredQuery": {{"from": [{{"collectionId": "c"}}], "orderBy": [{{"field": {{"fieldPath": "{path}"}}}}]}}}}"#
        );
        let before = resident_kib(daemon.child.id());
        // The peak, not only what stays resident afterwards: sampled while the requests run
        // (every few milliseconds, so a shorter spike can escape it).
        let pid = daemon.child.id();
        let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let sampler = {
            let done = done.clone();
            std::thread::spawn(move || {
                let mut peak = 0;
                while !done.load(std::sync::atomic::Ordering::Relaxed) {
                    peak = peak.max(sampled_resident_kib(pid).unwrap_or(0));
                    std::thread::sleep(std::time::Duration::from_millis(2));
                }
                peak
            })
        };
        for _ in 0..3 {
            let (status, answer) = http(
                port,
                "POST",
                &format!("/v1/projects/demo-profile-echo-{profile}/databases/(default)/documents:runQuery"),
                Some(&body),
            );
            assert_eq!(
                status,
                400,
                "{profile}: {}",
                &answer[..answer.len().min(300)]
            );
            assert!(
                answer.len() < 16 * 1024,
                "{profile}: {} bytes",
                answer.len()
            );
            // The refusal this request is meant to reach, not an earlier one.
            assert!(
                answer.contains(r#"Invalid property path \"~"#),
                "{profile}: {}",
                &answer[..answer.len().min(300)]
            );
        }
        done.store(true, std::sync::atomic::Ordering::Relaxed);
        let peak = sampler.join().unwrap();
        let after = resident_kib(daemon.child.id());
        eprintln!("{profile}: rss {before} KiB -> peak {peak} KiB -> {after} KiB");
        assert!(
            after < before + 160 * 1024,
            "{profile}: rss {before} KiB -> {after} KiB"
        );
        assert!(
            peak < before + 256 * 1024,
            "{profile}: rss {before} KiB -> peak {peak} KiB"
        );
        daemon.stop();
    }
}

/// A REST body nested deeper than production's JSON grammar allows: the strict profile refuses
/// it in production's words, the emulator profile reads it as standard JSON as fireemu did
/// before and answers for its content (confirmation review 2026-09-24, round 2).
#[test]
fn a_deep_body_is_refused_by_the_grammar_only_under_the_strict_profile() {
    let deep = format!("{}{}", "[".repeat(110), "]".repeat(110));
    let body = format!(
        r#"{{"structuredQuery": {{"from": [{{"collectionId": "c"}}]}}, "readTime": {deep}}}"#
    );
    for profile in ["strict", "emulator"] {
        let daemon = Daemon::start_with(&format!("deep-{profile}"), profile, "");
        let (status, answer) = http(
            daemon.firestore_port(),
            "POST",
            &format!(
                "/v1/projects/demo-profile-deep-{profile}/databases/(default)/documents:runQuery"
            ),
            Some(&body),
        );
        assert_eq!(status, 400, "{profile}: {answer}");
        assert_eq!(
            answer.contains("Message too deep"),
            profile == "strict",
            "{profile}: {answer}"
        );
        daemon.stop();
    }
}

/// Production refuses every client request while a project has no `cloud.firestore` release
/// (FS-RULES, 2026-09-24), which is what the strict profile does while no ruleset is loaded;
/// the emulator profile keeps the official emulator's allow-everything, and the banner says
/// which one applies.
#[test]
fn without_a_ruleset_strict_refuses_client_requests_and_the_emulator_profile_allows_them() {
    let document = "/v1/projects/demo-profile-unruled/databases/(default)/documents/notes/n1";
    // The rules line follows the readiness line; give it a moment.
    let rules_line = |daemon: &Daemon| {
        for _ in 0..100 {
            if daemon.banner().contains("  rules: ") {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        daemon.banner()
    };
    let strict = Daemon::start_with("unruled", "strict", "");
    assert!(
        rules_line(&strict).contains("rules: none loaded; every client request is refused"),
        "{}",
        strict.banner()
    );
    let port = strict.firestore_port();
    let (status, body) = http(port, "GET", document, None);
    assert_eq!(status, 403, "{body}");
    assert!(
        body.contains("Missing or insufficient permissions."),
        "{body}"
    );
    let (status, body) = http_as_owner(port, "GET", document, None);
    assert_eq!(
        status, 404,
        "the owner is never judged by Security Rules: {body}"
    );
    strict.stop();

    let emulator = Daemon::start_with("unruled", "emulator", "");
    assert!(
        rules_line(&emulator).contains("rules: none loaded; every request is allowed"),
        "{}",
        emulator.banner()
    );
    let (status, body) = http(emulator.firestore_port(), "GET", document, None);
    assert_eq!(status, 404, "{body}");
    emulator.stop();
}

/// The daemon loads and evaluates the deepest expressions production compiles on its own
/// runtime threads, whose stack is sized for them in a debug build too: lists and calls nested
/// 99 levels, and 62 nested negations (evaluation stops at 64 levels, `eval::MAX_EVAL_NESTING`),
/// are answered instead of overflowing a thread. With a 1 MiB stack the daemon does not answer.
#[test]
fn the_daemon_evaluates_the_deepest_accepted_expression() {
    let daemon = Daemon::start_with("deep", "strict", "");
    let port = daemon.firestore_port();
    // Negations nest in the syntax tree (parentheses do not), so evaluation recurses; an even
    // count keeps the condition true.
    let condition = format!("{}true", "!".repeat(62));
    let lists = format!("{}{} != null", "[".repeat(98), "]".repeat(98));
    let calls = format!("{}true{}", "id(".repeat(98), ")".repeat(98));
    let rules = serde_json::json!({"rules": {"files": [{"name": "firestore.rules", "content": format!(
        "rules_version = '2';\nservice cloud.firestore {{\n  match /databases/{{database}}/documents {{\n    function id(x) {{ return x; }}\n    match /deep/{{id}} {{ allow get: if {condition}; }}\n    match /lists/{{id}} {{ allow get: if {lists}; }}\n    match /calls/{{id}} {{ allow get: if {calls}; }}\n  }}\n}}\n"
    )}]}})
    .to_string();
    let (status, body) = http(
        port,
        "PUT",
        "/emulator/v1/projects/demo-profile-deep:securityRules",
        Some(&rules),
    );
    assert_eq!(status, 200, "{body}");
    let (status, body) = http(
        port,
        "GET",
        "/v1/projects/demo-profile-deep/databases/(default)/documents/deep/d",
        None,
    );
    assert_eq!(status, 404, "the rule allows a missing document: {body}");
    for collection in ["lists", "calls"] {
        let (status, body) = http(
            port,
            "GET",
            &format!("/v1/projects/demo-profile-deep/databases/(default)/documents/{collection}/d"),
            None,
        );
        assert!(matches!(status, 403 | 404), "{collection}: {status} {body}");
    }
    daemon.stop();
}
