//! Post-pressure recovery harness (REV-14): baseline, saturate, release, reuse.
//!
//! Speed is not what this measures. Each phase samples what the daemon retains -- the logical
//! Firestore charge and version count from the resource diagnostics, the process RSS, its
//! open file descriptors and child processes -- and the verdict asks whether a release really
//! gave the capacity back and whether the freed capacity can be used again. Logical retention
//! is the primary assertion; RSS is recorded but never asserted, because an allocator cache
//! keeps it high after the logical charge is gone. A measurement that fails is recorded as
//! missing with its reason, never as zero.
//!
//! The default run is a small smoke dataset; `FIREEMU_RECOVERY_LONG=1` runs the large one.
//! Every run writes a JSON artifact (`FIREEMU_RECOVERY_REPORT` or the target tmpdir) naming
//! the commit, machine, toolchain, build profile, dataset, run id and cleanup result.

mod census;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

// ---------------------------------------------------------------------------------------
// Pure report model: samples, phases, verdict.
// ---------------------------------------------------------------------------------------

/// One measurement; `None` means the measurement failed and `errors` says why.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct Sample {
    logical_bytes: Option<u64>,
    versions: Option<u64>,
    live_document_bytes: Option<u64>,
    snapshot_bytes: Option<u64>,
    sessions: Option<u64>,
    rss_kib: Option<u64>,
    open_fds: Option<u64>,
    children: Option<u64>,
    errors: Vec<String>,
}

#[derive(Debug, Clone)]
struct Phase {
    name: &'static str,
    accepted_changes: u64,
    refused_changes: u64,
    wall_ms: u128,
    sample: Sample,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Verdict {
    recovered: bool,
    reusable: bool,
    /// Gauges whose value after release exceeded the baseline (`gauge: baseline -> released`).
    leaks: Vec<String>,
    /// Measurements that were missing in some phase.
    missing: Vec<String>,
}

fn phase<'a>(phases: &'a [Phase], name: &str) -> Option<&'a Phase> {
    phases.iter().find(|p| p.name == name)
}

/// The verdict over the four phases. Logical gauges must return to the baseline after the
/// release; the reuse phase must have accepted its writes and charged the store again. A
/// missing measurement is reported, and a missing logical measurement fails recovery
/// because absence of data is not evidence of release.
fn evaluate(phases: &[Phase]) -> Verdict {
    let mut leaks = Vec::new();
    let mut missing = Vec::new();
    let (Some(baseline), Some(released), Some(reused)) = (
        phase(phases, "baseline"),
        phase(phases, "release"),
        phase(phases, "reuse"),
    ) else {
        return Verdict {
            recovered: false,
            reusable: false,
            leaks,
            missing: vec!["a phase is missing".to_owned()],
        };
    };
    for p in phases {
        for error in &p.sample.errors {
            missing.push(format!("{}: {error}", p.name));
        }
    }
    let mut compare = |gauge: &str, before: Option<u64>, after: Option<u64>| match (before, after) {
        (Some(before), Some(after)) => {
            if after > before {
                leaks.push(format!("{gauge}: {before} -> {after}"));
            }
            true
        }
        _ => false,
    };
    let mut measured = true;
    measured &= compare(
        "history.session_bytes",
        baseline.sample.logical_bytes,
        released.sample.logical_bytes,
    );
    measured &= compare(
        "history.session_versions",
        baseline.sample.versions,
        released.sample.versions,
    );
    measured &= compare(
        "history.live_document_bytes",
        baseline.sample.live_document_bytes,
        released.sample.live_document_bytes,
    );
    measured &= compare(
        "snapshots.retained_bytes",
        baseline.sample.snapshot_bytes,
        released.sample.snapshot_bytes,
    );
    measured &= compare(
        "sessions",
        baseline.sample.sessions,
        released.sample.sessions,
    );
    let recovered = measured && leaks.is_empty();
    let reusable = reused.refused_changes == 0
        && reused.accepted_changes > 0
        && matches!(
            (reused.sample.logical_bytes, released.sample.logical_bytes),
            (Some(after), Some(before)) if after > before
        );
    Verdict {
        recovered,
        reusable,
        leaks,
        missing,
    }
}

fn sample_json(sample: &Sample) -> Value {
    json!({
        "logicalBytes": sample.logical_bytes,
        "versions": sample.versions,
        "liveDocumentBytes": sample.live_document_bytes,
        "snapshotBytes": sample.snapshot_bytes,
        "sessions": sample.sessions,
        "rssKiB": sample.rss_kib,
        "openFds": sample.open_fds,
        "children": sample.children,
        "errors": sample.errors,
    })
}

fn report_json(
    run_id: &str,
    dataset: &Dataset,
    phases: &[Phase],
    verdict: &Verdict,
    cleanup: &str,
) -> Value {
    let git = |args: &[&str]| {
        Command::new("git")
            .args(args)
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
    };
    let rustc = Command::new("rustc")
        .arg("--version")
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned());
    json!({
        "schemaVersion": 1,
        "kind": "post-pressure-recovery",
        "runId": run_id,
        "commit": git(&["rev-parse", "HEAD"]),
        "dirty": git(&["status", "--porcelain"]).map(|s| !s.is_empty()),
        "machine": {"os": std::env::consts::OS, "arch": std::env::consts::ARCH},
        "toolchain": rustc,
        "profile": if cfg!(debug_assertions) { "debug" } else { "release" },
        "dataset": {"documents": dataset.documents, "payloadBytes": dataset.payload_bytes, "sessions": dataset.sessions, "long": dataset.long},
        "phases": phases.iter().map(|p| json!({
            "name": p.name,
            "acceptedChanges": p.accepted_changes,
            "refusedChanges": p.refused_changes,
            "wallMs": p.wall_ms,
            "sample": sample_json(&p.sample),
        })).collect::<Vec<_>>(),
        "verdict": {
            "recovered": verdict.recovered,
            "reusable": verdict.reusable,
            "leaks": verdict.leaks,
            "missing": verdict.missing,
        },
        "cleanup": cleanup,
    })
}

// ---------------------------------------------------------------------------------------
// Driving a real daemon.
// ---------------------------------------------------------------------------------------

struct Dataset {
    documents: usize,
    payload_bytes: usize,
    sessions: usize,
    long: bool,
}

impl Dataset {
    fn from_env() -> Self {
        if std::env::var("FIREEMU_RECOVERY_LONG").is_ok_and(|v| v == "1") {
            Self {
                documents: 4000,
                payload_bytes: 64 * 1024,
                sessions: 50,
                long: true,
            }
        } else {
            Self {
                documents: 120,
                payload_bytes: 4 * 1024,
                sessions: 8,
                long: false,
            }
        }
    }
}

fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

struct Daemon {
    child: Child,
    control: u16,
    firestore: u16,
    _banner: BufReader<std::process::ChildStdout>,
}

impl Daemon {
    fn start() -> Self {
        let firestore = free_port();
        let mut child = Command::new(env!("CARGO_BIN_EXE_fireemu"))
            .args([
                "up",
                "--project",
                "demo-recovery",
                "--only",
                "auth,firestore",
                "--firestore-port",
                &firestore.to_string(),
                "--http-port",
                "0",
                "--storage-port",
                "0",
                "--functions-port",
                "0",
                "--pubsub-port",
                "0",
                "--ui-port",
                "0",
                "--logging-port",
                "0",
                "--hub-port",
                "0",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("the daemon binary starts");
        let mut reader = BufReader::new(child.stdout.take().expect("stdout is piped"));
        let mut control = None;
        let mut banner = String::new();
        for _ in 0..60 {
            let mut line = String::new();
            if reader.read_line(&mut line).unwrap_or(0) == 0 {
                break;
            }
            banner.push_str(&line);
            if line.trim_start().starts_with("control API:") {
                control = line
                    .split("http://127.0.0.1:")
                    .nth(1)
                    .and_then(|rest| rest.split(|c: char| !c.is_ascii_digit()).next())
                    .and_then(|digits| digits.parse::<u16>().ok());
                break;
            }
        }
        let Some(control) = control else {
            let _ = child.kill();
            let _ = child.wait();
            panic!("the daemon printed no control API line:\n{banner}");
        };
        Self {
            child,
            control,
            firestore,
            _banner: reader,
        }
    }

    fn pid(&self) -> i32 {
        i32::try_from(self.child.id()).expect("pid fits i32")
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn http(port: u16, method: &str, path: &str, body: Option<&str>) -> Result<(u16, Value), String> {
    let mut stream =
        TcpStream::connect(("127.0.0.1", port)).map_err(|e| format!("connect {port}: {e}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(120)))
        .map_err(|e| e.to_string())?;
    let body = body.unwrap_or("");
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer owner\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .map_err(|e| e.to_string())?;
    let mut raw = String::new();
    stream.read_to_string(&mut raw).map_err(|e| e.to_string())?;
    let (head, body) = raw
        .split_once("\r\n\r\n")
        .ok_or_else(|| "no header block".to_owned())?;
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| format!("no status line in {head:?}"))?;
    let value = if body.trim().is_empty() {
        Value::Null
    } else {
        serde_json::from_str(body.trim()).unwrap_or_else(|_| Value::String(body.to_owned()))
    };
    Ok((status, value))
}

fn gauge(report: &Value, service: &str, id: &str) -> Result<u64, String> {
    report["services"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|s| s["service"] == service)
        .and_then(|s| s["gauges"].as_array())
        .into_iter()
        .flatten()
        .find(|g| g["id"] == id)
        .and_then(|g| g["current"].as_u64())
        .ok_or_else(|| format!("{service}.{id} is not in the resource report"))
}

fn measure(daemon: &Daemon) -> Sample {
    let mut sample = Sample::default();
    match http(
        daemon.control,
        "GET",
        "/v1/sessions/default/resources",
        None,
    ) {
        Ok((200, report)) => {
            for (slot, id) in [
                (&mut sample.logical_bytes, "history.session_bytes"),
                (&mut sample.versions, "history.session_versions"),
                (
                    &mut sample.live_document_bytes,
                    "history.live_document_bytes",
                ),
            ] {
                match gauge(&report, "firestore", id) {
                    Ok(value) => *slot = Some(value),
                    Err(error) => sample.errors.push(error),
                }
            }
            match gauge(&report, "snapshots", "snapshots.retained_bytes") {
                Ok(value) => sample.snapshot_bytes = Some(value),
                Err(error) => sample.errors.push(error),
            }
        }
        Ok((status, body)) => sample
            .errors
            .push(format!("resources: HTTP {status} {body}")),
        Err(error) => sample.errors.push(format!("resources: {error}")),
    }
    match http(daemon.control, "GET", "/v1/sessions", None) {
        Ok((200, body)) => {
            sample.sessions = body["sessions"].as_array().map(|s| s.len() as u64);
        }
        Ok((status, body)) => sample
            .errors
            .push(format!("sessions: HTTP {status} {body}")),
        Err(error) => sample.errors.push(format!("sessions: {error}")),
    }
    let pid = daemon.pid();
    match Command::new("ps")
        .args(["-o", "rss=", "-p", &pid.to_string()])
        .output()
    {
        Ok(out) if out.status.success() => {
            sample.rss_kib = String::from_utf8_lossy(&out.stdout).trim().parse().ok();
            if sample.rss_kib.is_none() {
                sample.errors.push("rss: ps printed no number".to_owned());
            }
        }
        Ok(out) => sample
            .errors
            .push(format!("rss: ps exited with {}", out.status)),
        Err(error) => sample.errors.push(format!("rss: {error}")),
    }
    match Command::new("lsof")
        .args(["-p", &pid.to_string()])
        .stderr(Stdio::null())
        .output()
    {
        Ok(out) if out.status.success() => {
            let lines = String::from_utf8_lossy(&out.stdout).lines().count();
            sample.open_fds = Some(lines.saturating_sub(1) as u64);
        }
        Ok(out) => sample
            .errors
            .push(format!("fds: lsof exited with {}", out.status)),
        Err(error) => sample.errors.push(format!("fds: {error}")),
    }
    sample.children = Some(census::descendants_of(pid).len() as u64);
    sample
}

/// Commits `documents` writes of `payload_bytes` each in batches of 100; returns
/// `(accepted, refused)` document changes.
fn saturate(daemon: &Daemon, dataset: &Dataset, generation: usize) -> (u64, u64) {
    let payload = "x".repeat(dataset.payload_bytes);
    let mut accepted = 0u64;
    let mut refused = 0u64;
    for chunk in (0..dataset.documents).collect::<Vec<_>>().chunks(100) {
        let writes: Vec<Value> = chunk
            .iter()
            .map(|index| {
                json!({"update": {
                    "name": format!("projects/demo-recovery/databases/(default)/documents/pressure-{generation}/{index:05}"),
                    "fields": {"payload": {"stringValue": payload}}
                }})
            })
            .collect();
        let body = json!({"writes": writes}).to_string();
        match http(
            daemon.firestore,
            "POST",
            "/v1/projects/demo-recovery/databases/(default)/documents:commit",
            Some(&body),
        ) {
            Ok((200, _)) => accepted += chunk.len() as u64,
            _ => refused += chunk.len() as u64,
        }
    }
    (accepted, refused)
}

fn session_churn(daemon: &Daemon, dataset: &Dataset) -> (u64, u64) {
    let mut accepted = 0u64;
    let mut refused = 0u64;
    for index in 0..dataset.sessions {
        let name = format!("churn-{index}");
        let body = json!({"name": name, "project": format!("demo-churn-{index}")}).to_string();
        let created = matches!(
            http(daemon.control, "POST", "/v1/sessions", Some(&body)),
            Ok((200, _))
        );
        let deleted = created
            && matches!(
                http(
                    daemon.control,
                    "DELETE",
                    &format!("/v1/sessions/{name}"),
                    None
                ),
                Ok((200, _))
            );
        if deleted {
            accepted += 1;
        } else {
            refused += 1;
        }
    }
    (accepted, refused)
}

fn timed(name: &'static str, daemon: &Daemon, work: impl FnOnce() -> (u64, u64)) -> Phase {
    let started = Instant::now();
    let (accepted_changes, refused_changes) = work();
    let wall_ms = started.elapsed().as_millis();
    Phase {
        name,
        accepted_changes,
        refused_changes,
        wall_ms,
        sample: measure(daemon),
    }
}

fn report_path(run_id: &str) -> std::path::PathBuf {
    std::env::var_os("FIREEMU_RECOVERY_REPORT").map_or_else(
        || {
            std::path::Path::new(env!("CARGO_TARGET_TMPDIR"))
                .join("recovery")
                .join(format!("{run_id}.json"))
        },
        std::path::PathBuf::from,
    )
}

fn run_id() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("{now}-{}", std::process::id())
}

// ---------------------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------------------

fn sample(logical: u64, versions: u64, snapshots: u64, sessions: u64) -> Sample {
    Sample {
        logical_bytes: Some(logical),
        versions: Some(versions),
        live_document_bytes: Some(logical / 2),
        snapshot_bytes: Some(snapshots),
        sessions: Some(sessions),
        rss_kib: Some(100_000),
        open_fds: Some(40),
        children: Some(0),
        errors: Vec::new(),
    }
}

fn phases(baseline: Sample, saturated: Sample, released: Sample, reused: Sample) -> Vec<Phase> {
    let make = |name, accepted, refused, sample| Phase {
        name,
        accepted_changes: accepted,
        refused_changes: refused,
        wall_ms: 1,
        sample,
    };
    vec![
        make("baseline", 0, 0, baseline),
        make("saturate", 100, 0, saturated),
        make("release", 0, 0, released),
        make("reuse", 100, 0, reused),
    ]
}

#[test]
fn the_verdict_detects_a_deliberate_leak_and_accepts_a_real_release() {
    let clean = phases(
        sample(1_000, 2, 0, 1),
        sample(900_000, 102, 0, 1),
        sample(1_000, 2, 0, 1),
        sample(900_000, 102, 0, 1),
    );
    assert_eq!(
        evaluate(&clean),
        Verdict {
            recovered: true,
            reusable: true,
            leaks: vec![],
            missing: vec![]
        }
    );

    // A retained snapshot after the release is a leak the verdict names.
    let leaky = phases(
        sample(1_000, 2, 0, 1),
        sample(900_000, 102, 0, 1),
        sample(1_000, 2, 450_000, 1),
        sample(900_000, 102, 450_000, 1),
    );
    let verdict = evaluate(&leaky);
    assert!(!verdict.recovered);
    assert_eq!(
        verdict.leaks,
        vec!["snapshots.retained_bytes: 0 -> 450000".to_owned()]
    );

    // History that did not go back to the baseline is a leak too, and a leaked session.
    let unreleased = phases(
        sample(1_000, 2, 0, 1),
        sample(900_000, 102, 0, 1),
        sample(500_000, 52, 0, 3),
        sample(900_000, 102, 0, 3),
    );
    let verdict = evaluate(&unreleased);
    assert!(!verdict.recovered);
    assert_eq!(verdict.leaks.len(), 4, "{:?}", verdict.leaks);

    // Reuse must charge the store again and be fully accepted; RSS staying high is not a leak.
    let mut refused = clean.clone();
    refused[3].refused_changes = 7;
    assert!(!evaluate(&refused).reusable);
    let mut unused = clean.clone();
    unused[3].sample.logical_bytes = Some(1_000);
    assert!(!evaluate(&unused).reusable);
    let mut cached_rss = clean.clone();
    cached_rss[2].sample.rss_kib = Some(900_000);
    assert!(evaluate(&cached_rss).recovered);
}

#[test]
fn a_missing_measurement_is_reported_and_never_counts_as_a_release() {
    let mut phases = phases(
        sample(1_000, 2, 0, 1),
        sample(900_000, 102, 0, 1),
        sample(1_000, 2, 0, 1),
        sample(900_000, 102, 0, 1),
    );
    phases[2].sample.logical_bytes = None;
    phases[2]
        .sample
        .errors
        .push("resources: connect refused".to_owned());
    let verdict = evaluate(&phases);
    assert!(!verdict.recovered, "{verdict:?}");
    assert_eq!(
        verdict.missing,
        vec!["release: resources: connect refused".to_owned()]
    );
    assert!(verdict.leaks.is_empty());
    let json = report_json(
        "test",
        &Dataset {
            documents: 1,
            payload_bytes: 1,
            sessions: 0,
            long: false,
        },
        &phases,
        &verdict,
        "not run",
    );
    assert_eq!(json["phases"][2]["sample"]["logicalBytes"], Value::Null);
    assert_eq!(json["verdict"]["recovered"], false);
    assert_eq!(json["kind"], "post-pressure-recovery");
    assert!(json["commit"].is_string());
    assert!(json["toolchain"].is_string());
    assert!(json["machine"]["os"].is_string());
    assert_eq!(
        evaluate(&phases[..2]).missing,
        vec!["a phase is missing".to_owned()]
    );
}

#[test]
fn a_real_daemon_releases_history_on_reset_and_admits_the_same_load_again() {
    let dataset = Dataset::from_env();
    let run_id = run_id();
    let daemon = Daemon::start();
    let pid = daemon.pid();
    let mut phases = Vec::new();
    phases.push(timed("baseline", &daemon, || (0, 0)));
    phases.push(timed("saturate", &daemon, || {
        saturate(&daemon, &dataset, 1)
    }));
    // A snapshot deliberately retained across the release: the verdict must see it.
    assert_eq!(
        http(
            daemon.control,
            "POST",
            "/v1/sessions/default/snapshots",
            Some(r#"{"name": "held"}"#)
        )
        .expect("snapshot")
        .0,
        200
    );
    let leaky_release = timed("release", &daemon, || {
        let (a, r) = session_churn(&daemon, &dataset);
        let reset = http(
            daemon.control,
            "POST",
            "/v1/sessions/default/reset",
            Some("{}"),
        );
        (a, r + u64::from(!matches!(reset, Ok((200, _)))))
    });
    let mut leaky = phases.clone();
    leaky.push(leaky_release.clone());
    leaky.push(timed("reuse", &daemon, || saturate(&daemon, &dataset, 2)));
    let detected = evaluate(&leaky);
    assert!(
        !detected.recovered,
        "the held snapshot must be reported as a leak: {detected:?}"
    );
    assert!(
        detected
            .leaks
            .iter()
            .any(|l| l.starts_with("snapshots.retained_bytes")),
        "{detected:?}"
    );

    // Now the honest run: drop the snapshot, release, and reuse.
    assert_eq!(
        http(
            daemon.control,
            "DELETE",
            "/v1/sessions/default/snapshots/held",
            None
        )
        .expect("delete snapshot")
        .0,
        200
    );
    phases.push(timed("release", &daemon, || {
        let reset = http(
            daemon.control,
            "POST",
            "/v1/sessions/default/reset",
            Some("{}"),
        );
        (0, u64::from(!matches!(reset, Ok((200, _)))))
    }));
    phases.push(timed("reuse", &daemon, || saturate(&daemon, &dataset, 3)));
    let verdict = evaluate(&phases);

    drop(daemon);
    let survivors = census::wait_for_no_descendants(pid, Duration::from_secs(10));
    let cleanup = if survivors.is_empty() {
        "daemon exited; no descendant survived".to_owned()
    } else {
        format!("survivors:\n{}", census::table(&survivors))
    };
    let report = report_json(&run_id, &dataset, &phases, &verdict, &cleanup);
    let path = report_path(&run_id);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, serde_json::to_string_pretty(&report).unwrap()).unwrap();
    eprintln!("recovery report: {}", path.display());

    assert!(survivors.is_empty(), "{cleanup}");
    assert!(verdict.missing.is_empty(), "{verdict:?}");
    assert!(verdict.recovered, "{verdict:?}\n{report}");
    assert!(verdict.reusable, "{verdict:?}\n{report}");
    let saturated = phase(&phases, "saturate").unwrap();
    assert_eq!(saturated.refused_changes, 0, "{saturated:?}");
    assert!(
        saturated.sample.logical_bytes > phase(&phases, "baseline").unwrap().sample.logical_bytes,
        "the load charged the store: {saturated:?}"
    );
    census::assert_no_owned_descendants("the recovery daemon", Duration::from_secs(10));
}
