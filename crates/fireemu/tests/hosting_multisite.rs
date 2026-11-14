//! Multiple Firebase Hosting sites keep distinct content roots and local endpoints.

mod scratch;
use scratch::Scratch;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct OwnedChild(Child);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        self.0.stdin.take();
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if self.0.try_wait().ok().flatten().is_some() {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn get(address: &str) -> String {
    get_path(address, "/")
}

fn get_path(address: &str, path: &str) -> String {
    let mut stream = TcpStream::connect(address).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    response
}

#[test]
#[allow(clippy::too_many_lines)] // One end-to-end test verifies both listeners and shutdown cleanup.
fn hosting_array_resolves_targets_and_serves_each_site_on_its_own_endpoint() {
    let dir = Scratch::new("hosting", "multisite");
    std::fs::create_dir_all(dir.join("public-a")).unwrap();
    std::fs::create_dir_all(dir.join("public-b")).unwrap();
    std::fs::write(dir.join("public-a/index.html"), "site-a").unwrap();
    std::fs::write(dir.join("public-b/index.html"), "site-b").unwrap();
    std::fs::write(
        dir.join("firebase.json"),
        r#"{"hosting":[{"target":"web","public":"public-a"},{"site":"demo-hosting-web","public":"public-b"}],"emulators":{"hosting":{"port":0},"ui":{"enabled":false},"hub":{"port":0},"logging":{"port":0}}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join(".firebaserc"),
        r#"{"projects":{"default":"demo-hosting"},"targets":{"demo-hosting":{"hosting":{"web":["demo-hosting-web"]}}}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("fireemu.json"),
        r#"{"schemaVersion":1,"profile":"emulator"}"#,
    )
    .unwrap();
    let ready = dir.join("ready.json");
    let mut child = OwnedChild(
        Command::new(env!("CARGO_BIN_EXE_fireemu"))
            .args(["up", "--config"])
            .arg(dir.join("fireemu.json"))
            .args([
                "--only",
                "hosting",
                "--project",
                "default",
                "--firebase-json",
            ])
            .arg(dir.join("firebase.json"))
            .arg("--ready-file")
            .arg(&ready)
            .args([
                "--owner-stdin",
                "--log-verbosity",
                "quiet",
                "--hub-port",
                "auto",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(15);
    let descriptor = loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            let mut stderr = String::new();
            child
                .0
                .stderr
                .take()
                .unwrap()
                .read_to_string(&mut stderr)
                .unwrap();
            panic!("multisite Hosting failed to start ({status}): {stderr}");
        }
        if let Ok(bytes) = std::fs::read(&ready) {
            break serde_json::from_slice::<serde_json::Value>(&bytes).unwrap();
        }
        assert!(
            Instant::now() < deadline,
            "Hosting multisite readiness deadline"
        );
        std::thread::sleep(Duration::from_millis(20));
    };
    let sites = descriptor["hostingSites"]
        .as_array()
        .expect("all site URLs are advertised");
    assert_eq!(sites.len(), 2);
    let endpoints: Vec<_> = sites
        .iter()
        .map(|site| {
            site["url"]
                .as_str()
                .unwrap()
                .strip_prefix("http://")
                .unwrap()
                .trim_end_matches('/')
                .to_owned()
        })
        .collect();
    assert_ne!(endpoints[0], endpoints[1]);
    assert!(get(&endpoints[0]).ends_with("site-a"));
    assert!(get(&endpoints[1]).ends_with("site-b"));
    let hub = descriptor["environment"]["FIREBASE_EMULATOR_HUB"]
        .as_str()
        .unwrap();
    let discovery = get_path(hub, "/emulators");
    let reserved_port = endpoints[1].rsplit(':').next().unwrap();
    let discovery_body = discovery.split_once("\r\n\r\n").unwrap().1;
    let discovery: serde_json::Value = serde_json::from_str(discovery_body).unwrap();
    assert_eq!(
        discovery["hosting"]["reservedPorts"][0],
        reserved_port.parse::<u16>().unwrap()
    );
    drop(child);
    assert!(
        !ready.exists(),
        "shutdown withdraws the readiness descriptor"
    );
    assert!(
        TcpStream::connect(&endpoints[0]).is_err(),
        "first listener is released"
    );
    assert!(
        TcpStream::connect(&endpoints[1]).is_err(),
        "second listener is released"
    );
}

#[test]
fn site_target_validation_and_resolution_fail_before_any_listener_starts() {
    for (name, hosting, rc, expected_error) in [
        (
            "object-both",
            r#"{"site":"site-a","target":"web","public":"public"}"#,
            Some(r#"{"targets":{"demo-hosting":{"hosting":{"web":["site-a"]}}}}"#),
            "must specify either site or target, not both",
        ),
        (
            "empty-site",
            r#"{"site":"","public":"public"}"#,
            None,
            "hosting.site must be a string",
        ),
        (
            "empty-target",
            r#"{"target":"","public":"public"}"#,
            None,
            "hosting.target must be a string",
        ),
        (
            "target-no-rc",
            r#"{"target":"web","public":"public"}"#,
            None,
            "Deploy target web not configured for project demo-hosting",
        ),
        (
            "target-multi-match",
            r#"{"target":"web","public":"public"}"#,
            Some(r#"{"targets":{"demo-hosting":{"hosting":{"web":["site-a","site-b"]}}}}"#),
            "Hosting target web is linked to 2 sites; exactly one is required",
        ),
        (
            "target-empty-mapping",
            r#"{"target":"web","public":"public"}"#,
            Some(r#"{"targets":{"demo-hosting":{"hosting":{"web":[]}}}}"#),
            "Hosting target web is linked to 0 sites; exactly one is required",
        ),
    ] {
        let dir = Scratch::new("hosting", name);
        std::fs::create_dir_all(dir.join("public")).unwrap();
        std::fs::write(
            dir.join("firebase.json"),
            format!("{{\"hosting\":{hosting}}}"),
        )
        .unwrap();
        if let Some(rc) = rc {
            std::fs::write(dir.join(".firebaserc"), rc).unwrap();
        }
        std::fs::write(
            dir.join("fireemu.json"),
            r#"{"schemaVersion":1,"profile":"emulator"}"#,
        )
        .unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_fireemu"))
            .args([
                "up",
                "--plan",
                "--json",
                "--only",
                "hosting",
                "--project",
                "demo-hosting",
                "--firebase-json",
                "firebase.json",
                "--config",
                "fireemu.json",
            ])
            .current_dir(dir.to_path_buf())
            .output()
            .unwrap();
        assert!(
            !output.status.success(),
            "{name} unexpectedly started: {}",
            String::from_utf8_lossy(&output.stdout)
        );
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(expected_error),
            "{name} should report {expected_error:?}; stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn a_missing_target_is_not_resolved_when_hosting_is_excluded() {
    let dir = Scratch::new("hosting", "excluded-target");
    std::fs::create_dir_all(dir.join("public")).unwrap();
    std::fs::write(
        dir.join("firebase.json"),
        r#"{"hosting":{"target":"missing","public":"public"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join(".firebaserc"),
        r#"{"projects":{"default":"demo-hosting"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("fireemu.json"),
        r#"{"schemaVersion":1,"profile":"emulator"}"#,
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_fireemu"))
        .args([
            "up",
            "--plan",
            "--json",
            "--only",
            "auth",
            "--project",
            "default",
            "--firebase-json",
            "firebase.json",
            "--config",
            "fireemu.json",
        ])
        .current_dir(dir.to_path_buf())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn every_pict_hosting_selector_row_is_exercised_by_the_plan_parser() {
    let rows = include_str!("fixtures/hosting_multisite_pict.tsv");
    let mut lines = rows.lines();
    assert_eq!(lines.next(), Some("HostingForm\tSelector\tTargetMapping"));
    for (index, row) in lines.enumerate() {
        let fields: Vec<_> = row.split('\t').collect();
        assert_eq!(fields.len(), 3, "generated PICT row {}", index + 1);
        let [form, selector, mapping] = [fields[0], fields[1], fields[2]];
        let dir = Scratch::new("hosting", &format!("pict-{index}"));
        std::fs::create_dir_all(dir.join("public-a")).unwrap();
        std::fs::create_dir_all(dir.join("public-b")).unwrap();
        let selector_fields = match selector {
            "implicit" => String::new(),
            "site" => r#""site":"demo-hosting-site-a","#.to_owned(),
            "target" => r#""target":"web","#.to_owned(),
            other => panic!("unexpected generated selector {other}"),
        };
        let first = format!("{{{selector_fields}\"public\":\"public-a\"}}");
        let hosting = if form == "single" {
            serde_json::from_str::<serde_json::Value>(&first).unwrap()
        } else {
            serde_json::json!([serde_json::from_str::<serde_json::Value>(&first).unwrap(), {
                "site": "demo-hosting-site-b", "public": "public-b"
            }])
        };
        std::fs::write(
            dir.join("firebase.json"),
            serde_json::json!({"hosting":hosting,"emulators":{"hosting":{"port":0},"ui":{"enabled":false},"logging":{"port":0},"hub":{"port":0}}}).to_string(),
        )
        .unwrap();
        let rc = if mapping == "resolved" {
            r#"{"projects":{"default":"demo-hosting"},"targets":{"demo-hosting":{"hosting":{"web":["demo-hosting-web"]}}}}"#
        } else {
            r#"{"projects":{"default":"demo-hosting"}}"#
        };
        std::fs::write(dir.join(".firebaserc"), rc).unwrap();
        std::fs::write(
            dir.join("fireemu.json"),
            r#"{"schemaVersion":1,"profile":"emulator"}"#,
        )
        .unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_fireemu"))
            .args([
                "up",
                "--plan",
                "--json",
                "--only",
                "hosting",
                "--project",
                "default",
                "--firebase-json",
                "firebase.json",
                "--config",
                "fireemu.json",
            ])
            .current_dir(dir.to_path_buf())
            .output()
            .unwrap();
        let should_start = selector != "target" || mapping == "resolved";
        assert_eq!(
            output.status.success(),
            should_start,
            "PICT row {row}; stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        if should_start {
            let plan: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
            let hosting = plan["services"]
                .as_array()
                .unwrap()
                .iter()
                .find(|service| service["name"] == "hosting")
                .unwrap();
            assert_eq!(hosting["start"], true, "PICT row {row}");
        }
    }
}
