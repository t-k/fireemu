//! Hosting starts through the shipped CLI and consumes the shared HTTP fixture corpus.

mod scratch;
use scratch::Scratch;
use std::fmt::Write as _;
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

fn site_fixture(fixture: &std::path::Path, name: &str) -> (Scratch, serde_json::Value) {
    let dir = Scratch::new("hosting", name);
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(fixture.join("manifest.json")).unwrap()).unwrap();
    for name in manifest["files"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(serde_json::Value::as_str)
        .filter(|name| name.starts_with("public/"))
    {
        let destination = dir.join(name);
        std::fs::create_dir_all(destination.parent().unwrap()).unwrap();
        std::fs::copy(fixture.join(name), destination).unwrap();
    }
    let security: serde_json::Value =
        serde_json::from_slice(&std::fs::read(fixture.join("security.json")).unwrap()).unwrap();
    let sentinel = security["outsideSentinel"].as_str().unwrap();
    std::fs::write(dir.join("outside.txt"), sentinel).unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink("../outside.txt", dir.join("public/outside-link.txt")).unwrap();
    #[cfg(windows)]
    std::os::windows::fs::symlink_file("../outside.txt", dir.join("public/outside-link.txt"))
        .expect("Windows symlink test requires symbolic-link support");
    (dir, security)
}

fn request(address: &str, target: &str) -> String {
    let mut stream = TcpStream::connect(address).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    write!(
        stream,
        "GET {target} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut reply = String::new();
    stream.read_to_string(&mut reply).unwrap();
    reply
}

#[test]
#[allow(clippy::too_many_lines)] // one CLI round trip: serve, probe, shut down, withdraw readiness
fn hosting_cli_serves_shared_fixture_and_withdraws_readiness_on_shutdown() {
    let fixture =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../conformance/hosting-fixtures");
    let corpus: serde_json::Value =
        serde_json::from_slice(&std::fs::read(fixture.join("cases.json")).unwrap()).unwrap();
    let (dir, security) = site_fixture(&fixture, "cli");
    let sentinel = security["outsideSentinel"].as_str().unwrap();
    let mut hosting = corpus["configs"]["default"].clone();
    hosting["public"] = dir.join("public").to_string_lossy().to_string().into();
    let firebase = serde_json::json!({"hosting":hosting,"emulators":{"hosting":{"port":0},"ui":{"enabled":false},"logging":{"port":0},"hub":{"port":0}}});
    std::fs::write(dir.join("firebase.json"), firebase.to_string()).unwrap();
    std::fs::write(dir.join("fireemu.json"), emulator_profile().to_string()).unwrap();
    let ready = dir.join("ready.json");
    let mut child = OwnedChild(
        Command::new(env!("CARGO_BIN_EXE_fireemu"))
            .args(["up", "--config"])
            .arg(dir.join("fireemu.json"))
            .args([
                "--only",
                "hosting",
                "--project",
                "demo-hosting",
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
            panic!("Hosting must start through --only hosting; {status}: {stderr}");
        }
        if let Ok(bytes) = std::fs::read(&ready) {
            break serde_json::from_slice::<serde_json::Value>(&bytes).unwrap();
        }
        assert!(Instant::now() < deadline, "Hosting readiness deadline");
        std::thread::sleep(Duration::from_millis(20));
    };
    let address = descriptor["hostingUrl"]
        .as_str()
        .unwrap()
        .strip_prefix("http://")
        .unwrap()
        .trim_end_matches('/');
    let hub = descriptor["environment"]["FIREBASE_EMULATOR_HUB"]
        .as_str()
        .unwrap();
    let discovery = request(hub, "/emulators");
    assert!(
        discovery.contains("\"hosting\"")
            && discovery.contains(address.rsplit(':').next().unwrap()),
        "{discovery}"
    );
    let case = corpus["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["id"] == "static")
        .unwrap();
    let reply = request(address, case["path"].as_str().unwrap());
    assert!(reply.starts_with("HTTP/1.1 200"), "{reply}");
    assert!(
        reply.ends_with(&std::fs::read_to_string(fixture.join("public/data.json")).unwrap()),
        "{reply}"
    );
    for case in security["cases"].as_array().unwrap() {
        let reply = request(address, case["path"].as_str().unwrap());
        assert!(
            !reply.contains(sentinel),
            "outside marker leaked for {}",
            case["id"]
        );
    }
    drop(child);
    assert!(
        !ready.exists(),
        "shutdown withdraws the owned readiness descriptor"
    );
    assert!(
        TcpStream::connect(address).is_err(),
        "shutdown releases the Hosting listener"
    );
}

#[test]
fn failed_hosting_startup_never_publishes_readiness() {
    let fixture =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../conformance/hosting-fixtures");
    let corpus: serde_json::Value =
        serde_json::from_slice(&std::fs::read(fixture.join("cases.json")).unwrap()).unwrap();
    let dir = Scratch::new("hosting", "failed-start");
    // A configured port is fixed, so an occupied one fails startup before readiness.
    let reservation = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let mut hosting = corpus["configs"]["default"].clone();
    hosting["public"] = fixture.join("public").to_string_lossy().to_string().into();
    let port = reservation.local_addr().unwrap().port();
    let firebase = serde_json::json!({"hosting":hosting,"emulators":{"hosting":{"port":port},"ui":{"enabled":false},"hub":{"port":0},"logging":{"port":0}}});
    std::fs::write(dir.join("firebase.json"), firebase.to_string()).unwrap();
    let ready = dir.join("ready.json");
    let output = Command::new(env!("CARGO_BIN_EXE_fireemu"))
        .args(["up", "--only", "hosting", "--firebase-json"])
        .arg(dir.join("firebase.json"))
        .arg("--ready-file")
        .arg(&ready)
        .args(["--owner-stdin", "--log-verbosity", "quiet"])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(!output.status.success(), "startup must fail");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("bind"), "{stderr}");
    assert!(
        !ready.exists(),
        "failed startup cannot publish a ready endpoint"
    );
}

/// The emulator profile, which answers as the pinned local oracle: the fixture tests below compare
/// with it. The strict profile answers as Hosting production (`hosting_strict.rs`).
fn emulator_profile() -> serde_json::Value {
    serde_json::json!({"schemaVersion": 1, "profile": "emulator"})
}

fn start(dir: &std::path::Path, firebase: &serde_json::Value, only: &str) -> (OwnedChild, String) {
    start_with_config(dir, firebase, only, Some(&emulator_profile()))
}

/// The profiles the path-confinement tests run under: the default (strict) one, which a user gets
/// without any configuration, and the emulator profile.
const PROFILES: [Option<&str>; 2] = [None, Some("emulator")];

/// [`start`] under `profile`: `None` is the default profile (no configuration at all).
fn start_under(
    profile: Option<&str>,
    dir: &std::path::Path,
    firebase: &serde_json::Value,
    only: &str,
) -> (OwnedChild, String) {
    match profile {
        None => start_with_config(dir, firebase, only, None),
        Some(name) => start_with_config(
            dir,
            firebase,
            only,
            Some(&serde_json::json!({"schemaVersion": 1, "profile": name})),
        ),
    }
}

/// [`start`] with a canonical fireemu configuration document.
fn start_with_config(
    dir: &std::path::Path,
    firebase: &serde_json::Value,
    only: &str,
    config: Option<&serde_json::Value>,
) -> (OwnedChild, String) {
    let (child, descriptor) = start_descriptor(dir, firebase, only, config, &[]);
    let address = descriptor["hostingUrl"]
        .as_str()
        .map(|url| {
            url.trim_start_matches("http://")
                .trim_end_matches('/')
                .to_owned()
        })
        .unwrap_or_default();
    (child, address)
}

/// Starts the daemon and returns it with the readiness descriptor it published.
fn start_descriptor(
    dir: &std::path::Path,
    firebase: &serde_json::Value,
    only: &str,
    config: Option<&serde_json::Value>,
    extra_args: &[&str],
) -> (OwnedChild, serde_json::Value) {
    std::fs::write(dir.join("firebase.json"), firebase.to_string()).unwrap();
    let ready = dir.join("ready.json");
    let mut command = Command::new(env!("CARGO_BIN_EXE_fireemu"));
    command.arg("up");
    if let Some(config) = config {
        std::fs::write(dir.join("fireemu.json"), config.to_string()).unwrap();
        command.arg("--config").arg(dir.join("fireemu.json"));
    }
    let mut child = OwnedChild(
        command
            .args([
                "--only",
                only,
                "--project",
                "demo-hosting",
                "--firebase-json",
            ])
            .arg(dir.join("firebase.json"))
            .arg("--ready-file")
            .arg(&ready)
            .args(["--owner-stdin", "--log-verbosity", "quiet"])
            .args(extra_args)
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
            panic!("startup failed; {status}: {stderr}");
        }
        if let Ok(bytes) = std::fs::read(&ready) {
            break serde_json::from_slice::<serde_json::Value>(&bytes).unwrap();
        }
        assert!(Instant::now() < deadline, "readiness deadline");
        std::thread::sleep(Duration::from_millis(20));
    };
    (child, descriptor)
}

fn emulators() -> serde_json::Value {
    serde_json::json!({"hosting":{"port":0},"ui":{"enabled":false},"hub":{"port":0},"logging":{"port":0}})
}

#[test]
fn hosting_ignored_assets_are_absent_from_every_route() {
    for profile in PROFILES {
        ignored_assets_are_absent_from_every_route(profile);
    }
}

fn ignored_assets_are_absent_from_every_route(profile: Option<&str>) {
    let dir = Scratch::new("hosting", "ignored-assets");
    for (path, contents) in [
        ("public/private.json", "private"),
        ("public/clean.html", "clean"),
        ("public/folder/index.html", "index"),
        ("public/locales/en/page.html", "localized"),
        ("public/page.html", "ordinary"),
        ("public/rewrite.html", "rewrite"),
        ("public/404.html", "custom404"),
        ("public/firebase-debug.log", "debug"),
        ("public/logs/firebase-debug.1.log", "debug"),
        ("public/.firebase/cache", "cache"),
    ] {
        let file = dir.join(path);
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(file, contents).unwrap();
    }
    #[cfg(unix)]
    std::os::unix::fs::symlink("private.json", dir.join("public/alias.json")).unwrap();
    let firebase = serde_json::json!({"hosting":{
        "public":dir.join("public"), "cleanUrls":true,
        "i18n":{"root":"locales"},
        "ignore":["private.json", "clean.html", "folder/index.html", "locales/en/page.html", "rewrite.html", "404.html"],
        "rewrites":[{"source":"/rewritten", "destination":"/rewrite.html"}]
    },"emulators":emulators()});
    let (_child, address) = start_under(profile, &dir, &firebase, "hosting");
    let mut failures = Vec::new();
    for path in [
        "/private.json",
        "/clean",
        "/folder/",
        "/rewritten",
        "/missing",
        "/firebase-debug.log",
        "/logs/firebase-debug.1.log",
        "/.firebase/cache",
    ] {
        let reply = request(&address, path);
        if !reply.starts_with("HTTP/1.1 404") || reply.contains("custom404") {
            failures.push(format!("{path}: {reply}"));
        }
    }
    #[cfg(unix)]
    {
        let reply = request(&address, "/alias.json");
        if !reply.starts_with("HTTP/1.1 404") {
            failures.push(format!("alias: {reply}"));
        }
    }
    let mut stream = TcpStream::connect(&address).unwrap();
    write!(
        stream,
        "GET /page HTTP/1.1\r\nHost: {address}\r\nAccept-Language: en\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut reply = String::new();
    stream.read_to_string(&mut reply).unwrap();
    if !reply.ends_with("ordinary") {
        failures.push(format!("i18n: {reply}"));
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

// Review 2026-11-07 P2 and Should: reserved initialization URLs precede a catch-all redirect,
// and the shared configuration carries a nonsecret local API key.
#[test]
fn reserved_routes_precede_a_catch_all_redirect() {
    let dir = Scratch::new("hosting", "reserved");
    std::fs::create_dir(dir.join("public")).unwrap();
    std::fs::write(dir.join("public/index.html"), "index").unwrap();
    let firebase = serde_json::json!({"hosting":{"public":dir.join("public"),"redirects":[{"source":"**","destination":"/maintenance","type":302}]},"emulators":emulators()});
    let (_child, address) = start(&dir, &firebase, "hosting");
    let init = request(&address, "/__/firebase/init.json");
    assert!(init.starts_with("HTTP/1.1 200"), "{init}");
    assert!(init.contains("\"apiKey\":\"fireemu-local-only\""), "{init}");
    assert!(init.contains("\"projectId\":\"demo-hosting\""), "{init}");
    let script = request(&address, "/__/firebase/init.js?useEmulator=true");
    assert!(script.starts_with("HTTP/1.1 200"), "{script}");
    assert!(script.contains("initializeApp"), "{script}");
    let ordinary = request(&address, "/ordinary");
    assert!(ordinary.starts_with("HTTP/1.1 302"), "{ordinary}");
    assert!(
        ordinary
            .to_ascii_lowercase()
            .contains("location: /maintenance\r\n"),
        "{ordinary}"
    );
}

// firebase-tools 15.28.2 only logs a missing public directory at debug level and starts.
#[test]
fn a_missing_public_directory_starts_and_answers_not_found() {
    let dir = Scratch::new("hosting", "missing-public");
    let firebase = serde_json::json!({"hosting":{"public":dir.join("missing-public")},"emulators":emulators()});
    let (_child, address) = start(&dir, &firebase, "hosting");
    let page = request(&address, "/index.html");
    assert!(page.starts_with("HTTP/1.1 404"), "{page}");
    let init = request(&address, "/__/firebase/init.json");
    assert!(init.starts_with("HTTP/1.1 200"), "{init}");
}

// Review 2026-11-07 P2: an unselected Hosting entry never blocks an Auth-only run, and a run
// that names no service keeps starting when its Hosting configuration is unsupported.
#[test]
fn unselected_or_unsupported_hosting_never_blocks_startup() {
    let dir = Scratch::new("hosting", "excluded");
    let mut emulators = emulators();
    emulators["hosting"]["host"] = "0.0.0.0".into();
    emulators["auth"] = serde_json::json!({"port":0});
    let firebase = serde_json::json!({"hosting":{"public":"public"},"emulators":emulators});
    let (_child, address) = start(&dir, &firebase, "auth");
    assert!(address.is_empty(), "Hosting must not start: {address}");
}

fn header(reply: &str, name: &str) -> Option<String> {
    reply
        .split("\r\n\r\n")
        .next()
        .unwrap()
        .lines()
        .skip(1)
        .find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.eq_ignore_ascii_case(name)
                .then(|| value.trim().to_owned())
        })
}

// Review 2026-11-08 Should: a header rule for `/data.json` does not apply to the percent-encoded
// spelling `/%64ata.json`. File lookup decodes the path while header rules see the raw one, exactly
// as the pinned superstatic headers middleware does (recorded rows `static` and `encoded-static` of
// official.json, firebase-tools 15.28.2). Production behaviour for this alias is not recorded.
#[test]
fn header_rules_match_the_raw_request_path_like_the_pinned_emulator() {
    let fixture =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../conformance/hosting-fixtures");
    let corpus: serde_json::Value =
        serde_json::from_slice(&std::fs::read(fixture.join("cases.json")).unwrap()).unwrap();
    let official: serde_json::Value =
        serde_json::from_slice(&std::fs::read(fixture.join("official.json")).unwrap()).unwrap();
    let recorded = |id: &str| {
        official["rows"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["id"] == id)
            .unwrap()["headers"]
            .clone()
    };
    let (dir, _) = site_fixture(&fixture, "header-rules");
    let mut hosting = corpus["configs"]["default"].clone();
    hosting["public"] = dir.join("public").to_string_lossy().to_string().into();
    let firebase = serde_json::json!({"hosting":hosting,"emulators":emulators()});
    let (_child, address) = start(&dir, &firebase, "hosting");
    for (id, target) in [("static", "/data.json"), ("encoded-static", "/%64ata.json")] {
        let reply = request(&address, target);
        assert!(reply.starts_with("HTTP/1.1 200"), "{id}: {reply}");
        let expected = recorded(id);
        for name in ["x-fixture", "cache-control"] {
            assert_eq!(
                header(&reply, name).as_deref(),
                expected[name].as_str(),
                "{id} {name}: {reply}"
            );
        }
    }
    // Repeated slashes: minimatch splits on runs of slashes, so the pinned emulator applies the
    // `/data.json` rule to `//data.json` (measured offline with superstatic 10.0.0's configMatcher;
    // not a recorded row), and the file route collapses them as well.
    let reply = request(&address, "//data.json");
    assert!(reply.starts_with("HTTP/1.1 200"), "{reply}");
    let expected = recorded("static");
    for name in ["x-fixture", "cache-control"] {
        assert_eq!(
            header(&reply, name).as_deref(),
            expected[name].as_str(),
            "{name}: {reply}"
        );
    }
}

// Review 2026-11-09 Should: `[^S]*.json` hides a file whose name starts with U+00DF (a JavaScript
// case-insensitive regex does not fold it to `S`), while a name starting with `S` stays served.
#[test]
fn a_negated_class_ignore_hides_sharp_s_and_keeps_the_excluded_letter() {
    for profile in PROFILES {
        a_negated_class_ignore_hides_sharp_s(profile);
    }
}

fn a_negated_class_ignore_hides_sharp_s(profile: Option<&str>) {
    let dir = Scratch::new("hosting", "sharp-s");
    for (name, contents) in [("\u{df}secret.json", "hidden"), ("Ssecret.json", "served")] {
        let file = dir.join("public").join(name);
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(file, contents).unwrap();
    }
    let firebase = serde_json::json!({"hosting":{
        "public":dir.join("public"), "ignore":["[^S]*.json"]
    },"emulators":emulators()});
    let (_child, address) = start_under(profile, &dir, &firebase, "hosting");
    let hidden = request(&address, "/%C3%9Fsecret.json");
    assert!(
        hidden.starts_with("HTTP/1.1 404") && !hidden.ends_with("hidden"),
        "{hidden}"
    );
    let kept = request(&address, "/Ssecret.json");
    assert!(
        kept.starts_with("HTTP/1.1 200") && kept.ends_with("served"),
        "{kept}"
    );
}

fn request_as(address: &str, host: &str, target: &str) -> String {
    let mut stream = TcpStream::connect(address).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    write!(
        stream,
        "GET {target} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut reply = String::new();
    stream.read_to_string(&mut reply).unwrap();
    reply
}

/// DNS rebinding through the shipped CLI: the daemon installs the `Host` policy of its
/// configuration before it serves. By default a public name is refused and loopback served;
/// `network.allowedHosts` admits exactly the listed names.
#[test]
fn the_daemon_applies_the_configured_host_policy() {
    let dir = Scratch::new("hosting", "host-policy");
    std::fs::create_dir_all(dir.join("public")).unwrap();
    std::fs::write(dir.join("public/index.html"), "site").unwrap();
    let firebase =
        serde_json::json!({"hosting":{"public":dir.join("public")},"emulators":emulators()});

    for profile in PROFILES {
        let (mut child, address) = start_under(profile, &dir, &firebase, "hosting");
        let refused = request_as(&address, "evil.example", "/");
        assert!(refused.starts_with("HTTP/1.1 403"), "{refused}");
        assert!(refused.contains("network.allowedHosts"), "{refused}");
        assert!(!refused.contains("site"), "{refused}");
        assert!(request_as(&address, "site.example", "/").starts_with("HTTP/1.1 403"));
        assert!(request_as(&address, "localhost", "/").ends_with("site"));
        assert!(request_as(&address, "10.0.2.2:5000", "/").ends_with("site"));
        // Each refused name is logged once, with where to allow it.
        let stderr = stderr_after_stop(&mut child);
        drop(child);
        assert_eq!(
            stderr
                .matches("warning: refused Host \"evil.example\"")
                .count(),
            1,
            "{stderr}"
        );
        assert!(
            stderr.contains("warning: refused Host \"site.example\""),
            "{stderr}"
        );
        assert!(
            stderr.contains("[network] section of fireemu.toml"),
            "{stderr}"
        );
    }

    let config =
        serde_json::json!({"schemaVersion": 1, "network": {"allowedHosts": ["site.example"]}});
    let (listed, address) = start_with_config(&dir, &firebase, "hosting", Some(&config));
    assert!(request_as(&address, "SITE.example:5000", "/").ends_with("site"));
    assert!(request_as(&address, "evil.example", "/").starts_with("HTTP/1.1 403"));
    assert!(request_as(&address, "x.site.example", "/").starts_with("HTTP/1.1 403"));
    drop(listed);

    // "*" and a whole top-level domain are warned about at start.
    let config =
        serde_json::json!({"schemaVersion": 1, "network": {"allowedHosts": ["*", ".com"]}});
    let (mut child, address) = start_with_config(&dir, &firebase, "hosting", Some(&config));
    assert!(request_as(&address, "evil.example", "/").ends_with("site"));
    let stderr = stderr_after_stop(&mut child);
    assert!(
        stderr.contains("warning: network.allowedHosts contains \"*\""),
        "{stderr}"
    );
    assert!(
        stderr.contains("warning: network.allowedHosts entry \".com\""),
        "{stderr}"
    );
}

/// Stops the daemon (its owner stdin closes) and returns everything it wrote to stderr.
fn stderr_after_stop(child: &mut OwnedChild) -> String {
    let mut stderr = child.0.stderr.take().unwrap();
    child.0.stdin.take();
    let mut text = String::new();
    stderr.read_to_string(&mut text).unwrap();
    text
}

fn raw_request(address: &str, method: &str, target: &str, headers: &[(&str, &str)]) -> String {
    let mut stream = TcpStream::connect(address).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let extra = headers
        .iter()
        .fold(String::new(), |mut lines, (name, value)| {
            let _ = write!(lines, "{name}: {value}\r\n");
            lines
        });
    write!(
        stream,
        "{method} {target} HTTP/1.1\r\nHost: {address}\r\n{extra}Connection: close\r\n\r\n"
    )
    .unwrap();
    let mut reply = String::new();
    stream.read_to_string(&mut reply).unwrap();
    reply
}

fn body(reply: &str) -> &str {
    reply.split_once("\r\n\r\n").map_or("", |(_, body)| body)
}

// The Content-Type of a served file is the pinned oracle's `mime.contentType(path.extname(file))`
// (mime-types 2.1.35 over mime-db 1.52.0), and `Vary: Accept-Encoding` follows whether the
// compression middleware treats that type as compressible. Expected values were measured by serving
// the same files from the pinned superstatic with `compression: true` (2026-11-09).
#[test]
fn served_files_carry_the_oracle_content_type_and_vary() {
    let dir = Scratch::new("hosting", "content-types");
    std::fs::create_dir_all(dir.join("public/dir.v1")).unwrap();
    // (path, content type, Vary: Accept-Encoding present)
    let cases = [
        ("a.js", "application/javascript; charset=utf-8", true),
        ("b.JS", "application/javascript; charset=utf-8", true),
        ("k.mjs", "application/javascript; charset=utf-8", true),
        ("c.json", "application/json; charset=utf-8", true),
        ("q.map", "application/json; charset=utf-8", true),
        ("d.woff2", "font/woff2", false),
        ("g.tar.gz", "application/gzip", false),
        ("h.svg", "image/svg+xml", true),
        ("i.md", "text/markdown; charset=utf-8", true),
        ("j.ico", "image/vnd.microsoft.icon", true),
        ("l.txt", "text/plain; charset=utf-8", true),
        ("m.css", "text/css; charset=utf-8", true),
        ("n.wasm", "application/wasm", true),
        ("o.xml", "application/xml", true),
        ("p.csv", "text/csv; charset=utf-8", true),
        ("r.ts", "video/mp2t", false),
        ("s.webp", "image/webp", false),
        ("t.htm", "text/html; charset=utf-8", true),
        // No type for the extension: the pinned emulator sends the literal `false`; Fireemu sends
        // a generic binary type, with no Vary.
        ("e", "application/octet-stream", false),
        ("noext.x", "application/octet-stream", false),
        ("dir.v1/file", "application/octet-stream", false),
    ];
    for (name, _, _) in cases {
        std::fs::write(dir.join("public").join(name), "x\n").unwrap();
    }
    let firebase =
        serde_json::json!({"hosting":{"public":dir.join("public")},"emulators":emulators()});
    let (_child, address) = start(&dir, &firebase, "hosting");
    for (name, content_type, vary) in cases {
        for method in ["GET", "HEAD"] {
            let reply = raw_request(&address, method, &format!("/{name}"), &[]);
            assert!(
                reply.starts_with("HTTP/1.1 200"),
                "{method} {name}: {reply}"
            );
            assert_eq!(
                header(&reply, "content-type").as_deref(),
                Some(content_type),
                "{method} {name}"
            );
            assert_eq!(
                header(&reply, "vary").as_deref() == Some("Accept-Encoding"),
                vary,
                "{method} {name}: {reply}"
            );
        }
    }
}

// Superstatic joins the i18n root with the language directory and the path and collapses every run
// of slashes, so a root written `/locales`, `locales/` or `//locales` finds the same files as
// `locales` (measured against the pinned superstatic 10.0.0, 2026-11-09).
#[test]
fn every_slash_spelling_of_the_i18n_root_serves_the_same_files() {
    for root in [
        "locales",
        "/locales",
        "locales/",
        "/locales/",
        "//locales",
        "/locales//",
    ] {
        let dir = Scratch::new("hosting", "i18n-root");
        for (path, text) in [
            ("public/locales/fr/page.html", "fr"),
            ("public/locales/ja_ALL/page.html", "ja"),
            ("public/locales/fr_CA/page.html", "fr-CA"),
            ("public/locales/ALL_US/page.html", "us"),
            ("public/page.html", "plain"),
        ] {
            std::fs::create_dir_all(dir.join(path).parent().unwrap()).unwrap();
            std::fs::write(dir.join(path), text).unwrap();
        }
        let firebase = serde_json::json!({
            "hosting":{"public":dir.join("public"),"i18n":{"root":root}},
            "emulators":emulators()
        });
        let (_child, address) = start(&dir, &firebase, "hosting");
        for (headers, expected) in [
            (vec![("Accept-Language", "fr")], "fr"),
            (vec![("Accept-Language", "ja")], "ja"),
            (
                vec![("Accept-Language", "fr"), ("X-Country-Code", "CA")],
                "fr-CA",
            ),
            (vec![("X-Country-Code", "US")], "us"),
            (vec![("Accept-Language", "de")], "plain"),
            (vec![], "plain"),
        ] {
            let reply = raw_request(&address, "GET", "/page.html", &headers);
            assert_eq!(
                body(&reply),
                expected,
                "root {root:?} headers {headers:?}: {reply}"
            );
        }
    }
}

/// One authenticated GET of the UI API: the status line's code and the JSON body.
fn ui_get(descriptor: &serde_json::Value, path: &str) -> (u16, serde_json::Value) {
    let ui = descriptor["uiUrl"].as_str().expect("the UI is bound");
    let address = ui.trim_start_matches("http://").trim_end_matches("/ui/");
    let token = descriptor["controlToken"].as_str().unwrap();
    let reply = raw_request(
        address,
        "GET",
        path,
        &[("Authorization", &format!("Bearer {token}"))],
    );
    let status = reply
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap();
    (
        status,
        serde_json::from_str(body(&reply)).unwrap_or_default(),
    )
}

#[test]
fn the_ui_reports_the_served_site_and_the_host_names_in_effect() {
    let dir = Scratch::new("hosting", "ui-report");
    std::fs::create_dir_all(dir.join("dist")).unwrap();
    let mut emulators = emulators();
    emulators.as_object_mut().unwrap().remove("ui");
    let firebase = serde_json::json!({
        "hosting": {
            "public": "dist",
            "cleanUrls": true,
            "rewrites": [{"source": "**", "destination": "/index.html"}],
            "headers": [{"source": "**", "headers": [{"key": "X-Test", "value": "1"}]}],
            "predeploy": ["echo not-for-the-page"],
        },
        "emulators": emulators,
    });
    let config = serde_json::json!({
        "schemaVersion": 1,
        "network": {"allowedHosts": ["Ci.Example"], "allowNonLoopbackHosts": true},
        "daemon": {"clock": "frozen"},
    });
    let (_child, descriptor) = start_descriptor(
        &dir,
        &firebase,
        "hosting",
        Some(&config),
        &["--ui-port", "auto"],
    );
    let (status, site) = ui_get(&descriptor, "/ui/api/hosting");
    assert_eq!(status, 200, "{site}");
    assert_eq!(site["served"], true);
    assert_eq!(site["url"], descriptor["hostingUrl"]);
    assert_eq!(site["publicExists"], true);
    let root = site["publicRoot"].as_str().unwrap();
    assert!(root.ends_with("/dist"), "{root}");
    assert_eq!(site["site"]["cleanUrls"], true);
    assert_eq!(site["site"]["rewrites"][0]["destination"], "/index.html");
    assert_eq!(site["site"]["headers"][0]["headers"][0]["key"], "X-Test");
    assert!(site["site"].get("predeploy").is_none(), "{site}");
    let (_, config) = ui_get(&descriptor, "/ui/api/config");
    assert_eq!(
        config["hosts"]["allowed"],
        serde_json::json!(["ci.example"])
    );
    assert_eq!(config["hosts"]["allowNonLoopbackHosts"], true);
    assert!(config["hosts"]["defaultNames"]
        .as_array()
        .unwrap()
        .contains(&serde_json::json!("localhost")));
    assert!(config["hosts"]["defaultSuffixes"]
        .as_array()
        .unwrap()
        .contains(&serde_json::json!(".internal")));
    assert_eq!(config["clockMode"], "frozen");
}

#[test]
fn the_ui_says_no_site_is_served_when_hosting_is_not_selected() {
    let dir = Scratch::new("hosting", "ui-not-served");
    let emulators = serde_json::json!({"auth":{"port":0},"hub":{"port":0},"logging":{"port":0}});
    let firebase = serde_json::json!({"hosting":{"public":"public"},"emulators":emulators});
    let (_child, descriptor) =
        start_descriptor(&dir, &firebase, "auth", None, &["--ui-port", "auto"]);
    let (status, site) = ui_get(&descriptor, "/ui/api/hosting");
    assert_eq!(status, 200, "{site}");
    assert_eq!(site, serde_json::json!({"served": false}));
    let (_, config) = ui_get(&descriptor, "/ui/api/config");
    assert_eq!(config["clockMode"], "realtime");
}

#[test]
fn the_ui_flags_a_public_directory_that_did_not_exist_at_start() {
    let dir = Scratch::new("hosting", "ui-missing-public");
    let mut emulators = emulators();
    emulators.as_object_mut().unwrap().remove("ui");
    let firebase = serde_json::json!({"hosting":{"public":"not-created"},"emulators":emulators});
    let (_child, descriptor) =
        start_descriptor(&dir, &firebase, "hosting", None, &["--ui-port", "auto"]);
    let (status, site) = ui_get(&descriptor, "/ui/api/hosting");
    assert_eq!(status, 200, "{site}");
    assert_eq!(site["served"], true);
    assert_eq!(site["publicExists"], false);
    assert!(site["publicRoot"]
        .as_str()
        .unwrap()
        .ends_with("/not-created"));
}

/// A runner that speaks the fireemu protocol and exports one scheduled function.
#[cfg(unix)]
const SCHEDULE_RUNNER: &str = r#"
import json, sys

def send(m):
    p = json.dumps(m).encode()
    sys.stdout.buffer.write(f"{len(p)}\n".encode())
    sys.stdout.buffer.write(p)
    sys.stdout.buffer.flush()

send({"type": "hello", "runner": "ui-runtime-test", "manifest": {"functions": [
    {"name": "tick", "trigger": {"type": "schedule", "schedule": "every 5 minutes"}}
]}})
while True:
    line = sys.stdin.buffer.readline()
    if not line:
        break
    msg = json.loads(sys.stdin.buffer.read(int(line.strip())))
    if msg.get("type") == "shutdown":
        break
    if msg.get("type") == "invoke":
        send({"type": "result", "invocationId": msg["invocationId"], "ok": True})
"#;

/// The runtime of each function in the UI follows the codebase's declared `runtime`, or the
/// loader picked when it declares none (the runner override skips the Python preflight).
#[cfg(unix)]
fn function_runtime_in_ui(declared: Option<&str>, name: &str) -> serde_json::Value {
    let dir = Scratch::new("hosting", name);
    std::fs::create_dir_all(dir.join("functions")).unwrap();
    std::fs::write(dir.join("runner.py"), SCHEDULE_RUNNER).unwrap();
    let mut codebase = serde_json::json!({"codebase": "app", "source": "functions"});
    if let Some(runtime) = declared {
        codebase["runtime"] = runtime.into();
    }
    let mut emulators = emulators();
    emulators.as_object_mut().unwrap().remove("ui");
    let firebase = serde_json::json!({"functions": [codebase], "emulators": emulators});
    let config = serde_json::json!({
        "schemaVersion": 1,
        "functions": {"runner": ["python3", dir.join("runner.py").to_str().unwrap()]},
    });
    let (_child, descriptor) = start_descriptor(
        &dir,
        &firebase,
        "functions",
        Some(&config),
        &["--ui-port", "auto"],
    );
    let (status, overview) = ui_get(&descriptor, "/ui/api/functions");
    assert_eq!(status, 200, "{overview}");
    let tick = overview["functions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["name"] == "tick")
        .unwrap_or_else(|| panic!("tick is listed: {overview}"))
        .clone();
    assert_eq!(tick["codebase"], "app");
    // The codebase list carries the same runtime.
    let listed = overview["codebases"].as_array().unwrap();
    assert_eq!(listed.len(), 1, "{overview}");
    assert_eq!(listed[0]["codebase"], "app");
    assert_eq!(
        (listed[0]["language"].clone(), listed[0]["declared"].clone()),
        (
            tick["runtime"]["language"].clone(),
            tick["runtime"]["declared"].clone()
        )
    );
    tick["runtime"].clone()
}

#[cfg(unix)]
#[test]
fn the_ui_names_the_runtime_a_codebase_declares_or_the_loader_picked() {
    assert_eq!(
        function_runtime_in_ui(Some("python312"), "ui-runtime-python"),
        serde_json::json!({"language": "python", "declared": "python312"})
    );
    assert_eq!(
        function_runtime_in_ui(Some("nodejs22"), "ui-runtime-node"),
        serde_json::json!({"language": "node", "declared": "nodejs22"})
    );
    assert_eq!(
        function_runtime_in_ui(None, "ui-runtime-bare"),
        serde_json::json!({"language": "node", "declared": null})
    );
}
