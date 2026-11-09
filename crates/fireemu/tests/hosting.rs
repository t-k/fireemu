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

fn site_fixture(fixture: &std::path::Path) -> (Scratch, serde_json::Value) {
    let dir = Scratch::new("hosting", "cli");
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
fn hosting_cli_serves_shared_fixture_and_withdraws_readiness_on_shutdown() {
    let fixture =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../conformance/hosting-fixtures");
    let corpus: serde_json::Value =
        serde_json::from_slice(&std::fs::read(fixture.join("cases.json")).unwrap()).unwrap();
    let (dir, security) = site_fixture(&fixture);
    let sentinel = security["outsideSentinel"].as_str().unwrap();
    let mut hosting = corpus["configs"]["default"].clone();
    hosting["public"] = dir.join("public").to_string_lossy().to_string().into();
    let firebase = serde_json::json!({"hosting":hosting,"emulators":{"hosting":{"port":0},"ui":{"enabled":false},"logging":{"port":0},"hub":{"port":0}}});
    std::fs::write(dir.join("firebase.json"), firebase.to_string()).unwrap();
    let ready = dir.join("ready.json");
    let mut child = OwnedChild(
        Command::new(env!("CARGO_BIN_EXE_fireemu"))
            .args([
                "up",
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

fn start(dir: &std::path::Path, firebase: &serde_json::Value, only: &str) -> (OwnedChild, String) {
    start_with_config(dir, firebase, only, None)
}

/// [`start`] with a canonical fireemu configuration document.
fn start_with_config(
    dir: &std::path::Path,
    firebase: &serde_json::Value,
    only: &str,
    config: Option<&serde_json::Value>,
) -> (OwnedChild, String) {
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

fn emulators() -> serde_json::Value {
    serde_json::json!({"hosting":{"port":0},"ui":{"enabled":false},"hub":{"port":0},"logging":{"port":0}})
}

#[test]
fn hosting_ignored_assets_are_absent_from_every_route() {
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
    let (_child, address) = start(&dir, &firebase, "hosting");
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
    let (dir, _) = site_fixture(&fixture);
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
    let dir = Scratch::new("hosting", "sharp-s");
    for (name, contents) in [("\u{df}secret.json", "hidden"), ("Ssecret.json", "served")] {
        let file = dir.join("public").join(name);
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(file, contents).unwrap();
    }
    let firebase = serde_json::json!({"hosting":{
        "public":dir.join("public"), "ignore":["[^S]*.json"]
    },"emulators":emulators()});
    let (_child, address) = start(&dir, &firebase, "hosting");
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

    let (mut child, address) = start(&dir, &firebase, "hosting");
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
