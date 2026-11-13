//! The strict profile answers as Hosting production does. Every expectation here is a row of the
//! production recording of the Hosting parent (runs 658bb2 and 9a8d57, corpus
//! `conformance/src/hosting-production`); the row id is named in the assertion text. The emulator
//! profile keeps the pinned local oracle's answers (`hosting.rs`), and a few rows are checked
//! there too, to show the two profiles differ where intended.

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

struct Site {
    dir: Scratch,
    _child: OwnedChild,
    address: String,
}

/// A site of `files` under `config`, served by the profile named: `strict` (the default profile:
/// the development defaults on), `exact` (strict with `productionExact`: production's answers) or
/// `emulator`.
fn site(name: &str, profile: &str, config: &serde_json::Value, files: &[(&str, &str)]) -> Site {
    let document = match profile {
        "exact" => {
            serde_json::json!({"schemaVersion": 1, "profile": "strict", "productionExact": true})
        }
        other => serde_json::json!({"schemaVersion": 1, "profile": other}),
    };
    site_with(name, &document, config, files)
}

/// [`site`] under a complete configuration document.
fn site_with(
    name: &str,
    document: &serde_json::Value,
    config: &serde_json::Value,
    files: &[(&str, &str)],
) -> Site {
    let dir = Scratch::new("hosting-strict", name);
    for (path, contents) in files {
        let target = dir.join("public").join(path);
        std::fs::create_dir_all(target.parent().unwrap()).unwrap();
        std::fs::write(target, contents).unwrap();
    }
    let mut hosting = config.clone();
    hosting["public"] = dir.join("public").to_string_lossy().to_string().into();
    let firebase = serde_json::json!({"hosting": hosting, "emulators": {"hosting": {"port": 0}, "ui": {"enabled": false}, "hub": {"port": 0}, "logging": {"port": 0}}});
    std::fs::write(dir.join("firebase.json"), firebase.to_string()).unwrap();
    std::fs::write(dir.join("fireemu.json"), document.to_string()).unwrap();
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
        .unwrap()
        .trim_start_matches("http://")
        .trim_end_matches('/')
        .to_owned();
    Site {
        dir,
        _child: child,
        address,
    }
}

struct Reply {
    status: u16,
    head: String,
    body: String,
    /// The body exactly as it came, before any chunked decoding.
    bytes: Vec<u8>,
}
impl Reply {
    fn header(&self, name: &str) -> Option<&str> {
        self.head.lines().skip(1).find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.eq_ignore_ascii_case(name).then(|| value.trim())
        })
    }
}

fn send(site: &Site, method: &str, target: &str, headers: &[(&str, &str)]) -> Reply {
    send_within(site, method, target, headers, Duration::from_secs(30))
}

/// [`send`] with the time the reply may take. Every request reads the whole file once to make its
/// `ETag` (MD5 and SHA-256), so a request for a 16 or 32 MiB file takes seconds in a debug build and
/// far more on a loaded machine: those tests wait for minutes, not for a guess of seconds.
fn send_within(
    site: &Site,
    method: &str,
    target: &str,
    headers: &[(&str, &str)],
    patience: Duration,
) -> Reply {
    send_to_host(site, &site.address, method, target, headers, patience)
}

/// [`send_within`] with the text of the `Host` header chosen by the caller (the site's address in
/// every other test): for a `Host` that no client library would send.
fn send_to_host(
    site: &Site,
    host: &str,
    method: &str,
    target: &str,
    headers: &[(&str, &str)],
    patience: Duration,
) -> Reply {
    let mut stream = TcpStream::connect(&site.address).unwrap();
    stream.set_read_timeout(Some(patience)).unwrap();
    let extra = headers
        .iter()
        .fold(String::new(), |mut lines, (name, value)| {
            let _ = write!(lines, "{name}: {value}\r\n");
            lines
        });
    write!(
        stream,
        "{method} {target} HTTP/1.1\r\nHost: {host}\r\n{extra}Connection: close\r\n\r\n"
    )
    .unwrap();
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).unwrap();
    let text = String::from_utf8_lossy(&raw).into_owned();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    let bytes = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map_or_else(Vec::new, |at| raw[at + 4..].to_vec());
    let status = head.split(' ').nth(1).unwrap().parse().unwrap();
    // a chunked body is decoded
    let body = if head
        .to_ascii_lowercase()
        .contains("transfer-encoding: chunked")
    {
        let mut decoded = String::new();
        let mut rest = body;
        while let Some((size, tail)) = rest.split_once("\r\n") {
            let length = usize::from_str_radix(size.trim(), 16).unwrap_or(0);
            if length == 0 {
                break;
            }
            decoded.push_str(&tail[..length]);
            rest = &tail[length + 2..];
        }
        decoded
    } else {
        body.to_owned()
    };
    Reply {
        status,
        head: head.to_owned(),
        body,
        bytes,
    }
}

fn get(site: &Site, target: &str) -> Reply {
    send(site, "GET", target, &[])
}

fn json(text: &str) -> serde_json::Value {
    serde_json::from_str(text).unwrap()
}

const FILES: &[(&str, &str)] = &[
    ("index.html", "<h1>home</h1>\n"),
    ("data.json", "{\"fixture\":true}\n"),
    ("404.html", "<h1>not found</h1>\n"),
    ("page.html", "<h1>page</h1>\n"),
    ("dir/index.html", "<h1>dir</h1>\n"),
    ("ct/noext", "x\n"),
    ("ct/file.unknownext", "x\n"),
    ("ct/file.js", "x\n"),
    ("ct/file.ico", "x\n"),
    ("ct/file.webmanifest", "{}\n"),
];

fn config() -> serde_json::Value {
    json(
        r#"{
        "redirects": [
            {"source": "/old/**", "destination": "/page.html", "type": 302},
            {"source": "/capture/:name", "destination": "/new/:name", "type": 301},
            {"source": "/capture/:id/:id2", "destination": "/new/:id2/:id", "type": 301},
            {"source": "/go1/:name", "destination": "/:name", "type": 302},
            {"source": "/go2/:name", "destination": "/next/:name", "type": 302},
            {"source": "/go3/:name", "destination": "https://example.test/:name", "type": 302}
        ],
        "rewrites": [{"source": "/rewrite/**", "destination": "/index.html"}],
        "headers": [
            {"source": "/**", "headers": [{"key": "X-Fixture", "value": "first"}]},
            {"source": "/data.json", "headers": [{"key": "X-Fixture", "value": "second"}, {"key": "Cache-Control", "value": "public, max-age=123"}]}
        ]
    }"#,
    )
}

#[test]
fn hosting_strict_a_file_answers_with_the_headers_production_adds() {
    let strict = site("static", "exact", &config(), FILES);
    // v01.root, v01.static
    let root = get(&strict, "/");
    assert_eq!(root.status, 200);
    assert_eq!(
        root.header("cache-control"),
        Some("max-age=3600"),
        "v01.root"
    );
    assert_eq!(root.header("accept-ranges"), Some("bytes"));
    assert_eq!(
        root.header("vary"),
        Some("x-fh-requested-host, accept-encoding")
    );
    assert_eq!(
        root.header("content-type"),
        Some("text/html; charset=utf-8")
    );
    let etag = root.header("etag").unwrap();
    assert!(
        etag.len() == 66 && etag.starts_with('"') && etag.ends_with('"'),
        "a quoted SHA-256: {etag}"
    );
    assert!(root.header("last-modified").unwrap().ends_with(" GMT"));
    assert_eq!(root.body, "<h1>home</h1>\n");
    let data = get(&strict, "/data.json");
    assert_eq!(
        data.header("cache-control"),
        Some("public, max-age=123"),
        "a rule wins"
    );
    assert_eq!(data.header("x-fixture"), Some("second"));
    assert_eq!(
        data.header("content-type"),
        Some("application/json"),
        "v01.static"
    );
    // v01.encoded-static: the rules see the decoded path
    let encoded = get(&strict, "/%64ata.json");
    assert_eq!(encoded.header("x-fixture"), Some("second"));
    // the emulator profile is the pinned oracle: no default Cache-Control, no Accept-Ranges
    let emulator = site("static-emulator", "emulator", &config(), FILES);
    let root = get(&emulator, "/");
    assert_eq!(root.header("cache-control"), None);
    assert_eq!(root.header("accept-ranges"), None);
    assert_eq!(
        get(&emulator, "/data.json").header("content-type"),
        Some("application/json; charset=utf-8")
    );
}

#[test]
fn hosting_strict_content_types_follow_production() {
    let strict = site("types", "exact", &config(), FILES);
    for (target, expected) in [
        ("/ct/file.js", "text/javascript; charset=utf-8"),
        ("/ct/file.ico", "image/x-icon"),
        ("/ct/file.webmanifest", "application/manifest+json"),
        ("/ct/noext", "text/plain; charset=utf-8"),
        ("/ct/file.unknownext", "text/plain; charset=utf-8"),
    ] {
        assert_eq!(
            get(&strict, target).header("content-type"),
            Some(expected),
            "{target}"
        );
    }
}

#[test]
fn hosting_strict_ranges_and_conditional_requests() {
    let strict = site("ranges", "exact", &config(), FILES);
    // v01.range, v01.range-suffix
    let head = send(&strict, "GET", "/data.json", &[("Range", "bytes=0-3")]);
    assert_eq!(head.status, 206);
    assert_eq!(head.header("content-range"), Some("bytes 0-3/17"));
    assert_eq!(head.header("content-length"), Some("4"));
    assert_eq!(head.body, "{\"fi");
    let tail = send(&strict, "GET", "/data.json", &[("Range", "bytes=-3")]);
    assert_eq!(tail.status, 206);
    assert_eq!(tail.header("content-range"), Some("bytes 14-16/17"));
    assert_eq!(tail.body, "e}\n");
    let past = send(&strict, "GET", "/data.json", &[("Range", "bytes=40-")]);
    assert_eq!(past.status, 416);
    assert_eq!(past.header("content-range"), Some("bytes */17"));
    // v01.cond-etag, v01.cond-etag-wrong, v01.cond-since-future, v01.cond-since-past
    let etag = get(&strict, "/data.json")
        .header("etag")
        .unwrap()
        .to_owned();
    let same = send(&strict, "GET", "/data.json", &[("If-None-Match", &etag)]);
    assert_eq!(same.status, 304);
    assert_eq!(same.header("etag"), Some(etag.as_str()));
    assert_eq!(same.header("cache-control"), Some("public, max-age=123"));
    assert_eq!(
        same.header("x-fixture"),
        None,
        "a 304 carries only the cache headers"
    );
    assert_eq!(same.header("accept-ranges"), None);
    assert_eq!(same.body, "");
    assert_eq!(
        send(
            &strict,
            "GET",
            "/data.json",
            &[("If-None-Match", "\"other\"")]
        )
        .status,
        200
    );
    assert_eq!(
        send(
            &strict,
            "GET",
            "/data.json",
            &[("If-Modified-Since", "Wed, 01 Jan 2200 00:00:00 GMT")]
        )
        .status,
        304
    );
    assert_eq!(
        send(
            &strict,
            "GET",
            "/data.json",
            &[("If-Modified-Since", "Mon, 01 Jan 2001 00:00:00 GMT")]
        )
        .status,
        200
    );
    // the emulator profile answers the same request whole
    let emulator = site("ranges-emulator", "emulator", &config(), FILES);
    assert_eq!(
        send(&emulator, "GET", "/data.json", &[("Range", "bytes=0-3")]).status,
        200
    );
}

#[test]
fn hosting_strict_options_on_a_file_and_the_other_methods() {
    let strict = site("options", "exact", &config(), FILES);
    // v01.options-static
    let options = send(&strict, "OPTIONS", "/data.json", &[]);
    assert_eq!(options.status, 200);
    assert_eq!(options.header("allow"), Some("GET, HEAD, OPTIONS"));
    assert_eq!(options.header("cache-control"), Some("no-cache"));
    assert_eq!(options.header("x-fixture"), Some("second"));
    assert_eq!(options.body, "");
    // v01.post-static, v01.put-static, v01.delete-static: served as the file
    for method in ["POST", "PUT", "DELETE"] {
        let reply = send(&strict, method, "/data.json", &[]);
        assert_eq!(
            (reply.status, reply.body.as_str()),
            (200, "{\"fixture\":true}\n"),
            "{method}"
        );
    }
    // v01.head-static
    let head = send(&strict, "HEAD", "/data.json", &[]);
    assert_eq!(head.header("content-length"), Some("17"));
    assert_eq!(head.body, "");
}

#[test]
fn hosting_strict_not_found_pages() {
    let strict = site("notfound", "exact", &config(), FILES);
    // v01.not-found-direct: the file is a file
    let direct = get(&strict, "/404.html");
    assert_eq!(
        (direct.status, direct.body.as_str()),
        (200, "<h1>not found</h1>\n")
    );
    assert_eq!(direct.header("cache-control"), Some("max-age=3600"));
    // an unmatched path gets the page with 404
    let missing = get(&strict, "/nothing/here");
    assert_eq!(
        (missing.status, missing.body.as_str()),
        (404, "<h1>not found</h1>\n")
    );
    // without a 404.html: production's page is longer than anything recorded as text; strict
    // answers with its own, 404, text/html and the same cache headers (v02.page-slash)
    let bare = site(
        "notfound-bare",
        "exact",
        &serde_json::json!({}),
        &[("index.html", "x")],
    );
    let missing = get(&bare, "/nothing");
    assert_eq!(missing.status, 404);
    assert_eq!(
        missing.header("content-type"),
        Some("text/html; charset=utf-8")
    );
    assert_eq!(missing.header("cache-control"), Some("max-age=3600"));
    assert_eq!(
        missing.header("vary"),
        Some("x-fh-requested-host, accept-encoding")
    );
    // the emulator profile keeps the oracle: /404.html is a 404 itself
    let emulator = site("notfound-emulator", "emulator", &config(), FILES);
    assert_eq!(get(&emulator, "/404.html").status, 404);
}

#[test]
fn hosting_strict_redirects_decode_each_capture_and_say_so_as_plain_text() {
    let strict = site("redirects", "exact", &config(), FILES);
    // v01.head-redirect and v01.redirect-first
    let first = get(&strict, "/old/a?q=1");
    assert_eq!(first.status, 302);
    assert_eq!(first.header("location"), Some("/page.html?q=1"));
    assert_eq!(
        first.header("content-type"),
        Some("text/plain; charset=utf-8")
    );
    assert_eq!(first.body, "Redirecting to /page.html?q=1");
    assert_eq!(first.header("x-fixture"), Some("first"));
    assert_eq!(
        first.header("vary"),
        Some("x-fh-requested-host, accept-encoding")
    );
    assert_eq!(first.header("cache-control"), None);
    let head = send(&strict, "HEAD", "/old/a", &[]);
    assert_eq!(head.header("content-length"), Some("25"));
    assert_eq!(head.body, "");
    // v01.edge-N-NN: the Location of a capture
    for (target, location) in [
        ("/go1/%2fevil.example", "/evil.example"),
        ("/go2/%2fevil.example", "/next/evil.example"),
        ("/go3/%2fevil.example", "https://example.test/evil.example"),
        ("/go1/%3Aother", "/:other"),
        ("/go1/a%3Fb", "/a?b"),
        ("/go1/plain?x=%5c", "/plain?x=%5c"),
        ("/go1/%5cevil.example", "/%5Cevil.example"),
        ("/go1/%255cevil.example", "/%255cevil.example"),
        ("/go1/a%20b", "/a%20b"),
        ("/go1/a:b", "/a:b"),
        ("/go1/%E6%97%A5", "/%E6%97%A5"),
    ] {
        let reply = get(&strict, target);
        assert_eq!(reply.status, 302, "{target}");
        assert_eq!(reply.header("location"), Some(location), "{target}");
    }
    // v01.redirect-capture: one parameter
    assert_eq!(
        get(&strict, "/capture/name").header("location"),
        Some("/new/name")
    );
    // v01.redirect-capture-prefix and -literal: `:id2` is the parameter `id` and a literal `2`,
    // so `/capture/:id/:id2` never matched in production
    assert_eq!(get(&strict, "/capture/one/two").status, 404);
    assert_eq!(get(&strict, "/capture/:id2/two").status, 404);
    // the emulator profile keeps the oracle: double-encoded, html
    let emulator = site("redirects-emulator", "emulator", &config(), FILES);
    // ... and a HEAD redirect names no length
    assert_eq!(
        send(&emulator, "HEAD", "/old/a", &[]).header("content-length"),
        None
    );
    let reply = get(&emulator, "/go1/%2fevil.example");
    assert_eq!(reply.header("location"), Some("/%252fevil.example"));
    assert_eq!(
        reply.header("content-type"),
        Some("text/html; charset=utf-8")
    );
    assert_eq!(
        get(&emulator, "/capture/one/two").header("location"),
        Some("/new/two/one")
    );
}

#[test]
fn hosting_strict_reserved_routes() {
    let catch_all =
        json(r#"{"redirects": [{"source": "**", "destination": "/page.html", "type": 302}]}"#);
    let strict = site("reserved", "exact", &catch_all, FILES);
    // v09.reserved-auth-handler: outside the redirects; v09.reserved-json, -js: inside them
    let handler = send(&strict, "HEAD", "/__/auth/handler", &[]);
    assert_eq!(handler.status, 200);
    assert_eq!(
        handler.header("content-type"),
        Some("text/html; charset=utf-8")
    );
    assert_eq!(handler.header("cache-control"), Some("max-age=1800"));
    assert_eq!(get(&strict, "/__/firebase/init.json").status, 302);
    assert_eq!(get(&strict, "/__/firebase/init.js").status, 302);
    assert_eq!(get(&strict, "/__/missing").status, 302);
    // v01: without the redirect, init.json is a cacheable file with an ETag
    let plain = site("reserved-plain", "exact", &config(), FILES);
    let init = get(&plain, "/__/firebase/init.json");
    assert_eq!(init.status, 200);
    assert_eq!(init.header("content-type"), Some("application/json"));
    assert_eq!(init.header("cache-control"), Some("max-age=3600"));
    assert!(init
        .header("etag")
        .is_some_and(|etag| etag.starts_with('"')));
    assert!(init.header("last-modified").is_some());
    assert_eq!(init.header("x-fixture"), Some("first"));
    assert_eq!(json(&init.body)["projectId"], "demo-hosting");
    let script = get(&plain, "/__/firebase/init.js");
    assert_eq!(
        script.header("content-type"),
        Some("text/javascript; charset=utf-8")
    );
    // the hosted SDK files stay out of the redirects (not served offline: 503)
    assert_eq!(
        get(&strict, "/__/firebase/9.0.0/firebase-app.js").status,
        503
    );
    // init.js points the SDK at the emulators of the run only when asked
    assert!(
        script.body.contains("var endpoints=null;"),
        "{}",
        script.body
    );
    let with_emulators = get(&plain, "/__/firebase/init.js?useEmulator=true");
    assert!(
        with_emulators.body.contains("var endpoints={"),
        "{}",
        with_emulators.body
    );
    assert!(with_emulators.body.contains("firebase.initializeApp("));
    // the emulator profile keeps init.* ahead of the redirects
    let emulator = site("reserved-emulator", "emulator", &catch_all, FILES);
    assert_eq!(get(&emulator, "/__/firebase/init.json").status, 200);
    assert_eq!(send(&emulator, "HEAD", "/__/auth/handler", &[]).status, 302);
    assert_eq!(
        get(&emulator, "/__/firebase/9.0.0/firebase-app.js").status,
        503
    );
    let emulator_plain = site("reserved-emulator-plain", "emulator", &config(), FILES);
    assert!(get(&emulator_plain, "/__/firebase/init.js")
        .body
        .contains("var endpoints=null;"));
    assert!(
        get(&emulator_plain, "/__/firebase/init.js?useEmulator=true")
            .body
            .contains("var endpoints={")
    );
}

#[test]
fn hosting_strict_a_malformed_target_is_a_chunked_400() {
    let strict = site("malformed", "exact", &config(), FILES);
    // v01.safety-bad-percent
    let reply = get(&strict, "/%GG");
    assert_eq!(reply.status, 400);
    assert_eq!(reply.body, "400 Bad Request");
    assert_eq!(
        reply.header("content-type"),
        Some("text/plain; charset=utf-8")
    );
    assert_eq!(reply.header("transfer-encoding"), Some("chunked"));
    assert_eq!(reply.header("accept-ranges"), Some("bytes"));
    assert_eq!(reply.header("vary"), None);
    let emulator = site("malformed-emulator", "emulator", &config(), FILES);
    assert_eq!(get(&emulator, "/%GG").body, "Malformed URL");
}

#[test]
fn hosting_strict_app_association_documents() {
    let auto = json(r#"{"appAssociation": "AUTO"}"#);
    let strict = site("association", "exact", &auto, FILES);
    // v02.assetlinks, v02.apple-app-site-association
    let links = get(&strict, "/.well-known/assetlinks.json");
    assert_eq!((links.status, links.body.as_str()), (200, "[]"));
    assert_eq!(links.header("cache-control"), Some("private, no-store"));
    assert_eq!(links.header("pragma"), Some("no-cache"));
    assert_eq!(
        links.header("content-type"),
        Some("application/json; charset=utf-8")
    );
    let apple = get(&strict, "/.well-known/apple-app-site-association");
    assert_eq!(apple.body, "{\"applinks\":{\"apps\":[],\"details\":[]}}");
    // not generated without AUTO, and not by the emulator profile
    let none = site("association-none", "exact", &serde_json::json!({}), FILES);
    assert_eq!(get(&none, "/.well-known/assetlinks.json").status, 404);
    let emulator = site("association-emulator", "emulator", &auto, FILES);
    assert_eq!(get(&emulator, "/.well-known/assetlinks.json").status, 404);
}

const LOCALES: &[(&str, &str)] = &[
    ("page.html", "default\n"),
    ("locales/fr/page.html", "fr\n"),
    ("locales/fr_CA/page.html", "fr_ca\n"),
    ("locales/ALL_CA/page.html", "all_ca\n"),
    ("locales/de/other.html", "de\n"),
];

#[test]
fn hosting_strict_localized_content_follows_production() {
    let config = json(r#"{"i18n": {"root": "locales"}}"#);
    let strict = site("i18n", "exact", &config, LOCALES);
    let page = |headers: &[(&str, &str)]| send(&strict, "GET", "/page.html", headers).body;
    // v07.language, v07.region-tag, v07.fallback
    assert_eq!(page(&[("Accept-Language", "fr")]), "fr\n");
    assert_eq!(page(&[("Accept-Language", "fr-CA")]), "fr\n");
    assert_eq!(page(&[("Accept-Language", "de")]), "default\n");
    // v07.quality: the highest quality that has a file
    assert_eq!(page(&[("Accept-Language", "de;q=0.9, fr;q=0.8")]), "fr\n");
    // v07.language-cookie
    assert_eq!(
        page(&[
            ("Accept-Language", "en"),
            ("Cookie", "firebase-language-override=fr")
        ]),
        "fr\n"
    );
    // v07.country-header, -only, v07.country-cookie, -only, v07.both-cookies: the country a client
    // sends decides nothing (production's edge decides it)
    assert_eq!(
        page(&[("Accept-Language", "fr"), ("X-Country-Code", "CA")]),
        "fr\n"
    );
    assert_eq!(page(&[("X-Country-Code", "CA")]), "default\n");
    assert_eq!(
        page(&[
            ("Accept-Language", "fr"),
            ("Cookie", "firebase-country-override=CA")
        ]),
        "fr\n"
    );
    assert_eq!(
        page(&[("Cookie", "firebase-country-override=CA")]),
        "default\n"
    );
    assert_eq!(
        page(&[(
            "Cookie",
            "firebase-language-override=fr; firebase-country-override=CA"
        )]),
        "fr\n"
    );
    // the files answer with the longer Vary
    let reply = send(&strict, "GET", "/page.html", &[("Accept-Language", "fr")]);
    assert_eq!(
        reply.header("vary"),
        Some("accept-language, x-country-code, x-fh-requested-host, accept-encoding")
    );
    // the emulator profile is the oracle: the country counts, a quality suffix breaks the language
    let emulator = site("i18n-emulator", "emulator", &config, LOCALES);
    let page = |headers: &[(&str, &str)]| send(&emulator, "GET", "/page.html", headers).body;
    assert_eq!(
        page(&[("Accept-Language", "fr"), ("X-Country-Code", "CA")]),
        "fr_ca\n"
    );
    assert_eq!(page(&[("X-Country-Code", "CA")]), "all_ca\n");
    assert_eq!(
        page(&[("Accept-Language", "de;q=0.9, fr;q=0.8")]),
        "default\n"
    );
}

#[test]
fn hosting_strict_header_and_rewrite_globs_match_what_production_matched() {
    let headers: Vec<serde_json::Value> = ["/**", "/a/*", "/a/**", "/a/?", "/a/?(x)", "/a/*(x)", "/a/.hidden"]
        .iter()
        .enumerate()
        .map(|(index, source)| serde_json::json!({"source": source, "headers": [{"key": format!("X-G{index:02}"), "value": "1"}]}))
        .collect();
    let config = serde_json::json!({"headers": headers, "rewrites": [{"source": "**", "destination": "/index.html"}]});
    let strict = site("globs", "exact", &config, &[("index.html", "home\n")]);
    let matched = |target: &str| -> String {
        let reply = get(&strict, target);
        (0..7)
            .filter(|index| reply.header(&format!("x-g{index:02}")).is_some())
            .map(|index| index.to_string())
            .collect()
    };
    // v10.path-05: the part after the trailing slash is empty and still matches
    assert_eq!(matched("/a/"), "01245");
    // v10.path-07: a dot file matches `*`, `**` and the rewrite
    assert_eq!(matched("/a/.hidden"), "0126");
    let hidden = get(&strict, "/a/.hidden");
    assert_eq!((hidden.status, hidden.body.as_str()), (200, "home\n"));
    // the emulator profile is minimatch: neither
    let emulator = site(
        "globs-emulator",
        "emulator",
        &config,
        &[("index.html", "home\n")],
    );
    assert_eq!(get(&emulator, "/a/.hidden").status, 404);
}

const CLEAN_FILES: &[(&str, &str)] = &[
    ("index.html", "<h1>home</h1>\n"),
    ("page.html", "<h1>page</h1>\n"),
    ("dir/index.html", "<h1>directory</h1>\n"),
];

/// Rows `v02` to `v06` of the recording: `cleanUrls` and `trailingSlash`, each request with the
/// status, the `Location` and, for a 200, the body production answered.
#[test]
fn hosting_strict_clean_urls_and_trailing_slash_follow_the_recorded_rows() {
    const HOME: &str = "<h1>home</h1>\n";
    const PAGE: &str = "<h1>page</h1>\n";
    const DIRECTORY: &str = "<h1>directory</h1>\n";
    type Row = (&'static str, u16, &'static str, &'static str);
    let tables: [(&str, &str, [Row; 7]); 5] = [
        (
            "v02",
            r#"{"cleanUrls": true}"#,
            [
                ("/page?q=1", 200, "", PAGE),
                ("/page/?q=1", 404, "", ""),
                ("/page.html?q=1", 301, "/page?q=1", ""),
                ("/dir?q=1", 200, "", DIRECTORY),
                ("/dir/?q=1", 200, "", DIRECTORY),
                ("/dir/index.html?q=1", 301, "/dir?q=1", ""),
                ("/", 200, "", HOME),
            ],
        ),
        (
            "v03",
            r#"{"trailingSlash": true}"#,
            [
                ("/page?q=1", 404, "", ""),
                ("/page/?q=1", 404, "", ""),
                ("/page.html?q=1", 200, "", PAGE),
                ("/dir?q=1", 301, "/dir/?q=1", ""),
                ("/dir/?q=1", 200, "", DIRECTORY),
                ("/dir/index.html?q=1", 200, "", DIRECTORY),
                ("/", 200, "", HOME),
            ],
        ),
        (
            "v04",
            r#"{"trailingSlash": false}"#,
            [
                ("/page?q=1", 404, "", ""),
                ("/page/?q=1", 404, "", ""),
                ("/page.html?q=1", 200, "", PAGE),
                ("/dir?q=1", 200, "", DIRECTORY),
                ("/dir/?q=1", 301, "/dir?q=1", ""),
                ("/dir/index.html?q=1", 200, "", DIRECTORY),
                ("/", 200, "", HOME),
            ],
        ),
        (
            "v05",
            r#"{"cleanUrls": true, "trailingSlash": true}"#,
            [
                ("/page?q=1", 301, "/page/?q=1", ""),
                ("/page/?q=1", 200, "", PAGE),
                ("/page.html?q=1", 301, "/page/?q=1", ""),
                ("/dir?q=1", 301, "/dir/?q=1", ""),
                ("/dir/?q=1", 200, "", DIRECTORY),
                ("/dir/index.html?q=1", 301, "/dir/?q=1", ""),
                ("/", 200, "", HOME),
            ],
        ),
        (
            "v06",
            r#"{"cleanUrls": true, "trailingSlash": false}"#,
            [
                ("/page?q=1", 200, "", PAGE),
                ("/page/?q=1", 301, "/page?q=1", ""),
                ("/page.html?q=1", 301, "/page?q=1", ""),
                ("/dir?q=1", 200, "", DIRECTORY),
                ("/dir/?q=1", 301, "/dir?q=1", ""),
                ("/dir/index.html?q=1", 301, "/dir?q=1", ""),
                ("/", 200, "", HOME),
            ],
        ),
    ];
    for (version, config, rows) in tables {
        let strict = site(
            &format!("clean-{version}"),
            "strict",
            &json(config),
            CLEAN_FILES,
        );
        for (target, status, location, body) in rows {
            let reply = get(&strict, target);
            assert_eq!(reply.status, status, "{version} {target}");
            assert_eq!(
                reply.header("location").unwrap_or(""),
                location,
                "{version} {target}"
            );
            if status == 200 {
                assert_eq!(reply.body, body, "{version} {target}");
            }
        }
    }
}

/// Function and Cloud Run rewrites are not compared with production (owner ledger 2435) and answer
/// as before in both profiles: 503 without a Functions runtime.
#[test]
fn hosting_strict_function_and_run_rewrites_are_unchanged() {
    let config = json(
        r#"{"rewrites": [
            {"source": "/fn/**", "function": "api"},
            {"source": "/run/**", "run": {"serviceId": "api"}}
        ]}"#,
    );
    for profile in ["strict", "exact", "emulator"] {
        let site = site(&format!("rewrites-{profile}"), profile, &config, FILES);
        for target in ["/fn/x", "/run/x"] {
            let reply = get(&site, target);
            assert_eq!(reply.status, 503, "{profile} {target}");
            assert_eq!(
                reply.body,
                "Hosting rewrite requires a registered local Functions runtime"
            );
        }
    }
}

// ---- the development defaults of the default profile (`hosting.cacheControl`, `hosting.clientCountry`)

#[test]
fn hosting_strict_the_default_profile_keeps_edits_visible_and_the_country_testable() {
    let config = json(r#"{"i18n": {"root": "locales"}}"#);
    let default = site("defaults", "strict", &config, LOCALES);
    // no default Cache-Control: an edited file shows at once (the official emulator's answer)
    let reply = send(&default, "GET", "/page.html", &[("Accept-Language", "fr")]);
    assert_eq!(reply.header("cache-control"), None);
    // the rest is production's: Vary, Accept-Ranges, a quoted ETag, quality values
    assert_eq!(
        reply.header("vary"),
        Some("accept-language, x-country-code, x-fh-requested-host, accept-encoding")
    );
    assert_eq!(reply.header("accept-ranges"), Some("bytes"));
    assert!(reply.header("etag").is_some_and(|tag| tag.starts_with('"')));
    let page = |headers: &[(&str, &str)]| send(&default, "GET", "/page.html", headers).body;
    assert_eq!(page(&[("Accept-Language", "de;q=0.9, fr;q=0.8")]), "fr\n");
    // the country a client sends selects content, as in the official emulator
    assert_eq!(
        page(&[("Accept-Language", "fr"), ("X-Country-Code", "CA")]),
        "fr_ca\n"
    );
    assert_eq!(page(&[("X-Country-Code", "CA")]), "all_ca\n");
    assert_eq!(
        page(&[("Cookie", "firebase-country-override=CA")]),
        "all_ca\n"
    );
    // a rule's Cache-Control still applies
    let ruled = site(
        "defaults-rule",
        "strict",
        &json(
            r#"{"headers": [{"source": "/**", "headers": [{"key": "Cache-Control", "value": "no-store"}]}]}"#,
        ),
        FILES,
    );
    assert_eq!(get(&ruled, "/").header("cache-control"), Some("no-store"));
}

#[test]
fn hosting_strict_production_exact_restores_production_and_each_key_can_be_set_alone() {
    let config = json(r#"{"i18n": {"root": "locales"}}"#);
    let exact = site("exact-defaults", "exact", &config, LOCALES);
    assert_eq!(
        get(&exact, "/page.html").header("cache-control"),
        Some("max-age=3600")
    );
    assert_eq!(
        send(&exact, "GET", "/page.html", &[("X-Country-Code", "CA")]).body,
        "default\n"
    );
    // an explicit key wins over productionExact, in both directions
    let document = json(
        r#"{"schemaVersion": 1, "profile": "strict", "productionExact": true,
            "hosting": {"cacheControl": "none", "clientCountry": "honoured"}}"#,
    );
    let explicit = site_with("explicit-open", &document, &config, LOCALES);
    assert_eq!(get(&explicit, "/page.html").header("cache-control"), None);
    assert_eq!(
        send(&explicit, "GET", "/page.html", &[("X-Country-Code", "CA")]).body,
        "all_ca\n"
    );
    let document = json(
        r#"{"schemaVersion": 1, "profile": "strict",
            "hosting": {"cacheControl": "production", "clientCountry": "ignored"}}"#,
    );
    let explicit = site_with("explicit-closed", &document, &config, LOCALES);
    assert_eq!(
        get(&explicit, "/page.html").header("cache-control"),
        Some("max-age=3600")
    );
    assert_eq!(
        send(&explicit, "GET", "/page.html", &[("X-Country-Code", "CA")]).body,
        "default\n"
    );
    // the emulator profile never adds the header and always honours the country
    let emulator = site("emulator-defaults", "emulator", &config, LOCALES);
    assert_eq!(get(&emulator, "/page.html").header("cache-control"), None);
    assert_eq!(
        send(&emulator, "GET", "/page.html", &[("X-Country-Code", "CA")]).body,
        "all_ca\n"
    );
}

// ---- path confinement under every profile (the fixture of conformance/hosting-fixtures)

const SENTINEL: &str = "HOSTING_PRIVATE_OUTSIDE_SENTINEL";

fn outside_site(name: &str, profile: &str, config: &serde_json::Value) -> Site {
    let hosting = site(
        name,
        profile,
        config,
        &[
            ("index.html", "home\n"),
            ("data.json", "{}\n"),
            ("firebase-debug.log", "debug-log-bytes"),
            ("private.json", "private-bytes"),
        ],
    );
    std::fs::write(hosting.dir.join("outside.txt"), SENTINEL).unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(
        "../outside.txt",
        hosting.dir.join("public/outside-link.txt"),
    )
    .unwrap();
    hosting
}

#[test]
fn hosting_strict_nothing_outside_public_or_ignored_is_served_by_any_profile() {
    let config = json(
        r#"{"ignore": ["private.json"], "rewrites": [{"source": "/rewritten", "destination": "/private.json"}]}"#,
    );
    // the request list is the probe of the closure review plus the fixture's security cases
    let targets = [
        "/../outside.txt",
        "/%2e%2e/outside.txt",
        "/..%2foutside.txt",
        "/%252e%252e/outside.txt",
        "/..%5coutside.txt",
        "/%2e%2e%2foutside.txt",
        "/sub/..%2f..%2foutside.txt",
        "/data.json%00",
        "/%GG",
        "/outside-link.txt",
        "/private.json",
        "/firebase-debug.log",
        "/rewritten",
    ];
    for profile in ["strict", "exact", "emulator"] {
        let hosting = outside_site(&format!("outside-{profile}"), profile, &config);
        for target in targets {
            for (method, headers) in [
                ("GET", vec![]),
                ("HEAD", vec![]),
                ("OPTIONS", vec![]),
                ("GET", vec![("Range", "bytes=0-")]),
                ("GET", vec![("Range", "bytes=-10")]),
                ("GET", vec![("If-None-Match", "*")]),
            ] {
                let reply = send(&hosting, method, target, &headers);
                let all = format!("{}\r\n\r\n{}", reply.head, reply.body);
                for secret in [SENTINEL, "debug-log-bytes", "private-bytes"] {
                    assert!(
                        !all.contains(secret),
                        "{profile} {method} {target} {headers:?} leaked {secret}: {all}"
                    );
                }
            }
        }
    }
}

/// `v01.safety-parent`, `-encoded-parent` and the `v11.dot-*` rows: production answers a request
/// with dot segments with a `302` to the normalized path on its content origin (a host that differs
/// per request); strict answers the `302` with the normalized path after the host the request came to.
#[test]
fn hosting_strict_a_request_with_dot_segments_is_a_302_to_the_normalized_path() {
    let hosting = outside_site("climb", "exact", &json("{}"));
    let at = |path: &str| format!("http://{}{path}", hosting.address);
    for target in [
        "/../outside.txt",
        "/%2e%2e/outside.txt",
        "/%2E%2e/outside.txt",
        "/a/../../outside.txt",
    ] {
        let reply = get(&hosting, target);
        assert_eq!(reply.status, 302, "{target}");
        assert_eq!(
            reply.header("location"),
            Some(at("/outside.txt").as_str()),
            "{target}"
        );
        assert_eq!(reply.header("cache-control"), Some("private"));
        assert_eq!(
            reply.header("content-type"),
            Some("text/html; charset=UTF-8")
        );
        assert_eq!(reply.header("content-length"), Some("0"));
        assert_eq!(reply.header("accept-ranges"), Some("bytes"));
        assert_eq!(reply.header("vary"), None);
        assert_eq!(reply.body, "");
        // and what the redirect points at is not a file of the site
        let followed = get(&hosting, "/outside.txt");
        assert_eq!(followed.status, 404, "{target}");
        assert!(!followed.body.contains(SENTINEL));
    }
    // the query stays, a trailing slash stays
    assert_eq!(
        get(&hosting, "/../index.html?x=1").header("location"),
        Some(at("/index.html?x=1").as_str())
    );
    assert_eq!(
        get(&hosting, "/a/../b/").header("location"),
        Some(at("/b/").as_str())
    );
    // the follow-up rows v11.dot-*: RFC 3986, a path that ends in a dot segment ends in a slash
    for (target, expected) in [
        ("/a/b/..", "/a/"),
        ("/a/./b", "/a/b"),
        ("/a/b/.", "/a/b/"),
        ("/a/.", "/a/"),
        ("/a/..", "/"),
        ("/a/../a/b", "/a/b"),
        ("/./a/b", "/a/b"),
        ("/a/%2e/b", "/a/b"),
        ("/a/b/%2e%2e", "/a/"),
        ("/a/b/../", "/a/"),
        ("/a/./b/", "/a/b/"),
    ] {
        let reply = get(&hosting, target);
        assert_eq!(reply.status, 302, "{target}");
        assert_eq!(
            reply.header("location"),
            Some(at(expected).as_str()),
            "{target}"
        );
    }
    // a name that merely contains dots is not a dot segment
    assert_eq!(get(&hosting, "/..data.json").status, 404);
    // the emulator profile keeps refusing with 404
    let emulator = outside_site("climb-emulator", "emulator", &json("{}"));
    assert_eq!(get(&emulator, "/../outside.txt").status, 404);
}

#[test]
fn hosting_strict_a_range_is_streamed_whatever_the_size_of_the_file() {
    let hosting = site("big-range", "exact", &json("{}"), &[("index.html", "x")]);
    // a 16 MiB sparse file, `bytes=0-`: the reply is the whole file as 206 and the server never
    // holds it (the frames are bounded: files::tests::a_range_of_an_asset_is_streamed_...)
    let big = hosting.dir.join("public/big.bin");
    std::fs::File::create(&big)
        .unwrap()
        .set_len(16 * 1024 * 1024)
        .unwrap();
    let reply = send_within(
        &hosting,
        "GET",
        "/big.bin",
        &[("Range", "bytes=0-")],
        LARGE_FILE_PATIENCE,
    );
    assert_eq!(reply.status, 206);
    assert_eq!(
        reply.header("content-range"),
        Some("bytes 0-16777215/16777216")
    );
    assert_eq!(reply.header("content-length"), Some("16777216"));
    let tail = send_within(
        &hosting,
        "GET",
        "/big.bin",
        &[("Range", "bytes=-5")],
        LARGE_FILE_PATIENCE,
    );
    assert_eq!((tail.status, tail.body.len()), (206, 5));
    assert_eq!(
        tail.header("content-range"),
        Some("bytes 16777211-16777215/16777216")
    );
    // HEAD with a range names the part and sends nothing
    let head = send_within(
        &hosting,
        "HEAD",
        "/big.bin",
        &[("Range", "bytes=10-19")],
        LARGE_FILE_PATIENCE,
    );
    assert_eq!((head.status, head.body.as_str()), (206, ""));
    assert_eq!(head.header("content-length"), Some("10"));
}

/// The follow-up rows `v11.backslash-*`: production reads a raw `\\` as `/` before it looks for dot
/// segments, and redirects only when there is one. The `Location` is an absolute URL on the origin
/// the request came to, so `//evil` and `/a//evil.example` are paths and name no other host.
#[test]
fn hosting_strict_a_backslash_next_to_a_dot_segment_is_a_slash() {
    for profile in ["strict", "exact"] {
        let hosting = outside_site(&format!("backslash-{profile}"), profile, &json("{}"));
        let at = |path: &str| format!("http://{}{path}", hosting.address);
        for (target, expected) in [
            ("/a/./\\evil.example", "/a//evil.example"),
            ("/.\\b", "/b"),
            ("/./\\evil", "//evil"),
            ("/a/./%5cevil.example", "/a/%5Cevil.example"),
            ("/a/../\\\\evil.example/", "///evil.example/"),
            ("/./%5c%5cevil.example", "/%5C%5Cevil.example"),
            ("/./%2f%2fevil.example", "/%2F%2Fevil.example"),
            ("/.//evil.example", "//evil.example"),
            ("/..//evil.example", "//evil.example"),
        ] {
            let reply = get(&hosting, target);
            assert_eq!(reply.status, 302, "{profile} {target}");
            let location = reply.header("location").unwrap();
            assert_eq!(location, at(expected), "{profile} {target}");
            // whatever the path, the authority is the origin the request came to
            assert!(
                location.starts_with(&format!("http://{}/", hosting.address)),
                "{profile} {target}: {location}"
            );
            assert!(!location.contains('\\'), "{location}");
        }
        // no dot segment: no redirect, the default page (v11.backslash-mid, -in-name)
        for target in ["/a\\b", "/a/\\b"] {
            let reply = get(&hosting, target);
            assert_eq!(reply.status, 404, "{profile} {target}");
            assert_eq!(reply.header("location"), None, "{profile} {target}");
            assert!(reply.body.contains("404 Not Found"), "{profile} {target}");
        }
    }
    // the emulator profile never leaves the origin either: a relative `Location` that starts with a
    // single slash, or none
    let emulator = outside_site("backslash-emulator", "emulator", &json("{}"));
    for target in [
        "/./\\evil.example",
        "/.\\b",
        "/./\\evil",
        "/a/./%5cevil.example",
    ] {
        let reply = get(&emulator, target);
        if let Some(location) = reply.header("location") {
            assert!(location.starts_with('/'), "{target}: {location}");
            assert!(
                !location.starts_with("//") && !location.contains('\\'),
                "{target}: {location}"
            );
        }
    }
}

const BIG: &str = "The quick brown fox jumps over the lazy dog.\n";

fn gunzip(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(bytes)
        .read_to_end(&mut out)
        .expect("a gzip body");
    out
}

/// Rows `v01.gz-*` of the production recording: gzip when the request holds `gzip`, the file's own
/// `ETag`, the same `Vary`, and a tiny file left alone.
#[test]
fn hosting_strict_gzip_answers_as_the_recorded_rows() {
    let big = BIG.repeat(100);
    for profile in ["strict", "exact"] {
        let hosting = site(
            "gzip-rows",
            profile,
            &json("{}"),
            &[
                ("compress/big.txt", &big),
                ("compress/big.json", &big),
                ("ct/file.png", "x\n"),
                ("index.html", "x"),
            ],
        );
        let plain = get(&hosting, "/compress/big.txt");
        assert_eq!(plain.header("content-encoding"), None, "{profile} gz-none");
        assert_eq!(plain.header("content-length"), Some("4500"));
        let etag = plain.header("etag").unwrap().to_owned();
        assert!(etag.starts_with('"') && !etag.contains("-gzip"), "{etag}");
        let identity = send(
            &hosting,
            "GET",
            "/compress/big.txt",
            &[("Accept-Encoding", "identity")],
        );
        assert_eq!(identity.header("content-encoding"), None, "gz-identity");
        assert_eq!(identity.body, big);
        // production answers `br` to the two forms that name it; strict has no Brotli and answers gzip
        for (row, target, accept) in [
            ("gz-gzip", "/compress/big.txt", "gzip"),
            ("gz-gzip-br", "/compress/big.txt", "gzip, br"),
            ("gz-br-refused", "/compress/big.txt", "br;q=0, gzip"),
            ("gz-json-gzip", "/compress/big.json", "gzip"),
        ] {
            let reply = send(&hosting, "GET", target, &[("Accept-Encoding", accept)]);
            assert_eq!(reply.status, 200, "{profile} {row}");
            assert_eq!(reply.header("content-encoding"), Some("gzip"), "{row}");
            assert_eq!(
                reply.header("vary"),
                Some("x-fh-requested-host, accept-encoding"),
                "{row}"
            );
            assert_eq!(reply.header("etag"), Some(etag.as_str()), "{row}");
            // a known type stays what it is once compressed
            assert_eq!(
                reply.header("content-type"),
                Some(
                    if std::path::Path::new(target)
                        .extension()
                        .is_some_and(|extension| extension == "json")
                    {
                        "application/json"
                    } else {
                        "text/plain; charset=utf-8"
                    }
                ),
                "{row}"
            );
            assert_eq!(reply.header("accept-ranges"), Some("bytes"), "{row}");
            // the recorded answer is 93 bytes; the length names the body that follows
            assert_eq!(reply.header("content-length"), Some("93"), "{row}");
            assert_eq!(reply.bytes.len(), 93, "{row}");
            assert_eq!(gunzip(&reply.bytes), big.as_bytes(), "{row}");
        }
        assert_eq!(
            send(
                &hosting,
                "GET",
                "/compress/big.json",
                &[("Accept-Encoding", "gzip")]
            )
            .header("content-type"),
            Some("application/json")
        );
        assert_eq!(
            get(&hosting, "/compress/big.txt").header("content-type"),
            Some("text/plain; charset=utf-8")
        );
        // gz-head-gzip: the head of the gzip answer, with its length and no body
        let head = send(
            &hosting,
            "HEAD",
            "/compress/big.txt",
            &[("Accept-Encoding", "gzip")],
        );
        assert_eq!(
            head.header("content-encoding"),
            Some("gzip"),
            "gz-head-gzip"
        );
        assert_eq!(head.header("content-length"), Some("93"));
        assert_eq!(head.bytes, [] as [u8; 0]);
        // gz-png-gzip: two bytes are left alone (the compressed body would be larger)
        let png = send(
            &hosting,
            "GET",
            "/ct/file.png",
            &[("Accept-Encoding", "gzip")],
        );
        assert_eq!(png.header("content-encoding"), None, "gz-png-gzip");
        assert_eq!(png.header("content-length"), Some("2"));
        assert_eq!(
            png.header("vary"),
            Some("x-fh-requested-host, accept-encoding")
        );
    }
}

/// The rows `v15.ae-*`: production looks for the text `gzip` in `Accept-Encoding` as a plain,
/// case-sensitive substring, and reads no quality.
#[test]
fn hosting_strict_gzip_is_decided_by_the_text_gzip_in_accept_encoding() {
    let big = BIG.repeat(100);
    let hosting = site(
        "gzip-forms",
        "exact",
        &json("{}"),
        &[("big.txt", &big), ("index.html", "x")],
    );
    for accept in ["br", "*", "deflate", "identity", "GZIP", "Gzip", "zip", ""] {
        let reply = send(&hosting, "GET", "/big.txt", &[("Accept-Encoding", accept)]);
        assert_eq!(reply.header("content-encoding"), None, "{accept:?}");
        assert_eq!(reply.header("content-length"), Some("4500"), "{accept:?}");
        assert_eq!(reply.body, big, "{accept:?}");
    }
    for accept in ["gzip", "x-gzip", "gzip;q=0", "gzip, deflate, br", "xgzip"] {
        let reply = send(&hosting, "GET", "/big.txt", &[("Accept-Encoding", accept)]);
        assert_eq!(reply.header("content-encoding"), Some("gzip"), "{accept:?}");
        assert_eq!(gunzip(&reply.bytes), big.as_bytes(), "{accept:?}");
    }
}

/// Conditional requests, ranges and error pages with gzip accepted.
#[test]
fn hosting_strict_gzip_with_conditions_ranges_and_pages() {
    let big = BIG.repeat(100);
    let hosting = site(
        "gzip-conditions",
        "exact",
        &json("{}"),
        &[("big.txt", &big), ("404.html", &big), ("index.html", "x")],
    );
    let gzip = [("Accept-Encoding", "gzip")];
    let full = send(&hosting, "GET", "/big.txt", &gzip);
    let etag = full.header("etag").unwrap().to_owned();
    // v15.ae-cond: a matching tag is 304 with no body: the tag is the file's, whatever the coding
    let not_modified = send(
        &hosting,
        "GET",
        "/big.txt",
        &[("Accept-Encoding", "gzip"), ("If-None-Match", &etag)],
    );
    assert_eq!(not_modified.status, 304);
    assert_eq!(not_modified.header("content-encoding"), None);
    assert_eq!(not_modified.bytes, [] as [u8; 0]);
    // v15.ae-range: a range is taken over the compressed body: 206, `Content-Encoding: gzip`, the
    // range of the 93 bytes
    let part = send(
        &hosting,
        "GET",
        "/big.txt",
        &[("Accept-Encoding", "gzip"), ("Range", "bytes=0-9")],
    );
    assert_eq!(part.status, 206);
    assert_eq!(part.header("content-encoding"), Some("gzip"));
    assert_eq!(part.header("content-range"), Some("bytes 0-9/93"));
    assert_eq!(part.header("content-length"), Some("10"));
    assert_eq!(part.bytes, &full.bytes[..10]);
    assert_eq!(part.header("etag"), Some(etag.as_str()));
    let tail = send(
        &hosting,
        "GET",
        "/big.txt",
        &[("Accept-Encoding", "gzip"), ("Range", "bytes=-5")],
    );
    assert_eq!(tail.header("content-range"), Some("bytes 88-92/93"));
    assert_eq!(tail.bytes, &full.bytes[88..]);
    // a start beyond the compressed body is unsatisfiable on it
    let beyond = send(
        &hosting,
        "GET",
        "/big.txt",
        &[("Accept-Encoding", "gzip"), ("Range", "bytes=1000-")],
    );
    assert_eq!(beyond.status, 416);
    assert_eq!(beyond.header("content-range"), Some("bytes */93"));
    assert_eq!(beyond.header("content-encoding"), None);
    // a start past the file itself is unsatisfiable over the file: identity, `*/<file length>`
    // (inferred, not recorded: only `bytes=0-9` was)
    let past_file = send(
        &hosting,
        "GET",
        "/big.txt",
        &[("Accept-Encoding", "gzip"), ("Range", "bytes=9999-")],
    );
    assert_eq!(past_file.status, 416);
    assert_eq!(past_file.header("content-range"), Some("bytes */4500"));
    assert_eq!(past_file.header("content-encoding"), None);
    // HEAD with a range names the part and sends nothing
    let head = send(
        &hosting,
        "HEAD",
        "/big.txt",
        &[("Accept-Encoding", "gzip"), ("Range", "bytes=0-9")],
    );
    assert_eq!((head.status, head.bytes.len()), (206, 0));
    assert_eq!(head.header("content-length"), Some("10"));
    // without gzip the range is over the file, as before
    let plain = send(&hosting, "GET", "/big.txt", &[("Range", "bytes=0-9")]);
    assert_eq!(plain.header("content-range"), Some("bytes 0-9/4500"));
    assert_eq!(plain.header("content-encoding"), None);
    assert_eq!(plain.body, &big[..10]);
    // the 404 page is a file and is compressed like any other
    let missing = send(&hosting, "GET", "/nope", &gzip);
    assert_eq!(missing.status, 404);
    assert_eq!(missing.header("content-encoding"), Some("gzip"));
    assert_eq!(gunzip(&missing.bytes), big.as_bytes());
    // an answer production generates, not a file, is not compressed
    let redirect_site = site(
        "gzip-generated",
        "exact",
        &json(r#"{"redirects":[{"source":"/old","destination":"/big.txt","type":301}]}"#),
        &[("big.txt", &big), ("index.html", "x")],
    );
    let redirect = send(&redirect_site, "GET", "/old", &gzip);
    assert_eq!(redirect.status, 301);
    assert_eq!(redirect.header("content-encoding"), None);
}

/// The emulator profile answers as the pinned oracle does and never compresses.
#[test]
fn hosting_strict_emulator_profile_never_gzips() {
    let big = BIG.repeat(100);
    let hosting = site(
        "gzip-emulator",
        "emulator",
        &json("{}"),
        &[("big.txt", &big), ("index.html", "x")],
    );
    let reply = send(
        &hosting,
        "GET",
        "/big.txt",
        &[("Accept-Encoding", "gzip, br")],
    );
    assert_eq!(reply.header("content-encoding"), None);
    assert_eq!(reply.header("content-length"), Some("4500"));
    assert_eq!(reply.body, big);
}

/// A file above the limit is answered as identity rather than held in memory.
#[test]
fn hosting_strict_a_file_above_the_gzip_limit_is_identity() {
    let hosting = site("gzip-limit", "exact", &json("{}"), &[("index.html", "x")]);
    let path = hosting.dir.join("public/huge.txt");
    std::fs::File::create(&path)
        .unwrap()
        .set_len(32 * 1024 * 1024 + 1)
        .unwrap();
    // `huge.txt` is above the limit: no gzip is decided, so the body is never packed; the one read of
    // the file is the one every request makes for its `ETag`
    let head = send_within(
        &hosting,
        "HEAD",
        "/huge.txt",
        &[("Accept-Encoding", "gzip")],
        LARGE_FILE_PATIENCE,
    );
    assert_eq!(head.header("content-encoding"), None);
    assert_eq!(head.header("content-length"), Some("33554433"));
}

/// The rows `v15.size-*` and `v15.type-*`: any content type is compressed when the compressed body
/// is smaller (an image, a zip and a font as well as text); a file of 1 or 10 bytes and an empty
/// file are not. A file with no known type is `text/html; charset=UTF-8` once compressed.
#[test]
fn hosting_strict_gzip_follows_the_size_and_not_the_type() {
    let big = BIG.repeat(100);
    let hosting = site(
        "gzip-types",
        "exact",
        &json("{}"),
        &[
            ("index.html", &big),
            ("notes", &big),
            ("data.unknownext", &big),
            ("image.png", &big),
            ("archive.zip", &big),
            ("font.woff2", &big),
            ("empty.txt", ""),
            ("sz/s0001.txt", "T"),
            ("sz/s0010.txt", "The quick "),
            ("sz/s0100.txt", &big[..100]),
        ],
    );
    let get_gzip = |target: &str| send(&hosting, "GET", target, &[("Accept-Encoding", "gzip")]);
    for target in [
        "/",
        "/notes",
        "/data.unknownext",
        "/image.png",
        "/archive.zip",
        "/font.woff2",
    ] {
        let reply = get_gzip(target);
        assert_eq!(reply.header("content-encoding"), Some("gzip"), "{target}");
        assert_eq!(gunzip(&reply.bytes), big.as_bytes(), "{target}");
    }
    // the types stay those of the files, except that of a file with no known one
    assert_eq!(
        get_gzip("/image.png").header("content-type"),
        Some("image/png")
    );
    assert_eq!(
        get_gzip("/archive.zip").header("content-type"),
        Some("application/zip")
    );
    assert_eq!(
        get_gzip("/font.woff2").header("content-type"),
        Some("font/woff2")
    );
    assert_eq!(
        get_gzip("/").header("content-type"),
        Some("text/html; charset=utf-8")
    );
    assert_eq!(
        get_gzip("/notes").header("content-type"),
        Some("text/html; charset=UTF-8")
    );
    assert_eq!(
        get_gzip("/data.unknownext").header("content-type"),
        Some("text/html; charset=UTF-8")
    );
    // without compression a file with no known type is still `text/plain` (v01.ct-noext)
    let plain = get(&hosting, "/notes");
    assert_eq!(
        plain.header("content-type"),
        Some("text/plain; charset=utf-8")
    );
    assert_eq!(plain.header("content-encoding"), None);
    // sizes: 1 and 10 bytes stay, 100 bytes is compressed; an empty file stays
    for (target, encoded) in [
        ("/sz/s0001.txt", false),
        ("/sz/s0010.txt", false),
        ("/sz/s0100.txt", true),
        ("/empty.txt", false),
    ] {
        let reply = get_gzip(target);
        assert_eq!(
            reply.header("content-encoding").is_some(),
            encoded,
            "{target}"
        );
    }
    assert_eq!(
        get_gzip("/sz/s0001.txt").header("content-length"),
        Some("1")
    );
    // and a gzip answer of the file is never larger than the file
    let hundred = get_gzip("/sz/s0100.txt");
    assert!(hundred.bytes.len() < 100, "{}", hundred.bytes.len());
}

/// An unknown type becomes `text/html; charset=UTF-8` once compressed only when fireemu chose the
/// type: a `Content-Type` that a `headers` rule sets is never rewritten, whatever its value (even the
/// one fireemu would have chosen itself).
#[test]
fn hosting_strict_a_content_type_set_by_a_rule_is_never_rewritten_when_compressed() {
    let big = BIG.repeat(100);
    let rules = json(
        r#"{"headers": [
            {"source": "/same", "headers": [{"key": "Content-Type", "value": "text/plain; charset=utf-8"}]},
            {"source": "/other", "headers": [{"key": "content-type", "value": "application/x-fixture"}]},
            {"source": "/html", "headers": [{"key": "Content-Type", "value": "text/html; charset=UTF-8"}]},
            {"source": "/known.txt", "headers": [{"key": "Content-Type", "value": "text/plain; charset=utf-8"}]},
            {"source": "/rule-elsewhere/**", "headers": [{"key": "X-Fixture", "value": "1"}]}
        ]}"#,
    );
    for profile in ["strict", "exact"] {
        let hosting = site(
            "gzip-type-rule",
            profile,
            &rules,
            &[
                ("same", &big),
                ("other", &big),
                ("html", &big),
                ("free", &big),
                ("known.txt", &big),
                ("index.html", "x"),
            ],
        );
        let gzip = [("Accept-Encoding", "gzip")];
        let type_of = |target: &str| {
            let reply = send(&hosting, "GET", target, &gzip);
            assert_eq!(reply.header("content-encoding"), Some("gzip"), "{target}");
            reply.header("content-type").map(str::to_owned)
        };
        // the rule sets the value fireemu would have chosen: it stays
        assert_eq!(
            type_of("/same").as_deref(),
            Some("text/plain; charset=utf-8")
        );
        assert_eq!(type_of("/other").as_deref(), Some("application/x-fixture"));
        assert_eq!(
            type_of("/html").as_deref(),
            Some("text/html; charset=UTF-8")
        );
        assert_eq!(
            type_of("/known.txt").as_deref(),
            Some("text/plain; charset=utf-8")
        );
        // no rule: fireemu's own default is rewritten, as recorded
        assert_eq!(
            type_of("/free").as_deref(),
            Some("text/html; charset=UTF-8")
        );
        // uncompressed, the same rule gives the same value
        let plain = send(&hosting, "GET", "/same", &[]);
        assert_eq!(
            plain.header("content-type"),
            Some("text/plain; charset=utf-8")
        );
    }
}

/// The rows `v14.*`: production does not serve a `Content-Encoding` that a `headers` rule sets. A
/// precompressed file (a `*.br`, `*.gz` or script of already packed bytes) is sent as it is because
/// compressing it again does not make it smaller; a text file with the rule `identity` or `br` is
/// compressed like any other. A `.br` file is `application/octet-stream`.
#[test]
fn hosting_strict_a_content_encoding_rule_is_never_served() {
    let big = BIG.repeat(100);
    // bytes that do not compress: a fixed pseudo-random run
    let packed = |length: usize| {
        let mut state = 0x9e37_79b9_u32;
        (0..length)
            .map(|_| {
                state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                (state >> 24) as u8
            })
            .collect::<Vec<u8>>()
    };
    let rules = json(
        r#"{"headers": [
            {"source": "/pre/*.br", "headers": [{"key": "Content-Encoding", "value": "br"}]},
            {"source": "/pre/*.gz", "headers": [{"key": "Content-Encoding", "value": "gzip"}]},
            {"source": "/pre/script.js", "headers": [{"key": "content-ENCODING", "value": "gzip"}]},
            {"source": "/pre/plain.txt", "headers": [{"key": "Content-Encoding", "value": "identity"}]},
            {"source": "/pre/shout.txt", "headers": [{"key": "CONTENT-ENCODING", "value": "BR"}]},
            {"source": "**", "headers": [{"key": "X-Fixture", "value": "all"}]}
        ]}"#,
    );
    for profile in ["strict", "exact"] {
        let hosting = site(
            "gzip-rule",
            profile,
            &rules,
            &[
                ("pre/plain.txt", &big),
                ("pre/shout.txt", &big),
                ("pre/free.txt", &big),
                ("index.html", "x"),
            ],
        );
        for (name, bytes) in [
            ("pre/big.txt.br", packed(61)),
            ("pre/big.txt.gz", packed(93)),
            ("pre/script.js", packed(93)),
        ] {
            std::fs::write(hosting.dir.join("public").join(name), bytes).unwrap();
        }
        let browser = [("Accept-Encoding", "gzip, deflate, br")];
        for (target, length, content_type) in [
            ("/pre/big.txt.br", "61", "application/octet-stream"),
            ("/pre/big.txt.gz", "93", "application/gzip"),
            ("/pre/script.js", "93", "text/javascript; charset=utf-8"),
        ] {
            for headers in [&browser[..], &[("Accept-Encoding", "gzip")][..], &[][..]] {
                let reply = send(&hosting, "GET", target, headers);
                assert_eq!(reply.status, 200, "{profile} {target}");
                assert_eq!(reply.header("content-encoding"), None, "{profile} {target}");
                assert_eq!(reply.header("content-length"), Some(length), "{target}");
                assert_eq!(reply.header("content-type"), Some(content_type), "{target}");
                assert_eq!(reply.header("x-fixture"), Some("all"));
            }
            let head = send(&hosting, "HEAD", target, &[("Accept-Encoding", "gzip")]);
            assert_eq!(head.header("content-encoding"), None, "HEAD {target}");
            assert_eq!(head.header("content-length"), Some(length), "HEAD {target}");
        }
        // the rule's value is ignored, whatever it is, and the text is compressed
        for target in ["/pre/plain.txt", "/pre/shout.txt", "/pre/free.txt"] {
            let reply = send(&hosting, "GET", target, &browser);
            assert_eq!(
                reply.header("content-encoding"),
                Some("gzip"),
                "{profile} {target}"
            );
            assert_eq!(gunzip(&reply.bytes), big.as_bytes(), "{target}");
        }
        // without `gzip` in the request the text is as it is, and still has no encoding header
        let plain = send(&hosting, "GET", "/pre/plain.txt", &[]);
        assert_eq!(plain.header("content-encoding"), None);
        assert_eq!(plain.body, big);
    }
}

/// Every `Accept-Encoding` line of a request is one list; the text `gzip` on any line is enough.
#[test]
fn hosting_strict_gzip_reads_every_accept_encoding_line() {
    let big = BIG.repeat(100);
    let hosting = site(
        "gzip-lines",
        "exact",
        &json("{}"),
        &[("big.txt", &big), ("index.html", "x")],
    );
    for (lines, gzipped) in [
        (vec!["br", "gzip"], true),
        (vec!["deflate", "gzip;q=0.5"], true),
        (vec!["gzip;q=0", "identity"], true),
        (vec!["br", "deflate"], false),
        (vec!["br", "GZIP"], false),
    ] {
        let headers: Vec<(&str, &str)> = lines
            .iter()
            .map(|line| ("Accept-Encoding", *line))
            .collect();
        let reply = send(&hosting, "GET", "/big.txt", &headers);
        assert_eq!(
            reply.header("content-encoding").is_some(),
            gzipped,
            "{lines:?}"
        );
    }
}

/// How long a request for a 16 or 32 MiB file may take (see [`send_within`]).
const LARGE_FILE_PATIENCE: Duration = Duration::from_secs(600);

/// The follow-up rows `v11.default-404*` and `v11.auth-handler*`: strict answers with status,
/// content type, cache control and `Vary` as production did, and with pages written for fireemu (the
/// owner decided not to ship production's own page bytes: the bodies are known differences). The
/// pages say what they are and do not imitate the hosted ones.
#[test]
fn hosting_strict_the_default_404_page_and_the_auth_handler_are_fireemu_pages() {
    for profile in ["strict", "exact"] {
        let hosting = site("pages", profile, &json("{}"), &[("index.html", "x")]);
        let mut seen = Vec::new();
        // v11.default-404, -json, -nested, v11.backslash-mid, -in-name: the same page for any path
        for target in [
            "/missing",
            "/missing.json",
            "/a/missing/deeper",
            "/a\\b",
            "/a/\\b",
        ] {
            let reply = get(&hosting, target);
            assert_eq!(reply.status, 404, "{profile} {target}");
            assert_eq!(
                reply.header("content-type"),
                Some("text/html; charset=utf-8")
            );
            assert_eq!(
                reply.header("content-length"),
                Some(reply.bytes.len().to_string().as_str()),
                "{target}"
            );
            assert!(reply.body.contains("404 Not Found"), "{target}");
            seen.push(reply.body);
        }
        assert!(seen.windows(2).all(|pair| pair[0] == pair[1]));
        let head = send(&hosting, "HEAD", "/missing", &[]);
        assert_eq!((head.status, head.bytes.len()), (404, 0));
        assert_eq!(
            head.header("content-length"),
            Some(seen[0].len().to_string().as_str())
        );
        // v11.auth-handler, -query
        let mut handler = Vec::new();
        for target in ["/__/auth/handler", "/__/auth/handler?mode=signIn"] {
            let reply = get(&hosting, target);
            assert_eq!(reply.status, 200, "{profile} {target}");
            assert_eq!(
                reply.header("content-type"),
                Some("text/html; charset=utf-8")
            );
            assert_eq!(reply.header("cache-control"), Some("max-age=1800"));
            assert_eq!(
                reply.header("content-length"),
                Some(reply.bytes.len().to_string().as_str())
            );
            assert!(reply.body.contains("local stand-in"));
            handler.push(reply.body);
        }
        assert_eq!(handler[0], handler[1]);
        let head = send(&hosting, "HEAD", "/__/auth/handler", &[]);
        assert_eq!((head.status, head.bytes.len()), (200, 0));
        assert_eq!(
            head.header("content-length"),
            Some(handler[0].len().to_string().as_str())
        );
        // neither page is the hosted one, nor says it is Firebase's
        for page in seen.iter().chain(handler.iter()) {
            let lower = page.to_ascii_lowercase();
            for word in ["firebase", "google", "fireauth", "roboto", "page not found"] {
                assert!(!lower.contains(word), "{word} in {page}");
            }
            assert!(page.len() < 1000);
        }
    }
    // the emulator profile keeps the pinned oracle's short page
    let emulator = site(
        "pages-emulator",
        "emulator",
        &json("{}"),
        &[("index.html", "x")],
    );
    let reply = get(&emulator, "/missing");
    assert_eq!(reply.status, 404);
    assert!(reply.bytes.len() < 1000 && reply.body.contains("Cannot GET /missing"));
}

/// The `Location` of a dot-segment redirect is an absolute URL on the `Host` of the request, so the
/// `Host` must be plain: a name or an address with a port. A `Host` with a `/`, `\`, `@`, `?`, `#`, a
/// space, a tab or an escape is refused (`400`; the host guard may refuse it first): never a redirect,
/// whatever the path.
#[test]
fn hosting_strict_a_host_that_is_not_plain_never_gets_a_redirect() {
    let hosting = outside_site("host-guard", "exact", &json("{}"));
    let patience = Duration::from_secs(30);
    let port = hosting.address.rsplit(':').next().unwrap().to_owned();
    for host in [
        format!("evil.example/{port}"),
        format!("127.0.0.1:{port}/evil"),
        format!("127.0.0.1:{port}@evil.example"),
        format!("evil.example\\@127.0.0.1:{port}"),
        format!("127.0.0.1:{port}?x"),
        format!("127.0.0.1:{port}#x"),
        format!("127.0.0.1:{port} evil.example"),
        format!("127.0.0.1:{port}\tx"),
        format!("127.0.0.1%2f:{port}"),
        "127.0.0.1:{port}".to_owned(),
        "ホスト".to_owned(),
    ] {
        for target in ["/../outside.txt", "/./\\evil", "/a/b/.."] {
            let reply = send_to_host(&hosting, &host, "GET", target, &[], patience);
            assert!(
                reply.header("location").is_none(),
                "{host:?} {target}: {:?}",
                reply.header("location")
            );
            assert!(
                [400, 403, 404].contains(&reply.status),
                "{host:?} {target}: {}",
                reply.status
            );
        }
    }
    // the same paths with the site's own host are the redirects
    for target in ["/../outside.txt", "/./\\evil", "/a/b/.."] {
        let reply = send_to_host(&hosting, &hosting.address, "GET", target, &[], patience);
        assert_eq!(reply.status, 302, "{target}");
        assert!(reply
            .header("location")
            .unwrap()
            .starts_with(&format!("http://{}/", hosting.address)));
    }
    // a name the guard admits is used as it is: `localhost` with the port
    let localhost = format!("localhost:{port}");
    let reply = send_to_host(&hosting, &localhost, "GET", "/a/./b", &[], patience);
    assert_eq!(reply.status, 302);
    assert_eq!(
        reply.header("location"),
        Some(format!("http://localhost:{port}/a/b").as_str())
    );
}

/// The follow-up rows `v12.*`: a redirect whose source has a digit in a `:name` matches nothing
/// (every request is the 404 page); `v13.*`: a repeated name matches, the last value wins.
#[test]
fn hosting_strict_a_digit_in_a_redirect_name_matches_nothing() {
    let rules = json(
        r#"{"redirects": [
            {"source": "/capture/:id/:id2", "destination": "/new/:id2/:id", "type": 301},
            {"source": "/p/:a1", "destination": "/to-p/:a1", "type": 302},
            {"source": "/s/:a1/x", "destination": "/to-s/:a1", "type": 302},
            {"source": "/t/:a1/:a2", "destination": "/to-t/:a2/:a1", "type": 302},
            {"source": "/q/:id/:id", "destination": "/to-q/:id", "type": 302}
        ]}"#,
    );
    for profile in ["strict", "exact"] {
        let hosting = site("digit-names", profile, &rules, &[("index.html", "x")]);
        for target in [
            "/capture/one/two2",
            "/capture/one/two",
            "/capture/x/:id2",
            "/capture/:id2/two",
            "/p/x",
            "/p/x1",
            "/p/:a1",
            "/s/v/x",
            "/s/:a1/x",
            "/t/u/v",
            "/t/1/2",
            "/q/a",
        ] {
            let reply = get(&hosting, target);
            assert_eq!(reply.status, 404, "{profile} {target}");
            assert_eq!(reply.header("location"), None, "{target}");
        }
        for (target, location) in [("/q/a/b", "/to-q/b"), ("/q/a/a", "/to-q/a")] {
            let reply = get(&hosting, target);
            assert_eq!(reply.status, 302, "{profile} {target}");
            assert_eq!(reply.header("location"), Some(location), "{target}");
        }
    }
    // the emulator profile reads a digit into the name, as the pinned oracle does
    let emulator = site(
        "digit-names-emulator",
        "emulator",
        &rules,
        &[("index.html", "x")],
    );
    assert_eq!(get(&emulator, "/p/x").header("location"), Some("/to-p/x"));
}
