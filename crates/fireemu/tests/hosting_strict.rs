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
    _dir: Scratch,
    _child: OwnedChild,
    address: String,
}

/// A site of `files` under `config`, served by the profile named (`strict` or `emulator`).
fn site(name: &str, profile: &str, config: &serde_json::Value, files: &[(&str, &str)]) -> Site {
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
    std::fs::write(
        dir.join("fireemu.json"),
        serde_json::json!({"schemaVersion": 1, "profile": profile}).to_string(),
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
        _dir: dir,
        _child: child,
        address,
    }
}

struct Reply {
    status: u16,
    head: String,
    body: String,
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
    let mut stream = TcpStream::connect(&site.address).unwrap();
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
        "{method} {target} HTTP/1.1\r\nHost: {}\r\n{extra}Connection: close\r\n\r\n",
        site.address
    )
    .unwrap();
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).unwrap();
    let text = String::from_utf8_lossy(&raw).into_owned();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
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
    let strict = site("static", "strict", &config(), FILES);
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
    let strict = site("types", "strict", &config(), FILES);
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
    let strict = site("ranges", "strict", &config(), FILES);
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
    let strict = site("options", "strict", &config(), FILES);
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
    let strict = site("notfound", "strict", &config(), FILES);
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
        "strict",
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
    let strict = site("redirects", "strict", &config(), FILES);
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
    let strict = site("reserved", "strict", &catch_all, FILES);
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
    let plain = site("reserved-plain", "strict", &config(), FILES);
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
    // the emulator profile keeps init.* ahead of the redirects
    let emulator = site("reserved-emulator", "emulator", &catch_all, FILES);
    assert_eq!(get(&emulator, "/__/firebase/init.json").status, 200);
    assert_eq!(send(&emulator, "HEAD", "/__/auth/handler", &[]).status, 302);
}

#[test]
fn a_malformed_target_is_a_chunked_400() {
    let strict = site("malformed", "strict", &config(), FILES);
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
    let strict = site("association", "strict", &auto, FILES);
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
    let none = site("association-none", "strict", &serde_json::json!({}), FILES);
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
    let strict = site("i18n", "strict", &config, LOCALES);
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
    let strict = site("globs", "strict", &config, &[("index.html", "home\n")]);
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
