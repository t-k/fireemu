//! The Eventarc listener under the strict profile and under the emulator profile, over HTTP.
//!
//! The pure answers are checked against the recordings in `eventarc_strict.rs`; here the listener is
//! reached through a socket, with a runner that declares one custom-event function on the channel
//! `locations/us-central1/channels/custom` filtered on `region = eu`.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use fireemu_adapter_functions::eventarc_channels::{ChannelStore, SystemEntropy, Timing};
use fireemu_adapter_functions::http::{
    serve_eventarc, serve_eventarc_with_channels, serve_eventarc_with_profile,
    FunctionsHttpProfile, HttpAdmission,
};
use fireemu_adapter_functions::manifest_json::parse_manifest;
use fireemu_adapter_functions::runner::{Runner, SpawnSpec};
use fireemu_adapter_functions::runtime::{CodebaseSpec, FunctionsConfig, FunctionsRuntime};
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_types::time::LogicalInstant;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const START: LogicalInstant = LogicalInstant::from_unix_seconds(1_788_004_860);
const PROJECT: &str = "demo-app";
const CUSTOM: &str = "projects/demo-app/locations/us-central1/channels/custom";

struct Listener {
    addr: std::net::SocketAddr,
    runtime: Arc<FunctionsRuntime>,
    scratch: std::path::PathBuf,
    frames: std::path::PathBuf,
    server: tokio::task::JoinHandle<std::io::Result<()>>,
}

async fn start(profile: Option<FunctionsHttpProfile>) -> Listener {
    start_in(profile, PROJECT).await
}

/// The same listener for another project (the recorded project, for the tests that pin production's bytes).
async fn start_in(profile: Option<FunctionsHttpProfile>, project: &str) -> Listener {
    start_with(profile, project, None).await
}

/// The same listener with the channels of its strict surface given (their timing and identifiers).
async fn start_with(
    profile: Option<FunctionsHttpProfile>,
    project: &str,
    channels: Option<Arc<ChannelStore>>,
) -> Listener {
    // One scratch directory for each listener: tests run in parallel in one process, and a listener that
    // stops removes its directory.
    static LISTENERS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "fireemu-eventarc-strict-{}-{}-{}",
        std::process::id(),
        LISTENERS.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        profile.map_or("default", |p| if p == FunctionsHttpProfile::Strict {
            "strict"
        } else {
            "emulator"
        })
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a scratch directory");
    let frames = dir.join("frames.jsonl");
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fake_runner.py");
    let spec = SpawnSpec {
        command: vec!["python3".to_owned(), script.to_owned()],
        cwd: None,
        env: vec![(
            "FIREEMU_FAKE_FRAME_LOG".to_owned(),
            frames.display().to_string(),
        )],
        hello_timeout: Duration::from_secs(60),
    };
    let runner = Runner::spawn_spec(&spec)
        .await
        .expect("the fake runner starts");
    let manifest =
        parse_manifest(runner.hello().manifest.as_ref().expect("a manifest")).expect("it parses");
    let runtime = FunctionsRuntime::with_codebases(
        vec![CodebaseSpec {
            name: "default".to_owned(),
            manifest,
            runner: Arc::new(runner),
            spawn: Some(spec),
            cleanup_dir: None,
        }],
        FunctionsConfig {
            project: project.into(),
            ..FunctionsConfig::for_tests(1000, "s".into())
        },
        Arc::new(Mutex::new(VirtualClock::new(START))),
        profile.unwrap_or(FunctionsHttpProfile::Emulator),
    )
    .expect("the runtime uses the listener profile");
    tokio::spawn(runtime.clone().dispatch_loop());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("an address");
    let for_server = runtime.clone();
    let server = tokio::spawn(async move {
        let admission = HttpAdmission::new();
        match (profile, channels) {
            (Some(profile), Some(channels)) => {
                serve_eventarc_with_channels(listener, for_server, admission, profile, channels)
                    .await
            }
            (Some(profile), None) => {
                serve_eventarc_with_profile(listener, for_server, admission, profile).await
            }
            (None, _) => serve_eventarc(listener, for_server, admission).await,
        }
    });
    Listener {
        addr,
        runtime,
        scratch: dir,
        frames,
        server,
    }
}

/// One answer: the status, the header block and the body bytes (as text).
struct Exchange {
    status: u16,
    head: String,
    body: String,
}

impl Listener {
    async fn stop(self) {
        self.server.abort();
        self.runtime.runner().shutdown().await;
        let _ = std::fs::remove_dir_all(&self.scratch);
    }

    /// One HTTP/1.1 exchange: the status and the body text. `bearer` sends the token shape a real client
    /// sends (an access token).
    async fn send(
        &self,
        method: &str,
        target: &str,
        bearer: bool,
        body: Option<&str>,
    ) -> (u16, String) {
        self.send_with(method, target, bearer, body, "").await
    }

    /// The same, with extra header lines (each ending in CRLF).
    async fn send_with(
        &self,
        method: &str,
        target: &str,
        bearer: bool,
        body: Option<&str>,
        extra: &str,
    ) -> (u16, String) {
        let token = bearer.then_some("ya29.a-token");
        let exchange = self.exchange(method, target, token, body, extra).await;
        (exchange.status, exchange.body)
    }

    /// The whole answer for a request with this bearer token (or none).
    async fn exchange(
        &self,
        method: &str,
        target: &str,
        token: Option<&str>,
        body: Option<&str>,
        extra: &str,
    ) -> Exchange {
        let mut stream = TcpStream::connect(self.addr).await.expect("connect");
        let auth = token.map_or_else(String::new, |token| {
            format!("authorization: Bearer {token}\r\n")
        });
        let payload = body.unwrap_or("");
        let request = format!(
            "{method} {target} HTTP/1.1\r\nhost: localhost\r\n{auth}{extra}content-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{payload}",
            payload.len()
        );
        stream.write_all(request.as_bytes()).await.expect("write");
        let mut raw = Vec::new();
        stream.read_to_end(&mut raw).await.expect("read");
        let text = String::from_utf8_lossy(&raw).into_owned();
        let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
        let status = head
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .expect("a status line");
        Exchange {
            status,
            head: head.to_owned(),
            body: body.to_owned(),
        }
    }

    /// The frames the runner has logged for the declared function so far, after the dispatcher has had time to
    /// finish what it was given.
    async fn frames_so_far(&self) -> usize {
        tokio::time::sleep(Duration::from_millis(600)).await;
        std::fs::read_to_string(&self.frames).map_or(0, |text| {
            text.lines()
                .filter(|line| line.contains("customEvent"))
                .count()
        })
    }

    /// Waits until the runner has logged at least `count` frames for the declared function (or a minute passes)
    /// and returns how many there are.
    async fn wait_for_frames(&self, count: usize) -> usize {
        let mut seen = 0;
        for _ in 0..1200 {
            seen = std::fs::read_to_string(&self.frames).map_or(0, |text| {
                text.lines()
                    .filter(|line| line.contains("customEvent"))
                    .count()
            });
            if seen >= count {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        seen
    }

    async fn delivered(&self) -> usize {
        for _ in 0..100 {
            if let Ok(text) = std::fs::read_to_string(&self.frames) {
                let count = text
                    .lines()
                    .filter(|line| line.contains("customEvent"))
                    .count();
                if count > 0 {
                    return count;
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        0
    }
}

fn event(region: &str) -> Value {
    json!({
        "@type": "type.googleapis.com/io.cloudevents.v1.CloudEvent",
        "id": "evt-1",
        "source": "//test/source",
        "specVersion": "1.0",
        "type": "com.example.done",
        "attributes": {
            "time": {"ceTimestamp": "2026-10-05T06:17:17.731Z"},
            "datacontenttype": {"ceString": "application/json"},
            "region": {"ceString": region},
        },
        "textData": "{\"n\":1}",
    })
}

fn publish_body(events: &[Value]) -> String {
    json!({ "events": events }).to_string()
}

fn error_of(body: &str) -> Value {
    serde_json::from_str::<Value>(body).expect("a JSON error body")["error"].clone()
}

#[tokio::test]
async fn custom_json_data_keeps_publisher_member_order_only_in_strict_deliveries() {
    use fireemu_adapter_functions::ordered_json::parse;

    let data = r#"{"run":"fixture-run","recording":"H1","case":"sdk-metadata","nested":{"z":3,"a":{"last":true,"first":null}},"items":[{"second":2,"first":1}]}"#;
    let sorted = serde_json::from_str::<Value>(data).unwrap().to_string();
    for (profile, expected) in [
        (FunctionsHttpProfile::Emulator, sorted.as_str()),
        (FunctionsHttpProfile::Strict, data),
    ] {
        let server = start(Some(profile)).await;
        let mut published = event("eu");
        published["textData"] = json!(data);
        let body = publish_body(&[published]);
        let answer = server
            .send(
                "POST",
                &format!("/{CUSTOM}:publishEvents"),
                true,
                Some(&body),
            )
            .await;
        let count = server.wait_for_frames(1).await;
        let frames = std::fs::read_to_string(&server.frames).unwrap_or_default();
        server.stop().await;

        assert_eq!(answer.0, 200);
        assert_eq!(count, 1);
        let frame = frames
            .lines()
            .find(|line| line.contains("customEvent"))
            .unwrap();
        assert_eq!(
            parse(frame.as_bytes()).unwrap()["event"]["data"],
            parse(expected.as_bytes()).unwrap(),
            "{profile:?} preserves its data member order through the runner"
        );
        let frame: Value = serde_json::from_str(frame).unwrap();
        if profile == FunctionsHttpProfile::Strict {
            let trace = frame["event"]["traceparent"].as_str().unwrap();
            assert_eq!(trace.len(), 55);
            assert!(trace.starts_with("00-") && trace.ends_with("-01"));
            assert!(frame["event"].get("datacontenttype").is_none());
        } else {
            assert!(frame["event"].get("traceparent").is_none());
        }
    }
}

#[tokio::test]
async fn strict_refuses_a_request_without_a_credential_and_serves_the_production_path_and_the_emulator_one(
) {
    let server = start(Some(FunctionsHttpProfile::Strict)).await;
    let publish = format!("/v1/{CUSTOM}:publishEvents");
    let body = publish_body(&[event("eu")]);
    let (status, answer) = server.send("POST", &publish, false, Some(&body)).await;
    assert_eq!(status, 401);
    assert_eq!(error_of(&answer)["status"], "UNAUTHENTICATED");
    assert_eq!(
        error_of(&answer)["details"][0]["metadata"]["method"],
        "google.cloud.eventarc.publishing.v1.Publisher.PublishEvents"
    );
    // The same publication with a credential reaches the declared channel and is delivered, on the
    // production path and on the path the Admin SDK writes to an emulator host.
    for target in [publish.clone(), format!("/{CUSTOM}:publishEvents")] {
        let (status, answer) = server.send("POST", &target, true, Some(&body)).await;
        assert_eq!((status, answer.as_str()), (200, "{}\n"), "{target}");
    }
    assert!(server.delivered().await > 0, "the handler was invoked");
    server.stop().await;
}

#[tokio::test]
async fn strict_answers_a_channel_nothing_declares_as_production_answers_a_missing_one() {
    let server = start(Some(FunctionsHttpProfile::Strict)).await;
    let body = publish_body(&[event("eu")]);
    let (status, answer) = server
        .send(
            "POST",
            "/v1/projects/demo-app/locations/us-central1/channels/nothing:publishEvents",
            true,
            Some(&body),
        )
        .await;
    assert_eq!(status, 404);
    assert_eq!(
        error_of(&answer)["message"],
        "Associated channel does not exist."
    );
    // The refusals that come before the channel is looked up.
    let (status, answer) = server
        .send(
            "POST",
            "/v1/projects/demo-app/locations/us-central1/channels/nothing:publishEvents",
            true,
            Some("{}"),
        )
        .await;
    assert_eq!(
        (status, error_of(&answer)["message"].as_str()),
        (400, Some("No events provided."))
    );
    // A project the caller cannot use.
    let (status, answer) = server
        .send(
            "GET",
            "/v1/projects/other/locations/us-central1/channels",
            true,
            None,
        )
        .await;
    assert_eq!(status, 403);
    assert_eq!(
        error_of(&answer)["details"][0]["reason"],
        "CONSUMER_INVALID"
    );
    // The channel API: nothing exists in another location, and a channel a function declares is read and listed.
    let (status, answer) = server
        .send(
            "GET",
            "/v1/projects/demo-app/locations/europe-west1/channels",
            true,
            None,
        )
        .await;
    assert_eq!((status, answer.as_str()), (200, "{}\n"));
    let (status, answer) = server
        .send(
            "GET",
            "/v1/projects/demo-app/locations/us-central1/channels",
            true,
            None,
        )
        .await;
    assert_eq!(status, 200, "{answer}");
    let listed: Value = serde_json::from_str(&answer).expect("JSON");
    assert_eq!(listed["channels"][0]["name"], CUSTOM);
    assert_eq!(listed["channels"][0]["state"], "ACTIVE");
    let (status, answer) = server
        .send("GET", &format!("/v1/{CUSTOM}"), true, None)
        .await;
    assert_eq!(status, 200, "{answer}");
    let read: Value = serde_json::from_str(&answer).expect("JSON");
    assert_eq!(read["name"], CUSTOM);
    assert_eq!(
        read["uid"], listed["channels"][0]["uid"],
        "the same channel"
    );
    let (status, answer) = server
        .send(
            "GET",
            "/v1/projects/demo-app/locations/us-central1/channels/missing",
            true,
            None,
        )
        .await;
    assert_eq!(status, 404);
    assert_eq!(
        error_of(&answer)["details"][0]["@type"],
        "type.googleapis.com/google.rpc.ResourceInfo"
    );
    server.stop().await;
}

#[tokio::test]
async fn strict_keeps_the_emulator_management_routes_and_gives_an_event_the_handler_would_refuse_a_json_error(
) {
    let server = start(Some(FunctionsHttpProfile::Strict)).await;
    let (status, answer) = server.send("GET", "/google/getTriggers", false, None).await;
    assert_eq!(status, 200);
    assert!(answer.contains("com.example.done"), "{answer}");
    // An event without the datacontenttype attribute: production answers 404 NOT_FOUND (stage B, row 90).
    let mut incomplete = event("eu");
    incomplete["attributes"]
        .as_object_mut()
        .unwrap()
        .remove("datacontenttype");
    let (status, answer) = server
        .send(
            "POST",
            &format!("/v1/{CUSTOM}:publishEvents"),
            true,
            Some(&publish_body(&[incomplete])),
        )
        .await;
    assert_eq!(status, 404, "{answer}");
    assert_eq!(error_of(&answer)["status"], "NOT_FOUND");
    assert_eq!(
        error_of(&answer)["message"],
        "The attribute 'datacontenttype' has not been defined in the CloudEvent attributes."
    );
    server.stop().await;
}

#[tokio::test]
async fn the_emulator_profile_and_the_default_entry_are_unchanged() {
    for profile in [Some(FunctionsHttpProfile::Emulator), None] {
        let server = start(profile).await;
        let body = publish_body(&[event("eu")]);
        // The official emulator knows the route without the `/v1`, answers a bare OK, and needs no credential.
        let (status, answer) = server
            .send(
                "POST",
                &format!("/{CUSTOM}:publishEvents"),
                false,
                Some(&body),
            )
            .await;
        assert_eq!((status, answer.as_str()), (200, "OK"));
        // It does not serve the production API: the path with `/v1` and the channel API are not found.
        for (method, target) in [
            ("POST", format!("/v1/{CUSTOM}:publishEvents")),
            (
                "GET",
                "/v1/projects/demo-app/locations/us-central1/channels".to_owned(),
            ),
        ] {
            let (status, answer) = server.send(method, &target, true, Some(&body)).await;
            assert_eq!((status, answer.as_str()), (404, "Not Found"), "{target}");
        }
        server.stop().await;
    }
}

#[tokio::test]
async fn both_profiles_refuse_a_foreign_origin_before_anything_else() {
    for profile in [
        Some(FunctionsHttpProfile::Strict),
        Some(FunctionsHttpProfile::Emulator),
    ] {
        let server = start(profile).await;
        let target = "/v1/projects/demo-app/locations/us-central1/channels";
        let (status, answer) = server
            .send_with(
                "GET",
                target,
                true,
                None,
                "origin: https://evil.example\r\n",
            )
            .await;
        assert_eq!(
            (status, answer.as_str()),
            (403, "forbidden origin"),
            "{profile:?}"
        );
        // A local origin is served as the request would be without one.
        let (local, _) = server
            .send_with(
                "GET",
                target,
                true,
                None,
                "origin: http://localhost:3000\r\n",
            )
            .await;
        let (plain, _) = server.send("GET", target, true, None).await;
        assert_eq!(local, plain, "{profile:?}");
        server.stop().await;
    }
}

/// The two raw bodies of preflight 002 (the fixtures of the lane), through the socket: the bytes, the
/// content type and the content length.
#[tokio::test]
async fn strict_writes_the_bytes_production_wrote() {
    let server = start_in(Some(FunctionsHttpProfile::Strict), "fireemu-oracle-idp").await;
    let raw = |name: &str| {
        let text = std::fs::read_to_string(format!(
            "{}/tests/fixtures/eventarc-stage-a/{name}",
            env!("CARGO_MANIFEST_DIR")
        ))
        .expect("the fixture exists");
        let fixture: Value = serde_json::from_str(&text).expect("JSON");
        fixture["body"].as_str().expect("a body").to_owned()
    };
    let missing = raw("preflight-002-channel-firebase-404.json");
    assert_eq!(missing.len(), 373);
    let list = raw("preflight-002-channels-list.json");
    for (target, expected) in [
        (
            "/v1/projects/fireemu-oracle-idp/locations/us-central1/channels/firebase",
            &missing,
        ),
        // The body of an empty list does not name its location; us-central1 holds the declared channel here.
        (
            "/v1/projects/fireemu-oracle-idp/locations/europe-west1/channels",
            &list,
        ),
        (
            "/projects/fireemu-oracle-idp/locations/us-central1/channels/firebase",
            &missing,
        ),
    ] {
        let exchange = server
            .exchange("GET", target, Some("ya29.a-token"), None, "")
            .await;
        assert_eq!(&exchange.body, expected, "{target}");
        let head = exchange.head.to_ascii_lowercase();
        assert!(
            head.contains("content-type: application/json; charset=utf-8"),
            "{head}"
        );
        assert!(
            head.contains(&format!("content-length: {}", expected.len())),
            "{head}"
        );
    }
    server.stop().await;
}

#[tokio::test]
async fn strict_accepts_an_access_token_in_shape_and_refuses_a_jwt_and_a_value_of_no_known_shape() {
    let server = start(Some(FunctionsHttpProfile::Strict)).await;
    let target = "/v1/projects/demo-app/locations/europe-west1/channels";
    for fine in ["ya29.A", "ya29.a0AfH6SMB-x_y"] {
        let exchange = server.exchange("GET", target, Some(fine), None, "").await;
        assert_eq!(
            (exchange.status, exchange.body.as_str()),
            (200, "{}\n"),
            "{fine}"
        );
    }
    // A JWT in shape was refused in the stage B recording, as garbage and as expired: no details.
    for jwt in ["h.p.s", "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.c2ln"] {
        let exchange = server.exchange("GET", target, Some(jwt), None, "").await;
        assert_eq!(exchange.status, 401, "{jwt}");
        let error = error_of(&exchange.body);
        assert!(error["message"]
            .as_str()
            .unwrap()
            .starts_with("Request had invalid authentication credentials."));
        assert!(error.get("details").is_none(), "{jwt}");
    }
    for bad in [
        "invalid-token-for-the-recording",
        "owner",
        "ya29",
        "ya29x",
        "ya29.",
        "a.b",
        "a.b.c.d",
        "a..c",
        "..",
        "Ya29.A",
    ] {
        let exchange = server.exchange("GET", target, Some(bad), None, "").await;
        assert_eq!(exchange.status, 401, "{bad}");
        let error = error_of(&exchange.body);
        assert!(
            error["message"]
                .as_str()
                .unwrap()
                .starts_with("Request had invalid authentication credentials."),
            "{bad}"
        );
        let info = &error["details"][0];
        assert_eq!(info["reason"], "CREDENTIALS_MISSING");
        assert!(
            info.get("domain").is_none(),
            "no domain on the invalid one: {bad}"
        );
        assert_eq!(
            info["metadata"]["method"],
            "google.cloud.eventarc.v1.Eventarc.ListChannels"
        );
    }
    // No credential is the other 401, with a domain.
    let exchange = server.exchange("GET", target, None, None, "").await;
    assert_eq!(exchange.status, 401);
    assert!(error_of(&exchange.body)["message"]
        .as_str()
        .unwrap()
        .starts_with("Request is missing required authentication credential."));
    assert_eq!(
        error_of(&exchange.body)["details"][0]["domain"],
        "googleapis.com"
    );
    server.stop().await;
}

#[tokio::test]
async fn the_emulator_profile_ignores_the_credential_as_the_official_emulator_does() {
    let server = start(Some(FunctionsHttpProfile::Emulator)).await;
    let body = publish_body(&[event("eu")]);
    for token in [
        None,
        Some("invalid-token-for-the-recording"),
        Some("owner"),
        Some("ya29.x"),
    ] {
        let exchange = server
            .exchange(
                "POST",
                &format!("/{CUSTOM}:publishEvents"),
                token,
                Some(&body),
                "",
            )
            .await;
        assert_eq!(
            (exchange.status, exchange.body.as_str()),
            (200, "OK"),
            "{token:?}"
        );
    }
    server.stop().await;
}

#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn strict_pinned_channel_clock_refuses_unrepresentable_instants_and_keeps_active_channels_after_rewind(
) {
    use fireemu_core_types::time::LogicalDuration;

    let clock = Arc::new(Mutex::new(VirtualClock::new(START)));
    let spec = SpawnSpec {
        command: vec![
            "python3".into(),
            concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fake_runner.py").into(),
        ],
        cwd: None,
        env: Vec::new(),
        hello_timeout: Duration::from_secs(60),
    };
    let runner = Arc::new(Runner::spawn_spec(&spec).await.unwrap());
    let manifest = parse_manifest(&json!({"functions": []})).unwrap();
    let runtime = FunctionsRuntime::with_codebases(
        vec![CodebaseSpec {
            name: "default".into(),
            manifest,
            runner,
            spawn: Some(spec),
            cleanup_dir: None,
        }],
        FunctionsConfig {
            project: PROJECT.into(),
            clock_start_pinned: true,
            ..FunctionsConfig::for_tests(1000, "s".into())
        },
        clock.clone(),
        FunctionsHttpProfile::Strict,
    )
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let serving = runtime.clone();
    let server = tokio::spawn(async move {
        serve_eventarc_with_profile(
            listener,
            serving,
            HttpAdmission::new(),
            FunctionsHttpProfile::Strict,
        )
        .await
    });
    let scratch =
        std::env::temp_dir().join(format!("fireemu-eventarc-pinned-{}", std::process::id()));
    std::fs::create_dir(&scratch).unwrap();
    let server = Listener {
        addr,
        runtime,
        frames: scratch.join("frames.jsonl"),
        scratch,
        server,
    };
    let parent = "/v1/projects/demo-app/locations/us-central1/channels";
    let body =
        json!({"name": "projects/demo-app/locations/us-central1/channels/pinned"}).to_string();
    for instant in [
        LogicalInstant::from_unix_seconds(32_503_680_000),
        LogicalInstant::from_nanos(-1),
    ] {
        clock
            .lock()
            .unwrap()
            .try_set_allow_backwards(instant)
            .unwrap();
        let (status, answer) = server
            .send(
                "POST",
                &format!("{parent}?channelId=pinned"),
                true,
                Some(&body),
            )
            .await;
        assert_eq!(status, 400, "{answer}");
        assert_eq!(error_of(&answer)["status"], "INVALID_ARGUMENT");
        assert!(error_of(&answer)["message"]
            .as_str()
            .unwrap()
            .contains("clock"));
    }
    clock
        .lock()
        .unwrap()
        .try_set_allow_backwards(START)
        .unwrap();
    clock
        .lock()
        .unwrap()
        .advance(LogicalDuration::from_seconds(10))
        .unwrap();
    let (status, answer) = server
        .send(
            "POST",
            &format!("{parent}?channelId=pinned"),
            true,
            Some(&body),
        )
        .await;
    assert_eq!(status, 200, "{answer}");
    let operation: Value = serde_json::from_str(&answer).unwrap();
    let channel = format!("{parent}/pinned");
    let (status, creating) = server.send("GET", &channel, true, None).await;
    assert_eq!(status, 200);
    assert!(serde_json::from_str::<Value>(&creating)
        .unwrap()
        .get("state")
        .is_none());
    clock
        .lock()
        .unwrap()
        .advance(LogicalDuration::from_seconds(10))
        .unwrap();
    let (status, active) = server.send("GET", &channel, true, None).await;
    assert_eq!(status, 200);
    assert_eq!(
        serde_json::from_str::<Value>(&active).unwrap()["state"],
        "ACTIVE"
    );
    clock
        .lock()
        .unwrap()
        .try_set_allow_backwards(START)
        .unwrap();
    let (status, rewound) = server.send("GET", &channel, true, None).await;
    assert_eq!((status, rewound), (200, active));
    let (status, finished) = server
        .send(
            "GET",
            &format!("/v1/{}", operation["name"].as_str().unwrap()),
            true,
            None,
        )
        .await;
    assert_eq!(status, 200);
    assert_eq!(
        serde_json::from_str::<Value>(&finished).unwrap()["done"],
        true
    );
    let body = publish_body(&[event("eu")]);
    let (status, answer) = server
        .send(
            "POST",
            &format!("{channel}:publishEvents"),
            true,
            Some(&body),
        )
        .await;
    assert_eq!((status, answer.as_str()), (200, "{}\n"));
    server.stop().await;
}

#[tokio::test]
async fn strict_serves_the_channel_api_over_http_and_the_emulator_profile_serves_none_of_it() {
    // Operations that take a tenth of a second, so that the test waits for them.
    let channels = Arc::new(ChannelStore::new(
        Box::new(SystemEntropy::default()),
        Timing {
            create: 100_000_000,
            delete: 100_000_000,
        },
    ));
    let server = start_with(Some(FunctionsHttpProfile::Strict), PROJECT, Some(channels)).await;
    let parent = "/v1/projects/demo-app/locations/us-central1";
    let create = |id: &str| {
        let body =
            json!({ "name": format!("projects/demo-app/locations/us-central1/channels/{id}") })
                .to_string();
        (format!("{parent}/channels?channelId={id}"), body)
    };
    // The quota project a request names is not checked: a project that does not exist is answered 200
    // (stage B rows 181 and 182), on a read and on a publication.
    let quota = "x-goog-user-project: fireemu-no-such-project-0\r\n";
    let (status, answer) = server
        .send_with(
            "GET",
            "/v1/projects/demo-app/locations/europe-west1/channels",
            true,
            None,
            quota,
        )
        .await;
    assert_eq!((status, answer.as_str()), (200, "{}\n"));
    let (target, body) = create("made");
    let (status, answer) = server
        .send_with("POST", &target, true, Some(&body), quota)
        .await;
    assert_eq!(status, 200, "{answer}");
    let operation: Value = serde_json::from_str(&answer).expect("JSON");
    let operation = operation["name"].as_str().expect("an operation").to_owned();
    // Read at once: not done; read later: done with the channel.
    let (status, pending) = server
        .send("GET", &format!("/v1/{operation}"), true, None)
        .await;
    assert_eq!(status, 200);
    assert!(pending.contains("\"done\": false"), "{pending}");
    tokio::time::sleep(Duration::from_millis(250)).await;
    let (status, finished) = server
        .send("GET", &format!("/v1/{operation}"), true, None)
        .await;
    assert_eq!(status, 200);
    assert!(
        finished.contains("\"done\": true") && finished.contains("\"state\": \"ACTIVE\""),
        "{finished}"
    );
    // A publication to it, with the quota project, is accepted; the same publication after the
    // deletion is not.
    let body = publish_body(&[event("eu")]);
    let publish = format!("{parent}/channels/made:publishEvents");
    let (status, answer) = server
        .send_with("POST", &publish, true, Some(&body), quota)
        .await;
    assert_eq!((status, answer.as_str()), (200, "{}\n"));
    let (status, _) = server
        .send("DELETE", &format!("{parent}/channels/made"), true, None)
        .await;
    assert_eq!(status, 200);
    tokio::time::sleep(Duration::from_millis(250)).await;
    let (status, answer) = server.send("POST", &publish, true, Some(&body)).await;
    assert_eq!(status, 404, "{answer}");
    assert_eq!(
        error_of(&answer)["message"],
        "Associated channel does not exist."
    );
    server.stop().await;
    // The emulator profile is the official emulator's: the channel API is not there.
    let server = start(Some(FunctionsHttpProfile::Emulator)).await;
    let (target, body) = create("made");
    for (method, path, payload) in [
        ("POST", target.as_str(), Some(body.as_str())),
        ("GET", &format!("{parent}/channels/made"), None),
        ("DELETE", &format!("{parent}/channels/made"), None),
        (
            "GET",
            &format!("{parent}/operations/operation-1-2-3-4"),
            None,
        ),
    ] {
        let (status, answer) = server.send(method, path, true, payload).await;
        assert_eq!(
            (status, answer.as_str()),
            (404, "Not Found"),
            "{method} {path}"
        );
    }
    server.stop().await;
}

/// The JSON text of a recorded request body (a text the capture omitted is rebuilt at its length).
fn recorded_body(value: &Value) -> String {
    match value {
        Value::Object(members) if members.len() == 1 && members.contains_key("omitted") => {
            let length = members["omitted"]["length"].as_u64().expect("a length");
            let text =
                serde_json::to_string(&"x".repeat(usize::try_from(length).expect("small") - 2))
                    .expect("a string");
            serde_json::to_string(&text).expect("a string")
        }
        Value::Object(members) => Value::Object(
            members
                .iter()
                .map(|(key, item)| {
                    (
                        key.clone(),
                        serde_json::from_str(&recorded_body(item)).expect("JSON"),
                    )
                })
                .collect(),
        )
        .to_string(),
        Value::Array(items) => Value::Array(
            items
                .iter()
                .map(|item| serde_json::from_str(&recorded_body(item)).expect("JSON"))
                .collect(),
        )
        .to_string(),
        other => other.to_string(),
    }
}

/// The emulator profile against the stage B recording, reported apart from the strict profile (ledger 811).
/// The official emulator (firebase-tools 15.28.2, `eventarcEmulator.js`) has no channel API: every route
/// but the publication, the trigger registration and `getTriggers` answers `404 Not Found`; the
/// publication answers `200 OK` for any event that has a `type` and checks nothing else. So the channel API
/// of the recording is not found here, as it is not found in the official emulator, and a recorded
/// publication that production accepted is not refused.
#[tokio::test]
async fn the_emulator_profile_has_no_channel_api_and_accepts_every_recorded_publication_production_accepts(
) {
    // Both recordings: stage B (233 rows) and stage C (424 rows, the second record of its cases and the new ones).
    let mut rows: Vec<Value> = Vec::new();
    for fixture in ["eventarc-stage-b", "eventarc-stage-c"] {
        let more: Vec<Value> = serde_json::from_slice(
            &std::fs::read(format!(
                "{}/tests/fixtures/{fixture}/rows.json",
                env!("CARGO_MANIFEST_DIR")
            ))
            .expect("the fixture exists"),
        )
        .expect("JSON");
        rows.extend(more);
    }
    let server = start(Some(FunctionsHttpProfile::Emulator)).await;
    let mut accepted_by_production = 0;
    let mut refused: Vec<(u64, u16, String)> = Vec::new();
    let mut by_pair: std::collections::BTreeMap<(u64, u16), usize> =
        std::collections::BTreeMap::new();
    for row in &rows {
        let op = row["op"].as_str().expect("an op");
        let path = row["request"]["path"].as_str().expect("a path");
        let production = row["response"]["status"].as_u64().expect("a status");
        if op == "publishEvents" || op == "sdk.publishEvents" {
            // The route of the official emulator has no `/v1` (and no credential is needed).
            let body = recorded_body(&row["request"]["body"]);
            let (status, answer) = server
                .send(
                    "POST",
                    path.strip_prefix("/v1").unwrap_or(path),
                    false,
                    Some(&body),
                )
                .await;
            *by_pair.entry((production, status)).or_default() += 1;
            // The official emulator checks nothing but the `type` of each event: a body that parses, whose
            // events all have one, is answered `200 OK` here whatever production said.
            let parsed: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
            if let Some(events) = parsed["events"].as_array() {
                if events
                    .iter()
                    .all(|e| e["type"].as_str().is_some_and(|t| !t.is_empty()))
                {
                    assert_eq!(
                        (status, answer.as_str()),
                        (200, "OK"),
                        "row {}: the official emulator accepts it",
                        row["n"]
                    );
                }
            }
            if production == 200 {
                accepted_by_production += 1;
                if (status, answer.as_str()) != (200, "OK") {
                    refused.push((row["n"].as_u64().expect("a number"), status, answer));
                }
            }
        } else if !path.contains("/services/") {
            let (status, answer) = server
                .send(
                    row["request"]["method"].as_str().expect("a method"),
                    path,
                    true,
                    row["request"].get("body").map(recorded_body).as_deref(),
                )
                .await;
            assert_eq!(
                (status, answer.as_str()),
                (404, "Not Found"),
                "row {} ({op}): the channel API is not in the official emulator",
                row["n"]
            );
        }
    }
    assert!(
        accepted_by_production > 20,
        "{accepted_by_production} publications"
    );
    // Every publication production accepted is answered `200 OK`, as the official emulator answers it. Two of
    // them (row 89: no `time` attribute; row 102: an attribute of the kind `ceBytes`) cannot be converted: the
    // official emulator converts after answering and only logs, and so does this one.
    assert_eq!(refused, Vec::<(u64, u16, String)>::new());
    eprintln!("emulator profile: (production status, emulator status) -> rows: {by_pair:?}");
    server.stop().await;
}

#[tokio::test]
async fn the_functions_and_tasks_listeners_serve_with_the_store_they_were_given() {
    // The two listeners that do not use the channel store still start and answer: each unknown route is
    // the official `404`.
    let dir_server = start(None).await;
    let runtime = dir_server.runtime.clone();
    for (profile, tasks) in [
        (FunctionsHttpProfile::Strict, false),
        (FunctionsHttpProfile::Emulator, false),
        (FunctionsHttpProfile::Emulator, true),
    ] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("an address");
        let runtime = runtime.clone();
        let server = tokio::spawn(async move {
            let admission = HttpAdmission::new();
            if tasks {
                fireemu_adapter_functions::http::serve_tasks(listener, runtime, admission).await
            } else {
                fireemu_adapter_functions::http::serve_functions_with_profile(
                    listener, runtime, admission, profile,
                )
                .await
            }
        });
        let mut stream = TcpStream::connect(addr).await.expect("connect");
        stream
            .write_all(
                b"GET /no/such/thing HTTP/1.1\r\nhost: localhost\r\nconnection: close\r\n\r\n",
            )
            .await
            .expect("write");
        let mut raw = Vec::new();
        stream.read_to_end(&mut raw).await.expect("read");
        let text = String::from_utf8_lossy(&raw);
        assert!(text.starts_with("HTTP/1.1 404"), "{text}");
        server.abort();
    }
    dir_server.stop().await;
}

/// A recorded shape that production accepts and the official emulator answers `200 OK` to, but whose conversion
/// the emulator cannot make: no `time` attribute (stage B row 89) and an attribute of the kind `ceBytes`
/// (row 102). The publication is answered as the official emulator answers it (it converts after answering, so
/// a failure is only logged); the event is not delivered, the others of the batch are.
fn without_time(id: &str) -> Value {
    let mut event = event("eu");
    event["id"] = json!(id);
    event["attributes"].as_object_mut().unwrap().remove("time");
    event
}

fn with_bytes_attribute(id: &str) -> Value {
    let mut event = event("eu");
    event["id"] = json!(id);
    event["attributes"]["blob"] = json!({"ceBytes": "AAEC"});
    event
}

fn with_id(id: &str) -> Value {
    let mut event = event("eu");
    event["id"] = json!(id);
    event
}

#[tokio::test]
async fn the_emulator_profile_answers_an_event_it_cannot_convert_as_the_official_emulator_does() {
    let server = start(Some(FunctionsHttpProfile::Emulator)).await;
    let target = format!("/{CUSTOM}:publishEvents");
    let (status, answer) = server
        .send(
            "POST",
            &target,
            false,
            Some(&publish_body(&[with_id("good-1")])),
        )
        .await;
    assert_eq!((status, answer.as_str()), (200, "OK"));
    let one = server.frames_so_far().await;
    assert!(one > 0, "the first event is delivered");
    // Two events the conversion cannot make, with a good one after them.
    let batch = publish_body(&[
        without_time("no-time"),
        with_bytes_attribute("bytes"),
        with_id("good-2"),
    ]);
    let (status, answer) = server.send("POST", &target, false, Some(&batch)).await;
    assert_eq!((status, answer.as_str()), (200, "OK"), "{answer}");
    assert_eq!(
        server.frames_so_far().await,
        2 * one,
        "only the good event of the batch is delivered"
    );
    // The two events alone are answered the same way and deliver nothing.
    let batch = publish_body(&[without_time("no-time-2"), with_bytes_attribute("bytes-2")]);
    let (status, answer) = server.send("POST", &target, false, Some(&batch)).await;
    assert_eq!((status, answer.as_str()), (200, "OK"), "{answer}");
    assert_eq!(server.frames_so_far().await, 2 * one);
    server.stop().await;
}

#[tokio::test]
async fn the_emulator_profile_still_refuses_what_the_official_emulator_refuses() {
    let server = start(Some(FunctionsHttpProfile::Emulator)).await;
    let target = format!("/{CUSTOM}:publishEvents");
    // The official handler answers 400 for an event with no `type`, and for a body it cannot read.
    let mut no_type = with_id("no-type");
    no_type.as_object_mut().unwrap().remove("type");
    for body in [
        publish_body(&[no_type.clone()]),
        publish_body(&[with_id("good-3"), no_type]),
        "not json".to_owned(),
        "{}".to_owned(),
    ] {
        let (status, _) = server.send("POST", &target, false, Some(&body)).await;
        assert_eq!(status, 400, "{body}");
    }
    server.stop().await;
}

#[tokio::test]
async fn strict_accepts_missing_time_and_bytes_extensions_and_delivers_them() {
    let server = start(Some(FunctionsHttpProfile::Strict)).await;
    let target = format!("/v1/{CUSTOM}:publishEvents");
    let (status, answer) = server
        .send(
            "POST",
            &target,
            true,
            Some(&publish_body(&[with_id("good-1")])),
        )
        .await;
    assert_eq!((status, answer.as_str()), (200, "{}\n"), "{answer}");
    let one = server.frames_so_far().await;
    assert!(one > 0, "the first event is delivered");
    let batch = publish_body(&[
        without_time("no-time"),
        with_bytes_attribute("bytes"),
        with_id("good-2"),
    ]);
    let (status, answer) = server.send("POST", &target, true, Some(&batch)).await;
    assert_eq!((status, answer.as_str()), (200, "{}\n"), "{answer}");
    assert_eq!(
        server.frames_so_far().await,
        4 * one,
        "all three accepted events are delivered"
    );
    // Near misses that production refuses stay refused: a missing `id`, and a missing content type.
    let mut no_id = with_id("x");
    no_id.as_object_mut().unwrap().remove("id");
    let (status, _) = server
        .send("POST", &target, true, Some(&publish_body(&[no_id])))
        .await;
    assert_eq!(status, 400);
    server.stop().await;
}

/// A batch of `count` events with distinct ids that the declared function's filter (`region = eu`) does not match.
fn unmatched_batch(count: usize) -> String {
    let events: Vec<Value> = (0..count)
        .map(|index| {
            let mut event = event("us");
            event["id"] = json!(format!("batch-{index}"));
            event
        })
        .collect();
    publish_body(&events)
}

#[tokio::test]
async fn the_emulator_profile_has_no_limit_on_the_number_of_events_as_the_official_emulator_has_none(
) {
    // 256 was the limit of an earlier version (a 429 above it); the official emulator accepts any number.
    let server = start(Some(FunctionsHttpProfile::Emulator)).await;
    let target = format!("/{CUSTOM}:publishEvents");
    for count in [1, 100, 101, 255, 256, 257, 1000, 5000] {
        let (status, answer) = server
            .send("POST", &target, false, Some(&unmatched_batch(count)))
            .await;
        assert_eq!((status, answer.as_str()), (200, "OK"), "{count} events");
    }
    // Near misses: a large batch with one event that has no `type` is still refused, as the official handler
    // refuses it, and so is a body that is not a batch.
    let mut batch: Vec<Value> = (0..300)
        .map(|index| {
            let mut event = event("us");
            event["id"] = json!(format!("near-{index}"));
            event
        })
        .collect();
    batch[299].as_object_mut().unwrap().remove("type");
    let (status, _) = server
        .send("POST", &target, false, Some(&publish_body(&batch)))
        .await;
    assert_eq!(status, 400);
    let (status, _) = server.send("POST", &target, false, Some("{}")).await;
    assert_eq!(status, 400);
    // The same on the sentinel channel the official emulator forwards verbatim.
    let (status, answer) = server
        .send(
            "POST",
            "/projects/demo-app/locations/us-central1/channels/google:publishEvents",
            false,
            Some(&unmatched_batch(400)),
        )
        .await;
    assert_eq!(status, 200, "{answer}");
    server.stop().await;
}

#[tokio::test]
async fn strict_refuses_above_the_recorded_event_count_and_accepts_up_to_it_in_the_same_batch_shapes(
) {
    // The strict profile follows production: 100 events pass, 101 are refused with `OUT_OF_RANGE` (stage B),
    // never the emulator profile's old 429.
    let server = start(Some(FunctionsHttpProfile::Strict)).await;
    let target = format!("/v1/{CUSTOM}:publishEvents");
    for (count, expected) in [(100, 200), (101, 400), (256, 400), (257, 400), (1000, 400)] {
        let (status, answer) = server
            .send("POST", &target, true, Some(&unmatched_batch(count)))
            .await;
        assert_eq!(status, expected, "{count} events: {answer}");
        if expected == 400 {
            assert_eq!(error_of(&answer)["status"], "OUT_OF_RANGE", "{count}");
            assert_eq!(error_of(&answer)["message"], "Too many events.", "{count}");
        } else {
            assert_eq!(answer, "{}\n");
        }
    }
    server.stop().await;
}

/// One matched event (region `eu`, the declared function's filter) with this id and this `type` member.
fn matched_event(id: &str, event_type: Value) -> Value {
    let mut event = event("eu");
    event["id"] = json!(id);
    event["type"] = event_type;
    event
}

fn good_event(id: &str) -> Value {
    matched_event(id, json!("com.example.done"))
}

#[tokio::test]
async fn the_emulator_profile_delivers_every_matched_event_of_a_large_publication() {
    // The per-publication cap of 256 deliveries is gone: 257 and 1000 events, each matching the one declared
    // function, are answered 200 and every one is delivered (the official emulator has no limit).
    for count in [257, 1000] {
        let server = start(Some(FunctionsHttpProfile::Emulator)).await;
        let target = format!("/{CUSTOM}:publishEvents");
        let (status, _) = server
            .send(
                "POST",
                &target,
                false,
                Some(&publish_body(&[good_event("one")])),
            )
            .await;
        assert_eq!(status, 200);
        let one = server.wait_for_frames(1).await;
        assert!(one > 0);
        tokio::time::sleep(Duration::from_millis(300)).await;
        let before = server.wait_for_frames(0).await;
        let events: Vec<Value> = (0..count).map(|i| good_event(&format!("m-{i}"))).collect();
        let (status, answer) = server
            .send("POST", &target, false, Some(&publish_body(&events)))
            .await;
        assert_eq!((status, answer.as_str()), (200, "OK"), "{count} events");
        assert_eq!(
            server.wait_for_frames(before + count * one).await,
            before + count * one,
            "{count} events, all delivered"
        );
        server.stop().await;
    }
}

#[tokio::test]
async fn the_emulator_profile_accepts_any_truthy_type_and_refuses_a_falsy_one_with_the_official_text(
) {
    let server = start(Some(FunctionsHttpProfile::Emulator)).await;
    let target = format!("/{CUSTOM}:publishEvents");
    // The official handler refuses `!event.type`: a missing type, null, false, 0 and "". Anything else passes.
    for (value, expected) in [
        (json!(5), 200),
        (json!(true), 200),
        (json!({}), 200),
        (json!([]), 200),
        (json!(1.5), 200),
        (json!("com.example.other"), 200),
        (json!(""), 400),
        (json!(null), 400),
        (json!(false), 400),
        (json!(0), 400),
    ] {
        let body = publish_body(&[matched_event("t-1", value.clone())]);
        let (status, answer) = server.send("POST", &target, false, Some(&body)).await;
        assert_eq!(status, expected, "type {value}: {answer}");
        assert_eq!(
            answer,
            if expected == 200 { "OK" } else { "Bad Request" },
            "type {value}"
        );
    }
    let mut missing = good_event("t-2");
    missing.as_object_mut().unwrap().remove("type");
    let (status, answer) = server
        .send("POST", &target, false, Some(&publish_body(&[missing])))
        .await;
    assert_eq!((status, answer.as_str()), (400, "Bad Request"));
    // A type that is not a string is accepted and not delivered (nothing can match it).
    assert_eq!(server.wait_for_frames(0).await, 0);
    server.stop().await;
}

#[tokio::test]
async fn a_type_the_runtime_cannot_hold_is_not_delivered_and_does_not_refuse_the_publication_in_both_profiles(
) {
    for profile in [FunctionsHttpProfile::Emulator, FunctionsHttpProfile::Strict] {
        let server = start(Some(profile)).await;
        let (target, bearer) = if profile == FunctionsHttpProfile::Strict {
            (format!("/v1/{CUSTOM}:publishEvents"), true)
        } else {
            (format!("/{CUSTOM}:publishEvents"), false)
        };
        let ok = if profile == FunctionsHttpProfile::Strict {
            "{}\n"
        } else {
            "OK"
        };
        for bad in [
            "a/b:c".to_owned(),
            "a b".to_owned(),
            "x".repeat(300),
            "é".to_owned(),
        ] {
            // Alone: answered, nothing delivered. With a good event after it: the good one is delivered.
            let body = publish_body(&[matched_event("bad-1", json!(bad))]);
            let (status, answer) = server.send("POST", &target, bearer, Some(&body)).await;
            assert_eq!((status, answer.as_str()), (200, ok), "{profile:?} {bad:?}");
        }
        assert_eq!(
            server.wait_for_frames(0).await,
            0,
            "{profile:?}: nothing delivered"
        );
        let body = publish_body(&[matched_event("bad-2", json!("a/b:c")), good_event("good-1")]);
        let (status, answer) = server.send("POST", &target, bearer, Some(&body)).await;
        assert_eq!((status, answer.as_str()), (200, ok), "{profile:?}");
        assert!(
            server.wait_for_frames(1).await > 0,
            "{profile:?}: the good event is delivered"
        );
        server.stop().await;
    }
}

#[tokio::test]
async fn the_emulator_profile_delivers_the_events_before_a_typeless_one_and_then_answers_400_as_the_official_handler_does(
) {
    let server = start(Some(FunctionsHttpProfile::Emulator)).await;
    let target = format!("/{CUSTOM}:publishEvents");
    let (status, _) = server
        .send(
            "POST",
            &target,
            false,
            Some(&publish_body(&[good_event("probe")])),
        )
        .await;
    assert_eq!(status, 200);
    let one = server.wait_for_frames(1).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let before = server.wait_for_frames(0).await;
    let mut typeless = good_event("c");
    typeless.as_object_mut().unwrap().remove("type");
    let body = publish_body(&[good_event("a"), good_event("b"), typeless, good_event("d")]);
    let (status, answer) = server.send("POST", &target, false, Some(&body)).await;
    assert_eq!((status, answer.as_str()), (400, "Bad Request"));
    // The two events before it are delivered; the one after it is not (the loop stops there).
    assert_eq!(
        server.wait_for_frames(before + 2 * one).await,
        before + 2 * one
    );
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(server.wait_for_frames(0).await, before + 2 * one);
    server.stop().await;
}

#[test]
fn the_declared_eventarc_queue_bounds_are_the_numbers_capabilities_json_states_and_it_states_no_per_publication_cap(
) {
    use fireemu_adapter_functions::runtime::{
        MAX_ACTIVE_EVENTARC_BYTES, MAX_ACTIVE_EVENTARC_RECORDS,
    };
    assert_eq!(MAX_ACTIVE_EVENTARC_RECORDS, 3072);
    assert_eq!(MAX_ACTIVE_EVENTARC_BYTES, 48 * 1024 * 1024);
    let capabilities = include_str!("../../fireemu/src/capabilities.json");
    assert!(capabilities.contains("capped at 3072 records and 48 MiB"));
    // The old per-publication caps are not stated any more: the queue bound is the only limit.
    assert!(!capabilities.contains("each publish to 256 input events"));
    assert!(!capabilities.contains("256 deliveries after fault expansion"));
    assert!(capabilities.contains("no per-publication cap on events or deliveries"));
}
