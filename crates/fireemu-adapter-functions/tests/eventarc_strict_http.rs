//! The Eventarc listener under the strict profile and under the emulator profile, over HTTP.
//!
//! The pure answers are checked against the recordings in `eventarc_strict.rs`; here the listener is
//! reached through a socket, with a runner that declares one custom-event function on the channel
//! `locations/us-central1/channels/custom` filtered on `region = eu`.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use fireemu_adapter_functions::http::{
    serve_eventarc, serve_eventarc_with_profile, FunctionsHttpProfile, HttpAdmission,
};
use fireemu_adapter_functions::manifest_json::parse_manifest;
use fireemu_adapter_functions::runner::{Runner, SpawnSpec};
use fireemu_adapter_functions::runtime::{FunctionsConfig, FunctionsRuntime};
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_types::ids::SessionId;
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
    let dir = std::env::temp_dir().join(format!(
        "fireemu-eventarc-strict-{}-{}",
        std::process::id(),
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
    let runtime = FunctionsRuntime::new(
        manifest,
        FunctionsConfig {
            project: project.into(),
            default_bucket: "demo-app.appspot.com".into(),
            location: "nam5".into(),
            session: SessionId::new(7),
            max_running: 4,
            debug_mode: false,
            retry_attempts: 4,
            max_catch_up_runs: 1000,
            runner_secret: "s".into(),
            overlap: fireemu_adapter_functions::runtime::OverlapPolicy::Allow,
            catch_up: fireemu_adapter_functions::runtime::CatchUpPolicy::All,
            functions_host: None,
            subscription_naming: fireemu_adapter_functions::events::SubscriptionNaming::default(),
        },
        Arc::new(Mutex::new(VirtualClock::new(START))),
        Arc::new(runner),
        Some(spec),
    );
    tokio::spawn(runtime.clone().dispatch_loop());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("an address");
    let for_server = runtime.clone();
    let server = tokio::spawn(async move {
        let admission = HttpAdmission::new();
        match profile {
            Some(profile) => {
                serve_eventarc_with_profile(listener, for_server, admission, profile).await
            }
            None => serve_eventarc(listener, for_server, admission).await,
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
    // The channel API: nothing exists in another location, and a declared channel is not served.
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
    assert_eq!(status, 501, "{answer}");
    assert_eq!(error_of(&answer)["status"], "UNIMPLEMENTED");
    let (status, _) = server
        .send("GET", &format!("/v1/{CUSTOM}"), true, None)
        .await;
    assert_eq!(status, 501);
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
    // A well-formed event the emulator's conversion refuses (no datacontenttype attribute).
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
    assert_eq!(status, 400, "{answer}");
    assert_eq!(error_of(&answer)["status"], "INVALID_ARGUMENT");
    assert_eq!(
        error_of(&answer)["message"],
        "CloudEvent must contain datacontenttype attribute"
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
async fn strict_refuses_a_bearer_value_that_is_neither_an_access_token_nor_a_jwt_in_shape() {
    let server = start(Some(FunctionsHttpProfile::Strict)).await;
    let target = "/v1/projects/demo-app/locations/europe-west1/channels";
    for fine in [
        "ya29.A",
        "ya29.a0AfH6SMB-x_y",
        "h.p.s",
        "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.c2ln",
    ] {
        let exchange = server.exchange("GET", target, Some(fine), None, "").await;
        assert_eq!(
            (exchange.status, exchange.body.as_str()),
            (200, "{}\n"),
            "{fine}"
        );
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
