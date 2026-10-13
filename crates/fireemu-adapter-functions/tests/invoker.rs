//! Who may call a function's public URL (FN-03, FN-04): under the strict profile a function whose
//! `invoker` is not public, and every task-queue function, refuses a call without a credential
//! with the front end's 403; the emulator profile serves everyone as the official emulator does.
//! The console's credential (the control token) and Fireemu's own task dispatch go around the
//! check.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use fireemu_adapter_functions::http::{
    parse_response, FunctionsHttpProfile, HttpAdmission, ProxiedResponse,
};
use fireemu_adapter_functions::invoker::OWNER_TOKEN_HEADER;
use fireemu_adapter_functions::manifest_json::parse_manifest;
use fireemu_adapter_functions::runner::{Runner, SpawnSpec};
use fireemu_adapter_functions::runtime::{FunctionsConfig, FunctionsRuntime};
use fireemu_core_functions::manifest::{TaskRateLimits, TaskRetryConfig, Trigger};
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_types::time::LogicalInstant;

const START: LogicalInstant = LogicalInstant::from_unix_seconds(1_788_004_860);
const PROJECT: &str = "demo-app";
const OWNER: &str = "owner-control-token-for-the-test";
const JWT: &str = "aGVhZGVy.cGF5bG9hZA.c2lnbmF0dXJl";

struct Harness {
    addr: std::net::SocketAddr,
    runtime: Arc<FunctionsRuntime>,
    server: tokio::task::JoinHandle<std::io::Result<()>>,
}

async fn start(profile: FunctionsHttpProfile, probe: Option<&std::path::Path>) -> Harness {
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fake_runner.py");
    let env = probe
        .map(|p| {
            vec![(
                "FIREEMU_FAKE_TASK_PROBE".to_owned(),
                p.display().to_string(),
            )]
        })
        .unwrap_or_default();
    let spec = SpawnSpec {
        command: vec!["python3".to_owned(), script.to_owned()],
        cwd: None,
        env,
        hello_timeout: Duration::from_secs(60),
    };
    let runner = Runner::spawn_spec(&spec)
        .await
        .expect("the fake runner starts");
    let mut manifest = parse_manifest(runner.hello().manifest.as_ref().unwrap()).unwrap();
    let template = manifest.get("echo").unwrap().clone();
    for (name, invokers) in [
        ("openByDefault", vec![]),
        ("openExplicitly", vec!["public".to_owned()]),
        ("privateOnly", vec!["private".to_owned()]),
        (
            "listedAccounts",
            vec!["sa@demo-app.iam.gserviceaccount.com".to_owned()],
        ),
        (
            "publicAndListed",
            vec!["public".to_owned(), "sa@x.iam".to_owned()],
        ),
    ] {
        let mut function = template.clone();
        name.clone_into(&mut function.name);
        name.clone_into(&mut function.entry_point);
        function.platform_options.invokers = invokers;
        manifest.functions.push(function);
    }
    let mut queue = template.clone();
    "taskA".clone_into(&mut queue.name);
    "taskA".clone_into(&mut queue.entry_point);
    queue.trigger = Trigger::TaskQueue {
        retry: TaskRetryConfig::default(),
        rate_limits: TaskRateLimits {
            max_concurrent_dispatches: 4,
            max_dispatches_per_second: 500.0,
        },
    };
    manifest.functions.push(queue);
    let runtime = FunctionsRuntime::new(
        manifest,
        FunctionsConfig {
            project: PROJECT.into(),
            functions_host: Some("127.0.0.1:5001".into()),
            ..FunctionsConfig::for_tests(1000, "runner-secret".into())
        },
        Arc::new(Mutex::new(VirtualClock::new(START))),
        Arc::new(runner),
        Some(spec),
    );
    runtime.set_owner_token(OWNER.to_owned());
    tokio::spawn(runtime.clone().dispatch_loop());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let for_listener = runtime.clone();
    let server = tokio::spawn(async move {
        fireemu_adapter_functions::http::serve_functions_with_profile(
            listener,
            for_listener,
            HttpAdmission::new(),
            profile,
        )
        .await
    });
    Harness {
        addr,
        runtime,
        server,
    }
}

impl Harness {
    async fn call(&self, function: &str, headers: &[(&str, &str)]) -> ProxiedResponse {
        use std::fmt::Write as _;
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let body = br#"{"data":{}}"#;
        let mut request = format!("POST /{PROJECT}/us-central1/{function} HTTP/1.1\r\n");
        for (name, value) in headers {
            let _ = write!(request, "{name}: {value}\r\n");
        }
        let _ = write!(
            request,
            "host: {}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
            self.addr,
            body.len()
        );
        let mut stream = tokio::net::TcpStream::connect(self.addr).await.unwrap();
        stream.write_all(request.as_bytes()).await.unwrap();
        stream.write_all(body).await.unwrap();
        let mut raw = Vec::new();
        stream.read_to_end(&mut raw).await.unwrap();
        parse_response(&raw, "POST").expect("a well-formed response")
    }

    async fn status(&self, function: &str, headers: &[(&str, &str)]) -> u16 {
        self.call(function, headers).await.status
    }

    async fn stop(self) {
        self.server.abort();
        self.runtime.shutdown().await;
    }
}

const RESTRICTED: [&str; 3] = ["privateOnly", "listedAccounts", "taskA"];
const OPEN: [&str; 4] = ["openByDefault", "openExplicitly", "publicAndListed", "echo"];

#[tokio::test]
async fn strict_refuses_a_call_without_credentials_to_a_function_that_is_not_public() {
    let h = start(FunctionsHttpProfile::Strict, None).await;
    for function in RESTRICTED {
        let answer = h.call(function, &[]).await;
        assert_eq!(answer.status, 403, "{function}");
        let page = String::from_utf8_lossy(&answer.body).into_owned();
        assert!(page.contains("403 Forbidden"), "{function}: {page}");
        assert!(
            page.contains(&format!("/{PROJECT}/us-central1/{function}")),
            "{function}: {page}"
        );
        assert!(
            !page.contains("\"method\""),
            "{function}: the runner must not be reached: {page}"
        );
    }
    for function in OPEN {
        assert_eq!(h.status(function, &[]).await, 200, "{function}");
    }
    h.stop().await;
}

#[tokio::test]
async fn an_identity_token_shaped_bearer_enters_and_any_other_bearer_is_refused() {
    let h = start(FunctionsHttpProfile::Strict, None).await;
    let bearer = format!("Bearer {JWT}");
    for function in RESTRICTED {
        assert_eq!(
            h.status(function, &[("authorization", &bearer)]).await,
            200,
            "{function}"
        );
        assert_eq!(
            h.status(function, &[("authorization", "Bearer not-a-token")])
                .await,
            401,
            "{function}"
        );
        assert_eq!(
            h.status(function, &[("authorization", "Basic dXNlcjpwYXNz")])
                .await,
            403,
            "{function}"
        );
        assert_eq!(
            h.status(
                function,
                &[("authorization", &bearer), ("authorization", &bearer)]
            )
            .await,
            401,
            "{function}: two credentials are ambiguous"
        );
    }
    h.stop().await;
}

/// The console and the control API present the control token. It admits the call, and it is
/// removed before the request reaches the function.
#[tokio::test]
async fn the_owner_credential_enters_and_never_reaches_the_function() {
    let h = start(FunctionsHttpProfile::Strict, None).await;
    for function in RESTRICTED.into_iter().chain(OPEN) {
        let answer = h.call(function, &[(OWNER_TOKEN_HEADER, OWNER)]).await;
        assert_eq!(answer.status, 200, "{function}");
        let seen = String::from_utf8_lossy(&answer.body).into_owned();
        assert!(!seen.contains(OWNER_TOKEN_HEADER), "{function}: {seen}");
        assert!(!seen.contains(OWNER), "{function}: {seen}");
    }
    // A wrong token is no credential; a right one sent twice still is one.
    assert_eq!(
        h.status(
            "privateOnly",
            &[(OWNER_TOKEN_HEADER, "not-the-owner-token-xxxxxxxxxxxxx")]
        )
        .await,
        403
    );
    assert_eq!(
        h.status("privateOnly", &[(OWNER_TOKEN_HEADER, "short")])
            .await,
        403
    );
    h.stop().await;
}

/// The official emulator serves every function to every caller, so the emulator profile may
/// not refuse what it serves.
#[tokio::test]
async fn the_emulator_profile_serves_every_function_to_every_caller() {
    let h = start(FunctionsHttpProfile::Emulator, None).await;
    for function in RESTRICTED.into_iter().chain(OPEN) {
        assert_eq!(h.status(function, &[]).await, 200, "{function}");
    }
    h.stop().await;
}

/// Fireemu's own dispatch of a task is not a call to the public URL: a task enqueued through the
/// runtime (which is what the Admin SDK, the Tasks port and the console's enqueue route all
/// reach) runs although the queue's URL refuses a direct call.
#[tokio::test]
async fn an_enqueued_task_runs_although_its_public_url_refuses_a_direct_call() {
    let dir = std::env::temp_dir().join(format!("fireemu-invoker-task-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let probe = dir.join("entries");
    std::fs::write(dir.join("entries.taskA.release"), "").unwrap();
    let h = start(FunctionsHttpProfile::Strict, Some(&probe)).await;

    assert_eq!(h.status("taskA", &[]).await, 403);
    assert!(
        !probe.exists(),
        "the refused call must not reach the function"
    );

    let body = serde_json::json!({"task": {
        "name": format!("projects/{PROJECT}/locations/us-central1/queues/taskA/tasks/t1"),
        "httpRequest": {"url": "", "body": "eyJkYXRhIjp7fX0="}
    }});
    h.runtime
        .enqueue_task(PROJECT, "us-central1", "taskA", &body)
        .expect("the enqueue is accepted");
    tokio::time::timeout(Duration::from_secs(5), async {
        while std::fs::read_to_string(&probe)
            .unwrap_or_default()
            .lines()
            .count()
            < 1
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the dispatch reached the task function");
    h.stop().await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// The owner credential is compared in full: a shorter or longer value, a prefix, and a value
/// that differs in exactly one position or in two positions whose differences cancel are all
/// refused; only the exact token is accepted.
#[tokio::test]
async fn the_owner_credential_is_compared_in_full() {
    let h = start(FunctionsHttpProfile::Strict, None).await;
    assert!(h.runtime.owner_token_matches(OWNER));
    assert!(!h.runtime.owner_token_matches(""));
    assert!(
        !h.runtime.owner_token_matches(&OWNER[..OWNER.len() - 1]),
        "a prefix"
    );
    assert!(
        !h.runtime.owner_token_matches(&format!("{OWNER}x")),
        "an extension"
    );
    for index in 0..OWNER.len() {
        let mut one = OWNER.as_bytes().to_vec();
        one[index] ^= 1;
        assert!(
            !h.runtime
                .owner_token_matches(&String::from_utf8(one).unwrap()),
            "one position at {index}"
        );
    }
    // Two positions flipped by the same mask: an accumulating XOR would cancel them.
    let mut two = OWNER.as_bytes().to_vec();
    two[0] ^= 1;
    two[1] ^= 1;
    assert!(!h
        .runtime
        .owner_token_matches(&String::from_utf8(two).unwrap()));
    // Without an installed token nothing matches, not even the empty string.
    let bare = FunctionsRuntime::new(
        fireemu_core_functions::manifest::FunctionManifest::default(),
        FunctionsConfig::for_tests(10, "s".into()),
        Arc::new(Mutex::new(VirtualClock::new(START))),
        h.runtime.runner().clone(),
        None,
    );
    assert!(!bare.owner_token_matches(""));
    assert!(!bare.owner_token_matches(OWNER));
    h.stop().await;
}
