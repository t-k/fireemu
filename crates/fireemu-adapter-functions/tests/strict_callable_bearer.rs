//! The strict profile's Bearer check for callables, through the HTTP ingress.
//!
//! A callable's wrapper under the Auth emulator accepts any structurally valid ID token without
//! checking its signature (the Admin SDK's emulator mode, in Node and in Python), so the daemon
//! verifies the Bearer itself before anything is forwarded. The check must not depend on how the
//! runner's HTTP server reads a request: two `Authorization` headers are refused here, because a
//! server that merges or picks one of them would hand the wrapper a credential the daemon never
//! verified.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use fireemu_adapter_functions::http::{
    parse_response, FunctionsHttpProfile, HttpAdmission, ProxiedResponse,
};
use fireemu_adapter_functions::manifest_json::parse_manifest;
use fireemu_adapter_functions::runner::{Runner, SpawnSpec};
use fireemu_adapter_functions::runtime::{FunctionsConfig, FunctionsRuntime};
use fireemu_adapter_grpc::rules::RulesEnforcer;
use fireemu_core_auth::jwt::{base64url_encode, encode_unsigned};
use fireemu_core_auth::mfa::TotpPolicy;
use fireemu_core_auth::store::{AuthStore, NewUser};
use fireemu_core_functions::manifest::{ConsumeAppCheckToken, Trigger};
use fireemu_core_rules::runtime::RulesetSlot;
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_types::determinism::SplitMix64;
use fireemu_core_types::time::LogicalInstant;

const START: LogicalInstant = LogicalInstant::from_unix_seconds(1_788_004_860);
const PROJECT: &str = "demo-app";

struct Harness {
    addr: std::net::SocketAddr,
    runtime: Arc<FunctionsRuntime>,
    auth: Arc<Mutex<AuthStore>>,
    server: tokio::task::JoinHandle<std::io::Result<()>>,
}

/// A strict runtime with one callable, `callableA`, served by the fake runner (whose answer to a
/// request that reached it contains `"method"`).
async fn start() -> Harness {
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fake_runner.py");
    let spec = SpawnSpec {
        command: vec!["python3".to_owned(), script.to_owned()],
        cwd: None,
        env: Vec::new(),
        hello_timeout: Duration::from_secs(60),
    };
    let runner = Runner::spawn_spec(&spec)
        .await
        .expect("the fake runner starts");
    let mut manifest = parse_manifest(runner.hello().manifest.as_ref().unwrap()).unwrap();
    let mut callable = manifest.get("echo").unwrap().clone();
    "callableA".clone_into(&mut callable.name);
    "callableA".clone_into(&mut callable.entry_point);
    callable.trigger = Trigger::Http {
        callable: true,
        enforce_app_check: false,
        consume_app_check_token: ConsumeAppCheckToken::Disabled,
    };
    manifest.functions.push(callable);
    let clock = Arc::new(Mutex::new(VirtualClock::new(START)));
    let runtime = FunctionsRuntime::new(
        manifest,
        FunctionsConfig {
            project: PROJECT.into(),
            functions_host: Some("127.0.0.1:5001".into()),
            ..FunctionsConfig::for_tests(1000, "runner-secret".into())
        },
        clock.clone(),
        Arc::new(runner),
        Some(spec),
    );
    let auth = Arc::new(Mutex::new(AuthStore::new(
        PROJECT,
        SplitMix64::new(3),
        TotpPolicy::default(),
    )));
    runtime.set_callable_auth_verifier(Arc::new(RulesEnforcer::new(
        Arc::new(RulesetSlot::default()),
        auth.clone(),
        clock,
    )));
    tokio::spawn(runtime.clone().dispatch_loop());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let for_listener = runtime.clone();
    let server = tokio::spawn(async move {
        fireemu_adapter_functions::http::serve_functions_with_profile(
            listener,
            for_listener,
            HttpAdmission::new(),
            FunctionsHttpProfile::Strict,
        )
        .await
    });
    Harness {
        addr,
        runtime,
        auth,
        server,
    }
}

impl Harness {
    /// The ID token of a user that exists, as the Auth emulator issues it.
    fn user_token(&self, email: &str) -> String {
        let mut store = self.auth.lock().unwrap();
        let uid = store.create_user(NewUser::email(email), START).unwrap();
        let claims = store.id_token_claims(&uid, None, START).unwrap();
        encode_unsigned(&claims)
    }

    async fn call(&self, headers: &[(&str, &str)]) -> ProxiedResponse {
        use std::fmt::Write as _;
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let body = br#"{"data":{}}"#;
        let mut request = format!("POST /{PROJECT}/us-central1/callableA HTTP/1.1\r\n");
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

    async fn stop(self) {
        self.server.abort();
        self.runtime.shutdown().await;
    }
}

fn reached_the_handler(answer: &ProxiedResponse) -> bool {
    String::from_utf8_lossy(&answer.body).contains("\"method\"")
}

/// An unsigned token for a user the Auth emulator has never created: structurally valid, forged.
fn forged_admin_token() -> String {
    let header = base64url_encode(br#"{"alg":"none","typ":"JWT"}"#);
    let claims = br#"{"iss":"https://securetoken.google.com/demo-app","aud":"demo-app","sub":"forged-admin","user_id":"forged-admin","iat":1788004860,"exp":1788008460,"firebase":{"sign_in_provider":"anonymous","identities":{}}}"#;
    format!("{header}.{}.", base64url_encode(claims))
}

#[tokio::test]
async fn a_call_without_a_credential_or_with_a_verified_user_reaches_the_handler() {
    let h = start().await;
    let anonymous = h.call(&[]).await;
    assert_eq!(anonymous.status, 200);
    assert!(reached_the_handler(&anonymous));
    let bearer = format!("Bearer {}", h.user_token("signed-in@example.com"));
    let user = h.call(&[("authorization", &bearer)]).await;
    assert_eq!(user.status, 200);
    assert!(reached_the_handler(&user));
    h.stop().await;
}

#[tokio::test]
async fn two_authorization_headers_are_refused_before_anything_is_forwarded() {
    let h = start().await;
    let valid = format!("Bearer {}", h.user_token("signed-in@example.com"));
    let forged = format!("Bearer {}", forged_admin_token());
    // The exploit: a server that merges the two values hands the wrapper `Bearer <forged>, AAAA`.
    for headers in [
        vec![
            ("authorization", forged.as_str()),
            ("authorization", "AAAA"),
        ],
        vec![
            ("authorization", "AAAA"),
            ("authorization", forged.as_str()),
        ],
        vec![("authorization", valid.as_str()), ("authorization", "AAAA")],
        vec![
            ("authorization", valid.as_str()),
            ("authorization", valid.as_str()),
        ],
        vec![
            ("authorization", forged.as_str()),
            ("Authorization", forged.as_str()),
        ],
    ] {
        let answer = h.call(&headers).await;
        assert_eq!(answer.status, 401, "{headers:?}");
        assert!(!reached_the_handler(&answer), "{headers:?}");
    }
    h.stop().await;
}

#[tokio::test]
async fn a_structurally_valid_token_for_a_user_that_does_not_exist_is_refused() {
    let h = start().await;
    let answer = h
        .call(&[("authorization", &format!("Bearer {}", forged_admin_token()))])
        .await;
    assert_eq!(answer.status, 401);
    assert!(!reached_the_handler(&answer));
    h.stop().await;
}

#[tokio::test]
async fn a_token_carrying_a_real_users_claims_with_a_forged_signature_is_refused() {
    let h = start().await;
    let unsigned = h.user_token("victim@example.com");
    let mut parts = unsigned.split('.');
    let payload = parts.nth(1).unwrap();
    let header = base64url_encode(br#"{"alg":"RS256","typ":"JWT","kid":"forged"}"#);
    let forged = format!("{header}.{payload}.{}", base64url_encode(&[7_u8; 256]));
    let answer = h
        .call(&[("authorization", &format!("Bearer {forged}"))])
        .await;
    assert_eq!(answer.status, 401);
    assert!(!reached_the_handler(&answer));
    h.stop().await;
}

#[tokio::test]
async fn a_single_credential_that_is_not_a_verified_bearer_gets_the_wrappers_envelope() {
    // Production's wrapper refuses these itself, with its own 401 envelope, and the handler never
    // runs (FUNCTIONS-HTTP-CALLABLE-INGRESS: another scheme, a scheme without a token; the
    // re-recordings: a token of the project with a bad signature or past its expiry).
    let h = start().await;
    for value in ["Basic dXNlcjpwYXNz", "Bearer ", "AAAA", "Bearer malformed"] {
        let answer = h.call(&[("authorization", value)]).await;
        assert_eq!(answer.status, 401, "{value}");
        assert!(!reached_the_handler(&answer), "{value}");
        assert_eq!(
            answer.body, br#"{"error":{"message":"Unauthenticated","status":"UNAUTHENTICATED"}}"#,
            "{value}"
        );
    }
    h.stop().await;
}
