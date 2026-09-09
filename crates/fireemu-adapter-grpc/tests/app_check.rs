//! App Check enforcement for Cloud Firestore (specification sections 12, 13.1, 17 and 19;
//! obligations `AC-FS-001`, `AC-BOUNDARY-001` and `AC-HEADER-001`).
//!
//! Milestone AC1 covered the unary gRPC surface and Firestore REST; milestone AC2 added the
//! `Write` / `Listen` stream and `WebChannel` lifetime contracts. The Firestore scenarios
//! checked here are 1 (an enforced unary request rejects a valid Auth user before Rules
//! evaluation), 2 (an unenforced request admits an invalid token without creating an app
//! identity), 3 (an admitted stream stays admitted after its token expires, until it
//! reconnects), 4 (a `WebChannel` rejects a replacement token from another app) and 5 (owner
//! traffic follows the explicit bypass).
//!
//! The signer is a deterministic stand-in rather than RS256: the shell's real `rsa` / `sha2`
//! implementations are exercised by the `fireemu-adapter-http` App Check tests, and key generation
//! is far too slow for a matrix of this size in a debug build.

use std::sync::{Arc, Mutex, RwLock};

use fireemu_adapter_grpc::gateway::Gateway;
use fireemu_adapter_grpc::local::LocalBackend;
use fireemu_adapter_grpc::rest::{RestRequest, RestState};
use fireemu_adapter_grpc::rules::RulesEnforcer;
use fireemu_adapter_grpc::service::GatewayService;
use fireemu_adapter_grpc::webchannel::{ChannelRequest, ChannelResponse, Hub, StreamKind};
use fireemu_core_app_check::admission::{AppCheckGate, ServiceAdmission};
use fireemu_core_app_check::claims::{audiences_for, issuer_for, AppCheckClaims};
use fireemu_core_app_check::crypto::AppCheckSigner;
use fireemu_core_app_check::registry::{AppCheckRegistry, AppRegistration, ProjectEpoch};
use fireemu_core_app_check::verify::BaselineMode;
use fireemu_core_auth::jwt::encode_unsigned;
use fireemu_core_auth::mfa::TotpPolicy;
use fireemu_core_auth::store::{AuthStore, NewUser};
use fireemu_core_firestore::index::{IndexSet, IndexValidationPolicy, PlanningContext};
use fireemu_core_rules::runtime::{LoadedRules, RulesetSlot};
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_types::determinism::{DeterministicRng, SplitMix64};
use fireemu_core_types::edition::{FirestoreApiMode, FirestoreEdition};
use fireemu_core_types::time::LogicalInstant;
use fireemu_proto_firestore::google::firestore::v1 as pb;
use fireemu_proto_firestore::google::firestore::v1::firestore_client::FirestoreClient;
use fireemu_proto_firestore::google::firestore::v1::firestore_server::FirestoreServer;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::metadata::MetadataValue;
use tonic::{Code, Request};

const DATABASE: &str = "projects/demo-app/databases/(default)";
const DOCS: &str = "projects/demo-app/databases/(default)/documents";
const START_SECONDS: i64 = 1_788_004_860;
const START: LogicalInstant = LogicalInstant::from_unix_seconds(START_SECONDS);
const APP_ID: &str = "1:1234567890:web:local-test-app";
/// A second app of the *same* project: what tells "another app" apart from "another project".
const SECOND_APP_ID: &str = "1:1234567890:web:second-test-app";
const OTHER_APP_ID: &str = "1:9876543210:web:other-test-app";
const UNREGISTERED_APP_ID: &str = "1:1234567890:web:not-registered";

/// Every profile is readable and writable by its owner; nothing else is.
const RULES: &str = r"
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /profiles/{uid} {
      allow read, write: if request.auth != null && request.auth.uid == uid;
    }
  }
}
";

// ------------------------------------------------------------------------------------------
// A deterministic stand-in for the RS256 signer (see the module comment).
// ------------------------------------------------------------------------------------------

fn keyed_tag(key: u64, input: &[u8]) -> [u8; 32] {
    let mut acc = SplitMix64::new(key).next_u64();
    for byte in input {
        acc = SplitMix64::new(acc ^ u64::from(*byte).wrapping_mul(0x9E37_79B9)).next_u64();
    }
    let mut out = [0u8; 32];
    for chunk in 0..4 {
        let word = SplitMix64::new(acc ^ chunk as u64).next_u64();
        out[chunk * 8..chunk * 8 + 8].copy_from_slice(&word.to_be_bytes());
    }
    out
}

struct TestSigner {
    key: u64,
    kid: String,
}

impl TestSigner {
    fn new(key: u64) -> Self {
        Self {
            key,
            kid: format!("fireemu-app-check-{key:016x}"),
        }
    }
}

impl AppCheckSigner for TestSigner {
    fn alg(&self) -> &'static str {
        "RS256"
    }
    fn kid(&self) -> &str {
        &self.kid
    }
    fn sign(&self, signing_input: &[u8]) -> Vec<u8> {
        keyed_tag(self.key, signing_input).to_vec()
    }
    fn verify(&self, signing_input: &[u8], signature: &[u8]) -> bool {
        signature == self.sign(signing_input)
    }
    fn public_jwk_json(&self) -> String {
        format!(r#"{{"kty":"oct","kid":"{}"}}"#, self.kid)
    }
}

fn registry() -> AppCheckRegistry {
    let mut registry = AppCheckRegistry::new(3600).expect("3600s is inside the TTL range");
    registry
        .register_app(AppRegistration {
            project_id: "demo-app".to_owned(),
            project_number: "1234567890".to_owned(),
            app_id: APP_ID.to_owned(),
            enabled: true,
            debug_token_digests: Vec::new(),
        })
        .expect("the demo app registers");
    registry
        .register_app(AppRegistration {
            project_id: "demo-app".to_owned(),
            project_number: "1234567890".to_owned(),
            app_id: SECOND_APP_ID.to_owned(),
            enabled: true,
            debug_token_digests: Vec::new(),
        })
        .expect("the second app of the demo project registers");
    registry
        .register_app(AppRegistration {
            project_id: "demo-other".to_owned(),
            project_number: "9876543210".to_owned(),
            app_id: OTHER_APP_ID.to_owned(),
            enabled: true,
            debug_token_digests: Vec::new(),
        })
        .expect("the second app registers");
    registry.set_project_epoch("demo-app", ProjectEpoch::new(0x0123_4567_89AB_CDEF));
    registry.set_project_epoch("demo-other", ProjectEpoch::new(0xFEDC_BA98_7654_3210));
    registry
}

fn gate() -> AppCheckGate {
    AppCheckGate::new(
        Arc::new(RwLock::new(registry())),
        Arc::new(TestSigner::new(11)),
    )
}

fn token_at(gate: &AppCheckGate, project: &str, app_id: &str, at: LogicalInstant) -> String {
    let registry = gate.registry().read().expect("readable");
    let claims = registry
        .issue_claims(project, app_id, at)
        .expect("the fixture app may exchange");
    fireemu_core_app_check::jwt::encode(&claims, gate.signer().as_ref())
}

/// Every credential state of the enforcement matrix (section 19), as header values.
fn credential_states(gate: &AppCheckGate) -> Vec<(&'static str, Option<String>)> {
    let valid = token_at(gate, "demo-app", APP_ID, START);
    let mut forged = valid.clone();
    forged.pop();
    forged.push(if valid.ends_with('A') { 'B' } else { 'A' });
    let expired = token_at(
        gate,
        "demo-app",
        APP_ID,
        LogicalInstant::from_unix_seconds(START_SECONDS - 7200),
    );
    let epoch = gate
        .registry()
        .read()
        .expect("readable")
        .project_epoch("demo-app")
        .expect("an epoch");
    let unknown_app = fireemu_core_app_check::jwt::encode(
        &AppCheckClaims {
            iss: issuer_for("1234567890"),
            sub: UNREGISTERED_APP_ID.to_owned(),
            aud: audiences_for("1234567890", "demo-app"),
            iat: START_SECONDS,
            exp: START_SECONDS + 3600,
            jti: "forged-1".to_owned(),
            fireemu_epoch: epoch.claim_text(),
        },
        gate.signer().as_ref(),
    );
    vec![
        ("missing", None),
        ("valid", Some(valid)),
        ("malformed", Some("not-a-jwt".to_owned())),
        ("bad signature", Some(forged)),
        ("expired", Some(expired)),
        (
            "wrong project",
            Some(token_at(gate, "demo-other", OTHER_APP_ID, START)),
        ),
        ("unknown app", Some(unknown_app)),
    ]
}

// ------------------------------------------------------------------------------------------
// Harness: a real gRPC server with Security Rules and an App Check policy, plus REST.
// ------------------------------------------------------------------------------------------

struct Harness {
    client: FirestoreClient<tonic::transport::Channel>,
    rest: Arc<RestState>,
    hub: Hub,
    auth: Arc<Mutex<AuthStore>>,
    gate: AppCheckGate,
    backend: Arc<LocalBackend>,
    clock: Arc<Mutex<VirtualClock>>,
    handle: tokio::task::JoinHandle<()>,
}

async fn start(mode: BaselineMode) -> Harness {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("a local address");
    let gateway = Gateway {
        enforce_limits: true,
        ctx: PlanningContext {
            edition: FirestoreEdition::Standard,
            api_mode: FirestoreApiMode::Native,
            policy: IndexValidationPolicy::Production,
        },
        indexes: IndexSet::default(),
    };
    let clock = Arc::new(Mutex::new(VirtualClock::new(START)));
    let backend = Arc::new(LocalBackend::new(gateway.clone(), clock.clone(), 7));
    let enforcer_clock = clock.clone();
    let auth = Arc::new(Mutex::new(AuthStore::new(
        "demo-app",
        SplitMix64::new(3),
        TotpPolicy::default(),
    )));
    let rules = Arc::new(RulesetSlot::new(
        LoadedRules::from_source(RULES).expect("the fixture ruleset compiles"),
    ));
    let enforcer = Arc::new(RulesEnforcer::new(rules, auth.clone(), enforcer_clock));
    let gate = gate();
    let policy = ServiceAdmission::new(gate.clone(), "firestore", mode).map(Arc::new);

    let mut service =
        GatewayService::local(gateway.clone(), backend.clone()).with_rules(enforcer.clone());
    if let Some(policy) = &policy {
        service = service.with_app_check(policy.clone());
    }
    let svc = FirestoreServer::new(service);
    let handle = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(svc)
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .expect("the test server runs");
    });
    let channel = tonic::transport::Endpoint::from_shared(format!("http://{addr}"))
        .expect("a valid endpoint")
        .connect()
        .await
        .expect("connect");
    let rest = Arc::new(RestState {
        local: backend.clone(),
        gateway: Arc::new(gateway),
        rules: Some(enforcer),
        app_check: policy,
    });
    Harness {
        client: FirestoreClient::new(channel),
        hub: Hub::new(rest.clone()),
        rest,
        auth,
        gate,
        backend,
        clock,
        handle,
    }
}

impl Harness {
    fn user(&self, email: &str) -> (String, String) {
        let mut store = self.auth.lock().expect("the store is not poisoned");
        let uid = store
            .create_user(NewUser::email(email), START)
            .expect("the user is created");
        let claims = store
            .id_token_claims(&uid, None, START)
            .expect("claims for the new user");
        (uid.as_str().to_owned(), encode_unsigned(&claims))
    }

    /// A signed-in user whose ID token is minted at `at`, so a test that moves the clock can
    /// keep a valid Auth credential while the App Check token ages out.
    fn user_at(&self, email: &str, at: LogicalInstant) -> (String, String) {
        let mut store = self.auth.lock().expect("the store is not poisoned");
        let uid = store
            .create_user(NewUser::email(email), START)
            .expect("the user is created");
        let claims = store
            .id_token_claims(&uid, None, at)
            .expect("claims for the new user");
        (uid.as_str().to_owned(), encode_unsigned(&claims))
    }

    fn token(&self) -> String {
        token_at(&self.gate, "demo-app", APP_ID, START)
    }

    /// A valid token for the other app of the same project.
    fn other_app_token(&self) -> String {
        token_at(&self.gate, "demo-app", SECOND_APP_ID, START)
    }

    /// Moves the virtual clock forward, as the control API clock route does.
    fn advance(&self, seconds: i64) {
        self.clock
            .lock()
            .expect("the clock is not poisoned")
            .advance(fireemu_core_types::time::LogicalDuration::from_seconds(
                seconds,
            ))
            .expect("the fixture clock moves forward");
    }

    /// The observation ring of the fixture's project. The registry keeps one per project.
    fn observations(&self) -> Vec<fireemu_core_app_check::observe::Observation> {
        self.gate
            .registry()
            .read()
            .expect("readable")
            .observations("demo-app")
    }

    /// A REST request with the given credentials.
    fn rest_call(
        &self,
        method: &str,
        path_and_query: &str,
        authorization: Option<&str>,
        app_check: &[&str],
        body: serde_json::Value,
    ) -> (u16, serde_json::Value) {
        let (path, query) = path_and_query
            .split_once('?')
            .map_or((path_and_query, ""), |(p, q)| (p, q));
        let r = self.rest.handle(&RestRequest {
            method: method.to_owned(),
            path: path.to_owned(),
            query: query.to_owned(),
            authorization: authorization.map(str::to_owned),
            app_check: app_check.iter().map(|v| (*v).to_owned()).collect(),
            body,
        });
        (r.status, r.body)
    }
}

fn request<T>(body: T, authorization: Option<&str>, app_check: &[&str]) -> Request<T> {
    let mut r = Request::new(body);
    if let Some(value) = authorization {
        r.metadata_mut().insert(
            "authorization",
            MetadataValue::try_from(value).expect("an ASCII credential"),
        );
    }
    for value in app_check {
        r.metadata_mut().append(
            "x-firebase-appcheck",
            MetadataValue::try_from(*value).unwrap_or_else(|_| MetadataValue::from_static("")),
        );
    }
    r
}

fn s(v: &str) -> pb::Value {
    pb::Value {
        value_type: Some(pb::value::ValueType::StringValue(v.to_owned())),
    }
}

fn profile(uid: &str) -> pb::CreateDocumentRequest {
    pb::CreateDocumentRequest {
        parent: DOCS.to_owned(),
        collection_id: "profiles".to_owned(),
        document_id: uid.to_owned(),
        document: Some(pb::Document {
            fields: [("name".to_owned(), s("Ada"))].into_iter().collect(),
            ..pb::Document::default()
        }),
        mask: None,
        request_options: None,
    }
}

// ------------------------------------------------------------------------------------------
// Scenario 1: an enforced unary request rejects a valid Auth user before Rules evaluation
// ------------------------------------------------------------------------------------------

#[tokio::test]
async fn enforced_unary_firestore_rejects_a_valid_auth_user_without_app_check_before_rules() {
    let mut h = start(BaselineMode::Enforced).await;
    let (uid, id_token) = h.user("ada@example.com");
    let bearer = format!("Bearer {id_token}");

    // The rules would allow this write: the user owns the profile it creates.
    let denied = h
        .client
        .create_document(request(profile(&uid), Some(&bearer), &[]))
        .await
        .expect_err("an enforced request without App Check is denied");
    assert_eq!(denied.code(), Code::PermissionDenied);
    assert_eq!(
        denied
            .metadata()
            .get("fireemu-code")
            .and_then(|v| v.to_str().ok()),
        Some("APP_CHECK_REQUIRED")
    );
    assert!(
        !denied.message().contains("Security Rules"),
        "the denial is App Check's, not the ruleset's: {}",
        denied.message()
    );

    // No document exists, so Rules never ran and nothing was written.
    let read = h
        .client
        .get_document(request(
            pb::GetDocumentRequest {
                name: format!("{DOCS}/profiles/{uid}"),
                ..pb::GetDocumentRequest::default()
            },
            Some("Bearer owner"),
            &[],
        ))
        .await;
    assert_eq!(
        read.expect_err("nothing was created").code(),
        Code::NotFound
    );

    // The same request with a valid token goes through and is then judged by the rules.
    let token = h.token();
    let created = h
        .client
        .create_document(request(profile(&uid), Some(&bearer), &[&token]))
        .await;
    assert!(created.is_ok(), "{:?}", created.err());
    h.handle.abort();
}

/// The App Check denial reaches the request before the ruleset does: a request the rules would
/// have refused anyway still reports the App Check reason, never a rules denial.
#[tokio::test]
async fn an_app_check_denial_precedes_a_rules_denial() {
    let mut h = start(BaselineMode::Enforced).await;
    let (_, id_token) = h.user("ada@example.com");
    let bearer = format!("Bearer {id_token}");
    let denied = h
        .client
        .create_document(request(profile("someone-else"), Some(&bearer), &[]))
        .await
        .expect_err("denied");
    assert_eq!(denied.code(), Code::PermissionDenied);
    assert_eq!(
        denied
            .metadata()
            .get("fireemu-code")
            .and_then(|v| v.to_str().ok()),
        Some("APP_CHECK_REQUIRED")
    );
    h.handle.abort();
}

// ------------------------------------------------------------------------------------------
// Scenario 2: unenforced admits an invalid token without creating an app identity
// ------------------------------------------------------------------------------------------

#[tokio::test]
async fn unenforced_firestore_admits_an_invalid_app_check_token_without_an_app_identity() {
    let mut h = start(BaselineMode::Unenforced).await;
    let (uid, id_token) = h.user("ada@example.com");
    let bearer = format!("Bearer {id_token}");
    let created = h
        .client
        .create_document(request(profile(&uid), Some(&bearer), &["not-a-jwt"]))
        .await;
    assert!(created.is_ok(), "{:?}", created.err());

    let observed = h.observations();
    assert_eq!(observed.len(), 1);
    assert_eq!(observed[0].service, "firestore");
    assert_eq!(observed[0].transport, "grpc");
    assert_eq!(observed[0].operation, "CreateDocument");
    assert_eq!(
        observed[0].category,
        fireemu_core_app_check::observe::CredentialCategory::Invalid
    );
    assert_eq!(
        observed[0].app_id, "unknown",
        "an invalid token never becomes an app identity"
    );
    assert!(observed[0].admitted);
    h.handle.abort();
}

// ------------------------------------------------------------------------------------------
// Scenario 5: owner traffic follows the explicit App Check bypass
// ------------------------------------------------------------------------------------------

#[tokio::test]
async fn owner_traffic_follows_the_explicit_app_check_bypass() {
    let mut h = start(BaselineMode::Enforced).await;
    let created = h
        .client
        .create_document(request(profile("owned"), Some("Bearer owner"), &[]))
        .await;
    assert!(created.is_ok(), "{:?}", created.err());
    assert_eq!(
        h.observations().last().map(|o| o.category),
        Some(fireemu_core_app_check::observe::CredentialCategory::Bypass)
    );
    h.handle.abort();
}

/// The bypass is the credential, not its shape: anything else is an ordinary request.
#[tokio::test]
async fn an_owner_shaped_credential_that_is_not_the_owner_does_not_bypass() {
    let mut h = start(BaselineMode::Enforced).await;
    for credential in [
        None,
        Some("Bearer owner-ish"),
        Some("Bearer ownerx"),
        Some("bearer owner"),
        Some("Bearer  owner"),
    ] {
        let denied = h
            .client
            .create_document(request(profile("nope"), credential, &[]))
            .await
            .expect_err("only the exact owner credential bypasses");
        assert_eq!(denied.code(), Code::PermissionDenied, "{credential:?}");
    }
    h.handle.abort();
}

// ------------------------------------------------------------------------------------------
// The enforcement matrix: mode x credential state, on both Firestore ingresses (section 19)
// ------------------------------------------------------------------------------------------

#[tokio::test]
async fn the_firestore_grpc_matrix_holds_for_every_mode_and_credential_state() {
    for (mode, denies) in [
        (BaselineMode::Off, false),
        (BaselineMode::Unenforced, false),
        (BaselineMode::Enforced, true),
    ] {
        let mut h = start(mode).await;
        for (index, (name, value)) in credential_states(&h.gate).into_iter().enumerate() {
            let values: Vec<&str> = value.iter().map(String::as_str).collect();
            let outcome = h
                .client
                .create_document(request(profile(&format!("m{index}")), None, &values))
                .await;
            if denies && name != "valid" {
                let status = outcome.expect_err("denied");
                assert_eq!(status.code(), Code::PermissionDenied, "{mode}/{name}");
                assert_eq!(
                    status
                        .metadata()
                        .get("fireemu-code")
                        .and_then(|v| v.to_str().ok()),
                    Some(if name == "missing" {
                        "APP_CHECK_REQUIRED"
                    } else {
                        "APP_CHECK_INVALID"
                    }),
                    "{mode}/{name} renders the public code only"
                );
            } else {
                // Everything else reaches Security Rules, which refuse an unauthenticated
                // write. That is exactly the point: App Check admitted it.
                let status = outcome.expect_err("the ruleset still judges the request");
                assert!(
                    status.message().contains("Security Rules"),
                    "{mode}/{name} must be judged by the rules, not by App Check: {}",
                    status.message()
                );
            }
        }
        h.handle.abort();
    }
}

#[tokio::test]
async fn the_firestore_rest_matrix_holds_for_every_mode_and_credential_state() {
    for (mode, denies) in [
        (BaselineMode::Off, false),
        (BaselineMode::Unenforced, false),
        (BaselineMode::Enforced, true),
    ] {
        let h = start(mode).await;
        for (index, (name, value)) in credential_states(&h.gate).into_iter().enumerate() {
            let values: Vec<&str> = value.iter().map(String::as_str).collect();
            let (status, body) = h.rest_call(
                "POST",
                &format!("/v1/{DOCS}/profiles?documentId=r{index}"),
                None,
                &values,
                serde_json::json!({"fields": {"name": {"stringValue": "Ada"}}}),
            );
            if denies && name != "valid" {
                assert_eq!(status, 403, "{mode}/{name}: {body}");
                assert_eq!(body["error"]["status"], "PERMISSION_DENIED");
                assert!(
                    !body.to_string().contains("Security Rules"),
                    "{mode}/{name} is an App Check denial: {body}"
                );
            } else {
                assert_eq!(status, 403, "{mode}/{name}: {body}");
                assert!(
                    body.to_string().contains("Security Rules"),
                    "{mode}/{name} must be judged by the rules: {body}"
                );
            }
        }
        h.handle.abort();
    }
}

#[tokio::test]
async fn firestore_rest_owner_traffic_follows_the_explicit_bypass() {
    let h = start(BaselineMode::Enforced).await;
    let (status, body) = h.rest_call(
        "POST",
        &format!("/v1/{DOCS}/profiles?documentId=rest-owner"),
        Some("Bearer owner"),
        &[],
        serde_json::json!({"fields": {"name": {"stringValue": "Ada"}}}),
    );
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        h.observations().last().map(|o| o.transport),
        Some("http"),
        "the REST ingress records its own transport"
    );
    h.handle.abort();
}

// ------------------------------------------------------------------------------------------
// The header contract on both transports (AC-HEADER-001)
// ------------------------------------------------------------------------------------------

#[tokio::test]
async fn firestore_metadata_refuses_duplicate_folded_empty_and_oversized_app_check_fields() {
    let mut h = start(BaselineMode::Enforced).await;
    let valid = h.token();
    let folded = format!("{valid},{valid}");
    let cases: Vec<(&str, Vec<&str>)> = vec![
        ("duplicate", vec![valid.as_str(), valid.as_str()]),
        ("folded", vec![folded.as_str()]),
        ("empty", vec![""]),
    ];
    for (name, values) in cases {
        let denied = h
            .client
            .create_document(request(profile("hdr"), None, &values))
            .await
            .expect_err("an ambiguous field is never a credential");
        assert_eq!(denied.code(), Code::PermissionDenied, "{name}");
        assert_eq!(
            denied
                .metadata()
                .get("fireemu-code")
                .and_then(|v| v.to_str().ok()),
            Some("APP_CHECK_INVALID"),
            "{name}"
        );
    }
    // An oversized value never reaches the daemon: the HTTP/2 header list is refused first.
    // The outcome the contract asks for is the same, so only the failure is asserted here,
    // and the size budget itself is checked on the REST transport below.
    let oversized = "a".repeat(16 * 1024 + 1);
    let refused = h
        .client
        .create_document(request(profile("hdr"), None, &[oversized.as_str()]))
        .await;
    assert!(refused.is_err(), "an oversized field is never a credential");

    // And one well-formed value is admitted through to the rules.
    let admitted = h
        .client
        .create_document(request(profile("hdr"), None, &[&valid]))
        .await
        .expect_err("the ruleset refuses an unauthenticated write");
    assert!(
        admitted.message().contains("Security Rules"),
        "{}",
        admitted.message()
    );
    h.handle.abort();
}

#[tokio::test]
async fn firestore_rest_refuses_duplicate_folded_empty_and_oversized_app_check_fields() {
    let h = start(BaselineMode::Enforced).await;
    let valid = token_at(&h.gate, "demo-app", APP_ID, START);
    let folded = format!("{valid},{valid}");
    let oversized = "a".repeat(16 * 1024 + 1);
    let cases: Vec<(&str, Vec<&str>)> = vec![
        ("duplicate", vec![valid.as_str(), valid.as_str()]),
        ("folded", vec![folded.as_str()]),
        ("empty", vec![""]),
        ("oversized", vec![oversized.as_str()]),
    ];
    for (name, values) in cases {
        let (status, body) = h.rest_call(
            "GET",
            &format!("/v1/{DOCS}/profiles/anything"),
            None,
            &values,
            serde_json::json!({}),
        );
        assert_eq!(status, 403, "{name}: {body}");
        assert!(
            !body.to_string().contains("Security Rules"),
            "{name} is an App Check denial: {body}"
        );
    }
    h.handle.abort();
}

// ------------------------------------------------------------------------------------------
// Lifecycle: an epoch rotation invalidates every token issued before it (AC-LIFE-001)
// ------------------------------------------------------------------------------------------

#[tokio::test]
async fn rotating_the_project_epoch_invalidates_an_issued_token_on_the_wire() {
    let mut h = start(BaselineMode::Enforced).await;
    let token = h.token();
    let created = h
        .client
        .create_document(request(profile("before"), Some("Bearer owner"), &[&token]))
        .await;
    assert!(created.is_ok(), "{:?}", created.err());

    // The daemon's lifecycle hooks do this under the exclusive admission barrier.
    let barrier = h.backend.barrier();
    let exclusive = barrier.exclusive();
    let rotated = h.gate.projects(|project| project == "demo-app");
    assert_eq!(rotated.len(), 1);
    h.gate
        .set_epochs(&[("demo-app".to_owned(), ProjectEpoch::new(0xABCD))]);
    drop(exclusive);

    let denied = h
        .client
        .create_document(request(profile("after"), None, &[&token]))
        .await
        .expect_err("a pre-rotation token is refused");
    assert_eq!(denied.code(), Code::PermissionDenied);
    assert_eq!(
        denied
            .metadata()
            .get("fireemu-code")
            .and_then(|v| v.to_str().ok()),
        Some("APP_CHECK_INVALID")
    );
    h.handle.abort();
}

// ------------------------------------------------------------------------------------------
// Observations (AC-OBS-001)
// ------------------------------------------------------------------------------------------

#[tokio::test]
async fn an_off_firestore_service_classifies_nothing() {
    let mut h = start(BaselineMode::Off).await;
    let _ = h
        .client
        .create_document(request(
            profile("off"),
            Some("Bearer owner"),
            &["junk", "junk"],
        ))
        .await;
    assert!(h.observations().is_empty(), "off does no token work at all");
    h.handle.abort();
}

#[tokio::test]
async fn a_firestore_observation_never_carries_the_raw_token() {
    let mut h = start(BaselineMode::Unenforced).await;
    let token = h.token();
    let _ = h
        .client
        .create_document(request(profile("obs"), Some("Bearer owner"), &[&token]))
        .await;
    let rendered = format!("{:?}", h.observations());
    assert!(!rendered.contains(&token), "{rendered}");
    h.handle.abort();
}

// ------------------------------------------------------------------------------------------
// Streams (specification section 13.1; Firestore scenario 3)
// ------------------------------------------------------------------------------------------

/// The stream helpers below drive a real `Write` / `Listen` stream over the tonic client and
/// return the first response, which is where a denial arrives: the opening metadata is
/// classified when the stream is created and the decision is taken as soon as the first
/// message names the database.
async fn write_stream_first(
    h: &mut Harness,
    authorization: Option<&str>,
    app_check: &[&str],
) -> Result<pb::WriteResponse, tonic::Status> {
    let (tx, rx) = tokio::sync::mpsc::channel(8);
    let mut responses = h
        .client
        .write(request(
            tokio_stream::wrappers::ReceiverStream::new(rx),
            authorization,
            app_check,
        ))
        .await
        .expect("the stream opens")
        .into_inner();
    tx.send(pb::WriteRequest {
        database: DATABASE.to_owned(),
        ..pb::WriteRequest::default()
    })
    .await
    .expect("the handshake is sent");
    let first = tokio_stream::StreamExt::next(&mut responses)
        .await
        .expect("a first response");
    drop(tx);
    first
}

async fn listen_stream_first(
    h: &mut Harness,
    authorization: Option<&str>,
    app_check: &[&str],
) -> Result<pb::ListenResponse, tonic::Status> {
    let (tx, rx) = tokio::sync::mpsc::channel(8);
    let mut responses = h
        .client
        .listen(request(
            tokio_stream::wrappers::ReceiverStream::new(rx),
            authorization,
            app_check,
        ))
        .await
        .expect("the stream opens")
        .into_inner();
    tx.send(pb::ListenRequest {
        database: DATABASE.to_owned(),
        target_change: Some(pb::listen_request::TargetChange::AddTarget(pb::Target {
            target_id: 2,
            target_type: Some(pb::target::TargetType::Query(pb::target::QueryTarget {
                parent: DOCS.to_owned(),
                query_type: Some(pb::target::query_target::QueryType::StructuredQuery(
                    pb::StructuredQuery {
                        from: vec![pb::structured_query::CollectionSelector {
                            collection_id: "profiles".to_owned(),
                            all_descendants: false,
                        }],
                        ..pb::StructuredQuery::default()
                    },
                )),
            })),
            ..pb::Target::default()
        })),
        ..pb::ListenRequest::default()
    })
    .await
    .expect("the first target is sent");
    let first = tokio_stream::StreamExt::next(&mut responses)
        .await
        .expect("a first response");
    drop(tx);
    first
}

#[tokio::test]
async fn an_enforced_write_stream_without_app_check_is_denied_before_the_handshake() {
    let mut h = start(BaselineMode::Enforced).await;
    let err = write_stream_first(&mut h, None, &[])
        .await
        .expect_err("an enforced Write stream needs a token");
    assert_eq!(err.code(), Code::PermissionDenied);
    assert_eq!(
        err.metadata()
            .get("fireemu-code")
            .map(|v| v.to_str().unwrap()),
        Some("APP_CHECK_REQUIRED")
    );
    let token = h.token();
    let ok = write_stream_first(&mut h, None, &[&token])
        .await
        .expect("a valid token opens the stream");
    assert!(!ok.stream_id.is_empty(), "the handshake answered");
    h.handle.abort();
}

#[tokio::test]
async fn an_enforced_listen_stream_without_app_check_is_denied() {
    let mut h = start(BaselineMode::Enforced).await;
    let err = listen_stream_first(&mut h, None, &["not-a-jwt"])
        .await
        .expect_err("an invalid token is refused");
    assert_eq!(err.code(), Code::PermissionDenied);
    assert_eq!(
        err.metadata()
            .get("fireemu-code")
            .map(|v| v.to_str().unwrap()),
        Some("APP_CHECK_INVALID")
    );
    let token = h.token();
    listen_stream_first(&mut h, None, &[&token])
        .await
        .expect("a valid token opens the stream");
    h.handle.abort();
}

/// Firestore scenario 3. The stream is admitted once, on the credential it opened with. Two
/// hours later that token is long expired, but the writes it is still carrying go through:
/// killing a live stream mid-flight because a token aged is not what the transport does. A
/// reconnect with the same expired token is refused, which is where the client learns it needs
/// a fresh one.
#[tokio::test]
async fn an_admitted_grpc_stream_remains_admitted_after_token_expiry_until_it_reconnects() {
    let mut h = start(BaselineMode::Enforced).await;
    let token = h.token();
    // A signed-in user, so that Security Rules admit the write the stream carries; the App
    // Check credential and the Auth credential are independent layers.
    let (uid, id_token) = h.user_at(
        "streamer@example.com",
        LogicalInstant::from_unix_seconds(START_SECONDS + 7200),
    );
    let bearer = format!("Bearer {id_token}");
    let (tx, rx) = tokio::sync::mpsc::channel(8);
    let mut responses = h
        .client
        .write(request(
            tokio_stream::wrappers::ReceiverStream::new(rx),
            Some(&bearer),
            &[&token],
        ))
        .await
        .expect("the stream opens")
        .into_inner();
    tx.send(pb::WriteRequest {
        database: DATABASE.to_owned(),
        ..pb::WriteRequest::default()
    })
    .await
    .expect("the handshake is sent");
    let handshake = tokio_stream::StreamExt::next(&mut responses)
        .await
        .expect("a handshake response")
        .expect("the stream was admitted");
    assert!(!handshake.stream_id.is_empty());

    h.advance(7200);

    tx.send(pb::WriteRequest {
        stream_token: handshake.stream_token.clone(),
        writes: vec![pb::Write {
            operation: Some(pb::write::Operation::Update(pb::Document {
                name: format!("{DOCS}/profiles/{uid}"),
                fields: [("name".to_owned(), s("Ada"))].into_iter().collect(),
                ..pb::Document::default()
            })),
            ..pb::Write::default()
        }],
        ..pb::WriteRequest::default()
    })
    .await
    .expect("a later write is sent");
    let committed = tokio_stream::StreamExt::next(&mut responses)
        .await
        .expect("a commit response")
        .expect("the admitted stream keeps serving after its token expired");
    assert_eq!(committed.write_results.len(), 1);
    drop(tx);

    // Reconnecting re-admits, and the same token no longer verifies.
    let err = write_stream_first(&mut h, None, &[&token])
        .await
        .expect_err("the reconnect is a new admission");
    assert_eq!(err.code(), Code::PermissionDenied);
    assert_eq!(
        err.metadata()
            .get("fireemu-code")
            .map(|v| v.to_str().unwrap()),
        Some("APP_CHECK_INVALID")
    );
    h.handle.abort();
}

/// The owner bypass reaches the streams too, and only for the exact owner credential: a
/// stream is a Firestore request like any other (specification section 12.2).
#[tokio::test]
async fn owner_stream_traffic_follows_the_explicit_app_check_bypass() {
    let mut h = start(BaselineMode::Enforced).await;
    let ok = write_stream_first(&mut h, Some("Bearer owner"), &[])
        .await
        .expect("the owner credential bypasses App Check");
    assert!(!ok.stream_id.is_empty());
    let err = write_stream_first(&mut h, Some("Bearer ownerx"), &[])
        .await
        .expect_err("an owner-shaped credential is not the owner credential");
    assert_eq!(err.code(), Code::PermissionDenied);
    h.handle.abort();
}

// ------------------------------------------------------------------------------------------
// WebChannel (specification section 13.1; Firestore scenario 4)
// ------------------------------------------------------------------------------------------

fn channel_params(pairs: &[(&str, &str)]) -> std::collections::BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect()
}

fn channel_form(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| format!("{k}={}", channel_urlencode(v)))
        .collect::<Vec<_>>()
        .join("&")
}

fn channel_urlencode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
            out.push(b as char);
        } else {
            use std::fmt::Write as _;
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

fn channel_full(r: ChannelResponse) -> (u16, Vec<(&'static str, String)>, String) {
    match r {
        ChannelResponse::Full {
            status,
            headers,
            body,
        } => (status, headers, body),
        ChannelResponse::Stream { .. } => panic!("expected a full response"),
    }
}

fn listen_target_json() -> String {
    serde_json::json!({
        "database": DATABASE,
        "addTarget": {
            "targetId": 2,
            "query": {
                "parent": DOCS,
                "structuredQuery": {"from": [{"collectionId": "profiles"}]}
            }
        }
    })
    .to_string()
}

/// Opens a channel, presenting `app_check` in the init header block the browser SDK uses.
fn channel_handshake(h: &Harness, app_check: Option<&str>) -> (u16, String, String) {
    let block = match app_check {
        Some(token) => format!("X-Goog-Api-Client:test\r\nX-Firebase-AppCheck:{token}\r\n"),
        None => "X-Goog-Api-Client:test\r\n".to_owned(),
    };
    let first = listen_target_json();
    let (status, headers, body) = channel_full(h.hub.handle(&ChannelRequest {
        kind: StreamKind::Listen,
        method: "POST".to_owned(),
        params: channel_params(&[
            ("database", DATABASE),
            ("VER", "8"),
            ("RID", "1"),
            ("CVER", "22"),
        ]),
        authorization: None,
        app_check: Vec::new(),
        origin: None,
        body: channel_form(&[
            ("headers", &block),
            ("count", "1"),
            ("ofs", "0"),
            ("req0___data__", &first),
        ]),
    }));
    let sid = headers
        .iter()
        .find(|(k, _)| *k == "x-http-session-id")
        .map(|(_, v)| v.clone())
        .unwrap_or_default();
    (status, sid, body)
}

/// A later forward-channel envelope, optionally presenting a replacement token.
fn channel_envelope(
    h: &Harness,
    sid: &str,
    rid: &str,
    ofs: &str,
    app_check: Option<&str>,
) -> (u16, String) {
    let mut fields: Vec<(&str, &str)> = Vec::new();
    let block;
    if let Some(token) = app_check {
        block = format!("X-Firebase-AppCheck:{token}\r\n");
        fields.push(("headers", &block));
    }
    let payload = listen_target_json();
    fields.push(("count", "1"));
    fields.push(("ofs", ofs));
    fields.push(("req0___data__", &payload));
    let (status, _, body) = channel_full(h.hub.handle(&ChannelRequest {
        kind: StreamKind::Listen,
        method: "POST".to_owned(),
        params: channel_params(&[("SID", sid), ("RID", rid), ("AID", "0")]),
        authorization: None,
        app_check: Vec::new(),
        origin: None,
        body: channel_form(&fields),
    }));
    (status, body)
}

#[tokio::test]
async fn an_enforced_webchannel_handshake_without_app_check_never_opens_a_channel() {
    let h = start(BaselineMode::Enforced).await;
    let (status, sid, body) = channel_handshake(&h, None);
    assert_eq!(status, 403, "{body}");
    assert!(sid.is_empty(), "no channel was opened");
    let parsed: serde_json::Value = serde_json::from_str(&body).expect("a JSON error envelope");
    assert_eq!(parsed["error"]["status"], "PERMISSION_DENIED");
    assert!(
        !parsed["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("Security Rules"),
        "an App Check denial is not a rules denial: {body}"
    );

    let token = h.token();
    let (status, sid, _) = channel_handshake(&h, Some(&token));
    assert_eq!(status, 200);
    assert!(!sid.is_empty(), "a valid token opens the channel");
    h.handle.abort();
}

/// Firestore scenario 4: a replacement token for another app closes the channel. The token is
/// perfectly valid — same project, current epoch, correct signature — so this is exactly the
/// case that re-admitting each envelope on its own merits would wave through.
#[tokio::test]
async fn a_webchannel_rejects_a_replacement_token_from_another_app() {
    let h = start(BaselineMode::Enforced).await;
    let token = h.token();
    let (status, sid, _) = channel_handshake(&h, Some(&token));
    assert_eq!(status, 200);

    // The same app may refresh its token.
    let refreshed = token_at(&h.gate, "demo-app", APP_ID, START);
    let (status, _) = channel_envelope(&h, &sid, "2", "1", Some(&refreshed));
    assert_eq!(status, 200, "the same app may present a replacement");

    let intruder = h.other_app_token();
    let (status, body) = channel_envelope(&h, &sid, "3", "2", Some(&intruder));
    assert_eq!(status, 403, "{body}");
    let parsed: serde_json::Value = serde_json::from_str(&body).expect("a JSON error envelope");
    assert_eq!(parsed["error"]["status"], "PERMISSION_DENIED");

    // The channel is gone: the session no longer answers.
    let (status, body) = channel_envelope(&h, &sid, "4", "3", Some(&token));
    assert_eq!(status, 400, "the channel was closed: {body}");
    h.handle.abort();
}

/// An admitted channel keeps its admission: a later envelope that presents nothing rides on
/// the handshake's decision, even after the token that opened it expired.
#[tokio::test]
async fn an_admitted_webchannel_keeps_serving_envelopes_without_a_token() {
    let h = start(BaselineMode::Enforced).await;
    let token = h.token();
    let (status, sid, _) = channel_handshake(&h, Some(&token));
    assert_eq!(status, 200);
    h.advance(7200);
    let (status, body) = channel_envelope(&h, &sid, "2", "1", None);
    assert_eq!(status, 200, "{body}");

    // Presenting the now-expired token, though, is an invalid replacement.
    let (status, _) = channel_envelope(&h, &sid, "3", "2", Some(&token));
    assert_eq!(status, 403);
    h.handle.abort();
}

/// `off` and `unenforced` never close a channel, and `unenforced` binds nothing: a client that
/// stops presenting a token must not be locked out of its own channel.
#[tokio::test]
async fn an_unenforced_webchannel_never_closes_on_a_foreign_token() {
    let h = start(BaselineMode::Unenforced).await;
    let (status, sid, _) = channel_handshake(&h, Some(&h.token()));
    assert_eq!(status, 200);
    let (status, body) = channel_envelope(&h, &sid, "2", "1", Some(&h.other_app_token()));
    assert_eq!(status, 200, "unenforced denies nothing: {body}");
    h.handle.abort();
}

/// The `WebChannel` shares the canonical header contract: two instances of the field are
/// ambiguous, whichever source they arrive from, and never a value the caller gets to pick.
#[tokio::test]
async fn the_webchannel_transport_refuses_duplicate_app_check_fields() {
    let h = start(BaselineMode::Enforced).await;
    let token = h.token();
    let block = format!("X-Firebase-AppCheck:{token}\r\nx-firebase-appcheck:{token}\r\n");
    let first = listen_target_json();
    let (status, _, _) = channel_full(h.hub.handle(&ChannelRequest {
        kind: StreamKind::Listen,
        method: "POST".to_owned(),
        params: channel_params(&[("database", DATABASE), ("VER", "8"), ("RID", "1")]),
        authorization: None,
        app_check: Vec::new(),
        origin: None,
        body: channel_form(&[
            ("headers", &block),
            ("count", "1"),
            ("ofs", "0"),
            ("req0___data__", &first),
        ]),
    }));
    assert_eq!(status, 403, "two instances in the init block are ambiguous");

    // One in the init block and one as a real HTTP field is the same ambiguity.
    let block = format!("X-Firebase-AppCheck:{token}\r\n");
    let (status, _, _) = channel_full(h.hub.handle(&ChannelRequest {
        kind: StreamKind::Listen,
        method: "POST".to_owned(),
        params: channel_params(&[("database", DATABASE), ("VER", "8"), ("RID", "1")]),
        authorization: None,
        app_check: vec![token.clone()],
        origin: None,
        body: channel_form(&[
            ("headers", &block),
            ("count", "1"),
            ("ofs", "0"),
            ("req0___data__", &first),
        ]),
    }));
    assert_eq!(status, 403, "two sources are two instances");
    h.handle.abort();
}

/// A channel opened against another project's database cannot drive this one: the handshake
/// admits against the `database` parameter, and the stream admits again against the database
/// its first message names.
#[tokio::test]
async fn a_webchannel_opened_for_another_project_is_denied() {
    let h = start(BaselineMode::Enforced).await;
    let token = h.token();
    let first = listen_target_json();
    let block = format!("X-Firebase-AppCheck:{token}\r\n");
    let (status, _, _) = channel_full(h.hub.handle(&ChannelRequest {
        kind: StreamKind::Listen,
        method: "POST".to_owned(),
        params: channel_params(&[
            ("database", "projects/demo-other/databases/(default)"),
            ("VER", "8"),
            ("RID", "1"),
        ]),
        authorization: None,
        app_check: Vec::new(),
        origin: None,
        body: channel_form(&[
            ("headers", &block),
            ("count", "1"),
            ("ofs", "0"),
            ("req0___data__", &first),
        ]),
    }));
    assert_eq!(
        status, 403,
        "a demo-app token does not authorize a demo-other channel"
    );
    h.handle.abort();
}

/// The stream observations name the `webchannel` transport, so the control API can tell a
/// browser channel apart from a gRPC stream.
#[tokio::test]
async fn webchannel_observations_name_the_transport() {
    let h = start(BaselineMode::Unenforced).await;
    let (status, _, _) = channel_handshake(&h, Some(&h.token()));
    assert_eq!(status, 200);
    let observations = h.observations();
    assert!(
        observations
            .iter()
            .any(|o| o.transport == "webchannel" && o.operation == "channel.open"),
        "{observations:?}"
    );
    h.handle.abort();
}
