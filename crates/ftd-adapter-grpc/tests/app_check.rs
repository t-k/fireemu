//! App Check enforcement for Cloud Firestore (specification sections 12, 13.1, 17 and 19;
//! obligations `AC-FS-001`, `AC-BOUNDARY-001` and `AC-HEADER-001`).
//!
//! Milestone AC1 covers the unary gRPC surface and Firestore REST; the `Write` / `Listen`
//! stream and `WebChannel` lifetime contracts are AC2. The Firestore scenarios checked here are
//! 1 (an enforced unary request rejects a valid Auth user before Rules evaluation), 2 (an
//! unenforced request admits an invalid token without creating an app identity) and 5 (owner
//! traffic follows the explicit bypass).
//!
//! The signer is a deterministic stand-in rather than RS256: the shell's real `rsa` / `sha2`
//! implementations are exercised by the `ftd-adapter-http` App Check tests, and key generation
//! is far too slow for a matrix of this size in a debug build.

use std::sync::{Arc, Mutex, RwLock};

use ftd_adapter_grpc::gateway::Gateway;
use ftd_adapter_grpc::local::LocalBackend;
use ftd_adapter_grpc::rest::{RestRequest, RestState};
use ftd_adapter_grpc::rules::RulesEnforcer;
use ftd_adapter_grpc::service::GatewayService;
use ftd_core_app_check::admission::{AppCheckGate, ServiceAdmission};
use ftd_core_app_check::claims::{audiences_for, issuer_for, AppCheckClaims};
use ftd_core_app_check::crypto::AppCheckSigner;
use ftd_core_app_check::registry::{AppCheckRegistry, AppRegistration, ProjectEpoch};
use ftd_core_app_check::verify::BaselineMode;
use ftd_core_auth::jwt::encode_unsigned;
use ftd_core_auth::mfa::TotpPolicy;
use ftd_core_auth::store::{AuthStore, NewUser};
use ftd_core_firestore::index::{IndexSet, IndexValidationPolicy, PlanningContext};
use ftd_core_rules::runtime::LoadedRules;
use ftd_core_session::clock::VirtualClock;
use ftd_core_types::determinism::{DeterministicRng, SplitMix64};
use ftd_core_types::edition::{FirestoreApiMode, FirestoreEdition};
use ftd_core_types::time::LogicalInstant;
use ftd_proto_firestore::google::firestore::v1 as pb;
use ftd_proto_firestore::google::firestore::v1::firestore_client::FirestoreClient;
use ftd_proto_firestore::google::firestore::v1::firestore_server::FirestoreServer;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::metadata::MetadataValue;
use tonic::{Code, Request};

const DOCS: &str = "projects/demo-app/databases/(default)/documents";
const START_SECONDS: i64 = 1_788_004_860;
const START: LogicalInstant = LogicalInstant::from_unix_seconds(START_SECONDS);
const APP_ID: &str = "1:1234567890:web:local-test-app";
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
            kid: format!("ftd-app-check-{key:016x}"),
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
    ftd_core_app_check::jwt::encode(&claims, gate.signer().as_ref())
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
    let unknown_app = ftd_core_app_check::jwt::encode(
        &AppCheckClaims {
            iss: issuer_for("1234567890"),
            sub: UNREGISTERED_APP_ID.to_owned(),
            aud: audiences_for("1234567890", "demo-app"),
            iat: START_SECONDS,
            exp: START_SECONDS + 3600,
            jti: "forged-1".to_owned(),
            ftd_epoch: epoch.claim_text(),
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
    rest: RestState,
    auth: Arc<Mutex<AuthStore>>,
    gate: AppCheckGate,
    backend: Arc<LocalBackend>,
    handle: tokio::task::JoinHandle<()>,
}

async fn start(mode: BaselineMode) -> Harness {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("a local address");
    let gateway = Gateway {
        ctx: PlanningContext {
            edition: FirestoreEdition::Standard,
            api_mode: FirestoreApiMode::Native,
            policy: IndexValidationPolicy::Conservative,
        },
        indexes: IndexSet::default(),
    };
    let clock = Arc::new(Mutex::new(VirtualClock::new(START)));
    let backend = Arc::new(LocalBackend::new(gateway.clone(), clock.clone(), 7));
    let auth = Arc::new(Mutex::new(AuthStore::new(
        "demo-app",
        SplitMix64::new(3),
        TotpPolicy::default(),
    )));
    let rules = Arc::new(RwLock::new(
        LoadedRules::from_source(RULES).expect("the fixture ruleset compiles"),
    ));
    let enforcer = Arc::new(RulesEnforcer::new(rules, auth.clone(), clock));
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
    let rest = RestState {
        local: backend.clone(),
        gateway: Arc::new(gateway),
        rules: Some(enforcer),
        app_check: policy,
    };
    Harness {
        client: FirestoreClient::new(channel),
        rest,
        auth,
        gate,
        backend,
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

    fn token(&self) -> String {
        token_at(&self.gate, "demo-app", APP_ID, START)
    }

    fn observations(&self) -> Vec<ftd_core_app_check::observe::Observation> {
        self.gate
            .registry()
            .read()
            .expect("readable")
            .observations()
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
            .get("ftd-code")
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
            .get("ftd-code")
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
        ftd_core_app_check::observe::CredentialCategory::Invalid
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
        Some(ftd_core_app_check::observe::CredentialCategory::Bypass)
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
                        .get("ftd-code")
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
                .get("ftd-code")
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
    let rotated = h.gate.rotate_epochs(
        |project| project == "demo-app",
        || ProjectEpoch::new(0xABCD),
    );
    assert_eq!(rotated, 1);
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
            .get("ftd-code")
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
