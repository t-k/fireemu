//! Security Rules enforcement on the gRPC surface: owner bypass, ID token verification,
//! per-method evaluation with `resource` / `request.resource`, and the list approximation.

use std::sync::{Arc, Mutex, RwLock};

use ftd_adapter_grpc::gateway::Gateway;
use ftd_adapter_grpc::local::LocalBackend;
use ftd_adapter_grpc::rules::RulesEnforcer;
use ftd_adapter_grpc::service::GatewayService;
use ftd_core_auth::jwt::encode_unsigned;
use ftd_core_auth::mfa::TotpPolicy;
use ftd_core_auth::store::{AuthStore, NewUser};
use ftd_core_firestore::index::{IndexSet, IndexValidationPolicy, PlanningContext};
use ftd_core_rules::runtime::LoadedRules;
use ftd_core_session::clock::VirtualClock;
use ftd_core_types::determinism::SplitMix64;
use ftd_core_types::edition::{FirestoreApiMode, FirestoreEdition};
use ftd_core_types::time::LogicalInstant;
use ftd_proto_firestore::google::firestore::v1 as pb;
use ftd_proto_firestore::google::firestore::v1::firestore_client::FirestoreClient;
use ftd_proto_firestore::google::firestore::v1::firestore_server::FirestoreServer;
use ftd_proto_firestore::google::firestore::v1::structured_query as sq;
use tokio_stream::wrappers::TcpListenerStream;
use tokio_stream::StreamExt;
use tonic::metadata::MetadataValue;
use tonic::Request;

const DB: &str = "projects/demo-app/databases/(default)";
const DOCS: &str = "projects/demo-app/databases/(default)/documents";
const START: LogicalInstant = LogicalInstant::from_unix_seconds(1_788_004_860);

const RULES: &str = r"
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /profiles/{uid} {
      allow read: if request.auth != null && request.auth.uid == uid;
      allow create: if request.auth != null && request.auth.uid == uid
                    && request.resource.data.name is string;
      allow update: if request.auth != null && request.auth.uid == uid
                    && request.resource.data.name == resource.data.name;
      allow delete: if false;
    }
    match /notes/{id} {
      allow read: if request.auth != null && resource.data.owner == request.auth.uid;
      allow write: if request.auth != null && request.resource.data.owner == request.auth.uid;
    }
    match /public/{id} {
      allow read: if true;
    }
    match /archive/{id} {
      allow read: if request.auth != null && resource.data.owner == request.auth.uid;
    }
  }
}
";

struct Harness {
    client: FirestoreClient<tonic::transport::Channel>,
    auth: Arc<Mutex<AuthStore>>,
    rules: Arc<RwLock<LoadedRules>>,
    handle: tokio::task::JoinHandle<()>,
}

async fn start() -> Harness {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
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
    let rules = Arc::new(RwLock::new(LoadedRules::from_source(RULES).unwrap()));
    let enforcer = Arc::new(RulesEnforcer::new(rules.clone(), auth.clone(), clock));
    let svc = FirestoreServer::new(GatewayService::local(gateway, backend).with_rules(enforcer));
    let handle = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(svc)
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .unwrap();
    });
    let channel = tonic::transport::Endpoint::from_shared(format!("http://{addr}"))
        .unwrap()
        .connect()
        .await
        .unwrap();
    Harness {
        client: FirestoreClient::new(channel),
        auth,
        rules,
        handle,
    }
}

impl Harness {
    /// Creates a user and returns (uid, ID token).
    fn user(&self, email: &str) -> (String, String) {
        let mut store = self.auth.lock().unwrap();
        let uid = store.create_user(NewUser::email(email), START).unwrap();
        let claims = store.id_token_claims(&uid, None, START).unwrap();
        (uid.as_str().to_owned(), encode_unsigned(&claims))
    }
}

fn s(v: &str) -> pb::Value {
    pb::Value {
        value_type: Some(pb::value::ValueType::StringValue(v.to_owned())),
    }
}
fn with_bearer<T>(req: T, token: &str) -> Request<T> {
    let mut r = Request::new(req);
    r.metadata_mut().insert(
        "authorization",
        MetadataValue::try_from(format!("Bearer {token}")).unwrap(),
    );
    r
}
fn set_write(name: &str, fields: &[(&str, pb::Value)]) -> pb::Write {
    pb::Write {
        operation: Some(pb::write::Operation::Update(pb::Document {
            name: format!("{DOCS}/{name}"),
            fields: fields
                .iter()
                .map(|(k, v)| ((*k).to_owned(), v.clone()))
                .collect(),
            ..Default::default()
        })),
        ..Default::default()
    }
}
fn commit(writes: Vec<pb::Write>) -> pb::CommitRequest {
    pb::CommitRequest {
        database: DB.to_owned(),
        writes,
        ..Default::default()
    }
}
fn get(name: &str) -> pb::GetDocumentRequest {
    pb::GetDocumentRequest {
        name: format!("{DOCS}/{name}"),
        ..Default::default()
    }
}
fn list(collection: &str) -> pb::RunQueryRequest {
    pb::RunQueryRequest {
        parent: DOCS.to_owned(),
        query_type: Some(pb::run_query_request::QueryType::StructuredQuery(
            pb::StructuredQuery {
                from: vec![sq::CollectionSelector {
                    collection_id: collection.to_owned(),
                    all_descendants: false,
                }],
                ..Default::default()
            },
        )),
        ..Default::default()
    }
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn owner_bypasses_rules_and_users_are_checked_per_method() {
    let mut h = start().await;
    let (alice, alice_token) = h.user("alice@example.com");
    let (_bob, bob_token) = h.user("bob@example.com");

    // Admin credentials bypass rules entirely (delete is `if false` for everyone else).
    h.client
        .commit(with_bearer(
            commit(vec![set_write("profiles/seed", &[("name", s("Seed"))])]),
            "owner",
        ))
        .await
        .unwrap();
    h.client
        .delete_document(with_bearer(
            pb::DeleteDocumentRequest {
                name: format!("{DOCS}/profiles/seed"),
                ..Default::default()
            },
            "owner",
        ))
        .await
        .unwrap();

    // Unauthenticated: denied. Wrong user: denied. Right user with valid data: allowed.
    let err = h
        .client
        .commit(commit(vec![set_write(
            &format!("profiles/{alice}"),
            &[("name", s("Alice"))],
        )]))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::PermissionDenied);
    let err = h
        .client
        .commit(with_bearer(
            commit(vec![set_write(
                &format!("profiles/{alice}"),
                &[("name", s("Alice"))],
            )]),
            &bob_token,
        ))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::PermissionDenied);
    // create requires name to be a string
    let err = h
        .client
        .commit(with_bearer(
            commit(vec![set_write(
                &format!("profiles/{alice}"),
                &[(
                    "name",
                    pb::Value {
                        value_type: Some(pb::value::ValueType::IntegerValue(1)),
                    },
                )],
            )]),
            &alice_token,
        ))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::PermissionDenied);
    h.client
        .commit(with_bearer(
            commit(vec![set_write(
                &format!("profiles/{alice}"),
                &[("name", s("Alice"))],
            )]),
            &alice_token,
        ))
        .await
        .unwrap();

    // update: the name must not change (resource vs request.resource).
    let err = h
        .client
        .commit(with_bearer(
            commit(vec![set_write(
                &format!("profiles/{alice}"),
                &[("name", s("Alicia"))],
            )]),
            &alice_token,
        ))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::PermissionDenied);
    h.client
        .commit(with_bearer(
            commit(vec![set_write(
                &format!("profiles/{alice}"),
                &[("name", s("Alice")), ("bio", s("hi"))],
            )]),
            &alice_token,
        ))
        .await
        .unwrap();

    // get: only the owner.
    assert!(h
        .client
        .get_document(with_bearer(get(&format!("profiles/{alice}")), &alice_token))
        .await
        .is_ok());
    let err = h
        .client
        .get_document(with_bearer(get(&format!("profiles/{alice}")), &bob_token))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::PermissionDenied);
    let err = h
        .client
        .get_document(get(&format!("profiles/{alice}")))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::PermissionDenied);

    // delete: nobody but the owner credential.
    let err = h
        .client
        .delete_document(with_bearer(
            pb::DeleteDocumentRequest {
                name: format!("{DOCS}/profiles/{alice}"),
                ..Default::default()
            },
            &alice_token,
        ))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::PermissionDenied);

    // A forged / unknown token is UNAUTHENTICATED, not silently anonymous.
    let err = h
        .client
        .get_document(with_bearer(get("public/x"), "not-a-jwt"))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unauthenticated);
    h.handle.abort();
}

#[tokio::test]
async fn list_is_evaluated_per_document_and_empty_results_do_not_leak() {
    let mut h = start().await;
    let (alice, alice_token) = h.user("alice@example.com");
    let (bob, bob_token) = h.user("bob@example.com");
    h.client
        .commit(with_bearer(
            commit(vec![
                set_write("notes/a1", &[("owner", s(&alice)), ("t", s("x"))]),
                set_write("notes/b1", &[("owner", s(&bob)), ("t", s("y"))]),
            ]),
            "owner",
        ))
        .await
        .unwrap();

    // An unfiltered list returns a document bob may not read: denied for bob.
    let err = h
        .client
        .run_query(with_bearer(list("notes"), &bob_token))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::PermissionDenied, "{err}");

    // Filtered on owner: every returned document passes the rule.
    let mut filtered = list("notes");
    if let Some(pb::run_query_request::QueryType::StructuredQuery(sq)) = &mut filtered.query_type {
        sq.r#where = Some(sq::Filter {
            filter_type: Some(sq::filter::FilterType::FieldFilter(sq::FieldFilter {
                field: Some(sq::FieldReference {
                    field_path: "owner".to_owned(),
                }),
                op: sq::field_filter::Operator::Equal as i32,
                value: Some(s(&bob)),
            })),
        });
    }
    let mut stream = h
        .client
        .run_query(with_bearer(filtered, &bob_token))
        .await
        .unwrap()
        .into_inner();
    let mut names = Vec::new();
    while let Some(r) = stream.next().await {
        if let Some(d) = r.unwrap().document {
            names.push(d.name);
        }
    }
    assert_eq!(names, vec![format!("{DOCS}/notes/b1")]);

    // Empty collection with a resource-dependent rule: allowed (nothing to leak); an
    // uncovered path is still denied.
    let mut stream = h
        .client
        .run_query(with_bearer(list("archive"), &alice_token))
        .await
        .unwrap()
        .into_inner();
    let first = stream.next().await.unwrap().unwrap();
    assert!(first.document.is_none());
    let err = h
        .client
        .run_query(with_bearer(list("uncovered"), &alice_token))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::PermissionDenied);
    // ...but a rule that denies regardless of resource still denies on empty results.
    let err = h.client.run_query(list("notes")).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::PermissionDenied);

    // `allow read: if true` collections are readable anonymously.
    assert!(h.client.run_query(list("public")).await.is_ok());

    // Rules can be swapped at runtime through the shared slot.
    *h.rules.write().unwrap() = LoadedRules::default();
    assert!(
        h.client.run_query(list("notes")).await.is_ok(),
        "no rules = allow"
    );
    h.handle.abort();
}
