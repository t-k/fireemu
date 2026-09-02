//! Security Rules enforcement on the gRPC surface: owner bypass, ID token verification,
//! per-method evaluation with `resource` / `request.resource`, and the list approximation.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, RwLock};

use fireemu_adapter_grpc::decode::Parent;
use fireemu_adapter_grpc::gateway::Gateway;
use fireemu_adapter_grpc::local::LocalBackend;
use fireemu_adapter_grpc::rules::{LatestReader, Principal, RulesEnforcer};
use fireemu_adapter_grpc::service::GatewayService;
use fireemu_core_auth::jwt::{base64url_encode, encode_unsigned, TokenAcceptance};
use fireemu_core_auth::mfa::TotpPolicy;
use fireemu_core_auth::store::{AuthRegistry, AuthStore, NewUser};
use fireemu_core_firestore::index::{IndexSet, IndexValidationPolicy, PlanningContext};
use fireemu_core_firestore::path::DocumentPath;
use fireemu_core_rules::runtime::LoadedRules;
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_types::determinism::SplitMix64;
use fireemu_core_types::edition::{FirestoreApiMode, FirestoreEdition};
use fireemu_core_types::ids::{DatabaseId, ProjectId};
use fireemu_core_types::time::LogicalInstant;
use fireemu_proto_firestore::google::firestore::v1 as pb;
use fireemu_proto_firestore::google::firestore::v1::firestore_client::FirestoreClient;
use fireemu_proto_firestore::google::firestore::v1::firestore_server::FirestoreServer;
use fireemu_proto_firestore::google::firestore::v1::structured_query as sq;
use tokio::sync::mpsc;
use tokio_stream::wrappers::{ReceiverStream, TcpListenerStream};
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
    match /strict/{id} {
      allow create: if resource.data.x == 1;
    }
    match /owned/{id} {
      allow create, update: if request.auth != null && request.resource.data.owner == request.auth.uid;
      allow delete: if request.auth != null && resource.data.owner == request.auth.uid;
    }
  }
}
";

#[test]
fn named_databases_select_their_own_ruleset() {
    let gateway = Gateway {
        enforce_limits: true,
        ctx: PlanningContext {
            edition: FirestoreEdition::Standard,
            api_mode: FirestoreApiMode::Native,
            policy: IndexValidationPolicy::Conservative,
        },
        indexes: IndexSet::default(),
    };
    let clock = Arc::new(Mutex::new(VirtualClock::new(START)));
    let backend = Arc::new(LocalBackend::new(gateway, clock.clone(), 7));
    let auth = Arc::new(Mutex::new(AuthStore::new(
        "demo-app",
        SplitMix64::new(3),
        TotpPolicy::default(),
    )));
    let deny = "service cloud.firestore { match /databases/{database}/documents { match /{document=**} { allow read: if false; } } }";
    let allow = "service cloud.firestore { match /databases/{database}/documents { match /{document=**} { allow read: if true; } } }";
    let enforcer = RulesEnforcer::new(
        Arc::new(RwLock::new(LoadedRules::from_source(deny).unwrap())),
        auth,
        clock,
    )
    .with_database_rules(BTreeMap::from([(
        "staging".to_owned(),
        Arc::new(RwLock::new(LoadedRules::from_source(allow).unwrap())),
    )]));
    let project = ProjectId::try_new("demo-app").unwrap();
    let default_database = DatabaseId::default_database();
    let staging_database = DatabaseId::try_new("staging").unwrap();
    let default_path = DocumentPath::parse(&project, &default_database, "items/a").unwrap();
    let staging_path = DocumentPath::parse(&project, &staging_database, "items/a").unwrap();
    let reader = LatestReader {
        backend,
        parent: Parent {
            project,
            database: staging_database,
            document: None,
        },
    };
    assert!(enforcer
        .authorize_get(&Principal::Anonymous, &default_path, None, &reader)
        .is_err());
    assert!(enforcer
        .authorize_get(&Principal::Anonymous, &staging_path, None, &reader)
        .is_ok());
}

#[test]
fn tenant_tokens_build_a_firestore_rules_principal() {
    let clock = Arc::new(Mutex::new(VirtualClock::new(START)));
    let parent = Arc::new(Mutex::new(AuthStore::new(
        "demo-app",
        SplitMix64::new(3),
        TotpPolicy::default(),
    )));
    let registry = Arc::new(AuthRegistry::new("demo-app", parent.clone()));
    let tenant = registry.ensure_tenant("demo-app", "customer-a").unwrap();
    let mut tenant = tenant.lock().unwrap();
    let uid = tenant
        .create_user(NewUser::email("tenant@example.com"), START)
        .unwrap();
    let token = encode_unsigned(&tenant.id_token_claims(&uid, None, START).unwrap());
    drop(tenant);
    let enforcer = RulesEnforcer::new(Arc::new(RwLock::new(LoadedRules::default())), parent, clock)
        .with_registry(registry);

    assert!(matches!(
        enforcer.principal_from_authorization(Some(&format!("Bearer {token}"))),
        Ok(Principal::User(_))
    ));
}

struct Harness {
    client: FirestoreClient<tonic::transport::Channel>,
    auth: Arc<Mutex<AuthStore>>,
    rules: Arc<RwLock<LoadedRules>>,
    handle: tokio::task::JoinHandle<()>,
}

async fn start() -> Harness {
    start_with(TokenAcceptance::Verified).await
}

async fn start_with(acceptance: TokenAcceptance) -> Harness {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let gateway = Gateway {
        enforce_limits: true,
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
    let enforcer = Arc::new(
        RulesEnforcer::new(rules.clone(), auth.clone(), clock).with_token_acceptance(acceptance),
    );
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
fn map(fields: &[(&str, pb::Value)]) -> pb::Value {
    pb::Value {
        value_type: Some(pb::value::ValueType::MapValue(pb::MapValue {
            fields: fields
                .iter()
                .map(|(key, value)| ((*key).to_owned(), value.clone()))
                .collect(),
        })),
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
async fn linear_regex_repeats_allow_valid_long_writes_without_depth_exhaustion() {
    let mut h = start().await;
    let (_alice, alice_token) = h.user("alice@example.com");
    *h.rules.write().unwrap() = LoadedRules::from_source(
        "rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /messages/{id} {
      allow create: if request.resource.data.content.matches('^(?:[\\t\\n\\r]|[^\\\\p{Cc}])*$');
    }
  }
}",
    )
    .unwrap();

    let long = "a".repeat(3_000);
    h.client
        .commit(with_bearer(
            commit(vec![set_write("messages/long", &[("content", s(&long))])]),
            &alice_token,
        ))
        .await
        .unwrap();

    let error = h
        .client
        .commit(with_bearer(
            commit(vec![set_write(
                "messages/control",
                &[("content", s("ok\u{0007}no"))],
            )]),
            &alice_token,
        ))
        .await
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::PermissionDenied);
    assert!(!error.message().contains("FIREEMU-REGEX"), "{error}");
    h.handle.abort();
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

    // A create rule that reads the (absent) existing resource evaluates to false: denied,
    // never silently allowed.
    let err = h
        .client
        .commit(with_bearer(
            commit(vec![set_write("strict/s1", &[("x", s("1"))])]),
            &alice_token,
        ))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::PermissionDenied);

    // delete rules see the existing document as `resource`.
    h.client
        .commit(with_bearer(
            commit(vec![set_write("owned/o1", &[("owner", s(&alice))])]),
            &alice_token,
        ))
        .await
        .unwrap();
    let err = h
        .client
        .commit(with_bearer(
            commit(vec![pb::Write {
                operation: Some(pb::write::Operation::Delete(format!("{DOCS}/owned/o1"))),
                ..Default::default()
            }]),
            &bob_token,
        ))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::PermissionDenied);
    h.client
        .commit(with_bearer(
            commit(vec![pb::Write {
                operation: Some(pb::write::Operation::Delete(format!("{DOCS}/owned/o1"))),
                ..Default::default()
            }]),
            &alice_token,
        ))
        .await
        .unwrap();

    // A forged / unknown token is UNAUTHENTICATED, not silently anonymous.
    let err = h
        .client
        .get_document(with_bearer(get("public/x"), "not-a-jwt"))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unauthenticated);
    h.handle.abort();
}

fn list_where(collection: &str, field: &str, value: pb::Value) -> pb::RunQueryRequest {
    let mut req = list(collection);
    if let Some(pb::run_query_request::QueryType::StructuredQuery(sq)) = &mut req.query_type {
        sq.r#where = Some(sq::Filter {
            filter_type: Some(sq::filter::FilterType::FieldFilter(sq::FieldFilter {
                field: Some(sq::FieldReference {
                    field_path: field.to_owned(),
                }),
                op: sq::field_filter::Operator::Equal as i32,
                value: Some(value),
            })),
        });
    }
    req
}

#[tokio::test]
async fn list_is_authorized_from_the_query_constraints() {
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

    // Without an owner constraint the rule cannot be proven: denied, whatever the data.
    let err = h
        .client
        .run_query(with_bearer(list("notes"), &bob_token))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::PermissionDenied, "{err}");

    // Constrained on owner == bob: the synthetic resource satisfies the rule.
    let mut stream = h
        .client
        .run_query(with_bearer(
            list_where("notes", "owner", s(&bob)),
            &bob_token,
        ))
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

    // The decision does not depend on stored data: an empty collection behaves the same
    // (constrained: allowed; unconstrained: denied), so nothing leaks about existence.
    let mut stream = h
        .client
        .run_query(with_bearer(
            list_where("archive", "owner", s(&alice)),
            &alice_token,
        ))
        .await
        .unwrap()
        .into_inner();
    let first = stream.next().await.unwrap().unwrap();
    assert!(first.document.is_none());
    let err = h
        .client
        .run_query(with_bearer(list("archive"), &alice_token))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::PermissionDenied);
    // Claiming someone else's owner value does not help.
    let err = h
        .client
        .run_query(with_bearer(
            list_where("notes", "owner", s(&alice)),
            &bob_token,
        ))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::PermissionDenied);
    let err = h
        .client
        .run_query(with_bearer(list("uncovered"), &alice_token))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::PermissionDenied);
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

#[tokio::test]
async fn document_name_in_authorizes_each_real_candidate_as_a_list() {
    let mut h = start().await;
    let (alice, alice_token) = h.user("alice@example.com");
    let (bob, _) = h.user("bob@example.com");
    h.client
        .commit(with_bearer(
            commit(vec![
                set_write("notes/a1", &[("owner", s(&alice))]),
                set_write("notes/a2", &[("owner", s(&alice))]),
                set_write("notes/b1", &[("owner", s(&bob))]),
            ]),
            "owner",
        ))
        .await
        .unwrap();
    let names_query = |names: &[&str]| {
        let mut request = list("notes");
        if let Some(pb::run_query_request::QueryType::StructuredQuery(query)) =
            &mut request.query_type
        {
            query.r#where = Some(sq::Filter {
                filter_type: Some(sq::filter::FilterType::FieldFilter(sq::FieldFilter {
                    field: Some(sq::FieldReference {
                        field_path: "__name__".to_owned(),
                    }),
                    op: sq::field_filter::Operator::In as i32,
                    value: Some(pb::Value {
                        value_type: Some(pb::value::ValueType::ArrayValue(pb::ArrayValue {
                            values: names
                                .iter()
                                .map(|name| pb::Value {
                                    value_type: Some(pb::value::ValueType::ReferenceValue(
                                        format!("{DOCS}/notes/{name}"),
                                    )),
                                })
                                .collect(),
                        })),
                    }),
                })),
            });
        }
        request
    };

    let mut stream = h
        .client
        .run_query(with_bearer(names_query(&["a2", "a1"]), &alice_token))
        .await
        .unwrap()
        .into_inner();
    let mut returned = Vec::new();
    while let Some(response) = stream.next().await {
        if let Some(document) = response.unwrap().document {
            returned.push(document.name);
        }
    }
    assert_eq!(
        returned,
        vec![format!("{DOCS}/notes/a1"), format!("{DOCS}/notes/a2")]
    );

    let missing = h
        .client
        .run_query(with_bearer(names_query(&["missing"]), &alice_token))
        .await
        .unwrap_err();
    assert_eq!(missing.code(), tonic::Code::PermissionDenied);
    assert_eq!(missing.message(), "query denied by Security Rules");

    let denied = h
        .client
        .run_query(with_bearer(names_query(&["a1", "b1"]), &alice_token))
        .await
        .unwrap_err();
    assert_eq!(denied.code(), tonic::Code::PermissionDenied);
    h.handle.abort();
}

#[tokio::test]
async fn query_proofs_are_sound_for_shapes_arrays_and_collection_groups() {
    let mut h = start().await;
    let (alice, alice_token) = h.user("alice@example.com");
    *h.rules.write().unwrap() = LoadedRules::from_source(
        "rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /shape/{id} { allow read: if !('blocked' in resource.data); }
    match /tagged/{id} { allow read: if resource.data.tags.hasAny(['x']); }
    match /sized/{id} { allow read: if resource.data.tags.size() == 1; }
    match /reviews/{id} { allow read: if true; }
    match /{path=**}/comments/{id} { allow read: if request.auth != null; }
  }
}",
    )
    .unwrap();
    let denied = |code: tonic::Code| assert_eq!(code, tonic::Code::PermissionDenied);
    // Map-shape conditions cannot be proven for an unfiltered query.
    denied(
        h.client
            .run_query(with_bearer(list("shape"), &alice_token))
            .await
            .unwrap_err()
            .code(),
    );
    // array-contains proves membership...
    let mut contains = list("tagged");
    if let Some(pb::run_query_request::QueryType::StructuredQuery(sq)) = &mut contains.query_type {
        sq.r#where = Some(sq::Filter {
            filter_type: Some(sq::filter::FilterType::FieldFilter(sq::FieldFilter {
                field: Some(sq::FieldReference {
                    field_path: "tags".to_owned(),
                }),
                op: sq::field_filter::Operator::ArrayContains as i32,
                value: Some(s("x")),
            })),
        });
    }
    assert!(h
        .client
        .run_query(with_bearer(contains.clone(), &alice_token))
        .await
        .is_ok());
    // ...but not the size of the array.
    let mut sized = contains.clone();
    sized.parent = DOCS.to_owned();
    if let Some(pb::run_query_request::QueryType::StructuredQuery(sq)) = &mut sized.query_type {
        sq.from[0].collection_id = "sized".to_owned();
    }
    denied(
        h.client
            .run_query(with_bearer(sized, &alice_token))
            .await
            .unwrap_err()
            .code(),
    );
    // A collection-group query needs a rule covering every depth.
    let group = |collection: &str| {
        let mut q = list(collection);
        if let Some(pb::run_query_request::QueryType::StructuredQuery(sq)) = &mut q.query_type {
            sq.from[0].all_descendants = true;
        }
        q
    };
    denied(
        h.client
            .run_query(with_bearer(group("reviews"), &alice_token))
            .await
            .unwrap_err()
            .code(),
    );
    assert!(h
        .client
        .run_query(with_bearer(group("comments"), &alice_token))
        .await
        .is_ok());
    let _ = alice;
    h.handle.abort();
}

#[tokio::test]
async fn rules_can_read_other_documents_with_get_and_exists() {
    let mut h = start().await;
    let (alice, alice_token) = h.user("alice@example.com");
    let (_bob, bob_token) = h.user("bob@example.com");
    *h.rules.write().unwrap() = LoadedRules::from_source(
        "rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /admin/{id} {
      allow read, write: if get(/databases/$(database)/documents/roles/$(request.auth.uid)).data.role == 'admin';
    }
    match /gated/{id} {
      allow list: if exists(/databases/$(database)/documents/flags/open);
    }
  }
}",
    )
    .unwrap();
    h.client
        .commit(with_bearer(
            commit(vec![
                set_write(&format!("roles/{alice}"), &[("role", s("admin"))]),
                set_write("admin/settings", &[("v", s("1"))]),
            ]),
            "owner",
        ))
        .await
        .unwrap();
    assert!(h
        .client
        .get_document(with_bearer(get("admin/settings"), &alice_token))
        .await
        .is_ok());
    let err = h
        .client
        .get_document(with_bearer(get("admin/settings"), &bob_token))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::PermissionDenied);
    // Writes evaluate get() against the same commit snapshot.
    assert!(h
        .client
        .commit(with_bearer(
            commit(vec![set_write("admin/settings", &[("v", s("2"))])]),
            &alice_token,
        ))
        .await
        .is_ok());
    // exists() in a list rule reads real documents (not part of the query proof).
    let err = h
        .client
        .run_query(with_bearer(list("gated"), &alice_token))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::PermissionDenied);
    h.client
        .commit(with_bearer(
            commit(vec![set_write("flags/open", &[("on", s("yes"))])]),
            "owner",
        ))
        .await
        .unwrap();
    assert!(h
        .client
        .run_query(with_bearer(list("gated"), &alice_token))
        .await
        .is_ok());
    h.handle.abort();
}

#[tokio::test]
async fn nested_create_lazily_evaluates_optional_parent_fields() {
    let mut h = start().await;
    let (alice, alice_token) = h.user("alice@example.com");
    let (bob, bob_token) = h.user("bob@example.com");
    *h.rules.write().unwrap() = LoadedRules::from_source(
        "rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /projects/{projectId}/private/{documentId} {
      function mayCreate() {
        let project = get(/databases/$(database)/documents/projects/$(projectId)).data;
        let primaryId = project.primaryId;
        let optionalId = project.optionalId;
        let members = get(/databases/$(database)/documents/projects/$(projectId)).data.members;
        return primaryId == request.auth.uid ||
               optionalId == request.auth.uid ||
               (
                 request.auth.uid in members &&
                 members[request.auth.uid].role in ['primary', 'agent']
               );
      }
      allow create: if request.auth != null && mayCreate();
    }
  }
}",
    )
    .unwrap();
    h.client
        .commit(with_bearer(
            commit(vec![set_write(
                "projects/primary",
                &[
                    ("primaryId", s(&alice)),
                    ("members", map(&[(&alice, map(&[("role", s("primary"))]))])),
                ],
            )]),
            "owner",
        ))
        .await
        .unwrap();
    h.client
        .commit(with_bearer(
            commit(vec![set_write(
                "projects/primary/private/creditor",
                &[("value", s("allowed"))],
            )]),
            &alice_token,
        ))
        .await
        .unwrap();
    let denied = h
        .client
        .commit(with_bearer(
            commit(vec![set_write(
                "projects/primary/private/unrelated",
                &[("value", s("denied"))],
            )]),
            &bob_token,
        ))
        .await
        .unwrap_err();
    assert_eq!(denied.code(), tonic::Code::PermissionDenied);

    h.client
        .commit(with_bearer(
            commit(vec![set_write(
                "projects/member",
                &[
                    ("primaryId", s("someone-else")),
                    ("members", map(&[(&bob, map(&[("role", s("primary"))]))])),
                ],
            )]),
            "owner",
        ))
        .await
        .unwrap();
    h.client
        .commit(with_bearer(
            commit(vec![set_write(
                "projects/member/private/creditor",
                &[("value", s("allowed"))],
            )]),
            &bob_token,
        ))
        .await
        .unwrap();

    let missing_parent = h
        .client
        .commit(with_bearer(
            commit(vec![set_write(
                "projects/missing/private/creditor",
                &[("value", s("denied"))],
            )]),
            &alice_token,
        ))
        .await
        .unwrap_err();
    assert_eq!(missing_parent.code(), tonic::Code::PermissionDenied);
    h.handle.abort();
}

#[tokio::test]
async fn rules_document_access_reads_the_snapshot_being_served() {
    let mut h = start().await;
    let (_alice, alice_token) = h.user("alice@example.com");
    *h.rules.write().unwrap() = LoadedRules::from_source(
        "rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /gated/{id} {
      allow get: if get(/databases/$(database)/documents/flags/open).data.on == 'yes';
    }
  }
}",
    )
    .unwrap();
    let first = h
        .client
        .commit(with_bearer(
            commit(vec![
                set_write("flags/open", &[("on", s("yes"))]),
                set_write("gated/x", &[("v", s("1"))]),
            ]),
            "owner",
        ))
        .await
        .unwrap()
        .into_inner();
    h.client
        .commit(with_bearer(
            commit(vec![set_write("flags/open", &[("on", s("no"))])]),
            "owner",
        ))
        .await
        .unwrap();
    // Latest state: the flag is off.
    let err = h
        .client
        .get_document(with_bearer(get("gated/x"), &alice_token))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::PermissionDenied);
    // A read_time snapshot: get() in the rules sees the flag as it was at that time.
    let mut at_first = get("gated/x");
    at_first.consistency_selector = Some(pb::get_document_request::ConsistencySelector::ReadTime(
        first.commit_time.unwrap(),
    ));
    assert!(h
        .client
        .get_document(with_bearer(at_first, &alice_token))
        .await
        .is_ok());
    h.handle.abort();
}

#[tokio::test]
async fn multi_document_commits_share_the_document_access_budget() {
    let mut h = start().await;
    let (_alice, alice_token) = h.user("alice@example.com");
    *h.rules.write().unwrap() = LoadedRules::from_source(
        "rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /items/{id} {
      allow write: if !exists(/databases/$(database)/documents/locks/$(id));
    }
  }
}",
    )
    .unwrap();
    let writes = |n: usize| {
        (0..n)
            .map(|i| set_write(&format!("items/{i}"), &[("v", s("1"))]))
            .collect::<Vec<_>>()
    };
    // Twenty distinct exists() documents across the commit fit RULES-DOC-ACCESS-MULTI-TOTAL.
    assert!(h
        .client
        .commit(with_bearer(commit(writes(20)), &alice_token))
        .await
        .is_ok());
    let err = h
        .client
        .commit(with_bearer(commit(writes(21)), &alice_token))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::PermissionDenied);
    assert!(
        err.message().contains("RULES-DOC-ACCESS-MULTI-TOTAL"),
        "{}",
        err.message()
    );
    h.handle.abort();
}

#[tokio::test]
async fn refused_transactional_reads_leave_no_trace_in_the_read_set() {
    let mut h = start().await;
    let (_alice, alice_token) = h.user("alice@example.com");
    *h.rules.write().unwrap() = LoadedRules::from_source(
        "rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /secret/{id} { allow read: if false; }
    match /mine/{id} { allow read, write: if true; }
  }
}",
    )
    .unwrap();
    h.client
        .commit(with_bearer(
            commit(vec![set_write("secret/x", &[("v", s("1"))])]),
            "owner",
        ))
        .await
        .unwrap();
    let txn = h
        .client
        .begin_transaction(with_bearer(
            pb::BeginTransactionRequest {
                database: DB.to_owned(),
                ..Default::default()
            },
            &alice_token,
        ))
        .await
        .unwrap()
        .into_inner()
        .transaction;
    let mut in_txn = get("secret/x");
    in_txn.consistency_selector = Some(pb::get_document_request::ConsistencySelector::Transaction(
        txn.clone(),
    ));
    let err = h
        .client
        .get_document(with_bearer(in_txn, &alice_token))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::PermissionDenied);
    // The forbidden document changes; the refused read must not abort the transaction.
    h.client
        .commit(with_bearer(
            commit(vec![set_write("secret/x", &[("v", s("2"))])]),
            "owner",
        ))
        .await
        .unwrap();
    let mut c = commit(vec![set_write("mine/y", &[("v", s("1"))])]);
    c.transaction = txn;
    assert!(h.client.commit(with_bearer(c, &alice_token)).await.is_ok());
    h.handle.abort();
}

#[tokio::test]
async fn batch_gets_share_the_multi_document_access_budget() {
    let mut h = start().await;
    let (_alice, alice_token) = h.user("alice@example.com");
    *h.rules.write().unwrap() = LoadedRules::from_source(
        "rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /items/{id} {
      allow get: if !exists(/databases/$(database)/documents/locks/$(id));
    }
  }
}",
    )
    .unwrap();
    let batch = |n: usize| pb::BatchGetDocumentsRequest {
        database: DB.to_owned(),
        documents: (0..n).map(|i| format!("{DOCS}/items/{i}")).collect(),
        ..Default::default()
    };
    let mut ok = h
        .client
        .batch_get_documents(with_bearer(batch(20), &alice_token))
        .await
        .unwrap()
        .into_inner();
    let mut count = 0;
    while let Some(r) = ok.next().await {
        r.unwrap();
        count += 1;
    }
    assert_eq!(count, 20);
    let err = h
        .client
        .batch_get_documents(with_bearer(batch(21), &alice_token))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::PermissionDenied);
    assert!(err.message().contains("RULES-DOC-ACCESS-MULTI-TOTAL"));
    h.handle.abort();
}

fn list_range(
    collection: &str,
    field: &str,
    op: sq::field_filter::Operator,
    value: pb::Value,
    limit: Option<i32>,
) -> pb::RunQueryRequest {
    let mut req = list(collection);
    if let Some(pb::run_query_request::QueryType::StructuredQuery(sq)) = &mut req.query_type {
        sq.r#where = Some(sq::Filter {
            filter_type: Some(sq::filter::FilterType::FieldFilter(sq::FieldFilter {
                field: Some(sq::FieldReference {
                    field_path: field.to_owned(),
                }),
                op: op as i32,
                value: Some(value),
            })),
        });
        sq.limit = limit;
    }
    req
}

#[tokio::test]
async fn queries_are_proven_from_inequality_constraints_and_request_query() {
    use sq::field_filter::Operator as Op;
    let mut h = start().await;
    let (_alice, alice_token) = h.user("alice@example.com");
    *h.rules.write().unwrap() = LoadedRules::from_source(
        "rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /people/{id} { allow list: if resource.data.age >= 18; }
    match /paged/{id} { allow list: if request.query.limit <= 20; }
  }
}",
    )
    .unwrap();
    let int = |v: i64| pb::Value {
        value_type: Some(pb::value::ValueType::IntegerValue(v)),
    };
    let people = |op, v| list_range("people", "age", op, int(v), None);
    // age >= 18 and age > 20 prove the rule; age >= 10 and an unfiltered list do not.
    assert!(h
        .client
        .run_query(with_bearer(
            people(Op::GreaterThanOrEqual, 18),
            &alice_token
        ))
        .await
        .is_ok());
    assert!(h
        .client
        .run_query(with_bearer(people(Op::GreaterThan, 20), &alice_token))
        .await
        .is_ok());
    for (op, v) in [(Op::GreaterThanOrEqual, 10), (Op::LessThan, 30)] {
        let err = h
            .client
            .run_query(with_bearer(people(op, v), &alice_token))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied, "{op:?} {v}");
    }
    assert_eq!(
        h.client
            .run_query(with_bearer(list("people"), &alice_token))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::PermissionDenied
    );
    // request.query.limit
    let paged = |limit| list_range("paged", "x", Op::Equal, int(1), limit);
    assert!(h
        .client
        .run_query(with_bearer(paged(Some(20)), &alice_token))
        .await
        .is_ok());
    for limit in [Some(21), None] {
        let err = h
            .client
            .run_query(with_bearer(paged(limit), &alice_token))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied, "{limit:?}");
    }
    // ListDocuments: the page size is the limit the rules see (100 by default).
    let listing = |page_size: i32| pb::ListDocumentsRequest {
        parent: DOCS.to_owned(),
        collection_id: "paged".to_owned(),
        page_size,
        ..Default::default()
    };
    assert!(h
        .client
        .list_documents(with_bearer(listing(20), &alice_token))
        .await
        .is_ok());
    for (page_size, code) in [
        (21, tonic::Code::PermissionDenied),
        (0, tonic::Code::PermissionDenied),
        (-1, tonic::Code::InvalidArgument),
    ] {
        let err = h
            .client
            .list_documents(with_bearer(listing(page_size), &alice_token))
            .await
            .unwrap_err();
        assert_eq!(err.code(), code, "page_size {page_size}");
    }
    h.handle.abort();
}

async fn query_code(
    h: &mut Harness,
    token: &str,
    req: pb::RunQueryRequest,
) -> Result<(), tonic::Code> {
    h.client
        .run_query(with_bearer(req, token))
        .await
        .map(|_| ())
        .map_err(|e| e.code())
}

fn arr(items: Vec<pb::Value>) -> pb::Value {
    pb::Value {
        value_type: Some(pb::value::ValueType::ArrayValue(pb::ArrayValue {
            values: items,
        })),
    }
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn queries_are_proven_from_in_not_in_not_equal_and_order_by() {
    use sq::field_filter::Operator as Op;
    let mut h = start().await;
    let (_alice, alice_token) = h.user("alice@example.com");
    *h.rules.write().unwrap() = LoadedRules::from_source(
        "rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /posts/{id} { allow list: if resource.data.status in ['published', 'archived']; }
    match /live/{id} { allow list: if resource.data.status != 'deleted'; }
    match /typed/{id} { allow list: if resource.data.kind is string; }
    match /ordered/{id} { allow list: if request.query.orderBy['createdAt'] == 'DESC'; }
  }
}",
    )
    .unwrap();
    let denied = Err(tonic::Code::PermissionDenied);
    // `in` with candidates all inside the rule's set proves it; one outside does not.
    assert_eq!(
        query_code(
            &mut h,
            &alice_token,
            list_range("posts", "status", Op::In, arr(vec![s("published")]), None)
        )
        .await,
        Ok(())
    );
    assert_eq!(
        query_code(
            &mut h,
            &alice_token,
            list_range(
                "posts",
                "status",
                Op::In,
                arr(vec![s("published"), s("archived")]),
                None
            )
        )
        .await,
        Ok(())
    );
    assert_eq!(
        query_code(
            &mut h,
            &alice_token,
            list_where("posts", "status", s("archived"))
        )
        .await,
        Ok(())
    );
    assert_eq!(
        query_code(
            &mut h,
            &alice_token,
            list_range(
                "posts",
                "status",
                Op::In,
                arr(vec![s("published"), s("draft")]),
                None
            )
        )
        .await,
        denied
    );
    assert_eq!(
        query_code(&mut h, &alice_token, list("posts")).await,
        denied
    );
    // `!=` and `not-in` prove a `!=` rule when the excluded value is among the filter's.
    assert_eq!(
        query_code(
            &mut h,
            &alice_token,
            list_range("live", "status", Op::NotEqual, s("deleted"), None)
        )
        .await,
        Ok(())
    );
    assert_eq!(
        query_code(
            &mut h,
            &alice_token,
            list_range(
                "live",
                "status",
                Op::NotIn,
                arr(vec![s("deleted"), s("hidden")]),
                None
            )
        )
        .await,
        Ok(())
    );
    assert_eq!(
        query_code(
            &mut h,
            &alice_token,
            list_range("live", "status", Op::NotEqual, s("hidden"), None)
        )
        .await,
        denied
    );
    // A type check is proven by an `in` over one type only.
    assert_eq!(
        query_code(
            &mut h,
            &alice_token,
            list_range("typed", "kind", Op::In, arr(vec![s("a"), s("b")]), None)
        )
        .await,
        Ok(())
    );
    let int = |v: i64| pb::Value {
        value_type: Some(pb::value::ValueType::IntegerValue(v)),
    };
    assert_eq!(
        query_code(
            &mut h,
            &alice_token,
            list_range("typed", "kind", Op::In, arr(vec![s("a"), int(1)]), None)
        )
        .await,
        denied
    );
    // request.query.orderBy
    let ordered = |direction: sq::Direction| {
        let mut req = list("ordered");
        if let Some(pb::run_query_request::QueryType::StructuredQuery(sq)) = &mut req.query_type {
            sq.order_by = vec![sq::Order {
                field: Some(sq::FieldReference {
                    field_path: "createdAt".to_owned(),
                }),
                direction: direction as i32,
            }];
        }
        req
    };
    assert_eq!(
        query_code(&mut h, &alice_token, ordered(sq::Direction::Descending)).await,
        Ok(())
    );
    assert_eq!(
        query_code(&mut h, &alice_token, ordered(sq::Direction::Ascending)).await,
        denied
    );
    assert_eq!(
        query_code(&mut h, &alice_token, list("ordered")).await,
        denied
    );
    h.handle.abort();
}

#[tokio::test]
async fn get_after_reads_the_state_the_whole_commit_leaves_behind() {
    let mut h = start().await;
    let (_alice, alice_token) = h.user("alice@example.com");
    *h.rules.write().unwrap() = LoadedRules::from_source(
        "rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    // A post may be created only together with the counter increment.
    match /posts/{id} {
      allow create: if getAfter(/databases/$(database)/documents/stats/posts).data.count
                       == get(/databases/$(database)/documents/stats/posts).data.count + 1;
    }
    match /stats/{id} {
      allow update: if request.resource.data.count == resource.data.count + 1;
    }
  }
}",
    )
    .unwrap();
    let int = |v: i64| pb::Value {
        value_type: Some(pb::value::ValueType::IntegerValue(v)),
    };
    h.client
        .commit(with_bearer(
            commit(vec![set_write("stats/posts", &[("count", int(0))])]),
            "owner",
        ))
        .await
        .unwrap();
    // The post alone: the counter would stay at 0 after the commit.
    let err = h
        .client
        .commit(with_bearer(
            commit(vec![set_write("posts/p1", &[("title", s("hi"))])]),
            &alice_token,
        ))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::PermissionDenied);
    // Post first, counter second: getAfter() sees the whole batch.
    assert!(h
        .client
        .commit(with_bearer(
            commit(vec![
                set_write("posts/p1", &[("title", s("hi"))]),
                set_write("stats/posts", &[("count", int(1))]),
            ]),
            &alice_token,
        ))
        .await
        .is_ok());
    // A read cannot use getAfter(): fails closed with the reason.
    *h.rules.write().unwrap() = LoadedRules::from_source(
        "rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /posts/{id} { allow read: if getAfter(/databases/$(database)/documents/stats/posts).data.count == 1; }
  }
}",
    )
    .unwrap();
    let err = h
        .client
        .get_document(with_bearer(get("posts/p1"), &alice_token))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::PermissionDenied);
    assert!(err.message().contains("getAfter()"), "{}", err.message());
    h.handle.abort();
}

#[tokio::test]
async fn array_contains_any_queries_are_proven_soundly() {
    use sq::field_filter::Operator as Op;
    let mut h = start().await;
    let (_alice, alice_token) = h.user("alice@example.com");
    *h.rules.write().unwrap() = LoadedRules::from_source(
        "rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /tagged/{id} { allow list: if resource.data.tags.hasAny(['x', 'y']); }
    match /strict/{id} { allow list: if resource.data.tags.hasAll(['x', 'y']); }
  }
}",
    )
    .unwrap();
    // Every candidate is accepted by the rule: proven.
    assert_eq!(
        query_code(
            &mut h,
            &alice_token,
            list_range(
                "tagged",
                "tags",
                Op::ArrayContainsAny,
                arr(vec![s("x"), s("y")]),
                None
            )
        )
        .await,
        Ok(())
    );
    // A candidate the rule does not accept: a document holding only `z` would be denied.
    assert_eq!(
        query_code(
            &mut h,
            &alice_token,
            list_range(
                "tagged",
                "tags",
                Op::ArrayContainsAny,
                arr(vec![s("x"), s("z")]),
                None
            )
        )
        .await,
        Err(tonic::Code::PermissionDenied)
    );
    // `hasAll` is never proven by array-contains-any (the array may hold one of them).
    assert_eq!(
        query_code(
            &mut h,
            &alice_token,
            list_range(
                "strict",
                "tags",
                Op::ArrayContainsAny,
                arr(vec![s("x"), s("y")]),
                None
            )
        )
        .await,
        Err(tonic::Code::PermissionDenied)
    );
    h.handle.abort();
}

#[tokio::test]
async fn id_tokens_are_bound_to_the_requested_project() {
    let mut h = start().await;
    let (_, token) = h.user("a@example.com");
    // The token's audience is demo-app: another project's data is off limits even where
    // its rules would let any signed-in user in.
    let err = h
        .client
        .get_document(with_bearer(
            pb::GetDocumentRequest {
                name: "projects/demo-b/databases/(default)/documents/users/x".to_owned(),
                ..Default::default()
            },
            &token,
        ))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unauthenticated, "{err}");
    assert!(err.message().contains("audience"), "{err}");
    h.handle.abort();
}

#[tokio::test]
async fn transactions_are_bound_to_the_token_audience_too() {
    let mut h = start().await;
    let (_, token) = h.user("t@example.com");
    let err = h
        .client
        .begin_transaction(with_bearer(
            pb::BeginTransactionRequest {
                database: "projects/demo-b/databases/(default)".to_owned(),
                ..Default::default()
            },
            &token,
        ))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unauthenticated, "{err}");
    let err = h
        .client
        .batch_get_documents(with_bearer(
            pb::BatchGetDocumentsRequest {
                database: "projects/demo-b/databases/(default)".to_owned(),
                documents: Vec::new(),
                consistency_selector: Some(
                    pb::batch_get_documents_request::ConsistencySelector::NewTransaction(
                        pb::TransactionOptions::default(),
                    ),
                ),
                ..Default::default()
            },
            &token,
        ))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unauthenticated, "{err}");
    // The token's own project is fine.
    assert!(h
        .client
        .begin_transaction(with_bearer(
            pb::BeginTransactionRequest {
                database: "projects/demo-app/databases/(default)".to_owned(),
                ..Default::default()
            },
            &token,
        ))
        .await
        .is_ok());
    h.handle.abort();
}

/// The token `@firebase/rules-unit-testing`'s `authenticatedContext(sub)` mints, byte for
/// byte: `@firebase/util`'s `createMockUserToken` defaults `iat` to 0, so `exp` is 3600 --
/// an hour after the epoch -- and `sub` names whoever the test asked for, existing or not.
fn mock_user_token(sub: &str, project: &str) -> String {
    let header = base64url_encode(br#"{"alg":"none","type":"JWT"}"#);
    let payload = base64url_encode(
        format!(
            r#"{{"iss":"https://securetoken.google.com/{project}","aud":"{project}","iat":0,"exp":3600,"auth_time":0,"sub":"{sub}","user_id":"{sub}","firebase":{{"sign_in_provider":"custom","identities":{{}}}}}}"#
        )
        .as_bytes(),
    );
    format!("{header}.{payload}.")
}

fn profile_write(uid: &str) -> pb::CommitRequest {
    commit(vec![set_write(
        &format!("profiles/{uid}"),
        &[("name", s("A name"))],
    )])
}

#[tokio::test]
async fn the_firebase_profile_admits_the_mock_tokens_the_official_emulator_admits() {
    // Measured against the pinned suite: the official Firestore emulator serves this write,
    // because it never checks the subject against the Auth emulator and never reads `exp`.
    // Nobody creates `alice` here, and the clock is far past the token's 1970 expiry.
    let mut h = start_with(TokenAcceptance::EmulatorMock).await;
    let token = mock_user_token("alice", "demo-app");
    assert!(
        h.client
            .commit(with_bearer(profile_write("alice"), &token))
            .await
            .is_ok(),
        "a mock token names its subject and the rule comparing it to the path allows"
    );
    // It is an identity, not a bypass: the same token is refused on another user's document.
    let err = h
        .client
        .commit(with_bearer(profile_write("bob"), &token))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::PermissionDenied, "{err}");
    h.handle.abort();
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn the_firebase_profile_binds_unknown_mock_tokens_to_the_requested_project() {
    let worker = "demo-app-w0";
    let worker_db = format!("projects/{worker}/databases/(default)");
    let worker_docs = format!("{worker_db}/documents");
    let token = mock_user_token("alice", worker);
    let write = |project_docs: &str| pb::Write {
        operation: Some(pb::write::Operation::Update(pb::Document {
            name: format!("{project_docs}/profiles/alice"),
            fields: [("name".to_owned(), s("A name"))].into_iter().collect(),
            ..Default::default()
        })),
        ..Default::default()
    };

    let mut firebase = start_with(TokenAcceptance::EmulatorMock).await;
    firebase
        .client
        .commit(with_bearer(
            pb::CommitRequest {
                database: worker_db.clone(),
                writes: vec![write(&worker_docs)],
                ..Default::default()
            },
            &token,
        ))
        .await
        .expect("the mock token audience equals the routed worker project");
    let err = firebase
        .client
        .commit(with_bearer(profile_write("alice"), &token))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unauthenticated, "{err}");

    *firebase.rules.write().unwrap() = LoadedRules::from_source(
        "rules_version = '2'; service cloud.firestore { match /databases/{database}/documents { match /{document=**} { allow read, write: if true; } } }",
    )
    .unwrap();
    let (write_tx, write_rx) = mpsc::channel(4);
    let mut write_responses = firebase
        .client
        .write(with_bearer(ReceiverStream::new(write_rx), &token))
        .await
        .unwrap()
        .into_inner();
    write_tx
        .send(pb::WriteRequest {
            database: worker_db.clone(),
            ..Default::default()
        })
        .await
        .unwrap();
    let handshake = write_responses.next().await.unwrap().unwrap();
    write_tx
        .send(pb::WriteRequest {
            writes: vec![write(&worker_docs)],
            stream_token: handshake.stream_token,
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(write_responses.next().await.unwrap().is_ok());
    drop(write_tx);
    drop(write_responses);

    let (listen_tx, listen_rx) = mpsc::channel(2);
    let mut listen_responses = firebase
        .client
        .listen(with_bearer(ReceiverStream::new(listen_rx), &token))
        .await
        .unwrap()
        .into_inner();
    listen_tx
        .send(pb::ListenRequest {
            database: worker_db.clone(),
            target_change: Some(pb::listen_request::TargetChange::AddTarget(pb::Target {
                target_id: 1,
                target_type: Some(pb::target::TargetType::Query(pb::target::QueryTarget {
                    parent: worker_docs.clone(),
                    query_type: Some(pb::target::query_target::QueryType::StructuredQuery(
                        pb::StructuredQuery {
                            from: vec![sq::CollectionSelector {
                                collection_id: "profiles".to_owned(),
                                ..Default::default()
                            }],
                            ..Default::default()
                        },
                    )),
                })),
                ..Default::default()
            })),
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(listen_responses.next().await.unwrap().is_ok());
    drop(listen_tx);
    drop(listen_responses);

    let (foreign_tx, foreign_rx) = mpsc::channel(2);
    let mut foreign_responses = firebase
        .client
        .listen(with_bearer(ReceiverStream::new(foreign_rx), &token))
        .await
        .unwrap()
        .into_inner();
    foreign_tx
        .send(pb::ListenRequest {
            database: DB.to_owned(),
            target_change: Some(pb::listen_request::TargetChange::AddTarget(pb::Target {
                target_id: 2,
                target_type: Some(pb::target::TargetType::Query(pb::target::QueryTarget {
                    parent: DOCS.to_owned(),
                    query_type: Some(pb::target::query_target::QueryType::StructuredQuery(
                        pb::StructuredQuery {
                            from: vec![sq::CollectionSelector {
                                collection_id: "profiles".to_owned(),
                                ..Default::default()
                            }],
                            ..Default::default()
                        },
                    )),
                })),
                ..Default::default()
            })),
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(foreign_responses.next().await.unwrap().is_ok());
    let removed = foreign_responses.next().await.unwrap().unwrap();
    let Some(pb::listen_response::ResponseType::TargetChange(change)) = removed.response_type
    else {
        panic!("expected target removal");
    };
    assert_eq!(
        change.cause.unwrap().code,
        tonic::Code::Unauthenticated as i32
    );
    let err = foreign_responses.next().await.unwrap().unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unauthenticated, "{err}");
    firebase.handle.abort();

    let mut strict = start_with(TokenAcceptance::Verified).await;
    let err = strict
        .client
        .commit(with_bearer(
            pb::CommitRequest {
                database: worker_db.clone(),
                writes: vec![write(&worker_docs)],
                ..Default::default()
            },
            &token,
        ))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unauthenticated, "{err}");

    let (strict_tx, strict_rx) = mpsc::channel(4);
    let mut strict_responses = strict
        .client
        .write(with_bearer(ReceiverStream::new(strict_rx), &token))
        .await
        .unwrap()
        .into_inner();
    strict_tx
        .send(pb::WriteRequest {
            database: worker_db,
            ..Default::default()
        })
        .await
        .unwrap();
    let handshake = strict_responses.next().await.unwrap().unwrap();
    strict_tx
        .send(pb::WriteRequest {
            writes: vec![write(&worker_docs)],
            stream_token: handshake.stream_token,
            ..Default::default()
        })
        .await
        .unwrap();
    let err = strict_responses.next().await.unwrap().unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unauthenticated, "{err}");
    strict.handle.abort();
}

#[tokio::test]
async fn the_strict_profile_refuses_a_mock_token_the_auth_store_cannot_verify() {
    let mut h = start_with(TokenAcceptance::Verified).await;
    let err = h
        .client
        .commit(with_bearer(
            profile_write("alice"),
            &mock_user_token("alice", "demo-app"),
        ))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unauthenticated, "{err}");
    assert!(err.message().contains("invalid ID token"), "{err}");
    h.handle.abort();
}

#[tokio::test]
async fn the_firebase_profile_keeps_the_project_binding_and_the_signature_it_can_check() {
    let mut h = start_with(TokenAcceptance::EmulatorMock).await;
    // The official emulator admits a token minted for another project; fireemu does not, and
    // the contract records that as a deliberate divergence of the firebase profile: a token
    // must never cross a session or a project boundary.
    let err = h
        .client
        .commit(with_bearer(
            profile_write("alice"),
            &mock_user_token("alice", "demo-other"),
        ))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unauthenticated, "{err}");
    assert!(err.message().contains("audience"), "{err}");

    // A token that claims to be signed is not a mock token: only `alg: none` is one, so a
    // forged RS256 header can never buy the identity the unsigned path would have granted.
    let header = base64url_encode(br#"{"alg":"RS256","typ":"JWT","kid":"nope"}"#);
    let payload = base64url_encode(
        br#"{"iss":"https://securetoken.google.com/demo-app","aud":"demo-app","iat":0,"exp":3600,"auth_time":0,"sub":"alice","user_id":"alice"}"#,
    );
    let err = h
        .client
        .commit(with_bearer(
            profile_write("alice"),
            &format!("{header}.{payload}.AAAA"),
        ))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unauthenticated, "{err}");

    // A real session token still takes the verified path, so a live user keeps every claim
    // the store puts in it rather than being re-read as a mock.
    let (uid, token) = h.user("real@example.com");
    assert!(h
        .client
        .commit(with_bearer(profile_write(&uid), &token))
        .await
        .is_ok());
    h.handle.abort();
}
