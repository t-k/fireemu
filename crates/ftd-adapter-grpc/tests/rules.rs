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
