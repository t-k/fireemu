//! Socket-free local Auth-to-Firestore Rules coverage. These tests exercise strict token
//! verification, read authorization and native in-memory listeners; they are not SDK or production evidence.

use fireemu_adapter_grpc::decode::Parent;
use fireemu_adapter_grpc::rules::{Principal, RulesEnforcer};
use fireemu_core_auth::claims::CustomClaims;
use fireemu_core_auth::jwt::{encode_unsigned, TokenAcceptance};
use fireemu_core_auth::mfa::TotpPolicy;
use fireemu_core_auth::store::{AuthRegistry, AuthStore, NewUser};
use fireemu_core_firestore::field_path::FieldPath;
use fireemu_core_firestore::path::DocumentPath;
use fireemu_core_firestore::query::{FieldOp, FilterExpr, Query, QueryScope};
use fireemu_core_firestore::store::{CommitVersion, Document};
use fireemu_core_firestore::value::Value;
use fireemu_core_rules::eval::NoDocumentAccess;
use fireemu_core_rules::runtime::{LoadedRules, RulesetSlot};
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_types::determinism::SplitMix64;
use fireemu_core_types::ids::{CollectionId, DatabaseId, ProjectId};
use fireemu_core_types::time::LogicalInstant;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use tonic::Code;

const PROJECT: &str = "demo-app";
const UID: &str = "shared-user";
const TENANTS: [&str; 2] = ["tenant-a", "tenant-b"];
const START: LogicalInstant = LogicalInstant::from_unix_seconds(1_788_004_860);
const RULES: &str = r"
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /tenantDocs/{id} {
      allow get, list: if request.auth != null
        && request.auth.uid == resource.data.owner
        && request.auth.token.firebase.tenant == resource.data.tenant
        && request.auth.token.reader == true;
    }
  }
}";

struct Identity {
    tenant: Option<&'static str>,
    reader: bool,
    token: String,
}
struct Fixture {
    enforcer: Arc<RulesEnforcer>,
    registry: Arc<AuthRegistry>,
    identities: Vec<Identity>,
}

impl Fixture {
    fn new() -> Self {
        let parent = Arc::new(Mutex::new(AuthStore::new(
            PROJECT,
            SplitMix64::new(3),
            TotpPolicy::default(),
        )));
        let registry = Arc::new(AuthRegistry::new(PROJECT, parent.clone()));
        let mut identities = Vec::new();
        for tenant in [None, Some(TENANTS[0]), Some(TENANTS[1])] {
            let store = tenant.map_or_else(
                || parent.clone(),
                |tenant| registry.ensure_tenant(PROJECT, tenant).unwrap(),
            );
            let mut store = store.lock().unwrap();
            let uid = store
                .create_user_with_id(NewUser::email("shared@example.com"), Some(UID), START)
                .unwrap();
            for reader in [false, true] {
                store
                    .set_custom_claims(
                        &uid,
                        CustomClaims::parse_attributes(if reader {
                            r#"{"reader":true}"#
                        } else {
                            r#"{"reader":false}"#
                        })
                        .unwrap(),
                    )
                    .unwrap();
                identities.push(Identity {
                    tenant,
                    reader,
                    token: encode_unsigned(&store.id_token_claims(&uid, None, START).unwrap()),
                });
            }
        }
        let enforcer = RulesEnforcer::new(
            Arc::new(RulesetSlot::new(LoadedRules::from_source(RULES).unwrap())),
            parent,
            Arc::new(Mutex::new(VirtualClock::new(START))),
        )
        .with_registry(registry.clone())
        .with_token_acceptance(TokenAcceptance::Verified);
        Self {
            enforcer: Arc::new(enforcer),
            registry,
            identities,
        }
    }
    fn principal(&self, identity: &Identity) -> Principal {
        self.enforcer
            .principal_from_authorization_for_project(
                Some(&format!("Bearer {}", identity.token)),
                PROJECT,
            )
            .unwrap()
    }
    fn reader(&self, tenant: &str) -> &Identity {
        self.identities
            .iter()
            .find(|i| i.tenant == Some(tenant) && i.reader)
            .unwrap()
    }
}

fn parent() -> Parent {
    Parent {
        project: ProjectId::try_new(PROJECT).unwrap(),
        database: DatabaseId::default_database(),
        document: None,
    }
}
fn document(tenant: &str) -> Document {
    let parent = parent();
    Document {
        path: DocumentPath::parse(
            &parent.project,
            &parent.database,
            &format!("tenantDocs/{tenant}"),
        )
        .unwrap(),
        fields: BTreeMap::from([
            ("owner".to_owned(), Value::String(UID.to_owned())),
            ("tenant".to_owned(), Value::String(tenant.to_owned())),
        ]),
        create_time: START,
        update_time: START,
        version: CommitVersion::from_value(1),
    }
}
fn equal(field: &str, value: &str) -> FilterExpr {
    FilterExpr::Field {
        field: FieldPath::parse(field).unwrap(),
        op: FieldOp::Equal,
        value: Value::String(value.to_owned()),
    }
}
fn query(filters: Vec<FilterExpr>) -> Query {
    let mut query = Query::new(QueryScope::collection(
        None,
        CollectionId::try_new("tenantDocs").unwrap(),
    ));
    query.filter = Some(FilterExpr::And(filters));
    query
}

#[test]
fn same_uid_tenant_and_reader_claims_control_gets_and_query_targets() {
    let fixture = Fixture::new();
    for identity in &fixture.identities {
        let principal = fixture.principal(identity);
        for tenant in TENANTS {
            let allowed = identity.tenant == Some(tenant) && identity.reader;
            let doc = document(tenant);
            let query = query(vec![equal("owner", UID), equal("tenant", tenant)]);
            let outcomes = [
                fixture.enforcer.authorize_get(
                    &principal,
                    &doc.path,
                    Some(&doc),
                    &NoDocumentAccess,
                ),
                fixture
                    .enforcer
                    .authorize_query(&principal, &parent(), &query, &NoDocumentAccess),
            ];
            for result in outcomes {
                if allowed {
                    result.unwrap();
                } else {
                    assert_eq!(result.unwrap_err().code(), Code::PermissionDenied);
                }
            }
        }
    }
    let doc = document(TENANTS[0]);
    assert_eq!(
        fixture
            .enforcer
            .authorize_query(
                &Principal::Anonymous,
                &parent(),
                &query(vec![equal("owner", UID), equal("tenant", TENANTS[0])]),
                &NoDocumentAccess,
            )
            .unwrap_err()
            .code(),
        Code::PermissionDenied
    );
    assert_eq!(
        fixture
            .enforcer
            .authorize_get(
                &Principal::Anonymous,
                &doc.path,
                Some(&doc),
                &NoDocumentAccess
            )
            .unwrap_err()
            .code(),
        Code::PermissionDenied
    );
}

#[test]
fn query_proofs_cannot_omit_tenant_or_owner_or_admit_another_tenant_branch() {
    let fixture = Fixture::new();
    for tenant in TENANTS {
        let principal = fixture.principal(fixture.reader(tenant));
        let filters = [
            vec![],
            vec![equal("owner", UID)],
            vec![equal("tenant", tenant)],
            vec![equal("owner", "another-user"), equal("tenant", tenant)],
            vec![
                equal("owner", UID),
                FilterExpr::Or(TENANTS.into_iter().map(|t| equal("tenant", t)).collect()),
            ],
        ];
        for filter in filters {
            assert_eq!(
                fixture
                    .enforcer
                    .authorize_query(&principal, &parent(), &query(filter), &NoDocumentAccess)
                    .unwrap_err()
                    .code(),
                Code::PermissionDenied
            );
        }
        fixture
            .enforcer
            .authorize_query(
                &principal,
                &parent(),
                &query(vec![equal("owner", UID), equal("tenant", tenant)]),
                &NoDocumentAccess,
            )
            .unwrap();
    }
}

#[test]
fn a_multi_document_get_refuses_a_foreign_tenant_with_the_same_owner_uid() {
    let fixture = Fixture::new();
    let docs = TENANTS.map(document);
    for (index, tenant) in TENANTS.into_iter().enumerate() {
        let principal = fixture.principal(fixture.reader(tenant));
        let own = &docs[index];
        fixture
            .enforcer
            .authorize_gets(
                &principal,
                &[(own.path.clone(), Some(own.clone()))],
                &NoDocumentAccess,
            )
            .unwrap();
        for ordered in [[&docs[0], &docs[1]], [&docs[1], &docs[0]]] {
            let items = ordered.map(|doc| (doc.path.clone(), Some(doc.clone())));
            assert_eq!(
                fixture
                    .enforcer
                    .authorize_gets(&principal, &items, &NoDocumentAccess)
                    .unwrap_err()
                    .code(),
                Code::PermissionDenied
            );
        }
    }
}

#[test]
fn deleted_tenant_tokens_cannot_fall_back_to_the_same_uid_in_the_parent_store() {
    let fixture = Fixture::new();
    for identity in &fixture.identities {
        fixture.principal(identity);
    }
    assert!(fixture.registry.delete_tenant(PROJECT, TENANTS[0]));
    for identity in &fixture.identities {
        let result = fixture.enforcer.principal_from_authorization_for_project(
            Some(&format!("Bearer {}", identity.token)),
            PROJECT,
        );
        if identity.tenant == Some(TENANTS[0]) {
            // A token Firestore cannot verify is refused in production's shape, as FS-RULES
            // recorded for other unusable bearers; production's answer for a deleted tenant's
            // token is not recorded yet (AUTH-FS-CROSS stage 1).
            assert!(matches!(result, Err(status) if status.code() == Code::PermissionDenied));
        } else {
            assert!(result.is_ok());
        }
    }
    let principal = fixture.principal(fixture.reader(TENANTS[1]));
    let doc = document(TENANTS[1]);
    fixture
        .enforcer
        .authorize_get(&principal, &doc.path, Some(&doc), &NoDocumentAccess)
        .unwrap();
}

mod listeners {
    use super::*;
    use fireemu_adapter_grpc::gateway::Gateway;
    use fireemu_adapter_grpc::local::LocalBackend;
    use fireemu_adapter_grpc::streams::{listen_stream, StreamContext};
    use fireemu_core_firestore::index::{IndexSet, IndexValidationPolicy, PlanningContext};
    use fireemu_core_types::edition::{FirestoreApiMode, FirestoreEdition};
    use fireemu_proto_firestore::google::firestore::v1 as pb;
    use std::time::Duration;
    use tokio::sync::mpsc;
    use tokio::task::JoinHandle;
    use tokio_stream::wrappers::ReceiverStream;
    use tonic::Status;

    const DB: &str = "projects/demo-app/databases/(default)";

    struct Listener {
        input: Option<mpsc::Sender<Result<pb::ListenRequest, Status>>>,
        output: mpsc::Receiver<Result<pb::ListenResponse, Status>>,
        task: Option<JoinHandle<()>>,
    }
    impl Drop for Listener {
        fn drop(&mut self) {
            // Assertion failures must not leave an in-memory stream task running.
            if let Some(task) = &self.task {
                task.abort();
            }
        }
    }
    impl Listener {
        async fn open(
            fixture: &Fixture,
            backend: &Arc<LocalBackend>,
            gateway: &Arc<Gateway>,
            tenant: &str,
            target: i32,
        ) -> Self {
            let identity = fixture.reader(tenant);
            let context = StreamContext {
                local: backend.clone(),
                gateway: gateway.clone(),
                rules: Some(fixture.enforcer.clone()),
                principal: fixture.principal(identity),
                authorization: Some(format!("Bearer {}", identity.token)),
                epoch: backend.epoch(),
                app_check: None,
            };
            let (input, requests) = mpsc::channel(8);
            let (responses, output) = mpsc::channel(16);
            let task = tokio::spawn(listen_stream(
                context,
                ReceiverStream::new(requests),
                responses,
            ));
            let listener = Self {
                input: Some(input),
                output,
                task: Some(task),
            };
            listener
                .input
                .as_ref()
                .unwrap()
                .send(Ok(pb::ListenRequest {
                    database: DB.to_owned(),
                    target_change: Some(pb::listen_request::TargetChange::AddTarget(pb::Target {
                        target_id: target,
                        target_type: Some(pb::target::TargetType::Documents(
                            pb::target::DocumentsTarget {
                                documents: vec![format!("{DB}/documents/tenantDocs/{tenant}")],
                            },
                        )),
                        ..Default::default()
                    })),
                    ..Default::default()
                }))
                .await
                .unwrap();
            listener
        }
        async fn next(&mut self) -> Option<Result<pb::ListenResponse, Status>> {
            tokio::time::timeout(Duration::from_secs(5), self.output.recv())
                .await
                .expect("bounded in-process Listen receive")
        }
        async fn snapshot(&mut self, tenant: &str, target: i32, marker: &str, initial: bool) {
            use pb::listen_response::ResponseType as R;
            let mut trace = Vec::new();
            for _ in 0..16 {
                let response = self.next().await.expect("stream remains open").unwrap();
                match response.response_type.unwrap() {
                    R::DocumentChange(change) => {
                        assert_eq!(change.target_ids, [target]);
                        assert!(change.removed_target_ids.is_empty());
                        let doc = change.document.unwrap();
                        assert_eq!(doc.name, format!("{DB}/documents/tenantDocs/{tenant}"));
                        for (key, expected) in
                            [("owner", UID), ("tenant", tenant), ("marker", marker)]
                        {
                            assert_eq!(
                                doc.fields[key].value_type,
                                Some(pb::value::ValueType::StringValue(expected.to_owned()))
                            );
                        }
                        trace.push("document");
                    }
                    R::TargetChange(change) => {
                        assert!(change.cause.is_none());
                        if change.target_ids.is_empty() {
                            assert_eq!(
                                change.target_change_type,
                                pb::target_change::TargetChangeType::NoChange as i32
                            );
                            let expected = if initial {
                                vec!["add", "document", "current", "no-change"]
                            } else {
                                vec!["document", "no-change"]
                            };
                            assert_eq!(trace, expected);
                            return;
                        }
                        assert_eq!(change.target_ids, [target]);
                        trace.push(match change.target_change_type {
                            1 => "add",
                            3 => "current",
                            0 => "no-change",
                            other => panic!("unexpected target change {other}"),
                        });
                    }
                    other => panic!("unexpected Listen response {other:?}"),
                }
            }
            panic!("missing snapshot boundary");
        }
        async fn finish(mut self) {
            self.input.take();
            self.output.close();
            let mut task = self.task.take().unwrap();
            if let Ok(result) = tokio::time::timeout(Duration::from_secs(5), &mut task).await {
                result.unwrap();
            } else {
                task.abort();
                let _ = task.await;
                panic!("Listen task did not stop after channel closure");
            }
        }
    }
    fn backend() -> (Arc<Gateway>, Arc<LocalBackend>) {
        let gateway = Arc::new(Gateway {
            enforce_limits: true,
            ctx: PlanningContext {
                edition: FirestoreEdition::Standard,
                api_mode: FirestoreApiMode::Native,
                policy: IndexValidationPolicy::Production,
            },
            indexes: IndexSet::default(),
        });
        let local = Arc::new(LocalBackend::new(
            (*gateway).clone(),
            Arc::new(Mutex::new(VirtualClock::new(START))),
            7,
        ));
        (gateway, local)
    }
    fn commit(backend: &LocalBackend, marker: &str) {
        let writes = TENANTS
            .into_iter()
            .map(|tenant| pb::Write {
                operation: Some(pb::write::Operation::Update(pb::Document {
                    name: format!("{DB}/documents/tenantDocs/{tenant}"),
                    fields: [("owner", UID), ("tenant", tenant), ("marker", marker)]
                        .into_iter()
                        .map(|(key, value)| {
                            (
                                key.to_owned(),
                                pb::Value {
                                    value_type: Some(pb::value::ValueType::StringValue(
                                        value.to_owned(),
                                    )),
                                },
                            )
                        })
                        .collect(),
                    ..Default::default()
                })),
                ..Default::default()
            })
            .collect();
        backend
            .commit(&pb::CommitRequest {
                database: DB.to_owned(),
                writes,
                ..Default::default()
            })
            .unwrap();
    }

    #[tokio::test]
    async fn deleted_tenant_listener_ends_on_refresh_while_sibling_keeps_receiving() {
        let fixture = Fixture::new();
        let (gateway, local) = backend();
        commit(&local, "initial");
        let mut removed = Listener::open(&fixture, &local, &gateway, TENANTS[0], 1).await;
        let mut sibling = Listener::open(&fixture, &local, &gateway, TENANTS[1], 2).await;
        removed.snapshot(TENANTS[0], 1, "initial", true).await;
        sibling.snapshot(TENANTS[1], 2, "initial", true).await;
        commit(&local, "before-delete");
        removed
            .snapshot(TENANTS[0], 1, "before-delete", false)
            .await;
        sibling
            .snapshot(TENANTS[1], 2, "before-delete", false)
            .await;
        assert!(fixture.registry.delete_tenant(PROJECT, TENANTS[0]));
        // Auth deletion alone is not a backend notification. This commit triggers reauthentication.
        commit(&local, "after-delete");
        let response = removed.next().await.unwrap().unwrap();
        let Some(pb::listen_response::ResponseType::TargetChange(change)) = response.response_type
        else {
            panic!("deleted tenant received document data before removal");
        };
        assert_eq!(
            change.target_change_type,
            pb::target_change::TargetChangeType::Remove as i32
        );
        assert_eq!(change.target_ids, [1]);
        // The refusal has the shape FS-RULES recorded for an unusable bearer (PERMISSION_DENIED);
        // production's listener behaviour after a tenant deletion is not recorded yet.
        assert_eq!(change.cause.unwrap().code, Code::PermissionDenied as i32);
        assert_eq!(
            removed.next().await.unwrap().unwrap_err().code(),
            Code::PermissionDenied
        );
        assert!(removed.next().await.is_none());
        sibling.snapshot(TENANTS[1], 2, "after-delete", false).await;
        removed.finish().await;
        sibling.finish().await;
    }
}
