//! A deleted tenant's unexpired ID token on Firestore, in a registered (non-default) project of a
//! daemon session: production honours it (AUTH-FS-CROSS stage 1), and fireemu does in the default
//! project. A registered project and its tenants each carry their own session epoch, so the
//! deleted tenant's token is checked against the epoch its tenant had, as long as the project has
//! not been reset since; after a reset the token belongs to a session that no longer exists.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use fireemu_adapter_grpc::rules::{Principal, RulesEnforcer, TokenSemantics};
use fireemu_core_auth::jwt::{encode_unsigned, TokenAcceptance};
use fireemu_core_auth::mfa::TotpPolicy;
use fireemu_core_auth::store::{AuthRegistry, AuthStore, NewUser};
use fireemu_core_rules::runtime::{LoadedRules, RulesetSlot};
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_types::determinism::SplitMix64;
use fireemu_core_types::time::LogicalInstant;

const DEFAULT: &str = "demo-app";
const OTHER: &str = "other-app";
const TENANT: &str = "tenant-x";
const START: LogicalInstant = LogicalInstant::from_unix_seconds(1_788_004_860);

struct Session {
    enforcer: RulesEnforcer,
    registry: Arc<AuthRegistry>,
}

fn session() -> Session {
    let default = Arc::new(Mutex::new(AuthStore::new(
        DEFAULT,
        SplitMix64::new(1),
        TotpPolicy::default(),
    )));
    let registry = Arc::new(
        AuthRegistry::with_project_numbers_and_lifecycle_incarnation(
            DEFAULT,
            default.clone(),
            BTreeMap::new(),
            7,
        ),
    );
    assert!(registry.register(
        OTHER,
        AuthStore::new(OTHER, SplitMix64::new(2), TotpPolicy::default())
    ));
    let enforcer = RulesEnforcer::new(
        Arc::new(RulesetSlot::new(
            LoadedRules::from_source(
                "rules_version = '2'; service cloud.firestore { match /{d=**} { allow read: if true; } }",
            )
            .unwrap(),
        )),
        default,
        Arc::new(Mutex::new(VirtualClock::new(START))),
    )
    .with_registry(registry.clone())
    .with_token_acceptance(TokenAcceptance::Verified)
    .with_token_semantics(TokenSemantics::Firestore);
    Session { enforcer, registry }
}

/// An ID token of a new user of `TENANT` in `OTHER`, issued at `START`.
fn tenant_token(registry: &AuthRegistry) -> String {
    let store = registry.ensure_tenant(OTHER, TENANT).unwrap();
    let mut store = store.lock().unwrap();
    let uid = store
        .create_user_with_id(NewUser::email("x@example.com"), Some("tenant-user"), START)
        .unwrap();
    encode_unsigned(&store.id_token_claims(&uid, None, START).unwrap())
}

#[allow(clippy::result_large_err)]
fn resolve(session: &Session, token: &str) -> Result<Principal, tonic::Status> {
    session
        .enforcer
        .principal_from_authorization_for_project(Some(&format!("Bearer {token}")), OTHER)
}

#[test]
fn a_deleted_tenants_unexpired_token_is_honoured_in_a_registered_project() {
    let session = session();
    let token = tenant_token(&session.registry);
    assert!(resolve(&session, &token).is_ok(), "before the deletion");
    assert!(session.registry.delete_tenant(OTHER, TENANT));
    let Principal::User(user) = resolve(&session, &token).expect("after the deletion") else {
        panic!("a user");
    };
    assert_eq!(user.uid, "tenant-user");
}

#[test]
fn a_reset_of_the_project_ends_the_deleted_tenants_token() {
    let session = session();
    let token = tenant_token(&session.registry);
    assert!(session.registry.delete_tenant(OTHER, TENANT));
    assert!(resolve(&session, &token).is_ok());
    session
        .registry
        .store_for(OTHER)
        .unwrap()
        .lock()
        .unwrap()
        .clear();
    assert!(
        resolve(&session, &token).is_err(),
        "a token of the session before the reset"
    );
}
