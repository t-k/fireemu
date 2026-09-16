#![allow(missing_docs)]

use std::sync::{Arc, Mutex};

use fireemu_core_auth::mfa::TotpPolicy;
use fireemu_core_auth::store::{
    AuthError, AuthPrincipal, AuthRegistry, AuthStore, NewUser, ProjectAuthConfig,
    ProjectAuthConfigPatch, TenantMetadataPatch,
};
use fireemu_core_types::determinism::SplitMix64;
use fireemu_core_types::time::LogicalInstant;

const NOW: LogicalInstant = LogicalInstant::UNIX_EPOCH;

fn store(project: &str) -> AuthStore {
    AuthStore::new(project, SplitMix64::new(7), TotpPolicy::default())
}

#[test]
fn client_permissions_default_to_allow_and_admin_bypasses_end_user_gates() {
    let mut store = store("demo-app");
    assert!(store.allows_user_signup(AuthPrincipal::EndUser));
    assert!(store.allows_user_deletion(AuthPrincipal::EndUser));
    assert!(store.allows_user_signup(AuthPrincipal::Admin));
    assert!(store.allows_user_deletion(AuthPrincipal::Admin));

    store.set_config(ProjectAuthConfig {
        disabled_user_signup: true,
        disabled_user_deletion: true,
        ..ProjectAuthConfig::default()
    });
    assert!(!store.allows_user_signup(AuthPrincipal::EndUser));
    assert!(!store.allows_user_deletion(AuthPrincipal::EndUser));
    assert!(store.allows_user_signup(AuthPrincipal::Admin));
    assert!(store.allows_user_deletion(AuthPrincipal::Admin));
}

#[test]
fn denied_end_user_creation_and_deletion_do_not_mutate_state() {
    let mut store = store("demo-app");
    let uid = store
        .create_user(NewUser::email("existing@example.test"), NOW)
        .unwrap();
    let _ = store.take_user_events();
    store.set_config(ProjectAuthConfig {
        disabled_user_signup: true,
        disabled_user_deletion: true,
        ..ProjectAuthConfig::default()
    });

    assert_eq!(
        store.create_user_as(
            AuthPrincipal::EndUser,
            NewUser::email("new@example.test"),
            NOW,
        ),
        Err(AuthError::UserSignupDisabled)
    );
    assert!(store.user_by_email("new@example.test").is_none());
    assert_eq!(store.take_user_events(), Vec::new());

    assert_eq!(
        store.delete_user_by_id_as(AuthPrincipal::EndUser, uid.as_str()),
        Err(AuthError::UserDeletionDisabled)
    );
    assert!(store.user_by_id(uid.as_str()).is_some());
    assert!(store.take_user_events().is_empty());

    assert!(store
        .delete_user_by_id_as(AuthPrincipal::Admin, uid.as_str())
        .is_ok());
    assert!(store.user_by_id(uid.as_str()).is_none());
}

#[test]
fn project_config_patch_preserves_unselected_client_permission_fields() {
    let mut store = store("demo-app");
    store.set_config(ProjectAuthConfig {
        allow_duplicate_emails: true,
        disabled_user_signup: true,
        disabled_user_deletion: true,
        ..ProjectAuthConfig::default()
    });
    let patched = ProjectAuthConfigPatch {
        disabled_user_signup: Some(false),
        ..ProjectAuthConfigPatch::default()
    }
    .apply_to(store.config());
    store.set_config(patched);
    assert!(!store.config().disabled_user_signup);
    assert!(store.config().disabled_user_deletion);
    assert!(store.config().allow_duplicate_emails);
}

#[test]
fn tenant_client_permissions_are_isolated_and_do_not_change_siblings() {
    let default = Arc::new(Mutex::new(store("demo-app")));
    let registry = AuthRegistry::new("demo-app", default);
    let alpha = registry.ensure_tenant("demo-app", "alpha").unwrap();
    let beta = registry.ensure_tenant("demo-app", "beta").unwrap();

    registry
        .patch_tenant(
            "demo-app",
            "alpha",
            TenantMetadataPatch {
                disabled_user_signup: Some(true),
                disabled_user_deletion: Some(true),
                ..TenantMetadataPatch::default()
            },
        )
        .unwrap();
    assert!(
        registry
            .tenant_metadata("demo-app", "alpha")
            .unwrap()
            .disabled_user_signup
    );
    assert!(
        !registry
            .tenant_metadata("demo-app", "beta")
            .unwrap()
            .disabled_user_signup
    );
    assert!(alpha.lock().unwrap().config().disabled_user_signup);
    assert!(!beta.lock().unwrap().config().disabled_user_signup);
}

#[test]
fn cross_namespace_snapshot_keeps_destination_client_permissions() {
    let mut source = store("source");
    source.set_config(ProjectAuthConfig {
        disabled_user_signup: true,
        disabled_user_deletion: true,
        ..ProjectAuthConfig::default()
    });
    let snapshot = fireemu_core_auth::store::AuthSnapshot::capture(&source);

    let mut destination = store("destination");
    destination.set_config(ProjectAuthConfig {
        disabled_user_signup: false,
        disabled_user_deletion: true,
        ..ProjectAuthConfig::default()
    });
    snapshot.restore_into(&mut destination);
    assert!(!destination.config().disabled_user_signup);
    assert!(destination.config().disabled_user_deletion);
}
