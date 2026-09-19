#![allow(missing_docs)]

use std::sync::{Arc, Mutex};

use fireemu_core_auth::mfa::TotpPolicy;
use fireemu_core_auth::signup_quota::{QuotaMode, SignupQuotaConfig};
use fireemu_core_auth::store::{
    AuthError, AuthNamespaceConfigPatch, AuthPrincipal, AuthRegistry, AuthStore, NewUser,
    ProjectAuthConfig, ProjectAuthConfigPatch, TenantMetadataPatch,
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
fn repeated_tenant_startup_overrides_preserve_each_selected_field() {
    let registry = AuthRegistry::new("demo-app", Arc::new(Mutex::new(store("demo-app"))));
    registry
        .ensure_tenant("demo-app", "tenant-a")
        .expect("tenant is created");

    assert!(registry.register_tenant_config_override(
        "demo-app",
        "tenant-a",
        AuthNamespaceConfigPatch {
            disabled_user_signup: Some(true),
            enable_improved_email_privacy: Some(true),
            ..AuthNamespaceConfigPatch::default()
        },
    ));
    assert!(registry.register_tenant_config_override(
        "demo-app",
        "tenant-a",
        AuthNamespaceConfigPatch {
            allow_duplicate_emails: Some(true),
            ..AuthNamespaceConfigPatch::default()
        },
    ));

    // A later project update reapplies the stored startup patch. Every field from both
    // registrations must remain explicit; a second partial registration must not replace the
    // first one.
    registry
        .patch_project_config(
            "demo-app",
            ProjectAuthConfigPatch {
                disabled_user_signup: Some(false),
                disabled_user_deletion: Some(true),
                ..ProjectAuthConfigPatch::default()
            },
        )
        .expect("project patch succeeds");

    let tenant = registry
        .tenant_store("demo-app", "tenant-a")
        .expect("tenant store");
    assert_eq!(
        tenant.lock().expect("tenant store lock").config(),
        ProjectAuthConfig {
            allow_duplicate_emails: true,
            enable_improved_email_privacy: true,
            disabled_user_signup: true,
            disabled_user_deletion: true,
        }
    );
}

#[test]
fn project_config_and_quota_patch_commit_under_one_namespace_gate() {
    let registry = AuthRegistry::new("demo-app", Arc::new(Mutex::new(store("demo-app"))));
    let quota = SignupQuotaConfig {
        mode: QuotaMode::Enforce,
        default_quota_per_hour: 17,
        max_tracked_buckets: 8,
        ..SignupQuotaConfig::default()
    };

    let result = registry.patch_project_config_with_password_policy_and_quota(
        "demo-app",
        ProjectAuthConfigPatch {
            disabled_user_signup: Some(true),
            ..ProjectAuthConfigPatch::default()
        },
        None,
        Some(quota.clone()),
    );

    assert!(result.unwrap().disabled_user_signup);
    let project = registry.default_store();
    let project = project.lock().unwrap();
    assert!(project.config().disabled_user_signup);
    assert_eq!(project.signup_quota().config(), &quota);
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

#[test]
fn project_config_override_waits_for_exact_namespace_registration() {
    let registry = AuthRegistry::new("demo-app", Arc::new(Mutex::new(store("demo-app"))));
    let patch = AuthNamespaceConfigPatch {
        disabled_user_signup: Some(true),
        enable_improved_email_privacy: Some(false),
        ..AuthNamespaceConfigPatch::default()
    };

    assert!(registry.register_project_config_override("future-project", patch));
    assert!(registry.store_for("future-project").is_none());
    assert!(registry.register("future-project", store("future-project")));

    let future = registry.store_for("future-project").unwrap();
    let future = future.lock().unwrap();
    assert!(future.config().disabled_user_signup);
    assert!(!future.config().enable_improved_email_privacy);
    assert!(
        !registry
            .default_store()
            .lock()
            .unwrap()
            .config()
            .disabled_user_signup
    );
}

#[test]
fn tenant_config_override_waits_for_exact_namespace_and_preserves_siblings() {
    let registry = AuthRegistry::new("demo-app", Arc::new(Mutex::new(store("demo-app"))));
    let patch = AuthNamespaceConfigPatch {
        allow_duplicate_emails: None,
        disabled_user_signup: Some(true),
        disabled_user_deletion: Some(true),
        enable_improved_email_privacy: Some(false),
    };

    assert!(registry.register_tenant_config_override("demo-app", "tenant-a", patch));
    assert!(registry.tenant_store("demo-app", "tenant-a").is_none());

    let tenant_a = registry.ensure_tenant("demo-app", "tenant-a").unwrap();
    let tenant_b = registry.ensure_tenant("demo-app", "tenant-b").unwrap();
    let config_a = tenant_a.lock().unwrap().config();
    assert!(config_a.disabled_user_signup);
    assert!(config_a.disabled_user_deletion);
    assert!(!config_a.enable_improved_email_privacy);
    assert!(
        registry
            .tenant_metadata("demo-app", "tenant-a")
            .unwrap()
            .disabled_user_signup
    );
    assert!(!tenant_b.lock().unwrap().config().disabled_user_signup);
    assert!(
        !registry
            .tenant_metadata("demo-app", "tenant-b")
            .unwrap()
            .disabled_user_signup
    );
}

#[test]
fn existing_tenant_config_override_updates_metadata_and_store_atomically() {
    let registry = AuthRegistry::new("demo-app", Arc::new(Mutex::new(store("demo-app"))));
    let tenant = registry.ensure_tenant("demo-app", "tenant-a").unwrap();
    tenant.lock().unwrap().set_config(ProjectAuthConfig {
        allow_duplicate_emails: true,
        ..ProjectAuthConfig::default()
    });

    assert!(registry.register_tenant_config_override(
        "demo-app",
        "tenant-a",
        AuthNamespaceConfigPatch {
            disabled_user_deletion: Some(true),
            ..AuthNamespaceConfigPatch::default()
        },
    ));
    assert!(
        registry
            .tenant_metadata("demo-app", "tenant-a")
            .unwrap()
            .disabled_user_deletion
    );
    let config = tenant.lock().unwrap().config();
    assert!(config.disabled_user_deletion);
    assert!(config.allow_duplicate_emails);
}

#[test]
fn empty_or_invalid_config_overrides_do_not_create_namespaces() {
    let registry = AuthRegistry::new("demo-app", Arc::new(Mutex::new(store("demo-app"))));
    assert!(!registry
        .register_project_config_override("future-project", AuthNamespaceConfigPatch::default(),));
    assert!(!registry.register_project_config_override(
        "bad/project",
        AuthNamespaceConfigPatch {
            disabled_user_signup: Some(true),
            ..AuthNamespaceConfigPatch::default()
        },
    ));
    assert!(!registry.register_tenant_config_override(
        "demo-app",
        "",
        AuthNamespaceConfigPatch {
            disabled_user_signup: Some(true),
            ..AuthNamespaceConfigPatch::default()
        },
    ));
    assert!(registry.store_for("future-project").is_none());
    assert!(registry.tenant_store("demo-app", "tenant-a").is_none());
}

#[test]
fn project_patch_preserves_tenant_permissions_and_admin_bypass() {
    let registry = AuthRegistry::new("demo-app", Arc::new(Mutex::new(store("demo-app"))));
    let tenant = registry.ensure_tenant("demo-app", "tenant-a").unwrap();

    registry
        .patch_tenant(
            "demo-app",
            "tenant-a",
            TenantMetadataPatch {
                disabled_user_signup: Some(true),
                disabled_user_deletion: Some(true),
                ..TenantMetadataPatch::default()
            },
        )
        .expect("tenant permission patch succeeds");

    let existing = tenant
        .lock()
        .unwrap()
        .create_user_as(
            AuthPrincipal::Admin,
            NewUser::email("existing@example.test"),
            NOW,
        )
        .expect("admin can create a tenant user");
    let _ = tenant.lock().unwrap().take_user_events();

    registry
        .patch_project_config(
            "demo-app",
            ProjectAuthConfigPatch {
                allow_duplicate_emails: Some(true),
                ..ProjectAuthConfigPatch::default()
            },
        )
        .expect("unrelated project patch succeeds");

    let config = tenant.lock().unwrap().config();
    assert!(config.allow_duplicate_emails);
    assert!(config.disabled_user_signup);
    assert!(config.disabled_user_deletion);
    let metadata = registry
        .tenant_metadata("demo-app", "tenant-a")
        .expect("tenant metadata remains published");
    assert!(metadata.disabled_user_signup);
    assert!(metadata.disabled_user_deletion);

    let mut tenant = tenant.lock().unwrap();
    assert_eq!(
        tenant.create_user_as(
            AuthPrincipal::EndUser,
            NewUser::email("new@example.test"),
            NOW,
        ),
        Err(AuthError::UserSignupDisabled)
    );
    assert!(tenant.user_by_email("new@example.test").is_none());
    assert_eq!(
        tenant.delete_user_by_id_as(AuthPrincipal::EndUser, existing.as_str()),
        Err(AuthError::UserDeletionDisabled)
    );
    assert!(tenant.user_by_id(existing.as_str()).is_some());
    assert!(tenant
        .delete_user_by_id_as(AuthPrincipal::Admin, existing.as_str())
        .is_ok());
}
