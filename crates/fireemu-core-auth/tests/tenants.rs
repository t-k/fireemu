//! Tenant stores are isolated namespaces whose tokens retain the parent project audience.

use std::sync::{Arc, Mutex};

use fireemu_core_auth::jwt::{encode_unsigned, verify_id_token_decoded, JwtError};
use fireemu_core_auth::mfa::{TotpFactor, TotpPolicy, TotpSecret};
use fireemu_core_auth::store::{
    AuthRegistry, AuthStore, NewUser, ProjectAuthConfigPatch, TenantMetadata, TenantMetadataPatch,
};
use fireemu_core_types::determinism::SplitMix64;
use fireemu_core_types::time::LogicalInstant;

const NOW: LogicalInstant = LogicalInstant::from_unix_seconds(1_788_004_860);

fn store(project: &str, seed: u64) -> AuthStore {
    AuthStore::new(project, SplitMix64::new(seed), TotpPolicy::default())
}

#[test]
fn tenant_namespaces_isolate_users_and_bind_tokens_to_the_tenant() {
    let default = Arc::new(Mutex::new(store("demo-app", 1)));
    let registry = AuthRegistry::new("demo-app", default.clone());
    let alpha = registry.ensure_tenant("demo-app", "alpha").unwrap();
    let beta = registry.ensure_tenant("demo-app", "beta").unwrap();

    let alpha_uid = alpha
        .lock()
        .unwrap()
        .create_user_with_id(NewUser::email("same@example.com"), Some("same-uid"), NOW)
        .unwrap();
    beta.lock()
        .unwrap()
        .create_user_with_id(NewUser::email("same@example.com"), Some("same-uid"), NOW)
        .unwrap();
    default
        .lock()
        .unwrap()
        .create_user_with_id(NewUser::email("same@example.com"), Some("same-uid"), NOW)
        .unwrap();

    let claims = alpha
        .lock()
        .unwrap()
        .id_token_claims(&alpha_uid, None, NOW)
        .unwrap();
    assert_eq!(claims.aud, "demo-app");
    assert_eq!(claims.firebase.tenant.as_deref(), Some("alpha"));
    let token = encode_unsigned(&claims);
    assert!(verify_id_token_decoded(&token, &alpha.lock().unwrap(), NOW).is_ok());
    assert!(matches!(
        verify_id_token_decoded(&token, &beta.lock().unwrap(), NOW),
        Err(JwtError::WrongTenant { .. })
    ));
    assert!(matches!(
        verify_id_token_decoded(&token, &default.lock().unwrap(), NOW),
        Err(JwtError::WrongTenant { .. })
    ));
}

#[test]
fn tenant_ids_cannot_contain_export_path_separators() {
    let default = Arc::new(Mutex::new(store("demo-app", 1)));
    let registry = AuthRegistry::new("demo-app", default);

    assert!(registry
        .ensure_tenant("demo-app", "forward/slash")
        .is_none());
    assert!(registry.ensure_tenant("demo-app", "back\\slash").is_none());
}

#[test]
fn implicitly_created_tenants_enable_each_supported_sign_in_policy_by_default() {
    let default = Arc::new(Mutex::new(store("demo-app", 1)));
    let registry = AuthRegistry::new("demo-app", default);

    registry.ensure_tenant("demo-app", "customer").unwrap();

    let metadata = registry.tenant_metadata("demo-app", "customer").unwrap();
    assert!(metadata.allow_password_signup);
    assert!(metadata.enable_email_link_signin);
    assert!(metadata.enable_anonymous_user);
}

#[test]
fn rejected_tenant_creation_does_not_consume_the_next_generated_id() {
    let default = Arc::new(Mutex::new(store("demo-app", 1)));
    let registry = AuthRegistry::new("demo-app", default);

    assert!(registry
        .create_tenant("unknown-project", TenantMetadata::default())
        .is_none());
    assert_eq!(
        registry.create_tenant("demo-app", TenantMetadata::default()),
        Some("fireemu-00000000000000000001".to_owned())
    );
}

#[test]
fn generated_tenant_ids_skip_existing_implicit_namespaces_without_overwriting_them() {
    let default = Arc::new(Mutex::new(store("demo-app", 1)));
    let registry = AuthRegistry::new("demo-app", default);
    let first = "fireemu-00000000000000000001";
    registry.ensure_tenant("demo-app", first).unwrap();

    let created = registry
        .create_tenant(
            "demo-app",
            TenantMetadata {
                disable_auth: true,
                ..TenantMetadata::default()
            },
        )
        .unwrap();

    assert_eq!(created, "fireemu-00000000000000000002");
    let implicit = registry.tenant_metadata("demo-app", first).unwrap();
    assert!(implicit.allow_password_signup);
    assert!(implicit.enable_email_link_signin);
    assert!(implicit.enable_anonymous_user);
    assert!(!implicit.disable_auth);
    assert!(
        registry
            .tenant_metadata("demo-app", &created)
            .unwrap()
            .disable_auth
    );
}

#[test]
fn concurrent_tenant_patches_compose_without_reverting_security_fields() {
    let default = Arc::new(Mutex::new(store("demo-app", 1)));
    let registry = Arc::new(AuthRegistry::new("demo-app", default));
    registry.ensure_tenant("demo-app", "customer").unwrap();
    let barrier = Arc::new(std::sync::Barrier::new(3));

    let display_registry = registry.clone();
    let display_barrier = barrier.clone();
    let display = std::thread::spawn(move || {
        display_barrier.wait();
        display_registry.patch_tenant(
            "demo-app",
            "customer",
            TenantMetadataPatch {
                display_name: Some(Some("Customer".to_owned())),
                ..TenantMetadataPatch::default()
            },
        )
    });
    let disable_registry = registry.clone();
    let disable_barrier = barrier.clone();
    let disable = std::thread::spawn(move || {
        disable_barrier.wait();
        disable_registry.patch_tenant(
            "demo-app",
            "customer",
            TenantMetadataPatch {
                disable_auth: Some(true),
                ..TenantMetadataPatch::default()
            },
        )
    });
    barrier.wait();
    display.join().unwrap().unwrap();
    disable.join().unwrap().unwrap();

    let metadata = registry.tenant_metadata("demo-app", "customer").unwrap();
    assert_eq!(metadata.display_name.as_deref(), Some("Customer"));
    assert!(metadata.disable_auth);
}

/// `TENRST-2`: a snapshot restore locks every tenant store before its first change, so a
/// poisoned tenant store refuses the restore and leaves every tenant as it was.
#[test]
fn a_tenant_restore_with_a_poisoned_store_changes_nothing() {
    let default = Arc::new(Mutex::new(store("demo-app", 1)));
    let registry = AuthRegistry::new("demo-app", default);
    registry.ensure_tenant("demo-app", "kept").unwrap();
    let snapshot = registry.capture_tenants_snapshot("demo-app").unwrap();
    let added = registry.ensure_tenant("demo-app", "added").unwrap();
    added
        .lock()
        .unwrap()
        .create_user(NewUser::email("added@example.com"), NOW)
        .unwrap();
    let poisoned = registry.tenant_store("demo-app", "kept").unwrap();
    let _ = std::thread::spawn(move || {
        let _guard = poisoned.lock().unwrap();
        panic!("poison the tenant store");
    })
    .join();

    assert!(registry
        .restore_tenants_snapshot("demo-app", &snapshot)
        .is_err());
    assert_eq!(registry.tenants("demo-app"), ["added", "kept"]);
    assert_eq!(added.lock().unwrap().user_count(), 1);
}

/// A project snapshot includes only its own tenant namespaces, even when another registered
/// project has tenants in the same registry.
#[test]
fn a_tenant_snapshot_does_not_capture_another_projects_tenants() {
    let registry = AuthRegistry::new("demo-app", Arc::new(Mutex::new(store("demo-app", 1))));
    assert!(registry.register("other-app", store("other-app", 2)));
    registry.ensure_tenant("demo-app", "kept").unwrap();
    registry.ensure_tenant("other-app", "foreign").unwrap();
    registry
        .patch_tenant(
            "other-app",
            "foreign",
            TenantMetadataPatch {
                allow_duplicate_emails: Some(true),
                ..TenantMetadataPatch::default()
            },
        )
        .unwrap();

    let snapshot = registry.capture_tenants_snapshot("demo-app").unwrap();
    registry.ensure_tenant("demo-app", "added").unwrap();
    registry
        .restore_tenants_snapshot("demo-app", &snapshot)
        .unwrap();

    assert_eq!(registry.tenants("demo-app"), ["kept"]);
    assert_eq!(registry.tenants("other-app"), ["foreign"]);
    assert!(registry.tenant_metadata("other-app", "foreign").is_some());
    registry
        .patch_project_config(
            "other-app",
            ProjectAuthConfigPatch {
                allow_duplicate_emails: Some(false),
                ..ProjectAuthConfigPatch::default()
            },
        )
        .unwrap();
    assert!(
        registry
            .tenant_store("other-app", "foreign")
            .unwrap()
            .lock()
            .unwrap()
            .config()
            .allow_duplicate_emails
    );
}

/// A session restore recovers captured tenant users and settings, recreates a deleted tenant,
/// and removes a namespace that was published after the capture.
#[test]
fn a_tenant_snapshot_restores_membership_users_and_settings() {
    let registry = AuthRegistry::new("demo-app", Arc::new(Mutex::new(store("demo-app", 1))));
    let kept = registry.ensure_tenant("demo-app", "kept").unwrap();
    let deleted = registry.ensure_tenant("demo-app", "deleted").unwrap();
    for (handle, uid) in [(&kept, "kept-user"), (&deleted, "deleted-user")] {
        let email = format!("{uid}@example.com");
        handle
            .lock()
            .unwrap()
            .create_user_with_id(NewUser::email(&email), Some(uid), NOW)
            .unwrap();
    }
    registry
        .patch_tenant(
            "demo-app",
            "kept",
            TenantMetadataPatch {
                display_name: Some(Some("Before capture".to_owned())),
                ..TenantMetadataPatch::default()
            },
        )
        .unwrap();
    let snapshot = registry.capture_tenants_snapshot("demo-app").unwrap();

    kept.lock()
        .unwrap()
        .create_user_with_id(NewUser::email("later@example.com"), Some("later"), NOW)
        .unwrap();
    registry
        .patch_tenant(
            "demo-app",
            "kept",
            TenantMetadataPatch {
                display_name: Some(Some("After capture".to_owned())),
                disable_auth: Some(true),
                ..TenantMetadataPatch::default()
            },
        )
        .unwrap();
    assert!(registry.delete_tenant("demo-app", "deleted"));
    let added = registry.ensure_tenant("demo-app", "added").unwrap();
    added
        .lock()
        .unwrap()
        .create_user_with_id(NewUser::email("added@example.com"), Some("added-user"), NOW)
        .unwrap();

    registry
        .restore_tenants_snapshot("demo-app", &snapshot)
        .unwrap();
    assert_eq!(registry.tenants("demo-app"), ["deleted", "kept"]);
    assert!(Arc::ptr_eq(
        &kept,
        &registry.tenant_store("demo-app", "kept").unwrap()
    ));
    let kept = kept.lock().unwrap();
    assert!(kept.user_by_id("kept-user").is_some());
    assert!(kept.user_by_id("later").is_none());
    drop(kept);
    let recreated = registry.tenant_store("demo-app", "deleted").unwrap();
    assert!(recreated
        .lock()
        .unwrap()
        .user_by_id("deleted-user")
        .is_some());
    assert!(registry.tenant_store("demo-app", "added").is_none());
    assert_eq!(added.lock().unwrap().user_count(), 0);
    let metadata = registry.tenant_metadata("demo-app", "kept").unwrap();
    assert_eq!(metadata.display_name.as_deref(), Some("Before capture"));
    assert!(!metadata.disable_auth);
}

/// A session snapshot cannot retain a TOTP secret. Restoring an enrolled factor after its live
/// secret disappeared reports every factor it had to drop, including a recreated tenant.
#[test]
fn a_tenant_snapshot_reports_all_totp_factors_it_cannot_rebind() {
    let registry = AuthRegistry::new("demo-app", Arc::new(Mutex::new(store("demo-app", 1))));
    let live = registry.ensure_tenant("demo-app", "live").unwrap();
    let recreated = registry.ensure_tenant("demo-app", "recreated").unwrap();
    for (handle, name) in [(&live, "live"), (&recreated, "recreated")] {
        let mut store = handle.lock().unwrap();
        let uid = store
            .create_user_with_id(NewUser::email("totp@example.com"), Some(name), NOW)
            .unwrap();
        store
            .user_mut(&uid)
            .unwrap()
            .mfa
            .import_factors(
                vec![TotpFactor {
                    mfa_enrollment_id: "factor".to_owned(),
                    display_name: None,
                    secret: TotpSecret::new(vec![1; 20]),
                    enrolled_at: NOW,
                    last_accepted_step: None,
                }],
                vec![],
            )
            .unwrap();
    }
    let snapshot = registry.capture_tenants_snapshot("demo-app").unwrap();
    assert!(snapshot.holds_no_totp_secret());
    let uid = live
        .lock()
        .unwrap()
        .user_by_id("live")
        .unwrap()
        .local_id
        .clone();
    assert!(live
        .lock()
        .unwrap()
        .unenroll_factor(&uid, "factor")
        .unwrap());
    assert!(registry.delete_tenant("demo-app", "recreated"));

    let report = registry
        .restore_tenants_snapshot("demo-app", &snapshot)
        .unwrap();
    assert_eq!(report.totp_factors_dropped, 2);
    for name in ["live", "recreated"] {
        let store = registry.tenant_store("demo-app", name).unwrap();
        assert!(store
            .lock()
            .unwrap()
            .user_by_id(name)
            .unwrap()
            .mfa
            .is_empty());
    }
}

/// Rolling a project's tenants back preserves the other project's published tenant metadata.
#[test]
fn a_tenant_rollback_preserves_another_projects_tenants() {
    let registry = AuthRegistry::new("demo-app", Arc::new(Mutex::new(store("demo-app", 1))));
    assert!(registry.register("other-app", store("other-app", 2)));
    registry.ensure_tenant("demo-app", "kept").unwrap();
    registry.ensure_tenant("other-app", "foreign").unwrap();
    registry
        .patch_tenant(
            "other-app",
            "foreign",
            TenantMetadataPatch {
                allow_duplicate_emails: Some(true),
                ..TenantMetadataPatch::default()
            },
        )
        .unwrap();

    let rollback = registry.capture_tenants_rollback("demo-app").unwrap();
    registry.ensure_tenant("demo-app", "added").unwrap();
    registry.rollback_tenants("demo-app", &rollback).unwrap();

    assert_eq!(registry.tenants("demo-app"), ["kept"]);
    assert_eq!(registry.tenants("other-app"), ["foreign"]);
    assert!(registry.tenant_metadata("other-app", "foreign").is_some());
    registry
        .patch_project_config(
            "other-app",
            ProjectAuthConfigPatch {
                allow_duplicate_emails: Some(false),
                ..ProjectAuthConfigPatch::default()
            },
        )
        .unwrap();
    assert!(
        registry
            .tenant_store("other-app", "foreign")
            .unwrap()
            .lock()
            .unwrap()
            .config()
            .allow_duplicate_emails
    );
}

/// A failed session transition puts both previously published handles and their contents back.
#[test]
fn a_tenant_rollback_restores_handles_users_and_settings() {
    let registry = AuthRegistry::new("demo-app", Arc::new(Mutex::new(store("demo-app", 1))));
    let kept = registry.ensure_tenant("demo-app", "kept").unwrap();
    let deleted = registry.ensure_tenant("demo-app", "deleted").unwrap();
    kept.lock()
        .unwrap()
        .create_user_with_id(NewUser::email("kept@example.com"), Some("kept-user"), NOW)
        .unwrap();
    deleted
        .lock()
        .unwrap()
        .create_user_with_id(
            NewUser::email("deleted@example.com"),
            Some("deleted-user"),
            NOW,
        )
        .unwrap();
    let rollback = registry.capture_tenants_rollback("demo-app").unwrap();

    kept.lock()
        .unwrap()
        .create_user_with_id(NewUser::email("later@example.com"), Some("later"), NOW)
        .unwrap();
    registry
        .patch_tenant(
            "demo-app",
            "kept",
            TenantMetadataPatch {
                disable_auth: Some(true),
                ..TenantMetadataPatch::default()
            },
        )
        .unwrap();
    assert!(registry.delete_tenant("demo-app", "deleted"));
    let added = registry.ensure_tenant("demo-app", "added").unwrap();
    added
        .lock()
        .unwrap()
        .create_user_with_id(NewUser::email("added@example.com"), Some("added-user"), NOW)
        .unwrap();

    registry.rollback_tenants("demo-app", &rollback).unwrap();
    assert_eq!(registry.tenants("demo-app"), ["deleted", "kept"]);
    assert!(Arc::ptr_eq(
        &kept,
        &registry.tenant_store("demo-app", "kept").unwrap()
    ));
    assert!(Arc::ptr_eq(
        &deleted,
        &registry.tenant_store("demo-app", "deleted").unwrap()
    ));
    assert!(kept.lock().unwrap().user_by_id("kept-user").is_some());
    assert!(kept.lock().unwrap().user_by_id("later").is_none());
    assert!(deleted.lock().unwrap().user_by_id("deleted-user").is_some());
    assert!(
        !registry
            .tenant_metadata("demo-app", "kept")
            .unwrap()
            .disable_auth
    );
    assert!(registry.tenant_store("demo-app", "added").is_none());
    assert_eq!(added.lock().unwrap().user_count(), 0);
}

/// A tenant created with a display name of the documented form (4-20 letters, digits and
/// hyphens, beginning with a letter) is named as production names it: the display name, a
/// hyphen and five characters of `[a-z0-9]` (FS-RULES sandbox recording 2026-09-25: `fsr-tenant`
/// gave `fsr-tenant-` and five such characters). The suffix is reproducible for a run.
#[test]
fn a_tenant_with_a_display_name_is_named_as_production_names_it() {
    let create = |registry: &AuthRegistry, name: Option<&str>| {
        registry
            .create_tenant(
                "demo-app",
                TenantMetadata {
                    display_name: name.map(str::to_owned),
                    ..TenantMetadata::default()
                },
            )
            .unwrap()
    };
    let shaped = |id: &str, name: &str| {
        id.strip_prefix(name)
            .and_then(|rest| rest.strip_prefix('-'))
            .is_some_and(|suffix| {
                suffix.len() == 5
                    && suffix
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
            })
    };
    let registry = AuthRegistry::new("demo-app", Arc::new(Mutex::new(store("demo-app", 1))));
    let first = create(&registry, Some("fsr-tenant"));
    let second = create(&registry, Some("fsr-tenant"));
    assert!(shaped(&first, "fsr-tenant"), "{first}");
    assert!(shaped(&second, "fsr-tenant"), "{second}");
    assert_ne!(first, second);
    let again = AuthRegistry::new("demo-app", Arc::new(Mutex::new(store("demo-app", 1))));
    assert_eq!(create(&again, Some("fsr-tenant")), first, "reproducible");
    assert_eq!(
        [first.as_str(), second.as_str()],
        ["fsr-tenant-bpkmw", "fsr-tenant-zr6h1"]
    );
    // Outside the documented form (production refuses it, unobserved) and without a display
    // name, the tenant keeps fireemu's generated name.
    assert_eq!(
        create(&registry, Some("ab")),
        "fireemu-00000000000000000003"
    );
    assert_eq!(
        create(&registry, Some("fsr-tenant")),
        "fsr-tenant-12xom",
        "sequence 4 has a seed bit that the earlier cases do not exercise"
    );
    assert_eq!(create(&registry, None), "fireemu-00000000000000000005");
}

/// `TENRST-2`: a capture waits for the project operation gate, so it never copies the tenant
/// namespaces halfway through a tenant creation or configuration change (mutation survivor of
/// `project_operation_gate`, 2026-09-25).
#[test]
fn a_tenant_capture_waits_for_the_project_operation_gate() {
    use std::time::Duration;

    let registry = Arc::new(AuthRegistry::new(
        "demo-app",
        Arc::new(Mutex::new(store("demo-app", 1))),
    ));
    registry.ensure_tenant("demo-app", "kept").unwrap();
    let gate = registry.operation_gate("demo-app", None).unwrap();
    let held = gate.lock().unwrap();
    let (sender, receiver) = std::sync::mpsc::channel();
    let capturing = registry.clone();
    let worker = std::thread::spawn(move || {
        sender
            .send(capturing.capture_tenants_snapshot("demo-app").is_ok())
            .unwrap();
    });
    assert!(
        receiver.recv_timeout(Duration::from_millis(200)).is_err(),
        "the capture must wait for the gate"
    );
    drop(held);
    assert!(receiver.recv_timeout(Duration::from_secs(5)).unwrap());
    worker.join().unwrap();
}
