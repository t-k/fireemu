//! A tenant created with an id its caller chose (a tenant declared in the configuration file):
//! the id is kept, an id already in use is refused, and a name that was deleted or wiped by a
//! reset can be used again.

use std::sync::{Arc, Mutex};

use fireemu_core_auth::config_members::ALLOW_TENANTS;
use fireemu_core_auth::mfa::TotpPolicy;
use fireemu_core_auth::store::{AuthRegistry, AuthStore, TenantMetadata, TenantMetadataPatch};
use fireemu_core_types::determinism::SplitMix64;

fn registry() -> (Arc<Mutex<AuthStore>>, AuthRegistry) {
    let parent = Arc::new(Mutex::new(AuthStore::new(
        "demo-app",
        SplitMix64::new(1),
        TotpPolicy::default(),
    )));
    let registry = AuthRegistry::new("demo-app", parent.clone());
    (parent, registry)
}

fn named(display_name: &str) -> TenantMetadata {
    TenantMetadata {
        display_name: Some(display_name.to_owned()),
        allow_password_signup: true,
        ..TenantMetadata::default()
    }
}

fn create(registry: &AuthRegistry, id: &str, display_name: &str) -> bool {
    registry
        .create_tenant_with_id(
            "demo-app",
            id,
            named(display_name),
            TenantMetadataPatch::default(),
            None,
        )
        .is_some()
}

#[test]
fn a_chosen_id_is_the_tenants_id() {
    let (_, registry) = registry();
    assert!(create(&registry, "acme-x7k2q", "acme"));
    assert!(registry.tenant_store("demo-app", "acme-x7k2q").is_some());
    assert_eq!(registry.tenants("demo-app"), ["acme-x7k2q"]);
    let metadata = registry.tenant_metadata("demo-app", "acme-x7k2q").unwrap();
    assert_eq!(metadata.display_name.as_deref(), Some("acme"));
    assert!(metadata.allow_password_signup);
}

#[test]
fn an_id_in_use_is_refused_and_the_tenant_is_not_replaced() {
    let (_, registry) = registry();
    assert!(create(&registry, "acme-x7k2q", "acme"));
    assert!(!create(&registry, "acme-x7k2q", "other"));
    let metadata = registry.tenant_metadata("demo-app", "acme-x7k2q").unwrap();
    assert_eq!(metadata.display_name.as_deref(), Some("acme"));
    assert_eq!(registry.tenants("demo-app"), ["acme-x7k2q"]);
}

#[test]
fn a_name_that_cannot_address_a_tenant_is_refused() {
    let (_, registry) = registry();
    for id in ["", "a/b", "a\\b"] {
        assert!(!create(&registry, id, "acme"), "{id:?}");
    }
    assert!(registry.tenants("demo-app").is_empty());
}

#[test]
fn an_unknown_project_is_refused() {
    let (_, registry) = registry();
    assert!(registry
        .create_tenant_with_id(
            "no-such-project",
            "acme-x7k2q",
            named("acme"),
            TenantMetadataPatch::default(),
            None
        )
        .is_none());
}

#[test]
fn a_deleted_id_can_be_created_again_and_is_no_longer_deleted() {
    let (_, registry) = registry();
    assert!(create(&registry, "acme-x7k2q", "acme"));
    assert!(registry.delete_tenant("demo-app", "acme-x7k2q"));
    assert!(registry.tenant_deleted("demo-app", "acme-x7k2q"));
    assert!(create(&registry, "acme-x7k2q", "acme"));
    assert!(!registry.tenant_deleted("demo-app", "acme-x7k2q"));
    assert!(registry.tenant_store("demo-app", "acme-x7k2q").is_some());
}

#[test]
fn a_reset_removes_the_tenant_and_its_id_can_be_created_again() {
    let (_, registry) = registry();
    assert!(create(&registry, "acme-x7k2q", "acme"));
    let prepared = registry.prepare_default_scope_reset().unwrap();
    registry.apply_default_scope_reset(&prepared).unwrap();
    assert!(registry.tenant_store("demo-app", "acme-x7k2q").is_none());
    assert!(create(&registry, "acme-x7k2q", "acme"));
    assert!(registry.tenant_store("demo-app", "acme-x7k2q").is_some());
}

#[test]
fn generated_ids_do_not_collide_with_a_chosen_one() {
    let (_, registry) = registry();
    assert!(create(&registry, "fireemu-00000000000000000001", "x"));
    let (generated, _, _) = registry
        .create_tenant_with_password_policy(
            "demo-app",
            TenantMetadata::default(),
            TenantMetadataPatch::default(),
            None,
        )
        .unwrap();
    assert_ne!(generated, "fireemu-00000000000000000001");
    assert_eq!(registry.tenants("demo-app").len(), 2);
}

#[test]
fn a_guarded_chosen_id_needs_multi_tenancy_on() {
    let (parent, registry) = registry();
    let guarded = |id: &str| {
        registry
            .create_tenant_with_id_guarded(
                "demo-app",
                id,
                named("acme"),
                TenantMetadataPatch::default(),
                None,
            )
            .is_some()
    };
    assert!(!guarded("acme-x7k2q"));
    {
        let mut store = parent.lock().unwrap();
        let mut members = store.stored_config_members().clone();
        members.set(ALLOW_TENANTS, Some("true".to_owned()));
        store.set_stored_config_members(members);
    }
    assert!(guarded("acme-x7k2q"));
}
