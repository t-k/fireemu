//! Tenant stores are isolated namespaces whose tokens retain the parent project audience.

use std::sync::{Arc, Mutex};

use fireemu_core_auth::jwt::{encode_unsigned, verify_id_token_decoded, JwtError};
use fireemu_core_auth::mfa::TotpPolicy;
use fireemu_core_auth::store::{AuthRegistry, AuthStore, NewUser, TenantMetadataPatch};
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
