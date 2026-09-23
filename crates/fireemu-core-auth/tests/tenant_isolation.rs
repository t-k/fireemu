//! Registry-level tenant isolation (TP-AUTH-E-01, parent AUTH-TENANT-BLOCKING): credentials
//! issued by one tenant store are refused by the sibling tenant and the parent project
//! without touching either namespace; project configuration follows into tenants only
//! where the tenant did not override it and the password policy never follows; provider
//! configurations are per namespace; deleting a tenant detaches its store, metadata and
//! provider configurations while the sibling tenant and the project keep their state.
//!
//! These are the local invariants behind the REST matrix in
//! `fireemu-adapter-http/tests/auth_tenant_isolation.rs`; they are not production evidence.

use std::sync::{Arc, Mutex};

use fireemu_core_auth::jwt::{encode_unsigned, verify_id_token_decoded, JwtError};
use fireemu_core_auth::mfa::TotpPolicy;
use fireemu_core_auth::password_policy::{EnforcementState, PasswordPolicy};
use fireemu_core_auth::store::{
    AuthError, AuthRegistry, AuthStore, NewUser, OAuthResponseType, OidcProviderConfig,
    ProjectAuthConfigPatch, RefreshTokenStoreMatch, TenantMetadata, TenantMetadataPatch,
};
use fireemu_core_types::determinism::SplitMix64;
use fireemu_core_types::time::LogicalInstant;

const NOW: LogicalInstant = LogicalInstant::from_unix_seconds(1_788_004_860);
const PROJECT: &str = "demo-app";

fn registry() -> (AuthRegistry, Arc<Mutex<AuthStore>>) {
    let default = Arc::new(Mutex::new(AuthStore::new(
        PROJECT,
        SplitMix64::new(1),
        TotpPolicy::default(),
    )));
    (AuthRegistry::new(PROJECT, default.clone()), default)
}

fn two_tenants(registry: &AuthRegistry) -> (Arc<Mutex<AuthStore>>, Arc<Mutex<AuthStore>>) {
    (
        registry.ensure_tenant(PROJECT, "tenant-a").unwrap(),
        registry.ensure_tenant(PROJECT, "tenant-b").unwrap(),
    )
}

/// A password user plus an issued refresh token and an unsigned ID token in `store`.
fn session(store: &Arc<Mutex<AuthStore>>, email: &str) -> (String, String, String) {
    let mut store = store.lock().unwrap();
    let uid = store
        .create_user_with_password(NewUser::email(email), "hunter22", NOW)
        .unwrap();
    let refresh = store.issue_refresh_token(&uid, NOW).unwrap();
    let id_token = encode_unsigned(&store.id_token_claims(&uid, None, NOW).unwrap());
    (uid.as_str().to_owned(), refresh, id_token)
}

fn oidc(id: &str, client_id: &str) -> OidcProviderConfig {
    OidcProviderConfig {
        id: id.to_owned(),
        display_name: None,
        enabled: true,
        client_id: client_id.to_owned(),
        issuer: format!("https://issuer.{client_id}.example"),
        client_secret: None,
        response_type: OAuthResponseType {
            id_token: true,
            ..OAuthResponseType::default()
        },
    }
}

fn enforced_minimum(min_length: usize) -> PasswordPolicy {
    PasswordPolicy {
        enforcement_state: EnforcementState::Enforce,
        min_length,
        ..PasswordPolicy::default()
    }
}

#[test]
fn tenant_credentials_are_refused_by_the_sibling_and_the_parent_without_mutation() {
    let (registry, default) = registry();
    let (a, b) = two_tenants(&registry);
    let (uid_a, refresh_a, id_token_a) = session(&a, "same@example.com");
    let (uid_b, refresh_b, id_token_b) = session(&b, "same@example.com");
    let (uid_p, refresh_p, id_token_p) = session(&default, "same@example.com");

    // ID tokens: every foreign namespace reports the wrong tenant, the own namespace
    // verifies. The parent project token has no tenant claim and is refused by both tenants.
    for (token, own, foreign) in [
        (&id_token_a, &a, [&b, &default]),
        (&id_token_b, &b, [&a, &default]),
        (&id_token_p, &default, [&a, &b]),
    ] {
        assert!(verify_id_token_decoded(token, &own.lock().unwrap(), NOW).is_ok());
        for store in foreign {
            assert!(matches!(
                verify_id_token_decoded(token, &store.lock().unwrap(), NOW),
                Err(JwtError::WrongTenant { .. })
            ));
        }
    }

    // Refresh tokens: only the issuing store owns and redeems them; the registry routes each
    // token to exactly that store.
    for (token, own, foreign, uid) in [
        (&refresh_a, &a, [&b, &default], &uid_a),
        (&refresh_b, &b, [&a, &default], &uid_b),
        (&refresh_p, &default, [&a, &b], &uid_p),
    ] {
        for store in foreign {
            let store = store.lock().unwrap();
            assert!(!store.owns_refresh_token(token));
            assert!(matches!(
                store.redeem_refresh_token(token),
                Err(AuthError::InvalidRefreshToken)
            ));
        }
        let own_store = own.lock().unwrap();
        assert!(own_store.owns_refresh_token(token));
        assert_eq!(own_store.redeem_refresh_token(token).unwrap().as_str(), uid);
        drop(own_store);
        match registry.store_for_refresh_token(token) {
            RefreshTokenStoreMatch::Unique(store) => assert!(Arc::ptr_eq(&store, own)),
            other => panic!("expected a unique namespace for {token}: {other:?}"),
        }
    }

    // Nothing moved: each namespace still holds exactly its one user under its own UID.
    for (store, uid) in [(&a, &uid_a), (&b, &uid_b), (&default, &uid_p)] {
        let store = store.lock().unwrap();
        assert_eq!(store.user_count(), 1);
        assert!(store.user_by_id(uid).is_some());
        assert!(store.user_by_email("same@example.com").is_some());
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn project_config_follows_into_tenants_unless_overridden_and_password_policy_never_follows() {
    let (registry, default) = registry();
    let (overridden, untouched) = two_tenants(&registry);

    // Email privacy on the project reaches both tenants' stores and metadata.
    let patch = |value: bool| ProjectAuthConfigPatch {
        enable_improved_email_privacy: Some(value),
        ..ProjectAuthConfigPatch::default()
    };
    assert!(registry
        .patch_project_config(PROJECT, patch(true))
        .is_some());
    for store in [&overridden, &untouched] {
        assert!(store.lock().unwrap().config().enable_improved_email_privacy);
    }
    for tenant in ["tenant-a", "tenant-b"] {
        assert!(
            registry
                .tenant_metadata(PROJECT, tenant)
                .unwrap()
                .enable_improved_email_privacy
        );
    }

    // A tenant override pins the field; the next project PATCH moves only the other tenant.
    assert!(registry
        .patch_tenant(
            PROJECT,
            "tenant-a",
            TenantMetadataPatch {
                enable_improved_email_privacy: Some(false),
                ..TenantMetadataPatch::default()
            },
        )
        .is_some());
    assert!(
        !overridden
            .lock()
            .unwrap()
            .config()
            .enable_improved_email_privacy
    );
    assert!(registry
        .patch_project_config(PROJECT, patch(false))
        .is_some());
    assert!(registry
        .patch_project_config(PROJECT, patch(true))
        .is_some());
    assert!(
        !overridden
            .lock()
            .unwrap()
            .config()
            .enable_improved_email_privacy
    );
    assert!(
        untouched
            .lock()
            .unwrap()
            .config()
            .enable_improved_email_privacy
    );
    assert!(
        default
            .lock()
            .unwrap()
            .config()
            .enable_improved_email_privacy
    );
    assert!(
        !registry
            .tenant_metadata(PROJECT, "tenant-a")
            .unwrap()
            .enable_improved_email_privacy
    );
    assert!(
        registry
            .tenant_metadata(PROJECT, "tenant-b")
            .unwrap()
            .enable_improved_email_privacy
    );

    // The project password policy is not copied into an existing tenant, a later tenant or
    // a tenant created explicitly, and a tenant policy does not leak upward or sideways.
    assert!(registry.set_project_password_policy(PROJECT, enforced_minimum(8)));
    assert_eq!(default.lock().unwrap().password_policy().min_length, 8);
    let later = registry.ensure_tenant(PROJECT, "tenant-c").unwrap();
    let (explicit, _, explicit_policy) = registry
        .create_tenant_with_password_policy(
            PROJECT,
            TenantMetadata::default(),
            TenantMetadataPatch::default(),
            None,
        )
        .unwrap();
    let explicit_store = registry.tenant_store(PROJECT, &explicit).unwrap();
    for store in [&overridden, &untouched, &later, &explicit_store] {
        let store = store.lock().unwrap();
        assert_eq!(
            store.password_policy().enforcement_state,
            EnforcementState::Off
        );
        assert_eq!(
            store.password_policy().min_length,
            PasswordPolicy::default().min_length
        );
    }
    assert_eq!(explicit_policy, PasswordPolicy::default());
    assert!(registry.set_tenant_password_policy(PROJECT, "tenant-a", enforced_minimum(12)));
    assert_eq!(overridden.lock().unwrap().password_policy().min_length, 12);
    assert_eq!(
        untouched.lock().unwrap().password_policy().min_length,
        PasswordPolicy::default().min_length
    );
    assert_eq!(default.lock().unwrap().password_policy().min_length, 8);
    // The stores enforce what they project: registration obeys each namespace's own policy.
    assert!(matches!(
        overridden.lock().unwrap().create_user_with_password(
            NewUser::email("eleven@example.com"),
            "eleven-char",
            NOW
        ),
        Err(AuthError::PasswordPolicyViolation(_))
    ));
    assert!(untouched
        .lock()
        .unwrap()
        .create_user_with_password(NewUser::email("seven@example.com"), "seven77", NOW)
        .is_ok());
    assert!(matches!(
        default.lock().unwrap().create_user_with_password(
            NewUser::email("seven@example.com"),
            "seven77",
            NOW
        ),
        Err(AuthError::PasswordPolicyViolation(_))
    ));
}

#[test]
fn provider_configs_are_per_namespace_and_a_shared_id_names_independent_configs() {
    let (registry, default) = registry();
    let (a, b) = two_tenants(&registry);
    assert!(a.lock().unwrap().create_oidc_config(oidc("oidc.acme", "a")));

    for store in [&b, &default] {
        let store = store.lock().unwrap();
        assert!(store.oidc_config("oidc.acme").is_none());
        assert_eq!(store.oidc_configs().count(), 0);
    }
    assert!(b.lock().unwrap().create_oidc_config(oidc("oidc.acme", "b")));
    assert!(default
        .lock()
        .unwrap()
        .create_oidc_config(oidc("oidc.acme", "p")));
    assert!(a.lock().unwrap().delete_oidc_config("oidc.acme"));
    assert!(a.lock().unwrap().oidc_config("oidc.acme").is_none());
    assert_eq!(
        b.lock()
            .unwrap()
            .oidc_config("oidc.acme")
            .unwrap()
            .client_id,
        "b"
    );
    assert_eq!(
        default
            .lock()
            .unwrap()
            .oidc_config("oidc.acme")
            .unwrap()
            .client_id,
        "p"
    );
}

#[test]
fn deleting_a_tenant_detaches_its_namespace_and_keeps_the_sibling_and_the_project() {
    let (registry, default) = registry();
    let (a, b) = two_tenants(&registry);
    let (_, refresh_a, _) = session(&a, "a@example.com");
    let (uid_b, refresh_b, id_token_b) = session(&b, "b@example.com");
    let (uid_p, refresh_p, id_token_p) = session(&default, "p@example.com");
    assert!(a.lock().unwrap().create_oidc_config(oidc("oidc.acme", "a")));
    let before_b = b.lock().unwrap().user_count();
    let before_p = default.lock().unwrap().user_count();

    assert!(registry.delete_tenant(PROJECT, "tenant-a"));
    assert!(!registry.delete_tenant(PROJECT, "tenant-a"));
    assert!(!registry.delete_tenant(PROJECT, "never-existed"));

    // The namespace is unreachable through every registry accessor.
    assert!(registry.tenant_store(PROJECT, "tenant-a").is_none());
    assert!(registry.tenant_metadata(PROJECT, "tenant-a").is_none());
    assert_eq!(registry.tenants(PROJECT), vec!["tenant-b".to_owned()]);
    assert!(
        registry.with_existing_tenant_metadata(PROJECT, "tenant-a", |metadata| metadata.is_none())
    );
    assert!(matches!(
        registry.store_for_refresh_token(&refresh_a),
        RefreshTokenStoreMatch::NotFound
    ));
    for store in [&b, &default] {
        let store = store.lock().unwrap();
        assert!(!store.owns_refresh_token(&refresh_a));
        assert!(matches!(
            store.redeem_refresh_token(&refresh_a),
            Err(AuthError::InvalidRefreshToken)
        ));
        assert!(store.oidc_config("oidc.acme").is_none());
    }

    // The sibling tenant and the project keep their users and their credentials.
    assert_eq!(b.lock().unwrap().user_count(), before_b);
    assert_eq!(default.lock().unwrap().user_count(), before_p);
    assert!(Arc::ptr_eq(
        &registry.tenant_store(PROJECT, "tenant-b").unwrap(),
        &b
    ));
    assert!(verify_id_token_decoded(&id_token_b, &b.lock().unwrap(), NOW).is_ok());
    assert!(verify_id_token_decoded(&id_token_p, &default.lock().unwrap(), NOW).is_ok());
    assert_eq!(
        b.lock()
            .unwrap()
            .redeem_refresh_token(&refresh_b)
            .unwrap()
            .as_str(),
        uid_b
    );
    assert_eq!(
        default
            .lock()
            .unwrap()
            .redeem_refresh_token(&refresh_p)
            .unwrap()
            .as_str(),
        uid_p
    );

    // A namespace re-created under the same ID is empty and does not revive the old token.
    let recreated = registry.ensure_tenant(PROJECT, "tenant-a").unwrap();
    assert!(!Arc::ptr_eq(&recreated, &a));
    let recreated = recreated.lock().unwrap();
    assert_eq!(recreated.user_count(), 0);
    assert!(recreated.oidc_config("oidc.acme").is_none());
    assert!(!recreated.owns_refresh_token(&refresh_a));
    assert!(matches!(
        recreated.redeem_refresh_token(&refresh_a),
        Err(AuthError::InvalidRefreshToken)
    ));
}
