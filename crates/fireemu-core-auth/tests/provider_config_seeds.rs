//! Provider declarations are local control-plane state, independent of Admin changes.
use fireemu_core_auth::mfa::TotpPolicy;
use fireemu_core_auth::store::{
    AuthRegistry, AuthSnapshot, AuthStore, InboundSamlProviderConfig, OAuthResponseType,
    OidcProviderConfig, ProviderConfigSeeds,
};
use fireemu_core_types::determinism::SplitMix64;
use std::sync::{Arc, Mutex};
fn store(project: &str) -> AuthStore {
    AuthStore::new(project, SplitMix64::new(7), TotpPolicy::default())
}
fn oidc(id: &str) -> OidcProviderConfig {
    OidcProviderConfig {
        id: id.into(),
        display_name: None,
        enabled: true,
        client_id: "client".into(),
        issuer: "https://issuer.test".into(),
        client_secret: Some("sensitive-client-secret".into()),
        response_type: OAuthResponseType {
            id_token: true,
            code: false,
            token: false,
        },
    }
}
fn saml(id: &str) -> InboundSamlProviderConfig {
    InboundSamlProviderConfig {
        id: id.into(),
        display_name: None,
        enabled: true,
        idp_entity_id: "idp".into(),
        sso_url: "https://sso.test".into(),
        idp_certificates: vec!["sensitive-certificate-body".into()],
        sign_request: false,
        sp_entity_id: "sp".into(),
        callback_uri: "https://callback.test".into(),
    }
}
fn seed(ids: &[&str]) -> ProviderConfigSeeds {
    ProviderConfigSeeds {
        oidc: Some(ids.iter().map(|id| oidc(id)).collect()),
        saml: None,
    }
}
fn ids(s: &AuthStore) -> Vec<&str> {
    s.oidc_configs().map(|c| c.id.as_str()).collect()
}
#[test]
fn provider_seed_restores_only_declared_kinds_and_order() {
    let mut s = store("demo-app");
    s.create_saml_config(saml("saml.live"));
    let declaration = seed(&["oidc.z", "oidc.a"]);
    s.set_provider_config_seeds(declaration.clone()).unwrap();
    s.delete_oidc_config("oidc.z");
    s.create_oidc_config(oidc("oidc.runtime"));
    assert_eq!(s.provider_config_seeds(), &declaration);
    s.restore_provider_config_seeds();
    assert_eq!(ids(&s), vec!["oidc.z", "oidc.a"]);
    assert!(s.saml_config("saml.live").is_some());
    s.set_provider_config_seeds(ProviderConfigSeeds {
        oidc: None,
        saml: Some(vec![]),
    })
    .unwrap();
    s.create_saml_config(saml("saml.runtime"));
    s.create_oidc_config(oidc("oidc.extra"));
    s.restore_provider_config_seeds();
    assert_eq!(s.saml_configs().count(), 0);
    assert!(s.oidc_config("oidc.extra").is_some());
}
#[test]
fn provider_seed_saml_replacement_and_reset_preserve_declared_creation_order() {
    let mut s = store("demo-app");
    s.create_saml_config(saml("saml.preexisting"));
    let declaration = ProviderConfigSeeds {
        oidc: None,
        saml: Some(vec![saml("saml.z"), saml("saml.a")]),
    };
    s.set_provider_config_seeds(declaration.clone()).unwrap();
    assert!(s.saml_config("saml.preexisting").is_none());
    s.delete_saml_config("saml.z");
    s.create_saml_config(saml("saml.runtime"));
    s.restore_provider_config_seeds();
    assert_eq!(
        s.saml_configs().map(|c| c.id.as_str()).collect::<Vec<_>>(),
        vec!["saml.z", "saml.a"]
    );
    assert_eq!(s.provider_config_seeds(), &declaration);
}

#[test]
fn provider_seed_undeclared_reset_and_clear_keep_live_resources() {
    let mut s = store("demo-app");
    s.create_oidc_config(oidc("oidc.live"));
    s.restore_provider_config_seeds();
    assert_eq!(ids(&s), vec!["oidc.live"]);
    s.set_provider_config_seeds(seed(&["oidc.seed"])).unwrap();
    s.delete_oidc_config("oidc.seed");
    s.create_oidc_config(oidc("oidc.live"));
    s.clear();
    assert_eq!(ids(&s), vec!["oidc.live"]);
    assert_eq!(s.provider_config_seeds(), &seed(&["oidc.seed"]));
}
#[test]
fn provider_seed_duplicate_install_is_atomic_across_kinds() {
    let mut s = store("demo-app");
    let original = seed(&["oidc.old"]);
    s.set_provider_config_seeds(original.clone()).unwrap();
    let invalid = ProviderConfigSeeds {
        oidc: Some(vec![oidc("oidc.new")]),
        saml: Some(vec![saml("saml.dupe"), saml("saml.dupe")]),
    };
    assert!(s.set_provider_config_seeds(invalid).is_err());
    assert_eq!(ids(&s), vec!["oidc.old"]);
    assert_eq!(s.provider_config_seeds(), &original);
    assert_eq!(s.saml_configs().count(), 0);
    assert!(s
        .set_provider_config_seeds(seed(&["oidc.dupe", "oidc.dupe"]))
        .is_err());
    assert_eq!(ids(&s), vec!["oidc.old"]);
    assert_eq!(s.provider_config_seeds(), &original);
}
#[test]
fn provider_seed_snapshot_restore_keeps_destination_declaration_and_live_resources() {
    let mut source = store("source");
    source
        .set_provider_config_seeds(seed(&["oidc.source"]))
        .unwrap();
    let uid = source
        .create_user(
            fireemu_core_auth::store::NewUser::email("snapshot-account@example.test"),
            fireemu_core_types::time::LogicalInstant::from_unix_seconds(1),
        )
        .unwrap();
    let snapshot = AuthSnapshot::capture(&source);
    assert!(!format!("{snapshot:?}").contains("sensitive-client-secret"));
    for project in ["source", "destination"] {
        for declaration in [ProviderConfigSeeds::default(), seed(&["oidc.destination"])] {
            let mut target = store(project);
            target
                .set_provider_config_seeds(declaration.clone())
                .unwrap();
            target.create_oidc_config(oidc("oidc.live"));
            let before = ids(&target)
                .into_iter()
                .map(str::to_owned)
                .collect::<Vec<_>>();
            assert!(target.user_by_id(uid.as_str()).is_none());
            snapshot.restore_into(&mut target);
            assert!(
                target.user_by_id(uid.as_str()).is_some(),
                "account data is restored while provider control-plane state stays local"
            );
            assert_eq!(target.provider_config_seeds(), &declaration);
            assert_eq!(ids(&target), before);
            target.restore_provider_config_seeds();
            assert!(target.oidc_config("oidc.source").is_none());
        }
    }
}
#[test]
fn provider_seed_routed_projects_use_declaration_instead_of_live_default() {
    let default = Arc::new(Mutex::new(store("demo-app")));
    let registry = AuthRegistry::new("demo-app", default.clone());
    default
        .lock()
        .unwrap()
        .create_oidc_config(oidc("oidc.live"));
    assert_eq!(
        registry
            .routed_candidate("plain")
            .unwrap()
            .oidc_configs()
            .count(),
        0
    );
    let declaration = seed(&["oidc.seed"]);
    registry.set_new_project_provider_config_seeds(declaration.clone());
    let candidate = registry.routed_candidate("routed").unwrap();
    assert_eq!(ids(&candidate), vec!["oidc.seed"]);
    assert_eq!(candidate.provider_config_seeds(), &declaration);
}
#[test]
fn provider_seed_debug_redacts_client_secrets_and_certificate_bodies() {
    let declaration = ProviderConfigSeeds {
        oidc: Some(vec![oidc("oidc.seed")]),
        saml: Some(vec![saml("saml.seed")]),
    };
    for debug in [
        format!("{declaration:?}"),
        format!("{:?}", saml("saml.seed")),
    ] {
        assert!(
            debug.contains("saml.seed"),
            "diagnostics retain the provider identity"
        );
        assert!(!debug.contains("sensitive-client-secret"));
        assert!(!debug.contains("sensitive-certificate-body"));
    }
}
