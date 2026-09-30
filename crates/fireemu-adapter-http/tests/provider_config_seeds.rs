//! Canonical seed framing delegates provider acceptance to the complete Admin create path.
use fireemu_adapter_http::identity_toolkit::provider_config_seeds;
use serde_json::{json, Value};
fn oidc(name: &str) -> Value {
    json!({"name":name,"clientId":"client","issuer":"https://issuer.test"})
}
#[test]
fn provider_seed_null_empty_and_order_are_distinct() {
    for input in [Value::Null, json!({}), json!({"oidc":null,"saml":null})] {
        let seed = provider_config_seeds(&input, true).unwrap();
        assert!(seed.oidc.is_none());
        assert!(seed.saml.is_none());
    }
    let seed = provider_config_seeds(
        &json!({"oidc":[oidc("oidc.z"),oidc("oidc.a")],"saml":[]}),
        true,
    )
    .unwrap();
    assert_eq!(
        seed.oidc
            .unwrap()
            .iter()
            .map(|c| c.id.as_str())
            .collect::<Vec<_>>(),
        vec!["oidc.z", "oidc.a"]
    );
    assert_eq!(seed.saml, Some(vec![]));
}
#[test]
fn provider_seed_preserves_admin_strict_refusals_and_safe_diagnostics() {
    let mut config = oidc("oidc.fixture");
    config["issuer"] = json!("http://issuer.test");
    assert!(provider_config_seeds(&json!({"oidc":[config.clone()]}), false).is_ok());
    let error = provider_config_seeds(&json!({"oidc":[config]}), true).unwrap_err();
    assert!(error.contains("auth.providers.oidc[0]"));
    assert!(error.contains("INVALID_ISSUER"));
    let error=provider_config_seeds(&json!({"oidc":[oidc("oidc.fixture"),{"name":"oidc.fixture","clientSecret":"NEVER-PRINT"}]}),true).unwrap_err();
    assert!(error.contains("CONFIGURATION_EXISTS"));
    assert!(!error.contains("NEVER-PRINT"));
    for name in [
        "projects/demo/oauthIdpConfigs/oidc.fixture",
        "projects/demo/tenants/t/oauthIdpConfigs/oidc.fixture",
    ] {
        let error = provider_config_seeds(&json!({"oidc":[oidc(name)]}), true).unwrap_err();
        assert!(error.contains("auth.providers.oidc[0].name"));
        assert!(error.contains("id form"));
    }
    for input in [
        json!(false),
        json!({"builtins":[]}),
        json!({"oidc":{}}),
        json!({"saml":[false]}),
    ] {
        assert!(provider_config_seeds(&input, true)
            .unwrap_err()
            .contains("auth.providers"));
    }
}

#[test]
fn provider_seed_deploy_wrapper_mistakes_name_the_key_and_configuration_source() {
    for strict in [false, true] {
        for key in ["anonymous", "emailPassword", "googleSignIn"] {
            let error =
                provider_config_seeds(&json!({key:{"clientSecret":"DO-NOT-PRINT"}}), strict)
                    .unwrap_err();
            assert!(
                error.contains(&format!("unknown config key auth.providers.{key}")),
                "{error}"
            );
            assert!(error.contains("firebase.json"), "{error}");
            assert!(error.contains("auth.signIn"), "{error}");
            assert!(!error.contains("DO-NOT-PRINT"), "{error}");
        }
        let error = provider_config_seeds(&json!({"unknown\nkey":true}), strict).unwrap_err();
        assert!(error.contains("unknown\\nkey"), "{error:?}");
        assert!(!error.contains('\n'), "{error:?}");
    }
}
