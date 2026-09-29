//! A tenant declared in the configuration file (`auth.tenants[]`) and the multi-tenancy switch
//! (`auth.multiTenant.allowTenants`): validated by the code the Admin create route reads a tenant
//! document with, then created with the id the file names.

use std::sync::{Arc, Mutex};

use fireemu_adapter_http::identity_toolkit::{
    handle, handle_with, AuthQueryLimits, AuthState, ClientApiKeyPolicy, FakeCustomTokenExpiry,
    IdpContinuationPolicy, RequestHeaders,
};
use fireemu_core_auth::mfa::TotpPolicy;
use fireemu_core_auth::store::{AuthRegistry, AuthStore};
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_types::determinism::SplitMix64;
use fireemu_core_types::time::{LogicalDuration, LogicalInstant};
use serde_json::{json, Value};

const V2: &str = "/identitytoolkit.googleapis.com/v2";
const PROJECT_CONFIG: &str = "/identitytoolkit.googleapis.com/admin/v2/projects/demo-app/config";

fn emulator_state() -> AuthState {
    AuthState {
        store: Arc::new(Mutex::new(AuthStore::new(
            "demo-app",
            SplitMix64::new(5),
            TotpPolicy::default(),
        ))),
        clock: Arc::new(Mutex::new(VirtualClock::new(
            LogicalInstant::from_unix_seconds(1_788_004_860),
        ))),
        wall_clock: None,
        totp_extension_enabled: false,
        barrier: None,
        events: None,
        notices: None,
        blocking: None,
        operation_gate: Arc::new(Mutex::new(())),
        control_token: None,
        registry: None,
        allow_routed_projects: false,
        stateless_refresh_tokens: true,
        idp_continuations: IdpContinuationPolicy::Disabled,
        query_limits: AuthQueryLimits::EmulatorUnbounded,
        client_api_key: ClientApiKeyPolicy::Optional,
        fake_custom_token_expiry: FakeCustomTokenExpiry::Ignore,
        custom_token_trust: None,
        idp_assertions: fireemu_adapter_http::identity_toolkit::IdpAssertionPolicy::Fixture,
        app_check: None,
        app_check_policy: None,
        tenancy: None,
    }
}

fn strict_state() -> AuthState {
    AuthState {
        idp_continuations: IdpContinuationPolicy::LocalBounded,
        query_limits: AuthQueryLimits::ProductionBounded,
        stateless_refresh_tokens: false,
        client_api_key: ClientApiKeyPolicy::Required,
        fake_custom_token_expiry: FakeCustomTokenExpiry::Reject,
        custom_token_trust: None,
        idp_assertions: fireemu_adapter_http::identity_toolkit::IdpAssertionPolicy::Fixture,
        ..emulator_state()
    }
}

use fireemu_adapter_http::identity_toolkit::{
    prepare_tenant_seeds, seed_multi_tenancy, TenantSeed,
};

fn owner() -> RequestHeaders {
    RequestHeaders {
        authorization: Some("Bearer owner".to_owned()),
        origin: None,
        content_type: Some("application/json".to_owned()),
        host: Some("127.0.0.1:9099".to_owned()),
        app_check: Vec::new(),
        peer_ip: None,
    }
}

fn admin(state: &AuthState, method: &str, path: &str, body: &Value) -> (u16, Value) {
    let r = handle_with(state, method, path, &owner(), body);
    (r.status, r.body)
}

fn with_registry(mut state: AuthState) -> (AuthState, Arc<AuthRegistry>) {
    let registry = Arc::new(AuthRegistry::new("demo-app", state.store.clone()));
    state.registry = Some(registry.clone());
    (state, registry)
}

fn acme() -> Value {
    json!({
        "tenantId": "acme-x7k2q",
        "displayName": "acme",
        "allowPasswordSignup": true,
        "mfaConfig": {"state": "ENABLED", "enabledProviders": ["PHONE_SMS"]}
    })
}

fn seeds(docs: &[Value], emulator: bool) -> Result<Vec<TenantSeed>, String> {
    prepare_tenant_seeds(docs, emulator, None)
}

#[test]
fn a_seeded_tenant_is_the_tenant_the_create_route_would_make_with_the_file_s_id() {
    for (emulator, state) in [(true, emulator_state()), (false, strict_state())] {
        let (state, registry) = with_registry(state);
        seed_multi_tenancy(&registry, "demo-app", true).unwrap();
        let prepared = seeds(&[acme()], emulator).unwrap();
        assert_eq!(prepared.len(), 1);
        assert_eq!(prepared[0].id(), "acme-x7k2q");
        prepared[0].apply(&registry, "demo-app").unwrap();
        assert_eq!(registry.tenants("demo-app"), ["acme-x7k2q"]);
        let (status, document) = admin(
            &state,
            "GET",
            &format!("{V2}/projects/demo-app/tenants/acme-x7k2q"),
            &json!({}),
        );
        assert_eq!(status, 200, "{emulator}: {document}");
        assert_eq!(document["displayName"], "acme", "{document}");
        assert_eq!(document["allowPasswordSignup"], true, "{document}");
        assert_eq!(
            document["mfaConfig"],
            json!({"state": "ENABLED", "enabledProviders": ["PHONE_SMS"]}),
            "{document}"
        );
        // The store holds the tenant's own MFA config.
        let store = registry.tenant_store("demo-app", "acme-x7k2q").unwrap();
        assert!(store.lock().unwrap().mfa_config().sms_enabled());
    }
}

#[test]
fn the_seed_reads_the_document_as_the_create_route_does() {
    // A member the create route refuses in strict is refused in a seed under either profile, and
    // a value the route reads as written is read the same way.
    let refused = |doc: Value, expected: &str| {
        for emulator in [true, false] {
            let error = seeds(&[doc.clone()], emulator).err().unwrap_or_default();
            assert!(error.starts_with("auth.tenants[0]:"), "{doc}: {error}");
            assert!(error.contains(expected), "{doc}: {error}");
        }
    };
    let with = |member: &str, value: Value| {
        let mut doc = acme();
        doc[member] = value;
        doc
    };
    refused(
        with("mfaConfig", json!({"state": "ON"})),
        "config.mfa.state",
    );
    refused(
        with(
            "mfaConfig",
            json!({"state": "ENABLED", "providerConfigs": [{"state": "ENABLED", "totpProviderConfig": {"adjacentIntervals": 11}}]}),
        ),
        "between 0 and 10",
    );
    refused(
        with("unknownMember", json!(1)),
        "Unknown name \"unknownMember\"",
    );
    refused(
        with("allowPasswordSignup", json!({})),
        "tenant.allow_password_signup",
    );
    refused(
        with(
            "passwordPolicyConfig",
            json!({"passwordPolicyEnforcementState": "MAYBE"}),
        ),
        "MAYBE",
    );
    let mut without_name = acme();
    without_name.as_object_mut().unwrap().remove("displayName");
    refused(without_name, "MISSING_DISPLAY_NAME");
    refused(with("displayName", json!("abc")), "display_name");
    refused(with("displayName", json!("1acme")), "display_name");
    refused(with("displayName", json!("acme_x")), "display_name");
}

#[test]
fn the_id_has_production_s_shape_and_names_its_display_name() {
    let refused = |id: Value, expected: &str| {
        let mut doc = acme();
        doc["tenantId"] = id.clone();
        let error = seeds(&[doc], true).err().unwrap_or_default();
        assert!(error.starts_with("auth.tenants[0]:"), "{id}: {error}");
        assert!(error.contains(expected), "{id}: {error}");
    };
    for bad in [
        "acme-x7k2",   // four characters of suffix
        "acme-x7k2q1", // six
        "acme-X7K2Q",  // upper case
        "acme-x7k2_",  // outside [a-z0-9]
        "other-x7k2q", // another display name
        "acmex7k2q",   // no separator
        "acme-x7k2q-",
        "-x7k2q",
        "",
    ] {
        refused(json!(bad), "tenantId");
    }
    refused(json!(7), "tenantId");
    refused(Value::Null, "tenantId");
    let mut missing = acme();
    missing.as_object_mut().unwrap().remove("tenantId");
    let error = seeds(&[missing], true).err().unwrap_or_default();
    assert!(error.contains("tenantId"), "{error}");
    // The longest display name production accepts, and a hyphen inside it.
    let mut long = acme();
    long["displayName"] = json!("a-b-c-d-e-f-g-h-i-j1");
    long["tenantId"] = json!("a-b-c-d-e-f-g-h-i-j1-9z9z9");
    assert!(seeds(&[long], true).is_ok());
}

#[test]
fn a_list_of_seeds_refuses_a_repeated_id_and_a_non_object_naming_its_place() {
    let error = seeds(&[acme(), acme()], true).err().unwrap_or_default();
    assert!(error.starts_with("auth.tenants[1]:"), "{error}");
    assert!(error.contains("acme-x7k2q"), "{error}");
    let error = seeds(&[acme(), json!("acme-x7k2q")], true)
        .err()
        .unwrap_or_default();
    assert!(error.starts_with("auth.tenants[1]:"), "{error}");
    let other = json!({"tenantId": "beta-a1b2c", "displayName": "beta"});
    let prepared = seeds(&[acme(), other], true).unwrap();
    assert_eq!(
        prepared.iter().map(TenantSeed::id).collect::<Vec<_>>(),
        ["acme-x7k2q", "beta-a1b2c"]
    );
    assert!(seeds(&[], true).unwrap().is_empty());
}

#[test]
fn a_seed_that_finds_its_id_in_use_says_so_and_changes_nothing() {
    let (_, registry) = with_registry(emulator_state());
    let prepared = seeds(&[acme()], true).unwrap();
    prepared[0].apply(&registry, "demo-app").unwrap();
    let error = prepared[0].apply(&registry, "demo-app").unwrap_err();
    assert!(error.contains("acme-x7k2q"), "{error}");
    assert_eq!(registry.tenants("demo-app"), ["acme-x7k2q"]);
    let error = prepared[0].apply(&registry, "no-such-project").unwrap_err();
    assert!(error.contains("no-such-project"), "{error}");
}

#[test]
fn a_seeded_tenant_can_be_applied_again_after_a_reset_wiped_it() {
    let (_, registry) = with_registry(emulator_state());
    let prepared = seeds(&[acme()], true).unwrap();
    prepared[0].apply(&registry, "demo-app").unwrap();
    let reset = registry.prepare_default_scope_reset().unwrap();
    registry.apply_default_scope_reset(&reset).unwrap();
    assert!(registry.tenants("demo-app").is_empty());
    prepared[0].apply(&registry, "demo-app").unwrap();
    assert_eq!(registry.tenants("demo-app"), ["acme-x7k2q"]);
}

#[test]
fn the_multi_tenancy_switch_is_set_as_the_config_update_sets_it() {
    let (state, registry) = with_registry(strict_state());
    let read = || {
        let (status, config) = admin(&state, "GET", PROJECT_CONFIG, &json!({}));
        assert_eq!(status, 200, "{config}");
        config["multiTenant"].clone()
    };
    assert_eq!(read(), json!({}));
    seed_multi_tenancy(&registry, "demo-app", true).unwrap();
    assert_eq!(read(), json!({"allowTenants": true}));
    assert!(state.store.lock().unwrap().allows_tenants());
    // Strict creates tenants through the Admin API now.
    let (status, created) = admin(
        &state,
        "POST",
        &format!("{V2}/projects/demo-app/tenants"),
        &json!({"displayName": "explicit"}),
    );
    assert_eq!(status, 200, "{created}");
    seed_multi_tenancy(&registry, "demo-app", false).unwrap();
    assert!(!state.store.lock().unwrap().allows_tenants());
    // Off is a new project's value, which reads back as unwritten.
    assert_eq!(read(), json!({}));
    assert!(seed_multi_tenancy(&registry, "no-such-project", true).is_err());
}

#[test]
fn a_declaration_sets_the_switch_when_declared_and_leaves_a_present_tenant_alone() {
    use fireemu_adapter_http::identity_toolkit::TenantSeeding;
    let (state, registry) = with_registry(strict_state());
    let documents = [
        acme(),
        json!({"tenantId": "beta-a1b2c", "displayName": "beta"}),
    ];
    let declaration = TenantSeeding::new(Some(true), seeds(&documents, false).unwrap());
    assert!(!declaration.is_empty());
    assert!(TenantSeeding::default().is_empty());
    assert!(!TenantSeeding::new(None, seeds(&documents, false).unwrap()).is_empty());
    assert!(!TenantSeeding::new(Some(false), Vec::new()).is_empty());
    // A tenant of the same id that is already there (an imported one) is kept as it is.
    let imported =
        json!({"tenantId": "acme-x7k2q", "displayName": "acme", "allowPasswordSignup": false});
    seed_multi_tenancy(&registry, "demo-app", true).unwrap();
    seeds(&[imported], false).unwrap()[0]
        .apply(&registry, "demo-app")
        .unwrap();
    declaration.apply(&registry, "demo-app").unwrap();
    assert_eq!(registry.tenants("demo-app"), ["acme-x7k2q", "beta-a1b2c"]);
    let (_, document) = admin(
        &state,
        "GET",
        &format!("{V2}/projects/demo-app/tenants/acme-x7k2q"),
        &json!({}),
    );
    // The imported document has no multi-factor config; the declared one would have.
    assert!(document.get("mfaConfig").is_none(), "{document}");
    // Undeclared, the switch is left as the project has it.
    seed_multi_tenancy(&registry, "demo-app", false).unwrap();
    TenantSeeding::new(None, Vec::new())
        .apply(&registry, "demo-app")
        .unwrap();
    assert!(!state.store.lock().unwrap().allows_tenants());
    declaration.apply(&registry, "demo-app").unwrap();
    assert!(state.store.lock().unwrap().allows_tenants());
}
