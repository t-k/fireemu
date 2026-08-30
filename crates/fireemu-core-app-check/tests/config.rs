//! The configuration rules the registry owns (specification section 8, scenarios 14 and 15).
//!
//! The canonical JSON loader in `fireemu` delegates every binding rule to these
//! functions, so a rule proved here holds for the schema, the loader and the runtime alike.

mod support;

use fireemu_core_app_check::limits::{
    MAX_DEBUG_TOKENS_PER_APP, MAX_TOKEN_TTL_SECONDS, MIN_TOKEN_TTL_SECONDS,
};
use fireemu_core_app_check::registry::{
    embedded_project_number, validate_display_name, validate_project_number, AppCheckRegistry,
    AppRegistration, DebugTokenDigest, RegistryError,
};
use support::{digest_of, DEMO_APP_ID, DEMO_SECRET};

fn app(project_id: &str, project_number: &str, app_id: &str) -> AppRegistration {
    AppRegistration {
        project_id: project_id.to_owned(),
        project_number: project_number.to_owned(),
        app_id: app_id.to_owned(),
        enabled: true,
        debug_token_digests: vec![digest_of(DEMO_SECRET)],
    }
}

fn registry() -> AppCheckRegistry {
    AppCheckRegistry::new(3600).expect("3600s is inside the TTL range")
}

#[test]
fn conflicting_project_id_and_project_number_mappings_fail_configuration() {
    let mut r = registry();
    r.register_app(app("demo-app", "1234567890", DEMO_APP_ID))
        .unwrap();

    // One project ID may not take a second project number.
    assert_eq!(
        r.register_app(app("demo-app", "9999999999", "1:9999999999:web:second")),
        Err(RegistryError::ProjectNumberConflict)
    );
    // One project number may not belong to a second project ID.
    assert_eq!(
        r.register_app(app("demo-second", "1234567890", "1:1234567890:web:second")),
        Err(RegistryError::ProjectIdConflict)
    );
    // The same registration twice is a duplicate, not an idempotent no-op.
    assert_eq!(
        r.register_app(app("demo-app", "1234567890", DEMO_APP_ID)),
        Err(RegistryError::DuplicateApp)
    );
}

#[test]
fn one_app_id_cannot_be_reused_across_projects() {
    let mut r = registry();
    r.register_app(app("demo-app", "1234567890", "shared-app-id"))
        .unwrap();
    assert_eq!(
        r.register_app(app("demo-other", "9876543210", "shared-app-id")),
        Err(RegistryError::AppIdReused)
    );
    // The same app ID inside its own project is still just a duplicate.
    assert_eq!(
        r.register_app(app("demo-app", "1234567890", "shared-app-id")),
        Err(RegistryError::DuplicateApp)
    );
}

#[test]
fn a_standard_app_id_must_embed_its_own_project_number() {
    assert_eq!(
        embedded_project_number("1:1234567890:web:abc"),
        Some("1234567890")
    );
    // Not the standard shape: nothing is embedded and nothing is checked.
    assert_eq!(embedded_project_number("custom-app-id"), None);
    assert_eq!(embedded_project_number("1:1234567890:web"), None);
    assert_eq!(embedded_project_number("1:1234567890:web:abc:extra"), None);
    assert_eq!(embedded_project_number("2:1234567890:web:abc"), None);

    let mut r = registry();
    assert_eq!(
        r.register_app(app("demo-app", "1234567890", "1:9999999999:web:abc")),
        Err(RegistryError::AppIdProjectNumberMismatch)
    );
    r.register_app(app("demo-app", "1234567890", "custom-app-id"))
        .expect("a non-standard app ID carries no embedded number to contradict");
}

#[test]
fn project_numbers_are_decimal_digits_without_a_leading_zero() {
    assert!(validate_project_number("1234567890").is_ok());
    assert!(validate_project_number("7").is_ok());
    for bad in ["", "0", "01234", "12 34", "12a4", "-1", "١٢٣"] {
        assert_eq!(
            validate_project_number(bad),
            Err(RegistryError::InvalidProjectNumber),
            "{bad:?} must be refused"
        );
    }
}

#[test]
fn debug_token_digests_are_lowercase_64_character_hexadecimal() {
    let good = "db8055e0e0307d5a016bec4dc338d69875eb0fb7e614a8b125b08fb082095d98";
    assert!(DebugTokenDigest::parse_hex(good).is_ok());
    assert_eq!(
        DebugTokenDigest::parse_hex(&good.to_uppercase()),
        Err(RegistryError::InvalidDigest),
        "uppercase hexadecimal is not the canonical configuration form"
    );
    for bad in [&good[..63], "", "zz", "not-a-digest"] {
        assert_eq!(
            DebugTokenDigest::parse_hex(bad),
            Err(RegistryError::InvalidDigest)
        );
    }
    // The prefix is the only publishable part; the digest itself never renders.
    let digest = DebugTokenDigest::parse_hex(good).unwrap();
    assert_eq!(digest.prefix(), "db8055e0");
    assert_eq!(format!("{digest:?}"), "DebugTokenDigest([redacted])");
}

#[test]
fn the_token_ttl_is_bounded_to_the_documented_session_range() {
    assert!(AppCheckRegistry::new(MIN_TOKEN_TTL_SECONDS).is_ok());
    assert!(AppCheckRegistry::new(MAX_TOKEN_TTL_SECONDS).is_ok());
    assert_eq!(
        AppCheckRegistry::new(MIN_TOKEN_TTL_SECONDS - 1).err(),
        Some(RegistryError::InvalidTokenTtl)
    );
    assert_eq!(
        AppCheckRegistry::new(MAX_TOKEN_TTL_SECONDS + 1).err(),
        Some(RegistryError::InvalidTokenTtl)
    );
    assert_eq!(
        AppCheckRegistry::new(0).err(),
        Some(RegistryError::InvalidTokenTtl)
    );
}

#[test]
fn app_ids_display_names_and_digest_sets_are_bounded() {
    let mut r = registry();
    let mut long = app("demo-app", "1234567890", &"a".repeat(257));
    long.debug_token_digests.clear();
    assert_eq!(r.register_app(long), Err(RegistryError::InvalidAppId));

    let mut many = app("demo-app", "1234567890", "bulk-app");
    many.debug_token_digests = vec![digest_of(DEMO_SECRET); MAX_DEBUG_TOKENS_PER_APP + 1];
    assert_eq!(r.register_app(many), Err(RegistryError::TooManyDebugTokens));

    assert!(validate_display_name("web debug token").is_ok());
    assert_eq!(
        validate_display_name(""),
        Err(RegistryError::InvalidDisplayName)
    );
    assert_eq!(
        validate_display_name(&"n".repeat(129)),
        Err(RegistryError::InvalidDisplayName)
    );
    assert_eq!(
        validate_display_name("null\u{0}byte"),
        Err(RegistryError::InvalidDisplayName)
    );
}

#[test]
fn a_project_resolves_by_id_and_by_number_but_only_when_it_is_registered() {
    let r = support::fixture_registry();
    assert_eq!(r.resolve_project("demo-app"), Some("demo-app"));
    assert_eq!(r.resolve_project("1234567890"), Some("demo-app"));
    assert_eq!(r.resolve_project("demo-other"), Some("demo-other"));
    assert_eq!(r.resolve_project("9876543210"), Some("demo-other"));
    // Only statically registered projects can use App Check.
    assert_eq!(r.resolve_project("demo-unregistered"), None);
    assert_eq!(r.resolve_project("5555555555"), None);
}

#[test]
fn the_project_epoch_never_renders_itself() {
    let epoch = support::seeded_epoch(7);
    assert_eq!(format!("{epoch:?}"), "ProjectEpoch([redacted])");
    assert_eq!(epoch.claim_text().len(), 32);
    assert!(epoch.claim_text().bytes().all(|b| b.is_ascii_hexdigit()));
    assert!(!format!("{epoch:?}").contains(&epoch.claim_text()));
}
