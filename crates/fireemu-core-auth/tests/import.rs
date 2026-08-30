//! Installing accounts from an import artifact: the recorded identity is kept, the emulator
//! password form survives, and a malformed account is refused rather than half-installed.

use fireemu_core_auth::claims::{ClaimValue, CustomClaims};
use fireemu_core_auth::mfa::{
    ImportedFactorError, PhoneFactor, TotpFactor, TotpPolicy, TotpSecret,
};
use fireemu_core_auth::store::{
    AuthError, AuthStore, FederatedIdentity, ImportUserError, ImportedUser, ProjectAuthConfig,
    Provider,
};
use fireemu_core_types::determinism::SplitMix64;
use fireemu_core_types::time::LogicalInstant;

fn store() -> AuthStore {
    AuthStore::new(
        "demo-app",
        SplitMix64::new(0x5eed),
        TotpPolicy {
            max_totp_factors_per_user: 5,
            ..TotpPolicy::default()
        },
    )
}

fn t(n: i64) -> LogicalInstant {
    LogicalInstant::from_unix_seconds(1_788_000_000 + n)
}

fn account(local_id: &str) -> ImportedUser {
    ImportedUser {
        local_id: local_id.to_owned(),
        email: None,
        email_verified: false,
        display_name: None,
        photo_url: None,
        phone_number: None,
        disabled: false,
        provider: Provider::Anonymous,
        custom_claims: CustomClaims::default(),
        created_at: t(-1_000),
        last_sign_in_at: None,
        tokens_valid_after: t(-1_000),
        federated: Vec::new(),
        password: None,
        totp_factors: Vec::new(),
        phone_factors: Vec::new(),
    }
}

#[test]
fn an_imported_account_keeps_its_recorded_identity_and_times() {
    let mut store = store();
    let mut claims = CustomClaims::default();
    claims
        .insert("role", ClaimValue::String("admin".to_owned()))
        .expect("a claim");
    let uid = store
        .import_user(ImportedUser {
            email: Some("alice@example.com".to_owned()),
            email_verified: true,
            display_name: Some("Alice Example".to_owned()),
            photo_url: Some("https://example.com/alice.png".to_owned()),
            phone_number: Some("+15555550100".to_owned()),
            provider: Provider::Password,
            custom_claims: claims,
            created_at: t(-5_000),
            last_sign_in_at: Some(t(-10)),
            tokens_valid_after: t(-20),
            federated: vec![FederatedIdentity {
                provider_id: "google.com".to_owned(),
                raw_id: "google-alice".to_owned(),
                email: Some("alice@example.com".to_owned()),
                display_name: None,
                photo_url: None,
            }],
            password: Some(("fakeSaltAbc".to_owned(), "s3cret-password".to_owned())),
            ..account("user-password")
        })
        .expect("the import succeeds");
    assert_eq!(uid.as_str(), "user-password");

    let user = store.user(&uid).expect("the account");
    assert_eq!(user.email.as_deref(), Some("alice@example.com"));
    assert!(user.email_verified);
    assert_eq!(user.created_at, t(-5_000));
    assert_eq!(user.last_sign_in_at, Some(t(-10)));
    assert_eq!(user.tokens_valid_after, t(-20));
    assert_eq!(user.federated.len(), 1);
    assert_eq!(user.custom_claims.canonical_json(), r#"{"role":"admin"}"#);
    assert!(store.has_password(&uid));
}

#[test]
fn an_imported_password_signs_in_and_is_written_back_in_the_emulator_form() {
    let mut store = store();
    let uid = store
        .import_user(ImportedUser {
            email: Some("alice@example.com".to_owned()),
            provider: Provider::Password,
            password: Some(("fakeSaltAbc".to_owned(), "s3cret-password".to_owned())),
            ..account("user-password")
        })
        .expect("the import succeeds");
    assert_eq!(
        store
            .verify_password("alice@example.com", "s3cret-password", t(0))
            .expect("the imported password signs in"),
        uid
    );
    assert!(store
        .verify_password("alice@example.com", "wrong", t(0))
        .is_err());
    let digest = store.password_digest(&uid).expect("a password credential");
    assert_eq!(
        digest.emulator_form(),
        Some(("fakeSaltAbc", "s3cret-password")),
        "an export writes back exactly the hash the artifact carried"
    );
}

#[test]
fn a_credential_created_through_the_api_has_no_emulator_form_to_export() {
    let mut store = store();
    let uid = store
        .import_user(account("user"))
        .expect("the import succeeds");
    store
        .set_password(&uid, "chosen-later")
        .expect("the password is set");
    assert!(
        store
            .password_digest(&uid)
            .expect("a credential")
            .emulator_form()
            .is_none(),
        "fireemu never invents a reversible hash for a password it only ever digested"
    );
}

#[test]
fn imported_second_factors_keep_their_enrollment_ids_secrets_and_times() {
    let mut store = store();
    let uid = store
        .import_user(ImportedUser {
            phone_factors: vec![PhoneFactor {
                mfa_enrollment_id: "enrollment-phone".to_owned(),
                display_name: Some("personal phone".to_owned()),
                phone_number: "+15555550102".to_owned(),
                enrolled_at: t(-100),
            }],
            totp_factors: vec![TotpFactor {
                mfa_enrollment_id: "enrollment-totp".to_owned(),
                display_name: Some("authenticator".to_owned()),
                secret: TotpSecret::new(vec![1, 2, 3, 4, 5]),
                enrolled_at: t(-200),
                last_accepted_step: None,
            }],
            ..account("user-mfa")
        })
        .expect("the import succeeds");
    let user = store.user(&uid).expect("the account");
    assert_eq!(user.mfa.factor_count(), 2);
    assert_eq!(user.mfa.phone_factors()[0].phone_number, "+15555550102");
    assert_eq!(user.mfa.phone_factors()[0].enrolled_at, t(-100));
    assert_eq!(
        user.mfa.totp_factors()[0].secret.expose_for_enrollment(),
        &[1, 2, 3, 4, 5]
    );
    assert!(user.mfa.has_factor("enrollment-totp"));
}

#[test]
fn an_account_that_repeats_a_local_id_is_refused() {
    let mut store = store();
    store
        .import_user(account("user"))
        .expect("the first import succeeds");
    assert_eq!(
        store.import_user(account("user")),
        Err(ImportUserError::Account(AuthError::LocalIdExists))
    );
}

#[test]
fn an_account_with_a_malformed_identifier_or_phone_number_is_refused() {
    let mut store = store();
    assert_eq!(
        store.import_user(account("")),
        Err(ImportUserError::Account(AuthError::InvalidLocalId))
    );
    assert_eq!(
        store.import_user(account("with\u{0}null")),
        Err(ImportUserError::Account(AuthError::InvalidLocalId))
    );
    assert_eq!(
        store.import_user(ImportedUser {
            phone_number: Some("not a number".to_owned()),
            ..account("user")
        }),
        Err(ImportUserError::Account(AuthError::InvalidPhoneNumber))
    );
    assert!(store.all_user_ids().is_empty(), "nothing was installed");
}

#[test]
fn second_factors_that_share_an_enrollment_id_are_refused() {
    let mut store = store();
    let duplicate = |id: &str| PhoneFactor {
        mfa_enrollment_id: id.to_owned(),
        display_name: None,
        phone_number: "+15555550102".to_owned(),
        enrolled_at: t(0),
    };
    assert_eq!(
        store.import_user(ImportedUser {
            phone_factors: vec![duplicate("same"), duplicate("same")],
            ..account("user")
        }),
        Err(ImportUserError::SecondFactor(
            ImportedFactorError::InvalidEnrollmentId
        ))
    );
    assert_eq!(
        store.import_user(ImportedUser {
            phone_factors: vec![duplicate("")],
            ..account("user")
        }),
        Err(ImportUserError::SecondFactor(
            ImportedFactorError::InvalidEnrollmentId
        ))
    );
    assert_eq!(
        store.import_user(ImportedUser {
            phone_factors: (0..6).map(|i| duplicate(&format!("f{i}"))).collect(),
            ..account("user")
        }),
        Err(ImportUserError::SecondFactor(ImportedFactorError::TooMany))
    );
    assert!(store.all_user_ids().is_empty(), "nothing was installed");
}

#[test]
fn an_import_records_no_user_event() {
    let mut store = store();
    store
        .import_user(account("user"))
        .expect("the import succeeds");
    assert!(
        store.take_user_events().is_empty(),
        "an import restores accounts; it never fires an Auth create trigger"
    );
}

#[test]
fn imported_accounts_list_in_the_order_they_were_imported() {
    let mut store = store();
    for id in ["zeta", "alpha", "mu"] {
        store.import_user(account(id)).expect("the import succeeds");
    }
    let ids: Vec<&str> = store
        .users_by_creation()
        .iter()
        .map(|u| u.local_id.as_str())
        .collect();
    assert_eq!(ids, vec!["zeta", "alpha", "mu"]);
}

#[test]
fn the_project_auth_configuration_survives_the_store() {
    let mut store = store();
    assert_eq!(store.config(), ProjectAuthConfig::default());
    let config = ProjectAuthConfig {
        allow_duplicate_emails: true,
        enable_improved_email_privacy: true,
    };
    store.set_config(config);
    assert_eq!(store.config(), config);
}

#[test]
fn custom_attributes_parse_back_from_the_text_the_api_carries_them_in() {
    let claims = CustomClaims::parse_attributes(r#"{"role":"admin","tier":3,"tags":["a","b"]}"#)
        .expect("the attributes parse");
    assert_eq!(
        claims.canonical_json(),
        r#"{"role":"admin","tags":["a","b"],"tier":3}"#
    );
    assert!(CustomClaims::parse_attributes("[]").is_err());
    assert!(CustomClaims::parse_attributes("not json").is_err());
    assert!(
        CustomClaims::parse_attributes(r#"{"sub":"impersonated"}"#).is_err(),
        "a reserved claim name is refused rather than dropped"
    );
}

#[test]
fn an_imported_account_is_reachable_by_every_lookup_the_surface_uses() {
    let mut store = store();
    store
        .import_user(ImportedUser {
            email: Some("dave@example.com".to_owned()),
            phone_number: Some("+15555550101".to_owned()),
            provider: Provider::Password,
            federated: vec![FederatedIdentity {
                provider_id: "google.com".to_owned(),
                raw_id: "google-dave".to_owned(),
                email: None,
                display_name: None,
                photo_url: None,
            }],
            ..account("user-mfa")
        })
        .expect("the import succeeds");
    let expected = store
        .user_by_id("user-mfa")
        .expect("the account")
        .local_id
        .clone();
    assert_eq!(
        store.user_by_email("dave@example.com").map(|u| &u.local_id),
        Some(&expected)
    );
    assert_eq!(
        store.user_by_phone("+15555550101").map(|u| &u.local_id),
        Some(&expected)
    );
    assert_eq!(
        store
            .user_by_federated("google.com", "google-dave")
            .map(|u| &u.local_id),
        Some(&expected)
    );
}
