//! Installing accounts from an import artifact: the recorded identity is kept, the emulator
//! password form survives, and a malformed account is refused rather than half-installed.

use fireemu_core_auth::claims::{ClaimValue, CustomClaims};
use fireemu_core_auth::mfa::{
    ImportedFactorError, PhoneFactor, TotpFactor, TotpPolicy, TotpSecret,
};
use fireemu_core_auth::store::{
    AuthError, AuthStore, FederatedIdentity, ImportUserError, ImportedHashFailure,
    ImportedHashVerifier, ImportedPasswordHash, ImportedUser, ProjectAuthConfig, Provider,
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
        last_refresh_at: None,
        tokens_valid_after: t(-1_000),
        federated: Vec::new(),
        password: None,
        imported_password: None,
        allow_shared_email: false,
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
fn imported_email_uses_the_same_canonical_ownership_key_as_sign_up() {
    let mut store = store();
    let imported = store
        .import_user(ImportedUser {
            email: Some("MixedCase@example.com".to_owned()),
            ..account("mixed")
        })
        .expect("the import succeeds");
    assert_eq!(
        store.user(&imported).and_then(|user| user.email.as_deref()),
        Some("mixedcase@example.com")
    );
    assert_eq!(
        store
            .user_by_email("MIXEDCASE@example.com")
            .unwrap()
            .local_id,
        imported
    );
    assert_eq!(
        store.import_user(ImportedUser {
            email: Some("mixedcase@example.com".to_owned()),
            ..account("duplicate")
        }),
        Err(ImportUserError::Account(AuthError::EmailExists))
    );
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
fn trusted_artifact_import_preserves_a_password_longer_than_the_new_password_limit() {
    let mut store = store();
    let password = "a".repeat(AuthStore::MAX_PASSWORD_UTF16_UNITS + 1);
    let imported = ImportedUser {
        email: Some("legacy-long-password@example.com".to_owned()),
        provider: Provider::Password,
        password: Some(("legacy-salt".to_owned(), password.clone())),
        ..account("legacy-long-password")
    };
    assert_eq!(
        store.import_user(imported.clone()),
        Err(ImportUserError::Account(AuthError::PasswordTooLong))
    );
    let uid = store
        .import_user_trusted(imported)
        .expect("a previously exported artifact restores exactly");
    assert_eq!(
        store
            .verify_password("legacy-long-password@example.com", &password, t(0))
            .expect("the restored long password signs in"),
        uid
    );
}

#[test]
fn a_credential_created_through_the_api_has_no_emulator_form_to_export() {
    let mut store = store();
    let uid = store
        .import_user(account("user"))
        .expect("the import succeeds");
    store
        .set_password(&uid, "chosen-later", t(0))
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
    let users = store.users_by_creation();
    let ids: Vec<&str> = users.iter().map(|u| u.local_id.as_str()).collect();
    assert_eq!(ids, vec!["zeta", "alpha", "mu"]);
    // Creation-order cursors are "everything after this sequence", so a sequence of zero
    // would hide the first imported account from them.
    assert!(
        users.iter().all(|u| u.sequence > 0),
        "imported accounts take listable sequences"
    );
}

#[test]
fn the_project_auth_configuration_survives_the_store() {
    let mut store = store();
    assert_eq!(store.config(), ProjectAuthConfig::default());
    let config = ProjectAuthConfig {
        allow_duplicate_emails: true,
        enable_improved_email_privacy: true,
        ..ProjectAuthConfig::default()
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

/// Every writer of a federated identity goes through `FederatedIdentity::validate`, so an
/// import row cannot install what a request would be refused, and nothing is half-installed.
/// Production's refusal shape for this input is unobserved.
#[test]
fn a_federated_identity_carrying_a_control_character_is_refused_by_every_writer() {
    let dirty = |field: &str| {
        let mut identity = FederatedIdentity {
            provider_id: "github.com".to_owned(),
            raw_id: "gh-1".to_owned(),
            email: Some("gh@example.com".to_owned()),
            display_name: Some("Grace".to_owned()),
            photo_url: Some("https://p.example/a.png".to_owned()),
        };
        match field {
            "providerId" => identity.provider_id.push('\u{0000}'),
            "rawId" => identity.raw_id.push('\u{0001}'),
            "email" => identity.email = Some("gh\u{0007}@example.com".to_owned()),
            "displayName" => identity.display_name = Some("Gr\u{0000}ace".to_owned()),
            "photoUrl" => identity.photo_url = Some("https://p.example/a.png\u{001f}".to_owned()),
            other => unreachable!("unknown field {other}"),
        }
        identity
    };

    for field in ["providerId", "rawId", "email", "displayName", "photoUrl"] {
        let mut store = store();

        // The import boundary.
        let mut row = account("import-ctrl");
        row.federated = vec![dirty(field)];
        assert_eq!(
            store.import_user(row),
            Err(ImportUserError::Account(AuthError::ControlCharacterInText(
                field
            ))),
            "{field}"
        );
        assert!(store.user_by_id("import-ctrl").is_none(), "{field}");

        // The link boundary.
        let uid = store.import_user(account("linked")).expect("a clean row");
        assert_eq!(
            store.link_federated(&uid, dirty(field)),
            Err(AuthError::ControlCharacterInText(field)),
            "{field}"
        );
        assert!(store.user(&uid).expect("the user").federated.is_empty());

        // The sign-in boundary, which creates an account before it links: it must refuse
        // before creating anything.
        let before = store.user_count();
        assert_eq!(
            store.sign_in_with_idp(dirty(field), true, t(0)).err(),
            Some(AuthError::ControlCharacterInText(field)),
            "{field}"
        );
        assert_eq!(store.user_count(), before, "{field}");
    }

    // The same identity without a control character installs, links and signs in.
    let mut store = store();
    let clean = FederatedIdentity {
        provider_id: "github.com".to_owned(),
        raw_id: "gh-1".to_owned(),
        email: Some("gh@example.com".to_owned()),
        display_name: Some("Grace".to_owned()),
        photo_url: Some("https://p.example/a.png".to_owned()),
    };
    assert!(store.sign_in_with_idp(clean, true, t(0)).is_ok());
}

/// A second factor's display name is stored text, so an import row is held to the same rule
/// as an enrollment request and nothing is half-installed. Production's refusal shape for
/// this input is unobserved.
#[test]
fn an_imported_second_factor_display_name_carrying_a_control_character_is_refused() {
    for (label, row) in [
        (
            "phone",
            ImportedUser {
                phone_factors: vec![PhoneFactor {
                    mfa_enrollment_id: "enrollment-phone".to_owned(),
                    display_name: Some("per\u{0000}sonal".to_owned()),
                    phone_number: "+15555550102".to_owned(),
                    enrolled_at: t(-100),
                }],
                ..account("factor-ctrl")
            },
        ),
        (
            "totp",
            ImportedUser {
                totp_factors: vec![TotpFactor {
                    mfa_enrollment_id: "enrollment-totp".to_owned(),
                    display_name: Some("authent\u{001f}icator".to_owned()),
                    secret: TotpSecret::new(vec![1, 2, 3, 4, 5]),
                    enrolled_at: t(-200),
                    last_accepted_step: None,
                }],
                ..account("factor-ctrl")
            },
        ),
    ] {
        let mut store = store();
        assert_eq!(
            store.import_user(row),
            Err(ImportUserError::SecondFactor(
                ImportedFactorError::ControlCharacterInDisplayName
            )),
            "{label}"
        );
        assert!(store.user_by_id("factor-ctrl").is_none(), "{label}");
    }

    // The same rows without the control character install.
    let mut store = store();
    assert!(store
        .import_user(ImportedUser {
            phone_factors: vec![PhoneFactor {
                mfa_enrollment_id: "enrollment-phone".to_owned(),
                display_name: Some("personal".to_owned()),
                phone_number: "+15555550102".to_owned(),
                enrolled_at: t(-100),
            }],
            ..account("factor-clean")
        })
        .is_ok());
}

/// A verifier standing in for the adapter's cryptography: it accepts exactly one password for
/// any imported hash whose spec is `test-spec`.
struct AcceptsOnly(&'static str);

impl ImportedHashVerifier for AcceptsOnly {
    fn verify(
        &self,
        imported: &ImportedPasswordHash,
        password: &str,
    ) -> Result<bool, ImportedHashFailure> {
        if imported.spec == "unevaluable-spec" {
            return Err(ImportedHashFailure);
        }
        Ok(imported.spec == "test-spec" && password == self.0)
    }
}

fn hashed_account(id: &str, email: &str) -> ImportedUser {
    ImportedUser {
        email: Some(email.to_owned()),
        provider: Provider::Password,
        imported_password: Some(ImportedPasswordHash {
            spec: "test-spec".to_owned(),
            hash: vec![1, 2, 3],
            salt: vec![4, 5],
        }),
        ..account(id)
    }
}

#[test]
fn an_imported_foreign_hash_signs_in_only_through_the_verifier_and_is_then_rehashed() {
    let mut store = store();
    let uid = store
        .import_user(hashed_account("hashed", "hashed@example.com"))
        .expect("the import succeeds");
    assert!(
        store.password_digest(&uid).is_some(),
        "an imported hash is a password credential"
    );
    assert!(
        store
            .verify_password("hashed@example.com", "right", t(0))
            .is_err(),
        "without a verifier a foreign hash never matches"
    );
    assert!(store
        .verify_password_with_imports("hashed@example.com", "wrong", t(0), &AcceptsOnly("right"))
        .is_err());
    let (signed_in, _) = store
        .verify_password_with_imports("hashed@example.com", "right", t(1), &AcceptsOnly("right"))
        .expect("the verifier accepts the right password");
    assert_eq!(signed_in, uid);
    assert_eq!(
        store
            .verify_password("hashed@example.com", "right", t(2))
            .expect("after a successful sign-in the credential is fireemu's own"),
        uid
    );
    assert!(store
        .verify_password("hashed@example.com", "wrong", t(2))
        .is_err());
}

#[test]
fn an_unevaluable_imported_hash_fails_the_sign_in_without_changing_the_account() {
    let mut store = store();
    let mut account = hashed_account("unevaluable", "unevaluable@example.com");
    if let Some(imported) = account.imported_password.as_mut() {
        imported.spec = "unevaluable-spec".to_owned();
    }
    let uid = store.import_user(account).expect("the import succeeds");
    assert_eq!(
        store.verify_password_with_imports(
            "unevaluable@example.com",
            "right",
            t(0),
            &AcceptsOnly("right")
        ),
        Err(AuthError::ImportedHashFailure)
    );
    assert!(store
        .password_digest(&uid)
        .is_some_and(|digest| digest.emulator_form().is_none()));
    assert_eq!(store.user(&uid).and_then(|u| u.last_sign_in_at), None);
}

#[test]
fn an_imported_hash_is_never_exported_as_an_emulator_form_and_debug_redacts_it() {
    let mut store = store();
    let uid = store
        .import_user(hashed_account("hashed-export", "export@example.com"))
        .expect("the import succeeds");
    assert_eq!(
        store.password_digest(&uid).and_then(|d| d.emulator_form()),
        None
    );
    let imported = ImportedPasswordHash {
        spec: "test-spec".to_owned(),
        hash: vec![9; 4],
        salt: vec![8; 4],
    };
    assert_eq!(format!("{imported:?}"), "ImportedPasswordHash([redacted])");
}
