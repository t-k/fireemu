//! `AuthStore` boundaries pinned by the mutation run: identifiers, uniqueness, validation,
//! credentials, refresh sessions and token validity.

use fireemu_core_auth::mfa::TotpPolicy;
use fireemu_core_auth::store::{
    AuthError, AuthStore, LocalId, NewUser, PendingSignInId, ProjectAuthConfig,
};
use fireemu_core_types::determinism::SplitMix64;
use fireemu_core_types::time::{LogicalDuration, LogicalInstant};

fn t0() -> LogicalInstant {
    LogicalInstant::from_unix_seconds(1_788_004_860)
}

fn t(seconds: i64) -> LogicalInstant {
    t0().checked_add(LogicalDuration::from_seconds(seconds))
        .unwrap()
}

fn store() -> AuthStore {
    AuthStore::new("demo-app", SplitMix64::new(11), TotpPolicy::default())
}

/// An ID that belonged to a user who no longer exists.
fn ghost(s: &mut AuthStore) -> LocalId {
    let id = s
        .create_user_with_id(NewUser::anonymous(), Some("ghost"), t0())
        .unwrap();
    s.delete_user_by_id("ghost").unwrap();
    id
}

#[test]
fn explicit_local_ids_are_validated_and_unique() {
    let mut s = store();
    let uid = s
        .create_user_with_id(NewUser::email("a@example.com"), Some("custom-id"), t0())
        .unwrap();
    assert_eq!(uid.as_str(), "custom-id");
    assert_eq!(uid.to_string(), "custom-id");
    assert_eq!(
        s.create_user_with_id(NewUser::email("b@example.com"), Some("custom-id"), t0()),
        Err(AuthError::LocalIdExists)
    );
    for bad in ["", &"x".repeat(129), "has\u{1}control"] {
        assert_eq!(
            s.create_user_with_id(NewUser::email("c@example.com"), Some(bad), t0()),
            Err(AuthError::InvalidLocalId),
            "{bad:?}"
        );
    }
    let longest = "y".repeat(128);
    assert!(s
        .create_user_with_id(NewUser::email("d@example.com"), Some(&longest), t0())
        .is_ok());
    // Generated IDs differ and creation order is the listing order.
    let e = s.create_user(NewUser::anonymous(), t(1)).unwrap();
    let f = s.create_user(NewUser::anonymous(), t(2)).unwrap();
    assert_ne!(e, f);
    let order: Vec<&str> = s
        .users_by_creation()
        .iter()
        .map(|u| u.local_id.as_str())
        .collect();
    assert_eq!(
        order,
        ["custom-id", longest.as_str(), e.as_str(), f.as_str()]
    );
    assert_eq!(s.all_user_ids().len(), 4);
    let sequences: Vec<u64> = s.users_by_creation().iter().map(|u| u.sequence).collect();
    assert!(sequences.windows(2).all(|w| w[1] == w[0] + 1));
    let page: Vec<&str> = s
        .users_after_sequence(sequences[0], 2)
        .iter()
        .map(|user| user.local_id.as_str())
        .collect();
    assert_eq!(page, [longest.as_str(), e.as_str()]);
    // Deleting removes the user and its refresh tokens; unknown users are an error.
    let token = s.issue_refresh_token(&e, t(2)).unwrap();
    assert!(s.redeem_refresh_token(&token).is_ok());
    s.delete_user_by_id(e.as_str()).unwrap();
    assert_eq!(
        s.redeem_refresh_token(&token),
        Err(AuthError::InvalidRefreshToken)
    );
    assert_eq!(s.delete_user_by_id("nobody"), Err(AuthError::UserNotFound));
    assert_eq!(s.all_user_ids().len(), 3);
    assert!(s
        .users_after_sequence(sequences[2], 1)
        .iter()
        .all(|user| user.local_id != e));
    s.clear();
    assert!(s.all_user_ids().is_empty());
    assert!(s.users_by_creation().is_empty());
}

#[test]
fn emails_and_phone_numbers_are_validated_and_unique_across_users() {
    let mut s = store();
    let ghost = ghost(&mut s);
    let a = s
        .create_user(NewUser::email("a@example.com"), t0())
        .unwrap();
    let b = s
        .create_user(NewUser::email("b@example.com"), t0())
        .unwrap();
    assert_eq!(
        s.create_user(NewUser::email("a@example.com"), t0()),
        Err(AuthError::EmailExists)
    );
    assert_eq!(
        s.create_user(NewUser::email("not-an-email"), t0()),
        Err(AuthError::InvalidEmail)
    );
    assert_eq!(
        s.create_user(NewUser::email("x@y\u{1}"), t0()),
        Err(AuthError::InvalidEmail)
    );
    assert_eq!(
        s.set_email(&b, "a@example.com"),
        Err(AuthError::EmailExists)
    );
    assert_eq!(
        s.set_email(&a, "a@example.com"),
        Ok(()),
        "own email again is fine"
    );
    assert_eq!(s.set_email(&a, "nope"), Err(AuthError::InvalidEmail));
    assert_eq!(
        s.set_email(&ghost, "g@example.com"),
        Err(AuthError::UserNotFound)
    );
    s.set_email(&b, "b2@example.com").unwrap();
    assert_eq!(s.user_by_email("b2@example.com").unwrap().local_id, b);
    assert!(s.user_by_email("b@example.com").is_none());
    assert!(s.user_by_email("B2@example.com").is_none(), "exact match");
    // E.164: `+` and 7..=15 digits.
    for ok in ["+1234567", "+123456789012345"] {
        assert_eq!(AuthStore::validate_phone_number(ok), Ok(()), "{ok}");
    }
    for bad in [
        "",
        "+",
        "+123456",
        "+1234567890123456",
        "1234567",
        "+12345a7",
    ] {
        assert_eq!(
            AuthStore::validate_phone_number(bad),
            Err(AuthError::InvalidPhoneNumber),
            "{bad:?}"
        );
    }
    s.set_phone_number(&a, Some("+819012345678")).unwrap();
    assert_eq!(
        s.set_phone_number(&b, Some("+819012345678")),
        Err(AuthError::PhoneNumberExists)
    );
    assert_eq!(s.set_phone_number(&a, Some("+819012345678")), Ok(()));
    assert_eq!(
        s.set_phone_number(&b, Some("bad")),
        Err(AuthError::InvalidPhoneNumber)
    );
    assert_eq!(s.user_by_phone("+819012345678").unwrap().local_id, a);
    assert!(s.user_by_phone("+819000000000").is_none());
    s.set_phone_number(&a, None).unwrap();
    assert!(s.user_by_phone("+819012345678").is_none());
    assert_eq!(
        s.set_phone_number(&ghost, None),
        Err(AuthError::UserNotFound)
    );
}

#[test]
fn duplicate_email_mode_allows_distinct_accounts_and_keeps_the_latest_lookup_target() {
    let mut s = store();
    let password_user = s
        .create_user(NewUser::email("shared@example.com"), t0())
        .unwrap();
    s.set_config(ProjectAuthConfig {
        allow_duplicate_emails: true,
        ..ProjectAuthConfig::default()
    });

    let password_user_2 = s
        .create_user(NewUser::email("shared@example.com"), t(1))
        .expect("duplicate-email mode permits another password/Admin account");
    assert_ne!(password_user, password_user_2);
    assert_eq!(
        s.user_by_email("shared@example.com").unwrap().local_id,
        password_user_2,
        "the latest password/Admin account is the active email lookup target"
    );

    let result = s
        .sign_in_with_idp(
            federated("oidc.partner", "subject-1", Some("shared@example.com")),
            true,
            t(2),
        )
        .unwrap();
    let fireemu_core_auth::store::IdpSignIn::SignedIn {
        uid: idp_user,
        is_new,
        ..
    } = result
    else {
        panic!("expected a completed IdP sign-in");
    };
    assert!(is_new);
    assert_ne!(idp_user, password_user);
    assert_eq!(
        s.user_by_email("shared@example.com").unwrap().local_id,
        idp_user,
        "the last created duplicate is the active email lookup target"
    );
    s.delete_user_by_id(password_user.as_str()).unwrap();
    assert!(
        s.user_by_email("shared@example.com").is_none(),
        "the official emulator clears its single email index when any duplicate is deleted"
    );
}

#[test]
fn duplicate_email_active_owner_follows_updates_and_any_owner_deletion_clears_it() {
    let mut s = store();
    s.set_config(ProjectAuthConfig {
        allow_duplicate_emails: true,
        ..ProjectAuthConfig::default()
    });
    let fireemu_core_auth::store::IdpSignIn::SignedIn { uid: first, .. } = s
        .sign_in_with_idp(
            federated("oidc.partner", "first", Some("shared@example.com")),
            true,
            t0(),
        )
        .unwrap()
    else {
        panic!("expected a completed IdP sign-in");
    };
    let fireemu_core_auth::store::IdpSignIn::SignedIn { uid: second, .. } = s
        .sign_in_with_idp(
            federated("oidc.partner", "second", Some("shared@example.com")),
            true,
            t(1),
        )
        .unwrap()
    else {
        panic!("expected a completed IdP sign-in");
    };
    assert_eq!(
        s.user_by_email("shared@example.com").unwrap().local_id,
        second
    );

    s.set_phone_number(&first, Some("+15550000001")).unwrap();
    assert_eq!(
        s.user_by_email("shared@example.com").unwrap().local_id,
        first,
        "a non-email update makes that duplicate the active owner"
    );
    s.record_sign_in(&second, t(2));
    assert_eq!(
        s.user_by_email("shared@example.com").unwrap().local_id,
        second,
        "a sign-in is also an official user update"
    );
    let factor = s
        .enroll_phone_factor(&first, "+15550000002", None, t(3))
        .unwrap();
    assert_eq!(
        s.user_by_email("shared@example.com").unwrap().local_id,
        first,
        "MFA enrollment updates the official user record"
    );
    s.record_sign_in(&second, t(4));
    assert!(s
        .unenroll_factor(&first, &factor.mfa_enrollment_id)
        .unwrap());
    assert_eq!(
        s.user_by_email("shared@example.com").unwrap().local_id,
        first,
        "MFA withdrawal updates the official user record"
    );
    s.record_sign_in(&second, t(5));
    s.delete_user_by_id(first.as_str()).unwrap();
    assert!(
        s.user_by_email("shared@example.com").is_none(),
        "deleting any duplicate clears the official emulator's single active index"
    );
}

#[test]
fn passwords_are_validated_hashed_and_verified() {
    let mut s = store();
    let ghost = ghost(&mut s);
    let a = s
        .create_user(NewUser::email("a@example.com"), t0())
        .unwrap();
    assert_eq!(
        AuthStore::validate_password("12345"),
        Err(AuthError::WeakPassword)
    );
    assert_eq!(AuthStore::validate_password("123456"), Ok(()));
    assert_eq!(
        AuthStore::validate_password("12345\u{1}"),
        Err(AuthError::WeakPassword)
    );
    assert_eq!(
        s.set_password(&a, "short", t(0)),
        Err(AuthError::WeakPassword)
    );
    s.set_password(&a, "correct horse", t(0)).unwrap();
    // The default mode reports what the official emulator reports; improved email privacy
    // collapses both refusals into one.
    assert_eq!(
        s.verify_password("a@example.com", "wrong", t(1)),
        Err(AuthError::InvalidPassword)
    );
    assert_eq!(
        s.verify_password("nobody@example.com", "correct horse", t(1)),
        Err(AuthError::EmailNotFound)
    );
    let mut private = s.config();
    private.enable_improved_email_privacy = true;
    s.set_config(private);
    assert_eq!(
        s.verify_password("a@example.com", "wrong", t(1)),
        Err(AuthError::InvalidCredentials)
    );
    assert_eq!(
        s.verify_password("nobody@example.com", "correct horse", t(1)),
        Err(AuthError::InvalidCredentials)
    );
    s.set_config(ProjectAuthConfig::default());
    assert_eq!(
        s.verify_password("a@example.com", "correct horse", t(1)),
        Ok(a.clone())
    );
    assert_eq!(s.user(&a).unwrap().last_sign_in_at, Some(t(1)));
    s.record_sign_in(&a, t(2));
    assert_eq!(s.user(&a).unwrap().last_sign_in_at, Some(t(2)));
    // The digest never appears in Debug output.
    let debug = format!("{:?}", s.user(&a).unwrap());
    assert!(debug.contains("PasswordDigest([redacted])"), "{debug}");
    assert!(!debug.contains("correct horse"));
    s.user_mut(&a).unwrap().disabled = true;
    assert_eq!(
        s.verify_password("a@example.com", "correct horse", t(3)),
        Err(AuthError::UserDisabled)
    );
    assert_eq!(
        s.set_password(&ghost, "long enough", t(0)),
        Err(AuthError::UserNotFound)
    );
}

#[test]
fn refresh_revocation_boundary_preserves_stateless_and_disabled_precedence() {
    for issued in [2, 3, 4] {
        let mut s = store();
        let uid = s
            .create_user(NewUser::email("boundary@example.com"), t0())
            .unwrap();
        let other = s
            .create_user(NewUser::email("other@example.com"), t0())
            .unwrap();
        let token = s.issue_refresh_token(&uid, t(issued)).unwrap();
        let other_token = s.issue_refresh_token(&other, t(1)).unwrap();
        s.revoke_tokens(&uid, t(3)).unwrap();
        let expected = if issued < 3 {
            Err(AuthError::ExpiredRefreshToken)
        } else {
            Ok(uid.clone())
        };
        assert_eq!(s.redeem_refresh_token(&token), expected);
        assert!(s.stateless_refresh_session(&token).is_ok());
        assert_eq!(s.redeem_refresh_token(&other_token), Ok(other));
        assert_eq!(
            s.redeem_refresh_token("unknown"),
            Err(AuthError::InvalidRefreshToken)
        );
        s.user_mut(&uid).unwrap().disabled = true;
        assert_eq!(s.redeem_refresh_token(&token), Err(AuthError::UserDisabled));
        assert_eq!(
            s.stateless_refresh_session(&token).unwrap_err(),
            AuthError::UserDisabled
        );
    }
}

#[test]
fn refresh_tokens_and_id_tokens_respect_revocation_and_disablement() {
    let mut s = store();
    let ghost = ghost(&mut s);
    let a = s
        .create_user(NewUser::email("a@example.com"), t0())
        .unwrap();
    let b = s
        .create_user(NewUser::email("b@example.com"), t0())
        .unwrap();
    let c = s
        .create_user(NewUser::email("c@example.com"), t0())
        .unwrap();
    let ta = s.issue_refresh_token(&a, t(1)).unwrap();
    let tb = s.issue_refresh_token(&b, t(1)).unwrap();
    assert_ne!(ta, tb);
    assert_eq!(s.redeem_refresh_token(&ta), Ok(a.clone()));
    assert_eq!(
        s.redeem_refresh_token("rt-unknown"),
        Err(AuthError::InvalidRefreshToken)
    );
    // Revoking one user's refresh tokens leaves the other's alone.
    s.revoke_refresh_tokens(&a);
    assert_eq!(
        s.redeem_refresh_token(&ta),
        Err(AuthError::InvalidRefreshToken)
    );
    assert_eq!(s.redeem_refresh_token(&tb), Ok(b.clone()));
    // revoke_tokens: sessions issued before the instant are invalid, later ones are fine.
    let tb2 = s.issue_refresh_token(&b, t(5)).unwrap();
    s.revoke_tokens(&b, t(3)).unwrap();
    assert_eq!(
        s.redeem_refresh_token(&tb),
        Err(AuthError::ExpiredRefreshToken)
    );
    assert_eq!(s.redeem_refresh_token(&tb2), Ok(b.clone()));
    assert_eq!(s.revoke_tokens(&ghost, t(3)), Err(AuthError::UserNotFound));
    s.revoke_tokens(&c, t(8)).unwrap();
    s.revoke_tokens(&c, t(4)).unwrap();
    assert!(!s.token_is_valid(&c, t(7), t(3600), t(10)));
    assert!(s.token_is_valid(&c, t(8), t(3600), t(10)));
    assert_eq!(
        s.issue_refresh_token(&ghost, t(3)),
        Err(AuthError::UserNotFound)
    );
    // token_is_valid: auth_time at the revocation instant is still valid, before it is
    // not; expiry is exclusive; disabled users never.
    let exp = t(3600);
    assert!(s.token_is_valid(&b, t(3), exp, t(10)));
    assert!(!s.token_is_valid(&b, t(2), exp, t(10)));
    assert!(!s.token_is_valid(&b, t(3), exp, exp));
    assert!(s.token_is_valid(
        &b,
        t(3),
        exp,
        exp.checked_add(LogicalDuration::from_seconds(-1)).unwrap()
    ));
    assert!(!s.token_is_valid(&ghost, t(3), exp, t(10)));
    s.user_mut(&b).unwrap().disabled = true;
    assert!(!s.token_is_valid(&b, t(3), exp, t(10)));
    assert_eq!(s.redeem_refresh_token(&tb2), Err(AuthError::UserDisabled));
    // Pending sign-in credentials are opaque non-empty strings without control characters.
    assert!(PendingSignInId::parse("").is_none());
    assert!(PendingSignInId::parse("a\nb").is_none());
    assert_eq!(PendingSignInId::parse("abc").unwrap().as_str(), "abc");
    for e in [
        AuthError::UserNotFound,
        AuthError::EmailExists,
        AuthError::InvalidRefreshToken,
        AuthError::WeakPassword,
    ] {
        assert!(!e.to_string().is_empty());
    }
}

#[test]
fn replacing_a_refresh_session_invalidates_the_provisional_token() {
    use fireemu_core_auth::claims::CustomClaims;

    let mut s = store();
    let uid = s
        .create_user(NewUser::email("blocking@example.com"), t0())
        .unwrap();
    let provisional = s.issue_refresh_token(&uid, t(1)).unwrap();

    let committed = s
        .replace_refresh_session(
            &provisional,
            &uid,
            t(1),
            None,
            CustomClaims::default(),
            None,
        )
        .unwrap();

    assert_ne!(committed, provisional);
    assert_eq!(
        s.redeem_refresh_token(&provisional),
        Err(AuthError::InvalidRefreshToken)
    );
    assert_eq!(s.redeem_refresh_token(&committed), Ok(uid.clone()));
    s.revoke_refresh_tokens(&uid);
    assert_eq!(
        s.redeem_refresh_token(&committed),
        Err(AuthError::InvalidRefreshToken)
    );
}

#[test]
fn refresh_ownership_index_removes_all_and_only_the_target_users_sessions() {
    use fireemu_core_auth::store::AuthSnapshot;

    let mut live = store();
    let a = live
        .create_user(NewUser::email("indexed-a@example.com"), t0())
        .unwrap();
    let b = live
        .create_user(NewUser::email("indexed-b@example.com"), t0())
        .unwrap();
    let a_tokens = (0..3)
        .map(|_| live.issue_refresh_token(&a, t(1)).unwrap())
        .collect::<Vec<_>>();
    let b_tokens = (0..3)
        .map(|_| live.issue_refresh_token(&b, t(1)).unwrap())
        .collect::<Vec<_>>();
    let snapshot = AuthSnapshot::capture(&live);

    let mut candidate = live.clone();
    candidate.revoke_refresh_tokens(&a);
    for token in &a_tokens {
        assert_eq!(
            candidate.redeem_refresh_token(token),
            Err(AuthError::InvalidRefreshToken)
        );
        assert_eq!(live.redeem_refresh_token(token), Ok(a.clone()));
    }
    for token in &b_tokens {
        assert_eq!(candidate.redeem_refresh_token(token), Ok(b.clone()));
    }

    let mut restored = store();
    snapshot.restore_into(&mut restored);
    restored.delete_user_by_id(a.as_str()).unwrap();
    for token in &a_tokens {
        assert_eq!(
            restored.redeem_refresh_token(token),
            Err(AuthError::InvalidRefreshToken)
        );
    }
    for token in &b_tokens {
        assert_eq!(restored.redeem_refresh_token(token), Ok(b.clone()));
    }
}

fn federated(
    provider: &str,
    raw: &str,
    email: Option<&str>,
) -> fireemu_core_auth::store::FederatedIdentity {
    fireemu_core_auth::store::FederatedIdentity {
        provider_id: provider.to_owned(),
        raw_id: raw.to_owned(),
        email: email.map(str::to_owned),
        display_name: Some("Name".to_owned()),
        photo_url: None,
    }
}

#[test]
fn federated_sign_in_creates_then_reuses_by_raw_id() {
    use fireemu_core_auth::store::IdpSignIn;
    let mut s = store();
    let first = s
        .sign_in_with_idp(
            federated("oidc.x", "u1", Some("u1@example.com")),
            true,
            t0(),
        )
        .unwrap();
    let IdpSignIn::SignedIn { uid, is_new, .. } = first else {
        panic!("expected sign-in");
    };
    assert!(is_new);
    // The same raw id signs the same user back in.
    let again = s
        .sign_in_with_idp(
            federated("oidc.x", "u1", Some("u1@example.com")),
            true,
            t(1),
        )
        .unwrap();
    let IdpSignIn::SignedIn {
        uid: uid2,
        is_new: new2,
        ..
    } = again
    else {
        panic!("expected sign-in");
    };
    assert_eq!(uid, uid2);
    assert!(!new2);
}

#[test]
fn a_verified_provider_email_links_to_the_owning_account() {
    use fireemu_core_auth::store::IdpSignIn;
    let mut s = store();
    let uid = s
        .create_user(NewUser::email("owner@example.com"), t0())
        .unwrap();
    let outcome = s
        .sign_in_with_idp(
            federated("oidc.x", "u9", Some("owner@example.com")),
            true,
            t(1),
        )
        .unwrap();
    let IdpSignIn::SignedIn {
        uid: signed,
        is_new,
        ..
    } = outcome
    else {
        panic!("expected sign-in");
    };
    assert_eq!(signed, uid);
    assert!(!is_new);
    assert!(s
        .user(&uid)
        .unwrap()
        .federated
        .iter()
        .any(|f| f.raw_id == "u9"));
}

#[test]
fn an_unverified_provider_email_needs_confirmation_and_changes_nothing() {
    use fireemu_core_auth::store::IdpSignIn;
    let mut s = store();
    let uid = s
        .create_user(NewUser::email("owner@example.com"), t0())
        .unwrap();
    let outcome = s
        .sign_in_with_idp(
            federated("oidc.x", "attacker", Some("owner@example.com")),
            false,
            t(1),
        )
        .unwrap();
    let IdpSignIn::NeedConfirmation {
        uid: named,
        verified_providers,
    } = outcome
    else {
        panic!("expected needConfirmation");
    };
    assert_eq!(named, uid);
    assert!(verified_providers.is_empty());
    // Nothing linked, no second account created.
    assert!(s.user(&uid).unwrap().federated.is_empty());
    assert_eq!(s.users_by_creation().len(), 1);
}

#[test]
fn a_verified_email_recycles_an_unverified_account() {
    use fireemu_core_auth::store::IdpSignIn;
    let mut s = store();
    // An unverified password account owns the email.
    let uid = s
        .create_user(NewUser::email("shared@example.com"), t0())
        .unwrap();
    s.set_password(&uid, "hunter22", t(0)).unwrap();
    assert!(s.has_password(&uid));
    let outcome = s
        .sign_in_with_idp(
            federated("oidc.x", "verified", Some("shared@example.com")),
            true,
            t(1),
        )
        .unwrap();
    let IdpSignIn::SignedIn {
        uid: signed,
        is_new,
        ..
    } = outcome
    else {
        panic!("expected sign-in");
    };
    assert_eq!(signed, uid);
    assert!(!is_new);
    // The verified IdP email took over: the password is gone and the email is verified.
    assert!(!s.has_password(&uid));
    assert!(s.user(&uid).unwrap().email_verified);
}

// ------------------------------------------------------------------------------------------
// Credential notices: the console lines the official emulator prints instead of sending mail
// or SMS (firebase-tools/lib/emulator/auth/operations.js).
// ------------------------------------------------------------------------------------------

#[test]
fn credential_notice_messages_are_the_official_console_lines() {
    use fireemu_core_auth::store::{CredentialNotice, OobRequestType, PhoneCodeUse};
    let email = |request_type, new_email: Option<&str>| CredentialNotice::EmailAction {
        request_type,
        email: "a@example.com".to_owned(),
        new_email: new_email.map(str::to_owned),
        link: "http://127.0.0.1:9099/emulator/action?mode=x&oobCode=oob-1".to_owned(),
    };
    assert_eq!(
        email(OobRequestType::VerifyEmail, None).message(),
        "To verify the email address a@example.com, follow this link: http://127.0.0.1:9099/emulator/action?mode=x&oobCode=oob-1"
    );
    assert_eq!(
        email(OobRequestType::PasswordReset, None).message(),
        "To reset the password for a@example.com, follow this link: http://127.0.0.1:9099/emulator/action?mode=x&oobCode=oob-1&newPassword=NEW_PASSWORD_HERE"
    );
    assert_eq!(
        email(OobRequestType::EmailSignIn, None).message(),
        "To sign in as a@example.com, follow this link: http://127.0.0.1:9099/emulator/action?mode=x&oobCode=oob-1"
    );
    assert_eq!(
        email(OobRequestType::VerifyAndChangeEmail, Some("b@example.com")).message(),
        "To verify and change the email address from a@example.com to b@example.com, follow this link: http://127.0.0.1:9099/emulator/action?mode=x&oobCode=oob-1"
    );
    let phone = |purpose| CredentialNotice::PhoneCode {
        phone_number: "+15551234567".to_owned(),
        code: "123456".to_owned(),
        purpose,
    };
    assert_eq!(
        phone(PhoneCodeUse::SignIn).message(),
        "To verify the phone number +15551234567, use the code 123456."
    );
    assert_eq!(
        phone(PhoneCodeUse::MfaEnrollment).message(),
        "To enroll MFA with +15551234567, use the code 123456."
    );
    assert_eq!(
        phone(PhoneCodeUse::MfaSignIn).message(),
        "To sign in with MFA using +15551234567, use the code 123456."
    );
}

#[test]
fn credential_notices_are_drained_once_in_issue_order() {
    use fireemu_core_auth::store::{CredentialNotice, PhoneCodeUse};
    let mut s = store();
    assert!(s.take_credential_notices().is_empty());
    let first = CredentialNotice::PhoneCode {
        phone_number: "+15551234567".to_owned(),
        code: "000001".to_owned(),
        purpose: PhoneCodeUse::SignIn,
    };
    let second = CredentialNotice::PhoneCode {
        phone_number: "+15557654321".to_owned(),
        code: "000002".to_owned(),
        purpose: PhoneCodeUse::MfaEnrollment,
    };
    s.push_credential_notice(first.clone());
    s.push_credential_notice(second.clone());
    // A clone (the speculative store of a blocking-hook request) carries its own queue.
    let mut speculative = s.clone();
    assert_eq!(
        speculative.take_credential_notices(),
        vec![first.clone(), second.clone()]
    );
    assert_eq!(s.take_credential_notices(), vec![first, second]);
    assert!(s.take_credential_notices().is_empty());
}
