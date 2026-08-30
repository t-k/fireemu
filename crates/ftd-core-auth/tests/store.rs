//! `AuthStore` boundaries pinned by the mutation run: identifiers, uniqueness, validation,
//! credentials, refresh sessions and token validity.

use ftd_core_auth::mfa::TotpPolicy;
use ftd_core_auth::store::{AuthError, AuthStore, LocalId, NewUser, PendingSignInId};
use ftd_core_types::determinism::SplitMix64;
use ftd_core_types::time::{LogicalDuration, LogicalInstant};

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
    assert_eq!(s.set_password(&a, "short"), Err(AuthError::WeakPassword));
    s.set_password(&a, "correct horse").unwrap();
    assert_eq!(
        s.verify_password("a@example.com", "wrong", t(1)),
        Err(AuthError::InvalidCredentials)
    );
    assert_eq!(
        s.verify_password("nobody@example.com", "correct horse", t(1)),
        Err(AuthError::InvalidCredentials)
    );
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
        s.set_password(&ghost, "long enough"),
        Err(AuthError::UserNotFound)
    );
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
        Err(AuthError::InvalidRefreshToken)
    );
    assert_eq!(s.redeem_refresh_token(&tb2), Ok(b.clone()));
    assert_eq!(s.revoke_tokens(&ghost, t(3)), Err(AuthError::UserNotFound));
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
