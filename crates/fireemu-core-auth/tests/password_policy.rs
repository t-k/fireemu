//! Regression coverage for Auth password-policy evaluation and atomic application.

use fireemu_core_auth::mfa::TotpPolicy;
use fireemu_core_auth::password_policy::{
    default_allowed_non_alphanumeric, EnforcementState, Operation, PasswordPolicy, ViolationCode,
};
use fireemu_core_auth::store::AuthRegistry;
use fireemu_core_auth::store::{AuthError, AuthStore, NewUser};
use fireemu_core_types::determinism::SplitMix64;
use fireemu_core_types::time::LogicalInstant;
use std::sync::{Arc, Mutex};

const NOW: LogicalInstant = LogicalInstant::UNIX_EPOCH;

fn strict(force_upgrade_on_signin: bool) -> PasswordPolicy {
    PasswordPolicy::try_new(
        EnforcementState::Enforce,
        force_upgrade_on_signin,
        12,
        Some(30),
        true,
        true,
        true,
        true,
        default_allowed_non_alphanumeric(),
    )
    .expect("strict policy is valid")
}

fn store() -> AuthStore {
    AuthStore::new("demo-app", SplitMix64::new(7), TotpPolicy::default())
}

#[test]
fn policy_reports_each_requirement_without_retaining_password_data() {
    let policy = strict(false);
    let violations = policy.violations("short");
    assert_eq!(
        violations,
        vec![
            ViolationCode::MinimumPasswordLength,
            ViolationCode::MissingUppercaseCharacter,
            ViolationCode::MissingNumericCharacter,
            ViolationCode::MissingNonAlphanumericCharacter,
        ]
    );
    assert!(policy.violations("ValidPassword9!").is_empty());
    assert_eq!(
        ViolationCode::MissingNumericCharacter.as_str(),
        "MISSING_NUMERIC_CHARACTER"
    );
}

#[test]
fn rejected_registration_is_atomic_and_does_not_create_an_account() {
    let mut store = store();
    store.set_password_policy(strict(false));
    assert_eq!(
        store.create_user_with_password(NewUser::email("weak@example.com"), "short", NOW),
        Err(AuthError::WeakPassword)
    );
    assert!(store.user_by_email("weak@example.com").is_none());
    assert!(store.take_user_events().is_empty());
}

#[test]
fn rejected_password_change_preserves_credential_and_sessions() {
    let mut store = store();
    let uid = store
        .create_user(NewUser::email("user@example.com"), NOW)
        .unwrap();
    store.set_password(&uid, "OldPassword9!", NOW).unwrap();
    let refresh = store.issue_refresh_token(&uid, NOW).unwrap();
    let before = store.user(&uid).cloned().unwrap();

    store.set_password_policy(strict(false));
    assert_eq!(
        store.set_password(&uid, "weak", NOW),
        Err(AuthError::WeakPassword)
    );
    assert_eq!(store.user(&uid), Some(&before));
    assert_eq!(store.redeem_refresh_token(&refresh), Ok(uid));
}

#[test]
fn forced_signin_rejects_noncompliant_existing_password_before_signin_commit() {
    let mut store = store();
    let uid = store
        .create_user(NewUser::email("user@example.com"), NOW)
        .unwrap();
    store.set_password(&uid, "OldPassword9!", NOW).unwrap();
    let before = store.user(&uid).cloned().unwrap();
    store.set_password_policy(strict(true));

    assert_eq!(
        store.verify_password("user@example.com", "OldPassword9!", NOW),
        Ok(uid.clone())
    );

    // A policy-compliant existing credential still signs in.  Change it under the old
    // policy, then force a refusal and verify that the sign-in timestamp remains unchanged.
    let mut weaker = strict(true);
    weaker.require_numeric = false;
    weaker.require_non_alphanumeric = false;
    store.set_password_policy(weaker);
    store
        .set_password(&uid, "OnlyLettersPassword", NOW)
        .unwrap();
    let before_refused = store.user(&uid).cloned().unwrap();
    let refresh = store.issue_refresh_token(&uid, NOW).unwrap();
    store.set_password_policy(strict(true));
    assert!(matches!(
        store.verify_password("user@example.com", "OnlyLettersPassword", NOW),
        Err(AuthError::PasswordPolicyViolation(_))
    ));
    assert_eq!(store.user(&uid), Some(&before_refused));
    assert_eq!(store.redeem_refresh_token(&refresh), Ok(uid));
    assert_eq!(before.last_sign_in_at, None);
}

#[test]
fn off_policy_keeps_existing_auth_behavior_but_hard_limits_remain_separate() {
    let mut store = store();
    let mut policy = strict(true);
    policy.enforcement_state = EnforcementState::Off;
    store.set_password_policy(policy);
    let uid = store
        .create_user_with_password(NewUser::email("user@example.com"), "short!", NOW)
        .unwrap();
    assert!(store.user(&uid).is_some());
    assert!(!store
        .password_policy()
        .rejects(Operation::Registration, "short"));
}

#[test]
fn project_and_tenant_password_policies_are_explicitly_isolated() {
    let default = Arc::new(Mutex::new(store()));
    let registry = AuthRegistry::new("demo-app", default.clone());
    let tenant = registry
        .ensure_tenant("demo-app", "tenant-a")
        .expect("tenant publishes atomically");

    assert!(registry.set_project_password_policy("demo-app", strict(false)));
    assert_eq!(default.lock().unwrap().password_policy().min_length, 12);
    assert_eq!(
        tenant.lock().unwrap().password_policy(),
        &PasswordPolicy::default(),
        "tenant policy is not implicitly inherited"
    );
    assert!(registry.set_tenant_password_policy("demo-app", "tenant-a", strict(true)));
    assert!(
        tenant
            .lock()
            .unwrap()
            .password_policy()
            .force_upgrade_on_signin
    );
    assert!(!registry.set_tenant_password_policy("demo-app", "tenant-b", strict(true)));
}

#[test]
fn non_forced_signin_returns_policy_violations_after_authentication() {
    let mut store = store();
    let uid = store
        .create_user(NewUser::email("user@example.com"), NOW)
        .unwrap();
    // This credential predates the stricter policy and is valid under the original policy.
    store
        .set_password(&uid, "OnlyLettersPassword", NOW)
        .unwrap();
    store.set_password_policy(strict(false));

    let result = store.verify_password_with_policy("user@example.com", "OnlyLettersPassword", NOW);

    assert_eq!(
        result,
        Ok((
            uid.clone(),
            vec![
                ViolationCode::MissingNumericCharacter,
                ViolationCode::MissingNonAlphanumericCharacter,
            ],
        ))
    );
    assert_eq!(store.user(&uid).unwrap().last_sign_in_at, Some(NOW));
}

#[test]
fn forced_signin_rejection_preserves_existing_signin_timestamp() {
    let mut store = store();
    let uid = store
        .create_user(NewUser::email("user@example.com"), NOW)
        .unwrap();
    store
        .set_password(&uid, "OnlyLettersPassword", NOW)
        .unwrap();

    let established_at = LogicalInstant::from_unix_seconds(10);
    store
        .verify_password("user@example.com", "OnlyLettersPassword", established_at)
        .unwrap();
    store.set_password_policy(strict(true));
    let before = store.user(&uid).cloned().unwrap();

    let refused_at = LogicalInstant::from_unix_seconds(20);
    assert!(matches!(
        store.verify_password_with_policy("user@example.com", "OnlyLettersPassword", refused_at),
        Err(AuthError::PasswordPolicyViolation(_))
    ));
    assert_eq!(store.user(&uid), Some(&before));
}

#[test]
fn signin_checks_credentials_before_forced_policy_rejection() {
    let mut store = store();
    let uid = store
        .create_user(NewUser::email("user@example.com"), NOW)
        .unwrap();
    store
        .set_password(&uid, "OnlyLettersPassword", NOW)
        .unwrap();
    store.set_password_policy(strict(true));

    assert_eq!(
        store.verify_password_with_policy("user@example.com", "WrongPassword", NOW),
        Err(AuthError::InvalidPassword)
    );
    assert_eq!(store.user(&uid).unwrap().last_sign_in_at, None);
}
