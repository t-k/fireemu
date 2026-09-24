//! Bearer credentials (action codes, verification sessions, refresh tokens, TOTP secrets) draw
//! from the installed credential entropy once the daemon installs the OS CSPRNG, keeping their
//! shapes. Identifiers that are not secrets keep the deterministic seeded stream.
//!
//! The source is process-wide and can be installed once, so this file holds one test.

use fireemu_core_auth::mfa::TotpPolicy;
use fireemu_core_auth::store::{
    install_credential_entropy, AuthStore, NewUser, OobRequestType, VerificationPurpose,
};
use fireemu_core_types::determinism::SplitMix64;
use fireemu_core_types::time::LogicalInstant;

fn t0() -> LogicalInstant {
    LogicalInstant::from_unix_seconds(1_788_004_860)
}

fn fill_with_5a(dest: &mut [u8]) -> bool {
    dest.fill(0x5a);
    true
}

fn store(seed: u64) -> AuthStore {
    AuthStore::new("demo-app", SplitMix64::new(seed), TotpPolicy::default())
}

#[test]
fn credentials_draw_from_the_installed_entropy_and_keep_their_shape() {
    // Before installation, a seeded store's credentials repeat with the seed.
    let before = |seed| {
        store(seed)
            .create_oob_code(
                OobRequestType::VerifyEmail,
                "a@example.com",
                None,
                None,
                t0(),
            )
            .unwrap()
    };
    assert_eq!(before(7), before(7));

    assert!(install_credential_entropy(fill_with_5a));
    assert!(!install_credential_entropy(fill_with_5a), "installed once");

    let mut s = store(7);
    let code = s
        .create_oob_code(
            OobRequestType::VerifyEmail,
            "a@example.com",
            None,
            None,
            t0(),
        )
        .unwrap();
    assert_eq!(code, "oob-5a5a5a5a5a5a5a5a0001");
    let session = s
        .send_verification_code("+16505550101", VerificationPurpose::SignIn, t0())
        .unwrap()
        .session_info;
    assert_eq!(session, "sms-5a5a5a5a5a5a5a5a0002");

    let uid = s
        .create_user_with_id(NewUser::email("u@example.com"), Some("u"), t0())
        .unwrap();
    let token = s.issue_refresh_token(&uid, t0()).unwrap();
    assert!(token.starts_with("rt1.8.0.demo-app."), "{token}");
    assert!(token.ends_with(".5a5a5a5a5a5a5a5a0003"), "{token}");

    // A generated account id is not a secret: it keeps the seeded stream and its shape.
    let generated = s.create_user(NewUser::anonymous(), t0()).unwrap();
    assert_eq!(generated.as_str().len(), 28);
    assert!(!generated.as_str().contains("5a5a"));

    let enrolled = s
        .create_user_with_id(NewUser::email("totp@example.com"), Some("totp"), t0())
        .unwrap();
    let material = s.start_totp_enrollment(&enrolled, t0()).unwrap();
    assert_eq!(material.secret_for_test(), &[0x5a; 20]);
}
