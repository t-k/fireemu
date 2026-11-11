//! Regression tests for critical authentication mutation gaps.

use fireemu_core_auth::jwt::{
    base64url_decode, base64url_encode, encode_unsigned,
    verify_firestore_rules_token_of_removed_tenant, IdTokenSigner, SignatureCheckedToken,
    TokenAcceptance,
};
use fireemu_core_auth::mfa::{
    ImportedFactorError, MfaState, PendingSignInContext, PendingSignInCredentials, TotpFactor,
    TotpPolicy, TotpSecret, MAX_FACTORS_PER_USER,
};
use fireemu_core_auth::store::{AuthStore, NewUser, RemovedTenantEpochs};
use fireemu_core_auth::totp::{time_step, TotpParams};
use fireemu_core_types::determinism::SplitMix64;
use fireemu_core_types::time::LogicalInstant;
use proptest::prelude::*;

fn factor(id: &str, step: Option<u64>) -> TotpFactor {
    TotpFactor {
        mfa_enrollment_id: id.into(),
        display_name: None,
        secret: TotpSecret::new(vec![1, 2, 3]),
        enrolled_at: LogicalInstant::UNIX_EPOCH,
        last_accepted_step: step,
    }
}

proptest! {
    #[test]
    fn base64url_round_trips(bytes in proptest::collection::vec(any::<u8>(), 0..128)) {
        prop_assert_eq!(base64url_decode(&base64url_encode(&bytes)).unwrap(), bytes);
    }
}

#[test]
fn base64url_rejects_one_mod_four() {
    assert!(base64url_decode("A").is_err());
    assert!(base64url_decode("AAAAA").is_err());
    assert_eq!(base64url_decode("AA").unwrap(), vec![0]);
}

struct Signer;
impl IdTokenSigner for Signer {
    fn alg(&self) -> &'static str {
        "test"
    }
    fn kid(&self) -> &'static str {
        "key"
    }
    fn sign(&self, _: &[u8]) -> Vec<u8> {
        Vec::new()
    }
    fn verify(&self, _: &[u8], _: &[u8]) -> bool {
        true
    }
    fn public_jwk_json(&self) -> String {
        String::new()
    }
}

#[test]
fn unsigned_signature_reuse_and_debug_output() {
    let mut store = AuthStore::new("demo-app", SplitMix64::new(1), TotpPolicy::default());
    let now = LogicalInstant::from_unix_seconds(1000);
    let uid = store
        .create_user(NewUser::email("a@example.test"), now)
        .unwrap();
    let token = encode_unsigned(&store.id_token_claims(&uid, None, now).unwrap());
    let checked = SignatureCheckedToken::decode(&token, &store).unwrap();
    assert!(checked.can_reuse_signature_for(&token, &store));
    assert!(!checked.can_reuse_signature_for("other", &store));
    assert_eq!(format!("{checked:?}"), "SignatureCheckedToken { .. }");
    let signer: &dyn IdTokenSigner = &Signer;
    assert_eq!(format!("{signer:?}"), "IdTokenSigner(test kid key)");
}

#[test]
fn removed_tenant_epoch_depends_on_matching_project_epoch() {
    let mut store = AuthStore::new("demo-app", SplitMix64::new(1), TotpPolicy::default());
    let now = LogicalInstant::from_unix_seconds(1000);
    let uid = store
        .create_user(NewUser::email("a@example.test"), now)
        .unwrap();
    let mut claims = store.id_token_claims(&uid, None, now).unwrap();
    claims.firebase.tenant = Some("tenant".into());
    claims.firebase.fireemu_session_epoch = Some("tenant-epoch".into());
    let token = encode_unsigned(&claims);
    let matching = RemovedTenantEpochs {
        project: None,
        tenant: Some("tenant-epoch".into()),
    };
    let mismatching = RemovedTenantEpochs {
        project: Some("old-project".into()),
        tenant: Some("different".into()),
    };
    assert!(verify_firestore_rules_token_of_removed_tenant(
        &token,
        &store,
        now,
        TokenAcceptance::Verified,
        None,
        Some(&matching)
    )
    .is_ok());
    assert!(verify_firestore_rules_token_of_removed_tenant(
        &token,
        &store,
        now,
        TokenAcceptance::Verified,
        None,
        Some(&mismatching)
    )
    .is_ok());
    let wrong = RemovedTenantEpochs {
        project: None,
        tenant: Some("different".into()),
    };
    assert!(verify_firestore_rules_token_of_removed_tenant(
        &token,
        &store,
        now,
        TokenAcceptance::Verified,
        None,
        Some(&wrong)
    )
    .is_err());
}

#[test]
fn factor_limit_rebinding_and_replay_reset() {
    let mut state = MfaState::default();
    let factors: Vec<_> = (0..MAX_FACTORS_PER_USER)
        .map(|i| factor(&format!("id-{i}"), Some(3)))
        .collect();
    state.import_factors(factors.clone(), vec![]).unwrap();
    assert!(state.has_factor("id-0"));
    assert!(!state.has_factor("absent"));
    let mut too_many = factors.clone();
    too_many.push(factor("extra", None));
    assert_eq!(
        state.import_factors(too_many, vec![]),
        Err(ImportedFactorError::TooMany)
    );
    assert!(!ImportedFactorError::TooMany.to_string().is_empty());
    let live = state.clone();
    state.detach_totp_secrets();
    assert_eq!(state.rebind_totp_secrets(&live), 0);
    assert_eq!(
        state.totp_factors()[0].secret.expose_for_enrollment(),
        &[1, 2, 3]
    );
    assert_eq!(state.rebind_totp_secrets(&MfaState::default()), 0);
    state.reset_replay_state_for_test();
    assert!(state
        .totp_factors()
        .iter()
        .all(|f| f.last_accepted_step.is_none()));
    let mut subset = MfaState::default();
    subset
        .import_factors(vec![factor("id-1", Some(5))], vec![])
        .unwrap();
    state.detach_totp_secrets();
    assert_eq!(state.rebind_totp_secrets(&subset), MAX_FACTORS_PER_USER - 1);
    assert_eq!(state.totp_factors()[0].mfa_enrollment_id, "id-1");
    subset.detach_totp_secrets();
    state.detach_totp_secrets();
    assert_eq!(state.rebind_totp_secrets(&subset), 1);
    assert!(state.totp_factors().is_empty());
}

#[test]
fn pending_credentials_getters_and_context_preserve_values() {
    let credentials = PendingSignInCredentials::new(
        Some("access".into()),
        Some("identity".into()),
        Some("refresh".into()),
    );
    assert_eq!(credentials.access_token(), Some("access"));
    assert_eq!(credentials.id_token(), Some("identity"));
    assert_eq!(credentials.refresh_token(), Some("refresh"));
    let debug = format!("{credentials:?}");
    assert!(debug.contains("[redacted]"));
    assert!(!debug.contains("identity"));
    let empty = PendingSignInCredentials::default();
    assert_eq!(
        (
            empty.access_token(),
            empty.id_token(),
            empty.refresh_token()
        ),
        (None, None, None)
    );
    assert!(PendingSignInContext::new(None, true, None).is_new_user());
    assert!(!PendingSignInContext::new(None, false, None).is_new_user());
}

#[test]
fn time_step_clamps_nonpositive_time_and_zero_period() {
    let normal = TotpParams {
        period_seconds: 30,
        digits: 6,
    };
    let zero = TotpParams {
        period_seconds: 0,
        digits: 6,
    };
    assert_eq!(time_step(&normal, LogicalInstant::from_unix_seconds(-1)), 0);
    assert_eq!(time_step(&normal, LogicalInstant::from_unix_seconds(60)), 2);
    assert_eq!(time_step(&zero, LogicalInstant::from_unix_seconds(60)), 0);
}
