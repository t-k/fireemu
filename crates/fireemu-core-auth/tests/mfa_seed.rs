//! The project's initial multi-factor configuration (`auth.mfa`): what the store keeps of it and
//! what a reset does with it.

use fireemu_core_auth::mfa::TotpPolicy;
use fireemu_core_auth::mfa_config::{MfaConfigState, MfaProjectConfig, TotpProviderConfig};
use fireemu_core_auth::store::AuthStore;
use fireemu_core_types::determinism::SplitMix64;

fn store() -> AuthStore {
    AuthStore::new("demo-seed", SplitMix64::new(7), TotpPolicy::default())
}

fn totp_on() -> MfaProjectConfig {
    MfaProjectConfig {
        state: MfaConfigState::Enabled,
        phone_sms: false,
        totp: Some(TotpProviderConfig {
            state: MfaConfigState::Enabled,
            adjacent_intervals: Some(1),
        }),
    }
}

fn sms_on() -> MfaProjectConfig {
    MfaProjectConfig {
        state: MfaConfigState::Enabled,
        phone_sms: true,
        totp: None,
    }
}

#[test]
fn a_new_store_has_no_seed_and_mfa_off() {
    let s = store();
    assert_eq!(s.mfa_seed(), None);
    assert_eq!(*s.mfa_config(), MfaProjectConfig::default());
}

#[test]
fn a_seed_is_the_initial_config_and_is_kept_apart_from_it() {
    let mut s = store();
    s.set_mfa_seed(totp_on());
    assert_eq!(s.mfa_seed(), Some(&totp_on()));
    assert_eq!(*s.mfa_config(), totp_on());
    // An Admin update replaces the live config, not the seed.
    s.set_mfa_config(sms_on());
    assert_eq!(*s.mfa_config(), sms_on());
    assert_eq!(s.mfa_seed(), Some(&totp_on()));
}

#[test]
fn restoring_a_seed_replaces_the_live_config_with_it() {
    let mut s = store();
    s.set_mfa_seed(totp_on());
    s.set_mfa_config(MfaProjectConfig::default());
    assert!(s.restore_mfa_seed());
    assert_eq!(*s.mfa_config(), totp_on());
    // A seed that declares MFA off is a seed too: reset returns to it.
    s.set_mfa_seed(MfaProjectConfig::default());
    s.set_mfa_config(sms_on());
    assert!(s.restore_mfa_seed());
    assert_eq!(*s.mfa_config(), MfaProjectConfig::default());
}

#[test]
fn without_a_seed_restoring_leaves_the_live_config_alone() {
    let mut s = store();
    s.set_mfa_config(sms_on());
    assert!(!s.restore_mfa_seed());
    assert_eq!(*s.mfa_config(), sms_on());
}

#[test]
fn wiping_accounts_touches_neither_the_config_nor_the_seed() {
    let mut s = store();
    s.set_mfa_seed(totp_on());
    s.set_mfa_config(sms_on());
    s.clear();
    assert_eq!(*s.mfa_config(), sms_on());
    assert_eq!(s.mfa_seed(), Some(&totp_on()));
}

#[test]
fn a_restored_snapshot_never_carries_its_source_projects_seed() {
    use fireemu_core_auth::store::AuthSnapshot;
    let mut source = AuthStore::new("source", SplitMix64::new(3), TotpPolicy::default());
    source.set_mfa_seed(totp_on());
    let snapshot = AuthSnapshot::capture(&source);
    // Into another namespace: the destination keeps its own seed, or none.
    let mut with_own = AuthStore::new("other", SplitMix64::new(4), TotpPolicy::default());
    with_own.set_mfa_seed(sms_on());
    snapshot.restore_into(&mut with_own);
    assert_eq!(with_own.mfa_seed(), Some(&sms_on()));
    assert_eq!(*with_own.mfa_config(), sms_on());
    let mut without = AuthStore::new("another", SplitMix64::new(5), TotpPolicy::default());
    snapshot.restore_into(&mut without);
    assert_eq!(without.mfa_seed(), None);
    // Into its own namespace, from a store whose seed was declared later: the live seed stays
    // (a seed is the daemon's, not captured data) while the captured config comes back.
    let mut same = AuthStore::new("source", SplitMix64::new(6), TotpPolicy::default());
    same.set_mfa_seed(sms_on());
    snapshot.restore_into(&mut same);
    assert_eq!(same.mfa_seed(), Some(&sms_on()));
    assert_eq!(*same.mfa_config(), totp_on());
}
