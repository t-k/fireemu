//! Deleted refresh credentials retain only rejection identity, never live authority.

use fireemu_core_auth::mfa::TotpPolicy;
use fireemu_core_auth::store::{AuthError, AuthSnapshot, AuthStore, NewUser};
use fireemu_core_types::determinism::SplitMix64;
use fireemu_core_types::time::{LogicalDuration, LogicalInstant};

fn store(project: &str) -> AuthStore {
    AuthStore::new(project, SplitMix64::new(7), TotpPolicy::default())
}

#[test]
fn deleted_refresh_exhaustive_lifecycle_traces_match_rejection_model() {
    #[derive(Clone, Copy)]
    enum Identity {
        Live,
        Deleted,
        Unknown,
    }
    let now = LogicalInstant::from_unix_seconds(1000);
    let mut initial = store("demo-app");
    let uid = initial
        .create_user_with_id(NewUser::anonymous(), Some("same"), now)
        .unwrap();
    let token = initial.issue_refresh_token(&uid, now).unwrap();
    // Exhaust all 4^6 traces: delete, recreate the same UID, revoke, reset.
    for trace in 0..4096_u32 {
        let mut live = initial.clone();
        let mut identity = Identity::Live;
        let mut exists = true;
        let mut steps = trace;
        for _ in 0..6 {
            match steps % 4 {
                0 => {
                    let result = live.delete_user_by_id("same");
                    assert_eq!(result.is_ok(), exists);
                    exists = false;
                    if matches!(identity, Identity::Live) {
                        identity = Identity::Deleted;
                    }
                }
                1 => {
                    let result = live.create_user_with_id(NewUser::anonymous(), Some("same"), now);
                    assert_eq!(result.is_ok(), !exists);
                    exists = true;
                }
                2 => {
                    live.revoke_refresh_tokens(&uid);
                    if matches!(identity, Identity::Live) {
                        identity = Identity::Unknown;
                    }
                }
                _ => {
                    live.clear();
                    exists = false;
                    identity = Identity::Unknown;
                }
            }
            let expected = match identity {
                Identity::Live => Ok(uid.clone()),
                Identity::Deleted => Err(AuthError::UserNotFound),
                Identity::Unknown => Err(AuthError::InvalidRefreshToken),
            };
            assert_eq!(live.redeem_refresh_token(&token), expected, "trace {trace}");
            assert_eq!(
                live.owns_refresh_token(&token),
                !matches!(identity, Identity::Unknown)
            );
            steps /= 4;
        }
    }
}

#[test]
fn deleted_refresh_never_revives_on_uid_recreation_and_reset_forgets_it() {
    let now = LogicalInstant::from_unix_seconds(1000);
    let mut live = store("demo-app");
    let uid = live
        .create_user_with_id(NewUser::anonymous(), Some("same"), now)
        .unwrap();
    let token = live.issue_refresh_token(&uid, now).unwrap();
    assert_eq!(live.redeem_refresh_token(&token), Ok(uid.clone()));
    let before = live.clone();
    live.delete_user_by_id(uid.as_str()).unwrap();
    assert!(live.owns_refresh_token(&token));
    assert_eq!(
        live.redeem_refresh_token(&token),
        Err(AuthError::UserNotFound)
    );
    assert!(live.refresh_session(&token).is_err());
    assert!(live.stateless_refresh_session(&token).is_err());
    assert_eq!(before.redeem_refresh_token(&token), Ok(uid.clone()));
    assert!(live.transient_bytes() >= 32);
    live.sweep_transient_credentials(
        now.checked_add(LogicalDuration::from_seconds(864000))
            .unwrap(),
    );
    assert_eq!(
        live.redeem_refresh_token(&token),
        Err(AuthError::UserNotFound)
    );
    let recreated = live
        .create_user_with_id(NewUser::anonymous(), Some("same"), now)
        .unwrap();
    assert_eq!(
        live.redeem_refresh_token(&token),
        Err(AuthError::UserNotFound)
    );
    let fresh = live.issue_refresh_token(&recreated, now).unwrap();
    assert_ne!(fresh, token);
    assert_eq!(live.redeem_refresh_token(&fresh), Ok(recreated));
    assert_eq!(
        live.redeem_refresh_token(&(token.clone() + "x")),
        Err(AuthError::InvalidRefreshToken)
    );
    assert!(!live.owns_refresh_token(&(token.clone() + "x")));
    let snapshot = AuthSnapshot::capture(&live);
    let mut same = store("demo-app");
    snapshot.restore_into(&mut same);
    assert_eq!(
        same.redeem_refresh_token(&token),
        Err(AuthError::UserNotFound)
    );
    let mut other = store("other-project");
    snapshot.restore_into(&mut other);
    assert_eq!(
        other.redeem_refresh_token(&token),
        Err(AuthError::InvalidRefreshToken)
    );
    let mut tenant = AuthStore::new_tenant(
        "demo-app",
        "other-tenant",
        SplitMix64::new(9),
        TotpPolicy::default(),
    );
    snapshot.restore_into(&mut tenant);
    assert!(!tenant.owns_refresh_token(&token));
    assert_eq!(
        tenant.redeem_refresh_token(&token),
        Err(AuthError::InvalidRefreshToken)
    );
    live.clear();
    assert!(!live.owns_refresh_token(&token));
    assert_eq!(
        live.redeem_refresh_token(&token),
        Err(AuthError::InvalidRefreshToken)
    );
    assert_eq!(live.transient_bytes(), 0);
}
