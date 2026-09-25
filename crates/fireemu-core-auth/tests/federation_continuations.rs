//! No cloud credentials: bounded local continuation state, time and namespace ownership.
use fireemu_core_auth::federation::{
    MAX_PENDING_IDP_BYTES, MAX_PENDING_IDP_ENTRY_BYTES, MAX_PENDING_IDP_TOKENS,
    PENDING_IDP_TTL_SECONDS,
};
use fireemu_core_auth::mfa::TotpPolicy;
use fireemu_core_auth::store::{AuthSnapshot, AuthStore};
use fireemu_core_types::determinism::SplitMix64;
use fireemu_core_types::time::LogicalInstant;

fn at(seconds: i64) -> LogicalInstant {
    LogicalInstant::from_unix_seconds(seconds)
}
fn store(project: &str, tenant: Option<&str>) -> AuthStore {
    match tenant {
        Some(tenant) => {
            AuthStore::new_tenant(project, tenant, SplitMix64::new(101), TotpPolicy::default())
        }
        None => AuthStore::new(project, SplitMix64::new(101), TotpPolicy::default()),
    }
}
fn issue(store: &mut AuthStore) -> String {
    store
        .remember_idp_sign_in("PRIVATE-ASSERTION".into(), "signed-pin-a".into(), at(10))
        .unwrap()
}

#[test]
fn only_the_bound_authority_can_read_a_live_handle_and_reuse_never_extends_expiry() {
    let mut s = store("demo-a", None);
    let token = issue(&mut s);
    assert!(s
        .pending_idp_sign_in(&token, "fixture-idp-v1", at(10))
        .is_none());
    assert!(s
        .pending_idp_sign_in(&token, "signed-pin-b", at(10))
        .is_none());
    assert!(s
        .pending_idp_sign_in(&token, "signed-pin-a", at(9))
        .is_none());
    for time in [10, 11, 10 + PENDING_IDP_TTL_SECONDS - 1] {
        assert_eq!(
            s.pending_idp_sign_in(&token, "signed-pin-a", at(time)),
            Some("PRIVATE-ASSERTION")
        );
    }
    assert!(s
        .pending_idp_sign_in(&token, "signed-pin-a", at(10 + PENDING_IDP_TTL_SECONDS))
        .is_none());
    assert_eq!(s.pending_idp_count(), 1);
    s.sweep_transient_credentials(at(10 + PENDING_IDP_TTL_SECONDS));
    assert_eq!(s.pending_idp_count(), 0);
}

#[test]
fn identical_seeds_cannot_cross_project_or_tenant_namespaces() {
    let mut stores = [
        store("demo-a", None),
        store("demo-b", None),
        store("demo-a", Some("a")),
        store("demo-a", Some("b")),
    ];
    let tokens: Vec<_> = stores.iter_mut().map(issue).collect();
    for (i, s) in stores.iter().enumerate() {
        for (j, token) in tokens.iter().enumerate() {
            assert_eq!(
                s.pending_idp_sign_in(token, "signed-pin-a", at(10))
                    .is_some(),
                i == j
            );
        }
    }
}

#[test]
fn clear_and_default_snapshot_restore_never_resurrect_raw_idp_credentials() {
    let mut s = store("demo-a", None);
    let first = issue(&mut s);
    let snapshot = AuthSnapshot::capture(&s);
    assert!(!format!("{snapshot:?}").contains("PRIVATE-ASSERTION"));
    s.clear();
    let second = issue(&mut s);
    assert_ne!(first, second);
    snapshot.restore_into(&mut s);
    assert_eq!(s.pending_idp_count(), 0);
    assert!(s
        .pending_idp_sign_in(&first, "signed-pin-a", at(10))
        .is_none());
    assert!(s
        .pending_idp_sign_in(&second, "signed-pin-a", at(10))
        .is_none());
    let after_restore = issue(&mut s);
    assert_ne!(after_restore, first);
    assert_ne!(
        after_restore, second,
        "rewound RNG must not reassign an old capability"
    );
    let mut other = store("demo-other", Some("other"));
    snapshot.restore_into(&mut other);
    assert_eq!(other.pending_idp_count(), 0);
}

#[test]
fn debug_never_serializes_handle_or_original_assertion() {
    let mut s = store("demo-a", None);
    let token = issue(&mut s);
    let text = format!("{s:?}");
    assert!(!text.contains(&token));
    assert!(!text.contains("PRIVATE-ASSERTION"));
    assert!(!text.contains("signed-pin-a"));
}

#[test]
fn no_op_sweeps_share_cache_and_candidate_writes_detach_only_that_registry() {
    let mut live = store("demo-a", None);
    let original = issue(&mut live);
    let mut candidate = live.clone();
    assert_eq!(candidate.transient_registries_shared_with(&live), 7);
    candidate.sweep_transient_credentials(at(11));
    assert_eq!(candidate.transient_registries_shared_with(&live), 7);
    let fresh = issue(&mut candidate);
    assert_eq!(candidate.transient_registries_shared_with(&live), 6);
    assert_eq!(live.pending_idp_count(), 1);
    assert!(live
        .pending_idp_sign_in(&fresh, "signed-pin-a", at(11))
        .is_none());
    assert!(live
        .pending_idp_sign_in(&original, "signed-pin-a", at(11))
        .is_some());
}

#[test]
fn handle_capacity_never_evicts_an_existing_live_credential() {
    let mut s = store("demo-a", None);
    let first = issue(&mut s);
    for _ in 1..MAX_PENDING_IDP_TOKENS {
        issue(&mut s);
    }
    assert_eq!(s.pending_idp_count(), MAX_PENDING_IDP_TOKENS);
    assert!(s
        .remember_idp_sign_in("new".into(), "a".into(), at(10))
        .is_none());
    assert!(s
        .pending_idp_sign_in(&first, "signed-pin-a", at(10))
        .is_some());
    assert!(s
        .remember_idp_sign_in("new".into(), "a".into(), at(10 + PENDING_IDP_TTL_SECONDS))
        .is_some());
    assert_eq!(s.pending_idp_count(), 1);
}

#[test]
fn per_entry_and_total_byte_bounds_include_the_retained_payloads() {
    let mut s = store("demo-a", None);
    assert!(s
        .remember_idp_sign_in("x".repeat(MAX_PENDING_IDP_ENTRY_BYTES), "a".into(), at(10))
        .is_none());
    let before = s.transient_bytes();
    let request = "x".repeat(MAX_PENDING_IDP_ENTRY_BYTES - 32);
    let mut count = 0;
    while s
        .remember_idp_sign_in(request.clone(), "a".into(), at(10))
        .is_some()
    {
        count += 1;
    }
    assert!(count > 0 && count < MAX_PENDING_IDP_TOKENS);
    assert!(s.transient_bytes() - before <= MAX_PENDING_IDP_BYTES as u64);
    assert!(s.transient_bytes() - before >= (count * request.len()) as u64);
}

#[test]
fn invalid_or_overflowing_entries_do_not_advance_the_identifier_stream() {
    let mut s = store("demo-a", None);
    let mut untouched = s.clone();
    for (request, authority, now) in [
        ("", "a", at(10)),
        ("r", "", at(10)),
        ("r", "a", LogicalInstant::MAX),
    ] {
        assert!(s
            .remember_idp_sign_in(request.into(), authority.into(), now)
            .is_none());
    }
    assert_eq!(issue(&mut s), issue(&mut untouched));
}

#[test]
fn matching_public_seeds_cannot_alias_different_cached_assertions_or_authorities() {
    let mut a = store("demo-same", None);
    let mut b = a.clone();
    let mut c = a.clone();
    let first = a
        .remember_idp_sign_in("assertion-a".into(), "signed-pin".into(), at(10))
        .unwrap();
    let other = b
        .remember_idp_sign_in("assertion-b".into(), "signed-pin".into(), at(10))
        .unwrap();
    let fixture = c
        .remember_idp_sign_in("assertion-a".into(), "fixture-idp-v1".into(), at(10))
        .unwrap();
    assert_ne!(first, other);
    assert_ne!(first, fixture);
    assert!(b
        .pending_idp_sign_in(&first, "signed-pin", at(10))
        .is_none());
    assert!(first.len() <= 256);
}

#[test]
fn consistent_export_views_omit_pending_provider_credentials_without_mutating_live_state() {
    use fireemu_core_auth::store::AuthRegistry;
    use std::sync::{Arc, Mutex};
    let live = Arc::new(Mutex::new(store("demo-export", None)));
    let handle = issue(&mut live.lock().unwrap());
    let registry = AuthRegistry::new("demo-export", live.clone());
    let snapshot = registry
        .capture_export_snapshot("demo-export")
        .unwrap()
        .unwrap();
    assert_eq!(snapshot.default_store().pending_idp_count(), 0);
    assert!(!format!("{snapshot:?}").contains("PRIVATE-ASSERTION"));
    assert_eq!(live.lock().unwrap().pending_idp_count(), 1);
    assert!(live
        .lock()
        .unwrap()
        .pending_idp_sign_in(&handle, "signed-pin-a", at(10))
        .is_some());
}
