//! Authorized domains keep their startup declaration separate from live Admin changes.

use fireemu_core_auth::mfa::TotpPolicy;
use fireemu_core_auth::store::{AuthRegistry, AuthSnapshot, AuthStore};
use fireemu_core_types::determinism::SplitMix64;
use std::sync::{Arc, Mutex};

fn store(project: &str) -> AuthStore {
    AuthStore::new(project, SplitMix64::new(7), TotpPolicy::default())
}

fn domains(host: &str) -> Vec<String> {
    vec![host.to_owned()]
}

fn patch(store: &mut AuthStore, hosts: Vec<String>) {
    let mut config = store.sign_in_config().clone();
    config.authorized_domains = Some(hosts);
    store.set_sign_in_config(config).unwrap();
}

#[test]
fn authorized_domains_seed_is_independent_of_live_config_and_restores_only_its_field() {
    let mut s = store("demo-app");
    assert_eq!(s.authorized_domains_seed(), None);
    assert!(!s.restore_authorized_domains_seed());
    s.set_authorized_domains_seed(domains("seed.test")).unwrap();
    assert_eq!(s.authorized_domains(), domains("seed.test"));
    patch(&mut s, domains("live.test"));
    let mut config = s.sign_in_config().clone();
    config.email_enabled = false;
    config.anonymous_enabled = false;
    config
        .test_phone_numbers
        .insert("+16505550101".to_owned(), "any code".to_owned());
    s.set_sign_in_config(config.clone()).unwrap();
    assert_eq!(s.authorized_domains_seed(), Some(&domains("seed.test")));
    assert!(s.restore_authorized_domains_seed());
    config.authorized_domains = Some(domains("seed.test"));
    assert_eq!(s.sign_in_config(), &config);
    s.set_authorized_domains_seed(vec![]).unwrap();
    patch(&mut s, domains("live.test"));
    assert!(s.restore_authorized_domains_seed());
    assert!(s.authorized_domains().is_empty());
}

#[test]
fn authorized_domains_unseeded_restore_and_accounts_clear_preserve_live_list() {
    let mut s = store("demo-app");
    patch(&mut s, domains("live.test"));
    assert!(!s.restore_authorized_domains_seed());
    assert_eq!(s.authorized_domains(), domains("live.test"));
    s.set_authorized_domains_seed(domains("seed.test")).unwrap();
    patch(&mut s, domains("changed.test"));
    s.clear();
    assert_eq!(s.authorized_domains(), domains("changed.test"));
    assert_eq!(s.authorized_domains_seed(), Some(&domains("seed.test")));
}

#[test]
fn authorized_domains_invalid_seed_is_atomic() {
    let mut s = store("demo-app");
    s.set_authorized_domains_seed(domains("seed.test")).unwrap();
    assert!(s.set_authorized_domains_seed(vec![String::new()]).is_err());
    assert_eq!(s.authorized_domains(), domains("seed.test"));
    assert_eq!(s.authorized_domains_seed(), Some(&domains("seed.test")));
}

#[test]
fn authorized_domains_snapshot_keeps_destination_declaration() {
    let mut source = store("source");
    source
        .set_authorized_domains_seed(domains("source.test"))
        .unwrap();
    let snapshot = AuthSnapshot::capture(&source);
    for project in ["source", "other"] {
        for seed in [None, Some(domains("target.test"))] {
            let mut target = store(project);
            if let Some(hosts) = &seed {
                target.set_authorized_domains_seed(hosts.clone()).unwrap();
            }
            let before = target.authorized_domains();
            snapshot.restore_into(&mut target);
            assert_eq!(target.authorized_domains_seed(), seed.as_ref());
            assert_eq!(
                target.authorized_domains(),
                if project == "source" {
                    domains("source.test")
                } else {
                    before
                }
            );
            target.restore_authorized_domains_seed();
            if let Some(hosts) = seed {
                assert_eq!(target.authorized_domains(), hosts);
            }
        }
    }
}

#[test]
fn authorized_domains_routed_projects_use_declared_seed_or_their_own_defaults() {
    let default = Arc::new(Mutex::new(store("demo-app")));
    let registry = AuthRegistry::new("demo-app", default.clone());
    patch(&mut default.lock().unwrap(), domains("live.test"));
    assert_eq!(registry.new_project_authorized_domains_seed(), None);
    let plain = registry.routed_candidate("routed-a").unwrap();
    assert_eq!(plain.authorized_domains_seed(), None);
    assert_eq!(
        plain.authorized_domains(),
        vec!["localhost", "routed-a.firebaseapp.com", "routed-a.web.app"]
    );
    registry.set_new_project_authorized_domains_seed(Some(domains("seed.test")));
    assert_eq!(
        registry.new_project_authorized_domains_seed(),
        Some(domains("seed.test"))
    );
    let candidate = registry.routed_candidate("routed-b").unwrap();
    assert_eq!(candidate.authorized_domains(), domains("seed.test"));
    assert_eq!(
        candidate.authorized_domains_seed(),
        Some(&domains("seed.test"))
    );
    registry.set_new_project_authorized_domains_seed(None);
    assert_eq!(registry.new_project_authorized_domains_seed(), None);
}
