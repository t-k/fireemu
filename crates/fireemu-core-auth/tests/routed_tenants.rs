//! A compatibility-routed project (the emulator profile's namespace for an unknown project id)
//! holds tenants as any project does, and a declaration stored on the registry is applied once to
//! each routed project when it is installed.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use fireemu_core_auth::mfa::TotpPolicy;
use fireemu_core_auth::store::{
    AuthRegistry, AuthStore, NewProjectSeed, RoutedStoreInstall, TenantMetadata,
    TenantMetadataPatch,
};
use fireemu_core_types::determinism::SplitMix64;

fn registry() -> AuthRegistry {
    let default = Arc::new(Mutex::new(AuthStore::new(
        "demo-app",
        SplitMix64::new(1),
        TotpPolicy::default(),
    )));
    AuthRegistry::new("demo-app", default)
}

fn install(registry: &AuthRegistry, project: &str) -> RoutedStoreInstall {
    let candidate = registry
        .routed_candidate(project)
        .expect("the project id is valid");
    registry.install_routed(project, Arc::new(Mutex::new(candidate)))
}

#[test]
fn a_routed_project_holds_tenants_that_a_default_scope_reset_drops() {
    let registry = registry();
    assert!(matches!(
        install(&registry, "demo-routed"),
        RoutedStoreInstall::Installed(_)
    ));
    // Every creation site takes the routed project as a parent.
    assert!(registry
        .ensure_tenant("demo-routed", "made-on-the-way")
        .is_some());
    let (generated, _, _) = registry
        .create_tenant_with_password_policy(
            "demo-routed",
            TenantMetadata::default(),
            TenantMetadataPatch::default(),
            None,
        )
        .expect("a tenant is created");
    assert!(registry
        .create_tenant_with_id(
            "demo-routed",
            "acme-x7k2q",
            TenantMetadata {
                display_name: Some("acme".to_owned()),
                ..TenantMetadata::default()
            },
            TenantMetadataPatch::default(),
            None,
        )
        .is_some());
    let mut listed = registry.tenants("demo-routed");
    listed.sort();
    let mut expected = vec![
        "made-on-the-way".to_owned(),
        generated,
        "acme-x7k2q".to_owned(),
    ];
    expected.sort();
    assert_eq!(listed, expected);
    // The tenants are the routed project's own: the same id in another project is another tenant.
    assert!(registry.tenants("demo-app").is_empty());
    assert!(registry
        .tenant_store("demo-app", "made-on-the-way")
        .is_none());
    let store = registry
        .tenant_store("demo-routed", "made-on-the-way")
        .unwrap();
    assert_eq!(store.lock().unwrap().project_id(), "demo-routed");
    // A default-scope reset drops the routed project and everything it held.
    let reset = registry.prepare_default_scope_reset().unwrap();
    registry.apply_default_scope_reset(&reset).unwrap();
    assert!(registry.tenants("demo-routed").is_empty());
    assert!(registry.routed_store_for("demo-routed").is_none());
}

#[test]
fn an_import_candidate_for_a_tenant_takes_a_routed_project_as_its_parent() {
    let registry = registry();
    assert!(registry
        .tenant_import_candidate("demo-routed", "t")
        .is_none());
    assert!(matches!(
        install(&registry, "demo-routed"),
        RoutedStoreInstall::Installed(_)
    ));
    let candidate = registry
        .tenant_import_candidate("demo-routed", "t")
        .expect("a routed project is a parent");
    assert_eq!(candidate.project_id(), "demo-routed");
    assert_eq!(candidate.tenant_id(), Some("t"));
}

#[test]
fn a_project_the_registry_does_not_hold_still_takes_no_tenant() {
    let registry = registry();
    assert!(registry.ensure_tenant("demo-unknown", "t").is_none());
    assert!(registry
        .create_tenant_with_password_policy(
            "demo-unknown",
            TenantMetadata::default(),
            TenantMetadataPatch::default(),
            None,
        )
        .is_none());
    assert!(registry.tenants("demo-unknown").is_empty());
}

#[derive(Debug)]
struct CountingSeed {
    applied: Mutex<Vec<String>>,
    calls: AtomicUsize,
}

impl NewProjectSeed for CountingSeed {
    fn apply(&self, registry: &AuthRegistry, project: &str) -> Result<(), String> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.applied.lock().unwrap().push(project.to_owned());
        // The seed takes the project's own gate and creates tenants, as the declaration does: it
        // runs with no registry lock and no gate held.
        registry
            .ensure_tenant(project, "seeded")
            .map(|_| ())
            .ok_or_else(|| "the project is gone".to_owned())
    }
}

#[test]
fn a_stored_declaration_is_applied_once_to_each_project_when_it_is_installed() {
    let registry = registry();
    let seed = Arc::new(CountingSeed {
        applied: Mutex::new(Vec::new()),
        calls: AtomicUsize::new(0),
    });
    registry.set_new_project_tenant_seed(seed.clone());
    assert!(matches!(
        install(&registry, "demo-routed"),
        RoutedStoreInstall::Installed(_)
    ));
    // Installed, not yet applied: applying is a step of its own, after the caller's locks.
    assert_eq!(seed.calls.load(Ordering::SeqCst), 0);
    registry.apply_pending_project_seeds().unwrap();
    assert_eq!(*seed.applied.lock().unwrap(), ["demo-routed"]);
    assert_eq!(registry.tenants("demo-routed"), ["seeded"]);
    // Nothing is pending any more, and a second install of the same project seeds nothing.
    registry.apply_pending_project_seeds().unwrap();
    assert!(matches!(
        install(&registry, "demo-routed"),
        RoutedStoreInstall::Existing(_)
    ));
    registry.apply_pending_project_seeds().unwrap();
    assert_eq!(seed.calls.load(Ordering::SeqCst), 1);
    // Another project is seeded on its own install; the default project never is.
    assert!(matches!(
        install(&registry, "demo-second"),
        RoutedStoreInstall::Installed(_)
    ));
    registry.apply_pending_project_seeds().unwrap();
    assert_eq!(seed.calls.load(Ordering::SeqCst), 2);
    assert!(registry.tenants("demo-app").is_empty());
    // After a default-scope reset the routed projects are gone, and their next install seeds again.
    let reset = registry.prepare_default_scope_reset().unwrap();
    registry.apply_default_scope_reset(&reset).unwrap();
    registry.apply_pending_project_seeds().unwrap();
    assert_eq!(seed.calls.load(Ordering::SeqCst), 2);
    assert!(matches!(
        install(&registry, "demo-routed"),
        RoutedStoreInstall::Installed(_)
    ));
    registry.apply_pending_project_seeds().unwrap();
    assert_eq!(seed.calls.load(Ordering::SeqCst), 3);
}

#[test]
fn concurrent_installs_of_one_project_seed_it_once_and_nothing_deadlocks() {
    let registry = Arc::new(registry());
    let seed = Arc::new(CountingSeed {
        applied: Mutex::new(Vec::new()),
        calls: AtomicUsize::new(0),
    });
    registry.set_new_project_tenant_seed(seed.clone());
    let installed = Arc::new(AtomicUsize::new(0));
    let threads: Vec<_> = (0..8)
        .map(|_| {
            let registry = registry.clone();
            let installed = installed.clone();
            std::thread::spawn(move || {
                if let Some(candidate) = registry.routed_candidate("demo-routed") {
                    if matches!(
                        registry.install_routed("demo-routed", Arc::new(Mutex::new(candidate))),
                        RoutedStoreInstall::Installed(_)
                    ) {
                        installed.fetch_add(1, Ordering::SeqCst);
                    }
                }
                registry.apply_pending_project_seeds().unwrap();
            })
        })
        .collect();
    for thread in threads {
        thread.join().unwrap();
    }
    assert_eq!(installed.load(Ordering::SeqCst), 1);
    assert_eq!(seed.calls.load(Ordering::SeqCst), 1);
    assert_eq!(registry.tenants("demo-routed"), ["seeded"]);
}

#[derive(Debug)]
struct FailingSeed(Mutex<Vec<String>>);

impl NewProjectSeed for FailingSeed {
    fn apply(&self, _: &AuthRegistry, project: &str) -> Result<(), String> {
        self.0.lock().unwrap().push(project.to_owned());
        Err(format!("cannot seed {project}"))
    }
}

#[test]
fn a_refused_seed_is_reported_after_every_project_was_tried() {
    let registry = registry();
    let seed = Arc::new(FailingSeed(Mutex::new(Vec::new())));
    registry.set_new_project_tenant_seed(seed.clone());
    for project in ["demo-routed", "demo-second"] {
        assert!(matches!(
            install(&registry, project),
            RoutedStoreInstall::Installed(_)
        ));
    }
    let error = registry.apply_pending_project_seeds().unwrap_err();
    assert_eq!(error, "cannot seed demo-routed");
    assert_eq!(*seed.0.lock().unwrap(), ["demo-routed", "demo-second"]);
    // Nothing stays pending for a retry: a project is seeded at its install, once.
    assert!(registry.apply_pending_project_seeds().is_ok());
}

#[test]
fn a_project_dropped_before_its_seed_is_applied_is_skipped() {
    let registry = registry();
    let seed = Arc::new(CountingSeed {
        applied: Mutex::new(Vec::new()),
        calls: AtomicUsize::new(0),
    });
    registry.set_new_project_tenant_seed(seed.clone());
    assert!(matches!(
        install(&registry, "demo-routed"),
        RoutedStoreInstall::Installed(_)
    ));
    let reset = registry.prepare_default_scope_reset().unwrap();
    registry.apply_default_scope_reset(&reset).unwrap();
    // The seed would refuse the project that is gone; skipping it is not an error.
    assert!(registry.apply_pending_project_seeds().is_ok());
    assert_eq!(seed.calls.load(Ordering::SeqCst), 0);
}
