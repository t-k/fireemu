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

fn session_store(project: &str) -> AuthStore {
    AuthStore::new(project, SplitMix64::new(9), TotpPolicy::default())
}

/// A session registered over a routed namespace displaces it together with its tenants (the
/// closed issue session-create-for-routed-auth-store-fails-500-in-emulator-profile).
#[test]
fn a_session_displaces_a_routed_project_with_its_tenants_and_a_rollback_restores_them() {
    let registry = registry();
    assert!(matches!(
        install(&registry, "demo-b"),
        RoutedStoreInstall::Installed(_)
    ));
    assert!(registry.ensure_tenant("demo-b", "kept").is_some());
    let routed = registry.routed_store_for("demo-b").unwrap();
    assert!(registry.register_session("demo-b", session_store("demo-b")));
    // The session starts without the routed namespace's tenants; the routed store is displaced.
    assert!(registry.tenants("demo-b").is_empty());
    assert!(registry.tenant_store("demo-b", "kept").is_none());
    assert!(registry.routed_store_for("demo-b").is_none());
    // Rolled back, the routed namespace and its tenants are what they were.
    assert_eq!(
        registry.rollback_session("demo-b"),
        fireemu_core_auth::store::SessionRegistrationRollback::Restored
    );
    assert!(Arc::ptr_eq(
        &registry.routed_store_for("demo-b").unwrap(),
        &routed
    ));
    assert_eq!(registry.tenants("demo-b"), ["kept"]);
    assert!(registry.tenant_store("demo-b", "kept").is_some());
    // Committed, the displaced tenants are gone for good.
    assert!(registry.register_session("demo-b", session_store("demo-b")));
    assert!(registry.commit_session("demo-b"));
    assert!(registry.tenants("demo-b").is_empty());
    assert!(registry.store_for("demo-b").is_some());
}

#[test]
fn tenants_of_no_routed_project_still_refuse_a_session() {
    let registry = registry();
    assert!(matches!(
        install(&registry, "demo-b"),
        RoutedStoreInstall::Installed(_)
    ));
    assert!(registry.ensure_tenant("demo-b", "kept").is_some());
    // A default-scope reset drops the routed namespace; nothing of it may block a session.
    let reset = registry.prepare_default_scope_reset().unwrap();
    registry.apply_default_scope_reset(&reset).unwrap();
    assert!(registry.register_session("demo-b", session_store("demo-b")));
    // A registered project's own tenants are not displaced by registering it again.
    assert!(registry.commit_session("demo-b"));
    assert!(registry.ensure_tenant("demo-b", "own").is_some());
    assert!(!registry.register_session("demo-b", session_store("demo-b")));
    assert_eq!(registry.tenants("demo-b"), ["own"]);
}

/// A pending seed belongs to the incarnation that was installed: a session that displaced the
/// project, or a reset and a re-install, are not seeded by it.
#[test]
fn a_seed_pending_for_a_displaced_incarnation_is_not_applied_to_its_successor() {
    let registry = registry();
    let seed = Arc::new(CountingSeed {
        applied: Mutex::new(Vec::new()),
        calls: AtomicUsize::new(0),
    });
    registry.set_new_project_tenant_seed(seed.clone());
    assert!(matches!(
        install(&registry, "demo-b"),
        RoutedStoreInstall::Installed(_)
    ));
    assert!(registry.register_session("demo-b", session_store("demo-b")));
    assert!(registry.commit_session("demo-b"));
    registry.apply_pending_project_seeds().unwrap();
    assert_eq!(seed.calls.load(Ordering::SeqCst), 0);
    assert!(registry.tenants("demo-b").is_empty());
}

/// A project registers once: not again while its registration is provisional, nor after it is
/// committed; and the tenants of other projects are no reason to refuse a new one.
#[test]
fn a_session_project_registers_once_whatever_other_projects_hold() {
    let registry = registry();
    assert!(registry
        .ensure_tenant("demo-app", "default-tenant")
        .is_some());
    assert!(matches!(
        install(&registry, "demo-routed"),
        RoutedStoreInstall::Installed(_)
    ));
    assert!(registry
        .ensure_tenant("demo-routed", "routed-tenant")
        .is_some());
    assert!(registry.register_session("demo-x", session_store("demo-x")));
    // Provisional: a second registration is refused.
    assert!(!registry.register_session("demo-x", session_store("demo-x")));
    assert!(registry.commit_session("demo-x"));
    // Committed, with no tenants of its own: still refused.
    assert!(!registry.register_session("demo-x", session_store("demo-x")));
    // The default project's name is never a session.
    assert!(!registry.register_session("demo-app", session_store("demo-app")));
}

/// A tenant created while a session registration is pending belongs to that session: a rollback
/// removes it (a stray tenant would refuse every later session for the project, and no reset
/// clears one), and brings back only the displaced routed namespace's tenants.
#[test]
fn a_rollback_removes_the_tenants_made_while_the_registration_was_pending() {
    let registry = registry();
    // A fresh project id.
    assert!(registry.register_session("demo-f", session_store("demo-f")));
    assert!(registry.ensure_tenant("demo-f", "born-pending").is_some());
    assert_eq!(
        registry.rollback_session("demo-f"),
        fireemu_core_auth::store::SessionRegistrationRollback::Restored
    );
    assert!(registry.tenants("demo-f").is_empty());
    assert!(registry.register_session("demo-f", session_store("demo-f")));
    assert!(registry.commit_session("demo-f"));
    // A displaced routed namespace.
    assert!(matches!(
        install(&registry, "demo-b"),
        RoutedStoreInstall::Installed(_)
    ));
    assert!(registry.ensure_tenant("demo-b", "kept").is_some());
    assert!(registry.register_session("demo-b", session_store("demo-b")));
    assert!(registry
        .create_tenant_with_id(
            "demo-b",
            "born-pending",
            TenantMetadata::default(),
            TenantMetadataPatch {
                allow_duplicate_emails: Some(true),
                ..TenantMetadataPatch::default()
            },
            None
        )
        .is_some());
    assert_eq!(
        registry.rollback_session("demo-b"),
        fireemu_core_auth::store::SessionRegistrationRollback::Restored
    );
    assert_eq!(registry.tenants("demo-b"), ["kept"]);
    // Nor do its runtime settings: a tenant of the same id made now starts clean.
    assert!(registry
        .create_tenant_with_id(
            "demo-b",
            "born-pending",
            TenantMetadata::default(),
            TenantMetadataPatch::default(),
            None
        )
        .is_some());
    let snapshot = registry.capture_export_snapshot("demo-b").unwrap().unwrap();
    assert_eq!(snapshot.tenant_config_override("born-pending"), None);
}

/// A tenant's runtime settings (what a create or a PATCH wrote) move with the tenant: they are
/// dropped when a committed session displaces the routed namespace (a tenant of the same id made
/// afterwards starts clean) and come back with it when the registration rolls back.
#[test]
fn a_displaced_tenants_runtime_settings_are_dropped_on_commit_and_restored_on_rollback() {
    let registry = registry();
    assert!(matches!(
        install(&registry, "demo-b"),
        RoutedStoreInstall::Installed(_)
    ));
    let with_setting = || TenantMetadataPatch {
        allow_duplicate_emails: Some(true),
        ..TenantMetadataPatch::default()
    };
    let setting_of = |project: &str, tenant: &str| {
        registry
            .capture_export_snapshot(project)
            .unwrap()
            .unwrap()
            .tenant_config_override(tenant)
            .and_then(|patch| patch.allow_duplicate_emails)
    };
    assert!(registry
        .create_tenant_with_id(
            "demo-b",
            "kept",
            TenantMetadata::default(),
            with_setting(),
            None
        )
        .is_some());
    assert_eq!(setting_of("demo-b", "kept"), Some(true));
    assert!(registry.register_session("demo-b", session_store("demo-b")));
    assert_eq!(
        registry.rollback_session("demo-b"),
        fireemu_core_auth::store::SessionRegistrationRollback::Restored
    );
    assert_eq!(setting_of("demo-b", "kept"), Some(true));
    assert!(registry.register_session("demo-b", session_store("demo-b")));
    assert!(registry.commit_session("demo-b"));
    assert!(registry
        .create_tenant_with_id(
            "demo-b",
            "kept",
            TenantMetadata::default(),
            TenantMetadataPatch::default(),
            None
        )
        .is_some());
    assert_eq!(setting_of("demo-b", "kept"), None);
}

#[test]
fn a_project_installed_with_a_declaration_has_a_pending_seed_until_it_is_applied() {
    let registry = registry();
    let seed = Arc::new(CountingSeed {
        applied: Mutex::new(Vec::new()),
        calls: AtomicUsize::new(0),
    });
    // Without a declaration nothing is ever pending.
    assert!(matches!(
        install(&registry, "demo-none"),
        RoutedStoreInstall::Installed(_)
    ));
    assert!(!registry.has_pending_project_seeds());
    registry.set_new_project_tenant_seed(seed);
    assert!(matches!(
        install(&registry, "demo-routed"),
        RoutedStoreInstall::Installed(_)
    ));
    assert!(registry.has_pending_project_seeds());
    registry.apply_pending_project_seeds().unwrap();
    assert!(!registry.has_pending_project_seeds());
}
