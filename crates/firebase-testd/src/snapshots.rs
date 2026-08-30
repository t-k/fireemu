//! Session snapshot parts: one [`SnapshotHook`] per adapter, each capturing a copy of what
//! the session owns and putting it back on restore (spec 14.3, in memory). Shared parts
//! (the clock, rules, functions) belong to the default session only.

use std::sync::{Arc, Mutex, RwLock};

use ftd_adapter_functions::runtime::FunctionsRuntime;
use ftd_adapter_grpc::local::{FirestoreSnapshot, LocalBackend};
use ftd_adapter_http::control::{SnapshotHook, SnapshotPart};
use ftd_core_auth::store::{AuthRegistry, AuthStore};
use ftd_core_firestore::text_index::TextIndexCatalog;
use ftd_core_rules::runtime::LoadedRules;
use ftd_core_session::clock::VirtualClock;
use ftd_core_session::fault::{FaultRegistry, FaultState};
use ftd_core_session::tenancy::Scope;
use ftd_core_types::determinism::Clock;

/// The session's Firestore databases (and the auto-ID generator for the default one).
pub struct Firestore(pub Arc<LocalBackend>);

impl SnapshotHook for Firestore {
    fn name(&self) -> &'static str {
        "firestore"
    }
    fn capture(&self, scope: &Scope) -> SnapshotPart {
        Arc::new(self.0.snapshot_scope(scope))
    }
    fn restore(&self, scope: &Scope, part: &SnapshotPart) -> Result<(), String> {
        let snapshot = part
            .downcast_ref::<FirestoreSnapshot>()
            .ok_or("not a Firestore snapshot")?;
        self.0.restore_scope(scope, snapshot);
        Ok(())
    }
}

/// The session's buckets and objects.
pub struct Storage(pub Arc<ftd_adapter_http::storage::StorageState>);

impl Storage {
    fn owned<'a>(&'a self, scope: &'a Scope) -> impl Fn(&str) -> bool + 'a {
        move |bucket| scope.owns_project(&self.0.project_of_bucket(bucket))
    }
}

impl SnapshotHook for Storage {
    fn name(&self) -> &'static str {
        "storage"
    }
    fn capture(&self, scope: &Scope) -> SnapshotPart {
        Arc::new(self.0.store.lock().map_or_else(
            |_| ftd_core_storage::store::StorageState::new(0),
            |s| s.capture_buckets(self.owned(scope)),
        ))
    }
    fn restore(&self, scope: &Scope, part: &SnapshotPart) -> Result<(), String> {
        let captured = part
            .downcast_ref::<ftd_core_storage::store::StorageState>()
            .ok_or("not a Storage snapshot")?;
        let mut store = self.0.store.lock().map_err(|_| "store poisoned")?;
        store.restore_buckets(self.owned(scope), captured, scope.is_default());
        Ok(())
    }
}

/// The session's users, credentials, codes and tokens.
pub struct Auth(pub Arc<AuthRegistry>);

impl Auth {
    fn store(&self, scope: &Scope) -> Option<Arc<Mutex<AuthStore>>> {
        match scope {
            Scope::Project(p) => self.0.store_for(p),
            Scope::AllExcept(_) => Some(self.0.default_store()),
        }
    }
}

impl SnapshotHook for Auth {
    fn name(&self) -> &'static str {
        "auth"
    }
    fn capture(&self, scope: &Scope) -> SnapshotPart {
        let store = self
            .store(scope)
            .and_then(|s| s.lock().map(|s| s.clone()).ok());
        Arc::new(store)
    }
    fn restore(&self, scope: &Scope, part: &SnapshotPart) -> Result<(), String> {
        let copy = part
            .downcast_ref::<Option<AuthStore>>()
            .ok_or("not an Auth snapshot")?
            .as_ref()
            .ok_or("the Auth snapshot was taken from a poisoned or missing store")?;
        let store = self.store(scope).ok_or("the session has no Auth store")?;
        let mut store = store.lock().map_err(|_| "auth store poisoned")?;
        *store = copy.clone();
        Ok(())
    }
}

/// The session's fault plan, counters and history.
pub struct Faults(pub Arc<FaultRegistry>, pub String);

impl Faults {
    fn state(&self, scope: &Scope) -> ftd_core_session::fault::SharedFaults {
        self.0.for_project(scope.project().unwrap_or(&self.1))
    }
}

impl SnapshotHook for Faults {
    fn name(&self) -> &'static str {
        "faults"
    }
    fn capture(&self, scope: &Scope) -> SnapshotPart {
        Arc::new(self.state(scope).lock().map(|f| f.clone()).ok())
    }
    fn restore(&self, scope: &Scope, part: &SnapshotPart) -> Result<(), String> {
        let copy = part
            .downcast_ref::<Option<FaultState>>()
            .ok_or("not a fault plan snapshot")?
            .as_ref()
            .ok_or("the fault plan snapshot was taken from a poisoned state")?;
        let state = self.state(scope);
        let mut state = state.lock().map_err(|_| "fault state poisoned")?;
        *state = copy.clone();
        Ok(())
    }
}

/// The session's text index definitions.
pub struct TextIndexes(pub Arc<Mutex<TextIndexCatalog>>);

impl SnapshotHook for TextIndexes {
    fn name(&self) -> &'static str {
        "text indexes"
    }
    fn capture(&self, scope: &Scope) -> SnapshotPart {
        Arc::new(
            self.0
                .lock()
                .map(|c| c.extract(|p| scope.owns_project(p)))
                .unwrap_or_default(),
        )
    }
    fn restore(&self, scope: &Scope, part: &SnapshotPart) -> Result<(), String> {
        let captured = part
            .downcast_ref::<TextIndexCatalog>()
            .ok_or("not a text index snapshot")?;
        let mut catalog = self.0.lock().map_err(|_| "text index catalog poisoned")?;
        catalog.replace(|p| scope.owns_project(p), captured);
        Ok(())
    }
}

/// The virtual clock (shared; restored even when that moves it backwards).
pub struct SessionClock(pub Arc<Mutex<VirtualClock>>);

impl SnapshotHook for SessionClock {
    fn name(&self) -> &'static str {
        "clock"
    }
    fn shared(&self) -> bool {
        true
    }
    fn capture(&self, _: &Scope) -> SnapshotPart {
        Arc::new(self.0.lock().map(|c| c.now()).ok())
    }
    fn restore(&self, _: &Scope, part: &SnapshotPart) -> Result<(), String> {
        let at = part
            .downcast_ref::<Option<ftd_core_types::time::LogicalInstant>>()
            .ok_or("not a clock snapshot")?
            .ok_or("the clock snapshot was taken from a poisoned clock")?;
        let mut clock = self.0.lock().map_err(|_| "clock poisoned")?;
        clock.set_allow_backwards(at);
        Ok(())
    }
}

/// A ruleset slot (shared).
pub struct Rules(pub &'static str, pub Arc<RwLock<LoadedRules>>);

impl SnapshotHook for Rules {
    fn name(&self) -> &'static str {
        self.0
    }
    fn shared(&self) -> bool {
        true
    }
    fn capture(&self, _: &Scope) -> SnapshotPart {
        Arc::new(self.1.read().map(|r| r.clone()).unwrap_or_default())
    }
    fn restore(&self, _: &Scope, part: &SnapshotPart) -> Result<(), String> {
        let rules = part
            .downcast_ref::<LoadedRules>()
            .ok_or("not a rules snapshot")?;
        let mut slot = self.1.write().map_err(|_| "rules poisoned")?;
        *slot = rules.clone();
        Ok(())
    }
}

/// The functions runtime (shared) keeps no snapshot state: a restore resets it (queue,
/// schedules and the runner belong to the state that was replaced).
pub struct Functions(pub Arc<FunctionsRuntime>);

impl SnapshotHook for Functions {
    fn name(&self) -> &'static str {
        "functions"
    }
    fn shared(&self) -> bool {
        true
    }
    fn capture(&self, _: &Scope) -> SnapshotPart {
        Arc::new(())
    }
    fn restore(&self, _: &Scope, _: &SnapshotPart) -> Result<(), String> {
        self.0.reset();
        Ok(())
    }
}
