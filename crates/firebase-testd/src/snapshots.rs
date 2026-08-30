//! Session snapshot parts: one [`SnapshotHook`] per adapter, each capturing a copy of what
//! the session owns and putting it back on restore (spec 14.3, in memory). Shared parts
//! (the clock, rules, functions) belong to the default session only.
//!
//! Every hook is fallible in all three phases of the restore protocol. `validate` says
//! whether the part is this hook's and whether the store can be written, without touching
//! it; `capture` copies the store (the control route also uses it to take the pre-image a
//! failed restore rolls back to); `restore` writes it back. A poisoned lock is reported
//! rather than turned into an empty part: a snapshot that silently captured nothing would
//! wipe the session the next time it was restored.

use std::sync::{Arc, Mutex, RwLock};

use ftd_adapter_functions::runtime::FunctionsRuntime;
use ftd_adapter_grpc::local::{FirestoreSnapshot, LocalBackend};
use ftd_adapter_http::control::{SnapshotHook, SnapshotPart, TransitionFailure};
use ftd_core_auth::store::{AuthRegistry, AuthStore};
use ftd_core_firestore::text_index::TextIndexCatalog;
use ftd_core_rules::runtime::LoadedRules;
use ftd_core_session::clock::VirtualClock;
use ftd_core_session::fault::{FaultRegistry, FaultState};
use ftd_core_session::tenancy::Scope;
use ftd_core_types::determinism::Clock;

/// The failure of a part whose captured value is not the shape the hook stores.
fn wrong_shape(part: &'static str) -> TransitionFailure {
    TransitionFailure::new(part, "the captured part is not this hook's")
}

/// The failure of a part whose store cannot be locked.
fn poisoned(part: &'static str, what: &str) -> TransitionFailure {
    TransitionFailure::new(part, format!("{what} is poisoned"))
}

/// The session's Firestore databases (and the auto-ID generator for the default one).
pub struct Firestore(pub Arc<LocalBackend>);

impl SnapshotHook for Firestore {
    fn name(&self) -> &'static str {
        "firestore"
    }
    fn capture(&self, scope: &Scope) -> Result<SnapshotPart, TransitionFailure> {
        Ok(Arc::new(self.0.snapshot_scope(scope)))
    }
    fn validate(&self, _: &Scope, part: &SnapshotPart) -> Result<(), TransitionFailure> {
        part.downcast_ref::<FirestoreSnapshot>()
            .map(|_| ())
            .ok_or_else(|| wrong_shape(self.name()))
    }
    fn restore(&self, scope: &Scope, part: &SnapshotPart) -> Result<(), TransitionFailure> {
        let snapshot = part
            .downcast_ref::<FirestoreSnapshot>()
            .ok_or_else(|| wrong_shape(self.name()))?;
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
    fn capture(&self, scope: &Scope) -> Result<SnapshotPart, TransitionFailure> {
        let store = self
            .0
            .store
            .lock()
            .map_err(|_| poisoned(self.name(), "the object store"))?;
        Ok(Arc::new(store.capture_buckets(self.owned(scope))))
    }
    fn validate(&self, _: &Scope, part: &SnapshotPart) -> Result<(), TransitionFailure> {
        part.downcast_ref::<ftd_core_storage::store::StorageState>()
            .ok_or_else(|| wrong_shape(self.name()))?;
        self.0
            .store
            .lock()
            .map(|_| ())
            .map_err(|_| poisoned(self.name(), "the object store"))
    }
    fn restore(&self, scope: &Scope, part: &SnapshotPart) -> Result<(), TransitionFailure> {
        let captured = part
            .downcast_ref::<ftd_core_storage::store::StorageState>()
            .ok_or_else(|| wrong_shape(self.name()))?;
        let mut store = self
            .0
            .store
            .lock()
            .map_err(|_| poisoned(self.name(), "the object store"))?;
        store.restore_buckets(self.owned(scope), captured, scope.is_default());
        Ok(())
    }
}

/// The session's users, credentials, codes and tokens.
pub struct Auth(pub Arc<AuthRegistry>);

impl Auth {
    fn store(&self, scope: &Scope) -> Result<Arc<Mutex<AuthStore>>, TransitionFailure> {
        match scope {
            Scope::Project(p) => self.0.store_for(p).ok_or_else(|| {
                TransitionFailure::new("auth", format!("project {p:?} has no reachable Auth store"))
            }),
            Scope::AllExcept(_) => Ok(self.0.default_store()),
        }
    }
}

impl SnapshotHook for Auth {
    fn name(&self) -> &'static str {
        "auth"
    }
    fn capture(&self, scope: &Scope) -> Result<SnapshotPart, TransitionFailure> {
        let store = self.store(scope)?;
        let copy = store
            .lock()
            .map_err(|_| poisoned(self.name(), "the Auth store"))?
            .clone();
        Ok(Arc::new(copy))
    }
    fn validate(&self, scope: &Scope, part: &SnapshotPart) -> Result<(), TransitionFailure> {
        part.downcast_ref::<AuthStore>()
            .ok_or_else(|| wrong_shape(self.name()))?;
        self.store(scope)?
            .lock()
            .map(|_| ())
            .map_err(|_| poisoned(self.name(), "the Auth store"))
    }
    fn restore(&self, scope: &Scope, part: &SnapshotPart) -> Result<(), TransitionFailure> {
        let copy = part
            .downcast_ref::<AuthStore>()
            .ok_or_else(|| wrong_shape(self.name()))?;
        let store = self.store(scope)?;
        let mut store = store
            .lock()
            .map_err(|_| poisoned(self.name(), "the Auth store"))?;
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
    fn capture(&self, scope: &Scope) -> Result<SnapshotPart, TransitionFailure> {
        let copy = self
            .state(scope)
            .lock()
            .map_err(|_| poisoned(self.name(), "the fault state"))?
            .clone();
        Ok(Arc::new(copy))
    }
    fn validate(&self, scope: &Scope, part: &SnapshotPart) -> Result<(), TransitionFailure> {
        part.downcast_ref::<FaultState>()
            .ok_or_else(|| wrong_shape(self.name()))?;
        self.state(scope)
            .lock()
            .map(|_| ())
            .map_err(|_| poisoned(self.name(), "the fault state"))
    }
    fn restore(&self, scope: &Scope, part: &SnapshotPart) -> Result<(), TransitionFailure> {
        let copy = part
            .downcast_ref::<FaultState>()
            .ok_or_else(|| wrong_shape(self.name()))?;
        let state = self.state(scope);
        let mut state = state
            .lock()
            .map_err(|_| poisoned(self.name(), "the fault state"))?;
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
    fn capture(&self, scope: &Scope) -> Result<SnapshotPart, TransitionFailure> {
        let catalog = self
            .0
            .lock()
            .map_err(|_| poisoned(self.name(), "the text index catalog"))?;
        Ok(Arc::new(catalog.extract(|p| scope.owns_project(p))))
    }
    fn validate(&self, _: &Scope, part: &SnapshotPart) -> Result<(), TransitionFailure> {
        part.downcast_ref::<TextIndexCatalog>()
            .ok_or_else(|| wrong_shape(self.name()))?;
        self.0
            .lock()
            .map(|_| ())
            .map_err(|_| poisoned(self.name(), "the text index catalog"))
    }
    fn restore(&self, scope: &Scope, part: &SnapshotPart) -> Result<(), TransitionFailure> {
        let captured = part
            .downcast_ref::<TextIndexCatalog>()
            .ok_or_else(|| wrong_shape(self.name()))?;
        let mut catalog = self
            .0
            .lock()
            .map_err(|_| poisoned(self.name(), "the text index catalog"))?;
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
    fn capture(&self, _: &Scope) -> Result<SnapshotPart, TransitionFailure> {
        let at = self
            .0
            .lock()
            .map_err(|_| poisoned(self.name(), "the clock"))?
            .now();
        Ok(Arc::new(at))
    }
    fn validate(&self, _: &Scope, part: &SnapshotPart) -> Result<(), TransitionFailure> {
        part.downcast_ref::<ftd_core_types::time::LogicalInstant>()
            .ok_or_else(|| wrong_shape(self.name()))?;
        self.0
            .lock()
            .map(|_| ())
            .map_err(|_| poisoned(self.name(), "the clock"))
    }
    fn restore(&self, _: &Scope, part: &SnapshotPart) -> Result<(), TransitionFailure> {
        let at = *part
            .downcast_ref::<ftd_core_types::time::LogicalInstant>()
            .ok_or_else(|| wrong_shape(self.name()))?;
        let mut clock = self
            .0
            .lock()
            .map_err(|_| poisoned(self.name(), "the clock"))?;
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
    fn capture(&self, _: &Scope) -> Result<SnapshotPart, TransitionFailure> {
        let copy = self
            .1
            .read()
            .map_err(|_| poisoned(self.name(), "the ruleset"))?
            .clone();
        Ok(Arc::new(copy))
    }
    fn validate(&self, _: &Scope, part: &SnapshotPart) -> Result<(), TransitionFailure> {
        part.downcast_ref::<LoadedRules>()
            .ok_or_else(|| wrong_shape(self.name()))?;
        self.1
            .write()
            .map(|_| ())
            .map_err(|_| poisoned(self.name(), "the ruleset"))
    }
    fn restore(&self, _: &Scope, part: &SnapshotPart) -> Result<(), TransitionFailure> {
        let rules = part
            .downcast_ref::<LoadedRules>()
            .ok_or_else(|| wrong_shape(self.name()))?;
        let mut slot = self
            .1
            .write()
            .map_err(|_| poisoned(self.name(), "the ruleset"))?;
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
    fn capture(&self, _: &Scope) -> Result<SnapshotPart, TransitionFailure> {
        Ok(Arc::new(()))
    }
    fn validate(&self, _: &Scope, _: &SnapshotPart) -> Result<(), TransitionFailure> {
        Ok(())
    }
    fn restore(&self, _: &Scope, _: &SnapshotPart) -> Result<(), TransitionFailure> {
        self.0.reset();
        Ok(())
    }
}
