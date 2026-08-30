//! Session snapshot parts: one [`SnapshotHook`] per adapter, each capturing a copy of its
//! state and putting it back on restore (spec 14.3, in memory).

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, RwLock};

use ftd_adapter_functions::runtime::FunctionsRuntime;
use ftd_adapter_grpc::local::LocalBackend;
use ftd_adapter_http::control::{SnapshotHook, SnapshotPart};
use ftd_core_auth::store::AuthStore;
use ftd_core_firestore::store::FirestoreState;
use ftd_core_rules::runtime::LoadedRules;
use ftd_core_session::clock::VirtualClock;
use ftd_core_types::determinism::Clock;

/// Every Firestore database.
pub struct Firestore(pub Arc<LocalBackend>);

impl SnapshotHook for Firestore {
    fn name(&self) -> &'static str {
        "firestore"
    }
    fn capture(&self) -> SnapshotPart {
        Arc::new(self.0.snapshot_databases())
    }
    fn restore(&self, part: &SnapshotPart) -> Result<(), String> {
        let dbs = part
            .downcast_ref::<BTreeMap<(String, String), FirestoreState>>()
            .ok_or("not a Firestore snapshot")?;
        self.0.restore_databases(dbs.clone());
        Ok(())
    }
}

/// Every Storage bucket and object.
pub struct Storage(pub Arc<ftd_adapter_http::storage::StorageState>);

impl SnapshotHook for Storage {
    fn name(&self) -> &'static str {
        "storage"
    }
    fn capture(&self) -> SnapshotPart {
        Arc::new(self.0.store.lock().map_or_else(
            |_| ftd_core_storage::store::StorageState::new(0),
            |s| s.clone(),
        ))
    }
    fn restore(&self, part: &SnapshotPart) -> Result<(), String> {
        let objects = part
            .downcast_ref::<ftd_core_storage::store::StorageState>()
            .ok_or("not a Storage snapshot")?;
        let mut store = self.0.store.lock().map_err(|_| "store poisoned")?;
        *store = objects.clone();
        Ok(())
    }
}

/// Users, credentials, codes and tokens.
pub struct Auth(pub Arc<Mutex<AuthStore>>);

impl SnapshotHook for Auth {
    fn name(&self) -> &'static str {
        "auth"
    }
    fn capture(&self) -> SnapshotPart {
        let store = self.0.lock().map(|s| s.clone()).ok();
        Arc::new(store)
    }
    fn restore(&self, part: &SnapshotPart) -> Result<(), String> {
        let copy = part
            .downcast_ref::<Option<AuthStore>>()
            .ok_or("not an Auth snapshot")?
            .as_ref()
            .ok_or("the Auth snapshot was taken from a poisoned store")?;
        let mut store = self.0.lock().map_err(|_| "auth store poisoned")?;
        *store = copy.clone();
        Ok(())
    }
}

/// The virtual clock (restored even when that moves it backwards).
pub struct SessionClock(pub Arc<Mutex<VirtualClock>>);

impl SnapshotHook for SessionClock {
    fn name(&self) -> &'static str {
        "clock"
    }
    fn capture(&self) -> SnapshotPart {
        Arc::new(self.0.lock().map(|c| c.now()).ok())
    }
    fn restore(&self, part: &SnapshotPart) -> Result<(), String> {
        let at = part
            .downcast_ref::<Option<ftd_core_types::time::LogicalInstant>>()
            .ok_or("not a clock snapshot")?
            .ok_or("the clock snapshot was taken from a poisoned clock")?;
        let mut clock = self.0.lock().map_err(|_| "clock poisoned")?;
        clock.set_allow_backwards(at);
        Ok(())
    }
}

/// A ruleset slot.
pub struct Rules(pub &'static str, pub Arc<RwLock<LoadedRules>>);

impl SnapshotHook for Rules {
    fn name(&self) -> &'static str {
        self.0
    }
    fn capture(&self) -> SnapshotPart {
        Arc::new(self.1.read().map(|r| r.clone()).unwrap_or_default())
    }
    fn restore(&self, part: &SnapshotPart) -> Result<(), String> {
        let rules = part
            .downcast_ref::<LoadedRules>()
            .ok_or("not a rules snapshot")?;
        let mut slot = self.1.write().map_err(|_| "rules poisoned")?;
        *slot = rules.clone();
        Ok(())
    }
}

/// The functions runtime keeps no snapshot state: a restore resets it (queue, schedules and
/// the runner belong to the state that was replaced).
pub struct Functions(pub Arc<FunctionsRuntime>);

impl SnapshotHook for Functions {
    fn name(&self) -> &'static str {
        "functions"
    }
    fn capture(&self) -> SnapshotPart {
        Arc::new(())
    }
    fn restore(&self, _: &SnapshotPart) -> Result<(), String> {
        self.0.reset();
        Ok(())
    }
}
