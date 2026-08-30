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

use fireemu_adapter_functions::runtime::FunctionsRuntime;
use fireemu_adapter_grpc::local::{FirestoreSnapshot, LocalBackend};
use fireemu_adapter_http::control::{SnapshotHook, SnapshotPart, TransitionFailure};
use fireemu_core_auth::store::{AuthRegistry, AuthStore};
use fireemu_core_firestore::text_index::TextIndexCatalog;
use fireemu_core_rules::runtime::LoadedRules;
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_session::fault::{FaultRegistry, FaultState};
use fireemu_core_session::tenancy::Scope;
use fireemu_core_types::determinism::Clock;

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
pub struct Storage(pub Arc<fireemu_adapter_http::storage::StorageState>);

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
        part.downcast_ref::<fireemu_core_storage::store::StorageState>()
            .ok_or_else(|| wrong_shape(self.name()))?;
        self.0
            .store
            .lock()
            .map(|_| ())
            .map_err(|_| poisoned(self.name(), "the object store"))
    }
    fn restore(&self, scope: &Scope, part: &SnapshotPart) -> Result<(), TransitionFailure> {
        let captured = part
            .downcast_ref::<fireemu_core_storage::store::StorageState>()
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
    fn state(&self, scope: &Scope) -> fireemu_core_session::fault::SharedFaults {
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
        part.downcast_ref::<fireemu_core_types::time::LogicalInstant>()
            .ok_or_else(|| wrong_shape(self.name()))?;
        self.0
            .lock()
            .map(|_| ())
            .map_err(|_| poisoned(self.name(), "the clock"))
    }
    fn restore(&self, _: &Scope, part: &SnapshotPart) -> Result<(), TransitionFailure> {
        let at = *part
            .downcast_ref::<fireemu_core_types::time::LogicalInstant>()
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

/// The session's dynamic App Check debug-token registrations (specification section 14).
///
/// Static registrations are canonical configuration and are never captured. A restore
/// *replaces* what the scope holds rather than merging it -- a registration created after the
/// snapshot disappears, one deleted after it returns -- and then a fresh epoch is generated
/// before admissions resume, so no token issued against the replaced state is admitted after
/// it (`AC-LIFE-001`). The captured part is sensitive process memory and is never serialized.
pub struct AppCheck(pub fireemu_core_app_check::AppCheckGate);

impl SnapshotHook for AppCheck {
    fn name(&self) -> &'static str {
        "app check"
    }
    fn capture(&self, scope: &Scope) -> Result<SnapshotPart, TransitionFailure> {
        Ok(Arc::new(
            self.0
                .capture_dynamic_debug_tokens(|p| scope.owns_project(p)),
        ))
    }
    fn validate(&self, _: &Scope, part: &SnapshotPart) -> Result<(), TransitionFailure> {
        part.downcast_ref::<fireemu_core_app_check::DynamicDebugTokens>()
            .map(|_| ())
            .ok_or_else(|| wrong_shape(self.name()))
    }
    fn restore(&self, scope: &Scope, part: &SnapshotPart) -> Result<(), TransitionFailure> {
        let captured = part
            .downcast_ref::<fireemu_core_app_check::DynamicDebugTokens>()
            .ok_or_else(|| wrong_shape(self.name()))?;
        let accept = |p: &str| scope.owns_project(p);
        // Drawn before anything is replaced: a failing CSPRNG read must not leave the scope
        // with restored registrations and a live pre-restore epoch (`INV-APPCHECK-007`).
        let projects = self.0.projects(accept);
        let mut epochs = Vec::with_capacity(projects.len());
        for project in projects {
            epochs.push((
                project,
                crate::random_epoch().map_err(|e| TransitionFailure::new(self.name(), e))?,
            ));
        }
        self.0.restore_dynamic_debug_tokens(accept, captured);
        self.0.set_epochs(&epochs);
        self.0.clear_observations(accept);
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

#[cfg(test)]
mod tests {
    //! `AC-LIFE-001` on the snapshot seam: a restore replaces the dynamic debug-token
    //! registrations of the scope and then rotates its epoch, so no token issued against the
    //! replaced state survives it (specification section 14).

    use super::{AppCheck, Scope, SnapshotHook};
    use crate::sessions::tests::{admits_for, gate, token_for, APP_ID};

    use fireemu_core_types::time::LogicalInstant;

    const AT: LogicalInstant = LogicalInstant::from_unix_seconds(1_788_004_860);

    #[test]
    fn a_restore_replaces_the_dynamic_debug_tokens_and_rotates_the_epoch() {
        let gate = gate();
        let hook = AppCheck(gate.clone());
        let scope = Scope::Project("demo-app".to_owned());

        let kept = gate
            .registry()
            .write()
            .expect("writable")
            .add_debug_token(
                "demo-app",
                APP_ID,
                "before",
                fireemu_core_app_check::DebugTokenDigest::from_bytes([1u8; 32]),
                AT,
            )
            .expect("the app takes a dynamic token");

        let part = hook.capture(&scope).expect("the capture succeeds");
        hook.validate(&scope, &part)
            .expect("the part is this hook's");

        let before = token_for(&gate, "demo-app", APP_ID);
        assert!(admits_for(&gate, "demo-app", &before));

        // After the capture: the registration is deleted and another is created.
        {
            let mut registry = gate.registry().write().expect("writable");
            registry
                .delete_debug_token("demo-app", APP_ID, &kept.id)
                .expect("the captured registration is deleted");
            registry
                .add_debug_token(
                    "demo-app",
                    APP_ID,
                    "after",
                    fireemu_core_app_check::DebugTokenDigest::from_bytes([2u8; 32]),
                    AT,
                )
                .expect("a later registration is created");
        }

        hook.restore(&scope, &part).expect("the restore succeeds");
        assert!(
            gate.registry()
                .read()
                .expect("readable")
                .observed_projects()
                .is_empty(),
            "counters reset with the state they described"
        );

        let restored: Vec<String> = gate
            .registry()
            .read()
            .expect("readable")
            .list_debug_tokens("demo-app", APP_ID)
            .expect("the app still exists")
            .iter()
            .map(|r| r.id.clone())
            .collect();
        assert_eq!(
            restored,
            vec![kept.id],
            "the restore replaces rather than merges"
        );
        assert!(
            !admits_for(&gate, "demo-app", &before),
            "a token from before the restore is refused afterwards"
        );
    }

    #[test]
    fn a_part_of_another_hook_is_refused() {
        let gate = gate();
        let hook = AppCheck(gate);
        let scope = Scope::Project("demo-app".to_owned());
        let foreign: super::SnapshotPart = std::sync::Arc::new(7u8);
        assert!(hook.validate(&scope, &foreign).is_err());
        assert!(hook.restore(&scope, &foreign).is_err());
    }
}
