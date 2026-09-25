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

use std::sync::{Arc, Mutex};

use fireemu_adapter_functions::runtime::FunctionsRuntime;
use fireemu_adapter_grpc::local::{FirestoreSnapshot, LocalBackend};
use fireemu_adapter_http::control::{SnapshotHook, SnapshotPart, TransitionFailure};
use fireemu_core_auth::store::{
    AuthRegistry, AuthSnapshot, AuthStore, AuthTenantsRollback, AuthTenantsSnapshot,
};
use fireemu_core_firestore::text_index::TextIndexCatalog;
use fireemu_core_rules::runtime::{LoadedRules, RulesetSlot};
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
        self.0
            .restore_scope(scope, snapshot)
            .map_err(|error| TransitionFailure::new(self.name(), error.to_string()))
    }
    fn retained_bytes(&self, part: &SnapshotPart) -> u64 {
        part.downcast_ref::<FirestoreSnapshot>()
            .map_or(0, FirestoreSnapshot::retained_bytes)
    }
}

/// The session's Firestore field configuration (the time-to-live policies).
///
/// It is a separate part from the databases: a restore that brought documents back without
/// their policies would report an expiry configuration the session no longer has.
pub struct FieldConfig(pub Arc<LocalBackend>);

/// One session's time-to-live catalogs, keyed by project and database.
type TtlCatalogs =
    std::collections::BTreeMap<(String, String), fireemu_core_firestore::ttl::TtlCatalog>;

/// One session's field configuration: the time-to-live catalogs and the operations that
/// produced them.
///
/// Both are captured together. A restore that brought the catalogs back but left the
/// operation records in place would keep answering an operation name minted against state
/// the restore has just replaced.
#[derive(Debug, Clone, Default)]
struct FieldConfigSnapshot {
    catalogs: TtlCatalogs,
    operations:
        std::collections::BTreeMap<String, Vec<fireemu_adapter_grpc::local::FieldOperation>>,
}

impl SnapshotHook for FieldConfig {
    fn name(&self) -> &'static str {
        "firestore field config"
    }
    fn capture(&self, scope: &Scope) -> Result<SnapshotPart, TransitionFailure> {
        Ok(Arc::new(FieldConfigSnapshot {
            catalogs: self
                .0
                .ttl_catalogs()
                .into_iter()
                .filter(|((project, _), _)| scope.owns_project(project))
                .collect(),
            operations: self
                .0
                .field_operations_by_project()
                .into_iter()
                .filter(|(project, _)| scope.owns_project(project))
                .collect(),
        }))
    }
    fn validate(&self, _: &Scope, part: &SnapshotPart) -> Result<(), TransitionFailure> {
        part.downcast_ref::<FieldConfigSnapshot>()
            .map(|_| ())
            .ok_or_else(|| wrong_shape(self.name()))
    }
    fn restore(&self, scope: &Scope, part: &SnapshotPart) -> Result<(), TransitionFailure> {
        let captured = part
            .downcast_ref::<FieldConfigSnapshot>()
            .ok_or_else(|| wrong_shape(self.name()))?;
        self.0
            .restore_ttl_catalogs(|project| scope.owns_project(project), &captured.catalogs);
        self.0
            .restore_field_operations(|project| scope.owns_project(project), &captured.operations);
        Ok(())
    }
    fn retained_bytes(&self, part: &SnapshotPart) -> u64 {
        part.downcast_ref::<FieldConfigSnapshot>()
            .map_or(0, |captured| {
                let policies: usize = captured
                    .catalogs
                    .iter()
                    .map(|((project, database), catalog)| {
                        project.len()
                            + database.len()
                            + catalog
                                .iter()
                                .map(|(group, policy)| {
                                    group.as_str().len() + policy.field.canonical().len()
                                })
                                .sum::<usize>()
                    })
                    .sum();
                let operations: usize = captured
                    .operations
                    .values()
                    .flat_map(|records| records.iter())
                    .map(|record| {
                        record.name.len() + record.field.len() + record.response.to_string().len()
                    })
                    .sum();
                u64::try_from(policies + operations).unwrap_or(u64::MAX)
            })
    }
}

/// The session's buckets and objects.
pub struct Storage(pub Arc<fireemu_adapter_http::storage::StorageState>);

impl Storage {
    fn owned<'a>(&'a self, scope: &'a Scope) -> impl Fn(&str) -> bool + 'a {
        move |bucket| scope.owns_project(&self.0.project_of_bucket(bucket))
    }
}

/// The complete global or target-based Storage Rules registry (shared: one table serves
/// every session, like the Firestore ruleset).
pub struct StorageRules(pub Arc<fireemu_adapter_http::storage::StorageRulesRegistry>);

impl SnapshotHook for StorageRules {
    fn name(&self) -> &'static str {
        "storage rules"
    }

    fn shared(&self) -> bool {
        true
    }

    fn capture(&self, _: &Scope) -> Result<SnapshotPart, TransitionFailure> {
        self.0
            .capture()
            .map(|snapshot| Arc::new(snapshot) as SnapshotPart)
            .map_err(|reason| TransitionFailure::new(self.name(), reason))
    }

    fn validate(&self, _: &Scope, part: &SnapshotPart) -> Result<(), TransitionFailure> {
        part.downcast_ref::<fireemu_adapter_http::storage::StorageRulesRegistrySnapshot>()
            .map(|_| ())
            .ok_or_else(|| wrong_shape(self.name()))
    }

    fn restore(&self, _: &Scope, part: &SnapshotPart) -> Result<(), TransitionFailure> {
        let snapshot = part
            .downcast_ref::<fireemu_adapter_http::storage::StorageRulesRegistrySnapshot>()
            .ok_or_else(|| wrong_shape(self.name()))?;
        self.0
            .restore(snapshot)
            .map_err(|reason| TransitionFailure::new(self.name(), reason))
    }

    fn retained_bytes(&self, part: &SnapshotPart) -> u64 {
        part.downcast_ref::<fireemu_adapter_http::storage::StorageRulesRegistrySnapshot>()
            .map_or(
                0,
                fireemu_adapter_http::storage::StorageRulesRegistrySnapshot::retained_bytes,
            )
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
        store.restore_buckets(self.owned(scope), captured);
        Ok(())
    }
    fn retained_bytes(&self, part: &SnapshotPart) -> u64 {
        part.downcast_ref::<fireemu_core_storage::store::StorageState>()
            .map_or(
                0,
                fireemu_core_storage::store::StorageState::retained_blob_bytes,
            )
    }
}

/// The session's users, credentials, codes and tokens -- captured as an
/// [`AuthSnapshot`], which holds no TOTP secret material (`INV-AUTH-003`, ADR-034): enrolled
/// TOTP factors are kept with a detached secret and rebound on restore to the secret the
/// live store still holds; a factor whose secret is gone by then is dropped from the
/// restored account and reported on stderr rather than restored unusable or claimed
/// faithful.
pub struct Auth(pub Arc<AuthRegistry>);

/// The Auth part of a snapshot: the project store and its tenant namespaces (`TENRST-2`).
struct AuthScopeSnapshot {
    project: AuthSnapshot,
    tenants: AuthTenantsSnapshot,
}

#[derive(Clone)]
struct AuthRollback {
    project: AuthStore,
    tenants: AuthTenantsRollback,
}

impl Auth {
    fn store(&self, scope: &Scope) -> Result<Arc<Mutex<AuthStore>>, TransitionFailure> {
        match scope {
            Scope::Project(p) => self.0.store_for(p).ok_or_else(|| {
                TransitionFailure::new("auth", format!("project {p:?} has no reachable Auth store"))
            }),
            Scope::AllExcept(_) => Ok(self.0.default_store()),
        }
    }

    /// The project whose tenant namespaces the scope owns.
    fn tenant_project<'a>(&'a self, scope: &'a Scope) -> &'a str {
        match scope {
            Scope::Project(p) => p,
            Scope::AllExcept(_) => self.0.default_project(),
        }
    }

    fn failure(&self, reason: &'static str) -> TransitionFailure {
        TransitionFailure::new(self.name(), reason)
    }
}

impl SnapshotHook for Auth {
    fn name(&self) -> &'static str {
        "auth"
    }
    fn capture(&self, scope: &Scope) -> Result<SnapshotPart, TransitionFailure> {
        let store = self.store(scope)?;
        let project = {
            let guard = store
                .lock()
                .map_err(|_| poisoned(self.name(), "the Auth store"))?;
            AuthSnapshot::capture(&guard)
        };
        let tenants = self
            .0
            .capture_tenants_snapshot(self.tenant_project(scope))
            .map_err(|reason| self.failure(reason))?;
        debug_assert!(project.holds_no_totp_secret() && tenants.holds_no_totp_secret());
        Ok(Arc::new(AuthScopeSnapshot { project, tenants }))
    }
    fn capture_rollback(&self, scope: &Scope) -> Result<SnapshotPart, TransitionFailure> {
        let store = self.store(scope)?;
        let project = store
            .lock()
            .map_err(|_| poisoned(self.name(), "the Auth store"))?
            .clone();
        let tenants = self
            .0
            .capture_tenants_rollback(self.tenant_project(scope))
            .map_err(|reason| self.failure(reason))?;
        Ok(Arc::new(AuthRollback { project, tenants }))
    }
    fn validate(&self, scope: &Scope, part: &SnapshotPart) -> Result<(), TransitionFailure> {
        part.downcast_ref::<AuthScopeSnapshot>()
            .ok_or_else(|| wrong_shape(self.name()))?;
        self.store(scope)?
            .lock()
            .map(|_| ())
            .map_err(|_| poisoned(self.name(), "the Auth store"))
    }
    fn restore(&self, scope: &Scope, part: &SnapshotPart) -> Result<(), TransitionFailure> {
        let snapshot = part
            .downcast_ref::<AuthScopeSnapshot>()
            .ok_or_else(|| wrong_shape(self.name()))?;
        let store = self.store(scope)?;
        let mut store = store
            .lock()
            .map_err(|_| poisoned(self.name(), "the Auth store"))?;
        let mut dropped = snapshot.project.restore_into(&mut store).totp_factors_dropped;
        drop(store);
        dropped += self
            .0
            .restore_tenants_snapshot(self.tenant_project(scope), &snapshot.tenants)
            .map_err(|reason| self.failure(reason))?
            .totp_factors_dropped;
        if dropped > 0 {
            eprintln!(
                "auth: restored project {} without {dropped} TOTP factor(s) whose secret the store no longer held (default snapshots carry no shared secret; enrol again)",
                snapshot.project.project_id(),
            );
        }
        Ok(())
    }
    fn rollback(&self, scope: &Scope, part: &SnapshotPart) -> Result<(), TransitionFailure> {
        let rollback = part
            .downcast_ref::<AuthRollback>()
            .ok_or_else(|| wrong_shape(self.name()))?;
        let store = self.store(scope)?;
        let mut store = store
            .lock()
            .map_err(|_| poisoned(self.name(), "the Auth store"))?;
        *store = rollback.project.clone();
        drop(store);
        self.0
            .rollback_tenants(self.tenant_project(scope), &rollback.tenants)
            .map_err(|reason| self.failure(reason))
    }
    fn retained_bytes(&self, part: &SnapshotPart) -> u64 {
        part.downcast_ref::<AuthScopeSnapshot>()
            .map_or(0, |snapshot| {
                snapshot
                    .project
                    .retained_bytes()
                    .saturating_add(snapshot.tenants.retained_bytes())
            })
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
    fn retained_bytes(&self, part: &SnapshotPart) -> u64 {
        part.downcast_ref::<FaultState>()
            .map_or(0, FaultState::retained_bytes)
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
    fn retained_bytes(&self, part: &SnapshotPart) -> u64 {
        part.downcast_ref::<TextIndexCatalog>()
            .map_or(0, TextIndexCatalog::retained_bytes)
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
pub struct Rules(pub &'static str, pub Arc<RulesetSlot>);

impl SnapshotHook for Rules {
    fn name(&self) -> &'static str {
        self.0
    }
    fn shared(&self) -> bool {
        true
    }
    fn capture(&self, _: &Scope) -> Result<SnapshotPart, TransitionFailure> {
        let snapshot = self
            .1
            .snapshot()
            .map_err(|_| poisoned(self.name(), "the ruleset"))?;
        let copy = (*snapshot).clone();
        Ok(Arc::new(copy))
    }
    fn validate(&self, _: &Scope, part: &SnapshotPart) -> Result<(), TransitionFailure> {
        part.downcast_ref::<LoadedRules>()
            .ok_or_else(|| wrong_shape(self.name()))?;
        self.1
            .snapshot()
            .map(|_| ())
            .map_err(|_| poisoned(self.name(), "the ruleset"))
    }
    fn restore(&self, _: &Scope, part: &SnapshotPart) -> Result<(), TransitionFailure> {
        let rules = part
            .downcast_ref::<LoadedRules>()
            .ok_or_else(|| wrong_shape(self.name()))?;
        self.1
            .replace_loaded(rules.clone())
            .map(|_| ())
            .map_err(|_| poisoned(self.name(), "the ruleset"))
    }
    fn retained_bytes(&self, part: &SnapshotPart) -> u64 {
        part.downcast_ref::<LoadedRules>()
            .map_or(0, LoadedRules::retained_bytes)
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
    fn retained_bytes(&self, part: &SnapshotPart) -> u64 {
        part.downcast_ref::<fireemu_core_app_check::DynamicDebugTokens>()
            .map_or(
                0,
                fireemu_core_app_check::DynamicDebugTokens::retained_bytes,
            )
    }
}

/// The functions runtime (shared) keeps no snapshot state: a restore resets it (queue,
/// schedules and the runner belong to the state that was replaced).
pub struct Functions {
    runtime: Arc<FunctionsRuntime>,
    publication_gate: Arc<Mutex<()>>,
}

impl Functions {
    /// Builds the shared Functions snapshot hook with the Pub/Sub publication coordinator.
    #[must_use]
    pub fn new(runtime: Arc<FunctionsRuntime>, publication_gate: Arc<Mutex<()>>) -> Self {
        Self {
            runtime,
            publication_gate,
        }
    }
}

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
        let _publication = self
            .publication_gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.runtime.reset();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    //! `AC-LIFE-001` on the snapshot seam: a restore replaces the dynamic debug-token
    //! registrations of the scope and then rotates its epoch, so no token issued against the
    //! replaced state survives it (specification section 14).

    use super::{AppCheck, FieldConfig, LocalBackend, Rules, Scope, SnapshotHook, StorageRules};
    use crate::sessions::tests::{admits_for, gate, token_for, APP_ID};

    use fireemu_core_rules::runtime::{LoadedRules, RulesetSlot};
    use fireemu_core_types::time::LogicalInstant;
    use std::collections::BTreeSet;
    use std::sync::Arc;

    const AT: LogicalInstant = LogicalInstant::from_unix_seconds(1_788_004_860);

    fn backend() -> Arc<LocalBackend> {
        use fireemu_core_firestore::index::{IndexSet, IndexValidationPolicy, PlanningContext};
        use fireemu_core_session::clock::VirtualClock;
        use fireemu_core_types::edition::{FirestoreApiMode, FirestoreEdition};

        let gateway = fireemu_adapter_grpc::gateway::Gateway {
            enforce_limits: true,
            ctx: PlanningContext {
                edition: FirestoreEdition::Standard,
                api_mode: FirestoreApiMode::Native,
                policy: IndexValidationPolicy::Production,
            },
            indexes: IndexSet::default(),
        };
        Arc::new(LocalBackend::new(
            gateway,
            Arc::new(std::sync::Mutex::new(VirtualClock::new(AT))),
            7,
        ))
    }

    fn group(name: &str) -> fireemu_core_types::ids::CollectionId {
        fireemu_core_types::ids::CollectionId::try_new(name).expect("collection")
    }

    fn field(name: &str) -> fireemu_core_firestore::field_path::FieldPath {
        fireemu_core_firestore::field_path::FieldPath::parse(name).expect("field")
    }

    #[test]
    fn a_restore_brings_back_the_time_to_live_policies_the_capture_held() {
        let backend = backend();
        backend
            .enable_ttl(
                "demo-app",
                "(default)",
                group("sessions"),
                field("expiresAt"),
            )
            .expect("enable ttl");
        let hook = FieldConfig(backend.clone());
        let scope = Scope::AllExcept(BTreeSet::new());
        let part = hook.capture(&scope).expect("capture");
        assert!(hook.retained_bytes(&part) > 0);

        assert!(backend.disable_ttl(
            "demo-app",
            "(default)",
            &group("sessions"),
            &field("expiresAt")
        ));
        assert!(backend.ttl_catalog("demo-app", "(default)").is_empty());

        hook.restore(&scope, &part).expect("restore");
        assert_eq!(
            backend
                .ttl_catalog("demo-app", "(default)")
                .state(&group("sessions"), &field("expiresAt")),
            Some(fireemu_core_firestore::ttl::TtlState::Active)
        );
    }

    #[test]
    fn a_restore_replaces_the_operation_records_of_its_scope() {
        let backend = backend();
        let hook = FieldConfig(backend.clone());
        let scope = Scope::AllExcept(BTreeSet::new());
        let before = backend.record_field_operation(
            "demo-app",
            "(default)",
            "a field",
            AT,
            serde_json::Value::Null,
        );
        let part = hook.capture(&scope).expect("capture");

        let after = backend.record_field_operation(
            "demo-app",
            "(default)",
            "another field",
            AT,
            serde_json::Value::Null,
        );
        hook.restore(&scope, &part).expect("restore");

        // The operation minted after the capture no longer resolves; the captured one does.
        assert!(backend.field_operation("demo-app", &before).is_some());
        assert_eq!(backend.field_operation("demo-app", &after), None);
    }

    #[test]
    fn a_restore_of_an_empty_capture_clears_the_policies_of_its_scope() {
        let backend = backend();
        let hook = FieldConfig(backend.clone());
        let scope = Scope::AllExcept(BTreeSet::new());
        let empty = hook.capture(&scope).expect("capture");
        backend
            .enable_ttl(
                "demo-app",
                "(default)",
                group("sessions"),
                field("expiresAt"),
            )
            .expect("enable ttl");
        let operation = backend.record_field_operation(
            "demo-app",
            "(default)",
            "a field",
            AT,
            serde_json::Value::Null,
        );
        hook.restore(&scope, &empty).expect("restore");
        assert!(backend.ttl_catalog("demo-app", "(default)").is_empty());
        assert_eq!(backend.field_operation("demo-app", &operation), None);
    }

    #[test]
    fn named_database_rules_restore_their_own_fresh_generations() {
        const DENY: &str = "service cloud.firestore { match /databases/{database}/documents { match /{document=**} { allow read: if false; } } }";
        const ALLOW: &str = "service cloud.firestore { match /databases/{database}/documents { match /{document=**} { allow read: if true; } } }";

        let staging = Arc::new(RulesetSlot::new(LoadedRules::from_source(DENY).unwrap()));
        let analytics = Arc::new(RulesetSlot::new(LoadedRules::from_source(ALLOW).unwrap()));
        let staging_hook = Rules("named database rules", staging.clone());
        let analytics_hook = Rules("named database rules", analytics.clone());
        let scope = Scope::AllExcept(BTreeSet::new());
        let staging_part = staging_hook.capture(&scope).expect("capture staging rules");
        let analytics_part = analytics_hook
            .capture(&scope)
            .expect("capture analytics rules");
        assert!(staging_hook.retained_bytes(&staging_part) > 0);
        assert!(analytics_hook.retained_bytes(&analytics_part) > 0);

        staging.replace_source(ALLOW).expect("change staging");
        analytics.replace_source(DENY).expect("change analytics");
        staging_hook
            .restore(&scope, &staging_part)
            .expect("restore staging rules");
        analytics_hook
            .restore(&scope, &analytics_part)
            .expect("restore analytics rules");

        let staging = staging.snapshot().expect("staging snapshot");
        let analytics = analytics.snapshot().expect("analytics snapshot");
        assert_eq!(
            (staging.source.as_deref(), staging.generation()),
            (Some(DENY), 2)
        );
        assert_eq!(
            (analytics.source.as_deref(), analytics.generation()),
            (Some(ALLOW), 2)
        );
    }

    /// SNAPSR-1 / SNAPSR-2: the Storage Rules registry is one process-wide table, so the hook
    /// captures and restores all of it whatever the scope. Only the default session may carry
    /// it, or a project session's restore would roll back the rules every other session is
    /// authorizing against.
    #[test]
    fn the_storage_rules_registry_is_a_shared_part_of_the_default_session_only() {
        const DENY: &str = "service firebase.storage { match /b/{bucket}/o { match /{p=**} { allow read: if false; } } }";
        const ALLOW: &str = "service firebase.storage { match /b/{bucket}/o { match /{p=**} { allow read: if true; } } }";

        let slot = Arc::new(RulesetSlot::new(LoadedRules::from_source(DENY).unwrap()));
        let registry = Arc::new(fireemu_adapter_http::storage::StorageRulesRegistry::global(
            slot.clone(),
        ));
        let hook = StorageRules(registry.clone());
        let source = || {
            registry
                .global_snapshot()
                .expect("read the registry")
                .expect("global rules")
                .source
                .clone()
        };

        assert!(
            hook.shared(),
            "the registry is daemon-global, so only the default session's snapshot carries it"
        );

        // SNAPSR-2: the default session's snapshot carries the registry and restores it.
        let default = Scope::AllExcept(BTreeSet::new());
        let part = hook.capture(&default).expect("capture the registry");
        slot.replace_source(ALLOW).expect("change the rules");
        assert_eq!(source().as_deref(), Some(ALLOW));
        hook.restore(&default, &part).expect("restore the registry");
        assert_eq!(source().as_deref(), Some(DENY));

        // SNAPSR-1: the hook is scope-blind. A project session's part would be the same
        // daemon-wide table, and restoring it would change what every other session reads.
        let project = Scope::Project("demo-b".to_owned());
        slot.replace_source(ALLOW).expect("change the rules again");
        let project_part = hook
            .capture(&project)
            .expect("capture under a project scope");
        slot.replace_source(DENY)
            .expect("change the rules once more");
        hook.restore(&project, &project_part)
            .expect("restore under a project scope");
        assert_eq!(
            source().as_deref(),
            Some(ALLOW),
            "the hook restores the whole registry whatever the scope"
        );
    }

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
        assert!(hook.retained_bytes(&part) > 0);

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

    /// `INV-AUTH-003` on the production Auth snapshot hook (ADR-034): a default snapshot of
    /// a store with an enrolled and a pending TOTP factor holds no secret material, a
    /// restore rebinds the enrolled factor to the secret the live store still holds so it
    /// stays usable, and a factor withdrawn between capture and restore is dropped rather
    /// than restored unusable (`AUTH-SNAPSHOT-SECRET-01`, `-02`, `-05`).
    #[test]
    fn a_default_auth_snapshot_holds_no_totp_secret_and_a_restore_rebinds_the_enrolled_factor() {
        use fireemu_core_auth::mfa::TotpPolicy;
        use fireemu_core_auth::store::{AuthRegistry, AuthStore, NewUser};
        use fireemu_core_auth::totp::totp_at;
        use fireemu_core_types::determinism::SplitMix64;
        use std::sync::{Arc, Mutex};

        let store = Arc::new(Mutex::new(AuthStore::new(
            "demo-app",
            SplitMix64::new(11),
            TotpPolicy::default(),
        )));
        let registry = Arc::new(AuthRegistry::new("demo-app", store.clone()));
        let hook = super::Auth(registry);
        let scope = Scope::Project("demo-app".to_owned());
        let t1 = AT
            .checked_add(fireemu_core_types::time::LogicalDuration::from_seconds(90))
            .unwrap();

        // An enrolled factor and a pending enrollment, both carrying a secret.
        let (uid, secret, other, other_secret) = {
            let mut s = store.lock().unwrap();
            let uid = s.create_user(NewUser::email("a@example.com"), AT).unwrap();
            let material = s.start_totp_enrollment(&uid, AT).unwrap();
            let secret = material.secret_for_test().to_vec();
            let code = totp_at(&secret, &s.policy().params(), AT);
            s.finalize_totp_enrollment(&uid, &material.session_id, code, AT)
                .unwrap();
            let other = s.create_user(NewUser::email("b@example.com"), AT).unwrap();
            let pending = s.start_totp_enrollment(&other, AT).unwrap();
            let other_secret = pending.secret_for_test().to_vec();
            (uid, secret, other, other_secret)
        };

        let part = hook.capture(&scope).expect("the capture succeeds");
        hook.validate(&scope, &part)
            .expect("the part is this hook's");
        let snapshot = part
            .downcast_ref::<super::AuthScopeSnapshot>()
            .map(|part| &part.project)
            .expect("an AuthSnapshot");
        assert!(
            snapshot.holds_no_totp_secret(),
            "AUTH-SNAPSHOT-SECRET-01 / -02"
        );
        let debug = format!("{snapshot:?}");
        for material in [&secret, &other_secret] {
            let base32 = fireemu_core_auth::base32::encode(material);
            assert!(
                !debug.contains(&base32),
                "Debug output never carries a secret"
            );
        }

        // After the capture: another user appears, and the first user's factor still works.
        {
            let mut s = store.lock().unwrap();
            s.create_user(NewUser::email("later@example.com"), t1)
                .unwrap();
        }
        hook.restore(&scope, &part).expect("the restore succeeds");
        {
            let mut s = store.lock().unwrap();
            assert!(
                s.user_by_email("later@example.com").is_none(),
                "the restore replaces"
            );
            assert!(
                s.user(&other).unwrap().mfa.pending_count() == 0,
                "a pending enrollment is not part of a default snapshot"
            );
            let pending = s.start_mfa_sign_in(&uid, t1).unwrap();
            let code = totp_at(&secret, &s.policy().params(), t1);
            let enrollment_id = s.user(&uid).unwrap().mfa.totp_factors()[0]
                .mfa_enrollment_id
                .clone();
            s.finalize_mfa_sign_in_for_factor(&uid, &pending, &enrollment_id, code, t1)
                .expect("the restored factor is rebound to the live secret and still verifies");
        }

        // Withdrawn between capture and restore: the factor is dropped, not restored blind.
        {
            let mut s = store.lock().unwrap();
            let id = s.user(&uid).unwrap().mfa.totp_factors()[0]
                .mfa_enrollment_id
                .clone();
            assert!(s.unenroll_factor(&uid, &id).unwrap());
        }
        hook.restore(&scope, &part).expect("the restore succeeds");
        let s = store.lock().unwrap();
        assert!(
            s.user(&uid).unwrap().mfa.is_empty(),
            "AUTH-SNAPSHOT-SECRET-05: no secret, no factor"
        );
    }

    #[test]
    fn auth_hook_rollback_preserves_credentials_valid_before_a_failed_restore() {
        use fireemu_core_auth::jwt::{encode_unsigned, verify_id_token, JwtError};
        use fireemu_core_auth::mfa::TotpPolicy;
        use fireemu_core_auth::store::{AuthRegistry, AuthStore, NewUser};
        use fireemu_core_types::determinism::SplitMix64;
        use std::collections::BTreeMap;
        use std::sync::{Arc, Mutex};

        let default = Arc::new(Mutex::new(AuthStore::new(
            "demo-app",
            SplitMix64::new(1),
            TotpPolicy::default(),
        )));
        let registry = Arc::new(
            AuthRegistry::with_project_numbers_and_lifecycle_incarnation(
                "demo-app",
                default,
                BTreeMap::new(),
                73,
            ),
        );
        assert!(registry.register(
            "worker-alpha",
            AuthStore::new("worker-alpha", SplitMix64::new(2), TotpPolicy::default(),),
        ));
        let store = registry.store_for("worker-alpha").unwrap();
        let uid = store
            .lock()
            .unwrap()
            .create_user_with_id(
                NewUser::email("rollback@example.test"),
                Some("same-user"),
                AT,
            )
            .unwrap();
        let hook = super::Auth(registry);
        let scope = Scope::Project("worker-alpha".to_owned());
        let target = hook.capture(&scope).unwrap();
        store
            .lock()
            .unwrap()
            .create_user(NewUser::email("later@example.test"), AT)
            .unwrap();
        let valid_before_route = {
            let store = store.lock().unwrap();
            encode_unsigned(&store.id_token_claims(&uid, None, AT).unwrap())
        };
        let pre_image = hook.capture_rollback(&scope).unwrap();

        hook.restore(&scope, &target).unwrap();
        assert!(matches!(
            verify_id_token(&valid_before_route, &store.lock().unwrap(), AT),
            Err(JwtError::WrongSessionEpoch { .. })
        ));
        hook.rollback(&scope, &pre_image).unwrap();

        assert!(store
            .lock()
            .unwrap()
            .user_by_email("later@example.test")
            .is_some());
        assert!(verify_id_token(&valid_before_route, &store.lock().unwrap(), AT).is_ok());
    }

    fn tenant_registry() -> std::sync::Arc<fireemu_core_auth::store::AuthRegistry> {
        use fireemu_core_auth::mfa::TotpPolicy;
        use fireemu_core_auth::store::{AuthRegistry, AuthStore};
        use fireemu_core_types::determinism::SplitMix64;
        use std::collections::BTreeMap;
        use std::sync::{Arc, Mutex};

        let default = Arc::new(Mutex::new(AuthStore::new(
            "demo-app",
            SplitMix64::new(1),
            TotpPolicy::default(),
        )));
        let registry = Arc::new(
            AuthRegistry::with_project_numbers_and_lifecycle_incarnation(
                "demo-app",
                default,
                BTreeMap::new(),
                73,
            ),
        );
        assert!(registry.register(
            "worker-alpha",
            AuthStore::new("worker-alpha", SplitMix64::new(2), TotpPolicy::default()),
        ));
        registry
    }

    fn tenant_user(
        registry: &fireemu_core_auth::store::AuthRegistry,
        project: &str,
        tenant: &str,
        email: &str,
    ) -> fireemu_core_auth::store::LocalId {
        registry
            .ensure_tenant(project, tenant)
            .unwrap()
            .lock()
            .unwrap()
            .create_user(fireemu_core_auth::store::NewUser::email(email), AT)
            .unwrap()
    }

    fn tenant_has(
        registry: &fireemu_core_auth::store::AuthRegistry,
        project: &str,
        tenant: &str,
        email: &str,
    ) -> bool {
        registry
            .tenant_store(project, tenant)
            .is_some_and(|store| store.lock().unwrap().user_by_email(email).is_some())
    }

    /// `TENRST-2`: a snapshot restore rolls the scope's tenant namespaces back to the capture.
    /// A tenant user added later is gone, a tenant created later is removed with its
    /// credentials, a tenant deleted later comes back with its users, and another project's
    /// tenants are untouched.
    #[test]
    fn a_restore_rolls_the_scopes_tenant_namespaces_back_to_the_capture() {
        use fireemu_core_auth::store::RefreshTokenStoreMatch;

        let registry = tenant_registry();
        tenant_user(&registry, "worker-alpha", "kept", "kept@example.test");
        tenant_user(&registry, "worker-alpha", "gone", "gone@example.test");
        tenant_user(&registry, "demo-app", "other", "other@example.test");
        let hook = super::Auth(registry.clone());
        let scope = Scope::Project("worker-alpha".to_owned());
        let target = hook.capture(&scope).unwrap();

        tenant_user(&registry, "worker-alpha", "kept", "later@example.test");
        assert!(registry.delete_tenant("worker-alpha", "gone"));
        let added = tenant_user(&registry, "worker-alpha", "added", "added@example.test");
        let added_refresh = registry
            .tenant_store("worker-alpha", "added")
            .unwrap()
            .lock()
            .unwrap()
            .issue_refresh_token(&added, AT)
            .unwrap();
        tenant_user(&registry, "demo-app", "other", "other-later@example.test");

        hook.restore(&scope, &target).unwrap();

        assert_eq!(registry.tenants("worker-alpha"), ["gone", "kept"]);
        assert!(tenant_has(&registry, "worker-alpha", "kept", "kept@example.test"));
        assert!(!tenant_has(&registry, "worker-alpha", "kept", "later@example.test"));
        assert!(tenant_has(&registry, "worker-alpha", "gone", "gone@example.test"));
        assert!(registry.tenant_store("worker-alpha", "added").is_none());
        assert!(matches!(
            registry.store_for_refresh_token(&added_refresh),
            RefreshTokenStoreMatch::NotFound
        ));
        assert!(registry.tenant_metadata("worker-alpha", "gone").is_some());
        assert!(tenant_has(&registry, "demo-app", "other", "other-later@example.test"));
    }

    /// `TENRST-2`: rolling back a restore puts the tenant namespaces back exactly as they were
    /// before it, including a tenant the restore removed and credentials it still holds.
    #[test]
    fn a_rollback_puts_the_tenant_namespaces_back_as_they_were_before_the_restore() {
        use fireemu_core_auth::store::RefreshTokenStoreMatch;

        let registry = tenant_registry();
        tenant_user(&registry, "worker-alpha", "kept", "kept@example.test");
        let hook = super::Auth(registry.clone());
        let scope = Scope::Project("worker-alpha".to_owned());
        let target = hook.capture(&scope).unwrap();

        tenant_user(&registry, "worker-alpha", "kept", "later@example.test");
        let added = tenant_user(&registry, "worker-alpha", "added", "added@example.test");
        let added_refresh = registry
            .tenant_store("worker-alpha", "added")
            .unwrap()
            .lock()
            .unwrap()
            .issue_refresh_token(&added, AT)
            .unwrap();
        let pre_image = hook.capture_rollback(&scope).unwrap();

        hook.restore(&scope, &target).unwrap();
        assert!(registry.tenant_store("worker-alpha", "added").is_none());
        hook.rollback(&scope, &pre_image).unwrap();

        assert_eq!(registry.tenants("worker-alpha"), ["added", "kept"]);
        assert!(tenant_has(&registry, "worker-alpha", "kept", "later@example.test"));
        assert!(tenant_has(&registry, "worker-alpha", "added", "added@example.test"));
        assert!(matches!(
            registry.store_for_refresh_token(&added_refresh),
            RefreshTokenStoreMatch::Unique(_)
        ));
    }

    /// `TENRST-2`, `SNAP-MEM-01`: tenant users count toward the snapshot's retained bytes.
    #[test]
    fn the_auth_hook_counts_tenant_users_in_the_retained_bytes() {
        let registry = tenant_registry();
        let hook = super::Auth(registry.clone());
        let scope = Scope::Project("worker-alpha".to_owned());
        let empty = hook.capture(&scope).unwrap();
        tenant_user(&registry, "worker-alpha", "kept", "kept@example.test");
        let populated = hook.capture(&scope).unwrap();
        assert!(hook.retained_bytes(&populated) > hook.retained_bytes(&empty));
    }

    /// `SNAP-MEM-01`: the production Auth hook reports a positive retained-byte estimate for a
    /// populated store and zero for a part that is not its shape, so the session byte budget
    /// counts the Auth part and never miscounts a foreign one.
    #[test]
    fn the_auth_hook_estimates_retained_bytes_and_ignores_a_foreign_part() {
        use fireemu_core_auth::mfa::TotpPolicy;
        use fireemu_core_auth::store::{AuthRegistry, AuthStore, NewUser};
        use fireemu_core_types::determinism::SplitMix64;
        use std::sync::{Arc, Mutex};

        let store = Arc::new(Mutex::new(AuthStore::new(
            "demo-app",
            SplitMix64::new(3),
            TotpPolicy::default(),
        )));
        let registry = Arc::new(AuthRegistry::new("demo-app", store.clone()));
        let hook = super::Auth(registry);
        let scope = Scope::Project("demo-app".to_owned());

        // No users: zero.
        let empty = hook.capture(&scope).expect("capture");
        assert_eq!(hook.retained_bytes(&empty), 0);

        {
            let mut s = store.lock().unwrap();
            s.create_user(NewUser::email("a@example.com"), AT).unwrap();
        }
        let part = hook.capture(&scope).expect("capture");
        assert!(
            hook.retained_bytes(&part) > 0,
            "a populated store retains a positive estimate"
        );

        // A part of another shape contributes zero rather than a wrong count.
        let foreign: super::SnapshotPart = Arc::new(7u8);
        assert_eq!(hook.retained_bytes(&foreign), 0);
    }

    /// `SNAP-MEM-01`: fault history is unbounded by the fault injector itself, so every
    /// fired record must contribute to the session snapshot byte budget.
    #[test]
    fn the_fault_hook_counts_fired_records_toward_the_snapshot_budget() {
        use fireemu_core_session::fault::{
            FaultAction, FaultMatch, FaultPlan, FaultRegistry, FaultRule,
        };

        let registry = Arc::new(FaultRegistry::new());
        let hook = super::Faults(registry.clone(), "demo-app".to_owned());
        let scope = Scope::Project("demo-app".to_owned());
        let state = registry.for_project("demo-app");
        state.lock().expect("writable").install(FaultPlan {
            seed: 1,
            rules: vec![FaultRule {
                matches: FaultMatch {
                    operation: "firestore.commit".to_owned(),
                    nth: None,
                    function: None,
                    event_type: None,
                },
                action: FaultAction::ReturnError {
                    code: "UNAVAILABLE".to_owned(),
                },
            }],
        });
        let before = hook.capture(&scope).expect("capture plan");
        state
            .lock()
            .expect("writable")
            .decide("firestore.commit", None, None);
        let after = hook.capture(&scope).expect("capture fired record");

        assert!(hook.retained_bytes(&before) > 0);
        assert!(hook.retained_bytes(&after) > hook.retained_bytes(&before));
    }
}
