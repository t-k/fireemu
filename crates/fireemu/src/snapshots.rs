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
use fireemu_core_auth::store::{AuthRegistry, AuthSnapshot, AuthStore};
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
        self.0.restore_scope(scope, snapshot);
        Ok(())
    }
    fn retained_bytes(&self, part: &SnapshotPart) -> u64 {
        part.downcast_ref::<FirestoreSnapshot>()
            .map_or(0, FirestoreSnapshot::retained_bytes)
    }
}

/// The session's buckets and objects.
pub struct Storage(pub Arc<fireemu_adapter_http::storage::StorageState>);

impl Storage {
    fn owned<'a>(&'a self, scope: &'a Scope) -> impl Fn(&str) -> bool + 'a {
        move |bucket| scope.owns_project(&self.0.project_of_bucket(bucket))
    }
}

/// The complete global or target-based Storage Rules registry.
pub struct StorageRules(pub Arc<fireemu_adapter_http::storage::StorageRulesRegistry>);

impl SnapshotHook for StorageRules {
    fn name(&self) -> &'static str {
        "storage rules"
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
            .map_or(0, |snapshot| snapshot.retained_bytes())
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
        let guard = store
            .lock()
            .map_err(|_| poisoned(self.name(), "the Auth store"))?;
        let snapshot = AuthSnapshot::capture(&guard);
        debug_assert!(snapshot.holds_no_totp_secret());
        Ok(Arc::new(snapshot))
    }
    fn validate(&self, scope: &Scope, part: &SnapshotPart) -> Result<(), TransitionFailure> {
        part.downcast_ref::<AuthSnapshot>()
            .ok_or_else(|| wrong_shape(self.name()))?;
        self.store(scope)?
            .lock()
            .map(|_| ())
            .map_err(|_| poisoned(self.name(), "the Auth store"))
    }
    fn restore(&self, scope: &Scope, part: &SnapshotPart) -> Result<(), TransitionFailure> {
        let snapshot = part
            .downcast_ref::<AuthSnapshot>()
            .ok_or_else(|| wrong_shape(self.name()))?;
        let store = self.store(scope)?;
        let mut store = store
            .lock()
            .map_err(|_| poisoned(self.name(), "the Auth store"))?;
        let report = snapshot.restore_into(&mut store);
        drop(store);
        if report.totp_factors_dropped > 0 {
            eprintln!(
                "auth: restored project {} without {} TOTP factor(s) whose secret the store no longer held (default snapshots carry no shared secret; enrol again)",
                snapshot.project_id(),
                report.totp_factors_dropped
            );
        }
        Ok(())
    }
    fn retained_bytes(&self, part: &SnapshotPart) -> u64 {
        part.downcast_ref::<AuthSnapshot>()
            .map_or(0, AuthSnapshot::retained_bytes)
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

    use super::{AppCheck, Rules, Scope, SnapshotHook};
    use crate::sessions::tests::{admits_for, gate, token_for, APP_ID};

    use fireemu_core_rules::runtime::{LoadedRules, RulesetSlot};
    use fireemu_core_types::time::LogicalInstant;
    use std::collections::BTreeSet;
    use std::sync::Arc;

    const AT: LogicalInstant = LogicalInstant::from_unix_seconds(1_788_004_860);

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
        use fireemu_core_auth::store::{AuthRegistry, AuthSnapshot, AuthStore, NewUser};
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
            .downcast_ref::<AuthSnapshot>()
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
            s.finalize_mfa_sign_in(&uid, &pending, code, t1)
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
