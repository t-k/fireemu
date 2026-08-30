//! Sessions other than the default one: isolated by project. Each gets its own Auth
//! store (registered with the shared verifier); a reset wipes what the session's scope
//! owns (its Firestore databases, its buckets, its users) and nothing else.
//!
//! A reset and a deletion touch three stores at once, so both start with a probe: every
//! store they will write is taken and released before the first of them is wiped. The only
//! failure these locks have is poisoning, which is permanent, so a probe that passes means
//! the wipe that follows cannot fail on a lock, and a probe that fails leaves the project
//! exactly as it was for the control route to report.

use std::sync::{Arc, Mutex};

use ftd_adapter_grpc::local::LocalBackend;
use ftd_adapter_http::control::{ProjectHooks, TransitionFailure};
use ftd_core_auth::mfa::TotpPolicy;
use ftd_core_auth::store::{AuthRegistry, AuthStore};
use ftd_core_session::tenancy::Scope;
use ftd_core_types::determinism::SplitMix64;

/// The daemon's per-project hooks.
pub struct Projects {
    /// Firestore.
    pub backend: Arc<LocalBackend>,
    /// Storage.
    pub storage: Arc<ftd_adapter_http::storage::StorageState>,
    /// Auth stores.
    pub registry: Arc<AuthRegistry>,
    /// Session seed (each project's generator derives from it and the project name).
    pub seed: u64,
}

impl Projects {
    /// Checks that every store `scope` owns can be written, and returns the Auth store to
    /// wipe (a project that has none has no users to clear: the default session's scope
    /// always has one). Nothing is mutated.
    fn prepare(&self, scope: &Scope) -> Result<Option<Arc<Mutex<AuthStore>>>, TransitionFailure> {
        if self.storage.store.lock().is_err() {
            return Err(TransitionFailure::new(
                "storage",
                "the object store is poisoned",
            ));
        }
        let auth = match scope {
            Scope::Project(p) => self.registry.store_for(p),
            Scope::AllExcept(_) => Some(self.registry.default_store()),
        };
        if let Some(auth) = &auth {
            if auth.lock().is_err() {
                return Err(TransitionFailure::new("auth", "the Auth store is poisoned"));
            }
        }
        Ok(auth)
    }
}

impl ProjectHooks for Projects {
    fn create(&self, project: &str) -> Result<(), String> {
        let mut seed = self.seed;
        for b in project.bytes() {
            seed = (seed ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3);
        }
        let mut store = AuthStore::new(project, SplitMix64::new(seed), TotpPolicy::default());
        if let Some(signer) = self
            .registry
            .default_store()
            .lock()
            .ok()
            .and_then(|s| s.signer_arc())
        {
            store.set_signer(signer);
        }
        if self.registry.register(project, store) {
            Ok(())
        } else {
            Err(format!("project {project:?} already has an Auth store"))
        }
    }

    fn reset_scope(&self, scope: &Scope) -> Result<(), TransitionFailure> {
        let auth = self.prepare(scope)?;
        // Apply: Firestore first (it publishes the new epoch for the default scope), then
        // the stores the probe above proved writable.
        self.backend.reset_scope(scope);
        {
            let mut store =
                self.storage.store.lock().map_err(|_| {
                    TransitionFailure::new("storage", "the object store is poisoned")
                })?;
            store.remove_buckets_where(|bucket| {
                scope.owns_project(&self.storage.project_of_bucket(bucket))
            });
        }
        if let Some(auth) = auth {
            auth.lock()
                .map_err(|_| TransitionFailure::new("auth", "the Auth store is poisoned"))?
                .clear();
        }
        Ok(())
    }

    fn remove(&self, project: &str) -> Result<(), TransitionFailure> {
        let scope = Scope::Project(project.to_owned());
        self.reset_scope(&scope)?;
        self.registry.remove(project);
        Ok(())
    }
}
