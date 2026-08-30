//! Sessions other than the default one: isolated by project. Each gets its own Auth
//! store (registered with the shared verifier); a reset wipes what the session's scope
//! owns (its Firestore databases, its buckets, its users) and nothing else.

use std::sync::Arc;

use ftd_adapter_grpc::local::LocalBackend;
use ftd_adapter_http::control::ProjectHooks;
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

    fn reset_scope(&self, scope: &Scope) {
        self.backend.reset_scope(scope);
        if let Ok(mut store) = self.storage.store.lock() {
            store.remove_buckets_where(|bucket| {
                scope.owns_project(&self.storage.project_of_bucket(bucket))
            });
        }
        let auth = match scope {
            Scope::Project(p) => self.registry.store_for(p),
            Scope::AllExcept(_) => Some(self.registry.default_store()),
        };
        if let Some(auth) = auth {
            if let Ok(mut auth) = auth.lock() {
                auth.clear();
            }
        }
    }

    fn remove(&self, project: &str) {
        self.reset_scope(&Scope::Project(project.to_owned()));
        self.registry.remove(project);
    }
}
