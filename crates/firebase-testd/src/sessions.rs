//! Sessions other than the default one: isolated by project. Each gets its own Auth
//! store (registered with the shared verifier), and a reset or delete wipes only that
//! project's Firestore databases, default Storage buckets and users.

use std::sync::Arc;

use ftd_adapter_grpc::local::LocalBackend;
use ftd_adapter_http::control::ProjectHooks;
use ftd_core_auth::mfa::TotpPolicy;
use ftd_core_auth::store::{AuthRegistry, AuthStore};
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
    fn default_buckets(project: &str) -> [String; 2] {
        [
            format!("{project}.appspot.com"),
            format!("{project}.firebasestorage.app"),
        ]
    }

    fn wipe(&self, project: &str) {
        self.backend.reset_project(project);
        if let Ok(mut store) = self.storage.store.lock() {
            for bucket in Self::default_buckets(project) {
                if let Ok(name) = ftd_core_storage::name::BucketName::try_new(bucket) {
                    store.remove_bucket(&name);
                }
            }
        }
        if let Some(auth) = self.registry.store_for(project) {
            if let Ok(mut auth) = auth.lock() {
                auth.clear();
            }
        }
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

    fn reset(&self, project: &str) {
        self.wipe(project);
    }

    fn remove(&self, project: &str) {
        self.wipe(project);
        self.registry.remove(project);
    }
}
