//! Resource diagnostics: one [`ResourceHook`] per service, each reporting what the session
//! owns in the shared schema of `fireemu_core_types::resources` (spec 15: control API).
//!
//! Every hook reads under its own store's lock and returns; the control route collects the
//! hooks one after another, so a report never holds two services' locks at once. No hook
//! returns a payload, a credential or another session's state: identifiers are the resource
//! names the caller chose (databases, buckets, subscriptions, snapshots) or digests of
//! capabilities (upload sessions).

use std::sync::{Arc, Mutex};

use fireemu_adapter_functions::runtime::FunctionsRuntime;
use fireemu_adapter_grpc::local::LocalBackend;
use fireemu_adapter_http::control::{ResourceHook, TransitionFailure};
use fireemu_core_auth::store::AuthRegistry;
use fireemu_core_session::tenancy::Scope;
use fireemu_core_types::resources::{Gauge, RootBudget, ServiceResources, Unit};

/// The session's Firestore databases and history charge.
pub struct Firestore(pub Arc<LocalBackend>);

impl ResourceHook for Firestore {
    fn name(&self) -> &'static str {
        "firestore"
    }
    fn collect(
        &self,
        scope: &Scope,
        budget: RootBudget,
    ) -> Result<ServiceResources, TransitionFailure> {
        self.0
            .resources(scope, budget)
            .map_err(|message| TransitionFailure::new("firestore", message))
    }
}

/// The functions runtime, which belongs to the default session.
pub struct Functions(pub Arc<FunctionsRuntime>);

impl ResourceHook for Functions {
    fn name(&self) -> &'static str {
        "functions"
    }
    fn collect(
        &self,
        scope: &Scope,
        budget: RootBudget,
    ) -> Result<ServiceResources, TransitionFailure> {
        if !scope.is_default() {
            // Another session owns no functions; an empty report is the truthful answer.
            return Ok(ServiceResources {
                service: "functions".to_owned(),
                gauges: Vec::new(),
                refusals: Vec::new(),
                roots: budget.bound(Vec::new()),
            });
        }
        self.0
            .resources(budget)
            .map_err(|message| TransitionFailure::new("functions", message))
    }
}

/// The session's Pub/Sub topics, subscriptions and snapshots.
pub struct PubSub(pub Arc<Mutex<fireemu_core_pubsub::PubSubState>>);

impl ResourceHook for PubSub {
    fn name(&self) -> &'static str {
        "pubsub"
    }
    fn collect(
        &self,
        scope: &Scope,
        budget: RootBudget,
    ) -> Result<ServiceResources, TransitionFailure> {
        let state = self
            .0
            .lock()
            .map_err(|_| TransitionFailure::new("pubsub", "the Pub/Sub state is poisoned"))?;
        Ok(state.resources(
            &|project| scope.owns_project(project),
            scope.is_default(),
            budget,
        ))
    }
}

/// The session's buckets, objects and unfinished uploads.
pub struct Storage(pub Arc<fireemu_adapter_http::storage::StorageState>);

impl ResourceHook for Storage {
    fn name(&self) -> &'static str {
        "storage"
    }
    fn collect(
        &self,
        scope: &Scope,
        budget: RootBudget,
    ) -> Result<ServiceResources, TransitionFailure> {
        let store = self
            .0
            .store
            .lock()
            .map_err(|_| TransitionFailure::new("storage", "the object store is poisoned"))?;
        Ok(store.resources(
            |bucket| scope.owns_project(&self.0.project_of_bucket(bucket)),
            budget,
        ))
    }
}

/// The session's Auth store: users and the transient sign-in state it retains.
pub struct Auth(pub Arc<AuthRegistry>);

impl ResourceHook for Auth {
    fn name(&self) -> &'static str {
        "auth"
    }
    fn collect(
        &self,
        scope: &Scope,
        budget: RootBudget,
    ) -> Result<ServiceResources, TransitionFailure> {
        let store = match scope {
            Scope::Project(project) => self.0.store_for(project).ok_or_else(|| {
                TransitionFailure::new(
                    "auth",
                    format!("project {project:?} has no reachable Auth store"),
                )
            })?,
            Scope::AllExcept(_) => self.0.default_store(),
        };
        let store = store
            .lock()
            .map_err(|_| TransitionFailure::new("auth", "the Auth store is poisoned"))?;
        let count = |value: usize| u64::try_from(value).unwrap_or(u64::MAX);
        Ok(ServiceResources {
            service: "auth".to_owned(),
            gauges: vec![
                Gauge::logical("users.count", Unit::Count, count(store.user_count()), None),
                Gauge::logical(
                    "users.bytes",
                    Unit::Bytes,
                    store.retained_user_bytes(),
                    None,
                ),
                Gauge::logical(
                    "transient.bytes",
                    Unit::Bytes,
                    store.transient_bytes(),
                    None,
                ),
            ],
            refusals: Vec::new(),
            roots: budget.bound(Vec::new()),
        })
    }
}
