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
use fireemu_core_types::resources::{Gauge, Measure, RootBudget, ServiceResources, Unit};

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

/// The daemon process itself: resident set size as the operating system reports it. This is
/// a `process` measure, never added to the logical charges; an allocator cache keeps it high
/// after every logical byte has been released, which is exactly what the two kinds of gauge
/// exist to tell apart. Reported for the default session only.
pub struct Process;

impl Process {
    /// Resident set size in bytes from `ps`, the one portable source without unsafe code.
    fn resident_set_bytes() -> Result<u64, String> {
        let pid = std::process::id().to_string();
        let output = std::process::Command::new("ps")
            .args(["-o", "rss=", "-p", &pid])
            .output()
            .map_err(|error| format!("ps is not available: {error}"))?;
        if !output.status.success() {
            return Err(format!("ps exited with {}", output.status));
        }
        let kib: u64 = String::from_utf8_lossy(&output.stdout)
            .trim()
            .parse()
            .map_err(|_| "ps printed no resident set size".to_owned())?;
        Ok(kib.saturating_mul(1024))
    }
}

impl ResourceHook for Process {
    fn name(&self) -> &'static str {
        "process"
    }
    fn collect(
        &self,
        scope: &Scope,
        budget: RootBudget,
    ) -> Result<ServiceResources, TransitionFailure> {
        let mut gauges = Vec::new();
        if scope.is_default() {
            let rss = Self::resident_set_bytes()
                .map_err(|message| TransitionFailure::new("process", message))?;
            let mut gauge = Gauge::logical("process.resident_set_bytes", Unit::Bytes, rss, None);
            gauge.measure = Measure::Process;
            gauges.push(gauge);
        }
        Ok(ServiceResources {
            service: "process".to_owned(),
            gauges,
            refusals: Vec::new(),
            roots: budget.bound(Vec::new()),
        })
    }
}
