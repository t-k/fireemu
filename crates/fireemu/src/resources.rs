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
use fireemu_core_types::resources::{Gauge, Measure, Refusal, RootBudget, ServiceResources, Unit};

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
    /// Resident set size in bytes.
    ///
    /// Linux publishes it in `/proc/self/status`, which is a plain read: no subprocess runs on
    /// the path that serves the control route. The platforms with no such file have no source
    /// this crate can read either, because their interface is a system call and the workspace
    /// forbids unsafe code, so `ps` stays the source there. Either way a failure is the
    /// gauge's, never the report's: [`Process::collect`] turns it into a counted refusal.
    fn resident_set_bytes() -> Result<u64, String> {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            let status = std::fs::read_to_string("/proc/self/status")
                .map_err(|error| format!("/proc/self/status is not readable: {error}"))?;
            Self::rss_from_proc_status(&status)
        }
        #[cfg(all(unix, not(any(target_os = "linux", target_os = "android"))))]
        {
            let pid = std::process::id().to_string();
            let output = std::process::Command::new("ps")
                .args(["-o", "rss=", "-p", &pid])
                .output()
                .map_err(|error| format!("ps is not available: {error}"))?;
            if !output.status.success() {
                return Err(format!("ps exited with {}", output.status));
            }
            Self::rss_from_ps(&String::from_utf8_lossy(&output.stdout))
        }
        #[cfg(not(unix))]
        {
            Err("this platform publishes no resident set size a safe API can read".to_owned())
        }
    }

    /// Reads `VmRSS` out of the `/proc/self/status` text. Kernels print kibibytes; a kernel
    /// that prints another unit is reported rather than silently misscaled.
    ///
    /// Both parsers are compiled everywhere so their unit tests run on every platform, while
    /// only one of them is on any given host's live path.
    #[cfg_attr(not(any(target_os = "linux", target_os = "android")), allow(dead_code))]
    fn rss_from_proc_status(status: &str) -> Result<u64, String> {
        let line = status
            .lines()
            .find_map(|line| line.strip_prefix("VmRSS:"))
            .ok_or_else(|| "/proc/self/status publishes no VmRSS".to_owned())?;
        let mut fields = line.split_whitespace();
        let value: u64 = fields
            .next()
            .and_then(|value| value.parse().ok())
            .ok_or_else(|| "VmRSS is not a number".to_owned())?;
        match fields.next() {
            None | Some("kB" | "KB") => Ok(value.saturating_mul(1024)),
            Some("B") => Ok(value),
            Some(unit) => Err(format!("VmRSS is in an unknown unit {unit:?}")),
        }
    }

    /// Reads the kibibytes `ps -o rss=` prints.
    #[cfg_attr(
        any(target_os = "linux", target_os = "android", not(unix)),
        allow(dead_code)
    )]
    fn rss_from_ps(stdout: &str) -> Result<u64, String> {
        let kib: u64 = stdout
            .trim()
            .parse()
            .map_err(|_| "ps printed no resident set size".to_owned())?;
        Ok(kib.saturating_mul(1024))
    }

    /// Turns what the platform answered into the service report.
    ///
    /// `None` is a session that is not charged for the process at all. A host that publishes
    /// no resident set size this process can read answers one gauge, not the report: the gauge
    /// is dropped and counted, so every other service still reports and the reader sees why
    /// the number is missing instead of an incomplete report.
    fn report(measured: Option<&Result<u64, String>>, budget: RootBudget) -> ServiceResources {
        let mut gauges = Vec::new();
        let mut refusals = Vec::new();
        match measured {
            Some(Ok(rss)) => {
                let mut gauge =
                    Gauge::logical("process.resident_set_bytes", Unit::Bytes, *rss, None);
                gauge.measure = Measure::Process;
                gauges.push(gauge);
            }
            Some(Err(_)) => refusals.push(Refusal {
                reason: "process.resident_set_bytes.unavailable".to_owned(),
                count: 1,
            }),
            None => {}
        }
        ServiceResources {
            service: "process".to_owned(),
            gauges,
            refusals,
            roots: budget.bound(Vec::new()),
        }
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
        // Only the default session is charged for the process, and the measurement is taken
        // once here so that turning it into a report stays a pure function the tests can
        // drive with either answer.
        let measured = scope.is_default().then(Self::resident_set_bytes);
        Ok(Self::report(measured.as_ref(), budget))
    }
}

#[cfg(test)]
mod tests {
    //! `RSSPS-1` / `RSSPS-2`: the process gauge is a diagnostic, never the reason a whole
    //! report fails. A host without `ps` (a minimal container, Windows) reports the gauge as
    //! unavailable and still answers with every other gauge.

    use super::{Process, Scope, Unit};
    use fireemu_adapter_http::control::ResourceHook;
    use fireemu_core_types::resources::{Measure, RootBudget};
    use std::collections::BTreeSet;

    /// The gauge id the process hook publishes, and the refusal category naming it when the
    /// platform publishes no resident set size.
    const GAUGE: &str = "process.resident_set_bytes";
    const UNAVAILABLE: &str = "process.resident_set_bytes.unavailable";

    #[test]
    fn a_host_that_publishes_no_resident_set_size_still_reports_the_service() {
        // The platform answered that it has no source for the gauge (no `ps` on a minimal
        // container, or Windows). The report is still the service's, with the gauge dropped
        // and counted. The answer is injected rather than provoked, so this test never
        // touches the environment other tests in this process are reading.
        let report = Process::report(
            Some(&Err("ps is not available".to_owned())),
            RootBudget::DEFAULT,
        );
        assert_eq!(report.service, "process");
        assert!(report.gauges.is_empty());
        assert_eq!(report.refusals.len(), 1);
        assert_eq!(report.refusals[0].reason, UNAVAILABLE);
        assert_eq!(report.refusals[0].count, 1);

        // A measured host publishes the gauge and refuses nothing.
        let report = Process::report(Some(&Ok(32_768)), RootBudget::DEFAULT);
        assert!(report.refusals.is_empty());
        assert_eq!(report.gauges.len(), 1);
        assert_eq!(report.gauges[0].id, GAUGE);
        assert_eq!(report.gauges[0].measure, Measure::Process);
        assert_eq!(report.gauges[0].unit, Unit::Bytes);
        assert_eq!(report.gauges[0].current, 32_768);
        assert_eq!(report.gauges[0].limit, None);

        // A session that is not charged for the process reports neither.
        let report = Process::report(None, RootBudget::DEFAULT);
        assert!(report.gauges.is_empty());
        assert!(report.refusals.is_empty());
    }

    /// On this host the hook itself answers, whatever the platform publishes: a measurement or
    /// a counted refusal, never a failed report.
    #[test]
    fn the_hook_never_fails_the_report_on_this_host() {
        let report = Process
            .collect(&Scope::AllExcept(BTreeSet::new()), RootBudget::DEFAULT)
            .expect("the process hook never fails the whole report");
        assert_eq!(report.gauges.len() + report.refusals.len(), 1);
        if let Some(gauge) = report.gauges.first() {
            assert_eq!(gauge.id, GAUGE);
            assert!(gauge.current > 0, "a reported resident set size is real");
        } else {
            assert_eq!(report.refusals[0].reason, UNAVAILABLE);
        }
    }

    /// RSSPS-2: both platform shapes are parsed by these unit tests on every host.
    #[test]
    fn the_platform_resident_set_shapes_are_parsed_or_named() {
        let status = "Name:\tfireemu\nVmHWM:\t  40960 kB\nVmRSS:\t  32768 kB\nThreads:\t9\n";
        assert_eq!(
            Process::rss_from_proc_status(status),
            Ok(32_768 * 1024),
            "kibibytes are the kernel's unit"
        );
        assert_eq!(Process::rss_from_proc_status("VmRSS: 4096 B"), Ok(4096));
        assert!(Process::rss_from_proc_status("VmRSS: 4096 MB").is_err());
        assert!(Process::rss_from_proc_status("VmRSS: nothing").is_err());
        assert!(Process::rss_from_proc_status("Name:\tfireemu\n").is_err());

        assert_eq!(Process::rss_from_ps("  32768\n"), Ok(32_768 * 1024));
        assert!(Process::rss_from_ps("").is_err());
        assert!(Process::rss_from_ps("rss\n32768\n").is_err());
    }

    #[test]
    fn a_project_session_reports_no_process_gauge() {
        let report = Process
            .collect(&Scope::Project("demo-b".to_owned()), RootBudget::DEFAULT)
            .expect("a project session reports the service with no process gauge");
        assert!(report.gauges.is_empty());
        assert!(report.refusals.is_empty());
    }
}
