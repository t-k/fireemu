//! Shared schema for runtime resource diagnostics (retention roots, limits, refusals).
//!
//! Every service reports what it retains for one session in the same shape, so a reader can
//! see limits, current values, refusal reasons, what is reclaimable and which roots hold the
//! rest without learning document contents, credentials or another session's state.
//!
//! Three kinds of measure are kept apart and never summed with each other:
//!
//! - [`Measure::Logical`]: the deterministic charge the service admits against (Firestore's
//!   storage-size model, Pub/Sub payload bytes, the functions outbox record bytes);
//! - [`Measure::Estimate`]: a saturating heap estimate, such as a snapshot part's retained
//!   bytes;
//! - [`Measure::Process`]: what the operating system reports for the whole process (RSS), which
//!   an allocator cache keeps high after the logical charge has been released.
//!
//! Retention roots are opaque: a root names a kind and an identifier the reader can match
//! against an allow-list, never a payload. The number of roots a report carries is bounded by
//! a [`RootBudget`]; a report says when it truncated.

/// What a gauge measures. See the module documentation for why these never add up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Measure {
    /// Deterministic logical charge (what admission decides on).
    Logical,
    /// Saturating heap estimate.
    Estimate,
    /// Operating-system process accounting (RSS).
    Process,
}

impl Measure {
    /// The wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Logical => "logical",
            Self::Estimate => "estimate",
            Self::Process => "process",
        }
    }
}

/// The unit of a gauge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unit {
    /// Bytes.
    Bytes,
    /// A count of items (documents, records, messages, sessions).
    Count,
}

impl Unit {
    /// The wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Bytes => "bytes",
            Self::Count => "count",
        }
    }
}

/// One current value against its limit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gauge {
    /// Stable identifier within the service (`history.total_bytes`, `outbox.records`).
    pub id: String,
    /// What the value measures.
    pub measure: Measure,
    /// The unit.
    pub unit: Unit,
    /// The current value.
    pub current: u64,
    /// The configured limit, when one applies.
    pub limit: Option<u64>,
    /// How much of `current` the service could release right now without losing anything a
    /// client can still observe (expired history, acknowledged messages, evictable records).
    pub reclaimable: u64,
}

impl Gauge {
    /// A logical gauge with no reclaimable part.
    #[must_use]
    pub fn logical(id: &str, unit: Unit, current: u64, limit: Option<u64>) -> Self {
        Self {
            id: id.to_owned(),
            measure: Measure::Logical,
            unit,
            current,
            limit,
            reclaimable: 0,
        }
    }

    /// The same gauge with a reclaimable part.
    #[must_use]
    pub fn with_reclaimable(mut self, reclaimable: u64) -> Self {
        self.reclaimable = reclaimable.min(self.current);
        self
    }

    /// Whether the current value has reached its limit.
    #[must_use]
    pub fn saturated(&self) -> bool {
        self.limit.is_some_and(|limit| self.current >= limit)
    }
}

/// Why admissions were refused, counted by category; never a payload or an identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    /// The category (`capacity`, `unavailable`, `budget.session`).
    pub reason: String,
    /// How many admissions this category refused since the last reset.
    pub count: u64,
}

/// One thing that keeps bytes retained.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetentionRoot {
    /// The kind of root (`transaction`, `listener`, `snapshot`, `unacked`, `event`).
    pub kind: String,
    /// An opaque identifier for allow-listing; never a resource name or payload.
    pub id: String,
    /// Items the root pins.
    pub count: u64,
    /// Logical bytes the root pins.
    pub bytes: u64,
    /// Whether the root is outstanding work: something a quiescent runtime would not have.
    pub outstanding: bool,
}

/// The roots one service reports, bounded by a [`RootBudget`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RetentionRoots {
    /// The roots kept, in the service's order.
    pub roots: Vec<RetentionRoot>,
    /// How many roots the service holds in total, including those not listed.
    pub total: u64,
    /// Whether `roots` is shorter than `total`.
    pub truncated: bool,
}

/// How many roots a report may carry per service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RootBudget {
    /// The maximum number of roots listed per service.
    pub max_roots: usize,
}

impl RootBudget {
    /// The default report size.
    pub const DEFAULT: Self = Self { max_roots: 64 };

    /// Keeps at most `max_roots` roots, outstanding ones first so a truncated report still
    /// shows what blocks quiescence; ties keep the service's order.
    #[must_use]
    pub fn bound(self, roots: Vec<RetentionRoot>) -> RetentionRoots {
        let total = roots.len() as u64;
        let mut kept: Vec<RetentionRoot> =
            roots.iter().filter(|r| r.outstanding).cloned().collect();
        kept.extend(roots.into_iter().filter(|r| !r.outstanding));
        kept.truncate(self.max_roots);
        RetentionRoots {
            truncated: (kept.len() as u64) < total,
            roots: kept,
            total,
        }
    }
}

/// What one service retains for one session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceResources {
    /// The service (`firestore`, `functions`, `pubsub`, `storage`, `auth`, `snapshots`).
    pub service: String,
    /// Current values against limits.
    pub gauges: Vec<Gauge>,
    /// Refused admissions by category.
    pub refusals: Vec<Refusal>,
    /// Retention roots.
    pub roots: RetentionRoots,
}

/// One entry of the allow-list `assert_quiescent` accepts: an exact root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllowedRoot {
    /// The service the root belongs to.
    pub service: String,
    /// The root kind.
    pub kind: String,
    /// The exact opaque identifier.
    pub id: String,
    /// Why the root is expected to be outstanding.
    pub reason: String,
}

/// Why a runtime is not quiescent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuiescenceFailure {
    /// Outstanding roots no allow-list entry names.
    pub leaks: Vec<(String, RetentionRoot)>,
    /// Allow-list entries that matched nothing: a stale entry hides nothing but is reported so
    /// it does not silently outlive the root it excused.
    pub stale_allowances: Vec<AllowedRoot>,
    /// Services whose root list was truncated: a report that dropped roots cannot prove the
    /// absence of a leak.
    pub truncated_services: Vec<String>,
}

/// Checks that no service holds outstanding work beyond the exact allow-list.
///
/// An entry allows one root: same service, same kind, same identifier. Prefixes and wildcards
/// are deliberately not supported, so an allow-list cannot grow to hide an unrelated leak.
///
/// # Errors
///
/// Returns the leaks, the stale allowances and the truncated services when any exist.
pub fn assert_quiescent(
    services: &[ServiceResources],
    allowed: &[AllowedRoot],
) -> Result<(), QuiescenceFailure> {
    let mut leaks = Vec::new();
    let mut used = vec![false; allowed.len()];
    let mut truncated_services = Vec::new();
    for service in services {
        if service.roots.truncated {
            truncated_services.push(service.service.clone());
        }
        for root in service.roots.roots.iter().filter(|r| r.outstanding) {
            let allowance = allowed.iter().position(|a| {
                a.service == service.service && a.kind == root.kind && a.id == root.id
            });
            match allowance {
                Some(index) => used[index] = true,
                None => leaks.push((service.service.clone(), root.clone())),
            }
        }
    }
    let stale_allowances: Vec<AllowedRoot> = allowed
        .iter()
        .zip(used)
        .filter(|(_, used)| !used)
        .map(|(a, _)| a.clone())
        .collect();
    if leaks.is_empty() && stale_allowances.is_empty() && truncated_services.is_empty() {
        Ok(())
    } else {
        Err(QuiescenceFailure {
            leaks,
            stale_allowances,
            truncated_services,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root(kind: &str, id: &str, outstanding: bool) -> RetentionRoot {
        RetentionRoot {
            kind: kind.to_owned(),
            id: id.to_owned(),
            count: 1,
            bytes: 10,
            outstanding,
        }
    }

    fn service(name: &str, roots: Vec<RetentionRoot>) -> ServiceResources {
        ServiceResources {
            service: name.to_owned(),
            gauges: Vec::new(),
            refusals: Vec::new(),
            roots: RootBudget::DEFAULT.bound(roots),
        }
    }

    fn allow(service: &str, kind: &str, id: &str) -> AllowedRoot {
        AllowedRoot {
            service: service.to_owned(),
            kind: kind.to_owned(),
            id: id.to_owned(),
            reason: "expected by the test".to_owned(),
        }
    }

    #[test]
    fn a_runtime_with_no_outstanding_root_is_quiescent() {
        let services = [
            service("firestore", vec![root("history", "db-1", false)]),
            service("functions", vec![]),
        ];
        assert_eq!(assert_quiescent(&services, &[]), Ok(()));
    }

    #[test]
    fn an_outstanding_root_is_a_leak_unless_allowed_exactly() {
        let services = [
            service("firestore", vec![root("transaction", "tx-7", true)]),
            service("functions", vec![root("event", "ev-1", true)]),
        ];
        let failure = assert_quiescent(&services, &[allow("functions", "event", "ev-1")])
            .expect_err("the transaction is a leak");
        assert_eq!(
            failure.leaks,
            vec![("firestore".to_owned(), root("transaction", "tx-7", true))]
        );
        assert!(failure.stale_allowances.is_empty());
        assert!(failure.truncated_services.is_empty());

        // The same identifier under another service or kind allows nothing.
        let wrong_service = assert_quiescent(&services, &[allow("firestore", "event", "ev-1")])
            .expect_err("the functions event is still a leak");
        assert_eq!(wrong_service.leaks.len(), 2);
        assert_eq!(wrong_service.stale_allowances.len(), 1);

        // A prefix never matches.
        let prefix = assert_quiescent(
            &services,
            &[
                allow("firestore", "transaction", "tx"),
                allow("functions", "event", "ev-1"),
            ],
        )
        .expect_err("a prefix is not an allowance");
        assert_eq!(prefix.leaks.len(), 1);
        assert_eq!(
            prefix.stale_allowances,
            vec![allow("firestore", "transaction", "tx")]
        );
    }

    #[test]
    fn allowing_one_root_does_not_hide_another_of_the_same_kind() {
        let services = [service(
            "firestore",
            vec![root("listener", "l-1", true), root("listener", "l-2", true)],
        )];
        let failure = assert_quiescent(&services, &[allow("firestore", "listener", "l-1")])
            .expect_err("l-2 is a leak");
        assert_eq!(
            failure.leaks,
            vec![("firestore".to_owned(), root("listener", "l-2", true))]
        );
    }

    #[test]
    fn a_stale_allowance_is_reported_even_when_nothing_leaks() {
        let services = [service("pubsub", vec![root("unacked", "s-1", false)])];
        let failure = assert_quiescent(&services, &[allow("pubsub", "unacked", "s-1")])
            .expect_err("the allowance excuses nothing");
        assert!(failure.leaks.is_empty());
        assert_eq!(failure.stale_allowances.len(), 1);
    }

    #[test]
    fn roots_are_bounded_with_outstanding_roots_first_and_truncation_reported() {
        let mut roots: Vec<RetentionRoot> = (0..10)
            .map(|i| root("history", &format!("h-{i}"), false))
            .collect();
        roots.push(root("transaction", "tx-1", true));
        roots.push(root("listener", "l-1", true));
        let bounded = RootBudget { max_roots: 3 }.bound(roots.clone());
        assert_eq!(bounded.total, 12);
        assert!(bounded.truncated);
        assert_eq!(bounded.roots.len(), 3);
        assert_eq!(bounded.roots[0].id, "tx-1");
        assert_eq!(bounded.roots[1].id, "l-1");
        assert_eq!(bounded.roots[2].id, "h-0");

        let whole = RootBudget { max_roots: 12 }.bound(roots);
        assert!(!whole.truncated);
        assert_eq!(whole.roots.len(), 12);
    }

    #[test]
    fn a_truncated_service_cannot_prove_quiescence() {
        let roots: Vec<RetentionRoot> = (0..5)
            .map(|i| root("history", &format!("h-{i}"), false))
            .collect();
        let truncated = ServiceResources {
            service: "firestore".to_owned(),
            gauges: Vec::new(),
            refusals: Vec::new(),
            roots: RootBudget { max_roots: 2 }.bound(roots),
        };
        let failure = assert_quiescent(&[truncated], &[]).expect_err("truncation is reported");
        assert!(failure.leaks.is_empty());
        assert_eq!(failure.truncated_services, vec!["firestore".to_owned()]);
    }

    #[test]
    fn gauges_keep_reclaimable_within_current_and_report_saturation() {
        let gauge = Gauge::logical("history.total_bytes", Unit::Bytes, 100, Some(100))
            .with_reclaimable(250);
        assert_eq!(gauge.reclaimable, 100);
        assert!(gauge.saturated());
        assert!(!Gauge::logical("x", Unit::Count, 1, None).saturated());
        assert!(!Gauge::logical("x", Unit::Count, 1, Some(2)).saturated());
        assert_eq!(Measure::Logical.as_str(), "logical");
        assert_eq!(Measure::Estimate.as_str(), "estimate");
        assert_eq!(Measure::Process.as_str(), "process");
        assert_eq!(Unit::Bytes.as_str(), "bytes");
    }
}
