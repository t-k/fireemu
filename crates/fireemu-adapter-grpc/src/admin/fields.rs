//! Runtime field configuration changes (`collectionGroups.fields.patch`, FS-CONFIG-RT-004).
//!
//! Production applies a field patch through a long-running operation: the change is pending,
//! the field reads back as the transitional configuration production reports meanwhile, and
//! only once the operation is done does a single-field exemption change which queries are
//! refused. A local change is pending for [`DEFAULT_FIELD_APPLY`] of wall-clock time (or any
//! advance of the virtual clock past it), after which it is applied (scope decision C10).

use std::sync::Mutex;
use std::time::{Duration, Instant};

use fireemu_core_firestore::field_path::FieldPath;
use fireemu_core_firestore::index::{IndexFieldMode, IndexQueryScope, IndexSet};
use fireemu_core_types::ids::CollectionId;
use fireemu_core_types::time::LogicalInstant;

/// How long a local field change stays pending.
pub const DEFAULT_FIELD_APPLY: Duration = Duration::from_millis(1500);

/// Single-field index modes, as an override lists them.
pub type Modes = Vec<(IndexQueryScope, IndexFieldMode)>;

/// What a patch changes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldChange {
    /// Enables a time-to-live policy on the field.
    TtlAdd,
    /// Removes the field's time-to-live policy.
    TtlRemove,
    /// Replaces the field's single-field indexes (`Some`), or makes it inherit again (`None`).
    IndexConfig(Option<Modes>),
}

/// One patch.
#[derive(Debug, Clone)]
pub struct FieldPatch {
    /// Project.
    pub project: String,
    /// Database.
    pub database: String,
    /// Collection group.
    pub group: CollectionId,
    /// The field (a literal path).
    pub field: FieldPath,
    /// The change.
    pub change: FieldChange,
    /// When it was made (wall clock).
    pub started: Instant,
    /// When it was made (virtual clock).
    pub start_time: LogicalInstant,
    /// The operation that applies it.
    pub operation: String,
}

#[derive(Debug, Default)]
struct State {
    patches: Vec<FieldPatch>,
}

/// The runtime field patches of every database of one backend.
#[derive(Debug)]
pub struct FieldRegistry {
    state: Mutex<State>,
    apply: Mutex<Duration>,
}

impl Default for FieldRegistry {
    fn default() -> Self {
        Self {
            state: Mutex::new(State::default()),
            apply: Mutex::new(DEFAULT_FIELD_APPLY),
        }
    }
}

impl FieldRegistry {
    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Sets how long a change stays pending (tests and embedders).
    pub fn set_apply_duration(&self, apply: Duration) {
        *self
            .apply
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = apply;
    }

    /// Whether `patch` has been applied at virtual time `now`.
    #[must_use]
    pub fn applied(&self, patch: &FieldPatch, now: LogicalInstant) -> bool {
        let apply = *self
            .apply
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        patch.started.elapsed() >= apply
            || now.as_nanos() - patch.start_time.as_nanos()
                >= i128::try_from(apply.as_nanos()).unwrap_or(i128::MAX)
    }

    /// Records a patch.
    pub fn record(&self, patch: FieldPatch) {
        self.lock().patches.push(patch);
    }

    /// The patch an operation applies.
    #[must_use]
    pub fn by_operation(&self, operation: &str) -> Option<FieldPatch> {
        self.lock()
            .patches
            .iter()
            .find(|p| p.operation == operation)
            .cloned()
    }

    /// The patches of one field, oldest first.
    #[must_use]
    pub fn of_field(
        &self,
        project: &str,
        database: &str,
        group: &CollectionId,
        field: &FieldPath,
    ) -> Vec<FieldPatch> {
        self.lock()
            .patches
            .iter()
            .filter(|p| {
                p.project == project
                    && p.database == database
                    && &p.group == group
                    && &p.field == field
            })
            .cloned()
            .collect()
    }

    /// The fields of a collection group with any patch, in first-patched order.
    #[must_use]
    pub fn fields_of_group(
        &self,
        project: &str,
        database: &str,
        group: &CollectionId,
    ) -> Vec<FieldPath> {
        let mut out: Vec<FieldPath> = Vec::new();
        for patch in &self.lock().patches {
            if patch.project == project
                && patch.database == database
                && &patch.group == group
                && !out.contains(&patch.field)
            {
                out.push(patch.field.clone());
            }
        }
        out
    }

    /// Applies every applied index-configuration patch of a database to the planner's catalog,
    /// in patch order.
    pub fn overlay(&self, project: &str, database: &str, now: LogicalInstant, set: &mut IndexSet) {
        let patches: Vec<FieldPatch> = self
            .lock()
            .patches
            .iter()
            .filter(|p| p.project == project && p.database == database)
            .cloned()
            .collect();
        for patch in patches {
            if !self.applied(&patch, now) {
                continue;
            }
            if let FieldChange::IndexConfig(modes) = &patch.change {
                match modes {
                    Some(modes) => {
                        set.set_single_field_indexes(&patch.group, &patch.field, modes.clone());
                    }
                    None => {
                        set.clear_single_field_override(&patch.group, &patch.field);
                    }
                }
            }
        }
    }

    /// Forgets the patches `owned` selects (a session reset or a database delete).
    pub fn forget(&self, owned: impl Fn(&str, &str) -> bool) {
        self.lock()
            .patches
            .retain(|p| !owned(&p.project, &p.database));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn patch(change: FieldChange, at: i128) -> FieldPatch {
        FieldPatch {
            project: "p".into(),
            database: "d".into(),
            group: CollectionId::try_new("items").unwrap(),
            field: FieldPath::parse("nx").unwrap(),
            change,
            started: Instant::now(),
            start_time: LogicalInstant::from_nanos(at),
            operation: format!("op{at}"),
        }
    }

    #[test]
    fn an_exemption_applies_only_after_it_is_pending_and_a_revert_restores_inheritance() {
        let registry = FieldRegistry::default();
        registry.set_apply_duration(Duration::from_secs(60));
        let group = CollectionId::try_new("items").unwrap();
        let field = FieldPath::parse("nx").unwrap();
        registry.record(patch(FieldChange::IndexConfig(Some(Vec::new())), 0));
        let mut set = IndexSet::default();
        registry.overlay("p", "d", LogicalInstant::from_nanos(0), &mut set);
        assert_eq!(
            set.single_field_modes(&group, &field).len(),
            3,
            "pending: still indexed"
        );
        let later = LogicalInstant::from_nanos(60 * 1_000_000_000);
        let mut set = IndexSet::default();
        registry.overlay("p", "d", later, &mut set);
        assert!(
            set.single_field_modes(&group, &field).is_empty(),
            "applied: exempt"
        );
        registry.record(patch(FieldChange::IndexConfig(None), 60 * 1_000_000_000));
        let much_later = LogicalInstant::from_nanos(120 * 1_000_000_000);
        let mut set = IndexSet::default();
        registry.overlay("p", "d", much_later, &mut set);
        assert_eq!(
            set.single_field_modes(&group, &field).len(),
            3,
            "reverted: inherits"
        );
        assert_eq!(registry.of_field("p", "d", &group, &field).len(), 2);
        assert!(registry.by_operation("op0").is_some());
        registry.forget(|p, d| p == "p" && d == "d");
        assert!(registry.of_field("p", "d", &group, &field).is_empty());
    }
}
