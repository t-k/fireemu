//! Plan capacity and support overrides (spec 8.10.6).

use crate::model::{LimitDefinition, LimitMaximum};

/// Billing plan profile of the emulated project.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FirestorePlanProfile {
    /// Whether billing is enabled (Blaze).
    pub billing_enabled: bool,
    /// Support-granted override for the composite index limit.
    pub composite_index_limit_override: Option<u32>,
    /// Support-granted override for the single-field configuration limit.
    pub single_field_config_limit_override: Option<u32>,
    /// Support-granted override for the Enterprise index limit.
    pub enterprise_index_limit_override: Option<u32>,
}

impl FirestorePlanProfile {
    /// Resolves the effective maximum of a limit under this plan. Overrides never apply
    /// implicitly: only the limit IDs listed here consult them.
    #[must_use]
    pub fn resolve_maximum(&self, def: &LimitDefinition) -> Option<u64> {
        let override_value = match def.id {
            "FS-LIMIT-COMPOSITE-INDEXES" => self.composite_index_limit_override,
            "FS-LIMIT-SINGLE-FIELD-CONFIGS" => self.single_field_config_limit_override,
            "FS-ENT-LIMIT-INDEXES" => self.enterprise_index_limit_override,
            _ => None,
        };
        if let Some(v) = override_value {
            return Some(u64::from(v));
        }
        match def.maximum {
            LimitMaximum::Fixed(v) => Some(v),
            LimitMaximum::PlanDependent {
                billing_disabled,
                billing_enabled,
            } => Some(if self.billing_enabled {
                billing_enabled
            } else {
                billing_disabled
            }),
            LimitMaximum::NotApplicable => None,
        }
    }

    /// Whether any support override is active. Used to surface overrides in the Capability
    /// Manifest and startup log.
    #[must_use]
    pub fn has_overrides(&self) -> bool {
        self.composite_index_limit_override.is_some()
            || self.single_field_config_limit_override.is_some()
            || self.enterprise_index_limit_override.is_some()
    }
}
