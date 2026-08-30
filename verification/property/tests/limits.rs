//! Property artifact for INV-LIMIT-001 (spec 8.10.8, 8.10.10).

use fireemu_core_limits::evaluate::{evaluate, ratio_micros, LimitDisposition, DEFAULT_THRESHOLDS};
use fireemu_core_limits::model::{
    EnforcementPrecision, EnforcementStage, ImplementationStatus, LimitBoundary, LimitClass,
    LimitDefinition, LimitMaximum, LimitUnit,
};
use fireemu_core_limits::plan::FirestorePlanProfile;
use proptest::prelude::*;

const fn def(boundary: LimitBoundary, maximum: u64, stage: EnforcementStage) -> LimitDefinition {
    LimitDefinition {
        id: "PROP-BOUNDARY",
        class: LimitClass::HardResource,
        boundary,
        unit: LimitUnit::Count,
        maximum: LimitMaximum::Fixed(maximum),
        precision: EnforcementPrecision::Exact,
        enforcement_stage: stage,
        implemented: ImplementationStatus::Implemented,
        official_text: "property",
        notes: "",
    }
}

proptest! {
    /// INV-LIMIT-001: the boundary decision comes first. A value outside the boundary is
    /// rejected (or, on an observe-stage limit, recorded) and never downgraded to a warning;
    /// a value inside the boundary is never rejected and its usage ratio stays below 100%.
    #[test]
    fn prop_boundary_reject_precedes_warning(
        maximum in 1u64..=1_000_000,
        current in 0u64..=1_100_000,
        exclusive: bool,
        observe: bool,
    ) {
        let boundary = if exclusive {
            LimitBoundary::ExclusiveMaximum
        } else {
            LimitBoundary::InclusiveMaximum
        };
        let stage = if observe {
            EnforcementStage::Observe
        } else {
            EnforcementStage::Request
        };
        let d = def(boundary, maximum, stage);
        let plan = FirestorePlanProfile::default();
        let outside = if exclusive { current >= maximum } else { current > maximum };
        match evaluate(&d, current, &plan, DEFAULT_THRESHOLDS) {
            LimitDisposition::Reject(v) => {
                prop_assert!(outside);
                prop_assert!(!observe);
                prop_assert_eq!(v.current.value(), current);
                prop_assert_eq!(v.maximum.value(), maximum);
            }
            LimitDisposition::ObservedOverLimit(v) => {
                prop_assert!(outside);
                prop_assert!(observe);
                prop_assert_eq!(v.current.value(), current);
            }
            LimitDisposition::Allow | LimitDisposition::AllowWithWarnings(_) => {
                // Warnings are only ever produced inside the boundary.
                prop_assert!(!outside);
                prop_assert!(ratio_micros(current, maximum) <= 1_000_000);
                if exclusive {
                    prop_assert!(ratio_micros(current, maximum) < 1_000_000);
                }
            }
        }
    }
}
