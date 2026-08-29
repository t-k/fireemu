//! Property tests for limit dispositions (spec 25.2, Security Rules / Limit section).

use ftd_core_limits::evaluate::{
    classify_severity, evaluate, ratio_micros, LimitDisposition, WarningSeverity,
    DEFAULT_THRESHOLDS,
};
use ftd_core_limits::model::{
    EnforcementPrecision, EnforcementStage, ImplementationStatus, LimitBoundary, LimitClass,
    LimitDefinition, LimitMaximum, LimitUnit,
};
use ftd_core_limits::plan::FirestorePlanProfile;
use proptest::prelude::*;

const fn def(boundary: LimitBoundary, maximum: u64) -> LimitDefinition {
    LimitDefinition {
        id: "PROP-LIMIT",
        class: LimitClass::HardResource,
        boundary,
        unit: LimitUnit::Count,
        maximum: LimitMaximum::Fixed(maximum),
        precision: EnforcementPrecision::Exact,
        enforcement_stage: EnforcementStage::Request,
        implemented: ImplementationStatus::Implemented,
        official_text: "property",
        notes: "",
    }
}

fn rank(d: &LimitDisposition) -> u8 {
    match d {
        LimitDisposition::Allow => 0,
        LimitDisposition::AllowWithWarnings(ws) => match ws[0].severity {
            WarningSeverity::Notice => 1,
            WarningSeverity::Warning => 2,
            WarningSeverity::Critical => 3,
        },
        LimitDisposition::Reject(_) | LimitDisposition::ObservedOverLimit(_) => 4,
    }
}

proptest! {
    #[test]
    fn severity_never_decreases_with_usage(maximum in 1u64..=1_000_000, a in 0u64..=1_100_000, b in 0u64..=1_100_000) {
        let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
        let plan = FirestorePlanProfile::default();
        for boundary in [LimitBoundary::InclusiveMaximum, LimitBoundary::ExclusiveMaximum] {
            let d = def(boundary, maximum);
            prop_assert!(rank(&evaluate(&d, lo, &plan, DEFAULT_THRESHOLDS)) <= rank(&evaluate(&d, hi, &plan, DEFAULT_THRESHOLDS)));
        }
    }

    #[test]
    fn inclusive_allows_n_and_rejects_n_plus_one(maximum in 0u64..u64::MAX) {
        let d = def(LimitBoundary::InclusiveMaximum, maximum);
        let plan = FirestorePlanProfile::default();
        prop_assert!(!matches!(evaluate(&d, maximum, &plan, DEFAULT_THRESHOLDS), LimitDisposition::Reject(_)));
        prop_assert!(matches!(evaluate(&d, maximum + 1, &plan, DEFAULT_THRESHOLDS), LimitDisposition::Reject(_)));
    }

    #[test]
    fn exclusive_allows_n_minus_one_and_rejects_n(maximum in 1u64..=u64::MAX) {
        let d = def(LimitBoundary::ExclusiveMaximum, maximum);
        let plan = FirestorePlanProfile::default();
        prop_assert!(!matches!(evaluate(&d, maximum - 1, &plan, DEFAULT_THRESHOLDS), LimitDisposition::Reject(_)));
        prop_assert!(matches!(evaluate(&d, maximum, &plan, DEFAULT_THRESHOLDS), LimitDisposition::Reject(_)));
    }

    #[test]
    fn allowed_ratio_is_at_most_one(maximum in 1u64..=u64::MAX, current in 0u64..=u64::MAX) {
        prop_assume!(current <= maximum);
        prop_assert!(ratio_micros(current, maximum) <= 1_000_000);
    }

    #[test]
    fn threshold_first_fire_value_is_ceil_of_maximum_times_bp(maximum in 1u64..=10_000_000, bp in 1u16..=10_000) {
        // First value at or above the threshold is ceil(maximum * bp / 10_000).
        let first = (u128::from(maximum) * u128::from(bp)).div_ceil(10_000);
        let first = u64::try_from(first).unwrap();
        let thresholds = [ftd_core_limits::evaluate::WarningThreshold { basis_points: bp, severity: WarningSeverity::Notice }];
        prop_assert_eq!(classify_severity(first, maximum, &thresholds), Some(WarningSeverity::Notice));
        if first > 0 {
            prop_assert_eq!(classify_severity(first - 1, maximum, &thresholds), None);
        }
    }
}
