//! Limit disposition: boundary check first, then warning severity from the usage ratio.
//! Ratios use checked integer arithmetic only (spec 8.10.8).

use fireemu_core_limits::evaluate::{
    evaluate, LimitDisposition, WarningSeverity, DEFAULT_THRESHOLDS,
};
use fireemu_core_limits::model::{
    EnforcementPrecision, EnforcementStage, ImplementationStatus, LimitBoundary, LimitClass,
    LimitDefinition, LimitMaximum, LimitUnit,
};
use fireemu_core_limits::plan::FirestorePlanProfile;

const fn def(boundary: LimitBoundary, maximum: LimitMaximum) -> LimitDefinition {
    LimitDefinition {
        id: "TEST-LIMIT",
        class: LimitClass::HardResource,
        boundary,
        unit: LimitUnit::Count,
        maximum,
        precision: EnforcementPrecision::Exact,
        enforcement_stage: EnforcementStage::Request,
        implemented: ImplementationStatus::Implemented,
        official_text: "test",
        notes: "",
    }
}

fn severity(d: &LimitDisposition) -> Option<WarningSeverity> {
    match d {
        LimitDisposition::Allow => None,
        LimitDisposition::AllowWithWarnings(ws) => ws.first().map(|w| w.severity),
        LimitDisposition::Reject(_) | LimitDisposition::ObservedOverLimit(_) => {
            panic!("unexpected over-limit disposition: {d:?}")
        }
    }
}

#[test]
fn function_arguments_seven_inclusive_maximum() {
    // RULES-FUNCTION-ARGUMENTS: 6 -> warning, 7 -> allowed but critical, 8 -> reject.
    let d = def(LimitBoundary::InclusiveMaximum, LimitMaximum::Fixed(7));
    let plan = FirestorePlanProfile::default();
    assert_eq!(severity(&evaluate(&d, 5, &plan, DEFAULT_THRESHOLDS)), None);
    assert_eq!(
        severity(&evaluate(&d, 6, &plan, DEFAULT_THRESHOLDS)),
        Some(WarningSeverity::Warning)
    );
    assert_eq!(
        severity(&evaluate(&d, 7, &plan, DEFAULT_THRESHOLDS)),
        Some(WarningSeverity::Critical)
    );
    match evaluate(&d, 8, &plan, DEFAULT_THRESHOLDS) {
        LimitDisposition::Reject(v) => {
            assert_eq!(v.limit_id, "TEST-LIMIT");
            assert_eq!(v.current.value(), 8);
            assert_eq!(v.maximum.value(), 7);
        }
        other => panic!("expected rejection, got {other:?}"),
    }
}

#[test]
fn let_bindings_ten_thresholds() {
    let d = def(LimitBoundary::InclusiveMaximum, LimitMaximum::Fixed(10));
    let plan = FirestorePlanProfile::default();
    assert_eq!(severity(&evaluate(&d, 7, &plan, DEFAULT_THRESHOLDS)), None);
    assert_eq!(
        severity(&evaluate(&d, 8, &plan, DEFAULT_THRESHOLDS)),
        Some(WarningSeverity::Notice)
    );
    assert_eq!(
        severity(&evaluate(&d, 9, &plan, DEFAULT_THRESHOLDS)),
        Some(WarningSeverity::Warning)
    );
    assert_eq!(
        severity(&evaluate(&d, 10, &plan, DEFAULT_THRESHOLDS)),
        Some(WarningSeverity::Critical)
    );
    assert!(matches!(
        evaluate(&d, 11, &plan, DEFAULT_THRESHOLDS),
        LimitDisposition::Reject(_)
    ));
}

#[test]
fn rules_source_size_exclusive_maximum_thresholds() {
    // RULES-SOURCE-SIZE: exclusive maximum 262,144 bytes (spec 13.7).
    let d = def(
        LimitBoundary::ExclusiveMaximum,
        LimitMaximum::Fixed(262_144),
    );
    let plan = FirestorePlanProfile::default();
    let sev = |n: u64| severity(&evaluate(&d, n, &plan, DEFAULT_THRESHOLDS));
    assert_eq!(sev(196_607), None);
    assert_eq!(sev(196_608), Some(WarningSeverity::Notice));
    assert_eq!(sev(222_822), Some(WarningSeverity::Notice));
    assert_eq!(sev(222_823), Some(WarningSeverity::Warning));
    assert_eq!(sev(249_036), Some(WarningSeverity::Warning));
    assert_eq!(sev(249_037), Some(WarningSeverity::Critical));
    assert_eq!(sev(262_143), Some(WarningSeverity::Critical));
    assert!(matches!(
        evaluate(&d, 262_144, &plan, DEFAULT_THRESHOLDS),
        LimitDisposition::Reject(_)
    ));
}

#[test]
fn ratio_micros_is_reported_without_floating_point_rounding() {
    let d = def(LimitBoundary::InclusiveMaximum, LimitMaximum::Fixed(7));
    let plan = FirestorePlanProfile::default();
    match evaluate(&d, 6, &plan, DEFAULT_THRESHOLDS) {
        LimitDisposition::AllowWithWarnings(ws) => assert_eq!(ws[0].ratio_micros, 857_142),
        other => panic!("{other:?}"),
    }
}

#[test]
fn huge_values_do_not_overflow() {
    let d = def(
        LimitBoundary::InclusiveMaximum,
        LimitMaximum::Fixed(u64::MAX),
    );
    let plan = FirestorePlanProfile::default();
    assert_eq!(
        severity(&evaluate(&d, u64::MAX, &plan, DEFAULT_THRESHOLDS)),
        Some(WarningSeverity::Critical)
    );
    assert_eq!(
        severity(&evaluate(&d, u64::MAX / 2, &plan, DEFAULT_THRESHOLDS)),
        None
    );
}

#[test]
fn zero_maximum_rejects_any_usage_and_allows_zero() {
    // RULES-RECURSION: maximum 0 cycles. A compliant ruleset (0 cycles) must not be flagged
    // as near the limit; there is no approach zone below zero.
    let d = def(LimitBoundary::InclusiveMaximum, LimitMaximum::Fixed(0));
    let plan = FirestorePlanProfile::default();
    assert_eq!(
        evaluate(&d, 0, &plan, DEFAULT_THRESHOLDS),
        LimitDisposition::Allow
    );
    assert!(matches!(
        evaluate(&d, 1, &plan, DEFAULT_THRESHOLDS),
        LimitDisposition::Reject(_)
    ));
}

#[test]
fn plan_dependent_maximum_follows_billing_and_override() {
    let d = def(
        LimitBoundary::InclusiveMaximum,
        LimitMaximum::PlanDependent {
            billing_disabled: 200,
            billing_enabled: 1_000,
        },
    );
    let free = FirestorePlanProfile {
        billing_enabled: false,
        ..FirestorePlanProfile::default()
    };
    let paid = FirestorePlanProfile {
        billing_enabled: true,
        ..FirestorePlanProfile::default()
    };
    assert!(matches!(
        evaluate(&d, 201, &free, DEFAULT_THRESHOLDS),
        LimitDisposition::Reject(_)
    ));
    assert!(matches!(
        evaluate(&d, 201, &paid, DEFAULT_THRESHOLDS),
        LimitDisposition::Allow
    ));
    assert!(matches!(
        evaluate(&d, 1_001, &paid, DEFAULT_THRESHOLDS),
        LimitDisposition::Reject(_)
    ));
}

#[test]
fn not_applicable_maximum_never_rejects() {
    let d = def(LimitBoundary::InclusiveMaximum, LimitMaximum::NotApplicable);
    let plan = FirestorePlanProfile::default();
    assert!(matches!(
        evaluate(&d, u64::MAX, &plan, DEFAULT_THRESHOLDS),
        LimitDisposition::Allow
    ));
}

#[test]
fn estimated_precision_is_carried_on_warnings_and_violations() {
    let mut d = def(LimitBoundary::InclusiveMaximum, LimitMaximum::Fixed(100));
    d.precision = EnforcementPrecision::Estimated;
    let plan = FirestorePlanProfile::default();
    match evaluate(&d, 90, &plan, DEFAULT_THRESHOLDS) {
        LimitDisposition::AllowWithWarnings(ws) => {
            assert_eq!(ws[0].precision, EnforcementPrecision::Estimated);
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn observe_stage_limits_report_but_never_reject() {
    // FS-QUOTA-*: free quotas in `observe` accounting mode must not fail a test run.
    let mut d = def(LimitBoundary::InclusiveMaximum, LimitMaximum::Fixed(50_000));
    d.enforcement_stage = EnforcementStage::Observe;
    let plan = FirestorePlanProfile::default();
    match evaluate(&d, 50_001, &plan, DEFAULT_THRESHOLDS) {
        LimitDisposition::ObservedOverLimit(v) => {
            assert_eq!(v.current.value(), 50_001);
            assert_eq!(v.maximum.value(), 50_000);
        }
        other => panic!("expected ObservedOverLimit, got {other:?}"),
    }
    assert_eq!(
        severity(&evaluate(&d, 49_000, &plan, DEFAULT_THRESHOLDS)),
        Some(WarningSeverity::Critical)
    );
}

#[test]
fn truncating_maximum_warns_but_never_rejects() {
    // FS-LIMIT-INDEXED-FIELD-VALUE-BYTES: production truncates the indexed value at 1,500
    // bytes; the full document value is kept and the write is not rejected.
    let d = def(LimitBoundary::TruncatingMaximum, LimitMaximum::Fixed(1_500));
    let plan = FirestorePlanProfile::default();
    assert_eq!(
        severity(&evaluate(&d, 1_501, &plan, DEFAULT_THRESHOLDS)),
        Some(WarningSeverity::Critical)
    );
    assert_eq!(
        severity(&evaluate(&d, 1_000, &plan, DEFAULT_THRESHOLDS)),
        None
    );
    match evaluate(&d, 10_000, &plan, DEFAULT_THRESHOLDS) {
        LimitDisposition::AllowWithWarnings(ws) => assert!(ws[0].ratio_micros > 1_000_000),
        other => panic!("{other:?}"),
    }
}

#[test]
fn boundary_helpers_and_zero_maximum_edges() {
    use fireemu_core_limits::evaluate::{ratio_micros, reaches_threshold, violates_boundary};
    assert!(!violates_boundary(LimitBoundary::Exact, 5, 5));
    assert!(violates_boundary(LimitBoundary::Exact, 4, 5));
    assert!(violates_boundary(LimitBoundary::Exact, 6, 5));
    assert!(!violates_boundary(LimitBoundary::RangeInclusive, 5, 5));
    assert!(violates_boundary(LimitBoundary::RangeInclusive, 6, 5));
    assert!(reaches_threshold(1, 0, 1));
    assert!(!reaches_threshold(0, 0, 1));
    assert_eq!(ratio_micros(0, 0), 0);
    assert_eq!(ratio_micros(1, 0), u32::MAX);
    assert_eq!(ratio_micros(1, 1), 1_000_000);
    assert_eq!(WarningSeverity::Notice.stable_code(), "LIMIT_APPROACHING");
    assert_eq!(WarningSeverity::Warning.stable_code(), "LIMIT_NEAR");
    assert_eq!(WarningSeverity::Critical.stable_code(), "LIMIT_CRITICAL");
}

#[test]
fn remediation_depends_on_limit_class() {
    use fireemu_core_limits::evaluate::RemediationCode;
    let plan = FirestorePlanProfile::default();
    let remediation = |class: LimitClass, maximum: LimitMaximum| {
        let mut d = def(LimitBoundary::InclusiveMaximum, maximum);
        d.class = class;
        match evaluate(&d, 95, &plan, DEFAULT_THRESHOLDS) {
            LimitDisposition::AllowWithWarnings(ws) => ws[0].remediation,
            other => panic!("{other:?}"),
        }
    };
    assert_eq!(
        remediation(
            LimitClass::PlanCapacity,
            LimitMaximum::PlanDependent {
                billing_disabled: 100,
                billing_enabled: 100
            }
        ),
        RemediationCode::UpgradePlan
    );
    assert_eq!(
        remediation(LimitClass::HardResource, LimitMaximum::Fixed(100)),
        RemediationCode::Split
    );
    assert_eq!(
        remediation(LimitClass::RuntimeBudget, LimitMaximum::Fixed(100)),
        RemediationCode::Split
    );
    assert_eq!(
        remediation(LimitClass::BackendOpaque, LimitMaximum::Fixed(100)),
        RemediationCode::SeeOfficialDocumentation
    );
    assert_eq!(
        remediation(LimitClass::TimeBudget, LimitMaximum::Fixed(100)),
        RemediationCode::ReduceUsage
    );
    assert_eq!(
        remediation(LimitClass::PlanCapacity, LimitMaximum::Fixed(100)),
        RemediationCode::ReduceUsage
    );
}

#[test]
fn violation_display_names_the_limit_and_values() {
    let d = def(LimitBoundary::InclusiveMaximum, LimitMaximum::Fixed(7));
    match evaluate(&d, 9, &FirestorePlanProfile::default(), DEFAULT_THRESHOLDS) {
        LimitDisposition::Reject(v) => {
            let text = v.to_string();
            assert!(
                text.contains("TEST-LIMIT") && text.contains('9') && text.contains('7'),
                "{text}"
            );
        }
        other => panic!("{other:?}"),
    }
}
