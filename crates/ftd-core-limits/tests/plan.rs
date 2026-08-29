//! Plan profile overrides apply only to the documented limit IDs (spec 8.10.6).

use ftd_core_limits::catalogs;
use ftd_core_limits::plan::FirestorePlanProfile;

#[test]
fn overrides_apply_only_to_their_own_limit_ids() {
    let standard = &catalogs::FIRESTORE_STANDARD_2026_08_25;
    let enterprise = &catalogs::FIRESTORE_ENTERPRISE_NATIVE_2026_08_27;
    let composite = standard.find("FS-LIMIT-COMPOSITE-INDEXES").unwrap();
    let single = standard.find("FS-LIMIT-SINGLE-FIELD-CONFIGS").unwrap();
    let ent = enterprise.find("FS-ENT-LIMIT-INDEXES").unwrap();
    let unrelated = standard.find("FS-LIMIT-DOCUMENT-BYTES").unwrap();

    let none = FirestorePlanProfile::default();
    assert!(!none.has_overrides());
    assert_eq!(none.resolve_maximum(composite), Some(200));

    let c = FirestorePlanProfile {
        composite_index_limit_override: Some(1_500),
        ..FirestorePlanProfile::default()
    };
    assert!(c.has_overrides());
    assert_eq!(c.resolve_maximum(composite), Some(1_500));
    assert_eq!(c.resolve_maximum(single), Some(200));
    assert_eq!(c.resolve_maximum(ent), Some(200));

    let s = FirestorePlanProfile {
        single_field_config_limit_override: Some(1_600),
        billing_enabled: true,
        ..FirestorePlanProfile::default()
    };
    assert!(s.has_overrides());
    assert_eq!(s.resolve_maximum(single), Some(1_600));
    assert_eq!(s.resolve_maximum(composite), Some(1_000));

    let e = FirestorePlanProfile {
        enterprise_index_limit_override: Some(1_700),
        ..FirestorePlanProfile::default()
    };
    assert!(e.has_overrides());
    assert_eq!(e.resolve_maximum(ent), Some(1_700));
    assert_eq!(e.resolve_maximum(composite), Some(200));
    assert_eq!(e.resolve_maximum(unrelated), Some(1_048_576));
}
