//! Generated catalogs must match the spec tables and stay internally consistent.

use std::collections::BTreeSet;

use ftd_core_limits::catalogs::{self, ALL_CATALOGS};
use ftd_core_limits::model::{
    EnforcementPrecision, EnforcementStage, ImplementationStatus, LimitBoundary, LimitMaximum,
    LimitUnit,
};
use ftd_core_types::ids::{LimitCatalogId, MAX_ID_UTF8_BYTES};

#[test]
fn all_catalog_ids_are_valid_and_unique() {
    let mut seen = BTreeSet::new();
    for c in ALL_CATALOGS {
        LimitCatalogId::try_new(c.meta.id).unwrap();
        assert!(seen.insert(c.meta.id), "duplicate catalog id {}", c.meta.id);
        assert!(!c.limits.is_empty());
    }
}

#[test]
fn limit_ids_are_unique_across_all_catalogs() {
    let mut seen = BTreeSet::new();
    for c in ALL_CATALOGS {
        for l in c.limits {
            assert!(seen.insert(l.id), "duplicate limit id {}", l.id);
        }
    }
}

#[test]
fn every_limit_has_an_implementation_status_and_official_text() {
    for c in ALL_CATALOGS {
        for l in c.limits {
            assert!(!l.official_text.is_empty(), "{} lacks official text", l.id);
            // Every entry is classified (spec 35.2); the match is exhaustive by construction.
            let classified = matches!(
                l.implemented,
                ImplementationStatus::Implemented
                    | ImplementationStatus::Unsupported
                    | ImplementationStatus::NotApplicable
            );
            assert!(classified);
            if l.precision == EnforcementPrecision::Exact {
                assert!(
                    !matches!(l.maximum, LimitMaximum::NotApplicable),
                    "{} claims exact precision without a maximum",
                    l.id
                );
            }
        }
    }
}

#[test]
fn standard_catalog_matches_spec_table() {
    let c = &catalogs::FIRESTORE_STANDARD_2026_08_25;
    assert_eq!(c.meta.id, "firestore-standard-2026-08-25");
    assert_eq!(c.meta.edition, "standard");
    assert_eq!(c.meta.official_last_updated_utc, "2026-08-25");
    let doc = c.find("FS-LIMIT-DOCUMENT-BYTES").unwrap();
    assert_eq!(doc.maximum, LimitMaximum::Fixed(1_048_576));
    assert_eq!(doc.boundary, LimitBoundary::InclusiveMaximum);
    assert_eq!(doc.unit, LimitUnit::LogicalBytes);
    let value = c.find("FS-LIMIT-FIELD-VALUE-BYTES").unwrap();
    assert_eq!(value.maximum, LimitMaximum::Fixed(1_048_487));
    let depth = c.find("FS-LIMIT-NESTED-MAP-ARRAY-DEPTH").unwrap();
    assert_eq!(depth.maximum, LimitMaximum::Fixed(20));
    let txn = c.find("FS-LIMIT-TRANSACTION-TOTAL-TIME").unwrap();
    assert_eq!(txn.maximum, LimitMaximum::Fixed(270));
    assert_eq!(txn.unit, LimitUnit::Seconds);
    let idx = c.find("FS-LIMIT-COMPOSITE-INDEXES").unwrap();
    assert_eq!(
        idx.maximum,
        LimitMaximum::PlanDependent {
            billing_disabled: 200,
            billing_enabled: 1_000
        }
    );
    let entries = c.find("FS-LIMIT-INDEX-ENTRIES-PER-DOCUMENT").unwrap();
    assert_eq!(entries.maximum, LimitMaximum::Fixed(40_000));
    let entry_bytes = c.find("FS-LIMIT-INDEX-ENTRY-BYTES").unwrap();
    assert_eq!(entry_bytes.maximum, LimitMaximum::Fixed(7_680));
    let entry_sum = c.find("FS-LIMIT-INDEX-ENTRY-SUM-PER-DOCUMENT").unwrap();
    assert_eq!(entry_sum.maximum, LimitMaximum::Fixed(8 * 1024 * 1024));
    assert!(c.find("max_writes_per_commit").is_none());
    // Production truncates indexed values instead of rejecting the write (spec 8.10.4).
    let truncating = c.find("FS-LIMIT-INDEXED-FIELD-VALUE-BYTES").unwrap();
    assert_eq!(truncating.boundary, LimitBoundary::TruncatingMaximum);
    // Free quotas are observed, never enforced by default (spec 8.10.7).
    for l in c.limits.iter().filter(|l| l.id.starts_with("FS-QUOTA-")) {
        assert_eq!(l.enforcement_stage, EnforcementStage::Observe, "{}", l.id);
    }
}

#[test]
fn identifier_byte_limits_agree_with_core_types_constant() {
    let c = &catalogs::FIRESTORE_STANDARD_2026_08_25;
    for id in [
        "FS-LIMIT-COLLECTION-ID",
        "FS-LIMIT-DOCUMENT-ID",
        "FS-LIMIT-FIELD-NAME",
    ] {
        let l = c.find(id).unwrap();
        assert_eq!(
            l.maximum,
            LimitMaximum::Fixed(MAX_ID_UTF8_BYTES as u64),
            "{id}"
        );
        assert_eq!(l.unit, LimitUnit::Utf8Bytes, "{id}");
        assert_eq!(l.boundary, LimitBoundary::SyntaxConstraint, "{id}");
    }
}

#[test]
fn standard_query_catalog_matches_spec_table() {
    let c = &catalogs::FIRESTORE_STANDARD_QUERY_2026_08_25;
    assert_eq!(
        c.find("FS-QUERY-LIMIT-DNF-DISJUNCTIONS").unwrap().maximum,
        LimitMaximum::Fixed(30)
    );
    assert_eq!(
        c.find("FS-QUERY-LIMIT-NOT-IN-VALUES").unwrap().maximum,
        LimitMaximum::Fixed(10)
    );
    assert_eq!(
        c.find("FS-QUERY-LIMIT-INEQUALITY-FIELDS").unwrap().maximum,
        LimitMaximum::Fixed(10)
    );
    assert_eq!(
        c.find("FS-QUERY-LIMIT-COMPONENTS").unwrap().maximum,
        LimitMaximum::Fixed(100)
    );
    assert_eq!(
        c.find("FS-QUERY-LIMIT-ARRAY-CONTAINS-PER-DISJUNCTION")
            .unwrap()
            .maximum,
        LimitMaximum::Fixed(1)
    );
    assert!(c.find("FS-QUERY-LIMIT-NOT-IN-NEQ-COMBINATION").is_some());
    assert!(c
        .find("FS-QUERY-LIMIT-ARRAY-CONTAINS-COMBINATION")
        .is_some());
    for l in c.limits {
        assert_eq!(c.meta.edition, "standard");
        assert!(l.id.starts_with("FS-QUERY-LIMIT-"));
    }
}

#[test]
fn enterprise_catalog_matches_spec_table() {
    let c = &catalogs::FIRESTORE_ENTERPRISE_NATIVE_2026_08_27;
    assert_eq!(c.meta.edition, "enterprise");
    assert_eq!(c.meta.official_last_updated_utc, "2026-08-27");
    assert_eq!(
        c.find("FS-ENT-LIMIT-QUERY-MEMORY").unwrap().maximum,
        LimitMaximum::Fixed(128 * 1024 * 1024)
    );
    assert_eq!(
        c.find("FS-ENT-LIMIT-INDEXES").unwrap().maximum,
        LimitMaximum::PlanDependent {
            billing_disabled: 200,
            billing_enabled: 1_000
        }
    );
    assert_eq!(
        c.find("FS-ENT-LIMIT-INDEX-ENTRIES-PER-DOCUMENT")
            .unwrap()
            .maximum,
        LimitMaximum::Fixed(40_000)
    );
    assert_eq!(
        c.find("FS-ENT-LIMIT-FIELDS-PER-INDEX").unwrap().maximum,
        LimitMaximum::Fixed(100)
    );
    assert_eq!(
        c.find("FS-ENT-LIMIT-INDEX-ENTRY-BYTES").unwrap().maximum,
        LimitMaximum::Fixed(7_680)
    );
    assert_eq!(
        c.find("FS-ENT-LIMIT-INDEX-ENTRY-SUM-PER-DOCUMENT")
            .unwrap()
            .maximum,
        LimitMaximum::Fixed(8 * 1024 * 1024)
    );
    assert_eq!(
        c.find("FS-ENT-LIMIT-SAVED-QUERIES-PER-PROJECT")
            .unwrap()
            .maximum,
        LimitMaximum::Fixed(10_000)
    );
    assert_eq!(
        c.find("FS-ENT-LIMIT-SAVED-QUERY-BYTES").unwrap().maximum,
        LimitMaximum::Fixed(1024 * 1024)
    );
    // Saved Queries API is not implemented; the catalog keeps the entry but must not claim it.
    assert_eq!(
        c.find("FS-ENT-LIMIT-SAVED-QUERIES-PER-PROJECT")
            .unwrap()
            .implemented,
        ImplementationStatus::Unsupported
    );
}

#[test]
fn rules_catalog_matches_spec_table() {
    let c = &catalogs::FIREBASE_RULES_2026_08_25;
    let src = c.find("RULES-SOURCE-SIZE").unwrap();
    assert_eq!(src.maximum, LimitMaximum::Fixed(262_144));
    assert_eq!(src.boundary, LimitBoundary::ExclusiveMaximum);
    assert_eq!(src.unit, LimitUnit::Utf8Bytes);
    let compiled = c.find("RULES-COMPILED-SIZE").unwrap();
    assert_eq!(compiled.unit, LimitUnit::PublishedKilobytes);
    assert_eq!(compiled.maximum, LimitMaximum::Fixed(250));
    assert_eq!(compiled.precision, EnforcementPrecision::Estimated);
    assert_eq!(
        c.find("RULES-FUNCTION-ARGUMENTS").unwrap().maximum,
        LimitMaximum::Fixed(7)
    );
    assert_eq!(
        c.find("RULES-LET-BINDINGS").unwrap().maximum,
        LimitMaximum::Fixed(10)
    );
    assert_eq!(
        c.find("RULES-RECURSION").unwrap().maximum,
        LimitMaximum::Fixed(0)
    );
    assert_eq!(
        c.find("RULES-FUNCTION-CALL-DEPTH").unwrap().maximum,
        LimitMaximum::Fixed(20)
    );
    assert_eq!(
        c.find("RULES-MATCH-DEPTH").unwrap().maximum,
        LimitMaximum::Fixed(10)
    );
    assert_eq!(
        c.find("RULES-MATCH-PATH-SEGMENTS").unwrap().maximum,
        LimitMaximum::Fixed(100)
    );
    assert_eq!(
        c.find("RULES-PATH-CAPTURES").unwrap().maximum,
        LimitMaximum::Fixed(20)
    );
    assert_eq!(
        c.find("RULES-EXPRESSIONS-PER-REQUEST").unwrap().maximum,
        LimitMaximum::Fixed(1_000)
    );
    assert_eq!(
        c.find("RULES-DOC-ACCESS-SINGLE").unwrap().maximum,
        LimitMaximum::Fixed(10)
    );
    assert_eq!(
        c.find("RULES-DOC-ACCESS-MULTI-TOTAL").unwrap().maximum,
        LimitMaximum::Fixed(20)
    );
    assert_eq!(
        c.find("RULES-DOC-ACCESS-PER-OP").unwrap().maximum,
        LimitMaximum::Fixed(10)
    );
    assert_eq!(
        c.find("RULES-RULESETS-PER-PROJECT").unwrap().maximum,
        LimitMaximum::Fixed(2_500)
    );
    assert_eq!(
        c.find("STORAGE-RULES-FIRESTORE-ACCESS").unwrap().maximum,
        LimitMaximum::Fixed(2)
    );
}

#[test]
fn catalog_lookup_by_id() {
    assert!(catalogs::find_catalog("firestore-standard-2026-08-25").is_some());
    assert!(catalogs::find_catalog("firestore-standard-2026-01-01").is_none());
}
