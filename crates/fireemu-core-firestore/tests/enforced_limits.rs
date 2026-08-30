//! `LIMIT-META-01` / `LIMIT-META-05`: the catalog's implementation status and the runtime's
//! enforcement are the same set, in both directions.
//!
//! `fireemu_core_firestore::limits::ENFORCED_LIMIT_IDS` names every catalog limit the local
//! Firestore runtime can refuse a request over. The catalog marks a limit `implemented` when
//! it is enforced or observed locally and `unsupported` otherwise (`ImplementationStatus`),
//! `/v1/limits` reports the catalog verbatim, and the `FS-LIM-1` capability entry lists the
//! implemented ids. This test is the gate between the two: an enforcement site whose limit
//! the catalog still calls unsupported fails here, and so does a catalog entry promoted to
//! implemented without an enforcement behind it.

use std::collections::BTreeSet;

use fireemu_core_firestore::limits::{ENFORCED_LIMIT_IDS, ENFORCED_QUERY_LIMIT_IDS};
use fireemu_core_limits::catalogs::{
    FIRESTORE_STANDARD_2026_08_25, FIRESTORE_STANDARD_QUERY_2026_08_25,
};
use fireemu_core_limits::model::{EnforcementPrecision, ImplementationStatus};

#[test]
fn every_enforced_limit_is_a_catalog_entry_marked_implemented() {
    for id in ENFORCED_LIMIT_IDS {
        let limit = FIRESTORE_STANDARD_2026_08_25
            .find(id)
            .unwrap_or_else(|| panic!("{id} is enforced but is not in the Standard catalog"));
        assert_eq!(
            limit.implemented,
            ImplementationStatus::Implemented,
            "{id} is enforced by the runtime but the catalog reports it {:?}",
            limit.implemented
        );
        assert_ne!(
            limit.precision,
            EnforcementPrecision::Unsupported,
            "{id} is enforced but its precision says unsupported"
        );
    }
}

#[test]
fn every_catalog_entry_marked_implemented_is_enforced() {
    let enforced: BTreeSet<&str> = ENFORCED_LIMIT_IDS.iter().copied().collect();
    let implemented: BTreeSet<&str> = FIRESTORE_STANDARD_2026_08_25
        .limits
        .iter()
        .filter(|l| l.implemented == ImplementationStatus::Implemented)
        .map(|l| l.id)
        .collect();
    assert_eq!(
        implemented, enforced,
        "the catalog's implemented set and the runtime's enforced set differ"
    );
}

#[test]
fn the_enforced_list_has_no_duplicates() {
    let unique: BTreeSet<&str> = ENFORCED_LIMIT_IDS.iter().copied().collect();
    assert_eq!(unique.len(), ENFORCED_LIMIT_IDS.len());
    let unique: BTreeSet<&str> = ENFORCED_QUERY_LIMIT_IDS.iter().copied().collect();
    assert_eq!(unique.len(), ENFORCED_QUERY_LIMIT_IDS.len());
}

#[test]
fn the_query_catalog_and_the_evaluated_query_limits_are_the_same_set() {
    for id in ENFORCED_QUERY_LIMIT_IDS {
        let limit = FIRESTORE_STANDARD_QUERY_2026_08_25
            .find(id)
            .unwrap_or_else(|| panic!("{id} is evaluated but is not in the query catalog"));
        assert_eq!(
            limit.implemented,
            ImplementationStatus::Implemented,
            "{id} is evaluated by check_standard_limits but the catalog reports it {:?}",
            limit.implemented
        );
    }
    let evaluated: BTreeSet<&str> = ENFORCED_QUERY_LIMIT_IDS.iter().copied().collect();
    let implemented: BTreeSet<&str> = FIRESTORE_STANDARD_QUERY_2026_08_25
        .limits
        .iter()
        .filter(|l| l.implemented == ImplementationStatus::Implemented)
        .map(|l| l.id)
        .collect();
    assert_eq!(
        implemented, evaluated,
        "the query catalog's implemented set and the evaluated set differ"
    );
}
