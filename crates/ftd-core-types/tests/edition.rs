//! Database edition and API mode are fixed database capabilities, not per-request guesses.

use ftd_core_types::edition::{
    DatabaseCapabilities, EditionError, FeatureCapability, FirestoreApiMode, FirestoreEdition,
};
use ftd_core_types::ids::LimitCatalogId;

#[test]
fn standard_native_has_no_pipeline_or_text_search() {
    let caps = DatabaseCapabilities::try_new(
        FirestoreEdition::Standard,
        FirestoreApiMode::Native,
        LimitCatalogId::try_new("firestore-standard-2026-08-25").unwrap(),
    )
    .unwrap();
    assert!(caps.core_operations);
    assert!(!caps.pipeline_operations);
    assert_eq!(caps.text_search, FeatureCapability::Unsupported);
}

#[test]
fn enterprise_native_declares_pipeline_and_preview_text_search() {
    let caps = DatabaseCapabilities::try_new(
        FirestoreEdition::Enterprise,
        FirestoreApiMode::Native,
        LimitCatalogId::try_new("firestore-enterprise-native-2026-08-27").unwrap(),
    )
    .unwrap();
    assert!(caps.pipeline_operations);
    assert_eq!(caps.text_search, FeatureCapability::Preview);
}

#[test]
fn standard_with_mongodb_compatible_is_rejected() {
    let err = DatabaseCapabilities::try_new(
        FirestoreEdition::Standard,
        FirestoreApiMode::MongoDbCompatible,
        LimitCatalogId::try_new("firestore-standard-2026-08-25").unwrap(),
    )
    .unwrap_err();
    assert_eq!(
        err,
        EditionError::InvalidCombination {
            edition: FirestoreEdition::Standard,
            api_mode: FirestoreApiMode::MongoDbCompatible,
        }
    );
}

#[test]
fn catalog_edition_must_match_database_edition() {
    let err = DatabaseCapabilities::try_new(
        FirestoreEdition::Enterprise,
        FirestoreApiMode::Native,
        LimitCatalogId::try_new("firestore-standard-2026-08-25").unwrap(),
    )
    .unwrap_err();
    assert!(matches!(err, EditionError::CatalogEditionMismatch { .. }));
}

#[test]
fn edition_and_mode_have_stable_config_names() {
    assert_eq!(FirestoreEdition::Standard.as_config_str(), "standard");
    assert_eq!(FirestoreEdition::Enterprise.as_config_str(), "enterprise");
    assert_eq!(FirestoreApiMode::Native.as_config_str(), "native");
    assert_eq!(
        FirestoreApiMode::MongoDbCompatible.as_config_str(),
        "mongodb-compatible"
    );
    assert_eq!(
        FirestoreEdition::parse_config_str("enterprise"),
        Some(FirestoreEdition::Enterprise)
    );
    assert_eq!(FirestoreEdition::parse_config_str("strict"), None);
}
