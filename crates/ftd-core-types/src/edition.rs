//! Firestore database edition and API mode (spec 7.2, ADR-021).
//!
//! Edition and API mode are first-class database capabilities fixed at database creation.
//! They are never inferred per request and never mutated in place.

use core::fmt;

use crate::ids::LimitCatalogId;

/// Firestore database edition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FirestoreEdition {
    /// Firestore Standard edition.
    Standard,
    /// Firestore Enterprise edition.
    Enterprise,
}

impl FirestoreEdition {
    /// Canonical config value (`firestore.edition`).
    #[must_use]
    pub const fn as_config_str(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::Enterprise => "enterprise",
        }
    }

    /// Parses the canonical config value.
    #[must_use]
    pub fn parse_config_str(s: &str) -> Option<Self> {
        match s {
            "standard" => Some(Self::Standard),
            "enterprise" => Some(Self::Enterprise),
            _ => None,
        }
    }
}

impl fmt::Display for FirestoreEdition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_config_str())
    }
}

/// Firestore API mode: the protocol and semantic family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FirestoreApiMode {
    /// Native Firestore RPC / REST API.
    Native,
    /// MongoDB-compatible API (Enterprise only).
    MongoDbCompatible,
}

impl FirestoreApiMode {
    /// Canonical config value (`firestore.apiMode`).
    #[must_use]
    pub const fn as_config_str(self) -> &'static str {
        match self {
            Self::Native => "native",
            Self::MongoDbCompatible => "mongodb-compatible",
        }
    }

    /// Parses the canonical config value.
    #[must_use]
    pub fn parse_config_str(s: &str) -> Option<Self> {
        match s {
            "native" => Some(Self::Native),
            "mongodb-compatible" => Some(Self::MongoDbCompatible),
            _ => None,
        }
    }
}

impl fmt::Display for FirestoreApiMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_config_str())
    }
}

/// Availability of a feature for a database.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FeatureCapability {
    /// The feature is not offered for this edition / API mode combination.
    Unsupported,
    /// The feature is offered as a Preview by the official backend.
    Preview,
    /// The feature is generally available on the official backend.
    GeneralAvailability,
}

/// Fixed capabilities of a database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatabaseCapabilities {
    /// Database edition.
    pub edition: FirestoreEdition,
    /// API mode.
    pub api_mode: FirestoreApiMode,
    /// Whether Core (Standard-style) query operations are available.
    pub core_operations: bool,
    /// Whether Pipeline operations (`ExecutePipeline`) are available.
    pub pipeline_operations: bool,
    /// Text Search availability.
    pub text_search: FeatureCapability,
    /// Geospatial search availability.
    pub geospatial_search: FeatureCapability,
    /// Immutable limit catalog governing this database.
    pub limit_catalog_id: LimitCatalogId,
}

/// Errors raised when fixing database capabilities.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EditionError {
    /// The edition / API mode combination does not exist on the official backend.
    InvalidCombination {
        /// Requested edition.
        edition: FirestoreEdition,
        /// Requested API mode.
        api_mode: FirestoreApiMode,
    },
    /// The limit catalog belongs to a different edition.
    CatalogEditionMismatch {
        /// Database edition.
        edition: FirestoreEdition,
        /// Offending catalog ID.
        catalog: LimitCatalogId,
    },
}

impl fmt::Display for EditionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCombination { edition, api_mode } => {
                write!(f, "edition {edition} does not support API mode {api_mode}")
            }
            Self::CatalogEditionMismatch { edition, catalog } => {
                write!(
                    f,
                    "limit catalog {catalog} does not belong to edition {edition}"
                )
            }
        }
    }
}

impl std::error::Error for EditionError {}

impl DatabaseCapabilities {
    /// Fixes the capabilities for a database, rejecting impossible combinations.
    pub fn try_new(
        edition: FirestoreEdition,
        api_mode: FirestoreApiMode,
        limit_catalog_id: LimitCatalogId,
    ) -> Result<Self, EditionError> {
        if edition == FirestoreEdition::Standard && api_mode == FirestoreApiMode::MongoDbCompatible
        {
            return Err(EditionError::InvalidCombination { edition, api_mode });
        }
        let expected_prefix = match edition {
            FirestoreEdition::Standard => "firestore-standard-",
            FirestoreEdition::Enterprise => "firestore-enterprise-",
        };
        if !limit_catalog_id.as_str().starts_with(expected_prefix) {
            return Err(EditionError::CatalogEditionMismatch {
                edition,
                catalog: limit_catalog_id,
            });
        }
        let (pipeline_operations, text_search, geospatial_search) = match (edition, api_mode) {
            // Status as of the spec baseline date 2026-08-29: Pipeline operations are GA and
            // Text Search is Preview (Firestore release notes, 2026-04-20).
            (FirestoreEdition::Enterprise, FirestoreApiMode::Native) => {
                (true, FeatureCapability::Preview, FeatureCapability::Preview)
            }
            // Standard has neither. MongoDB-compatible Text Search is a separate protocol
            // (FS-MONGO-TEXT-0) and is declared unsupported until a dedicated track exists.
            (FirestoreEdition::Standard | FirestoreEdition::Enterprise, _) => (
                false,
                FeatureCapability::Unsupported,
                FeatureCapability::Unsupported,
            ),
        };
        Ok(Self {
            edition,
            api_mode,
            core_operations: api_mode == FirestoreApiMode::Native,
            pipeline_operations,
            text_search,
            geospatial_search,
            limit_catalog_id,
        })
    }
}
