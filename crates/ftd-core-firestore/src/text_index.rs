//! Text Index definitions and their validation (`FS-TEXT-VAL-1`, spec 8.9.5):
//! `strict-validation-only` in 1.0. Definitions come from `firestore.text-indexes.json`
//! or the control API; they are checked for duplicates, field validity, scopes, the
//! supported index / match types, language tags and the override policy. No posting data
//! is built and no search runs.

use std::fmt;

use crate::field_path::FieldPath;
use crate::index::IndexQueryScope;
use ftd_core_types::ids::CollectionId;

/// Maximum indexed fields per text index (Enterprise limit placeholder; conformance item).
pub const MAX_FIELDS_PER_INDEX: usize = 25;
/// Maximum text indexes per database (Enterprise limit placeholder; conformance item).
pub const MAX_TEXT_INDEXES: usize = 200;

/// Tokenization type (initial support: `TOKENIZED`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextIndexType {
    /// Tokenized full text.
    Tokenized,
}

/// Match type (initial support: `MATCH_GLOBALLY`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextMatchType {
    /// Match anywhere in the field.
    MatchGlobally,
}

/// One indexed field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextIndexedField {
    /// Field.
    pub path: FieldPath,
    /// Index type.
    pub index_type: TextIndexType,
    /// Match type.
    pub match_type: TextMatchType,
}

/// The index's default language.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DefaultTextLanguage {
    /// A BCP 47 tag.
    Tag(String),
    /// Autodetect per document.
    Autodetect,
}

/// Where a document's language comes from when it differs from the default.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LanguageOverridePolicy {
    /// A named field.
    ExplicitField(FieldPath),
    /// The backend's implicit `language` field.
    ImplicitLanguageField,
    /// No override.
    Disabled,
    /// The import did not say (a warning in validation-only mode).
    BackendDefaultUnresolved,
}

/// Lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextIndexState {
    /// Being built.
    Creating,
    /// Serving.
    Ready,
    /// Needs a repair.
    NeedsRepair,
}

impl TextIndexState {
    /// Name as in the canonical file.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Creating => "CREATING",
            Self::Ready => "READY",
            Self::NeedsRepair => "NEEDS_REPAIR",
        }
    }

    /// Parses the canonical name.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "CREATING" => Some(Self::Creating),
            "READY" => Some(Self::Ready),
            "NEEDS_REPAIR" => Some(Self::NeedsRepair),
            _ => None,
        }
    }
}

/// A validated definition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextIndexDefinition {
    /// Index ID (the last segment of the Admin API name).
    pub id: String,
    /// Collection group.
    pub collection_id: CollectionId,
    /// Query scope.
    pub query_scope: IndexQueryScope,
    /// API scope (`ANY_API`, ...).
    pub api_scope: String,
    /// Indexed fields.
    pub fields: Vec<TextIndexedField>,
    /// Default language.
    pub language: DefaultTextLanguage,
    /// Override policy.
    pub language_override: LanguageOverridePolicy,
    /// State.
    pub state: TextIndexState,
}

/// Why a definition is refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TextIndexError {
    /// Empty or malformed ID.
    InvalidId(String),
    /// The ID is already defined (delete first, or replace explicitly).
    DuplicateId(String),
    /// No indexed field.
    NoFields,
    /// A field is listed twice.
    DuplicateField(String),
    /// Too many fields.
    TooManyFields(usize),
    /// Too many indexes.
    TooManyIndexes,
    /// Not a BCP 47 language tag.
    InvalidLanguage(String),
    /// Unsupported API scope.
    InvalidApiScope(String),
}

impl fmt::Display for TextIndexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidId(id) => write!(f, "invalid text index id {id:?}"),
            Self::DuplicateId(id) => write!(
                f,
                "text index {id:?} is already defined (DELETE it first or replace explicitly)"
            ),
            Self::NoFields => f.write_str("a text index needs at least one indexed field"),
            Self::DuplicateField(p) => write!(f, "field {p:?} is listed twice"),
            Self::TooManyFields(n) => {
                write!(f, "{n} indexed fields exceed {MAX_FIELDS_PER_INDEX}")
            }
            Self::TooManyIndexes => write!(f, "more than {MAX_TEXT_INDEXES} text indexes"),
            Self::InvalidLanguage(t) => write!(f, "{t:?} is not a BCP 47 language tag"),
            Self::InvalidApiScope(s) => write!(f, "unsupported apiScope {s:?}"),
        }
    }
}

impl std::error::Error for TextIndexError {}

/// Whether `tag` has the shape of a BCP 47 language tag with an ISO 639 primary subtag
/// (`ja`, `en-US`, `zh-Hant-TW`); registered 5-8 letter primaries are not accepted.
#[must_use]
pub fn is_language_tag(tag: &str) -> bool {
    let mut parts = tag.split('-');
    let Some(primary) = parts.next() else {
        return false;
    };
    if !(2..=3).contains(&primary.len()) || !primary.bytes().all(|b| b.is_ascii_alphabetic()) {
        return false;
    }
    parts.all(|p| (1..=8).contains(&p.len()) && p.bytes().all(|b| b.is_ascii_alphanumeric()))
}

/// The definitions of one database.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TextIndexSet {
    definitions: Vec<TextIndexDefinition>,
}

impl TextIndexSet {
    /// Validates and adds a definition; returns warnings (`FS_TEXT_*` codes).
    pub fn add(&mut self, def: TextIndexDefinition) -> Result<Vec<String>, TextIndexError> {
        if def.id.is_empty()
            || def.id.len() > 128
            || !def
                .id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
        {
            return Err(TextIndexError::InvalidId(def.id.clone()));
        }
        if self.definitions.iter().any(|d| d.id == def.id) {
            return Err(TextIndexError::DuplicateId(def.id.clone()));
        }
        if self.definitions.len() >= MAX_TEXT_INDEXES {
            return Err(TextIndexError::TooManyIndexes);
        }
        if def.fields.is_empty() {
            return Err(TextIndexError::NoFields);
        }
        if def.fields.len() > MAX_FIELDS_PER_INDEX {
            return Err(TextIndexError::TooManyFields(def.fields.len()));
        }
        for (i, f) in def.fields.iter().enumerate() {
            if def.fields[..i].iter().any(|g| g.path == f.path) {
                return Err(TextIndexError::DuplicateField(f.path.canonical()));
            }
        }
        if let DefaultTextLanguage::Tag(t) = &def.language {
            if !is_language_tag(t) {
                return Err(TextIndexError::InvalidLanguage(t.clone()));
            }
        }
        if !matches!(
            def.api_scope.as_str(),
            "ANY_API" | "DATASTORE_MODE_API" | "MONGODB_COMPATIBLE_API"
        ) {
            return Err(TextIndexError::InvalidApiScope(def.api_scope.clone()));
        }
        let mut warnings = Vec::new();
        if def.language_override == LanguageOverridePolicy::BackendDefaultUnresolved {
            warnings.push("FS_TEXT_LANGUAGE_OVERRIDE_UNRESOLVED".to_owned());
        }
        let same_shape = self.definitions.iter().any(|d| {
            d.collection_id == def.collection_id
                && d.query_scope == def.query_scope
                && d.fields == def.fields
                && d.language == def.language
                && d.language_override == def.language_override
        });
        if same_shape {
            warnings.push("FS_TEXT_DUPLICATE_INDEX_DEFINITION".to_owned());
        }
        self.definitions.push(def);
        Ok(warnings)
    }

    /// Removes a definition; `true` when it existed.
    pub fn remove(&mut self, id: &str) -> bool {
        let before = self.definitions.len();
        self.definitions.retain(|d| d.id != id);
        self.definitions.len() != before
    }

    /// A definition by ID.
    #[must_use]
    pub fn get(&self, id: &str) -> Option<&TextIndexDefinition> {
        self.definitions.iter().find(|d| d.id == id)
    }

    /// Every definition, in load order.
    #[must_use]
    pub fn definitions(&self) -> &[TextIndexDefinition] {
        &self.definitions
    }
}
