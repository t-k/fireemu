//! Text Index definitions and their validation (`FS-TEXT-VAL-1`, spec 8.9.5):
//! `strict-validation-only` in 1.0. Definitions come from `firestore.text-indexes.json`
//! or the control API; they are checked for duplicates, field validity, scopes, the
//! supported index / match types, language tags and the override policy. No posting data
//! is built and no search runs.

use std::fmt;

use crate::field_path::FieldPath;
use crate::index::IndexQueryScope;
use fireemu_core_types::ids::CollectionId;

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
        let shape = |d: &TextIndexDefinition| {
            let mut fields: Vec<String> = d
                .fields
                .iter()
                .map(|f| {
                    format!(
                        "{}|{:?}|{:?}",
                        f.path.canonical(),
                        f.index_type,
                        f.match_type
                    )
                })
                .collect();
            fields.sort();
            (
                d.collection_id.clone(),
                d.query_scope,
                d.api_scope.clone(),
                fields,
                d.language.clone(),
                d.language_override.clone(),
            )
        };
        let same_shape = self.definitions.iter().any(|d| shape(d) == shape(&def));
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

/// The definitions of every database, keyed by `(project, database)`: sessions see and
/// change only the databases of the projects they own.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TextIndexCatalog {
    sets: std::collections::BTreeMap<(String, String), TextIndexSet>,
}

impl TextIndexCatalog {
    /// A cheap, saturating estimate of heap bytes retained by a session snapshot.
    #[must_use]
    pub fn retained_bytes(&self) -> u64 {
        const BTREE_ENTRY_OVERHEAD: u64 = 128;

        fn bytes(value: usize) -> u64 {
            u64::try_from(value).unwrap_or(u64::MAX)
        }

        fn field_path_bytes(path: &FieldPath) -> u64 {
            path.segments().iter().fold(
                bytes(path.segments().len()).saturating_mul(bytes(core::mem::size_of::<String>())),
                |total, segment| total.saturating_add(bytes(segment.capacity())),
            )
        }

        let mut total = 0u64;
        for ((project, database), set) in &self.sets {
            total = total
                .saturating_add(BTREE_ENTRY_OVERHEAD)
                .saturating_add(bytes(project.capacity()))
                .saturating_add(bytes(database.capacity()))
                .saturating_add(
                    bytes(set.definitions.capacity())
                        .saturating_mul(bytes(core::mem::size_of::<TextIndexDefinition>())),
                );
            for definition in &set.definitions {
                total = total
                    .saturating_add(bytes(definition.id.capacity()))
                    .saturating_add(bytes(definition.collection_id.as_str().len()))
                    .saturating_add(bytes(definition.api_scope.capacity()))
                    .saturating_add(
                        bytes(definition.fields.capacity())
                            .saturating_mul(bytes(core::mem::size_of::<TextIndexedField>())),
                    );
                for field in &definition.fields {
                    total = total.saturating_add(field_path_bytes(&field.path));
                }
                if let DefaultTextLanguage::Tag(language) = &definition.language {
                    total = total.saturating_add(bytes(language.capacity()));
                }
                if let LanguageOverridePolicy::ExplicitField(path) = &definition.language_override {
                    total = total.saturating_add(field_path_bytes(path));
                }
            }
        }
        total
    }

    /// Validates and adds a definition to one database; returns its warnings.
    pub fn add(
        &mut self,
        project: &str,
        database: &str,
        def: TextIndexDefinition,
    ) -> Result<Vec<String>, TextIndexError> {
        self.sets
            .entry((project.to_owned(), database.to_owned()))
            .or_default()
            .add(def)
    }

    /// Removes a definition; `true` when it existed.
    pub fn remove(&mut self, project: &str, database: &str, id: &str) -> bool {
        let key = (project.to_owned(), database.to_owned());
        let Some(set) = self.sets.get_mut(&key) else {
            return false;
        };
        let removed = set.remove(id);
        if set.definitions().is_empty() {
            self.sets.remove(&key);
        }
        removed
    }

    /// A definition by database and ID.
    #[must_use]
    pub fn get(&self, project: &str, database: &str, id: &str) -> Option<&TextIndexDefinition> {
        self.sets
            .get(&(project.to_owned(), database.to_owned()))
            .and_then(|s| s.get(id))
    }

    /// Every definition with its database, in `(project, database)` then load order.
    pub fn entries(&self) -> impl Iterator<Item = (&str, &str, &TextIndexDefinition)> {
        self.sets.iter().flat_map(|((p, d), set)| {
            set.definitions()
                .iter()
                .map(move |def| (p.as_str(), d.as_str(), def))
        })
    }

    /// The definitions of the projects `owned` selects.
    #[must_use]
    pub fn extract(&self, owned: impl Fn(&str) -> bool) -> Self {
        Self {
            sets: self
                .sets
                .iter()
                .filter(|((p, _), _)| owned(p))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
        }
    }

    /// Replaces the definitions of the projects `owned` selects with `captured`'s.
    pub fn replace(&mut self, owned: impl Fn(&str) -> bool, captured: &Self) {
        self.sets.retain(|(p, _), _| !owned(p));
        for (k, v) in &captured.sets {
            if owned(&k.0) {
                self.sets.insert(k.clone(), v.clone());
            }
        }
    }

    /// Drops the definitions of the projects `owned` selects.
    pub fn retain_others(&mut self, owned: impl Fn(&str) -> bool) {
        self.sets.retain(|(p, _), _| !owned(p));
    }

    /// Number of definitions.
    #[must_use]
    pub fn len(&self) -> usize {
        self.sets.values().map(|s| s.definitions().len()).sum()
    }

    /// Whether there is no definition.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod retained_bytes_tests {
    use super::*;

    #[test]
    fn definitions_increase_the_snapshot_estimate() {
        let mut catalog = TextIndexCatalog::default();
        let empty = catalog.retained_bytes();
        catalog
            .add(
                "demo-app",
                "(default)",
                TextIndexDefinition {
                    id: "search-index".repeat(8),
                    collection_id: CollectionId::try_new("articles").expect("collection"),
                    query_scope: IndexQueryScope::Collection,
                    api_scope: "ANY_API".to_owned(),
                    fields: vec![TextIndexedField {
                        path: FieldPath::parse("description.long_field").expect("field path"),
                        index_type: TextIndexType::Tokenized,
                        match_type: TextMatchType::MatchGlobally,
                    }],
                    language: DefaultTextLanguage::Tag("en-US".to_owned()),
                    language_override: LanguageOverridePolicy::ExplicitField(
                        FieldPath::parse("locale").expect("field path"),
                    ),
                    state: TextIndexState::Ready,
                },
            )
            .expect("valid definition");

        assert!(catalog.retained_bytes() > empty);
    }
}
