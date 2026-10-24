//! Text Index definitions and their validation (`FS-TEXT-VAL-1`, spec 8.9.5):
//! `strict-validation-only` in 1.0. Definitions come from `firestore.text-indexes.json`
//! or the control API; they are checked for duplicates, field validity, scopes, the
//! supported index / match types, language tags and the override policy. Build state is
//! explicit and generation-scoped; requests cannot silently repair or complete a failed build.

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
    /// No unique local generation remains.
    GenerationExhausted,
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
            Self::GenerationExhausted => f.write_str("text index generation capacity exhausted"),
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

/// Native build provenance and transport-neutral scheduling offsets. The owning backend
/// interprets the monotonic offset against its own lifetime; snapshots stay in that backend.
#[derive(Debug, Clone)]
pub struct NativeTextBuildSchedule {
    /// The operation's final resource segment.
    pub operation: String,
    /// Logical start instant used by the shared build timing policy.
    pub start_time: fireemu_core_types::time::LogicalInstant,
    /// Nanoseconds elapsed from the owning backend's monotonic epoch at creation.
    pub monotonic_start_nanos: u128,
    /// Identity of the owning backend epoch; cloning preserves identity rather than rebasing.
    pub owner_epoch: std::sync::Arc<()>,
}

impl PartialEq for NativeTextBuildSchedule {
    fn eq(&self, other: &Self) -> bool {
        self.operation == other.operation
            && self.start_time == other.start_time
            && self.monotonic_start_nanos == other.monotonic_start_nanos
            && std::sync::Arc::ptr_eq(&self.owner_epoch, &other.owner_epoch)
    }
}
impl Eq for NativeTextBuildSchedule {}

/// Progress of one explicit local index build. A completed snapshot is published only by
/// `completeBackfill`; advancing a batch never makes a partially built index searchable.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct TextIndexBuild {
    /// Unique local build identity, changed on repair.
    pub generation: u64,
    /// Documents visited in the frozen backfill source.
    pub processed: usize,
    /// Frozen source size, unknown until the first build operation.
    pub total: Option<usize>,
    /// Injected failure, retained until repair.
    pub failure: Option<String>,
    /// Native provenance survives bounded operation-view eviction and terminal view deletion.
    pub native: Option<NativeTextBuildSchedule>,
    source: Vec<crate::store::Document>,
    index: Option<crate::text_search::SearchIndex>,
}

impl TextIndexBuild {
    /// Real documents retained in the partial or completed positional index.
    #[must_use]
    pub fn indexed_documents(&self) -> usize {
        self.index
            .as_ref()
            .map_or(0, crate::text_search::SearchIndex::document_count)
    }

    /// The immutable partial or completed posting data.
    #[must_use]
    pub fn index(&self) -> Option<&crate::text_search::SearchIndex> {
        self.index.as_ref()
    }
}

/// Structured source refusals retain the local control API's existing error text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TextIndexSourceError {
    /// An index input failure with its original typed search cause.
    Search(crate::text_search::SearchError),
    /// A source document belongs to another project, database or collection.
    OutsideScope,
}
impl fmt::Display for TextIndexSourceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Search(error) => fmt::Display::fmt(error, f),
            Self::OutsideScope => f.write_str("document is outside the text index scope"),
        }
    }
}

/// A refused local build operation. A refusal never changes the catalog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TextIndexBuildError {
    /// The selected index does not exist.
    NotFound,
    /// An operation names a previous build generation.
    StaleGeneration,
    /// The index state does not admit the operation.
    InvalidState,
    /// Work batches must be between one and ten thousand documents.
    InvalidBatch,
    /// No further unique generation can be allocated.
    GenerationExhausted,
    /// Invalid source language or duplicate document identity.
    InvalidSource(TextIndexSourceError),
}

impl fmt::Display for TextIndexBuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Self::InvalidSource(message) = self {
            return fmt::Display::fmt(message, f);
        }
        f.write_str(match self {
            Self::InvalidSource(_) => "invalid text index source",
            Self::NotFound => "text index not found",
            Self::StaleGeneration => "text index generation has changed",
            Self::InvalidState => "text index state does not allow this build operation",
            Self::InvalidBatch => "batchSize must be an integer between 1 and 10000",
            Self::GenerationExhausted => "text index generation capacity exhausted",
        })
    }
}

impl std::error::Error for TextIndexBuildError {}

/// The definitions of every database, keyed by `(project, database)`: sessions see and
/// change only the databases of the projects they own.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct TextIndexCatalog {
    sets: std::collections::BTreeMap<(String, String), TextIndexSet>,
    builds: std::collections::BTreeMap<(String, String, String), TextIndexBuild>,
    next_generation: u64,
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
        for ((project, database, id), build) in &self.builds {
            total = total
                .saturating_add(128)
                .saturating_add(bytes(project.capacity()))
                .saturating_add(bytes(database.capacity()))
                .saturating_add(bytes(id.capacity()))
                .saturating_add(
                    bytes(build.source.capacity())
                        .saturating_mul(bytes(core::mem::size_of::<crate::store::Document>())),
                );
            for document in &build.source {
                total = total
                    .saturating_add(crate::store::document_path_retained_bytes(&document.path))
                    .saturating_add(crate::store::fields_retained_bytes(&document.fields));
            }
            if let Some(index) = &build.index {
                total = total.saturating_add(index.retained_bytes());
            }
            if let Some(native) = &build.native {
                total = total
                    .saturating_add(bytes(native.operation.capacity()))
                    .saturating_add(16);
            }
            if let Some(failure) = &build.failure {
                total = total.saturating_add(bytes(failure.capacity()));
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
        let key = (project.to_owned(), database.to_owned(), def.id.clone());
        let next = self
            .next_generation
            .checked_add(1)
            .ok_or(TextIndexError::GenerationExhausted)?;
        let database_key = (project.to_owned(), database.to_owned());
        let mut trial = self.sets.get(&database_key).cloned().unwrap_or_default();
        let warnings = trial.add(def)?;
        self.sets.insert(database_key, trial);
        self.next_generation = next;
        self.builds.insert(
            key,
            TextIndexBuild {
                generation: self.next_generation,
                ..TextIndexBuild::default()
            },
        );
        Ok(warnings)
    }

    /// Attaches Native provenance to exactly the newly inserted generation.
    pub fn schedule_native(
        &mut self,
        project: &str,
        database: &str,
        id: &str,
        generation: u64,
        schedule: NativeTextBuildSchedule,
    ) -> Result<(), TextIndexBuildError> {
        let build = self
            .builds
            .get_mut(&(project.to_owned(), database.to_owned(), id.to_owned()))
            .ok_or(TextIndexBuildError::NotFound)?;
        if build.generation != generation {
            return Err(TextIndexBuildError::StaleGeneration);
        }
        build.native = Some(schedule);
        Ok(())
    }

    /// Removes a definition; `true` when it existed.
    pub fn remove(&mut self, project: &str, database: &str, id: &str) -> bool {
        let key = (project.to_owned(), database.to_owned());
        let Some(set) = self.sets.get_mut(&key) else {
            return false;
        };
        let removed = set.remove(id);
        if removed {
            self.builds
                .remove(&(project.to_owned(), database.to_owned(), id.to_owned()));
        }
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
            builds: self
                .builds
                .iter()
                .filter(|((p, _, _), _)| owned(p))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
            next_generation: self.next_generation,
        }
    }

    /// Replaces the definitions of the projects `owned` selects with `captured`'s.
    pub fn replace(&mut self, owned: impl Fn(&str) -> bool, captured: &Self) {
        self.sets.retain(|(p, _), _| !owned(p));
        self.builds.retain(|(p, _, _), _| !owned(p));
        self.next_generation = self.next_generation.max(captured.next_generation);
        for (k, v) in &captured.builds {
            if owned(&k.0) {
                self.builds.insert(k.clone(), v.clone());
            }
        }
        for (k, v) in &captured.sets {
            if owned(&k.0) {
                self.sets.insert(k.clone(), v.clone());
            }
        }
    }

    /// Drops the definitions of the projects `owned` selects.
    pub fn retain_others(&mut self, owned: impl Fn(&str) -> bool) {
        self.sets.retain(|(p, _), _| !owned(p));
        self.builds.retain(|(p, _, _), _| !owned(p));
    }

    /// Captured build progress for exactly one project, database and index.
    #[must_use]
    pub fn build(&self, project: &str, database: &str, id: &str) -> Option<&TextIndexBuild> {
        self.builds
            .get(&(project.to_owned(), database.to_owned(), id.to_owned()))
    }

    /// Applies one explicit local lifecycle action. Documents are captured under the
    /// request's admission boundary. Completion reconciles the latest source so writes
    /// made while a build was paused are not lost.
    #[allow(clippy::too_many_arguments)]
    pub fn lifecycle(
        &mut self,
        project: &str,
        database: &str,
        id: &str,
        action: &str,
        generation: Option<u64>,
        batch: usize,
        reason: Option<&str>,
        documents: Vec<crate::store::Document>,
        analyze: fn(&str) -> Vec<String>,
    ) -> Result<(), TextIndexBuildError> {
        if !(1..=10_000).contains(&batch) {
            return Err(TextIndexBuildError::InvalidBatch);
        }
        let key = (project.to_owned(), database.to_owned(), id.to_owned());
        let def = self
            .get(project, database, id)
            .ok_or(TextIndexBuildError::NotFound)?;
        let state = def.state;
        let build = self.builds.get(&key).ok_or(TextIndexBuildError::NotFound)?;
        if generation.is_some_and(|value| value != build.generation) {
            return Err(TextIndexBuildError::StaleGeneration);
        }
        let allowed = match action {
            "advanceBackfill" | "completeBackfill" => state == TextIndexState::Creating,
            "failBuild" => matches!(state, TextIndexState::Creating | TextIndexState::Ready),
            "repair" => state == TextIndexState::NeedsRepair,
            _ => false,
        };
        if !allowed {
            return Err(TextIndexBuildError::InvalidState);
        }
        let next = if action == "repair" {
            Some(
                self.next_generation
                    .checked_add(1)
                    .ok_or(TextIndexBuildError::GenerationExhausted)?,
            )
        } else {
            None
        };
        if documents.iter().any(|document| {
            document.path.project().as_str() != project
                || document.path.database().as_str() != database
                || document.path.collection_id() != &def.collection_id
        }) {
            return Err(TextIndexBuildError::InvalidSource(
                TextIndexSourceError::OutsideScope,
            ));
        }
        let (prepared_index, prepared_processed) =
            prepare_postings(def, build, action, batch, &documents, analyze)?;
        let build = self
            .builds
            .get_mut(&key)
            .ok_or(TextIndexBuildError::NotFound)?;
        let new_state = match action {
            "failBuild" => {
                build.failure = Some(reason.unwrap_or("injected build failure").to_owned());
                build.source = Vec::new();
                build.index = None;
                TextIndexState::NeedsRepair
            }
            "repair" => {
                let next = next.ok_or(TextIndexBuildError::GenerationExhausted)?;
                self.next_generation = next;
                *build = TextIndexBuild {
                    generation: next,
                    ..TextIndexBuild::default()
                };
                TextIndexState::Creating
            }
            "advanceBackfill" => {
                if build.total.is_none() {
                    build.source = documents;
                    build.total = Some(build.source.len());
                }
                build.processed = prepared_processed;
                build.index = prepared_index;
                TextIndexState::Creating
            }
            "completeBackfill" => {
                build.processed = documents.len();
                build.total = Some(documents.len());
                build.source = Vec::new();
                build.index = prepared_index;
                TextIndexState::Ready
            }
            _ => return Err(TextIndexBuildError::InvalidState),
        };
        let set = self
            .sets
            .get_mut(&(project.to_owned(), database.to_owned()))
            .ok_or(TextIndexBuildError::NotFound)?;
        let def = set
            .definitions
            .iter_mut()
            .find(|def| def.id == id)
            .ok_or(TextIndexBuildError::NotFound)?;
        def.state = new_state;
        Ok(())
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

fn prepare_postings(
    def: &TextIndexDefinition,
    build: &TextIndexBuild,
    action: &str,
    batch: usize,
    documents: &[crate::store::Document],
    analyze: fn(&str) -> Vec<String>,
) -> Result<(Option<crate::text_search::SearchIndex>, usize), TextIndexBuildError> {
    let source_error =
        |error| TextIndexBuildError::InvalidSource(TextIndexSourceError::Search(error));
    let convert = |documents: &[crate::store::Document]| {
        documents
            .iter()
            .map(|document| crate::text_search::SearchDocument {
                path: document.path.clone(),
                fields: document.fields.clone(),
                created_at: document.create_time,
            })
            .collect::<Vec<_>>()
    };
    // Prepare all fallible posting work before changing progress or readiness.
    let mut prepared_index = None;
    let mut prepared_processed = 0;
    if action == "advanceBackfill" {
        let source = if build.total.is_none() {
            documents
        } else {
            build.source.as_slice()
        };
        prepared_processed = build.processed.saturating_add(batch).min(source.len());
        let mut index = match &build.index {
            Some(index) => index.clone(),
            None => {
                crate::text_search::SearchIndex::build(def, &[], analyze).map_err(source_error)?
            }
        };
        index
            .extend(
                def,
                &convert(&source[build.processed..prepared_processed]),
                analyze,
            )
            .map_err(source_error)?;
        prepared_index = Some(index);
    } else if action == "completeBackfill" {
        prepared_index = Some(
            crate::text_search::SearchIndex::build(def, &convert(documents), analyze)
                .map_err(source_error)?,
        );
    }
    Ok((prepared_index, prepared_processed))
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
                fireemu_core_types::ids::DatabaseId::DEFAULT,
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

#[cfg(test)]
mod generation_properties {
    use super::*;

    fn definition() -> TextIndexDefinition {
        TextIndexDefinition {
            id: "generation".into(),
            collection_id: CollectionId::try_new("items").unwrap(),
            query_scope: IndexQueryScope::Collection,
            api_scope: "ANY_API".into(),
            fields: vec![TextIndexedField {
                path: FieldPath::parse("title").unwrap(),
                index_type: TextIndexType::Tokenized,
                match_type: TextMatchType::MatchGlobally,
            }],
            language: DefaultTextLanguage::Tag("en".into()),
            language_override: LanguageOverridePolicy::ExplicitField(
                FieldPath::parse("language").unwrap(),
            ),
            state: TextIndexState::Creating,
        }
    }

    proptest::proptest! {
        #![proptest_config(proptest::test_runner::Config::with_cases(64))]
        #[test]
        fn generations_and_lifecycle_are_scoped_under_replacement(
            steps in proptest::collection::vec((0usize..4, 0u8..5, proptest::prelude::any::<bool>()), 1..64)
        ) {
            let mut catalog=TextIndexCatalog::default();
            let mut model=std::collections::BTreeMap::<usize,(u64,TextIndexState)>::new();
            let mut stale=std::collections::BTreeMap::new();
            for (scope,action,use_stale) in steps {
                let project=if scope<2 {"p"} else {"other"};
                let database=if scope%2==0 {"(default)"} else {"named"};
                if action==0 {
                    if let std::collections::btree_map::Entry::Vacant(entry) = model.entry(scope) {
                        catalog.add(project,database,definition()).unwrap();
                        let generation=catalog.build(project,database,"generation").unwrap().generation;
                        if let Some(old)=stale.get(&scope) {proptest::prop_assert!(generation>*old);}
                        entry.insert((generation,TextIndexState::Creating));
                    }
                } else if action==1 {
                    if let Some((generation,_))=model.remove(&scope) {stale.insert(scope,generation);}
                    catalog.remove(project,database,"generation");
                } else if let Some(&(generation,state))=model.get(&scope) {
                    let supplied=if use_stale {Some(stale.get(&scope).copied().unwrap_or(0))} else {Some(generation)};
                    let operation=match action {2=>"completeBackfill",3=>"failBuild",_=>"repair"};
                    let before=catalog.clone();
                    let answer=catalog.lifecycle(project,database,"generation",operation,supplied,1,None,Vec::new(),|_|Vec::new());
                    let allowed=supplied==Some(generation) && match action {2=>state==TextIndexState::Creating,3=>state!=TextIndexState::NeedsRepair,_=>state==TextIndexState::NeedsRepair};
                    proptest::prop_assert_eq!(answer.is_ok(),allowed);
                    if allowed {
                        let next_state=match action {2=>TextIndexState::Ready,3=>TextIndexState::NeedsRepair,_=>TextIndexState::Creating};
                        let next_generation=catalog.build(project,database,"generation").unwrap().generation;
                        if action==4 {proptest::prop_assert!(next_generation>generation);stale.insert(scope,generation);}
                        model.insert(scope,(next_generation,next_state));
                    } else {proptest::prop_assert_eq!(&catalog,&before);}
                }
                for (&index,&(generation,state)) in &model {
                    let p=if index<2 {"p"} else {"other"};let d=if index%2==0 {"(default)"} else {"named"};
                    proptest::prop_assert_eq!(catalog.build(p,d,"generation").unwrap().generation,generation);
                    proptest::prop_assert_eq!(catalog.get(p,d,"generation").unwrap().state,state);
                }
            }
        }
    }
}

#[cfg(test)]
mod native_schedule_tests {
    use super::*;

    #[test]
    fn source_causes_keep_the_existing_local_control_display() {
        let cause = crate::text_search::SearchError::InvalidLanguageOverride(
            "projects/p/databases/(default)/documents/items/doc".into(),
        );
        let error = TextIndexBuildError::InvalidSource(TextIndexSourceError::Search(cause.clone()));
        assert_eq!(error.to_string(), cause.to_string());
        assert!(matches!(
            error,
            TextIndexBuildError::InvalidSource(TextIndexSourceError::Search(
                crate::text_search::SearchError::InvalidLanguageOverride(_)
            ))
        ));
        assert_eq!(
            TextIndexBuildError::InvalidSource(TextIndexSourceError::OutsideScope).to_string(),
            "document is outside the text index scope"
        );
    }

    #[test]
    fn native_schedule_identity_is_pointer_based_and_survives_catalog_capture() {
        let epoch = std::sync::Arc::new(());
        let schedule = NativeTextBuildSchedule {
            operation: "operation".into(),
            start_time: fireemu_core_types::time::LogicalInstant::UNIX_EPOCH,
            monotonic_start_nanos: 17,
            owner_epoch: std::sync::Arc::clone(&epoch),
        };
        assert_eq!(schedule, schedule.clone());
        assert_ne!(
            schedule,
            NativeTextBuildSchedule {
                owner_epoch: std::sync::Arc::new(()),
                ..schedule.clone()
            }
        );
        let mut catalog = TextIndexCatalog::default();
        catalog
            .add(
                "p",
                "(default)",
                TextIndexDefinition {
                    id: "native".into(),
                    collection_id: CollectionId::try_new("items").unwrap(),
                    query_scope: IndexQueryScope::Collection,
                    api_scope: "ANY_API".into(),
                    fields: vec![TextIndexedField {
                        path: FieldPath::parse("title").unwrap(),
                        index_type: TextIndexType::Tokenized,
                        match_type: TextMatchType::MatchGlobally,
                    }],
                    language: DefaultTextLanguage::Tag("en".into()),
                    language_override: LanguageOverridePolicy::ExplicitField(
                        FieldPath::parse("language").unwrap(),
                    ),
                    state: TextIndexState::Creating,
                },
            )
            .unwrap();
        let generation = catalog
            .build("p", "(default)", "native")
            .unwrap()
            .generation;
        let before = catalog.clone();
        assert_eq!(
            catalog.schedule_native("p", "(default)", "native", generation + 1, schedule.clone()),
            Err(TextIndexBuildError::StaleGeneration)
        );
        assert_eq!(catalog, before);
        catalog
            .schedule_native("p", "(default)", "native", generation, schedule.clone())
            .unwrap();
        let captured = catalog.extract(|project| project == "p");
        catalog.retain_others(|project| project == "p");
        catalog.replace(|project| project == "p", &captured);
        assert_eq!(
            catalog
                .build("p", "(default)", "native")
                .unwrap()
                .native
                .as_ref(),
            Some(&schedule)
        );
        assert!(std::sync::Arc::ptr_eq(
            &catalog
                .build("p", "(default)", "native")
                .unwrap()
                .native
                .as_ref()
                .unwrap()
                .owner_epoch,
            &epoch
        ));
        catalog.remove("p", "(default)", "native");
        assert!(catalog.build("p", "(default)", "native").is_none());
    }
}
