//! Deterministic lexical-v1 search. Language tags do not enable morphology, stemming, or autodetection. This module makes no production equivalence claim.
use crate::{
    field_path::FieldPath,
    path::DocumentPath,
    store::get_field,
    text_index::{is_language_tag, LanguageOverridePolicy, TextIndexDefinition},
    value::Value,
};
use fireemu_core_types::time::LogicalInstant;
use std::collections::{BTreeMap, BTreeSet};

/// Maximum accepted query bytes.
pub const MAX_QUERY_BYTES: usize = 8192;
/// Maximum query clauses.
pub const MAX_QUERY_CLAUSES: usize = 64;
/// A source document. Only strings at indexed paths produce postings; other values are ignored.
#[derive(Debug, Clone)]
pub struct SearchDocument {
    /// Document name.
    pub path: DocumentPath,
    /// Source fields.
    pub fields: BTreeMap<String, Value>,
    /// Creation time.
    pub created_at: LogicalInstant,
}
/// Lexical query or index input error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SearchError {
    /// Unsupported or malformed syntax.
    InvalidQuery(String),
    /// A restriction names an unindexed path.
    UnknownField(String),
    /// Invalid or unresolved language override.
    InvalidLanguageOverride(String),
    /// Duplicate corpus name.
    DuplicateDocument(String),
}
impl std::fmt::Display for SearchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for SearchError {}
fn invalid(message: &str) -> SearchError {
    SearchError::InvalidQuery(message.into())
}
fn validate_clause_syntax(raw: &str, quoted: bool) -> Result<(), SearchError> {
    if raw.is_empty()
        || raw
            .chars()
            .any(|c| matches!(c, '(' | ')' | '|' | '*' | '\\' | ':' | '"'))
        || (!quoted && matches!(raw, "AND" | "NOT"))
    {
        return Err(invalid("empty or unsupported query syntax"));
    }
    Ok(())
}
#[derive(Debug, Clone, PartialEq, Eq)]
struct Clause {
    field: Option<FieldPath>,
    tokens: Vec<String>,
    excluded: bool,
}
struct QueryFragment {
    clause: Option<Clause>,
    connector: bool,
}
impl QueryFragment {
    fn parse(
        raw: &str,
        field: Option<FieldPath>,
        excluded: bool,
        quoted: bool,
        analyze: fn(&str) -> Vec<String>,
    ) -> Result<Self, SearchError> {
        validate_clause_syntax(raw, quoted)?;
        let connector = !quoted && raw.eq_ignore_ascii_case("or");
        if connector && excluded {
            return Err(invalid("unsupported OR context"));
        }
        let tokens = analyze(raw);
        let clause = if tokens.is_empty() {
            if quoted || excluded || field.is_some() {
                return Err(invalid("clause contains no searchable tokens"));
            }
            None
        } else {
            Some(Clause {
                field,
                tokens,
                excluded,
            })
        };
        Ok(Self { clause, connector })
    }
    fn is_positive_operand(&self) -> bool {
        !self.connector && self.clause.as_ref().is_some_and(|clause| !clause.excluded)
    }
}
fn searchable_clauses(fragments: Vec<QueryFragment>) -> Result<Vec<Clause>, SearchError> {
    let multiple = fragments.len() > 1;
    if multiple {
        for (i, _) in fragments
            .iter()
            .enumerate()
            .filter(|(_, fragment)| fragment.connector)
        {
            let before = i.checked_sub(1).and_then(|i| fragments.get(i));
            let after = fragments.get(i + 1);
            if !before.is_some_and(QueryFragment::is_positive_operand)
                || !after.is_some_and(QueryFragment::is_positive_operand)
            {
                return Err(invalid("unsupported OR context"));
            }
        }
    }
    Ok(fragments
        .into_iter()
        .filter_map(|fragment| {
            if multiple && fragment.connector {
                None
            } else {
                fragment.clause
            }
        })
        .collect())
}
/// A bounded conjunction of terms and same-field positional phrases, optionally excluded or field-restricted. Queries without positive clauses match no documents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchQuery {
    clauses: Vec<Clause>,
}
impl SearchQuery {
    /// Whether every explicit field restriction is covered by this definition.
    #[must_use]
    pub fn is_covered_by(&self, definition: &TextIndexDefinition) -> bool {
        self.clauses.iter().all(|clause| {
            clause
                .field
                .as_ref()
                .is_none_or(|path| definition.fields.iter().any(|field| &field.path == path))
        })
    }

    /// The caller must use the same analyzer for queries and corpus batches.
    /// Plain tokenless fragments are ignored; no positive searchable clauses means no matches. Quoted, restricted, and excluded tokenless fragments remain invalid.
    /// Unquoted colons delimit conjunctive terms. A leading unmatched quote leaves an ordinary conjunction; balanced phrases remain positional.
    /// OR is a conjunctive connector between positive operands and a searchable term alone. Legacy `field:"phrase"` restrictions are development approximations; grouping, escapes, and wildcards remain unsupported.
    pub fn parse(input: &str, analyze: fn(&str) -> Vec<String>) -> Result<Self, SearchError> {
        if input.len() > MAX_QUERY_BYTES {
            return Err(invalid("query byte limit exceeded"));
        }
        if let Some(remainder) = input
            .trim_start()
            .strip_prefix('"')
            .filter(|remainder| !remainder.contains('"'))
        {
            return Self::parse(remainder, analyze);
        }
        let mut chars = input.char_indices().peekable();
        let mut fragments = Vec::new();
        while let Some(&(start, c)) = chars.peek() {
            if c.is_whitespace() || c == ':' {
                chars.next();
                continue;
            }
            let excluded = c == '-';
            if excluded {
                chars.next();
            }
            let begin = chars.peek().map_or(input.len(), |(i, _)| *i);
            let mut field = None;
            let mut value_start = begin;
            let mut backtick = false;
            while let Some(&(i, c)) = chars.peek() {
                if c == '`' {
                    backtick = !backtick;
                }
                if !backtick && (c.is_whitespace() || c == '"') {
                    break;
                }
                if !backtick && c == ':' {
                    if input[i + 1..].starts_with('"') {
                        let raw = &input[begin..i];
                        let parsed = FieldPath::parse(raw)
                            .map_err(|_| invalid("invalid field restriction"))?;
                        if parsed.canonical() != raw {
                            return Err(invalid("field restriction must be canonical"));
                        }
                        field = Some(parsed);
                        chars.next();
                        value_start = i + 1;
                    }
                    break;
                }
                chars.next();
            }
            let quoted = chars.peek().is_some_and(|(_, c)| *c == '"');
            let raw;
            if quoted {
                if value_start != chars.peek().map_or(input.len(), |(i, _)| *i) {
                    return Err(invalid("unexpected quote"));
                }
                let open = chars.next().map_or(input.len(), |(i, _)| i + 1);
                let mut end = None;
                for (i, c) in chars.by_ref() {
                    if c == '"' {
                        end = Some(i);
                        break;
                    }
                }
                let end = end.ok_or_else(|| invalid("unterminated phrase"))?;
                raw = &input[open..end];
                if chars.peek().is_some_and(|(_, c)| !c.is_whitespace()) {
                    return Err(invalid("missing clause separator"));
                }
            } else {
                while let Some(&(_, c)) = chars.peek() {
                    if c.is_whitespace() || c == ':' {
                        break;
                    }
                    chars.next();
                }
                let end = chars.peek().map_or(input.len(), |(i, _)| *i);
                raw = &input[value_start..end];
            }
            fragments.push(QueryFragment::parse(raw, field, excluded, quoted, analyze)?);
            if fragments.len() > MAX_QUERY_CLAUSES {
                return Err(invalid("query clause limit exceeded"));
            }
            if chars.peek().is_some_and(|(i, _)| *i <= start) {
                return Err(invalid("invalid query"));
            }
        }
        Ok(Self {
            clauses: searchable_clauses(fragments)?,
        })
    }
}
/// Result ordering; ties use ascending document resource names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SearchOrder {
    /// Newest creation time first.
    #[default]
    CreationDescending,
    /// Largest BM25 approximation first.
    ScoreDescending,
}
/// Pagination and candidate selection. Retrieval depth selects newest matching documents before ranking.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SearchOptions {
    /// Number of ranked hits to skip.
    pub offset: usize,
    /// Maximum returned hits.
    pub limit: Option<usize>,
    /// Maximum newest matching candidates before ranking.
    pub retrieval_depth: Option<usize>,
    /// Ranking policy.
    pub order: SearchOrder,
}
/// A matching document and its approximate BM25 score.
#[derive(Debug, Clone, PartialEq)]
pub struct SearchHit {
    /// Matching document name.
    pub path: DocumentPath,
    /// Approximate BM25 relevance.
    pub score: f64,
}
#[derive(Debug, Clone, PartialEq, Eq)]
struct IndexedDocument {
    path: DocumentPath,
    created_at: LogicalInstant,
    length: usize,
}
/// Immutable corpus with positional postings keyed by term, document, then indexed field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchIndex {
    fields: Vec<FieldPath>,
    documents: Vec<IndexedDocument>,
    postings: BTreeMap<String, BTreeMap<usize, BTreeMap<usize, Vec<usize>>>>,
}
impl SearchIndex {
    /// Extend with a validated disjoint corpus batch atomically.
    pub fn extend(
        &mut self,
        definition: &TextIndexDefinition,
        documents: &[SearchDocument],
        analyze: fn(&str) -> Vec<String>,
    ) -> Result<(), SearchError> {
        let batch = Self::build(definition, documents, analyze)?;
        if self.fields != batch.fields {
            return Err(invalid("batch indexed fields differ from the corpus"));
        }
        let existing: BTreeSet<_> = self
            .documents
            .iter()
            .map(|document| &document.path)
            .collect();
        for document in &batch.documents {
            if existing.contains(&document.path) {
                return Err(SearchError::DuplicateDocument(
                    document.path.resource_name(),
                ));
            }
        }
        let offset = self.documents.len();
        self.documents.extend(batch.documents);
        for (term, documents) in batch.postings {
            let target = self.postings.entry(term).or_default();
            for (id, fields) in documents {
                target.insert(offset + id, fields);
            }
        }
        Ok(())
    }

    /// The analyzer must match the query analyzer; it is never retained in snapshots.
    /// Build postings from source strings. Duplicate document names and malformed language overrides are rejected.
    pub fn build(
        definition: &TextIndexDefinition,
        documents: &[SearchDocument],
        analyze: fn(&str) -> Vec<String>,
    ) -> Result<Self, SearchError> {
        let mut index = Self {
            fields: definition.fields.iter().map(|f| f.path.clone()).collect(),
            documents: Vec::new(),
            postings: BTreeMap::new(),
        };
        let mut names = BTreeSet::new();
        for document in documents {
            if !names.insert(document.path.clone()) {
                return Err(SearchError::DuplicateDocument(
                    document.path.resource_name(),
                ));
            }
            let override_path = match &definition.language_override {
                LanguageOverridePolicy::ExplicitField(p) => Some(p.clone()),
                LanguageOverridePolicy::ImplicitLanguageField => {
                    Some(FieldPath::parse("language").map_err(|_| invalid("language field"))?)
                }
                LanguageOverridePolicy::BackendDefaultUnresolved => {
                    return Err(SearchError::InvalidLanguageOverride(
                        "unresolved backend default".into(),
                    ));
                }
                LanguageOverridePolicy::Disabled => None,
            };
            if let Some(value) = override_path
                .as_ref()
                .and_then(|p| get_field(&document.fields, p))
            {
                if !matches!(value, Value::String(tag) if is_language_tag(tag)) {
                    return Err(SearchError::InvalidLanguageOverride(
                        document.path.resource_name(),
                    ));
                }
            }
            let id = index.documents.len();
            let mut length = 0;
            for (field_id, field) in index.fields.iter().enumerate() {
                if let Some(Value::String(text)) = get_field(&document.fields, field) {
                    for (position, term) in analyze(text).into_iter().enumerate() {
                        length += 1;
                        index
                            .postings
                            .entry(term)
                            .or_default()
                            .entry(id)
                            .or_default()
                            .entry(field_id)
                            .or_default()
                            .push(position);
                    }
                }
            }
            index.documents.push(IndexedDocument {
                path: document.path.clone(),
                created_at: document.created_at,
                length,
            });
        }
        Ok(index)
    }
    /// Source document count, including documents with no searchable strings.
    #[must_use]
    pub fn document_count(&self) -> usize {
        self.documents.len()
    }
    /// Conservative saturating estimate of retained allocations, including posting tree overhead.
    #[must_use]
    pub fn retained_bytes(&self) -> u64 {
        fn bytes(n: usize) -> u64 {
            u64::try_from(n).unwrap_or(u64::MAX)
        }
        let mut size = bytes(self.documents.capacity())
            .saturating_mul(bytes(std::mem::size_of::<IndexedDocument>()));
        for d in &self.documents {
            size = size.saturating_add(bytes(d.path.resource_name().len()).saturating_mul(4));
        }
        for f in &self.fields {
            size = size
                .saturating_add(bytes(f.canonical().len()).saturating_mul(4))
                .saturating_add(128);
        }
        for (term, docs) in &self.postings {
            size = size
                .saturating_add(bytes(term.capacity()))
                .saturating_add(128);
            for fields in docs.values() {
                size = size.saturating_add(128);
                for positions in fields.values() {
                    size = size.saturating_add(128).saturating_add(
                        bytes(positions.capacity())
                            .saturating_mul(bytes(std::mem::size_of::<usize>())),
                    );
                }
            }
        }
        size
    }
    fn matches(&self, id: usize, clause: &Clause) -> bool {
        let Some(first) = self
            .postings
            .get(&clause.tokens[0])
            .and_then(|docs| docs.get(&id))
        else {
            return false;
        };
        first.iter().any(|(field, positions)| {
            if clause
                .field
                .as_ref()
                .is_some_and(|p| p != &self.fields[*field])
            {
                return false;
            }
            positions.iter().any(|start| {
                clause
                    .tokens
                    .iter()
                    .enumerate()
                    .skip(1)
                    .all(|(offset, term)| {
                        self.postings
                            .get(term)
                            .and_then(|docs| docs.get(&id))
                            .and_then(|fields| fields.get(field))
                            .is_some_and(|positions| {
                                positions.binary_search(&(start + offset)).is_ok()
                            })
                    })
            })
        })
    }
    /// Evaluate conjunction/exclusion, select retrieval depth by creation order, rank, then paginate.
    #[allow(clippy::cast_precision_loss)] // BM25 is explicitly an approximate floating-point score.
    pub fn search(
        &self,
        query: &SearchQuery,
        options: &SearchOptions,
    ) -> Result<Vec<SearchHit>, SearchError> {
        for clause in &query.clauses {
            if let Some(field) = &clause.field {
                if !self.fields.contains(field) {
                    return Err(SearchError::UnknownField(field.canonical()));
                }
            }
        }
        if !query.clauses.iter().any(|clause| !clause.excluded) {
            return Ok(Vec::new());
        }
        let mut candidates: Vec<usize> = (0..self.documents.len())
            .filter(|id| {
                query
                    .clauses
                    .iter()
                    .all(|c| self.matches(*id, c) != c.excluded)
            })
            .collect();
        candidates.sort_by(|a, b| {
            self.documents[*b]
                .created_at
                .cmp(&self.documents[*a].created_at)
                .then_with(|| {
                    self.documents[*a]
                        .path
                        .cmp_resource_name(&self.documents[*b].path)
                })
        });
        if let Some(depth) = options.retrieval_depth {
            candidates.truncate(depth);
        }
        let total = self.documents.len() as f64;
        let average = (self.documents.iter().map(|d| d.length).sum::<usize>() as f64
            / total.max(1.0))
        .max(1.0);
        let mut hits: Vec<SearchHit> = candidates
            .into_iter()
            .map(|id| {
                let mut score = 0.0;
                for clause in query.clauses.iter().filter(|c| !c.excluded) {
                    for term in &clause.tokens {
                        if let Some(postings) = self.postings.get(term) {
                            let frequency = postings.get(&id).map_or(0, |fields| {
                                fields
                                    .iter()
                                    .filter(|(field, _)| {
                                        clause
                                            .field
                                            .as_ref()
                                            .is_none_or(|p| p == &self.fields[**field])
                                    })
                                    .map(|(_, positions)| positions.len())
                                    .sum::<usize>()
                            }) as f64;
                            let df = postings
                                .values()
                                .filter(|fields| {
                                    fields.keys().any(|field| {
                                        clause
                                            .field
                                            .as_ref()
                                            .is_none_or(|p| p == &self.fields[*field])
                                    })
                                })
                                .count() as f64;
                            let idf = (1.0 + (total - df + 0.5) / (df + 0.5)).ln();
                            let denominator = frequency
                                + 1.2 * (0.25 + 0.75 * self.documents[id].length as f64 / average);
                            score += idf * frequency * 2.2 / denominator;
                        }
                    }
                }
                SearchHit {
                    path: self.documents[id].path.clone(),
                    score,
                }
            })
            .collect();
        if options.order == SearchOrder::ScoreDescending {
            hits.sort_by(|a, b| {
                b.score
                    .total_cmp(&a.score)
                    .then_with(|| a.path.cmp_resource_name(&b.path))
            });
        }
        Ok(hits
            .into_iter()
            .skip(options.offset)
            .take(options.limit.unwrap_or(usize::MAX))
            .collect())
    }
}
