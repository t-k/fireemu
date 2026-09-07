//! Index definitions and the conservative index validator (spec 8.6, 8.7, 8.8).
//!
//! Soundness rule (`INV-INDEX-001`): a `UseIndex` decision always names a concrete supporting
//! index, either an explicit composite index or the automatic single-field index. Anything the
//! reference rules cannot prove servable is `MissingRequired` (Standard) or a full-scan plan
//! (Enterprise); the validator never guesses in favour of the query.

use core::fmt;
use std::collections::{BTreeMap, BTreeSet};

use fireemu_core_types::edition::{FirestoreApiMode, FirestoreEdition};
use fireemu_core_types::ids::CollectionId;

use crate::field_path::FieldPath;
use crate::query::{Direction, FieldOp, FilterExpr, OrderClause, Query, UnaryOp};

/// Index field mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IndexFieldMode {
    /// Ascending order.
    Ascending,
    /// Descending order.
    Descending,
    /// Array contains.
    Contains,
}

impl IndexFieldMode {
    fn json(self) -> &'static str {
        match self {
            Self::Ascending => "\"order\": \"ASCENDING\"",
            Self::Descending => "\"order\": \"DESCENDING\"",
            Self::Contains => "\"arrayConfig\": \"CONTAINS\"",
        }
    }
}

/// One field of an index.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IndexField {
    /// Field path.
    pub path: FieldPath,
    /// Mode.
    pub mode: IndexFieldMode,
}

/// Index query scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IndexQueryScope {
    /// Collection scope.
    Collection,
    /// Collection-group scope.
    CollectionGroup,
}

/// A composite index definition (`firestore.indexes.json` entry).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IndexDefinition {
    /// Collection group.
    pub collection_group: CollectionId,
    /// Query scope.
    pub query_scope: IndexQueryScope,
    /// Fields in order.
    pub fields: Vec<IndexField>,
}

impl IndexDefinition {
    /// `firestore.indexes.json` fragment.
    #[must_use]
    pub fn indexes_json_fragment(&self) -> String {
        let fields: Vec<String> = self
            .fields
            .iter()
            .map(|f| {
                format!(
                    "      {{\"fieldPath\": \"{}\", {}}}",
                    f.path.canonical(),
                    f.mode.json()
                )
            })
            .collect();
        format!(
            "{{\n  \"collectionGroup\": \"{}\",\n  \"queryScope\": \"{}\",\n  \"fields\": [\n{}\n  ]\n}}",
            self.collection_group.as_str(),
            match self.query_scope {
                IndexQueryScope::Collection => "COLLECTION",
                IndexQueryScope::CollectionGroup => "COLLECTION_GROUP",
            },
            fields.join(",\n")
        )
    }
}

/// A single-field index exemption.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SingleFieldExemption {
    /// Collection group.
    pub collection_group: CollectionId,
    /// Field.
    pub field: FieldPath,
    /// Scope of the disabled automatic index.
    pub query_scope: IndexQueryScope,
}

type SingleFieldModes = Vec<(IndexQueryScope, IndexFieldMode)>;
type SingleFieldOverrides = BTreeMap<(String, Vec<String>), SingleFieldModes>;

/// The set of configured indexes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IndexSet {
    composites: Vec<IndexDefinition>,
    single_fields: SingleFieldOverrides,
}

impl IndexSet {
    /// Adds a composite index.
    pub fn add_composite(&mut self, index: IndexDefinition) {
        self.composites.push(index);
    }

    /// Adds a single-field exemption.
    pub fn add_exemption(&mut self, exemption: &SingleFieldExemption) {
        let mut modes = self.single_field_modes(&exemption.collection_group, &exemption.field);
        modes.retain(|(scope, _)| *scope != exemption.query_scope);
        self.set_single_field_indexes(&exemption.collection_group, &exemption.field, modes);
    }

    /// Overrides automatic modes for a literal field, inherited by map descendants.
    pub fn set_single_field_indexes(
        &mut self,
        collection: &CollectionId,
        field: &FieldPath,
        modes: Vec<(IndexQueryScope, IndexFieldMode)>,
    ) {
        let mut unique = Vec::new();
        for mode in modes {
            if !unique.contains(&mode) {
                unique.push(mode);
            }
        }
        self.single_fields.insert(
            (collection.as_str().to_owned(), field.segments().to_vec()),
            unique,
        );
    }

    /// Overrides defaults for every field in a collection group (the unquoted `*`).
    pub fn set_default_single_field_indexes(
        &mut self,
        collection: &CollectionId,
        modes: Vec<(IndexQueryScope, IndexFieldMode)>,
    ) {
        let mut unique = Vec::new();
        for mode in modes {
            if !unique.contains(&mode) {
                unique.push(mode);
            }
        }
        self.single_fields
            .insert((collection.as_str().to_owned(), Vec::new()), unique);
    }

    /// Effective automatic modes, after the most specific field override.
    #[must_use]
    pub fn single_field_modes(
        &self,
        collection: &CollectionId,
        field: &FieldPath,
    ) -> Vec<(IndexQueryScope, IndexFieldMode)> {
        self.single_fields
            .iter()
            .filter(|((c, path), _)| c == collection.as_str() && field.segments().starts_with(path))
            .max_by_key(|((_, path), _)| path.len())
            .map_or_else(
                || {
                    vec![
                        (IndexQueryScope::Collection, IndexFieldMode::Ascending),
                        (IndexQueryScope::Collection, IndexFieldMode::Descending),
                        (IndexQueryScope::Collection, IndexFieldMode::Contains),
                    ]
                },
                |(_, modes)| modes.clone(),
            )
    }

    /// Composite indexes.
    #[must_use]
    pub fn composites(&self) -> &[IndexDefinition] {
        &self.composites
    }

    pub(crate) fn is_exempt(
        &self,
        collection: &CollectionId,
        field: &FieldPath,
        group: bool,
    ) -> bool {
        !self
            .single_field_modes(collection, field)
            .iter()
            .any(|(scope, _)| (*scope == IndexQueryScope::CollectionGroup) == group)
    }
}

/// Index validation policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndexValidationPolicy {
    /// Production-compatible rules verified by conformance.
    Firebase,
    /// Sound: never accepts a query without a proven supporting index.
    Conservative,
    /// Firebase Emulator Suite parity: every composite index a query needs is assumed to
    /// exist (`AssumedIndex`), so a project without `firestore.indexes.json` runs the same
    /// queries it runs against the Emulator. Structural validation and the Standard query
    /// limits are unchanged; it says nothing about production index conformance.
    Emulator,
}

/// Planning inputs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlanningContext {
    /// Edition.
    pub edition: FirestoreEdition,
    /// API mode.
    pub api_mode: FirestoreApiMode,
    /// Policy.
    pub policy: IndexValidationPolicy,
}

/// Enterprise full-scan plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FullScanPlan {
    /// Collection scope description.
    pub collection_scope: String,
    /// Diagnostics such as `FS_ENT_FULL_COLLECTION_SCAN`.
    pub diagnostics: Vec<&'static str>,
    /// Index that would have served the query.
    pub missing_index: IndexDefinition,
}

/// Index decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IndexDecision {
    /// A supporting index exists (explicit or the automatic single-field index).
    UseIndex {
        /// Supporting index.
        index: IndexDefinition,
    },
    /// Enterprise: no index; scan the collection with a cost warning.
    FullScanAllowed {
        /// Plan.
        plan: FullScanPlan,
    },
    /// Standard: a required composite index is missing.
    MissingRequired {
        /// Required index.
        requirement: IndexDefinition,
    },
    /// `IndexValidationPolicy::Emulator`: the required composite index is not configured but
    /// the query is served as if it were (what the Firebase Emulator does).
    AssumedIndex {
        /// The index production would require.
        requirement: IndexDefinition,
    },
    /// Internal kindless descendant query; no collection-specific index can represent it.
    KindlessScan,
    /// The query uses an operator the validator does not model; never treated as index-free.
    Unsupported {
        /// Feature.
        feature: &'static str,
    },
}

impl fmt::Display for IndexDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UseIndex { index } => write!(f, "use index {}", describe(index)),
            Self::FullScanAllowed { plan } => write!(f, "full scan of {}", plan.collection_scope),
            Self::MissingRequired { requirement } => {
                write!(f, "missing index {}", describe(requirement))
            }
            Self::AssumedIndex { requirement } => {
                write!(
                    f,
                    "assumed index {} (emulator policy)",
                    describe(requirement)
                )
            }
            Self::KindlessScan => write!(f, "kindless descendant scan"),
            Self::Unsupported { feature } => write!(f, "unsupported: {feature}"),
        }
    }
}

fn describe(i: &IndexDefinition) -> String {
    let parts: Vec<String> = i
        .fields
        .iter()
        .map(|f| format!("{} {:?}", f.path, f.mode))
        .collect();
    format!("({})", parts.join(", "))
}

/// Requirement derived from one DNF disjunction.
struct Requirement {
    equality: Vec<FieldPath>,
    contains: Option<FieldPath>,
    order: Vec<OrderClause>,
}

fn requirement_for(disjunction: &[FilterExpr], effective_order: &[OrderClause]) -> Requirement {
    let mut equality: Vec<FieldPath> = Vec::new();
    let mut contains = None;
    for atom in disjunction {
        match atom {
            FilterExpr::Field {
                field,
                op: FieldOp::Equal,
                ..
            }
            | FilterExpr::Unary {
                field,
                op: UnaryOp::IsNull | UnaryOp::IsNan,
            } => {
                if !equality.contains(field) {
                    equality.push(field.clone());
                }
            }
            FilterExpr::Field {
                field,
                op: FieldOp::ArrayContains | FieldOp::ArrayContainsAny,
                ..
            } => contains = Some(field.clone()),
            _ => {}
        }
    }
    // Ordered fields: the effective order minus fields already constrained by equality.
    let order: Vec<OrderClause> = effective_order
        .iter()
        .filter(|o| !equality.contains(&o.field))
        .cloned()
        .collect();
    Requirement {
        equality,
        contains,
        order,
    }
}

/// The index that would serve `req` (canonical: equality fields in canonical order, then the
/// array field, then ordered fields).
fn required_index(req: &Requirement, collection: &CollectionId, group: bool) -> IndexDefinition {
    let mut fields: Vec<IndexField> = Vec::new();
    let mut eq = req.equality.clone();
    eq.sort();
    for e in eq {
        fields.push(IndexField {
            path: e,
            mode: IndexFieldMode::Ascending,
        });
    }
    if let Some(c) = &req.contains {
        fields.push(IndexField {
            path: c.clone(),
            mode: IndexFieldMode::Contains,
        });
    }
    for o in &req.order {
        fields.push(IndexField {
            path: o.field.clone(),
            mode: match o.direction {
                Direction::Ascending => IndexFieldMode::Ascending,
                Direction::Descending => IndexFieldMode::Descending,
            },
        });
    }
    IndexDefinition {
        collection_group: collection.clone(),
        query_scope: if group {
            IndexQueryScope::CollectionGroup
        } else {
            IndexQueryScope::Collection
        },
        fields,
    }
}

/// Whether the automatic single-field indexes serve `req`: at most one non-`__name__` field
/// is touched (by equality, array-contains, or ordering), and it is not exempt.
fn automatic_index_for(
    req: &Requirement,
    set: &IndexSet,
    collection: &CollectionId,
    group: bool,
) -> Option<IndexDefinition> {
    let mut touched: BTreeSet<FieldPath> = req.equality.iter().cloned().collect();
    if let Some(c) = &req.contains {
        touched.insert(c.clone());
    }
    for o in &req.order {
        if !o.field.is_document_name() {
            touched.insert(o.field.clone());
        }
    }
    if touched.len() > 1 {
        return None;
    }
    let field = touched.into_iter().next();
    if let Some(f) = &field {
        if set.is_exempt(collection, f, group) {
            return None;
        }
        let scope = if group {
            IndexQueryScope::CollectionGroup
        } else {
            IndexQueryScope::Collection
        };
        let supported =
            set.single_field_modes(collection, f)
                .iter()
                .any(|(candidate_scope, mode)| {
                    *candidate_scope == scope
                        && if req.contains.is_some() {
                            *mode == IndexFieldMode::Contains
                        } else {
                            *mode != IndexFieldMode::Contains
                        }
                });
        if !supported {
            return None;
        }
    }
    // Ordering on the single field can be served ascending or descending; array-contains
    // together with ordering on the same field is not (one automatic index per mode).
    if req.contains.is_some() && req.order.iter().any(|o| !o.field.is_document_name()) {
        return None;
    }
    // Equality on f plus ordering on f is redundant, and ordering on another field is
    // impossible here because touched.len() <= 1.
    Some(required_index(req, collection, group))
}

/// Whether composite `index` serves `req`: equality fields (any order) as a prefix, then the
/// array field, then the ordered fields with all directions equal or all reversed, then
/// `__name__` implicitly.
fn composite_serves(
    index: &IndexDefinition,
    req: &Requirement,
    collection: &CollectionId,
    group: bool,
) -> bool {
    if &index.collection_group != collection {
        return false;
    }
    let scope_ok = match index.query_scope {
        IndexQueryScope::CollectionGroup => true,
        IndexQueryScope::Collection => !group,
    };
    if !scope_ok {
        return false;
    }
    let fields = &index.fields;
    let n_eq = req.equality.len();
    if fields.len() < n_eq {
        return false;
    }
    let prefix: BTreeSet<&FieldPath> = fields[..n_eq].iter().map(|f| &f.path).collect();
    let wanted: BTreeSet<&FieldPath> = req.equality.iter().collect();
    if prefix != wanted
        || fields[..n_eq]
            .iter()
            .any(|f| f.mode == IndexFieldMode::Contains)
    {
        return false;
    }
    let mut pos = n_eq;
    if let Some(c) = &req.contains {
        match fields.get(pos) {
            Some(f) if &f.path == c && f.mode == IndexFieldMode::Contains => pos += 1,
            _ => return false,
        }
    }
    // Remaining ordered fields, ignoring a trailing implicit __name__ on both sides.
    let order: Vec<&OrderClause> = req
        .order
        .iter()
        .filter(|o| !o.field.is_document_name())
        .collect();
    let rest: Vec<&IndexField> = fields[pos..]
        .iter()
        .filter(|f| !f.path.is_document_name())
        .collect();
    if rest.len() != order.len() {
        return false;
    }
    let mut same = true;
    let mut reversed = true;
    for (f, o) in rest.iter().zip(order.iter()) {
        if f.path != o.field || f.mode == IndexFieldMode::Contains {
            return false;
        }
        let dir = if f.mode == IndexFieldMode::Ascending {
            Direction::Ascending
        } else {
            Direction::Descending
        };
        if dir != o.direction {
            same = false;
        }
        if dir != o.direction.reversed() {
            reversed = false;
        }
    }
    // Explicit __name__ direction in the index must agree with the chosen scan direction.
    if let Some(name_field) = fields[pos..].iter().find(|f| f.path.is_document_name()) {
        let dir = if name_field.mode == IndexFieldMode::Ascending {
            Direction::Ascending
        } else {
            Direction::Descending
        };
        let wanted = req
            .order
            .iter()
            .find(|o| o.field.is_document_name())
            .map_or(Direction::Ascending, |o| o.direction);
        if same && dir != wanted {
            same = false;
        }
        if reversed && dir != wanted.reversed() {
            reversed = false;
        }
    }
    same || reversed
}

/// Decides how a canonical query is served.
#[must_use]
pub fn decide(query: &Query, indexes: &IndexSet, ctx: &PlanningContext) -> IndexDecision {
    let Some(collection) = query.scope.collection_id() else {
        return IndexDecision::KindlessScan;
    };
    let group = query.scope.all_descendants();
    let effective_order = query.effective_order_by();
    let mut chosen: Option<IndexDefinition> = None;
    let mut assumed: Option<IndexDefinition> = None;
    for disjunction in query.dnf() {
        let req = requirement_for(&disjunction, &effective_order);
        if let Some(auto) = automatic_index_for(&req, indexes, collection, group) {
            chosen.get_or_insert(auto);
            continue;
        }
        if let Some(i) = indexes
            .composites()
            .iter()
            .find(|i| composite_serves(i, &req, collection, group))
        {
            chosen.get_or_insert(i.clone());
        } else {
            let requirement = required_index(&req, collection, group);
            if ctx.policy == IndexValidationPolicy::Emulator
                && ctx.edition == FirestoreEdition::Standard
            {
                assumed.get_or_insert(requirement);
                continue;
            }
            return match ctx.edition {
                FirestoreEdition::Standard => IndexDecision::MissingRequired { requirement },
                FirestoreEdition::Enterprise => IndexDecision::FullScanAllowed {
                    plan: FullScanPlan {
                        collection_scope: format!(
                            "{}{}",
                            collection.as_str(),
                            if group { " (collection group)" } else { "" }
                        ),
                        diagnostics: vec!["FS_ENT_FULL_COLLECTION_SCAN"],
                        missing_index: requirement,
                    },
                },
            };
        }
    }
    if let Some(requirement) = assumed {
        return IndexDecision::AssumedIndex { requirement };
    }
    match chosen {
        Some(index) => IndexDecision::UseIndex { index },
        None => IndexDecision::Unsupported {
            feature: "empty query plan",
        },
    }
}
