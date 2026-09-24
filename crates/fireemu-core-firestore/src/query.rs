//! Canonical query AST, canonicalization, DNF and Standard query limits (spec 8.5, 8.10.4).

use core::fmt;
use std::collections::BTreeSet;

use fireemu_core_types::codec::echo;

use fireemu_core_limits::catalogs::FIRESTORE_STANDARD_QUERY_2026_08_25;
use fireemu_core_limits::model::LimitMaximum;
use fireemu_core_types::ids::CollectionId;

use crate::field_path::FieldPath;
use crate::path::DocumentPath;
use crate::value::{IndexValue, Value};

/// Where a query reads from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueryScope {
    /// One named collection directly under a parent.
    Collection {
        /// Parent document; `None` for a root collection.
        parent: Option<DocumentPath>,
        /// Collection ID.
        collection_id: CollectionId,
    },
    /// Every collection of one name below a parent.
    CollectionGroup {
        /// Parent document; `None` for the whole database.
        parent: Option<DocumentPath>,
        /// Collection ID.
        collection_id: CollectionId,
    },
    /// Every descendant document below a parent, regardless of collection name.
    KindlessAllDescendants {
        /// Parent document; `None` for the whole database.
        parent: Option<DocumentPath>,
    },
    /// Every direct child document of a parent, regardless of collection name: an empty
    /// collection id without `allDescendants`.
    KindlessChildren {
        /// Parent document; `None` for the root.
        parent: Option<DocumentPath>,
    },
}

impl QueryScope {
    /// A single collection under `parent` (root when `None`).
    #[must_use]
    pub const fn collection(parent: Option<DocumentPath>, collection_id: CollectionId) -> Self {
        Self::Collection {
            parent,
            collection_id,
        }
    }

    /// A collection-group query.
    #[must_use]
    pub const fn collection_group(collection_id: CollectionId) -> Self {
        Self::CollectionGroup {
            parent: None,
            collection_id,
        }
    }

    /// A collection-group query scoped below `parent`.
    #[must_use]
    pub const fn collection_group_under(
        parent: Option<DocumentPath>,
        collection_id: CollectionId,
    ) -> Self {
        Self::CollectionGroup {
            parent,
            collection_id,
        }
    }

    /// The kindless all-descendants query used for recursive deletion.
    #[must_use]
    pub const fn kindless_all_descendants(parent: Option<DocumentPath>) -> Self {
        Self::KindlessAllDescendants { parent }
    }

    /// The kindless query of the direct children of `parent` (root when `None`).
    #[must_use]
    pub const fn kindless_children(parent: Option<DocumentPath>) -> Self {
        Self::KindlessChildren { parent }
    }

    /// Parent document, when the query is scoped below one.
    #[must_use]
    pub const fn parent(&self) -> Option<&DocumentPath> {
        match self {
            Self::Collection { parent, .. }
            | Self::CollectionGroup { parent, .. }
            | Self::KindlessAllDescendants { parent }
            | Self::KindlessChildren { parent } => parent.as_ref(),
        }
    }

    /// Named collection selector, absent only for a kindless scan.
    #[must_use]
    pub const fn collection_id(&self) -> Option<&CollectionId> {
        match self {
            Self::Collection { collection_id, .. }
            | Self::CollectionGroup { collection_id, .. } => Some(collection_id),
            Self::KindlessAllDescendants { .. } | Self::KindlessChildren { .. } => None,
        }
    }

    /// Whether descendants, rather than one direct collection, are selected.
    #[must_use]
    pub const fn all_descendants(&self) -> bool {
        matches!(
            self,
            Self::CollectionGroup { .. } | Self::KindlessAllDescendants { .. }
        )
    }

    /// Whether collection names are ignored.
    #[must_use]
    pub const fn is_kindless(&self) -> bool {
        matches!(
            self,
            Self::KindlessAllDescendants { .. } | Self::KindlessChildren { .. }
        )
    }

    /// Whether a document at `path` belongs to the range this scope selects. Only the
    /// `(collection, document)` pairs are compared; a caller that admits paths from more
    /// than one project or database compares those itself.
    #[must_use]
    pub fn contains(&self, path: &DocumentPath) -> bool {
        let parent_len = self.parent().map_or(0, |parent| parent.pairs().len());
        match self {
            Self::Collection {
                parent,
                collection_id,
            } => {
                path.pairs().len() == parent_len + 1
                    && path.collection_id() == collection_id
                    && parent
                        .as_ref()
                        .is_none_or(|prefix| path.pairs()[..parent_len] == *prefix.pairs())
            }
            Self::CollectionGroup {
                parent,
                collection_id,
            } => {
                path.collection_id() == collection_id
                    && parent.as_ref().is_none_or(|prefix| {
                        path.pairs().len() > parent_len
                            && path.pairs()[..parent_len] == *prefix.pairs()
                    })
            }
            Self::KindlessAllDescendants { parent } => parent.as_ref().is_none_or(|prefix| {
                path.pairs().len() > parent_len && path.pairs()[..parent_len] == *prefix.pairs()
            }),
            Self::KindlessChildren { parent } => {
                path.pairs().len() == parent_len + 1
                    && parent
                        .as_ref()
                        .is_none_or(|prefix| path.pairs()[..parent_len] == *prefix.pairs())
            }
        }
    }
}

/// Field comparison operators.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FieldOp {
    /// `==`
    Equal,
    /// `!=`
    NotEqual,
    /// `<`
    LessThan,
    /// `<=`
    LessThanOrEqual,
    /// `>`
    GreaterThan,
    /// `>=`
    GreaterThanOrEqual,
    /// `array-contains`
    ArrayContains,
    /// `in`
    In,
    /// `array-contains-any`
    ArrayContainsAny,
    /// `not-in`
    NotIn,
}

impl FieldOp {
    /// Whether the operator is a range / inequality operator for index and limit purposes.
    #[must_use]
    pub const fn is_inequality(self) -> bool {
        matches!(
            self,
            Self::NotEqual
                | Self::LessThan
                | Self::LessThanOrEqual
                | Self::GreaterThan
                | Self::GreaterThanOrEqual
                | Self::NotIn
        )
    }

    /// Whether the operator takes an array of candidate values.
    #[must_use]
    pub const fn takes_array(self) -> bool {
        matches!(self, Self::In | Self::ArrayContainsAny | Self::NotIn)
    }

    /// Stable wire-style name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Equal => "EQUAL",
            Self::NotEqual => "NOT_EQUAL",
            Self::LessThan => "LESS_THAN",
            Self::LessThanOrEqual => "LESS_THAN_OR_EQUAL",
            Self::GreaterThan => "GREATER_THAN",
            Self::GreaterThanOrEqual => "GREATER_THAN_OR_EQUAL",
            Self::ArrayContains => "ARRAY_CONTAINS",
            Self::In => "IN",
            Self::ArrayContainsAny => "ARRAY_CONTAINS_ANY",
            Self::NotIn => "NOT_IN",
        }
    }
}

/// Unary operators.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum UnaryOp {
    /// `IS_NULL`
    IsNull,
    /// `IS_NAN`
    IsNan,
    /// `IS_NOT_NULL`
    IsNotNull,
    /// `IS_NOT_NAN`
    IsNotNan,
}

/// Filter expression tree.
#[derive(Debug, Clone, PartialEq)]
pub enum FilterExpr {
    /// Field comparison.
    Field {
        /// Field.
        field: FieldPath,
        /// Operator.
        op: FieldOp,
        /// Comparison value.
        value: Value,
    },
    /// Unary test.
    Unary {
        /// Field.
        field: FieldPath,
        /// Operator.
        op: UnaryOp,
    },
    /// Conjunction.
    And(Vec<FilterExpr>),
    /// Disjunction.
    Or(Vec<FilterExpr>),
}

/// Sort direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Direction {
    /// Ascending.
    Ascending,
    /// Descending.
    Descending,
}

/// Distance metric for a Standard Native nearest-neighbor query.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DistanceMeasure {
    /// Square-rooted sum of squared component differences.
    Euclidean,
    /// One minus cosine similarity.
    Cosine,
    /// Sum of component products; larger values are nearer.
    DotProduct,
}

/// Nearest-neighbor search applied after the ordinary query stages.
#[derive(Debug, Clone, PartialEq)]
pub struct FindNearest {
    /// Indexed vector field to search.
    pub vector_field: FieldPath,
    /// Query vector components.
    pub query_vector: Vec<f64>,
    /// Distance metric.
    pub distance_measure: DistanceMeasure,
    /// Maximum nearest neighbors to return (1 through 1000).
    pub limit: u32,
    /// Optional field receiving the calculated distance.
    pub distance_result_field: Option<FieldPath>,
    /// Optional inclusive distance threshold.
    pub distance_threshold: Option<f64>,
}

impl Direction {
    /// The opposite direction.
    #[must_use]
    pub const fn reversed(self) -> Self {
        match self {
            Self::Ascending => Self::Descending,
            Self::Descending => Self::Ascending,
        }
    }
}

/// One `orderBy` clause.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct OrderClause {
    /// Field.
    pub field: FieldPath,
    /// Direction.
    pub direction: Direction,
}

/// Cursor position.
#[derive(Debug, Clone, PartialEq)]
pub struct Cursor {
    /// Values aligned with the effective order-by.
    pub values: Vec<Value>,
    /// Whether the position itself is included.
    pub before: bool,
}

/// Which refusals canonicalization applies.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Refusals {
    /// Every refusal production makes (the strict profile).
    Production,
    /// Only those the official emulator makes too.
    Emulator,
}

/// Canonical query.
#[derive(Debug, Clone, PartialEq)]
pub struct Query {
    /// Scope.
    pub scope: QueryScope,
    /// Filter.
    pub filter: Option<FilterExpr>,
    /// Explicit ordering.
    pub order_by: Vec<OrderClause>,
    /// Start cursor.
    pub start_at: Option<Cursor>,
    /// End cursor.
    pub end_at: Option<Cursor>,
    /// Offset.
    pub offset: u32,
    /// Limit.
    pub limit: Option<u32>,
    /// Projection.
    pub projection: Option<Vec<FieldPath>>,
    /// Optional nearest-neighbor stage, applied after ordinary query stages.
    pub find_nearest: Option<FindNearest>,
    /// Whether execution refuses what only production refuses (the strict profile): a
    /// cosine search that meets a zero vector. The emulator profile's canonicalization clears
    /// it, and such a candidate is then left out as a distance that is not finite.
    pub production_refusals: bool,
}

/// Structural validation errors found while canonicalizing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueryError {
    /// `in` / `array-contains-any` / `not-in` needs an array value.
    ArrayValueRequired {
        /// Field.
        field: FieldPath,
        /// Operator.
        op: FieldOp,
    },
    /// `in` / `array-contains-any` / `not-in` needs a non-empty array value.
    NonEmptyArrayRequired {
        /// Operator.
        op: FieldOp,
    },
    /// The same field appears twice in the explicit order-by.
    DuplicateOrderField {
        /// Field.
        field: FieldPath,
    },
    /// An array-membership filter on `__name__`.
    NameReserved,
    /// A kindless query filters on a field other than `__name__`.
    KindRequiredForFilter {
        /// Field.
        field: FieldPath,
    },
    /// A kindless query orders by anything but `__name__` ascending.
    KindRequiredForOrder,
    /// A cursor document reference names a collection, not a document.
    CursorReferenceNotDocument {
        /// The reference.
        name: String,
    },
    /// An empty `and` / `or`.
    EmptyComposite,
    /// More than one `not-in` filter.
    MultipleNotIn,
    /// `not-in` combined with `in`, `array-contains-any` or `or`.
    NotInWithDisjunction,
    /// A cursor has more values than the explicit order-by has fields.
    CursorArityMismatch {
        /// Cursor values.
        cursor: usize,
        /// Effective order-by length.
        order_by: usize,
    },
    /// A cursor value standing in a `__name__` position is not a document reference.
    CursorNameValue {
        /// Zero-based position in the effective order-by.
        position: usize,
    },
    /// More than one of `!=`, `not-in`, `IS_NOT_NAN` and `IS_NOT_NULL` in one query.
    MultipleNegations,
    /// The effective ordering names a field after `__name__`, which is unique, so the
    /// extra clause could never take effect.
    OrderAfterDocumentName,
    /// A filter on `__name__` compares against something other than a document reference.
    NameFilterValue,
    /// A key equality with other inequalities requires a key inequality too (Standard).
    KeyEqualityWithOtherInequalities,
    /// `FindNearest` query vector is empty.
    FindNearestQueryVectorEmpty,
    /// `FindNearest` query vector is too large or contains a non-finite component.
    FindNearestQueryVector,
    /// `FindNearest` limit must be between one and 1000.
    FindNearestLimit,
    /// `FindNearest` distance measure is unspecified.
    FindNearestDistanceMeasure,
    /// `FindNearest` threshold must be finite.
    FindNearestDistanceThreshold,
    /// `FindNearest` distance output field is invalid.
    FindNearestDistanceResultField,
}

impl fmt::Display for QueryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ArrayValueRequired { op, .. } => {
                write!(f, "'{}' requires an ArrayValue.", op.name())
            }
            Self::NonEmptyArrayRequired { op } => {
                write!(f, "'{}' requires an non-empty ArrayValue.", op.name())
            }
            Self::DuplicateOrderField { field } => {
                let field = field.to_string();
                write!(
                    f,
                    "order by clause cannot contain duplicate fields {}",
                    echo(&field)
                )
            }
            Self::NameReserved => f.write_str("the name __key__ is reserved"),
            Self::KindRequiredForFilter { field } => {
                let field = field.to_string();
                write!(f, "kind is required for filter: {}", echo(&field))
            }
            Self::KindRequiredForOrder => {
                f.write_str("kind is required for all orders except __key__ ascending")
            }
            Self::CursorReferenceNotDocument { name } => write!(
                f,
                "Document parent name \"{}\" lacks \"/\" at index {}.",
                echo(name),
                name.len()
            ),
            Self::EmptyComposite => {
                f.write_str("Composite filter must have at least one sub-filter.")
            }
            Self::NotInWithDisjunction => f.write_str(
                "'NOT_IN' cannot be used in the same query with 'IN', 'ARRAY_CONTAINS_ANY' or 'OR'.",
            ),
            Self::CursorArityMismatch { .. } => f.write_str("Cursor has too many values."),
            Self::CursorNameValue { .. } => {
                f.write_str("Cursor __key__ value is not a document reference.")
            }
            Self::MultipleNotIn | Self::MultipleNegations => f.write_str(
                "Only a single 'NOT_EQUAL', 'NOT_IN', 'IS_NOT_NAN', or 'IS_NOT_NULL' filter allowed per query.",
            ),
            Self::OrderAfterDocumentName => {
                f.write_str("order by clause cannot contain more fields after the key")
            }
            Self::NameFilterValue => f.write_str("__key__ filter value must be a Key"),
            Self::KeyEqualityWithOtherInequalities => f.write_str(
                "Equality on key is not allowed if there are other inequality fields and key does not appear in inequalities.",
            ),
            // Production's text for an empty vector (FS-QUERY-INDEX
            // vector/validation#query-vector-empty); the other cases are unrecorded.
            Self::FindNearestQueryVectorEmpty => f.write_str("Cannot have a zero length vector."),
            Self::FindNearestQueryVector => f.write_str(
                "findNearest query vector must contain between 1 and 2048 finite dimensions",
            ),
            Self::FindNearestLimit => f.write_str(
                "FindNearest.limit must be a positive integer of no more than 1000",
            ),
            Self::FindNearestDistanceMeasure => f.write_str("Unknown Distance Measure."),
            Self::FindNearestDistanceThreshold => {
                f.write_str("distanceThreshold must be a finite number.")
            }
            Self::FindNearestDistanceResultField => {
                f.write_str("The distanceResultField.property.name \"__name__\" is reserved.")
            }
        }
    }
}

impl std::error::Error for QueryError {}

/// One Standard query limit violation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryLimitViolation {
    /// Limit ID from `firestore-standard-query-2026-08-25`.
    pub limit_id: &'static str,
    /// Observed value.
    pub current: u64,
    /// Maximum.
    pub maximum: u64,
    /// Human-readable detail.
    pub detail: String,
    /// The text production refuses the query with.
    pub message: String,
}

/// Component count breakdown (`FS-QUERY-LIMIT-COMPONENTS`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComponentCount {
    /// Filters counted on the DNF (largest disjunction).
    pub filters: u64,
    /// Explicit order-by clauses.
    pub orders: u64,
    /// 1 for a subcollection query, 0 for a root collection.
    pub parent_path: u64,
    /// Total.
    pub total: u64,
}

impl Query {
    /// Validates Standard operator combinations independently of configurable limits.
    /// Call after canonicalization to preserve structural error precedence.
    pub fn check_standard_constraints(&self) -> Result<(), QueryError> {
        fn has_key_equality(filter: &FilterExpr) -> bool {
            match filter {
                FilterExpr::Field {
                    field,
                    op: FieldOp::Equal | FieldOp::In,
                    ..
                } => field.is_document_name(),
                FilterExpr::And(children) | FilterExpr::Or(children) => {
                    children.iter().any(has_key_equality)
                }
                _ => false,
            }
        }
        let inequalities = self.inequality_fields();
        if !inequalities.is_empty()
            && !inequalities.iter().any(FieldPath::is_document_name)
            && self.filter.as_ref().is_some_and(has_key_equality)
        {
            return Err(QueryError::KeyEqualityWithOtherInequalities);
        }
        Ok(())
    }

    /// Validates the `__name__` values of cursors as production does. Call on a canonicalized
    /// query: the arity rule in [`Self::canonicalize`] runs first, so nothing here looks past
    /// the order-by.
    ///
    /// A value in a `__name__` position must be a document reference (FS-QUERY-INDEX
    /// cursors/names#name-string-value), and a reference to a collection is refused
    /// (`name-collection-reference`). Production positions by any document of the database,
    /// inside the query's scope or not (`name-foreign-collection`,
    /// `name-subcollection-document`, `name-reference-absent-document`).
    ///
    /// These are production refusals, so the strict profile applies them and the `emulator`
    /// profile does not; `spec/compatibility/contract.json` forbids the `emulator` profile
    /// from adding a rejection.
    pub fn check_production_cursor_constraints(&self) -> Result<(), QueryError> {
        let order = self.effective_order_by();
        for cursor in [&self.start_at, &self.end_at].into_iter().flatten() {
            for (position, value) in cursor.values.iter().enumerate() {
                // Arity is refused by `canonicalize`; a longer cursor never reaches here.
                let Some(clause) = order.get(position) else {
                    break;
                };
                if !clause.field.is_document_name() {
                    continue;
                }
                let Value::Reference(name) = value else {
                    return Err(QueryError::CursorNameValue { position });
                };
                // Production positions by any document of the database, inside the query's
                // scope or not (observed 2026-09-24); a reference to a collection is refused
                // in its words. Another malformed reference positions nothing.
                if DocumentPath::from_resource_name(name).is_none() {
                    return Err(if names_a_collection(name) {
                        QueryError::CursorReferenceNotDocument { name: name.clone() }
                    } else {
                        QueryError::CursorNameValue { position }
                    });
                }
            }
        }
        Ok(())
    }

    /// A kindless query (the all-descendants scan without a collection id) may filter and
    /// order only by `__name__`, ascending.
    fn check_kindless_constraints(&self) -> Result<(), QueryError> {
        if !self.scope.is_kindless() {
            return Ok(());
        }
        if let Some(field) = self.filter.as_ref().and_then(first_non_name_field) {
            return Err(QueryError::KindRequiredForFilter { field });
        }
        if self
            .order_by
            .iter()
            .any(|o| !o.field.is_document_name() || o.direction != Direction::Ascending)
        {
            return Err(QueryError::KindRequiredForOrder);
        }
        Ok(())
    }

    /// A query over `scope` with no filter, ordering or cursor.
    #[must_use]
    pub const fn new(scope: QueryScope) -> Self {
        Self {
            scope,
            filter: None,
            order_by: Vec::new(),
            start_at: None,
            end_at: None,
            offset: 0,
            limit: None,
            projection: None,
            find_nearest: None,
            production_refusals: true,
        }
    }

    /// Sets the filter.
    #[must_use]
    pub fn with_filter(mut self, filter: FilterExpr) -> Self {
        self.filter = Some(filter);
        self
    }

    /// Appends an order-by clause.
    #[must_use]
    pub fn with_order(mut self, order: OrderClause) -> Self {
        self.order_by.push(order);
        self
    }

    /// Sets the nearest-neighbor stage.
    #[must_use]
    pub fn with_find_nearest(mut self, find_nearest: FindNearest) -> Self {
        self.find_nearest = Some(find_nearest);
        self
    }

    /// Canonicalizes the filter tree: validates operator/value shapes, flattens nested
    /// `and`/`or`, collapses single-child composites and sorts children, with every refusal
    /// production makes (the strict profile). Idempotent.
    pub fn canonicalize(&self) -> Result<Self, QueryError> {
        self.canonicalize_with(Refusals::Production)
    }

    /// [`Self::canonicalize`] without the refusals only production makes: the `emulator`
    /// profile may add no rejection the official emulator does not make
    /// (`spec/compatibility/contract.json`, profiles.emulator). Those are the kindless
    /// constraints, a duplicate order field, an empty `or`, array membership and unary
    /// filters on `__name__`, and a cursor longer than the explicit order (the official
    /// emulator counts the implied order too).
    pub fn canonicalize_emulator(&self) -> Result<Self, QueryError> {
        self.canonicalize_with(Refusals::Emulator)
    }

    fn canonicalize_with(&self, refusals: Refusals) -> Result<Self, QueryError> {
        let production = refusals == Refusals::Production;
        let filter = match &self.filter {
            None => None,
            Some(f) => match canonicalize_filter(f, production)? {
                // An empty composite constrains nothing: the query runs unfiltered, which
                // is what the official emulator does with it.
                FilterExpr::And(children) if children.is_empty() => None,
                c => {
                    check_negation_rules(&c)?;
                    check_not_in_rules(&c)?;
                    check_name_filters(&c, production)?;
                    Some(c)
                }
            },
        };
        let q = Self {
            filter,
            production_refusals: production,
            ..self.clone()
        };
        if let Some(find_nearest) = &q.find_nearest {
            validate_find_nearest(find_nearest)?;
        }
        if production {
            q.check_kindless_constraints()?;
            let mut seen = BTreeSet::new();
            for clause in &q.order_by {
                if !seen.insert(&clause.field) {
                    return Err(QueryError::DuplicateOrderField {
                        field: clause.field.clone(),
                    });
                }
            }
        }
        let order = q.effective_order_by();
        // `__name__` is unique, so a clause after it could never decide anything; the
        // backend refuses such an ordering rather than silently ignoring the clause. It
        // arises when an inequality field is appended after an explicit `__name__` order.
        if let Some(position) = order.iter().position(|o| o.field.is_document_name()) {
            if position + 1 < order.len() {
                return Err(QueryError::OrderAfterDocumentName);
            }
        }
        // Production positions a cursor against the explicit order-by only: neither the
        // implicit `__name__` tiebreak nor an inequality's implied order takes a value. The
        // official emulator counts the implied order as well.
        let arity = if production {
            q.order_by.len()
        } else {
            order.len()
        };
        for cursor in [&q.start_at, &q.end_at].into_iter().flatten() {
            if cursor.values.len() > arity {
                return Err(QueryError::CursorArityMismatch {
                    cursor: cursor.values.len(),
                    order_by: arity,
                });
            }
        }
        Ok(q)
    }

    /// Disjunctions of the canonical filter in disjunctive normal form. Each disjunction is a
    /// list of atomic filters. An absent filter yields one empty disjunction.
    #[must_use]
    pub fn dnf(&self) -> Vec<Vec<FilterExpr>> {
        match &self.filter {
            None => vec![Vec::new()],
            Some(f) => dnf_of(f),
        }
    }

    /// Number of DNF disjunctions (`in` / `array-contains-any` values expand).
    #[must_use]
    pub fn dnf_disjunction_count(&self) -> u64 {
        match &self.filter {
            None => 1,
            Some(f) => dnf_count(f),
        }
    }

    /// Distinct fields with an inequality / range operator.
    #[must_use]
    pub fn inequality_fields(&self) -> BTreeSet<FieldPath> {
        let mut out = BTreeSet::new();
        if let Some(f) = &self.filter {
            collect_inequality_fields(f, &mut out);
        }
        out
    }

    /// Effective ordering: explicit clauses, then inequality fields not already present (in
    /// canonical field order), then `__name__` following the last explicit direction.
    #[must_use]
    pub fn effective_order_by(&self) -> Vec<OrderClause> {
        let mut out = self.order_by.clone();
        let last_direction = out.last().map_or(Direction::Ascending, |o| o.direction);
        let explicit: BTreeSet<FieldPath> = out.iter().map(|o| o.field.clone()).collect();
        for field in self.inequality_fields() {
            if !field.is_document_name() && !explicit.contains(&field) {
                out.push(OrderClause {
                    field,
                    direction: last_direction,
                });
            }
        }
        if !out.iter().any(|o| o.field.is_document_name()) {
            out.push(OrderClause {
                field: FieldPath::document_name(),
                direction: last_direction,
            });
        }
        out
    }

    /// Component count on the DNF basis: the sum of every filter occurrence across all
    /// disjunctions, plus explicit orders and the parent path. Queries whose expansion exceeds
    /// [`MAX_MATERIALIZED_DISJUNCTIONS`] are reported as saturated without materializing.
    #[must_use]
    pub fn component_count(&self) -> ComponentCount {
        let filters = if self.dnf_disjunction_count() > MAX_MATERIALIZED_DISJUNCTIONS {
            u64::MAX / 4
        } else {
            self.dnf().iter().map(|d| d.len() as u64).sum()
        };
        let orders = self.order_by.len() as u64;
        let parent_path = u64::from(self.scope.parent().is_some());
        ComponentCount {
            filters,
            orders,
            parent_path,
            total: filters + orders + parent_path,
        }
    }

    /// Checks the Standard query limits from `firestore-standard-query-2026-08-25`, in the
    /// order production checks them: the values of one `in` / `array-contains-any` / `not-in`
    /// filter, the disjunction count, array membership per disjunction, inequality fields and
    /// the component total. Each violation carries production's refusal text.
    pub fn check_standard_limits(&self) -> Result<(), Vec<QueryLimitViolation>> {
        let mut limits = LimitCheck::default();
        // Production reports a value count first; the checks after it still run, so a limit
        // the official emulator refuses is never hidden behind one it only observes.
        self.check_value_counts(&mut limits);
        let disjunctions = self.dnf_disjunction_count();
        let maximum_disjunctions = LimitCheck::maximum("FS-QUERY-LIMIT-DNF-DISJUNCTIONS");
        limits.check(
            "FS-QUERY-LIMIT-DNF-DISJUNCTIONS",
            disjunctions,
            format!("{disjunctions} disjunctions after DNF expansion"),
            format!(
                "Too many disjunctions after normalization. Result had {disjunctions} disjunctions which is more than the maximum of {maximum_disjunctions}"
            ),
        );
        if disjunctions > maximum_disjunctions {
            // Never materialize an unbounded expansion; the count alone rejects the query.
            return Err(limits.violations);
        }
        self.check_disjunction_membership(&mut limits);
        let fields = self.inequality_fields();
        let inequality = fields.len() as u64;
        let listed: Vec<String> = fields.iter().map(ToString::to_string).collect();
        let maximum_inequality = LimitCheck::maximum("FS-QUERY-LIMIT-INEQUALITY-FIELDS");
        limits.check(
            "FS-QUERY-LIMIT-INEQUALITY-FIELDS",
            inequality,
            format!("{inequality} distinct range / inequality fields"),
            format!(
                "The query contains {inequality} distinct inequality fields: [{}]. A query may not have more than {maximum_inequality} distinct inequality fields.",
                echo(&listed.join(", "))
            ),
        );
        let components = self.component_count();
        let maximum_components = LimitCheck::maximum("FS-QUERY-LIMIT-COMPONENTS");
        limits.check(
            "FS-QUERY-LIMIT-COMPONENTS",
            components.total,
            format!(
                "{} filters + {} orders + {} parent path",
                components.filters, components.orders, components.parent_path
            ),
            format!(
                "The query may not have more than {maximum_components} filters + sort orders + ancestor total. Currently there are {} filters, {} sort orders, and {} ancestor filter.",
                components.filters,
                components.orders,
                if components.parent_path == 0 { "no" } else { "one" }
            ),
        );
        if limits.violations.is_empty() {
            Ok(())
        } else {
            Err(limits.violations)
        }
    }

    /// The value count of each `in` / `array-contains-any` (30) and `not-in` (10) filter.
    fn check_value_counts(&self, limits: &mut LimitCheck) {
        let Some(filter) = &self.filter else {
            return;
        };
        let mut atoms = Vec::new();
        collect_atoms(filter, &mut atoms);
        for (field, op, values) in atoms {
            let (id, name) = match op {
                FieldOp::In => ("FS-QUERY-LIMIT-DNF-DISJUNCTIONS", "IN"),
                FieldOp::ArrayContainsAny => {
                    ("FS-QUERY-LIMIT-DNF-DISJUNCTIONS", "ARRAY_CONTAINS_ANY")
                }
                FieldOp::NotIn => ("FS-QUERY-LIMIT-NOT-IN-VALUES", "NOT_IN"),
                _ => continue,
            };
            let maximum = LimitCheck::maximum(id);
            limits.check(
                id,
                values,
                format!("{name} on {field} has {values} values"),
                format!("'{name}' supports up to {maximum} comparison values."),
            );
        }
    }

    /// One array membership filter per disjunction, and no `not-in` beside `!=`.
    fn check_disjunction_membership(&self, limits: &mut LimitCheck) {
        let mut has_not_in = false;
        let mut has_neq = false;
        for disjunction in self.dnf() {
            let mut array_contains = 0u64;
            let mut array_contains_any = 0u64;
            for atom in &disjunction {
                if let FilterExpr::Field { op, .. } = atom {
                    match op {
                        FieldOp::ArrayContains => array_contains += 1,
                        FieldOp::ArrayContainsAny => array_contains_any += 1,
                        FieldOp::NotIn => has_not_in = true,
                        FieldOp::NotEqual => has_neq = true,
                        _ => {}
                    }
                }
            }
            // Each disjunction may hold one array membership filter of either kind.
            limits.check(
                "FS-QUERY-LIMIT-ARRAY-CONTAINS-PER-DISJUNCTION",
                array_contains.max(array_contains_any),
                format!(
                    "{array_contains} array-contains and {array_contains_any} array-contains-any filters in one disjunction"
                ),
                ARRAY_CONTAINS_LIMIT.to_owned(),
            );
            limits.check(
                "FS-QUERY-LIMIT-ARRAY-CONTAINS-COMBINATION",
                u64::from(array_contains > 0 && array_contains_any > 0),
                "array-contains combined with array-contains-any in one disjunction".to_owned(),
                ARRAY_CONTAINS_LIMIT.to_owned(),
            );
        }
        limits.check(
            "FS-QUERY-LIMIT-NOT-IN-NEQ-COMBINATION",
            u64::from(has_not_in && has_neq),
            "not-in combined with != in one compound query".to_owned(),
            "Only a single 'NOT_EQUAL', 'NOT_IN', 'IS_NOT_NAN', or 'IS_NOT_NULL' filter allowed per query."
                .to_owned(),
        );
    }
}

/// Production's refusal of a second array membership filter in one disjunction.
const ARRAY_CONTAINS_LIMIT: &str =
    "A maximum of 1 'ARRAY_CONTAINS' filter is allowed per disjunction.";

/// The Standard limit catalog and the violations found so far.
#[derive(Default)]
struct LimitCheck {
    violations: Vec<QueryLimitViolation>,
}

impl LimitCheck {
    fn maximum(id: &str) -> u64 {
        match FIRESTORE_STANDARD_QUERY_2026_08_25
            .find(id)
            .map(|l| l.maximum)
        {
            Some(LimitMaximum::Fixed(v)) => v,
            _ => u64::MAX,
        }
    }

    fn check(&mut self, id: &'static str, current: u64, detail: String, message: String) {
        let maximum = Self::maximum(id);
        if current > maximum {
            self.violations.push(QueryLimitViolation {
                limit_id: id,
                current,
                maximum,
                detail,
                message,
            });
        }
    }
}

/// Every field filter of a filter tree with the number of values it compares against.
fn collect_atoms<'a>(f: &'a FilterExpr, out: &mut Vec<(&'a FieldPath, FieldOp, u64)>) {
    match f {
        FilterExpr::Field { field, op, value } => {
            let values = match value {
                Value::Array(items) => items.len() as u64,
                _ => 1,
            };
            out.push((field, *op, values));
        }
        FilterExpr::Unary { .. } => {}
        FilterExpr::And(children) | FilterExpr::Or(children) => {
            for child in children {
                collect_atoms(child, out);
            }
        }
    }
}

/// Upper bound on the DNF size this crate will materialize (the Standard limit is 30).
pub const MAX_MATERIALIZED_DISJUNCTIONS: u64 = 4096;

/// Structural operator-combination rules that hold in every edition.
fn check_not_in_rules(f: &FilterExpr) -> Result<(), QueryError> {
    fn walk(f: &FilterExpr, not_in: &mut u64, disjunctive: &mut bool) {
        match f {
            FilterExpr::Field { op, .. } => match op {
                FieldOp::NotIn => *not_in += 1,
                FieldOp::In | FieldOp::ArrayContainsAny => *disjunctive = true,
                _ => {}
            },
            FilterExpr::Unary { .. } => {}
            FilterExpr::Or(children) => {
                *disjunctive = true;
                for c in children {
                    walk(c, not_in, disjunctive);
                }
            }
            FilterExpr::And(children) => {
                for c in children {
                    walk(c, not_in, disjunctive);
                }
            }
        }
    }
    let mut not_in = 0;
    let mut disjunctive = false;
    walk(f, &mut not_in, &mut disjunctive);
    if not_in > 1 {
        return Err(QueryError::MultipleNotIn);
    }
    if not_in == 1 && disjunctive {
        return Err(QueryError::NotInWithDisjunction);
    }
    Ok(())
}

/// At most one negating filter (`!=`, `not-in`, `IS_NOT_NAN`, `IS_NOT_NULL`) per query,
/// as the `StructuredQuery` contract requires of each of them.
fn check_negation_rules(f: &FilterExpr) -> Result<(), QueryError> {
    fn count(f: &FilterExpr) -> u64 {
        match f {
            FilterExpr::Field {
                op: FieldOp::NotEqual | FieldOp::NotIn,
                ..
            }
            | FilterExpr::Unary {
                op: UnaryOp::IsNotNan | UnaryOp::IsNotNull,
                ..
            } => 1,
            FilterExpr::Field { .. } | FilterExpr::Unary { .. } => 0,
            FilterExpr::And(children) | FilterExpr::Or(children) => {
                children.iter().map(count).sum()
            }
        }
    }
    if count(f) > 1 {
        return Err(QueryError::MultipleNegations);
    }
    Ok(())
}

/// Whether a resource name is well formed but names a collection: an odd number of
/// non-empty segments after `.../documents/`.
fn names_a_collection(name: &str) -> bool {
    name.split_once("/documents/").is_some_and(|(_, relative)| {
        let segments: Vec<&str> = relative.split('/').collect();
        segments.len() % 2 == 1 && segments.iter().all(|segment| !segment.is_empty())
    })
}

/// A filter on `__name__` compares document references and nothing else (an `in` /
/// `not-in` list holds references only).
/// The first filtered field that is not `__name__`, in filter order.
fn first_non_name_field(f: &FilterExpr) -> Option<FieldPath> {
    match f {
        FilterExpr::Field { field, .. } | FilterExpr::Unary { field, .. } => {
            (!field.is_document_name()).then(|| field.clone())
        }
        FilterExpr::And(children) | FilterExpr::Or(children) => {
            children.iter().find_map(first_non_name_field)
        }
    }
}

fn check_name_filters(f: &FilterExpr, production: bool) -> Result<(), QueryError> {
    match f {
        FilterExpr::Field {
            field,
            op: FieldOp::ArrayContains | FieldOp::ArrayContainsAny,
            ..
        } if production && field.is_document_name() => Err(QueryError::NameReserved),
        FilterExpr::Unary { field, .. } if production && field.is_document_name() => {
            Err(QueryError::NameFilterValue)
        }
        FilterExpr::Field { field, value, .. } if field.is_document_name() => {
            let ok = match value {
                Value::Reference(_) => true,
                Value::Array(items) => items.iter().all(|v| matches!(v, Value::Reference(_))),
                _ => false,
            };
            if ok {
                Ok(())
            } else {
                Err(QueryError::NameFilterValue)
            }
        }
        FilterExpr::Field { .. } | FilterExpr::Unary { .. } => Ok(()),
        FilterExpr::And(children) | FilterExpr::Or(children) => children
            .iter()
            .try_for_each(|child| check_name_filters(child, production)),
    }
}

fn validate_find_nearest(find_nearest: &FindNearest) -> Result<(), QueryError> {
    // A `__name__` vector field is not refused here: no vector index can serve it, so the
    // index check answers production's missing-vector-index text.
    if find_nearest.query_vector.is_empty() {
        return Err(QueryError::FindNearestQueryVectorEmpty);
    }
    if find_nearest.query_vector.len() > 2048
        || find_nearest
            .query_vector
            .iter()
            .any(|component| !component.is_finite())
    {
        return Err(QueryError::FindNearestQueryVector);
    }
    if !(1..=1000).contains(&find_nearest.limit) {
        return Err(QueryError::FindNearestLimit);
    }
    if find_nearest
        .distance_threshold
        .is_some_and(|threshold| !threshold.is_finite())
    {
        return Err(QueryError::FindNearestDistanceThreshold);
    }
    if find_nearest
        .distance_result_field
        .as_ref()
        .is_some_and(FieldPath::is_document_name)
    {
        return Err(QueryError::FindNearestDistanceResultField);
    }
    Ok(())
}

fn canonicalize_filter(f: &FilterExpr, production: bool) -> Result<FilterExpr, QueryError> {
    match f {
        FilterExpr::Field { field, op, value } => {
            if op.takes_array() {
                match value {
                    Value::Array(items) if !items.is_empty() => {}
                    Value::Array(_) => {
                        return Err(QueryError::NonEmptyArrayRequired { op: *op });
                    }
                    _ => {
                        return Err(QueryError::ArrayValueRequired {
                            field: field.clone(),
                            op: *op,
                        })
                    }
                }
            }
            Ok(f.clone())
        }
        FilterExpr::Unary { .. } => Ok(f.clone()),
        FilterExpr::And(children) => canonicalize_composite(children, true, production),
        FilterExpr::Or(children) => canonicalize_composite(children, false, production),
    }
}

// Canonicalization order is separate from structural filter equality (notably for NaN
// and integer/double operands). Keep deduplication structural below.
fn canonical_filter_cmp(a: &FilterExpr, b: &FilterExpr) -> core::cmp::Ordering {
    use core::cmp::Ordering;
    let rank = |filter: &FilterExpr| match filter {
        FilterExpr::Field { .. } => 0,
        FilterExpr::Unary { .. } => 1,
        FilterExpr::And(_) => 2,
        FilterExpr::Or(_) => 3,
    };
    rank(a).cmp(&rank(b)).then_with(|| match (a, b) {
        (
            FilterExpr::Field {
                field: af,
                op: ao,
                value: av,
            },
            FilterExpr::Field {
                field: bf,
                op: bo,
                value: bv,
            },
        ) => (af, ao, IndexValue(av)).cmp(&(bf, bo, IndexValue(bv))),
        (FilterExpr::Unary { field: af, op: ao }, FilterExpr::Unary { field: bf, op: bo }) => {
            (af, ao).cmp(&(bf, bo))
        }
        (FilterExpr::And(a), FilterExpr::And(b)) | (FilterExpr::Or(a), FilterExpr::Or(b)) => a
            .iter()
            .zip(b)
            .map(|(a, b)| canonical_filter_cmp(a, b))
            .find(|order| *order != Ordering::Equal)
            .unwrap_or_else(|| a.len().cmp(&b.len())),
        _ => Ordering::Equal,
    })
}

fn canonicalize_composite(
    children: &[FilterExpr],
    is_and: bool,
    production: bool,
) -> Result<FilterExpr, QueryError> {
    // Production refuses an empty `or` (an empty `and` constrains nothing and is served).
    if production && !is_and && children.is_empty() {
        return Err(QueryError::EmptyComposite);
    }
    let mut flat: Vec<FilterExpr> = Vec::new();
    for child in children {
        let c = canonicalize_filter(child, production)?;
        match (&c, is_and) {
            (FilterExpr::And(inner), true) | (FilterExpr::Or(inner), false) => {
                flat.extend(inner.iter().cloned());
            }
            // An empty composite of either kind constrains nothing, so it drops out of
            // its parent (and an empty top-level one becomes "no filter").
            (FilterExpr::And(inner) | FilterExpr::Or(inner), _) if inner.is_empty() => {}
            _ => flat.push(c),
        }
    }
    if flat.is_empty() {
        return Ok(FilterExpr::And(Vec::new()));
    }
    flat.sort_by(canonical_filter_cmp);
    flat.dedup();
    if flat.len() == 1 {
        return Ok(flat.remove(0));
    }
    Ok(if is_and {
        FilterExpr::And(flat)
    } else {
        FilterExpr::Or(flat)
    })
}

/// DNF expansion. `in` / `array-contains-any` are expanded into one disjunction per value.
fn dnf_of(f: &FilterExpr) -> Vec<Vec<FilterExpr>> {
    match f {
        FilterExpr::Field {
            field,
            op: FieldOp::In,
            value: Value::Array(items),
        } => items
            .iter()
            .map(|v| {
                vec![FilterExpr::Field {
                    field: field.clone(),
                    op: FieldOp::Equal,
                    value: v.clone(),
                }]
            })
            .collect(),
        // array-contains-any keeps its operator (with a single-value array) so that the
        // "array-contains combined with array-contains-any" rule stays distinguishable.
        FilterExpr::Field {
            field,
            op: FieldOp::ArrayContainsAny,
            value: Value::Array(items),
        } => items
            .iter()
            .map(|v| {
                vec![FilterExpr::Field {
                    field: field.clone(),
                    op: FieldOp::ArrayContainsAny,
                    value: Value::Array(vec![v.clone()]),
                }]
            })
            .collect(),
        FilterExpr::Field { .. } | FilterExpr::Unary { .. } => vec![vec![f.clone()]],
        FilterExpr::Or(children) => children.iter().flat_map(dnf_of).collect(),
        FilterExpr::And(children) => {
            let mut acc: Vec<Vec<FilterExpr>> = vec![Vec::new()];
            for child in children {
                let child_dnf = dnf_of(child);
                let mut next =
                    Vec::with_capacity(acc.len().saturating_mul(child_dnf.len()).min(1 << 16));
                for a in &acc {
                    for c in &child_dnf {
                        let mut merged = a.clone();
                        merged.extend(c.iter().cloned());
                        next.push(merged);
                    }
                }
                acc = next;
            }
            acc
        }
    }
}

fn dnf_count(f: &FilterExpr) -> u64 {
    match f {
        FilterExpr::Field {
            op: FieldOp::In | FieldOp::ArrayContainsAny,
            value: Value::Array(items),
            ..
        } => items.len() as u64,
        FilterExpr::Field { .. } | FilterExpr::Unary { .. } => 1,
        FilterExpr::Or(children) => children.iter().map(dnf_count).fold(0, u64::saturating_add),
        FilterExpr::And(children) => children.iter().map(dnf_count).fold(1, u64::saturating_mul),
    }
}

fn collect_inequality_fields(f: &FilterExpr, out: &mut BTreeSet<FieldPath>) {
    match f {
        FilterExpr::Field { field, op, .. } if op.is_inequality() => {
            out.insert(field.clone());
        }
        FilterExpr::Unary {
            field,
            op: UnaryOp::IsNotNull | UnaryOp::IsNotNan,
        } => {
            out.insert(field.clone());
        }
        FilterExpr::And(children) | FilterExpr::Or(children) => {
            for c in children {
                collect_inequality_fields(c, out);
            }
        }
        _ => {}
    }
}
