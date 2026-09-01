//! Canonical query AST, canonicalization, DNF and Standard query limits (spec 8.5, 8.10.4).

use core::fmt;
use std::collections::BTreeSet;

use fireemu_core_limits::catalogs::FIRESTORE_STANDARD_QUERY_2026_08_25;
use fireemu_core_limits::model::LimitMaximum;
use fireemu_core_types::ids::CollectionId;

use crate::field_path::FieldPath;
use crate::path::DocumentPath;
use crate::value::Value;

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

    /// Parent document, when the query is scoped below one.
    #[must_use]
    pub const fn parent(&self) -> Option<&DocumentPath> {
        match self {
            Self::Collection { parent, .. }
            | Self::CollectionGroup { parent, .. }
            | Self::KindlessAllDescendants { parent } => parent.as_ref(),
        }
    }

    /// Named collection selector, absent only for a kindless scan.
    #[must_use]
    pub const fn collection_id(&self) -> Option<&CollectionId> {
        match self {
            Self::Collection { collection_id, .. }
            | Self::CollectionGroup { collection_id, .. } => Some(collection_id),
            Self::KindlessAllDescendants { .. } => None,
        }
    }

    /// Whether descendants, rather than one direct collection, are selected.
    #[must_use]
    pub const fn all_descendants(&self) -> bool {
        !matches!(self, Self::Collection { .. })
    }

    /// Whether collection names are ignored.
    #[must_use]
    pub const fn is_kindless(&self) -> bool {
        matches!(self, Self::KindlessAllDescendants { .. })
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
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cursor {
    /// Values aligned with the effective order-by.
    pub values: Vec<Value>,
    /// Whether the position itself is included.
    pub before: bool,
}

/// Canonical query.
#[derive(Debug, Clone, PartialEq, Eq)]
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
}

/// Structural validation errors found while canonicalizing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueryError {
    /// `in` / `array-contains-any` / `not-in` needs a non-empty array value.
    ArrayValueRequired {
        /// Field.
        field: FieldPath,
        /// Operator.
        op: FieldOp,
    },
    /// An empty `and` / `or`.
    EmptyComposite,
    /// More than one `not-in` filter.
    MultipleNotIn,
    /// `not-in` combined with `in`, `array-contains-any` or `or`.
    NotInWithDisjunction,
    /// Cursor arity does not match the effective order-by.
    CursorArityMismatch {
        /// Cursor values.
        cursor: usize,
        /// Effective order-by length.
        order_by: usize,
    },
    /// More than one of `!=`, `not-in`, `IS_NOT_NAN` and `IS_NOT_NULL` in one query.
    MultipleNegations,
    /// The effective ordering names a field after `__name__`, which is unique, so the
    /// extra clause could never take effect.
    OrderAfterDocumentName,
    /// A filter on `__name__` compares against something other than a document reference.
    NameFilterValue,
}

impl fmt::Display for QueryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ArrayValueRequired { field, op } => {
                write!(
                    f,
                    "{} requires a non-empty array value on {field}",
                    op.name()
                )
            }
            Self::EmptyComposite => f.write_str("composite filter has no children"),
            Self::MultipleNotIn => f.write_str("a query can have at most one not-in filter"),
            Self::NotInWithDisjunction => {
                f.write_str("not-in cannot be combined with in, array-contains-any or or")
            }
            Self::CursorArityMismatch { cursor, order_by } => {
                write!(
                    f,
                    "cursor has {cursor} values but the order-by has {order_by} fields"
                )
            }
            Self::MultipleNegations => f.write_str(
                "Only a single 'NOT_EQUAL', 'NOT_IN', 'IS_NOT_NAN', or 'IS_NOT_NULL' filter allowed per query.",
            ),
            Self::OrderAfterDocumentName => {
                f.write_str("order by clause cannot contain more fields after the key")
            }
            Self::NameFilterValue => f.write_str("__key__ filter value must be a Key"),
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

    /// Canonicalizes the filter tree: validates operator/value shapes, flattens nested
    /// `and`/`or`, collapses single-child composites and sorts children. Idempotent.
    pub fn canonicalize(&self) -> Result<Self, QueryError> {
        let filter = match &self.filter {
            None => None,
            Some(f) => match canonicalize_filter(f)? {
                // An empty composite constrains nothing: the query runs unfiltered, which
                // is what the official emulator does with it.
                FilterExpr::And(children) if children.is_empty() => None,
                c => {
                    check_not_in_rules(&c)?;
                    check_negation_rules(&c)?;
                    check_name_filters(&c)?;
                    Some(c)
                }
            },
        };
        let q = Self {
            filter,
            ..self.clone()
        };
        let order = q.effective_order_by();
        // `__name__` is unique, so a clause after it could never decide anything; the
        // backend refuses such an ordering rather than silently ignoring the clause. It
        // arises when an inequality field is appended after an explicit `__name__` order.
        if let Some(position) = order.iter().position(|o| o.field.is_document_name()) {
            if position + 1 < order.len() {
                return Err(QueryError::OrderAfterDocumentName);
            }
        }
        let arity = order.len();
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
        for field in self.inequality_fields() {
            if !out.iter().any(|o| o.field == field) {
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

    /// Checks the Standard query limits from `firestore-standard-query-2026-08-25`.
    pub fn check_standard_limits(&self) -> Result<(), Vec<QueryLimitViolation>> {
        let catalog = &FIRESTORE_STANDARD_QUERY_2026_08_25;
        let max = |id: &str| match catalog.find(id).map(|l| l.maximum) {
            Some(LimitMaximum::Fixed(v)) => v,
            _ => u64::MAX,
        };
        let mut violations = Vec::new();
        let mut check = |id: &'static str, current: u64, detail: String| {
            let maximum = max(id);
            if current > maximum {
                violations.push(QueryLimitViolation {
                    limit_id: id,
                    current,
                    maximum,
                    detail,
                });
            }
        };

        let disjunctions = self.dnf_disjunction_count();
        check(
            "FS-QUERY-LIMIT-DNF-DISJUNCTIONS",
            disjunctions,
            format!("{disjunctions} disjunctions after DNF expansion"),
        );
        if disjunctions > max("FS-QUERY-LIMIT-DNF-DISJUNCTIONS") {
            // Never materialize an unbounded expansion; the count alone rejects the query.
            return Err(violations);
        }

        let mut has_not_in = false;
        let mut has_neq = false;
        for disjunction in self.dnf() {
            let mut array_contains = 0u64;
            let mut array_contains_any = 0u64;
            for atom in &disjunction {
                if let FilterExpr::Field { field, op, value } = atom {
                    match op {
                        FieldOp::ArrayContains => array_contains += 1,
                        FieldOp::ArrayContainsAny => array_contains_any += 1,
                        FieldOp::NotIn => {
                            has_not_in = true;
                            let n = match value {
                                Value::Array(items) => items.len() as u64,
                                _ => 0,
                            };
                            check(
                                "FS-QUERY-LIMIT-NOT-IN-VALUES",
                                n,
                                format!("not-in on {field} has {n} values"),
                            );
                        }
                        FieldOp::NotEqual => has_neq = true,
                        _ => {}
                    }
                }
            }
            // Each disjunction may hold one array membership filter of either kind.
            check(
                "FS-QUERY-LIMIT-ARRAY-CONTAINS-PER-DISJUNCTION",
                array_contains.max(array_contains_any),
                format!(
                    "{array_contains} array-contains and {array_contains_any} array-contains-any filters in one disjunction"
                ),
            );
            let combination = u64::from(array_contains > 0 && array_contains_any > 0);
            check(
                "FS-QUERY-LIMIT-ARRAY-CONTAINS-COMBINATION",
                combination,
                "array-contains combined with array-contains-any in one disjunction".to_owned(),
            );
        }
        check(
            "FS-QUERY-LIMIT-NOT-IN-NEQ-COMBINATION",
            u64::from(has_not_in && has_neq),
            "not-in combined with != in one compound query".to_owned(),
        );

        let inequality = self.inequality_fields().len() as u64;
        check(
            "FS-QUERY-LIMIT-INEQUALITY-FIELDS",
            inequality,
            format!("{inequality} distinct range / inequality fields"),
        );

        let components = self.component_count();
        check(
            "FS-QUERY-LIMIT-COMPONENTS",
            components.total,
            format!(
                "{} filters + {} orders + {} parent path",
                components.filters, components.orders, components.parent_path
            ),
        );

        if violations.is_empty() {
            Ok(())
        } else {
            Err(violations)
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

/// A filter on `__name__` compares document references and nothing else (an `in` /
/// `not-in` list holds references only).
fn check_name_filters(f: &FilterExpr) -> Result<(), QueryError> {
    match f {
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
        FilterExpr::And(children) | FilterExpr::Or(children) => {
            children.iter().try_for_each(check_name_filters)
        }
    }
}

fn canonicalize_filter(f: &FilterExpr) -> Result<FilterExpr, QueryError> {
    match f {
        FilterExpr::Field { field, op, value } => {
            if op.takes_array() {
                match value {
                    Value::Array(items) if !items.is_empty() => {}
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
        FilterExpr::And(children) => canonicalize_composite(children, true),
        FilterExpr::Or(children) => canonicalize_composite(children, false),
    }
}

fn canonicalize_composite(children: &[FilterExpr], is_and: bool) -> Result<FilterExpr, QueryError> {
    let mut flat: Vec<FilterExpr> = Vec::new();
    for child in children {
        let c = canonicalize_filter(child)?;
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
    flat.sort();
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
