//! Query execution: the optimized executor against a straightforward reference executor
//! (`FS-QUERY-PERF-03`, `FS-QUERY-PERF-04`) and its bounded-selection counters
//! (`FS-QUERY-PERF-01`, `FS-QUERY-PERF-02`).
//!
//! The generator is hand-rolled on the seeded `SplitMix64` of `fireemu-core-types`: the core
//! crates stay dependency-free, and every failure is reproducible from its seed.

use core::cmp::Ordering;
use std::collections::BTreeMap;

use fireemu_core_firestore::field_path::FieldPath;
use fireemu_core_firestore::path::DocumentPath;
use fireemu_core_firestore::query::{
    Cursor, Direction, FieldOp, FilterExpr, OrderClause, Query, QueryScope, UnaryOp,
};
use fireemu_core_firestore::store::{
    get_field, Aggregation, Document, FirestoreState, Write, WriteOp,
};
use fireemu_core_firestore::value::{GeoPoint, Timestamp, Value};
use fireemu_core_types::determinism::{DeterministicRng, SplitMix64};
use fireemu_core_types::ids::{CollectionId, DatabaseId, ProjectId};
use fireemu_core_types::time::LogicalInstant;

// ---------------------------------------------------------------------------------------
// Reference executor: clone everything, sort everything, then cut.
// ---------------------------------------------------------------------------------------

fn reference_field(doc: &Document, path: &FieldPath) -> Option<Value> {
    if path.is_document_name() {
        return Some(Value::Reference(doc.path.resource_name()));
    }
    get_field(&doc.fields, path).cloned()
}

/// Equality of a stored value with a filter operand: NaN equals nothing, and neither does a
/// null operand (null is matched through the unary filters; the official emulator answers
/// the raw field filter the same way, see conformance/src/firestore-probe queries/filters).
fn reference_equal(a: &Value, b: &Value) -> bool {
    let nan = |v: &Value| matches!(v, Value::Double(d) if d.is_nan());
    !nan(a) && !nan(b) && *b != Value::Null && a.canonical_cmp(b) == Ordering::Equal
}

fn reference_comparable(a: &Value, b: &Value) -> bool {
    use fireemu_core_firestore::value::ValueKind;
    let numeric = |k: ValueKind| matches!(k, ValueKind::Number | ValueKind::Nan);
    a.kind() == b.kind() || (numeric(a.kind()) && numeric(b.kind()))
}

fn reference_filter(filter: &FilterExpr, doc: &Document) -> bool {
    match filter {
        FilterExpr::And(children) => children.iter().all(|c| reference_filter(c, doc)),
        FilterExpr::Or(children) => children.iter().any(|c| reference_filter(c, doc)),
        FilterExpr::Unary { field, op } => {
            let value = reference_field(doc, field);
            let is_nan = |v: &Value| matches!(v, Value::Double(d) if d.is_nan());
            match (op, value) {
                (UnaryOp::IsNull, Some(v)) => v == Value::Null,
                (UnaryOp::IsNotNull, Some(v)) => v != Value::Null,
                (UnaryOp::IsNan, Some(v)) => is_nan(&v),
                (UnaryOp::IsNotNan, Some(v)) => !is_nan(&v),
                (_, None) => false,
            }
        }
        FilterExpr::Field { field, op, value } => {
            let Some(v) = reference_field(doc, field) else {
                return false;
            };
            if *value == Value::Null {
                return false;
            }
            let is_nan = matches!(v, Value::Double(d) if d.is_nan());
            match op {
                FieldOp::Equal => reference_equal(&v, value),
                FieldOp::NotEqual => !reference_equal(&v, value) && v != Value::Null,
                FieldOp::LessThan
                | FieldOp::LessThanOrEqual
                | FieldOp::GreaterThan
                | FieldOp::GreaterThanOrEqual => {
                    if !reference_comparable(&v, value) || is_nan {
                        return false;
                    }
                    match (op, v.canonical_cmp(value)) {
                        (FieldOp::LessThan, o) => o == Ordering::Less,
                        (FieldOp::LessThanOrEqual, o) => o != Ordering::Greater,
                        (FieldOp::GreaterThan, o) => o == Ordering::Greater,
                        (_, o) => o != Ordering::Less,
                    }
                }
                FieldOp::ArrayContains => match &v {
                    Value::Array(items) => items.iter().any(|i| reference_equal(i, value)),
                    _ => false,
                },
                FieldOp::In => match value {
                    Value::Array(candidates) => candidates.iter().any(|c| reference_equal(&v, c)),
                    _ => false,
                },
                FieldOp::NotIn => match value {
                    Value::Array(candidates) => {
                        v != Value::Null
                            && !candidates
                                .iter()
                                .any(|c| reference_equal(&v, c) || *c == Value::Null)
                    }
                    _ => false,
                },
                FieldOp::ArrayContainsAny => match (&v, value) {
                    (Value::Array(items), Value::Array(candidates)) => items
                        .iter()
                        .any(|i| candidates.iter().any(|c| reference_equal(i, c))),
                    _ => false,
                },
            }
        }
    }
}

fn reference_compare(a: &[Value], b: &[Value], order: &[OrderClause]) -> Ordering {
    for ((x, y), clause) in a.iter().zip(b).zip(order) {
        let ord = match clause.direction {
            Direction::Ascending => x.canonical_cmp(y),
            Direction::Descending => x.canonical_cmp(y).reverse(),
        };
        if ord != Ordering::Equal {
            return ord;
        }
    }
    Ordering::Equal
}

fn reference_cursor(key: &[Value], cursor: &Cursor, order: &[OrderClause], start: bool) -> bool {
    let n = cursor.values.len().min(key.len());
    let ord = reference_compare(&key[..n], &cursor.values[..n], &order[..n]);
    if start {
        match ord {
            Ordering::Greater => true,
            Ordering::Equal => cursor.before,
            Ordering::Less => false,
        }
    } else {
        match ord {
            Ordering::Less => true,
            Ordering::Equal => !cursor.before,
            Ordering::Greater => false,
        }
    }
}

fn reference_set_field(fields: &mut BTreeMap<String, Value>, path: &FieldPath, value: Value) {
    let segments = path.segments();
    let mut map = fields;
    for s in &segments[..segments.len() - 1] {
        let entry = map
            .entry(s.clone())
            .or_insert_with(|| Value::Map(BTreeMap::new()));
        if !matches!(entry, Value::Map(_)) {
            *entry = Value::Map(BTreeMap::new());
        }
        map = match entry {
            Value::Map(m) => m,
            _ => unreachable!("just replaced with a map"),
        };
    }
    map.insert(segments[segments.len() - 1].clone(), value);
}

/// The obvious executor: every match is cloned and the whole match set is sorted before the
/// cursors, the offset, the limit and the projection are applied.
fn reference_run(corpus: &[Document], query: &Query) -> Vec<Document> {
    let scope = &query.scope;
    let parent_len = scope.parent.as_ref().map_or(0, |p| p.pairs().len());
    let order = query.effective_order_by();
    let mut rows: Vec<(Vec<Value>, Document)> = Vec::new();
    for doc in corpus {
        let in_scope = if scope.all_descendants {
            doc.path.collection_id() == &scope.collection_id
        } else {
            doc.path.pairs().len() == parent_len + 1
                && doc.path.collection_id() == &scope.collection_id
                && scope
                    .parent
                    .as_ref()
                    .is_none_or(|p| doc.path.pairs()[..parent_len] == *p.pairs())
        };
        if !in_scope {
            continue;
        }
        if let Some(f) = &query.filter {
            if !reference_filter(f, doc) {
                continue;
            }
        }
        let Some(key) = order
            .iter()
            .map(|o| reference_field(doc, &o.field))
            .collect::<Option<Vec<Value>>>()
        else {
            continue;
        };
        rows.push((key, doc.clone()));
    }
    rows.sort_by(|a, b| reference_compare(&a.0, &b.0, &order));
    let mut selected: Vec<Document> = rows
        .into_iter()
        .filter(|(key, _)| {
            query
                .start_at
                .as_ref()
                .is_none_or(|c| reference_cursor(key, c, &order, true))
                && query
                    .end_at
                    .as_ref()
                    .is_none_or(|c| reference_cursor(key, c, &order, false))
        })
        .map(|(_, d)| d)
        .collect();
    let offset = query.offset as usize;
    selected.drain(..offset.min(selected.len()));
    if let Some(limit) = query.limit {
        selected.truncate(limit as usize);
    }
    if let Some(projection) = &query.projection {
        for d in &mut selected {
            let mut out = BTreeMap::new();
            for p in projection {
                if p.is_document_name() {
                    continue;
                }
                if let Some(v) = get_field(&d.fields, p) {
                    reference_set_field(&mut out, p, v.clone());
                }
            }
            d.fields = out;
        }
    }
    selected
}

// ---------------------------------------------------------------------------------------
// Generators
// ---------------------------------------------------------------------------------------

fn project_id() -> ProjectId {
    ProjectId::try_new("demo-app").unwrap()
}

fn path(p: &str) -> DocumentPath {
    DocumentPath::parse(&project_id(), &DatabaseId::default_database(), p).unwrap()
}

fn fp(s: &str) -> FieldPath {
    FieldPath::parse(s).unwrap()
}

fn collection(id: &str) -> CollectionId {
    CollectionId::try_new(id).unwrap()
}

struct Gen {
    rng: SplitMix64,
}

impl Gen {
    fn new(seed: u64) -> Self {
        Self {
            rng: SplitMix64::new(seed),
        }
    }

    fn below(&mut self, bound: u64) -> u64 {
        self.rng.next_below(bound)
    }

    /// An index into a slice of `len` elements.
    fn index(&mut self, len: usize) -> usize {
        usize::try_from(self.rng.next_below(len as u64)).unwrap_or(0)
    }

    fn chance(&mut self, one_in: u64) -> bool {
        self.below(one_in) == 0
    }

    /// A value from a deliberately small pool: repeated values create ties, and every kind
    /// of the official value order appears.
    fn value(&mut self) -> Value {
        match self.below(15) {
            0 => Value::Null,
            1 => Value::Boolean(self.below(2) == 1),
            2 => Value::Integer(i64::try_from(self.below(5)).unwrap_or(0) - 2),
            3 => Value::Double(f64::from(u32::try_from(self.below(4)).unwrap_or(0)) / 2.0),
            4 => Value::Double(f64::NAN),
            5 => Value::Double(-0.0),
            6 => Value::Timestamp(
                Timestamp::new(1_788_000_000 + i64::try_from(self.below(3)).unwrap_or(0), 0)
                    .unwrap(),
            ),
            7 => Value::String(["", "a", "ab", "b"][self.index(4)].to_owned()),
            8 => Value::Bytes(vec![u8::try_from(self.below(3)).unwrap_or(0)]),
            9 => Value::Reference(path(&format!("items/d{:02}", self.below(4))).resource_name()),
            10 => Value::GeoPoint(
                GeoPoint::new(f64::from(i32::try_from(self.below(3)).unwrap_or(0)), 1.0).unwrap(),
            ),
            11 => Value::Array(vec![
                Value::Integer(i64::try_from(self.below(3)).unwrap_or(0)),
                Value::String("x".to_owned()),
            ]),
            12 => Value::Vector(vec![
                1.0,
                f64::from(u32::try_from(self.below(2)).unwrap_or(0)),
            ]),
            13 => Value::Map(BTreeMap::from([(
                "k".to_owned(),
                Value::Integer(i64::try_from(self.below(3)).unwrap_or(0)),
            )])),
            _ => Value::Integer(0),
        }
    }

    fn operand(&mut self, op: FieldOp) -> Value {
        match op {
            FieldOp::In | FieldOp::NotIn | FieldOp::ArrayContainsAny => {
                let n = 1 + self.below(3);
                Value::Array((0..n).map(|_| self.value()).collect())
            }
            _ => self.value(),
        }
    }

    fn filter(&mut self, depth: u32) -> FilterExpr {
        if depth > 0 && self.chance(3) {
            let children = vec![self.filter(depth - 1), self.filter(depth - 1)];
            return if self.chance(2) {
                FilterExpr::And(children)
            } else {
                FilterExpr::Or(children)
            };
        }
        let field = fp(["a", "b", "m.k", "__name__"][self.index(4)]);
        if self.chance(6) {
            let op = [
                UnaryOp::IsNull,
                UnaryOp::IsNotNull,
                UnaryOp::IsNan,
                UnaryOp::IsNotNan,
            ][self.index(4)];
            return FilterExpr::Unary { field, op };
        }
        let op = [
            FieldOp::Equal,
            FieldOp::NotEqual,
            FieldOp::LessThan,
            FieldOp::LessThanOrEqual,
            FieldOp::GreaterThan,
            FieldOp::GreaterThanOrEqual,
            FieldOp::ArrayContains,
            FieldOp::In,
            FieldOp::NotIn,
            FieldOp::ArrayContainsAny,
        ][self.index(10)];
        FilterExpr::Field {
            field,
            op,
            value: self.operand(op),
        }
    }

    fn order(&mut self) -> Vec<OrderClause> {
        let n = self.below(4);
        let mut out: Vec<OrderClause> = Vec::new();
        for _ in 0..n {
            let field = fp(["a", "b", "m.k", "__name__"][self.index(4)]);
            if out.iter().any(|o: &OrderClause| o.field == field) {
                continue;
            }
            out.push(OrderClause {
                field,
                direction: if self.chance(2) {
                    Direction::Ascending
                } else {
                    Direction::Descending
                },
            });
        }
        out
    }

    fn query(&mut self, corpus: &[Document]) -> Query {
        let scope = match self.below(4) {
            0 => QueryScope {
                parent: Some(path("items/d01")),
                collection_id: collection("sub"),
                all_descendants: false,
            },
            1 => QueryScope {
                parent: None,
                collection_id: collection("sub"),
                all_descendants: true,
            },
            2 => QueryScope {
                parent: None,
                collection_id: collection("other"),
                all_descendants: false,
            },
            _ => QueryScope {
                parent: None,
                collection_id: collection("items"),
                all_descendants: false,
            },
        };
        let mut q = Query::new(scope);
        q.order_by = self.order();
        if !self.chance(4) {
            q.filter = Some(self.filter(2));
        }
        q.offset = u32::try_from(self.below(4)).unwrap_or(0);
        q.limit = if self.chance(3) {
            None
        } else {
            Some(u32::try_from(self.below(5)).unwrap_or(0))
        };
        if self.chance(4) {
            q.projection = Some(vec![fp("a"), fp("__name__")]);
        }
        let order = q.effective_order_by();
        if self.chance(2) {
            q.start_at = Some(self.cursor(corpus, &order));
        }
        if self.chance(2) {
            q.end_at = Some(self.cursor(corpus, &order));
        }
        q
    }

    /// A cursor over the first `n` order clauses, usually taken from a real document so that
    /// `before` decides an exact tie.
    fn cursor(&mut self, corpus: &[Document], order: &[OrderClause]) -> Cursor {
        let n = 1 + self.index(order.len());
        let values: Vec<Value> = if self.chance(4) || corpus.is_empty() {
            (0..n).map(|_| self.value()).collect()
        } else {
            let doc = &corpus[self.index(corpus.len())];
            order
                .iter()
                .take(n)
                .map(|o| reference_field(doc, &o.field).unwrap_or(Value::Null))
                .collect()
        };
        Cursor {
            values,
            before: self.chance(2),
        }
    }
}

fn set(p: &str, fields: BTreeMap<String, Value>) -> Write {
    Write {
        op: WriteOp::Set {
            path: path(p),
            fields,
            update_mask: None,
        },
        precondition: None,
        transforms: vec![],
    }
}

/// A database whose documents cover ties, missing fields and every value kind, plus the
/// same documents as a flat corpus for the reference executor.
fn corpus(g: &mut Gen) -> (FirestoreState, Vec<Document>) {
    let mut names: Vec<String> = (0..24).map(|i| format!("items/d{i:02}")).collect();
    names.extend((0..4).map(|i| format!("other/o{i:02}")));
    names.extend((0..3).map(|i| format!("items/d01/sub/s{i:02}")));
    names.extend((0..2).map(|i| format!("items/d02/sub/s{i:02}")));
    let mut state = FirestoreState::new();
    let mut writes = Vec::new();
    for name in &names {
        let mut fields = BTreeMap::new();
        if !g.chance(5) {
            fields.insert("a".to_owned(), g.value());
        }
        if !g.chance(5) {
            fields.insert("b".to_owned(), g.value());
        }
        if !g.chance(4) {
            fields.insert(
                "m".to_owned(),
                Value::Map(BTreeMap::from([("k".to_owned(), g.value())])),
            );
        }
        writes.push(set(name, fields));
    }
    state
        .commit(
            &writes,
            None,
            LogicalInstant::from_unix_seconds(1_788_000_000),
        )
        .unwrap();
    let mut docs = state.list_documents(None, "items");
    docs.extend(state.list_documents(None, "other"));
    docs.extend(state.list_documents(Some(&path("items/d01")), "sub"));
    docs.extend(state.list_documents(Some(&path("items/d02")), "sub"));
    (state, docs)
}

// ---------------------------------------------------------------------------------------
// Properties
// ---------------------------------------------------------------------------------------

/// FS-QUERY-PERF-03 / FS-QUERY-PERF-04: the optimized executor and the reference executor
/// are observationally equivalent over value kinds, ties, missing fields, cursors, offsets,
/// limits and projections.
#[test]
fn optimized_and_reference_execution_agree() {
    for seed in 0..12u64 {
        let mut g = Gen::new(0x5eed_0000 + seed);
        let (db, docs) = corpus(&mut g);
        for case in 0..120u32 {
            let query = g.query(&docs);
            let (got, stats) = db.run_query_with_stats(&query, None).unwrap();
            let want = reference_run(&docs, &query);
            // Documents are compared through their debug form: `Value`'s derived `PartialEq`
            // says NaN != NaN, which would make identical results look different.
            assert_eq!(
                format!("{got:#?}"),
                format!("{want:#?}"),
                "seed {seed} case {case}: optimized and reference results differ for {query:?}"
            );
            assert_eq!(usize::try_from(stats.cloned_documents).unwrap(), got.len());
            if let Some(limit) = query.limit {
                let bound = u64::from(query.offset) + u64::from(limit);
                assert!(
                    stats.peak_candidates <= bound,
                    "seed {seed} case {case}: {} candidates held for offset {} limit {limit}",
                    stats.peak_candidates,
                    query.offset
                );
            }
        }
    }
}

/// Document names order exactly like the reference values they are compared against, without
/// being rendered.
#[test]
fn document_names_order_like_reference_values() {
    let names = [
        "items/a/sub/b",
        "items/a-x/sub/b",
        "items/a/sub/a",
        "items/b",
        "items/ab",
        "items/a",
    ];
    for left in names {
        for right in names {
            let (l, r) = (path(left), path(right));
            assert_eq!(
                l.cmp_resource_name(&r),
                Value::Reference(l.resource_name())
                    .canonical_cmp(&Value::Reference(r.resource_name())),
                "{left} vs {right}"
            );
            assert_eq!(
                l.cmp_reference(&r.resource_name()),
                l.cmp_resource_name(&r),
                "{left} vs {right}"
            );
        }
    }
}

fn large_collection(documents: usize) -> FirestoreState {
    let mut state = FirestoreState::new();
    let payload = Value::String("x".repeat(4096));
    let writes: Vec<Write> = (0..documents)
        .map(|i| {
            set(
                &format!("items/d{i:04}"),
                BTreeMap::from([
                    (
                        "n".to_owned(),
                        Value::Integer(i64::try_from(i).unwrap_or(0)),
                    ),
                    ("blob".to_owned(), payload.clone()),
                    (
                        "tags".to_owned(),
                        Value::Array(vec![Value::String(format!("t{}", i % 7))]),
                    ),
                ]),
            )
        })
        .collect();
    state
        .commit(
            &writes,
            None,
            LogicalInstant::from_unix_seconds(1_788_000_000),
        )
        .unwrap();
    state
}

/// FS-QUERY-PERF-01 / FS-QUERY-PERF-02: a finite limit bounds the candidates that are held,
/// and the only documents copied are the ones returned. Every rejected row is filtered and
/// ordered on borrowed values, so its 4 KiB payload is never cloned.
#[test]
fn a_finite_limit_bounds_candidates_and_only_selected_documents_are_cloned() {
    let db = large_collection(500);
    let base = Query::new(QueryScope {
        parent: None,
        collection_id: collection("items"),
        all_descendants: false,
    })
    .with_order(OrderClause {
        field: fp("n"),
        direction: Direction::Ascending,
    });

    let mut top_one = base.clone();
    top_one.limit = Some(1);
    let (docs, stats) = db.run_query_with_stats(&top_one, None).unwrap();
    assert_eq!(docs.len(), 1);
    assert_eq!(docs[0].fields.get("n"), Some(&Value::Integer(0)));
    assert_eq!(stats.scanned, 500);
    assert_eq!(stats.matched, 500, "every row is a candidate for the order");
    assert_eq!(stats.peak_candidates, 1, "one row is kept at a time");
    assert_eq!(stats.cloned_documents, 1, "only the answer is copied");

    // Offset plus limit widens the bound by exactly the offset.
    let mut paged = base.clone();
    paged.offset = 3;
    paged.limit = Some(2);
    let (docs, stats) = db.run_query_with_stats(&paged, None).unwrap();
    assert_eq!(docs.len(), 2);
    assert_eq!(docs[0].fields.get("n"), Some(&Value::Integer(3)));
    assert_eq!(stats.peak_candidates, 5);
    assert_eq!(stats.cloned_documents, 2);

    // A filter that rejects almost everything copies nothing for the rejected rows.
    let mut selective = base.clone();
    selective.filter = Some(FilterExpr::Field {
        field: fp("n"),
        op: FieldOp::Equal,
        value: Value::Integer(499),
    });
    let (docs, stats) = db.run_query_with_stats(&selective, None).unwrap();
    assert_eq!(docs.len(), 1);
    assert_eq!(stats.scanned, 500);
    assert_eq!(stats.matched, 1);
    assert_eq!(stats.cloned_documents, 1);

    // Without a limit the caller asked for the whole result, so every match is returned.
    let (docs, stats) = db.run_query_with_stats(&base, None).unwrap();
    assert_eq!(docs.len(), 500);
    assert_eq!(stats.cloned_documents, 500);
}

// ---------------------------------------------------------------------------------------
// Aggregations (FS-AGG-PERF-*)
// ---------------------------------------------------------------------------------------

/// The materializing reference: aggregate over the documents the reference executor
/// returns, with the documented numeric semantics.
#[allow(clippy::cast_precision_loss)]
fn reference_aggregate(selected: &[Document], aggregation: &Aggregation) -> Value {
    let numeric = |field: &FieldPath| -> (f64, i64, bool, u64) {
        let mut as_double = 0.0f64;
        let mut as_integer = 0i64;
        let mut any_double = false;
        let mut contributors = 0u64;
        for d in selected {
            match get_field(&d.fields, field) {
                Some(Value::Integer(i)) => {
                    as_integer = as_integer.saturating_add(*i);
                    as_double += *i as f64;
                    contributors += 1;
                }
                Some(Value::Double(x)) => {
                    any_double = true;
                    as_double += x;
                    contributors += 1;
                }
                _ => {}
            }
        }
        (as_double, as_integer, any_double, contributors)
    };
    match aggregation {
        Aggregation::Count { up_to } => {
            let n = u64::try_from(selected.len()).unwrap();
            Value::Integer(i64::try_from(up_to.map_or(n, |cap| n.min(cap))).unwrap())
        }
        Aggregation::Sum(field) => {
            let (as_double, as_integer, any_double, _) = numeric(field);
            if any_double {
                Value::Double(as_double)
            } else {
                Value::Integer(as_integer)
            }
        }
        Aggregation::Avg(field) => {
            let (as_double, as_integer, any_double, contributors) = numeric(field);
            if contributors == 0 {
                Value::Null
            } else if any_double {
                Value::Double(as_double / contributors as f64)
            } else {
                Value::Double(as_integer as f64 / contributors as f64)
            }
        }
    }
}

/// FS-AGG-PERF-03 / FS-AGG-PERF-04: the streaming aggregations agree with the materializing
/// reference over the same generated queries -- filters, ordering, cursors, offset, limit,
/// projection, missing fields, mixed integer / double contributors, NaN, empty results and
/// `count.up_to` -- and never clone a document.
#[test]
fn streaming_aggregations_agree_with_the_materializing_reference() {
    let aggregations = [
        Aggregation::Count { up_to: None },
        Aggregation::Count { up_to: Some(3) },
        Aggregation::Count { up_to: Some(0) },
        Aggregation::Sum(fp("a")),
        Aggregation::Avg(fp("a")),
        Aggregation::Sum(fp("m.k")),
        Aggregation::Avg(fp("m.k")),
        Aggregation::Sum(fp("missing")),
        Aggregation::Avg(fp("missing")),
    ];
    for seed in 0..12u64 {
        let mut g = Gen::new(0xa66_0000 + seed);
        let (db, docs) = corpus(&mut g);
        for case in 0..120u32 {
            let query = g.query(&docs);
            let (got, stats) = db
                .run_aggregation_with_stats(&query, &aggregations, None)
                .unwrap();
            // An aggregation reads the stored fields: a projection selects what a result
            // returns and takes nothing away from what `sum` / `avg` see.
            let mut unprojected = query.clone();
            unprojected.projection = None;
            let selected = reference_run(&docs, &unprojected);
            let want: Vec<Value> = aggregations
                .iter()
                .map(|a| reference_aggregate(&selected, a))
                .collect();
            assert_eq!(
                format!("{got:#?}"),
                format!("{want:#?}"),
                "seed {seed} case {case}: streaming and reference aggregations differ for {query:?}"
            );
            assert_eq!(stats.cloned_documents, 0, "seed {seed} case {case}");
            if query.limit.is_none() && query.offset == 0 {
                assert_eq!(
                    stats.peak_candidates, 0,
                    "seed {seed} case {case}: an unbounded aggregation retains no candidate"
                );
            } else if let Some(limit) = query.limit {
                assert!(stats.peak_candidates <= u64::from(query.offset) + u64::from(limit));
            }
        }
    }
}

/// FS-AGG-PERF-01 / FS-AGG-PERF-02 / FS-AGG-PERF-05: a count, a sum and an average over 500
/// documents carrying a 4 KiB payload each clone nothing and, without offset or limit,
/// retain no candidate. The counters are the evidence: the retained payload of a scalar
/// aggregation is zero documents whatever the size of the matched set. Elapsed time is
/// printed for the record (`cargo nextest run ... --no-capture`), never asserted.
#[test]
fn scalar_aggregations_retain_no_document_payload() {
    let db = large_collection(500);
    let base = Query::new(QueryScope {
        parent: None,
        collection_id: collection("items"),
        all_descendants: false,
    });
    let aggregations = [
        Aggregation::Count { up_to: None },
        Aggregation::Sum(fp("n")),
        Aggregation::Avg(fp("n")),
    ];

    let started = std::time::Instant::now();
    let (values, stats) = db
        .run_aggregation_with_stats(&base, &aggregations, None)
        .unwrap();
    let elapsed = started.elapsed();
    assert_eq!(values[0], Value::Integer(500));
    assert_eq!(values[1], Value::Integer((0..500).sum()));
    assert_eq!(values[2], Value::Double(249.5));
    assert_eq!(stats.scanned, 500);
    assert_eq!(stats.matched, 500);
    assert_eq!(stats.cloned_documents, 0, "no document is copied");
    assert_eq!(stats.peak_candidates, 0, "no candidate is retained");
    println!(
        "aggregation over 500 x 4 KiB documents: cloned={} peak_candidates={} elapsed={elapsed:?}",
        stats.cloned_documents, stats.peak_candidates
    );

    // With a limit the selection needs its bounded heap of borrowed rows, and still no copy.
    let mut top = base.clone();
    top.limit = Some(10);
    top.offset = 5;
    let (values, stats) = db
        .run_aggregation_with_stats(&top, &aggregations, None)
        .unwrap();
    assert_eq!(values[0], Value::Integer(10));
    assert_eq!(stats.cloned_documents, 0);
    assert_eq!(stats.peak_candidates, 15);

    // `up_to` caps the count and nothing else.
    let (values, stats) = db
        .run_aggregation_with_stats(&base, &[Aggregation::Count { up_to: Some(7) }], None)
        .unwrap();
    assert_eq!(values, vec![Value::Integer(7)]);
    assert_eq!(stats.cloned_documents, 0);

    // The ordered path used by `run_query` is unchanged: a full result still clones every row.
    let (docs, stats) = db.run_query_with_stats(&base, None).unwrap();
    assert_eq!(docs.len(), 500);
    assert_eq!(stats.cloned_documents, 500);
}
