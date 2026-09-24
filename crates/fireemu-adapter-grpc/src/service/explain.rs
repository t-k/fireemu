//! Explain: the plan summary (the index each DNF disjunct scans) and the execution statistics
//! production reports for it (FS-QUERY-INDEX explain rows, recorded 2026-09-24).

use std::collections::{BTreeMap, HashMap};
use std::time::Duration;

use fireemu_core_firestore::field_path::FieldPath;
use fireemu_core_firestore::index::{
    IndexDefinition, IndexFieldMode, IndexQueryScope, PlannedScan,
};
use fireemu_core_firestore::path::DocumentPath;
use fireemu_core_firestore::query::{Direction, FieldOp, FilterExpr, Query, QueryScope, UnaryOp};
use fireemu_core_firestore::store::{
    get_field, Aggregation, CommitVersion, FirestoreError, FirestoreState,
};
use fireemu_core_firestore::value::Value as FsValue;
use fireemu_proto_firestore::google::firestore::v1 as pb;
use prost_types::{value::Kind, Struct, Value};

pub(crate) struct ExplainExecution {
    pub results_returned: i64,
    /// Documents read, including rows consumed by an offset.
    pub entries: u64,
    /// Index entries the plan's scans read ([`index_entries`]); `None` without a plan.
    pub index_entries: Option<u64>,
    pub duration: Duration,
}

fn string(value: impl Into<String>) -> Value {
    Value {
        kind: Some(Kind::StringValue(value.into())),
    }
}

fn object(fields: impl IntoIterator<Item = (&'static str, Value)>) -> Struct {
    Struct {
        fields: fields
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect::<BTreeMap<_, _>>(),
    }
}

const fn direction_word(direction: Direction) -> &'static str {
    match direction {
        Direction::Ascending => "ASC",
        Direction::Descending => "DESC",
    }
}

/// An index as production's plan summary prints it: `(g ASC, n ASC, __name__ ASC)`,
/// `(tags ARRAY_CONTAINS, __name__ ASC)`, `(color ASC, __name__ ASC, emb VECTOR<3>)`. An
/// index without an explicit `__name__` ends with it in the direction of its last ordered
/// field; in a vector index it comes before the vector.
fn index_properties(index: &IndexDefinition) -> String {
    let mut parts = Vec::new();
    let mut vector = None;
    let mut last_ordered = Direction::Ascending;
    let mut has_name = false;
    for field in &index.fields {
        let path = field.path.canonical();
        match field.mode {
            IndexFieldMode::Ascending => {
                last_ordered = Direction::Ascending;
                parts.push(format!("{path} ASC"));
            }
            IndexFieldMode::Descending => {
                last_ordered = Direction::Descending;
                parts.push(format!("{path} DESC"));
            }
            IndexFieldMode::Contains => parts.push(format!("{path} ARRAY_CONTAINS")),
            IndexFieldMode::Vector { dimension } => {
                vector = Some(format!("{path} VECTOR<{dimension}>"));
            }
        }
        has_name |= field.path.is_document_name();
    }
    if !has_name {
        let direction = if vector.is_some() {
            Direction::Ascending
        } else {
            last_ordered
        };
        parts.push(format!("__name__ {}", direction_word(direction)));
    }
    parts.extend(vector);
    format!("({})", parts.join(", "))
}

fn index_used(index: &IndexDefinition) -> Struct {
    object([
        ("properties", string(index_properties(index))),
        (
            "query_scope",
            string(match index.query_scope {
                IndexQueryScope::Collection => "Collection",
                IndexQueryScope::CollectionGroup => "Collection group",
            }),
        ),
    ])
}

/// At most this many plan entries are reported. Production plans at most 30 disjunctions and
/// refuses a `not-in` of more than ten values, so a query it serves never comes near; a query
/// only the emulator profile or the Enterprise edition serves cannot make the plan grow with
/// its request (safety review M2).
const MAX_PLAN_ENTRIES: usize = 1024;

/// How many index scans one DNF disjunct becomes: `!=` scans the two ranges around its value
/// (FS-QUERY-INDEX explain not-equal) and `not-in` the ranges between its values. (`in` and
/// `array-contains-any` are already one disjunct per value.)
fn scan_count(disjunct: &[FilterExpr]) -> usize {
    disjunct
        .iter()
        .map(|filter| match filter {
            FilterExpr::Field {
                op: FieldOp::NotEqual,
                ..
            } => 2,
            FilterExpr::Field {
                op: FieldOp::NotIn,
                value: FsValue::Array(values),
                ..
            } => values.len().saturating_add(1),
            _ => 1,
        })
        .fold(1, usize::saturating_mul)
}

/// The plan summary's `indexesUsed`: per disjunct, per scan, the index (or each merge member
/// in join order), up to [`MAX_PLAN_ENTRIES`].
fn indexes_used(query: &Query, scans: &[PlannedScan]) -> Vec<Struct> {
    let mut out = Vec::new();
    for (disjunct, scan) in query.dnf().iter().zip(scans) {
        for _ in 0..scan_count(disjunct) {
            if out.len() >= MAX_PLAN_ENTRIES {
                return out;
            }
            match scan {
                PlannedScan::Index(index) => out.push(index_used(index)),
                PlannedScan::Merge(members) => out.extend(
                    members
                        .iter()
                        .take(MAX_PLAN_ENTRIES - out.len())
                        .map(index_used),
                ),
            }
        }
    }
    out
}

/// The query one disjunct's scan reads: its filters, the query's order and cursors, and no
/// limit, offset, nearest-neighbour stage or projection (the vector count reads the field).
fn disjunct_query(query: &Query, filters: Vec<FilterExpr>) -> Query {
    let mut sub = query.clone();
    sub.filter = match filters.len() {
        0 => None,
        1 => filters.into_iter().next(),
        _ => Some(FilterExpr::And(filters)),
    };
    sub.limit = None;
    sub.offset = 0;
    sub.find_nearest = None;
    sub.projection = None;
    sub
}

/// The index entries a zig-zag join of `members` reads (each list holds the members' entries
/// as positions in the shared order): each member seeks to the current target, one entry per
/// seek, and after a match every member steps once. Production's counts for two and three
/// members fit this walk (FS-QUERY-INDEX explain/merge-order).
fn zig_zag_entries(members: &[Vec<usize>], matches_needed: Option<u64>) -> u64 {
    let mut cursor = vec![0usize; members.len()];
    let mut current: Vec<Option<usize>> = vec![None; members.len()];
    let mut target = 0usize;
    let mut entries = 0u64;
    let mut matches = 0u64;
    loop {
        let mut aligned = true;
        for (i, list) in members.iter().enumerate() {
            if current[i].is_none_or(|key| key < target) {
                let Some(offset) = list[cursor[i]..].iter().position(|&key| key >= target) else {
                    return entries;
                };
                cursor[i] += offset;
                current[i] = Some(list[cursor[i]]);
                entries += 1;
            }
            let key = current[i].unwrap_or(target);
            if key > target {
                target = key;
                aligned = false;
            }
        }
        if !aligned || current.iter().any(|key| *key != Some(target)) {
            continue;
        }
        matches += 1;
        if matches_needed.is_some_and(|needed| matches >= needed) {
            return entries;
        }
        for (i, list) in members.iter().enumerate() {
            cursor[i] += 1;
            let Some(&key) = list.get(cursor[i]) else {
                return entries;
            };
            current[i] = Some(key);
            entries += 1;
        }
        target = current.iter().flatten().copied().max().unwrap_or(target);
    }
}

/// Whether `document` has an embedding of `dimension` components at `field`, and so an entry
/// in the vector index.
fn has_vector(fields: &BTreeMap<String, FsValue>, field: &FieldPath, dimension: u32) -> bool {
    matches!(
        get_field(fields, field),
        Some(FsValue::Vector(components)) if u32::try_from(components.len()) == Ok(dimension)
    )
}

/// Whether `filter` is one a merge member serves with its prefix: an equality, `IS_NULL`,
/// `IS_NAN`, `array-contains` or a one-value `array-contains-any` (the atoms the planner makes
/// equality or contains fields of), on a field other than `__name__`.
fn is_member_atom(filter: &FilterExpr) -> Option<&FieldPath> {
    match filter {
        FilterExpr::Field {
            field,
            op: FieldOp::Equal | FieldOp::ArrayContains | FieldOp::ArrayContainsAny,
            ..
        }
        | FilterExpr::Unary {
            field,
            op: UnaryOp::IsNull | UnaryOp::IsNan,
        } if !field.is_document_name() => Some(field),
        _ => None,
    }
}

/// The filters a merge member's entries satisfy: the member atoms on the fields of its prefix,
/// and every other filter of the disjunct (ranges and inequalities, which every member shares
/// with the order suffix they imply). `member` `None` is the shared order alone.
fn member_filters(member: Option<&IndexDefinition>, disjunct: &[FilterExpr]) -> Vec<FilterExpr> {
    disjunct
        .iter()
        .filter(|filter| match is_member_atom(filter) {
            Some(field) => {
                member.is_some_and(|member| member.fields.iter().any(|f| &f.path == field))
            }
            None => true,
        })
        .cloned()
        .collect()
}

/// The index entries one disjunct's scan reads when it runs to the end, or until
/// `matches_needed` results for a merge.
fn disjunct_entries(
    db: &FirestoreState,
    version: Option<CommitVersion>,
    query: &Query,
    disjunct: &[FilterExpr],
    scan: &PlannedScan,
    matches_needed: Option<u64>,
) -> Result<u64, FirestoreError> {
    match scan {
        PlannedScan::Index(index) => {
            let sub = disjunct_query(query, disjunct.to_vec());
            let vector = index.fields.iter().find_map(|field| match field.mode {
                IndexFieldMode::Vector { dimension } => Some((&field.path, dimension)),
                _ => None,
            });
            match vector {
                Some((field, dimension)) => Ok(db
                    .run_query(&sub, version)?
                    .iter()
                    .filter(|document| has_vector(&document.fields, field, dimension))
                    .count() as u64),
                None => Ok(db.run_query_paths_with_stats(&sub, version)?.0.len() as u64),
            }
        }
        PlannedScan::Merge(members) => {
            let everything = disjunct_query(query, member_filters(None, disjunct));
            let (order, _) = db.run_query_paths_with_stats(&everything, version)?;
            let position: HashMap<&DocumentPath, usize> = order
                .iter()
                .enumerate()
                .map(|(i, path)| (path, i))
                .collect();
            let mut lists = Vec::with_capacity(members.len());
            for member in members {
                let sub = disjunct_query(query, member_filters(Some(member), disjunct));
                let (paths, _) = db.run_query_paths_with_stats(&sub, version)?;
                lists.push(
                    paths
                        .iter()
                        .filter_map(|path| position.get(path).copied())
                        .collect::<Vec<_>>(),
                );
            }
            Ok(zig_zag_entries(&lists, matches_needed))
        }
    }
}

/// The index entries the plan's scans read. A query with a limit stops once its offset and
/// limit are filled and reads one entry past them when there is one (production: `limit 3`
/// over 10 entries reads 4); an aggregation stops at its cap without reading past it.
pub(crate) fn index_entries(
    db: &FirestoreState,
    version: Option<CommitVersion>,
    query: &Query,
    aggregations: Option<&[Aggregation]>,
    scans: &[PlannedScan],
) -> Result<u64, FirestoreError> {
    let limit = query
        .limit
        .map(|limit| u64::from(limit) + u64::from(query.offset));
    let cap = match aggregations {
        Some(aggregations) => {
            let count_cap = match aggregations {
                [Aggregation::Count { up_to: Some(up_to) }] => {
                    Some(up_to.saturating_add(u64::from(query.offset)))
                }
                _ => None,
            };
            match (limit, count_cap) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (a, b) => a.or(b),
            }
        }
        None => limit,
    };
    let peek = u64::from(aggregations.is_none());
    let mut total = 0u64;
    for (disjunct, scan) in query.dnf().iter().zip(scans) {
        let entries = disjunct_entries(db, version, query, disjunct, scan, cap)?;
        total = total.saturating_add(match (cap, scan) {
            (Some(cap), PlannedScan::Index(_)) if entries > cap => cap + peek,
            _ => entries,
        });
    }
    Ok(total)
}

fn duration(elapsed: Duration) -> prost_types::Duration {
    prost_types::Duration {
        seconds: i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX),
        nanos: i32::try_from(elapsed.subsec_nanos()).unwrap_or(0),
    }
}

fn debug_stats(
    index_entries_scanned: u64,
    documents: u64,
    index_entries_billable: u64,
    knn_entries: Option<u64>,
    min_query_cost: bool,
) -> Struct {
    let mut billing = vec![
        (
            "index_entries_billable",
            string(index_entries_billable.to_string()),
        ),
        ("documents_billable", string(documents.to_string())),
        (
            "min_query_cost",
            string(u8::from(min_query_cost).to_string()),
        ),
        ("small_ops", string("0")),
    ];
    if let Some(knn) = knn_entries {
        billing.push(("knn_vector_index_entries_billable", string(knn.to_string())));
    }
    object([
        (
            "index_entries_scanned",
            string(index_entries_scanned.to_string()),
        ),
        ("documents_scanned", string(documents.to_string())),
        (
            "billing_details",
            Value {
                kind: Some(Kind::StructValue(object(billing))),
            },
        ),
    ])
}

pub(crate) fn explain_metrics(
    query: &Query,
    aggregations: Option<&[Aggregation]>,
    scans: Option<&[PlannedScan]>,
    execution: Option<ExplainExecution>,
) -> pb::ExplainMetrics {
    match scans {
        Some(scans) => planned_metrics(query, aggregations, scans, execution),
        None => unplanned_metrics(query, aggregations, execution),
    }
}

/// Metrics from the index plan: production's accounting for queries, aggregations and
/// nearest-neighbour searches.
fn planned_metrics(
    query: &Query,
    aggregations: Option<&[Aggregation]>,
    scans: &[PlannedScan],
    execution: Option<ExplainExecution>,
) -> pb::ExplainMetrics {
    let aggregation = aggregations.is_some();
    // A query with limit 0 reads nothing and names no index; an aggregation over one still
    // plans its scan.
    let empty = query.limit == Some(0);
    let indexes_used = if empty && !aggregation {
        Vec::new()
    } else {
        indexes_used(query, scans)
    };
    let execution_stats = execution.map(|execution| {
        let entries = execution.index_entries.unwrap_or(0);
        let (scanned, documents, billable, knn, reads) = if aggregation {
            // An aggregation bills index entries, one read per thousand; over limit 0 it
            // still probes its index boundary.
            let scanned = if empty { 1 } else { entries };
            let billable = if empty { 0 } else { entries };
            (scanned, 0, billable, None, billable.div_ceil(1000))
        } else if query.find_nearest.is_some() {
            // A nearest-neighbour search bills its vector entries, one read per hundred.
            let documents = u64::try_from(execution.results_returned).unwrap_or(0);
            (
                entries,
                documents,
                0,
                Some(entries),
                documents + entries.div_ceil(100),
            )
        } else if empty {
            (0, 0, 0, None, 0)
        } else {
            (entries, execution.entries, 0, None, execution.entries)
        };
        pb::ExecutionStats {
            results_returned: execution.results_returned,
            read_operations: i64::try_from(reads.max(1)).unwrap_or(i64::MAX),
            execution_duration: Some(duration(execution.duration)),
            debug_stats: Some(debug_stats(scanned, documents, billable, knn, reads == 0)),
        }
    });
    pb::ExplainMetrics {
        plan_summary: Some(pb::PlanSummary { indexes_used }),
        execution_stats,
    }
}

/// Metrics without an index plan (a kindless scan, an Enterprise full scan): only the
/// unconstrained collection name scan is modeled.
fn unplanned_metrics(
    query: &Query,
    aggregations: Option<&[Aggregation]>,
    execution: Option<ExplainExecution>,
) -> pb::ExplainMetrics {
    let order = query.effective_order_by();
    let aggregation = aggregations.is_some();
    let count_cap = match aggregations {
        Some([Aggregation::Count { up_to }]) => Some(*up_to),
        _ => None,
    };
    let modeled = (!aggregation || count_cap.is_some())
        && matches!(query.scope, QueryScope::Collection { .. })
        && query.filter.is_none()
        && query.find_nearest.is_none()
        && query.start_at.is_none()
        && query.end_at.is_none()
        && order.len() == 1
        && order[0].field.is_document_name();
    let indexes_used = if modeled && (aggregation || query.limit != Some(0)) {
        vec![object([
            (
                "properties",
                string(format!("(__name__ {})", direction_word(order[0].direction))),
            ),
            ("query_scope", string("Collection")),
        ])]
    } else {
        Vec::new()
    };
    pb::ExplainMetrics {
        plan_summary: Some(pb::PlanSummary { indexes_used }),
        execution_stats: execution.map(|execution| {
            // COUNT stops after its cap, after consuming any offset.
            let entries = count_cap.flatten().map_or(execution.entries, |cap| {
                execution
                    .entries
                    .min(cap.saturating_add(u64::from(query.offset)))
            });
            let documents = if aggregation { 0 } else { entries };
            let billable_entries = if aggregation { entries } else { 0 };
            let reads = if aggregation {
                entries.div_ceil(1000)
            } else {
                entries
            };
            pb::ExecutionStats {
                results_returned: execution.results_returned,
                read_operations: if modeled {
                    i64::try_from(reads.max(1)).unwrap_or(i64::MAX)
                } else {
                    0
                },
                execution_duration: Some(duration(execution.duration)),
                // An empty count still probes its index boundary; a zero-limit query does not.
                debug_stats: modeled.then(|| {
                    debug_stats(
                        if aggregation { entries.max(1) } else { entries },
                        documents,
                        billable_entries,
                        None,
                        reads == 0,
                    )
                }),
            }
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fireemu_core_firestore::index::IndexField;
    use fireemu_core_types::ids::CollectionId;

    fn index(scope: IndexQueryScope, fields: &[(&str, IndexFieldMode)]) -> IndexDefinition {
        IndexDefinition {
            collection_group: CollectionId::try_new("qn").unwrap(),
            query_scope: scope,
            fields: fields
                .iter()
                .map(|(path, mode)| IndexField {
                    path: FieldPath::parse(path).unwrap(),
                    mode: *mode,
                })
                .collect(),
        }
    }

    #[test]
    fn indexes_print_as_production_prints_them() {
        use IndexFieldMode::{Ascending as A, Contains, Descending as D};
        let collection = IndexQueryScope::Collection;
        let cases = [
            (index(collection, &[("__name__", A)]), "(__name__ ASC)"),
            (
                index(collection, &[("g", A), ("__name__", A)]),
                "(g ASC, __name__ ASC)",
            ),
            (
                index(collection, &[("a", D), ("__name__", D)]),
                "(a DESC, __name__ DESC)",
            ),
            (
                index(collection, &[("g", A), ("n", A)]),
                "(g ASC, n ASC, __name__ ASC)",
            ),
            (
                index(collection, &[("g", A), ("n", D)]),
                "(g ASC, n DESC, __name__ DESC)",
            ),
            (
                index(collection, &[("n", A), ("__name__", D)]),
                "(n ASC, __name__ DESC)",
            ),
            (
                index(collection, &[("tags", Contains), ("__name__", A)]),
                "(tags ARRAY_CONTAINS, __name__ ASC)",
            ),
            (
                index(
                    collection,
                    &[("emb", IndexFieldMode::Vector { dimension: 3 })],
                ),
                "(__name__ ASC, emb VECTOR<3>)",
            ),
            (
                index(
                    collection,
                    &[
                        ("color", A),
                        ("emb", IndexFieldMode::Vector { dimension: 3 }),
                    ],
                ),
                "(color ASC, __name__ ASC, emb VECTOR<3>)",
            ),
        ];
        for (index, expected) in cases {
            assert_eq!(index_properties(&index), expected);
        }
        let group = index_used(&index(IndexQueryScope::CollectionGroup, &[("a", A)]));
        assert_eq!(
            group.fields["query_scope"].kind,
            Some(Kind::StringValue("Collection group".to_owned()))
        );
    }

    #[test]
    fn not_equal_and_not_in_scan_once_per_range_and_the_plan_is_bounded() {
        let field = |op, value| FilterExpr::Field {
            field: FieldPath::parse("n").unwrap(),
            op,
            value,
        };
        let values = |count: i64| FsValue::Array((0..count).map(FsValue::Integer).collect());
        assert_eq!(scan_count(&[]), 1);
        assert_eq!(scan_count(&[field(FieldOp::Equal, FsValue::Integer(1))]), 1);
        assert_eq!(
            scan_count(&[field(FieldOp::NotEqual, FsValue::Integer(4))]),
            2
        );
        assert_eq!(scan_count(&[field(FieldOp::NotIn, values(3))]), 4);
        // `in` is one disjunct per value already.
        let collection = || {
            Query::new(QueryScope::collection(
                None,
                CollectionId::try_new("qn").unwrap(),
            ))
        };
        let scan = || {
            PlannedScan::Index(index(
                IndexQueryScope::Collection,
                &[
                    ("n", IndexFieldMode::Ascending),
                    ("__name__", IndexFieldMode::Ascending),
                ],
            ))
        };
        let in_query = collection()
            .with_filter(field(FieldOp::In, values(3)))
            .canonicalize()
            .unwrap();
        assert_eq!(in_query.dnf().len(), 3);
        assert_eq!(indexes_used(&in_query, &[scan(), scan(), scan()]).len(), 3);
        // A not-in only the emulator profile serves cannot grow the plan with the request.
        let huge = collection().with_filter(field(FieldOp::NotIn, values(100_000)));
        assert_eq!(indexes_used(&huge, &[scan()]).len(), MAX_PLAN_ENTRIES);
    }

    /// A merge member's entries are the documents its atoms select, `IS_NULL` included, and the
    /// disjunct's range stays on every member (core review should-fix 1).
    #[test]
    fn merge_members_read_the_entries_their_atoms_select() {
        use fireemu_core_firestore::path::DocumentPath;
        use fireemu_core_firestore::store::{Write, WriteOp};
        use fireemu_core_types::ids::{DatabaseId, ProjectId};
        let mut db = FirestoreState::new();
        let project = ProjectId::try_new("p").unwrap();
        let write = |id: &str, fields: &[(&str, FsValue)]| Write {
            op: WriteOp::Set {
                path: DocumentPath::parse(&project, &DatabaseId::default_database(), id).unwrap(),
                fields: fields
                    .iter()
                    .map(|(k, v)| ((*k).to_owned(), v.clone()))
                    .collect(),
                update_mask: None,
            },
            precondition: None,
            transforms: vec![],
        };
        db.commit(
            &[
                write(
                    "qx/x1",
                    &[
                        ("a", FsValue::Integer(1)),
                        ("b", FsValue::Null),
                        ("c", FsValue::Integer(5)),
                    ],
                ),
                write(
                    "qx/x2",
                    &[
                        ("a", FsValue::Integer(1)),
                        ("b", FsValue::Integer(2)),
                        ("c", FsValue::Integer(1)),
                    ],
                ),
                write(
                    "qx/x3",
                    &[
                        ("a", FsValue::Integer(1)),
                        ("b", FsValue::Integer(3)),
                        ("c", FsValue::Integer(9)),
                    ],
                ),
            ],
            None,
            fireemu_core_types::time::LogicalInstant::from_unix_seconds(1_788_000_000),
        )
        .unwrap();
        let auto = |path: &str| {
            index(
                IndexQueryScope::Collection,
                &[
                    (path, IndexFieldMode::Ascending),
                    ("__name__", IndexFieldMode::Ascending),
                ],
            )
        };
        let query = |filters: Vec<FilterExpr>| {
            Query::new(QueryScope::collection(
                None,
                CollectionId::try_new("qx").unwrap(),
            ))
            .with_filter(FilterExpr::And(filters))
            .canonicalize()
            .unwrap()
        };
        let a_is_1 = FilterExpr::Field {
            field: FieldPath::parse("a").unwrap(),
            op: FieldOp::Equal,
            value: FsValue::Integer(1),
        };
        let b_is_null = FilterExpr::Unary {
            field: FieldPath::parse("b").unwrap(),
            op: UnaryOp::IsNull,
        };
        // a == 1 selects [x1, x2, x3], b IS NULL selects [x1]: a walk of three entries.
        let null_merge = query(vec![a_is_1.clone(), b_is_null.clone()]);
        let merge = [PlannedScan::Merge(vec![auto("a"), auto("b")])];
        assert_eq!(
            index_entries(&db, None, &null_merge, None, &merge).unwrap(),
            3
        );
        // With c > 3 on every member only x1 and x3 are entries of a, x1 of b.
        let ranged = query(vec![
            a_is_1,
            b_is_null,
            FilterExpr::Field {
                field: FieldPath::parse("c").unwrap(),
                op: FieldOp::GreaterThan,
                value: FsValue::Integer(3),
            },
        ]);
        assert_eq!(index_entries(&db, None, &ranged, None, &merge).unwrap(), 3);
    }

    /// Production's index entry counts for the merges of FS-QUERY-INDEX explain (entries as
    /// positions in the order the members share).
    #[test]
    fn zig_zag_joins_read_the_entries_production_counts() {
        // merge-with-order: `b == 1` over c = [1, 4], `a == 1` over c = [1, 3, 5].
        assert_eq!(zig_zag_entries(&[vec![1, 4], vec![1, 3, 5]], None), 5);
        // larger-later-field: `b == 1` gains c = 10..13.
        assert_eq!(
            zig_zag_entries(&[vec![1, 4, 10, 11, 12, 13], vec![1, 3, 5]], None),
            6
        );
        // larger-earlier-field: `b == 2` over [2, 5], `a == 0` over [0, 2, 4, 10..13].
        assert_eq!(
            zig_zag_entries(&[vec![2, 5], vec![0, 2, 4, 10, 11, 12, 13]], None),
            5
        );
        // automatic members: one entry each, one match.
        assert_eq!(zig_zag_entries(&[vec![1], vec![1]], None), 2);
        assert_eq!(zig_zag_entries(&[vec![1], vec![1], vec![1]], None), 3);
        // Nothing in common, and an empty member.
        assert_eq!(zig_zag_entries(&[vec![1, 3], vec![2, 4]], None), 4);
        assert_eq!(zig_zag_entries(&[vec![], vec![1]], None), 0);
        // A limit stops at its last match.
        assert_eq!(zig_zag_entries(&[vec![1, 2, 3], vec![1, 2, 3]], Some(1)), 2);
        assert_eq!(zig_zag_entries(&[vec![1, 2, 3], vec![1, 2, 3]], None), 6);
    }
}
