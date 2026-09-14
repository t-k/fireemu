//! Explain accounting for unconstrained collection name-index scans.

use std::collections::BTreeMap;
use std::time::Duration;

use fireemu_core_firestore::query::{Direction, Query, QueryScope};
use fireemu_core_firestore::store::Aggregation;
use fireemu_proto_firestore::google::firestore::v1 as pb;
use prost_types::{value::Kind, Struct, Value};

pub(crate) struct ExplainExecution {
    pub results_returned: i64,
    /// Selected index entries, including rows consumed by an offset.
    pub entries: u64,
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

pub(crate) fn explain_metrics(
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
    // Physical composite/filter plans and their billing are not inferred from a local full scan.
    let modeled = (!aggregation || count_cap.is_some())
        && matches!(query.scope, QueryScope::Collection { .. })
        && query.filter.is_none()
        && query.find_nearest.is_none()
        && query.start_at.is_none()
        && query.end_at.is_none()
        && order.len() == 1
        && order[0].field.is_document_name();
    let indexes_used = if modeled && (aggregation || query.limit != Some(0)) {
        let direction = match order[0].direction {
            Direction::Ascending => "ASC",
            Direction::Descending => "DESC",
        };
        vec![object([
            ("properties", string(format!("(__name__ {direction})"))),
            ("query_scope", string("Collection")),
        ])]
    } else {
        Vec::new()
    };
    pb::ExplainMetrics {
        plan_summary: Some(pb::PlanSummary { indexes_used }),
        execution_stats: execution.map(|execution| {
            // COUNT stops after its cap, after consuming any offset. Other aggregate
            // operators need different index fields and retain the unmodeled fallback.
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
                execution_duration: Some(prost_types::Duration {
                    seconds: i64::try_from(execution.duration.as_secs()).unwrap_or(i64::MAX),
                    nanos: i32::try_from(execution.duration.subsec_nanos()).unwrap_or(0),
                }),
                debug_stats: modeled.then(|| {
                    object([
                        // An empty count still probes its index boundary; a zero-limit query does not.
                        (
                            "index_entries_scanned",
                            string(
                                (if aggregation { entries.max(1) } else { entries }).to_string(),
                            ),
                        ),
                        ("documents_scanned", string(documents.to_string())),
                        (
                            "billing_details",
                            Value {
                                kind: Some(Kind::StructValue(object([
                                    (
                                        "index_entries_billable",
                                        string(billable_entries.to_string()),
                                    ),
                                    ("documents_billable", string(documents.to_string())),
                                    ("min_query_cost", string(u8::from(reads == 0).to_string())),
                                    ("small_ops", string("0")),
                                ]))),
                            },
                        ),
                    ])
                }),
            }
        }),
    }
}
