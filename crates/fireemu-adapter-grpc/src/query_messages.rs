//! Production's refusal texts for malformed queries (FS-QUERY-INDEX, recorded 2026-09-24 on
//! `fireemu-oracle-query/(default)`).
//!
//! Each function turns fireemu's structured error into the text production answers for the
//! same request, so the decoders keep their typed errors and only the wording lives here.

use fireemu_core_firestore::field_path::FieldPathError;
use fireemu_core_types::ids::IdSyntaxError;

use fireemu_core_types::codec::echo;

use crate::decode::{parse_parent, DecodeError, Parent};

/// Production's refusal of a `runQuery` without a query (REST and gRPC alike: the transcoder
/// forwards an absent oneof as absent). FS-QUERY-INDEX request-shape/rest#body-empty.
pub const RUN_QUERY_WITHOUT_QUERY: &str = "only structured queries are supported";
/// Production's refusal of a `runAggregationQuery` without an aggregation query
/// (request-shape/rest#aggregation-without-query).
pub const AGGREGATION_WITHOUT_QUERY: &str = "Only structured aggregation queries are supported.";
/// Production's refusal of a `partitionQuery` without a query
/// (partition-query/refusals#structured-query-missing).
pub const PARTITION_WITHOUT_QUERY: &str = "Query is required.";

/// The query of an aggregation: production aggregates an absent one as the empty query, every
/// document under the parent (request-shape/rest#aggregation-without-structured-query).
#[must_use]
pub fn aggregation_structured_query(
    aggregation: &fireemu_proto_firestore::google::firestore::v1::StructuredAggregationQuery,
) -> std::borrow::Cow<'_, fireemu_proto_firestore::google::firestore::v1::StructuredQuery> {
    use fireemu_proto_firestore::google::firestore::v1::structured_aggregation_query::QueryType;
    match &aggregation.query_type {
        Some(QueryType::StructuredQuery(query)) => std::borrow::Cow::Borrowed(query),
        None => std::borrow::Cow::Owned(
            fireemu_proto_firestore::google::firestore::v1::StructuredQuery::default(),
        ),
    }
}

/// The text production uses for an empty or absent property path.
pub const EMPTY_PROPERTY_PATH: &str = "Invalid empty property path string.";

/// Characters production refuses in an unquoted property path before matching it against the
/// path grammar (observed for `a[0]`, answered without the grammar; `~`, `*` and `/` get the
/// grammar text).
const FORBIDDEN_UNQUOTED: &[char] = &['['];

/// The refusal of a property path (a filter, order, projection or aggregation field) that
/// does not parse. `input` is the path as the request spelled it.
#[must_use]
pub fn property_path_error(input: &str, error: &FieldPathError) -> DecodeError {
    let message = match error {
        FieldPathError::Empty => EMPTY_PROPERTY_PATH.to_owned(),
        FieldPathError::ReservedSegment { index } => {
            let segment = segment_text(input, *index);
            format!("Invalid reserved name in field path {}", echo(segment))
        }
        FieldPathError::PathTooLong { .. } | FieldPathError::SegmentTooLong { .. } => {
            "property path is longer than 1500 bytes.".to_owned()
        }
        FieldPathError::UnquotedSpecialCharacter { offset }
            if input[*offset..]
                .chars()
                .next()
                .is_some_and(|c| FORBIDDEN_UNQUOTED.contains(&c)) =>
        {
            "Invalid property path".to_owned()
        }
        _ => format!(
            r#"Invalid property path "{}". Unquoted property paths must match regex ([a-zA-Z_][a-zA-Z_0-9]*), and quoted property paths must match regex (`(?:[^`\\]|(?:\\.))+`)"#,
            echo(input)
        ),
    };
    DecodeError::Refused(message)
}

/// The `index`-th dot-separated segment of an unquoted path, as the request spelled it.
fn segment_text(input: &str, index: usize) -> &str {
    input.split('.').nth(index).unwrap_or(input)
}

/// The refusal of a collection id in a query's `from` clause.
#[must_use]
pub fn collection_id_error(id: &str, error: &IdSyntaxError) -> DecodeError {
    let message = match error {
        IdSyntaxError::TooManyBytes { .. } => {
            "The query kind is longer than 1500 bytes.".to_owned()
        }
        IdSyntaxError::ReservedDunder | IdSyntaxError::DotSegment => {
            format!(
                "Collection id \"{}\" is invalid because it is reserved.",
                echo(id)
            )
        }
        IdSyntaxError::ContainsSlash => {
            format!(
                "Collection id \"{}\" is invalid because it contains \"/\".",
                echo(id)
            )
        }
        other => format!("Collection id \"{}\" is invalid: {other}", echo(id)),
    };
    DecodeError::Refused(message)
}

/// The refusal of a reference value, used as a document name, that names a collection.
#[must_use]
pub fn reference_is_not_a_document(name: &str) -> String {
    format!(
        "Document parent name \"{}\" lacks \"/\" at index {}.",
        echo(name),
        name.len()
    )
}

/// Parses the parent of a query (`runQuery`, `runAggregationQuery`, `partitionQuery`).
/// Production calls it a document parent name when its path does not end at a document.
pub fn parse_query_parent(parent: &str) -> Result<Parent, DecodeError> {
    parse_parent(parent).map_err(|error| match error {
        DecodeError::InvalidDocumentName(message)
            if message.starts_with("Document name ") && message.contains(" lacks \"/\" ") =>
        {
            DecodeError::InvalidDocumentName(message.replacen(
                "Document name ",
                "Document parent name ",
                1,
            ))
        }
        other => other,
    })
}

/// Production refuses a nearest-neighbour query that also carries a limit, an offset or a
/// cursor (FS-QUERY-INDEX vector/with-query-clauses). Checked on the request as the caller
/// sent it, because the gRPC service pages a query by adding a limit of its own. Only with
/// `production_refusals` (the strict profile); the emulator profile applies those stages
/// before the nearest-neighbour ranking, as fireemu did before.
#[allow(clippy::result_large_err)]
pub fn check_find_nearest_request(
    query: &fireemu_proto_firestore::google::firestore::v1::StructuredQuery,
    production_refusals: bool,
) -> Result<(), tonic::Status> {
    if !production_refusals || query.find_nearest.is_none() {
        return Ok(());
    }
    let refusal = if query.limit.is_some() {
        "A query limit cannot be used with FindNearest"
    } else if query.offset != 0 {
        "A query offset cannot be used with FindNearest"
    } else if query.start_at.is_some() || query.end_at.is_some() {
        "A cursor cannot be used with FindNearest"
    } else {
        return Ok(());
    };
    Err(tonic::Status::invalid_argument(refusal))
}

/// Decodes the aggregations of a `StructuredAggregationQuery` the way production does
/// (FS-QUERY-INDEX aggregation rows, recorded 2026-09-24): one to five aggregations, default
/// aliases `field_1`, `field_2`, ... numbered over the unnamed aggregations only, aliases held
/// to the property-name rules, and production's texts for every refusal.
///
/// Without `production_refusals` (the emulator profile) the aliases are what fireemu gave
/// before: a default alias numbered by position, and no property-name rule, so the profile adds
/// no rejection.
#[allow(clippy::result_large_err)]
pub fn decode_aggregations(
    saq: &fireemu_proto_firestore::google::firestore::v1::StructuredAggregationQuery,
    production_refusals: bool,
) -> Result<(Vec<String>, Vec<fireemu_core_firestore::store::Aggregation>), tonic::Status> {
    use fireemu_core_firestore::store::Aggregation;
    use fireemu_proto_firestore::google::firestore::v1::structured_aggregation_query::aggregation::Operator as O;
    const MAXIMUM: usize = 5;
    if saq.aggregations.is_empty() {
        return Err(tonic::Status::invalid_argument(
            "Aggregations can not be empty.",
        ));
    }
    if saq.aggregations.len() > MAXIMUM {
        return Err(crate::production_status::too_many_aggregations(
            saq.aggregations.len(),
        ));
    }
    let field = |reference: Option<
        &fireemu_proto_firestore::google::firestore::v1::structured_query::FieldReference,
    >| {
        let Some(reference) = reference else {
            return Err(tonic::Status::invalid_argument(EMPTY_PROPERTY_PATH));
        };
        fireemu_core_firestore::field_path::FieldPath::parse(&reference.field_path).map_err(
            |error| {
                tonic::Status::invalid_argument(
                    property_path_error(&reference.field_path, &error).to_string(),
                )
            },
        )
    };
    let mut aliases: Vec<String> = Vec::with_capacity(saq.aggregations.len());
    let mut aggregations = Vec::with_capacity(saq.aggregations.len());
    let mut unnamed = 0;
    for (position, a) in saq.aggregations.iter().enumerate() {
        let aggregation = match &a.operator {
            Some(O::Count(count)) => Aggregation::Count {
                up_to: match count.up_to {
                    None => None,
                    Some(n) if n >= 0 => Some(u64::try_from(n).unwrap_or(u64::MAX)),
                    Some(_) => {
                        return Err(tonic::Status::invalid_argument(
                            "The `up_to` value in a COUNT aggregation must be greater than or equal to zero.",
                        ))
                    }
                },
            },
            Some(O::Sum(sum)) => Aggregation::Sum(field(sum.field.as_ref())?),
            Some(O::Avg(avg)) => Aggregation::Avg(field(avg.field.as_ref())?),
            None => {
                return Err(tonic::Status::invalid_argument(
                    "Operator field in Aggregation is not set.",
                ))
            }
        };
        let alias = if a.alias.is_empty() {
            unnamed += 1;
            format!(
                "field_{}",
                if production_refusals {
                    unnamed
                } else {
                    position + 1
                }
            )
        } else if !production_refusals {
            a.alias.clone()
        } else {
            if a.alias.len() > 1500 {
                return Err(tonic::Status::invalid_argument(
                    "The property.name is longer than 1500 bytes.",
                ));
            }
            if a.alias.len() >= 4 && a.alias.starts_with("__") && a.alias.ends_with("__") {
                return Err(tonic::Status::invalid_argument(format!(
                    "The property.name \"{}\" is reserved.",
                    a.alias
                )));
            }
            a.alias.clone()
        };
        aliases.push(alias);
        aggregations.push(aggregation);
    }
    for (index, alias) in aliases.iter().enumerate() {
        if aliases[..index].contains(alias) {
            return Err(tonic::Status::invalid_argument(format!(
                "Aggregation aliases contain duplicate alias: {alias}."
            )));
        }
    }
    Ok((aliases, aggregations))
}

/// Production answers an aggregation whose every aggregation is a count capped at zero without
/// reading anything: zero, at the instant before the epoch (FS-QUERY-INDEX
/// aggregation/options#count-up-to-zero). `None` when the query must run (or is an Explain or a
/// read in a transaction or at a read time, which were not observed this way).
#[must_use]
pub fn zero_capped_count(
    aliases: &[String],
    aggregations: &[fireemu_core_firestore::store::Aggregation],
    excluded: bool,
) -> Option<fireemu_proto_firestore::google::firestore::v1::RunAggregationQueryResponse> {
    use fireemu_core_firestore::store::Aggregation;
    use fireemu_proto_firestore::google::firestore::v1 as pb;
    if excluded
        || !aggregations
            .iter()
            .all(|a| matches!(a, Aggregation::Count { up_to: Some(0) }))
    {
        return None;
    }
    Some(pb::RunAggregationQueryResponse {
        result: Some(pb::AggregationResult {
            aggregate_fields: aliases
                .iter()
                .map(|alias| {
                    (
                        alias.clone(),
                        pb::Value {
                            value_type: Some(pb::value::ValueType::IntegerValue(0)),
                        },
                    )
                })
                .collect(),
        }),
        read_time: Some(prost_types::Timestamp {
            seconds: -1,
            nanos: 999_999_000,
        }),
        ..Default::default()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(clippy::needless_pass_by_value)]
    fn text(error: DecodeError) -> String {
        error.to_string()
    }

    #[test]
    fn property_paths_are_refused_in_production_words() {
        let grammar = |p: &str| {
            format!(
                r#"Invalid property path "{p}". Unquoted property paths must match regex ([a-zA-Z_][a-zA-Z_0-9]*), and quoted property paths must match regex (`(?:[^`\\]|(?:\\.))+`)"#
            )
        };
        let cases = [
            ("", EMPTY_PROPERTY_PATH.to_owned()),
            ("a..b", grammar("a..b")),
            ("a.", grammar("a.")),
            ("`a", grammar("`a")),
            ("``", grammar("``")),
            (
                "__x__",
                "Invalid reserved name in field path __x__".to_owned(),
            ),
            (
                "a.__x__",
                "Invalid reserved name in field path __x__".to_owned(),
            ),
            ("a[0]", "Invalid property path".to_owned()),
        ];
        for (input, expected) in cases {
            let error = fireemu_core_firestore::field_path::FieldPath::parse(input).unwrap_err();
            assert_eq!(
                text(property_path_error(input, &error)),
                expected,
                "{input}"
            );
        }
    }

    #[test]
    fn collection_ids_are_refused_in_production_words() {
        let cases = [
            (
                "a/b",
                "Collection id \"a/b\" is invalid because it contains \"/\".",
            ),
            (
                "__x__",
                "Collection id \"__x__\" is invalid because it is reserved.",
            ),
            (
                ".",
                "Collection id \".\" is invalid because it is reserved.",
            ),
        ];
        for (id, expected) in cases {
            let error = fireemu_core_types::ids::CollectionId::try_new(id).unwrap_err();
            assert_eq!(text(collection_id_error(id, &error)), expected, "{id}");
        }
        let long = "q".repeat(1501);
        let error = fireemu_core_types::ids::CollectionId::try_new(long.as_str()).unwrap_err();
        assert_eq!(
            text(collection_id_error(&long, &error)),
            "The query kind is longer than 1500 bytes."
        );
    }

    #[test]
    fn a_query_parent_that_names_a_collection_is_a_document_parent_name() {
        let parent = "projects/p/databases/(default)/documents/qroot/r1/qg";
        assert_eq!(
            text(parse_query_parent(parent).unwrap_err()),
            format!(
                "Document parent name \"{parent}\" lacks \"/\" at index {}.",
                parent.len()
            )
        );
        assert_eq!(
            reference_is_not_a_document("projects/p/databases/(default)/documents/qn"),
            "Document parent name \"projects/p/databases/(default)/documents/qn\" lacks \"/\" at index 43."
        );
    }
}
