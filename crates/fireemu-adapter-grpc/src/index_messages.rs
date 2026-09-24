//! Production's missing-index refusals (FS-QUERY-INDEX, recorded 2026-09-24).
//!
//! Production names the index a query needs in one of three forms:
//! - a composite index: `The query requires an index. You can create it here: <console link
//!   with create_composite=<encoded Index>>`, followed by a pointer to the multiple-range-fields
//!   guide when the query has inequality filters on more than one field;
//! - a single-field index that is disabled (an exemption, or the collection-group scope that is
//!   off by default): `The query requires a <SCOPE>_<ASC|DESC|CONTAINS> index for collection <G>
//!   and field <F>. You can create it here: <console link with create_exemption=<encoded Index>>`;
//! - a vector index: `Missing vector index configuration. Please create the required index with
//!   the following gcloud command: gcloud firestore indexes composite create ...`.
//!
//! The console links carry a `google.firestore.admin.v1.Index` message, base64url without
//! padding, whose name ends in `/indexes/_` (composite) or `/fields/<field>` (exemption).

use fireemu_core_firestore::index::{IndexDefinition, IndexFieldMode, IndexQueryScope};
use prost::Message;

/// `google.firestore.admin.v1.Index.IndexField`.
#[derive(Clone, PartialEq, Message)]
struct AdminIndexField {
    #[prost(string, tag = "1")]
    field_path: String,
    #[prost(int32, optional, tag = "2")]
    order: Option<i32>,
    #[prost(int32, optional, tag = "3")]
    array_config: Option<i32>,
}

/// `google.firestore.admin.v1.Index` (the fields the console link carries).
#[derive(Clone, PartialEq, Message)]
struct AdminIndex {
    #[prost(string, tag = "1")]
    name: String,
    #[prost(int32, tag = "2")]
    query_scope: i32,
    #[prost(message, repeated, tag = "3")]
    fields: Vec<AdminIndexField>,
}

const MULTIPLE_RANGE_FIELDS: &str = " .\nThe query contains range and inequality filters on \
multiple fields, please refer to the documentation for index selection best practices: \
https://cloud.google.com/firestore/docs/query-data/multiple-range-fields.";

fn scope_number(scope: IndexQueryScope) -> i32 {
    match scope {
        IndexQueryScope::Collection => 1,
        IndexQueryScope::CollectionGroup => 2,
    }
}

fn admin_field(path: String, mode: IndexFieldMode) -> AdminIndexField {
    let (order, array_config) = match mode {
        IndexFieldMode::Ascending => (Some(1), None),
        IndexFieldMode::Descending => (Some(2), None),
        IndexFieldMode::Contains => (None, Some(1)),
        IndexFieldMode::Vector { .. } => (None, None),
    };
    AdminIndexField {
        field_path: path,
        order,
        array_config,
    }
}

/// base64url without padding, as the console links carry it.
fn blob(index: &AdminIndex) -> String {
    crate::rest::json::base64_encode(&index.encode_to_vec())
        .trim_end_matches('=')
        .replace('+', "-")
        .replace('/', "_")
}

/// `projects/<p>` of a database name `projects/<p>/databases/<d>`.
fn project_of(database: &str) -> &str {
    database
        .strip_prefix("projects/")
        .and_then(|rest| rest.split('/').next())
        .unwrap_or_default()
}

fn console(database: &str) -> String {
    format!(
        "https://console.firebase.google.com/v1/r/project/{}/firestore/indexes",
        project_of(database)
    )
}

/// The one field of a requirement a single-field index would serve: one ordered or
/// array-contains field followed only by `__name__` in the direction the automatic index
/// implies.
fn single_field(requirement: &IndexDefinition) -> Option<(String, IndexFieldMode)> {
    let fields = &requirement.fields;
    let first = fields.first()?;
    if first.path.is_document_name() || matches!(first.mode, IndexFieldMode::Vector { .. }) {
        return None;
    }
    let implied = match first.mode {
        IndexFieldMode::Descending => IndexFieldMode::Descending,
        _ => IndexFieldMode::Ascending,
    };
    let rest_is_implied_name = match &fields[1..] {
        [] => true,
        [name] => name.path.is_document_name() && name.mode == implied,
        _ => false,
    };
    rest_is_implied_name.then(|| (first.path.canonical(), first.mode))
}

fn vector_message(database: &str, requirement: &IndexDefinition) -> String {
    let scope = match requirement.query_scope {
        IndexQueryScope::Collection => "COLLECTION",
        IndexQueryScope::CollectionGroup => "COLLECTION_GROUP",
    };
    // The implied `__name__` tiebreak is not configured; a `__name__` vector field is.
    let configs: Vec<String> = requirement
        .fields
        .iter()
        .filter(|field| {
            !field.path.is_document_name() || matches!(field.mode, IndexFieldMode::Vector { .. })
        })
        .map(|field| match field.mode {
            IndexFieldMode::Ascending => format!("--field-config=order=ASCENDING,field-path={}", field.path.canonical()),
            IndexFieldMode::Descending => format!("--field-config=order=DESCENDING,field-path={}", field.path.canonical()),
            IndexFieldMode::Contains => format!("--field-config=array-config=CONTAINS,field-path={}", field.path.canonical()),
            IndexFieldMode::Vector { dimension } => format!(
                "--field-config=vector-config='{{\"dimension\":\"{dimension}\",\"flat\": \"{{}}\"}}',field-path={}",
                field.path.canonical()
            ),
        })
        .collect();
    format!(
        "Missing vector index configuration. Please create the required index with the following gcloud command: gcloud firestore indexes composite create --project={} --collection-group={} --query-scope={scope} {}",
        project_of(database),
        requirement.collection_group.as_str(),
        configs.join(" ")
    )
}

/// Production's refusal text for a query on `database` (`projects/<p>/databases/<d>`) that
/// needs `requirement`; `multiple_inequalities` is whether the query has inequality filters on
/// more than one field.
#[must_use]
pub fn missing_index_message(
    database: &str,
    requirement: &IndexDefinition,
    multiple_inequalities: bool,
) -> String {
    if requirement
        .fields
        .iter()
        .any(|field| matches!(field.mode, IndexFieldMode::Vector { .. }))
    {
        return vector_message(database, requirement);
    }
    let group = requirement.collection_group.as_str();
    let scope = scope_number(requirement.query_scope);
    if let Some((path, mode)) = single_field(requirement) {
        let kind = match (requirement.query_scope, mode) {
            (IndexQueryScope::Collection, IndexFieldMode::Descending) => "COLLECTION_DESC",
            (IndexQueryScope::Collection, IndexFieldMode::Contains) => "COLLECTION_CONTAINS",
            (IndexQueryScope::Collection, _) => "COLLECTION_ASC",
            (IndexQueryScope::CollectionGroup, IndexFieldMode::Descending) => {
                "COLLECTION_GROUP_DESC"
            }
            (IndexQueryScope::CollectionGroup, IndexFieldMode::Contains) => {
                "COLLECTION_GROUP_CONTAINS"
            }
            (IndexQueryScope::CollectionGroup, _) => "COLLECTION_GROUP_ASC",
        };
        let index = AdminIndex {
            name: format!("{database}/collectionGroups/{group}/fields/{path}"),
            query_scope: scope,
            fields: vec![admin_field(path.clone(), mode)],
        };
        return format!(
            "The query requires a {kind} index for collection {group} and field {path}. You can create it here: {}?create_exemption={}",
            console(database),
            blob(&index)
        );
    }
    let index = AdminIndex {
        name: format!("{database}/collectionGroups/{group}/indexes/_"),
        query_scope: scope,
        fields: requirement
            .fields
            .iter()
            .map(|field| admin_field(field.path.canonical(), field.mode))
            .collect(),
    };
    let mut message = format!(
        "The query requires an index. You can create it here: {}?create_composite={}",
        console(database),
        blob(&index)
    );
    if multiple_inequalities {
        message.push_str(MULTIPLE_RANGE_FIELDS);
    }
    message
}

/// What production answers a plan-only Explain of a query that needs a missing index.
pub const PLAN_ONLY_MISSING_INDEX: &str = "no matching index found.";

/// A missing-index refusal of a plan-only Explain (`explainOptions` without `analyze`) in
/// production's words; every other status is returned unchanged.
#[must_use]
pub fn for_explain(
    options: Option<&fireemu_proto_firestore::google::firestore::v1::ExplainOptions>,
    status: tonic::Status,
) -> tonic::Status {
    let plan_only = options.is_some_and(|options| !options.analyze);
    let missing_index = status
        .metadata()
        .get("fireemu-reason")
        .is_some_and(|reason| reason == "FS_GW_MISSING_INDEX");
    if !(plan_only && missing_index) {
        return status;
    }
    let mut refused = tonic::Status::failed_precondition(PLAN_ONLY_MISSING_INDEX);
    if let Ok(v) = "FS_GW_MISSING_INDEX".parse() {
        refused.metadata_mut().insert("fireemu-reason", v);
    }
    refused
}

#[cfg(test)]
mod tests {
    use super::*;
    use fireemu_core_firestore::field_path::FieldPath;
    use fireemu_core_firestore::index::IndexField;
    use fireemu_core_types::ids::CollectionId;

    const DATABASE: &str = "projects/fireemu-oracle-query/databases/(default)";

    fn field(path: &str, mode: IndexFieldMode) -> IndexField {
        IndexField {
            path: FieldPath::parse(path).unwrap(),
            mode,
        }
    }

    fn requirement(
        group: &str,
        scope: IndexQueryScope,
        fields: Vec<IndexField>,
    ) -> IndexDefinition {
        IndexDefinition {
            collection_group: CollectionId::try_new(group).unwrap(),
            query_scope: scope,
            fields,
        }
    }

    // Links recorded from production on 2026-09-24 (fireemu-oracle-query, raw answers).
    #[test]
    fn a_composite_requirement_links_the_encoded_index() {
        let message = missing_index_message(
            DATABASE,
            &requirement(
                "flt",
                IndexQueryScope::Collection,
                vec![
                    field("q", IndexFieldMode::Ascending),
                    field("z", IndexFieldMode::Ascending),
                    field("__name__", IndexFieldMode::Ascending),
                ],
            ),
            false,
        );
        assert_eq!(
            message,
            "The query requires an index. You can create it here: https://console.firebase.google.com/v1/r/project/fireemu-oracle-query/firestore/indexes?create_composite=ClBwcm9qZWN0cy9maXJlZW11LW9yYWNsZS1xdWVyeS9kYXRhYmFzZXMvKGRlZmF1bHQpL2NvbGxlY3Rpb25Hcm91cHMvZmx0L2luZGV4ZXMvXxABGgUKAXEQARoFCgF6EAEaDAoIX19uYW1lX18QAQ"
        );
    }

    #[test]
    fn multiple_inequality_fields_add_the_guide() {
        let message = missing_index_message(
            DATABASE,
            &requirement(
                "qx",
                IndexQueryScope::Collection,
                vec![
                    field("b", IndexFieldMode::Ascending),
                    field("a", IndexFieldMode::Ascending),
                    field("__name__", IndexFieldMode::Ascending),
                ],
            ),
            true,
        );
        assert!(message.ends_with(" .\nThe query contains range and inequality filters on multiple fields, please refer to the documentation for index selection best practices: https://cloud.google.com/firestore/docs/query-data/multiple-range-fields."));
    }

    #[test]
    fn a_disabled_single_field_index_links_an_exemption() {
        let message = missing_index_message(
            DATABASE,
            &requirement(
                "pk",
                IndexQueryScope::Collection,
                vec![
                    field("a", IndexFieldMode::Ascending),
                    field("__name__", IndexFieldMode::Ascending),
                ],
            ),
            false,
        );
        assert!(message.starts_with("The query requires a COLLECTION_ASC index for collection pk and field a. You can create it here: https://console.firebase.google.com/v1/r/project/fireemu-oracle-query/firestore/indexes?create_exemption="));
        let group_desc = missing_index_message(
            DATABASE,
            &requirement(
                "qg",
                IndexQueryScope::CollectionGroup,
                vec![
                    field("n", IndexFieldMode::Descending),
                    field("__name__", IndexFieldMode::Descending),
                ],
            ),
            false,
        );
        assert!(group_desc.starts_with(
            "The query requires a COLLECTION_GROUP_DESC index for collection qg and field n."
        ));
        let contains = missing_index_message(
            DATABASE,
            &requirement(
                "qg",
                IndexQueryScope::CollectionGroup,
                vec![
                    field("tags", IndexFieldMode::Contains),
                    field("__name__", IndexFieldMode::Ascending),
                ],
            ),
            false,
        );
        assert!(contains.starts_with(
            "The query requires a COLLECTION_GROUP_CONTAINS index for collection qg and field tags."
        ));
    }

    #[test]
    fn a_name_descending_or_mixed_direction_requirement_stays_composite() {
        for fields in [
            vec![field("__name__", IndexFieldMode::Descending)],
            vec![
                field("n", IndexFieldMode::Descending),
                field("__name__", IndexFieldMode::Ascending),
            ],
        ] {
            let message = missing_index_message(
                DATABASE,
                &requirement("qn", IndexQueryScope::Collection, fields),
                false,
            );
            assert!(message.starts_with("The query requires an index. You can create it here:"));
        }
    }

    #[test]
    fn a_vector_requirement_names_the_gcloud_command() {
        let message = missing_index_message(
            DATABASE,
            &requirement(
                "qvec",
                IndexQueryScope::Collection,
                vec![
                    field("n", IndexFieldMode::Ascending),
                    field("emb", IndexFieldMode::Vector { dimension: 3 }),
                ],
            ),
            false,
        );
        assert_eq!(
            message,
            "Missing vector index configuration. Please create the required index with the following gcloud command: gcloud firestore indexes composite create --project=fireemu-oracle-query --collection-group=qvec --query-scope=COLLECTION --field-config=order=ASCENDING,field-path=n --field-config=vector-config='{\"dimension\":\"3\",\"flat\": \"{}\"}',field-path=emb"
        );
    }
}
