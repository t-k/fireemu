//! Production's refusal texts for malformed queries (FS-QUERY-INDEX, recorded 2026-09-24 on
//! `fireemu-oracle-query/(default)`).
//!
//! Each function turns fireemu's structured error into the text production answers for the
//! same request, so the decoders keep their typed errors and only the wording lives here.

use fireemu_core_firestore::field_path::FieldPathError;
use fireemu_core_types::ids::IdSyntaxError;

use crate::decode::{parse_parent, DecodeError, Parent};

/// The text production uses for an empty or absent property path.
pub const EMPTY_PROPERTY_PATH: &str = "Invalid empty property path string.";

/// Characters production refuses in an unquoted property path before matching it against the
/// path grammar (observed for `a[0]`, answered without the grammar).
const FORBIDDEN_UNQUOTED: &[char] = &['~', '*', '/', '[', ']'];

/// The refusal of a property path (a filter, order, projection or aggregation field) that
/// does not parse. `input` is the path as the request spelled it.
#[must_use]
pub fn property_path_error(input: &str, error: &FieldPathError) -> DecodeError {
    let message = match error {
        FieldPathError::Empty => EMPTY_PROPERTY_PATH.to_owned(),
        FieldPathError::ReservedSegment { index } => {
            let segment = segment_text(input, *index);
            format!("Invalid reserved name in field path {segment}")
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
            r#"Invalid property path "{input}". Unquoted property paths must match regex ([a-zA-Z_][a-zA-Z_0-9]*), and quoted property paths must match regex (`(?:[^`\\]|(?:\\.))+`)"#
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
            format!("Collection id \"{id}\" is invalid because it is reserved.")
        }
        IdSyntaxError::ContainsSlash => {
            format!("Collection id \"{id}\" is invalid because it contains \"/\".")
        }
        other => format!("Collection id \"{id}\" is invalid: {other}"),
    };
    DecodeError::Refused(message)
}

/// The refusal of a reference value, used as a document name, that names a collection.
#[must_use]
pub fn reference_is_not_a_document(name: &str) -> String {
    format!(
        "Document parent name {name:?} lacks \"/\" at index {}.",
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
