//! Replays every recorded production text-search response (`production_text_membership.json`,
//! 531 REST responses including those with zero or one result, so over-matching shows) and
//! checks that the local analysis returns the same SET of documents. The order is checked by
//! `text_score_order.rs`.
use fireemu_adapter_support::lexical::{tokenize_index, tokenize_query};
use fireemu_core_firestore::{
    field_path::FieldPath, index::IndexQueryScope, path::DocumentPath, text_index::*,
    text_search::*, value::Value,
};
use fireemu_core_types::{
    ids::{CollectionId, DatabaseId, ProjectId},
    json::{parse, JsonValue},
    time::LogicalInstant,
};
use std::collections::BTreeMap;

fn array(value: &JsonValue) -> &[JsonValue] {
    let JsonValue::Array(values) = value else {
        panic!("expected a fixture array");
    };
    values
}
fn object(value: &JsonValue) -> &BTreeMap<String, JsonValue> {
    let JsonValue::Object(map) = value else {
        panic!("expected a fixture object");
    };
    map
}
fn string<'a>(value: &'a JsonValue, key: &str) -> &'a str {
    value.get(key).and_then(JsonValue::as_str).unwrap()
}

struct Corpus {
    index: SearchIndex,
}

fn corpus(value: &JsonValue) -> Corpus {
    let collection = string(value, "collection");
    let definition = TextIndexDefinition {
        id: "recorded".into(),
        collection_id: CollectionId::try_new(collection).unwrap(),
        query_scope: IndexQueryScope::Collection,
        api_scope: "ANY_API".into(),
        fields: array(value.get("fields").unwrap())
            .iter()
            .map(|path| TextIndexedField {
                path: FieldPath::parse(path.as_str().unwrap()).unwrap(),
                index_type: TextIndexType::Tokenized,
                match_type: TextMatchType::MatchGlobally,
            })
            .collect(),
        language: DefaultTextLanguage::Tag("en".into()),
        language_override: match value.get("languageOverride").and_then(JsonValue::as_str) {
            Some(path) => LanguageOverridePolicy::ExplicitField(FieldPath::parse(path).unwrap()),
            None => LanguageOverridePolicy::Disabled,
        },
        state: TextIndexState::Ready,
    };
    let documents: Vec<SearchDocument> = array(value.get("documents").unwrap())
        .iter()
        .map(|row| SearchDocument {
            path: DocumentPath::parse(
                &ProjectId::try_new("demo-app").unwrap(),
                &DatabaseId::try_new("(default)").unwrap(),
                &format!("{collection}/{}", string(row, "id")),
            )
            .unwrap(),
            fields: object(row.get("fields").unwrap())
                .iter()
                .map(|(k, v)| (k.clone(), Value::String(v.as_str().unwrap().into())))
                .collect(),
            created_at: LogicalInstant::from_nanos(i128::from(
                row.get("created").and_then(JsonValue::as_i64).unwrap(),
            )),
        })
        .collect();
    Corpus {
        index: SearchIndex::build(&definition, &documents, tokenize_index).unwrap(),
    }
}

/// Each recorded case's corpus, query, production members and local members.
fn replay() -> Vec<(String, String, Vec<String>, Vec<String>)> {
    let fixture = parse(include_str!("fixtures/production_text_membership.json")).unwrap();
    assert_eq!(
        fixture.get("responses").and_then(JsonValue::as_i64),
        Some(531),
        "recorded production search responses"
    );
    let corpora: BTreeMap<&str, Corpus> = object(fixture.get("corpora").unwrap())
        .iter()
        .map(|(name, value)| (name.as_str(), corpus(value)))
        .collect();
    array(fixture.get("cases").unwrap())
        .iter()
        .map(|case| {
            let query = string(case, "query");
            let mut actual: Vec<String> = corpora[string(case, "corpus")]
                .index
                .search(
                    &SearchQuery::parse(query, tokenize_query).unwrap(),
                    &SearchOptions::default(),
                )
                .unwrap()
                .into_iter()
                .map(|hit| hit.path.relative().rsplit('/').next().unwrap().to_owned())
                .collect();
            actual.sort();
            let expected: Vec<String> = array(case.get("expected").unwrap())
                .iter()
                .map(|id| id.as_str().unwrap().to_owned())
                .collect();
            (
                string(case, "corpus").to_owned(),
                query.to_owned(),
                expected,
                actual,
            )
        })
        .collect()
}

#[path = "support/text_known_differences.rs"]
mod text_known_differences;
use text_known_differences::{known_difference, UNEXPLAINED};

/// Every recorded production response has the local membership, apart from the documented
/// [`UNEXPLAINED`] cases.
#[test]
fn recorded_production_memberships_replay_exactly() {
    let cases = replay();
    assert_eq!(cases.len(), 223, "distinct recorded cases");
    let mut differing: Vec<(String, String)> = Vec::new();
    let mut report = Vec::new();
    for (corpus, query, expected, actual) in cases {
        if expected != actual {
            report.push(format!(
                "corpus={corpus} query={query:?}\n  expected={expected:?}\n  actual  ={actual:?}"
            ));
            if !differing.contains(&(corpus.clone(), query.clone())) {
                differing.push((corpus, query));
            }
        }
    }
    let unexplained: Vec<(String, String)> = UNEXPLAINED
        .iter()
        .map(|(corpus, query, _)| ((*corpus).to_owned(), (*query).to_owned()))
        .collect();
    differing.sort();
    let mut wanted = unexplained;
    wanted.sort();
    assert_eq!(differing, wanted, "{}", report.join("\n"));
}

/// Every pinned case names one of the two closure known differences, and the lookup the closure
/// comparison uses finds each pinned case under that name.
#[test]
fn pinned_cases_name_their_closure_known_difference() {
    for (corpus, query, kind) in UNEXPLAINED {
        assert!(
            matches!(kind, "cjkDictionarySegmentation" | "dottedCapitalIpek"),
            "{corpus} {query:?}"
        );
        assert_eq!(
            known_difference(corpus, query),
            Some(kind),
            "{corpus} {query:?}"
        );
    }
    let ipek = UNEXPLAINED
        .iter()
        .filter(|(_, _, kind)| *kind == "dottedCapitalIpek")
        .count();
    assert_eq!(
        (UNEXPLAINED.len() - ipek, ipek),
        (20, 2),
        "20 CJK/kana plus 2 İpek"
    );
}
