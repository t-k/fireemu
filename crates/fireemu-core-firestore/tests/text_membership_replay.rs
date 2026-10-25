//! Replays every recorded production text-search response of `production_text_order.json` and
//! checks that the local analysis returns the same SET of documents (membership). The order is
//! checked by `text_score_order.rs`.
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
    let fixture = parse(include_str!("fixtures/production_text_order.json")).unwrap();
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
            let mut expected: Vec<String> = array(case.get("expected").unwrap())
                .iter()
                .map(|id| id.as_str().unwrap().to_owned())
                .collect();
            actual.sort();
            expected.sort();
            (
                string(case, "corpus").to_owned(),
                query.to_owned(),
                expected,
                actual,
            )
        })
        .collect()
}

/// Recorded cases no general analysis rule explains, kept so a change in either direction
/// surfaces. `京都`, `都` and `東京都` need dictionary segmentation of an unspaced Han run (the
/// document `京都東京駅東京都京都東京駅` contains `東京都` yet matches neither `都` nor
/// `東京都`). `𠮷` alone matches only documents containing `𠮷`, while `𠮷ミナ` and `𠮷野家`
/// also match `吉ミナ` and `吉野家`, and `ミナ` alone matches `森ミナ`, which `𠮷ミナ` does
/// not: no per-character fold reproduces all three.
const UNEXPLAINED: [(&str, &str); 6] = [
    ("textlex20261024#0", "京都"),
    ("textlex20261024#0", "都"),
    ("textlex20261024#0", "東京都"),
    ("textproof20261024#0", "𠮷野家"),
    ("textdisc20261024#0", "𠮷ミナ"),
    ("textdisc20261024#0", "𠮷野家"),
];

/// Every recorded production response has the local membership, apart from the documented
/// [`UNEXPLAINED`] dictionary-segmentation cases.
#[test]
fn recorded_production_memberships_replay_exactly() {
    let cases = replay();
    assert_eq!(cases.len(), 168, "recorded cases");
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
        .map(|(corpus, query)| ((*corpus).to_owned(), (*query).to_owned()))
        .collect();
    differing.sort();
    let mut wanted = unexplained;
    wanted.sort();
    assert_eq!(differing, wanted, "{}", report.join("\n"));
}
