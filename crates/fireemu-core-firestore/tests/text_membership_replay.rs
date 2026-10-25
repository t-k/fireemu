//! Replays every recorded production text-search response and checks that the local analysis
//! returns the same SET of documents (membership). `production_text_order.json` holds the
//! responses with two or more results, whose order `text_score_order.rs` checks;
//! `production_text_sparse.json` holds the responses with zero or one result. Both fixtures are
//! built from the same recorded captures, so together they cover every recorded search response.
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

const ORDER_FIXTURE: &str = include_str!("fixtures/production_text_order.json");
const SPARSE_FIXTURE: &str = include_str!("fixtures/production_text_sparse.json");

/// Each recorded case's corpus, query, production members and local members.
fn replay(text: &str) -> Vec<(String, String, Vec<String>, Vec<String>)> {
    let fixture = parse(text).unwrap();
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
/// surfaces. Owner decision 2026-10-26 (ledger 1785) accepts the first six as known differences.
///
/// - `京都`, `都` and `東京都` need dictionary segmentation of an unspaced Han run (the document
///   `京都東京駅東京都京都東京駅` contains `東京都` yet matches neither `都` nor `東京都`).
/// - `𠮷` alone matches only documents containing `𠮷`, while `𠮷ミナ` and `𠮷野家` also match
///   `吉ミナ` and `吉野家`, and `ミナ` alone matches `森ミナ`, which `𠮷ミナ` does not: no
///   per-character fold reproduces all three.
/// - `İpek` matches both `İpek` and `ipek`, while `İstanbul`, `İzmir`, `İnci` and `İzunex` match
///   no document at all, not even their own word ([`SPARSE_UNEXPLAINED`] has none of them, as
///   the query analysis keeps the mark case folding splits off `İ`). No per-character rule
///   reproduces both; the query analysis follows the larger recorded group.
const UNEXPLAINED: [(&str, &str); 8] = [
    ("textlex20261024#0", "京都"),
    ("textlex20261024#0", "都"),
    ("textlex20261024#0", "東京都"),
    ("textproof20261024#0", "𠮷野家"),
    ("textdisc20261024#0", "𠮷ミナ"),
    ("textdisc20261024#0", "𠮷野家"),
    ("textproof20261024#0", "İpek"),
    ("textdisc20261024#0", "İpek"),
];

/// Recorded zero- and one-result cases no general analysis rule explains. All are dictionary
/// segmentation of unspaced Han or Katakana text, the same kind as the first six of
/// [`UNEXPLAINED`]:
///
/// - `京` matches only a document that is `京` alone (or `京 都`), never `京都`, `東京` or
///   `東京駅`; `京都東京駅` and `東京駅京都` match `京都東京駅東京都京都東京駅` but not
///   `東京都の猫と東京駅`; the phrase `"京 都"` matches only the spaced `京 都`.
/// - `生物研究所` and the phrase `"生物 研究所"` match `生物研究所` but not `生 物 研究 所`,
///   while `"生 物"` matches only the spaced form.
/// - `吉` matches `吉ミナ` but not `吉野家`.
/// - `ネムラ・ﾈﾑﾗ`, `ネムラ ﾈﾑﾗ` and `ネムラ･ﾈﾑﾗ` match only `ネムラネムラ`, not the documents
///   that spell the query itself; `カタカナ・ｶﾀｶﾅ` matches no document, not even its own text.
const SPARSE_UNEXPLAINED: [(&str, &str); 14] = [
    ("textcal20261024#1", "京"),
    ("textlex20261024#0", "京"),
    ("textlex20261024#0", "京都東京駅"),
    ("textlex20261024#0", "東京駅京都"),
    ("textlex20261024#0", "\"京 都\""),
    ("textproof20261024#0", "生物研究所"),
    ("textproof20261024#0", "\"生物 研究所\""),
    ("textproof20261024#0", "\"生 物\""),
    ("textproof20261024#0", "カタカナ・ｶﾀｶﾅ"),
    ("textdisc20261024#0", "ネムラ・ﾈﾑﾗ"),
    ("textdisc20261024#0", "ネムラ ﾈﾑﾗ"),
    ("textdisc20261024#0", "ネムラ･ﾈﾑﾗ"),
    ("textdisc20261024#0", "吉"),
    ("textdisc20261024#0", "カタカナ・ｶﾀｶﾅ"),
];

/// The (corpus, query) pairs whose local membership differs from production, sorted, and a
/// report of each difference.
fn differing(
    cases: Vec<(String, String, Vec<String>, Vec<String>)>,
) -> (Vec<(String, String)>, String) {
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
    differing.sort();
    (differing, report.join("\n"))
}

fn sorted_pairs(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
    let mut pairs: Vec<(String, String)> = pairs
        .iter()
        .map(|(corpus, query)| ((*corpus).to_owned(), (*query).to_owned()))
        .collect();
    pairs.sort();
    pairs
}

/// Every recorded production response with two or more results has the local membership,
/// apart from the documented [`UNEXPLAINED`] cases.
#[test]
fn recorded_production_memberships_replay_exactly() {
    let cases = replay(ORDER_FIXTURE);
    assert_eq!(cases.len(), 168, "recorded cases");
    let (differing, report) = differing(cases);
    assert_eq!(differing, sorted_pairs(&UNEXPLAINED), "{report}");
}

/// Every recorded production response with zero or one result (65 distinct cases from 140
/// responses) has the local membership, apart from the documented [`SPARSE_UNEXPLAINED`]
/// cases: empty and exclusions-only queries, contextual `OR`, unquoted colons, quoted phrases,
/// Latin and Greek folding, dotted capital I and half-width forms all match.
#[test]
fn recorded_sparse_production_memberships_replay_exactly() {
    let cases = replay(SPARSE_FIXTURE);
    assert_eq!(cases.len(), 65, "recorded zero- and one-result cases");
    let (differing, report) = differing(cases);
    assert_eq!(differing, sorted_pairs(&SPARSE_UNEXPLAINED), "{report}");
}
