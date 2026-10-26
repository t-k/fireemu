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

/// Recorded cases no general analysis rule explains: 20 CJK/kana cases plus 2 `İpek` cases, all
/// known differences by owner decision 1788 (which widens the six cases of 1785; text search is
/// verified for Latin-script text). They stay pinned so a change in either direction surfaces.
///
/// - Han and kana runs: production segments them with a dictionary. `京都`, `都`, `東京都`,
///   `京` and `京都東京駅` depend on the words around the character (`京都東京駅東京都京都東京駅`
///   contains `東京都` yet matches neither `都` nor `東京都`; `京` alone matches `京` and `京 都`
///   only); `生物研究所` and `"生 物"` separate `生物` from `生 物`; `吉` does not match `吉野家`.
/// - `𠮷`: alone it matches only `𠮷`, but `𠮷ミナ` and `𠮷野家` also match `吉ミナ` and `吉野家`.
/// - Katakana with width and `・` variants: unquoted `ネムラ ﾈﾑﾗ` (and the `・`/`･` forms) match only
///   `ネムラネムラ`, and `カタカナ・ｶﾀｶﾅ` matches nothing, not even the document holding it.
/// - `İpek`: the query keeps the mark case folding splits off `İ` (so `İzmir`, `İnci`, `İzunex`
///   and `İstanbul` match nothing, as production answered), yet production matched `İpek` and
///   `ipek` for the query `İpek`.
const UNEXPLAINED: [(&str, &str); 22] = [
    ("textcal20261024#4", "京"),
    ("textlex20261024#0", "京都"),
    ("textlex20261024#0", "京"),
    ("textlex20261024#0", "都"),
    ("textlex20261024#0", "東京都"),
    ("textlex20261024#0", "京都東京駅"),
    ("textlex20261024#0", "東京駅京都"),
    ("textlex20261024#0", "\"京 都\""),
    ("textproof20261024#0", "生物研究所"),
    ("textproof20261024#0", "\"生物 研究所\""),
    ("textproof20261024#0", "\"生 物\""),
    ("textproof20261024#0", "カタカナ・ｶﾀｶﾅ"),
    ("textproof20261024#0", "𠮷野家"),
    ("textproof20261024#0", "İpek"),
    ("textdisc20261024#0", "ネムラ・ﾈﾑﾗ"),
    ("textdisc20261024#0", "ネムラ ﾈﾑﾗ"),
    ("textdisc20261024#0", "ネムラ･ﾈﾑﾗ"),
    ("textdisc20261024#0", "吉"),
    ("textdisc20261024#0", "𠮷ミナ"),
    ("textdisc20261024#0", "カタカナ・ｶﾀｶﾅ"),
    ("textdisc20261024#0", "𠮷野家"),
    ("textdisc20261024#0", "İpek"),
];

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
        .map(|(corpus, query)| ((*corpus).to_owned(), (*query).to_owned()))
        .collect();
    differing.sort();
    let mut wanted = unexplained;
    wanted.sort();
    assert_eq!(differing, wanted, "{}", report.join("\n"));
}
