//! The FS-TEXT-SEARCH closure comparison: every recorded production text-search case replayed
//! through the local engine, one row per case, written to
//! `spec/compatibility/closure/evidence/FS-TEXT-SEARCH-comparison.json`.
//!
//! The committed file must equal what the current engine produces, so a change in any recorded
//! membership or order shows up as a difference here. Regenerate it after an intended change
//! with `FIREEMU_WRITE_TEXT_COMPARISON=1 cargo nextest run -p fireemu-core-firestore -E
//! 'binary(text_closure_comparison)'` and review the diff.
//!
//! Numeric `score()` values are not compared: they are a documented approximation.
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
use std::fmt::Write as _;

const ORDER_FIXTURE: &str = include_str!("fixtures/production_text_order.json");
const SPARSE_FIXTURE: &str = include_str!("fixtures/production_text_sparse.json");
const BOUNDARY_FIXTURE: &str = include_str!("fixtures/production_text_boundary.json");
const COMPARISON: &str = "spec/compatibility/closure/evidence/FS-TEXT-SEARCH-comparison.json";

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

fn definition(
    collection: &str,
    fields: &[&str],
    language_override: Option<&str>,
) -> TextIndexDefinition {
    TextIndexDefinition {
        id: "recorded".into(),
        collection_id: CollectionId::try_new(collection).unwrap(),
        query_scope: IndexQueryScope::Collection,
        api_scope: "ANY_API".into(),
        fields: fields
            .iter()
            .map(|path| TextIndexedField {
                path: FieldPath::parse(path).unwrap(),
                index_type: TextIndexType::Tokenized,
                match_type: TextMatchType::MatchGlobally,
            })
            .collect(),
        language: DefaultTextLanguage::Tag("en".into()),
        language_override: match language_override {
            Some(path) => LanguageOverridePolicy::ExplicitField(FieldPath::parse(path).unwrap()),
            None => LanguageOverridePolicy::Disabled,
        },
        state: TextIndexState::Ready,
    }
}

fn document(
    collection: &str,
    id: &str,
    fields: Vec<(String, String)>,
    created: i128,
) -> SearchDocument {
    SearchDocument {
        path: DocumentPath::parse(
            &ProjectId::try_new("demo-app").unwrap(),
            &DatabaseId::try_new("(default)").unwrap(),
            &format!("{collection}/{id}"),
        )
        .unwrap(),
        fields: fields
            .into_iter()
            .map(|(k, v)| (k, Value::String(v)))
            .collect(),
        created_at: LogicalInstant::from_nanos(created),
    }
}

fn corpus(value: &JsonValue) -> SearchIndex {
    let collection = string(value, "collection");
    let fields: Vec<&str> = array(value.get("fields").unwrap())
        .iter()
        .map(|path| path.as_str().unwrap())
        .collect();
    let documents: Vec<SearchDocument> = array(value.get("documents").unwrap())
        .iter()
        .map(|row| {
            document(
                collection,
                string(row, "id"),
                object(row.get("fields").unwrap())
                    .iter()
                    .map(|(k, v)| (k.clone(), v.as_str().unwrap().to_owned()))
                    .collect(),
                i128::from(row.get("created").and_then(JsonValue::as_i64).unwrap()),
            )
        })
        .collect();
    let definition = definition(
        collection,
        &fields,
        value.get("languageOverride").and_then(JsonValue::as_str),
    );
    SearchIndex::build(&definition, &documents, tokenize_index).unwrap()
}

fn search(index: &SearchIndex, query: &str, score_sort: bool) -> Vec<String> {
    let options = SearchOptions {
        order: if score_sort {
            SearchOrder::ScoreDescending
        } else {
            SearchOrder::CreationDescending
        },
        ..SearchOptions::default()
    };
    index
        .search(
            &SearchQuery::parse(query, tokenize_query).unwrap(),
            &options,
        )
        .unwrap()
        .into_iter()
        .map(|hit| hit.path.relative().rsplit('/').next().unwrap().to_owned())
        .collect()
}

fn quoted(text: &str) -> String {
    let mut out = String::from("\"");
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn list(items: &[String]) -> String {
    format!(
        "[{}]",
        items
            .iter()
            .map(|s| quoted(s))
            .collect::<Vec<_>>()
            .join(", ")
    )
}

struct Row {
    id: String,
    corpus: String,
    query: String,
    score_sort: bool,
    recordings: Vec<String>,
    expected: Vec<String>,
    actual: Vec<String>,
    membership: &'static str,
    order: &'static str,
}

impl Row {
    fn status(&self) -> &'static str {
        if self.membership == "MATCH" && self.order != "MISMATCH" {
            "MATCH"
        } else if self.membership == "DIFFERENT" && self.order != "MISMATCH" {
            "KNOWN_DIFFERENCE"
        } else {
            "MISMATCH"
        }
    }
}

/// One row per recorded case of a replay fixture. Order is compared for responses with two or
/// more results; where the membership differs, the order of the members both sides return.
fn replay_rows(prefix: &str, text: &str) -> Vec<Row> {
    let fixture = parse(text).unwrap();
    let corpora: BTreeMap<&str, SearchIndex> = object(fixture.get("corpora").unwrap())
        .iter()
        .map(|(name, value)| (name.as_str(), corpus(value)))
        .collect();
    array(fixture.get("cases").unwrap())
        .iter()
        .enumerate()
        .map(|(n, case)| {
            let score_sort = case.get("scoreSort").and_then(JsonValue::as_bool).unwrap();
            let query = string(case, "query");
            let expected: Vec<String> = array(case.get("expected").unwrap())
                .iter()
                .map(|id| id.as_str().unwrap().to_owned())
                .collect();
            let actual = search(&corpora[string(case, "corpus")], query, score_sort);
            let (mut a, mut e) = (actual.clone(), expected.clone());
            a.sort();
            e.sort();
            let membership = if a == e { "MATCH" } else { "DIFFERENT" };
            let common = |list: &[String]| -> Vec<String> {
                list.iter()
                    .filter(|id| actual.contains(id) && expected.contains(id))
                    .cloned()
                    .collect()
            };
            let order = if expected.len() < 2 {
                "NOT_APPLICABLE"
            } else if actual == expected {
                "MATCH"
            } else if membership == "DIFFERENT" && common(&actual) == common(&expected) {
                "MATCH_COMMON_MEMBERS"
            } else {
                "MISMATCH"
            };
            Row {
                id: format!("{prefix}#{n}"),
                corpus: string(case, "corpus").to_owned(),
                query: query.to_owned(),
                score_sort,
                recordings: array(case.get("recordings").unwrap())
                    .iter()
                    .map(|r| r.as_str().unwrap().to_owned())
                    .collect(),
                expected,
                actual,
                membership,
                order,
            }
        })
        .collect()
}

/// Boundary03: one row per query and round; membership over all nine documents.
fn boundary_rows() -> Vec<Row> {
    let fixture = parse(BOUNDARY_FIXTURE).unwrap();
    let docs: Vec<SearchDocument> = array(fixture.get("documents").unwrap())
        .iter()
        .map(|row| {
            document(
                "docs",
                string(row, "id"),
                vec![
                    ("title".into(), string(row, "title").into()),
                    ("body".into(), string(row, "body").into()),
                ],
                1,
            )
        })
        .collect();
    let index = SearchIndex::build(
        &definition("docs", &["title", "body"], None),
        &docs,
        tokenize_index,
    )
    .unwrap();
    let mut rows = Vec::new();
    for (round, queries) in array(fixture.get("rounds").unwrap()).iter().enumerate() {
        for (n, row) in array(queries).iter().enumerate() {
            let query = string(row, "query");
            let mut expected: Vec<String> = array(row.get("members").unwrap())
                .iter()
                .map(|m| m.as_str().unwrap().to_owned())
                .collect();
            let mut actual = search(&index, query, false);
            expected.sort();
            actual.sort();
            rows.push(Row {
                id: format!("boundary03/round{}#{n}", round + 1),
                corpus: "boundary03".into(),
                query: query.to_owned(),
                score_sort: false,
                recordings: vec![format!("boundary03/round{}", round + 1)],
                membership: if expected == actual {
                    "MATCH"
                } else {
                    "DIFFERENT"
                },
                order: "NOT_APPLICABLE",
                expected,
                actual,
            });
        }
    }
    rows
}

fn render(rows: &[Row]) -> String {
    let count = |f: &dyn Fn(&Row) -> bool| rows.iter().filter(|r| f(r)).count();
    let mut out = String::new();
    out.push_str("{\n");
    out.push_str("  \"schemaVersion\": 1,\n");
    out.push_str("  \"kind\": \"fs-text-search-replay-comparison-v1\",\n");
    out.push_str("  \"parent\": \"FS-TEXT-SEARCH\",\n");
    out.push_str(
        "  \"producer\": \"crates/fireemu-core-firestore/tests/text_closure_comparison.rs\",\n",
    );
    out.push_str("  \"about\": \"Every recorded production Firestore Enterprise text-search case replayed through the local engine: membership for every case, result order for every case with two or more results (score-sorted and default), and Boundary03 membership for both rounds. expected is the production response (order kept where it has two or more results), actual the local answer. Numeric score() values are not compared.\",\n");
    let _ = writeln!(
        out,
        "  \"summary\": {{\"rows\": {}, \"MATCH\": {}, \"KNOWN_DIFFERENCE\": {}, \"MISMATCH\": {}, \"scoreSortedOrderRows\": {}, \"scoreSortedOrderMatch\": {}, \"defaultOrderRows\": {}, \"defaultOrderMatch\": {}, \"defaultOrderMatchCommonMembers\": {}, \"recordings\": {}}},",
        rows.len(),
        count(&|r| r.status() == "MATCH"),
        count(&|r| r.status() == "KNOWN_DIFFERENCE"),
        count(&|r| r.status() == "MISMATCH"),
        count(&|r| r.score_sort && r.order != "NOT_APPLICABLE"),
        count(&|r| r.score_sort && r.order == "MATCH"),
        count(&|r| !r.score_sort && r.order != "NOT_APPLICABLE"),
        count(&|r| !r.score_sort && r.order == "MATCH"),
        count(&|r| !r.score_sort && r.order == "MATCH_COMMON_MEMBERS"),
        rows.iter().map(|r| r.recordings.len()).sum::<usize>(),
    );
    out.push_str("  \"rows\": [\n");
    for (i, row) in rows.iter().enumerate() {
        let _ = write!(
            out,
            "    {{\"row\": {}, \"status\": {}, \"membership\": {}, \"order\": {}, \"corpus\": {}, \"query\": {}, \"scoreSort\": {}, \"expected\": {}, \"actual\": {}, \"recordings\": {}}}",
            quoted(&row.id),
            quoted(row.status()),
            quoted(row.membership),
            quoted(row.order),
            quoted(&row.corpus),
            quoted(&row.query),
            row.score_sort,
            list(&row.expected),
            list(&row.actual),
            list(&row.recordings),
        );
        out.push_str(if i + 1 == rows.len() { "\n" } else { ",\n" });
    }
    out.push_str("  ]\n}\n");
    out
}

fn all_rows() -> Vec<Row> {
    let mut rows = replay_rows("order", ORDER_FIXTURE);
    rows.extend(replay_rows("sparse", SPARSE_FIXTURE));
    rows.extend(boundary_rows());
    rows
}

/// The committed closure comparison equals the current replay, and no row is a mismatch: every
/// difference is a membership difference whose common members keep the production order.
#[test]
fn committed_closure_comparison_equals_the_replay() {
    let rows = all_rows();
    assert_eq!(rows.len(), 168 + 65 + 26, "recorded cases");
    let mismatches: Vec<&str> = rows
        .iter()
        .filter(|row| row.status() == "MISMATCH")
        .map(|row| row.id.as_str())
        .collect();
    assert!(mismatches.is_empty(), "order mismatches: {mismatches:?}");
    let rendered = render(&rows);
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(COMPARISON);
    if std::env::var_os("FIREEMU_WRITE_TEXT_COMPARISON").is_some() {
        std::fs::write(&path, &rendered).unwrap();
    }
    let committed = std::fs::read_to_string(&path).unwrap_or_default();
    assert!(
        committed == rendered,
        "{COMPARISON} differs from the replay; regenerate it with FIREEMU_WRITE_TEXT_COMPARISON=1 and review the diff"
    );
}

/// Every score-sorted case has exact membership and the production order, and every
/// boundary row matches: the known differences are confined to default-order and sparse cases.
#[test]
fn score_sorted_and_boundary_rows_all_match() {
    for row in all_rows() {
        if row.score_sort || row.corpus == "boundary03" {
            assert_eq!(row.status(), "MATCH", "{} {:?}", row.id, row.query);
        }
    }
}
