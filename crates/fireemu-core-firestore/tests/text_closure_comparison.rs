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

#[path = "support/text_known_differences.rs"]
mod text_known_differences;
use text_known_differences::known_difference;

const ORDER_FIXTURE: &str = include_str!("fixtures/production_text_order.json");
const MEMBERSHIP_FIXTURE: &str = include_str!("fixtures/production_text_membership.json");
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
    /// The closure known difference a membership difference belongs to; `None` when the
    /// membership matches or the difference is not a named one.
    known_difference: Option<&'static str>,
}

impl Row {
    fn status(&self) -> &'static str {
        if self.membership == "MATCH" && self.order != "MISMATCH" {
            "MATCH"
        } else if self.membership == "DIFFERENT"
            && self.known_difference.is_some()
            && self.order != "MISMATCH"
        {
            "KNOWN_DIFFERENCE"
        } else {
            "MISMATCH"
        }
    }
}

/// One row per recorded case of a replay fixture. With `with_order`, the order is compared for
/// responses with two or more results; where the membership differs, the order of the members
/// both sides return (`MATCH_COMMON_MEMBERS`), or `NOT_COMPARABLE` when fewer than two members
/// are common. A membership difference is a known difference only when it is named in
/// `support/text_known_differences.rs`; any other is a mismatch. The membership fixture's cases
/// carry no sort and count their responses.
fn replay_rows(prefix: &str, text: &str, with_order: bool) -> Vec<Row> {
    let fixture = parse(text).unwrap();
    let corpora: BTreeMap<&str, SearchIndex> = object(fixture.get("corpora").unwrap())
        .iter()
        .map(|(name, value)| (name.as_str(), corpus(value)))
        .collect();
    array(fixture.get("cases").unwrap())
        .iter()
        .enumerate()
        .map(|(n, case)| {
            let score_sort = case
                .get("scoreSort")
                .and_then(JsonValue::as_bool)
                .unwrap_or(false);
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
            let order = if !with_order || expected.len() < 2 {
                "NOT_APPLICABLE"
            } else if actual == expected {
                "MATCH"
            } else if membership == "DIFFERENT" && common(&actual).len() < 2 {
                "NOT_COMPARABLE"
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
                recordings: match case.get("recordings") {
                    Some(list) => array(list)
                        .iter()
                        .map(|r| r.as_str().unwrap().to_owned())
                        .collect(),
                    None => (0..case.get("responses").and_then(JsonValue::as_i64).unwrap())
                        .map(|n| format!("response {}", n + 1))
                        .collect(),
                },
                known_difference: if membership == "DIFFERENT" {
                    known_difference(string(case, "corpus"), query)
                } else {
                    None
                },
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
                known_difference: None,
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
    out.push_str("  \"about\": \"Every recorded production Firestore Enterprise text-search case replayed through the local engine: membership rows for the 223 distinct cases of all 531 responses, order rows for the 168 cases with two or more results (score-sorted and default; their membership is repeated there), and Boundary03 membership for both rounds. A membership difference is KNOWN_DIFFERENCE only when it is a named closure known difference (knownDifference), otherwise MISMATCH. Where membership differs, order is MATCH_COMMON_MEMBERS when two or more common members keep production order and NOT_COMPARABLE when fewer than two are common. expected is the production response (order kept where it has two or more results), actual the local answer. Numeric score() values are not compared.\",\n");
    let _ = writeln!(
        out,
        "  \"summary\": {{\"rows\": {}, \"MATCH\": {}, \"KNOWN_DIFFERENCE\": {}, \"MISMATCH\": {}, \"scoreSortedOrderRows\": {}, \"scoreSortedOrderMatch\": {}, \"defaultOrderRows\": {}, \"defaultOrderMatch\": {}, \"defaultOrderMatchCommonMembers\": {}, \"defaultOrderNotComparable\": {}, \"membershipResponses\": {}}},",
        rows.len(),
        count(&|r| r.status() == "MATCH"),
        count(&|r| r.status() == "KNOWN_DIFFERENCE"),
        count(&|r| r.status() == "MISMATCH"),
        count(&|r| r.score_sort && r.order != "NOT_APPLICABLE"),
        count(&|r| r.score_sort && r.order == "MATCH"),
        count(&|r| !r.score_sort && r.order != "NOT_APPLICABLE"),
        count(&|r| !r.score_sort && r.order == "MATCH"),
        count(&|r| !r.score_sort && r.order == "MATCH_COMMON_MEMBERS"),
        count(&|r| !r.score_sort && r.order == "NOT_COMPARABLE"),
        rows.iter()
            .filter(|r| r.id.starts_with("membership"))
            .map(|r| r.recordings.len())
            .sum::<usize>(),
    );
    out.push_str("  \"rows\": [\n");
    for (i, row) in rows.iter().enumerate() {
        let _ = write!(
            out,
            "    {{\"row\": {}, \"status\": {}, \"membership\": {}, \"order\": {}, \"knownDifference\": {}, \"corpus\": {}, \"query\": {}, \"scoreSort\": {}, \"expected\": {}, \"actual\": {}, \"recordings\": {}}}",
            quoted(&row.id),
            quoted(row.status()),
            quoted(row.membership),
            quoted(row.order),
            row.known_difference.map_or_else(|| "null".to_owned(), quoted),
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
    let mut rows = replay_rows("membership", MEMBERSHIP_FIXTURE, false);
    rows.extend(replay_rows("order", ORDER_FIXTURE, true));
    rows.extend(boundary_rows());
    rows
}

/// The committed closure comparison equals the current replay, and no row is a mismatch: every
/// difference is a membership difference whose common members keep the production order.
#[test]
fn committed_closure_comparison_equals_the_replay() {
    let rows = all_rows();
    assert_eq!(rows.len(), 223 + 168 + 26, "recorded cases");
    let mismatches: Vec<&str> = rows
        .iter()
        .filter(|row| row.status() == "MISMATCH")
        .map(|row| row.id.as_str())
        .collect();
    assert!(
        mismatches.is_empty(),
        "unnamed membership differences or order mismatches: {mismatches:?}"
    );
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
/// boundary row matches: the known differences are confined to default-order and membership rows.
#[test]
fn score_sorted_and_boundary_rows_all_match() {
    for row in all_rows() {
        if row.score_sort || row.corpus == "boundary03" {
            assert_eq!(row.status(), "MATCH", "{} {:?}", row.id, row.query);
        }
    }
}

/// A membership difference counts as a known difference only when it is named; an unnamed one
/// is a mismatch, and every named difference occurs as a membership row.
#[test]
fn only_named_membership_differences_are_known_differences() {
    let row = |known_difference| Row {
        id: "synthetic#0".into(),
        corpus: "textlex20261024#0".into(),
        query: "京都".into(),
        score_sort: false,
        recordings: Vec::new(),
        expected: vec!["a".into()],
        actual: vec!["b".into()],
        membership: "DIFFERENT",
        order: "NOT_APPLICABLE",
        known_difference,
    };
    assert_eq!(row(None).status(), "MISMATCH");
    assert_eq!(
        row(Some("cjkDictionarySegmentation")).status(),
        "KNOWN_DIFFERENCE"
    );
    assert_eq!(known_difference("textlex20261024#0", "fox"), None);
    assert_eq!(known_difference("othercollection#0", "京都"), None);
    let mut named: Vec<(String, String)> = all_rows()
        .into_iter()
        .filter(|r| r.id.starts_with("membership") && r.known_difference.is_some())
        .map(|r| (r.corpus, r.query))
        .collect();
    named.sort();
    let mut pinned: Vec<(String, String)> = text_known_differences::UNEXPLAINED
        .iter()
        .map(|(c, q, _)| ((*c).to_owned(), (*q).to_owned()))
        .collect();
    pinned.sort();
    assert_eq!(named, pinned);
}

/// Where membership differs, an order is compared only over two or more common members.
#[test]
fn common_member_order_needs_two_common_members() {
    for row in all_rows() {
        if row.order == "MATCH_COMMON_MEMBERS" {
            let common = row
                .actual
                .iter()
                .filter(|id| row.expected.contains(id))
                .count();
            assert!(common >= 2, "{} {:?}", row.id, row.query);
        }
    }
}
