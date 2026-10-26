//! Replays every recorded production text-search response that returned two or more
//! documents and checks that the local engine returns the same documents in the same order.
//!
//! The fixture `production_text_order.json` holds the corpus reconstructed from the recorded
//! writes at the time of each search, and the production response order. Numeric `score()`
//! values are deliberately not compared: they are a documented approximation.
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

/// Every recorded case with the given sort whose production order the engine does not reproduce, with the reason.
fn mismatches(wanted_score_sort: bool) -> (usize, usize, Vec<String>) {
    let fixture = parse(include_str!("fixtures/production_text_order.json")).unwrap();
    let corpora: BTreeMap<&str, Corpus> = object(fixture.get("corpora").unwrap())
        .iter()
        .map(|(name, value)| (name.as_str(), corpus(value)))
        .collect();
    let mut checked = 0;
    let mut failures = Vec::new();
    let mut membership_gaps = 0;
    for case in array(fixture.get("cases").unwrap()) {
        let score_sort = case.get("scoreSort").and_then(JsonValue::as_bool).unwrap();
        if score_sort != wanted_score_sort {
            continue;
        }
        checked += 1;
        let query = string(case, "query");
        let options = SearchOptions {
            order: if score_sort {
                SearchOrder::ScoreDescending
            } else {
                SearchOrder::CreationDescending
            },
            ..SearchOptions::default()
        };
        let actual: Vec<String> = corpora[string(case, "corpus")]
            .index
            .search(
                &SearchQuery::parse(query, tokenize_query).unwrap(),
                &options,
            )
            .unwrap()
            .into_iter()
            .map(|hit| hit.path.relative().rsplit('/').next().unwrap().to_owned())
            .collect();
        let expected: Vec<String> = array(case.get("expected").unwrap())
            .iter()
            .map(|id| id.as_str().unwrap().to_owned())
            .collect();
        let mut a = actual.clone();
        let mut e = expected.clone();
        a.sort();
        e.sort();
        if a != e {
            // Membership differences (tokenizer gaps) are owned elsewhere; still require the
            // documents both sides return to appear in the production order.
            membership_gaps += 1;
            let common = |list: &[String]| -> Vec<String> {
                list.iter()
                    .filter(|id| actual.contains(id) && expected.contains(id))
                    .cloned()
                    .collect()
            };
            if common(&actual) != common(&expected) {
                failures.push(format!(
                    "order among common members: corpus={} query={query:?}\n  expected={expected:?}\n  actual  ={actual:?}",
                    string(case, "corpus")
                ));
            }
        } else if actual != expected {
            failures.push(format!(
                "order: corpus={} query={query:?} scoreSort={score_sort}\n  expected={expected:?}\n  actual  ={actual:?}",
                string(case, "corpus")
            ));
        }
    }
    (checked, membership_gaps, failures)
}

#[test]
fn recorded_production_score_orders_replay_exactly() {
    let (checked, membership_gaps, failures) = mismatches(true);
    assert_eq!(checked, 64, "score-sorted recorded cases");
    assert_eq!(
        membership_gaps, 0,
        "score-sorted cases must have exact membership"
    );
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn recorded_production_default_orders_replay_exactly() {
    let (checked, membership_gaps, failures) = mismatches(false);
    assert_eq!(checked, 104, "unsorted recorded cases");
    // Eight unsorted cases differ in membership only: the documented CJK segmentation and
    // `İpek` cases of `text_membership_replay.rs`. Their common members still follow the
    // production order.
    assert_eq!(
        membership_gaps, 8,
        "unsorted cases with a membership difference"
    );
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// Pairwise combinations (PICT, 2-way, with the required seed rows) of query shape, token
/// placement, sort, padding and retrieval depth. Each row checks membership, the exact score
/// formula, and the tie order against an independent reference.
const PAIRWISE: [(&str, &str, &str, &str, &str); 20] = [
    ("PairAB", "Reverse", "Score", "None", "Unset"),
    ("PairAB", "Adjacent", "Score", "Twenty", "Unset"),
    ("Phrase", "Adjacent", "Score", "None", "Unset"),
    ("WithExclusion", "Gap", "Score", "None", "Unset"),
    ("Single", "CrossField", "None", "None", "Two"),
    ("Phrase", "Gap", "None", "Twenty", "Two"),
    ("Single", "Gap", "None", "Twenty", "Unset"),
    ("Single", "Adjacent", "Score", "Twenty", "Two"),
    ("Repeated", "Adjacent", "None", "Twenty", "Two"),
    ("Repeated", "Reverse", "Score", "Twenty", "Two"),
    ("Phrase", "Reverse", "None", "None", "Unset"),
    ("Phrase", "CrossField", "Score", "Twenty", "Unset"),
    ("Repeated", "CrossField", "None", "None", "Unset"),
    ("PairAB", "CrossField", "None", "Twenty", "Two"),
    ("PairAB", "Gap", "None", "Twenty", "Two"),
    ("WithExclusion", "CrossField", "None", "Twenty", "Two"),
    ("WithExclusion", "Reverse", "Score", "None", "Two"),
    ("WithExclusion", "Adjacent", "Score", "Twenty", "Unset"),
    ("Repeated", "Gap", "Score", "None", "Two"),
    ("Single", "Reverse", "Score", "None", "Two"),
];

#[test]
fn pairwise_query_placement_sort_padding_and_depth() {
    for (shape, placement, sort, padding, depth) in PAIRWISE {
        let row = format!("{shape} {placement} {sort} {padding} {depth}");
        let (first, second) = if shape == "Repeated" {
            ("a", "a")
        } else {
            ("a", "b")
        };
        let query = match shape {
            "Single" => "a".to_string(),
            "PairAB" | "Repeated" => format!("{first} {second}"),
            "Phrase" => format!("\"{first} {second}\""),
            "WithExclusion" => "a -zzz b".to_string(),
            _ => unreachable!(),
        };
        let (mut title, body) = match placement {
            "Adjacent" => (format!("{first} {second}"), "x".to_string()),
            "Gap" => (format!("{first} pad pad {second}"), "x".to_string()),
            "Reverse" => (format!("{second} {first}"), "x".to_string()),
            "CrossField" => (first.to_string(), second.to_string()),
            _ => unreachable!(),
        };
        if padding == "Twenty" {
            title = format!("{} {title} {}", repeat("pad", 10), repeat("pad", 10));
        }
        let index = small_corpus(&[
            ("older", title.clone(), body.clone(), 1),
            ("target", title.clone(), body.clone(), 2),
            ("newer", title, body, 3),
        ]);
        // Reference: which documents match and what each scores.
        let matches = shape != "Phrase" || placement == "Adjacent";
        let adjacent = match shape {
            "PairAB" | "Phrase" => placement == "Adjacent",
            "Repeated" => matches!(placement, "Adjacent" | "Reverse"),
            _ => false,
        };
        let expected_score = match shape {
            "Single" => occurrence_weight(1),
            "Repeated" => 2.0 * occurrence_weight(2) + adjacency_weight(usize::from(adjacent)),
            _ => 2.0 * occurrence_weight(1) + adjacency_weight(usize::from(adjacent)),
        };
        let options = SearchOptions {
            order: if sort == "Score" {
                SearchOrder::ScoreDescending
            } else {
                SearchOrder::CreationDescending
            },
            retrieval_depth: (depth == "Two").then_some(2),
            ..SearchOptions::default()
        };
        let hits = index
            .search(
                &SearchQuery::parse(&query, tokenize_query).unwrap(),
                &options,
            )
            .unwrap();
        let names: Vec<_> = hits
            .iter()
            .map(|hit| hit.path.relative().replace("docs/", ""))
            .collect();
        let expected_names: &[&str] = match (matches, depth) {
            (false, _) => &[],
            (true, "Two") => &["newer", "target"],
            (true, _) => &["newer", "target", "older"],
        };
        assert_eq!(names, expected_names, "{row}");
        for hit in &hits {
            assert!(
                (hit.score - expected_score).abs() < 1e-12,
                "{row}: {} != {expected_score}",
                hit.score
            );
        }
    }
}

// ---- Properties of the ordering model that the recorded orders rely on. ----

fn small_corpus(rows: &[(&str, String, String, i128)]) -> SearchIndex {
    let value = |text: &str| JsonValue::String(text.into());
    let documents = rows
        .iter()
        .map(|(id, title, body, created)| {
            JsonValue::Object(BTreeMap::from([
                ("id".into(), value(id)),
                (
                    "created".into(),
                    JsonValue::Int(i64::try_from(*created).unwrap()),
                ),
                (
                    "fields".into(),
                    JsonValue::Object(BTreeMap::from([
                        ("title".into(), value(title)),
                        ("body".into(), value(body)),
                    ])),
                ),
            ]))
        })
        .collect();
    corpus(&JsonValue::Object(BTreeMap::from([
        ("collection".into(), value("docs")),
        (
            "fields".into(),
            JsonValue::Array(vec![value("title"), value("body")]),
        ),
        ("documents".into(), JsonValue::Array(documents)),
    ])))
    .index
}

fn ranked(index: &SearchIndex, query: &str) -> Vec<(String, f64)> {
    index
        .search(
            &SearchQuery::parse(query, tokenize_query).unwrap(),
            &SearchOptions {
                order: SearchOrder::ScoreDescending,
                ..SearchOptions::default()
            },
        )
        .unwrap()
        .into_iter()
        .map(|hit| (hit.path.relative().replace("docs/", ""), hit.score))
        .collect()
}

fn score_of(index: &SearchIndex, query: &str, id: &str) -> f64 {
    ranked(index, query)
        .into_iter()
        .find(|(name, _)| name == id)
        .unwrap_or_else(|| panic!("{id} did not match {query:?}"))
        .1
}

fn repeat(word: &str, count: usize) -> String {
    vec![word; count].join(" ")
}

#[test]
fn equal_scores_keep_newest_first_then_path_order() {
    let index = small_corpus(&[
        ("b", "fox".into(), "x".into(), 5),
        ("a", "fox".into(), "x".into(), 5),
        ("c", "fox".into(), "x".into(), 9),
        ("d", "fox".into(), "x".into(), 1),
    ]);
    let names: Vec<_> = ranked(&index, "fox").into_iter().map(|(n, _)| n).collect();
    assert_eq!(names, ["c", "a", "b", "d"]);
}

#[test]
fn adjacency_counts_only_in_query_order_within_one_field() {
    let index = small_corpus(&[
        ("exact", "cedar plum".into(), "x".into(), 1),
        ("gap1", "cedar pad plum".into(), "x".into(), 2),
        ("gap3", "cedar pad pad pad plum".into(), "x".into(), 3),
        ("reverse", "plum cedar".into(), "x".into(), 4),
        ("cross", "cedar".into(), "plum".into(), 5),
    ]);
    let s = |id| score_of(&index, "cedar plum", id);
    assert!(s("exact") > s("gap1"));
    for id in ["gap3", "reverse", "cross"] {
        assert_eq!(s(id).to_bits(), s("gap1").to_bits(), "{id}");
    }
    let r = |id| score_of(&index, "plum cedar", id);
    assert!(r("reverse") > r("exact"));
    assert_eq!(r("exact").to_bits(), r("gap1").to_bits());
}

#[test]
fn exclusions_break_query_adjacency() {
    let index = small_corpus(&[
        ("adjacent", "cedar plum".into(), "x".into(), 1),
        ("apart", "cedar pad plum".into(), "x".into(), 2),
    ]);
    let s = |id| score_of(&index, "cedar -zzz plum", id);
    assert_eq!(s("adjacent").to_bits(), s("apart").to_bits());
}

proptest::proptest! {
    #![proptest_config(proptest::prelude::ProptestConfig::with_cases(64))]

    #[test]
    fn more_occurrences_never_lower_a_single_term_score(
        tf in 1usize..24,
        extra in 1usize..8,
        padding in 0usize..30,
        in_body in proptest::bool::ANY,
    ) {
        let more = repeat("cedar", tf + extra);
        let (title, body) = if in_body { ("x".to_string(), more) } else { (more, "x".to_string()) };
        let index = small_corpus(&[
            ("few", format!("{} {}", repeat("cedar", tf), repeat("pad", padding)), "x".into(), 1),
            ("many", title, body, 2),
        ]);
        proptest::prop_assert!(score_of(&index, "cedar", "many") > score_of(&index, "cedar", "few"));
    }

    #[test]
    fn scores_ignore_padding_and_the_rest_of_the_corpus(
        tf in 1usize..12,
        padding in 0usize..40,
        others in proptest::collection::vec("[a-c]{1,3}( [a-c]{1,3}){0,4}", 0..6),
    ) {
        let mut rows = vec![
            ("base", repeat("cedar", tf), "x".to_string(), 0),
            ("padded", format!("{} {}", repeat("pad", padding), repeat("cedar", tf)), "y".to_string(), 1),
        ];
        let alone = small_corpus(&rows);
        let names: Vec<String> = (0..others.len()).map(|i| format!("o{i}")).collect();
        for (i, text) in others.iter().enumerate() {
            rows.push((names[i].as_str(), format!("{text} cedar"), "x".into(), 10 + i128::try_from(i).unwrap()));
        }
        let crowded = small_corpus(&rows);
        let base = score_of(&alone, "cedar", "base");
        proptest::prop_assert_eq!(score_of(&alone, "cedar", "padded").to_bits(), base.to_bits());
        proptest::prop_assert_eq!(score_of(&crowded, "cedar", "base").to_bits(), base.to_bits());
    }

    #[test]
    fn one_ordered_adjacency_outranks_one_more_occurrence(tf in 1usize..16, pairs in 1usize..6) {
        // `adjacent` has `pairs` ordered pairs; `apart` has one fewer pair but one more cedar.
        let adjacent = format!("{} {}", repeat("cedar plum", pairs), repeat("cedar", tf));
        let apart = format!("{} pad plum {}", repeat("cedar plum", pairs - 1), repeat("cedar", tf + 1));
        let index = small_corpus(&[("adjacent", adjacent, "x".into(), 1), ("apart", apart, "x".into(), 2)]);
        proptest::prop_assert!(score_of(&index, "cedar plum", "adjacent") > score_of(&index, "cedar plum", "apart"));
    }

    #[test]
    fn more_ordered_adjacencies_never_lower_the_score(pairs in 0usize..10, extra in 1usize..4) {
        let many_pairs = repeat("cedar plum", pairs + extra);
        // Same occurrence counts; `broken` splits `extra` of the pairs apart with padding.
        let broken = (0..pairs + extra)
            .map(|i| if i < extra { "cedar pad plum" } else { "cedar plum" })
            .collect::<Vec<_>>()
            .join(" ");
        let index = small_corpus(&[("many", many_pairs, "x".into(), 1), ("broken", broken, "x".into(), 2)]);
        proptest::prop_assert!(score_of(&index, "cedar plum", "many") > score_of(&index, "cedar plum", "broken"));
    }
}

/// Review S6: scoring once recomputed document frequency for every candidate, so a term present
/// in every document took quadratic time (1.79 s for 20k documents in a release build). Scoring
/// now uses only the candidate's own postings; the budget leaves ample room for debug builds.
#[test]
fn scoring_a_common_term_over_many_documents_stays_linear() {
    let rows: Vec<(String, String)> = (0..20_000)
        .map(|i| (format!("d{i:05}"), format!("cedar plum w{}", i % 97)))
        .collect();
    let borrowed: Vec<(&str, String, String, i128)> = rows
        .iter()
        .enumerate()
        .map(|(i, (id, title))| {
            (
                id.as_str(),
                title.clone(),
                "x".to_string(),
                i128::try_from(i).unwrap(),
            )
        })
        .collect();
    let index = small_corpus(&borrowed);
    let started = std::time::Instant::now();
    let hits = ranked(&index, "cedar plum");
    let elapsed = started.elapsed();
    assert_eq!(hits.len(), 20_000);
    assert!(
        elapsed < std::time::Duration::from_secs(3),
        "scoring 20k documents took {elapsed:?}"
    );
}

/// The retained legacy `field:"phrase"` restriction limits both occurrences and adjacency to
/// the named field; a pair counts only in a field that both of its clauses allow.
#[test]
fn field_restrictions_limit_occurrences_and_adjacency() {
    let index = small_corpus(&[("d", "cedar plum".into(), "cedar cedar cedar plum".into(), 1)]);
    let title_only = score_of(&index, "title:\"cedar\"", "d");
    assert_eq!(title_only.to_bits(), occurrence_weight(1).to_bits());
    let split = score_of(&index, "title:\"cedar\" body:\"plum\"", "d");
    assert_eq!(split.to_bits(), (2.0 * occurrence_weight(1)).to_bits());
    let both = score_of(&index, "cedar plum", "d");
    assert_eq!(
        both.to_bits(),
        (occurrence_weight(4) + occurrence_weight(2) + adjacency_weight(2)).to_bits()
    );
}
