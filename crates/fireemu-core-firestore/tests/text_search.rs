//! Lexical-v1 contract and bounded property tests.
use fireemu_adapter_support::lexical::{tokenize_index as tokenize, tokenize_query};
#[test]
fn unicode_normalization_and_casefold() {
    assert_eq!(
        tokenize("Ｓtraße CAFÉ cafe\u{301} 東京"),
        ["strasse", "cafe", "cafe", "東", "京"]
    );
}
use fireemu_core_firestore::{
    field_path::FieldPath, index::IndexQueryScope, path::DocumentPath, text_index::*,
    text_search::*, value::Value,
};
use fireemu_core_types::{
    ids::{CollectionId, DatabaseId, ProjectId},
    time::LogicalInstant,
};
use std::collections::BTreeMap;
fn definition() -> TextIndexDefinition {
    TextIndexDefinition {
        id: "lexical".into(),
        collection_id: CollectionId::try_new("docs").unwrap(),
        query_scope: IndexQueryScope::Collection,
        api_scope: "ANY_API".into(),
        fields: ["title", "body"]
            .into_iter()
            .map(|p| TextIndexedField {
                path: FieldPath::parse(p).unwrap(),
                index_type: TextIndexType::Tokenized,
                match_type: TextMatchType::MatchGlobally,
            })
            .collect(),
        language: DefaultTextLanguage::Autodetect,
        language_override: LanguageOverridePolicy::Disabled,
        state: TextIndexState::Ready,
    }
}
fn document(id: &str, title: &str, body: &str, time: i128) -> SearchDocument {
    SearchDocument {
        path: DocumentPath::parse(
            &ProjectId::try_new("demo-app").unwrap(),
            &DatabaseId::try_new("(default)").unwrap(),
            &format!("docs/{id}"),
        )
        .unwrap(),
        fields: BTreeMap::from([
            ("title".into(), Value::String(title.into())),
            ("body".into(), Value::String(body.into())),
        ]),
        created_at: LogicalInstant::from_nanos(time),
    }
}
fn names(index: &SearchIndex, query: &str) -> Vec<String> {
    index
        .search(
            &SearchQuery::parse(query, tokenize_query).unwrap(),
            &SearchOptions::default(),
        )
        .unwrap()
        .into_iter()
        .map(|h| h.path.relative())
        .collect()
}

#[test]
fn production_text_boundary_membership_matches_both_finite_rounds() {
    use fireemu_core_types::json::{parse, JsonValue};
    fn array(value: &JsonValue) -> &[JsonValue] {
        let JsonValue::Array(values) = value else {
            panic!("expected fixture array");
        };
        values
    }
    fn string<'a>(value: &'a JsonValue, key: &str) -> &'a str {
        value.get(key).unwrap().as_str().unwrap()
    }
    // Only synthetic text and Boolean membership are observed here; scores and rank are unresolved.
    let fixture = parse(include_str!("fixtures/production_text_boundary.json")).unwrap();
    let docs: Vec<_> = array(fixture.get("documents").unwrap())
        .iter()
        .map(|row| {
            document(
                string(row, "id"),
                string(row, "title"),
                string(row, "body"),
                1,
            )
        })
        .collect();
    assert_eq!(docs.len(), 9);
    let mut definition = definition();
    definition.language = DefaultTextLanguage::Tag("en".into());
    let index = SearchIndex::build(&definition, &docs, tokenize).unwrap();
    let rounds = array(fixture.get("rounds").unwrap());
    assert_eq!(rounds.len(), 2);
    let mut cells = 0;
    for round in rounds {
        let queries = array(round);
        assert_eq!(queries.len(), 13);
        for row in queries {
            let query = string(row, "query");
            let actual = names(&index, query);
            let expected = array(row.get("members").unwrap());
            for doc in &docs {
                let id = doc.path.relative();
                let expected_member = expected
                    .iter()
                    .any(|member| format!("docs/{}", member.as_str().unwrap()) == id);
                assert_eq!(
                    actual.contains(&id),
                    expected_member,
                    "query={query:?}, doc={id}"
                );
                cells += 1;
            }
        }
    }
    assert_eq!(cells, 234);
}

fn composition_corpus(first: &str, second: &str, in_body: bool) -> Vec<SearchDocument> {
    [
        ("forward", format!("{first}{second}"), String::new()),
        ("reverse", format!("{second}{first}"), String::new()),
        ("repeated", format!("{first}{second}{first}"), String::new()),
        ("separated", format!("{first} {second}"), String::new()),
        ("backwards", format!("{second} {first}"), String::new()),
        ("gap", format!("{first} spacer {second}"), String::new()),
        ("cross", first.into(), second.into()),
        (
            "substring",
            format!("prefix{first}{second}suffix"),
            String::new(),
        ),
        ("single", first.into(), String::new()),
    ]
    .into_iter()
    .map(|(id, title, body)| {
        if in_body {
            document(id, &body, &title, 1)
        } else {
            document(id, &title, &body, 1)
        }
    })
    .collect()
}

fn composition_case(syntax: &str, order: &str, placement: &str) {
    let terms = match order {
        "forward" => "larch quartz",
        "reverse" => "quartz larch",
        "repeated" => "larch quartz larch",
        _ => panic!("unknown order"),
    };
    let query = match syntax {
        "plain" => terms.to_owned(),
        "punctuation" => terms.replace(' ', ","),
        "quoted" => format!("\"{terms}\""),
        "excluded" => format!("{terms} -absent"),
        "mixed" => {
            let (first, rest) = terms.split_once(' ').unwrap();
            format!("\"{first}\" {rest}")
        }
        "colon" => terms.replace(' ', ":"),
        "contextual_or" => terms.replace(' ', " OR "),
        "unmatched_quote" => format!("\"{terms}"),
        _ => panic!("unknown syntax"),
    };
    let index = SearchIndex::build(
        &definition(),
        &composition_corpus("larch", "quartz", placement == "body"),
        tokenize,
    )
    .unwrap();
    let mut expected = if syntax == "quoted" {
        match order {
            "forward" => vec!["docs/separated"],
            "reverse" => vec!["docs/backwards"],
            _ => vec![],
        }
    } else {
        vec!["docs/backwards", "docs/cross", "docs/gap", "docs/separated"]
    };
    if matches!(syntax, "plain" | "punctuation") {
        expected.push(match order {
            "forward" => "docs/forward",
            "reverse" => "docs/reverse",
            _ => "docs/repeated",
        });
    }
    expected.sort_unstable();
    assert_eq!(
        names(&index, &query),
        expected,
        "{syntax}/{order}/{placement}: {query}"
    );
}

#[test]
fn plain_composition_and_legacy_grammar_follow_the_membership_table() {
    // A private PICT table can select rows; the default covers the entire finite grammar table.
    if let Ok(path) = std::env::var("FIREEMU_TEXT_MEMBERSHIP_CASES") {
        let table = std::fs::read_to_string(path).unwrap();
        for line in table.lines().skip(1) {
            let cells: Vec<_> = line.split('\t').collect();
            assert_eq!(cells.len(), 3);
            composition_case(cells[0], cells[1], cells[2]);
        }
    } else {
        for syntax in [
            "plain",
            "punctuation",
            "quoted",
            "excluded",
            "mixed",
            "colon",
            "contextual_or",
            "unmatched_quote",
        ] {
            for order in ["forward", "reverse", "repeated"] {
                for placement in ["title", "body"] {
                    composition_case(syntax, order, placement);
                }
            }
        }
    }
}

#[test]
fn composition_candidates_precede_depth_and_pagination_without_new_score_rules() {
    let docs = [
        document("old", "larch quartz", "", 1),
        document("new", "larchquartz", "", 2),
        document("partial", "larchquartz", "larch", 0),
    ];
    let index = SearchIndex::build(&definition(), &docs, tokenize).unwrap();
    let query = SearchQuery::parse("larch quartz", tokenize_query).unwrap();
    let hits = index
        .search(
            &query,
            &SearchOptions {
                retrieval_depth: Some(1),
                order: SearchOrder::ScoreDescending,
                ..SearchOptions::default()
            },
        )
        .unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].path.relative(), "docs/new");
    assert_eq!(hits[0].score.to_bits(), 0.0_f64.to_bits());
    let partial_score = |query| {
        index
            .search(
                &SearchQuery::parse(query, tokenize_query).unwrap(),
                &SearchOptions::default(),
            )
            .unwrap()
            .into_iter()
            .find(|hit| hit.path.relative() == "docs/partial")
            .unwrap()
            .score
    };
    assert!(partial_score("larch quartz") > 0.0);
    assert_eq!(
        partial_score("larch quartz").to_bits(),
        partial_score("larch").to_bits()
    );
    let page = index
        .search(
            &query,
            &SearchOptions {
                offset: 1,
                limit: Some(1),
                ..SearchOptions::default()
            },
        )
        .unwrap();
    assert_eq!(page[0].path.relative(), "docs/old");
    assert!(index
        .search(
            &query,
            &SearchOptions {
                retrieval_depth: Some(0),
                ..SearchOptions::default()
            }
        )
        .unwrap()
        .is_empty());
    assert!(names(&index, "larch").iter().all(|id| id != "docs/new"));
    assert!(SearchQuery::parse(&"larch ".repeat(MAX_QUERY_CLAUSES + 1), tokenize_query).is_err());
    assert!(SearchQuery::parse(
        &format!("larch {}", "q".repeat(MAX_QUERY_BYTES)),
        tokenize_query
    )
    .is_err());
}

proptest::proptest! {
    #[test]
    fn composition_is_independent_of_word_spelling(first in "[a-n]{2,6}", second in "[p-z]{2,6}", in_body in proptest::bool::ANY) {
        let index = SearchIndex::build(&definition(), &composition_corpus(&first, &second, in_body), tokenize).unwrap();
        let expected = vec!["docs/backwards", "docs/cross", "docs/forward", "docs/gap", "docs/separated"];
        proptest::prop_assert_eq!(names(&index, &format!("{first} {second}")), expected);
        proptest::prop_assert_eq!(names(&index, &format!("\"{first} {second}\"")), vec!["docs/separated"]);
        proptest::prop_assert_eq!(names(&index, &format!("{first} {first}")), vec!["docs/backwards", "docs/cross", "docs/gap", "docs/separated", "docs/single"]);
    }
}
#[test]
fn positional_phrases_do_not_cross_fields_and_exclusions_apply() {
    let docs = [
        document("a", "red fox", "jumps", 1),
        document("b", "red", "fox jumps", 2),
        document("c", "fox red", "jumps", 3),
    ];
    let index = SearchIndex::build(&definition(), &docs, tokenize).unwrap();
    assert_eq!(names(&index, "red fox"), ["docs/c", "docs/b", "docs/a"]);
    assert_eq!(names(&index, "\"red fox\""), ["docs/a"]);
    assert_eq!(names(&index, "red -\"red fox\""), ["docs/c", "docs/b"]);
    assert!(names(&index, "title:red body:fox").is_empty());
    assert!(index
        .search(
            &SearchQuery::parse("missing:\"red\"", tokenize_query).unwrap(),
            &SearchOptions::default()
        )
        .is_err());
    assert_eq!(index.document_count(), 3);
    assert!(index.retained_bytes() > 100);
}
#[test]
fn malformed_and_unsupported_queries_are_errors() {
    for query in ["red|fox", "(red)", "red*", "red\"fox\"", "title:\"red\"fox"] {
        assert!(
            SearchQuery::parse(query, tokenize_query).is_err(),
            "{query}"
        );
    }
    assert!(SearchQuery::parse(&"x ".repeat(65), tokenize_query).is_err());
    assert!(SearchQuery::parse(&"x".repeat(MAX_QUERY_BYTES + 1), tokenize_query).is_err());
}
#[test]
fn rebuild_reconciles_updates_and_deletes() {
    let initial = document("a", "red fox", "", 1);
    let old = SearchIndex::build(&definition(), &[initial], tokenize).unwrap();
    let fresh =
        SearchIndex::build(&definition(), &[document("a", "blue fox", "", 2)], tokenize).unwrap();
    assert_eq!(names(&old, "red").len(), 1);
    assert!(names(&fresh, "red").is_empty());
    assert!(names(
        &SearchIndex::build(&definition(), &[], tokenize).unwrap(),
        "fox"
    )
    .is_empty());
}
#[test]
fn retrieval_depth_precedes_score_ranking_and_pagination() {
    let docs = [
        document("a", "fox", "", 1),
        document("b", "fox extra extra extra extra", "", 3),
        document("c", "fox", "", 2),
    ];
    let index = SearchIndex::build(&definition(), &docs, tokenize).unwrap();
    let query = SearchQuery::parse("fox", tokenize_query).unwrap();
    let options = SearchOptions {
        order: SearchOrder::ScoreDescending,
        retrieval_depth: Some(2),
        offset: 1,
        limit: Some(1),
    };
    let hits = index.search(&query, &options).unwrap();
    assert_eq!(hits[0].path.relative(), "docs/b");
    assert!(hits[0].score.is_finite() && hits[0].score > 0.0);
}
#[test]
fn language_overrides_are_validated_and_non_strings_are_ignored() {
    let mut def = definition();
    def.language_override = LanguageOverridePolicy::ImplicitLanguageField;
    let mut doc = document("a", "fox", "", 1);
    doc.fields
        .insert("language".into(), Value::String("not a tag".into()));
    assert!(SearchIndex::build(&def, &[doc.clone()], tokenize).is_err());
    doc.fields
        .insert("language".into(), Value::String("ja".into()));
    doc.fields.insert("title".into(), Value::Integer(1));
    assert!(names(&SearchIndex::build(&def, &[doc], tokenize).unwrap(), "fox").is_empty());
}
proptest::proptest! {
 #[test]
 fn conjunction_is_commutative_and_phrase_is_subset(a in "[a-z]{1,12}", b in "[a-z]{1,12}") {
  proptest::prop_assume!(a != "or" && b != "or");
  let docs=[document("a",&format!("{a} {b}"),"",1),document("b",&b,&a,2)]; let index=SearchIndex::build(&definition(),&docs, tokenize).unwrap();
  proptest::prop_assert_eq!(names(&index,&format!("{a} {b}")),names(&index,&format!("{b} {a}")));
  for hit in names(&index,&format!("\"{a} {b}\"")) {let contains=names(&index,&format!("{a} {b}")).contains(&hit);proptest::prop_assert!(contains);}
 }
 #[test]
 fn arbitrary_unicode_never_panics(input in ".*") {let _=SearchQuery::parse(&input, tokenize_query);let _=tokenize(&input);}
}

#[test]
fn nested_canonical_paths_duplicates_and_creation_ties() {
    let mut def = definition();
    def.fields[0].path = FieldPath::parse("nested.`display name`").unwrap();
    let mut a = document("a", "ignored", "", 1);
    a.fields.insert(
        "nested".into(),
        Value::Map(BTreeMap::from([(
            "display name".into(),
            Value::String("red fox".into()),
        )])),
    );
    let mut b = a.clone();
    b.path = document("b", "", "", 1).path;
    let index = SearchIndex::build(&def, &[b, a.clone()], tokenize).unwrap();
    assert_eq!(
        names(&index, "nested.`display name`:\"red fox\""),
        ["docs/a", "docs/b"]
    );
    assert!(SearchIndex::build(&def, &[a.clone(), a], tokenize).is_err());
}

proptest::proptest! {
    #[test]
    fn postings_match_a_reference_set_intersection(rows in proptest::collection::vec((proptest::bool::ANY, proptest::bool::ANY, proptest::bool::ANY), 0..40)) {
        let docs:Vec<_> = rows.iter().enumerate().map(|(i,(red,fox,blue))| document(&format!("d{i:02}"),if *red {"red"} else {""}, &format!("{} {}", if *fox {"fox"} else {""}, if *blue {"blue"} else {""}),i128::try_from(i).unwrap())).collect();
        let index=SearchIndex::build(&definition(),&docs, tokenize).unwrap();
        let expected:Vec<_>=rows.iter().enumerate().rev().filter(|(_, (red,fox,blue))| *red && *fox && !*blue).map(|(i,_)|format!("docs/d{i:02}")).collect();
        proptest::prop_assert_eq!(names(&index,"red fox -blue"),expected);
    }
}

#[test]
fn incremental_batches_equal_full_build_and_rejections_are_atomic() {
    let def = definition();
    let a = document("a", "red fox", "", 1);
    let b = document("b", "red", "fox", 2);
    let full = SearchIndex::build(&def, &[a.clone(), b.clone()], tokenize).unwrap();
    let mut batches = SearchIndex::build(&def, &[], tokenize).unwrap();
    batches
        .extend(&def, std::slice::from_ref(&a), tokenize)
        .unwrap();
    batches.extend(&def, &[b], tokenize).unwrap();
    assert_eq!(batches, full);
    assert_eq!(
        batches
            .search(
                &SearchQuery::parse("red fox", tokenize_query).unwrap(),
                &SearchOptions::default()
            )
            .unwrap(),
        full.search(
            &SearchQuery::parse("red fox", tokenize_query).unwrap(),
            &SearchOptions::default()
        )
        .unwrap()
    );
    let before = batches.clone();
    assert!(batches
        .extend(&def, &[document("c", "new", "", 3), a], tokenize)
        .is_err());
    assert_eq!(batches, before);
    let mut invalid = document("z", "new", "", 4);
    invalid.fields.insert("language".into(), Value::Integer(1));
    let mut override_def = def;
    override_def.language_override = LanguageOverridePolicy::ImplicitLanguageField;
    assert!(batches
        .extend(
            &override_def,
            &[document("d", "new", "", 3), invalid],
            tokenize
        )
        .is_err());
    assert_eq!(batches, before);
}

#[test]
fn exclusion_only_queries_match_no_documents() {
    let docs = [
        document("copper", "nebula", "", 1),
        document("willow", "quartz mica", "", 2),
        document("blank", "", "", 3),
    ];
    let index = SearchIndex::build(&definition(), &docs, tokenize).unwrap();
    for query in ["-nebula", "-absent", "-\"quartz mica\"", "-nebula -mica"] {
        assert!(names(&index, query).is_empty(), "{query}");
    }
    assert_eq!(names(&index, "quartz -nebula"), ["docs/willow"]);
    assert!(names(&index, "quartz -mica").is_empty());
}

#[test]
fn empty_and_whole_plain_tokenless_queries_match_no_documents() {
    let docs = [
        document("juniper", "nebula quartz", "mica", 1),
        document("alder", "copper", "nebula", 2),
        document("blank", "", "", 3),
    ];
    let index = SearchIndex::build(&definition(), &docs, tokenize).unwrap();
    for query in ["", " \t\n", "!!!", "! . , ;", "… —"] {
        assert!(names(&index, query).is_empty(), "{query:?}");
    }
    assert_eq!(names(&index, "nebula"), ["docs/alder", "docs/juniper"]);
}

#[test]
fn match_none_preserves_query_bounds_and_rejects_structured_tokenless_clauses() {
    let index = SearchIndex::build(
        &definition(),
        &[document("cedar", "nebula", "", 1)],
        tokenize,
    )
    .unwrap();
    for query in ["title:\"!!!\"", "\"!!!\"", "-", "()", "*"] {
        assert!(
            SearchQuery::parse(query, tokenize_query).is_err(),
            "{query}"
        );
    }
    assert!(names(&index, &"!".repeat(MAX_QUERY_BYTES)).is_empty());
    assert!(SearchQuery::parse(&"!".repeat(MAX_QUERY_BYTES + 1), tokenize_query).is_err());
    assert!(names(&index, &vec!["!!!"; MAX_QUERY_CLAUSES].join(" ")).is_empty());
    assert!(SearchQuery::parse(
        &vec!["!!!"; MAX_QUERY_CLAUSES + 1].join(" "),
        tokenize_query
    )
    .is_err());
    assert!(names(&index, &vec!["-nebula"; MAX_QUERY_CLAUSES].join(" ")).is_empty());
    assert!(SearchQuery::parse(
        &vec!["-nebula"; MAX_QUERY_CLAUSES + 1].join(" "),
        tokenize_query
    )
    .is_err());
}

proptest::proptest! {
    #[test]
    fn no_positive_plain_queries_never_match_an_arbitrary_nonempty_corpus(
        rows in proptest::collection::vec("[a-z]{1,12}", 1..8),
        punctuation in proptest::collection::vec(proptest::sample::select(vec!["!", ".", ",", ";", "…"]), 0..=MAX_QUERY_CLAUSES),
    ) {
        let docs: Vec<_> = rows.iter().enumerate().map(|(i, word)| document(&format!("sample{i}"), word, "", i128::try_from(i).unwrap())).collect();
        let index = SearchIndex::build(&definition(), &docs, tokenize).unwrap();
        proptest::prop_assert!(names(&index, &punctuation.join(" ")).is_empty());
        proptest::prop_assert!(names(&index, "-nebula -quartz").is_empty());
    }
}

#[test]
fn unquoted_colons_delimit_conjunctive_terms_without_field_scoping() {
    let docs = [
        document("oak", "moss", "nebula title", 1),
        document("elm", "title gap nebula", "", 2),
        document("fir", "nebula", "", 3),
        document("ash", "body nebula", "", 4),
        document("pine", "title", "", 5),
        document("cedar", "irrelevant", "nebula", 6),
    ];
    let index = SearchIndex::build(&definition(), &docs, tokenize).unwrap();
    for query in ["title:nebula", "title : nebula", "title nebula"] {
        assert_eq!(names(&index, query), ["docs/elm", "docs/oak"], "{query}");
    }
    assert_eq!(names(&index, "body:nebula"), ["docs/ash"]);
    assert!(names(&index, "unknown:nebula").is_empty());
    assert!(SearchQuery::parse("unknown:nebula", tokenize_query)
        .unwrap()
        .is_covered_by(&definition()));
}

#[test]
fn a_leading_unmatched_quote_is_a_conjunction_not_an_eof_phrase() {
    let docs = [
        document("copper", "cedar amber", "", 1),
        document("silver", "cedar spacer amber", "", 2),
        document("iron", "cedar", "amber", 3),
        document("gold", "amber cedar", "", 4),
    ];
    let index = SearchIndex::build(&definition(), &docs, tokenize).unwrap();
    assert_eq!(names(&index, "\"cedar amber"), names(&index, "cedar amber"));
    assert_eq!(
        names(&index, " \t\"cedar amber"),
        ["docs/gold", "docs/iron", "docs/silver", "docs/copper"]
    );
    assert_eq!(names(&index, "\"cedar amber\""), ["docs/copper"]);
    assert!(names(&index, "\"").is_empty());
    for query in [
        "cedar\"",
        "\"cedar\" amber\"",
        "cedar \"amber",
        "-\"cedar amber",
        "\"\"",
    ] {
        assert!(
            SearchQuery::parse(query, tokenize_query).is_err(),
            "{query}"
        );
    }
}

#[test]
fn contextual_or_is_conjunctive_while_standalone_or_is_searchable() {
    let docs = [
        document("argile", "cedar amber", "", 1),
        document("dolomite", "cedar", "", 2),
        document("granite", "amber", "", 3),
        document("chalk", "or", "", 4),
        document("slate", "cedar or amber", "", 5),
    ];
    let index = SearchIndex::build(&definition(), &docs, tokenize).unwrap();
    for query in ["cedar OR amber", "cedar or amber"] {
        assert_eq!(
            names(&index, query),
            ["docs/slate", "docs/argile"],
            "{query}"
        );
    }
    for query in ["OR", "or"] {
        assert_eq!(names(&index, query), ["docs/slate", "docs/chalk"]);
    }
    for query in [
        "OR cedar",
        "cedar OR",
        "or cedar",
        "cedar or",
        "cedar OR -amber",
        "-cedar OR amber",
        "cedar !!! OR amber",
        "cedar OR OR amber",
    ] {
        assert!(
            SearchQuery::parse(query, tokenize_query).is_err(),
            "{query}"
        );
    }
}

#[test]
fn plain_tokenless_fragments_are_ignored_but_still_count_toward_bounds() {
    let docs = [
        document("mauve", "cedar amber", "", 1),
        document("ochre", "cedar", "", 2),
    ];
    let index = SearchIndex::build(&definition(), &docs, tokenize).unwrap();
    for query in ["cedar !!!", "!!! cedar", "!!! cedar !!!"] {
        assert_eq!(names(&index, query), names(&index, "cedar"));
    }
    assert_eq!(names(&index, "cedar !!! -amber"), ["docs/ochre"]);
    assert!(names(&index, "-cedar !!!").is_empty());
    let at_limit = format!("{} cedar", vec!["!!!"; MAX_QUERY_CLAUSES - 1].join(" "));
    assert_eq!(names(&index, &at_limit), names(&index, "cedar"));
    assert!(SearchQuery::parse(&format!("!!! {at_limit}"), tokenize_query).is_err());
    assert!(SearchQuery::parse(&vec!["cedar"; 32].join(" OR "), tokenize_query).is_ok());
    assert!(SearchQuery::parse(&vec!["cedar"; 33].join(" OR "), tokenize_query).is_err());
}

proptest::proptest! {
    #[test]
    fn bounded_native_parser_forms_match_conjunctions_on_arbitrary_corpora(
        rows in proptest::collection::vec((proptest::bool::ANY, proptest::bool::ANY, proptest::bool::ANY), 1..12)
    ) {
        let docs: Vec<_> = rows.iter().enumerate().map(|(i, (left, right, literal_or))| document(&format!("synthetic{i}"), &format!("{} {}", if *left { "cedar" } else { "" }, if *literal_or { "or" } else { "" }), if *right { "amber" } else { "" }, i128::try_from(i).unwrap())).collect();
        let index = SearchIndex::build(&definition(), &docs, tokenize).unwrap();
        let expected = names(&index, "cedar amber");
        for query in ["cedar:amber", "cedar OR amber", "cedar or amber", "\"cedar amber"] {
            proptest::prop_assert_eq!(names(&index, query), expected.clone());
        }
        proptest::prop_assert_eq!(names(&index, "cedar !!!"), names(&index, "cedar"));
        let expected_or: Vec<_> = rows.iter().enumerate().rev().filter(|(_, (_, _, literal_or))| *literal_or).map(|(i, _)| format!("docs/synthetic{i}")).collect();
        proptest::prop_assert_eq!(names(&index, "OR"), expected_or);
    }
}

#[test]
fn latin_purpose_search_keeps_greek_and_phrase_positions() {
    let docs = [
        document("copper", "İris", "", 1),
        document("silver", "Crème brûlée", "", 2),
        document("jade", "ά", "", 3),
        document("opal", "α", "", 4),
    ];
    let index = SearchIndex::build(&definition(), &docs, tokenize).unwrap();
    assert_eq!(names(&index, "iris"), ["docs/copper"]);
    // Review S8: the indexed text matches a query of itself.
    assert_eq!(names(&index, "İris"), ["docs/copper"]);
    assert_eq!(names(&index, "\"creme brulee\""), ["docs/silver"]);
    assert_eq!(names(&index, "ά"), ["docs/jade"]);
    assert_eq!(names(&index, "α"), ["docs/opal"]);
}

proptest::proptest! {
    #[test]
    fn latin_purpose_membership_ignores_document_names_and_field_placement(
        first in "[a-z]{1,8}", second in "[a-z]{1,8}", in_body in proptest::bool::ANY
    ) {
        proptest::prop_assume!(first != second);
        let docs = [document(&first, if in_body { "" } else { "İris" }, if in_body { "İris" } else { "" }, 1), document(&second, "unrelated", "", 2)];
        let index = SearchIndex::build(&definition(), &docs, tokenize).unwrap();
        proptest::prop_assert_eq!(names(&index, "iris"), vec![format!("docs/{first}")]);
        proptest::prop_assert_eq!(names(&index, "İris"), vec![format!("docs/{first}")]);
    }

    /// Review S8: any indexed word matches a query that repeats it, including Latin letters
    /// whose case folding expands into a base letter and a combining mark.
    #[test]
    fn any_indexed_text_matches_a_query_of_itself(
        letters in proptest::collection::vec(proptest::sample::select(vec![
            "a", "z", "İ", "I", "i", "ẖ", "ǰ", "É", "é", "ß", "ẞ", "Ω", "ά", "東", "ﬁ", "Å", "Ǆ",
        ]), 1..8)
    ) {
        let word: String = letters.concat();
        proptest::prop_assume!(!tokenize(&word).is_empty());
        let docs = [document("self", &word, "", 1), document("other", "unrelated", "", 2)];
        let index = SearchIndex::build(&definition(), &docs, tokenize).unwrap();
        proptest::prop_assert_eq!(names(&index, &format!("\"{word}\"")), vec!["docs/self".to_owned()]);
    }
}
