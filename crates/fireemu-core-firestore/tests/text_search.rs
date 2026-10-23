//! Lexical-v1 contract and bounded property tests.
use fireemu_adapter_support::lexical::tokenize;
#[test]
fn unicode_normalization_and_casefold() {
    assert_eq!(
        tokenize("Ｓtraße CAFÉ cafe\u{301} 東京"),
        ["strasse", "café", "café", "東", "京"]
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
            &SearchQuery::parse(query, tokenize).unwrap(),
            &SearchOptions::default(),
        )
        .unwrap()
        .into_iter()
        .map(|h| h.path.relative())
        .collect()
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
            &SearchQuery::parse("missing:\"red\"", tokenize).unwrap(),
            &SearchOptions::default()
        )
        .is_err());
    assert_eq!(index.document_count(), 3);
    assert!(index.retained_bytes() > 100);
}
#[test]
fn malformed_and_unsupported_queries_are_errors() {
    for query in ["red|fox", "(red)", "red*", "red\"fox\"", "title:\"red\"fox"] {
        assert!(SearchQuery::parse(query, tokenize).is_err(), "{query}");
    }
    assert!(SearchQuery::parse(&"x ".repeat(65), tokenize).is_err());
    assert!(SearchQuery::parse(&"x".repeat(MAX_QUERY_BYTES + 1), tokenize).is_err());
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
    let query = SearchQuery::parse("fox", tokenize).unwrap();
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
 fn arbitrary_unicode_never_panics(input in ".*") {let _=SearchQuery::parse(&input, tokenize);let _=tokenize(&input);}
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
                &SearchQuery::parse("red fox", tokenize).unwrap(),
                &SearchOptions::default()
            )
            .unwrap(),
        full.search(
            &SearchQuery::parse("red fox", tokenize).unwrap(),
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
        assert!(SearchQuery::parse(query, tokenize).is_err(), "{query}");
    }
    assert!(names(&index, &"!".repeat(MAX_QUERY_BYTES)).is_empty());
    assert!(SearchQuery::parse(&"!".repeat(MAX_QUERY_BYTES + 1), tokenize).is_err());
    assert!(names(&index, &vec!["!!!"; MAX_QUERY_CLAUSES].join(" ")).is_empty());
    assert!(SearchQuery::parse(&vec!["!!!"; MAX_QUERY_CLAUSES + 1].join(" "), tokenize).is_err());
    assert!(names(&index, &vec!["-nebula"; MAX_QUERY_CLAUSES].join(" ")).is_empty());
    assert!(
        SearchQuery::parse(&vec!["-nebula"; MAX_QUERY_CLAUSES + 1].join(" "), tokenize).is_err()
    );
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
    assert!(SearchQuery::parse("unknown:nebula", tokenize)
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
        assert!(SearchQuery::parse(query, tokenize).is_err(), "{query}");
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
        assert!(SearchQuery::parse(query, tokenize).is_err(), "{query}");
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
    assert!(SearchQuery::parse(&format!("!!! {at_limit}"), tokenize).is_err());
    assert!(SearchQuery::parse(&vec!["cedar"; 32].join(" OR "), tokenize).is_ok());
    assert!(SearchQuery::parse(&vec!["cedar"; 33].join(" OR "), tokenize).is_err());
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
