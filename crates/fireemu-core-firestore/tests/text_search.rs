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
    assert_eq!(names(&index, "red -title:fox"), ["docs/b"]);
    assert_eq!(names(&index, "title:red body:fox"), ["docs/b"]);
    assert!(index
        .search(
            &SearchQuery::parse("missing:red", tokenize).unwrap(),
            &SearchOptions::default()
        )
        .is_err());
    assert_eq!(index.document_count(), 3);
    assert!(index.retained_bytes() > 100);
}
#[test]
fn malformed_and_unsupported_queries_are_errors() {
    for query in [
        "red OR fox",
        "red|fox",
        "(red)",
        "red*",
        "\"red",
        "title:",
        "red\"fox\"",
        "title:\"red\"fox",
        "red:fox:jump",
    ] {
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
fn match_none_preserves_query_bounds_and_rejects_mixed_or_structured_tokenless_clauses() {
    let index = SearchIndex::build(
        &definition(),
        &[document("cedar", "nebula", "", 1)],
        tokenize,
    )
    .unwrap();
    for query in [
        "nebula !!!",
        "!!! nebula",
        "-nebula !!!",
        "title:!!!",
        "\"!!!\"",
        "-",
        "()",
        "*",
    ] {
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
