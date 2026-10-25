//! Local index lifecycle, real posting data, and scope-preserving snapshot properties.
use fireemu_adapter_support::lexical::{tokenize_index as tokenize, tokenize_query};
use fireemu_core_firestore::{
    field_path::FieldPath,
    index::IndexQueryScope,
    path::DocumentPath,
    store::{CommitVersion, Document},
    text_index::*,
    text_search::{SearchOptions, SearchQuery},
    value::Value,
};
use fireemu_core_types::{
    ids::{CollectionId, DatabaseId, ProjectId},
    time::LogicalInstant,
};
use proptest::prelude::*;
use std::collections::BTreeMap;
fn definition(id: &str) -> TextIndexDefinition {
    TextIndexDefinition {
        id: id.into(),
        collection_id: CollectionId::try_new("products").unwrap(),
        query_scope: IndexQueryScope::Collection,
        api_scope: "ANY_API".into(),
        fields: vec![TextIndexedField {
            path: FieldPath::parse("title").unwrap(),
            index_type: TextIndexType::Tokenized,
            match_type: TextMatchType::MatchGlobally,
        }],
        language: DefaultTextLanguage::Tag("en".into()),
        language_override: LanguageOverridePolicy::Disabled,
        state: TextIndexState::Creating,
    }
}
fn document(id: &str, text: &str) -> Document {
    Document {
        path: DocumentPath::parse(
            &ProjectId::try_new("demo-app").unwrap(),
            &DatabaseId::try_new("(default)").unwrap(),
            &format!("products/{id}"),
        )
        .unwrap(),
        fields: BTreeMap::from([("title".into(), Value::String(text.into()))]),
        create_time: LogicalInstant::UNIX_EPOCH,
        update_time: LogicalInstant::UNIX_EPOCH,
        version: CommitVersion::from_value(1),
    }
}
fn hits(catalog: &TextIndexCatalog, query: &str) -> Vec<String> {
    catalog
        .build("demo-app", "(default)", "text")
        .unwrap()
        .index()
        .unwrap()
        .search(
            &SearchQuery::parse(query, tokenize_query).unwrap(),
            &SearchOptions::default(),
        )
        .unwrap()
        .into_iter()
        .map(|hit| hit.path.relative())
        .collect()
}
#[test]
fn completion_reconciles_writes_instead_of_publishing_stale_backfill_postings() {
    let mut catalog = TextIndexCatalog::default();
    catalog
        .add("demo-app", "(default)", definition("text"))
        .unwrap();
    let original = vec![document("a", "old"), document("b", "removed")];
    let before_bytes = catalog.retained_bytes();
    catalog
        .lifecycle(
            "demo-app",
            "(default)",
            "text",
            "advanceBackfill",
            None,
            1,
            None,
            original.clone(),
            tokenize,
        )
        .unwrap();
    assert_eq!(hits(&catalog, "old"), ["products/a"]);
    assert_eq!(
        catalog
            .build("demo-app", "(default)", "text")
            .unwrap()
            .indexed_documents(),
        1
    );
    assert!(catalog.retained_bytes() > before_bytes);
    let changed = vec![document("a", "updated"), document("c", "inserted")];
    catalog
        .lifecycle(
            "demo-app",
            "(default)",
            "text",
            "advanceBackfill",
            None,
            1,
            None,
            changed.clone(),
            tokenize,
        )
        .unwrap();
    assert_eq!(hits(&catalog, "removed"), ["products/b"]);
    assert_eq!(
        catalog.get("demo-app", "(default)", "text").unwrap().state,
        TextIndexState::Creating
    );
    catalog
        .lifecycle(
            "demo-app",
            "(default)",
            "text",
            "completeBackfill",
            None,
            100,
            None,
            changed,
            tokenize,
        )
        .unwrap();
    assert!(hits(&catalog, "old").is_empty());
    assert!(hits(&catalog, "removed").is_empty());
    assert_eq!(hits(&catalog, "updated"), ["products/a"]);
    assert_eq!(hits(&catalog, "inserted"), ["products/c"]);
}
#[test]
fn failure_repair_source_rejection_and_scope_restore_preserve_independent_builds() {
    let mut catalog = TextIndexCatalog::default();
    for (project, database) in [
        ("demo-app", "(default)"),
        ("demo-other", "(default)"),
        ("demo-app", "named"),
    ] {
        catalog.add(project, database, definition("text")).unwrap();
    }
    catalog
        .lifecycle(
            "demo-app",
            "(default)",
            "text",
            "advanceBackfill",
            None,
            1,
            None,
            vec![document("a", "saved")],
            tokenize,
        )
        .unwrap();
    let captured = catalog.extract(|p| p == "demo-app");
    let generation = catalog
        .build("demo-app", "(default)", "text")
        .unwrap()
        .generation;
    catalog
        .lifecycle(
            "demo-app",
            "(default)",
            "text",
            "failBuild",
            Some(generation),
            100,
            Some("failed"),
            Vec::new(),
            tokenize,
        )
        .unwrap();
    assert!(catalog
        .build("demo-app", "(default)", "text")
        .unwrap()
        .index()
        .is_none());
    catalog
        .lifecycle(
            "demo-app",
            "(default)",
            "text",
            "repair",
            Some(generation),
            100,
            None,
            Vec::new(),
            tokenize,
        )
        .unwrap();
    assert!(
        catalog
            .build("demo-app", "(default)", "text")
            .unwrap()
            .generation
            > generation
    );
    let before = catalog.clone();
    assert_eq!(
        catalog.lifecycle(
            "demo-app",
            "(default)",
            "text",
            "completeBackfill",
            Some(generation),
            100,
            None,
            Vec::new(),
            tokenize
        ),
        Err(TextIndexBuildError::StaleGeneration)
    );
    assert_eq!(catalog, before);
    catalog.replace(|p| p == "demo-app", &captured);
    assert_eq!(hits(&catalog, "saved"), ["products/a"]);
    assert!(catalog.get("demo-other", "(default)", "text").is_some());
    catalog.retain_others(|p| p == "demo-app");
    assert!(catalog.build("demo-app", "(default)", "text").is_none());
    assert!(catalog.build("demo-app", "named", "text").is_none());
    assert!(catalog.build("demo-other", "(default)", "text").is_some());
    assert!(catalog.remove("demo-other", "(default)", "text"));
    assert!(catalog.is_empty());
}
proptest! {
    #[test]
    fn lifecycle_matches_a_three_state_model_and_refusals_are_atomic(actions in prop::collection::vec(0u8..6,0..80)) {
        let mut catalog=TextIndexCatalog::default();catalog.add("demo-app","(default)",definition("text")).unwrap();
        let mut state=TextIndexState::Creating;
        let source=vec![document("a","one"),document("b","two"),document("c","three")];
        for action in actions {
            let before=catalog.clone();let old_gen=catalog.build("demo-app","(default)","text").unwrap().generation;
            let name=match action {0|4=>"advanceBackfill",2=>"failBuild",3=>"repair",_=>"completeBackfill"};
            let valid_state=match name {"advanceBackfill"|"completeBackfill"=>state==TextIndexState::Creating,"failBuild"=>state!=TextIndexState::NeedsRepair,"repair"=>state==TextIndexState::NeedsRepair,_=>false};
            let generation=if action==5 {Some(old_gen+1)} else {Some(old_gen)};
            let batch=usize::from(action != 4);
            let result=catalog.lifecycle("demo-app","(default)","text",name,generation,batch,None,source.clone(),tokenize);
            let expected=valid_state&&action!=4&&action!=5;
            prop_assert_eq!(result.is_ok(),expected);
            if expected {
                state=match name {"completeBackfill"=>TextIndexState::Ready,"failBuild"=>TextIndexState::NeedsRepair,"repair"=>TextIndexState::Creating,_=>state};
                let build=catalog.build("demo-app","(default)","text").unwrap();
                prop_assert!(build.processed<=build.total.unwrap_or(0));
                if name=="repair" {prop_assert!(build.generation>old_gen);}
                if state==TextIndexState::NeedsRepair {prop_assert!(build.index().is_none());}
            } else {prop_assert_eq!(&catalog,&before);}
            prop_assert_eq!(catalog.get("demo-app","(default)","text").unwrap().state,state);
        }
    }
}

#[test]
fn backfill_rejects_documents_outside_its_catalog_scope_atomically() {
    let mut catalog = TextIndexCatalog::default();
    catalog
        .add("demo-app", "(default)", definition("text"))
        .unwrap();
    for (project, database, relative) in [
        ("demo-other", "(default)", "products/a"),
        ("demo-app", "named", "products/a"),
        ("demo-app", "(default)", "others/a"),
    ] {
        let mut source = document("a", "text");
        source.path = DocumentPath::parse(
            &ProjectId::try_new(project).unwrap(),
            &DatabaseId::try_new(database).unwrap(),
            relative,
        )
        .unwrap();
        let before = catalog.clone();
        assert!(matches!(
            catalog.lifecycle(
                "demo-app",
                "(default)",
                "text",
                "completeBackfill",
                None,
                100,
                None,
                vec![source],
                tokenize
            ),
            Err(TextIndexBuildError::InvalidSource(_))
        ));
        assert_eq!(catalog, before);
    }
}

#[test]
fn latin_purpose_lifecycle_keeps_index_analysis_across_batches_and_completion() {
    let mut catalog = TextIndexCatalog::default();
    catalog
        .add("demo-app", "(default)", definition("text"))
        .unwrap();
    let docs = vec![document("copper", "İris"), document("silver", "Crème")];
    for _ in 0..2 {
        catalog
            .lifecycle(
                "demo-app",
                "(default)",
                "text",
                "advanceBackfill",
                None,
                1,
                None,
                docs.clone(),
                tokenize,
            )
            .unwrap();
    }
    assert_eq!(hits(&catalog, "iris"), ["products/copper"]);
    assert_eq!(hits(&catalog, "creme"), ["products/silver"]);
    assert!(hits(&catalog, "İris").is_empty());
    catalog
        .lifecycle(
            "demo-app",
            "(default)",
            "text",
            "completeBackfill",
            None,
            100,
            None,
            docs,
            tokenize,
        )
        .unwrap();
    assert_eq!(hits(&catalog, "iris"), ["products/copper"]);
    assert!(hits(&catalog, "İris").is_empty());
}
