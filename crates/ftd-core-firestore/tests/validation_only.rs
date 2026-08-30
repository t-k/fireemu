//! `FS-PIPE-RPC-1` stage canonicalization and `FS-TEXT-VAL-1` text index validation.

use ftd_core_firestore::field_path::FieldPath;
use ftd_core_firestore::index::IndexQueryScope;
use ftd_core_firestore::pipeline::{canonicalize, PipelineError, StageRole, StageSpec};
use ftd_core_firestore::text_index::{
    is_language_tag, DefaultTextLanguage, LanguageOverridePolicy, TextIndexDefinition,
    TextIndexError, TextIndexSet, TextIndexState, TextIndexType, TextIndexedField, TextMatchType,
};
use ftd_core_types::ids::CollectionId;

fn stage(name: &str, args: usize) -> StageSpec {
    StageSpec {
        name: name.to_owned(),
        args,
        options: Vec::new(),
    }
}

#[test]
fn pipelines_are_identified_and_misplaced_or_unknown_stages_refused() {
    let ast = canonicalize(&[
        stage("collection", 1),
        stage("where", 1),
        stage("sort", 2),
        stage("limit", 1),
    ])
    .unwrap();
    assert_eq!(
        ast.canonical_text(),
        "collection(1) | where(1) | sort(2) | limit(1)"
    );
    assert_eq!(ast.stages[0].role, StageRole::Input);
    assert_eq!(canonicalize(&[]), Err(PipelineError::Empty));
    assert_eq!(
        canonicalize(&[stage("where", 1)]),
        Err(PipelineError::InputPosition("where".into()))
    );
    assert_eq!(
        canonicalize(&[stage("collection", 1), stage("collection_group", 1)]),
        Err(PipelineError::InputPosition("collection_group".into()))
    );
    assert_eq!(
        canonicalize(&[stage("collection", 1), stage("explode", 1)]),
        Err(PipelineError::UnknownStage("explode".into()))
    );
    assert_eq!(
        canonicalize(&[stage("collection", 2)]),
        Err(PipelineError::Arity {
            stage: "collection".into(),
            min: 1,
            max: Some(1),
            got: 2
        })
    );
    assert_eq!(
        canonicalize(&[stage("collection", 1), stage("delete", 0)]),
        Err(PipelineError::WriteStage("delete".into()))
    );
    assert!(canonicalize(&[stage("database", 0), stage("find_nearest", 3)]).is_ok());
    assert!(PipelineError::WriteStage("update".into())
        .to_string()
        .contains("FS-PIPE-WRITE-0"));
}

fn definition(id: &str, fields: &[&str], language: &str) -> TextIndexDefinition {
    TextIndexDefinition {
        id: id.to_owned(),
        collection_id: CollectionId::try_new("products").unwrap(),
        query_scope: IndexQueryScope::Collection,
        api_scope: "ANY_API".to_owned(),
        fields: fields
            .iter()
            .map(|f| TextIndexedField {
                path: FieldPath::parse(f).unwrap(),
                index_type: TextIndexType::Tokenized,
                match_type: TextMatchType::MatchGlobally,
            })
            .collect(),
        language: DefaultTextLanguage::Tag(language.to_owned()),
        language_override: LanguageOverridePolicy::Disabled,
        state: TextIndexState::Ready,
    }
}

#[test]
fn text_index_definitions_are_validated_and_deduplicated() {
    assert!(is_language_tag("ja"));
    assert!(is_language_tag("en-US"));
    assert!(is_language_tag("zh-Hant-TW"));
    assert!(!is_language_tag(""));
    assert!(!is_language_tag("j"));
    assert!(!is_language_tag("en_US"));
    let mut set = TextIndexSet::default();
    assert_eq!(
        set.add(definition("products_text_v1", &["title"], "ja"))
            .unwrap(),
        Vec::<String>::new()
    );
    assert_eq!(
        set.add(definition("products_text_v1", &["body"], "ja")),
        Err(TextIndexError::DuplicateId("products_text_v1".into()))
    );
    assert_eq!(
        set.add(definition("v2", &["title"], "ja")).unwrap(),
        vec!["FS_TEXT_DUPLICATE_INDEX_DEFINITION".to_owned()],
        "same shape under another id warns"
    );
    assert_eq!(
        set.add(definition("v3", &[], "ja")),
        Err(TextIndexError::NoFields)
    );
    assert_eq!(
        set.add(definition("v3", &["title", "title"], "ja")),
        Err(TextIndexError::DuplicateField("title".into()))
    );
    assert_eq!(
        set.add(definition("v3", &["title"], "japanese")),
        Err(TextIndexError::InvalidLanguage("japanese".into()))
    );
    assert_eq!(
        set.add(definition("bad id!", &["title"], "ja")),
        Err(TextIndexError::InvalidId("bad id!".into()))
    );
    let mut unresolved = definition("v4", &["body"], "en");
    unresolved.language_override = LanguageOverridePolicy::BackendDefaultUnresolved;
    assert_eq!(
        set.add(unresolved).unwrap(),
        vec!["FS_TEXT_LANGUAGE_OVERRIDE_UNRESOLVED".to_owned()]
    );
    let mut scoped = definition("v5", &["body"], "en");
    scoped.api_scope = "SOMETHING".into();
    assert_eq!(
        set.add(scoped),
        Err(TextIndexError::InvalidApiScope("SOMETHING".into()))
    );
    assert_eq!(set.definitions().len(), 3);
    assert!(set.remove("v2"));
    assert!(!set.remove("v2"));
    assert!(set.get("products_text_v1").is_some());
    assert_eq!(TextIndexState::parse("READY"), Some(TextIndexState::Ready));
    assert_eq!(TextIndexState::NeedsRepair.as_str(), "NEEDS_REPAIR");
}
