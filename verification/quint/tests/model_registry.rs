//! Cross-model contracts for the sole Quint formal authority.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use fireemu_verification_quint::model::{all_models, model};

const AUTHORITY_MODELS: [&str; 12] = [
    "AtomicCommitOutbox",
    "AtomicExportPublication",
    "AuthTotp",
    "AwaitIdle",
    "CompatibilitySelection",
    "EventDelivery",
    "RegexAuthorization",
    "RegexLinearRepeat",
    "RulesetActivation",
    "SessionEpoch",
    "StorageGeneration",
    "TransactionConditionalLock",
];

#[test]
fn registry_contains_the_twelve_authority_models() {
    let names = all_models()
        .map(|descriptor| descriptor.name)
        .collect::<Vec<_>>();
    assert_eq!(names, AUTHORITY_MODELS);
}

#[test]
fn ruleset_activation_names_the_production_evaluation_boundary() {
    let descriptor = model("RulesetActivation").expect("RulesetActivation must be registered");
    descriptor
        .property("EvaluationSnapshotIsImmutable")
        .expect("the immutable boundary must be one production rules evaluation");
    assert!(descriptor.property("RequestVersionIsImmutable").is_err());
}

#[test]
fn each_model_has_unique_properties_actions_mutations_and_sources() {
    let mut manifests = BTreeSet::new();
    for descriptor in all_models() {
        assert!(
            !descriptor.properties.is_empty(),
            "{} properties",
            descriptor.name
        );
        assert!(
            !descriptor.actions.is_empty(),
            "{} actions",
            descriptor.name
        );
        assert!(
            !descriptor.production_sources.is_empty(),
            "{} production sources",
            descriptor.name
        );
        assert!(
            manifests.insert(descriptor.mutation_manifest),
            "{} mutation manifest",
            descriptor.name
        );

        let properties = descriptor
            .properties
            .iter()
            .map(|property| property.name)
            .collect::<BTreeSet<_>>();
        let actions = descriptor.actions.iter().copied().collect::<BTreeSet<_>>();
        let sources = descriptor
            .production_sources
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        assert_eq!(
            properties.len(),
            descriptor.properties.len(),
            "{}",
            descriptor.name
        );
        assert_eq!(
            actions.len(),
            descriptor.actions.len(),
            "{}",
            descriptor.name
        );
        assert_eq!(
            sources.len(),
            descriptor.production_sources.len(),
            "{}",
            descriptor.name
        );
    }
}

#[test]
fn unknown_model_is_rejected() {
    assert_eq!(
        model("UnknownModel").unwrap_err(),
        "unknown Quint model UnknownModel"
    );
}

#[test]
fn await_idle_authority_checks_both_text_index_policies() {
    let spec = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("specs/AwaitIdle.qnt");
    let source = fs::read_to_string(spec).expect("AwaitIdle specification must exist");
    assert!(source.contains("IGNORE_TEXT_INDEX_VALUES = Set(false, true)"));
    assert!(source.contains("module AwaitIdleIgnoreTextIndexScenarios"));
    assert!(source.contains(
        "beginExternal(\"i1\", \"textIndexBuild\")).then(RequestFence).then(ReturnIdle)"
    ));
}
