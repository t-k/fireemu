//! Cross-model contracts for the sole Quint formal authority.

use std::collections::BTreeSet;

use fireemu_verification_quint::model::{all_models, model};

const AUTHORITY_MODELS: [&str; 9] = [
    "AtomicCommitOutbox",
    "AtomicExportPublication",
    "AuthTotp",
    "AwaitIdle",
    "EventDelivery",
    "RegexAuthorization",
    "RulesetActivation",
    "SessionEpoch",
    "StorageGeneration",
];

#[test]
fn registry_contains_the_nine_authority_models() {
    let names = all_models()
        .map(|descriptor| descriptor.name)
        .collect::<Vec<_>>();
    assert_eq!(names, AUTHORITY_MODELS);
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
