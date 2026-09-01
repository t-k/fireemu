//! Strict mutation and evidence contracts for the `EventDelivery` Quint pilot.

use std::path::PathBuf;

use fireemu_verification_quint::process::{
    apply_source_replacement, mutate_event_delivery, MutationManifest, MutationOutcome,
};

const MANIFEST: &str = include_str!("../mutations/EventDelivery.json");

#[test]
fn mutation_manifest_preserves_legacy_ids_and_properties() {
    let manifest = MutationManifest::parse(MANIFEST).expect("valid checked-in manifest");
    let mappings = manifest
        .mutations
        .iter()
        .map(|mutation| (mutation.id.as_str(), mutation.property.as_str()))
        .collect::<Vec<_>>();
    assert_eq!(
        mappings,
        [
            ("M-TLA-EVENT-TERMINAL-001", "NoTerminalRegression"),
            ("M-TLA-EVENT-LIVENESS-001", "EventEventuallyTerminates"),
            ("M-TLA-EVENT-LEGAL-001", "LegalStateTransitions"),
            ("M-TLA-EVENT-ATTEMPTS-001", "AttemptsChangeOnlyOnStart"),
            ("M-TLA-EVENT-STALE-001", "StaleDiscardRequiresOlderEpoch"),
        ]
    );
}

#[test]
fn mutation_manifest_rejects_ambiguous_or_invalid_intents() {
    let unknown = MANIFEST.replacen("\"model\":", "\"unknown\": true, \"model\":", 1);
    assert!(MutationManifest::parse(&unknown).is_err());

    let duplicate_id = MANIFEST.replacen("M-TLA-EVENT-LIVENESS-001", "M-TLA-EVENT-TERMINAL-001", 1);
    assert!(MutationManifest::parse(&duplicate_id).is_err());

    let duplicate_intent = MANIFEST.replacen(
        "remove-worker-fairness",
        "allow-cancel-from-terminal-state",
        1,
    );
    assert!(MutationManifest::parse(&duplicate_intent).is_err());

    for field in ["from", "to"] {
        let needle = format!("\"{field}\": \"");
        let end = MANIFEST.find(&needle).expect("field exists") + needle.len();
        let remaining = &MANIFEST[end..];
        let value_end = remaining.find('"').expect("field value ends");
        let invalid = format!("{}{}{}", &MANIFEST[..end], &remaining[value_end..], "");
        assert!(MutationManifest::parse(&invalid).is_err(), "field {field}");
    }
}

#[test]
fn source_replacement_requires_exactly_one_occurrence() {
    let manifest = MutationManifest::parse(MANIFEST).expect("valid checked-in manifest");
    let mutation = &manifest.mutations[0];
    assert!(apply_source_replacement("missing", mutation).is_err());
    let duplicated = format!("{}\n{}", mutation.from, mutation.from);
    assert!(apply_source_replacement(&duplicated, mutation).is_err());
    assert_eq!(
        apply_source_replacement(&mutation.from, mutation).expect("one replacement"),
        mutation.to
    );
}

#[test]
#[ignore = "requires Java and the pinned local Quint CLI"]
fn real_tlc_kills_all_required_mutants() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .expect("verification/quint must have a repository parent")
        .to_path_buf();
    let results = mutate_event_delivery(&root, None).expect("all required mutants must be killed");
    assert_eq!(results.len(), 5);
    assert_eq!(results[0].outcome, MutationOutcome::KilledSafety);
    assert_eq!(results[1].outcome, MutationOutcome::KilledTemporal);
    assert!(results.iter().all(|result| result.outcome.is_killed()));
}
