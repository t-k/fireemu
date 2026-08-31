//! Contract tests for persisted mutation manifests and evidence.

use tla_verification::{
    parse_evidence, parse_manifest, sha256_file, MutationEvidence, MutationOutcome,
};

fn valid_manifest() -> &'static str {
    r#"{
        "schemaVersion": 1,
        "model": "EventDelivery",
        "mutations": [{
            "id": "M-EVENT-STATE-001",
            "property": "LegalStateTransitions",
            "operator": "allow-cancel-from-succeeded",
            "from": "state = \"pending\"",
            "to": "state \\in {\"pending\", \"succeeded\"}"
        }]
    }"#
}

fn valid_evidence() -> &'static str {
    r#"{
        "schemaVersion": 1,
        "model": "EventDelivery",
        "generatedAt": "2026-08-31T00:00:00Z",
        "tlcVersion": "2.20 of Day Month 20??",
        "moduleSha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "configSha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "manifestSha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        "jarSha256": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        "results": [{
            "id": "M-EVENT-STATE-001",
            "property": "LegalStateTransitions",
            "outcome": "killed_safety",
            "detail": "Invariant LegalStateTransitions is violated"
        }]
    }"#
}

#[test]
fn a_strict_manifest_parses_and_materializes_one_exact_span() {
    let manifest = parse_manifest(valid_manifest()).expect("valid manifest");
    let source = "Init == state = \"pending\"\nNext == UNCHANGED state\n";

    let mutated = manifest.mutations[0]
        .materialize(source)
        .expect("one exact source span");

    assert_eq!(manifest.model, "EventDelivery");
    assert!(mutated.contains("state \\in {\"pending\", \"succeeded\"}"));
    assert!(!mutated.contains("state = \"pending\""));
}

#[test]
fn manifests_reject_unknown_fields_duplicate_ids_and_empty_replacements() {
    let unknown = valid_manifest().replace(
        "\"model\": \"EventDelivery\",",
        "\"model\": \"EventDelivery\", \"surprise\": true,",
    );
    assert!(parse_manifest(&unknown).is_err());

    let duplicate = valid_manifest().replace(
        "]\n    }",
        ", {\"id\":\"M-EVENT-STATE-001\",\"property\":\"Safe\",\"operator\":\"duplicate\",\"from\":\"A\",\"to\":\"B\"}]\n    }",
    );
    assert!(parse_manifest(&duplicate)
        .unwrap_err()
        .contains("duplicate mutation id"));

    let empty = valid_manifest().replace(
        "\"to\": \"state \\\\in {\\\"pending\\\", \\\"succeeded\\\"}\"",
        "\"to\": \"\"",
    );
    assert!(parse_manifest(&empty).unwrap_err().contains("non-empty to"));
}

#[test]
fn mutation_materialization_rejects_zero_or_multiple_matches() {
    let manifest = parse_manifest(valid_manifest()).expect("valid manifest");
    let mutation = &manifest.mutations[0];

    assert!(mutation.materialize("Init == TRUE").is_err());
    assert!(mutation
        .materialize("state = \"pending\" /\\ state = \"pending\"")
        .is_err());
}

#[test]
fn evidence_is_strict_complete_and_only_counterexamples_are_kills() {
    let evidence = parse_evidence(valid_evidence()).expect("valid evidence");
    assert_eq!(evidence.results.len(), 1);
    assert!(evidence.results[0].outcome.is_killed());
    assert!(MutationOutcome::KilledTemporal.is_killed());
    for outcome in [
        MutationOutcome::Survived,
        MutationOutcome::Timeout,
        MutationOutcome::ToolError,
        MutationOutcome::NotRun,
    ] {
        assert!(!outcome.is_killed());
    }

    let unknown = valid_evidence().replace(
        "\"model\": \"EventDelivery\",",
        "\"model\": \"EventDelivery\", \"surprise\": true,",
    );
    assert!(parse_evidence(&unknown).is_err());

    let missing_digest = valid_evidence().replace(
        "        \"jarSha256\": \"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd\",\n",
        "",
    );
    assert!(parse_evidence(&missing_digest).is_err());
}

#[test]
fn evidence_rejects_duplicate_results_and_invalid_digests() {
    let duplicate = valid_evidence().replace(
        "]\n    }",
        ", {\"id\":\"M-EVENT-STATE-001\",\"property\":\"Safe\",\"outcome\":\"survived\",\"detail\":\"duplicate\"}]\n    }",
    );
    assert!(parse_evidence(&duplicate)
        .unwrap_err()
        .contains("duplicate mutation result"));

    let invalid_digest = valid_evidence().replace(
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "not-a-digest",
    );
    assert!(parse_evidence(&invalid_digest)
        .unwrap_err()
        .contains("moduleSha256"));
}

#[test]
fn sha256_file_returns_lowercase_hex() {
    let path = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("sha256-file.txt");
    std::fs::write(&path, b"abc").expect("write fixture");

    let digest = sha256_file(&path).expect("hash fixture");

    assert_eq!(
        digest,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    std::fs::remove_file(path).expect("remove fixture");
}

#[test]
fn public_evidence_type_is_deserializable() {
    let evidence: MutationEvidence = serde_json::from_str(valid_evidence()).expect("shape");
    assert_eq!(evidence.schema_version, 1);
}
