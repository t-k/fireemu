//! Strict mutation and evidence contracts for the `EventDelivery` Quint pilot.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use fireemu_verification_quint::evidence::validate_evidence_json;
use fireemu_verification_quint::model::model;
use fireemu_verification_quint::process::{
    apply_source_replacement, mutate_event_delivery, MutationManifest, MutationOutcome,
};

const MANIFEST: &str = include_str!("../mutations/EventDelivery.json");
const EVIDENCE: &str = include_str!("../evidence/EventDelivery.json");
const BOUND_INPUTS: [&str; 30] = [
    ".github/workflows/ci.yml",
    "Cargo.toml",
    "Cargo.lock",
    "crates/fireemu-core-events/Cargo.toml",
    "crates/fireemu-core-events/src/event.rs",
    "crates/fireemu-core-events/src/retry.rs",
    "crates/fireemu-core-events/src/state.rs",
    "crates/fireemu-core-types/Cargo.toml",
    "crates/fireemu-core-types/src/ids.rs",
    "crates/fireemu-core-types/src/time.rs",
    "verification/quint/Cargo.toml",
    "verification/quint/README.md",
    "verification/quint/bin/quint",
    "verification/quint/bin/process-group",
    "verification/quint/run-pilot.sh",
    "verification/quint/specs/EventDelivery.qnt",
    "verification/quint/specs/tlc-config.json",
    "verification/quint/mutations/EventDelivery.json",
    "verification/quint/package.json",
    "verification/quint/pnpm-lock.yaml",
    "verification/quint/src/event_delivery.rs",
    "verification/quint/src/evidence.rs",
    "verification/quint/src/lib.rs",
    "verification/quint/src/main.rs",
    "verification/quint/src/model.rs",
    "verification/quint/src/process.rs",
    "verification/quint/tests/cli_contract.rs",
    "verification/quint/tests/event_delivery_connect.rs",
    "verification/quint/tests/event_delivery_evidence.rs",
    "verification/quint/tests/model_registry.rs",
];

fn repository_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .expect("verification/quint must have a repository parent")
        .to_path_buf()
}

fn parse_manifest(json: &str) -> Result<MutationManifest, String> {
    MutationManifest::parse(
        json,
        model("EventDelivery").expect("EventDelivery must remain registered"),
    )
}

#[test]
fn evidence_schema_rejects_missing_and_unknown_fields() {
    assert!(validate_evidence_json("{}", None).is_err());
    assert!(validate_evidence_json("{\"unknown\":true}", None).is_err());
}

#[test]
fn checked_in_evidence_rejects_each_bound_input_tamper() {
    validate_evidence_json(EVIDENCE, Some(&repository_root())).expect("checked-in evidence");

    for relative in BOUND_INPUTS {
        let temporary = OwnedTestRepository::copy_bound_inputs().expect("copy bound inputs");
        let path = temporary.path.join(relative);
        let mut bytes = fs::read(&path).expect("read copied bound input");
        bytes.push(b'!');
        fs::write(&path, bytes).expect("tamper copied bound input");
        let error = validate_evidence_json(EVIDENCE, Some(&temporary.path))
            .expect_err("tampered input must invalidate evidence");
        assert!(error.contains(relative), "{relative}: {error}");
        temporary.close().expect("remove owned test repository");
    }
}

#[test]
fn evidence_rejects_coverage_and_outcome_tampering() {
    let baseline: serde_json::Value = serde_json::from_str(EVIDENCE).expect("valid evidence JSON");
    let mut variants = Vec::new();

    let mut changed_tool = baseline.clone();
    changed_tool["tools"]["quint"] = "0.33.0".into();
    variants.push(changed_tool);

    for outcome in ["Survived", "Timeout", "ToolError"] {
        let mut changed = baseline.clone();
        changed["mutations"][0]["outcome"] = outcome.into();
        variants.push(changed);
    }

    for field in ["mutations", "scenarios", "actions", "projectionFields"] {
        let mut missing = baseline.clone();
        missing[field]
            .as_array_mut()
            .expect("coverage field is an array")
            .pop();
        variants.push(missing);
    }

    let mut changed_seed = baseline.clone();
    changed_seed["simulation"]["seeds"][0] = "0xdead".into();
    variants.push(changed_seed);

    let mut unknown = baseline;
    unknown["unknown"] = true.into();
    variants.push(unknown);

    for changed in variants {
        let json = serde_json::to_string(&changed).expect("serialize tampered evidence");
        assert!(
            validate_evidence_json(&json, Some(&repository_root())).is_err(),
            "tampered evidence unexpectedly validated"
        );
    }
}

#[test]
fn mutation_manifest_preserves_legacy_ids_and_properties() {
    let manifest = parse_manifest(MANIFEST).expect("valid checked-in manifest");
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
    assert!(parse_manifest(&unknown).is_err());

    let duplicate_id = MANIFEST.replacen("M-TLA-EVENT-LIVENESS-001", "M-TLA-EVENT-TERMINAL-001", 1);
    assert!(parse_manifest(&duplicate_id).is_err());

    let duplicate_intent = MANIFEST.replacen(
        "remove-worker-fairness",
        "allow-cancel-from-terminal-state",
        1,
    );
    assert!(parse_manifest(&duplicate_intent).is_err());

    let wrong_model = MANIFEST.replacen("EventDelivery", "SessionEpoch", 1);
    assert!(parse_manifest(&wrong_model).is_err());

    let wrong_property = MANIFEST.replacen("LegalStateTransitions", "UnknownProperty", 1);
    assert!(parse_manifest(&wrong_property).is_err());

    for field in ["from", "to"] {
        let needle = format!("\"{field}\": \"");
        let end = MANIFEST.find(&needle).expect("field exists") + needle.len();
        let remaining = &MANIFEST[end..];
        let value_end = remaining.find('"').expect("field value ends");
        let invalid = format!("{}{}{}", &MANIFEST[..end], &remaining[value_end..], "");
        assert!(parse_manifest(&invalid).is_err(), "field {field}");
    }
}

#[test]
fn source_replacement_requires_exactly_one_occurrence() {
    let manifest = parse_manifest(MANIFEST).expect("valid checked-in manifest");
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
    let root = repository_root();
    let results = mutate_event_delivery(&root, None).expect("all required mutants must be killed");
    assert_eq!(results.len(), 5);
    assert_eq!(results[0].outcome, MutationOutcome::KilledSafety);
    assert_eq!(results[1].outcome, MutationOutcome::KilledTemporal);
    assert!(results.iter().all(|result| result.outcome.is_killed()));
}

struct OwnedTestRepository {
    path: PathBuf,
    closed: bool,
}

impl OwnedTestRepository {
    fn copy_bound_inputs() -> std::io::Result<Self> {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(std::io::Error::other)?
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "fireemu-quint-evidence-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&path)?;
        for relative in BOUND_INPUTS {
            let destination = path.join(relative);
            fs::create_dir_all(destination.parent().unwrap_or(Path::new(".")))?;
            fs::copy(repository_root().join(relative), destination)?;
        }
        Ok(Self {
            path,
            closed: false,
        })
    }

    fn close(mut self) -> std::io::Result<()> {
        fs::remove_dir_all(&self.path)?;
        self.closed = true;
        Ok(())
    }
}

impl Drop for OwnedTestRepository {
    fn drop(&mut self) {
        if !self.closed {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}
