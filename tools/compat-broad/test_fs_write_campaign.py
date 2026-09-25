"""Validate the bounded Firestore write/transaction preparation package."""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PACKAGE_DIR = ROOT / "spec/compatibility/broad-runs"
MANIFEST_PATH = PACKAGE_DIR / "fs-write-txn-precedence-01.json"
BINDING_PATH = PACKAGE_DIR / "fs-write-txn-precedence-01-binding.json"
SHADOW_PATH = PACKAGE_DIR / "fs-write-txn-precedence-01-local-shadow.json"


def load_json(path: Path) -> dict:
    return json.loads(path.read_bytes())


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_package_is_explicitly_blocked_without_production_execution():
    manifest = load_json(MANIFEST_PATH)
    binding = load_json(BINDING_PATH)
    shadow = load_json(SHADOW_PATH)

    assert manifest["campaignId"] == "FS-WRITE-TXN-PRECEDENCE-01"
    assert manifest["status"] == "BLOCKED_OWNER"
    assert manifest["technicalStatus"] == "BLOCKED_TECHNICAL"
    assert binding["status"] == "BLOCKED_OWNER"
    assert shadow["status"] == "prepared-local-only"
    assert manifest["productionExecuted"] is False
    assert binding["productionExecuted"] is False
    assert shadow["productionExecuted"] is False
    assert manifest["gate"]["productionAuthorization"] is False
    assert binding["gateEnvelope"]["productionAuthorization"] is False
    assert binding["collector"]["productionCollector"] is None
    assert binding["comparator"]["productionComparator"] is None
    assert manifest["collectorBinding"]["productionCollector"] is None
    assert manifest["comparatorBinding"]["productionComparator"] is None
    assert manifest["gate"]["owner"] is None
    assert manifest["gate"]["productionNonce"] is None
    assert all(manifest["gate"][key] is None for key in ("permissionReference", "recoveryOwner"))
    technical_blocker = manifest["collectorBinding"]["technicalBlocker"]
    assert "REST-only" in technical_blocker
    assert "production execution is prohibited" in technical_blocker
    assert any(
        "production gRPC Write stream collector" in reason
        for reason in manifest["gate"]["requiredInputs"]
    )


def test_manifest_source_and_companion_bindings_match_frozen_source():
    manifest = load_json(MANIFEST_PATH)
    binding = load_json(BINDING_PATH)
    shadow = load_json(SHADOW_PATH)

    manifest_digest = sha256(MANIFEST_PATH)
    assert binding["manifest"]["path"] == str(MANIFEST_PATH.relative_to(ROOT))
    assert binding["manifest"]["sha256"] == manifest_digest
    assert shadow["manifestSha256"] == manifest_digest
    assert manifest["sourceBinding"]["featureHead"] == binding["source"]["commit"]
    assert manifest["sourceBinding"]["featureHead"] == shadow["sourceCommit"]
    assert manifest["sourceBinding"]["artifactSha256"] == binding["source"]["artifactSha256"]
    assert manifest["sourceBinding"]["artifactSha256"] == shadow["artifactSha256"]

    source = manifest["sourceBinding"]["featureHead"]
    assert source == "d813c811945e262296b16fce7609f4d0a8698909"

    def source_digest(relative_path: str) -> str:
        content = subprocess.run(
            ["git", "show", f"{source}:{relative_path}"],
            cwd=ROOT,
            check=True,
            capture_output=True,
        ).stdout
        return hashlib.sha256(content).hexdigest()

    for relative_path, expected in manifest["sourceBinding"]["runtimeSourceDigests"].items():
        assert source_digest(relative_path) == expected, relative_path

    for section in (manifest["collectorBinding"], binding["collector"]):
        for entry in section.values():
            if isinstance(entry, dict) and "path" in entry and "sha256" in entry:
                assert source_digest(entry["path"]) == entry["sha256"]
    comparator = manifest["comparatorBinding"]
    assert source_digest(comparator["path"]) == comparator["sha256"]
    local_comparator = binding["comparator"]["localTypedComparator"]
    assert source_digest(local_comparator["path"]) == local_comparator["sha256"]


def test_cases_bind_required_observation_and_recovery_contracts():
    manifest = load_json(MANIFEST_PATH)
    required = {
        "parentFeatureGroups",
        "requirementSurface",
        "semantics",
        "productionOperationSequence",
        "requiredConfiguration",
        "principalTenantDatabase",
        "ownedResources",
        "preflight",
        "setup",
        "observation",
        "postStateReadback",
        "cleanup",
        "comparator",
        "localPreRunControl",
        "estimate",
        "configurationRestorationRule",
        "productionOnlyReason",
    }

    assert {"FS-DATA-WRITE", "FS-TRANSACTION"} <= set(manifest["parentFeatureGroups"])
    assert len(manifest["cases"]) == 2
    for case in manifest["cases"]:
        assert required <= set(case)
        assert case["ownedResources"]
        assert all("{freshNonce}" in resource for resource in case["ownedResources"])
        assert case["preflight"] and case["setup"] and case["observation"]
        assert case["postStateReadback"] and case["cleanup"]
        assert case["localPreRunControl"]
        assert case["estimate"]["observationRequests"] > 0
        assert case["estimate"]["recoveryRequests"] > 0
        assert case["estimate"]["maxRequestsIncludingGate"] == (
            case["estimate"]["observationRequests"]
            + case["estimate"]["recoveryRequests"]
            + manifest["budgets"]["coordinatorRequests"]
        )
        assert case["estimate"]["costCapUsd"] < 10
        assert case["configurationRestorationRule"].startswith("No configuration")
        assert "local" in case["productionOnlyReason"]

    assert manifest["budgets"]["maxOwnedDocuments"] == sum(
        len(case["ownedResources"]) for case in manifest["cases"]
    )
    assert manifest["budgets"]["maxRequests"] == (
        manifest["budgets"]["observationRequests"]
        + manifest["budgets"]["recoveryRequests"]
        + manifest["budgets"]["coordinatorRequests"]
    )
    assert manifest["budgets"]["maxInFlightRequests"] == 1
    assert manifest["budgets"]["automaticRetries"] == 0
    assert manifest["budgets"]["reobservations"] == 0


def test_queue_and_evidence_boundary_keep_current_next_backlog_distinct():
    manifest = load_json(MANIFEST_PATH)
    queue = manifest["queue"]

    assert queue["CURRENT"]["campaignId"] == manifest["campaignId"]
    assert queue["CURRENT"]["state"] == "BLOCKED_OWNER"
    assert queue["NEXT"]["state"] == "PREPARATION"
    assert queue["BACKLOG"]
    assert all(
        item["campaignId"] != queue["CURRENT"]["campaignId"]
        for item in queue["BACKLOG"]
    )
    assert manifest["localShadow"]["status"] == "prepared-local-only"
    assert manifest["localShadow"]["evidenceBoundary"].startswith("local invariant")
    assert all(
        "production" not in command.lower()
        for command in manifest["localShadow"]["commands"]
    )
