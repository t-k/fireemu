"""Validate the current feature-head binding for the Firestore write campaign."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from fs_write_binding_test_support import historical_sha256

ROOT = Path(__file__).resolve().parents[2]
PACKAGE_DIR = ROOT / "spec/compatibility/broad-runs"
CURRENT = "fs-write-txn-precedence-01-v2"
CURRENT_MANIFEST = PACKAGE_DIR / f"{CURRENT}.json"
CURRENT_BINDING = PACKAGE_DIR / f"{CURRENT}-binding.json"
CURRENT_SHADOW = PACKAGE_DIR / f"{CURRENT}-local-shadow.json"
HISTORICAL_MANIFEST = PACKAGE_DIR / "fs-write-txn-precedence-01.json"


def load_json(path: Path) -> dict:
    return json.loads(path.read_bytes())


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_current_package_is_versioned_and_preserves_historical_binding():
    manifest = load_json(CURRENT_MANIFEST)
    binding = load_json(CURRENT_BINDING)
    shadow = load_json(CURRENT_SHADOW)
    historical = load_json(HISTORICAL_MANIFEST)

    assert manifest["campaignId"] == "FS-WRITE-TXN-PRECEDENCE-01-V2"
    assert binding["campaignId"] == manifest["campaignId"]
    assert shadow["campaignId"] == manifest["campaignId"]
    assert manifest["sourceBinding"]["featureHead"] == "cfaebaefe1604cd01502213cd99c139f1fb1b516"
    assert binding["source"]["commit"] == manifest["sourceBinding"]["featureHead"]
    assert shadow["sourceCommit"] == manifest["sourceBinding"]["featureHead"]
    assert historical["campaignId"] == "FS-WRITE-TXN-PRECEDENCE-01"
    assert historical["sourceBinding"]["featureHead"] == "d813c811945e262296b16fce7609f4d0a8698909"
    assert sha256(HISTORICAL_MANIFEST) == (
        "4788da1f38f1672988a59be816115cf6b8c077d0fdc95b86a5a457d271812015"
    )


def test_current_package_binds_current_artifact_and_manifest_digest():
    manifest = load_json(CURRENT_MANIFEST)
    binding = load_json(CURRENT_BINDING)
    shadow = load_json(CURRENT_SHADOW)

    artifact = manifest["sourceBinding"]["artifactSha256"]
    assert artifact == "019cf6fea913cfdb38984d8dda72a0de5b99d8392d7c336528390a00d399e7ee"
    assert binding["source"]["artifactSha256"] == artifact
    assert shadow["artifactSha256"] == artifact
    manifest_digest = sha256(CURRENT_MANIFEST)
    assert binding["manifest"] == {
        "path": "spec/compatibility/broad-runs/fs-write-txn-precedence-01-v2.json",
        "sha256": manifest_digest,
    }
    assert shadow["manifestSha256"] == manifest_digest

    for relative_path, expected in manifest["sourceBinding"]["runtimeSourceDigests"].items():
        assert (
            historical_sha256(
                ROOT, manifest["sourceBinding"]["featureHead"], relative_path
            )
            == expected
        )


def test_current_package_remains_blocked_until_owner_and_technical_inputs_exist():
    manifest = load_json(CURRENT_MANIFEST)
    binding = load_json(CURRENT_BINDING)
    shadow = load_json(CURRENT_SHADOW)

    assert manifest["status"] == "BLOCKED_OWNER"
    assert manifest["technicalStatus"] == "BLOCKED_TECHNICAL"
    assert binding["status"] == "BLOCKED_OWNER"
    assert shadow["status"] == "prepared-local-only"
    assert manifest["productionExecuted"] is False
    assert binding["productionExecuted"] is False
    assert shadow["productionExecuted"] is False
    assert manifest["gate"]["productionAuthorization"] is False
    assert binding["gateEnvelope"]["productionAuthorization"] is False
    assert manifest["collectorBinding"]["productionCollector"] is None
    assert manifest["comparatorBinding"]["productionComparator"] is None
    assert manifest["gate"]["owner"] is None
    assert manifest["gate"]["productionNonce"] is None
    assert binding["gateEnvelope"]["freshNonce"] is None
    assert any(
        "production gRPC Write stream collector" in item
        for item in manifest["gate"]["requiredInputs"]
    )
    assert any("production gRPC Write collector" in reason for reason in binding["blockingReasons"])
    assert any("stream/transaction comparator" in reason for reason in binding["blockingReasons"])
