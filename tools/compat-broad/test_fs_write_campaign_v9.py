"""Validate the immutable current-head Firestore write campaign package."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from fs_write_binding_test_support import historical_sha256
ROOT = Path(__file__).resolve().parents[2]
PACKAGE_DIR = ROOT / "spec/compatibility/broad-runs"
CURRENT_MANIFEST = PACKAGE_DIR / "fs-write-txn-precedence-01-v9.json"
CURRENT_BINDING = PACKAGE_DIR / "fs-write-txn-precedence-01-v9-binding.json"
CURRENT_SHADOW = PACKAGE_DIR / "fs-write-txn-precedence-01-v9-local-shadow.json"
PREVIOUS_MANIFEST = PACKAGE_DIR / "fs-write-txn-precedence-01-v8.json"

EXPECTED_HEAD = "9830ccaf53def5d51bb620411648e2a30337a32f"
EXPECTED_ARTIFACT = "a744d52c56a5f16045b246bd83c207634158468285a8a3086614b9e0d384c3eb"


def load_json(path: Path) -> dict:
    return json.loads(path.read_bytes())


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_v9_is_a_new_immutable_package_bound_to_current_head() -> None:
    manifest = load_json(CURRENT_MANIFEST)
    binding = load_json(CURRENT_BINDING)
    shadow = load_json(CURRENT_SHADOW)
    previous = load_json(PREVIOUS_MANIFEST)

    assert manifest["campaignId"] == "FS-WRITE-TXN-PRECEDENCE-01-V9"
    assert binding["campaignId"] == manifest["campaignId"]
    assert shadow["campaignId"] == manifest["campaignId"]
    assert manifest["preparation"]["supersedes"] == "FS-WRITE-TXN-PRECEDENCE-01-V8"
    assert previous["campaignId"] == "FS-WRITE-TXN-PRECEDENCE-01-V8"
    assert previous["sourceBinding"]["featureHead"] != EXPECTED_HEAD
    historical = load_json(PACKAGE_DIR / "fs-write-txn-precedence-01.json")
    assert historical["campaignId"] == "FS-WRITE-TXN-PRECEDENCE-01"
    assert historical["sourceBinding"]["featureHead"] != EXPECTED_HEAD

    assert manifest["sourceBinding"]["featureHead"] == EXPECTED_HEAD
    assert manifest["sourceBinding"]["codeSourceHead"] == EXPECTED_HEAD
    assert manifest["preparation"]["codeSourceHead"] == EXPECTED_HEAD
    assert binding["source"]["commit"] == EXPECTED_HEAD
    assert binding["source"]["codeSourceHead"] == EXPECTED_HEAD
    assert shadow["sourceCommit"] == EXPECTED_HEAD
    assert shadow["codeSourceHead"] == EXPECTED_HEAD


def test_v9_artifact_and_manifest_bindings_are_consistent() -> None:
    manifest = load_json(CURRENT_MANIFEST)
    binding = load_json(CURRENT_BINDING)
    shadow = load_json(CURRENT_SHADOW)

    assert manifest["sourceBinding"]["artifactSha256"] == EXPECTED_ARTIFACT
    assert binding["source"]["artifactSha256"] == EXPECTED_ARTIFACT
    assert shadow["artifactSha256"] == EXPECTED_ARTIFACT
    assert manifest["sourceBinding"]["artifactBuild"]["relativePath"] == "target/o3-fs-write-current/release/fireemu"
    assert binding["artifactBuild"]["relativePath"] == "target/o3-fs-write-current/release/fireemu"
    assert shadow["artifactBuild"]["relativePath"] == "target/o3-fs-write-current/release/fireemu"
    assert binding["artifactBuild"]["sha256"] == EXPECTED_ARTIFACT
    assert shadow["artifactBuild"]["sha256"] == EXPECTED_ARTIFACT

    manifest_digest = sha256(CURRENT_MANIFEST)
    assert binding["manifest"] == {
        "path": "spec/compatibility/broad-runs/fs-write-txn-precedence-01-v9.json",
        "sha256": manifest_digest,
    }
    assert shadow["manifestSha256"] == manifest_digest

    for relative_path, expected in manifest["sourceBinding"]["runtimeSourceDigests"].items():
        assert (
            historical_sha256(
                ROOT, manifest["sourceBinding"]["featureHead"], relative_path
            )
            == expected
        ), relative_path


def test_v9_remains_blocked_without_owner_or_stream_comparator() -> None:
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
    assert binding["collector"]["productionCollector"] is None
    assert binding["comparator"]["productionComparator"] is None
    assert manifest["gate"]["owner"] is None
    assert manifest["gate"]["productionNonce"] is None
    assert any(
        "production gRPC Write stream collector" in item
        for item in manifest["gate"]["requiredInputs"]
    )
    assert any(
        "production gRPC Write collector" in reason
        for reason in binding["blockingReasons"]
    )
    assert any(
        "stream/transaction comparator" in reason
        for reason in binding["blockingReasons"]
    )
    assert all("production" not in command.lower() for command in shadow["execution"]["commands"])
