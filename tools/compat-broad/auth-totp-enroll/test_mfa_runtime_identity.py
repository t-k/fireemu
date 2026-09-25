"""Runtime identity and independent local-artifact anchor contract tests."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from mfa_cases import CAMPAIGN_ID, CASE_IDS
from mfa_collector import digest
from mfa_comparator import compare
from mfa_manifest import compile_campaign
from mfa_provenance import compute_provenance, repository_root

NONCE = "0123456789abcdef0123456789abcdef"


def anchor() -> dict[str, str]:
    return {
        "artifactSha256": "a" * 64,
        "executionCommit": "b" * 40,
        "configurationDigest": "c" * 64,
        "runId": "run-1",
    }


def receipt(side: str) -> dict:
    runtime = anchor()
    return {
        "campaignId": CAMPAIGN_ID,
        "campaign": compile_campaign(NONCE),
        "side": side,
        "recordingComplete": True,
        "productionExecuted": side == "production",
        "provenance": compute_provenance(repository_root()),
        "worktree": {"commit": runtime["executionCommit"], "clean": True, "resolved": True},
        "runtimeIdentity": runtime,
        "rows": [
            {"id": identifier, "status": 200, "errorCode": None, "outcome": "observed"}
            for identifier in CASE_IDS
        ],
        "recovery": {
            "cleanupVerified": True,
            "remainingOwnedResources": 0,
            "configurationRestored": True,
            "runId": "run-1",
        },
    }


def approved(record: dict) -> dict:
    record["ownerApproval"] = {
        "approvedBy": "project owner",
        "manifestDigest": digest(record["campaign"]),
        "nonceDigest": record["campaign"]["owner"]["nonceDigest"],
        "grant": "one-run",
    }
    return record


def test_local_runtime_identity_is_derived_from_binary_and_config_bytes(tmp_path: Path) -> None:
    from mfa_local_shadow import build_runtime_identity

    binary = tmp_path / "fireemu"
    config = tmp_path / "fireemu.json"
    binary.write_bytes(b"binary")
    config.write_bytes(b"config")
    value = build_runtime_identity(binary, config, "b" * 40, "run-1")
    assert value == {
        "artifactSha256": hashlib.sha256(b"binary").hexdigest(),
        "executionCommit": "b" * 40,
        "configurationDigest": hashlib.sha256(b"config").hexdigest(),
        "runId": "run-1",
    }


def test_production_comparison_requires_an_independent_runtime_anchor() -> None:
    local = receipt("local")
    production = approved(receipt("production"))
    assert compare(local, production)["classification"] == "INDETERMINATE"
    result = compare(local, production, runtime_anchor=anchor())
    assert result["classification"] in {"DIFF", "EXPECTED_NONDETERMINISM", "MATCH"}


def test_downgraded_final_record_without_identity_cannot_match() -> None:
    local = receipt("local")
    production = approved(receipt("production"))
    local.pop("runtimeIdentity")
    local["recovery"].pop("runId")
    local["productionExecuted"] = True
    local["ownerApproval"] = production["ownerApproval"]
    assert compare(local, production)["classification"] == "INDETERMINATE"


def test_local_preparation_without_identity_cannot_match_approved_production() -> None:
    local = receipt("local")
    production = approved(receipt("production"))
    local.pop("runtimeIdentity")
    local["recovery"].pop("runId")

    result = compare(local, production)

    assert result["classification"] == "INDETERMINATE"
    assert result["runtimeProblems"] == ["local runtime identity unavailable"]


def test_preparation_pair_keeps_preparation_only_classification() -> None:
    local = receipt("local")
    preparation = receipt("production")
    preparation["productionExecuted"] = False

    result = compare(local, preparation)

    assert result["classification"] == "PREPARATION_ONLY"


@pytest.mark.parametrize("malformed", [None, {}, {"artifactSha256": "A" * 64}])
def test_malformed_independent_anchor_is_indeterminate(malformed) -> None:
    local = receipt("local")
    production = approved(receipt("production"))
    assert compare(local, production, runtime_anchor=malformed)["classification"] == "INDETERMINATE"


@pytest.mark.parametrize(
    "mutation, reason",
    [
        (lambda value: value.update(artifactSha256="d" * 64), "artifact"),
        (lambda value: value.update(executionCommit="d" * 40), "source"),
        (lambda value: value.update(configurationDigest="d" * 64), "configuration"),
        (lambda value: value.pop("artifactSha256"), "identity"),
    ],
)
def test_wrong_runtime_identity_is_indeterminate(
    mutation, reason: str
) -> None:
    local = receipt("local")
    production = approved(receipt("production"))
    expected = anchor()
    mutation(expected)
    result = compare(local, production, runtime_anchor=expected)
    assert result["classification"] == "INDETERMINATE", reason


def test_runtime_identity_and_cleanup_must_share_the_run_id() -> None:
    local = receipt("local")
    production = approved(receipt("production"))
    local["recovery"]["runId"] = "run-2"
    result = compare(local, production, runtime_anchor=anchor())
    assert result["classification"] == "INDETERMINATE"


def test_runtime_identity_has_no_path_or_secret_material(tmp_path: Path) -> None:
    from mfa_local_shadow import build_runtime_identity

    binary = tmp_path / "fireemu"
    config = tmp_path / "config"
    binary.write_bytes(b"binary")
    config.write_bytes(b"config")
    value = build_runtime_identity(binary, config, "b" * 40, "run-1")
    assert "path" not in json.dumps(value).lower()
    assert "binary" not in json.dumps(value).lower()
