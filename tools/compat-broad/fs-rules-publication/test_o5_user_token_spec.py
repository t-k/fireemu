from __future__ import annotations

import json
import re
from pathlib import Path

from o5_user_token_campaign import OWNER_PRECONDITIONS, PERMISSION_ENVELOPE, budget
from o5_user_token_case import CAMPAIGN, compile_case

SPEC_DIRECTORY = Path(__file__).resolve().parents[3] / "spec" / "compatibility"
MATRIX = SPEC_DIRECTORY / "fs-rules-user-token-matrix.json"
SHADOW = SPEC_DIRECTORY / "fs-rules-user-token-local-shadow.json"

TEMPLATE_PROJECT = "template-project"
TEMPLATE_NONCE = "0" * 32


def matrix() -> dict:
    return json.loads(MATRIX.read_text())


def shadow() -> dict:
    return json.loads(SHADOW.read_text())


def test_the_checked_in_matrix_is_the_compiled_matrix() -> None:
    plan = compile_case(TEMPLATE_PROJECT, "(default)", TEMPLATE_NONCE)
    assert matrix()["observationCase"] == plan


def test_the_checked_in_budget_and_envelope_match_the_campaign_module() -> None:
    document = matrix()
    plan = compile_case(TEMPLATE_PROJECT, "(default)", TEMPLATE_NONCE)
    assert document["budget"] == budget(plan)
    assert document["permissionEnvelope"] == PERMISSION_ENVELOPE
    assert document["ownerPreconditions"] == list(OWNER_PRECONDITIONS)


def test_the_checked_in_matrix_claims_no_production_evidence() -> None:
    document = matrix()
    assert document["campaignId"] == CAMPAIGN
    assert document["status"] == "PREPARATION_ONLY"
    assert document["productionExecuted"] is False
    assert document["productionReady"] is False


def test_the_checked_in_identities_are_placeholders() -> None:
    case = matrix()["observationCase"]
    assert case["project"] == TEMPLATE_PROJECT
    assert case["nonce"] == TEMPLATE_NONCE
    assert case["tenantIsPlaceholder"] is True


def test_the_shadow_record_is_bound_to_this_matrix() -> None:
    """The record is a real execution. Changing the matrix invalidates it.

    If this fails after a case change, re-run the shadow with
    `o5_user_token_local_run.py --run <directory>` and replace the record.
    """
    record = shadow()
    plan = compile_case("fireemu-35fe6", "(default)", record["nonce"], record["tenant"])
    assert record["planDigest"] == plan["planDigest"]
    assert record["bundle"]["planDigest"] == plan["planDigest"]


def test_the_shadow_record_binds_its_artifact_and_source() -> None:
    artifact = shadow()["artifact"]
    assert len(artifact["artifactSha256"]) == 64
    assert len(artifact["sourceCommit"]) == 40
    assert artifact["rustc"].startswith("rustc ")
    assert artifact["worktree"].endswith("o5-rules-user-token-prep")


def test_the_shadow_record_is_a_complete_local_run() -> None:
    record = shadow()
    bundle = record["bundle"]
    assert record["status"] == "LOCAL_SHADOW_ONLY"
    assert record["productionExecuted"] is False
    assert record["productionReady"] is False
    assert record["exitCode"] == 0
    assert record["originsClosed"] is True
    assert record["tenantDeleted"] is True
    assert bundle["abort"] is None
    assert bundle["recordingComplete"] is True
    assert bundle["cleanup"]["cleanupComplete"] is True
    assert bundle["cleanup"]["outstandingResources"] == []
    assert bundle["cleanup"]["outstandingAccounts"] == []
    assert len(bundle["rows"]) == len(matrix()["observationCase"]["observation"])


def test_the_local_runtime_matched_every_expected_decision() -> None:
    assert shadow()["deviations"] == []


def test_the_shadow_record_carries_no_credential() -> None:
    raw = SHADOW.read_text().lower()
    for marker in ("idtoken", "refreshtoken", "password", "apikey", "authorization"):
        assert marker not in raw
    shape = re.compile(r"[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]*")

    def walk(value) -> None:
        if isinstance(value, dict):
            for nested in value.values():
                walk(nested)
        elif isinstance(value, list):
            for nested in value:
                walk(nested)
        elif isinstance(value, str):
            assert not shape.fullmatch(value), value[:40]

    walk(shadow())
    for row in shadow()["bundle"]["rows"]:
        assert len(row["credentialFingerprint"]) == 16
