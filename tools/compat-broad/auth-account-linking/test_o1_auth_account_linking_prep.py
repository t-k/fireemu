from __future__ import annotations

import copy
import hashlib
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
from o1_auth_account_linking_comparator import compare  # noqa: E402
from o1_auth_account_linking_compiler import (  # noqa: E402
    BOUNDS,
    SDK_PINS,
    compile_case,
    compile_manifest,
    validate_manifest,
)
from o1_auth_account_linking_shadow import run_shadow  # noqa: E402


def plan() -> dict:
    return compile_case("oracle-project", None, "fresh-opaque-nonce-123456")


def test_compiler_closes_case_and_never_retains_nonce_or_production_expectation():
    value = plan()
    assert value["status"] == "PREPARATION"
    assert value["productionExecuted"] is False
    assert value["campaign"] == "auth-settings-sdk-next-v10"
    assert value["slice"] == "account-linking-duplicate-email"
    assert "fresh-opaque-nonce" not in str(value)
    assert value["expectedProduction"] is None
    assert value["bounds"] == BOUNDS
    assert len(value["operations"]) == 12


def test_manifest_binds_artifact_source_sdk_and_configuration_without_owner_authority():
    value = compile_manifest(
        plan(),
        artifact_sha256="a" * 64,
        source_commit="b" * 40,
        sdk={"firebase": "12.18.0", "firebase-admin": "14.3.0"},
        configuration_digest="c" * 64,
    )
    assert value["status"] == "PREPARATION"
    assert value["ownerBinding"] is None
    assert value["cleanup"] == {"required": True, "complete": False}
    validate_manifest(value)
    for key, replacement in (("artifactSha256", "d" * 64), ("sourceCommit", "e" * 40)):
        changed = copy.deepcopy(value)
        changed[key] = replacement
        validate_manifest(changed)
    changed = copy.deepcopy(value)
    changed["sdk"] = {
        "firebase": "latest",
        "firebase-admin": SDK_PINS["firebase-admin"],
    }
    with pytest.raises(ValueError, match="SDK pins"):
        validate_manifest(changed)
    with pytest.raises(ValueError, match="production-disabled"):
        compile_manifest(
            {**plan(), "productionExecuted": True},
            artifact_sha256="a" * 64,
            source_commit="b" * 40,
            sdk={"firebase": "1", "firebase-admin": "2"},
            configuration_digest="c" * 64,
        )


def test_local_shadow_models_provider_email_collision_and_full_cleanup_for_both_modes():
    for mode in (False, True):
        receipt = run_shadow(plan(), allow_duplicate_emails=mode)
        collision = next(
            row for row in receipt["operations"] if row["id"] == "provider-collision"
        )
        assert collision == {
            "id": "provider-collision",
            "status": "accepted",
            "uid": "local-b",
            "providerOwner": "B",
            "emailOwner": "A",
            "emailOwnershipMode": "multiple" if mode else "single",
        }
        assert receipt["cleanup"]["complete"] is True
        assert receipt["after"] == {}
        assert receipt["productionExpectation"] is None


def test_comparator_distinguishes_match_mismatch_and_missing_cleanup():
    left = run_shadow(plan(), allow_duplicate_emails=True)
    assert compare(left, copy.deepcopy(left))["classification"] == "MATCH"
    changed = copy.deepcopy(left)
    next(row for row in changed["operations"] if row["id"] == "provider-collision")[
        "status"
    ] = "refused"
    assert compare(left, changed)["classification"] == "SEMANTIC_MISMATCH"
    incomplete = copy.deepcopy(left)
    incomplete["cleanup"]["complete"] = False
    assert compare(left, incomplete)["classification"] == "INDETERMINATE"


def test_comparator_does_not_compare_secret_like_fields_or_dynamic_ids():
    left = run_shadow(plan(), allow_duplicate_emails=False)
    right = copy.deepcopy(left)
    right["token"] = "secret-token"
    right["operations"][3]["uid"] = "prod-rotated"
    assert compare(left, right)["classification"] == "MATCH"


def test_comparator_preserves_operation_order_and_fails_closed_for_malformed_cleanup():
    left = run_shadow(plan(), allow_duplicate_emails=True)
    reordered = copy.deepcopy(left)
    reordered["operations"][0], reordered["operations"][1] = (
        reordered["operations"][1],
        reordered["operations"][0],
    )
    assert compare(left, reordered)["classification"] == "SEMANTIC_MISMATCH"
    malformed = copy.deepcopy(left)
    malformed["cleanup"] = None
    assert compare(left, malformed)["classification"] == "INDETERMINATE"
    transport = copy.deepcopy(left)
    transport["operations"][0]["failure"] = "timeout"
    assert compare(left, transport)["classification"] == "INDETERMINATE"


def test_nonce_is_digest_only():
    nonce = "x" * 32
    value = compile_case("p", "t", nonce)
    assert value["nonceDigest"] == hashlib.sha256(nonce.encode()).hexdigest()
    assert nonce not in str(value)
