from __future__ import annotations

import copy
import hashlib
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
from comparator import compare  # noqa: E402
from compiler import BOUNDS, compile_case, compile_manifest  # noqa: E402
from shadow import run_shadow  # noqa: E402


def plan() -> dict:
    return compile_case("oracle-project", None, "fresh-opaque-nonce-123456")


def test_compiler_closes_case_and_never_retains_nonce_or_production_expectation():
    value = plan()
    assert value["status"] == "PREPARATION"
    assert value["productionExecuted"] is False
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
        }
        assert receipt["cleanup"]["complete"] is True
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


def test_nonce_is_digest_only():
    nonce = "x" * 32
    value = compile_case("p", "t", nonce)
    assert value["nonceDigest"] == hashlib.sha256(nonce.encode()).hexdigest()
    assert nonce not in str(value)
