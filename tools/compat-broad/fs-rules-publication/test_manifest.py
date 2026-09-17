from __future__ import annotations

import copy

import pytest

from manifest import bound_manifest, manifest, validate_manifest


def test_template_is_explicitly_preparation_only() -> None:
    value = manifest()
    assert value["status"] == "PREPARATION_ONLY"
    assert value["productionExecuted"] is False
    assert value["productionReady"] is False
    assert "local-rules-evaluator" in value["forbiddenEvidence"]


def test_bound_manifest_has_stable_plan_digest() -> None:
    value = bound_manifest("demo", "a" * 32)
    validate_manifest(value)
    assert value["planDigest"] == bound_manifest("demo", "a" * 32)["planDigest"]
    changed = copy.deepcopy(value)
    changed["manifestDigest"] = "0" * 64
    with pytest.raises(ValueError):
        validate_manifest(changed)


@pytest.mark.parametrize("mutation", ["plan", "digest", "ready"])
def test_manifest_mutations_are_rejected(mutation: str) -> None:
    value = bound_manifest("demo", "b" * 32)
    changed = copy.deepcopy(value)
    if mutation == "plan":
        changed["plan"]["nonce"] = "c" * 32
    elif mutation == "digest":
        changed["planDigest"] = "0" * 64
    else:
        changed["productionReady"] = True
    with pytest.raises(ValueError):
        validate_manifest(changed)
