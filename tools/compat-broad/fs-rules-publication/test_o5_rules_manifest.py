from __future__ import annotations

import copy

import pytest
from o5_rules_manifest import bound_manifest, manifest, validate_manifest


def test_manifest_is_preparation_only() -> None:
    value = bound_manifest("demo-project", "a" * 32)
    validate_manifest(value)
    assert value["status"] == "PREPARATION_ONLY"
    assert value["productionExecuted"] is False
    assert value["productionReady"] is False
    assert "typed production receipt collector" in value["unresolved"]
    assert "plan" not in value
    assert manifest()["status"] == "PREPARATION_ONLY"


@pytest.mark.parametrize(
    "replacement", [None, [], {"project": []}, {"project": "demo-project", "nonce": []}]
)
def test_malformed_nested_case_rejected(replacement) -> None:
    value = bound_manifest("demo-project", "a" * 32)
    value["observationCase"] = replacement
    with pytest.raises(ValueError):
        validate_manifest(value)


def test_mutation_rejected() -> None:
    value = bound_manifest("demo-project", "a" * 32)
    changed = copy.deepcopy(value)
    changed["productionReady"] = True
    with pytest.raises(ValueError):
        validate_manifest(changed)
