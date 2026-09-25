"""A local handoff carries state validation only after both full receipts pass."""

import copy

import pytest
from broad_contract import digest
from second_admission import manifest
from second_mapped import validated_pair_state
from test_second_mapping import receipt


def validated_receipt(mode):
    value = receipt(mode)
    value["admissionDigest"] = digest(manifest())
    return value


def test_pair_state_requires_both_complete_observed_validations():
    direct = validated_receipt("direct")
    mapped = validated_receipt("mapped")

    assert validated_pair_state(direct, mapped) is True


@pytest.mark.parametrize(
    "side, mutation",
    [
        ("direct", "safety"),
        ("mapped", "trace"),
        ("direct", "admission"),
        ("mapped", "missing-safety"),
    ],
)
def test_pair_state_fails_closed_on_missing_or_failed_validation(side, mutation):
    direct = validated_receipt("direct")
    mapped = validated_receipt("mapped")
    target = direct if side == "direct" else mapped
    target = copy.deepcopy(target)
    if mutation == "safety":
        target["safety"] = False
    elif mutation == "trace":
        target["trace"].pop()
    elif mutation == "admission":
        target.pop("admissionDigest")
    else:
        target.pop("safety")

    assert (
        validated_pair_state(
            target if side == "direct" else direct,
            target if side == "mapped" else mapped,
        )
        is False
    )
