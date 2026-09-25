"""Minimum input shape and prior evidence are never interchangeable."""

import copy
import importlib.util
import json
from pathlib import Path

import pytest


def publisher():
    path = Path(__file__).parents[1] / "publish-auth-password-minimum.py"
    spec = importlib.util.spec_from_file_location("minimum_publisher", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_prior_password_evidence_is_not_minimum_evidence():
    p = publisher()
    value = json.loads(
        (p.ROOT / "spec/compatibility/evidence/auth-password/receipt.json").read_bytes()
    )
    with pytest.raises(ValueError):
        p.validate(value)


def test_committed_minimum_candidate_preserves_shape_and_success():
    p = publisher()
    value = json.loads(p.BUNDLE.read_bytes())
    p.validate(value)
    assert p.PAGE.read_text() == p.render(value)
    assert value["acceptance"] == "candidate"
    for target in ("local", "production"):
        assert len(value[target]["cases"]) == 12
        assert all(row["passed"] for row in value[target]["cases"])
        assert value[target]["inputShape"] == p.INPUT_SHAPE


@pytest.mark.parametrize(
    "mutation",
    [
        "five",
        "seven",
        "boolean-length",
        "non-ascii",
        "same",
        "extra-secret",
        "artifact",
        "cleanup",
        "exit",
        "approval",
        "case",
    ],
)
def test_mutated_minimum_receipt_is_rejected(mutation):
    p = publisher()
    value = json.loads(p.BUNDLE.read_bytes())
    p.validate(value)
    value = copy.deepcopy(value)
    shape = value["local"]["inputShape"]
    if mutation in {"five", "seven", "boolean-length"}:
        shape["replacementPasswordLength"] = {
            "five": 5,
            "seven": 7,
            "boolean-length": True,
        }[mutation]
    elif mutation == "non-ascii":
        shape["replacementAscii"] = False
    elif mutation == "same":
        shape["distinct"] = False
    elif mutation == "extra-secret":
        shape["password"] = "PRIVATE_SECRET"
    elif mutation == "artifact":
        value["local"]["artifact"]["sha256"] = "0" * 64
    elif mutation == "cleanup":
        value["local"]["cleanup"]["emailAbsent"] = False
    elif mutation == "exit":
        value["local"]["ownedProcess"]["exitCode"] = 2
    elif mutation == "approval":
        value["acceptance"] = "approved"
    else:
        value["local"]["cases"].pop()
    with pytest.raises(ValueError):
        p.validate(value)
