"""Published maximum inputs, cleanup and observed error projections are checked."""

import copy
import importlib.util
import json
from pathlib import Path

import pytest


def publisher():
    spec = importlib.util.spec_from_file_location(
        "maximum_publisher",
        Path(__file__).parents[1] / "publish-auth-password-maximum.py",
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_committed_maximum_candidate():
    p = publisher()
    value = json.loads(p.BUNDLE.read_bytes())
    p.validate(value)
    assert p.render(value) == p.PAGE.read_text()
    assert value["acceptance"] == "candidate"
    assert len(value["local"]["cases"]) == 21
    assert value["local"]["cases"] == value["production"]["cases"]
    assert all(row["passed"] for row in value["local"]["cases"])


@pytest.mark.parametrize(
    "mutation",
    [
        "length",
        "tail",
        "secret",
        "error",
        "expiry",
        "cleanup",
        "exit",
        "artifact",
        "approval",
        "case",
    ],
)
def test_mutated_receipt_is_rejected(mutation):
    p = publisher()
    value = copy.deepcopy(json.loads(p.BUNDLE.read_bytes()))
    local = value["local"]
    if mutation == "length":
        local["inputShape"]["maximumLength"] = 4095
    elif mutation == "tail":
        local["inputShape"]["tailLastDifferent"] = False
    elif mutation == "secret":
        local["inputShape"]["password"] = "PRIVATE_SECRET"
    elif mutation == "error":
        local["cases"][13]["observedError"] = "INVALID_ID_TOKEN"
    elif mutation == "expiry":
        local["cases"][0]["expirySeconds"] = "1"
    elif mutation == "cleanup":
        local["cleanup"]["uidAbsent"] = False
    elif mutation == "exit":
        local["ownedProcess"]["exitCode"] = 2
    elif mutation == "artifact":
        local["artifact"]["sha256"] = "0" * 64
    elif mutation == "approval":
        value["acceptance"] = "approved"
    else:
        local["cases"].pop()
    with pytest.raises(ValueError):
        p.validate(value)
