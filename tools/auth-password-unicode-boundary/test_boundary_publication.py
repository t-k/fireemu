"""Keep mismatches visible and incomplete or secret-bearing records private."""

import copy
import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "boundary_publication", ROOT / "tools/publish-auth-password-unicode-boundary.py"
)
publisher = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(publisher)


def receipt():
    return json.loads(publisher.BUNDLE.read_bytes())


def test_three_complete_patterns_match_without_approval():
    value = receipt()
    publisher.validate(value)
    assert value["local"]["cases"] == value["production"]["cases"]
    assert [row["outcome"] for row in value["local"]["cases"]] == [
        "accepted",
        "accepted",
        "refused",
    ]
    assert value["acceptance"] == "candidate"


@pytest.mark.parametrize(
    "mutation",
    ["secret", "cleanup", "control", "expiry", "shape", "error", "exit", "approval"],
)
def test_publication_rejects_incomplete_or_misrepresented_records(mutation):
    value = copy.deepcopy(receipt())
    row = value["production"]["cases"][0]
    if mutation == "secret":
        row["idToken"] = "must-not-publish"
    elif mutation == "cleanup":
        row["cleanup"]["uidAbsent"] = False
    elif mutation == "control":
        row["checks"]["postLookup"] = False
    elif mutation == "expiry":
        row["tokenChecks"]["signup"]["expirySeconds"] = "1"
    elif mutation == "shape":
        row["inputShape"]["utf16Units"] = 1
    elif mutation == "error":
        value["production"]["cases"][2]["observedError"] = "INVALID_ID_TOKEN"
    elif mutation == "exit":
        value["local"]["ownedProcess"]["exitCode"] = 2
    else:
        value["acceptance"] = "approved"
    with pytest.raises((ValueError, AssertionError)):
        publisher.validate(value)
