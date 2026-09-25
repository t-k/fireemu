"""Publication preserves diagnostic outcomes and rejects incomplete controls."""

import copy
import importlib.util
import json
from pathlib import Path

import pytest


def publisher():
    path = Path(__file__).resolve().parents[1] / "publish-auth-disabled.py"
    spec = importlib.util.spec_from_file_location("disabled_publisher", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_completed_flow_is_candidate_not_universal_revocation():
    module = publisher()
    value = json.loads(module.BUNDLE.read_bytes())
    module.validate(value)
    assert len(value["local"]["cases"]) == 18
    assert value["acceptance"] == "candidate"
    assert "not simultaneous" in module.render(value)


@pytest.mark.parametrize(
    "mutation",
    [
        "secret",
        "control",
        "elapsed",
        "expiry",
        "cleanup",
        "transition",
        "setup",
        "exit",
        "approval",
    ],
)
def test_invalid_evidence_is_not_publishable(mutation):
    module = publisher()
    value = copy.deepcopy(json.loads(module.BUNDLE.read_bytes()))
    local = value["local"]
    row = local["cases"][0]
    if mutation == "secret":
        row["idToken"] = "private"
    elif mutation == "control":
        row["checks"]["derivedLookup"] = False
    elif mutation == "elapsed":
        row["elapsedMs"] = 120001
    elif mutation == "expiry":
        row["expirySeconds"] = "1"
    elif mutation == "cleanup":
        local["cleanup"]["uidAbsent"] = False
    elif mutation == "transition":
        local["transitions"][0]["disabled"] = 1
    elif mutation == "setup":
        local["setup"]["a"] = 1
    elif mutation == "exit":
        local["ownedProcess"]["exitCode"] = 2
    else:
        value["acceptance"] = "approved"
    with pytest.raises(ValueError):
        module.validate(value)
