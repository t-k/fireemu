"""The human decision cannot transfer to altered evidence or scope."""

import copy
import importlib.util
import json
from pathlib import Path

import pytest


def load():
    spec = importlib.util.spec_from_file_location(
        "deleted_approval",
        Path(__file__).with_name("auth-deleted-recheck-approval.py"),
    )
    assert spec and spec.loader and spec.origin and Path(spec.origin).exists()
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_human_approval_matches_complete_subject():
    module = load()
    page = module.render(
        json.loads(module.APPROVAL.read_bytes()),
        json.loads(module.publisher.BUNDLE.read_bytes()),
    )
    assert "12 observations verified and approved" in page
    assert "not a new production run" in page
    assert (
        "password signin, fixed original ID-token lookup, then fixed original refresh-token exchange"
        in page
    )
    assert "identifier-based accounts:lookup authorization" in page


@pytest.mark.parametrize(
    "field",
    ["subjectSha256", "scope", "reviewer", "reviewedAt", "sourceCommit", "cases"],
)
def test_changed_human_decision_is_rejected(field):
    module = load()
    approval = json.loads(module.APPROVAL.read_bytes())
    approval[field] = [] if field == "cases" else "changed"
    with pytest.raises(ValueError):
        module.render(approval, json.loads(module.publisher.BUNDLE.read_bytes()))


@pytest.mark.parametrize(
    "field", ["artifact", "production", "control", "error", "order", "elapsed"]
)
def test_changed_observation_cannot_inherit_approval(field):
    module = load()
    receipt = copy.deepcopy(json.loads(module.publisher.BUNDLE.read_bytes()))
    if field == "artifact":
        receipt["observation"]["local"]["artifact"]["sha256"] = "0" * 64
    elif field == "production":
        receipt["observation"]["production"]["recordedAt"] = "changed"
    elif field == "error":
        receipt["observation"]["local"]["cases"][6]["observedError"] = "TOKEN_EXPIRED"
    elif field == "order":
        receipt["observation"]["local"]["cases"].reverse()
    elif field == "elapsed":
        receipt["observation"]["local"]["cases"][0]["elapsedMs"] += 1
    else:
        receipt["observation"]["local"]["cases"][0]["checks"]["derivedLookup"] = False
    with pytest.raises(ValueError):
        module.render(json.loads(module.APPROVAL.read_bytes()), receipt)
