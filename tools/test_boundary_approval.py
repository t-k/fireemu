"""The human decision cannot transfer to altered evidence or scope."""

import copy
import importlib.util
import json
from pathlib import Path

import pytest


def load():
    spec = importlib.util.spec_from_file_location(
        "boundary_approval",
        Path(__file__).with_name("auth-password-unicode-boundary-approval.py"),
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_human_approval_matches_complete_subject():
    module = load()
    page = module.render(
        json.loads(module.APPROVAL.read_bytes()),
        json.loads(module.publisher.BUNDLE.read_bytes()),
    )
    assert "3 input patterns verified and approved" in page
    assert "4095/4096 accepted and 4097 refused" in page


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


@pytest.mark.parametrize("field", ["artifact", "production", "control"])
def test_changed_observation_cannot_inherit_approval(field):
    module = load()
    receipt = copy.deepcopy(json.loads(module.publisher.BUNDLE.read_bytes()))
    if field == "artifact":
        receipt["local"]["artifact"]["sha256"] = "0" * 64
    elif field == "production":
        receipt["production"]["recordedAt"] = "changed"
    else:
        receipt["local"]["cases"][0]["checks"]["postLookup"] = False
    with pytest.raises(ValueError):
        module.render(json.loads(module.APPROVAL.read_bytes()), receipt)
