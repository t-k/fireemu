"""Minimum approval is bound to one immutable receipt and 12 observations."""

import copy
import importlib.util
import json
from pathlib import Path

import pytest


def tool():
    path = Path(__file__).parents[1] / "auth-password-minimum-approval.py"
    assert path.exists(), "Subject-bound approval overlay required"
    spec = importlib.util.spec_from_file_location("minimum_approval", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_approval_page_is_current_and_bounded():
    t = tool()
    approval = json.loads(t.APPROVAL.read_bytes())
    receipt = json.loads(t.publisher.BUNDLE.read_bytes())
    page = t.render(approval, receipt)
    assert t.PAGE.read_text() == page
    assert "12 observations verified and approved" in page
    assert "not a guarantee of all password-policy boundaries" in page
    assert "historical integrity" in page
    assert len(approval["cases"]) == 12
    assert t.publisher.PAGE.read_text() == t.publisher.render(receipt)


@pytest.mark.parametrize(
    "field,value",
    [
        ("subjectSha256", "f" * 64),
        ("sourceCommit", "f" * 40),
        ("scope", "All Auth"),
        ("cases", ["signup"]),
        ("reviewer", "agent"),
        ("reviewedAt", "2099-01-01"),
        ("decision", "reject"),
        ("schemaVersion", True),
        ("extra", True),
    ],
)
def test_approval_cannot_be_transferred_or_expanded(field, value):
    t = tool()
    approval = json.loads(t.APPROVAL.read_bytes())
    approval[field] = value
    with pytest.raises(ValueError):
        t.render(approval, json.loads(t.publisher.BUNDLE.read_bytes()))


@pytest.mark.parametrize("change", ["outcome", "control", "artifact", "timing"])
def test_changed_receipt_cannot_reuse_approval(change):
    t = tool()
    receipt = copy.deepcopy(json.loads(t.publisher.BUNDLE.read_bytes()))
    if change == "artifact":
        receipt["local"]["artifact"]["sha256"] = "0" * 64
    elif change == "timing":
        receipt["local"]["cases"][0]["expirySeconds"] = "1"
    elif change == "control":
        receipt["local"]["cases"][10]["passed"] = False
    else:
        receipt["local"]["inputShape"]["replacementPasswordLength"] = 7
    with pytest.raises(ValueError):
        t.render(json.loads(t.APPROVAL.read_bytes()), receipt)
