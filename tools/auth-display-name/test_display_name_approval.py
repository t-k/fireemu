"""Approval is an immutable, scoped overlay, never a replacement receipt."""

import copy
import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def load_tool():
    path = ROOT / "auth-display-name-approval.py"
    assert path.exists(), "The subject-preserving approval overlay must exist"
    spec = importlib.util.spec_from_file_location("auth_display_name_approval", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_approved_overlay_is_current_and_scoped():
    tool = load_tool()
    approval = json.loads(tool.APPROVAL.read_bytes())
    receipt = json.loads(tool.publisher.BUNDLE.read_bytes())
    page = tool.render(approval, receipt)
    assert tool.PAGE.read_text() == page
    assert "Twelve scoped cases verified and approved" in page
    assert "end-user tokens" in page
    assert "Expired-token refusal" in page
    assert tool.publisher.PAGE.read_text() == tool.publisher.render(receipt)


@pytest.mark.parametrize(
    "field,value",
    [
        ("subjectSha256", "f" * 64),
        ("sourceCommit", "f" * 40),
        ("scope", "All Auth, Admin only"),
        ("cases", ["signup"]),
        ("reviewer", "agent"),
        ("reviewedAt", "2099-01-01"),
        ("decision", "reject"),
        ("extra", True),
    ],
)
def test_approval_metadata_cannot_be_transferred_or_expanded(field, value):
    tool = load_tool()
    approval = json.loads(tool.APPROVAL.read_bytes())
    approval[field] = value
    with pytest.raises(ValueError):
        tool.render(approval, json.loads(tool.publisher.BUNDLE.read_bytes()))


def test_changed_observation_cannot_reuse_approval():
    tool = load_tool()
    receipt = copy.deepcopy(json.loads(tool.publisher.BUNDLE.read_bytes()))
    receipt["local"]["cases"][0]["passed"] = False
    with pytest.raises(ValueError):
        tool.render(json.loads(tool.APPROVAL.read_bytes()), receipt)
