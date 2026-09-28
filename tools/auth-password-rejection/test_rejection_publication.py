"""A new refusal slice cannot reinterpret an earlier approved password receipt."""

import copy
import importlib.util
import json
from pathlib import Path

import pytest


def publisher():
    path = Path(__file__).parents[1] / "publish-auth-password-rejection.py"
    spec = importlib.util.spec_from_file_location("rejection_publisher", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_previous_password_receipt_is_not_this_candidate():
    p = publisher()
    old = json.loads(
        (p.ROOT / "spec/compatibility/evidence/auth-password/receipt.json").read_bytes()
    )
    with pytest.raises(ValueError):
        p.validate(old)


def test_committed_candidate_has_16_successes_without_approval():
    p = publisher()
    value = json.loads(p.BUNDLE.read_bytes())
    p.validate(value)
    assert value["acceptance"] == "candidate"
    assert p.PAGE.read_text() == p.render(value)
    for target in ("local", "production"):
        assert len(value[target]["cases"]) == 16
        assert all(row["passed"] for row in value[target]["cases"])
        assert value[target]["cases"][4]["observedError"] == "WEAK_PASSWORD"


@pytest.mark.parametrize(
    "mutation",
    [
        "artifact",
        "case",
        "approval",
        "secret",
        "unknown-code",
        "wrong-code",
        "cleanup",
        "exit",
    ],
)
def test_publication_mutations_are_rejected_after_valid_control(mutation):
    p = publisher()
    value = json.loads(p.BUNDLE.read_bytes())
    p.validate(value)
    altered = copy.deepcopy(value)
    if mutation == "artifact":
        altered["local"]["artifact"]["sha256"] = "0" * 64
    elif mutation == "case":
        altered["local"]["cases"].pop()
    elif mutation == "approval":
        altered["acceptance"] = "approved"
    elif mutation == "secret":
        altered["local"]["cases"][4]["idToken"] = "PRIVATE_SECRET"
    elif mutation in {"unknown-code", "wrong-code"}:
        altered["local"]["cases"][4]["observedError"] = (
            "PRIVATE_SECRET" if mutation == "unknown-code" else "INVALID_ID_TOKEN"
        )
    elif mutation == "cleanup":
        altered["local"]["cleanup"]["uidAbsent"] = False
    else:
        altered["local"]["ownedProcess"]["exitCode"] = 2
    with pytest.raises(ValueError):
        p.validate(altered)


def test_well_formed_refusal_disagreement_remains_visible_not_approved():
    p = publisher()
    value = json.loads(p.BUNDLE.read_bytes())
    p.validate(value)
    row = value["local"]["cases"][4]
    row["observedError"] = "INVALID_ID_TOKEN"
    row["checks"]["expectedError"] = False
    row["passed"] = False
    p.validate(value)
    assert "Mismatch" in p.render(value)
    assert value["acceptance"] == "candidate"
