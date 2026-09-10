"""No-change evidence has its own subject, never inherited password-change approval."""

import copy
import importlib.util
import json
from pathlib import Path

import pytest


def publisher():
    path = Path(__file__).parents[1] / "publish-auth-session-continuity.py"
    assert path.exists(), "Independent continuity publisher required"
    spec = importlib.util.spec_from_file_location("continuity_publisher", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_changed_password_receipt_is_not_no_change_evidence():
    p = publisher()
    receipt = json.loads(
        (
            p.ROOT / "spec/compatibility/evidence/auth-session-v2/receipt.json"
        ).read_bytes()
    )
    with pytest.raises(ValueError):
        p.validate(receipt)


def test_committed_candidate_has_34_matching_observations():
    p = publisher()
    value = json.loads(p.BUNDLE.read_bytes())
    p.validate(value)
    assert value["acceptance"] == "candidate"
    assert p.PAGE.read_text() == p.render(value)
    assert len(value["local"]["cases"]) == 34
    for local, production in zip(
        value["local"]["cases"], value["production"]["cases"], strict=True
    ):
        assert (
            p.comparison(local, production, p.round_controls(value, local["id"]))
            == "Same observed result"
        )


@pytest.mark.parametrize(
    "mutation", ["artifact", "case", "timing", "corpus", "approval", "secret"]
)
def test_mutations_rejected_after_positive_validation(mutation):
    p = publisher()
    value = json.loads(p.BUNDLE.read_bytes())
    p.validate(value)
    altered = copy.deepcopy(value)
    if mutation == "artifact":
        altered["local"]["artifact"]["sha256"] = "0" * 64
    elif mutation == "case":
        altered["local"]["cases"].pop()
    elif mutation == "timing":
        altered["local"]["cases"][0]["primaryEndMs"] = -1
    elif mutation == "corpus":
        altered["corpus"]["revision"] = 2
    elif mutation == "approval":
        altered["acceptance"] = "approved"
    else:
        altered["local"]["cases"][0]["response"]["idToken"] = "must-not-publish"
    with pytest.raises(ValueError):
        p.validate(altered)


def test_failed_invalid_input_control_suppresses_continuity_claims():
    p = publisher()
    value = json.loads(p.BUNDLE.read_bytes())
    p.validate(value)
    row = next(row for row in value["local"]["cases"] if row["id"] == "unknown-refresh")
    row["response"]["error"] = "TOKEN_EXPIRED"
    row["quality"] = "inconclusive"
    value["local"]["status"] = "inconclusive"
    p.validate(value)
    assert not p.round_controls(value, "a-refresh@0")
    assert "Inconclusive (controls/timing)" in p.render(value)
