"""The new publisher must not reinterpret revision 1 evidence."""

import copy
import importlib.util
import json
from pathlib import Path

import pytest


def publisher():
    path = Path(__file__).parents[1] / "publish-auth-session-v2.py"
    assert path.exists(), "New publisher required"
    spec = importlib.util.spec_from_file_location("session_v2_publisher", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_revision1_receipt_is_not_revision2_evidence():
    p = publisher()
    original = json.loads(
        (
            p.ROOT / "spec/compatibility/evidence/auth-session-token/receipt.json"
        ).read_bytes()
    )
    with pytest.raises(ValueError):
        p.validate(original)


def test_committed_revision2_is_current_candidate_with_matching_observations():
    p = publisher()
    value = json.loads(p.BUNDLE.read_bytes())
    p.validate(value)
    assert value["acceptance"] == "candidate"
    assert p.PAGE.read_text() == p.render(value)
    assert len(value["local"]["cases"]) == len(value["production"]["cases"]) == 34
    for local, production in zip(
        value["local"]["cases"], value["production"]["cases"], strict=True
    ):
        assert (
            p.comparison(local, production, p.round_controls(value, local["id"]))
            == "Same observed result"
        )


@pytest.mark.parametrize(
    "mutation",
    ["artifact", "case", "timing", "corpus", "approval", "secret", "wrong-control"],
)
def test_receipt_mutations_fail_with_valid_positive_control(mutation):
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
        altered["corpus"]["revision"] = 1
    elif mutation == "approval":
        altered["acceptance"] = "approved"
    elif mutation == "secret":
        altered["local"]["cases"][0]["response"]["idToken"] = "must-not-publish"
    else:
        next(
            row for row in altered["local"]["cases"] if row["id"] == "unknown-refresh"
        )["response"]["error"] = "TOKEN_EXPIRED"
    with pytest.raises(ValueError):
        p.validate(altered)


def test_invalid_input_control_failure_suppresses_timed_comparisons():
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
