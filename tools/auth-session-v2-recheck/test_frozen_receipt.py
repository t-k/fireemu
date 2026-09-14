"""Verify historical auth-session-v2 receipts without changing frozen sources."""

import copy
import importlib.util
import json
from pathlib import Path

import pytest


ROOT = Path(__file__).parents[2]


def module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


@pytest.fixture(scope="module")
def frozen():
    return module(ROOT / "tools/auth-session-v2-frozen.py", "session_v2_frozen")


def receipt(frozen):
    return json.loads(frozen.BUNDLE.read_bytes())


def test_frozen_receipt_binds_recorded_probe_and_runtime(frozen):
    value = receipt(frozen)
    frozen.validate_frozen(value)
    assert value["probeInputs"] == frozen._probe_inputs_at_commit(
        value["local"]["probeSourceCommit"]
    )
    assert value["probeInputs"] != frozen.inputs()


def test_frozen_receipt_rejects_probe_input_tampering(frozen):
    value = receipt(frozen)
    value["probeInputs"]["tools/auth-session-v2/session_v2_contract.py"] = "0" * 64
    with pytest.raises(ValueError):
        frozen.validate_frozen(value)


@pytest.mark.parametrize(
    "mutation",
    ["artifact", "case", "timing", "corpus", "approval", "secret", "control"],
)
def test_frozen_receipt_mutations_fail(mutation, frozen):
    value = copy.deepcopy(receipt(frozen))
    if mutation == "artifact":
        value["local"]["artifact"]["sha256"] = "0" * 64
    elif mutation == "case":
        value["local"]["cases"].pop()
    elif mutation == "timing":
        value["local"]["cases"][0]["primaryEndMs"] = -1
    elif mutation == "corpus":
        value["corpus"]["revision"] = 1
    elif mutation == "approval":
        value["acceptance"] = "approved"
    elif mutation == "secret":
        value["local"]["cases"][0]["response"]["idToken"] = "must-not-publish"
    else:
        next(
            row for row in value["local"]["cases"] if row["id"] == "unknown-refresh"
        )["response"]["error"] = "TOKEN_EXPIRED"
    with pytest.raises(ValueError):
        frozen.validate_frozen(value)


def test_frozen_render_matches_published_page(frozen):
    value = receipt(frozen)
    assert frozen.PAGE.read_text() == frozen.render_frozen(value)


def test_approval_uses_frozen_validation_without_modifying_approval_source(frozen):
    approval_tool = module(
        ROOT / "tools/auth-session-v2-approval.py", "session_v2_approval"
    )
    approval_tool.publisher.validate = frozen.validate_frozen
    value = receipt(frozen)
    approval = json.loads(approval_tool.APPROVAL.read_bytes())
    assert approval_tool.PAGE.read_text() == approval_tool.render(approval, value)
