"""Validate a new artifact without rewriting the original mismatch."""

import copy
import importlib.util
import json
from pathlib import Path

import pytest


def test_recheck_publisher_exists_and_preserves_original_subject():
    path = Path(__file__).with_name("publish-auth-password-unicode-recheck.py")
    assert path.exists()
    spec = importlib.util.spec_from_file_location("unicode_recheck", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert (
        module.PREVIOUS_SUBJECT
        == "9c0364b6cabdf9497c243db1956655e9d455a08578b0ce1f58bd39d5aa9dcfbf"
    )
    assert module.BUNDLE != module.old.BUNDLE


def publisher():
    spec = importlib.util.spec_from_file_location(
        "unicode_recheck",
        Path(__file__).with_name("publish-auth-password-unicode-recheck.py"),
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_recheck_matches_without_rewriting_production():
    module = publisher()
    value = json.loads(module.BUNDLE.read_bytes())
    module.validate(value)
    assert "not a new production run" in module.render(value)


@pytest.mark.parametrize(
    "mutation",
    [
        "previous",
        "production",
        "artifact",
        "control",
        "secret",
        "acceptance",
        "publisher",
    ],
)
def test_recheck_rejects_misattribution_or_failed_controls(mutation):
    module = publisher()
    value = copy.deepcopy(json.loads(module.BUNDLE.read_bytes()))
    observation = value["observation"]
    if mutation == "previous":
        value["previousSubject"] = "0" * 64
    elif mutation == "production":
        observation["production"]["recordedAt"] = observation["local"]["recordedAt"]
    elif mutation == "artifact":
        observation["local"]["artifact"]["sha256"] = "0" * 64
    elif mutation == "control":
        observation["local"]["cases"][0]["checks"]["postLookup"] = False
    elif mutation == "secret":
        observation["local"]["cases"][0]["idToken"] = "must-not-publish"
    elif mutation == "acceptance":
        observation["acceptance"] = "approved"
    else:
        value["publicationContractSha256"] = "0" * 64
    with pytest.raises(ValueError):
        module.validate(value)
