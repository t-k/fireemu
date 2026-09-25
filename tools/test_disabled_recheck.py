"""Validate a new artifact without rewriting the original mismatch."""

import copy
import importlib.util
import json
from pathlib import Path

import pytest


def test_recheck_publisher_exists_and_preserves_original_subject():
    path = Path(__file__).with_name("publish-auth-disabled-recheck.py")
    assert path.exists()
    spec = importlib.util.spec_from_file_location("disabled_recheck", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert (
        module.PREVIOUS_SUBJECT
        == "ff502af7fc37542347394d0f28e8df1b9b1566b64a5acb496a41402f040cf3de"
    )
    assert module.BUNDLE != module.old.BUNDLE


def publisher():
    spec = importlib.util.spec_from_file_location(
        "disabled_recheck",
        Path(__file__).with_name("publish-auth-disabled-recheck.py"),
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
        "error",
        "timing",
        "cleanup",
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
        observation["local"]["cases"][0]["checks"]["derivedLookup"] = False
    elif mutation == "secret":
        observation["local"]["cases"][0]["idToken"] = "must-not-publish"
    elif mutation == "acceptance":
        observation["acceptance"] = "approved"
    elif mutation == "error":
        observation["local"]["cases"][6]["observedError"] = "TOKEN_EXPIRED"
    elif mutation == "timing":
        observation["local"]["cases"][0]["elapsedMs"] = 120001
    elif mutation == "cleanup":
        observation["local"]["cleanup"]["uidAbsent"] = False
    else:
        value["publicationContractSha256"] = "0" * 64
    with pytest.raises(ValueError):
        module.validate(value)


def test_only_bounded_elapsed_time_is_excluded_from_comparison():
    module = publisher()
    value = json.loads(module.BUNDLE.read_bytes())
    value["observation"]["local"]["cases"][0]["elapsedMs"] = 119999
    module.validate(value)
