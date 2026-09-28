"""Validate a new artifact without rewriting the original mismatch."""

import copy
import importlib.util
import json
from pathlib import Path

import pytest


def test_recheck_publisher_exists_and_preserves_original_subject():
    path = Path(__file__).with_name("publish-auth-deleted-recheck.py")
    assert path.exists()
    spec = importlib.util.spec_from_file_location("deleted_recheck", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert (
        module.PREVIOUS_SUBJECT
        == "04f8ac7d63ee9e34eab54057a03c876dce2d75bc8e0e5eb0430b1f7cb5faedc1"
    )
    assert module.BUNDLE != module.old.BUNDLE


def publisher():
    spec = importlib.util.spec_from_file_location(
        "deleted_recheck",
        Path(__file__).with_name("publish-auth-deleted-recheck.py"),
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_recheck_matches_without_rewriting_production():
    module = publisher()
    value = json.loads(module.BUNDLE.read_bytes())
    module.validate(value)
    assert "not a new production run" in module.render(value)
    rows = value["observation"]["local"]["cases"]
    assert [row["observedError"] for row in rows[6:9]] == [
        "INVALID_LOGIN_CREDENTIALS",
        "USER_NOT_FOUND",
        "USER_NOT_FOUND",
    ]
    assert sum(row["outcome"] == "accepted" for row in rows) == 9


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
        "same-artifact",
        "same-receipt",
        "exit",
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
    elif mutation in {"same-artifact", "same-receipt"}:
        previous = json.loads(module.old.BUNDLE.read_bytes())
        key = "artifact" if mutation == "same-artifact" else "privateReceiptSha256"
        observation["local"][key] = previous["local"][key]
    elif mutation == "exit":
        observation["local"]["ownedProcess"]["exitCode"] = 2
    else:
        value["publicationContractSha256"] = "0" * 64
    with pytest.raises(ValueError):
        module.validate(value)


def test_only_bounded_elapsed_time_is_excluded_from_comparison():
    module = publisher()
    value = json.loads(module.BUNDLE.read_bytes())
    value["observation"]["local"]["cases"][0]["elapsedMs"] = 119999
    module.validate(value)
