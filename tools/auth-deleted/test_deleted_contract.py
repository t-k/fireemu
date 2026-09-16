"""Deleted-user rejections cannot replace successful baseline or control use."""

import importlib.util
from pathlib import Path

import pytest


def contract():
    path = Path(__file__).with_name("deleted_contract.py")
    assert path.exists()
    spec = importlib.util.spec_from_file_location("deleted_contract", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def refused(name):
    return {
        "id": name,
        "httpStatus": 400,
        "outcome": "refused",
        "observedError": "USER_NOT_FOUND",
        "checks": {},
        "expirySeconds": None,
        "elapsedMs": 1,
    }


def test_only_deleted_target_may_be_refused():
    module = contract()
    assert len(module.CASES) == 12
    for name in module.CASES:
        if name.startswith("deleted-a-"):
            module.validate_row(refused(name), name)
        else:
            with pytest.raises(ValueError):
                module.validate_row(refused(name), name)


@pytest.mark.parametrize(
    "field,value",
    [
        ("httpStatus", 200),
        ("observedError", "private diagnostic"),
        ("elapsedMs", 120001),
        ("idToken", "secret"),
    ],
)
def test_bad_rejection_or_secret_is_rejected(field, value):
    module = contract()
    row = refused("deleted-a-id")
    row[field] = value
    with pytest.raises(ValueError):
        module.validate_row(row, row["id"])


def test_unknown_error_text_is_never_retained():
    module = contract()
    assert (
        module.error_code({"error": {"message": "USER_NOT_FOUND : private detail"}})
        == "USER_NOT_FOUND"
    )
    assert module.error_code({"error": {"message": "secret"}}) == "UNCLASSIFIED_ERROR"


def test_success_for_deleted_target_is_not_an_accepted_result():
    module = contract()
    row = refused("deleted-a-id")
    row.update(
        httpStatus=200,
        outcome="accepted",
        observedError=None,
        checks={"stateMatches": True},
    )
    with pytest.raises(ValueError):
        module.validate_row(row, row["id"])


def successful_report():
    module = contract()
    rows = []
    for name in module.CASES:
        row = refused(name)
        if not name.startswith("deleted-a-"):
            route = name.split("-")[-1]
            flags = (
                {"stateMatches"}
                if route == "id"
                else set(module.tokens({}, "uid", "email", route == "refresh"))
                | {"derivedLookup"}
            )
            row.update(
                httpStatus=200,
                outcome="accepted",
                observedError=None,
                checks={flag: True for flag in flags},
                expirySeconds=None if route == "id" else "3600",
            )
        rows.append(row)
    return {
        "status": "observed",
        "cases": rows,
        "setup": {"a": True, "b": True},
        "transitions": [
            {
                "deleteHttpStatus": 200,
                "uidAbsent": True,
                "emailAbsent": True,
                "controlUnchanged": True,
            }
        ],
        "cleanup": {"uidAbsent": True, "emailAbsent": True},
    }


@pytest.mark.parametrize(
    "mutation",
    [
        "failure",
        "cleanupFailure",
        "childCleanupFailure",
        "transition",
        "setup",
        "cleanup",
        "missing",
        "duplicate",
        "control",
    ],
)
def test_completion_needs_every_control_and_cleanup(mutation):
    module = contract()
    report = successful_report()
    assert module.complete(report)
    if mutation in {"failure", "cleanupFailure", "childCleanupFailure"}:
        report[mutation] = "Failure"
    elif mutation == "transition":
        report["transitions"][0]["uidAbsent"] = 1
    elif mutation == "setup":
        report["setup"]["a"] = 1
    elif mutation == "cleanup":
        report["cleanup"]["uidAbsent"] = False
    elif mutation == "missing":
        report["cases"].pop()
    elif mutation == "duplicate":
        report["cases"][-1] = report["cases"][0]
    else:
        report["cases"][0]["checks"]["derivedLookup"] = False
    assert not module.complete(report)
