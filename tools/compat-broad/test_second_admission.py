"""Closed45 recipes detect symmetric mistakes before comparison."""

import copy

import pytest
from second_admission import (
    BASE,
    FS_IDS,
    SecondBudget,
    auth_recipe,
    fs_recipe,
    manifest,
    origins,
    require_operation,
)
from second_cases import auth_cases
from second_mapped import render_auth, render_fs
from second_mapping import compare_second

USERS = {
    r: {"uid": r + "-uid", "token": r + "-token", "email": r + "@example.invalid"}
    for r in ("a", "b")
}


def test_closed_source_and_independent_recipes_agree():
    assert manifest()["diagnosticRows"] == 45
    for i, case in enumerate(auth_cases()):
        require_operation(render_auth(case, USERS), auth_recipe(i, USERS))
    for program in manifest()["firestorePrograms"]:
        for step in program["steps"]:
            versions = {
                "original": "2026-09-13T00:00:00Z",
                "before": "2026-09-13T00:00:01Z",
            }
            expected, _ = fs_recipe(
                program["id"], step["id"], BASE + "/cur/c", versions
            )
            require_operation(render_fs(step, BASE + "/cur/c", versions), expected)


@pytest.mark.parametrize(
    "index,field,value",
    [
        (0, "idToken", "a-token"),
        (2, "localId", "foreign"),
        (3, "localId", 0),
        (9, "displayName", False),
        (26, "localId", "a-uid"),
    ],
)
def test_wrong_subject_and_typed_input_rejected(index, field, value):
    expected = auth_recipe(index, USERS)
    wrong = copy.deepcopy(expected)
    wrong["body"][field] = value
    with pytest.raises(ValueError):
        require_operation(wrong, expected)


@pytest.mark.parametrize(
    "change", ["drop", "deduplicate", "wrong-project", "wrong-document", "latest"]
)
def test_firestore_mutations_rejected(change):
    versions = {"original": "old", "before": "new"}
    program = FS_IDS[1] if change == "latest" else FS_IDS[0]
    expected, _ = fs_recipe(program, "diagnostic", BASE + "/cur/c", versions)
    wrong = copy.deepcopy(expected)
    if change in ("drop", "deduplicate"):
        wrong["query"] = [] if change == "drop" else wrong["query"][:1]
    elif change == "latest":
        wrong["query"][0][1] = "new"
    else:
        wrong["path"] = (
            wrong["path"].replace("fireemu-35fe6", "other")
            if change == "wrong-project"
            else wrong["path"] + "-foreign"
        )
    with pytest.raises(ValueError):
        require_operation(wrong, expected)


def test_original_version_relation_cannot_be_erased():
    with pytest.raises(ValueError):
        fs_recipe(
            FS_IDS[1],
            "diagnostic",
            BASE + "/cur/c",
            {"original": "same", "before": "same"},
        )


@pytest.mark.parametrize(
    "value",
    [
        None,
        {},
        {"auth": "http://127.0.0.1:9000"},
        {"auth": "https://google.com", "firestore": "http://127.0.0.1:9001"},
    ],
)
def test_no_remote_fallback(value):
    with pytest.raises((ValueError, TypeError)):
        origins(value)


def test_recovery_service_reserve_survives_observation_exhaustion():
    budget = SecondBudget(0)
    for _ in range(388):
        budget.reserve("auth", 1)
    with pytest.raises(ValueError):
        budget.reserve("auth", 1)
    budget.recovery = True
    for _ in range(12):
        budget.reserve("auth", 901)
    assert budget.counts == {
        "auth": 400,
        "firestore": 0,
        "metadata": 0,
        "recovery": 12,
        "total": 400,
    }
    with pytest.raises(ValueError):
        budget.reserve("auth", 901)
    with pytest.raises(ValueError):
        budget.reserve("firestore", 1190)


def test_symmetric_missing_rows_not_mapping_success():
    result = {
        "rows": [],
        "recordingComplete": True,
        "cleanupComplete": True,
        "safety": True,
    }
    assert compare_second(result, copy.deepcopy(result))["mapping"] == "invalid"
