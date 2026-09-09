"""Finite approval-state model: only matching, explicitly reviewed subjects advance."""

import json
import shutil
from itertools import product

import pytest
from aggregation_corpus import corpus, query_body
from aggregation_evidence import (
    DIRECTORY,
    approved_cases,
    case_ids,
    validate_bundle,
    validate_document,
    validate_query_cases,
)
from evidence_common import save, sha


def test_approval_state_space_fails_closed():
    for present, current, scoped, identified in product([False, True], repeat=4):
        approval = {
            "subjectSha256": "subject" if current else "stale",
            "cases": ["count-alone"] if scoped else ["unknown"],
            "reviewer": "human-reviewer" if identified else "",
            "reviewedAt": "2000-01-01",
            "decision": "approve",
        }
        if not present:
            assert approved_cases([], "subject") == set()
        elif current and scoped and identified:
            assert approved_cases([approval], "subject") == {"count-alone"}
        else:
            with pytest.raises(ValueError):
                approved_cases([approval], "subject")


def test_well_formed_mismatch_is_visible_but_never_approval_eligible():
    collection = "compat_" + "a" * 32
    rows = [
        {
            "id": c["id"],
            "request": query_body(c, collection),
            "httpStatus": 200,
            "rawResponse": [{"result": {"aggregateFields": c["expected"]}}],
            "passed": True,
        }
        for c in corpus()["queries"]
    ]
    rows[6]["rawResponse"][0]["result"]["aggregateFields"] = {
        "count": {"integerValue": "2"},
        "sum": {"doubleValue": 30.5},
    }
    rows[6]["passed"] = False
    eligible = validate_query_cases(rows, collection)
    assert "missing-before-limit" not in eligible
    assert len(eligible) == 7
    approval = {
        "subjectSha256": "subject",
        "cases": ["missing-before-limit"],
        "reviewer": "synthetic",
        "reviewedAt": "2000-01-01",
        "decision": "approve",
    }
    with pytest.raises(ValueError):
        approved_cases([approval], "subject", eligible)


@pytest.mark.parametrize(
    "fields",
    [
        {"count": []},
        {"count": {"integerValue": True}},
        {"count": {"integerValue": "not-an-int"}},
        {"count": {"integerValue": "4", "doubleValue": 4}},
        {},
        {"count": {"integerValue": "4"}, "unexpected": {"integerValue": "0"}},
    ],
)
def test_malformed_inner_values_are_not_publishable_mismatches(fields):
    collection = "compat_" + "a" * 32
    rows = [
        {
            "id": c["id"],
            "request": query_body(c, collection),
            "httpStatus": 200,
            "rawResponse": [{"result": {"aggregateFields": c["expected"]}}],
            "passed": True,
        }
        for c in corpus()["queries"]
    ]
    rows[0]["rawResponse"] = [{"result": {"aggregateFields": fields}}]
    rows[0]["passed"] = False
    with pytest.raises((ValueError, TypeError)):
        validate_query_cases(rows, collection)


def test_state_control_requires_complete_document_timestamps():
    document = {
        "name": "fixture",
        "fields": {},
        "createTime": "2026-09-09T00:00:00Z",
        "updateTime": "2026-09-09T00:00:00Z",
    }
    validate_document(document)
    for key in ["createTime", "updateTime"]:
        missing = dict(document)
        del missing[key]
        with pytest.raises(ValueError):
            validate_document(missing)


def test_every_raw_response_element_is_checked_even_when_passed_is_true():
    collection = "compat_" + "a" * 32
    rows = [
        {
            "id": c["id"],
            "request": query_body(c, collection),
            "httpStatus": 200,
            "rawResponse": [{"result": {"aggregateFields": c["expected"]}}],
            "passed": True,
        }
        for c in corpus()["queries"]
    ]
    validate_query_cases(rows, collection)
    for tail in [None, {"error": {"code": 13}}, {}]:
        rows[0]["rawResponse"].append(tail)
        with pytest.raises((ValueError, TypeError)):
            validate_query_cases(rows, collection)
        rows[0]["rawResponse"].pop()
    with pytest.raises(ValueError):
        validate_query_cases(rows[:-1], collection)


def test_real_bundle_remains_pending_and_test_only_approval_is_scoped(tmp_path):
    _index, _accepted, subject = validate_bundle()
    copied = tmp_path / "bundle"
    shutil.copytree(DIRECTORY, copied)
    index = json.loads((copied / "index.json").read_bytes())
    index["approvals"] = []
    save(copied / "index.json", index)
    assert validate_bundle(copied)[1] == set()
    eligible = set(case_ids())
    for target in ["local", "production"]:
        receipt = json.loads((copied / f"{target}.json").read_bytes())
        eligible &= {row["id"] for row in receipt["cases"] if row["passed"]}
    index["approvals"] = [
        {
            "decision": "approve",
            "subjectSha256": subject,
            "cases": sorted(eligible),
            "reviewer": "synthetic-test-only",
            "reviewedAt": "2000-01-01",
        }
    ]
    save(copied / "index.json", index)
    assert validate_bundle(copied)[1] == eligible


@pytest.mark.parametrize(
    "mutation",
    [
        "artifact",
        "launch",
        "config-hash",
        "index-hash",
        "child-pid",
        "origin",
        "compiler",
        "profile",
        "external",
        "case",
        "raw-error",
        "timestamps",
        "cleanup",
        "runtime",
        "probe",
        "source",
        "approval",
    ],
)
def test_bound_bundle_mutations_never_strengthen_evidence(tmp_path, mutation):
    copied = tmp_path / "bundle"
    shutil.copytree(DIRECTORY, copied)
    index = json.loads((copied / "index.json").read_bytes())
    local = json.loads((copied / "local.json").read_bytes())
    if mutation == "artifact":
        local["artifact"]["sha256"] = local["build"]["artifactSha256"] = "not-a-hash"
    elif mutation == "launch":
        local["ownedProcess"]["launch"]["only"] = "auth"
    elif mutation in ["config-hash", "index-hash"]:
        local["configuration"][
            "fileSha256" if mutation == "config-hash" else "indexFileSha256"
        ] = "wrong"
    elif mutation == "child-pid":
        del local["instance"]["childPid"]
    elif mutation == "origin":
        local["instance"]["firestoreOrigin"] = "http://foreign.test:123"
    elif mutation == "compiler":
        del local["build"]["rustc"]
    elif mutation == "profile":
        local["instance"]["profile"] = "emulator"
    elif mutation == "external":
        local["connection"] = "external-daemon-unverified"
    elif mutation == "case":
        local["cases"].pop()
    elif mutation == "raw-error":
        local["cases"][0]["rawResponse"].append({"error": {"code": 13}})
    elif mutation == "timestamps":
        for states in ["stateBefore", "stateAfter"]:
            for document in local[states].values():
                del document["updateTime"]
    elif mutation == "cleanup":
        local["cleanup"][0]["confirmedMissing"] = False
    elif mutation == "runtime":
        local["runtimeSource"]["files"].pop("Cargo.toml")
    elif mutation == "probe":
        local["probeSource"]["files"].pop("capture.py")
    elif mutation == "source":
        review = json.loads((copied / "source-review.json").read_bytes())
        review["bodySha256"] = "wrong"
        save(copied / "source-review.json", review)
        index["files"]["source-review.json"] = sha(
            (copied / "source-review.json").read_bytes()
        )
    elif mutation == "approval":
        index["approvals"] = [
            {
                "decision": "approve",
                "subjectSha256": "stale",
                "cases": case_ids(),
                "reviewer": "synthetic-test-only",
                "reviewedAt": "2000-01-01",
            }
        ]
    save(copied / "local.json", local)
    index["files"]["local.json"] = sha((copied / "local.json").read_bytes())
    save(copied / "index.json", index)
    with pytest.raises((ValueError, KeyError, TypeError)):
        validate_bundle(copied)
