"""Bind the checked-in local shadow evidence to the current working tree.

The receipt under `spec/compatibility/` was produced by running the collector
against an owned local `fireemu` instance. These checks fail if the sources it
names have changed, if the catalog has drifted, or if any case stopped agreeing
with its expected local result. They say nothing about production.
"""

import json
from pathlib import Path

from o6_listen_resume import cases
from o6_listen_resume.observation import compute_source_digests

REPO_ROOT = Path(__file__).resolve().parents[3]
EVIDENCE = REPO_ROOT / "spec/compatibility/fs-listen-sdk-local-shadow.json"


def _receipt():
    return json.loads(EVIDENCE.read_text(encoding="utf-8"))


def test_the_local_shadow_ran_to_completion_with_proven_cleanup():
    receipt = _receipt()
    assert receipt["complete"] is True
    assert receipt["productionExecuted"] is False
    assert receipt["environment"]["kind"] == "local-fireemu"
    assert receipt["cleanup"]["complete"] is True
    assert receipt["budget"]["exhausted"] is False
    assert receipt["cleanupBudget"]["exhausted"] is False


def test_every_cleanup_row_proves_absence_or_never_created_the_document():
    outcomes = {row["name"]: row["outcome"] for row in _receipt()["cleanup"]["rows"]}
    assert set(outcomes) == {"alpha", "beta", "gamma", "absent", "private"}
    assert set(outcomes.values()) <= {"deleted-and-absent", "not-created"}


def test_the_evidence_names_the_sources_that_produced_it():
    receipt = _receipt()
    current = compute_source_digests(REPO_ROOT)
    for relative, value in receipt["sourceDigests"].items():
        assert value == current[relative], relative
    assert receipt["catalogDigest"] == cases.catalog_digest()
    assert receipt["environment"]["sourceCommit"]


def test_the_evidence_carries_no_secret_material():
    raw = EVIDENCE.read_text(encoding="utf-8")
    for marker in ("password", "idToken", "refreshToken", "Bearer "):
        assert marker not in raw


def test_every_case_agreed_with_its_expected_local_result():
    receipt = _receipt()
    rows = {row["caseId"]: row for row in receipt["cases"]}
    assert set(rows) == set(cases.case_ids())
    for case in cases.CASES:
        row = rows[case["caseId"]]
        assert row["complete"] is True, case["caseId"]
        assert row["listenersClosed"] is True, case["caseId"]
        assert row["invariantViolations"] == [], case["caseId"]
        fields = case["comparedFields"]
        observed = [
            {key: event.get(key) for key in fields} for event in row["observed"]
        ]
        expected = [
            {key: event.get(key) for key in fields} for event in case["expectedLocal"]
        ]
        assert observed == expected, case["caseId"]


def test_every_listener_case_actually_delivered_or_declared_silence():
    for row in _receipt()["cases"]:
        case = cases.get_case(row["caseId"])
        if case["expectedLocal"]:
            assert row["observed"], row["caseId"]
        else:
            assert case["invariants"], row["caseId"]
