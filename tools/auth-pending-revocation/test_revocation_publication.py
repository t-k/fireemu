"""The receipt carries only allowlisted fields of the private report, and names the
recorder that produced it separately from the contract that re-evaluated it."""

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
import importlib

publisher = importlib.import_module("publish-auth-pending-revocation")
from test_revocation_safety import complete_report


def private_report():
    report = complete_report()
    report.update(
        {
            "schemaVersion": 1,
            "acceptance": "candidate",
            "target": "production",
            "project": "fireemu-35fe6",
            "projectNumber": "592603257417",
            "corpus": publisher.CORPUS,
            "recordedAt": "2026-09-11T00:00:00+00:00",
            "probeSourceCommit": "0" * 40,
            "probeInputs": {path: "1" * 64 for path in publisher.RECORDER_FILES},
            "configReadback": {
                "sha256": "2" * 64,
                "emailEnabled": True,
                "passwordRequired": True,
                "improvedEmailPrivacy": True,
                "blockingTriggersAbsent": True,
                "adminPasswordPolicyAbsent": True,
            },
            "configRestoredReadback": {
                "mfa": {"state": "DISABLED"},
                "phoneNumber": {},
                "smsRegionConfig": {"allowlistOnly": {}},
            },
            "heldFinalizeTimes": {"authTime": 3, "iat": 3, "validSince": 1},
            # Fields a run may leave behind that must never be published.
            "lastStep": "mfaSignIn:finalize",
            "lastStatus": 200,
            "lastError": None,
            "lastErrorDetail": None,
            "lastPendingShape": ["mfaPendingCredential"],
            "idToken": "secret-token-value",
        }
    )
    return report


RECORDER, REEVALUATION = "5" * 40, "3" * 40


def fake_git(monkeypatch):
    contract_sha = publisher.working_tree_sha256(publisher.RECORDER_FILES[0])

    def blob(commit, path):
        if commit == RECORDER:
            return "1" * 64
        if commit == REEVALUATION and path == publisher.RECORDER_FILES[0]:
            return contract_sha
        return "f" * 64

    monkeypatch.setattr(publisher, "git_blob_sha256", blob)
    monkeypatch.setattr(
        publisher,
        "reevaluated_with",
        lambda: {"commit": REEVALUATION, "contractSha256": contract_sha},
    )


def test_projection_keeps_only_allowlisted_fields(monkeypatch):
    fake_git(monkeypatch)
    out = publisher.project(private_report(), RECORDER)
    assert "secret-token-value" not in json.dumps(out)
    assert set(out) == set(publisher.PROJECTED) | {
        "configuration",
        "privateReceiptSha256",
        "recordedWith",
        "reevaluatedWith",
    }
    assert out["recordedWith"]["recorderCommit"] == RECORDER
    assert out["recordedWith"]["probeSourceCommit"] == "0" * 40


def test_projection_refuses_a_recorder_that_does_not_match_the_named_commit(
    monkeypatch,
):
    monkeypatch.setattr(publisher, "git_blob_sha256", lambda commit, path: "9" * 64)
    with pytest.raises(ValueError):
        publisher.project(private_report(), "5" * 40)


def test_projection_refuses_an_incomplete_report(monkeypatch):
    fake_git(monkeypatch)
    report = private_report()
    report["configDigestMatches"] = False
    with pytest.raises(ValueError):
        publisher.project(report, "5" * 40)


def published(monkeypatch):
    fake_git(monkeypatch)
    return publisher.project(private_report(), RECORDER)


def test_projection_refuses_unknown_nested_fields(monkeypatch):
    fake_git(monkeypatch)
    report = private_report()
    report["configRestoredReadback"]["lastErrorMessage"] = "REVIEW_SENTINEL"
    with pytest.raises(ValueError):
        publisher.project(report, RECORDER)


def test_validation_refuses_unknown_nested_fields_in_a_receipt(monkeypatch):
    out = published(monkeypatch)

    def check(mutate):
        value = json.loads(json.dumps(out))
        mutate(value)
        with pytest.raises(ValueError):
            publisher.validate_production(value)

    check(lambda v: v["configRestoredReadback"].__setitem__("extra", "REVIEW_SENTINEL"))
    check(lambda v: v["recordedWith"]["recorderInputs"].__setitem__("extra", "1" * 64))
    check(lambda v: v["heldFinalizeTimes"].__setitem__("extra", 1))
    check(lambda v: v["configuration"].__setitem__("extra", True))


def test_validation_checks_reevaluation_sources_by_content(monkeypatch):
    out = published(monkeypatch)
    publisher.validate_production(json.loads(json.dumps(out)))
    for mutate in (
        lambda v: v["reevaluatedWith"].__setitem__("contractSha256", "0" * 64),
        lambda v: v["reevaluatedWith"].__setitem__("commit", RECORDER),
        lambda v: v.__setitem__("probeSourceCommit", "7" * 40),
    ):
        value = json.loads(json.dumps(out))
        mutate(value)
        with pytest.raises(ValueError):
            publisher.validate_production(value)
