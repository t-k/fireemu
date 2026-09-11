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
            "configReadback": {"sha256": "2" * 64},
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


def test_projection_keeps_only_allowlisted_fields(monkeypatch):
    monkeypatch.setattr(publisher, "git_blob_sha256", lambda commit, path: "1" * 64)
    monkeypatch.setattr(
        publisher,
        "reevaluated_with",
        lambda: {"commit": "3" * 40, "contractSha256": "4" * 64},
    )
    out = publisher.project(private_report(), "5" * 40)
    assert "secret-token-value" not in json.dumps(out)
    assert set(out) == set(publisher.PROJECTED) | {
        "configuration",
        "privateReceiptSha256",
        "recordedWith",
        "reevaluatedWith",
    }
    assert out["recordedWith"]["recorderCommit"] == "5" * 40
    assert out["recordedWith"]["probeSourceCommit"] == "0" * 40


def test_projection_refuses_a_recorder_that_does_not_match_the_named_commit(
    monkeypatch,
):
    monkeypatch.setattr(publisher, "git_blob_sha256", lambda commit, path: "9" * 64)
    with pytest.raises(ValueError):
        publisher.project(private_report(), "5" * 40)


def test_projection_refuses_an_incomplete_report(monkeypatch):
    monkeypatch.setattr(publisher, "git_blob_sha256", lambda commit, path: "1" * 64)
    report = private_report()
    report["configDigestMatches"] = False
    with pytest.raises(ValueError):
        publisher.project(report, "5" * 40)
