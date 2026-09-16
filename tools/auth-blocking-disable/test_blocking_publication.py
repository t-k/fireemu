"""The receipt carries only allowlisted fields, nested objects included, and names the
recorder that produced it separately from the contract that re-evaluated it."""

import importlib
import json
import sys
from pathlib import Path

import pytest
from test_blocking_contract import complete_report

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
publisher = importlib.import_module("publish-auth-blocking-disable")
RECORDER, REEVALUATION = "5" * 40, "3" * 40


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
            "configReadback": dict.fromkeys(publisher.CONFIGURATION_KEYS, True)
            | {"sha256": "2" * 64},
            "configRestoredReadback": {
                "mfa": {"state": "DISABLED"},
                "phoneNumber": {},
                "smsRegionConfig": {"allowlistOnly": {}},
                "blockingFunctions": {"forwardInboundCredentials": {}},
            },
            "lastStep": "lookup",
            "lastStatus": 200,
            "lastError": None,
            "lastErrorDetail": None,
            "idToken": "secret-token-value",
        }
    )
    return report


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
    assert set(out["configRestoredReadback"]) == set(publisher.RESTORED_KEYS)


def test_projection_refuses_nested_unknown_fields_and_incomplete_reports(monkeypatch):
    fake_git(monkeypatch)
    report = private_report()
    report["configRestoredReadback"]["lastErrorMessage"] = "REVIEW_SENTINEL"
    with pytest.raises(ValueError):
        publisher.project(report, RECORDER)
    report = private_report()
    report["functionRemoved"] = False
    with pytest.raises(ValueError):
        publisher.project(report, RECORDER)


def test_validation_checks_reevaluation_sources_by_content(monkeypatch):
    fake_git(monkeypatch)
    out = publisher.project(private_report(), RECORDER)
    publisher.validate_production(json.loads(json.dumps(out)))
    for mutate in (
        lambda v: v["reevaluatedWith"].__setitem__("contractSha256", "0" * 64),
        lambda v: v["reevaluatedWith"].__setitem__("commit", RECORDER),
        lambda v: v.__setitem__("probeSourceCommit", "7" * 40),
        lambda v: v["recordedWith"]["recorderInputs"].__setitem__("extra", "1" * 64),
    ):
        value = json.loads(json.dumps(out))
        mutate(value)
        with pytest.raises(ValueError):
            publisher.validate_production(value)
