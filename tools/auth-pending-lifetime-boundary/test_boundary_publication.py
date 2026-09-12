"""Revision-2 publication source binding, redaction and candidate semantics."""

import copy
import importlib
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "tools/compat-inventory"))
production = importlib.import_module("publish-auth-pending-lifetime-boundary")
comparison = importlib.import_module(
    "publish-auth-pending-lifetime-boundary-comparison"
)
from manifest_closure import in_repo_closure
from test_boundary_safety import run

COMMIT = "267b10f5a1edf70a2da1a7dff7260e9945f2bd05"
REC = ROOT / "tools/auth-pending-lifetime-boundary/boundary_recorder.py"
OWN = ROOT / "tools/auth-pending-lifetime-boundary/boundary_owned.py"


@pytest.mark.parametrize(
    "publisher,entries", [(production, [REC]), (comparison, [REC, OWN])]
)
def test_execution_manifest_matches_transitive_import_closure(publisher, entries):
    assert set(publisher.RECORDER_FILES) == in_repo_closure(entries)


@pytest.mark.parametrize("publisher", [production, comparison])
def test_execution_commit_hashes_are_checked_against_real_git(publisher):
    report: dict = {
        "probeSourceCommit": COMMIT,
        "probeInputs": {
            p: publisher.git_blob_sha256(COMMIT, p) for p in publisher.RECORDER_FILES
        },
    }
    assert publisher.recorded_with(report, COMMIT)["recorderCommit"] == COMMIT
    for path in publisher.RECORDER_FILES:
        changed = copy.deepcopy(report)
        changed["probeInputs"][path] = "f" * 64
        with pytest.raises(ValueError):
            publisher.recorded_with(changed, COMMIT)
        del changed["probeInputs"][path]
        with pytest.raises((ValueError, KeyError)):
            publisher.recorded_with(changed, COMMIT)
    report["probeSourceCommit"] = "a" * 40
    with pytest.raises(ValueError):
        publisher.recorded_with(report, COMMIT)


def publishable_report(tmp_path, monkeypatch):
    _, _, report = run(tmp_path, monkeypatch, ttl=3901, delay={"signInWithPassword": 3})
    report["probeSourceCommit"] = COMMIT
    report["configRestoredReadback"]["phoneNumber"] = {}
    report["configReadback"] = {
        key: "0" * 64 if key == "sha256" else True
        for key in production.CONFIGURATION_KEYS
    }
    # The fixture deliberately bypasses config projection, so supply the already checked
    # allowlisted projection rather than make a network request.
    return report


def test_projection_keeps_auth_evidence_and_only_candidate_intervals(
    tmp_path, monkeypatch
):
    report = publishable_report(tmp_path, monkeypatch)
    report["privateSecret"] = "do-not-publish"
    projected = production.project(report, COMMIT)
    assert projected["privilegedRequests"] == report["privilegedRequests"]
    assert projected["authOperations"] == report["authOperations"]
    assert "privateSecret" not in projected
    assert projected["lifetimeSummary"]["upperBoundEstablished"] is False
    assert projected["lifetimeSummary"]["boundaryCandidates"][0]["upperSeconds"] == 3903
    production.validate_production(projected)
    projected["lifetimeSummary"]["upperBoundEstablished"] = True
    with pytest.raises(ValueError):
        production.validate_production(projected)


@pytest.mark.parametrize("field", ["privilegedRequests", "authOperations"])
def test_nested_auth_secrets_are_rejected(tmp_path, monkeypatch, field):
    report = publishable_report(tmp_path, monkeypatch)
    report[field][0]["token"] = "do-not-publish"
    with pytest.raises(ValueError):
        production.project(report, COMMIT)


def test_incomplete_recovery_cannot_be_projected(tmp_path, monkeypatch):
    report = publishable_report(tmp_path, monkeypatch)
    report["recoveryIncomplete"] = True
    with pytest.raises(ValueError):
        production.project(report, COMMIT)


def test_missing_auth_evidence_cannot_be_projected(tmp_path, monkeypatch):
    report = publishable_report(tmp_path, monkeypatch)
    report["privilegedRequests"] = []
    with pytest.raises(ValueError):
        production.project(report, COMMIT)


def test_comparison_preserves_refusal_stage_but_excludes_timing(tmp_path, monkeypatch):
    _, _, report = run(tmp_path, monkeypatch)
    rows = report["cases"]
    changed = copy.deepcopy(rows)
    changed[0]["elapsedMs"] += 123
    changed[0]["timing"]["pendingSent"] += 1
    assert all(r["sameSemanticProjection"] for r in comparison.compare(rows, changed))
    changed[-2].update(
        outcome="refused",
        httpStatus=400,
        observedError="INVALID_MFA_PENDING_CREDENTIAL",
        checks={},
    )
    differences = [
        r["id"]
        for r in comparison.compare(rows, changed)
        if not r["sameSemanticProjection"]
    ]
    assert differences == [changed[-2]["id"]]


def test_rendered_interval_does_not_round_upper_endpoint_inward():
    row = {"timing": {"pendingAgeAtStart": {"lower": 3900.0, "upper": 3900.0000001}}}
    assert production.age_display(row) == "[3900.0, 3900.0000001]"


def test_published_budget_cannot_be_inflated_after_the_run(tmp_path, monkeypatch):
    report = publishable_report(tmp_path, monkeypatch)
    report["budget"]["totalBudgetSeconds"] += 1
    with pytest.raises(ValueError):
        production.project(report, COMMIT)


def local_report(tmp_path, monkeypatch):
    # A structural owned-run model; real runtime/recorder Git blobs fence provenance.
    # Real artifact execution is checked separately before publishing any comparison.
    _, _, report = run(tmp_path, monkeypatch, production=False)
    report.update(
        probeSourceCommit=COMMIT,
        runtimeSourceCommit=COMMIT,
        connection="owned-artifact",
    )
    config = {"schemaVersion": 1, "profile": "strict"}
    artifact = "1" * 64
    report["configuration"] = {
        "value": config,
        "sha256": production.digest(config),
        "fileSha256": "2" * 64,
    }
    report["artifact"] = {"sha256": artifact, "version": "0.7.0", "kind": "local-build"}
    report["ownedProcess"] = {
        "pid": 1001,
        "exitCode": 0,
        "stopped": True,
        "listenersClosed": True,
    }
    report["instance"] = {
        "parentPid": 1001,
        "childPid": 1002,
        "nonce": "a" * 32,
        "profile": "strict",
        "version": "0.7.0",
        "wrongTokenStatus": 403,
    }
    report["build"] = {
        "command": [
            "cargo",
            "build",
            "--locked",
            "-p",
            "fireemu",
            "--message-format=json",
        ],
        "exitCode": 0,
        "artifactSha256": artifact,
        "inputs": comparison.runtime_inputs_at(COMMIT),
    }
    return report


def test_local_projection_rejects_secret_in_recorded_timestamp(tmp_path, monkeypatch):
    report = local_report(tmp_path, monkeypatch)
    projected = comparison.project_local(report, COMMIT, COMMIT)
    comparison.validate_local(projected)
    report["recordedAt"] = {"access_token": "do-not-publish"}
    with pytest.raises(ValueError):
        comparison.project_local(report, COMMIT, COMMIT)


def test_local_projection_requires_confirmed_process_cleanup(tmp_path, monkeypatch):
    report = local_report(tmp_path, monkeypatch)
    report["ownedProcess"]["listenersClosed"] = False
    with pytest.raises(ValueError):
        comparison.project_local(report, COMMIT, COMMIT)
