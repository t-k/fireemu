"""The publication contract binds every execution-dependency file to the recorder commit:
tampering (or dropping) any one dependency hash is refused. Covers the production receipt
publisher and the local-comparison publisher, whose dependency sets differ."""

import importlib
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
production = importlib.import_module("publish-auth-pending-triggers")
comparison = importlib.import_module("publish-auth-pending-triggers-comparison")

COMMIT = "a" * 40


def report_for(publisher):
    # A hash per bound file, distinct so a corruption is unambiguous.
    return {
        "probeSourceCommit": "b" * 40,
        "probeInputs": {
            path: format(i, "064x") for i, path in enumerate(publisher.RECORDER_FILES)
        },
    }


def fake_git(publisher, report, monkeypatch):
    truth = dict(report["probeInputs"])
    monkeypatch.setattr(publisher, "git_blob_sha256", lambda commit, path: truth[path])


@pytest.mark.parametrize("publisher", [production, comparison])
def test_recorded_with_accepts_matching_dependency_hashes(publisher, monkeypatch):
    report = report_for(publisher)
    fake_git(publisher, report, monkeypatch)
    out = publisher.recorded_with(report, COMMIT)
    assert set(out["recorderInputs"]) == set(publisher.RECORDER_FILES)
    assert out["recorderCommit"] == COMMIT


@pytest.mark.parametrize("publisher", [production, comparison])
def test_each_dependency_file_is_bound(publisher, monkeypatch):
    # Corrupting any one dependency hash (as a changed helper at the commit would) is
    # refused; this is the negative test the manifest exists for.
    for tampered in publisher.RECORDER_FILES:
        report = report_for(publisher)
        fake_git(publisher, report, monkeypatch)
        report["probeInputs"][tampered] = "f" * 64
        with pytest.raises(ValueError):
            publisher.recorded_with(report, COMMIT)


@pytest.mark.parametrize("publisher", [production, comparison])
def test_a_missing_dependency_hash_is_refused(publisher, monkeypatch):
    for dropped in publisher.RECORDER_FILES:
        report = report_for(publisher)
        fake_git(publisher, report, monkeypatch)
        del report["probeInputs"][dropped]
        with pytest.raises((ValueError, KeyError)):
            publisher.recorded_with(report, COMMIT)


def test_the_two_publishers_cover_distinct_dependency_sets():
    # The comparison run executes the owned-runner stack the production run does not.
    prod = set(production.RECORDER_FILES)
    comp = set(comparison.RECORDER_FILES)
    assert prod < comp
    assert "tools/auth-pending-revocation/revocation_contract.py" in prod
    assert {
        "tools/auth-pending-triggers/triggers_owned.py",
        "tools/compat-inventory/owned_runner.py",
        "tools/compat-inventory/evidence_common.py",
    } <= comp
    assert {
        "tools/auth-pending-triggers/triggers_owned.py",
        "tools/compat-inventory/owned_runner.py",
        "tools/compat-inventory/evidence_common.py",
    }.isdisjoint(prod)
