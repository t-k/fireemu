"""The publication contract binds every execution-dependency file to the recorder commit,
and the manifest equals the transitive top-level import closure of the run's entry
modules (completeness), for both the production and the comparison publisher."""

import importlib
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "tools/compat-inventory"))
production = importlib.import_module("publish-auth-mfa-start-disabled")
comparison = importlib.import_module("publish-auth-mfa-start-disabled-comparison")
from manifest_closure import in_repo_closure

REC = ROOT / "tools/auth-mfa-start-disabled/start_disabled_recorder.py"
OWN = ROOT / "tools/auth-mfa-start-disabled/start_disabled_owned.py"
COMMIT = "a" * 40


def test_production_manifest_equals_the_recorder_closure():
    assert set(production.RECORDER_FILES) == in_repo_closure([REC])


def test_comparison_manifest_equals_the_owned_run_closure():
    assert set(comparison.RECORDER_FILES) == in_repo_closure([REC, OWN])


def report_for(publisher):
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
def test_recorded_with_accepts_matching_hashes(publisher, monkeypatch):
    report = report_for(publisher)
    fake_git(publisher, report, monkeypatch)
    out = publisher.recorded_with(report, COMMIT)
    assert set(out["recorderInputs"]) == set(publisher.RECORDER_FILES)


@pytest.mark.parametrize("publisher", [production, comparison])
def test_each_dependency_file_is_bound(publisher, monkeypatch):
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
