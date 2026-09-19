"""The publication contract binds every execution-dependency file to the recorder commit,
and the manifest equals the transitive top-level import closure of the run's entry modules
(completeness), for both the production and the comparison publisher."""

import importlib
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "tools/compat-inventory"))
production = importlib.import_module("publish-auth-pending-lifetime")
comparison = importlib.import_module("publish-auth-pending-lifetime-comparison")
from manifest_closure import in_repo_closure

REC = ROOT / "tools/auth-pending-lifetime/lifetime_recorder.py"
OWN = ROOT / "tools/auth-pending-lifetime/lifetime_owned.py"
COMMIT = "a" * 40


def test_no_publisher_prose_claims_an_upper_bound_from_a_refusal():
    # Revision 1 asserts no lifetime upper bound: the machine summary hardcodes it False, so
    # the human-facing SCOPE and module docstrings (which are rendered onto the page and,
    # for production, pinned into the receipt) must not claim a refusal establishes one.
    forbidden = ("upper bound only if", "an upper bound only")
    for module in (production, comparison):
        text = f"{module.SCOPE}\n{module.__doc__ or ''}".lower()
        for phrase in forbidden:
            assert phrase not in text, (module.__name__, phrase)


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


def test_the_two_manifests_differ_only_by_the_owned_run_files():
    # The comparison run additionally imports the owned runner and its helpers; the
    # production run does not. Everything else is shared.
    extra = set(comparison.RECORDER_FILES) - set(production.RECORDER_FILES)
    assert extra == {
        "tools/auth-pending-lifetime/lifetime_owned.py",
        "tools/compat-inventory/owned_runner.py",
        "tools/compat-inventory/evidence_common.py",
    }
    assert set(production.RECORDER_FILES) - set(comparison.RECORDER_FILES) == set()


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
