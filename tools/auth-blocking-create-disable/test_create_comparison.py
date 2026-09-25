"""The comparison publisher refuses an owned run whose child was not confirmed stopped,
and binds the runner and the local fixture to committed content."""

import importlib
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
publisher = importlib.import_module("publish-auth-blocking-create-disable-comparison")
from test_create_safety import World, run


def local_report(tmp_path, monkeypatch):
    world = World("accepted-disabled")
    report, _ = run(tmp_path, monkeypatch, world)
    assert report["status"] == "observed"
    # Fields the owned runner adds around observe().
    report.update(
        {
            "connection": "owned-artifact",
            "artifact": {"sha256": "a" * 64, "version": "0.7.0", "kind": "local-build"},
            "configuration": {
                "value": {"schemaVersion": 1, "profile": "strict"},
                "sha256": publisher.digest({"schemaVersion": 1, "profile": "strict"}),
                "fileSha256": "b" * 64,
            },
            "ownedProcess": {
                "pid": 10,
                "exitCode": 0,
                "stopped": True,
                "listenersClosed": True,
            },
            "instance": {
                "parentPid": 10,
                "childPid": 11,
                "nonce": "c" * 32,
                "profile": "strict",
                "version": "0.7.0",
                "wrongTokenStatus": 403,
            },
            "build": {
                "command": [
                    "cargo",
                    "build",
                    "--locked",
                    "-p",
                    "fireemu",
                    "--message-format=json",
                ],
                "exitCode": 0,
                "artifactSha256": "a" * 64,
                "inputs": {"crates/x.rs": "d" * 64},
            },
            "runtimeSourceCommit": "1" * 40,
            "functionsRunner": {
                "path": "tools/runner-node/index.mjs",
                "sha256": "e" * 64,
            },
            "localFixtureInputs": {path: "f" * 64 for path in publisher.FIXTURE_FILES},
            "nodeRuntime": {"node": "v24.14.0", "npm": "11.6.0"},
            "probeInputs": {path: "9" * 64 for path in publisher.RECORDER_FILES},
        }
    )
    report["localFunctionFixture"] = "tools/auth-blocking-create-disable/function-local"
    report["target"] = "local"
    report["projectNumber"] = None
    report["probeSourceCommit"] = "1" * 40
    return report


def fake_git(monkeypatch):
    def blob(commit, path):
        if commit == "2" * 40 and path in publisher.RECORDER_FILES:
            return "9" * 64
        if commit == "2" * 40 and path in publisher.FIXTURE_FILES:
            return "f" * 64
        if commit == "3" * 40 and path == "tools/runner-node/index.mjs":
            return "e" * 64
        return "0" * 64

    monkeypatch.setattr(publisher, "git_blob_sha256", blob)
    monkeypatch.setattr(
        publisher,
        "runtime_inputs_at",
        lambda commit: {"crates/x.rs": "d" * 64} if commit == "3" * 40 else {},
    )


def test_a_clean_owned_run_projects(tmp_path, monkeypatch):
    report = local_report(tmp_path, monkeypatch)
    fake_git(monkeypatch)
    out = publisher.project_local(report, "2" * 40, "3" * 40)
    assert out["runtimeInputsCommit"] == "3" * 40
    assert set(out["localFixtureInputs"]) == set(publisher.FIXTURE_FILES)
    assert "secret" not in json.dumps(out)


def test_a_child_cleanup_failure_is_refused(tmp_path, monkeypatch):
    report = local_report(tmp_path, monkeypatch)
    fake_git(monkeypatch)
    report["childCleanupFailure"] = "ValueError"
    with pytest.raises(ValueError):
        publisher.project_local(report, "2" * 40, "3" * 40)


def test_runner_and_fixture_are_bound_to_commits(tmp_path, monkeypatch):
    report = local_report(tmp_path, monkeypatch)
    fake_git(monkeypatch)
    for mutate in (
        lambda r: r["functionsRunner"].__setitem__("sha256", "1" * 64),
        lambda r: r["localFixtureInputs"].__setitem__(
            publisher.FIXTURE_FILES[0], "1" * 64
        ),
        lambda r: r["build"]["inputs"].__setitem__("crates/x.rs", "1" * 64),
    ):
        broken = json.loads(json.dumps(report))
        mutate(broken)
        with pytest.raises(ValueError):
            publisher.project_local(broken, "2" * 40, "3" * 40)
