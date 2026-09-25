"""A post-spawn finalizer error must not erase possible recovery responsibility.

The owned child is a real Python process, never a Firebase SDK or daemon.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest
from o6_listen_resume import local_supervisor as m


class ClosingFailure:
    def __init__(self, stream, calls, label):
        self.stream, self.calls, self.label = stream, calls, label

    def __getattr__(self, name):
        return getattr(self.stream, name)

    def close(self):
        self.calls.append(self.label)
        self.stream.close()
        raise OSError("PRIVATE-FINALIZER-MATERIAL")


def environment(tmp_path):
    return {"PATH": os.environ["PATH"], "GOOGLE_CLOUD_PROJECT": "demo-finalizer",
            "FIRESTORE_EMULATOR_HOST": "127.0.0.1:18081",
            "FIREBASE_AUTH_EMULATOR_HOST": "127.0.0.1:18082",
            "O6_FIREBASE_MODULE_DIR": str(tmp_path)}


def inject_real_child(monkeypatch, broken, calls):
    original = subprocess.Popen
    children = []

    def spawn(_command, **kwargs):
        # Replace only the SDK child: actual process ownership, pipes and
        # stopping logic remain the real supervisor implementation.
        child = original([sys.executable, "-I", "-S", "-c",
                          "import sys; print('owned-child'); print('diagnostic', file=sys.stderr)"], **kwargs)
        children.append(child)
        for label in ("stdout", "stderr"):
            if label in broken:
                setattr(child, label, ClosingFailure(getattr(child, label), calls, label))
        return child

    monkeypatch.setattr(m.subprocess, "Popen", spawn)
    return children


@pytest.mark.parametrize("broken", [("stdout",), ("stderr",), ("stdout", "stderr")])
def test_real_post_spawn_pipe_close_failures_retain_responsibility(tmp_path, monkeypatch, broken):
    calls = []
    children = inject_real_child(monkeypatch, broken, calls)
    result = m.run(tmp_path / "run", env=environment(tmp_path), timeout=3)
    assert len(children) == 1
    assert children[0].poll() is not None
    assert result["completed"] is False
    assert result["resourceCleanupComplete"] is False
    assert result["recoveryRequired"] is True
    assert result["processCleanupComplete"] is True
    assert result["execution"]["started"] is True
    assert any("close" in issue for issue in result["execution"]["issues"])
    assert all(label in calls for label in broken)
    assert "PRIVATE-FINALIZER-MATERIAL" not in json.dumps(result)
    assert (tmp_path / "run" / "launch.json").is_file()
    saved = json.loads((tmp_path / "run" / "result.json").read_text())
    assert saved["recoveryRequired"] is True
    assert saved["authorizesCleanup"] is False


def test_selector_close_failure_still_closes_captures_and_records_started_child(tmp_path, monkeypatch):
    calls = []
    children = inject_real_child(monkeypatch, (), calls)
    factory = m.selectors.DefaultSelector

    class FailingSelector:
        def __init__(self):
            self.original = factory()

        def __getattr__(self, name):
            return getattr(self.original, name)

        def close(self):
            self.original.close()
            raise OSError("PRIVATE-SELECTOR-MATERIAL")

    monkeypatch.setattr(m.selectors, "DefaultSelector", FailingSelector)
    result = m.run(tmp_path / "run", env=environment(tmp_path), timeout=3)
    assert children[0].poll() is not None
    assert result["completed"] is False
    assert result["recoveryRequired"] is True
    assert result["execution"]["streams"]["stdout"]["bytes"] > 0
    assert result["execution"]["streams"]["stderr"]["bytes"] > 0
    assert "PRIVATE-SELECTOR-MATERIAL" not in json.dumps(result)
    assert any("selector-close" in issue for issue in result["execution"]["issues"])


@pytest.mark.parametrize("raised", [OSError, ValueError, RuntimeError])
def test_capture_failure_without_a_returned_spawn_receipt_is_conservatively_unresolved(tmp_path, monkeypatch, raised):
    def failed(*_args, **_kwargs):
        raise raised("PRIVATE-CAPTURE-MATERIAL")

    monkeypatch.setattr(m, "_capture", failed)
    result = m.run(tmp_path / "run", env=environment(tmp_path))
    assert result["completed"] is False
    assert result["recoveryRequired"] is True
    assert result["processCleanupComplete"] is False
    assert "PRIVATE-CAPTURE-MATERIAL" not in json.dumps(result)
    assert (tmp_path / "run" / "launch.json").exists()


def test_confirmed_spawn_failure_does_not_claim_outstanding_resources(tmp_path, monkeypatch):
    def not_started(*_args, **_kwargs):
        raise FileNotFoundError("PRIVATE-NODE-PATH")

    monkeypatch.setattr(m.subprocess, "Popen", not_started)
    result = m.run(tmp_path / "run", env=environment(tmp_path))
    assert result["completed"] is False
    assert result["execution"]["started"] is False
    assert result["recoveryRequired"] is False
    assert "PRIVATE-NODE-PATH" not in json.dumps(result)


def test_pre_launch_publish_failure_does_not_claim_a_submitted_child(tmp_path, monkeypatch):
    original = m._publish

    def publish(path, value):
        if path.name == "launch.json":
            raise OSError("disk")
        original(path, value)

    monkeypatch.setattr(m, "_publish", publish)
    monkeypatch.setattr(m, "_capture", lambda *_a, **_k: pytest.fail("must not submit child"))
    result = m.run(tmp_path / "run", env=environment(tmp_path))
    assert result["completed"] is False
    assert result["recoveryRequired"] is False
