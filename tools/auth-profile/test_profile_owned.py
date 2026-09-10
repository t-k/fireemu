"""Opt-in integration against the actual owned strict artifact."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest


@pytest.mark.skipif(
    os.getenv("AUTH_PROFILE_LIVE_LOCAL") != "1", reason="owned process opt-in"
)
def test_profile_owned_lifecycle(tmp_path):
    path = Path(__file__).with_name("profile_owned.py")
    assert path.exists(), "Profile owned launcher is required"
    result = subprocess.run(
        [sys.executable, str(path), "--output", str(tmp_path / "run")],
        capture_output=True,
        timeout=420,
        check=False,
    )
    assert result.returncode == 0, result.stdout.decode()
    report = json.loads((tmp_path / "run/local.json").read_bytes())
    assert report["status"] in {"passed", "failed"}
    assert not any(
        key in report for key in ("failure", "cleanupFailure", "childCleanupFailure")
    )
    assert report["ownedProcess"]["exitCode"] == 0
    assert report["ownedProcess"]["listenersClosed"] is True
    assert report["cleanup"] == {"uidAbsent": True, "emailAbsent": True}
    assert len(report["cases"]) == 12
    assert all(row["passed"] for row in report["cases"])
    sys.path.insert(0, str(Path(__file__).parent))
    from profile_recorder import recovery_identity

    _, uid = recovery_identity(tmp_path / "run/observation/recovery.json")
    assert isinstance(uid, str) and uid
