"""Real process lifecycle and fixed observation grid, never fake Firebase results."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest


@pytest.mark.skipif(
    os.getenv("AUTH_SESSION_V2_LIVE_LOCAL") != "1", reason="owned process opt-in"
)
def test_session_v2_owned_lifecycle(tmp_path):
    path = Path(__file__).with_name("session_v2_owned.py")
    assert path.exists(), "Session owned launcher required"
    result = subprocess.run(
        [sys.executable, str(path), "--output", str(tmp_path / "run")],
        capture_output=True,
        timeout=420,
        check=False,
    )
    assert result.returncode == 0, result.stdout.decode()
    value = json.loads((tmp_path / "run/local.json").read_bytes())
    sys.path.insert(0, str(path.parent))
    from session_v2_contract import complete

    assert complete(value)
    assert len(value["cases"]) == 34
    assert value["ownedProcess"]["exitCode"] == 0
    assert value["ownedProcess"]["listenersClosed"] is True
    assert value["timing"]["orderEstablished"] is True
