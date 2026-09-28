import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest


def recorder():
    path = Path(__file__).with_name("recorder.py")
    assert path.exists(), "Independent Auth recorder must exist"
    sys.path.insert(0, str(path.parent))
    spec = importlib.util.spec_from_file_location("auth_basic_recorder", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_routes_separate_production_and_local_credentials():
    r = recorder()
    assert r.origins(None) == (
        "https://identitytoolkit.googleapis.com",
        "https://securetoken.googleapis.com",
    )
    assert r.origins("http://127.0.0.1:12345") == (
        "http://127.0.0.1:12345/identitytoolkit.googleapis.com",
        "http://127.0.0.1:12345/securetoken.googleapis.com",
    )
    for origin in [
        "https://example.com",
        "http://127.0.0.1:12345/path",
        "http://user@127.0.0.1:12345",
        "http://localhost:12345?x=1",
    ]:
        with pytest.raises(ValueError):
            r.origins(origin)


def test_config_fails_closed_and_returns_only_safe_projection():
    r = recorder()
    config = {
        "name": "projects/592603257417/config",
        "signIn": {"email": {"enabled": True, "passwordRequired": True}},
        "emailPrivacyConfig": {"enableImprovedEmailPrivacy": True},
        "secret": "SECRET",
    }
    result = r.config_projection(200, config)
    assert "SECRET" not in json.dumps(result)
    for value in [
        {},
        {**config, "blockingFunctions": {"triggers": {"beforeCreate": {}}}},
        {**config, "name": "projects/other/config"},
    ]:
        with pytest.raises(ValueError):
            r.config_projection(200, value)


def test_private_journal_is_exclusive_and_mode_0600(tmp_path):
    r = recorder()
    path = tmp_path / "journal.json"
    r.save(path, {"attempted": True})
    assert path.stat().st_mode & 0o777 == 0o600
    with pytest.raises(FileExistsError):
        r.save(path, {})


def test_recovery_journal_is_bound_to_owned_namespace():
    r = recorder()
    assert hasattr(r, "validate_journal")
    value = {
        "project": r.PROJECT,
        "email": "fireemu-basic-" + "a" * 32 + "@example.test",
        "marker": "fireemu-owned-" + "b" * 48,
        "creationAttempted": True,
    }
    r.validate_journal(value)
    for field, invalid in [
        ("project", "other"),
        ("email", "real@example.com"),
        ("marker", ""),
        ("creationAttempted", False),
    ]:
        with pytest.raises(ValueError):
            r.validate_journal({**value, field: invalid})


@pytest.mark.skipif(
    os.getenv("AUTH_BASIC_LIVE_LOCAL") != "1",
    reason="explicit owned-process integration opt-in",
)
def test_actual_owned_artifact_lifecycle(tmp_path):
    path = Path(__file__).with_name("owned.py")
    assert path.exists(), "Owned Auth launcher must exist"
    run = subprocess.run(
        [sys.executable, str(path), "--output", str(tmp_path / "run")],
        timeout=420,
        capture_output=True,
        check=False,
    )
    assert run.returncode == 0, "Owned lifecycle did not complete"
    report = json.loads((tmp_path / "run" / "local.json").read_text())
    r = recorder()
    assert r.complete(report)
    assert report["ownedProcess"]["exitCode"] == 0
    assert report["ownedProcess"]["listenersClosed"] is True
    assert report["instance"]["parentPid"] == report["ownedProcess"]["pid"]
    assert report["instance"]["wrongTokenStatus"] == 403
    assert report["instance"]["profile"] == "strict"
