import hashlib
import importlib.util
import json
import sys
from pathlib import Path

import pytest

_spec = importlib.util.spec_from_file_location("auth_account_linking_owned", Path(__file__).with_name("auth-account-linking-owned.py"))
_module = importlib.util.module_from_spec(_spec)
assert _spec.loader is not None
_spec.loader.exec_module(_module)
validate_manifest = _module.validate_manifest
validate_sdk_pins = _module.validate_sdk_pins
run = _module.run


def test_manifest_binds_completed_local_artifact(tmp_path: Path):
    artifact = tmp_path / "fireemu"
    artifact.write_bytes(b"owned-artifact")
    digest = hashlib.sha256(b"owned-artifact").hexdigest()
    source, actual = validate_manifest(
        {
            "status": "completed",
            "productionExecuted": False,
            "executionCommit": "8b33aac4d" * 4 + "8b33aac4d"[:4],
            "artifactSha256": digest,
        },
        artifact,
    )
    assert source == "8b33aac4d" * 4 + "8b33aac4d"[:4]
    assert actual == digest


def test_manifest_rejects_production_or_artifact_drift(tmp_path: Path):
    artifact = tmp_path / "fireemu"
    artifact.write_bytes(b"owned-artifact")
    digest = hashlib.sha256(b"other-artifact").hexdigest()
    with pytest.raises(ValueError, match="production"):
        validate_manifest(
            {
                "status": "completed",
                "productionExecuted": True,
                "executionCommit": "8b33aac4d" * 4 + "8b33aac4d"[:4],
                "artifactSha256": digest,
            },
            artifact,
        )
    with pytest.raises(ValueError, match="artifact"):
        validate_manifest(
            {
                "status": "completed",
                "productionExecuted": False,
                "executionCommit": "8b33aac4d" * 4 + "8b33aac4d"[:4],
                "artifactSha256": digest,
            },
            artifact,
        )


def test_sdk_pins_are_exact():
    assert validate_sdk_pins({"dependencies": {"firebase": "12.18.0", "firebase-admin": "14.3.0"}}) == {
        "firebase": "12.18.0",
        "firebase-admin": "14.3.0",
    }
    with pytest.raises(ValueError, match="SDK"):
        validate_sdk_pins({"dependencies": {"firebase": "12.18.0", "firebase-admin": "14.3.1"}})


def test_runner_persists_failure_without_false_success(tmp_path: Path):
    artifact = tmp_path / "fireemu"
    artifact.write_bytes(b"wrong-artifact")
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({"status": "completed", "productionExecuted": False}), encoding="utf-8")
    output = tmp_path / "run"
    result = run(output, manifest, artifact)
    assert result["status"] == "owned-run-failed"
    assert (output / "failure.json").is_file()
    assert not (output / "receipt.json").exists()
