"""Owned artifact shadow refuses unattested or incomplete acquisition."""

import importlib.util
import sys
from pathlib import Path

import pytest
from test_stream_bridge import trusted_node_runtime  # noqa: F401

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parents[1]))


def test_shadow_requires_real_supervisor_and_control_challenge():
    assert importlib.util.find_spec("stream_shadow") is not None, (
        "owned artifact shadow is required"
    )
    import stream_shadow

    with pytest.raises(ValueError):
        stream_shadow.validate_owned_receipt({"acquisitionValidated": True}, "a" * 64)


def test_shadow_command_rejects_missing_artifact_without_launch(tmp_path):
    assert importlib.util.find_spec("stream_shadow") is not None, (
        "owned artifact shadow is required"
    )
    import stream_shadow

    with pytest.raises((ValueError, FileNotFoundError)):
        stream_shadow.run_shadow(
            tmp_path / "missing", tmp_path / "missing-build.json", tmp_path / "output"
        )
    assert not (tmp_path / "output").exists()


def test_shadow_cli_bootstraps_sibling_imports():
    import subprocess

    result = subprocess.run(
        [sys.executable, str(Path(__file__).with_name("stream_shadow.py")), "--help"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "--artifact" in result.stdout
