"""Retained artifact runs bind exact runtime inputs before starting any process."""

import hashlib
import importlib.util
import json

import pytest


def test_retained_artifact_rejects_changed_source_and_binary(tmp_path):
    assert importlib.util.find_spec("partition"), "partition launcher is required"
    from partition import retained_artifact

    binary = tmp_path / "fireemu"
    binary.write_bytes(b"owned artifact")
    inputs = {"crates/one.rs": "same"}
    receipt = tmp_path / "manifest.json"
    receipt.write_text(
        json.dumps(
            {
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
                    "artifactSha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                    "inputs": inputs,
                }
            }
        )
    )
    assert retained_artifact(binary, receipt, inputs)["exitCode"] == 0
    with pytest.raises(ValueError):
        retained_artifact(binary, receipt, {"crates/one.rs": "changed"})
    binary.write_bytes(b"different")
    with pytest.raises(ValueError):
        retained_artifact(binary, receipt, inputs)
