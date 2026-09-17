from __future__ import annotations

import json

import pytest
from owned_transform_runner import validate_retained_artifact


def test_unapproved_executable_is_rejected_without_starting_it(tmp_path):
    artifact = tmp_path / "fake-fireemu"
    marker = tmp_path / "executed"
    artifact.write_text(f"#!/bin/sh\ntouch '{marker}'\n")
    artifact.chmod(0o700)
    manifest = tmp_path / "run-manifest.json"
    manifest.write_text(json.dumps({"artifactSha256": "0" * 64}))
    with pytest.raises(ValueError):
        validate_retained_artifact(artifact, manifest)
    assert not marker.exists()


def test_symlink_artifact_is_not_an_immutable_identity(tmp_path):
    artifact = tmp_path / "fake-fireemu"
    artifact.write_text("fake")
    link = tmp_path / "linked"
    link.symlink_to(artifact)
    manifest = tmp_path / "run-manifest.json"
    manifest.write_text("{}")
    with pytest.raises(ValueError):
        validate_retained_artifact(link, manifest)
