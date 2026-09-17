from __future__ import annotations

import json
from pathlib import Path

import pytest
from owned_transform_runner import (
    REPAIRED_PROFILE,
    validate_copied_manifest,
    validate_retained_artifact,
)


def test_repaired_profile_accepts_original_build_manifest_without_derived_fields():
    root = Path(__file__).parents[5]
    artifact = root / (
        "docs.local/logs/2026-09-17/stream-repair-shadow-567565bdd/owned-run/fireemu"
    )
    manifest = root / (
        "docs.local/logs/2026-09-17/stream-repair-shadow-567565bdd/run-manifest.json"
    )

    result = validate_retained_artifact(artifact, manifest, profile=REPAIRED_PROFILE)

    assert result["runtimeSourceCommit"] == REPAIRED_PROFILE["runtimeCommit"]
    assert result["artifactSha256"] == REPAIRED_PROFILE["artifactSha256"]
    assert result["retainedManifestSha256"]


def test_unknown_profile_is_rejected_before_artifact_validation(tmp_path):
    with pytest.raises(ValueError, match="unknown artifact profile"):
        validate_retained_artifact(
            tmp_path / "artifact", tmp_path / "manifest", profile="unreviewed"
        )


@pytest.mark.parametrize("mutation", ["hash", "source", "inputs"])
def test_repaired_profile_rejects_manifest_binding_mutations(tmp_path, mutation):
    root = Path(__file__).parents[5]
    artifact = root / (
        "docs.local/logs/2026-09-17/stream-repair-shadow-567565bdd/owned-run/fireemu"
    )
    original = root / (
        "docs.local/logs/2026-09-17/stream-repair-shadow-567565bdd/run-manifest.json"
    )
    manifest = json.loads(original.read_text())
    if mutation == "hash":
        manifest["build"]["artifactSha256"] = "0" * 64
    elif mutation == "source":
        manifest["executionCommit"] = "0" * 40
    else:
        manifest["build"]["inputs"]["Cargo.toml"] = "0" * 64
    mutated = tmp_path / "run-manifest.json"
    mutated.write_text(json.dumps(manifest))

    with pytest.raises(ValueError):
        validate_retained_artifact(artifact, mutated, profile=REPAIRED_PROFILE)


def test_copied_manifest_binds_profile_and_full_provenance_before_io(tmp_path):
    root = Path(__file__).parents[5]
    original = root / (
        "docs.local/logs/2026-09-17/stream-repair-shadow-567565bdd/run-manifest.json"
    )
    artifact = root / (
        "docs.local/logs/2026-09-17/stream-repair-shadow-567565bdd/owned-run/fireemu"
    )
    validated = validate_retained_artifact(artifact, original, profile=REPAIRED_PROFILE)
    copied = tmp_path / "retained-manifest.json"
    copied.write_bytes(original.read_bytes())
    inputs = {
        **validated,
        "artifactProfile": REPAIRED_PROFILE["name"],
        "retainedManifestPath": str(copied),
    }

    assert validate_copied_manifest(tmp_path, inputs, REPAIRED_PROFILE) == validated


@pytest.mark.parametrize("mutation", ["missing", "profile", "tuple", "tamper"])
def test_copied_manifest_mutations_are_rejected(tmp_path, mutation):
    root = Path(__file__).parents[5]
    original = root / (
        "docs.local/logs/2026-09-17/stream-repair-shadow-567565bdd/run-manifest.json"
    )
    artifact = root / (
        "docs.local/logs/2026-09-17/stream-repair-shadow-567565bdd/owned-run/fireemu"
    )
    validated = validate_retained_artifact(artifact, original, profile=REPAIRED_PROFILE)
    copied = tmp_path / "retained-manifest.json"
    copied.write_bytes(original.read_bytes())
    inputs = {
        **validated,
        "artifactProfile": REPAIRED_PROFILE["name"],
        "retainedManifestPath": str(copied),
    }
    if mutation == "missing":
        copied.unlink()
    elif mutation == "profile":
        inputs["artifactProfile"] = "historical-default"
    elif mutation == "tuple":
        inputs["runtimeInputsDigest"] = "0" * 64
    else:
        copied.write_bytes(copied.read_bytes() + b"\n")

    with pytest.raises(ValueError):
        validate_copied_manifest(tmp_path, inputs, REPAIRED_PROFILE)


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


@pytest.mark.parametrize("mutation", ["extra", "missing", "changed"])
def test_forged_runtime_input_map_is_rejected_against_fixed_git_tree(mutation):
    from evidence_common import runtime_inputs_at_commit
    from owned_transform_runner import ROOT, RUNTIME_COMMIT, validate_runtime_provenance

    manifest = {
        "sourceCommit": RUNTIME_COMMIT,
        "build": {"inputs": runtime_inputs_at_commit(RUNTIME_COMMIT, ROOT)},
    }
    if mutation == "extra":
        manifest["build"]["inputs"]["forged-input"] = "0" * 64
    elif mutation == "missing":
        del manifest["build"]["inputs"]["Cargo.toml"]
    else:
        manifest["build"]["inputs"]["Cargo.toml"] = "0" * 64
    with pytest.raises(ValueError, match="runtime input"):
        validate_runtime_provenance(manifest)


def test_original_path_replacement_after_copy_is_never_executed(tmp_path):
    import hashlib
    import subprocess

    from owned_transform_runner import owned_artifact

    source = tmp_path / "retained-executable"
    approved = b"#!/bin/sh\nprintf approved\n"
    source.write_bytes(approved)
    source.chmod(0o500)
    with owned_artifact(source, hashlib.sha256(approved).hexdigest()) as (
        executable,
        identity,
    ):
        replacement = tmp_path / "replacement"
        replacement.write_text("#!/bin/sh\nprintf UNAPPROVED\n")
        replacement.chmod(0o700)
        replacement.replace(source)
        assert executable != source
        assert subprocess.check_output([str(executable)], text=True) == "approved"
        assert identity["inode"] == executable.stat().st_ino
        assert identity["device"] == executable.stat().st_dev
        assert identity["sha256"] == hashlib.sha256(approved).hexdigest()
    assert not executable.exists()


def test_replacement_before_copy_fails_without_execution(tmp_path):
    import hashlib

    from owned_transform_runner import owned_artifact

    source = tmp_path / "retained-executable"
    approved = b"#!/bin/sh\nprintf approved\n"
    source.write_bytes(b"#!/bin/sh\nprintf UNAPPROVED\n")
    source.chmod(0o700)
    with (
        pytest.raises(ValueError, match="digest"),
        owned_artifact(source, hashlib.sha256(approved).hexdigest()),
    ):
        pytest.fail("unapproved executable reached launch scope")
