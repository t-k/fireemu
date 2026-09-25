from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

import owned_transform_runner as runner
import pytest
from owned_transform_runner import (
    BUILD_COMMAND,
    CURRENT_8245_PROFILE,
    CURRENT_PROFILE,
    G0_CURRENT_648_PROFILE,
    G0_CURRENT_PROFILE,
    PROFILES,
    REPAIRED_PROFILE,
    resolve_profile,
    validate_copied_manifest,
    validate_current_g0_artifact,
    validate_manifest_payload,
    validate_retained_artifact,
)


def test_current_profile_is_bound_to_the_locked_build_identity():
    assert CURRENT_PROFILE == {
        "name": "current-4f11e691",
        "artifactSha256": "a34c865c2c87b16281080dba9327543a9d8f8876f172a74569b5291ef2a1219f",
        "runtimeCommit": "4f11e691a739b1659d2b95aaf3faeb081842b239",
        "manifestCommitField": "executionCommit",
        "requireTopLevelArtifactSha": False,
        "historicalCompilerSha256": "eab79d565e2ab28c2be0c46d2d3dfcef193aee808bf570a484e9121f3c7c7d53",
    }
    assert BUILD_COMMAND == [
        "cargo",
        "build",
        "--locked",
        "-p",
        "fireemu",
        "--message-format=json",
    ]


def test_g0_profile_is_closed_to_the_retained_build_identity():
    assert G0_CURRENT_PROFILE == {
        "name": "current-8f129b10",
        "artifactSha256": "bf713deb0952db610c840d6233b9c343496df5b69b9c4e934a4054c27f765897",
        "runtimeCommit": "8f129b10aac6cf9a875fbf67fd8775a746daec40",
        "manifestCommitField": "executionCommit",
        "requireTopLevelArtifactSha": False,
    }


def test_current_648_g0_profile_is_bound_to_the_retained_build_identity():
    assert G0_CURRENT_648_PROFILE == {
        "name": "current-648-7737",
        "artifactSha256": "7737f6c389aff0a0f280757591af3b81f11edfbc8438cb69268da0f4c2237026",
        "runtimeCommit": "648aabe56cf6147128ffadf565d93ca7a92013c1",
        "manifestCommitPath": ["runtimeSource", "commit"],
        "requireTopLevelArtifactSha": False,
    }
    assert PROFILES[G0_CURRENT_648_PROFILE["name"]] is G0_CURRENT_648_PROFILE


def _current_648_manifest(mutation: str | None = None) -> tuple[dict, bytes]:
    from evidence_common import runtime_inputs_at_commit

    inputs = runtime_inputs_at_commit(
        G0_CURRENT_648_PROFILE["runtimeCommit"], runner.ROOT
    )
    manifest = {
        "runtimeSource": {"commit": G0_CURRENT_648_PROFILE["runtimeCommit"]},
        "build": {
            "artifactSha256": G0_CURRENT_648_PROFILE["artifactSha256"],
            "exitCode": 0,
            "command": BUILD_COMMAND,
            "inputs": inputs,
        },
    }
    if mutation == "source":
        manifest["runtimeSource"]["commit"] = "f" * 40
    elif mutation == "receipt-artifact":
        manifest["build"]["artifactSha256"] = "0" * 64
    elif mutation == "extra-input":
        manifest["build"]["inputs"]["forged-input"] = "0" * 64
    elif mutation == "missing-input":
        del manifest["build"]["inputs"]["Cargo.toml"]
    elif mutation == "changed-input":
        manifest["build"]["inputs"]["Cargo.toml"] = "0" * 64
    return manifest, json.dumps(manifest).encode()


def test_current_648_g0_profile_accepts_exact_build_receipt_and_runtime_map():
    manifest, manifest_bytes = _current_648_manifest()

    result = validate_manifest_payload(
        manifest, manifest_bytes, profile="current-648-7737"
    )

    assert result["artifactSha256"] == G0_CURRENT_648_PROFILE["artifactSha256"]
    assert result["runtimeSourceCommit"] == G0_CURRENT_648_PROFILE["runtimeCommit"]
    assert result["artifactProfile"] == "current-648-7737"
    assert result["runtimeInputCount"] == 430


def test_current_648_g0_profile_accepts_ancestor_source_with_current_runtime_inputs(
    tmp_path, monkeypatch
):
    artifact = tmp_path / "fireemu"
    artifact.write_bytes(b"test artifact identity")
    artifact.chmod(0o500)
    _, manifest_bytes = _current_648_manifest()
    manifest_path = tmp_path / "build-local.json"
    manifest_path.write_bytes(manifest_bytes)
    original_sha_file = runner.sha_file
    monkeypatch.setattr(
        runner,
        "sha_file",
        lambda path: (
            G0_CURRENT_648_PROFILE["artifactSha256"]
            if path == artifact
            else original_sha_file(path)
        ),
    )

    result = validate_current_g0_artifact(
        artifact,
        manifest_path,
        profile="current-648-7737",
        repo=runner.ROOT,
    )

    assert result["runtimeSourceCommit"] == G0_CURRENT_648_PROFILE["runtimeCommit"]
    assert (
        result["currentSourceCommit"]
        == subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=runner.ROOT, text=True
        ).strip()
    )
    assert result["sourceInputsEqualCurrent"] is True


def test_current_648_g0_profile_rejects_an_artifact_with_a_different_hash(tmp_path):
    artifact = tmp_path / "fireemu"
    artifact.write_bytes(b"different artifact")
    _, manifest_bytes = _current_648_manifest()
    manifest_path = tmp_path / "build-local.json"
    manifest_path.write_bytes(manifest_bytes)

    with pytest.raises(ValueError, match="retained artifact/build/source binding"):
        validate_current_g0_artifact(
            artifact,
            manifest_path,
            profile="current-648-7737",
            repo=runner.ROOT,
        )


@pytest.mark.parametrize(
    "mutation",
    ["source", "receipt-artifact", "extra-input", "missing-input", "changed-input"],
)
def test_current_648_g0_profile_rejects_build_provenance_mutations(mutation):
    manifest, manifest_bytes = _current_648_manifest(mutation)

    with pytest.raises(ValueError):
        validate_manifest_payload(
            manifest, manifest_bytes, profile="current-648-7737"
        )


def test_current_648_g0_profile_rejects_profile_relabeling():
    relabeled = {
        **G0_CURRENT_648_PROFILE,
        "name": "current-648-other-artifact",
        "artifactSha256": "0" * 64,
    }

    with pytest.raises(ValueError, match="unregistered artifact profile"):
        resolve_profile(relabeled)


PRIVATE_8245_ENABLED = os.environ.get("G0_8245_RUN_PRIVATE_TESTS") == "1"
REPOSITORY = Path(__file__).resolve().parents[3]
PRIVATE_8245_ARTIFACT = Path(
    os.environ.get(
        "G0_8245_RETAINED_ARTIFACT",
        str(
            REPOSITORY
            / "docs.local/runs/saved-runtime-20260922-approved/projection-e896/fireemu"
        ),
    )
)
PRIVATE_8245_MANIFEST = Path(
    os.environ.get(
        "G0_8245_BUILD_MANIFEST",
        str(
            REPOSITORY
            / "docs.local/runs/saved-runtime-20260922-approved/projection-e896/build-local.json"
        ),
    )
)


@pytest.mark.skipif(
    not PRIVATE_8245_ENABLED
    or not PRIVATE_8245_ARTIFACT.is_file()
    or not PRIVATE_8245_MANIFEST.is_file(),
    reason="opt-in retained 8245 provenance fixture is unavailable",
)
def test_current_8245_profile_accepts_private_nested_runtime_source():
    assert PROFILES["current-8245-e896132a"] == CURRENT_8245_PROFILE == {
        "name": "current-8245-e896132a",
        "artifactSha256": "8245b80ea941344e114fe8f61cd7721d2519739509779e7504c295c1bbb66849",
        "runtimeCommit": "e896132a2317a5f38b2780857301f7b0f88b2e68",
        "manifestCommitPath": ["runtimeSource", "commit"],
        "requireTopLevelArtifactSha": False,
    }
    result = validate_current_g0_artifact(
        PRIVATE_8245_ARTIFACT,
        PRIVATE_8245_MANIFEST,
        profile="current-8245-e896132a",
        repo=runner.ROOT,
    )

    assert result["artifactSha256"] == "8245b80ea941344e114fe8f61cd7721d2519739509779e7504c295c1bbb66849"
    assert result["runtimeSourceCommit"] == "e896132a2317a5f38b2780857301f7b0f88b2e68"
    assert result["runtimeInputCount"] == 430
    assert result["sourceInputsDigest"] == result["currentInputsDigest"]


@pytest.mark.skipif(
    not PRIVATE_8245_ENABLED
    or not PRIVATE_8245_ARTIFACT.is_file()
    or not PRIVATE_8245_MANIFEST.is_file(),
    reason="opt-in retained 8245 provenance fixture is unavailable",
)
@pytest.mark.parametrize("mutation", ["nested-commit", "extra-input", "missing-input", "changed-input", "artifact-hash", "build-command"])
def test_current_8245_profile_rejects_private_provenance_mutations(tmp_path, mutation):
    artifact = tmp_path / "fireemu"
    shutil.copyfile(PRIVATE_8245_ARTIFACT, artifact)
    manifest = json.loads(PRIVATE_8245_MANIFEST.read_text())
    if mutation == "nested-commit":
        manifest["runtimeSource"]["commit"] = "f" * 40
    elif mutation == "extra-input":
        manifest["build"]["inputs"]["forged-input"] = "0" * 64
    elif mutation == "missing-input":
        del manifest["build"]["inputs"]["Cargo.toml"]
    elif mutation == "changed-input":
        manifest["build"]["inputs"]["Cargo.toml"] = "0" * 64
    elif mutation == "artifact-hash":
        manifest["build"]["artifactSha256"] = "0" * 64
    else:
        manifest["build"]["command"] = ["cargo", "build", "--unlocked"]
    mutated = tmp_path / "build-local.json"
    mutated.write_text(json.dumps(manifest))

    with pytest.raises(ValueError):
        validate_current_g0_artifact(
            artifact,
            mutated,
            profile="current-8245-e896132a",
            repo=runner.ROOT,
        )


@pytest.fixture
def generated_repaired_fixture(tmp_path, monkeypatch):
    artifact = tmp_path / "fireemu"
    artifact.write_bytes(b"#!/bin/sh\nprintf generated\n")
    artifact.chmod(0o500)
    profile = {
        **REPAIRED_PROFILE,
        "name": "test-generated-repaired",
        "artifactSha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
    }
    monkeypatch.setitem(PROFILES, profile["name"], profile)

    manifest = tmp_path / "run-manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "executionCommit": profile["runtimeCommit"],
                "build": {
                    "artifactSha256": profile["artifactSha256"],
                    "exitCode": 0,
                    "command": BUILD_COMMAND,
                    "inputs": runner.runtime_inputs_at_commit(
                        profile["runtimeCommit"], runner.ROOT
                    ),
                },
            }
        )
    )
    return artifact, manifest, profile


def test_repaired_profile_accepts_original_build_manifest_without_derived_fields(
    generated_repaired_fixture,
):
    artifact, manifest, profile = generated_repaired_fixture

    result = validate_retained_artifact(artifact, manifest, profile=profile)

    assert result["runtimeSourceCommit"] == profile["runtimeCommit"]
    assert result["artifactSha256"] == profile["artifactSha256"]
    assert result["retainedManifestSha256"]


def test_generated_artifact_is_rejected_by_pinned_repaired_profile(
    generated_repaired_fixture,
    tmp_path,
):
    artifact, manifest, _ = generated_repaired_fixture
    pinned_manifest = json.loads(manifest.read_text())
    pinned_manifest["build"]["artifactSha256"] = REPAIRED_PROFILE["artifactSha256"]
    pinned_path = tmp_path / "pinned-manifest.json"
    pinned_path.write_text(json.dumps(pinned_manifest))

    with pytest.raises(ValueError, match="retained artifact/build/source binding"):
        validate_retained_artifact(artifact, pinned_path, profile=REPAIRED_PROFILE)


def test_current_g0_binding_accepts_ancestor_source_with_identical_runtime_inputs(
    generated_repaired_fixture,
):
    artifact, manifest, repaired = generated_repaired_fixture
    profile = {
        **repaired,
        "name": "test-generated-current",
        "runtimeCommit": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=runner.ROOT, text=True
        ).strip(),
    }
    runner.PROFILES[profile["name"]] = profile
    payload = json.loads(manifest.read_text())
    payload["executionCommit"] = profile["runtimeCommit"]
    payload["build"]["inputs"] = runner.runtime_inputs_at_commit(
        profile["runtimeCommit"], runner.ROOT
    )
    manifest.write_text(json.dumps(payload))
    result = validate_current_g0_artifact(
        artifact, manifest, profile=profile, repo=runner.ROOT
    )
    assert result["artifactSha256"] == profile["artifactSha256"]
    assert result["runtimeSourceCommit"] == profile["runtimeCommit"]
    assert result["currentSourceCommit"] == subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=runner.ROOT, text=True
    ).strip()


@pytest.mark.parametrize("mutation", ["artifact", "source", "inputs"])
def test_current_g0_binding_rejects_provenance_mutations(
    generated_repaired_fixture, tmp_path, mutation
):
    artifact, original, profile = generated_repaired_fixture
    if mutation == "artifact":
        artifact.chmod(0o600)
        artifact.write_bytes(b"mutated")
        with pytest.raises(ValueError):
            validate_current_g0_artifact(artifact, original, profile=profile, repo=runner.ROOT)
        return
    manifest = json.loads(original.read_text())
    if mutation == "source":
        manifest[profile["manifestCommitField"]] = "f" * 40
    else:
        manifest["build"]["inputs"]["Cargo.toml"] = "0" * 64
    mutated = tmp_path / "run-manifest.json"
    mutated.write_text(json.dumps(manifest))
    with pytest.raises(ValueError):
        validate_current_g0_artifact(artifact, mutated, profile=profile, repo=runner.ROOT)


def test_current_g0_binding_rejects_a_valid_but_nonancestor_source(
    generated_repaired_fixture,
):
    artifact, manifest, repaired = generated_repaired_fixture
    source = subprocess.check_output(
        ["git", "rev-list", "--all", "--not", "HEAD"], cwd=runner.ROOT, text=True
    ).splitlines()[0]
    profile = {
        **repaired,
        "name": "test-generated-nonancestor",
        "runtimeCommit": source,
    }
    runner.PROFILES[profile["name"]] = profile
    payload = json.loads(manifest.read_text())
    payload["executionCommit"] = source
    payload["build"]["inputs"] = runner.runtime_inputs_at_commit(source, runner.ROOT)
    manifest.write_text(json.dumps(payload))
    with pytest.raises(ValueError, match="ancestor"):
        validate_current_g0_artifact(artifact, manifest, profile=profile, repo=runner.ROOT)


def test_generated_manifest_contains_independently_verified_git_tree_digest(
    generated_repaired_fixture,
):
    _, manifest_path, profile = generated_repaired_fixture
    manifest = json.loads(manifest_path.read_text())
    content = subprocess.check_output(
        ["git", "show", f"{profile['runtimeCommit']}:Cargo.toml"],
        cwd=runner.ROOT,
    )

    assert manifest["build"]["inputs"]["Cargo.toml"] == hashlib.sha256(
        content
    ).hexdigest()


def test_unknown_profile_is_rejected_before_artifact_validation(tmp_path):
    with pytest.raises(ValueError, match="unknown artifact profile"):
        validate_retained_artifact(
            tmp_path / "artifact", tmp_path / "manifest", profile="unreviewed"
        )


@pytest.mark.parametrize("mutation", ["hash", "source", "inputs"])
def test_repaired_profile_rejects_manifest_binding_mutations(
    generated_repaired_fixture, tmp_path, mutation
):
    artifact, original, profile = generated_repaired_fixture
    manifest = json.loads(original.read_text())
    if mutation == "hash":
        manifest["build"]["artifactSha256"] = "0" * 64
    elif mutation == "source":
        manifest["executionCommit"] = "f" * 40
    else:
        manifest["build"]["inputs"]["Cargo.toml"] = "0" * 64
    mutated = tmp_path / "run-manifest.json"
    mutated.write_text(json.dumps(manifest))

    with pytest.raises(ValueError):
        validate_retained_artifact(artifact, mutated, profile=profile)


def test_copied_manifest_binds_profile_and_full_provenance_before_io(
    generated_repaired_fixture, tmp_path
):
    artifact, original, profile = generated_repaired_fixture
    validated = validate_retained_artifact(artifact, original, profile=profile)
    copied = tmp_path / "retained-manifest.json"
    copied.write_bytes(original.read_bytes())
    inputs = {
        **validated,
        "artifactProfile": profile["name"],
        "retainedManifestPath": str(copied),
    }

    assert validate_copied_manifest(tmp_path, inputs, profile) == validated


@pytest.mark.parametrize("mutation", ["missing", "profile", "tuple", "tamper"])
def test_copied_manifest_mutations_are_rejected(
    generated_repaired_fixture, tmp_path, mutation
):
    artifact, original, profile = generated_repaired_fixture
    validated = validate_retained_artifact(artifact, original, profile=profile)
    copied = tmp_path / "retained-manifest.json"
    copied.write_bytes(original.read_bytes())
    inputs = {
        **validated,
        "artifactProfile": profile["name"],
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
        validate_copied_manifest(tmp_path, inputs, profile)


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
