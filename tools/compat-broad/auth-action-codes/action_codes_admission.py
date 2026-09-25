"""O8 admission adapter for AUTH-ACTION; production execution stays closed."""

from __future__ import annotations

import sys
import hashlib
import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "tools/compat-broad/o8-core"))
sys.path.insert(0, str(HERE))

import action_codes_descriptor as campaign
import o8_admission


def descriptor():
    return campaign.descriptor()


def freeze_inputs(permission, plan, *, source_commit, artifact_sha256):
    return o8_admission.freeze_inputs(
        descriptor(),
        permission,
        plan,
        source_commit=source_commit,
        artifact_sha256=artifact_sha256,
    )


def validate_frozen_inputs(inputs):
    o8_admission.validate_frozen_inputs(descriptor(), inputs)
    expected_commit = subprocess.check_output(
        ["git", "-C", str(ROOT), "rev-parse", "HEAD"], text=True
    ).strip()
    expected_sources = campaign.source_map()
    for name, expected_digest in expected_sources.items():
        try:
            committed = subprocess.check_output(
                ["git", "-C", str(ROOT), "show", f"{expected_commit}:{name}"],
                stderr=subprocess.DEVNULL,
            )
        except subprocess.CalledProcessError as exc:
            raise ValueError("frozen source path is not present in checkout HEAD") from exc
        if hashlib.sha256(committed).hexdigest() != expected_digest:
            raise ValueError("frozen source differs from checkout HEAD")
    campaign.validate_permission(
        inputs["permission"],
        inputs["plan"],
        source_inputs=expected_sources,
        source_commit=expected_commit,
        artifact_sha256=inputs["artifactSha256"],
    )
    if inputs["sourceCommit"] != expected_commit or inputs["sourceInputs"] != expected_sources:
        raise ValueError("independently frozen source provenance differs")


def _validate_artifact_binding(inputs, artifact_path):
    path = Path(artifact_path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size == 0:
        raise ValueError("retained regular artifact required")
    if hashlib.sha256(path.read_bytes()).hexdigest() != inputs["artifactSha256"]:
        raise ValueError("independently frozen artifact provenance differs")


def validate_o7_admission(**bindings):
    validate_frozen_inputs(bindings["inputs"])
    _validate_artifact_binding(bindings["inputs"], bindings["artifact_path"])
    return o8_admission.validate_o7_admission(descriptor(), **bindings)


def issue_production_capability(**bindings):
    validate_frozen_inputs(bindings["inputs"])
    _validate_artifact_binding(bindings["inputs"], bindings["artifact_path"])
    return o8_admission.issue_production_capability(descriptor(), **bindings)


def execution_host():
    return o8_admission.execution_host()
