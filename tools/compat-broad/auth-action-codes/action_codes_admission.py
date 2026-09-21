"""O8 admission adapter for AUTH-ACTION; production execution stays closed."""

from __future__ import annotations

import sys
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
    return o8_admission.validate_frozen_inputs(descriptor(), inputs)


def validate_o7_admission(**bindings):
    return o8_admission.validate_o7_admission(descriptor(), **bindings)


def issue_production_capability(**bindings):
    return o8_admission.issue_production_capability(descriptor(), **bindings)


def execution_host():
    return o8_admission.execution_host()
