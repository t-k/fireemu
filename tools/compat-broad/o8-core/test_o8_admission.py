"""Admission negatives for the campaign-generic O8 core.

Every artifact here is built locally from repository sources. No credential, no
network, no production origin and no Ledger outside the test's own temp path.
"""

import copy
import hashlib
import json
import sys
import time
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "tools/compat-broad"))
sys.path.insert(0, str(HERE))

import o8_admission
from broad_contract import digest
from o8_campaign import (
    BASE_APPROVAL_FIELDS,
    CAMPAIGN_APPROVAL_FIELDS,
    CampaignDescriptor,
)

COLLECTOR_ENTRY = "tools/compat-broad/o8-core/o8_admission.py"
COMPARATOR_ENTRY = "tools/compat-broad/o8-core/o8_campaign.py"
CAMPAIGN_A = "TEST-CAMPAIGN-A"
CAMPAIGN_B = "TEST-CAMPAIGN-B"


def source_map():
    names = (COLLECTOR_ENTRY, COMPARATOR_ENTRY)
    return {
        name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in names
    }


def forbidden():
    return (o8_admission.regular_file_digest,)


def descriptor_for(campaign=CAMPAIGN_A, **overrides):
    members = {
        "campaign_id": campaign,
        "frozen_inputs_kind": "test-frozen-inputs-v1",
        "permission_kind": "test-owner-execution-permission-v1",
        "approval_kind": "test-o8-approval-v1",
        "manifest_kind": "test-o8-manifest-v1",
        "approval_fields": CAMPAIGN_APPROVAL_FIELDS,
        "artifact_profile": "test-profile",
        "campaign_seconds": 600,
        "recovery_seconds": 120,
        "source_map": source_map,
        "abort_closure_sources": (COLLECTOR_ENTRY,),
        "required_source_entries": (COLLECTOR_ENTRY, COMPARATOR_ENTRY),
        "frozen_bounds": {"totalRequests": 4},
        "budget": {"requests": 4},
        "plan_compiler": lambda nonce: {"campaignId": campaign, "nonce": nonce},
        "lock_scopes": lambda plan: [{"key": plan["nonce"], "mode": "WRITE"}],
        "collector": lambda *args, **kwargs: None,
        "comparator": lambda *args, **kwargs: None,
        "cost_model": lambda: {"totalCostMicrousd": 1},
        "permission_bindings": lambda *args: {},
        "transport_bound": lambda value, **kwargs: {"echo": value, **kwargs},
        "binding_verifier": lambda binding, digest_, frozen: None,
        "retained_artifact_validator": None,
        "forbidden_transports": forbidden,
    }
    members.update(overrides)
    return members


class Admission:
    """One complete, locally built O7 artifact set for a synthetic campaign."""

    def __init__(self, tmp_path, campaign=CAMPAIGN_A, **overrides):
        self.permission = {
            "kind": "test-owner-execution-permission-v1",
            "wallSeconds": 600,
            "recoverySeconds": 120,
        }
        members = descriptor_for(campaign, **overrides)
        members["retained_artifact_validator"] = self._retained
        self.descriptor = CampaignDescriptor(**members)
        self.plan = self.descriptor.plan_compiler("a" * 32)
        self.inputs = o8_admission.freeze_inputs(
            self.descriptor,
            self.permission,
            self.plan,
            source_commit="0" * 40,
            artifact_sha256="b" * 64,
        )
        self.ledger = tmp_path / f"ledger-{campaign}"
        self.manifest = {
            "kind": "test-o8-manifest-v1",
            "inputsDigest": self.inputs["inputsDigest"],
        }
        self.manifest_bytes = json.dumps(self.manifest).encode()
        self.manifest_path = tmp_path / f"manifest-{campaign}.json"
        self.manifest_path.write_bytes(self.manifest_bytes)
        self.artifact_path = tmp_path / f"artifact-{campaign}"
        self.artifact_path.write_bytes(b"retained artifact")
        self.launcher_path = tmp_path / f"launcher-{campaign}.py"
        self.launcher_path.write_bytes(b"# bounded launcher\n")
        self.approval = self._approval()

    def _retained(self, artifact_path, manifest_path, profile):
        assert profile == self.descriptor.artifact_profile
        return {
            "artifactSha256": self.inputs["artifactSha256"],
            "retainedManifestSha256": hashlib.sha256(
                Path(manifest_path).read_bytes()
            ).hexdigest(),
        }

    def _approval(self):
        now = time.time()
        approval = {
            "kind": self.descriptor.approval_kind,
            "status": "approved",
            "manifestSha256": hashlib.sha256(self.manifest_bytes).hexdigest(),
            "inputsDigest": self.inputs["inputsDigest"],
            "permissionDigest": self.inputs["permissionDigest"],
            "sourceCommit": self.inputs["sourceCommit"],
            "sourceInputsDigest": digest(self.inputs["sourceInputs"]),
            "artifactSha256": self.inputs["artifactSha256"],
            "planDigest": self.inputs["planDigest"],
            "nonceDigest": digest(self.inputs["plan"]["nonce"]),
            "ledgerRoot": str(self.ledger.resolve(strict=False)),
            "launcherSha256": hashlib.sha256(
                self.launcher_path.read_bytes()
            ).hexdigest(),
            "artifactProfile": self.descriptor.artifact_profile,
            "windowStartsAt": now - 1,
            "windowExpiresAt": now + 4 * self.descriptor.window_seconds,
            "executionHost": o8_admission.execution_host(),
            "campaignId": self.descriptor.campaign_id,
        }
        return {
            key: value
            for key, value in approval.items()
            if key in self.descriptor.approval_fields
        }

    def bindings(self, **overrides):
        value = {
            "inputs": self.inputs,
            "approval": self.approval,
            "manifest": self.manifest,
            "manifest_bytes": self.manifest_bytes,
            "manifest_path": self.manifest_path,
            "permission": self.permission,
            "ledger_root": self.ledger,
            "artifact_path": self.artifact_path,
            "launcher_path": self.launcher_path,
        }
        value.update(overrides)
        return value

    def validate(self, descriptor=None, **overrides):
        return o8_admission.validate_o7_admission(
            descriptor or self.descriptor, **self.bindings(**overrides)
        )

    def issue(self, descriptor=None, **overrides):
        return o8_admission.issue_production_capability(
            descriptor or self.descriptor,
            binding=7,
            binding_digest="c" * 64,
            **self.bindings(**overrides),
        )


def test_frozen_inputs_are_built_over_the_declared_source_map(tmp_path):
    admission = Admission(tmp_path)
    inputs = admission.inputs
    assert inputs["kind"] == "test-frozen-inputs-v1"
    assert inputs["bounds"] == admission.descriptor.frozen_bounds
    assert inputs["sourceInputs"] == source_map()
    assert inputs["inputsDigest"] == digest(
        {key: value for key, value in inputs.items() if key != "inputsDigest"}
    )
    o8_admission.validate_frozen_inputs(admission.descriptor, inputs)


def test_a_frozen_record_is_refused_without_the_campaign_entry_sources(tmp_path):
    """A collector the frozen inputs do not name can never be admitted."""
    admission = Admission(tmp_path)
    for missing in (COLLECTOR_ENTRY, COMPARATOR_ENTRY):
        inputs = copy.deepcopy(admission.inputs)
        del inputs["sourceInputs"][missing]
        inputs["inputsDigest"] = digest(
            {key: value for key, value in inputs.items() if key != "inputsDigest"}
        )
        with pytest.raises(ValueError, match="campaign entry source"):
            o8_admission.validate_frozen_inputs(admission.descriptor, inputs)
        with pytest.raises(ValueError, match="campaign entry source"):
            admission.validate(inputs=inputs)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda inputs: inputs.update(kind="other-frozen-inputs-v1"),
        lambda inputs: inputs["permission"].update(kind="other-permission-v1"),
        lambda inputs: inputs.pop("artifactSha256"),
        lambda inputs: inputs.update(sourceCommit=None),
    ],
    ids=["kind", "permission-kind", "missing-field", "malformed-commit"],
)
def test_a_frozen_record_outside_its_campaign_schema_is_refused(tmp_path, mutate):
    admission = Admission(tmp_path)
    inputs = copy.deepcopy(admission.inputs)
    mutate(inputs)
    if "inputsDigest" in inputs:
        inputs["inputsDigest"] = digest(
            {key: value for key, value in inputs.items() if key != "inputsDigest"}
        )
    with pytest.raises(ValueError):
        o8_admission.validate_frozen_inputs(admission.descriptor, inputs)


def test_a_complete_binding_is_admitted(tmp_path):
    admission = Admission(tmp_path)
    admitted = admission.validate()
    assert admitted["campaignId"] == CAMPAIGN_A
    assert admitted["ledgerRoot"] == str(admission.ledger.resolve(strict=False))
    assert admitted["windowStartsAt"] == admission.approval["windowStartsAt"]


def test_one_campaigns_descriptor_cannot_admit_another_campaigns_approval(tmp_path):
    """A descriptor is bound to exactly one campaign identity."""
    first = Admission(tmp_path, CAMPAIGN_A)
    second = Admission(tmp_path, CAMPAIGN_B)
    other = CampaignDescriptor(
        **{**first.descriptor.members(), "campaign_id": CAMPAIGN_B}
    )
    with pytest.raises(ValueError, match="another campaign"):
        first.validate(descriptor=other)
    with pytest.raises(ValueError, match="another campaign"):
        second.validate(descriptor=first.descriptor)
    assert first.validate()["campaignId"] == CAMPAIGN_A
    assert second.validate()["campaignId"] == CAMPAIGN_B


def test_a_generic_approval_must_carry_its_own_campaign_id(tmp_path):
    admission = Admission(tmp_path)
    assert "campaignId" in admission.approval
    without = {
        key: value for key, value in admission.approval.items() if key != "campaignId"
    }
    with pytest.raises(ValueError, match="approval artifact"):
        admission.validate(approval=without)
    with pytest.raises(ValueError, match="another campaign"):
        admission.validate(approval={**admission.approval, "campaignId": CAMPAIGN_B})


def test_a_base_schema_campaign_binds_its_identity_through_the_frozen_plan(tmp_path):
    """A 16-key approval is admitted, and still only for its own campaign."""
    admission = Admission(tmp_path, approval_fields=BASE_APPROVAL_FIELDS)
    assert set(admission.approval) == set(BASE_APPROVAL_FIELDS)
    assert admission.validate()["campaignId"] == CAMPAIGN_A
    other = CampaignDescriptor(
        **{**admission.descriptor.members(), "campaign_id": CAMPAIGN_B}
    )
    with pytest.raises(ValueError, match="another campaign"):
        admission.validate(descriptor=other)


@pytest.mark.parametrize(
    "override",
    [
        {"status": "pending"},
        {"kind": "other-o8-approval-v1"},
        {"inputsDigest": "0" * 64},
        {"permissionDigest": "0" * 64},
        {"planDigest": "0" * 64},
        {"nonceDigest": "0" * 64},
        {"artifactSha256": "0" * 64},
        {"sourceCommit": "1" * 40},
        {"sourceInputsDigest": "0" * 64},
        {"manifestSha256": "0" * 64},
        {"launcherSha256": "0" * 64},
        {"artifactProfile": "unreviewed"},
        {"ledgerRoot": "/nonexistent/private/ledger"},
        {"windowStartsAt": lambda now: now + 600},
        {"windowExpiresAt": lambda now: now + 10},
        {"windowExpiresAt": "soon"},
        {"windowStartsAt": float("nan")},
        {"executionHost": {"platform": "other", "machine": "other"}},
    ],
)
def test_an_incomplete_o7_binding_is_refused(tmp_path, override):
    admission = Admission(tmp_path)
    # Window cases are resolved now, not at import: a long suite would otherwise
    # leave a "future" window already in the past by the time the case runs.
    now = time.time()
    override = {
        key: value(now) if callable(value) else value for key, value in override.items()
    }
    with pytest.raises(ValueError):
        admission.validate(approval={**admission.approval, **override})


def test_the_campaign_window_comes_from_the_descriptor(tmp_path):
    admission = Admission(tmp_path)
    for permission in (
        {**admission.permission, "wallSeconds": 1200},
        {**admission.permission, "recoverySeconds": 180},
    ):
        with pytest.raises(ValueError, match="campaign window"):
            admission.validate(permission=permission)


def test_a_capability_is_one_shot_and_bound_to_its_admission(tmp_path):
    admission = Admission(tmp_path)
    capability = admission.issue()
    assert o8_admission.issued_capability(capability) is True
    assert capability.campaign_id == CAMPAIGN_A
    with pytest.raises(ValueError, match="another campaign"):
        capability._consume(
            campaign_id=CAMPAIGN_B,
            inputs_digest=admission.inputs["inputsDigest"],
            ledger_root=admission.ledger,
        )
    with pytest.raises(ValueError, match="other frozen inputs"):
        capability._consume(
            campaign_id=CAMPAIGN_A,
            inputs_digest="0" * 64,
            ledger_root=admission.ledger,
        )
    with pytest.raises(ValueError, match="another shared Ledger"):
        capability._consume(
            campaign_id=CAMPAIGN_A,
            inputs_digest=admission.inputs["inputsDigest"],
            ledger_root=tmp_path / "private-ledger",
        )
    with pytest.raises(ValueError, match="unconsumed"):
        capability._transmit({"request": 1})
    capability._consume(
        campaign_id=CAMPAIGN_A,
        inputs_digest=admission.inputs["inputsDigest"],
        ledger_root=admission.ledger,
    )
    assert o8_admission.issued_capability(capability) is False
    transmitted = capability._transmit({"request": 1})
    assert transmitted["echo"] == {"request": 1}
    assert transmitted["binding"] == 7
    assert transmitted["binding_digest"] == "c" * 64
    assert transmitted["capability"] is capability
    with pytest.raises(ValueError, match="one-shot"):
        capability._consume(
            campaign_id=CAMPAIGN_A,
            inputs_digest=admission.inputs["inputsDigest"],
            ledger_root=admission.ledger,
        )


def test_capability_binding_cannot_be_replaced_after_issue(tmp_path):
    admission = Admission(tmp_path)
    capability = admission.issue()
    capability._consume(
        campaign_id=CAMPAIGN_A,
        inputs_digest=admission.inputs["inputsDigest"],
        ledger_root=admission.ledger,
    )
    for name, value in (
        ("_transport_bound", lambda value, **_: {"echo": value}),
        ("_binding", object()),
        ("binding_digest", "forged"),
        ("window_expires_at", time.time() + 999999),
    ):
        with pytest.raises(AttributeError):
            object.__setattr__(capability, name, value)
    with pytest.raises(ValueError, match="binding differs"):
        o8_admission.authorize_transport(
            capability, binding=object(), binding_digest="forged"
        )
    o8_admission.revoke_production_capability(capability)
    with pytest.raises(ValueError, match="revoked"):
        capability._transmit({"request": 1})


def test_an_issued_capability_can_be_revoked(tmp_path):
    admission = Admission(tmp_path)
    capability = admission.issue()
    o8_admission.revoke_production_capability(capability)
    assert o8_admission.issued_capability(capability) is False


def test_a_capability_is_not_constructible_copyable_or_serializable(tmp_path):
    admission = Admission(tmp_path)
    capability = admission.issue()
    try:
        with pytest.raises(TypeError):
            o8_admission.ProductionWireCapability(object())
        with pytest.raises(TypeError):
            copy.copy(capability)
        with pytest.raises(TypeError):
            copy.deepcopy(capability)
        with pytest.raises(TypeError):
            json.dumps(capability)
    finally:
        o8_admission.revoke_production_capability(capability)


def test_the_binding_verifier_runs_before_a_capability_exists(tmp_path):
    seen = []

    def verifier(binding, binding_digest, frozen):
        seen.append((binding, binding_digest, dict(frozen)))
        raise ValueError("frozen worker source digest differs")

    admission = Admission(tmp_path, binding_verifier=verifier)
    with pytest.raises(ValueError, match="worker source"):
        admission.issue()
    assert seen == [(7, "c" * 64, source_map())]


def test_abort_generation_is_derived_from_the_descriptors_closure(tmp_path):
    admission = Admission(tmp_path)
    generation = o8_admission.abort_generation(admission.descriptor, admission.inputs)
    assert generation["sourceCommit"] == admission.inputs["sourceCommit"]
    assert generation["collectorSourceDigest"] == digest(
        admission.inputs["sourceInputs"]
    )
    assert set(generation["sourceDigests"]) == {"o8_admission.py"}
    inputs = copy.deepcopy(admission.inputs)
    del inputs["sourceInputs"][COLLECTOR_ENTRY]
    with pytest.raises(ValueError, match="source closure"):
        o8_admission.abort_generation(admission.descriptor, inputs)


def test_an_injected_transport_cannot_name_the_campaigns_production_wire(tmp_path):
    admission = Admission(tmp_path)
    descriptor = admission.descriptor
    assert (
        o8_admission.reject_production_transport(descriptor, lambda value: value)
        is not None
    )
    for build in (
        lambda: o8_admission.regular_file_digest,
        lambda: lambda value: o8_admission.regular_file_digest(value),
        lambda: lambda value, _fixed=o8_admission.regular_file_digest: _fixed(value),
        lambda: o8_admission.ProductionWireCapability._transmit,
    ):
        with pytest.raises(ValueError, match="production wire"):
            o8_admission.reject_production_transport(descriptor, build())
    with pytest.raises(ValueError, match="callable"):
        o8_admission.reject_production_transport(descriptor, "not-callable")


@pytest.mark.parametrize(
    "call",
    [
        lambda inputs: o8_admission.validate_frozen_inputs("not-a-descriptor", inputs),
        lambda inputs: o8_admission.abort_generation(None, inputs),
        lambda inputs: o8_admission.freeze_inputs(
            {}, {}, {}, source_commit="0" * 40, artifact_sha256="b" * 64
        ),
    ],
)
def test_the_core_refuses_a_value_that_is_not_a_campaign_descriptor(tmp_path, call):
    admission = Admission(tmp_path)
    with pytest.raises(ValueError, match="campaign descriptor required"):
        call(admission.inputs)
