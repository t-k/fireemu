"""Fail-closed admission tests for the O8 production wire capability.

No production credential, origin or request is used. The capability here is
bound to a locally built archive descriptor and is never executed.
"""

import copy
import hashlib
import importlib.util
import pickle
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE.parent / "production-admission"))
sys.path.insert(0, str(HERE))

import commit_acquisition as acquisition
import commit_remote_transport as transport
from broad_contract import digest

_SPEC = importlib.util.spec_from_file_location("o8_bundle", HERE / "o8_bundle.py")
assert _SPEC is not None and _SPEC.loader is not None
o8_bundle = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(o8_bundle)


def frozen_inputs(campaign: str = "campaign-a") -> dict:
    permission = {"kind": "commit-owner-execution-permission-v1", "campaign": campaign}
    plan = {"campaignId": campaign, "nonce": "a" * 32}
    source_inputs = {
        name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
        for name in o8_bundle.WORKER_SOURCES
    }
    value = {
        "kind": "commit-frozen-inputs-v2",
        "permission": permission,
        "permissionDigest": digest(permission),
        "plan": plan,
        "planDigest": digest(plan),
        "sourceCommit": "0" * 40,
        "sourceInputs": source_inputs,
        "artifactSha256": "b" * 64,
    }
    value["inputsDigest"] = digest(value)
    return value


def approval_for(inputs: dict, manifest_bytes: bytes) -> dict:
    return {
        "kind": "commit-o8-approval-v1",
        "status": "approved",
        "manifestSha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "inputsDigest": inputs["inputsDigest"],
        "permissionDigest": inputs["permissionDigest"],
        "sourceCommit": inputs["sourceCommit"],
        "sourceInputsDigest": digest(inputs["sourceInputs"]),
        "artifactSha256": inputs["artifactSha256"],
        "planDigest": inputs["planDigest"],
        "nonceDigest": digest(inputs["plan"]["nonce"]),
    }


def issue(inputs: dict, fd: int, sha: str, **overrides):
    manifest_bytes = b'{"kind": "commit-o8-manifest-v1"}'
    approval = {**approval_for(inputs, manifest_bytes), **overrides}
    return acquisition.issue_production_capability(
        inputs=inputs,
        approval=approval,
        manifest_bytes=manifest_bytes,
        archive_fd=fd,
        archive_sha256=sha,
    )


def archive_for(inputs: dict):
    return o8_bundle.build_worker_archive_from_source(ROOT, inputs["sourceInputs"])


def test_run_acquisition_refuses_a_raw_callable_as_production_authority(tmp_path):
    """A caller supplied callable can never be the production wire."""
    with pytest.raises(ValueError, match="exactly one"):
        acquisition.run_acquisition(
            tmp_path / "out",
            frozen_inputs(),
            permission_path=tmp_path / "permission.json",
            source_root=tmp_path,
            artifact_path=tmp_path / "artifact",
            ledger_root=tmp_path / "ledger",
            api_key="unused",
            credential_handoff={},
        )
    assert (
        "transmit"
        not in acquisition.run_acquisition.__code__.co_varnames[
            : acquisition.run_acquisition.__code__.co_argcount
            + acquisition.run_acquisition.__code__.co_kwonlyargcount
        ]
    )


@pytest.mark.parametrize(
    "build",
    [
        lambda: transport.request,
        lambda: transport.request_bound,
        lambda: lambda value: transport.request_bound(value),
        lambda: lambda value, _fixed=transport.request_bound: _fixed(value),
    ],
    ids=["direct", "bound", "global-wrapper", "default-argument-wrapper"],
)
def test_injected_transport_rejects_the_production_wire_and_its_wrappers(
    tmp_path, build
):
    with pytest.raises(ValueError, match="production"):
        acquisition.run_acquisition(
            tmp_path / "out",
            frozen_inputs(),
            permission_path=tmp_path / "permission.json",
            source_root=tmp_path,
            artifact_path=tmp_path / "artifact",
            ledger_root=tmp_path / "ledger",
            api_key="unused",
            credential_handoff={},
            injected_transport=build(),
        )


def test_capability_is_issued_only_for_a_complete_o7_binding(tmp_path):
    inputs = frozen_inputs()
    archive, sha = archive_for(inputs)
    with o8_bundle.unlinked_archive_fd(archive, sha) as fd:
        capability = issue(inputs, fd, sha)
        assert capability.campaign_id == inputs["plan"]["campaignId"]
        assert capability.archive_sha256 == sha
        for override in (
            {"status": "pending"},
            {"kind": "other"},
            {"inputsDigest": "0" * 64},
            {"permissionDigest": "0" * 64},
            {"planDigest": "0" * 64},
            {"nonceDigest": "0" * 64},
            {"artifactSha256": "0" * 64},
            {"sourceCommit": "1" * 40},
            {"sourceInputsDigest": "0" * 64},
            {"manifestSha256": "0" * 64},
        ):
            with pytest.raises(ValueError):
                issue(inputs, fd, sha, **override)


def test_capability_requires_a_verified_archive_descriptor(tmp_path):
    inputs = frozen_inputs()
    archive, sha = archive_for(inputs)
    linked = tmp_path / "linked.pyz"
    linked.write_bytes(archive)
    import os

    handle = os.open(linked, os.O_RDONLY)
    try:
        with pytest.raises(ValueError):
            issue(inputs, handle, sha)
    finally:
        os.close(handle)
    with o8_bundle.unlinked_archive_fd(archive, sha) as fd:
        with pytest.raises(ValueError):
            issue(inputs, fd, "0" * 64)
        drifted = copy.deepcopy(inputs)
        first = next(iter(drifted["sourceInputs"]))
        drifted["sourceInputs"][first] = "0" * 64
        drifted["inputsDigest"] = digest(
            {k: v for k, v in drifted.items() if k != "inputsDigest"}
        )
        with pytest.raises(ValueError):
            issue(drifted, fd, sha)


def test_a_forged_capability_with_matching_attributes_is_refused(tmp_path):
    inputs = frozen_inputs()
    archive, sha = archive_for(inputs)

    class Forged:
        campaign_id = inputs["plan"]["campaignId"]
        archive_sha256 = sha
        inputs_digest = inputs["inputsDigest"]

        def _transmit(self, value):  # pragma: no cover -- must never run
            raise AssertionError("forged capability transmitted")

    for forged in (Forged(), object()):
        with pytest.raises(ValueError, match="capability"):
            acquisition.run_acquisition(
                tmp_path / "out",
                inputs,
                permission_path=tmp_path / "permission.json",
                source_root=tmp_path,
                artifact_path=tmp_path / "artifact",
                ledger_root=tmp_path / "ledger",
                api_key="unused",
                credential_handoff={},
                capability=forged,
            )
    with o8_bundle.unlinked_archive_fd(archive, sha) as fd:
        capability = issue(inputs, fd, sha)
        with pytest.raises(TypeError):
            copy.copy(capability)
        with pytest.raises(TypeError):
            copy.deepcopy(capability)
        with pytest.raises(TypeError):
            pickle.dumps(capability)
        with pytest.raises(TypeError):
            acquisition.ProductionWireCapability(
                object(),
                archive_fd=fd,
                archive_sha256=sha,
                campaign_id=capability.campaign_id,
                inputs_digest=capability.inputs_digest,
            )


def test_capability_is_one_shot_and_bound_to_its_own_campaign(tmp_path):
    first = frozen_inputs("campaign-a")
    second = frozen_inputs("campaign-b")
    archive, sha = archive_for(first)
    with o8_bundle.unlinked_archive_fd(archive, sha) as fd:
        capability = issue(first, fd, sha)
        with pytest.raises(ValueError, match="campaign"):
            capability._consume(
                campaign_id=second["plan"]["campaignId"],
                inputs_digest=second["inputsDigest"],
            )
        with pytest.raises(ValueError, match="frozen"):
            capability._consume(
                campaign_id=first["plan"]["campaignId"], inputs_digest="0" * 64
            )
        capability._consume(
            campaign_id=first["plan"]["campaignId"],
            inputs_digest=first["inputsDigest"],
        )
        with pytest.raises(ValueError, match="one-shot"):
            capability._consume(
                campaign_id=first["plan"]["campaignId"],
                inputs_digest=first["inputsDigest"],
            )


def test_a_consumed_capability_cannot_be_presented_again(tmp_path):
    inputs = frozen_inputs()
    archive, sha = archive_for(inputs)
    with o8_bundle.unlinked_archive_fd(archive, sha) as fd:
        capability = issue(inputs, fd, sha)
        capability._consume(
            campaign_id=inputs["plan"]["campaignId"],
            inputs_digest=inputs["inputsDigest"],
        )
        with pytest.raises(ValueError, match="capability"):
            acquisition.run_acquisition(
                tmp_path / "out",
                inputs,
                permission_path=tmp_path / "permission.json",
                source_root=tmp_path,
                artifact_path=tmp_path / "artifact",
                ledger_root=tmp_path / "ledger",
                api_key="unused",
                credential_handoff={},
                capability=capability,
            )


def test_outer_supervisor_is_not_a_source_of_production_wire_authority():
    """broad.supervise() prepares an isolated child; it issues no capability."""
    sys.path.insert(0, str(HERE.parent))
    try:
        import broad
    finally:
        sys.path.pop(0)
    assert not hasattr(broad, "issue_production_capability")
    assert not hasattr(broad, "ProductionWireCapability")
    source = (ROOT / "tools/compat-broad/broad.py").read_text()
    assert "commit_acquisition" not in source
    assert "run_acquisition" not in source


def test_permission_gate_and_coordinator_share_one_source_digest():
    import commit_reserved_adapter as reserved
    from batch_contract import PROJECT
    from gate_adapter import compiler_plan

    inputs = reserved.source_inputs()
    plan = compiler_plan(PROJECT, "(default)", "a" * 32)
    bindings = acquisition.permission_bindings(plan, "0" * 40, "b" * 64, inputs)
    assert bindings["collectorSourceDigest"] == reserved.source_digest()
    assert bindings["sourceInputs"] == inputs
    subset = {name: value for name, value in list(inputs.items())[1:]}
    assert digest(subset) != reserved.source_digest()
    reordered = dict(reversed(list(inputs.items())))
    assert digest(reordered) == reserved.source_digest()
    assert reordered == inputs
