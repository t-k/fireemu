"""Fail-closed admission tests for the O8 production wire capability.

No production credential, origin or request is used. The capability here is
bound to a locally built archive descriptor and is never executed.
"""

import copy
import hashlib
import importlib.util
import json
import pickle
import platform
import sys
import time
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
from o8_campaign import CampaignDescriptor


def descriptor_for(campaign: str) -> CampaignDescriptor:
    """The Commit descriptor rebound to one test campaign identity."""
    return CampaignDescriptor(
        **{**acquisition.COMMIT.members(), "campaign_id": campaign}
    )


_SPEC = importlib.util.spec_from_file_location("o8_bundle", HERE / "o8_bundle.py")
assert _SPEC is not None and _SPEC.loader is not None
o8_bundle = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(o8_bundle)


def frozen_inputs(campaign: str = "campaign-a") -> dict:
    permission = {
        "kind": "commit-owner-execution-permission-v1",
        "campaign": campaign,
        "wallSeconds": acquisition.CAMPAIGN_SECONDS,
        "recoverySeconds": acquisition.RECOVERY_SECONDS,
    }
    plan = {"campaignId": campaign, "nonce": "a" * 32}
    source_inputs = {
        name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
        for name in (
            *o8_bundle.WORKER_SOURCES,
            *acquisition.COMMIT.required_source_entries,
        )
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


def approval_for(inputs: dict, manifest_bytes: bytes, ledger: Path) -> dict:
    now = time.time()
    return {
        "kind": acquisition.APPROVAL_KIND,
        "status": "approved",
        "manifestSha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "inputsDigest": inputs["inputsDigest"],
        "permissionDigest": inputs["permissionDigest"],
        "sourceCommit": inputs["sourceCommit"],
        "sourceInputsDigest": digest(inputs["sourceInputs"]),
        "artifactSha256": inputs["artifactSha256"],
        "planDigest": inputs["planDigest"],
        "nonceDigest": digest(inputs["plan"]["nonce"]),
        "ledgerRoot": str(Path(ledger).resolve(strict=False)),
        "launcherSha256": hashlib.sha256(
            (HERE / "commit_o8.py").read_bytes()
        ).hexdigest(),
        "artifactProfile": acquisition.REVIEWED_ARTIFACT_PROFILE,
        "windowStartsAt": now - 1,
        "windowExpiresAt": now + 4 * acquisition.CAMPAIGN_SECONDS,
        "executionHost": acquisition.execution_host(),
    }


class Admission:
    """A complete, locally built O7 artifact set for one campaign."""

    def __init__(self, tmp_path: Path, monkeypatch, campaign: str = "campaign-a"):
        self.inputs = frozen_inputs(campaign)
        self.descriptor = descriptor_for(campaign)
        self.ledger = tmp_path / f"ledger-{campaign}"
        self.manifest = {
            "kind": acquisition.MANIFEST_KIND,
            "inputsDigest": self.inputs["inputsDigest"],
        }
        self.manifest_bytes = json.dumps(self.manifest).encode()
        self.manifest_path = tmp_path / f"manifest-{campaign}.json"
        self.manifest_path.write_bytes(self.manifest_bytes)
        self.artifact_path = tmp_path / f"artifact-{campaign}"
        self.artifact_path.write_bytes(b"retained artifact")
        self.approval = approval_for(self.inputs, self.manifest_bytes, self.ledger)
        self.permission = self.inputs["permission"]
        monkeypatch.setattr(
            acquisition,
            "validate_retained_artifact",
            lambda artifact, manifest_path, profile=None: {
                "artifactSha256": self.inputs["artifactSha256"],
                "retainedManifestSha256": hashlib.sha256(
                    Path(manifest_path).read_bytes()
                ).hexdigest(),
            },
        )

    def issue(self, fd: int, sha: str, **overrides):
        # Pop every non-approval override first; the rest override the approval.
        inputs = overrides.pop("inputs", self.inputs)
        permission = overrides.pop("permission", self.permission)
        ledger = overrides.pop("ledger_root", self.ledger)
        launcher = overrides.pop("launcher_path", HERE / "commit_o8.py")
        descriptor = overrides.pop("descriptor", self.descriptor)
        manifest = {**self.manifest, **(overrides.pop("manifest", None) or {})}
        manifest_bytes = (
            self.manifest_bytes
            if manifest == self.manifest
            else json.dumps(manifest).encode()
        )
        return acquisition.issue_production_capability(
            descriptor=descriptor,
            inputs=inputs,
            approval={**self.approval, **overrides},
            manifest=manifest,
            manifest_bytes=manifest_bytes,
            manifest_path=self.manifest_path,
            permission=permission,
            ledger_root=ledger,
            artifact_path=self.artifact_path,
            launcher_path=launcher,
            binding=fd,
            binding_digest=sha,
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


def test_capability_is_issued_only_for_a_complete_o7_binding(tmp_path, monkeypatch):
    admission = Admission(tmp_path, monkeypatch)
    inputs = admission.inputs
    archive, sha = archive_for(inputs)
    with o8_bundle.unlinked_archive_fd(archive, sha) as fd:
        capability = admission.issue(fd, sha)
        assert capability.campaign_id == inputs["plan"]["campaignId"]
        assert capability.binding_digest == sha
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
            {"launcherSha256": "0" * 64},
            {"artifactProfile": "unreviewed"},
            {"ledgerRoot": "/nonexistent/private/ledger"},
            {"windowStartsAt": time.time() + 600},
            {"windowExpiresAt": time.time() + 10},
            {"executionHost": {"platform": "other-platform", "machine": "other-arch"}},
            {
                "executionHost": {
                    **acquisition.execution_host(),
                    "machine": "other-arch",
                }
            },
            {"executionHost": {"platform": acquisition.execution_host()["platform"]}},
            {"executionHost": None},
            {"manifest": {"kind": "other"}},
            {"manifest": {"inputsDigest": "0" * 64}},
        ):
            with pytest.raises(ValueError):
                admission.issue(fd, sha, **override)


def test_approval_must_bind_the_running_execution_host(tmp_path, monkeypatch):
    """An approval issued on one host can never authorize a run on another."""
    assert "executionHost" in acquisition.APPROVAL_FIELDS
    assert len(acquisition.APPROVAL_FIELDS) == 16
    host = acquisition.execution_host()
    assert host == {
        "platform": platform.system().lower(),
        "machine": platform.machine(),
    }
    admission = Admission(tmp_path, monkeypatch)
    archive, sha = archive_for(admission.inputs)
    campaign = admission.inputs["plan"]["campaignId"]
    with o8_bundle.unlinked_archive_fd(archive, sha) as fd:
        assert admission.issue(fd, sha).campaign_id == campaign
    without = {
        key: value
        for key, value in admission.approval.items()
        if key != "executionHost"
    }
    with pytest.raises(ValueError, match="approval artifact"):
        acquisition.validate_o7_admission(
            descriptor=admission.descriptor,
            inputs=admission.inputs,
            approval=without,
            manifest=admission.manifest,
            manifest_bytes=admission.manifest_bytes,
            manifest_path=admission.manifest_path,
            permission=admission.permission,
            ledger_root=admission.ledger,
            artifact_path=admission.artifact_path,
            launcher_path=HERE / "commit_o8.py",
        )


def test_the_window_must_hold_the_campaign_and_its_recovery(tmp_path, monkeypatch):
    """A window sized to the wall budget alone leaves no room for recovery."""
    assert acquisition.WINDOW_SECONDS == (
        acquisition.CAMPAIGN_SECONDS + acquisition.RECOVERY_SECONDS
    )
    admission = Admission(tmp_path, monkeypatch)
    archive, sha = archive_for(admission.inputs)
    now = time.time()
    with o8_bundle.unlinked_archive_fd(archive, sha) as fd:
        for margin in (acquisition.CAMPAIGN_SECONDS, acquisition.WINDOW_SECONDS - 1):
            with pytest.raises(ValueError, match="window expired"):
                admission.issue(
                    fd,
                    sha,
                    windowStartsAt=now - 1,
                    windowExpiresAt=now - 1 + margin,
                )
        capability = admission.issue(
            fd,
            sha,
            windowStartsAt=now - 1,
            windowExpiresAt=now + acquisition.WINDOW_SECONDS + 60,
        )
        assert capability.campaign_id == admission.inputs["plan"]["campaignId"]


def test_capability_requires_a_verified_archive_descriptor(tmp_path, monkeypatch):
    admission = Admission(tmp_path, monkeypatch)
    inputs = admission.inputs
    archive, sha = archive_for(inputs)
    linked = tmp_path / "linked.pyz"
    linked.write_bytes(archive)
    import os

    handle = os.open(linked, os.O_RDONLY)
    try:
        with pytest.raises(ValueError):
            admission.issue(handle, sha)
    finally:
        os.close(handle)
    with o8_bundle.unlinked_archive_fd(archive, sha) as fd:
        with pytest.raises(ValueError):
            admission.issue(fd, "0" * 64)
        drifted = copy.deepcopy(inputs)
        first = next(iter(drifted["sourceInputs"]))
        drifted["sourceInputs"][first] = "0" * 64
        drifted["inputsDigest"] = digest(
            {k: v for k, v in drifted.items() if k != "inputsDigest"}
        )
        with pytest.raises(ValueError):
            admission.issue(fd, sha, inputs=drifted)


def test_a_forged_capability_with_matching_attributes_is_refused(tmp_path, monkeypatch):
    admission = Admission(tmp_path, monkeypatch)
    inputs = admission.inputs
    archive, sha = archive_for(inputs)

    class Forged:
        campaign_id = inputs["plan"]["campaignId"]
        binding_digest = sha
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
        capability = admission.issue(fd, sha)
        with pytest.raises(TypeError):
            copy.copy(capability)
        with pytest.raises(TypeError):
            copy.deepcopy(capability)
        with pytest.raises(TypeError):
            pickle.dumps(capability)
        with pytest.raises(TypeError):
            acquisition.ProductionWireCapability(
                object(),
                binding=fd,
                binding_digest=sha,
                campaign_id=capability.campaign_id,
                window_seconds=capability.window_seconds,
                inputs_digest=capability.inputs_digest,
                ledger_root=capability.ledger_root,
                window_starts_at=capability.window_starts_at,
                window_expires_at=capability.window_expires_at,
                approval_digest=capability.approval_digest,
            )


def test_capability_is_one_shot_and_bound_to_its_own_campaign(tmp_path, monkeypatch):
    admission = Admission(tmp_path, monkeypatch)
    first = admission.inputs
    second = frozen_inputs("campaign-b")
    archive, sha = archive_for(first)
    with o8_bundle.unlinked_archive_fd(archive, sha) as fd:
        capability = admission.issue(fd, sha)
        bound = {
            "campaign_id": first["plan"]["campaignId"],
            "inputs_digest": first["inputsDigest"],
            "ledger_root": admission.ledger,
        }
        with pytest.raises(ValueError, match="campaign"):
            capability._consume(
                **{**bound, "campaign_id": second["plan"]["campaignId"]}
            )
        with pytest.raises(ValueError, match="frozen"):
            capability._consume(**{**bound, "inputs_digest": "0" * 64})
        with pytest.raises(ValueError, match="shared Ledger"):
            capability._consume(**{**bound, "ledger_root": tmp_path / "private"})
        capability._consume(**bound)
        with pytest.raises(ValueError, match="one-shot"):
            capability._consume(**bound)


def test_a_consumed_capability_cannot_be_presented_again(tmp_path, monkeypatch):
    admission = Admission(tmp_path, monkeypatch)
    inputs = admission.inputs
    archive, sha = archive_for(inputs)
    with o8_bundle.unlinked_archive_fd(archive, sha) as fd:
        capability = admission.issue(fd, sha)
        capability._consume(
            campaign_id=inputs["plan"]["campaignId"],
            inputs_digest=inputs["inputsDigest"],
            ledger_root=admission.ledger,
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


def test_a_private_ledger_root_cannot_run_an_admitted_campaign(tmp_path, monkeypatch):
    """The approval binds one shared Ledger; another root cannot be substituted."""
    admission = Admission(tmp_path, monkeypatch)
    inputs = admission.inputs
    archive, sha = archive_for(inputs)
    with o8_bundle.unlinked_archive_fd(archive, sha) as fd:
        capability = admission.issue(fd, sha)
        private_root = tmp_path / "private-ledger"
        with pytest.raises(ValueError, match="shared Ledger"):
            acquisition.run_acquisition(
                tmp_path / "out",
                inputs,
                permission_path=tmp_path / "permission.json",
                source_root=tmp_path,
                artifact_path=admission.artifact_path,
                ledger_root=private_root,
                api_key="unused",
                credential_handoff={},
                capability=capability,
            )
    assert not private_root.exists()
    assert not (tmp_path / "out").exists()


def test_an_expired_or_future_window_cannot_be_issued_or_spent(tmp_path, monkeypatch):
    admission = Admission(tmp_path, monkeypatch)
    inputs = admission.inputs
    archive, sha = archive_for(inputs)
    with o8_bundle.unlinked_archive_fd(archive, sha) as fd:
        for override in (
            {"windowStartsAt": time.time() + 3600},
            {"windowExpiresAt": time.time() + 5},
        ):
            with pytest.raises(ValueError, match="window"):
                admission.issue(fd, sha, **override)
        capability = admission.issue(fd, sha)
        # The window is rechecked when the admission is spent, not only at issue.
        monkeypatch.setattr(
            acquisition.time,
            "time",
            lambda: capability.window_expires_at + 1,
        )
        with pytest.raises(ValueError, match="window"):
            capability._consume(
                campaign_id=inputs["plan"]["campaignId"],
                inputs_digest=inputs["inputsDigest"],
                ledger_root=admission.ledger,
            )


def test_a_retained_artifact_mismatch_refuses_issuance(tmp_path, monkeypatch):
    admission = Admission(tmp_path, monkeypatch)
    inputs = admission.inputs
    archive, sha = archive_for(inputs)
    monkeypatch.setattr(
        acquisition,
        "validate_retained_artifact",
        lambda artifact, manifest_path, profile=None: {
            "artifactSha256": "0" * 64,
            "retainedManifestSha256": hashlib.sha256(
                Path(manifest_path).read_bytes()
            ).hexdigest(),
        },
    )
    with (
        o8_bundle.unlinked_archive_fd(archive, sha) as fd,
        pytest.raises(ValueError, match="retained"),
    ):
        admission.issue(fd, sha)


def test_a_wrong_permission_window_refuses_issuance(tmp_path, monkeypatch):
    admission = Admission(tmp_path, monkeypatch)
    inputs = admission.inputs
    archive, sha = archive_for(inputs)
    permission = {**admission.permission, "wallSeconds": 60}
    with (
        o8_bundle.unlinked_archive_fd(archive, sha) as fd,
        pytest.raises(ValueError, match="campaign window"),
    ):
        admission.issue(fd, sha, permission=permission)


def test_issuance_runs_the_same_check_set_as_the_o8_cli():
    """The CLI must not enforce anything issuance skips."""
    import commit_o8

    assert commit_o8._validate_approval.__doc__
    source = (HERE / "commit_o8.py").read_text()
    # The CLI delegates; it keeps no private copy of the O7 check set.
    assert "validate_o7_admission" in source
    assert "windowExpiresAt" not in source
    assert "launcherSha256" not in source
    assert "artifactProfile" not in source


def test_admission_binds_the_running_launcher_not_a_sibling_file(tmp_path, monkeypatch):
    """launcherSha256 must bind the launcher that is actually running."""
    admission = Admission(tmp_path, monkeypatch)
    inputs = admission.inputs
    archive, sha = archive_for(inputs)
    modified = tmp_path / "elsewhere" / "commit_o8.py"
    modified.parent.mkdir()
    modified.write_bytes(
        (HERE / "commit_o8.py").read_bytes() + b"\n# modified launcher\n"
    )
    real = HERE / "commit_o8.py"
    with o8_bundle.unlinked_archive_fd(archive, sha) as fd:
        # The approval binds the real launcher, so a modified one is refused.
        with pytest.raises(ValueError, match="approval binding"):
            admission.issue(fd, sha, launcher_path=modified)
        # And an approval bound to the modified launcher is refused for the real one.
        modified_digest = hashlib.sha256(modified.read_bytes()).hexdigest()
        with pytest.raises(ValueError, match="approval binding"):
            admission.issue(fd, sha, launcherSha256=modified_digest)
        # The self-consistent pairing is the only one accepted.
        capability = admission.issue(
            fd,
            sha,
            launcher_path=modified,
            launcherSha256=modified_digest,
        )
        assert capability.campaign_id == inputs["plan"]["campaignId"]
        acquisition.revoke_production_capability(capability)
        assert admission.issue(fd, sha, launcher_path=real) is not None


def test_admission_requires_an_explicit_launcher_path(tmp_path, monkeypatch):
    admission = Admission(tmp_path, monkeypatch)
    with pytest.raises(TypeError):
        acquisition.validate_o7_admission(
            inputs=admission.inputs,
            approval=admission.approval,
            manifest=admission.manifest,
            manifest_bytes=admission.manifest_bytes,
            manifest_path=admission.manifest_path,
            permission=admission.permission,
            ledger_root=admission.ledger,
            artifact_path=admission.artifact_path,
        )
