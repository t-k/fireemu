"""O8 admission and temporary-Ledger integration proof for FS-CONFIG-LIFECYCLE.

Every artifact here is built locally. No credential, no network origin, no
production project, and no Ledger outside the test's own temporary path: the
proof Ledger is created by the test and marked as such, and the production path
refuses any Ledger without that marker when a transport is injected.
"""

from __future__ import annotations

import copy
import hashlib
import json
import sys
import time
from pathlib import Path

import pytest
from fs_config_lifecycle import (
    lifecycle_admission as admission,
)
from fs_config_lifecycle import (
    lifecycle_descriptor as campaign,
)
from fs_config_lifecycle import (
    lifecycle_o8,
    lifecycle_production,
    lifecycle_remote_transport,
)
from fs_config_lifecycle.cases import compile_cases
from fs_config_lifecycle.fake_admin import FakeAdmin, saved_projection
from fs_config_lifecycle.lifecycle_gate import APPLY_REFUSED, NOT_APPLIED, RESTORED

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "tools/compat-broad"))
sys.path.insert(0, str(ROOT / "tools/compat-broad/production-admission"))
sys.path.insert(0, str(ROOT / "tools/compat-broad/o8-core"))

import o8_admission
import reservations
from batch_contract import database_evidence
from broad_contract import digest
from o8_campaign import CampaignDescriptor

NONCE = "a1b2c3d4e5f60718293a4b5c6d7e8f90"
BASELINE = database_evidence(saved_projection())


def _no_sleep(_seconds: float) -> None:
    return None


def _permission(plan, inputs, *, commit="0" * 40, artifact="b" * 64) -> dict:
    now = time.time()
    required = campaign.permission_bindings(plan, commit, artifact, inputs, BASELINE)
    return {
        **required,
        "ownerIdentity": "t-k",
        "recoveryOwner": "t-k",
        "permissionReference": "conversation:test:FS-CONFIG-LIFECYCLE",
        "credentialPrincipal": {
            "clientId": "client",
            "subject": "subject",
            "requiredScopes": [campaign.PRINCIPAL_SCOPE],
        },
        "issuedAt": now - 5,
        "expiresAt": now + 4 * 3600,
    }


class Admission:
    """One complete, locally built O7 artifact set for the real descriptor."""

    def __init__(self, tmp_path: Path, *, nonce: str = NONCE) -> None:
        self.descriptor = campaign.descriptor()
        self.plan = campaign.plan_compiler(nonce)
        self.sources = campaign.source_map()
        self.artifact_path = tmp_path / "artifact"
        self.artifact_path.write_bytes(b"retained artifact")
        artifact = hashlib.sha256(self.artifact_path.read_bytes()).hexdigest()
        self.permission = _permission(self.plan, self.sources, artifact=artifact)
        admission._approve(
            self.permission, self.plan, "0" * 40, artifact, self.sources, BASELINE
        )
        self.inputs = o8_admission.freeze_inputs(
            self.descriptor,
            self.permission,
            self.plan,
            source_commit="0" * 40,
            artifact_sha256=artifact,
        )
        self.ledger = tmp_path / "ledger"
        self.manifest = {
            "kind": campaign.MANIFEST_KIND,
            "inputsDigest": self.inputs["inputsDigest"],
        }
        self.manifest_bytes = json.dumps(self.manifest).encode()
        self.manifest_path = tmp_path / "manifest.json"
        self.manifest_path.write_bytes(self.manifest_bytes)
        self.manifest_path.chmod(0o600)
        self.launcher_path = HERE / "lifecycle_o8.py"
        self.approval = self._approval()

    def _approval(self) -> dict:
        now = time.time()
        return {
            "kind": campaign.APPROVAL_KIND,
            "status": "approved",
            "campaignId": campaign.CAMPAIGN,
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
        }

    def bindings(self, **overrides) -> dict:
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

    def validate(self, **overrides):
        return admission.validate_o7_admission(**self.bindings(**overrides))


def _proof_ledger(tmp_path: Path) -> Path:
    root = tmp_path / "ledger"
    reservations.Ledger.create(root)
    (root / lifecycle_production.PROOF_MARKER).write_text("temporary proof ledger\n")
    return root


# -- descriptor ---------------------------------------------------------------


def test_the_descriptor_constructs_and_refuses_a_missing_member() -> None:
    descriptor = campaign.descriptor()
    assert descriptor.campaign_id == "FS-CONFIG-LIFECYCLE-01"
    assert descriptor.window_seconds == 900 + 360
    assert descriptor.binds_campaign_id
    assert descriptor.artifact_profile.startswith("fs-config-lifecycle-")
    assert set(descriptor.required_source_entries) == {
        campaign.COLLECTOR_ENTRY,
        campaign.COMPARATOR_ENTRY,
        campaign.WORKER_ENTRY,
        campaign.GATE_ENTRY,
    }
    members = descriptor.members()
    for name in ("collector", "transport_bound", "lock_scopes", "budget"):
        broken = dict(members)
        broken.pop(name)
        with pytest.raises(ValueError, match="requires every member"):
            CampaignDescriptor(**broken)
    with pytest.raises(AttributeError):
        descriptor.campaign_id = "other"


def test_the_source_map_covers_the_whole_lane_and_the_shared_closure() -> None:
    sources = campaign.source_map()
    lane = [name for name in sources if name.startswith(campaign.LANE_DIRECTORY + "/")]
    assert {Path(name).name for name in lane} >= {
        "cases.py",
        "manifest.py",
        "comparator.py",
        "lifecycle_gate.py",
        "lifecycle_collector.py",
        "lifecycle_descriptor.py",
        "lifecycle_admission.py",
        "lifecycle_production.py",
        "lifecycle_o8.py",
        "lifecycle_https_worker.py",
        "lifecycle_remote_transport.py",
        "test_fs_config_o8.py",
    }
    for name in campaign.ABORT_CLOSURE_SOURCES:
        assert name in sources
    assert "tools/compat-broad/production-admission/reservations.py" in sources


def test_the_worker_digest_pinned_by_the_transport_is_the_worker_on_disk() -> None:
    source, observed = campaign.worker_binding()
    assert observed == lifecycle_remote_transport._WORKER_SHA256
    campaign.verify_worker_binding(source, observed, campaign.source_map())
    with pytest.raises(ValueError, match="differs"):
        campaign.verify_worker_binding(source + b"\n", observed, None)
    with pytest.raises(ValueError, match="frozen inputs"):
        campaign.verify_worker_binding(source, observed, {campaign.WORKER_ENTRY: "x"})


def test_ledger_budget_and_lock_scopes_name_no_document_and_no_lifecycle_permission() -> (
    None
):
    plan = campaign.plan_compiler(NONCE)
    budget = campaign.ledger_budget()
    assert budget == {
        "requests": 128,
        "accounts": 1,
        "resources": 0,
        "costMicrousd": 128,
    }
    assert budget["costMicrousd"] <= 1_000_000
    locks = campaign.lock_scopes(plan)
    assert [lock["mode"] for lock in locks] == [
        "EXCLUSIVE",
        "EXCLUSIVE",
        "READ",
        "READ",
        "READ",
    ]
    assert all("/documents/" not in lock["key"] for lock in locks)
    text = json.dumps(
        campaign.permission_bindings(plan, "0" * 40, "b" * 64, campaign.source_map())
    )
    assert "databases.create" not in text
    assert "databases.delete" not in text


def test_the_plan_reference_is_recompiled_and_any_other_bytes_are_refused() -> None:
    plan = campaign.plan_compiler(NONCE)
    assert campaign.execution_plan(plan) == plan
    forged = {**plan, "lockScopes": []}
    with pytest.raises(ValueError, match="differs"):
        campaign.execution_plan(forged)
    with pytest.raises(ValueError):
        campaign.plan_compiler("zz")


def test_an_injected_transport_that_names_the_production_wire_is_refused() -> None:
    descriptor = campaign.descriptor()

    def leaks(request, *, deadline):
        return lifecycle_remote_transport.request(
            request,
            "t",
            deadline=deadline,
            capability=None,
            binding=b"",
            binding_digest="",
        )

    with pytest.raises(ValueError, match="production wire"):
        o8_admission.reject_production_transport(descriptor, leaks)
    o8_admission.reject_production_transport(descriptor, FakeAdmin().transmit)


# -- admission ----------------------------------------------------------------


def test_synthetic_freeze_and_o7_validation_pass_and_bind_the_running_launcher(
    tmp_path: Path,
) -> None:
    built = Admission(tmp_path)
    admission.validate_frozen_inputs(built.inputs)
    admitted = built.validate()
    assert admitted["campaignId"] == campaign.CAMPAIGN
    assert admitted["ledgerRoot"] == str(built.ledger.resolve(strict=False))
    other_launcher = tmp_path / "other.py"
    other_launcher.write_bytes(b"# not the launcher\n")
    with pytest.raises(ValueError, match="binding differs"):
        built.validate(launcher_path=other_launcher)


def test_another_campaigns_approval_and_a_drifted_binding_are_refused(
    tmp_path: Path,
) -> None:
    built = Admission(tmp_path)
    foreign = {**built.approval, "campaignId": "FS-LIMIT-API-REQUEST-BYTES"}
    with pytest.raises(ValueError, match="another campaign"):
        built.validate(approval=foreign)
    drifted = {**built.approval, "inputsDigest": "0" * 64}
    with pytest.raises(ValueError, match="binding differs"):
        built.validate(approval=drifted)
    pending = {**built.approval, "status": "pending-independent-o7-review"}
    with pytest.raises(ValueError, match="not approved"):
        built.validate(approval=pending)
    wrong_profile = {
        **built.approval,
        "artifactProfile": "fs-config-lifecycle-000000000",
    }
    with pytest.raises(ValueError, match="profile differs"):
        built.validate(approval=wrong_profile)
    other_plan = campaign.plan_compiler("f" * 32)
    foreign_inputs = o8_admission.freeze_inputs(
        built.descriptor,
        built.permission,
        other_plan,
        source_commit="0" * 40,
        artifact_sha256="b" * 64,
    )
    with pytest.raises(ValueError, match="binding differs"):
        built.validate(inputs=foreign_inputs)


def test_the_owner_permission_needs_the_frozen_projection_digest_and_real_identities(
    tmp_path: Path,
) -> None:
    built = Admission(tmp_path)
    good = built.permission
    args = (built.plan, "0" * 40, good["artifactSha256"], built.sources)
    no_baseline = {k: v for k, v in good.items() if k != "databaseProjectionDigest"}
    with pytest.raises(ValueError, match="binding differs"):
        admission._approve(no_baseline, *args, BASELINE)
    wrong_baseline = {**good, "databaseProjectionDigest": "0" * 64}
    with pytest.raises(ValueError, match="binding differs"):
        admission._approve(wrong_baseline, *args, BASELINE)
    placeholder = {**good, "ownerIdentity": "agent"}
    with pytest.raises(ValueError, match="ownerIdentity"):
        admission._approve(placeholder, *args, BASELINE)
    short = {**good, "expiresAt": time.time() + 60}
    with pytest.raises(ValueError, match="too short"):
        admission._approve(short, *args, BASELINE)
    no_principal = {k: v for k, v in good.items() if k != "credentialPrincipal"}
    with pytest.raises(ValueError, match="credential principal"):
        admission._approve(no_principal, *args, BASELINE)


def test_the_gate_plan_carries_the_frozen_baseline_and_the_permission_expiry(
    tmp_path: Path,
) -> None:
    built = Admission(tmp_path)
    plan = admission.gate_plan_for(built.inputs, built.permission)
    assert plan["baselineProjectionDigest"] == BASELINE["projectionDigest"]
    assert plan["permissionExpiresAt"] == built.permission["expiresAt"]
    claim = admission.reservation_claim(
        built.inputs, gate_path=tmp_path / "gate", gate_plan=plan
    )
    assert claim["gateJob"] == "configuration"
    assert claim["budget"] == campaign.ledger_budget()
    assert claim["durationSeconds"] == 900
    assert claim["locks"] == campaign.lock_scopes(built.plan)


def test_release_is_blocked_by_the_shared_gate_contract_and_says_so() -> None:
    supported, blocker = admission.release_supported()
    assert supported is False
    assert blocker["reason"] == "shared-gate-document-contract"
    assert "shared_gate.py" in blocker["detail"]


# -- temporary-Ledger integration proof -----------------------------------------


def test_the_proof_path_refuses_a_ledger_that_is_not_marked_as_a_proof(
    tmp_path: Path,
) -> None:
    built = Admission(tmp_path)
    root = tmp_path / "canonical-shaped"
    reservations.Ledger.create(root)
    with pytest.raises(ValueError, match="proof Ledger"):
        lifecycle_production.execute_reserved(
            inputs=built.inputs,
            permission=built.permission,
            ledger_root=root,
            output=tmp_path / "run",
            transmit=FakeAdmin().transmit,
        )
    assert not (tmp_path / "run").exists()
    assert reservations.Ledger(root).snapshot()["reservations"] == {}


def test_all_twelve_cases_run_under_a_held_reservation_with_restore_verified(
    tmp_path: Path,
) -> None:
    built = Admission(tmp_path)
    root = _proof_ledger(tmp_path)
    admin = FakeAdmin(poll_rounds=2)
    result = lifecycle_production.execute_reserved(
        inputs=built.inputs,
        permission=built.permission,
        ledger_root=root,
        output=tmp_path / "run",
        transmit=admin.transmit,
        sleeper=_no_sleep,
    )
    collection = result["collection"]
    assert collection["completed"] is True
    assert collection["restoreVerified"] is True
    assert collection["cleanupComplete"] is True
    assert set(collection["observedCases"]) == {c["id"] for c in compile_cases(NONCE)}
    assert result["restore"]["ttl"]["restore"] == RESTORED
    assert result["restore"]["exemption"]["restore"] == RESTORED
    assert result["disposition"]["disposition"] == admission.RESTORED_DISPOSITION
    assert result["releaseEligible"] is False
    assert result["reservationReleased"] is False
    assert result["releaseBlocked"]["kind"] == admission.RELEASE_BLOCKED_KIND
    assert result["executionKind"] == "injected-transport"
    assert result["productionExecuted"] is False
    # The Ledger row is held under the EXCLUSIVE field locks and never released.
    row = reservations.Ledger(root).snapshot()["reservations"][
        result["ticket"]["reservation"]
    ]
    assert row["state"] == "held"
    assert row["claim"]["locks"] == campaign.lock_scopes(built.plan)
    assert row["generation"]["sourceCommit"] == "0" * 40
    assert result["chargedCalls"] == collection["rowCount"]
    assert result["chargedMicrousd"] == collection["rowCount"]
    # Evidence: inputs, gate snapshot, rows and raw bodies, all private.
    for name in ("inputs.json", "gate-snapshot.json", "receipt.json"):
        assert (tmp_path / "run" / name).is_file()
    receipt = json.loads((tmp_path / "run" / "receipt.json").read_bytes())
    assert receipt["kind"] == campaign.RECEIPT_KIND
    assert receipt["restore"] == result["restore"]
    assert "collection/result.json" in receipt["evidenceFiles"]
    assert NONCE not in json.dumps(receipt)
    # The same nonce cannot be admitted again, and a conflicting field lock is refused.
    with pytest.raises(ValueError, match="already reserved"):
        admission.validate_fresh_admission(root, built.inputs["plan"], built.permission)
    with pytest.raises(ValueError, match="already spent"):
        admission.validate_fresh_admission(
            root, {**built.inputs["plan"], "nonce": "e" * 32}, built.permission
        )
    with pytest.raises(ValueError, match="lock conflict"):
        _reserve_conflicting(root, built)


def _reserve_conflicting(root: Path, built: Admission) -> None:
    """A second campaign asking for the same field key is refused by the Ledger."""
    ledger = reservations.Ledger(root)
    plan = admission.gate_plan_for(built.inputs, built.permission)
    other_plan = {**plan, "nonce": "e" * 32}
    claim = admission.reservation_claim(
        {
            **built.inputs,
            "plan": {**built.inputs["plan"], "nonce": "e" * 32},
            "planDigest": "1" * 64,
        },
        gate_path=root.parent / "other-gate",
        gate_plan=other_plan,
    )
    claim["locks"] = [campaign.lock_scopes(built.plan)[0]]
    permission = {**built.permission, "nonce": "e" * 32}
    ledger.reserve(admission.envelope(permission, claim), claim, other_plan)


def test_a_stop_after_the_ttl_patch_reverts_before_the_release_disposition(
    tmp_path: Path,
) -> None:
    built = Admission(tmp_path)
    root = _proof_ledger(tmp_path)
    admin = FakeAdmin(fail_at={"OC-15": "incomplete"})
    result = lifecycle_production.execute_reserved(
        inputs=built.inputs,
        permission=built.permission,
        ledger_root=root,
        output=tmp_path / "run",
        transmit=admin.transmit,
        sleeper=_no_sleep,
    )
    assert result["collection"]["completed"] is False
    assert result["restore"]["ttl"]["restore"] == RESTORED
    assert result["restore"]["exemption"]["restore"] == NOT_APPLIED
    assert result["disposition"]["disposition"] == admission.RESTORED_DISPOSITION
    assert result["failure"] is None
    assert result["reservationReleased"] is False
    ttl_field = built.plan["lockedSteps"][0]["resource"]
    assert "ttlConfig" not in admin.fields[ttl_field]
    assert [m for _n, m, _b in admin.patches] == ["ttlConfig", "ttlConfig"]


def test_a_refused_revert_holds_the_reservation_with_a_typed_record(
    tmp_path: Path,
) -> None:
    built = Admission(tmp_path)
    root = _proof_ledger(tmp_path)
    admin = FakeAdmin(refuse_revert={"OC-20"})
    result = lifecycle_production.execute_reserved(
        inputs=built.inputs,
        permission=built.permission,
        ledger_root=root,
        output=tmp_path / "run",
        transmit=admin.transmit,
        sleeper=_no_sleep,
    )
    assert result["failure"] == "restore-incomplete"
    assert result["restore"]["ttl"]["restore"] == RESTORED
    assert result["restore"]["exemption"]["restore"] == "revert-refused"
    assert result["disposition"]["disposition"] == admission.UNRECOVERED_DISPOSITION
    assert result["disposition"]["resources"] == [
        built.plan["lockedSteps"][1]["resource"]
    ]
    assert result["collection"]["unrecoveredRecord"]["reservation"] == "held"
    assert result["reservationReleased"] is False
    row = reservations.Ledger(root).snapshot()["reservations"][
        result["ticket"]["reservation"]
    ]
    assert row["state"] == "held"
    # The pre-value the owner restores from is referenced, by digest and file.
    ref = result["collection"]["steps"]["exemption"]["preBodyRef"]
    saved = tmp_path / "run" / "collection" / ref["file"]
    assert hashlib.sha256(saved.read_bytes()).hexdigest() == ref["sha256"]


def test_the_local_unimplemented_exemption_is_a_recorded_deviation_not_hidden(
    tmp_path: Path,
) -> None:
    built = Admission(tmp_path)
    root = _proof_ledger(tmp_path)
    admin = FakeAdmin(refuse_apply={"OC-18"})
    result = lifecycle_production.execute_reserved(
        inputs=built.inputs,
        permission=built.permission,
        ledger_root=root,
        output=tmp_path / "run",
        transmit=admin.transmit,
        sleeper=_no_sleep,
    )
    assert result["restore"]["exemption"]["restore"] == APPLY_REFUSED
    assert result["collection"]["deviations"][0]["case"] == "OC-18"
    assert result["disposition"]["disposition"] == admission.RESTORED_DISPOSITION


# -- launcher -------------------------------------------------------------------


def test_the_credential_handoff_is_bound_to_the_permission_and_never_logged() -> None:
    permission = {"kind": campaign.PERMISSION_KIND}
    good = {
        "kind": lifecycle_o8.HANDOFF_KIND,
        "permissionDigest": digest(permission),
        "token": "tok",
    }
    assert lifecycle_o8.validate_handoff(good, permission) == "tok"
    for bad in (
        {**good, "kind": "request-bytes-bearer-token-v1"},
        {**good, "permissionDigest": "0" * 64},
        {**good, "token": ""},
        {**good, "extra": 1},
    ):
        with pytest.raises(ValueError, match="handoff"):
            lifecycle_o8.validate_handoff(bad, permission)


def test_a_credential_refusal_stops_before_any_wire_with_the_reservation_taken(
    tmp_path: Path,
) -> None:
    built = Admission(tmp_path)
    root = _proof_ledger(tmp_path)
    built.approval["ledgerRoot"] = str(root.resolve())
    binding, binding_digest = campaign.worker_binding()
    capability = admission.issue_production_capability(
        binding=binding,
        binding_digest=binding_digest,
        **built.bindings(ledger_root=root),
    )

    def refuse():
        raise ValueError("handoff refused")

    result = lifecycle_production.execute(
        capability=capability,
        inputs=built.inputs,
        permission=built.permission,
        credential_reader=refuse,
        ledger_root=root,
        output=tmp_path / "run",
    )
    assert result["failure"] == "ValueError"
    assert result["collection"] is None
    assert result["chargedCalls"] == 0
    assert result["productionExecuted"] is False
    assert result["disposition"]["disposition"] == admission.ESCALATION_DISPOSITION
    row = reservations.Ledger(root).snapshot()["reservations"][
        result["ticket"]["reservation"]
    ]
    assert row["state"] == "held"
    assert not o8_admission.issued_capability(capability)
    with pytest.raises(ValueError):
        capability._transmit({})


def test_the_launcher_exit_codes_are_zero_one_two() -> None:
    assert lifecycle_o8.exit_code({"reservationReleased": True, "failure": None}) == 0
    assert lifecycle_o8.exit_code({"reservationReleased": False, "failure": None}) == 1
    assert lifecycle_o8.exit_code({"reservationReleased": True, "failure": "x"}) == 1
    parser = lifecycle_o8.build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["--inputs", "a"])


def test_the_launcher_refuses_admission_with_exit_two_and_sends_nothing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    built = Admission(tmp_path)
    inputs_path = tmp_path / "inputs.json"
    inputs_path.write_text(json.dumps(built.inputs))
    approval_path = tmp_path / "approval.json"
    approval_path.write_text(json.dumps({**built.approval, "status": "pending"}))
    approval_path.chmod(0o600)
    permission_path = tmp_path / "permission.json"
    permission_path.write_text(json.dumps(built.permission))
    credential = tmp_path / "credential.json"
    credential.write_text("{}")
    credential.chmod(0o600)
    code = lifecycle_o8.main(
        [
            "--inputs",
            str(inputs_path),
            "--approval",
            str(approval_path),
            "--manifest",
            str(built.manifest_path),
            "--permission",
            str(permission_path),
            "--source",
            str(ROOT),
            "--artifact",
            str(built.artifact_path),
            "--ledger",
            str(built.ledger),
            "--output",
            str(tmp_path / "run"),
            "--credential-file",
            str(credential),
        ]
    )
    assert code == 2
    assert "refused" in capsys.readouterr().err
    assert not (tmp_path / "run").exists()


def test_receipt_classification_names_the_three_dispositions() -> None:
    restored = {
        "collection": {
            "steps": {"ttl": {"restore": RESTORED}},
            "unrecovered": [],
            "cleanupComplete": True,
        }
    }
    assert (
        admission.classify_stop(restored)["disposition"]
        == admission.RESTORED_DISPOSITION
    )
    unrecovered = {
        "collection": {
            "steps": {"ttl": {"restore": "unverified"}},
            "unrecovered": [{"resource": "r"}],
        }
    }
    assert (
        admission.classify_stop(unrecovered)["disposition"]
        == admission.UNRECOVERED_DISPOSITION
    )
    assert (
        admission.classify_stop({"collection": None})["disposition"]
        == admission.ESCALATION_DISPOSITION
    )
    with pytest.raises(ValueError):
        admission.classify_stop("x")
    assert copy.deepcopy(admission.RELEASE_BLOCKER) == admission.release_supported()[1]
