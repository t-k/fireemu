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


def test_forged_receipt_generation_stays_held_after_rehashed_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    built = Admission(tmp_path)
    root = _proof_ledger(tmp_path)
    receipt_path = tmp_path / "run" / "receipt.json"
    original_attach = reservations.Ledger.attach_evidence

    def forge_receipt_before_attachment(
        self, ticket, receipt_sha256, gate_digest, collection_digest
    ):
        receipt = json.loads(receipt_path.read_bytes())
        receipt["generation"] = {
            **receipt["generation"],
            "sourceCommit": "1" * 40,
        }
        receipt_path.write_text(
            json.dumps(receipt, sort_keys=True, separators=(",", ":"))
        )
        original_attach(
            self,
            ticket,
            hashlib.sha256(receipt_path.read_bytes()).hexdigest(),
            gate_digest,
            collection_digest,
        )

    monkeypatch.setattr(
        reservations.Ledger, "attach_evidence", forge_receipt_before_attachment
    )
    result = lifecycle_production.execute_reserved(
        inputs=built.inputs,
        permission=built.permission,
        ledger_root=root,
        output=tmp_path / "run",
        transmit=FakeAdmin(poll_rounds=2).transmit,
        sleeper=_no_sleep,
    )
    assert result["releaseFailure"] == "ValueError"
    assert result["reservationReleased"] is False
    assert reservations.Ledger(root).snapshot()["reservations"][
        result["ticket"]["reservation"]
    ]["state"] == "held"


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


def test_release_policy_admits_only_the_typed_configuration_finalizer() -> None:
    supported, blocker = admission.release_supported()
    assert supported is True
    assert blocker["kind"] == "configuration-management-finalizer-v1"


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
    assert result["disposition"]["disposition"] == "release-eligible"
    assert result["releaseEligible"] is True
    assert result["reservationReleased"] is True
    assert result["releaseRecord"]["kind"] == "fs-config-lifecycle-release-v1"
    assert result["executionKind"] == "injected-transport"
    assert result["productionExecuted"] is False
    # The Ledger row is released only after the lifecycle Gate proves restoration.
    row = reservations.Ledger(root).snapshot()["reservations"][
        result["ticket"]["reservation"]
    ]
    assert row["state"] == "released"
    assert row["finalGateDigest"] == result["releaseRecord"]["gateDigest"]
    reservations.Ledger(root).finish_management_only(
        result["ticket"], result["releaseRecord"]
    )
    assert reservations.Ledger(root).snapshot()["reservations"][
        result["ticket"]["reservation"]
    ]["state"] == "released"
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
    _reserve_conflicting(root, built)
    assert len(reservations.Ledger(root).snapshot()["reservations"]) == 2


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


def test_release_refusal_keeps_an_unrecovered_configuration_reservation_held(
    tmp_path: Path,
) -> None:
    built = Admission(tmp_path)
    root = _proof_ledger(tmp_path)
    result = lifecycle_production.execute_reserved(
        inputs=built.inputs,
        permission=built.permission,
        ledger_root=root,
        output=tmp_path / "run",
        transmit=FakeAdmin(refuse_revert={"OC-20"}).transmit,
        sleeper=_no_sleep,
    )
    ticket = result["ticket"]
    receipt_path = tmp_path / "run" / "receipt.json"
    record = {
        "kind": "fs-config-lifecycle-release-v1",
        "ticket": ticket,
        "receiptPath": str(receipt_path.resolve()),
        "receiptDigest": hashlib.sha256(receipt_path.read_bytes()).hexdigest(),
        "gateDigest": result["gateDigest"],
        "collectionDigest": digest(result["collection"]),
        "generation": result["generation"],
    }
    with pytest.raises(ValueError, match="release evidence"):
        reservations.Ledger(root).finish_management_only(ticket, record)
    assert reservations.Ledger(root).snapshot()["reservations"][
        ticket["reservation"]
    ]["state"] == "held"


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
    assert admission.release_supported()[1]["kind"] == "configuration-management-finalizer-v1"


# -- credential preflight (review Must Fix 3) ------------------------------------


def _tokeninfo(body: dict | None, status: int = 200):
    def exchange(token, *, deadline):
        assert token == "tok"
        assert deadline > time.monotonic()
        return {
            "complete": body is not None,
            "workerReaped": True,
            "status": status,
            "body": body,
        }

    return exchange


GOOD_TOKENINFO = {
    "issued_to": "client",
    "audience": "client",
    "user_id": "subject",
    "scope": "https://www.googleapis.com/auth/cloud-platform openid",
    "expires_in": 3599,
}
PRINCIPAL = {
    "clientId": "client",
    "subject": "subject",
    "requiredScopes": [campaign.PRINCIPAL_SCOPE],
}


def test_the_attestation_verifies_principal_scope_and_lifetime_and_keeps_no_body() -> (
    None
):
    from fs_config_lifecycle import lifecycle_preflight as preflight

    assert preflight.required_seconds() == 1260
    run = preflight.credential_preflight(
        "tok", PRINCIPAL, tokeninfo=_tokeninfo(GOOD_TOKENINFO)
    )
    receipt = run(time.monotonic() + 30)
    assert receipt["complete"] is True and receipt["failure"] is None
    body = receipt["body"]
    assert body["verified"] is True
    assert body["requiredSeconds"] == 1260
    assert body["remainingSecondsAtVerification"] >= 1260
    assert "user_id" not in json.dumps(body) and "tok" not in json.dumps(body)
    for bad, reason in (
        ({**GOOD_TOKENINFO, "user_id": "someone-else"}, "identity"),
        ({**GOOD_TOKENINFO, "issued_to": "other", "audience": "other"}, "identity"),
        ({**GOOD_TOKENINFO, "scope": "openid email"}, "identity"),
        ({**GOOD_TOKENINFO, "expires_in": 1200}, "lifetime"),
        (None, "attestation"),
    ):
        refused = preflight.credential_preflight(
            "tok", PRINCIPAL, tokeninfo=_tokeninfo(bad)
        )(time.monotonic() + 30)
        assert refused["complete"] is False
        assert refused["failure"] == "credential-preflight"
        assert refused["body"]["verified"] is False
        assert reason in refused["body"]["reason"], (bad, refused["body"]["reason"])


def _capability_run(tmp_path: Path, tokeninfo):
    built = Admission(tmp_path)
    root = _proof_ledger(tmp_path)
    built.approval["ledgerRoot"] = str(root.resolve())
    binding, binding_digest = campaign.worker_binding()
    capability = admission.issue_production_capability(
        binding=binding,
        binding_digest=binding_digest,
        **built.bindings(ledger_root=root),
    )
    result = lifecycle_production.execute_reserved(
        inputs=built.inputs,
        permission=built.permission,
        ledger_root=root,
        output=tmp_path / "run",
        transmit=None,
        capability=capability,
        credential_reader=lambda: "tok",
        tokeninfo=tokeninfo,
    )
    return built, root, result


def test_a_foreign_principal_or_short_lived_token_stops_before_oc_01(
    tmp_path: Path,
) -> None:
    for bad in (
        {**GOOD_TOKENINFO, "user_id": "someone-else"},
        {**GOOD_TOKENINFO, "expires_in": 600},
    ):
        run_dir = tmp_path / digest(bad)[:8]
        run_dir.mkdir()
        _built, root, result = _capability_run(run_dir, _tokeninfo(bad))
        collection = result["collection"]
        assert collection["stopPoint"] == "credential-preflight"
        assert collection["mutationAttempted"] is False
        assert collection["rowCount"] == 1
        assert collection["rows"][0]["case"] == "PRE-01"
        assert collection["rows"][0]["role"] == "preflight"
        assert collection["credentialPreflight"]["complete"] is False
        assert not any(row["case"].startswith("OC-") for row in collection["rows"])
        assert result["disposition"]["disposition"] == admission.NO_MUTATION_DISPOSITION
        row = reservations.Ledger(root).snapshot()["reservations"][
            result["ticket"]["reservation"]
        ]
        assert row["state"] == "held"
        receipt = json.loads((run_dir / "run" / "receipt.json").read_bytes())
        assert "user_id" not in json.dumps(receipt)


def test_an_injected_tokeninfo_exchange_is_refused_against_a_ledger_without_the_proof_marker(
    tmp_path: Path,
) -> None:
    built = Admission(tmp_path)
    root = tmp_path / "canonical-shaped"
    reservations.Ledger.create(root)
    built.approval["ledgerRoot"] = str(root.resolve())
    binding, binding_digest = campaign.worker_binding()
    capability = admission.issue_production_capability(
        binding=binding,
        binding_digest=binding_digest,
        **built.bindings(ledger_root=root),
    )
    try:
        with pytest.raises(ValueError, match="proof Ledger"):
            lifecycle_production.execute_reserved(
                inputs=built.inputs,
                permission=built.permission,
                ledger_root=root,
                output=tmp_path / "run",
                transmit=None,
                capability=capability,
                credential_reader=lambda: "tok",
                tokeninfo=_tokeninfo(GOOD_TOKENINFO),
            )
    finally:
        o8_admission.revoke_production_capability(capability)
    assert not (tmp_path / "run").exists()


# -- verified acquisition (owner review d7f7ce184 finding 2) ---------------------


def _proof_run(tmp_path: Path, **admin) -> tuple[Admission, Path, dict]:
    tmp_path.mkdir(exist_ok=True)
    built = Admission(tmp_path)
    root = _proof_ledger(tmp_path)
    result = lifecycle_production.execute_reserved(
        inputs=built.inputs,
        permission=built.permission,
        ledger_root=root,
        output=tmp_path / "run",
        transmit=FakeAdmin(**admin).transmit,
        sleeper=_no_sleep,
    )
    return built, root, result


def _rewrite(path: Path, value: dict) -> None:
    path.unlink()
    lifecycle_production._write_receipt(path, value)


def _as_production_receipt(run: Path) -> None:
    """Rewrite a proof run's receipt as the production path would have written it.

    Synthetic: no production run happened. The Ledger row, the ticket, the gate
    snapshot and the evidence files are the proof run's own; only the fields the
    capability path sets differently (execution kind, worker digest, preflight row,
    productionExecuted) are rewritten, and the evidence digests are recomputed the
    way execute_reserved computes them. This is the positive control for
    verify_saved's binding checks; every tamper test below starts from it.
    """
    receipt = json.loads((run / "receipt.json").read_bytes())
    collection = json.loads((run / "collection" / "result.json").read_bytes())
    collection["credentialPreflight"] = {
        "status": 200,
        "complete": True,
        "attestationDigest": "a" * 64,
    }
    (run / "collection" / "result.json").write_bytes(
        json.dumps(collection, sort_keys=True, indent=1).encode()
    )
    receipt["collection"] = collection
    receipt["executionKind"] = "fixed-production-wire"
    receipt["productionExecuted"] = True
    receipt["workerSha256"] = lifecycle_remote_transport._WORKER_SHA256
    receipt["evidenceFiles"] = {
        name: hashlib.sha256((run / name).read_bytes()).hexdigest()
        for name in receipt["evidenceFiles"]
    }
    _rewrite(run / "receipt.json", receipt)


def _receipt(run: Path) -> dict:
    return json.loads((run / "receipt.json").read_bytes())


def test_a_proof_run_with_an_injected_transport_is_never_a_verified_acquisition(
    tmp_path: Path,
) -> None:
    _built, root, result = _proof_run(tmp_path)
    assert result["executionKind"] == "injected-transport"
    with pytest.raises(ValueError, match="not a production acquisition"):
        lifecycle_production.verify_saved(
            tmp_path / "run", ledger_root=root, synthetic=True
        )


def test_a_proof_ledger_anchor_requires_the_explicit_synthetic_flag_and_says_so(
    tmp_path: Path,
) -> None:
    """Reviewer Should Fix 2, both directions: a proof Ledger is refused as the
    anchor without synthetic=True, a Ledger without the proof marker refuses
    synthetic=True, and a synthetic anchor is carried on the object."""
    _built, root, _result = _proof_run(tmp_path)
    run = tmp_path / "run"
    _as_production_receipt(run)
    with pytest.raises(ValueError, match="proof Ledger anchors require synthetic"):
        lifecycle_production.verify_saved(run, ledger_root=root)
    with pytest.raises(ValueError, match="proof Ledger anchors require synthetic"):
        lifecycle_production.verify_saved(run, ledger_root=root, synthetic=False)
    with pytest.raises(ValueError, match="explicit boolean"):
        lifecycle_production.verify_saved(run, ledger_root=root, synthetic=1)
    canonical_shaped = tmp_path / "canonical-shaped"
    reservations.Ledger.create(canonical_shaped)
    with pytest.raises(ValueError, match="canonical Ledger refuses"):
        lifecycle_production.verify_saved(
            run, ledger_root=canonical_shaped, synthetic=True
        )
    _record, acquisition = lifecycle_production.verify_saved(
        run, ledger_root=root, synthetic=True
    )
    assert acquisition.synthetic is True
    assert acquisition.summary()["synthetic"] is True
    assert lifecycle_production.verified(acquisition) is True


def test_verify_saved_binds_the_receipt_directory_to_its_ledger_row(
    tmp_path: Path,
) -> None:
    """Positive control on a synthetic production receipt (see _as_production_receipt)."""
    from fs_config_lifecycle.comparator import PRODUCTION_KIND, VerifiedAcquisition
    from fs_config_lifecycle.surface_matrix import digest as canonical

    built, root, _result = _proof_run(tmp_path, poll_rounds=2)
    run = tmp_path / "run"
    _as_production_receipt(run)
    record, acquisition = lifecycle_production.verify_saved(
        run, ledger_root=root, synthetic=True
    )
    receipt = _receipt(run)
    assert type(acquisition) is VerifiedAcquisition
    assert lifecycle_production.verified(acquisition) is True
    assert acquisition.synthetic is True
    assert record == {
        "executionKind": PRODUCTION_KIND,
        "collection": receipt["collection"],
    }
    assert acquisition.campaign_id == campaign.CAMPAIGN
    assert acquisition.execution_kind == PRODUCTION_KIND
    assert acquisition.endpoint == lifecycle_remote_transport.ORIGIN
    assert acquisition.reservation == receipt["ticket"]["reservation"]
    assert acquisition.ledger_identity == receipt["ticket"]["ledgerIdentity"]
    assert (
        acquisition.receipt_digest
        == hashlib.sha256((run / "receipt.json").read_bytes()).hexdigest()
    )
    assert acquisition.gate_digest == receipt["gateDigest"]
    assert acquisition.artifact_sha256 == built.inputs["artifactSha256"]
    assert acquisition.worker_sha256 == lifecycle_remote_transport._WORKER_SHA256
    assert acquisition.collection_digest == canonical(receipt["collection"])
    assert NONCE not in json.dumps(acquisition.summary())


def test_verify_saved_refuses_every_broken_binding(tmp_path: Path) -> None:
    import os
    import shutil

    def tampered(name: str, mutate) -> tuple[Path, Path]:
        # Each tamper starts from its own proof run, so the receipt directory is
        # still the one the Ledger claim names and only the named binding breaks.
        _built, root, _result = _proof_run(tmp_path / name, poll_rounds=2)
        run = tmp_path / name / "run"
        _as_production_receipt(run)
        lifecycle_production.verify_saved(run, ledger_root=root, synthetic=True)
        mutate(run)
        return run, root

    def edit_receipt(**fields):
        def mutate(directory: Path) -> None:
            _rewrite(directory / "receipt.json", {**_receipt(directory), **fields})

        return mutate

    def edit_result(directory: Path) -> None:
        # The evidence file no longer hashes to what the receipt names.
        path = directory / "collection" / "result.json"
        value = json.loads(path.read_bytes())
        value["rows"][0]["status"] = 418
        path.write_bytes(json.dumps(value, sort_keys=True, indent=1).encode())

    def edit_collection_in_receipt(directory: Path) -> None:
        # The receipt's collection no longer equals result.json, digests intact.
        receipt = _receipt(directory)
        receipt["collection"]["rows"][0]["status"] = 418
        _rewrite(directory / "receipt.json", receipt)

    def edit_snapshot(directory: Path) -> None:
        path = directory / "gate-snapshot.json"
        value = json.loads(path.read_bytes())
        value["total"] += 1
        path.write_bytes(json.dumps(value, sort_keys=True).encode())
        receipt = _receipt(directory)
        receipt["evidenceFiles"]["gate-snapshot.json"] = hashlib.sha256(
            path.read_bytes()
        ).hexdigest()
        _rewrite(directory / "receipt.json", receipt)

    def symlink_receipt(directory: Path) -> None:
        real = directory / "receipt.json"
        real.rename(directory / "receipt.real.json")
        os.symlink(directory / "receipt.real.json", real)

    def drop_preflight(directory: Path) -> None:
        receipt = _receipt(directory)
        receipt["collection"]["credentialPreflight"] = None
        path = directory / "collection" / "result.json"
        path.write_bytes(
            json.dumps(receipt["collection"], sort_keys=True, indent=1).encode()
        )
        receipt["evidenceFiles"]["collection/result.json"] = hashlib.sha256(
            path.read_bytes()
        ).hexdigest()
        _rewrite(directory / "receipt.json", receipt)

    cases = [
        ("kind", edit_receipt(kind="other-receipt-v1"), "acquisition receipt"),
        ("campaign", edit_receipt(campaignId="OTHER-01"), "acquisition receipt"),
        (
            "not-executed",
            edit_receipt(productionExecuted=False),
            "not a production acquisition",
        ),
        (
            "worker",
            edit_receipt(workerSha256="0" * 64),
            "reviewed worker",
        ),
        ("evidence", edit_result, "evidence digest"),
        ("collection", edit_collection_in_receipt, "collection differs"),
        ("gate", edit_snapshot, "gate digest"),
        ("inputs", edit_receipt(inputsDigest="0" * 64), "frozen inputs"),
        ("claim", edit_receipt(claimDigest="0" * 64), "reservation"),
        ("symlink", symlink_receipt, "regular"),
        ("preflight", drop_preflight, "credential preflight"),
    ]
    for name, mutate, reason in cases:
        directory, root = tampered(name, mutate)
        with pytest.raises(ValueError, match=reason):
            lifecycle_production.verify_saved(
                directory, ledger_root=root, synthetic=True
            )
    # The right receipt against a Ledger that never held its reservation.
    intact, _root = tampered("intact", lambda _directory: None)
    (tmp_path / "other").mkdir()
    other_root = _proof_ledger(tmp_path / "other")
    with pytest.raises(ValueError, match="reservation"):
        lifecycle_production.verify_saved(
            intact, ledger_root=other_root, synthetic=True
        )
    # A receipt directory copied elsewhere no longer sits at the gate path the
    # Ledger claim names.
    good, root = tampered("good", lambda _directory: None)
    moved = tmp_path / "moved"
    shutil.copytree(good, moved, symlinks=True)
    with pytest.raises(ValueError, match="gate path"):
        lifecycle_production.verify_saved(moved, ledger_root=root, synthetic=True)


def test_the_verified_acquisition_yields_the_semantic_result_and_a_relabelled_copy_does_not(
    tmp_path: Path,
) -> None:
    """End to end: verify_saved's object is what makes compare() a production comparison."""
    from fs_config_lifecycle.comparator import LOCAL_KIND, MATCH, REFUSED, compare
    from fs_config_lifecycle.manifest import compile_manifest
    from fs_config_lifecycle.test_fs_config_comparator import _collection

    # Default FakeAdmin on both sides: a second poll round would change the shape of
    # the first operation row and this test is about the acquisition, not a mismatch.
    _built, root, _result = _proof_run(tmp_path)
    run = tmp_path / "run"
    _as_production_receipt(run)
    record, acquisition = lifecycle_production.verify_saved(
        run, ledger_root=root, synthetic=True
    )
    local = {"executionKind": LOCAL_KIND, "collection": _collection(tmp_path, "local")}
    manifest = compile_manifest(NONCE)
    verified = compare(manifest, local, record, NONCE, acquisition=acquisition)
    assert verified["classification"] == MATCH
    # The anchor is a proof Ledger, so the semantic rows are there but the run
    # is marked synthetic and never a validated production acquisition.
    assert verified["syntheticAnchor"] is True
    assert verified["acquisitionValidated"] is False
    assert verified["acquisition"] == acquisition.summary()
    assert verified["acquisition"]["synthetic"] is True
    assert verified["promotionReady"] is False
    # The same collection bytes, handed over without the boundary's object.
    relabelled = compare(manifest, local, copy.deepcopy(record), NONCE)
    assert relabelled["classification"] == REFUSED
    assert relabelled["acquisitionValidated"] is False
    # The local collection itself, relabelled as the production side.
    forged = compare(
        manifest,
        local,
        {"executionKind": "fixed-production-wire", "collection": local["collection"]},
        NONCE,
        acquisition=acquisition,
    )
    assert forged["classification"] == REFUSED
    assert forged["errors"] == ["production-acquisition-binding"]
