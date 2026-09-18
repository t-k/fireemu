"""O8 admission tests for the request-byte boundary campaign.

Every artifact here is built locally. No production request is made, no
credential is read, no origin outside the process is contacted, and the shared
Ledger is only ever a temporary copy.
"""

import hashlib
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "tools/compat-broad"))
sys.path.insert(0, str(ROOT / "tools/compat-broad/production-admission"))
sys.path.insert(0, str(ROOT / "tools/compat-broad/o8-core"))
sys.path.insert(0, str(HERE))

import request_bytes_admission as admission
import request_bytes_descriptor as campaign
import request_bytes_o8
import request_bytes_remote_transport
from broad_contract import digest
from o8_campaign import BASE_APPROVAL_FIELDS, CampaignDescriptor

NONCE = "b" * 32
CAMPAIGN_ID = "FS-LIMIT-API-REQUEST-BYTES"


def test_the_descriptor_is_complete_and_published_budget_bound():
    descriptor = campaign.descriptor()
    assert descriptor.campaign_id == CAMPAIGN_ID
    assert descriptor.approval_fields == BASE_APPROVAL_FIELDS
    assert len(descriptor.approval_fields) == 16
    assert descriptor.binds_campaign_id is False
    assert descriptor.budget == {
        "requests": 258,
        "accounts": 1,
        "resources": 51,
        "costMicrousd": 190,
    }
    assert (descriptor.campaign_seconds, descriptor.recovery_seconds) == (900, 300)
    assert descriptor.window_seconds == 1200


def test_the_transport_deadline_is_the_published_one_and_the_enforced_one():
    assert campaign.transport_deadline_seconds() == 60.0
    assert request_bytes_remote_transport.TIMEOUT == 60.0
    published = campaign.budget_document()
    assert published["transportDeadline"]["perRequestSeconds"] == 60.0
    assert published["budget"]["perRequestTimeoutSeconds"] == 60.0


def test_the_lock_scopes_cover_the_nonce_unique_owned_namespace():
    descriptor = campaign.descriptor()
    plan = descriptor.plan_compiler(NONCE)
    locks = descriptor.lock_scopes(plan)
    write = [lock for lock in locks if lock["mode"] == "WRITE"]
    assert len(write) == 1
    assert NONCE in write[0]["key"]
    assert write[0]["key"].endswith("/request-bytes-01/*")
    assert plan["ownedResourceCount"] == 51
    assert f"/oracle/{NONCE}/request-bytes-01" in plan["ownedScope"]
    assert {lock["mode"] for lock in locks} == {"WRITE", "READ"}


def test_the_source_map_names_the_collector_comparator_and_worker():
    sources = campaign.source_map()
    for entry in (
        campaign.COLLECTOR_ENTRY,
        campaign.COMPARATOR_ENTRY,
        campaign.WORKER_ENTRY,
    ):
        assert sources[entry] == hashlib.sha256((ROOT / entry).read_bytes()).hexdigest()
    assert not any(Path(name).name.startswith("test_") for name in sources)
    assert sources[campaign.WORKER_ENTRY] == (
        request_bytes_remote_transport._WORKER_SHA256
    )


def frozen_checkout(tmp_path):
    """A clean git checkout carrying byte-identical copies of the frozen sources."""
    source = tmp_path / "checkout"
    for name in campaign.source_map():
        target = source / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, target)
    for args in (
        ["init", "-q"],
        ["add", "-A"],
        [
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit",
            "-qm",
            "fixture",
        ],
    ):
        subprocess.run(["git", "-C", str(source), *args], check=True)
    return source


def owner_permission(plan, commit, artifact_digest, inputs):
    return {
        **campaign.permission_bindings(plan, commit, artifact_digest, inputs),
        "ownerIdentity": "offline-fixture-not-permission",
        "permissionReference": "offline-fixture",
        "recoveryOwner": "offline-recovery",
        "issuedAt": time.time() - 1,
        "expiresAt": time.time() + 4800,
    }


class Admission:
    """A complete, locally built O7 artifact set for the request-byte campaign."""

    def __init__(self, tmp_path):
        self.descriptor = campaign.descriptor()
        self.source = frozen_checkout(tmp_path)
        self.commit = subprocess.check_output(
            ["git", "-C", str(self.source), "rev-parse", "HEAD"], text=True
        ).strip()
        self.artifact_path = tmp_path / "artifact"
        self.artifact_path.write_bytes(b"retained request-byte artifact")
        self.plan = self.descriptor.plan_compiler(NONCE)
        self.execution_plan = campaign.execution_plan(self.plan)
        self.permission = owner_permission(
            self.plan,
            self.commit,
            hashlib.sha256(self.artifact_path.read_bytes()).hexdigest(),
            campaign.source_map(),
        )
        self.permission_path = tmp_path / "permission.json"
        self.permission_path.write_text(json.dumps(self.permission))
        self.inputs = admission.freeze_inputs(
            self.permission_path,
            self.plan,
            source_root=self.source,
            artifact_path=self.artifact_path,
        )
        self.ledger = tmp_path / "ledger"
        self.ledger.mkdir()
        (self.ledger / "state.json").write_text(
            json.dumps({"kind": "shared-ledger", "envelopes": {}, "reservations": {}})
        )
        self.manifest = {
            "kind": campaign.MANIFEST_KIND,
            "inputsDigest": self.inputs["inputsDigest"],
        }
        self.manifest_bytes = json.dumps(self.manifest).encode()
        self.manifest_path = tmp_path / "manifest.json"
        self.manifest_path.write_bytes(self.manifest_bytes)
        self.manifest_path.chmod(0o600)
        self.launcher_path = HERE / "request_bytes_o8.py"
        self.approval = self._approval()
        self.approval_path = tmp_path / "approval.json"
        self.approval_path.write_text(json.dumps(self.approval))
        self.approval_path.chmod(0o600)
        self.handoff_path = tmp_path / "handoff.json"
        self.handoff_path.write_text(
            json.dumps(
                {
                    "kind": request_bytes_o8.HANDOFF_KIND,
                    "permissionDigest": digest(self.permission),
                    "token": "offline-fixture-token",
                }
            )
        )
        self.handoff_path.chmod(0o600)

    def _approval(self):
        now = time.time()
        return {
            "kind": campaign.APPROVAL_KIND,
            "status": "approved",
            "manifestSha256": hashlib.sha256(self.manifest_bytes).hexdigest(),
            "inputsDigest": self.inputs["inputsDigest"],
            "permissionDigest": self.inputs["permissionDigest"],
            "sourceCommit": self.inputs["sourceCommit"],
            "sourceInputsDigest": digest(self.inputs["sourceInputs"]),
            "artifactSha256": self.inputs["artifactSha256"],
            "planDigest": self.inputs["planDigest"],
            "nonceDigest": digest(self.plan["nonce"]),
            "ledgerRoot": str(self.ledger.resolve(strict=False)),
            "launcherSha256": hashlib.sha256(
                self.launcher_path.read_bytes()
            ).hexdigest(),
            "artifactProfile": campaign.ARTIFACT_PROFILE,
            "windowStartsAt": now - 1,
            "windowExpiresAt": now + 4 * self.descriptor.window_seconds,
            "executionHost": admission.execution_host(),
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

    def argv(self, tmp_path):
        inputs_path = tmp_path / "inputs.json"
        inputs_path.write_text(json.dumps(self.inputs))
        return [
            "--inputs",
            str(inputs_path),
            "--approval",
            str(self.approval_path),
            "--manifest",
            str(self.manifest_path),
            "--permission",
            str(self.permission_path),
            "--source",
            str(self.source),
            "--artifact",
            str(self.artifact_path),
            "--ledger",
            str(self.ledger),
            "--output",
            str(tmp_path / "output"),
            "--credential-file",
            str(self.handoff_path),
        ]


def test_frozen_inputs_bind_the_plan_permission_and_source_snapshot(tmp_path):
    built = Admission(tmp_path)
    inputs = built.inputs
    assert inputs["kind"] == campaign.FROZEN_INPUTS_KIND
    assert inputs["plan"]["campaignId"] == CAMPAIGN_ID
    assert inputs["bounds"]["totalRequests"] == 258
    assert inputs["bounds"]["perRequestTimeoutSeconds"] == 60.0
    assert inputs["sourceCommit"] == built.commit
    admission.validate_frozen_inputs(inputs)
    generation = admission.abort_generation(inputs)
    assert set(generation["sourceDigests"]) == {
        "shared_gate.py",
        "reservations.py",
        "o8_admission.py",
        "request_bytes_admission.py",
        "request_bytes_descriptor.py",
    }


@pytest.mark.parametrize(
    "damage",
    [
        {"ownerIdentity": "agent"},
        {"ownerIdentity": ""},
        {"recoveryOwner": "<<fill me in>>"},
        {"permissionReference": "  "},
        {"wallSeconds": 1200},
        {"perRequestTimeoutSeconds": 12.0},
        {"ownedResourceCount": 50},
        {"planDigest": "0" * 64},
    ],
    ids=[
        "placeholder-owner",
        "empty-owner",
        "placeholder-recovery",
        "blank-reference",
        "wrong-wall",
        "wrong-deadline",
        "wrong-resource-count",
        "wrong-plan-digest",
    ],
)
def test_a_permission_that_does_not_bind_the_campaign_is_refused(tmp_path, damage):
    built = Admission(tmp_path)
    built.permission_path.write_text(json.dumps({**built.permission, **damage}))
    with pytest.raises(ValueError):
        admission.freeze_inputs(
            built.permission_path,
            built.plan,
            source_root=built.source,
            artifact_path=built.artifact_path,
        )


def test_the_frozen_plan_is_a_reference_that_recompiles_to_one_plan():
    """The compiled plan is 63 MB of request bodies; a record binds its digest."""
    reference = campaign.plan_compiler(NONCE)
    assert len(json.dumps(reference)) < 4096
    assert set(reference) == {
        "schemaVersion",
        "campaignId",
        "catalogId",
        "project",
        "database",
        "nonce",
        "planDigest",
        "ownedScope",
        "ownedResourceCount",
        "bounds",
    }
    plan = campaign.execution_plan(reference)
    assert len(plan["executionSchedule"]) == 258
    assert plan["nonce"] == NONCE
    for damaged in (
        {},
        {**reference, "planDigest": "0" * 64},
        {**reference, "ownedResourceCount": 50},
        {**reference, "nonce": "c" * 32},
    ):
        with pytest.raises(ValueError, match="plan reference"):
            campaign.execution_plan(damaged)


def test_bind_execute_refuses_the_reference_instead_of_the_compiled_plan(tmp_path):
    built = Admission(tmp_path)
    capability = consumed(built)
    with pytest.raises(ValueError, match="compiled plan"):
        admission.bind_execute(capability, built.plan, "offline-token")


def test_a_complete_o7_binding_is_admitted(tmp_path):
    built = Admission(tmp_path)
    admitted = admission.validate_o7_admission(**built.bindings())
    assert admitted["campaignId"] == CAMPAIGN_ID
    assert admitted["ledgerRoot"] == str(built.ledger.resolve(strict=False))


@pytest.mark.parametrize(
    "override",
    [
        {"status": "pending"},
        {"kind": "commit-o8-approval-v1"},
        {"inputsDigest": "0" * 64},
        {"planDigest": "0" * 64},
        {"nonceDigest": "0" * 64},
        {"sourceInputsDigest": "0" * 64},
        {"launcherSha256": "0" * 64},
        {"artifactProfile": "repaired-567565bdd"},
        {"ledgerRoot": "/nonexistent/private/ledger"},
        {"windowStartsAt": time.time() + 600},
        {"windowExpiresAt": time.time() + 10},
        {"executionHost": {"platform": "other", "machine": "other"}},
    ],
)
def test_an_incomplete_o7_binding_is_refused(tmp_path, override):
    built = Admission(tmp_path)
    with pytest.raises(ValueError):
        admission.validate_o7_admission(
            **built.bindings(approval={**built.approval, **override})
        )


def test_the_window_must_hold_the_campaign_and_its_recovery(tmp_path):
    built = Admission(tmp_path)
    now = time.time()
    for margin in (built.descriptor.campaign_seconds, 1199):
        with pytest.raises(ValueError, match="window expired"):
            admission.validate_o7_admission(
                **built.bindings(
                    approval={
                        **built.approval,
                        "windowStartsAt": now - 1,
                        "windowExpiresAt": now - 1 + margin,
                    }
                )
            )


def test_another_campaigns_descriptor_cannot_admit_this_approval(tmp_path):
    built = Admission(tmp_path)
    other = CampaignDescriptor(
        **{**built.descriptor.members(), "campaign_id": "FS-DATA-WRITE-COMMIT-03"}
    )
    with pytest.raises(ValueError, match="another campaign"):
        admission.o8_admission.validate_o7_admission(other, **built.bindings())


def issued(built):
    binding, binding_digest = campaign.worker_binding()
    return admission.issue_production_capability(
        **built.bindings(), binding=binding, binding_digest=binding_digest
    )


def test_a_capability_is_issued_against_the_reviewed_worker_source(tmp_path):
    built = Admission(tmp_path)
    capability = issued(built)
    try:
        assert capability.campaign_id == CAMPAIGN_ID
        assert capability.binding_digest == (
            request_bytes_remote_transport._WORKER_SHA256
        )
        assert capability.window_seconds == 1200
    finally:
        admission.revoke_production_capability(capability)


@pytest.mark.parametrize(
    "binding",
    [b"not the reviewed worker", b"", "not bytes", None],
    ids=["other-bytes", "empty", "not-bytes", "missing"],
)
def test_a_capability_is_refused_for_worker_bytes_that_are_not_reviewed(
    tmp_path, binding
):
    built = Admission(tmp_path)
    source, pinned = campaign.worker_binding()
    binding_digest = (
        hashlib.sha256(binding).hexdigest() if isinstance(binding, bytes) else pinned
    )
    assert binding != source
    with pytest.raises(ValueError, match="worker source"):
        admission.issue_production_capability(
            **built.bindings(), binding=binding, binding_digest=binding_digest
        )


def test_the_bound_transport_refuses_anything_but_one_closed_slot_call():
    source, pinned = campaign.worker_binding()
    for value in ({}, {"plan": {}}, "not a dict", {"plan": 1, "phase": 2, "index": 3}):
        with pytest.raises(ValueError, match="closed request-byte wire call"):
            campaign.transport_bound(value, binding=source, binding_digest=pinned)


def test_the_bound_transport_refuses_a_binding_that_is_not_the_reviewed_worker():
    call = {
        "plan": {},
        "phase": "observation",
        "index": 0,
        "operation": {},
        "token": "t",
    }
    with pytest.raises(ValueError, match="worker source"):
        campaign.transport_bound(
            call, binding=b"other", binding_digest=hashlib.sha256(b"other").hexdigest()
        )


def consumed(built):
    capability = issued(built)
    capability._consume(
        campaign_id=CAMPAIGN_ID,
        inputs_digest=built.inputs["inputsDigest"],
        ledger_root=built.ledger,
    )
    return capability


def test_the_collector_callable_walks_the_frozen_schedule_in_order(tmp_path):
    built = Admission(tmp_path)
    capability = consumed(built)
    sent = []
    object.__setattr__(
        capability,
        "_transport_bound",
        lambda value, **_: (sent.append(value), {"status": 200})[1],
    )
    execute = admission.bind_execute(capability, built.execution_plan, "offline-token")
    schedule = built.execution_plan["executionSchedule"]
    for expected in schedule[:4]:
        assert execute({"slot": expected["index"]}) == {"status": 200}
    assert [(item["phase"], item["index"]) for item in sent] == [
        (item["phase"], item["index"]) for item in schedule[:4]
    ]
    assert sent[0]["token"] == "offline-token"
    assert sent[0]["plan"]["campaignId"] == CAMPAIGN_ID


def test_the_collector_callable_cannot_outrun_the_schedule(tmp_path):
    built = Admission(tmp_path)
    capability = consumed(built)
    object.__setattr__(
        capability, "_transport_bound", lambda value, **_: {"status": 200}
    )
    execute = admission.bind_execute(
        capability,
        built.plan,
        "offline-token",
        schedule=[{"phase": "observation", "index": 0}],
    )
    assert execute({}) == {"status": 200}
    with pytest.raises(ValueError, match="schedule exhausted"):
        execute({})


def test_a_reused_nonce_or_a_respent_permission_is_refused(tmp_path):
    built = Admission(tmp_path)
    state = {
        "kind": "shared-ledger",
        "envelopes": {},
        "reservations": {
            "row": {"claim": {"nonceDigest": digest(built.plan["nonce"]), "locks": []}}
        },
    }
    (built.ledger / "state.json").write_text(json.dumps(state))
    with pytest.raises(ValueError, match="nonce already reserved"):
        admission.validate_fresh_admission(built.ledger, built.plan, built.permission)

    state["reservations"] = {}
    state["envelopes"] = {
        "e": {"envelope": {"permissionDigest": digest(built.permission)}}
    }
    (built.ledger / "state.json").write_text(json.dumps(state))
    with pytest.raises(ValueError, match="permission already spent"):
        admission.validate_fresh_admission(built.ledger, built.plan, built.permission)

    state["envelopes"] = {}
    (built.ledger / "state.json").write_text(json.dumps(state))
    fresh = admission.validate_fresh_admission(
        built.ledger, built.plan, built.permission
    )
    assert fresh["nonceDigest"] == digest(built.plan["nonce"])


def test_a_lock_key_carrying_the_nonce_also_counts_as_reuse(tmp_path):
    built = Admission(tmp_path)
    locks = built.descriptor.lock_scopes(built.plan)
    (built.ledger / "state.json").write_text(
        json.dumps(
            {
                "kind": "shared-ledger",
                "envelopes": {},
                "reservations": {"row": {"claim": {"locks": locks}}},
            }
        )
    )
    with pytest.raises(ValueError, match="nonce already reserved"):
        admission.validate_fresh_admission(built.ledger, built.plan, built.permission)


def test_the_reservation_claim_is_settled_except_for_its_gate(tmp_path):
    built = Admission(tmp_path)
    with pytest.raises(ValueError, match="reservation is unavailable"):
        admission.reservation_claim(built.inputs)
    claim = admission.reservation_claim(built.inputs, gate_path=tmp_path / "gate")
    assert claim["campaignId"] == CAMPAIGN_ID
    assert claim["budget"] == built.descriptor.budget
    assert claim["nonceDigest"] == digest(built.plan["nonce"])
    assert claim["durationSeconds"] == 900
    assert any(lock["mode"] == "WRITE" for lock in claim["locks"])


def test_the_receipt_binds_every_route_it_observed(tmp_path):
    built = Admission(tmp_path)
    capability = issued(built)
    try:
        rows = [
            {
                "phase": "observation",
                "index": index,
                "route": f"/v1/{built.plan['ownedScope']}/probe-u01/items/p{index}",
                "status": 200,
                "responseDigest": digest({"index": index}),
            }
            for index in range(3)
        ]
        receipt = admission.build_receipt(
            built.inputs,
            {"completed": True},
            capability=capability,
            rows=rows,
            generation=admission.abort_generation(built.inputs),
        )
        assert receipt["kind"] == "request-bytes-acquisition-receipt-v1"
        assert receipt["executionKind"] == "fixed-production-wire"
        assert receipt["productionExecuted"] is True
        assert receipt["workerSha256"] == capability.binding_digest
        assert receipt["transportDeadlineSeconds"] == 60.0
        assert [item["responseDigest"] for item in receipt["metadata"]] == [
            row["responseDigest"] for row in rows
        ]
        assert receipt["routeDigest"] == digest(receipt["metadata"])
    finally:
        admission.revoke_production_capability(capability)


def test_the_launcher_admits_the_campaign_and_stops_at_the_reservation(tmp_path):
    built = Admission(tmp_path)
    before = len(admission.o8_admission._ISSUED)
    assert request_bytes_o8.main(built.argv(tmp_path)) == 3
    # The admission that will not be executed is not left issued.
    assert len(admission.o8_admission._ISSUED) == before
    assert not (tmp_path / "output").exists()


@pytest.mark.parametrize(
    "damage",
    [
        {"status": "pending"},
        {"launcherSha256": "0" * 64},
        {"executionHost": {"platform": "other", "machine": "other"}},
    ],
    ids=["not-approved", "other-launcher", "other-host"],
)
def test_the_launcher_refuses_an_incomplete_approval_before_anything_else(
    tmp_path, damage
):
    built = Admission(tmp_path)
    built.approval_path.write_text(json.dumps({**built.approval, **damage}))
    built.approval_path.chmod(0o600)
    before = len(admission.o8_admission._ISSUED)
    assert request_bytes_o8.main(built.argv(tmp_path)) == 2
    assert len(admission.o8_admission._ISSUED) == before


def test_the_launcher_refuses_a_world_readable_approval(tmp_path):
    built = Admission(tmp_path)
    built.approval_path.chmod(0o644)
    assert request_bytes_o8.main(built.argv(tmp_path)) == 2


def test_the_launcher_refuses_a_handoff_that_is_not_bound_to_the_permission(tmp_path):
    built = Admission(tmp_path)
    built.handoff_path.write_text(
        json.dumps(
            {
                "kind": request_bytes_o8.HANDOFF_KIND,
                "permissionDigest": "0" * 64,
                "token": "offline-fixture-token",
            }
        )
    )
    built.handoff_path.chmod(0o600)
    before = len(admission.o8_admission._ISSUED)
    assert request_bytes_o8.main(built.argv(tmp_path)) == 2
    assert len(admission.o8_admission._ISSUED) == before


def test_the_launcher_has_no_injected_transport_or_preparation_mode():
    parser = request_bytes_o8.build_parser()
    options = {action.dest for action in parser._actions}
    assert "injected_transport" not in options
    assert "transmit" not in options
