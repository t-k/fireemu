"""Offline admission checks of the partition/cursor descriptor.

Nothing here reaches production: no credential, no origin, no Ledger and no
collector run. The synthetic approval is built from local files in tmp_path.
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
sys.path.insert(0, str(ROOT / "tools/compat-broad/fs-query-partition-cursor"))
sys.path.insert(0, str(HERE))

import o4_partition_cursor_descriptor as o4
import o8_admission
import partition_cursor_gate as gate_projection
import partition_cursor_manifest
import partition_cursor_wire as wire
import shared_gate
from broad_contract import digest
from o8_campaign import CAMPAIGN_APPROVAL_FIELDS, REQUIRED_MEMBERS, CampaignDescriptor

NONCE = "a" * 32


def synthetic(tmp_path, descriptor):
    """A complete O7 artifact set for the dry run, built from local files only."""
    permission = {
        "kind": o4.PERMISSION_KIND,
        "wallSeconds": o4.CAMPAIGN_SECONDS,
        "recoverySeconds": o4.RECOVERY_SECONDS,
    }
    plan = descriptor.plan_compiler(NONCE)
    inputs = o8_admission.freeze_inputs(
        descriptor, permission, plan, source_commit="0" * 40, artifact_sha256="b" * 64
    )
    manifest = {"kind": o4.MANIFEST_KIND, "inputsDigest": inputs["inputsDigest"]}
    manifest_bytes = json.dumps(manifest).encode()
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_bytes(manifest_bytes)
    artifact_path = tmp_path / "artifact"
    artifact_path.write_bytes(b"synthetic artifact")
    launcher_path = tmp_path / "launcher.py"
    launcher_path.write_bytes(b"# synthetic launcher\n")
    ledger = tmp_path / "ledger"
    now = time.time()
    approval = {
        "kind": o4.APPROVAL_KIND,
        "status": "approved",
        "campaignId": descriptor.campaign_id,
        "manifestSha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "inputsDigest": inputs["inputsDigest"],
        "permissionDigest": inputs["permissionDigest"],
        "sourceCommit": inputs["sourceCommit"],
        "sourceInputsDigest": digest(inputs["sourceInputs"]),
        "artifactSha256": inputs["artifactSha256"],
        "planDigest": inputs["planDigest"],
        "nonceDigest": digest(plan["nonce"]),
        "ledgerRoot": str(ledger.resolve(strict=False)),
        "launcherSha256": hashlib.sha256(launcher_path.read_bytes()).hexdigest(),
        "artifactProfile": descriptor.artifact_profile,
        "windowStartsAt": now - 1,
        "windowExpiresAt": now + 4 * descriptor.window_seconds,
        "executionHost": o8_admission.execution_host(),
    }
    return {
        "inputs": inputs,
        "approval": approval,
        "manifest": manifest,
        "manifest_bytes": manifest_bytes,
        "manifest_path": manifest_path,
        "permission": permission,
        "ledger_root": ledger,
        "artifact_path": artifact_path,
        "launcher_path": launcher_path,
    }


def retained(tmp_path, bindings):
    """A retained artifact whose bytes hash to what the synthetic inputs froze."""
    bindings["inputs"]["artifactSha256"] = hashlib.sha256(
        bindings["artifact_path"].read_bytes()
    ).hexdigest()
    unsigned = {
        key: value for key, value in bindings["inputs"].items() if key != "inputsDigest"
    }
    bindings["inputs"]["inputsDigest"] = digest(unsigned)
    bindings["manifest"] = {
        "kind": o4.MANIFEST_KIND,
        "inputsDigest": bindings["inputs"]["inputsDigest"],
    }
    bindings["manifest_bytes"] = json.dumps(bindings["manifest"]).encode()
    bindings["manifest_path"].write_bytes(bindings["manifest_bytes"])
    bindings["approval"].update(
        manifestSha256=hashlib.sha256(bindings["manifest_bytes"]).hexdigest(),
        inputsDigest=bindings["inputs"]["inputsDigest"],
        artifactSha256=bindings["inputs"]["artifactSha256"],
    )
    return bindings


def test_every_required_member_is_real_and_the_descriptor_constructs():
    descriptor = o4.descriptor()
    assert type(descriptor) is CampaignDescriptor
    assert descriptor.campaign_id == "FS-QUERY-PARTITION-CURSOR-04"
    assert descriptor.approval_fields == CAMPAIGN_APPROVAL_FIELDS
    assert descriptor.binds_campaign_id is True
    assert (
        descriptor.artifact_profile
        == "partition-cursor-" + o4.shadow_record()["artifact"]["sourceCommit"][:9]
    )
    assert (descriptor.campaign_seconds, descriptor.recovery_seconds) == (840, 520)
    assert descriptor.window_seconds == 1360
    assert descriptor.budget == {
        "requests": 109,
        "accounts": 1,
        "resources": 21,
        "costMicrousd": 10_000,
    }
    assert descriptor.frozen_bounds["totalRequests"] == 109
    assert descriptor.frozen_bounds["planSlots"] == 37
    assert descriptor.frozen_bounds["expectedWireRequests"] == 88
    for member in REQUIRED_MEMBERS:
        assert getattr(descriptor, member) is not None
    assert descriptor.collector is o4.collector
    assert descriptor.comparator is o4.comparator
    assert descriptor.transport_bound is o4.transport_bound
    assert descriptor.binding_verifier is o4.verify_worker_binding
    assert descriptor.retained_artifact_validator is o4.retained_artifact_validator
    assert wire.production_request in descriptor.forbidden_transports()


def test_a_descriptor_missing_any_member_is_refused():
    members = o4.descriptor().members()
    for name in REQUIRED_MEMBERS:
        with pytest.raises(ValueError, match="requires every member"):
            CampaignDescriptor(
                **{key: value for key, value in members.items() if key != name}
            )


def test_the_frozen_inputs_cover_the_lane_and_the_shared_closure(tmp_path):
    descriptor = o4.descriptor()
    bindings = synthetic(tmp_path, descriptor)
    inputs = bindings["inputs"]
    sources = inputs["sourceInputs"]
    assert inputs["kind"] == o4.FROZEN_INPUTS_KIND
    assert inputs["bounds"]["totalRequests"] == 109
    assert set(partition_cursor_manifest.source_inputs()) <= set(sources)
    assert any(Path(name).name.startswith("test_") for name in sources)
    for name in (
        *o4.SHARED_SOURCES,
        o4.COLLECTOR_ENTRY,
        o4.COMPARATOR_ENTRY,
        o4.WORKER_ENTRY,
        o4.GATE_ENTRY,
    ):
        assert sources[name] == hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
    o8_admission.validate_frozen_inputs(descriptor, inputs)
    generation = o8_admission.abort_generation(descriptor, inputs)
    assert set(generation["sourceDigests"]) == {
        "shared_gate.py",
        "reservations.py",
        "o8_admission.py",
        "partition_cursor_admission.py",
        "o4_partition_cursor_descriptor.py",
        "partition_cursor_gate.py",
        "partition_cursor_production.py",
    }


def test_a_synthetic_approval_passes_the_shared_o7_check_set(tmp_path):
    descriptor = o4.descriptor()
    bindings = retained(tmp_path, synthetic(tmp_path, descriptor))
    admitted = o8_admission.validate_o7_admission(descriptor, **bindings)
    assert admitted["campaignId"] == "FS-QUERY-PARTITION-CURSOR-04"
    assert admitted["ledgerRoot"] == str(bindings["ledger_root"].resolve(strict=False))
    assert (
        admitted["retained"]["artifactSha256"] == bindings["inputs"]["artifactSha256"]
    )


@pytest.mark.parametrize(
    "override",
    [
        {"campaignId": "FS-DATA-WRITE-COMMIT-TRANSFORMS-03"},
        {"campaignId": "FS-LIMIT-API-REQUEST-BYTES"},
        {"kind": "commit-o8-approval-v1"},
        {"kind": "request-bytes-o8-approval-v1"},
        {"artifactProfile": "repaired-567565bdd"},
        {"status": "pending"},
    ],
)
def test_another_campaigns_approval_cannot_be_admitted_by_this_descriptor(
    tmp_path, override
):
    descriptor = o4.descriptor()
    bindings = retained(tmp_path, synthetic(tmp_path, descriptor))
    with pytest.raises(ValueError):
        o8_admission.validate_o7_admission(
            descriptor, **{**bindings, "approval": {**bindings["approval"], **override}}
        )


def test_the_lock_scopes_cover_the_compiled_owned_scope():
    descriptor = o4.descriptor()
    plan = descriptor.plan_compiler(NONCE)
    locks = descriptor.lock_scopes(plan)
    write = [lock for lock in locks if lock["mode"] == "WRITE"]
    assert len(write) == 1
    assert write[0]["key"] == (
        f"project/fireemu-35fe6/firestore/(default)/documents/oracle/{NONCE}/o4-query-partition-cursor/root/*"
    )
    assert {
        lock["key"].rsplit("/", 1)[-1] for lock in locks if lock["mode"] == "READ"
    } == {
        "indexes",
        "ruleset",
        "database",
        "config",
        "api-key-binding",
    }
    owned = plan["ownedScope"].removeprefix(
        "projects/fireemu-35fe6/databases/(default)/documents/"
    )
    assert write[0]["key"].endswith(owned + "/*")
    with pytest.raises(ValueError, match="owned scope differs"):
        descriptor.lock_scopes(
            {**plan, "ownedScope": plan["ownedScope"].replace("root", "other")}
        )


def test_the_index_prerequisites_name_no_composite_index_and_digest_the_file():
    value = o4.index_prerequisites()
    assert value["requiredCompositeIndexes"] == []
    assert value["indexFileChangeRequired"] is False
    assert (
        value["indexFileSha256"]
        == hashlib.sha256((ROOT / o4.INDEX_FILE).read_bytes()).hexdigest()
    )
    assert value["deliberatelyUnindexed"] == ["partition-order-non-name"]


def test_the_gate_projection_fits_the_campaign_wall():
    plan = o4.plan_compiler(NONCE)
    gate_plan = o4.gate_plan(plan, slot_seconds=6.0)
    job = gate_plan["jobs"][gate_projection.JOB]
    assert len(job["observation"]) == 36
    assert len(job["recovery"]) == 66
    assert len(job["schedule"]) == 102
    assert job["schedule"][-1]["phase"] == "recovery"
    assert set(job["resources"]) == set(plan["ownedResources"])
    assert gate_plan["observationRequests"] == 40
    assert gate_plan["costMicrousd"] == 10_000
    assert gate_plan["receiptKind"] == "partition-cursor-acquisition-receipt-v1"
    assert gate_plan["management"]["credentialSlots"] == ["tokeninfo"]
    with pytest.raises(ValueError, match="below the wire ceiling"):
        o4.gate_plan(plan, slot_seconds=1.0)
    with pytest.raises(ValueError, match="do not fit"):
        gate_projection.gate_plan(
            plan,
            slot_seconds=60.0,
            wall_seconds=840,
            recovery_seconds=520,
            cost_microusd=10_000,
        )


def test_the_creating_declaration_gap_is_empty_for_partition_queries():
    plan = o4.plan_compiler(NONCE)
    gap = gate_projection.creating_declaration_gap(plan)
    # Shared Gate recognizes partitionQuery as a non-creating read, so no
    # partition slot remains in the declaration gap.
    assert gap == []


def test_partition_schedule_declarations_remain_fail_closed_for_mutations():
    plan = o4.plan_compiler(NONCE)
    projection = gate_projection.gate_operations(plan)
    coordinate = next(
        (phase, index)
        for phase, index in projection["order"]
        if projection[phase][index]["kind"] == "partition-page-token-continuation"
    )
    phase, index = coordinate
    schedule = gate_projection._schedule(projection, slot_seconds=6.0)
    by_coordinate = {(entry["phase"], entry["index"]): entry for entry in schedule}
    assert by_coordinate[coordinate]["creates"] is False

    mutations = (
        (
            "unknown RPC",
            {
                "path": projection[phase][index]["path"].replace(
                    ":partitionQuery", ":unknownRpc"
                )
            },
        ),
        (
            "unknown body key",
            {"body": {**projection[phase][index]["body"], "unknown": True}},
        ),
        ("creating body", {"body": {"writes": []}}),
    )
    for _label, mutation in mutations:
        mutated = copy.deepcopy(projection)
        mutated[phase][index].update(mutation)
        operation = mutated[phase][index]
        assert shared_gate.can_create(operation) is True
        mutated_schedule = gate_projection._schedule(mutated, slot_seconds=6.0)
        mutated_entry = next(
            entry
            for entry in mutated_schedule
            if (entry["phase"], entry["index"]) == coordinate
        )
        assert "creates" not in mutated_entry


def test_the_permission_bindings_carry_the_projection_and_index_facts():
    plan = o4.plan_compiler(NONCE)
    inputs = o4.source_map()
    bindings = o4.permission_bindings(plan, "0" * 40, "b" * 64, inputs)
    assert bindings["gateProjection"]["totalRequests"] == 109
    assert bindings["gateProjection"]["creatingDeclarationGap"] == []
    assert bindings["indexPrerequisites"]["requiredCompositeIndexes"] == []
    assert bindings["productionOrigin"] == "https://firestore.googleapis.com"
    assert bindings["tariffsConfirmedBelowPlanningCeilings"] is False
    assert bindings["workerSha256"] == inputs[o4.WORKER_ENTRY]
    with pytest.raises(ValueError):
        o4.permission_bindings({**plan, "nonce": "c" * 32}, "0" * 40, "b" * 64, inputs)


def test_the_worker_binding_is_the_wire_module_on_disk():
    binding, binding_digest = o4.worker_binding()
    assert binding == (ROOT / o4.WORKER_ENTRY).read_bytes()
    o4.verify_worker_binding(binding, binding_digest, o4.source_map())
    with pytest.raises(ValueError, match="worker source digest differs"):
        o4.verify_worker_binding(
            binding + b"\n#", hashlib.sha256(binding + b"\n#").hexdigest(), None
        )
    with pytest.raises(ValueError, match="frozen inputs"):
        o4.verify_worker_binding(binding, binding_digest, {o4.WORKER_ENTRY: "0" * 64})


def test_an_injected_preparation_transport_must_not_reach_the_production_wire():
    descriptor = o4.descriptor()

    def leaks(request):
        return wire.production_request(request, "token")

    with pytest.raises(ValueError, match="must not reach the production wire"):
        o8_admission.reject_production_transport(descriptor, leaks)
    assert (
        o8_admission.reject_production_transport(
            descriptor, lambda request: {"status": 404}
        )
        is not None
    )


def test_the_lane_manifest_admission_stays_closed_outside_the_o8_path():
    """The preparation manifest never opens admission; only the O8 launcher does."""
    status = partition_cursor_manifest.admission_status(o4.plan_compiler(NONCE))
    assert status["productionReady"] is False
    with pytest.raises(PermissionError):
        status["admit"]()
