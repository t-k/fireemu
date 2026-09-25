"""Real Ledger/O7 coverage for the closed recovery issuer boundary."""

from __future__ import annotations

import copy
import hashlib
import json
import multiprocessing
import shutil
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE.parent / "o8-core"))
sys.path.insert(0, str(HERE.parent / "production-admission"))

import o8_admission
import pytest
import request_bytes_admission as parent_admission
import request_bytes_compiler as parent_compiler
import request_bytes_descriptor as parent_descriptor
import request_bytes_production as parent_production
import request_bytes_recovery_admission as recovery
import request_bytes_recovery_campaign as recovery_campaign
import reservations
import shared_gate
from broad_contract import digest
from test_request_bytes_admission import Admission


def _uncertain_parent_worker(gate_path: str, gate_plan: dict, uncertain_body: dict) -> None:
    shared_gate.create(gate_path, gate_plan)
    gates = {name: shared_gate.Gate(gate_path, name) for name in gate_plan["jobs"]}
    coordinator = next(iter(gates.values()))
    for entry in gate_plan["management"]["observation"]:
        body = None
        if entry["id"] == "oauth-tokeninfo":
            body = {
                "kind": "request-byte-token-attestation-v1",
                "principalDigest": "0" * 64,
                "requiredScopeVerified": True,
                "identityMode": "subject",
                "identityVerified": True,
                "oauthClientVerified": True,
                "expiresInSeconds": 3600,
                "remainingSecondsAtVerification": 3600,
                "requiredSeconds": 1700,
                "complete": True,
                "workerReaped": True,
            }
        coordinator.management_dispatch(
            "observation",
            entry["id"],
            lambda _deadline, body=body: {
                "status": 200,
                "complete": True,
                "workerReaped": True,
                "bodyKind": "json" if body is not None else "empty",
                "body": body,
            },
        )
    for gate in gates.values():
        gate.claim()
    name = parent_descriptor.gate_job_name("probe-u01")
    operations = gates[name].snapshot()["plan"]["jobs"][name]["observation"]
    for operation in operations[:17]:
        gates[name].dispatch(
            operation,
            False,
            lambda operation=operation: (
                200,
                {"name": operation["resource"], "fields": {}},
            ),
        )
    operation = operations[17]
    operation = copy.deepcopy(operation)
    operation.pop("bodyRef", None)
    operation["body"] = uncertain_body
    try:
        gates[name].dispatch(
            operation, False, lambda: (_ for _ in ()).throw(TimeoutError())
        )
    except TimeoutError:
        gates[name].abandon_observation("transport-deadline")


def _actual_child(tmp_path):
    o7 = Admission(tmp_path / "o7")
    shutil.rmtree(o7.ledger)
    reservations.Ledger.create(o7.ledger)
    ledger = reservations.Ledger(o7.ledger)
    parent_plan = parent_compiler.compile_request_bytes_plan(
        parent_descriptor.PROJECT, parent_descriptor.DATABASE, o7.plan["nonce"]
    )
    parent_gate_plan = parent_admission.gate_plan_for(o7.inputs, o7.permission)
    parent_path = (tmp_path / "parent-gate").resolve()
    parent_claim = parent_admission.reservation_claim(
        o7.inputs, gate_path=parent_path, gate_plan=parent_gate_plan
    )
    parent_ticket = ledger.reserve(
        parent_production._envelope(o7.permission, parent_claim),
        parent_claim,
        parent_gate_plan,
        generation=parent_admission.abort_generation(o7.inputs),
        now=time.time(),
    )
    recovery_nonce = "fedcba9876543210fedcba9876543210"
    recovery_plan = recovery_campaign.compile_recovery_plan(
        parent_plan, selected_probe="under", recovery_nonce=recovery_nonce
    )
    child_gate_plan = recovery_campaign.compile_gate_plan(
        parent_plan,
        selected_probe="under",
        recovery_nonce=recovery_nonce,
        recovery_plan=recovery_plan,
    )
    recovery_manifest_digest = digest(recovery_plan)
    recovery_plan["nonce"] = recovery_nonce
    uncertain_body = next(
        operation["body"]
        for operation in parent_plan["observation"]
        if operation.get("probe") == "under" and operation.get("kind") == "conditional-create-commit"
    )
    parent_process = multiprocessing.Process(
        target=_uncertain_parent_worker,
        args=(str(parent_path), parent_gate_plan, uncertain_body),
    )
    parent_process.start()
    parent_process.join(30)
    assert parent_process.exitcode == 0
    resources = sorted(
        {
            operation["resource"]
            for operation in child_gate_plan["jobs"][recovery_campaign.RECOVERY_JOB]["recovery"]
        }
    )
    child_permission = recovery._permission_bindings(
        recovery_plan,
        o7.inputs["sourceCommit"],
        o7.inputs["artifactSha256"],
        recovery.descriptor().source_map(),
    )
    child_generation = parent_admission.abort_generation(o7.inputs)
    child_generation["sourceCommit"] = o7.inputs["sourceCommit"]
    recovery_sources = recovery.descriptor().source_map()
    child_generation["collectorSourceDigest"] = digest(recovery_sources)
    child_generation["sourceDigests"][
        Path(recovery._RECOVERY_SOURCE).name
    ] = recovery_sources[recovery._RECOVERY_SOURCE]
    child_claim = {
        "kind": reservations.RECOVERY_CHILD_KIND,
        "version": 2,
        "campaignId": recovery.CAMPAIGN,
        "manifestDigest": recovery_manifest_digest,
        "nonceDigest": digest(recovery_nonce),
        "gatePath": str((tmp_path / "child-gate").resolve()),
        "gatePlanDigest": digest(child_gate_plan),
        "locks": parent_claim["locks"],
        "budget": dict(recovery.CHILD_BUDGET),
        "durationSeconds": 1200,
        "generation": child_generation,
        "parentClaimDigest": parent_ticket["claimDigest"],
        "parentPlanDigest": digest(parent_plan),
        "recoveryNonce": recovery_nonce,
        "selectedProbe": "under",
        "resourceDigest": digest(resources),
        "ownedResources": resources,
        "ownerIdentity": "offline-child-owner",
        "recoveryOwner": "offline-recovery-owner",
        "operationClass": reservations.RECOVERY_OPERATION_CLASS,
        "readCount": 68,
        "inspectionCount": 17,
        "absenceCount": 51,
        "deleteCount": 17,
        "tariffEstimateMicrousd": 45,
        "expiresAt": time.time() + 1800,
        "executionHost": o8_admission.execution_host(),
        "permissionDigest": digest(child_permission),
    }
    child_envelope = {
        "permissionDigest": digest(child_permission),
        "issuedAt": time.time() - 1,
        "expiresAt": time.time() + 1800,
        "limits": dict(recovery.CHILD_BUDGET),
        "concurrency": 1,
        "scopes": parent_claim["locks"],
    }
    child_ticket = ledger.begin_recovery_extension(
        parent_ticket,
        child_claim,
        child_envelope,
        parent_plan,
        child_gate_plan,
        now=time.time(),
        canonical_parent_inputs=o7.inputs,
        parent_permission=o7.permission,
    )
    return o7, ledger, child_ticket, parent_plan, child_gate_plan, child_permission


def _o7_files(tmp_path, o7, inputs):
    manifest = {
        "kind": recovery.descriptor().manifest_kind,
        "inputsDigest": inputs["inputsDigest"],
    }
    manifest_bytes = json.dumps(manifest).encode()
    manifest_path = tmp_path / "child-manifest.json"
    manifest_path.write_bytes(manifest_bytes)
    approval = {
        "kind": recovery.descriptor().approval_kind,
        "status": "approved",
        "manifestSha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "inputsDigest": inputs["inputsDigest"],
        "permissionDigest": inputs["permissionDigest"],
        "sourceCommit": inputs["sourceCommit"],
        "sourceInputsDigest": digest(inputs["sourceInputs"]),
        "artifactSha256": inputs["artifactSha256"],
        "planDigest": inputs["planDigest"],
        "nonceDigest": digest(inputs["plan"]["recoveryNonce"]),
        "ledgerRoot": str(Path(o7.ledger).resolve()),
        "launcherSha256": hashlib.sha256(o7.launcher_path.read_bytes()).hexdigest(),
        "artifactProfile": recovery.descriptor().artifact_profile,
        "campaignId": recovery.CAMPAIGN,
        "windowStartsAt": time.time() - 1,
        "windowExpiresAt": time.time() + 4000,
        "executionHost": o8_admission.execution_host(),
    }
    binding, binding_digest = parent_descriptor.worker_binding()
    return {
        "approval": approval,
        "manifest": manifest,
        "manifest_bytes": manifest_bytes,
        "manifest_path": manifest_path,
        "artifact_path": o7.artifact_path,
        "launcher_path": o7.launcher_path,
        "binding": binding,
        "binding_digest": binding_digest,
    }


def test_recovery_descriptor_is_stable_and_closed():
    value = recovery.descriptor()
    assert value.campaign_id == recovery.CAMPAIGN
    assert value.budget == recovery.CHILD_BUDGET
    sources = value.source_map()
    assert "tools/compat-broad/production-admission/reservations.py" in sources
    assert "tools/compat-broad/shared_gate.py" in sources
    assert "tools/compat-broad/fs-request-bytes-boundary/request_bytes_recovery_admission.py" in sources


def test_real_ledger_getter_and_o7_issuer_re_read_persisted_child(tmp_path):
    o7, ledger, child_ticket, parent_plan, child_gate_plan, permission = _actual_child(tmp_path)
    inputs = recovery.freeze_inputs(
        ledger,
        child_ticket,
        parent_plan,
        permission,
        selected_probe="under",
        source_commit=o7.commit,
        artifact_sha256=o7.inputs["artifactSha256"],
    )
    files = _o7_files(tmp_path, o7, inputs)
    capability = recovery.issue_production_capability(
        ledger=ledger,
        child_ticket=child_ticket,
        parent_plan=parent_plan,
        child_gate_plan=child_gate_plan,
        selected_probe="under",
        inputs=inputs,
        permission=permission,
        ledger_root=o7.ledger,
        **files,
    )
    assert type(capability).__name__ == "ProductionWireCapability"
    assert capability.inputs_digest == inputs["inputsDigest"]
    with pytest.raises(ValueError):
        recovery.issue_production_capability(
            ledger=ledger,
            child_ticket={**child_ticket, "claimDigest": "0" * 64},
            parent_plan=parent_plan,
            child_gate_plan=child_gate_plan,
            selected_probe="under",
            inputs=inputs,
            permission=permission,
            ledger_root=o7.ledger,
            **files,
        )


@pytest.mark.parametrize(
    "mutation",
    ["deadline", "envelope", "parent", "source", "host", "gate", "permission", "plan"],
)
def test_persisted_child_mutations_fail_before_capability_or_ledger_write(
    tmp_path, mutation
):
    o7, ledger, child_ticket, parent_plan, child_gate_plan, permission = _actual_child(
        tmp_path
    )
    inputs = recovery.freeze_inputs(
        ledger,
        child_ticket,
        parent_plan,
        permission,
        selected_probe="under",
        source_commit=o7.commit,
        artifact_sha256=o7.inputs["artifactSha256"],
    )
    files = _o7_files(tmp_path, o7, inputs)
    issue_permission = permission
    issue_parent_plan = parent_plan
    bound = ledger.bound_recovery_claim(child_ticket)
    mutated = copy.deepcopy(bound)
    if mutation == "deadline":
        mutated["deadline"] = time.time() - 1
    elif mutation == "envelope":
        mutated["newEnvelope"]["permissionDigest"] = "0" * 64
    elif mutation == "parent":
        mutated["parentIdentity"]["claimDigest"] = "0" * 64
    elif mutation == "source":
        mutated["childClaim"]["generation"]["sourceCommit"] = "0" * 40
    elif mutation == "host":
        mutated["childClaim"]["executionHost"] = {"platform": "other", "machine": "other"}
    elif mutation == "gate":
        mutated["childClaim"]["gatePlanDigest"] = "0" * 64
    elif mutation == "permission":
        issue_permission = {**permission, "nonce": "0" * 32}
    elif mutation == "plan":
        issue_parent_plan = {**parent_plan, "nonce": "0" * 32}
    before = ledger.snapshot()
    original_reader = ledger.bound_recovery_claim
    ledger.bound_recovery_claim = lambda _ticket: copy.deepcopy(mutated)
    try:
        with pytest.raises(ValueError):
            recovery.issue_production_capability(
                ledger=ledger,
                child_ticket=child_ticket,
                parent_plan=issue_parent_plan,
                child_gate_plan=child_gate_plan,
                selected_probe="under",
                inputs=inputs,
                permission=issue_permission,
                ledger_root=o7.ledger,
                **files,
            )
    finally:
        ledger.bound_recovery_claim = original_reader
    assert ledger.snapshot() == before
