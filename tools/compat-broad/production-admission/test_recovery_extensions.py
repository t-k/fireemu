"""Read-only evidence and recovery-allocation contract tests."""

import copy
import json
import multiprocessing
import os
import subprocess
import shutil
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "fs-request-bytes-boundary"))
sys.path.insert(0, str(HERE.parent / "auth-credential-tokens"))
import credential_gate
import request_bytes_admission
import request_bytes_compiler
import request_bytes_descriptor
import request_bytes_production
import request_bytes_recovery_campaign
import reservations
from broad_contract import digest
from shared_gate import Gate, _save
from shared_gate import create as create_gate
from test_request_bytes_admission import Admission

ACTUAL_INPUTS = None
ACTUAL_PERMISSION = None


class EnrichedRecoveryGate(Gate):
    """Test facade for the future recovery transport's response-bound capture."""

    def _recovery_capture(self, operation, status, body):
        capture = super()._recovery_capture(operation, status, body)
        capture["responseDigest"] = digest(body)
        return capture


class MixedRecoveryGate(EnrichedRecoveryGate):
    def __init__(self, path, job, expected_fields):
        super().__init__(path, job)
        self.expected_fields = expected_fields

    def _validate_cleanup_ownership(self, operation, recovery, resource, source, job):
        capture = job["captures"].get(str(source), {})
        if (
            not recovery
            or capture.get("name") != resource
            or capture.get("fieldsDigest") != self.expected_fields[resource]
            or not isinstance(capture.get("updateTime"), str)
            or not capture["updateTime"]
        ):
            raise ValueError("strict mixed cleanup ownership required")


def _exit_immediately():
    return None


def _dead_pid():
    process = multiprocessing.get_context("spawn").Process(target=_exit_immediately)
    process.start()
    pid = process.pid
    process.join()
    return pid


def test_bounded_evidence_reader_rejects_symlink_and_fifo(tmp_path):
    target = tmp_path / "target.json"
    target.write_text("{}")
    link = tmp_path / "link.json"
    link.symlink_to(target)
    with pytest.raises(ValueError, match="canonical evidence"):
        reservations.Ledger._read_bounded_json(link)

    fifo = tmp_path / "evidence.fifo"
    os.mkfifo(fifo)
    with pytest.raises(ValueError, match="regular evidence"):
        reservations.Ledger._read_bounded_json(fifo)


def test_bounded_evidence_reader_rejects_changed_file_after_read(tmp_path, monkeypatch):
    path = tmp_path / "evidence.json"
    path.write_text("{}")
    original_fstat = reservations.os.fstat
    calls = 0

    def changed_fstat(descriptor):
        nonlocal calls
        calls += 1
        value = original_fstat(descriptor)
        if calls == 2:
            return SimpleNamespace(
                st_mode=value.st_mode,
                st_ino=value.st_ino,
                st_dev=value.st_dev,
                st_size=value.st_size + 1,
                st_mtime_ns=value.st_mtime_ns,
                st_ctime_ns=value.st_ctime_ns,
            )
        return value

    monkeypatch.setattr(reservations.os, "fstat", changed_fstat)
    with pytest.raises(ValueError, match="stable evidence"):
        reservations.Ledger._read_bounded_json(path)


def _recovery_fixture(tmp_path):
    global ACTUAL_INPUTS, ACTUAL_PERMISSION
    fixture = Admission(tmp_path)
    ACTUAL_INPUTS, ACTUAL_PERMISSION = fixture.inputs, fixture.permission
    import shutil
    shutil.rmtree(fixture.ledger)
    reservations.Ledger.create(fixture.ledger)
    ledger = reservations.Ledger(fixture.ledger)
    parent_gate_plan = request_bytes_admission.gate_plan_for(fixture.inputs, fixture.permission)
    parent_path = (tmp_path / "parent-gate").resolve()
    parent_claim = request_bytes_admission.reservation_claim(fixture.inputs, gate_path=parent_path, gate_plan=parent_gate_plan)
    parent_envelope = request_bytes_production._envelope(fixture.permission, parent_claim)
    parent_envelope["expiresAt"] = time.time() + 3600
    parent_generation = request_bytes_admission.abort_generation(fixture.inputs)
    parent_plan = request_bytes_compiler.compile_request_bytes_plan(
        request_bytes_descriptor.PROJECT, request_bytes_descriptor.DATABASE, fixture.plan["nonce"]
    )
    ticket = ledger.reserve(parent_envelope, parent_claim, parent_gate_plan, generation=parent_generation, now=time.time())
    create_gate(parent_path, parent_gate_plan)
    Gate(parent_path, request_bytes_descriptor.gate_job_name("probe-u01")).claim()
    gate_state = json.loads((parent_path / "state.json").read_text())
    dead = _dead_pid()
    gate_state["coordinatorPid"] = dead
    job_name = request_bytes_descriptor.gate_job_name("probe-u01")
    gate_state["jobs"][job_name]["pid"] = dead
    job = gate_state["plan"]["jobs"][job_name]
    create_index, create_operation = next(
        (index, operation) for index, operation in enumerate(job["observation"])
        if operation.get("kind") == "conditional-create-commit"
    )
    event_operation = json.loads(json.dumps(create_operation))
    if event_operation.get("bodyRef") is not None:
        event_operation["body"] = next(
            operation["body"]
            for operation in parent_plan["observation"]
            if operation.get("kind") == event_operation["kind"]
            and operation.get("probe") == event_operation.get("probe")
        )
        event_operation.pop("bodyRef", None)
    gate_state["events"] = [{"job": job_name, "phase": "observation", "index": create_index,
                              "started": time.monotonic(), "ended": time.monotonic(),
                              "requestDigest": digest(event_operation),
                              "service": create_operation["service"], "method": create_operation["method"],
                              "completed": False, "creationOutcome": "unknown"}]
    gate_state["stopped"] = True
    _save(parent_path, gate_state)
    recovery_nonce = "fedcba9876543210fedcba9876543210"
    recovery_source = request_bytes_recovery_campaign.compile_recovery_plan(
        parent_plan, selected_probe="under", recovery_nonce=recovery_nonce
    )
    recovery_plan = request_bytes_recovery_campaign.compile_gate_plan(
        parent_plan, selected_probe="under", recovery_nonce=recovery_nonce, recovery_plan=recovery_source
    )
    resources = recovery_plan["jobs"][request_bytes_recovery_campaign.RECOVERY_JOB]["resources"]
    child_generation = dict(parent_generation)
    child_generation["sourceCommit"] = "f" * 40
    child_claim = {
        "kind": reservations.RECOVERY_CHILD_KIND, "version": 2,
        "campaignId": parent_claim["campaignId"], "manifestDigest": digest(recovery_source),
        "nonceDigest": digest(recovery_nonce), "gatePath": str((tmp_path / "child-gate").resolve()),
        "gatePlanDigest": digest(recovery_plan), "locks": parent_claim["locks"],
        "budget": {"requests": 85, "accounts": 0, "resources": 51, "costMicrousd": 85},
        "durationSeconds": 1200, "generation": child_generation, "parentClaimDigest": ticket["claimDigest"],
        "parentPlanDigest": digest(parent_plan), "recoveryNonce": recovery_nonce, "selectedProbe": "under",
        "resourceDigest": digest(resources), "ownedResources": resources,
        "ownerIdentity": "owner", "recoveryOwner": "recovery-owner",
        "operationClass": reservations.RECOVERY_OPERATION_CLASS, "readCount": 68,
        "inspectionCount": 17, "absenceCount": 51, "deleteCount": 17,
        "tariffEstimateMicrousd": 45, "expiresAt": time.time() + 2400,
        "executionHost": request_bytes_admission.execution_host(), "permissionDigest": "b" * 64,
    }
    envelope = {"permissionDigest": "b" * 64, "issuedAt": 1000, "expiresAt": time.time() + 3000,
                "limits": {"requests": 85, "accounts": 0, "resources": 51, "costMicrousd": 85},
                "concurrency": 1, "scopes": parent_envelope["scopes"]}
    original_begin = ledger.begin_recovery_extension
    def begin(*args, **kwargs):
        kwargs.setdefault("canonical_parent_inputs", ACTUAL_INPUTS)
        kwargs.setdefault("parent_permission", ACTUAL_PERMISSION)
        return original_begin(*args, **kwargs)
    ledger.begin_recovery_extension = begin
    return ledger, ticket, child_claim, envelope, parent_plan, recovery_plan


def test_recovery_extension_persists_child_before_any_issuer(tmp_path):
    ledger, parent, child, envelope, parent_plan, child_plan = _recovery_fixture(tmp_path)
    before = ledger.snapshot()
    result = ledger.begin_recovery_extension(parent, child, envelope, parent_plan, child_plan, now=1100,
                                             canonical_parent_inputs=ACTUAL_INPUTS,
                                             parent_permission=ACTUAL_PERMISSION)
    assert result["claimDigest"] == digest(child)
    state = ledger.snapshot()
    row = state["reservations"][parent["reservation"]]
    assert row["claim"]["budget"] == before["reservations"][parent["reservation"]]["claim"]["budget"]
    assert row["claimDigest"] == parent["claimDigest"]
    assert row["recoveryChildren"][0]["claim"]["budget"]["requests"] == 85
    assert reservations.task_spent_microusd(state, child["campaignId"]) == 388
    assert not hasattr(ledger, "_consume")
    assert ledger.begin_recovery_extension(parent, child, envelope, parent_plan, child_plan, now=1100) == result


def test_bound_recovery_claim_reads_nested_child_after_restart_without_expiry_gate(tmp_path, monkeypatch):
    ledger, parent, child, envelope, parent_plan, child_plan = _recovery_fixture(tmp_path)
    child_ticket = ledger.begin_recovery_extension(
        parent, child, envelope, parent_plan, child_plan, now=1100,
        canonical_parent_inputs=ACTUAL_INPUTS, parent_permission=ACTUAL_PERMISSION,
    )
    # Inspection remains available for an expired row; authorization is a
    # separate issuer responsibility.
    monkeypatch.setattr(reservations.time, "time", lambda: 10**12)
    restarted = reservations.Ledger(ledger.path)
    before = restarted.snapshot()
    bound = restarted.bound_recovery_claim(child_ticket)
    assert bound["ticket"] == child_ticket
    assert bound["childClaim"] == child
    assert bound["newEnvelope"] == before["recoveryEnvelopes"][child_ticket["envelopeDigest"]]["envelope"]
    assert bound["parentClaim"] == before["reservations"][parent["reservation"]]["claim"]
    assert bound["parentIdentity"]["reservation"] == parent["reservation"]
    assert bound["deadline"] == before["reservations"][parent["reservation"]]["recoveryChildren"][0]["deadline"]
    assert bound["state"] == "allocated"
    bound["childClaim"]["campaignId"] = "forged"
    bound["newEnvelope"]["expiresAt"] = -1
    bound["parentClaim"]["campaignId"] = "forged"
    assert restarted.snapshot() == before


@pytest.mark.parametrize("mutation", [
    "ledgerPath", "ledgerIdentity", "reservation", "claimDigest",
    "envelopeDigest", "parentReservation", "topLevelParent",
])
def test_bound_recovery_claim_rejects_forged_or_parent_ticket(tmp_path, mutation):
    ledger, parent, child, envelope, parent_plan, child_plan = _recovery_fixture(tmp_path)
    child_ticket = ledger.begin_recovery_extension(
        parent, child, envelope, parent_plan, child_plan, now=1100,
        canonical_parent_inputs=ACTUAL_INPUTS, parent_permission=ACTUAL_PERMISSION,
    )
    forged = dict(parent if mutation == "topLevelParent" else child_ticket)
    if mutation != "topLevelParent":
        forged[mutation] = "forged"
    with pytest.raises(ValueError, match="recovery child|persisted|ledger binding"):
        ledger.bound_recovery_claim(forged)


def test_settle_recovery_child_uses_completed_real_gate_and_is_idempotent(tmp_path):
    ledger, parent, child, envelope, parent_plan, child_plan = _recovery_fixture(tmp_path)
    child_ticket = ledger.begin_recovery_extension(
        parent, child, envelope, parent_plan, child_plan, now=1100,
        canonical_parent_inputs=ACTUAL_INPUTS, parent_permission=ACTUAL_PERMISSION,
    )
    create_gate(child["gatePath"], child_plan)
    gate = EnrichedRecoveryGate(child["gatePath"], reservations.RECOVERY_GATE_JOB)
    gate.claim()
    operations = child_plan["jobs"][reservations.RECOVERY_GATE_JOB]["recovery"]
    for operation in operations:
        wire_operation = dict(operation)
        if operation["kind"] == "recovery-conditional-delete":
            # The preceding typed-absent inspection makes this registered
            # cleanup slot a real Gate skip; no parent proof is fabricated.
            wire_operation.pop("versionFrom")
        gate.dispatch(
            wire_operation,
            True,
            lambda: (404, {"error": {"code": 404, "status": "NOT_FOUND"}}),
        )
    gate.finish()
    gate_state_path = Path(child["gatePath"]) / "state.json"
    gate_state = json.loads(gate_state_path.read_text())
    gate_state["jobs"][reservations.RECOVERY_GATE_JOB]["creationProofs"] = {"foreign": {}}
    _save(Path(child["gatePath"]), gate_state)
    before = ledger.snapshot()
    with pytest.raises(ValueError, match="creation proofs"):
        ledger.settle_recovery_child(
            child_ticket, receipt_digest="receipt-correlation",
            canonical_parent_plan=parent_plan, now=10**12,
        )
    assert ledger.snapshot() == before
    gate_state["jobs"][reservations.RECOVERY_GATE_JOB]["creationProofs"] = {}
    _save(Path(child["gatePath"]), gate_state)
    settled = ledger.settle_recovery_child(
        child_ticket, receipt_digest="receipt-correlation", canonical_parent_plan=parent_plan, now=10**12
    )
    assert settled == child_ticket
    child_row = ledger.snapshot()["reservations"][parent["reservation"]]["recoveryChildren"][0]
    assert child_row["state"] == "settled"
    assert ledger.settle_recovery_child(child_ticket, receipt_digest="receipt-correlation", canonical_parent_plan=parent_plan) == child_ticket
    before = ledger.snapshot()
    with pytest.raises(ValueError, match="different recovery settlement"):
        ledger.settle_recovery_child(child_ticket, receipt_digest="other-receipt", canonical_parent_plan=parent_plan)
    assert ledger.snapshot() == before


def test_settle_recovery_child_accepts_one_authoritative_200_delete_chain(tmp_path):
    ledger, parent, child, envelope, parent_plan, child_plan = _recovery_fixture(tmp_path)
    child_ticket = ledger.begin_recovery_extension(
        parent, child, envelope, parent_plan, child_plan, now=1100,
        canonical_parent_inputs=ACTUAL_INPUTS, parent_permission=ACTUAL_PERMISSION,
    )
    expected_fields = {
        write["update"]["name"]: digest(write["update"]["fields"])
        for operation in parent_plan["observation"]
        if isinstance(operation.get("body"), dict)
        for write in operation["body"].get("writes", [])
    }
    create_gate(child["gatePath"], child_plan)
    gate = MixedRecoveryGate(child["gatePath"], reservations.RECOVERY_GATE_JOB, expected_fields)
    gate.claim()
    for operation in child_plan["jobs"][reservations.RECOVERY_GATE_JOB]["recovery"]:
        wire_operation = dict(operation)
        resource = operation["resource"]
        if operation["kind"] == "recovery-inspection-read" and resource.endswith("/control"):
            fields = next(
                write["update"]["fields"]
                for parent_operation in parent_plan["observation"]
                if isinstance(parent_operation.get("body"), dict)
                for write in parent_operation["body"].get("writes", [])
                if write["update"]["name"] == resource
            )
            response = (200, {"name": resource, "fields": fields, "updateTime": "2026-01-01T00:00:00.000000Z"})
        elif operation["kind"] == "recovery-conditional-delete" and resource.endswith("/control"):
            wire_operation.pop("versionFrom")
            wire_operation["path"] += "?currentDocument.updateTime=2026-01-01T00%3A00%3A00.000000Z"
            response = (404, {"error": {"code": 404, "status": "NOT_FOUND"}})
        else:
            if operation["kind"] == "recovery-conditional-delete":
                wire_operation.pop("versionFrom")
            response = (404, {"error": {"code": 404, "status": "NOT_FOUND"}})
        gate.dispatch(wire_operation, True, lambda response=response: response)
    gate.finish()
    assert ledger.settle_recovery_child(
        child_ticket,
        receipt_digest="mixed-receipt",
        canonical_parent_plan=parent_plan,
        now=10**12,
    ) == child_ticket
    before = ledger.snapshot()
    gate_state_path = Path(child["gatePath"]) / "state.json"
    gate_state = json.loads(gate_state_path.read_text())
    gate_state["planDigest"] = "0" * 64
    _save(Path(child["gatePath"]), gate_state)
    with pytest.raises(ValueError):
        ledger.settle_recovery_child(child_ticket, receipt_digest="mixed-receipt", canonical_parent_plan=parent_plan)
    assert ledger.snapshot() == before


def test_close_after_recovery_child_releases_only_parent_and_is_idempotent(tmp_path):
    ledger, parent, child, envelope, parent_plan, child_plan = _recovery_fixture(tmp_path)
    child_ticket = ledger.begin_recovery_extension(
        parent, child, envelope, parent_plan, child_plan, now=1100,
        canonical_parent_inputs=ACTUAL_INPUTS, parent_permission=ACTUAL_PERMISSION,
    )
    create_gate(child["gatePath"], child_plan)
    gate = EnrichedRecoveryGate(child["gatePath"], reservations.RECOVERY_GATE_JOB)
    gate.claim()
    for operation in child_plan["jobs"][reservations.RECOVERY_GATE_JOB]["recovery"]:
        wire = dict(operation)
        if operation["kind"] == "recovery-conditional-delete":
            wire.pop("versionFrom")
        gate.dispatch(wire, True, lambda: (404, {"error": {"code": 404, "status": "NOT_FOUND"}}))
    gate.finish()
    ledger.settle_recovery_child(child_ticket, receipt_digest="close-receipt", canonical_parent_plan=parent_plan, now=10**12)
    closed = ledger.close_after_recovery_child(
        parent, child_ticket, receipt_digest="close-receipt", canonical_parent_plan=parent_plan, now=10**12,
    )
    assert closed == parent
    assert ledger.snapshot()["reservations"][parent["reservation"]]["state"] == "closed-after-recovery-child"
    assert ledger.close_after_recovery_child(
        parent, child_ticket, receipt_digest="close-receipt", canonical_parent_plan=parent_plan,
    ) == parent
    before = ledger.snapshot()
    parent_gate_path = Path(before["reservations"][parent["reservation"]]["claim"]["gatePath"])
    parent_gate_state_path = parent_gate_path / "state.json"
    parent_gate_state = json.loads(parent_gate_state_path.read_text())
    parent_gate_state["planDigest"] = "0" * 64
    _save(parent_gate_path, parent_gate_state)
    with pytest.raises(ValueError):
        ledger.close_after_recovery_child(
            parent, child_ticket, receipt_digest="close-receipt", canonical_parent_plan=parent_plan,
        )
    assert ledger.snapshot() == before
    parent_gate_state["planDigest"] = digest(parent_gate_state["plan"])
    _save(parent_gate_path, parent_gate_state)
    with pytest.raises(ValueError, match="different recovery settlement receipt"):
        ledger.close_after_recovery_child(
            parent, child_ticket, receipt_digest="wrong", canonical_parent_plan=parent_plan,
        )
    assert ledger.snapshot() == before


def test_recovery_extension_refuses_tariff_or_plan_count_mutation_without_save(tmp_path):
    ledger, parent, child, envelope, parent_plan, child_plan = _recovery_fixture(tmp_path)
    before = ledger.snapshot()
    bad = dict(child, tariffEstimateMicrousd=85)
    with pytest.raises(ValueError, match="allocation counts"):
        ledger.begin_recovery_extension(parent, bad, envelope, parent_plan, child_plan, now=1100)
    assert ledger.snapshot() == before


def test_recovery_extension_save_after_replace_is_recovered_idempotently(tmp_path, monkeypatch):
    ledger, parent, child, envelope, parent_plan, child_plan = _recovery_fixture(tmp_path)
    original_save = ledger._save

    def save_then_report_failure(state):
        original_save(state)
        raise OSError("post-replace")

    monkeypatch.setattr(ledger, "_save", save_then_report_failure)
    with pytest.raises(OSError, match="post-replace"):
        ledger.begin_recovery_extension(parent, child, envelope, parent_plan, child_plan, now=1100)
    monkeypatch.setattr(ledger, "_save", original_save)
    recovered = ledger.begin_recovery_extension(parent, child, envelope, parent_plan, child_plan, now=1100)
    assert recovered["claimDigest"] == digest(child)
    assert len(ledger.snapshot()["reservations"][parent["reservation"]]["recoveryChildren"]) == 1


def test_recovery_extension_refuses_live_parent_workers(tmp_path):
    ledger, parent, child, envelope, parent_plan, child_plan = _recovery_fixture(tmp_path)
    state_path = Path(child["gatePath"]).parent / "parent-gate" / "state.json"
    state = json.loads(state_path.read_text())
    state["coordinatorPid"] = os.getpid()
    state["jobs"][request_bytes_descriptor.gate_job_name("probe-u01")]["pid"] = os.getpid()
    _save(state_path.parent, state)
    before = ledger.snapshot()
    with pytest.raises(ValueError, match="still alive"):
        ledger.begin_recovery_extension(parent, child, envelope, parent_plan, child_plan, now=1100)
    assert ledger.snapshot() == before


@pytest.mark.parametrize("mutation", ["nonce", "wire"])
def test_recovery_extension_requires_compiler_exact_child_plan(tmp_path, mutation):
    ledger, parent, child, envelope, parent_plan, child_plan = _recovery_fixture(tmp_path)
    mutated = json.loads(json.dumps(child_plan))
    if mutation == "nonce":
        altered = dict(child, recoveryNonce="c" * 32)
    else:
        mutated["jobs"][request_bytes_recovery_campaign.RECOVERY_JOB]["recovery"][0]["path"] += "/foreign"
        altered = child
    before = ledger.snapshot()
    with pytest.raises(ValueError, match="authoritative|provenance|nonce"):
        ledger.begin_recovery_extension(parent, altered, envelope, parent_plan, mutated, now=1100)
    assert ledger.snapshot() == before


def test_active_child_blocks_ordinary_parent_validate_and_finish(tmp_path):
    ledger, parent, child, envelope, parent_plan, child_plan = _recovery_fixture(tmp_path)
    ledger.begin_recovery_extension(parent, child, envelope, parent_plan, child_plan, now=1100)
    before = ledger.snapshot()
    with pytest.raises(ValueError, match="recovery child"):
        ledger.validate(parent, now=1100)
    with pytest.raises(ValueError, match="recovery child"):
        ledger.finish(parent)
    assert ledger.snapshot() == before


@pytest.mark.parametrize("field", ["version", "readCount", "inspectionCount", "absenceCount", "deleteCount"])
def test_recovery_extension_rejects_noncanonical_integer_shape(tmp_path, field):
    ledger, parent, child, envelope, parent_plan, child_plan = _recovery_fixture(tmp_path)
    altered = dict(child, **{field: True if field != "version" else 1})
    before = ledger.snapshot()
    with pytest.raises(ValueError):
        ledger.begin_recovery_extension(parent, altered, envelope, parent_plan, child_plan, now=1100)
    assert ledger.snapshot() == before


def test_recovery_extension_requires_window_to_cover_persisted_duration(tmp_path):
    ledger, parent, child, envelope, parent_plan, child_plan = _recovery_fixture(tmp_path)
    altered = dict(child, expiresAt=1100 + child["durationSeconds"] - 1)
    before = ledger.snapshot()
    with pytest.raises(ValueError, match="permission window"):
        ledger.begin_recovery_extension(parent, altered, envelope, parent_plan, child_plan, now=1100)
    assert ledger.snapshot() == before


def test_recovery_extension_rejects_child_locks_that_miss_owned_resources(tmp_path):
    ledger, parent, child, envelope, parent_plan, child_plan = _recovery_fixture(tmp_path)
    altered = dict(child, locks=[{"key": "project/fireemu-35fe6", "mode": "READ"}])
    before = ledger.snapshot()
    with pytest.raises(ValueError, match="resource locks|permission scope"):
        ledger.begin_recovery_extension(parent, altered, envelope, parent_plan, child_plan, now=1100)
    assert ledger.snapshot() == before


@pytest.mark.parametrize("mutation", ["bodyRef", "precondition", "privileged", "form", "order"])
def test_recovery_extension_requires_full_registered_parent_gate_digest(tmp_path, mutation):
    ledger, parent, child, envelope, parent_plan, child_plan = _recovery_fixture(tmp_path)
    gate_path = Path(ledger.snapshot()["reservations"][parent["reservation"]]["claim"]["gatePath"])
    state = json.loads((gate_path / "state.json").read_text())
    job_name = request_bytes_descriptor.gate_job_name("probe-u01")
    operations = state["plan"]["jobs"][job_name]["observation"]
    if mutation == "order":
        operations[0], operations[1] = operations[1], operations[0]
    else:
        operation = operations[0]
        if mutation == "bodyRef":
            operation["bodyRef"] = "foreign"
        elif mutation == "precondition":
            operation["expect"] = {"foreign": True}
        elif mutation == "privileged":
            operation["privileged"] = not operation["privileged"]
        else:
            operation["form"] = not operation.get("form", False)
    state["planDigest"] = digest(state["plan"])
    _save(gate_path, state)
    before = ledger.snapshot()
    with pytest.raises(ValueError, match="registered parent Gate plan differs"):
        ledger.begin_recovery_extension(
            parent, child, envelope, parent_plan, child_plan, now=1100,
            canonical_parent_inputs=ACTUAL_INPUTS, parent_permission=ACTUAL_PERMISSION,
        )
    assert ledger.snapshot() == before


def test_recovery_extension_rejects_mutated_caller_parent_payload(tmp_path):
    ledger, parent, child, envelope, parent_plan, child_plan = _recovery_fixture(tmp_path)
    mutated_parent = json.loads(json.dumps(parent_plan))
    operation = next(
        operation
        for operation in mutated_parent["observation"] + mutated_parent["recovery"]
        if operation.get("body") is not None
    )
    operation["body"] = json.loads(json.dumps(operation["body"]))
    operation["body"]["writes"][0]["update"]["fields"]["_owner"]["stringValue"] = "foreign"
    before = ledger.snapshot()
    with pytest.raises(ValueError, match="canonical parent compiler plan differs"):
        ledger.begin_recovery_extension(
            parent,
            child,
            envelope,
            mutated_parent,
            child_plan,
            now=1100,
            canonical_parent_inputs=ACTUAL_INPUTS,
            parent_permission=ACTUAL_PERMISSION,
        )
    assert ledger.snapshot() == before


def test_recovery_extension_rejects_child_lock_outside_persisted_parent_boundary(tmp_path):
    ledger, parent, child, envelope, parent_plan, child_plan = _recovery_fixture(tmp_path)
    altered = dict(child, locks=[{"key": "project/fireemu-35fe6", "mode": "EXCLUSIVE"}])
    altered_envelope = dict(
        envelope,
        scopes=[{"key": "project/fireemu-35fe6", "mode": "EXCLUSIVE"}],
    )
    before = ledger.snapshot()
    with pytest.raises(ValueError, match="parent lock boundary"):
        ledger.begin_recovery_extension(
            parent,
            altered,
            altered_envelope,
            parent_plan,
            child_plan,
            now=1100,
            canonical_parent_inputs=ACTUAL_INPUTS,
            parent_permission=ACTUAL_PERMISSION,
        )
    assert ledger.snapshot() == before


@pytest.mark.parametrize("outcome", ["created", "refused", None])
def test_recovery_extension_requires_uncertain_selected_create_event(tmp_path, outcome):
    ledger, parent, child, envelope, parent_plan, child_plan = _recovery_fixture(tmp_path)
    gate_path = Path(ledger.snapshot()["reservations"][parent["reservation"]]["claim"]["gatePath"])
    state = json.loads((gate_path / "state.json").read_text())
    event = state["events"][0]
    if outcome is None:
        event["completed"] = True
        event.pop("creationOutcome", None)
    else:
        event["completed"] = True
        event["creationOutcome"] = outcome
    state["planDigest"] = digest(state["plan"])
    _save(gate_path, state)
    before = ledger.snapshot()
    with pytest.raises(ValueError, match="uncertain"):
        ledger.begin_recovery_extension(
            parent, child, envelope, parent_plan, child_plan, now=1100,
            canonical_parent_inputs=ACTUAL_INPUTS, parent_permission=ACTUAL_PERMISSION,
        )
    assert ledger.snapshot() == before


@pytest.mark.parametrize("missing", ["both", "inputs", "permission"])
def test_recovery_extension_requires_canonical_parent_producer_inputs(tmp_path, missing):
    ledger, parent, child, envelope, parent_plan, child_plan = _recovery_fixture(tmp_path)
    before = ledger.snapshot()
    kwargs = {"canonical_parent_inputs": ACTUAL_INPUTS, "parent_permission": ACTUAL_PERMISSION}
    if missing == "both":
        kwargs = {"canonical_parent_inputs": None, "parent_permission": None}
    elif missing == "inputs":
        kwargs["canonical_parent_inputs"] = None
    else:
        kwargs["parent_permission"] = None
    with pytest.raises(ValueError, match="canonical parent producer"):
        reservations.Ledger.begin_recovery_extension(
            ledger, parent, child, envelope, parent_plan, child_plan, now=1100, **kwargs
        )
    assert ledger.snapshot() == before


def _auth_recovery_fixture(tmp_path):
    """Build a held Auth parent with one uncertain custom-sign-in event."""
    nonce = "a" * 32
    custom_uid = f"custom-{nonce}"
    resource = f"projects/demo/auth/accounts/{custom_uid}"
    parent_path = (tmp_path / "auth-parent-gate").resolve()
    child_path = (tmp_path / "auth-child-gate").resolve()
    operation = {
        "service": "auth",
        "method": "POST",
        "path": "identitytoolkit.googleapis.com/v1/accounts:signInWithCustomToken",
        "form": False,
        "body": {"token": "$binding:customToken", "returnSecureToken": True},
        "kind": "custom-sign-in",
        "account": "custom",
        "resource": resource,
        "binds": {"customUid": "idToken.sub"},
    }
    parent_plan = {
        "contract": "shared-local-v1", "campaignId": "AUTH-CREDENTIAL-TOKENS-01",
        "nonce": nonce, "project": "demo", "jobSlots": 1, "requestSeconds": 5,
        "wallSeconds": 600, "recoverySeconds": 60, "intervalSeconds": 0.25,
        "observationRequests": 1, "dataRequests": 1, "managementRequests": 0,
        "requestCostMicrousd": 1, "costMicrousd": 50_000,
        "jobs": {"auth-credential": {"resources": [resource], "observation": [operation],
            "recovery": [], "schedule": [{"phase": "observation", "index": 0, "seconds": 5}]}},
    }
    parent_claim = {
        "campaignId": parent_plan["campaignId"], "manifestDigest": digest(parent_plan),
        "nonceDigest": digest(nonce), "gatePath": str(parent_path),
        "gatePlanDigest": digest(parent_plan), "gateJob": "auth-credential",
        "locks": [{"key": f"project/demo/auth/accounts/{custom_uid}", "mode": "WRITE"}],
        "budget": {"requests": 60, "accounts": 3, "resources": 3, "costMicrousd": 50_000},
        "durationSeconds": 600,
    }
    envelope = {"permissionDigest": "1" * 64, "issuedAt": 900, "expiresAt": 2_000,
        "limits": parent_claim["budget"], "concurrency": 1, "scopes": parent_claim["locks"]}
    ledger = reservations.Ledger.create(tmp_path / "ledger")
    parent_ticket = ledger.reserve(envelope, parent_claim, parent_plan, now=1000)
    parent_path.mkdir(mode=0o700)
    (parent_path / "lock").touch(mode=0o600)
    dead = _dead_pid()
    parent_state = {
        "plan": parent_plan, "planDigest": digest(parent_plan), "started": 1, "total": 1,
        "observation": 1, "recovery": 0, "reservedRecovery": 0, "costMicrousd": 1,
        "lastSent": 1, "stopped": True, "coordinatorPid": dead, "coordinatorDone": 0,
        "managementUsed": [], "managementEvents": [], "managementSkipped": [],
        "managementAbort": None, "coordinatorInflight": False,
        "events": [{"job": "auth-credential", "phase": "observation", "index": 0,
            "requestDigest": digest(operation), "service": "auth", "method": "POST",
            "completed": False, "creationOutcome": "unknown", "ended": 2}],
        "jobs": {"auth-credential": {"resources": [resource], "pid": dead, "stopped": True,
            "inflight": False, "observation": 1, "recovery": 0, "owned": [],
            "creationProofs": {}, "absent": [], "captures": {}, "complete": False, "scheduleDone": 1}},
    }
    _save(parent_path, parent_state)
    child_plan = {
        "contract": "shared-local-v1", "campaignId": parent_plan["campaignId"], "nonce": "b" * 32,
        "project": "demo", "jobSlots": 1, "requestSeconds": 5, "wallSeconds": 60,
        "recoverySeconds": 30, "intervalSeconds": 0.25, "observationRequests": 0,
        "dataRequests": 1, "managementRequests": 0, "recoveryRequests": 1,
        "requestCostMicrousd": 1, "costMicrousd": 1,
        "sourceBindingDigest": "2" * 64, "transportBindingDigest": "3" * 64,
        "o7BindingDigest": "4" * 64, "o8BindingDigest": "5" * 64,
        "jobs": {"auth-recovery": {"resources": [resource], "observation": [], "recovery": [{
            "service": "auth", "method": "POST",
            "path": "identitytoolkit.googleapis.com/v1/projects/demo/accounts:lookup",
            "body": {"localId": ["$binding:customUid"]}, "kind": "uid-absence",
            "account": "custom", "uidBinding": "customUid", "resource": resource,
            "form": False, "owner": True,
        }], "accountBindings": {"custom": {"resource": resource, "uidBinding": "customUid"}},
            "schedule": [{"phase": "recovery", "index": 0, "seconds": 5}]}},
    }
    bindings = {
        "source": {"kind": "auth-source-binding-v1", "digest": "2" * 64},
        "transport": {"kind": "auth-transport-binding-v1", "digest": "3" * 64},
        "o7": {"kind": "auth-o7-binding-v1", "digest": "4" * 64},
        "o8": {"kind": "auth-o8-binding-v1", "digest": "5" * 64},
    }
    evidence = {"kind": "auth-parent-uncertain-create-v1", "gateDigest": digest(parent_state),
        "gatePlanDigest": digest(parent_plan), "job": "auth-credential", "eventIndex": 0,
        "requestDigest": digest(operation), "resource": resource, "completed": False,
        "creationOutcome": "unknown"}
    evidence["evidenceDigest"] = digest(evidence)
    child_claim = {
        "kind": reservations.AUTH_RECOVERY_CHILD_KIND, "version": 1,
        "campaignId": parent_plan["campaignId"], "manifestDigest": digest(child_plan),
        "nonceDigest": digest("b" * 32), "gatePath": str(child_path), "gateJob": "auth-recovery",
        "parentGateJob": "auth-credential",
        "gatePlanDigest": digest(child_plan), "parentClaimDigest": parent_ticket["claimDigest"],
        "parentPlanDigest": digest(parent_plan), "parentGateDigest": evidence["gateDigest"],
        "parentEvidenceDigest": evidence["evidenceDigest"], "parentEventIndex": 0,
        "parentRequestDigest": digest(operation), "recoveryNonce": "b" * 32,
        "resourceDigest": digest([resource]), "ownedResources": [resource],
        "locks": parent_claim["locks"], "budget": {"requests": 1, "accounts": 1, "resources": 1, "costMicrousd": 1},
        "durationSeconds": 60, "generation": {"sourceCommit": "a" * 40,
            "collectorSourceDigest": "6" * 64, "sourceDigests": {"auth-recovery.py": "7" * 64}},
        "ownerIdentity": "owner", "recoveryOwner": "recovery-owner",
        "operationClass": reservations.AUTH_RECOVERY_OPERATION_CLASS, "readCount": 1,
        "inspectionCount": 1, "absenceCount": 1, "deleteCount": 0, "expiresAt": 1_500,
        "executionHost": {"platform": reservations.platform.system().lower(), "machine": reservations.platform.machine()},
        "permissionDigest": "8" * 64, "sourceBindingDigest": bindings["source"]["digest"],
        "transportBindingDigest": bindings["transport"]["digest"], "o7BindingDigest": bindings["o7"]["digest"],
        "o8BindingDigest": bindings["o8"]["digest"],
    }
    child_envelope = {"permissionDigest": child_claim["permissionDigest"], "issuedAt": 900,
        "expiresAt": 2_000, "limits": {"requests": 1, "accounts": 1, "resources": 1, "costMicrousd": 1},
        "concurrency": 1, "scopes": child_claim["locks"]}
    return ledger, parent_ticket, child_claim, child_envelope, child_plan, bindings, evidence, resource, child_path


def _compiler_auth_projection_fixture(tmp_path, *, management_count=0, malformed_management=None, variant_outcome=None, variant_slot=1, foreign_body=False):
    """Build a real compiler plan and Gate journal with a stopped custom create."""
    nonce = "a" * 32
    plan = credential_gate.gate_plan(
        "demo", nonce, signing=True, wall_seconds=600, recovery_seconds=60,
        cost_microusd=50_000, observation_window_seconds=500,
    )
    plan["permissionExpiresAt"] = time.time() + 3_600
    if foreign_body:
        normal_operation = next(
            operation for operation in plan["jobs"]["auth-credential"]["observation"]
            if operation.get("kind") == "custom-sign-in"
            and operation["body"].get("token") == "$binding:customToken"
        )
        normal_operation["body"] = {**normal_operation["body"], "tenantId": "attacker-tenant"}
    resources = plan["jobs"]["auth-credential"]["resources"]
    parent_path = (tmp_path / "compiler-auth-parent-gate").resolve()
    locks = [
        {"key": resource.replace("projects/", "project/"), "mode": "WRITE"}
        for resource in resources
    ]
    claim = {
        "campaignId": plan["campaignId"], "manifestDigest": digest(plan),
        "nonceDigest": digest(nonce), "gatePath": str(parent_path),
        "gatePlanDigest": digest(plan), "gateJob": "auth-credential", "locks": locks,
        "budget": {"requests": 100, "accounts": 3, "resources": 3, "costMicrousd": 50_000},
        "durationSeconds": 600,
    }
    envelope = {
        "permissionDigest": "1" * 64, "issuedAt": 900, "expiresAt": 2_000,
        "limits": claim["budget"], "concurrency": 1, "scopes": locks,
    }
    ledger = reservations.Ledger.create(tmp_path / "compiler-auth-ledger")
    ledger.reserve(envelope, claim, plan, now=1000)
    credential_gate.create(parent_path, plan)
    gate = credential_gate.CredentialGate(parent_path, "auth-credential")
    gate.claim()
    receipt = {
        "status": 200, "complete": True, "workerReaped": True,
        "bodyKind": "json", "body": {},
    }
    attestation = {
        "kind": "request-byte-token-attestation-v1", "principalDigest": "a" * 64,
        "requiredScopeVerified": True, "identityMode": "subject", "identityVerified": True,
        "oauthClientVerified": True, "expiresInSeconds": 600,
        "remainingSecondsAtVerification": 600, "requiredSeconds": 600,
        "complete": True, "workerReaped": True,
    }
    for slot in plan["management"]["observation"][:management_count]:
        result = dict(receipt)
        if slot["id"] == "oauth-tokeninfo":
            result["body"] = attestation
        gate.management_dispatch("observation", slot["id"], lambda _deadline, result=result: result)
    operations = plan["jobs"]["auth-credential"]["observation"]
    signups = [
        (index, operation) for index, operation in enumerate(operations)
        if operation.get("kind") == "sign-up"
    ]
    custom = [
        (index, operation) for index, operation in enumerate(operations)
        if operation.get("kind") == "custom-sign-in"
    ]
    assert len(signups) == 2 and len(custom) == 3
    events = []
    for index, operation in signups:
        events.append({
            "job": "auth-credential", "phase": "observation", "index": index,
            "requestDigest": digest(operation), "service": "auth", "method": "POST",
            "completed": True, "creationOutcome": "refused", "status": 400,
            "failure": None, "authEvidence": {
                "account": operation["account"], "creationOutcome": "refused",
            },
        })
    normal_index, normal_operation = custom[0]
    events.append({
        "job": "auth-credential", "phase": "observation", "index": normal_index,
        "requestDigest": digest(normal_operation), "service": "auth", "method": "POST",
        "completed": False, "creationOutcome": "unknown", "ended": 2,
    })
    schedule_done = normal_index + 1
    if variant_outcome is not None:
        if variant_slot == 2:
            reserved_index, reserved_operation = custom[1]
            events.append({
                "job": "auth-credential", "phase": "observation", "index": reserved_index,
                "requestDigest": digest(reserved_operation), "service": "auth", "method": "POST",
                "completed": True, "creationOutcome": "refused", "status": 400,
                "failure": None, "ended": 2,
                "authEvidence": {"account": "custom", "creationOutcome": "refused"},
            })
        variant_index, variant_operation = custom[variant_slot]
        events.append({
            "job": "auth-credential", "phase": "observation", "index": variant_index,
            "requestDigest": digest(variant_operation), "service": "auth", "method": "POST",
            "completed": variant_outcome == "refused", "creationOutcome": variant_outcome,
            "status": 400 if variant_outcome == "refused" else None,
            "failure": None, "ended": 2,
            "authEvidence": {"account": "custom", "creationOutcome": variant_outcome},
        })
        schedule_done = variant_index + 1
    state = gate.snapshot()
    state["events"] = events
    state["observation"] = management_count + len(events)
    state["total"] = management_count + len(events)
    job = state["jobs"]["auth-credential"]
    job["observation"] = len(events)
    job["scheduleDone"] = schedule_done
    dead = _dead_pid()
    state["coordinatorPid"] = dead
    state["jobs"]["auth-credential"]["pid"] = dead
    state["stopped"] = True
    if malformed_management == "order":
        state["managementUsed"] = list(reversed(state["managementUsed"]))
    elif malformed_management == "event":
        state["managementEvents"][0]["id"] = "observation:wrong" if state["managementEvents"] else "observation:wrong"
    elif malformed_management == "phase":
        if state["managementEvents"]:
            state["managementEvents"][0]["id"] = "recovery:" + state["managementEvents"][0]["id"].split(":", 1)[1]
    _save(parent_path, state)
    child_claim = {
        "parentGateJob": "auth-credential", "parentEventIndex": normal_index,
        "parentRequestDigest": digest(normal_operation), "ownedResources": [normal_operation["resource"]],
    }
    return ledger, parent_path, child_claim


def _full_compiler_auth_recovery_fixture(tmp_path):
    """Bind the real compiler plan to the Ledger child-admission fixture."""
    fixture = _auth_recovery_fixture(tmp_path)
    ledger, parent, child, envelope, child_plan, bindings, _evidence, resource, child_path = fixture
    parent_path = Path(parent["ledgerPath"]).parent / "auth-parent-gate"
    shutil.rmtree(parent_path)
    plan = credential_gate.gate_plan(
        "demo", "a" * 32, signing=True, wall_seconds=600, recovery_seconds=60,
        cost_microusd=50_000, observation_window_seconds=500,
    )
    plan["permissionExpiresAt"] = time.time() + 3_600
    resources = plan["jobs"]["auth-credential"]["resources"]
    locks = [{"key": item.replace("projects/", "project/"), "mode": "WRITE"} for item in resources]
    state = ledger.snapshot()
    row = state["reservations"][parent["reservation"]]
    claim = copy.deepcopy(row["claim"])
    claim.update(
        gatePath=str(parent_path), gatePlanDigest=digest(plan), manifestDigest=digest(plan), locks=locks,
    )
    row["claim"] = claim
    row["claimDigest"] = digest(claim)
    parent["claimDigest"] = row["claimDigest"]
    envelope["scopes"] = locks
    _save(ledger.path, state)
    credential_gate.create(parent_path, plan)
    gate = credential_gate.CredentialGate(parent_path, "auth-credential")
    gate.claim()
    operations = plan["jobs"]["auth-credential"]["observation"]
    signups = [(index, item) for index, item in enumerate(operations) if item.get("kind") == "sign-up"]
    custom = [(index, item) for index, item in enumerate(operations) if item.get("kind") == "custom-sign-in"]
    normal_index, normal_operation = custom[0]
    events = [
        {
            "job": "auth-credential", "phase": "observation", "index": index,
            "requestDigest": digest(operation), "service": "auth", "method": "POST",
            "completed": True, "creationOutcome": "refused", "status": 400, "failure": None,
            "authEvidence": {"account": operation["account"], "creationOutcome": "refused"},
        }
        for index, operation in signups
    ]
    events.append({
        "job": "auth-credential", "phase": "observation", "index": normal_index,
        "requestDigest": digest(normal_operation), "service": "auth", "method": "POST",
        "completed": False, "creationOutcome": "unknown", "ended": 2,
    })
    gate_state = gate.snapshot()
    gate_state["events"] = events
    gate_state["observation"] = len(events)
    gate_state["total"] = len(events)
    gate_state["jobs"]["auth-credential"]["observation"] = len(events)
    gate_state["jobs"]["auth-credential"]["scheduleDone"] = normal_index + 1
    dead = _dead_pid()
    gate_state["coordinatorPid"] = dead
    gate_state["jobs"]["auth-credential"]["pid"] = dead
    gate_state["stopped"] = True
    _save(parent_path, gate_state)
    child["parentClaimDigest"] = parent["claimDigest"]
    child["parentPlanDigest"] = digest(plan)
    child["parentEventIndex"] = normal_index
    child["parentRequestDigest"] = digest(normal_operation)
    child["locks"] = locks
    evidence = reservations._auth_parent_projection(gate_state, child)
    child["parentGateDigest"] = evidence["gateDigest"]
    child["parentEvidenceDigest"] = evidence["evidenceDigest"]
    return ledger, parent, child, envelope, child_plan, bindings, evidence, resource, child_path


def _real_abandoned_compiler_auth_recovery_fixture(tmp_path):
    """Produce the parent journal through a real CredentialGate subprocess."""
    fixture = _auth_recovery_fixture(tmp_path / "template")
    ledger, parent, child, envelope, child_plan, bindings, _evidence, resource, child_path = fixture
    parent_path = Path(parent["ledgerPath"]).parent / "auth-parent-gate"
    shutil.rmtree(parent_path)
    plan = credential_gate.gate_plan(
        "demo", "a" * 32, signing=True, wall_seconds=600, recovery_seconds=60,
        cost_microusd=50_000, observation_window_seconds=500,
    )
    plan["permissionExpiresAt"] = time.time() + 3_600
    resources = plan["jobs"]["auth-credential"]["resources"]
    locks = [{"key": item.replace("projects/", "project/"), "mode": "WRITE"} for item in resources]
    state = ledger.snapshot()
    row = state["reservations"][parent["reservation"]]
    claim = copy.deepcopy(row["claim"])
    claim.update(
        gatePath=str(parent_path), gatePlanDigest=digest(plan),
        manifestDigest=digest(plan), locks=locks,
    )
    row["claim"] = claim
    row["claimDigest"] = digest(claim)
    parent["claimDigest"] = row["claimDigest"]
    envelope["scopes"] = locks
    _save(ledger.path, state)

    child_program = """
import json, sys
from pathlib import Path
sys.path.insert(0, 'tools/compat-broad/auth-credential-tokens')
import credential_gate as c
v = json.loads(sys.stdin.read())
path, plan = Path(v['path']), v['plan']
c.create(path, plan)
g = c.CredentialGate(path)
g.claim()
receipt = {'status': 200, 'complete': True, 'workerReaped': True, 'bodyKind': 'json', 'body': {}}
attestation = {'kind': 'request-byte-token-attestation-v1', 'principalDigest': 'a' * 64,
    'requiredScopeVerified': True, 'identityMode': 'subject', 'identityVerified': True,
    'oauthClientVerified': True, 'expiresInSeconds': 600,
    'remainingSecondsAtVerification': 600, 'requiredSeconds': 600,
    'complete': True, 'workerReaped': True}
for slot in plan['management']['observation']:
    result = dict(receipt)
    if slot['id'] == 'oauth-tokeninfo':
        result['body'] = attestation
    g.management_dispatch('observation', slot['id'], lambda _deadline, result=result: result)
for operation in plan['jobs']['auth-credential']['observation']:
    if operation['kind'] == 'custom-sign-in':
        try:
            g.dispatch(operation, False, lambda: (_ for _ in ()).throw(TimeoutError('controlled response loss')))
        except TimeoutError:
            pass
        break
    body = ({'localId': 'uid-' + operation['account'], 'idToken': 'dummy-id', 'refreshToken': 'dummy-refresh'}
            if operation['kind'] == 'sign-up' else {'error': {'message': 'CONTROLLED_REFUSAL'}})
    status = 200 if operation['kind'] == 'sign-up' else 400
    g.dispatch(operation, False, lambda status=status, body=body: (status, body))
g.abandon_observation('controlled custom uncertainty')
for operation in plan['jobs']['auth-credential']['recovery']:
    if operation['account'] == 'custom':
        break
    body = {} if operation['kind'] == 'delete' else {'kind': 'identitytoolkit#GetAccountInfoResponse', 'users': []}
    g.dispatch(operation, True, lambda body=body: (200, body))
"""
    run = subprocess.run(
        [sys.executable, "-c", child_program],
        input=json.dumps({"path": str(parent_path), "plan": plan}),
        text=True, capture_output=True, check=False,
    )
    assert run.returncode == 0, run.stderr
    gate_state = Gate(parent_path, "auth-credential").snapshot()
    operations = plan["jobs"]["auth-credential"]["observation"]
    normal_index, normal_operation = next(
        (index, operation) for index, operation in enumerate(operations)
        if operation["kind"] == "custom-sign-in"
    )
    assert gate_state["jobs"]["auth-credential"]["scheduleDone"] == 40
    assert gate_state["jobs"]["auth-credential"]["skippedByStop"] == 20
    child.update(
        parentClaimDigest=parent["claimDigest"], parentPlanDigest=digest(plan),
        parentEventIndex=normal_index, parentRequestDigest=digest(normal_operation),
        locks=locks,
    )
    evidence = reservations._auth_parent_projection(gate_state, child)
    child.update(parentGateDigest=evidence["gateDigest"], parentEvidenceDigest=evidence["evidenceDigest"])
    return ledger, parent, child, envelope, child_plan, bindings, evidence, resource, child_path


def _auth_child_gate(path, child_plan, resource, *, body=None, status=200):
    create_gate(path, child_plan)
    gate = Gate(path, "auth-recovery")
    gate.claim()
    operation = child_plan["jobs"]["auth-recovery"]["recovery"][0]
    body = {"kind": "identitytoolkit#GetAccountInfoResponse", "users": []} if body is None else body
    try:
        gate.dispatch(operation, True, lambda: (status, body))
    except ValueError:
        if status == 504 or body.get("users") == []:
            raise
    if status == 200 and body.get("users") == []:
        gate.finish()
        state = gate.snapshot()
        dead = _dead_pid()
        state["coordinatorPid"] = dead
        state["jobs"]["auth-recovery"]["pid"] = dead
        _save(path, state)


def _auth_recovery_fixture_with_unplanned_account(tmp_path):
    fixture = _auth_recovery_fixture(tmp_path)
    ledger, parent, child, envelope, child_plan, bindings, evidence, resource, child_path = fixture
    parent_path = Path(parent["ledgerPath"]).parent / "auth-parent-gate"
    parent_gate = Gate(parent_path, "auth-credential").snapshot()
    parent_gate["jobs"]["auth-credential"]["authAccounts"] = {
        "acct0": {
            "uid": "unexpected-uid",
            "resource": "projects/demo/auth/accounts/unexpected-uid",
        }
    }
    _save(parent_path, parent_gate)
    updated_evidence = reservations._auth_parent_projection(parent_gate, child)
    child["parentGateDigest"] = updated_evidence["gateDigest"]
    child["parentEvidenceDigest"] = updated_evidence["evidenceDigest"]
    return ledger, parent, child, envelope, child_plan, bindings, updated_evidence, resource, child_path


def _auth_recovery_fixture_with_second_creation(tmp_path, *, unknown_kind=False, consumed_missing=False, spoofed_kind=False, query_route=False):
    fixture = _auth_recovery_fixture(tmp_path)
    ledger, parent, child, envelope, child_plan, bindings, evidence, resource, child_path = fixture
    parent_path = Path(parent["ledgerPath"]).parent / "auth-parent-gate"
    parent_gate = Gate(parent_path, "auth-credential").snapshot()
    plan = parent_gate["plan"]
    acct_resource = "projects/demo/auth/accounts/fireemu-cred-aaaaaaaa-0"
    operation = {
        "service": "auth", "method": "POST",
        "path": "identitytoolkit.googleapis.com/v1/accounts:signUp?key=fixture" if query_route else "identitytoolkit.googleapis.com/v1/accounts:signUp",
        "form": False,
        "body": {"email": "fireemu-cred-aaaaaaaa-0@fireemu-credential.invalid", "password": "$binding:password", "returnSecureToken": True},
        "kind": "unrecognized-creating-operation" if unknown_kind else "lookup" if spoofed_kind else "sign-up",
        "account": "acct0", "resource": acct_resource,
        "binds": {"acct0Uid": "localId"},
    }
    plan["jobs"]["auth-credential"]["resources"].append(acct_resource)
    plan["jobs"]["auth-credential"]["observation"].append(operation)
    plan["jobs"]["auth-credential"]["schedule"].append({"phase": "observation", "index": 1, "seconds": 5, "creates": True})
    plan["observationRequests"] = 2
    plan["dataRequests"] = 2
    plan["accountResources"] = [resource, acct_resource]
    claim = copy.deepcopy(ledger.snapshot()["reservations"][parent["reservation"]]["claim"])
    claim["gatePlanDigest"] = digest(plan)
    claim["manifestDigest"] = digest(plan)
    claim["locks"] = claim["locks"] + [{"key": "project/demo/auth/accounts/fireemu-cred-aaaaaaaa-0", "mode": "WRITE"}]
    ledger_state = ledger.snapshot()
    row = ledger_state["reservations"][parent["reservation"]]
    row["claim"] = claim
    row["claimDigest"] = digest(claim)
    parent.update(claimDigest=row["claimDigest"])
    _save(ledger.path, ledger_state)
    envelope["scopes"] = claim["locks"]
    parent_gate["plan"] = plan
    parent_gate["planDigest"] = digest(plan)
    consumed_count = 2 if unknown_kind or consumed_missing or spoofed_kind or query_route else 1
    parent_gate["total"] = consumed_count
    parent_gate["observation"] = consumed_count
    parent_gate["jobs"]["auth-credential"]["resources"] = [resource, acct_resource]
    parent_gate["jobs"]["auth-credential"]["observation"] = consumed_count
    parent_gate["jobs"]["auth-credential"]["scheduleDone"] = 2 if unknown_kind or spoofed_kind or query_route else 1
    if unknown_kind:
        parent_gate["events"].append({
            "job": "auth-credential", "phase": "observation", "index": 1,
            "requestDigest": digest(operation), "service": "auth", "method": "POST",
            "completed": False, "creationOutcome": "unknown", "ended": 2,
        })
    _save(parent_path, parent_gate)
    child["parentPlanDigest"] = digest(plan)
    updated_evidence = reservations._auth_parent_projection(parent_gate, child)
    child.update(
        parentClaimDigest=parent["claimDigest"], parentPlanDigest=digest(plan),
        parentGateDigest=updated_evidence["gateDigest"], parentEvidenceDigest=updated_evidence["evidenceDigest"],
        locks=claim["locks"],
    )
    return ledger, parent, child, envelope, child_plan, bindings, updated_evidence, resource, child_path


def _auth_recovery_fixture_with_two_account_cleanup(tmp_path):
    """Build a persisted Gate with a second created account and cleanup chain."""
    fixture = _auth_recovery_fixture_with_second_creation(tmp_path)
    ledger, parent, child, envelope, child_plan, bindings, evidence, resource, child_path = fixture
    parent_path = Path(parent["ledgerPath"]).parent / "auth-parent-gate"
    parent_gate = Gate(parent_path, "auth-credential").snapshot()
    plan = parent_gate["plan"]
    job_plan = plan["jobs"]["auth-credential"]
    acct_resource = "projects/demo/auth/accounts/fireemu-cred-aaaaaaaa-0"
    delete = {
        "service": "auth", "method": "POST",
        "path": "identitytoolkit.googleapis.com/v1/projects/demo/accounts:delete",
        "body": {"localId": "$binding:acct0Uid"}, "kind": "delete",
        "account": "acct0", "uidBinding": "acct0Uid", "resource": acct_resource,
        "form": False, "owner": True,
    }
    absence = {
        "service": "auth", "method": "POST",
        "path": "identitytoolkit.googleapis.com/v1/projects/demo/accounts:lookup",
        "body": {"localId": ["$binding:acct0Uid"]}, "kind": "uid-absence",
        "account": "acct0", "uidBinding": "acct0Uid", "resource": acct_resource,
        "form": False, "owner": True,
    }
    job_plan["recovery"] = [delete, absence]
    job_plan["schedule"] = [
        {"phase": "observation", "index": 0, "seconds": 5},
        {"phase": "observation", "index": 1, "seconds": 5, "creates": True},
        {"phase": "recovery", "index": 0, "seconds": 5},
        {"phase": "recovery", "index": 1, "seconds": 5},
    ]
    plan["dataRequests"] = 4
    plan["recoveryRequests"] = 2
    claim = copy.deepcopy(ledger.snapshot()["reservations"][parent["reservation"]]["claim"])
    claim["gatePlanDigest"] = digest(plan)
    claim["manifestDigest"] = digest(plan)
    state = ledger.snapshot()
    row = state["reservations"][parent["reservation"]]
    row["claim"] = claim
    row["claimDigest"] = digest(claim)
    parent.update(claimDigest=row["claimDigest"])
    _save(ledger.path, state)
    envelope["scopes"] = claim["locks"]
    parent_gate["plan"] = plan
    parent_gate["planDigest"] = digest(plan)
    parent_gate["total"] = 4
    parent_gate["observation"] = 2
    parent_gate["recovery"] = 2
    parent_gate["jobs"]["auth-credential"].update(
        resources=[resource, acct_resource], observation=2, recovery=2, scheduleDone=4,
        authAccounts={
            "acct0": {
                "uid": "acct0-uid", "resource": acct_resource,
                "createEvent": 1, "deleteEvent": 2, "absenceEvent": 3,
            }
        },
        absenceProofs={
            acct_resource: {
                "body": {"kind": "identitytoolkit#GetAccountInfoResponse", "users": []},
                "eventIndex": 3,
            }
        },
    )
    job = parent_gate["jobs"]["auth-credential"]
    parent_gate["events"] = [
        parent_gate["events"][0],
        {
            "job": "auth-credential", "phase": "observation", "index": 1,
            "requestDigest": digest(job_plan["observation"][1]), "service": "auth", "method": "POST",
            "completed": True, "creationOutcome": "created", "status": 200, "ended": 2,
            "authEvidence": {"account": "acct0", "uid": "acct0-uid", "creationOutcome": "created"},
        },
        {
            "job": "auth-credential", "phase": "recovery", "index": 0,
            "requestDigest": digest(delete), "service": "auth", "method": "POST",
            "completed": True, "failure": None, "status": 200, "responseDigest": digest({}),
            "authEvidence": {"account": "acct0", "responseDigest": digest({}), "body": {}},
        },
        {
            "job": "auth-credential", "phase": "recovery", "index": 1,
            "requestDigest": digest(absence), "service": "auth", "method": "POST",
            "completed": True, "failure": None, "status": 200,
            "responseDigest": digest({"kind": "identitytoolkit#GetAccountInfoResponse", "users": []}),
            "authEvidence": {
                "account": "acct0", "body": {"kind": "identitytoolkit#GetAccountInfoResponse", "users": []},
                "responseDigest": digest({"kind": "identitytoolkit#GetAccountInfoResponse", "users": []}),
            },
        },
    ]
    _save(parent_path, parent_gate)
    child["parentPlanDigest"] = digest(plan)
    updated_evidence = reservations._auth_parent_projection(parent_gate, child)
    child.update(
        parentClaimDigest=parent["claimDigest"], parentPlanDigest=digest(plan),
        parentGateDigest=updated_evidence["gateDigest"], parentEvidenceDigest=updated_evidence["evidenceDigest"],
        locks=claim["locks"],
    )
    return ledger, parent, child, envelope, child_plan, bindings, updated_evidence, resource, child_path


def _settle_auth_child_for_fixture(ledger, parent, child, envelope, child_plan, bindings, evidence, resource, child_path):
    child_ticket = ledger.begin_auth_recovery_extension(parent, child, envelope, child_plan,
        source_binding=bindings["source"], transport_binding=bindings["transport"],
        o7_binding=bindings["o7"], o8_binding=bindings["o8"], parent_evidence=evidence, now=1000)
    _auth_child_gate(child_path, child_plan, resource)
    body = {"kind": "identitytoolkit#GetAccountInfoResponse", "users": []}
    proof = {"kind": "auth-uid-absence-proof-v1", "resource": resource, "status": 200,
        "bodyShape": body, "bodyDigest": digest(body), "responseDigest": digest(body), "eventIndex": 0,
        "requestDigest": digest(child_plan["jobs"]["auth-recovery"]["recovery"][0])}
    ledger.settle_auth_recovery_child(child_ticket, absence_proof=proof,
        receipt_digest=digest(proof), now=1000)
    return child_ticket, proof


def _fresh_auth_reservation_after_close(ledger, parent, envelope, tmp_path):
    fresh_claim = copy.deepcopy(ledger.snapshot()["reservations"][parent["reservation"]]["claim"])
    fresh_gate_plan = copy.deepcopy(json.loads((Path(parent["ledgerPath"]).parent / "auth-parent-gate" / "state.json").read_text())["plan"])
    fresh_gate_plan["nonce"] = "c" * 32
    fresh_claim["gatePath"] = str((tmp_path / "fresh-auth-parent-gate").resolve())
    fresh_claim["manifestDigest"] = digest(fresh_gate_plan)
    fresh_claim["gatePlanDigest"] = digest(fresh_gate_plan)
    fresh_claim["nonceDigest"] = digest(fresh_gate_plan["nonce"])
    fresh_envelope = copy.deepcopy(envelope)
    fresh_envelope["permissionDigest"] = "2" * 64
    fresh_envelope["scopes"] = fresh_claim["locks"]
    fresh_envelope["limits"] = copy.deepcopy(fresh_claim["budget"])
    return ledger.reserve(fresh_envelope, fresh_claim, fresh_gate_plan, now=1000)


def test_auth_recovery_child_is_durable_lookup_only_and_closes_parent_on_typed_absence(tmp_path):
    ledger, parent, child, envelope, child_plan, bindings, evidence, resource, child_path = _auth_recovery_fixture(tmp_path)
    child_ticket = ledger.begin_auth_recovery_extension(parent, child, envelope, child_plan,
        source_binding=bindings["source"], transport_binding=bindings["transport"],
        o7_binding=bindings["o7"], o8_binding=bindings["o8"], parent_evidence=evidence, now=1000)
    assert ledger.snapshot()["reservations"][parent["reservation"]]["recoveryChildren"][0]["state"] == "allocated"
    _auth_child_gate(child_path, child_plan, resource)
    body = {"kind": "identitytoolkit#GetAccountInfoResponse", "users": []}
    proof = {"kind": "auth-uid-absence-proof-v1", "resource": resource, "status": 200,
        "bodyShape": body, "bodyDigest": digest(body), "responseDigest": digest(body), "eventIndex": 0,
        "requestDigest": digest(child_plan["jobs"]["auth-recovery"]["recovery"][0])}
    assert ledger.settle_auth_recovery_child(child_ticket, absence_proof=proof,
        receipt_digest=digest(proof), now=1000) == child_ticket
    assert ledger.close_after_auth_recovery_child(parent, child_ticket,
        receipt_digest=digest(proof), now=1000) == parent
    assert ledger.snapshot()["reservations"][parent["reservation"]]["state"] == "closed-after-auth-recovery-child"
    assert len(ledger.snapshot()["reservations"][parent["reservation"]]["authRecoveryCloseResponsibilitiesDigest"]) == 64


def test_auth_recovery_allocation_runs_full_parent_responsibility_preflight(tmp_path, monkeypatch):
    fixture = _auth_recovery_fixture(tmp_path)
    ledger, parent, child, envelope, child_plan, bindings, evidence, _resource, _child_path = fixture
    calls = []
    original = reservations._auth_parent_responsibility_projection

    def traced(gate, child_claim):
        calls.append((gate, child_claim))
        return original(gate, child_claim)

    monkeypatch.setattr(reservations, "_auth_parent_responsibility_projection", traced)
    ledger.begin_auth_recovery_extension(
        parent, child, envelope, child_plan,
        source_binding=bindings["source"], transport_binding=bindings["transport"],
        o7_binding=bindings["o7"], o8_binding=bindings["o8"],
        parent_evidence=evidence, now=1000,
    )
    assert len(calls) == 1


def test_full_compiler_custom_token_parent_begins_and_settles(tmp_path):
    fixture = _full_compiler_auth_recovery_fixture(tmp_path)
    ledger, parent, child, envelope, child_plan, bindings, evidence, resource, child_path = fixture
    child_ticket = ledger.begin_auth_recovery_extension(
        parent, child, envelope, child_plan,
        source_binding=bindings["source"], transport_binding=bindings["transport"],
        o7_binding=bindings["o7"], o8_binding=bindings["o8"],
        parent_evidence=evidence, now=1000,
    )
    _auth_child_gate(child_path, child_plan, resource)
    body = {"kind": "identitytoolkit#GetAccountInfoResponse", "users": []}
    proof = {
        "kind": "auth-uid-absence-proof-v1", "resource": resource, "status": 200,
        "bodyShape": body, "bodyDigest": digest(body), "responseDigest": digest(body),
        "eventIndex": 0, "requestDigest": digest(child_plan["jobs"]["auth-recovery"]["recovery"][0]),
    }
    ledger.settle_auth_recovery_child(child_ticket, absence_proof=proof,
        receipt_digest=digest(proof), now=1000)
    assert ledger.snapshot()["reservations"][parent["reservation"]]["recoveryChildren"][0]["state"] == "settled"


def test_real_compiler_abandonment_closes_parent_and_reopens_ledger(tmp_path):
    fixture = _real_abandoned_compiler_auth_recovery_fixture(tmp_path)
    ledger, parent, child, envelope, child_plan, bindings, evidence, resource, child_path = fixture
    child_ticket, proof = _settle_auth_child_for_fixture(
        ledger, parent, child, envelope, child_plan, bindings, evidence, resource, child_path,
    )
    assert ledger.close_after_auth_recovery_child(
        parent, child_ticket, receipt_digest=digest(proof), now=1000,
    ) == parent
    reopened = reservations.Ledger(ledger.path)
    fresh = _fresh_auth_reservation_after_close(reopened, parent, envelope, tmp_path)
    assert fresh["reservation"] != parent["reservation"]
    assert reopened.close_after_auth_recovery_child(
        parent, child_ticket, receipt_digest=digest(proof), now=1000,
    ) == parent


@pytest.mark.parametrize("control", ["missing-stop", "wrong-cursor"])
def test_real_compiler_abandonment_evidence_controls_refuse(tmp_path, control):
    fixture = _real_abandoned_compiler_auth_recovery_fixture(tmp_path)
    _ledger, _parent, child, _envelope, _child_plan, _bindings, _evidence, _resource, child_path = fixture
    gate_path = Path(child_path).parent / "auth-parent-gate"
    gate_state = Gate(gate_path, "auth-credential").snapshot()
    job = gate_state["jobs"]["auth-credential"]
    if control == "missing-stop":
        job.pop("stopReason", None)
    else:
        job["skippedByStop"] = 19
    _save(gate_path, gate_state)
    with pytest.raises(ValueError, match="stop"):
        reservations._auth_parent_responsibility_projection(gate_state, child)


def test_real_compiler_prior_uncertain_create_is_not_a_skipped_suffix(tmp_path):
    fixture = _real_abandoned_compiler_auth_recovery_fixture(tmp_path)
    _ledger, _parent, child, _envelope, _child_plan, _bindings, _evidence, _resource, child_path = fixture
    gate_path = Path(child_path).parent / "auth-parent-gate"
    gate_state = Gate(gate_path, "auth-credential").snapshot()
    plan = gate_state["plan"]["jobs"]["auth-credential"]
    index, operation = next(
        (index, operation) for index, operation in enumerate(plan["observation"])
        if operation.get("kind") == "custom-sign-in"
        and operation.get("body", {}).get("token") == "$binding:customTokenReserved"
    )
    gate_state["events"].append({
        "job": "auth-credential", "phase": "observation", "index": index,
        "requestDigest": digest(operation), "service": "auth", "method": "POST",
        "completed": False, "creationOutcome": "unknown", "ended": 2,
    })
    gate_state["observation"] += 1
    gate_state["total"] += 1
    job = gate_state["jobs"]["auth-credential"]
    job["observation"] += 1
    job["skippedByStop"] -= 1
    _save(gate_path, gate_state)
    with pytest.raises(ValueError, match="unresolved"):
        reservations._auth_parent_responsibility_projection(gate_state, child)


@pytest.mark.parametrize("management_count", [0, 1, 3])
def test_auth_parent_projection_counts_validated_management_observations(tmp_path, management_count):
    ledger, parent_path, child_claim = _compiler_auth_projection_fixture(
        tmp_path, management_count=management_count,
    )
    gate = Gate(parent_path, "auth-credential").snapshot()
    projection = reservations._auth_parent_responsibility_projection(gate, child_claim)
    assert projection["kind"] == "auth-parent-responsibility-close-v1"
    assert gate["observation"] == management_count + gate["jobs"]["auth-credential"]["observation"]
    assert ledger.snapshot()["reservations"]


@pytest.mark.parametrize("malformed_management,management_count", [("order", 2), ("event", 1), ("phase", 1)])
def test_auth_parent_projection_rejects_malformed_management_journal(tmp_path, malformed_management, management_count):
    _ledger, parent_path, child_claim = _compiler_auth_projection_fixture(
        tmp_path, management_count=management_count, malformed_management=malformed_management,
    )
    gate = Gate(parent_path, "auth-credential").snapshot()
    with pytest.raises(ValueError, match="management"):
        reservations._auth_parent_responsibility_projection(gate, child_claim)


def test_auth_parent_projection_accepts_compiler_custom_token_negative_slots(tmp_path):
    _ledger, parent_path, child_claim = _compiler_auth_projection_fixture(tmp_path)
    gate = Gate(parent_path, "auth-credential").snapshot()
    projection = reservations._auth_parent_responsibility_projection(gate, child_claim)
    dispositions = {
        (item["phase"], item["index"]): item["disposition"]
        for item in projection["responsibilities"]
    }
    custom = [
        index for index, operation in enumerate(gate["plan"]["jobs"]["auth-credential"]["observation"])
        if operation.get("kind") == "custom-sign-in"
    ]
    assert dispositions[("observation", custom[1])] == "not-dispatched"
    assert dispositions[("observation", custom[2])] == "not-dispatched"


@pytest.mark.parametrize("variant_slot", [1, 2])
def test_auth_parent_projection_accepts_typed_custom_token_refusal(tmp_path, variant_slot):
    _ledger, parent_path, child_claim = _compiler_auth_projection_fixture(
        tmp_path, variant_outcome="refused", variant_slot=variant_slot,
    )
    gate = Gate(parent_path, "auth-credential").snapshot()
    projection = reservations._auth_parent_responsibility_projection(gate, child_claim)
    custom = [
        index for index, operation in enumerate(gate["plan"]["jobs"]["auth-credential"]["observation"])
        if operation.get("kind") == "custom-sign-in"
    ]
    dispositions = {
        (item["phase"], item["index"]): item["disposition"]
        for item in projection["responsibilities"]
    }
    assert dispositions[("observation", custom[1])] == "refused"


@pytest.mark.parametrize("variant_slot", [1, 2])
def test_auth_parent_projection_retains_unresolved_custom_token_responsibility(tmp_path, variant_slot):
    _ledger, parent_path, child_claim = _compiler_auth_projection_fixture(
        tmp_path, variant_outcome="unknown", variant_slot=variant_slot,
    )
    gate = Gate(parent_path, "auth-credential").snapshot()
    with pytest.raises(ValueError, match="creating event unresolved"):
        reservations._auth_parent_responsibility_projection(gate, child_claim)


def test_auth_parent_projection_rejects_foreign_custom_token_body(tmp_path):
    _ledger, parent_path, child_claim = _compiler_auth_projection_fixture(tmp_path, foreign_body=True)
    gate = Gate(parent_path, "auth-credential").snapshot()
    with pytest.raises(ValueError, match="creating operation semantics"):
        reservations._auth_parent_responsibility_projection(gate, child_claim)


def test_valid_auth_recovery_close_releases_parent_lock_for_new_reservation(tmp_path):
    ledger, parent, child, envelope, child_plan, bindings, evidence, resource, child_path = _auth_recovery_fixture(tmp_path)
    child_ticket = ledger.begin_auth_recovery_extension(parent, child, envelope, child_plan,
        source_binding=bindings["source"], transport_binding=bindings["transport"],
        o7_binding=bindings["o7"], o8_binding=bindings["o8"], parent_evidence=evidence, now=1000)
    _auth_child_gate(child_path, child_plan, resource)
    body = {"kind": "identitytoolkit#GetAccountInfoResponse", "users": []}
    proof = {"kind": "auth-uid-absence-proof-v1", "resource": resource, "status": 200,
        "bodyShape": body, "bodyDigest": digest(body), "responseDigest": digest(body), "eventIndex": 0,
        "requestDigest": digest(child_plan["jobs"]["auth-recovery"]["recovery"][0])}
    ledger.settle_auth_recovery_child(child_ticket, absence_proof=proof,
        receipt_digest=digest(proof), now=1000)
    ledger.close_after_auth_recovery_child(parent, child_ticket,
        receipt_digest=digest(proof), now=1000)

    fresh_plan = copy.deepcopy(ledger.snapshot()["reservations"][parent["reservation"]]["claim"])
    fresh_gate_plan = copy.deepcopy(json.loads((Path(parent["ledgerPath"]) / ".." / "auth-parent-gate" / "state.json").read_text())["plan"])
    fresh_gate_plan["nonce"] = "c" * 32
    fresh_claim = copy.deepcopy(fresh_plan)
    fresh_claim["gatePath"] = str((tmp_path / "fresh-auth-parent-gate").resolve())
    fresh_claim["manifestDigest"] = digest(fresh_gate_plan)
    fresh_claim["gatePlanDigest"] = digest(fresh_gate_plan)
    fresh_claim["nonceDigest"] = digest(fresh_gate_plan["nonce"])
    fresh_envelope = copy.deepcopy(envelope)
    fresh_envelope["permissionDigest"] = "2" * 64
    fresh_envelope["scopes"] = fresh_claim["locks"]
    fresh_envelope["limits"] = copy.deepcopy(fresh_claim["budget"])
    assert ledger.reserve(fresh_envelope, fresh_claim, fresh_gate_plan, now=1000)


def test_auth_recovery_close_refuses_unplanned_parent_account_without_mutating_ledger(tmp_path):
    ledger, parent, child, envelope, child_plan, bindings, evidence, resource, child_path = _auth_recovery_fixture_with_unplanned_account(tmp_path)
    before = ledger.snapshot()
    with pytest.raises(ValueError, match="Auth parent responsibility"):
        ledger.begin_auth_recovery_extension(parent, child, envelope, child_plan,
            source_binding=bindings["source"], transport_binding=bindings["transport"],
            o7_binding=bindings["o7"], o8_binding=bindings["o8"], parent_evidence=evidence, now=1000)
    assert ledger.snapshot() == before


def test_auth_recovery_close_refuses_missing_consumed_signup_event(tmp_path):
    fixture = _auth_recovery_fixture_with_second_creation(tmp_path, consumed_missing=True)
    ledger, parent, child, envelope, child_plan, bindings, evidence, resource, child_path = fixture
    before = ledger.snapshot()
    with pytest.raises(ValueError, match="creating event missing|responsibility"):
        ledger.begin_auth_recovery_extension(parent, child, envelope, child_plan,
            source_binding=bindings["source"], transport_binding=bindings["transport"],
            o7_binding=bindings["o7"], o8_binding=bindings["o8"], parent_evidence=evidence, now=1000)
    assert ledger.snapshot() == before


def test_auth_recovery_close_accepts_canonical_undispatched_signup(tmp_path):
    fixture = _auth_recovery_fixture_with_second_creation(tmp_path)
    ledger, parent, child, envelope, child_plan, bindings, evidence, resource, child_path = fixture
    child_ticket, proof = _settle_auth_child_for_fixture(*fixture)
    assert ledger.close_after_auth_recovery_child(parent, child_ticket,
        receipt_digest=digest(proof), now=1000) == parent


def test_auth_recovery_close_accepts_persisted_two_account_cleanup(tmp_path):
    fixture = _auth_recovery_fixture_with_two_account_cleanup(tmp_path)
    ledger, parent, child, envelope, child_plan, bindings, evidence, resource, child_path = fixture
    child_ticket, proof = _settle_auth_child_for_fixture(*fixture)
    assert ledger.close_after_auth_recovery_child(parent, child_ticket,
        receipt_digest=digest(proof), now=1000) == parent
    row = ledger.snapshot()["reservations"][parent["reservation"]]
    assert row["state"] == "closed-after-auth-recovery-child"
    assert len(row["authRecoveryCloseResponsibilitiesDigest"]) == 64


def test_auth_recovery_close_refuses_unknown_creating_operation_and_retains_lock(tmp_path):
    fixture = _auth_recovery_fixture_with_second_creation(tmp_path, unknown_kind=True)
    ledger, parent, child, envelope, child_plan, bindings, evidence, resource, child_path = fixture
    before = ledger.snapshot()
    with pytest.raises(ValueError, match="creating|responsibility"):
        ledger.begin_auth_recovery_extension(parent, child, envelope, child_plan,
            source_binding=bindings["source"], transport_binding=bindings["transport"],
            o7_binding=bindings["o7"], o8_binding=bindings["o8"], parent_evidence=evidence, now=1000)
    assert ledger.snapshot() == before
    with pytest.raises(ValueError, match="production resource lock conflict"):
        _fresh_auth_reservation_after_close(ledger, parent, envelope, tmp_path)


def test_auth_recovery_close_refuses_spoofed_lookup_kind_for_signup_route(tmp_path):
    fixture = _auth_recovery_fixture_with_second_creation(tmp_path, spoofed_kind=True)
    ledger, parent, child, envelope, child_plan, bindings, evidence, resource, child_path = fixture
    before = ledger.snapshot()
    with pytest.raises(ValueError, match="operation semantics"):
        ledger.begin_auth_recovery_extension(parent, child, envelope, child_plan,
            source_binding=bindings["source"], transport_binding=bindings["transport"],
            o7_binding=bindings["o7"], o8_binding=bindings["o8"], parent_evidence=evidence, now=1000)
    assert ledger.snapshot() == before


def test_auth_recovery_close_refuses_query_bearing_signup_route(tmp_path):
    fixture = _auth_recovery_fixture_with_second_creation(tmp_path, query_route=True)
    ledger, parent, child, envelope, child_plan, bindings, evidence, resource, child_path = fixture
    before = ledger.snapshot()
    with pytest.raises(ValueError, match="observation operation semantics"):
        ledger.begin_auth_recovery_extension(parent, child, envelope, child_plan,
            source_binding=bindings["source"], transport_binding=bindings["transport"],
            o7_binding=bindings["o7"], o8_binding=bindings["o8"], parent_evidence=evidence, now=1000)
    assert ledger.snapshot() == before


def test_legacy_auth_recovery_close_without_projection_digest_retains_lock(tmp_path):
    fixture = _auth_recovery_fixture(tmp_path)
    ledger, parent, child, envelope, child_plan, bindings, evidence, resource, child_path = fixture
    child_ticket, proof = _settle_auth_child_for_fixture(*fixture)
    assert ledger.close_after_auth_recovery_child(parent, child_ticket,
        receipt_digest=digest(proof), now=1000) == parent
    state = ledger.snapshot()
    row = state["reservations"][parent["reservation"]]
    row.pop("authRecoveryCloseResponsibilitiesDigest", None)
    _save(ledger.path, state)
    with pytest.raises(ValueError, match="production resource lock conflict"):
        _fresh_auth_reservation_after_close(ledger, parent, envelope, tmp_path)


def _settled_auth_recovery(tmp_path):
    ledger, parent, child, envelope, child_plan, bindings, evidence, resource, child_path = _auth_recovery_fixture(tmp_path)
    child_ticket = ledger.begin_auth_recovery_extension(
        parent, child, envelope, child_plan,
        source_binding=bindings["source"], transport_binding=bindings["transport"],
        o7_binding=bindings["o7"], o8_binding=bindings["o8"],
        parent_evidence=evidence, now=1000,
    )
    _auth_child_gate(child_path, child_plan, resource)
    body = {"kind": "identitytoolkit#GetAccountInfoResponse", "users": []}
    proof = {
        "kind": "auth-uid-absence-proof-v1", "resource": resource, "status": 200,
        "bodyShape": body, "bodyDigest": digest(body), "responseDigest": digest(body),
        "eventIndex": 0,
        "requestDigest": digest(child_plan["jobs"]["auth-recovery"]["recovery"][0]),
    }
    ledger.settle_auth_recovery_child(
        child_ticket, absence_proof=proof, receipt_digest=digest(proof), now=1000,
    )
    return ledger, parent, child_ticket, proof, child_path


def test_auth_recovery_settlement_rejects_parent_race_after_gate_validation(tmp_path, monkeypatch):
    ledger, parent, child_ticket, proof, child_path = _settled_auth_recovery(tmp_path)
    # A second child ticket is not needed: mutate the held parent after the
    # external Gate snapshot and before the settlement critical section.
    state = ledger.snapshot()
    state["reservations"][parent["reservation"]]["state"] = "held"
    reservations._save(ledger.path, state)
    original_snapshot = reservations.Gate.snapshot

    def race_snapshot(gate):
        snapshot = original_snapshot(gate)
        if gate.path == child_path:
            raced = ledger.snapshot()
            raced["reservations"][parent["reservation"]]["state"] = "closed-after-auth-recovery-child"
            reservations._save(ledger.path, raced)
        return snapshot

    monkeypatch.setattr(reservations.Gate, "snapshot", race_snapshot)
    with pytest.raises(ValueError, match="changed during settlement"):
        ledger.settle_auth_recovery_child(
            child_ticket, absence_proof=proof, receipt_digest=digest(proof), now=1000,
        )


def test_auth_recovery_close_rejects_parent_race_after_child_gate_validation(tmp_path, monkeypatch):
    ledger, parent, child_ticket, proof, child_path = _settled_auth_recovery(tmp_path)
    original_snapshot = reservations.Gate.snapshot

    def race_snapshot(gate):
        snapshot = original_snapshot(gate)
        if gate.path == child_path:
            raced = ledger.snapshot()
            raced["reservations"][parent["reservation"]]["state"] = "closed-after-auth-recovery-child"
            reservations._save(ledger.path, raced)
        return snapshot

    monkeypatch.setattr(reservations.Gate, "snapshot", race_snapshot)
    with pytest.raises(ValueError, match="Auth parent changed during close"):
        ledger.close_after_auth_recovery_child(
            parent, child_ticket, receipt_digest=digest(proof), now=1000,
        )


@pytest.mark.parametrize("mutation", [
    (200, {"kind": "identitytoolkit#GetAccountInfoResponse", "users": [{"localId": "foreign"}]}),
    (200, {"users": "malformed"}), (504, {}),
])
def test_auth_recovery_child_keeps_parent_held_for_non_absent_result(tmp_path, mutation):
    ledger, parent, child, envelope, child_plan, bindings, evidence, resource, child_path = _auth_recovery_fixture(tmp_path)
    child_ticket = ledger.begin_auth_recovery_extension(parent, child, envelope, child_plan,
        source_binding=bindings["source"], transport_binding=bindings["transport"],
        o7_binding=bindings["o7"], o8_binding=bindings["o8"], parent_evidence=evidence, now=1000)
    status, body = mutation
    _auth_child_gate(child_path, child_plan, resource, body=body, status=status)
    proof = {"kind": "auth-uid-absence-proof-v1", "resource": resource, "status": status,
        "bodyShape": body, "bodyDigest": digest(body), "responseDigest": digest(body), "eventIndex": 0,
        "requestDigest": digest(child_plan["jobs"]["auth-recovery"]["recovery"][0])}
    before = ledger.snapshot()
    with pytest.raises(ValueError, match="typed Auth absence"):
        ledger.settle_auth_recovery_child(child_ticket, absence_proof=proof,
            receipt_digest=digest(proof), now=1000)
    assert ledger.snapshot() == before


@pytest.mark.parametrize("path", [
    "https://attacker.example/accounts:lookup",
    "identitytoolkit.googleapis.com/v1/projects/foreign/accounts:lookup",
    "identitytoolkit.googleapis.com/v1/projects/demo/accounts:lookup?key=leak",
])
def test_auth_recovery_rejects_lookup_route_escape(tmp_path, path):
    ledger, parent, child, envelope, child_plan, bindings, evidence, _resource, _ = _auth_recovery_fixture(tmp_path)
    escaped_plan = copy.deepcopy(child_plan)
    escaped_plan["jobs"]["auth-recovery"]["recovery"][0]["path"] = path
    escaped_child = copy.deepcopy(child)
    escaped_child["manifestDigest"] = digest(escaped_plan)
    escaped_child["gatePlanDigest"] = digest(escaped_plan)
    with pytest.raises(ValueError, match="Auth recovery operation"):
        ledger.begin_auth_recovery_extension(
            parent, escaped_child, envelope, escaped_plan,
            source_binding=bindings["source"], transport_binding=bindings["transport"],
            o7_binding=bindings["o7"], o8_binding=bindings["o8"],
            parent_evidence=evidence, now=1000,
        )


def test_auth_recovery_rejects_gate_cost_above_child_budget(tmp_path):
    ledger, parent, child, envelope, child_plan, bindings, evidence, _resource, _ = _auth_recovery_fixture(tmp_path)
    expensive_plan = copy.deepcopy(child_plan)
    expensive_plan["costMicrousd"] = 100_000
    expensive_plan["requestCostMicrousd"] = 100_000
    expensive_child = copy.deepcopy(child)
    expensive_child["manifestDigest"] = digest(expensive_plan)
    expensive_child["gatePlanDigest"] = digest(expensive_plan)
    with pytest.raises(ValueError, match="Auth recovery Gate cost exceeds child budget"):
        ledger.begin_auth_recovery_extension(
            parent, expensive_child, envelope, expensive_plan,
            source_binding=bindings["source"], transport_binding=bindings["transport"],
            o7_binding=bindings["o7"], o8_binding=bindings["o8"],
            parent_evidence=evidence, now=1000,
        )


def test_auth_recovery_allows_compiled_gate_cost_within_child_budget(tmp_path):
    ledger, parent, child, envelope, child_plan, bindings, evidence, resource, child_path = _auth_recovery_fixture(tmp_path)
    funded_child = copy.deepcopy(child)
    funded_child["budget"]["costMicrousd"] = 50_000
    funded_envelope = copy.deepcopy(envelope)
    funded_envelope["limits"]["costMicrousd"] = 50_000
    child_ticket = ledger.begin_auth_recovery_extension(
        parent, funded_child, funded_envelope, child_plan,
        source_binding=bindings["source"], transport_binding=bindings["transport"],
        o7_binding=bindings["o7"], o8_binding=bindings["o8"],
        parent_evidence=evidence, now=1000,
    )
    # Exercise the real shared Gate compiler/validator with the lower-cost
    # one-request plan instead of a hand-written terminal state.
    _auth_child_gate(child_path, child_plan, resource)
    assert ledger.bound_auth_recovery_claim(child_ticket)["state"] == "allocated"


def test_auth_recovery_rejects_parent_change_between_gate_check_and_append(tmp_path, monkeypatch):
    ledger, parent, child, envelope, child_plan, bindings, evidence, _resource, _ = _auth_recovery_fixture(tmp_path)
    original_snapshot = reservations.Gate.snapshot

    def race_snapshot(gate):
        snapshot = original_snapshot(gate)
        state = ledger.snapshot()
        state["reservations"][parent["reservation"]]["state"] = "closing"
        reservations._save(ledger.path, state)
        return snapshot

    monkeypatch.setattr(reservations.Gate, "snapshot", race_snapshot)
    with pytest.raises(ValueError, match="parent changed during Auth recovery admission"):
        ledger.begin_auth_recovery_extension(
            parent, child, envelope, child_plan,
            source_binding=bindings["source"], transport_binding=bindings["transport"],
            o7_binding=bindings["o7"], o8_binding=bindings["o8"],
            parent_evidence=evidence, now=1000,
        )
    assert ledger.snapshot()["reservations"][parent["reservation"]]["state"] == "closing"


def test_auth_recovery_rejects_forged_other_parent_event_digest(tmp_path):
    ledger, parent, child, envelope, child_plan, bindings, evidence, _resource, _ = _auth_recovery_fixture(tmp_path)
    parent_gate_path = (tmp_path / "auth-parent-gate").resolve()
    parent_gate = Gate(parent_gate_path, "auth-credential").snapshot()
    operation = parent_gate["plan"]["jobs"]["auth-credential"]["observation"][0]
    other_operation = copy.deepcopy(operation)
    other_operation["path"] = "identitytoolkit.googleapis.com/v1/accounts:signInWithPassword"
    forged_digest = digest(other_operation)
    parent_gate["events"][0]["requestDigest"] = forged_digest
    _save(parent_gate_path, parent_gate)

    forged_evidence = copy.deepcopy(evidence)
    forged_evidence["gateDigest"] = digest(parent_gate)
    forged_evidence["requestDigest"] = forged_digest
    forged_evidence.pop("evidenceDigest")
    forged_evidence["evidenceDigest"] = digest(forged_evidence)
    forged_child = copy.deepcopy(child)
    forged_child["parentGateDigest"] = forged_evidence["gateDigest"]
    forged_child["parentEvidenceDigest"] = forged_evidence["evidenceDigest"]
    forged_child["parentRequestDigest"] = forged_digest
    with pytest.raises(ValueError, match="Auth parent custom create is not uncertain"):
        ledger.begin_auth_recovery_extension(
            parent, forged_child, envelope, child_plan,
            source_binding=bindings["source"], transport_binding=bindings["transport"],
            o7_binding=bindings["o7"], o8_binding=bindings["o8"],
            parent_evidence=forged_evidence, now=1000,
        )


def test_real_compiler_stop_suffix_with_recorded_event_is_refused(tmp_path):
    """An event inside the stop journal's abandoned suffix contradicts the stop.

    Every count still agrees, so only the slot comparison can catch it. Review
    R8D-01 found that comparison matching ``(phase, index)`` against the
    ``(job, phase, index)`` event keys, so it never fired.
    """
    fixture = _real_abandoned_compiler_auth_recovery_fixture(tmp_path)
    _ledger, _parent, child, _envelope, _child_plan, _bindings, _evidence, _resource, child_path = fixture
    gate_path = Path(child_path).parent / "auth-parent-gate"
    gate_state = Gate(gate_path, "auth-credential").snapshot()
    operations = gate_state["plan"]["jobs"]["auth-credential"]["observation"]
    job = gate_state["jobs"]["auth-credential"]
    cursor = job["observation"]

    def non_creating(index):
        return operations[index].get("kind") not in {"sign-up", "custom-sign-in"}

    event = next(
        event for event in reversed(gate_state["events"])
        if event["job"] == "auth-credential" and event["phase"] == "observation"
        and event["index"] < cursor and non_creating(event["index"])
    )
    target = next(
        index for index in range(cursor, cursor + job["skippedByStop"]) if non_creating(index)
    )
    event.update(
        index=target, requestDigest=digest(operations[target]),
        service=operations[target]["service"], method=operations[target]["method"],
    )
    _save(gate_path, gate_state)
    with pytest.raises(ValueError, match="stop journal has an event"):
        reservations._auth_parent_responsibility_projection(gate_state, child)
