"""Read-only evidence and recovery-allocation contract tests."""

import json
import multiprocessing
import os
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "fs-request-bytes-boundary"))
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
        "body": {"token": "$binding:customToken"},
        "kind": "custom-sign-in",
        "account": "custom",
        "resource": resource,
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
            "requestDigest": digest(operation), "completed": False, "creationOutcome": "unknown", "ended": 2}],
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
            "body": {"localId": [custom_uid]}, "kind": "auth-custom-uid-lookup", "resource": resource,
        }], "schedule": [{"phase": "recovery", "index": 0, "seconds": 5}]}},
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


def _auth_child_gate(path, child_plan, resource, *, body=None, status=200):
    path.mkdir(mode=0o700)
    (path / "lock").touch(mode=0o600)
    operation = child_plan["jobs"]["auth-recovery"]["recovery"][0]
    body = {"kind": "identitytoolkit#GetAccountInfoResponse", "users": []} if body is None else body
    _save(path, {"plan": child_plan, "planDigest": digest(child_plan), "started": 1, "total": 1,
        "observation": 0, "recovery": 1, "reservedRecovery": 0, "costMicrousd": 1, "lastSent": 1,
        "stopped": True, "coordinatorPid": _dead_pid(), "coordinatorInflight": False,
        "events": [{"job": "auth-recovery", "phase": "recovery", "index": 0,
            "requestDigest": digest(operation), "method": "POST", "service": "auth",
            "completed": True, "status": status, "responseDigest": digest(body)}],
        "jobs": {"auth-recovery": {"resources": [resource], "pid": _dead_pid(), "inflight": False,
            "recovery": 1, "observation": 0, "complete": True,
            "absent": [resource] if status == 200 and body.get("users") == [] else [],
            "creationProofs": {}, "captures": {}, "owned": []}}})


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
    assert ledger.close_after_auth_recovery_child(parent, child_ticket,
        receipt_digest=digest(proof), now=1000) == parent


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
