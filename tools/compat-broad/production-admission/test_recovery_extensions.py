"""Read-only evidence and recovery-allocation contract tests."""

import os
import multiprocessing
import json
import time
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "fs-request-bytes-boundary"))
import reservations
from broad_contract import digest
from shared_gate import Gate
from shared_gate import _save
from shared_gate import create as create_gate
import request_bytes_compiler
import request_bytes_admission
import request_bytes_descriptor
import request_bytes_production
import request_bytes_recovery_campaign
from test_request_bytes_admission import Admission


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
    fixture = Admission(tmp_path)
    import shutil
    shutil.rmtree(fixture.ledger)
    reservations.Ledger.create(fixture.ledger)
    ledger = reservations.Ledger(fixture.ledger)
    parent_gate_plan = request_bytes_admission.gate_plan_for(fixture.inputs, fixture.permission)
    parent_path = (tmp_path / "parent-gate").resolve()
    parent_claim = request_bytes_admission.reservation_claim(fixture.inputs, gate_path=parent_path, gate_plan=parent_gate_plan)
    parent_envelope = request_bytes_production._envelope(fixture.permission, parent_claim)
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
    gate_state["jobs"][request_bytes_descriptor.gate_job_name("probe-u01")]["pid"] = dead
    gate_state["events"] = [{"phase": "observation", "index": 0, "completed": False, "failure": "TimeoutError"}]
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
        "kind": reservations.RECOVERY_CHILD_KIND, "version": 1,
        "campaignId": parent_claim["campaignId"], "manifestDigest": parent_claim["manifestDigest"],
        "nonceDigest": digest(recovery_nonce), "gatePath": str((tmp_path / "child-gate").resolve()),
        "gatePlanDigest": digest(recovery_plan), "locks": parent_claim["locks"],
        "budget": {"requests": 85, "accounts": 0, "resources": 51, "costMicrousd": 85},
        "durationSeconds": 100, "generation": child_generation, "parentClaimDigest": ticket["claimDigest"],
        "parentPlanDigest": digest(parent_plan), "recoveryNonce": recovery_nonce, "selectedProbe": "under",
        "resourceDigest": digest(resources), "ownedResources": resources,
        "ownerIdentity": "owner", "recoveryOwner": "recovery-owner",
        "operationClass": reservations.RECOVERY_OPERATION_CLASS, "readCount": 68,
        "inspectionCount": 17, "absenceCount": 51, "deleteCount": 17,
        "tariffEstimateMicrousd": 45, "expiresAt": 1900,
        "executionHost": request_bytes_admission.execution_host(), "permissionDigest": "b" * 64,
    }
    envelope = {"permissionDigest": "b" * 64, "issuedAt": 1000, "expiresAt": 2000,
                "limits": {"requests": 85, "accounts": 0, "resources": 51, "costMicrousd": 85},
                "concurrency": 1, "scopes": parent_envelope["scopes"]}
    return ledger, ticket, child_claim, envelope, parent_plan, recovery_plan


def test_recovery_extension_persists_child_before_any_issuer(tmp_path):
    ledger, parent, child, envelope, parent_plan, child_plan = _recovery_fixture(tmp_path)
    before = ledger.snapshot()
    result = ledger.begin_recovery_extension(parent, child, envelope, parent_plan, child_plan, now=1100)
    assert result["claimDigest"] == digest(child)
    state = ledger.snapshot()
    row = state["reservations"][parent["reservation"]]
    assert row["claim"]["budget"] == before["reservations"][parent["reservation"]]["claim"]["budget"]
    assert row["claimDigest"] == parent["claimDigest"]
    assert row["recoveryChildren"][0]["claim"]["budget"]["requests"] == 85
    assert reservations.task_spent_microusd(state, child["campaignId"]) == 388
    assert not hasattr(ledger, "_consume")
    assert ledger.begin_recovery_extension(parent, child, envelope, parent_plan, child_plan, now=1100) == result


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
