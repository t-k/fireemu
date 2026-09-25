"""Commander-facing Auth recovery executor tests.

These tests deliberately use a deterministic transport callback. The callback
records the one Gate operation but never opens a socket, so the executor's
ordering, private handoff and Ledger settlement rules can be exercised without
production traffic.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import credential_recovery as recovery
import credential_recovery_executor as executor
import reservations
import shared_gate
from broad_contract import digest
from test_credential_recovery_prepare import (
    _ledger_parent,
    _ReadOnlyLedger,
    _real_signing_parent,
    _reviewed,
    _reviews,
    _source_inputs,
)

RUNTIME_CLOSURE = (
    "tools/compat-broad/auth-credential-tokens/credential_recovery_executor.py",
    "tools/compat-broad/auth-credential-tokens/credential_recovery_prepare.py",
    "tools/compat-broad/auth-credential-tokens/credential_recovery.py",
    "tools/compat-broad/auth-credential-tokens/credential_remote_transport.py",
    "tools/compat-broad/auth-credential-tokens/credential_wire.py",
    "tools/compat-broad/batch_wire.py",
    "tools/compat-broad/auth-credential-tokens/credential_https_worker.py",
    "tools/compat-broad/shared_gate.py",
    "tools/compat-broad/production-admission/reservations.py",
)
EXECUTION_SOURCE_KIND = "auth-recovery-executor-source-v1"


class RecordingLedger(_ReadOnlyLedger):
    """A deterministic Ledger seam that records the child lifecycle calls."""

    def __init__(self, parent: dict) -> None:
        super().__init__(parent)
        self.lifecycle: list[str] = []
        self.child_ticket = {
            "parentReservation": parent["ticket"]["reservation"],
            "reservation": "child-ticket",
        }

    def begin_auth_recovery_extension(
        self, parent_ticket, child_claim, envelope, gate_plan, **kwargs
    ):
        self.lifecycle.append("begin-child")
        assert parent_ticket == self.parent["ticket"]
        assert child_claim["gatePlanDigest"] == digest(gate_plan)
        return copy.deepcopy(self.child_ticket)

    def settle_auth_recovery_child(
        self, child_ticket, *, absence_proof, receipt_digest, now=None
    ):
        self.lifecycle.append("settle-child")
        assert child_ticket == self.child_ticket
        assert absence_proof["kind"] == recovery.ABSENCE_KIND
        assert isinstance(receipt_digest, str)
        return copy.deepcopy(child_ticket)

    def close_after_auth_recovery_child(
        self, parent_ticket, child_ticket, *, receipt_digest, now=None
    ):
        self.lifecycle.append("close-parent")
        assert parent_ticket == self.parent["ticket"]
        assert child_ticket == self.child_ticket
        return {"state": "closed-after-auth-recovery-child"}


def _packet(tmp_path: Path):
    parent = _ledger_parent()
    parent["claim"].pop("claimDigest", None)
    parent["ticket"]["claimDigest"] = digest(parent["claim"])
    source_root, provenance = _source_inputs(tmp_path, parent, include_execution_closure=False)
    execution_root, execution_source = _execution_source(tmp_path)
    permission, o7, o8 = _reviewed(parent, provenance, execution_root)
    permission.update(
        ownerIdentity="owner@example.com",
        recoveryOwner="recovery@example.com",
        executionSourceDigest=digest(execution_source),
    )
    authority_digest = digest(permission)
    o7.update(
        permissionDigest=authority_digest,
        executionSourceDigest=digest(execution_source),
    )
    o8.update(
        permissionDigest=authority_digest,
        executionSourceDigest=digest(execution_source),
    )
    reviews = _reviews(permission, o7, o8)
    import credential_recovery_prepare as prepare

    bundle = prepare.prepare_packet(
        parent,
        ledger=RecordingLedger(parent),
        provenance=provenance,
        source_root=source_root,
        execution_source_root=execution_root,
        permission=permission,
        o7=o7,
        o8=o8,
        permission_review=reviews[0],
        o7_review=reviews[1],
        o8_review=reviews[2],
        recovery_nonce="fedcba9876543210fedcba9876543210",
        now=1000.0,
        authority_now=1001.0,
    )
    return parent, source_root, execution_root, bundle


def _id_token_sub_packet(tmp_path: Path):
    parent = _real_signing_parent()
    parent["claim"].pop("claimDigest", None)
    parent["ticket"]["claimDigest"] = digest(parent["claim"])
    source_root, provenance = _source_inputs(tmp_path, parent, include_execution_closure=False)
    execution_root, execution_source = _execution_source(tmp_path)
    permission, o7, o8 = _reviewed(parent, provenance, execution_root)
    permission.update(
        ownerIdentity="owner@example.com",
        recoveryOwner="recovery@example.com",
        executionSourceDigest=digest(execution_source),
    )
    authority_digest = digest(permission)
    o7.update(
        permissionDigest=authority_digest,
        executionSourceDigest=digest(execution_source),
    )
    o8.update(
        permissionDigest=authority_digest,
        executionSourceDigest=digest(execution_source),
    )
    reviews = _reviews(permission, o7, o8)
    import credential_recovery_prepare as prepare

    bundle = prepare.prepare_packet(
        parent,
        ledger=RecordingLedger(parent),
        provenance=provenance,
        source_root=source_root,
        execution_source_root=execution_root,
        permission=permission,
        o7=o7,
        o8=o8,
        permission_review=reviews[0],
        o7_review=reviews[1],
        o8_review=reviews[2],
        recovery_nonce="fedcba9876543210fedcba9876543210",
        now=1000.0,
        authority_now=1001.0,
    )
    return parent, source_root, execution_root, bundle


def _real_ledger_packet(tmp_path: Path):
    """Prepare a packet whose held parent is persisted by the real Ledger."""
    parent = _ledger_parent()
    parent["claim"].pop("claimDigest", None)
    source_root, provenance = _source_inputs(tmp_path, parent, include_execution_closure=False)
    execution_root, execution_source = _execution_source(tmp_path)
    gate_path = (tmp_path / "parent-gate").resolve()
    resource = parent["gate"]["plan"]["jobs"]["auth-credential"]["observation"][0][
        "resource"
    ]
    gate_plan = parent["gate"]["plan"]
    gate_plan.update(
        contract="shared-local-v1",
        project=recovery.PROJECT,
        signing=True,
        jobSlots=1,
        requestSeconds=5.0,
        wallSeconds=120,
        recoverySeconds=0,
        intervalSeconds=0.25,
        observationRequests=1,
        dataRequests=1,
        managementRequests=0,
        recoveryRequests=0,
        requestCostMicrousd=1,
        costMicrousd=1,
        receiptKind="auth-credential-receipt-v1",
        plannedAccounts=["custom"],
        accountResources=[resource],
        mintedBindings=[],
        management={
            "dispatchKind": "closed-v1",
            "observation": [],
            "recovery": [],
            "credentialIds": [],
            "credentialSlots": [],
            "slotSeconds": 0,
            "intervalSeconds": 0.25,
            "totalRequests": 0,
            "observationWindowSeconds": 0,
            "recoveryWindowSeconds": 0,
            "permissionExpiryBound": True,
        },
    )
    gate_plan["jobs"]["auth-credential"].update(
        resources=[resource],
        accountBindings={"custom": {"resource": resource, "uidBinding": "localId"}},
        schedule=[{"phase": "observation", "index": 0, "seconds": 5.0}],
    )
    parent["gate"]["planDigest"] = digest(gate_plan)
    parent["gate"].update(observation=1, recovery=0, total=1)
    parent["gate"]["jobs"]["auth-credential"].update(
        observation=1,
        recovery=0,
        scheduleDone=1,
        skippedByStop=0,
        complete=False,
        stopped=False,
        resources=[resource],
        authAccounts={},
        owned=[],
        creationProofs={},
        absenceProofs={},
        captures={},
    )
    operation = gate_plan["jobs"]["auth-credential"]["observation"][0]
    parent["gate"]["events"] = [
        {
            "job": "auth-credential",
            "phase": "observation",
            "index": 0,
            "requestDigest": digest(operation),
            "service": operation["service"],
            "method": operation["method"],
            "completed": False,
            "creationOutcome": "unknown",
            "ended": 999.0,
        }
    ]
    parent["claim"].update(
        manifestDigest=digest(parent["gate"]["plan"]),
        nonceDigest=digest(parent["gate"]["plan"]["nonce"]),
        gatePath=str(gate_path),
        gateJob="auth-credential",
        gatePlanDigest=digest(parent["gate"]["plan"]),
        locks=[{"key": "project/fireemu-35fe6/auth/accounts/*", "mode": "WRITE"}],
        budget={"requests": 1, "accounts": 1, "resources": 1, "costMicrousd": 1},
        durationSeconds=120,
    )
    gate_path.mkdir(mode=0o700, parents=True, exist_ok=False)
    (gate_path / "lock").touch(mode=0o600, exist_ok=False)
    shared_gate._save(gate_path, parent["gate"])
    parent["claim"]["gatePlanDigest"] = digest(gate_plan)
    parent["immutableParent"].update(
        gateDigest=digest(parent["gate"]),
        gatePlanDigest=digest(gate_plan),
        resource=resource,
        eventIndex=0,
        requestDigest=digest(operation),
    )
    ledger = reservations.Ledger.create(tmp_path / "ledger")
    envelope = {
        "permissionDigest": "9" * 64,
        "issuedAt": 900.0,
        "expiresAt": 2000.0,
        "limits": parent["claim"]["budget"],
        "concurrency": 1,
        "scopes": [{"key": "project/fireemu-35fe6/auth/accounts/*", "mode": "WRITE"}],
    }
    envelope_digest = digest(envelope)
    claim_digest = digest(parent["claim"])
    parent["ticket"] = {
        "ledgerPath": str(ledger.path),
        "ledgerIdentity": ledger.identity,
        "reservation": "p" * 64,
        "claimDigest": claim_digest,
        "envelopeDigest": envelope_digest,
    }
    state = ledger.snapshot()
    state["envelopes"][envelope_digest] = {
        "envelope": envelope,
        "allocated": copy.deepcopy(parent["claim"]["budget"]),
    }
    state["reservations"][parent["ticket"]["reservation"]] = {
        "claim": copy.deepcopy(parent["claim"]),
        "claimDigest": claim_digest,
        "envelopeDigest": envelope_digest,
        "state": "held",
        "deadline": 1100.0,
        "generation": copy.deepcopy(parent["generation"]),
    }
    reservations._save(ledger.path, state)
    permission, o7, o8 = _reviewed(parent, provenance, execution_root)
    permission.update(
        ownerIdentity="owner@example.com",
        recoveryOwner="recovery@example.com",
        executionSourceDigest=digest(execution_source),
    )
    authority_digest = digest(permission)
    o7.update(
        permissionDigest=authority_digest,
        executionSourceDigest=digest(execution_source),
    )
    o8.update(
        permissionDigest=authority_digest,
        executionSourceDigest=digest(execution_source),
    )
    reviews = _reviews(permission, o7, o8)
    import credential_recovery_prepare as prepare

    packet = prepare.prepare_packet(
        parent,
        ledger=RecordingLedger(parent),
        provenance=provenance,
        source_root=source_root,
        execution_source_root=execution_root,
        permission=permission,
        o7=o7,
        o8=o8,
        permission_review=reviews[0],
        o7_review=reviews[1],
        o8_review=reviews[2],
        recovery_nonce="fedcba9876543210fedcba9876543210",
        now=1000.0,
        authority_now=1001.0,
    )
    return parent, source_root, execution_root, packet, ledger


def _execution_source(tmp_path: Path) -> tuple[Path, dict]:
    """Create a separate reviewed child checkout for the executing closure."""
    source_root = tmp_path / "executor-source"
    for relative in RUNTIME_CLOSURE:
        destination = source_root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(HERE.parents[2] / relative, destination)
    subprocess.run(["git", "-C", str(source_root), "init", "-q"], check=True)
    subprocess.run(
        ["git", "-C", str(source_root), "config", "user.email", "test@example.invalid"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(source_root), "config", "user.name", "Auth test"], check=True
    )
    subprocess.run(["git", "-C", str(source_root), "add", "tools"], check=True)
    subprocess.run(
        ["git", "-C", str(source_root), "commit", "-qm", "runtime closure"], check=True
    )
    commit = subprocess.check_output(
        ["git", "-C", str(source_root), "rev-parse", "HEAD"], text=True
    ).strip()
    source_inputs = {
        relative: hashlib.sha256((source_root / relative).read_bytes()).hexdigest()
        for relative in RUNTIME_CLOSURE
    }
    execution_source = {
        "kind": EXECUTION_SOURCE_KIND,
        "sourceCommit": commit,
        "sourceInputs": source_inputs,
        "sourceInputsDigest": digest(source_inputs),
    }
    return source_root, execution_source


def _credential_fd(tmp_path: Path) -> int:
    path = tmp_path / "handoff.json"
    path.write_text(json.dumps({"token": "oauth-token", "apiKey": "web-api-key"}))
    path.chmod(0o600)
    return os.open(path, os.O_RDONLY)


def test_executor_registers_child_before_fd_read_and_runs_one_typed_empty_gate_request(
    tmp_path: Path,
) -> None:
    parent, source_root, execution_root, packet = _packet(tmp_path)
    ledger = RecordingLedger(parent)
    order_path = tmp_path / "order.log"
    credential_fd = _credential_fd(tmp_path)

    def read_fd(fd):
        with order_path.open("a") as stream:
            stream.write("credential-read\n")
        return executor.read_private_handoff(fd)

    def transport(operation, body, *, token, api_key, deadline):
        with order_path.open("a") as stream:
            stream.write("wire\n")
        assert token == "oauth-token"
        assert api_key == "web-api-key"
        assert operation["path"].endswith("/projects/fireemu-35fe6/accounts:lookup")
        assert body == {"localId": [packet["plan"]["customUid"]]}
        assert deadline > 0
        return 200, {"kind": "identitytoolkit#GetAccountInfoResponse", "users": []}

    try:
        result = executor.execute_recovery(
            packet,
            parent=parent,
            ledger=ledger,
            source_root=source_root,
            execution_root=execution_root,
            credential_fd=credential_fd,
            gate_path=tmp_path / "child-gate",
            now=1001.0,
            clock=lambda: 1001.0,
            read_handoff=read_fd,
            transport=transport,
        )
    finally:
        os.close(credential_fd)

    assert order_path.read_text().splitlines() == ["credential-read", "wire"]
    assert ledger.lifecycle == ["begin-child", "settle-child", "close-parent"]
    assert result["disposition"] == "typed-empty"
    assert result["lookupCount"] == 1
    assert "oauth-token" not in repr(result)
    assert "web-api-key" not in repr(result)
    state = json.loads((tmp_path / "child-gate" / "state.json").read_text())
    job = state["jobs"][recovery.GATE_JOB]
    assert job["complete"] is True
    assert job["recovery"] == 1
    assert state["coordinatorInflight"] is False
    assert not [event for event in state["events"] if event.get("skipped")]


def test_executor_accepts_receipt_when_child_is_reaped_before_pipe_eof(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Pipe EOF may arrive after WNOHANG has already reaped the child."""
    parent, source_root, execution_root, packet = _packet(tmp_path)
    ledger = RecordingLedger(parent)
    credential_fd = _credential_fd(tmp_path)
    controller_pid = os.getpid()
    delayed = False
    original_select = executor.select.select

    def delayed_controller_select(read, write, error, timeout=None):
        nonlocal delayed
        if os.getpid() == controller_pid and not delayed:
            delayed = True
            time.sleep(0.03)
        return original_select(read, write, error, timeout)

    monkeypatch.setattr(executor.select, "select", delayed_controller_select)
    try:
        result = executor.execute_recovery(
            packet,
            parent=parent,
            ledger=ledger,
            source_root=source_root,
            execution_root=execution_root,
            credential_fd=credential_fd,
            gate_path=tmp_path / "child-gate",
            now=1001.0,
            clock=lambda: 1001.0,
            transport=lambda *_args, **_kwargs: (
                200,
                {"kind": "identitytoolkit#GetAccountInfoResponse", "users": []},
            ),
        )
    finally:
        os.close(credential_fd)
    assert result["disposition"] == "typed-empty"
    assert ledger.lifecycle == ["begin-child", "settle-child", "close-parent"]


def test_stop_worker_escalates_and_reaps_term_ignoring_child() -> None:
    ready_read, ready_write = os.pipe()
    child_pid = os.fork()
    if child_pid == 0:
        os.close(ready_read)
        os.setsid()
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        os.write(ready_write, b"r")
        os.close(ready_write)
        while True:
            time.sleep(1.0)
    os.close(ready_write)
    assert os.read(ready_read, 1) == b"r"
    os.close(ready_read)

    alarm_triggered = False

    def alarm_handler(_signum, _frame):
        nonlocal alarm_triggered
        alarm_triggered = True
        raise TimeoutError("unbounded worker cleanup")

    previous_handler = signal.signal(signal.SIGALRM, alarm_handler)
    signal.alarm(1)
    started = time.monotonic()
    try:
        executor._stop_worker(child_pid)
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous_handler)
        if alarm_triggered:
            try:
                os.killpg(child_pid, signal.SIGKILL)
            except OSError:
                pass
            os.waitpid(child_pid, 0)
    assert not alarm_triggered
    assert time.monotonic() - started < 1.0
    with pytest.raises(ChildProcessError):
        os.waitpid(child_pid, os.WNOHANG)


@pytest.mark.parametrize("fault", ["select", "read", "interrupt"])
def test_supervisor_fault_reaps_real_worker_and_preserves_exception(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    _parent, _source_root, _execution_root, packet = _packet(tmp_path)
    plan = packet["plan"]
    o7, o8 = packet["o7"], packet["o8"]
    credential_fd = _credential_fd(tmp_path)
    controller_pid = os.getpid()
    child_pids: list[int] = []
    cleanup_pids: list[int] = []
    original_fork = executor.os.fork
    original_stop = executor._stop_worker
    original_select = executor.select.select
    original_read = executor.os.read

    def record_fork() -> int:
        pid = original_fork()
        if pid > 0:
            child_pids.append(pid)
        return pid

    def record_stop(pid: int) -> None:
        cleanup_pids.append(pid)
        original_stop(pid)

    def fault_select(read, write, error, timeout=None):
        if os.getpid() == controller_pid and fault == "select":
            raise OSError("supervisor select fault")
        return original_select(read, write, error, timeout)

    def fault_read(fd: int, count: int) -> bytes:
        if os.getpid() == controller_pid and fault == "read":
            raise OSError("supervisor read fault")
        return original_read(fd, count)

    monkeypatch.setattr(executor.os, "fork", record_fork)
    monkeypatch.setattr(executor, "_stop_worker", record_stop)
    monkeypatch.setattr(executor.select, "select", fault_select)
    monkeypatch.setattr(executor.os, "read", fault_read)
    try:
        expected = KeyboardInterrupt if fault == "interrupt" else OSError
        if fault == "interrupt":

            def interrupt_select(read, write, error, timeout=None):
                if os.getpid() == controller_pid:
                    raise KeyboardInterrupt()
                return original_select(read, write, error, timeout)

            monkeypatch.setattr(executor.select, "select", interrupt_select)
        with pytest.raises(expected):
            executor._run_gate_worker(
                plan=plan,
                o7=o7,
                o8=o8,
                credential_fd=credential_fd,
                gate_path=tmp_path / "child-gate",
                allocation_now=1001.0,
                clock=lambda: 1001.0,
                read_handoff=executor.read_private_handoff,
                transport=lambda *_args, **_kwargs: (
                    200,
                    {"kind": "identitytoolkit#GetAccountInfoResponse", "users": []},
                ),
            )
    finally:
        os.close(credential_fd)
        if child_pids and not cleanup_pids:
            original_stop(child_pids[0])
    assert len(child_pids) == 1
    assert cleanup_pids == child_pids
    with pytest.raises(ChildProcessError):
        os.waitpid(child_pids[0], os.WNOHANG)


@pytest.mark.parametrize("fault", ["write-close", "monotonic"])
def test_postfork_initialization_fault_closes_pipe_and_reaps_real_worker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    _parent, _source_root, _execution_root, packet = _packet(tmp_path)
    plan = packet["plan"]
    o7, o8 = packet["o7"], packet["o8"]
    credential_fd = _credential_fd(tmp_path)
    controller_pid = os.getpid()
    child_pids: list[int] = []
    pipe_fds: list[tuple[int, int]] = []
    cleanup_pids: list[int] = []
    original_fork = executor.os.fork
    original_pipe = executor.os.pipe
    original_close = executor.os.close
    original_monotonic = executor.time.monotonic
    original_stop = executor._stop_worker
    fault_instance: BaseException
    if fault == "write-close":
        fault_instance = OSError("post-fork write-end close fault")
    else:
        fault_instance = KeyboardInterrupt("post-fork monotonic fault")
    forked = False
    fired = False

    def record_pipe() -> tuple[int, int]:
        fds = original_pipe()
        pipe_fds.append(fds)
        return fds

    def record_fork() -> int:
        nonlocal forked
        pid = original_fork()
        if pid > 0:
            child_pids.append(pid)
            forked = True
        return pid

    def fault_close(fd: int) -> None:
        nonlocal fired
        if (
            os.getpid() == controller_pid
            and forked
            and not fired
            and fault == "write-close"
        ):
            fired = True
            raise fault_instance
        original_close(fd)

    def fault_monotonic() -> float:
        nonlocal fired
        if (
            os.getpid() == controller_pid
            and forked
            and not fired
            and fault == "monotonic"
        ):
            fired = True
            raise fault_instance
        return original_monotonic()

    def record_stop(pid: int) -> None:
        cleanup_pids.append(pid)
        original_stop(pid)

    monkeypatch.setattr(executor.os, "pipe", record_pipe)
    monkeypatch.setattr(executor.os, "fork", record_fork)
    monkeypatch.setattr(executor.os, "close", fault_close)
    monkeypatch.setattr(executor.time, "monotonic", fault_monotonic)
    monkeypatch.setattr(executor, "_stop_worker", record_stop)
    try:
        with pytest.raises(type(fault_instance)) as raised:
            executor._run_gate_worker(
                plan=plan,
                o7=o7,
                o8=o8,
                credential_fd=credential_fd,
                gate_path=tmp_path / "child-gate",
                allocation_now=1001.0,
                clock=lambda: 1001.0,
                read_handoff=executor.read_private_handoff,
                transport=lambda *_args, **_kwargs: (
                    200,
                    {"kind": "identitytoolkit#GetAccountInfoResponse", "users": []},
                ),
            )
        assert raised.value is fault_instance
    finally:
        os.close(credential_fd)
        if child_pids and not cleanup_pids:
            original_stop(child_pids[0])
    assert len(child_pids) == 1
    assert cleanup_pids == child_pids
    assert len(pipe_fds) == 1
    for fd in pipe_fds[0]:
        with pytest.raises(OSError):
            os.fstat(fd)
    with pytest.raises(ChildProcessError):
        os.waitpid(child_pids[0], os.WNOHANG)


def test_supervisor_fault_preserves_exception_when_cleanup_reports_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _parent, _source_root, _execution_root, packet = _packet(tmp_path)
    credential_fd = _credential_fd(tmp_path)
    controller_pid = os.getpid()
    child_pids: list[int] = []
    cleanup_pids: list[int] = []
    original_fork = executor.os.fork
    original_stop = executor._stop_worker
    original_select = executor.select.select
    supervisor_fault = OSError("supervisor select fault")
    cleanup_fault = RuntimeError("cleanup reporting fault")

    def record_fork() -> int:
        pid = original_fork()
        if pid > 0:
            child_pids.append(pid)
        return pid

    def fault_select(read, write, error, timeout=None):
        if os.getpid() == controller_pid:
            raise supervisor_fault
        return original_select(read, write, error, timeout)

    def stop_and_report(pid: int) -> None:
        cleanup_pids.append(pid)
        original_stop(pid)
        raise cleanup_fault

    monkeypatch.setattr(executor.os, "fork", record_fork)
    monkeypatch.setattr(executor.select, "select", fault_select)
    monkeypatch.setattr(executor, "_stop_worker", stop_and_report)
    try:
        with pytest.raises(OSError) as raised:
            executor._run_gate_worker(
                plan=packet["plan"],
                o7=packet["o7"],
                o8=packet["o8"],
                credential_fd=credential_fd,
                gate_path=tmp_path / "child-gate",
                allocation_now=1001.0,
                clock=lambda: 1001.0,
                read_handoff=executor.read_private_handoff,
                transport=lambda *_args, **_kwargs: (
                    200,
                    {"kind": "identitytoolkit#GetAccountInfoResponse", "users": []},
                ),
            )
        assert raised.value is supervisor_fault
    finally:
        os.close(credential_fd)
        if child_pids and not cleanup_pids:
            original_stop(child_pids[0])
    assert cleanup_pids == child_pids
    with pytest.raises(ChildProcessError):
        os.waitpid(child_pids[0], os.WNOHANG)


def test_executor_reconstructs_the_real_signing_compiler_id_token_sub_parent(
    tmp_path: Path,
) -> None:
    parent, source_root, execution_root, packet = _id_token_sub_packet(tmp_path)
    ledger = RecordingLedger(parent)
    credential_fd = _credential_fd(tmp_path)
    try:
        result = executor.execute_recovery(
            packet,
            parent=parent,
            ledger=ledger,
            source_root=source_root,
            execution_root=execution_root,
            credential_fd=credential_fd,
            gate_path=tmp_path / "child-gate",
            now=1001.0,
            clock=lambda: 1001.0,
            transport=lambda *_args, **_kwargs: (
                200,
                {"kind": "identitytoolkit#GetAccountInfoResponse", "users": []},
            ),
        )
    finally:
        os.close(credential_fd)
    assert result["disposition"] == "typed-empty"
    assert packet["plan"]["parent"]["requestDigest"] == digest(
        parent["gate"]["plan"]["jobs"]["auth-credential"]["observation"][
            parent["immutableParent"]["eventIndex"]
        ]
    )


def test_executor_settles_and_closes_a_real_temp_ledger(tmp_path: Path) -> None:
    parent, source_root, execution_root, packet, ledger = _real_ledger_packet(tmp_path)
    assert (
        packet["executionSource"]["sourceCommit"]
        != parent["immutableParent"]["sourceCommit"]
    )
    assert not (source_root / executor.EXECUTOR_ENTRY).exists()
    credential_fd = _credential_fd(tmp_path)
    try:

        def transport(*_args, **_kwargs):
            return 200, {"kind": "identitytoolkit#GetAccountInfoResponse", "users": []}

        result = executor.execute_recovery(
            packet,
            parent=parent,
            ledger=ledger,
            source_root=source_root,
            execution_root=execution_root,
            credential_fd=credential_fd,
            gate_path=tmp_path / "child-gate",
            now=1001.0,
            clock=lambda: 1001.0,
            transport=transport,
        )
    finally:
        os.close(credential_fd)
    row = ledger.snapshot()["reservations"][parent["ticket"]["reservation"]]
    assert result["settlement"] == "closed-after-auth-recovery-child"
    assert row["state"] == "closed-after-auth-recovery-child"
    assert row["recoveryChildren"][0]["state"] == "settled"
    child_gate = json.loads((tmp_path / "child-gate" / "state.json").read_text())
    worker_pid = child_gate["coordinatorPid"]
    assert worker_pid != os.getpid()
    with pytest.raises(ProcessLookupError):
        os.kill(worker_pid, 0)


def test_absolute_deadline_is_rechecked_before_private_fd_read(tmp_path: Path) -> None:
    parent, source_root, execution_root, packet = _packet(tmp_path)
    ledger = RecordingLedger(parent)
    credential_fd = _credential_fd(tmp_path)
    reads: list[str] = []
    clock_values = iter((1001.0, 1061.0))
    try:
        with pytest.raises(recovery.RecoveryRefusal, match="deadline"):
            executor.execute_recovery(
                packet,
                parent=parent,
                ledger=ledger,
                source_root=source_root,
                execution_root=execution_root,
                credential_fd=credential_fd,
                gate_path=tmp_path / "child-gate",
                now=1001.0,
                clock=lambda: next(clock_values),
                read_handoff=lambda _fd: reads.append("read"),
            )
    finally:
        os.close(credential_fd)
    assert reads == []
    assert ledger.lifecycle == ["begin-child"]


def test_source_validation_elapsed_past_deadline_does_not_allocate_child(
    tmp_path: Path,
) -> None:
    parent, source_root, execution_root, packet = _packet(tmp_path)
    ledger = RecordingLedger(parent)
    credential_fd = _credential_fd(tmp_path)
    try:
        with pytest.raises(recovery.RecoveryRefusal, match="deadline"):
            executor.execute_recovery(
                packet,
                parent=parent,
                ledger=ledger,
                source_root=source_root,
                execution_root=execution_root,
                credential_fd=credential_fd,
                gate_path=tmp_path / "child-gate",
                now=1001.0,
                clock=lambda: 1061.0,
            )
    finally:
        os.close(credential_fd)
    assert ledger.lifecycle == []


def test_absolute_deadline_is_rechecked_before_gate_dispatch(tmp_path: Path) -> None:
    parent, source_root, execution_root, packet = _packet(tmp_path)
    ledger = RecordingLedger(parent)
    credential_fd = _credential_fd(tmp_path)
    clock_values = iter((1001.0, 1061.0))
    dispatched: list[str] = []
    try:
        with pytest.raises(recovery.RecoveryRefusal, match="deadline"):
            executor.execute_recovery(
                packet,
                parent=parent,
                ledger=ledger,
                source_root=source_root,
                execution_root=execution_root,
                credential_fd=credential_fd,
                gate_path=tmp_path / "child-gate",
                now=1001.0,
                clock=lambda: next(clock_values),
                transport=lambda *_args, **_kwargs: dispatched.append("wire"),
            )
    finally:
        os.close(credential_fd)
    assert dispatched == []
    assert ledger.lifecycle == ["begin-child"]


def test_absolute_deadline_is_rechecked_after_gate_finish_before_settlement(
    tmp_path: Path,
) -> None:
    parent, source_root, execution_root, packet = _packet(tmp_path)
    ledger = RecordingLedger(parent)
    credential_fd = _credential_fd(tmp_path)
    clock_values = iter((1001.0, 1001.0, 1001.0, 1001.0, 1061.0))
    try:
        with pytest.raises(recovery.RecoveryRefusal, match="deadline"):
            executor.execute_recovery(
                packet,
                parent=parent,
                ledger=ledger,
                source_root=source_root,
                execution_root=execution_root,
                credential_fd=credential_fd,
                gate_path=tmp_path / "child-gate",
                now=1001.0,
                clock=lambda: next(clock_values),
                transport=lambda *_args, **_kwargs: (
                    200,
                    {"kind": "identitytoolkit#GetAccountInfoResponse", "users": []},
                ),
            )
    finally:
        os.close(credential_fd)
    assert ledger.lifecycle == ["begin-child"]


def test_absolute_deadline_is_rechecked_after_terminal_gate_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    parent, source_root, execution_root, packet = _packet(tmp_path)
    ledger = RecordingLedger(parent)
    credential_fd = _credential_fd(tmp_path)
    controller_pid = os.getpid()
    snapshot_done = False
    original_snapshot = shared_gate.Gate.snapshot

    def snapshot(gate):
        nonlocal snapshot_done
        result = original_snapshot(gate)
        if os.getpid() == controller_pid and str(gate.path) == str(
            tmp_path / "child-gate"
        ):
            snapshot_done = True
        return result

    monkeypatch.setattr(shared_gate.Gate, "snapshot", snapshot)

    def clock() -> float:
        return 1061.0 if snapshot_done and os.getpid() == controller_pid else 1001.0

    try:
        with pytest.raises(recovery.RecoveryRefusal, match="deadline"):
            executor.execute_recovery(
                packet,
                parent=parent,
                ledger=ledger,
                source_root=source_root,
                execution_root=execution_root,
                credential_fd=credential_fd,
                gate_path=tmp_path / "child-gate",
                now=1001.0,
                clock=clock,
                transport=lambda *_args, **_kwargs: (
                    200,
                    {"kind": "identitytoolkit#GetAccountInfoResponse", "users": []},
                ),
            )
    finally:
        os.close(credential_fd)
    assert ledger.lifecycle == ["begin-child"]


def test_packet_parent_ticket_binding_is_required(tmp_path: Path) -> None:
    parent, source_root, execution_root, packet = _packet(tmp_path)
    packet["plan"]["parent"]["ticketDigest"] = "0" * 64
    ledger = RecordingLedger(parent)
    credential_fd = _credential_fd(tmp_path)
    try:
        with pytest.raises(recovery.RecoveryRefusal):
            executor.execute_recovery(
                packet,
                parent=parent,
                ledger=ledger,
                source_root=source_root,
                execution_root=execution_root,
                credential_fd=credential_fd,
                gate_path=tmp_path / "child-gate",
                now=1001.0,
                clock=lambda: 1001.0,
            )
    finally:
        os.close(credential_fd)
    assert ledger.lifecycle == []


@pytest.mark.parametrize(
    "relative",
    [
        executor.EXECUTOR_ENTRY,
        recovery.WORKER_ENTRY,
        "tools/compat-broad/auth-credential-tokens/credential_wire.py",
        "tools/compat-broad/batch_wire.py",
    ],
)
def test_runtime_executor_source_must_be_in_reviewed_closure(
    tmp_path: Path, relative: str
) -> None:
    parent, source_root, execution_root, packet = _packet(tmp_path)
    mutated = execution_root / relative
    if relative in {
        "tools/compat-broad/auth-credential-tokens/credential_wire.py",
        "tools/compat-broad/batch_wire.py",
    }:
        mutated.write_bytes(mutated.read_bytes() + b"\n# reviewed decoder mutation\n")
    else:
        mutated.unlink()
    ledger = RecordingLedger(parent)
    credential_fd = _credential_fd(tmp_path)
    try:
        with pytest.raises(recovery.RecoveryRefusal, match="source"):
            executor.execute_recovery(
                packet,
                parent=parent,
                ledger=ledger,
                source_root=source_root,
                execution_root=execution_root,
                credential_fd=credential_fd,
                gate_path=tmp_path / "child-gate",
                now=1001.0,
                clock=lambda: 1001.0,
            )
    finally:
        os.close(credential_fd)
    assert ledger.lifecycle == []


def test_missing_reviewed_owner_identities_do_not_use_executor_defaults(
    tmp_path: Path,
) -> None:
    parent, source_root, execution_root, packet = _packet(tmp_path)
    packet["permission"].pop("ownerIdentity")
    packet["permission"].pop("recoveryOwner")
    packet["o7"]["permissionDigest"] = digest(packet["permission"])
    packet["o8"]["permissionDigest"] = digest(packet["permission"])
    reviews = _reviews(packet["permission"], packet["o7"], packet["o8"])
    packet["permissionReview"], packet["o7Review"], packet["o8Review"] = reviews
    ledger = RecordingLedger(parent)
    credential_fd = _credential_fd(tmp_path)
    try:
        with pytest.raises(recovery.RecoveryRefusal):
            executor.execute_recovery(
                packet,
                parent=parent,
                ledger=ledger,
                source_root=source_root,
                execution_root=execution_root,
                credential_fd=credential_fd,
                gate_path=tmp_path / "child-gate",
                now=1001.0,
                clock=lambda: 1001.0,
            )
    finally:
        os.close(credential_fd)
    assert ledger.lifecycle == []


@pytest.mark.parametrize(
    "response",
    [
        (
            200,
            {
                "kind": "identitytoolkit#GetAccountInfoResponse",
                "users": [{"localId": "foreign"}],
            },
        ),
        (200, {"kind": "identitytoolkit#GetAccountInfoResponse", "users": "malformed"}),
        (504, {}),
    ],
)
def test_non_empty_malformed_or_timeout_result_keeps_parent_held(
    tmp_path: Path, response: tuple[int, dict]
) -> None:
    parent, source_root, execution_root, packet = _packet(tmp_path)
    ledger = RecordingLedger(parent)
    credential_fd = _credential_fd(tmp_path)

    def transport(_operation, _body, *, token, api_key, deadline):
        assert token and api_key and deadline > 0
        if response[0] == 504:
            raise TimeoutError("bounded timeout")
        return response

    try:
        with pytest.raises(recovery.RecoveryRefusal):
            executor.execute_recovery(
                packet,
                parent=parent,
                ledger=ledger,
                source_root=source_root,
                execution_root=execution_root,
                credential_fd=credential_fd,
                gate_path=tmp_path / "child-gate",
                now=1001.0,
                clock=lambda: 1001.0,
                transport=transport,
            )
    finally:
        os.close(credential_fd)

    assert ledger.lifecycle == ["begin-child"]
    assert not (
        "settle-child" in ledger.lifecycle or "close-parent" in ledger.lifecycle
    )


def test_invalid_packet_is_refused_before_private_fd_read_or_child_allocation(
    tmp_path: Path,
) -> None:
    parent, source_root, execution_root, packet = _packet(tmp_path)
    packet["o8"]["consumed"] = True
    ledger = RecordingLedger(parent)
    credential_fd = _credential_fd(tmp_path)
    reads: list[str] = []

    try:
        with pytest.raises(recovery.RecoveryRefusal):
            executor.execute_recovery(
                packet,
                parent=parent,
                ledger=ledger,
                source_root=source_root,
                execution_root=execution_root,
                credential_fd=credential_fd,
                gate_path=tmp_path / "child-gate",
                now=1001.0,
                clock=lambda: 1001.0,
                read_handoff=lambda _fd: reads.append("read"),
                transport=lambda *_args, **_kwargs: (200, {}),
            )
    finally:
        os.close(credential_fd)

    assert reads == []
    assert ledger.lifecycle == []
    assert not (tmp_path / "child-gate").exists()


def test_fd_handoff_requires_private_regular_owned_descriptor(tmp_path: Path) -> None:
    path = tmp_path / "handoff.json"
    path.write_text('{"token":"oauth-token","apiKey":"web-api-key"}')
    path.chmod(0o644)
    fd = os.open(path, os.O_RDONLY)
    try:
        with pytest.raises(ValueError, match="contract refused"):
            executor.read_private_handoff(fd)
    finally:
        os.close(fd)
