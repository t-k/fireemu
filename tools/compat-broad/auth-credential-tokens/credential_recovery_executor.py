"""Bounded production executor for one reviewed Auth recovery packet.

The executor is intentionally a separate boundary from offline preparation. It
reconstructs the held parent from the canonical Ledger, validates the detached
permission/O7/O8 packet and fixed source checkout, registers the child, and only
then reads the private credential descriptor. One exact Admin ``accounts:lookup``
is dispatched through a child shared Gate. Only the exact typed-empty response
permits settlement and parent close; every other result leaves both reservations
held.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import re
import select
import signal
import stat
import subprocess
import sys
import time
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "tools/compat-broad"))
sys.path.insert(0, str(ROOT / "tools/compat-broad/production-admission"))
sys.path.insert(0, str(HERE))

import credential_recovery as recovery
import credential_recovery_prepare as prepare
import credential_remote_transport as remote
import reservations
import shared_gate
from broad_contract import digest

MAX_HANDOFF_BYTES = 16 * 1024
HANDOFF_FIELDS = frozenset({"token", "apiKey"})
PACKET_KIND = prepare.PACKET_KIND
EXECUTOR_ENTRY = (
    "tools/compat-broad/auth-credential-tokens/credential_recovery_executor.py"
)
RUNTIME_CLOSURE = (
    EXECUTOR_ENTRY,
    "tools/compat-broad/auth-credential-tokens/credential_recovery_prepare.py",
    "tools/compat-broad/auth-credential-tokens/credential_recovery.py",
    "tools/compat-broad/auth-credential-tokens/credential_remote_transport.py",
    "tools/compat-broad/auth-credential-tokens/credential_wire.py",
    "tools/compat-broad/batch_wire.py",
    recovery.WORKER_ENTRY,
    "tools/compat-broad/shared_gate.py",
    "tools/compat-broad/production-admission/reservations.py",
)
EXECUTION_SOURCE_KIND = "auth-recovery-executor-source-v1"


def _refuse(reason: str) -> None:
    raise recovery.RecoveryRefusal(reason)


def _same(left: Any, right: Any, reason: str) -> None:
    if left != right:
        _refuse(reason)


def _verify_runtime_closure(
    execution_source: Mapping[str, Any], execution_root: Path
) -> None:
    """Require the running executor and separate reviewed child checkout to match."""
    if (
        not isinstance(execution_source, Mapping)
        or set(execution_source)
        != {"kind", "sourceCommit", "sourceInputs", "sourceInputsDigest"}
        or execution_source.get("kind") != EXECUTION_SOURCE_KIND
        or not isinstance(execution_source.get("sourceCommit"), str)
        or re.fullmatch(r"[0-9a-f]{40}", execution_source["sourceCommit"]) is None
        or execution_source.get("sourceInputsDigest")
        != digest(execution_source.get("sourceInputs"))
    ):
        _refuse("reviewed executor source closure required")
    source_inputs = execution_source.get("sourceInputs")
    if not isinstance(source_inputs, Mapping) or set(source_inputs) != set(
        RUNTIME_CLOSURE
    ):
        _refuse("reviewed executor source closure required")
    if execution_root.is_symlink() or not execution_root.is_dir():
        _refuse("reviewed executor source checkout required")
    try:
        actual_commit = subprocess.check_output(
            ["git", "-C", str(execution_root), "rev-parse", "HEAD"],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
        dirty = subprocess.check_output(
            [
                "git",
                "-C",
                str(execution_root),
                "status",
                "--porcelain",
                "--untracked-files=all",
            ],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except (OSError, subprocess.CalledProcessError):
        _refuse("reviewed executor source checkout required")
    if actual_commit != execution_source["sourceCommit"] or dirty:
        _refuse("reviewed executor source checkout differs")
    for relative in RUNTIME_CLOSURE:
        expected = source_inputs.get(relative)
        if (
            not isinstance(expected, str)
            or re.fullmatch(r"[0-9a-f]{64}", expected) is None
        ):
            _refuse("reviewed executor source closure required")
        approved = execution_root / relative
        running = ROOT / relative
        try:
            approved_digest = hashlib.sha256(approved.read_bytes()).hexdigest()
            running_digest = hashlib.sha256(running.read_bytes()).hexdigest()
        except OSError:
            _refuse("reviewed executor source closure required")
        if approved_digest != expected or running_digest != expected:
            _refuse("reviewed executor source closure differs")


def read_private_handoff(fd: int) -> dict[str, str]:
    """Read exactly one private OAuth/API-key object from an already-open FD.

    No path, environment variable or command-line value is accepted for the
    secrets. The descriptor must be a private regular file owned by this user;
    the parsed object is retained only by the caller in memory.
    """
    if type(fd) is not int or fd < 0:
        _refuse("private credential descriptor required")
    try:
        info = os.fstat(fd)
    except OSError:
        _refuse("private credential descriptor required")
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.getuid()
        or info.st_mode & 0o077
    ):
        _refuse("private credential descriptor required")
    raw = bytearray()
    deadline = time.monotonic() + 5.0
    while len(raw) <= MAX_HANDOFF_BYTES:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            _refuse("private credential handoff deadline")
        try:
            readable, _, _ = select.select([fd], [], [], remaining)
            if not readable:
                _refuse("private credential handoff deadline")
            chunk = os.read(fd, MAX_HANDOFF_BYTES + 1 - len(raw))
        except OSError:
            _refuse("private credential handoff unreadable")
        if not chunk:
            break
        raw.extend(chunk)
    if len(raw) > MAX_HANDOFF_BYTES:
        _refuse("bounded private credential handoff required")
    try:
        value = json.loads(bytes(raw))
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError):
        _refuse("private credential handoff required")
    if (
        not isinstance(value, dict)
        or set(value) != HANDOFF_FIELDS
        or not isinstance(value.get("token"), str)
        or not isinstance(value.get("apiKey"), str)
        or not value["token"].isascii()
        or not value["apiKey"].isascii()
        or not 0 < len(value["token"]) <= 8192
        or not 0 < len(value["apiKey"]) <= 256
        or any(
            char.isspace() or ord(char) < 33 or ord(char) == 127
            for char in value["token"] + value["apiKey"]
        )
    ):
        _refuse("private credential handoff required")
    return {"token": value["token"], "apiKey": value["apiKey"]}


def _validate_packet(
    packet: Mapping[str, Any],
    *,
    parent: Mapping[str, Any],
    ledger: Any,
    source_root: Path,
    execution_root: Path,
    now: float,
) -> tuple[
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
]:
    if (
        not isinstance(packet, Mapping)
        or packet.get("kind") != PACKET_KIND
        or packet.get("productionExecuted") is not False
        or packet.get("productionAllowed") is not False
        or packet.get("ledgerMutated") is not False
    ):
        _refuse("Auth packet05 recovery preparation bundle required")
    try:
        canonical_parent, state = prepare._reconstruct_parent(parent, ledger)
        parent_snapshot = recovery._parent_snapshot(canonical_parent)
        _same(
            packet.get("immutableParent"),
            canonical_parent.get("immutableParent"),
            "immutable parent changed",
        )
        _same(
            packet.get("parentEvidence"),
            parent_snapshot["evidence"],
            "parent evidence changed",
        )
        plan = packet.get("plan")
        if not isinstance(plan, Mapping):
            _refuse("recovery plan required")
        recovery.validate_plan(plan, canonical_parent)
        prepare._verify_fixed_source(
            packet["plan"]["provenance"],
            source_root,
            parent_snapshot["sourceCommit"],
            parent_snapshot["generation"],
        )
        execution_source = packet.get("executionSource")
        _verify_runtime_closure(execution_source, execution_root)
        prepare._assert_fresh_nonce(ledger, plan["recoveryNonce"], state)
        permission, o7, o8, _reviews = prepare._validate_reviewed_authorities(
            plan,
            packet.get("permission"),
            packet.get("o7"),
            packet.get("o8"),
            packet.get("permissionReview"),
            packet.get("o7Review"),
            packet.get("o8Review"),
            now=now,
        )
        _same(
            packet.get("permission"), permission, "permission review evidence changed"
        )
        _same(packet.get("o7"), o7, "O7 review evidence changed")
        _same(packet.get("o8"), o8, "O8 review evidence changed")
        execution_source_digest = digest(execution_source)
        for authority in (permission, o7, o8):
            _same(
                authority.get("executionSourceDigest"),
                execution_source_digest,
                "reviewed executor source binding changed",
            )
        parent_claim_digest = canonical_parent["claim"].get(
            "claimDigest", digest(canonical_parent["claim"])
        )
        _same(
            plan["parent"].get("ticketDigest"),
            digest(canonical_parent["ticket"]),
            "parent ticket binding changed",
        )
        _same(
            plan["parent"].get("claimDigest"),
            parent_claim_digest,
            "parent claim binding changed",
        )
        _same(
            canonical_parent["ticket"].get("claimDigest"),
            parent_claim_digest,
            "parent ticket claim binding changed",
        )
        owner_identity = permission.get("ownerIdentity")
        recovery_owner = permission.get("recoveryOwner")
        if (
            not isinstance(owner_identity, str)
            or not owner_identity.strip()
            or not isinstance(recovery_owner, str)
            or not recovery_owner.strip()
            or owner_identity == recovery_owner
        ):
            _refuse("reviewed recovery owner identities required")
        _same(
            permission.get("parentClaimDigest"),
            parent_claim_digest,
            "permission parent binding changed",
        )
        return (
            copy.deepcopy(dict(canonical_parent)),
            copy.deepcopy(dict(parent_snapshot)),
            copy.deepcopy(dict(plan)),
            copy.deepcopy(dict(permission)),
            copy.deepcopy(dict(o7)),
            copy.deepcopy(dict(o8)),
            copy.deepcopy(dict(execution_source)),
        )
    except recovery.RecoveryRefusal:
        raise
    except Exception as error:  # noqa: BLE001 -- packet details never cross this boundary.
        raise recovery.RecoveryRefusal(
            f"malformed Auth recovery packet ({type(error).__name__})"
        ) from None


def _production_transport(
    operation: Mapping[str, Any],
    body: Mapping[str, Any],
    *,
    token: str,
    api_key: str,
    deadline: float,
) -> tuple[int, dict[str, Any]]:
    """Use the existing pinned worker transport for the one recovery route.

    Recovery's reviewed O8 packet is the authority for this child, so it does
    not use the ordinary campaign capability. The remote transport still pins
    the worker bytes and enforces the HTTPS allowlist before opening a socket.
    """
    if (
        dict(operation).get("service") != "auth"
        or dict(operation).get("method") != "POST"
        or dict(operation).get("owner") is not True
        or dict(operation).get("form") is not False
        or dict(operation).get("path")
        != f"{recovery.IDENTITY}/projects/{recovery.PROJECT}/accounts:lookup"
    ):
        _refuse("closed Auth recovery route required")
    binding, binding_digest = remote.worker_binding()
    remote.verify_worker_binding(binding, binding_digest, None)
    url = "https://" + operation["path"]
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        _refuse("recovery request deadline expired")
    return remote.request(
        url,
        dict(body),
        headers={
            "Authorization": "Bearer " + token,
            "x-goog-user-project": recovery.PROJECT,
        },
        seconds=min(remote.MAX_SECONDS, remaining),
        form=False,
    )


def _bound_child_gate_plan(
    plan: Mapping[str, Any],
    *,
    o7: Mapping[str, Any],
    o8: Mapping[str, Any],
    now: float,
) -> dict[str, Any]:
    """Reconstruct the exact bound Gate plan persisted by ``begin_child``."""
    source_binding = {
        "kind": "auth-source-binding-v1",
        "digest": plan["provenance"]["sourceInputsDigest"],
    }
    transport_binding = {
        "kind": "auth-transport-binding-v1",
        "digest": digest(plan["provenance"]["transport"]),
    }
    o7_binding = {
        "kind": "auth-o7-binding-v1",
        "digest": digest(o7),
        "authority": copy.deepcopy(dict(o7)),
    }
    o8_binding = {
        "kind": "auth-o8-binding-v1",
        "digest": digest(o8),
        "authority": copy.deepcopy(dict(o8)),
    }
    bound = recovery._bound_plan(
        plan,
        source_binding=source_binding,
        transport_binding=transport_binding,
        o7_binding=o7_binding,
        o8_binding=o8_binding,
    )
    remaining = bound["deadlineAt"] - now
    if remaining < 1:
        _refuse("recovery deadline expired")
    duration = min(bound["deadlineSeconds"], int(remaining))
    child_gate_plan = copy.deepcopy(bound["gatePlan"])
    child_gate_plan["wallSeconds"] = duration
    child_gate_plan["jobs"][recovery.GATE_JOB]["schedule"][0]["seconds"] = min(
        5.0, float(duration)
    )
    return child_gate_plan


def _execute_gate_worker(
    *,
    plan: Mapping[str, Any],
    o7: Mapping[str, Any],
    o8: Mapping[str, Any],
    credential_fd: int,
    gate_path: Path,
    allocation_now: float,
    clock: Callable[[], float],
    read_handoff: Callable[[int], Mapping[str, str]],
    transport: Callable[..., tuple[Any, Any]],
) -> dict[str, Any]:
    """Own one child Gate from creation through its terminal receipt."""
    child_gate_plan = _bound_child_gate_plan(plan, o7=o7, o8=o8, now=allocation_now)
    shared_gate.create(gate_path, child_gate_plan)
    gate = shared_gate.Gate(gate_path, recovery.GATE_JOB)
    gate.claim()
    if float(clock()) >= float(plan["deadlineAt"]):
        _refuse("recovery deadline expired")
    handoff = dict(read_handoff(credential_fd))
    if set(handoff) != HANDOFF_FIELDS:
        _refuse("private credential handoff required")
    operation = copy.deepcopy(plan["operation"])
    body = {"localId": [plan["customUid"]]}
    current_wall = float(clock())
    if current_wall >= float(plan["deadlineAt"]):
        _refuse("recovery request deadline expired")
    request_seconds = min(
        float(plan["gatePlan"]["requestSeconds"]),
        float(plan["deadlineAt"]) - current_wall,
    )
    if request_seconds <= 0:
        _refuse("recovery request deadline expired")
    deadline = time.monotonic() + request_seconds

    def send() -> tuple[Any, Any]:
        return transport(
            operation,
            body,
            token=handoff["token"],
            api_key=handoff["apiKey"],
            deadline=deadline,
        )

    status, response = gate.dispatch(operation, True, send)
    if float(clock()) >= float(plan["deadlineAt"]) or time.monotonic() >= deadline:
        _refuse("recovery request deadline expired")
    expected = {"kind": "identitytoolkit#GetAccountInfoResponse", "users": []}
    if type(status) is not int or status != 200 or response != expected:
        _refuse("typed-empty Auth recovery response required")
    gate.finish()
    if float(clock()) >= float(plan["deadlineAt"]) or time.monotonic() >= deadline:
        _refuse("recovery request deadline expired")
    final_gate = gate.snapshot()
    receipt = {
        "kind": "auth-credential-recovery-worker-receipt-v1",
        "gateDigest": digest(final_gate),
        "gatePlanDigest": digest(final_gate["plan"]),
        "responseDigest": digest(expected),
        "completed": True,
    }
    receipt["receiptDigest"] = digest(receipt)
    return receipt


def _write_worker_message(fd: int, value: Mapping[str, Any]) -> None:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    if len(payload) > MAX_HANDOFF_BYTES:
        return
    view = memoryview(payload)
    while view:
        written = os.write(fd, view)
        view = view[written:]


def _reap_worker_within(pid: int, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while True:
        try:
            waited, _status = os.waitpid(pid, os.WNOHANG)
        except InterruptedError:
            continue
        except ChildProcessError:
            return True
        if waited == pid:
            return True
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        time.sleep(min(0.01, remaining))


def _stop_worker(pid: int) -> None:
    try:
        os.killpg(pid, signal.SIGTERM)
    except (OSError, ProcessLookupError):
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError:
            pass
    if _reap_worker_within(pid, 0.25):
        return
    try:
        os.killpg(pid, signal.SIGKILL)
    except (OSError, ProcessLookupError):
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass
    while True:
        try:
            os.waitpid(pid, 0)
            return
        except InterruptedError:
            continue
        except ChildProcessError:
            return


def _run_gate_worker(
    *,
    plan: Mapping[str, Any],
    o7: Mapping[str, Any],
    o8: Mapping[str, Any],
    credential_fd: int,
    gate_path: Path,
    allocation_now: float,
    clock: Callable[[], float],
    read_handoff: Callable[[int], Mapping[str, str]],
    transport: Callable[..., tuple[Any, Any]],
) -> tuple[int, dict[str, Any]]:
    """Fork, supervise and reap the sole process that owns the Gate."""
    read_fd, write_fd = os.pipe()
    payload = bytearray()
    status: int | None = None
    eof = False
    stop_attempted = False
    worker_reaped = False

    def stop_worker_once() -> None:
        nonlocal stop_attempted, worker_reaped
        if stop_attempted or worker_reaped:
            return
        stop_attempted = True
        _stop_worker(pid)
        worker_reaped = True

    try:
        pid = os.fork()
    except OSError:
        os.close(read_fd)
        os.close(write_fd)
        _refuse("recovery worker could not start")
    if pid == 0:
        os.close(read_fd)
        try:
            os.setsid()
            receipt = _execute_gate_worker(
                plan=plan,
                o7=o7,
                o8=o8,
                credential_fd=credential_fd,
                gate_path=gate_path,
                allocation_now=allocation_now,
                clock=clock,
                read_handoff=read_handoff,
                transport=transport,
            )
            os.close(credential_fd)
            _write_worker_message(write_fd, receipt)
            os.close(write_fd)
            os._exit(0)
        except BaseException as error:  # noqa: BLE001 -- child never leaks details.
            try:
                os.close(credential_fd)
            except OSError:
                pass
            try:
                _write_worker_message(
                    write_fd,
                    {
                        "kind": "auth-credential-recovery-worker-failure-v1",
                        "error": type(error).__name__,
                        "reason": (
                            error.reason
                            if isinstance(error, recovery.RecoveryRefusal)
                            else "recovery worker failed"
                        ),
                    },
                )
            except OSError:
                pass
            os.close(write_fd)
            os._exit(1)

    try:
        os.close(write_fd)
        hard_deadline = time.monotonic() + max(
            0.0, float(plan["deadlineAt"]) - allocation_now
        )
        while status is None or not eof:
            remaining = hard_deadline - time.monotonic()
            if remaining <= 0:
                stop_worker_once()
                _refuse("recovery worker deadline expired")
            readable, _, _ = select.select([read_fd], [], [], min(remaining, 0.25))
            if readable:
                chunk = os.read(read_fd, MAX_HANDOFF_BYTES + 1 - len(payload))
                if not chunk:
                    eof = True
                else:
                    payload.extend(chunk)
                    if len(payload) > MAX_HANDOFF_BYTES:
                        stop_worker_once()
                        _refuse("bounded recovery worker receipt required")
            if status is None:
                waited, wait_status = os.waitpid(pid, os.WNOHANG)
                if waited == pid:
                    status = wait_status
                    worker_reaped = True
        if status is None:
            _, status = os.waitpid(pid, 0)
        try:
            value = json.loads(bytes(payload))
        except (json.JSONDecodeError, UnicodeDecodeError, RecursionError):
            _refuse("recovery worker receipt required")
        if not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 0:
            if (
                isinstance(value, dict)
                and value.get("kind") == "auth-credential-recovery-worker-failure-v1"
            ):
                reason = value.get("reason")
                if isinstance(reason, str) and reason:
                    _refuse(f"recovery worker refused ({reason})")
            _refuse("recovery worker failed")
        if (
            not isinstance(value, dict)
            or value.get("kind") != "auth-credential-recovery-worker-receipt-v1"
        ):
            _refuse("recovery worker receipt required")
        return pid, value
    except BaseException:
        try:
            stop_worker_once()
        except BaseException as cleanup_error:  # noqa: BLE001 -- preserve original.
            del cleanup_error
        raise
    finally:
        for fd in (read_fd, write_fd):
            try:
                os.close(fd)
            except OSError:
                pass


def execute_recovery(
    packet: Mapping[str, Any],
    *,
    parent: Mapping[str, Any],
    ledger: Any,
    source_root: Path,
    execution_root: Path,
    credential_fd: int,
    gate_path: Path,
    now: float | None = None,
    clock: Callable[[], float] = time.time,
    read_handoff: Callable[[int], Mapping[str, str]] = read_private_handoff,
    transport: Callable[..., tuple[Any, Any]] = _production_transport,
) -> dict[str, Any]:
    """Execute exactly one persisted Auth recovery child.

    Child allocation is intentionally before ``read_handoff``. Once allocated,
    all errors retain the child and held parent; only a completed child Gate
    with the exact typed-empty response calls ``settle_and_close``.
    """
    if not callable(clock):
        _refuse("recovery wall clock required")
    decision_now = clock() if now is None else now
    if type(decision_now) not in (int, float):
        _refuse("finite recovery execution time required")
    (
        canonical_parent,
        _parent_snapshot_value,
        plan,
        permission,
        o7,
        o8,
        _execution_source,
    ) = _validate_packet(
        packet,
        parent=parent,
        ledger=ledger,
        source_root=source_root,
        execution_root=execution_root,
        now=float(decision_now),
    )
    destination = Path(gate_path)
    if destination.exists() or destination.is_symlink():
        _refuse("new recovery Gate path required")
    allocation_now = float(clock())
    if allocation_now >= float(plan["deadlineAt"]):
        _refuse("recovery deadline expired")
    child_ticket = recovery.begin_child(
        ledger,
        parent_ticket=canonical_parent["ticket"],
        parent=canonical_parent,
        plan=plan,
        permission=permission,
        o7=o7,
        o8=o8,
        gate_path=str(destination),
        owner_identity=permission["ownerIdentity"],
        recovery_owner=permission["recoveryOwner"],
        now=allocation_now,
    )
    try:
        _bound_child_gate_plan(plan, o7=o7, o8=o8, now=allocation_now)
        parent_hard_deadline = time.monotonic() + max(
            0.0, float(plan["deadlineAt"]) - allocation_now
        )
        worker_pid, receipt = _run_gate_worker(
            plan=plan,
            o7=o7,
            o8=o8,
            credential_fd=credential_fd,
            gate_path=destination,
            allocation_now=allocation_now,
            clock=clock,
            read_handoff=read_handoff,
            transport=transport,
        )
        final_gate = shared_gate.Gate(destination, recovery.GATE_JOB).snapshot()
        final_job = final_gate.get("jobs", {}).get(recovery.GATE_JOB, {})
        if (
            final_gate.get("coordinatorPid") != worker_pid
            or final_job.get("pid") != worker_pid
        ):
            _refuse("recovery worker ownership changed")
        expected = {"kind": "identitytoolkit#GetAccountInfoResponse", "users": []}
        _same(
            receipt.get("gateDigest"), digest(final_gate), "worker Gate receipt changed"
        )
        _same(
            receipt.get("gatePlanDigest"),
            digest(final_gate["plan"]),
            "worker Gate plan receipt changed",
        )
        recovery._worker_receipt(receipt, final_gate, digest(expected))
        settle_now = float(clock())
        if (
            settle_now >= float(plan["deadlineAt"])
            or time.monotonic() >= parent_hard_deadline
        ):
            _refuse("recovery request deadline expired")
        result = recovery.settle_and_close(
            ledger,
            parent_ticket=canonical_parent["ticket"],
            child_ticket=child_ticket,
            parent=canonical_parent,
            plan=plan,
            child_gate=final_gate,
            worker_receipt=receipt,
            now=settle_now,
        )
        return {
            "kind": "auth-credential-recovery-result-v1",
            "disposition": "typed-empty",
            "lookupCount": 1,
            "status": 200,
            "responseDigest": digest(expected),
            "settlement": "closed-after-auth-recovery-child",
            "ticketDigest": digest(result),
        }
    except recovery.RecoveryRefusal:
        raise
    except Exception as error:  # noqa: BLE001 -- commander boundary is secret-free.
        raise recovery.RecoveryRefusal(
            f"Auth recovery execution held ({type(error).__name__})"
        ) from None


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Execute one reviewed Auth packet05 recovery child."
    )
    parser.add_argument("--packet", type=Path, required=True)
    parser.add_argument("--parent", type=Path, required=True)
    parser.add_argument("--ledger", type=Path, required=True)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--execution-source", type=Path, required=True)
    parser.add_argument("--gate", type=Path, required=True)
    parser.add_argument("--credential-fd", type=int, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        args = build_parser().parse_args(argv)
        ledger = reservations.Ledger(args.ledger)
        packet = prepare._read_json(args.packet)
        parent = prepare._read_json(args.parent)
        result = execute_recovery(
            packet,
            parent=parent,
            ledger=ledger,
            source_root=args.source,
            execution_root=args.execution_source,
            credential_fd=args.credential_fd,
            gate_path=args.gate,
        )
    except SystemExit:
        raise
    except Exception as error:  # noqa: BLE001 -- commander output is secret-free.
        print(
            f"AUTH-CREDENTIAL packet05 recovery held ({type(error).__name__}).",
            file=sys.stderr,
        )
        return 1
    print("AUTH-CREDENTIAL packet05 recovery closed after typed-empty lookup.")
    return 0 if result.get("settlement") == "closed-after-auth-recovery-child" else 1


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "HANDOFF_FIELDS",
    "MAX_HANDOFF_BYTES",
    "build_parser",
    "execute_recovery",
    "main",
    "read_private_handoff",
]
