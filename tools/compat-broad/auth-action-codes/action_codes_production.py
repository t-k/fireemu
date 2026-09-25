"""Bounded local-shadow executor for the typed AUTH-ACTION Gate.

The executor is deliberately fixture-only: O7/O8 admission, the shared Ledger,
the typed Gate, and the reviewed bounded worker are exercised together, while a
caller must explicitly provide the loopback origin and private handoff.
"""

from __future__ import annotations

import copy
import hashlib
import json
import sys
import time
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "tools/compat-broad"))
sys.path.insert(0, str(ROOT / "tools/compat-broad/production-admission"))
sys.path.insert(0, str(ROOT / "tools/compat-broad/o8-core"))
sys.path.insert(0, str(HERE))

import action_codes_admission as admission
import action_codes_descriptor as descriptor
import action_codes_gate as gate_module
import action_codes_remote_transport as remote
import o8_admission
import reservations
from broad_contract import digest


def _resolve(value: Any, bindings: dict[str, str]) -> Any:
    if isinstance(value, str) and value.startswith("$binding:"):
        name = value.removeprefix("$binding:")
        if name not in bindings:
            raise ValueError("Action runtime binding missing")
        return bindings[name]
    if isinstance(value, dict):
        return {key: _resolve(item, bindings) for key, item in value.items()}
    if isinstance(value, list):
        return [_resolve(item, bindings) for item in value]
    return value


def _envelope(permission: dict, claim: dict, now: float) -> dict:
    return {
        "permissionDigest": digest(permission),
        "issuedAt": now - 1,
        "expiresAt": now + claim["durationSeconds"] + 30,
        "limits": copy.deepcopy(claim["budget"]),
        "concurrency": 1,
        "scopes": copy.deepcopy(claim["locks"]),
    }


def _claim(inputs: dict, plan: dict, gate_plan: dict, output: Path) -> dict:
    job = gate_plan["jobs"][gate_module.JOB]
    resources = len(job["resources"])
    management = gate_plan.get("management", {})
    requests = (
        len(job["observation"])
        + len(job["recovery"])
        + len(management.get("observation", []))
        + len(management.get("recovery", []))
    )
    return {
        "campaignId": descriptor.CAMPAIGN,
        "manifestDigest": inputs["planDigest"],
        "nonceDigest": digest(plan["nonce"]),
        "gatePath": str((output / "gate").resolve()),
        "gatePlanDigest": digest(gate_plan),
        "gateJob": gate_module.JOB,
        "locks": descriptor.lock_scopes(plan),
        "budget": {
            "requests": requests,
            "accounts": resources,
            "resources": resources,
            "costMicrousd": gate_plan["costMicrousd"],
        },
        # The owner window covers observation plus recovery; the phase bounds
        # remain 300 and 180 seconds inside this 480-second reservation.
        "durationSeconds": 480,
    }


def _runtime_body(operation: dict, bindings: dict[str, str]) -> dict:
    return _resolve(operation["body"], bindings)


def _wire_body(plan: dict, operation: dict, bindings: dict[str, str]) -> dict:
    rows = (*plan["stages"], *plan["recovery"])
    row = next((candidate for candidate in rows if candidate["id"] == operation["id"]), None)
    if row is None:
        raise ValueError("Action operation is outside frozen manifest")
    return _resolve(row["body"], bindings)


def _operation_deadline(now, run_started, *, is_recovery, wall_seconds, recovery_seconds):
    phase_end = run_started + (wall_seconds + recovery_seconds if is_recovery else wall_seconds)
    return min(now + 8, phase_end)


def _persist_receipt(
    output: Path,
    *,
    plan: dict,
    snapshot: dict,
    reservation: str,
    error: str | None = None,
    terminal_phase: str = "complete",
    primary_error: str | None = None,
    cleanup_errors: list[dict[str, str]] | None = None,
    reservation_state: str = "unknown",
) -> None:
    """Persist only bounded execution facts; never persist credentials or bodies."""
    cleanup_errors = cleanup_errors or []
    receipt = {
        "kind": "auth-action-production-receipt-v1",
        "campaignId": descriptor.CAMPAIGN,
        "planDigest": digest(plan),
        "gateDigest": digest(snapshot),
        "requests": snapshot.get("total"),
        "observation": snapshot.get("observation"),
        "recovery": snapshot.get("recovery"),
        "reservation": reservation,
        "cleanup": {
            "complete": snapshot.get("jobs", {}).get(gate_module.JOB, {}).get("complete"),
            "owned": snapshot.get("jobs", {}).get(gate_module.JOB, {}).get("owned", []),
            "absent": snapshot.get("jobs", {}).get(gate_module.JOB, {}).get("absent", []),
        },
        "error": error,
        "reservationState": reservation_state,
        "reservationReleased": reservation_state == "released",
        "terminal": {
            "phase": terminal_phase,
            "primaryError": primary_error,
            "cleanupErrors": cleanup_errors,
            "releaseEvidence": reservation_state == "released",
        },
    }
    path = output / "production-receipt.json"
    with path.open("x", encoding="utf-8") as stream:
        json.dump(receipt, stream, sort_keys=True, separators=(",", ":"), allow_nan=False)
        stream.write("\n")


def execute(
    *,
    capability,
    inputs: dict,
    permission: dict,
    ledger_root: Path,
    output: Path,
    bindings: dict[str, dict[str, str]],
    credential_handoff: dict,
    verify_handoff,
    fixture_origin: str | None = None,
    production: bool = False,
    permission_expires_at: float | None = None,
) -> dict:
    """Run all 26 observation and 6 recovery slots through one O8 capability."""
    if not o8_admission.issued_capability(capability):
        raise ValueError("unissued O8 production capability")
    admission.validate_frozen_inputs(inputs)
    if digest(permission) != inputs["permissionDigest"]:
        raise ValueError("independent Action permission differs")
    output = Path(output)
    ledger_root = Path(ledger_root)
    if output.exists() or output.is_symlink():
        raise ValueError("fresh Action output required")
    if not ledger_root.is_dir() or not (ledger_root / "state.json").is_file():
        raise ValueError("existing temporary Ledger required")
    plan = inputs["plan"]
    project = permission.get("projectId")
    nonce = plan.get("nonce")
    gate_plan = gate_module.gate_plan(project, nonce)
    gate_plan["permissionDigest"] = digest(permission)
    gate_plan["permissionExpiresAt"] = permission_expires_at or time.time() + 600
    claim = _claim(inputs, plan, gate_plan, output)
    now = time.time()
    envelope = _envelope(permission, claim, now)
    ledger = reservations.Ledger(ledger_root)
    capability._consume(
        campaign_id=claim["campaignId"],
        inputs_digest=inputs["inputsDigest"],
        ledger_root=ledger_root,
    )
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    ticket = ledger.reserve(envelope, claim, gate_plan)
    handle = None
    transport_started = False

    snapshot = {}
    primary_error = None
    primary_traceback = None
    terminal_error = None
    terminal_phase = "complete"
    cleanup_errors = []
    reservation_state = "unknown"

    def remember_primary(error, phase, label):
        nonlocal primary_error, primary_traceback, terminal_error, terminal_phase
        if primary_error is None:
            primary_error = error
            primary_traceback = error.__traceback__
            terminal_error = label
            terminal_phase = phase

    def remember_cleanup_error(error, phase):
        cleanup_errors.append({"phase": phase, "error": type(error).__name__})

    def record_terminal():
        nonlocal snapshot, reservation_state, primary_error, primary_traceback
        if handle is not None:
            try:
                snapshot = handle.snapshot()
            except Exception as error:  # noqa: BLE001 -- terminal evidence must survive Gate failures.
                remember_cleanup_error(error, "gate-snapshot")
                if primary_error is None:
                    remember_primary(error, "terminal-record", "action-terminal-record-failure")
                snapshot = {}
        try:
            ledger_state = ledger.snapshot()
            row = ledger_state.get("reservations", {}).get(ticket["reservation"])
            state = row.get("state") if isinstance(row, dict) else None
            if state in {"held", "released"}:
                reservation_state = state
        except Exception as error:  # noqa: BLE001 -- terminal evidence must survive Ledger failures.
            remember_cleanup_error(error, "ledger-snapshot")
            if primary_error is None:
                remember_primary(error, "terminal-record", "action-terminal-record-failure")
        try:
            _persist_receipt(
                output,
                plan=plan,
                snapshot=snapshot,
                reservation=ticket["reservation"],
                error=terminal_error,
                terminal_phase=terminal_phase,
                primary_error=(
                    type(primary_error).__name__ if primary_error is not None else None
                ),
                cleanup_errors=cleanup_errors,
                reservation_state=reservation_state,
            )
        except Exception as error:  # noqa: BLE001 -- preserve the primary failure.
            remember_cleanup_error(error, "terminal-record")
            if primary_error is None:
                primary_error = error
                primary_traceback = error.__traceback__

    def finish_terminal():
        if transport_started:
            try:
                remote.forget_transport(inputs["inputsDigest"])
            except Exception as error:  # noqa: BLE001 -- transport cleanup cannot replace primary failure.
                remember_cleanup_error(error, "transport-forget")
        record_terminal()

    try:
        gate_module.create(output / "gate", gate_plan)
        handle = gate_module.ActionGate(output / "gate", gate_module.JOB)
        handle.claim()
    except Exception as error:  # noqa: BLE001 -- preserve Gate setup failure after reservation.
        remember_primary(error, "gate-setup", "action-gate-setup-failure")
        finish_terminal()
        raise primary_error.with_traceback(primary_traceback)

    def prepare():
        nonlocal transport_started
        transport_bindings = copy.deepcopy(bindings)
        for stage_bindings in transport_bindings.values():
            for name in tuple(stage_bindings):
                if name in remote.GENERATED_BINDINGS and not name.endswith(".localId"):
                    stage_bindings[name] = "$generated:" + name
        transport_started = True
        remote.make_transport(
            frozen_inputs=inputs,
            declared_bindings=transport_bindings,
            credential_handoff=credential_handoff,
            verify_handoff=verify_handoff,
            fixture_origin=fixture_origin,
            production=production,
        )
        binding = (ROOT / descriptor.WORKER_ENTRY).read_bytes()
        binding_digest = hashlib.sha256(binding).hexdigest()
        runtime = {
            name: value
            for stage_bindings in bindings.values()
            for name, value in stage_bindings.items()
        }
        for account in ("accountA", "accountB"):
            if account + ".localId" in runtime:
                runtime[account + "Uid"] = runtime[account + ".localId"]
        observations = gate_plan["jobs"][gate_module.JOB]["observation"]
        recovery = gate_plan["jobs"][gate_module.JOB]["recovery"]
        run_started = time.monotonic()

        def management(slot_id, deadline):
            return remote.management_receipt(
                slot_id=slot_id,
                deadline=deadline,
                capability=capability,
                binding=binding,
                binding_digest=binding_digest,
                handoff=credential_handoff,
                permission=permission,
                required_seconds=gate_plan["wallSeconds"] + gate_plan["recoverySeconds"],
                fixture_origin=fixture_origin,
            )

        handle.management_dispatch(
            "observation", "oauth-tokeninfo", lambda deadline: management("oauth-tokeninfo", deadline)
        )
        handle.management_dispatch(
            "observation", "auth-project-readback", lambda deadline: management("auth-project-readback", deadline)
        )

        def dispatch_one(operation, is_recovery):
            body = _wire_body(plan, operation, runtime)
            deadline = _operation_deadline(
                time.monotonic(),
                run_started,
                is_recovery=is_recovery,
                wall_seconds=gate_plan["wallSeconds"],
                recovery_seconds=gate_plan["recoverySeconds"],
            )
            result = handle.dispatch(
                operation,
                is_recovery,
                lambda: remote.send(
                    capability,
                    stage_id=operation["id"],
                    project=project,
                    nonce=nonce,
                    body=body,
                    deadline=deadline,
                    binding=binding,
                    binding_digest=binding_digest,
                    inputs_digest=inputs["inputsDigest"],
                ),
            )
            status, response = result
            if status == 200 and operation.get("kind") == "sign-up":
                account = operation["account"]
                runtime[account + ".localId"] = response["localId"]
                runtime[account + "Uid"] = response["localId"]
            for name in operation.get("binds", {}):
                if isinstance(response, dict) and isinstance(
                    response.get(operation["binds"][name]), str
                ):
                    runtime[name] = response[operation["binds"][name]]
            return result

        return observations, recovery, dispatch_one

    try:
        observations, recovery, dispatch_one = prepare()
    except Exception as error:  # noqa: BLE001 -- preserve preflight/setup failure.
        remember_primary(error, "preflight", "action-preflight-failure")
        finish_terminal()
        raise primary_error.with_traceback(primary_traceback)

    try:
        try:
            for operation in observations:
                dispatch_one(operation, False)
        except Exception as error:  # noqa: BLE001 -- preserve the observation failure.
            remember_primary(
                error,
                "observation",
                "action-observation-failure",
            )
            try:
                handle.abandon_observation("action-observation-failure")
            except Exception as cleanup_error:  # noqa: BLE001 -- retain cleanup status.
                remember_cleanup_error(cleanup_error, "observation-abandon")
            for operation in recovery:
                try:
                    dispatch_one(operation, True)
                except Exception as cleanup_error:  # noqa: BLE001 -- retain cleanup status.
                    remember_cleanup_error(cleanup_error, "recovery")
        else:
            for operation in recovery:
                try:
                    dispatch_one(operation, True)
                except Exception as error:  # noqa: BLE001 -- preserve the recovery failure.
                    remember_primary(error, "recovery", "action-recovery-failure")
                    break
            if primary_error is None:
                try:
                    handle.finish()
                except Exception as error:  # noqa: BLE001 -- preserve Gate finish refusal.
                    remember_primary(error, "gate-finish", "action-gate-finish-failure")
            if primary_error is None:
                try:
                    ledger.finish(ticket)
                    ledger_state = ledger.snapshot()
                    row = ledger_state.get("reservations", {}).get(ticket["reservation"])
                    if not isinstance(row, dict) or row.get("state") != "released":
                        raise ValueError("reservation release evidence missing")
                except Exception as error:  # noqa: BLE001 -- never imply an unverified release.
                    remember_primary(error, "ledger-finish", "action-ledger-finish-failure")
    finally:
        finish_terminal()

    if primary_error is not None:
        raise primary_error.with_traceback(primary_traceback)
    return {
        "campaignId": descriptor.CAMPAIGN,
        "planDigest": digest(plan),
        "gateDigest": digest(snapshot),
        "ticket": ticket,
        "requests": snapshot["total"],
        "observation": snapshot["observation"],
        "recovery": snapshot["recovery"],
        "reservation": reservation_state,
    }


__all__ = ["execute"]
