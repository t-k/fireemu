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
import reservations
import o8_admission
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
    requests = len(job["observation"]) + len(job["recovery"])
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
        "durationSeconds": 300,
    }


def _runtime_body(operation: dict, bindings: dict[str, str]) -> dict:
    return _resolve(operation["body"], bindings)


def _wire_body(plan: dict, operation: dict, bindings: dict[str, str]) -> dict:
    rows = (*plan["stages"], *plan["recovery"])
    row = next((candidate for candidate in rows if candidate["id"] == operation["id"]), None)
    if row is None:
        raise ValueError("Action operation is outside frozen manifest")
    return _resolve(row["body"], bindings)


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
    fixture_origin: str,
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
    gate_module.create(output / "gate", gate_plan)
    handle = gate_module.ActionGate(output / "gate", gate_module.JOB)
    handle.claim()
    transport_bindings = copy.deepcopy(bindings)
    for stage_bindings in transport_bindings.values():
        for name in tuple(stage_bindings):
            if name in remote.GENERATED_BINDINGS and not name.endswith(".localId"):
                stage_bindings[name] = "$generated:" + name
    remote.make_transport(
        frozen_inputs=inputs,
        declared_bindings=transport_bindings,
        credential_handoff=credential_handoff,
        verify_handoff=verify_handoff,
        fixture_origin=fixture_origin,
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

    def dispatch_one(operation, is_recovery):
        body = _wire_body(plan, operation, runtime)
        result = remote.send(
            capability,
            stage_id=operation["id"],
            project=project,
            nonce=nonce,
            body=body,
            deadline=min(time.monotonic() + 8, run_started + (180 if is_recovery else 300)),
            binding=binding,
            binding_digest=binding_digest,
            inputs_digest=inputs["inputsDigest"],
        )
        handle.dispatch(operation, is_recovery, lambda result=result: result)
        status, response = result
        if status == 200 and operation.get("kind") == "sign-up":
            account = operation["account"]
            runtime[account + ".localId"] = response["localId"]
            runtime[account + "Uid"] = response["localId"]
        for name in operation.get("binds", {}):
            if isinstance(response, dict) and isinstance(response.get(operation["binds"][name]), str):
                runtime[name] = response[operation["binds"][name]]
        return result

    try:
        for operation in observations:
            dispatch_one(operation, False)
    except Exception:
        handle.abandon_observation("action-observation-failure")
        for operation in recovery:
            try:
                dispatch_one(operation, True)
            except Exception:
                continue
        raise
    else:
        for operation in recovery:
            dispatch_one(operation, True)
        handle.finish()
        ledger.finish(ticket)
        snapshot = handle.snapshot()
    finally:
        remote.forget_transport(inputs["inputsDigest"])
    return {
        "campaignId": descriptor.CAMPAIGN,
        "planDigest": digest(plan),
        "gateDigest": digest(snapshot),
        "ticket": ticket,
        "requests": snapshot["total"],
        "observation": snapshot["observation"],
        "recovery": snapshot["recovery"],
        "reservation": ledger.snapshot()["reservations"][ticket["reservation"]]["state"],
    }


__all__ = ["execute"]
