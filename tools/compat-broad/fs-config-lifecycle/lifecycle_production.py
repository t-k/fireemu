"""One admitted FS-CONFIG-LIFECYCLE acquisition, with immutable offline evidence.

`execute` is the production path: it consumes the capability, reserves the shared
Ledger under the EXCLUSIVE field-configuration locks, creates the configuration gate,
reads the private credential handoff only after the reservation, and drives the
collector through the capability-bound wire. `execute_reserved` is the same
reservation-to-receipt path with an injected transport; it exists for the integration
proof against a temporary Ledger and refuses any Ledger that is not marked as one.

Neither path releases the reservation today: `lifecycle_admission.release_supported`
says the shared core cannot retire a configuration-only reservation, and the receipt
carries the typed release-blocked record instead of a release record.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "tools/compat-broad"))
sys.path.insert(0, str(ROOT / "tools/compat-broad/production-admission"))
sys.path.insert(0, str(ROOT / "tools/compat-broad/o8-core"))
sys.path.insert(0, str(HERE))

import _lane

_lane.ensure_package()

import o8_admission
import reservations
from broad_contract import digest
from fs_config_lifecycle import lifecycle_admission as admission
from fs_config_lifecycle import lifecycle_descriptor as campaign
from fs_config_lifecycle.lifecycle_collector import collect
from fs_config_lifecycle.lifecycle_gate import ConfigurationGate, create

PROOF_MARKER = "PROOF-LEDGER"


def _write_receipt(path: Path, receipt: dict) -> None:
    encoded = json.dumps(
        receipt, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()
    if len(encoded) > reservations.MAX_BYTES:
        raise ValueError("bounded immutable production evidence required")
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, path, follow_symlinks=False)
    finally:
        os.unlink(temporary)
    directory = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _proof_ledger(ledger_root) -> None:
    """An injected transport may reserve only in a Ledger created for a proof."""
    root = Path(ledger_root)
    marker = root / PROOF_MARKER
    if root.is_symlink() or marker.is_symlink() or not marker.is_file():
        raise ValueError(
            "injected transport requires a proof Ledger, never the canonical one"
        )


def execute_reserved(
    *,
    inputs,
    permission,
    ledger_root,
    output,
    transmit,
    capability=None,
    credential_reader=None,
    sleeper=None,
):
    """Reserve, gate, collect, receipt, and the typed release disposition."""
    inputs, permission = copy.deepcopy(inputs), copy.deepcopy(permission)
    admission.validate_frozen_inputs(inputs)
    if digest(permission) != inputs["permissionDigest"]:
        raise ValueError("independent permission differs from frozen inputs")
    if capability is None:
        _proof_ledger(ledger_root)
        o8_admission.reject_production_transport(admission.descriptor(), transmit)
    output = Path(output)
    if output.exists() or output.is_symlink():
        raise ValueError("fresh production output required")
    ledger = reservations.Ledger(ledger_root)
    plan = campaign.execution_plan(inputs["plan"])
    gate_plan = admission.gate_plan_for(inputs, permission)
    generation = admission.abort_generation(inputs)
    claim = admission.reservation_claim(
        inputs, gate_path=output / "gate", gate_plan=gate_plan
    )
    worker_sha256 = capability.binding_digest if capability is not None else None
    if capability is not None:
        capability._consume(
            campaign_id=claim["campaignId"],
            inputs_digest=inputs["inputsDigest"],
            ledger_root=ledger_root,
        )
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    output = output.resolve()
    _write_receipt(output / "inputs.json", inputs)
    ticket = ledger.reserve(
        admission.envelope(permission, claim), claim, gate_plan, generation=generation
    )
    result = None
    failure = None
    gate = None
    token = None
    try:
        create(output / "gate", gate_plan)
        gate = ConfigurationGate(output / "gate")
        if capability is not None:
            token = credential_reader()

            def execute_wire(request, *, deadline):
                return capability._transmit(
                    {"request": request, "token": token, "deadline": deadline}
                )

            wire = execute_wire
        else:
            wire = transmit
        extra = {} if sleeper is None else {"sleeper": sleeper}
        result = collect(plan["nonce"], wire, output / "collection", gate=gate, **extra)
        token = None
        if not result.get("cleanupComplete"):
            failure = "restore-incomplete"
    except Exception as error:  # noqa: BLE001 -- preserve only a secret-free failure class.
        failure = type(error).__name__
    finally:
        if capability is not None:
            o8_admission.revoke_production_capability(capability)
    snapshot = gate.snapshot() if gate is not None else None
    if snapshot is not None:
        _write_receipt(output / "gate-snapshot.json", snapshot)
    evidence = {}
    for path in [
        output / "inputs.json",
        output / "gate-snapshot.json",
        *sorted((output / "collection").glob("*")),
    ]:
        if path.is_file():
            evidence[str(path.relative_to(output))] = hashlib.sha256(
                path.read_bytes()
            ).hexdigest()
    receipt = admission.build_receipt(
        inputs,
        result,
        production=capability is not None,
        worker_sha256=worker_sha256,
        generation=generation,
        failure=failure,
    )
    disposition = admission.classify_stop(receipt)
    supported, blocker = admission.release_supported()
    receipt.update(
        ticket=ticket,
        claimDigest=digest(claim),
        campaignPlanDigest=inputs["planDigest"],
        gatePlanDigest=digest(gate_plan),
        gateDigest=digest(snapshot) if snapshot is not None else None,
        evidenceFiles=evidence,
        chargedCalls=snapshot["total"] if snapshot else 0,
        chargedMicrousd=snapshot["costMicrousd"] if snapshot else 0,
        disposition=disposition,
        reservationStateAtPublication="held",
        releaseEligible=bool(disposition["releaseEligible"]),
        releaseRecord=None,
        releaseBlocked=None
        if supported
        else {"kind": admission.RELEASE_BLOCKED_KIND, **blocker},
        productionExecuted=capability is not None
        and bool((result or {}).get("rowCount")),
    )
    _write_receipt(output / "receipt.json", receipt)
    return {
        **receipt,
        "failure": failure,
        "reservationReleased": False,
        "reservationFinal": ledger.snapshot()["reservations"][ticket["reservation"]],
    }


def execute(*, capability, inputs, permission, credential_reader, ledger_root, output):
    """Execute only the consumed capability's fixed transport; never accept one."""
    if not admission.issued_capability(capability):
        raise ValueError("unissued O7 production capability")
    return execute_reserved(
        inputs=inputs,
        permission=permission,
        ledger_root=ledger_root,
        output=output,
        transmit=None,
        capability=capability,
        credential_reader=credential_reader,
    )
