# ruff: noqa: I001 -- Load the limits module path bootstrap before shared imports.
"""Connect admitted limits collection to Coordinator without a second Gate dispatch.

This is an internal execution component, not O7 approval or a production CLI.
The caller must first freeze permission, reserve the envelope/locks and nonce,
verify the checkout/artifact and complete Coordinator acquisition/preflight.
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import json
import math
import time
import threading

from production_plan import production_plan
from remote_transport import (
    _request,
    prepare,
)
from transport import _exchange
from shadow import source_inputs

from batch_adapter import observer_digest
from broad_contract import digest
from shared_production import Coordinator, ProductionGate

ADMISSION_SOURCE = (
    Path(__file__).resolve().parent.parent / "production-admission/reservations.py"
)
sys.path.insert(0, str(ADMISSION_SOURCE.parent))
from reservations import Ledger

TRANSPORT = "limits-explicit-production-v1"


class LimitsGate(ProductionGate):
    """Expose one wire attempt only inside the existing charged dispatch callback."""

    def __init__(self, path, job="limits"):
        super().__init__(path, job)
        self._wire_context = None

    def dispatch(self, operation, recovery, send):
        # Capture immutable phase timing before entering dispatch's held Gate lock.
        state = self.snapshot()
        deadline = (
            state["started"]
            + state["plan"]["wallSeconds"]
            - (0 if recovery else state["plan"]["recoverySeconds"])
        )

        def admitted():
            self._wire_context = (
                threading.get_ident(),
                digest(operation),
                recovery,
                deadline,
            )
            try:
                return send()
            finally:
                self._wire_context = None

        return super().dispatch(operation, recovery, admitted)

    def consume_wire(self, operation, recovery):
        if self._wire_context is None or self._wire_context[:3] != (
            threading.get_ident(),
            digest(operation),
            recovery,
        ):
            raise ValueError("wire requires the charged Gate callback")
        deadline = self._wire_context[3]
        self._wire_context = None
        return deadline


def source_digest():
    return digest(
        {
            "shared": observer_digest(),
            "limits": source_inputs(),
            "sharedReservations": hashlib.sha256(
                ADMISSION_SOURCE.read_bytes()
            ).hexdigest(),
        }
    )


def execution_plan(permission, nonce):
    """Bind an inert execution plan; this function grants no permission."""
    plan = production_plan(nonce)["gatePlan"]
    plan.update(
        transport=TRANSPORT,
        permissionDigest=digest(permission),
        collectorSourceDigest=source_digest(),
    )
    return plan


def bind_wire(
    coordinator,
    plan,
    *,
    transmit=_request,
    artifact=None,
    artifact_sha256=None,
    production=False,
):
    """Return the collector wire callback, called inside Gate.dispatch after waiting.

    No callback below reacquires a Gate lock or refreshes credentials. The
    collector's before_recovery hook must call coordinator.recover_credentials
    outside dispatch; the outer runner owns final metadata readback.
    """
    if not isinstance(coordinator, Coordinator) or not isinstance(
        coordinator.gate, LimitsGate
    ):
        raise TypeError("existing production Coordinator required")
    if production:
        if transmit is not _request:
            raise ValueError("production bridge requires fixed remote transport")
        if not isinstance(coordinator, ReservedCoordinator):
            raise ValueError("reserved O7 coordinator required for production")
        coordinator.validate_reservation()
        if not isinstance(artifact, (str, Path)) or not isinstance(
            artifact_sha256, str
        ):
            raise ValueError("production artifact binding required")
        artifact = Path(artifact).resolve()
        if artifact.is_symlink() or not artifact.is_file():
            raise ValueError("regular production artifact required")
        with artifact.open("rb") as stream:
            initial_artifact = hashlib.file_digest(stream, "sha256").hexdigest()
        if initial_artifact != artifact_sha256:
            raise ValueError("production artifact binding changed")
    frozen = json.loads(json.dumps(plan, allow_nan=False))
    nonce = frozen.get("nonce")
    if (
        digest(frozen) != digest(execution_plan(coordinator.permission, nonce))
        or digest(coordinator.gate.snapshot()["plan"]) != digest(frozen)
        or coordinator.gate.job != "limits"
    ):
        raise ValueError("closed limits execution plan required")
    bound_gate = coordinator.gate
    key_digest = coordinator.key_digest
    def send_value(value):
        if production:
            prepared = prepare(value)
            return _exchange(**prepared, timeout=12)
        return transmit(value)

    def validate(recovery):
        expiry = coordinator.permission.get("expiresAt")
        if (
            coordinator.gate is not bound_gate
            or coordinator.local is not None
            or coordinator.ready is not True
            or coordinator.nonce != nonce
            or digest(coordinator.permission) != frozen["permissionDigest"]
            or coordinator.permission.get("collectorSourceDigest")
            != frozen["collectorSourceDigest"]
            or source_digest() != frozen["collectorSourceDigest"]
            or digest(coordinator.api_key) != key_digest
            or coordinator.key_digest != key_digest
            or type(expiry) not in (int, float)
            or not math.isfinite(expiry)
            or time.time() + 13 > expiry
            or coordinator.budget.recovery is not recovery
            or not coordinator.credential.usable(time.monotonic(), 13)
        ):
            raise ValueError("limits production binding or credential changed")

    validate(False)

    if production:
        def validate_session(value):
            if not isinstance(value, dict) or value.get("phase") not in (
                "observation",
                "recovery",
            ):
                raise ValueError("invalid production bridge request")
            validate(value["phase"] == "recovery")
            with artifact.open("rb") as stream:
                current_artifact = hashlib.file_digest(stream, "sha256").hexdigest()
            if current_artifact != artifact_sha256:
                raise ValueError("production artifact binding changed")


    def wire(operation, recovery, index, request_index):
        # Gate has already waited and charged the attempt. Reject drift before I/O.
        if (
            type(recovery) is not bool
            or type(index) is not int
            or type(request_index) is not int
        ):
            raise ValueError("typed collector position required")
        phase = "recovery" if recovery else "observation"
        offset = len(frozen["jobs"]["limits"]["observation"]) if recovery else 0
        if request_index != offset + index:
            raise ValueError("collector position differs")
        phase_deadline = bound_gate.consume_wire(operation, recovery)
        validate(recovery)
        if production:
            coordinator.validate_reservation()
        if production:
            with artifact.open("rb") as stream:
                current_artifact = hashlib.file_digest(stream, "sha256").hexdigest()
            if current_artifact != artifact_sha256:
                raise ValueError("production artifact binding changed")
        value = {
            "nonce": nonce,
            "phase": phase,
            "index": index,
            "operation": operation,
            "token": coordinator.access(),
        }
        prepare(value)
        if time.monotonic() + 13 > phase_deadline:
            raise ValueError("phase deadline after shared admission wait")
        result = send_value(value)
        if result.get("status") in {401, 403}:
            # Retain the complete response for the collector before it stops.
            # Never refresh/reuse a principal already rejected by production.
            coordinator.credential.fail()
            return {**result, "failure": "AdministratorCredentialRejected"}
        status = result.get("status")
        if type(status) is int and (status == 429 or status >= 500):
            return {**result, "failure": "UnexpectedServiceResponse"}
        return result

    return wire


class ReservedCoordinator(Coordinator):
    """Limits Coordinator whose metadata attempts also require the shared lease."""

    def __init__(self, permission, nonce, output, gate, api_key, *, ledger, ticket):
        if not isinstance(ledger, Ledger) or not isinstance(gate, LimitsGate):
            raise TypeError("shared ledger and limits Gate required")
        frozen_plan = gate.snapshot()["plan"]
        claim = ledger.bound_claim(ticket)
        if claim["gatePath"] != str(gate.path.resolve()) or claim[
            "gatePlanDigest"
        ] != digest(frozen_plan):
            raise ValueError("reservation belongs to another Gate")
        self.ledger = ledger
        self.reservation_ticket = json.loads(json.dumps(ticket))
        self._reserved_ledger = ledger
        self._reserved_ledger_path = str(ledger.path)
        self._reserved_ledger_identity = ledger.identity
        self._reserved_ticket_digest = digest(self.reservation_ticket)
        self._reserved_gate_path = str(gate.path.resolve())
        self._reserved_gate_plan_digest = digest(frozen_plan)
        self._reserved_claim_digest = digest(claim)
        self.reserved_permission_digest = frozen_plan["permissionDigest"]
        self.reserved_source_digest = frozen_plan["collectorSourceDigest"]
        ledger.validate(self.reservation_ticket)
        super().__init__(permission, nonce, output, gate, api_key)

    def reserve(self, service, duration=12):
        # super.reserve performs the existing rate wait and durable attempt debit.
        super().reserve(service, duration)
        self.validate_reservation(duration + 1)
        # manage already holds this state; never reacquire Gate.snapshot here.
        context = self.management_context
        if context is None:
            raise ValueError("management context changed")
        state, _ = context
        deadline = (
            state["started"]
            + state["plan"]["wallSeconds"]
            - (0 if self.budget.recovery else state["plan"]["recoverySeconds"])
        )
        if time.monotonic() + duration + 1 > deadline:
            raise ValueError("phase deadline after shared admission wait")
        if time.time() + duration + 1 > (self.permission or {})["expiresAt"]:
            raise ValueError("permission deadline after shared admission wait")

    def validate_reservation(self, duration=13):
        if (
            self.ledger is not self._reserved_ledger
            or str(self.ledger.path) != self._reserved_ledger_path
            or self.ledger.identity != self._reserved_ledger_identity
            or digest(self.reservation_ticket) != self._reserved_ticket_digest
            or digest(self.permission) != self.reserved_permission_digest
            or source_digest() != self.reserved_source_digest
        ):
            raise ValueError("reserved production binding changed")
        if str(self.gate.path.resolve()) != self._reserved_gate_path:
            raise ValueError("reserved production binding changed")
        if (
            self.ledger.validate(self.reservation_ticket, duration=duration)
            != self._reserved_claim_digest
        ):
            raise ValueError("reserved production binding changed")


def bind_reserved_wire(
    coordinator,
    plan,
    *,
    transmit=_request,
    artifact=None,
    artifact_sha256=None,
    production=False,
):
    """The outer runner must use this lease-bound variant after O7 admission."""
    if not isinstance(coordinator, ReservedCoordinator):
        raise TypeError("shared-reservation Coordinator required")
    coordinator.validate_reservation()
    wire = bind_wire(
        coordinator,
        plan,
        transmit=transmit,
        artifact=artifact,
        artifact_sha256=artifact_sha256,
        production=production,
    )

    def reserved(operation, recovery, index, request_index):
        coordinator.validate_reservation()
        return wire(operation, recovery, index, request_index)

    if hasattr(wire, "close"):
        reserved.close = wire.close

    return reserved
