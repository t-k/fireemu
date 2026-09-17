# ruff: noqa: I001 -- Load the limits module path bootstrap before shared imports.
"""Connect admitted limits collection to Coordinator without a second Gate dispatch.

This is an internal execution component, not O7 approval or a production CLI.
The caller must first freeze permission, reserve the envelope/locks and nonce,
verify the checkout/artifact and complete Coordinator acquisition/preflight.
"""

from __future__ import annotations

import json
import math
import time
import threading

from production_plan import production_plan
from remote_transport import prepare, request
from shadow import source_inputs

from batch_adapter import observer_digest
from broad_contract import digest
from shared_production import Coordinator, ProductionGate

TRANSPORT = "limits-explicit-production-v1"


class LimitsGate(ProductionGate):
    """Expose one wire attempt only inside the existing charged dispatch callback."""

    def __init__(self, path, job="limits"):
        super().__init__(path, job)
        self._wire_context = None

    def dispatch(self, operation, recovery, send):
        def admitted():
            self._wire_context = (threading.get_ident(), digest(operation), recovery)
            try:
                return send()
            finally:
                self._wire_context = None

        return super().dispatch(operation, recovery, admitted)

    def consume_wire(self, operation, recovery):
        if self._wire_context != (threading.get_ident(), digest(operation), recovery):
            raise ValueError("wire requires the charged Gate callback")
        self._wire_context = None


def source_digest():
    return digest({"shared": observer_digest(), "limits": source_inputs()})


def execution_plan(permission, nonce):
    """Bind an inert execution plan; this function grants no permission."""
    plan = production_plan(nonce)["gatePlan"]
    plan.update(
        transport=TRANSPORT,
        permissionDigest=digest(permission),
        collectorSourceDigest=source_digest(),
    )
    return plan


def bind_wire(coordinator, plan, *, transmit=request):
    """Return the collector wire callback, called inside Gate.dispatch after waiting.

    No callback below reacquires a Gate lock or refreshes credentials. The
    collector's before_recovery hook must call coordinator.recover_credentials
    outside dispatch; the outer runner owns final metadata readback.
    """
    if not isinstance(coordinator, Coordinator) or not isinstance(
        coordinator.gate, LimitsGate
    ):
        raise TypeError("existing production Coordinator required")
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
        bound_gate.consume_wire(operation, recovery)
        validate(recovery)
        value = {
            "nonce": nonce,
            "phase": phase,
            "index": index,
            "operation": operation,
            "token": coordinator.access(),
        }
        prepare(value)
        result = transmit(value)
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
