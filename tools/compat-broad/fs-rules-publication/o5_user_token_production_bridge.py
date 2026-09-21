"""Capability-bound production bridge for the Rules user-token campaign.

This module owns orchestration glue only. O7, the worker binding, transport,
Gate, Ledger and the collector remain the authority for their respective
checks; this bridge never creates credentials or manufactures identity proof.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

from broad_contract import digest
from o5_user_token_campaign import budget as campaign_budget
from o5_user_token_collector import RulesManagementSession
from o5_user_token_descriptor import CAMPAIGN, collector, gate_plan
from o5_user_token_remote_transport import (
    make_transport,
    verify_worker_binding,
    worker_binding,
)
from o8_admission import authorize_transport

TOTAL_REQUESTS = 146
RULES_REQUESTS = 23
OBSERVATION_REQUESTS = 33
RECOVERY_REQUESTS = 63
WORKER_TIMEOUT_SECONDS = 8.0


def validate_compiled_accounting(plan: dict[str, Any]) -> dict[str, int]:
    """Require the compiler's complete 146-request accounting."""
    estimate = campaign_budget(plan)
    expected = {
        "observationRequests": OBSERVATION_REQUESTS,
        "fixtureRequests": 10,
        "authRequests": 17,
        "rulesRequests": RULES_REQUESTS,
        "recoveryRequests": RECOVERY_REQUESTS,
        "requestUpperBound": TOTAL_REQUESTS,
    }
    if any(estimate.get(key) != value for key, value in expected.items()):
        raise ValueError("Rules campaign accounting differs")
    return expected


def bound_execute(
    plan: dict[str, Any],
    *,
    credentials: dict[str, Any],
    frozen_inputs: dict[str, Any],
    account_bindings: dict[str, Any],
    identity_proofs: dict[str, Any],
    capability: Any,
    fixture_origin: str | None = None,
) -> Callable[..., dict[str, Any]]:
    """Return the collector callback carrying the exact O7 worker binding."""
    if capability is None:
        raise ValueError("active O8 production capability required")
    binding, binding_digest = worker_binding()
    verify_worker_binding(binding, binding_digest, frozen_inputs.get("sourceInputs"))
    transport = make_transport(
        plan,
        credentials=credentials,
        frozen_inputs=frozen_inputs,
        account_bindings=account_bindings,
        identity_proofs=identity_proofs,
        fixture_origin=fixture_origin,
    )

    def execute(operation: dict[str, Any], *, deadline: float | None = None) -> dict[str, Any]:
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining < WORKER_TIMEOUT_SECONDS:
                raise TimeoutError("Rules worker cannot fit within Gate deadline")
        authorize_transport(capability, binding=binding, binding_digest=binding_digest)
        return transport(
            operation,
            binding=binding,
            binding_digest=binding_digest,
            capability=capability,
        )

    return execute


def run_bound_collection(
    *,
    plan: dict[str, Any],
    gate: Any,
    ledger: Any,
    ticket: dict[str, Any],
    execute: Callable[..., dict[str, Any]],
    acquisition: dict[str, Any],
    run_id: str,
    journal_path: Any = None,
) -> dict[str, Any]:
    """Run the existing collector through real Gate/Ledger ownership."""
    if plan.get("campaignId") != CAMPAIGN:
        raise ValueError("Rules campaign identity differs")
    validate_compiled_accounting(plan)
    frozen_gate = gate_plan(plan)
    if gate.snapshot().get("planDigest") != digest(frozen_gate):
        raise ValueError("Rules Gate plan differs")
    session = RulesManagementSession(
        gate=gate,
        ledger=ledger,
        ticket=ticket,
        execute=execute,
        plan=plan,
    )
    return collector(
        plan,
        execute,
        run_id=run_id,
        acquisition=acquisition,
        journal_path=journal_path,
        management_session=session,
    )


__all__ = ["bound_execute", "run_bound_collection", "validate_compiled_accounting"]
