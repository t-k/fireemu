"""Capability-bound production bridge for the Rules user-token campaign.

This module owns orchestration glue only. O7, the worker binding, transport,
Gate, Ledger and the collector remain the authority for their respective
checks; this bridge never creates credentials or manufactures identity proof.
"""

from __future__ import annotations

import math
import time
from collections.abc import Callable
from typing import Any

from broad_contract import digest
from o5_user_token_campaign import budget as campaign_budget
from o5_user_token_campaign import setup_plan
from o5_user_token_collector import RulesManagementSession
from o5_user_token_descriptor import CAMPAIGN, collector, gate_plan
from o5_user_token_remote_transport import (
    adapt_setup_result,
    make_transport,
    prepare_setup_request,
    run_worker,
    verify_worker_binding,
    worker_binding,
)
from o8_admission import authorize_transport

TOTAL_REQUESTS = 146
RULES_REQUESTS = 23
OBSERVATION_REQUESTS = 33
RECOVERY_REQUESTS = 63
WORKER_TIMEOUT_SECONDS = 8.0


def run_bound_setup(
    *,
    plan: dict[str, Any],
    gate: Any,
    credentials: dict[str, Any],
    setup_secrets: dict[str, str],
    account_bindings: dict[str, Any],
    capability: Any,
    fixture_origin: str | None,
    binding: bytes,
    binding_digest: str,
) -> list[dict[str, Any]]:
    """Charge and execute compiler-owned setup through the Gate journal."""
    items = [*setup_plan(plan)["fixtures"], *setup_plan(plan)["auth"]]
    receipts: list[dict[str, Any]] = []
    for item in items:
        def send(deadline: float, item: dict[str, Any] = item) -> dict[str, Any]:
            if deadline - time.monotonic() < WORKER_TIMEOUT_SECONDS:
                raise TimeoutError("setup worker cannot fit within Gate deadline")
            prepared = prepare_setup_request(
                plan,
                item,
                credentials=credentials,
                account_bindings=account_bindings,
                setup_secrets=setup_secrets,
            )
            authorize_transport(capability, binding=binding, binding_digest=binding_digest)
            envelope = {
                key: prepared[key]
                for key in ("service", "route", "method", "path", "headers", "body")
            }
            envelope["seconds"] = WORKER_TIMEOUT_SECONDS
            result = run_worker(
                envelope,
                binding=binding,
                binding_digest=binding_digest,
                fixture_origin=fixture_origin,
            )
            typed = adapt_setup_result(
                item,
                result,
                endpoint=fixture_origin or prepared["origin"],
                sequence=len(receipts) + 1,
                account_bindings=account_bindings,
            )
            # Keep issued tokens private to this in-memory handoff. Gate
            # persists only a provenance digest and the typed resource result;
            # neither its event body nor the returned setup receipt may carry
            # passwords or user ID tokens.
            receipt = typed.receipt.as_dict()
            private_receipt_digest = digest(receipt)
            receipts.append(receipt)
            if item["service"] == "identity" and typed.receipt.local_id is not None:
                account_bindings[item["accountRef"]] = {
                    **account_bindings.get(item["accountRef"], {}),
                    "uid": typed.receipt.local_id,
                }
            return {
                "status": result["status"],
                "complete": True,
                "workerReaped": True,
                "bodyKind": "json",
                "body": {
                    "kind": "setup-receipt-v1",
                    "id": item["id"],
                    "receiptDigest": private_receipt_digest,
                },
            }

        gate.management_dispatch("observation", "setup/" + item["id"], send)
    return receipts


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
    permission_expires_at: float | None = None,
    setup_secrets: dict[str, str] | None = None,
    capability: Any = None,
    account_bindings: dict[str, Any] | None = None,
    credentials: dict[str, Any] | None = None,
    fixture_origin: str | None = None,
    binding: bytes | None = None,
    binding_digest: str | None = None,
    journal_path: Any = None,
) -> dict[str, Any]:
    """Run the existing collector through real Gate/Ledger ownership."""
    if plan.get("campaignId") != CAMPAIGN:
        raise ValueError("Rules campaign identity differs")
    if permission_expires_at is not None and (
        type(permission_expires_at) not in (int, float)
        or not math.isfinite(permission_expires_at)
    ):
        raise ValueError("Rules Gate expiry differs")
    validate_compiled_accounting(plan)
    frozen_gate = gate_plan(plan, permission_expires_at=permission_expires_at)
    if gate.snapshot().get("planDigest") != digest(frozen_gate):
        raise ValueError("Rules Gate plan differs")
    def execute_management(operation: dict[str, Any], *, deadline: float | None = None) -> dict[str, Any]:
        """Adapt the transport body to the management session's typed receipt.

        The shared transport intentionally returns the decoded body to the
        collector. Rules lifecycle management additionally needs the HTTP
        status to distinguish a typed 404 absence during cleanup. Derive that
        status only from the response body (success is 200; the sole accepted
        absence is the typed 404 error), without changing ordinary receipts.
        """
        raw = execute(operation, deadline=deadline)
        if not isinstance(raw, dict):
            raise TypeError("Rules management response body required")
        error = raw.get("error")
        status = 404 if isinstance(error, dict) and error.get("code") == 404 else 200
        return {
            "status": status,
            "complete": True,
            "workerReaped": True,
            "bodyKind": "json",
            "body": raw,
        }

    if setup_secrets is None or capability is None or account_bindings is None or credentials is None:
        raise ValueError("bound setup inputs required")
    if (
        not isinstance(binding, bytes)
        or not binding
        or not isinstance(binding_digest, str)
    ):
        raise ValueError("bound worker source required")
    verify_worker_binding(binding, binding_digest, None)
    setup_receipts = run_bound_setup(
        plan=plan,
        gate=gate,
        credentials=credentials,
        setup_secrets=setup_secrets,
        account_bindings=account_bindings,
        capability=capability,
        fixture_origin=fixture_origin,
        binding=binding,
        binding_digest=binding_digest,
    )
    session = RulesManagementSession(
        gate=gate,
        ledger=ledger,
        ticket=ticket,
        execute=execute_management,
        plan=plan,
    )
    bundle = collector(
        plan,
        execute,
        run_id=run_id,
        acquisition=acquisition,
        journal_path=journal_path,
        management_session=session,
    )
    bundle["setup"] = {
        "recordingComplete": len(setup_receipts) == 19,
        "requestCount": len(setup_receipts),
        "receipts": setup_receipts,
    }
    return bundle


__all__ = ["bound_execute", "run_bound_collection", "validate_compiled_accounting"]
