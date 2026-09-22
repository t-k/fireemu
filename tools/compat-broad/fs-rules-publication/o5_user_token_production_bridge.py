"""Capability-bound production bridge for the Rules user-token campaign.

This module owns orchestration glue only. O7, the worker binding, transport,
Gate, Ledger and the collector remain the authority for their respective
checks; this bridge never creates credentials or manufactures identity proof.
"""

from __future__ import annotations

import hashlib
import math
import re
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from broad_contract import digest
from o5_user_token_campaign import budget as campaign_budget
from o5_user_token_campaign import (
    RULES_MANAGEMENT_OBSERVATION,
    RULES_MANAGEMENT_RECOVERY,
    setup_plan,
)
from o5_user_token_collector import (
    RulesManagementReceipt,
    RulesManagementSession,
    open_ownership_journal,
)
from o5_user_token_descriptor import CAMPAIGN, collector, gate_plan
from o5_user_token_identity_proof import mint_acknowledged_setup_proof
from o5_user_token_remote_transport import (
    adapt_setup_result,
    make_transport,
    prepare_setup_request,
    run_worker,
    verify_worker_binding,
    worker_binding,
)
from o8_admission import authorize_transport

TOTAL_REQUESTS = 144
RULES_REQUESTS = 23
OBSERVATION_REQUESTS = 33
RECOVERY_REQUESTS = 63
WORKER_TIMEOUT_SECONDS = 12.0
SETUP_TIMEOUT_SECONDS = 2.0


def worker_timeout(operation: dict[str, Any], deadline: float | None) -> float:
    """Keep every worker within its existing compiled management slot."""
    seconds = (
        WORKER_TIMEOUT_SECONDS
        if operation.get("kind") == "rules-lifecycle"
        else SETUP_TIMEOUT_SECONDS
    )
    if deadline is not None:
        if type(deadline) not in (int, float) or not math.isfinite(deadline):
            raise ValueError("finite worker deadline required")
        seconds = min(seconds, deadline - time.monotonic())
        if seconds <= 0:
            raise TimeoutError("Rules worker deadline exhausted")
    return seconds


def rules_gate_receipt(
    plan: dict[str, Any], operation: dict[str, Any], raw: dict[str, Any]
) -> RulesManagementReceipt:
    """Project actual Rules HTTP facts into the durable, secret-free Gate schema."""
    if (
        not isinstance(raw, dict)
        or type(raw.get("httpStatus")) is not int
        or type(raw.get("complete")) is not bool
        or type(raw.get("workerReaped")) is not bool
    ):
        raise ValueError("actual Rules wire facts required")
    slot = operation.get("managementSlot")
    phase = operation.get("managementPhase")
    slots = (
        RULES_MANAGEMENT_OBSERVATION
        if phase == "observation"
        else RULES_MANAGEMENT_RECOVERY
        if phase == "recovery"
        else ()
    )
    if slot not in slots:
        raise ValueError("compiled Rules management slot required")
    metadata = {"httpStatus", "complete", "workerReaped", "endpoint", "wireSequence"}
    body = {key: value for key, value in raw.items() if key not in metadata}
    effects = []
    proof = None
    subject = "release/baseline"
    if slot.startswith(("create-", "delete-")):
        subject = "ruleset/" + slot.split("-")[1]
    if (
        raw["httpStatus"] == 404
        and slot in {"delete-a-absence", "delete-b-absence"}
        and isinstance(body.get("error"), dict)
        and body["error"].get("code") == 404
    ):
        proof = {"kind": "absence", "resource": operation["rulesetName"]}
    elif 200 <= raw["httpStatus"] < 300 and raw["complete"] and raw["workerReaped"]:
        try:
            if slot in {"create-a", "create-b"}:
                name = body.get("name")
                if (
                    not isinstance(name, str)
                    or re.fullmatch(
                        r"projects/fireemu-35fe6/rulesets/[A-Za-z0-9_-]{1,128}", name
                    )
                    is None
                ):
                    raise ValueError("Rules create name differs")
                proof = {
                    "kind": "ruleset",
                    "name": name,
                    "sourceDigest": digest(
                        plan["rulesets"][slot[-1].upper()]["source"]
                    ),
                }
            elif slot in {
                "baseline-ruleset-get",
                "create-a-get",
                "create-b-get",
                "delete-a-get",
                "delete-b-get",
            }:
                expected = (
                    None
                    if slot == "baseline-ruleset-get"
                    else digest(plan["rulesets"][subject[-1].upper()]["source"])
                )
                name = RulesManagementSession._ruleset(body, expected)
                proof = {
                    "kind": "ruleset",
                    "name": name,
                    "sourceDigest": RulesManagementSession._ruleset_digest(body),
                }
            elif slot not in {
                "delete-a",
                "delete-b",
                "delete-a-absence",
                "delete-b-absence",
            }:
                name = (
                    "projects/fireemu-35fe6/releases/cloud.firestore"
                    if operation.get("action") == "release-get-executable"
                    else body.get("name")
                )
                release = {"name": name, "rulesetName": body.get("rulesetName")}
                name, ruleset = RulesManagementSession._release(release)
                proof = {"kind": "release", "name": name, "rulesetName": ruleset}
        except ValueError:
            # A malformed response still has real HTTP/reap facts. Keep it
            # charged without inventing ownership; the collector rejects it.
            proof = None
    if proof is not None:
        effects.append({"subject": subject, "proof": proof})
    receipt = RulesManagementReceipt(
        {
            "status": raw["httpStatus"],
            "complete": raw["complete"],
            "workerReaped": raw["workerReaped"],
            "bodyKind": "json",
            "body": {
                "kind": "rules-management-proof-v1",
                "responseDigest": digest(body),
                "effects": effects,
            },
        },
        endpoint=raw.get("endpoint"),
        wire_sequence=raw.get("wireSequence"),
    )
    receipt.response_body = body
    return receipt


def skip_unused_recovery(
    gate: Any, *, stop_before: str | None = None
) -> dict[str, Any]:
    """Advance only through dependency-authorized, durably recorded Gate skips."""
    snapshot = gate.snapshot()
    slots = [entry["id"] for entry in snapshot["plan"]["management"]["recovery"]]
    consumed = set(snapshot["managementUsed"]) | {
        entry["id"] for entry in snapshot["managementSkipped"]
    }
    if stop_before is not None and (
        stop_before not in slots or "recovery:" + stop_before in consumed
    ):
        raise ValueError("fresh compiled recovery destination required")
    for slot in slots:
        if "recovery:" + slot in consumed:
            continue
        if slot == stop_before:
            break
        snapshot = gate.skip_management_recovery(
            slot,
            expected_plan_digest=snapshot["planDigest"],
            expected_prefix_digest=digest(
                {
                    "used": snapshot["managementUsed"],
                    "skipped": snapshot["managementSkipped"],
                }
            ),
        )
    return snapshot


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
    journal: Any = None,
    ownership: dict[str, dict[str, Any]] | None = None,
    private_handoffs: dict[str, Any] | None = None,
    identity_handoffs: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Charge and execute compiler-owned setup through the Gate journal."""
    if journal is None or journal.path is None or journal.failures:
        raise ValueError("durable setup journal required")
    if ownership is None:
        raise ValueError("shared setup ownership required")
    items = setup_plan(plan)["operations"]
    receipts: list[dict[str, Any]] = []
    for item in items:
        subject = item.get("resource", item.get("accountRef"))
        creating = item["service"] == "firestore" or item["id"].endswith("/signup")
        slot_id = "setup/" + item["id"]
        journal.record(
            "setup-intent",
            {"slot": slot_id, "subject": subject, "planDigest": plan["planDigest"]},
        )
        if journal.failures:
            raise ValueError("setup journal intent failed")
        pending: dict[str, Any] = {}

        def send(deadline: float, item: dict[str, Any] = item) -> dict[str, Any]:
            if deadline - time.monotonic() < SETUP_TIMEOUT_SECONDS - 0.25:
                raise TimeoutError("setup worker cannot fit within Gate deadline")
            if creating:
                ownership[subject] = {"phase": "creation-unconfirmed", "slot": slot_id}
            prepared = prepare_setup_request(
                plan,
                item,
                credentials=credentials,
                account_bindings=account_bindings,
                setup_secrets=setup_secrets,
            )
            authorize_transport(
                capability, binding=binding, binding_digest=binding_digest
            )
            envelope = {
                key: prepared[key]
                for key in ("service", "route", "method", "path", "headers", "body")
            }
            envelope["seconds"] = SETUP_TIMEOUT_SECONDS
            result = run_worker(
                envelope,
                binding=binding,
                binding_digest=binding_digest,
                fixture_origin=fixture_origin,
            )
            try:
                typed = adapt_setup_result(
                    item,
                    result,
                    endpoint=fixture_origin or prepared["origin"],
                    sequence=len(receipts) + 1,
                    account_bindings=account_bindings,
                    request_digest=digest(
                        {key: prepared[key] for key in ("method", "path", "body")}
                    ),
                )
            except ValueError:
                pending["failure"] = "setup response acknowledgement refused"
                return {
                    "status": result["status"],
                    "complete": True,
                    "workerReaped": True,
                    "bodyKind": "json",
                    "body": {
                        "kind": "rules-management-proof-v1",
                        "responseDigest": digest(result["body"]),
                        "effects": [],
                    },
                }
            # Keep issued tokens private to this in-memory handoff. Gate
            # persists only a provenance digest and the typed resource result;
            # neither its event body nor the returned setup receipt may carry
            # passwords or user ID tokens.
            receipt = typed.receipt.as_dict()
            pending["receipt"] = receipt
            pending["typedReceipt"] = typed.receipt
            pending["private"] = typed.private
            subject_id = (
                "document/" + item["document"]
                if item["service"] == "firestore"
                else "account/" + item["accountRef"]
            )
            proof = (
                {
                    "kind": "document",
                    "name": receipt["name"],
                    "fieldsDigest": receipt["fieldsDigest"],
                    "updateTime": receipt["updateTime"],
                }
                if item["service"] == "firestore"
                else {
                    "kind": "account",
                    "accountRef": item["accountRef"],
                    "tenantId": item["tenant"],
                    "uid": receipt["localId"],
                }
            )
            return {
                "status": result["status"],
                "complete": True,
                "workerReaped": True,
                "bodyKind": "json",
                "body": {
                    "kind": "rules-management-proof-v1",
                    "responseDigest": digest(result["body"]),
                    "effects": [{"subject": subject_id, "proof": proof}],
                },
            }

        result = gate.management_dispatch("observation", slot_id, send)
        if "failure" in pending:
            gate.cancel_management_observation()
            raise ValueError(pending["failure"])
        receipt = pending["receipt"]
        events = gate.snapshot()["managementEvents"]
        event = events[-1]
        if (
            event.get("responseDigest") != digest(result)
            or event.get("completed") is not True
        ):
            raise ValueError("durable setup Gate acknowledgement required")
        proof = {
            "slot": slot_id,
            "subject": subject,
            "planDigest": plan["planDigest"],
            "gateEventDigest": digest(event),
            "gatePlanDigest": gate.snapshot()["planDigest"],
            "nonce": plan["nonce"],
            "receiptDigest": digest(receipt),
            "version": receipt.get("updateTime"),
            "fieldsDigest": receipt.get("fieldsDigest"),
            "uid": receipt.get("localId"),
            "tenantId": item.get("tenant"),
        }
        journal.record("setup-acknowledged", proof)
        if journal.failures:
            raise ValueError("setup journal acknowledgement failed")
        if creating:
            ownership[subject] = {"phase": "acknowledged", **proof}
        receipts.append(receipt)
        if private_handoffs is not None and item["route"] in {
            "accounts:signUp",
            "accounts:signInWithPassword",
        }:
            private_handoffs[item["accountRef"]] = pending["private"]
        if identity_handoffs is not None and item["route"] in {
            "accounts:signUp",
            "accounts:signInWithPassword",
        }:
            identity_handoffs[item["accountRef"]] = {
                "receipt": pending["typedReceipt"],
                "private": pending["private"],
                "event": event,
            }
        if item["service"] == "identity" and receipt.get("localId") is not None:
            account_bindings[item["accountRef"]] = {
                **account_bindings.get(item["accountRef"], {}),
                "uid": receipt["localId"],
            }
    return receipts


def setup_identity_proofs(plan, gate, handoffs, *, fixture_origin=None):
    """Mint identities solely from acknowledged setup, without another exchange."""
    accounts = {account["ref"]: account for account in plan["ownedAccounts"]}
    if set(handoffs) != set(accounts):
        raise ValueError("complete acknowledged setup identities required")
    state = gate.snapshot()
    proofs = {}
    for ref, account in accounts.items():
        handoff = handoffs[ref]
        event = handoff["event"]
        suffix = "signin" if account["claims"] else "signup"
        if event["id"] != f"observation:setup/account/{ref}/{suffix}":
            raise ValueError("final compiled identity handoff required")
        token, _, request_digest = handoff["private"].proof_material()
        acknowledgment = {
            "kind": "setup-ack",
            "principalRef": ref,
            "uid": handoff["receipt"].local_id,
            "tenant": account["tenant"],
            "tokenHash": hashlib.sha256(token.encode()).hexdigest(),
            "requestDigest": request_digest,
            "responseDigest": event["responseDigest"],
            "eventDigest": digest(event),
            "planDigest": state["planDigest"],
            "nonce": plan["nonce"],
            "slotId": event["id"],
        }
        proofs[ref] = mint_acknowledged_setup_proof(
            ref,
            private_handoff=handoff["private"],
            setup_receipt=handoff["receipt"],
            gate_authority=gate,
            gate_acknowledgment=acknowledgment,
            expected_provider="anonymous"
            if account["kind"] == "anonymous"
            else "password",
            expected_tenant=account["tenant"],
            expected_claims=account["claims"],
            request_digest=request_digest,
            fixture_origin=fixture_origin,
        )
    return proofs


def validate_compiled_accounting(plan: dict[str, Any]) -> dict[str, int]:
    """Require the compiler's complete 144-request accounting."""
    estimate = campaign_budget(plan)
    expected = {
        "observationRequests": OBSERVATION_REQUESTS,
        "fixtureRequests": 10,
        "authRequests": 15,
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

    def execute(
        operation: dict[str, Any], *, deadline: float | None = None
    ) -> dict[str, Any]:
        seconds = worker_timeout(operation, deadline)
        authorize_transport(capability, binding=binding, binding_digest=binding_digest)
        return transport(
            operation,
            binding=binding,
            binding_digest=binding_digest,
            capability=capability,
            deadline=deadline,
            timeout_seconds=seconds,
        )

    return execute


def management_session(*, plan, gate, ledger, ticket, execute, journal, ownership):
    """Bind the Rules slice to the one existing setup/resource lifecycle."""
    if journal.path is None or journal.failures:
        raise ValueError("durable ownership journal required")
    snapshot = gate.snapshot()
    schedule = snapshot["plan"]["management"]
    lifecycle = {
        "observationIds": list(RULES_MANAGEMENT_OBSERVATION),
        "recoveryIds": list(RULES_MANAGEMENT_RECOVERY),
    }
    prefix = {
        "planDigest": plan["planDigest"],
        "journalDigest": hashlib.sha256(Path(journal.path).read_bytes()).hexdigest(),
        "proofDigest": digest(ownership),
        "observationIds": [
            slot["id"]
            for slot in schedule["observation"]
            if slot["id"] not in lifecycle["observationIds"]
        ],
        "recoveryIds": [
            slot["id"]
            for slot in schedule["recovery"]
            if slot["id"] not in lifecycle["recoveryIds"]
        ],
    }
    return RulesManagementSession(
        gate=gate,
        ledger=ledger,
        ticket=ticket,
        execute=execute,
        plan=plan,
        setup_prefix=prefix,
        lifecycle_slice=lifecycle,
    )


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

    def execute_management(
        operation: dict[str, Any], *, deadline: float | None = None
    ) -> dict[str, Any]:
        """Keep actual wire facts and project only typed ownership to Gate."""
        return rules_gate_receipt(
            plan, operation, execute(operation, deadline=deadline)
        )

    if (
        setup_secrets is None
        or capability is None
        or account_bindings is None
        or credentials is None
    ):
        raise ValueError("bound setup inputs required")
    if (
        not isinstance(binding, bytes)
        or not binding
        or not isinstance(binding_digest, str)
    ):
        raise ValueError("bound worker source required")
    verify_worker_binding(binding, binding_digest, None)
    if journal_path is None:
        journal_path = Path(gate.path).with_suffix(".ownership.jsonl")
    if Path(journal_path).exists():
        raise ValueError("fresh ownership journal required")
    journal = open_ownership_journal(
        journal_path, run_id=run_id, plan_digest=plan["planDigest"]
    )
    ownership: dict[str, dict[str, Any]] = {}
    private_handoffs: dict[str, Any] = {}
    try:
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
            journal=journal,
            ownership=ownership,
            private_handoffs=private_handoffs,
        )
        session = management_session(
            gate=gate,
            ledger=ledger,
            ticket=ticket,
            execute=execute_management,
            plan=plan,
            journal=journal,
            ownership=ownership,
        )
        bundle = collector(
            plan,
            execute,
            run_id=run_id,
            acquisition=acquisition,
            journal=journal,
            ownership=ownership,
            management_session=session,
        )
    finally:
        journal.close()
    bundle["setup"] = {
        "recordingComplete": len(setup_receipts) == 19,
        "requestCount": len(setup_receipts),
        "receipts": setup_receipts,
    }
    return bundle


__all__ = ["bound_execute", "run_bound_collection", "validate_compiled_accounting"]
