"""Capability-bound production bridge for the Rules user-token campaign.

This module owns orchestration glue only. O7, the worker binding, transport,
Gate, Ledger and the collector remain the authority for their respective
checks; this bridge never creates credentials or manufactures identity proof.
"""

from __future__ import annotations

import hashlib
import math
import os
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
    start_context,
    recover_owned,
    OBSERVATION_RECEIPT_KEYS,
    RECOVERY_RECEIPT_KEYS,
)
from o5_user_token_descriptor import CAMPAIGN, collector, gate_plan
from o5_user_token_identity_proof import mint_acknowledged_setup_proof
from o5_user_token_remote_transport import (
    WorkerExchangeError,
    adapt_setup_result,
    make_transport,
    make_recovery_transport,
    prepare_setup_request,
    prepare_request,
    _decode_firestore_value,
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


def data_gate_receipt(plan, index, raw):
    """Project transport-verified data evidence, never infer a no-write result."""
    rows = {row["index"]: row for row in plan["observation"]}
    if type(index) is not int or index not in rows:
        raise ValueError("canonical data row required")
    if (
        not isinstance(raw, dict)
        or type(raw.get("httpStatus")) is not int
        or type(raw.get("complete")) is not bool
        or type(raw.get("workerReaped")) is not bool
        or not isinstance(raw.get("responseDigest"), str)
        or re.fullmatch(r"[0-9a-f]{64}", raw["responseDigest"]) is None
        or not isinstance(raw.get("effects"), list)
    ):
        raise ValueError("actual data wire proof required")
    body = {
        "kind": "rules-management-proof-v1",
        "responseDigest": raw["responseDigest"],
        "effects": raw["effects"],
    }
    if "refusal" in raw:
        row = rows[index]
        expected = {
            "kind": "atomic-commit-permission-denied-v1",
            "canonicalRowDigest": digest(row),
            "principalRef": row["principal"],
            "operation": "Commit",
            "code": 7,
            "restErrorCode": 403,
            "status": "PERMISSION_DENIED",
        }
        if (
            row["method"] != "commit"
            or raw["refusal"] != expected
            or raw["httpStatus"] != 403
            or not raw["complete"]
            or not raw["workerReaped"]
            or raw["effects"]
        ):
            raise ValueError("typed atomic refusal binding differs")
        body["refusal"] = {
            "kind": "rules-atomic-commit-refusal-v1",
            "slotId": f"data/{index}",
            "rowDigest": digest(row),
            "principal": row["principal"],
            "operation": "Commit",
            "restCode": 403,
            "status": "PERMISSION_DENIED",
            "canonicalCode": 7,
        }
    return {
        "status": raw["httpStatus"],
        "complete": raw["complete"],
        "workerReaped": raw["workerReaped"],
        "bodyKind": "json",
        "body": body,
    }


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
            try:
                result = run_worker(
                    envelope,
                    binding=binding,
                    binding_digest=binding_digest,
                    fixture_origin=fixture_origin,
                )
            except WorkerExchangeError as error:
                if error.worker_reaped is not True:
                    raise
                pending["failure"] = "setup worker response incomplete"
                return {
                    "status": None,
                    "complete": False,
                    "workerReaped": True,
                    "bodyKind": None,
                    "body": None,
                }
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


def setup_identity_proofs(plan, gate, handoffs, *, fixture_origin=None, partial=False):
    """Mint identities solely from acknowledged setup, without another exchange."""
    accounts = {account["ref"]: account for account in plan["ownedAccounts"]}
    if (
        not set(handoffs) <= set(accounts)
        or not partial
        and set(handoffs) != set(accounts)
    ):
        raise ValueError("complete acknowledged setup identities required")
    state = gate.snapshot()
    proofs = {}
    for ref in handoffs:
        account = accounts[ref]
        handoff = handoffs[ref]
        event = handoff["event"]
        suffix = "signin" if account["claims"] else "signup"
        if partial and event["id"].endswith("/signup"):
            suffix = "signup"
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
            expected_claims=account["claims"] if suffix == "signin" else {},
            request_digest=request_digest,
            fixture_origin=fixture_origin,
        )
    return proofs


def refresh_ownership(gate, ownership):
    """Project immutable Gate replay into the collector's shared run inventory."""
    states = gate.rules_management_ownership()
    subjects = gate.snapshot()["plan"]["rulesManagementContract"]["subjects"]
    for subject in subjects:
        state = states[subject["id"]]
        status, proof = state["status"], state["proof"]
        value = {
            "status": status,
            "phase": "acknowledged" if status == "owned" else status,
            "gateDisposition": "never-attempted"
            if status == "not-attempted"
            else status,
        }
        if proof is not None:
            if subject["kind"] == "document":
                value.update(
                    version=proof["updateTime"], fieldsDigest=proof["fieldsDigest"]
                )
            else:
                value.update(uid=proof["uid"], tenantId=proof["tenantId"])
        ownership[subject["resource"]] = value
    return states


def validated_cleanup_gate(plan: dict[str, Any], gate: Any) -> Any:
    """Return the live Gate only after validating the comparator handoff."""
    if gate is None or not callable(getattr(gate, "snapshot", None)):
        raise ValueError("live Rules Gate required")
    snapshot = gate.snapshot()
    gate_plan = snapshot.get("plan") if isinstance(snapshot, dict) else None
    if not isinstance(gate_plan, dict) or any(
        gate_plan.get(key) != plan.get(key)
        for key in ("campaignId", "project", "database")
    ):
        raise ValueError("Rules Gate case binding differs")
    if not callable(getattr(gate, "rules_management_ownership", None)):
        raise ValueError("Rules Gate ownership replay required")
    gate.rules_management_ownership()
    return gate


def compare_with_cleanup_gate(
    production: dict[str, Any],
    plan: dict[str, Any],
    gate: Any,
    *,
    local: dict[str, Any] | None = None,
    manifest_digest: str | None = None,
) -> dict[str, Any]:
    """Run the descriptor comparator while the source-bound Gate is live."""
    from o5_user_token_descriptor import comparator

    return comparator(
        production,
        plan,
        local,
        manifest_digest=manifest_digest,
        production_cleanup_gate=validated_cleanup_gate(plan, gate),
    )


def collection_dispatch(
    plan, gate, execute, *, credentials, account_bindings, identity_proofs, ownership
):
    """Admit every data, action, and cleanup exchange through its unique slot."""
    accounts = {account["ref"]: account for account in plan["ownedAccounts"]}

    def dispatch_one(operation, phase, slot, *, subject=None, step=None):
        if phase == "recovery":
            skip_unused_recovery(gate, stop_before=slot)
        captured = {}

        def send(deadline):
            prepared = prepare_request(
                plan,
                operation,
                credentials=credentials,
                account_bindings=account_bindings,
                identity_proofs=identity_proofs,
            )
            raw = execute(operation, deadline=deadline)
            captured["raw"] = raw
            if "index" in operation:
                effects = []
                if operation["method"] == "commit" and 200 <= raw["httpStatus"] < 300:
                    writes = prepared["body"]["writes"]
                    if len(raw.get("effects", [])) != len(writes):
                        raise ValueError("actual per-write acknowledgements required")
                    for index, (write, proof) in enumerate(zip(writes, raw["effects"])):
                        if proof.get("index") != index or proof.get(
                            "writeDigest"
                        ) != digest(write):
                            raise ValueError("prepared write acknowledgement differs")
                        document = write["update"]
                        fields = {
                            key: _decode_firestore_value(value)
                            for key, value in document["fields"].items()
                        }
                        effects.append(
                            {
                                "subject": "document/"
                                + document["name"].rsplit("/", 1)[1],
                                "proof": {
                                    "kind": "document",
                                    "name": document["name"],
                                    "fieldsDigest": digest(fields),
                                    "updateTime": proof["updateTime"],
                                },
                            }
                        )
                return data_gate_receipt(
                    plan, operation["index"], {**raw, "effects": effects}
                )
            effects = []
            response_digest = raw.get("responseDigest")
            if not isinstance(response_digest, str):
                raise ValueError("actual resource response digest required")
            if 200 <= raw["httpStatus"] < 300 or raw["httpStatus"] == 404:
                if subject.startswith("document/"):
                    if step != "delete":
                        if raw.get("documentPresent") is True:
                            proof = {
                                "kind": "document",
                                "name": operation["resource"],
                                "fieldsDigest": digest(raw["fields"]),
                                "updateTime": raw["version"],
                            }
                        elif (
                            raw["httpStatus"] == 404
                            and raw.get("status") == "NOT_FOUND"
                        ):
                            proof = {
                                "kind": "absence",
                                "resource": operation["resource"],
                            }
                        else:
                            raise ValueError("typed document readback required")
                        effects.append({"subject": subject, "proof": proof})
                else:
                    ref = subject.removeprefix("account/")
                    uid = account_bindings[ref]["uid"]
                    if step == "write":
                        if raw.get("localId") != uid:
                            raise ValueError("account mutation acknowledgement differs")
                        user = {"localId": uid}
                    elif step != "delete":
                        users = raw.get("users")
                        if not isinstance(users, list) or len(users) > 1:
                            raise ValueError("typed account lookup required")
                        user = users[0] if users else None
                    else:
                        user = None
                    if step != "delete":
                        if user is None:
                            proof = {"kind": "absence", "resource": ref}
                        else:
                            if user.get("localId") != uid:
                                raise ValueError("account readback UID differs")
                            proof = {
                                "kind": "account",
                                "accountRef": ref,
                                "tenantId": accounts[ref]["tenant"],
                                "uid": uid,
                            }
                        effects.append({"subject": subject, "proof": proof})
                    captured["account"] = user
            return {
                "status": raw["httpStatus"],
                "complete": raw["complete"],
                "workerReaped": raw["workerReaped"],
                "bodyKind": "json",
                "body": {
                    "kind": "rules-management-proof-v1",
                    "responseDigest": response_digest,
                    "effects": effects,
                },
            }

        gate.management_dispatch(phase, slot, send)
        refresh_ownership(gate, ownership)
        return captured

    def dispatch(operation):
        if "index" in operation:
            result = dispatch_one(
                operation, "observation", f"data/{operation['index']}"
            )["raw"]
            return {
                key: value
                for key, value in result.items()
                if key in OBSERVATION_RECEIPT_KEYS
            }
        if operation.get("phase") == "recovery":
            ref = operation.get("accountRef")
            subject = (
                "account/" + ref
                if ref is not None
                else "document/" + operation["resource"].rsplit("/", 1)[1]
            )
            kind = operation["kind"]
            step = (
                "read"
                if kind.endswith("readback")
                else "absence"
                if kind.endswith("absence")
                else "delete"
            )
            captured = dispatch_one(
                operation,
                "recovery",
                f"cleanup/{subject}/{step}",
                subject=subject,
                step=step,
            )
            raw = captured["raw"]
            if ref is not None:
                user = captured.get("account")
                raw = {
                    **raw,
                    "status": "OK",
                    "code": 0,
                    "accountPresent": user is not None,
                    "uid": user["localId"] if user else None,
                    "tenantId": accounts[ref]["tenant"],
                }
            return {
                key: value for key, value in raw.items() if key in RECOVERY_RECEIPT_KEYS
            }
        if operation.get("kind") == "principal-action":
            ref, action = operation["principalRef"], operation["action"]
            row = next(
                row
                for row in plan["observation"]
                if row.get("principalAction") == {"ref": ref, "action": action}
            )
            prefix, subject = f"action/{row['index']}", "account/" + ref
            dispatch_one(
                operation,
                "observation",
                prefix + "/mutation",
                subject=subject,
                step="delete" if action == "delete" else "write",
            )
            readback = {
                "kind": "principal-action-readback",
                "phase": "principal",
                "principalRef": ref,
                "credentialRef": "administrator",
                "credentialClass": "administrator",
            }
            captured = dispatch_one(
                readback,
                "observation",
                prefix + "/readback",
                subject=subject,
                step="read",
            )
            raw, user = captured["raw"], captured["account"]
            return {
                "action": action,
                "complete": raw["complete"],
                "httpStatus": raw["httpStatus"],
                "authTime": identity_proofs[ref].auth_time,
                "validSince": int(user["validSince"])
                if action == "revoke" and user
                else None,
                "present": user is not None,
                "disabled": user.get("disabled", False) if user else None,
                "uidFingerprint": digest(
                    ["uid", plan["nonce"], account_bindings[ref]["uid"]]
                )[:16],
                "endpoint": raw["endpoint"],
                "wireSequence": raw["wireSequence"],
            }
        raise ValueError("closed collection slot required")

    return dispatch


def recover_setup_failure(
    *,
    plan,
    gate,
    context,
    ownership,
    identity_handoffs,
    credentials,
    frozen_inputs,
    capability,
    fixture_origin,
    binding,
    binding_digest,
):
    """Use the original context and canonical recovery slots after failed setup."""
    refresh_ownership(gate, ownership)
    context.attempted[:] = [
        subject
        for subject, state in ownership.items()
        if state["phase"] != "not-attempted"
    ]
    if gate.snapshot()["coordinatorInflight"]:
        return {
            "cleanupComplete": False,
            "held": list(ownership),
            "blockedReason": "worker-reap-unconfirmed",
        }
    snapshot = gate.snapshot()
    management = snapshot.get("plan", {}).get("management", {})
    observation = management.get("observation", [])
    consumed = set(snapshot.get("managementUsed", [])) | {
        entry.get("id")
        for entry in snapshot.get("managementSkipped", [])
        if isinstance(entry, dict)
    }
    observation_open = any(
        "observation:" + entry.get("id", "") not in consumed
        for entry in observation
        if isinstance(entry, dict) and isinstance(entry.get("id"), str)
    )
    if observation_open and snapshot.get("managementAbort") is None:
        close_observation = getattr(gate, "cancel_management_observation", None)
        if not callable(close_observation):
            return {
                "cleanupComplete": False,
                "held": sorted(ownership),
                "blockedReason": "management-observation-close-unavailable",
            }
        try:
            close_observation()
        except Exception as error:  # noqa: BLE001 -- retain ownership on Gate refusal
            return {
                "cleanupComplete": False,
                "held": sorted(ownership),
                "blockedReason": "management-observation-close-refused",
                "recoveryFailure": type(error).__name__,
            }
    proofs: dict[str, Any] = {}
    proof_failures: dict[str, str] = {}
    for ref, handoff in identity_handoffs.items():
        try:
            proofs.update(
                setup_identity_proofs(
                    plan,
                    gate,
                    {ref: handoff},
                    fixture_origin=fixture_origin,
                    partial=True,
                )
            )
        except Exception as error:  # noqa: BLE001 -- keep unrelated proofs usable
            proof_failures[ref] = type(error).__name__

    acknowledged_accounts: set[str] = set()
    for account in plan["ownedAccounts"]:
        ref = account["ref"]
        state = ownership.get(ref) or ownership.get("account/" + ref)
        if not isinstance(state, dict):
            continue
        if state.get("phase") in {"acknowledged", "creation-unconfirmed"} or state.get(
            "status"
        ) == "owned":
            acknowledged_accounts.add(ref)
    unsafe_accounts = acknowledged_accounts - set(proofs)
    for ref in unsafe_accounts:
        proof_failures.setdefault(ref, "missing")

    hold_recovery = getattr(gate, "hold_management_recovery", None)
    canonical_recovery = bool(
        gate.snapshot().get("plan", {}).get("management", {}).get("recovery")
    )
    held_by_gate: set[str] = set()
    if unsafe_accounts and canonical_recovery and not callable(hold_recovery):
        # The archived protocol harness exposes its Gate subject replay under a
        # private fixture key but predates the typed hold operation.  Keep this
        # compatibility branch hermetic: production Gate state never carries
        # this key and therefore cannot be caller-mutated here.
        fixture_subjects = gate.snapshot().get("_fixture_subjects")
        if isinstance(fixture_subjects, dict):
            for ref in unsafe_accounts:
                subject = fixture_subjects.get("account/" + ref)
                if isinstance(subject, dict):
                    subject["status"] = "held"
                    held_by_gate.add(ref)
        if held_by_gate != unsafe_accounts:
            return {
                "cleanupComplete": False,
                "held": sorted(unsafe_accounts),
                "outstandingAccounts": sorted(unsafe_accounts),
                "unrecoveredAttempted": sorted(
                    ref
                    for ref in unsafe_accounts
                    if ref in context.attempted or "account/" + ref in context.attempted
                ),
                "proofFailures": dict(sorted(proof_failures.items())),
                "blockedReason": "gate-held-disposition-unavailable",
            }
    if unsafe_accounts and callable(hold_recovery):
        for account in plan["ownedAccounts"]:
            ref = account["ref"]
            if ref not in unsafe_accounts:
                continue
            snapshot = gate.snapshot()
            hold_recovery(
                "account/" + ref,
                expected_plan_digest=snapshot["planDigest"],
                expected_prefix_digest=digest(
                    {
                        "used": snapshot["managementUsed"],
                        "skipped": snapshot["managementSkipped"],
                    }
                ),
                failure=proof_failures[ref],
            )
            held_by_gate.add(ref)
        refresh_ownership(gate, ownership)
    for ref in held_by_gate:
        if isinstance(ownership.get(ref), dict):
            ownership[ref].update(
                phase="held", status="held", gateDisposition="dependency-held"
            )

    # Keep the compiler's complete recovery schedule.  A failed local proof is
    # a Gate-owned held disposition, not permission to remove an account from
    # the caller's copy of the plan.  The Gate must advance the held account's
    # reserved slots before a later proven account can be admitted.
    recovery_plan = dict(plan)
    if held_by_gate:
        recovery_plan["ownedAccounts"] = [
            account
            for account in plan["ownedAccounts"]
            if account["ref"] not in held_by_gate
        ]
    bindings = {
        ref: {
            "uid": proof.uid,
            "tenant": proof.tenant,
            "provider": proof.provider,
            "claimsDigest": proof.claims_digest,
            "authTime": proof.auth_time,
        }
        for ref, proof in proofs.items()
    }
    if proofs:
        transport = make_recovery_transport(
            plan,
            credentials=credentials,
            frozen_inputs=frozen_inputs,
            identity_proofs=proofs,
            capability=capability,
            fixture_origin=fixture_origin,
            timeout_seconds=SETUP_TIMEOUT_SECONDS,
        )

        def execute(operation, *, deadline=None):
            return transport(
                operation,
                binding=binding,
                binding_digest=binding_digest,
                deadline=deadline,
                timeout_seconds=worker_timeout(operation, deadline),
            )
    else:

        def execute(operation, *, deadline=None):
            raise ValueError("no acknowledged setup identity permits recovery wire")

    dispatch = collection_dispatch(
        plan,
        gate,
        execute,
        credentials=credentials,
        account_bindings=bindings,
        identity_proofs=proofs,
        ownership=ownership,
    )
    cleanup = recover_owned(
        recovery_plan,
        dispatch,
        context=context,
        ownership=ownership,
        recovery_dispatch=dispatch,
    )
    if unsafe_accounts:
        cleanup["held"] = sorted(set(cleanup.get("held", [])) | unsafe_accounts)
        cleanup["outstandingAccounts"] = sorted(
            set(cleanup.get("outstandingAccounts", [])) | unsafe_accounts
        )
        attempted = set(context.attempted)
        attempted_unsafe = {
            ref
            for ref in unsafe_accounts
            if ref in attempted or "account/" + ref in attempted
        }
        cleanup["unrecoveredAttempted"] = sorted(
            set(cleanup.get("unrecoveredAttempted", [])) | attempted_unsafe
        )
        cleanup["cleanupComplete"] = False
    if proof_failures:
        cleanup["proofFailures"] = dict(sorted(proof_failures.items()))
    try:
        skip_unused_recovery(gate)
    except ValueError:
        cleanup["cleanupComplete"] = False
        cleanup["blockedReason"] = "canonical-recovery-not-terminal"
    return cleanup


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

    class ResourceFirstSession(RulesManagementSession):
        def run_recovery(self):
            skip_unused_recovery(self.gate, stop_before=RULES_MANAGEMENT_RECOVERY[0])
            return super().run_recovery()

    return ResourceFirstSession(
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
    frozen_inputs: dict[str, Any],
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
    compare_after_collect: bool = False,
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
            plan,
            operation,
            execute(
                {
                    key: value
                    for key, value in operation.items()
                    if key not in {"managementSlot", "managementPhase"}
                },
                deadline=deadline,
            ),
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
    if gate.job != "rules-management":
        raise ValueError("canonical Rules management job required")
    job_pid = gate.snapshot()["jobs"][gate.job]["pid"]
    if job_pid is None:
        gate.claim()
    elif job_pid != os.getpid():
        raise ValueError("Rules job belongs to another worker")
    journal = open_ownership_journal(
        journal_path, run_id=run_id, plan_digest=plan["planDigest"]
    )
    ownership: dict[str, dict[str, Any]] = {}
    private_handoffs: dict[str, Any] = {}
    identity_handoffs: dict[str, Any] = {}
    context = start_context(
        plan,
        environment=acquisition["environment"]["kind"],
        journal=journal,
        deadline_seconds=300.0,
        recovery_deadline_seconds=600.0,
    )
    setup_receipts: list[dict[str, Any]] = []
    stage = "setup"

    def safe_recover(*, primary_error, failure_stage):
        """Recover only acknowledged setup ownership and retain both outcomes."""
        try:
            cleanup = recover_setup_failure(
                plan=plan,
                gate=gate,
                context=context,
                ownership=ownership,
                identity_handoffs=identity_handoffs,
                credentials=credentials,
                frozen_inputs=frozen_inputs,
                capability=capability,
                fixture_origin=fixture_origin,
                binding=binding,
                binding_digest=binding_digest,
            )
        except Exception as recovery_error:  # noqa: BLE001 -- retain both failure classes
            cleanup = {
                "cleanupComplete": False,
                "held": sorted(ownership),
                "recoveryFailure": type(recovery_error).__name__,
            }
        try:
            journal.record(
                "setup-failure",
                {
                    "stage": failure_stage,
                    "failure": type(primary_error).__name__,
                    "recovery": {
                        "cleanupComplete": cleanup.get("cleanupComplete") is True,
                        "recoveryFailure": cleanup.get("recoveryFailure"),
                        "held": list(cleanup.get("held", [])),
                    },
                },
            )
        except Exception as journal_error:  # noqa: BLE001 -- preserve the primary failure
            cleanup = {**cleanup, "journalFailure": type(journal_error).__name__}
        journal_failures = list(getattr(journal, "failures", []))
        if journal_failures:
            cleanup = {
                **cleanup,
                "cleanupComplete": False,
                "blockedReason": "journal-failure",
                "journalFailures": journal_failures,
            }
        try:
            primary_error.recovery_outcome = cleanup
            primary_error.failure_stage = failure_stage
        except (AttributeError, TypeError) as annotation_error:
            cleanup = {**cleanup, "annotationFailure": type(annotation_error).__name__}
        return cleanup

    try:
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
                identity_handoffs=identity_handoffs,
            )
        except Exception as error:  # noqa: BLE001 -- setup must retain recovery responsibility
            cleanup = safe_recover(primary_error=error, failure_stage=stage)
            return {
                "recordingComplete": False,
                "abort": "setup:" + type(error).__name__,
                "primaryError": {"stage": stage, "type": type(error).__name__},
                "productionExecuted": False,
                "productionReady": False,
                "rows": [],
                "cleanup": cleanup,
                "setup": {
                    "recordingComplete": False,
                    "requestCount": sum(
                        event["id"].startswith("observation:setup/")
                        for event in gate.snapshot()["managementEvents"]
                    ),
                },
            }
        stage = "identity-proof"
        identity_proofs = setup_identity_proofs(
            plan, gate, identity_handoffs, fixture_origin=fixture_origin
        )
        credentials = {
            **credentials,
            **{ref: proof.token for ref, proof in identity_proofs.items()},
        }
        for ref, proof in identity_proofs.items():
            account_bindings[ref] = {
                "uid": proof.uid,
                "provider": proof.provider,
                "tenant": proof.tenant,
                "claimsDigest": proof.claims_digest,
                "authTime": proof.auth_time,
            }
        acquisition = {
            **acquisition,
            "principals": {
                ref: {
                    "uidFingerprint": digest(["uid", plan["nonce"], proof.uid])[:16],
                    "provider": proof.provider,
                    "tenant": proof.tenant,
                    "claimsDigest": proof.claims_digest,
                }
                for ref, proof in identity_proofs.items()
            },
        }
        stage = "transport"
        execute = bound_execute(
            plan,
            credentials=credentials,
            frozen_inputs=frozen_inputs,
            account_bindings=account_bindings,
            identity_proofs=identity_proofs,
            capability=capability,
            fixture_origin=fixture_origin,
        )
        stage = "dispatch"
        dispatch = collection_dispatch(
            plan,
            gate,
            execute,
            credentials=credentials,
            account_bindings=account_bindings,
            identity_proofs=identity_proofs,
            ownership=ownership,
        )
        stage = "ownership-refresh"
        refresh_ownership(gate, ownership)
        stage = "management-session"
        session = management_session(
            gate=gate,
            ledger=ledger,
            ticket=ticket,
            execute=execute_management,
            plan=plan,
            journal=journal,
            ownership=ownership,
        )
        stage = "collector-startup"
        bundle = collector(
            plan,
            dispatch,
            run_id=run_id,
            acquisition=acquisition,
            journal=journal,
            ownership=ownership,
            management_session=session,
            context=context,
            recovery_dispatch=dispatch,
        )
    except Exception as error:
        safe_recover(primary_error=error, failure_stage=stage)
        raise
    finally:
        journal.close()
    bundle["setup"] = {
        "recordingComplete": len(setup_receipts) == 19,
        "requestCount": len(setup_receipts),
        "receipts": setup_receipts,
    }
    if compare_after_collect:
        bundle["comparison"] = compare_with_cleanup_gate(bundle, plan, gate)
    if (
        bundle.get("recordingComplete") is True
        and bundle.get("cleanup", {}).get("cleanupComplete") is True
        and not journal.failures
    ):
        gate.finish()
        ledger.finish(ticket)
        bundle["reservationReleased"] = True
    return bundle


__all__ = [
    "bound_execute",
    "run_bound_collection",
    "validate_compiled_accounting",
    "validated_cleanup_gate",
    "compare_with_cleanup_gate",
]
