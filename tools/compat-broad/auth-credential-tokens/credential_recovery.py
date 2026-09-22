"""Parent-linked, read-only recovery for an unresolved Auth custom sign-in.

The packet05 parent contains one unresolved ``custom-sign-in`` creation.  This
module deliberately does not resume that request, discover an account by email,
or acquire ownership from a successful lookup.  A fresh child may perform one
privileged lookup for the UID derived from the immutable parent plan.  Only the
typed empty result is closable; every other result leaves the parent held.

The Ledger methods used here are intentionally Auth-specific.  The generic
Firestore recovery extension must not be used for an Auth account resource.
"""

from __future__ import annotations

import copy
import hashlib
import math
import re
import time
from collections.abc import Callable, Mapping
from typing import Any

from broad_contract import digest

CAMPAIGN = "AUTH-CREDENTIAL-TOKENS-01"
KIND = "auth-credential-custom-uid-recovery-v1"
PERMISSION_KIND = "auth-credential-recovery-permission-v1"
O7_KIND = "auth-credential-recovery-o7-approval-v1"
O8_KIND = "auth-credential-recovery-o8-capability-v1"
CHILD_KIND = "auth-credential-recovery-child-claim-v1"
ENVELOPE_KIND = "auth-credential-recovery-envelope-v1"
OPERATION_CLASS = "read-only-custom-uid-v1"
PROJECT = "fireemu-35fe6"
IDENTITY = "identitytoolkit.googleapis.com/v1"
WORKER_ENTRY = "tools/compat-broad/auth-credential-tokens/credential_https_worker.py"
TRANSPORT_ENTRY = "tools/compat-broad/auth-credential-tokens/credential_remote_transport.py"
LAUNCHER_ENTRY = "tools/compat-broad/auth-credential-tokens/credential_bootstrap.py"
NONCE = re.compile(r"^[0-9a-f]{32}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_DEADLINE_SECONDS = 300
CHILD_BUDGET = {
    "requests": 1,
    "accounts": 0,
    "resources": 1,
    "costMicrousd": 50_000,
}


class RecoveryRefusal(ValueError):
    """A secret-free refusal that cannot authorize parent closure."""

    def __init__(self, reason: str):
        if not isinstance(reason, str) or not reason or any(
            marker in reason.lower() for marker in ("token", "password", "apikey", "credential")
        ):
            reason = "recovery contract refused"
        self.reason = reason
        super().__init__(reason)


def _refuse(reason: str) -> None:
    raise RecoveryRefusal(reason)


def _sha(value: Any, field: str) -> None:
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        _refuse(f"{field} digest required")


def _nonce(value: Any, field: str) -> None:
    if not isinstance(value, str) or NONCE.fullmatch(value) is None:
        _refuse(f"{field} nonce required")


def _finite(value: Any, field: str) -> None:
    if type(value) not in (int, float) or isinstance(value, bool) or not math.isfinite(value):
        _refuse(f"finite {field} required")


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value) and len(value) <= 1024


def _project(parent_plan: Mapping[str, Any]) -> str:
    project = parent_plan.get("project")
    if project != PROJECT:
        _refuse("oracle project binding differs")
    return project


def _parent_plan(parent: Mapping[str, Any]) -> Mapping[str, Any]:
    if not isinstance(parent, Mapping) or parent.get("state") != "held":
        _refuse("parent is not held")
    plan = parent.get("plan")
    claim = parent.get("claim")
    gate = parent.get("gate")
    receipt = parent.get("receipt")
    responsibility = parent.get("responsibility")
    if not all(isinstance(value, Mapping) for value in (plan, claim, gate, receipt, responsibility)):
        _refuse("immutable parent evidence required")
    if plan.get("campaignId") != CAMPAIGN or claim.get("campaignId") != CAMPAIGN:
        _refuse("parent campaign differs")
    nonce = plan.get("nonce")
    _nonce(nonce, "parent")
    _project(plan)
    if claim.get("nonceDigest") != digest(nonce):
        _refuse("parent nonce binding differs")
    if gate.get("coordinatorInflight") or any(
        isinstance(job, Mapping) and job.get("inflight") for job in (gate.get("jobs") or {}).values()
    ):
        _refuse("parent worker is still active")
    gate_plan = gate.get("plan")
    if not isinstance(gate_plan, Mapping) or digest(gate_plan) != claim.get("gatePlanDigest"):
        _refuse("parent Gate plan differs")
    if receipt.get("failure") is None or receipt.get("postflightComplete") is True:
        _refuse("unresolved parent failure required")
    custom = [
        operation
        for operation in plan.get("jobs", {}).get("auth-credential", {}).get("observation", [])
        if isinstance(operation, Mapping)
        and operation.get("kind") == "custom-sign-in"
        and operation.get("account") == "custom"
    ]
    if len(custom) != 1:
        _refuse("one immutable custom sign-in required")
    operation = custom[0]
    expected_digest = digest(operation)
    events = gate.get("events")
    if not isinstance(events, list):
        _refuse("parent custom event required")
    matching = [event for event in events if isinstance(event, Mapping) and event.get("requestDigest") == expected_digest]
    if len(matching) != 1 or matching[0].get("completed") is not False or matching[0].get("creationOutcome") not in {"unknown", "pending"}:
        _refuse("parent custom event is not unresolved")
    custom_intent = responsibility.get("custom") or responsibility.get("custom-signin")
    if not isinstance(custom_intent, Mapping) or custom_intent.get("state") != "unknown" or custom_intent.get("uid") is not None:
        _refuse("custom creation responsibility is not unresolved")
    return plan


def _provenance(value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        _refuse("source provenance required")
    source_commit = value.get("sourceCommit")
    if not isinstance(source_commit, str) or COMMIT.fullmatch(source_commit) is None:
        _refuse("source commit provenance required")
    source_inputs = value.get("sourceInputs")
    if not isinstance(source_inputs, Mapping) or not source_inputs:
        _refuse("source input provenance required")
    normalized_inputs: dict[str, str] = {}
    for path, value_hash in source_inputs.items():
        if not isinstance(path, str) or not path.startswith("tools/") or ".." in path.split("/"):
            _refuse("source path provenance differs")
        _sha(value_hash, "source")
        normalized_inputs[path] = value_hash
    normalized: dict[str, Any] = {
        "sourceCommit": source_commit,
        "sourceInputs": normalized_inputs,
        "sourceInputsDigest": digest(normalized_inputs),
    }
    for name, expected_path in (
        ("worker", WORKER_ENTRY),
        ("transport", TRANSPORT_ENTRY),
        ("launcher", LAUNCHER_ENTRY),
    ):
        binding = value.get(name)
        if not isinstance(binding, Mapping) or set(binding) != {"path", "sha256"} or binding["path"] != expected_path:
            _refuse(f"{name} provenance differs")
        _sha(binding["sha256"], name)
        if normalized_inputs.get(expected_path) != binding["sha256"]:
            _refuse(f"{name} source digest differs")
        normalized[name] = {"path": expected_path, "sha256": binding["sha256"]}
    return normalized


def _operation(parent_plan: Mapping[str, Any]) -> dict[str, Any]:
    nonce = parent_plan["nonce"]
    uid = f"custom-{nonce}"
    project = _project(parent_plan)
    return {
        "service": "auth",
        "method": "POST",
        "path": f"{IDENTITY}/projects/{project}/accounts:lookup",
        "body": {"localId": [uid]},
        "form": False,
        "owner": True,
        "kind": "recovery-custom-uid-lookup",
        "account": "custom",
        "resource": f"projects/{project}/auth/accounts/{uid}",
    }


def _stable_plan(plan: Mapping[str, Any]) -> dict[str, Any]:
    value = copy.deepcopy(dict(plan))
    for key in ("planDigest", "permissionDigest", "o7Digest", "o8Digest"):
        value.pop(key, None)
    return value


def _validate_shape(plan: Mapping[str, Any]) -> None:
    if plan.get("kind") != KIND or plan.get("campaignId") != CAMPAIGN or plan.get("operationClass") != OPERATION_CLASS:
        _refuse("Auth recovery plan kind differs")
    _project(plan)
    _nonce(plan.get("recoveryNonce"), "recovery")
    _sha(plan.get("recoveryNonceDigest"), "recovery nonce")
    if plan["recoveryNonceDigest"] != digest(plan["recoveryNonce"]):
        _refuse("recovery nonce binding differs")
    _sha(plan.get("planDigest"), "recovery plan")
    if digest(_stable_plan(plan)) != plan["planDigest"]:
        _refuse("recovery plan digest differs")
    _finite(plan.get("issuedAt"), "recovery issue time")
    _finite(plan.get("deadlineAt"), "recovery deadline")
    if (
        type(plan.get("deadlineSeconds")) is not int
        or not 1 <= plan["deadlineSeconds"] <= MAX_DEADLINE_SECONDS
        or plan["deadlineAt"] <= plan["issuedAt"]
    ):
        _refuse("recovery deadline bound differs")
    if plan.get("budget") != CHILD_BUDGET:
        _refuse("recovery budget differs")
    operations = plan.get("operations")
    if not isinstance(operations, list) or len(operations) != 1:
        _refuse("one recovery lookup required")
    operation = operations[0]
    if not isinstance(operation, Mapping) or operation.get("kind") != "recovery-custom-uid-lookup" or operation.get("method") != "POST" or operation.get("owner") is not True:
        _refuse("read-only custom lookup required")
    if "email" in repr(operation).lower() or operation.get("method") == "DELETE":
        _refuse("email adoption or deletion is forbidden")
    if plan.get("gatePlan") != {"campaignId": CAMPAIGN, "job": "auth-credential-recovery", "observation": [], "recovery": [operation]}:
        _refuse("recovery Gate plan differs")
    _provenance(plan.get("provenance", {}))


def compile_recovery_plan(
    parent: Mapping[str, Any],
    *,
    recovery_nonce: str,
    provenance: Mapping[str, Any],
    now: float | None = None,
    deadline_seconds: int = 180,
) -> dict[str, Any]:
    """Compile one fresh child without reading credentials or touching a Ledger."""
    parent_plan = _parent_plan(parent)
    _nonce(recovery_nonce, "recovery")
    if recovery_nonce == parent_plan["nonce"]:
        _refuse("recovery nonce must be fresh")
    if type(deadline_seconds) is not int or not 1 <= deadline_seconds <= MAX_DEADLINE_SECONDS:
        _refuse("finite recovery deadline required")
    issued_at = time.time() if now is None else now
    _finite(issued_at, "recovery issue time")
    provenance_value = _provenance(provenance)
    if provenance_value["sourceCommit"] != parent_plan.get("sourceCommit"):
        _refuse("source commit must remain parent-linked")
    parent_claim = parent["claim"]
    parent_gate = parent["gate"]
    parent_receipt = parent["receipt"]
    parent_responsibility = parent["responsibility"]
    operation = _operation(parent_plan)
    resource = operation["resource"]
    gate_plan = {
        "campaignId": CAMPAIGN,
        "job": "auth-credential-recovery",
        "observation": [],
        "recovery": [operation],
    }
    plan: dict[str, Any] = {
        "kind": KIND,
        "campaignId": CAMPAIGN,
        "operationClass": OPERATION_CLASS,
        "project": PROJECT,
        "recoveryNonce": recovery_nonce,
        "recoveryNonceDigest": digest(recovery_nonce),
        "issuedAt": issued_at,
        "deadlineSeconds": deadline_seconds,
        "deadlineAt": issued_at + deadline_seconds,
        "budget": copy.deepcopy(CHILD_BUDGET),
        "parent": {
            "ticketDigest": digest(parent.get("ticket")),
            "claimDigest": parent_claim.get("claimDigest", digest(parent_claim)),
            "planDigest": digest(parent_plan),
            "gateDigest": digest(parent_gate),
            "receiptDigest": digest(parent_receipt),
            "responsibilityDigest": digest(parent_responsibility),
            "state": "held",
        },
        "customUid": operation["body"]["localId"][0],
        "customUidDigest": digest(operation["body"]["localId"][0]),
        "resource": resource,
        "operationDigest": digest(operation),
        "operations": [operation],
        "gatePlan": gate_plan,
        "provenance": provenance_value,
    }
    plan["planDigest"] = digest(_stable_plan(plan))
    _validate_shape(plan)
    return plan


def validate_plan(plan: Mapping[str, Any], parent: Mapping[str, Any]) -> dict[str, Any]:
    """Revalidate a detached plan against the unchanged held parent."""
    parent_plan = _parent_plan(parent)
    _validate_shape(plan)
    expected_operation = _operation(parent_plan)
    if plan.get("parent", {}).get("planDigest") != digest(parent_plan) or plan.get("operations") != [expected_operation] or plan.get("customUid") != expected_operation["body"]["localId"][0]:
        _refuse("parent-linked custom UID plan differs")
    if plan.get("operationDigest") != digest(expected_operation) or plan.get("resource") != expected_operation["resource"]:
        _refuse("custom UID operation binding differs")
    return copy.deepcopy(dict(plan))


def _authority_fields(value: Mapping[str, Any], kind: str) -> None:
    if not isinstance(value, Mapping) or value.get("kind") != kind:
        _refuse(f"{kind} authority required")
    for field in ("campaignId", "planDigest", "permissionDigest", "nonceDigest", "sourceInputsDigest"):
        if value.get(field) is None:
            _refuse(f"{kind} binding required")
    if value.get("campaignId") != CAMPAIGN:
        _refuse(f"{kind} campaign differs")
    _sha(value["planDigest"], f"{kind} plan")
    _sha(value["permissionDigest"], f"{kind} permission")
    _sha(value["nonceDigest"], f"{kind} nonce")
    _sha(value["sourceInputsDigest"], f"{kind} source")
    _finite(value.get("issuedAt"), f"{kind} issue time")
    _finite(value.get("expiresAt"), f"{kind} expiry")
    if value["expiresAt"] <= value["issuedAt"]:
        _refuse(f"{kind} window differs")


def validate_authority_bundle(
    plan: Mapping[str, Any], *, permission: Mapping[str, Any], o7: Mapping[str, Any], o8: Mapping[str, Any], now: float | None = None
) -> None:
    """Require fresh, mutually bound O7/O8 metadata without handling secrets."""
    _validate_shape(plan)
    if not isinstance(permission, Mapping) or permission.get("kind") != PERMISSION_KIND:
        _refuse("fresh recovery permission required")
    if permission.get("campaignId") != CAMPAIGN or permission.get("planDigest") != plan["planDigest"] or permission.get("nonceDigest") != plan["recoveryNonceDigest"] or permission.get("sourceInputsDigest") != plan["provenance"]["sourceInputsDigest"] or permission.get("budget") != CHILD_BUDGET:
        _refuse("recovery permission binding differs")
    if permission.get("parentClaimDigest") != plan["parent"]["claimDigest"]:
        _refuse("recovery parent claim binding differs")
    _finite(permission.get("issuedAt"), "permission issue time")
    _finite(permission.get("expiresAt"), "permission expiry")
    if permission["expiresAt"] <= permission["issuedAt"]:
        _refuse("permission window differs")
    permission_digest = digest(permission)
    _authority_fields(o7, O7_KIND)
    _authority_fields(o8, O8_KIND)
    for value in (o7, o8):
        if value["planDigest"] != plan["planDigest"] or value["permissionDigest"] != permission_digest or value["nonceDigest"] != plan["recoveryNonceDigest"] or value["sourceInputsDigest"] != plan["provenance"]["sourceInputsDigest"]:
            _refuse("fresh O7/O8 binding differs")
    if o7.get("status") != "approved" or o8.get("status") != "issued" or o8.get("oneShot") is not True or o8.get("consumed") is not False or not isinstance(o8.get("capabilityDigest"), str) or SHA256.fullmatch(o8["capabilityDigest"]) is None:
        _refuse("fresh O7/O8 status differs")
    current = time.time() if now is None else now
    _finite(current, "authority check time")
    if not all(value["issuedAt"] >= plan["issuedAt"] for value in (permission, o7, o8)):
        _refuse("fresh O7/O8 issue time differs")
    if not all(current < value["expiresAt"] for value in (permission, o7, o8)):
        _refuse("fresh O7/O8 authority expired")


def build_child_claim(
    parent: Mapping[str, Any],
    plan: Mapping[str, Any],
    *,
    permission: Mapping[str, Any],
    gate_path: str,
    owner_identity: str,
    recovery_owner: str,
    execution_host: Mapping[str, str],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Build the Auth-specific claim and envelope passed to the shared Ledger."""
    validate_plan(plan, parent)
    if not _text(gate_path) or not gate_path.startswith("/") or not _text(owner_identity) or not _text(recovery_owner):
        _refuse("recovery child authority fields required")
    if owner_identity == recovery_owner or not isinstance(execution_host, Mapping) or set(execution_host) != {"platform", "machine"} or not all(_text(value) for value in execution_host.values()):
        _refuse("recovery execution authority differs")
    _sha(permission.get("permissionDigest", digest(permission)), "permission")
    resource = plan["resource"]
    claim = {
        "kind": CHILD_KIND,
        "version": 1,
        "campaignId": CAMPAIGN,
        "operationClass": OPERATION_CLASS,
        "manifestDigest": plan["planDigest"],
        "nonceDigest": plan["recoveryNonceDigest"],
        "gatePlanDigest": digest(plan["gatePlan"]),
        "parentClaimDigest": parent["claim"].get("claimDigest", digest(parent["claim"])),
        "parentPlanDigest": plan["parent"]["planDigest"],
        "permissionDigest": digest(permission),
        "resourceDigest": digest([resource]),
        "ownedResources": [resource],
        "recoveryNonce": plan["recoveryNonce"],
        "ownerIdentity": owner_identity,
        "recoveryOwner": recovery_owner,
        "executionHost": dict(execution_host),
        "expiresAt": plan["deadlineAt"],
        "durationSeconds": plan["deadlineSeconds"],
        "gatePath": gate_path,
        "gateJob": plan["gatePlan"]["job"],
        "budget": copy.deepcopy(CHILD_BUDGET),
        "readCount": 1,
        "inspectionCount": 1,
        "absenceCount": 1,
        "deleteCount": 0,
        "provenance": copy.deepcopy(plan["provenance"]),
        "customUidDigest": plan["customUidDigest"],
    }
    envelope = {
        "kind": ENVELOPE_KIND,
        "permissionDigest": digest(permission),
        "issuedAt": plan["issuedAt"],
        "expiresAt": plan["deadlineAt"],
        "limits": copy.deepcopy(CHILD_BUDGET),
        "concurrency": 1,
        "scopes": [{"key": f"project/{PROJECT}/auth/accounts/{plan['customUid']}", "mode": "READ"}],
    }
    return claim, envelope


def begin_child(
    ledger: Any,
    *,
    parent_ticket: Mapping[str, Any],
    parent: Mapping[str, Any],
    plan: Mapping[str, Any],
    permission: Mapping[str, Any],
    o7: Mapping[str, Any],
    o8: Mapping[str, Any],
    gate_path: str = "/tmp/auth-recovery-gate",
    owner_identity: str = "owner@example.invalid",
    recovery_owner: str = "recovery@example.invalid",
    execution_host: Mapping[str, str] | None = None,
    now: float | None = None,
) -> Any:
    """Persist the child before capability use; never call the generic FS API."""
    validate_plan(plan, parent)
    validate_authority_bundle(plan, permission=permission, o7=o7, o8=o8, now=now)
    claim, envelope = build_child_claim(
        parent,
        plan,
        permission=permission,
        gate_path=gate_path,
        owner_identity=owner_identity,
        recovery_owner=recovery_owner,
        execution_host=execution_host or {"platform": "unknown", "machine": "unknown"},
    )
    method = getattr(ledger, "begin_auth_recovery_extension", None)
    if not callable(method):
        _refuse("Auth recovery Ledger API required")
    try:
        ticket = method(
            parent_ticket,
            claim,
            envelope,
            parent["plan"],
            plan["gatePlan"],
            parent_inputs=parent.get("inputs"),
            parent_permission=parent.get("permission"),
            child_permission=copy.deepcopy(permission),
            o7=copy.deepcopy(o7),
            o8=copy.deepcopy(o8),
        )
    except RecoveryRefusal:
        raise
    except Exception as error:  # noqa: BLE001 -- shared boundary returns no secret text
        raise RecoveryRefusal(f"Auth recovery child refused: {type(error).__name__}") from None
    if not isinstance(ticket, Mapping) or ticket.get("parentReservation") != parent_ticket.get("reservation"):
        _refuse("Auth recovery child parent binding differs")
    return copy.deepcopy(dict(ticket))


def _shape(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, dict):
        return "object"
    if isinstance(value, list):
        return "array"
    if isinstance(value, str):
        return "string"
    if isinstance(value, (int, float)):
        return "number"
    return "other"


def custom_sign_in_diagnostic(status: Any, body: Any) -> dict[str, Any]:
    """Project creation-status facts without retaining UID or token values."""
    result: dict[str, Any] = {"status": status, "bodyType": _shape(body)}
    if not isinstance(body, Mapping):
        result.update(localId="missing", isNewUser="missing", tokens={"idToken": "missing", "refreshToken": "missing"})
        return result
    local_id = body.get("localId")
    result["localId"] = "present" if _text(local_id) else ("malformed" if "localId" in body else "missing")
    if body.get("isNewUser") is True:
        result["isNewUser"] = "boolean-true"
    elif body.get("isNewUser") is False:
        result["isNewUser"] = "boolean-false"
    elif "isNewUser" not in body:
        result["isNewUser"] = "missing"
    else:
        result["isNewUser"] = "malformed"
    result["tokens"] = {name: "present" if _text(body.get(name)) else ("malformed" if name in body else "missing") for name in ("idToken", "refreshToken")}
    return result


def _typed_empty(status: Any, body: Any) -> bool:
    return type(status) is int and status == 200 and isinstance(body, Mapping) and body.get("kind") == "identitytoolkit#GetAccountInfoResponse" and body.get("users") == [] and set(body) == {"kind", "users"}


def execute_lookup(
    plan: Mapping[str, Any],
    *,
    send: Callable[[Mapping[str, Any], float], tuple[Any, Any]],
    now: Callable[[], float] | float | None = None,
) -> dict[str, Any]:
    """Send exactly one UID lookup and return only a secret-free typed result."""
    _validate_shape(plan)
    clock = now if callable(now) else (lambda: time.time() if now is None else float(now))
    started = clock()
    _finite(started, "lookup clock")
    remaining = plan["deadlineAt"] - started
    if remaining <= 0:
        _refuse("recovery deadline expired")
    try:
        status, body = send(copy.deepcopy(plan["operations"][0]), remaining)
    except TimeoutError:
        _refuse("lookup timeout")
    except Exception as error:  # noqa: BLE001 -- no transport text crosses the boundary
        raise RecoveryRefusal(f"lookup transport refused: {type(error).__name__}") from None
    if _typed_empty(status, body):
        return {
            "kind": "auth-credential-recovery-result-v1",
            "disposition": "typed-empty",
            "lookupCount": 1,
            "status": 200,
            "responseDigest": digest(body),
            "response": {"kind": body["kind"], "users": 0},
            "receiptDigest": hashlib.sha256(repr((plan["planDigest"], digest(body))).encode()).hexdigest(),
        }
    if type(status) is int and status == 200 and isinstance(body, Mapping) and isinstance(body.get("users"), list):
        if not body["users"]:
            _refuse("malformed custom account lookup response")
        if len(body["users"]) == 1 and isinstance(body["users"][0], Mapping):
            _refuse("present custom account")
        _refuse("ambiguous custom account result")
    _refuse("malformed custom account lookup response")


def settle_and_close(
    ledger: Any,
    *,
    parent_ticket: Mapping[str, Any],
    child_ticket: Mapping[str, Any],
    parent: Mapping[str, Any],
    plan: Mapping[str, Any],
    result: Mapping[str, Any],
) -> Any:
    """Settle and close only after the typed empty lookup result."""
    if not isinstance(result, Mapping) or result.get("disposition") != "typed-empty" or result.get("lookupCount") != 1:
        _refuse("typed-empty child result required")
    if result.get("status") != 200 or result.get("response") != {
        "kind": "identitytoolkit#GetAccountInfoResponse",
        "users": 0,
    }:
        _refuse("typed-empty child response required")
    _sha(result.get("responseDigest"), "recovery response")
    _sha(result.get("receiptDigest"), "recovery receipt")
    expected_receipt = hashlib.sha256(
        repr((plan["planDigest"], result["responseDigest"])).encode()
    ).hexdigest()
    if result["receiptDigest"] != expected_receipt:
        _refuse("recovery receipt binding differs")
    validate_plan(plan, parent)
    settle = getattr(ledger, "settle_auth_recovery_child", None)
    close = getattr(ledger, "close_after_auth_recovery_child", None)
    if not callable(settle) or not callable(close):
        _refuse("Auth recovery close API required")
    try:
        settled = settle(
            child_ticket,
            receipt_digest=result["receiptDigest"],
            canonical_parent_plan=parent["plan"],
            canonical_child_plan=plan["gatePlan"],
            result=copy.deepcopy(dict(result)),
        )
        return close(
            parent_ticket,
            settled,
            receipt_digest=result["receiptDigest"],
            canonical_parent_plan=parent["plan"],
            canonical_child_plan=plan["gatePlan"],
            result=copy.deepcopy(dict(result)),
        )
    except RecoveryRefusal:
        raise
    except Exception as error:  # noqa: BLE001 -- parent remains held on shared refusal
        raise RecoveryRefusal(f"Auth recovery close refused: {type(error).__name__}") from None


__all__ = [
    "CAMPAIGN",
    "CHILD_BUDGET",
    "LAUNCHER_ENTRY",
    "O7_KIND",
    "O8_KIND",
    "PERMISSION_KIND",
    "RecoveryRefusal",
    "TRANSPORT_ENTRY",
    "WORKER_ENTRY",
    "begin_child",
    "build_child_claim",
    "compile_recovery_plan",
    "custom_sign_in_diagnostic",
    "execute_lookup",
    "settle_and_close",
    "validate_authority_bundle",
    "validate_plan",
]
