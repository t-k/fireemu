"""Source-bound, read-only Auth recovery for an unresolved custom sign-in.

The recovery child is deliberately narrower than the observation campaign. It
can perform one exact Admin ``accounts:lookup`` request for the UID derived
from the immutable parent Gate. It cannot adopt an account, delete an account,
or release the parent from a caller-supplied response. The shared Ledger and
the child Gate remain authoritative for allocation and terminal evidence.
"""

from __future__ import annotations

import copy
import math
import os
import platform
import re
import time
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

import shared_gate
from broad_contract import digest

CAMPAIGN = "AUTH-CREDENTIAL-TOKENS-01"
KIND = "auth-custom-uid-recovery-child-v1"
CHILD_KIND = KIND
PERMISSION_KIND = "auth-credential-recovery-permission-v1"
O7_KIND = "auth-credential-recovery-o7-approval-v1"
O8_KIND = "auth-credential-recovery-o8-capability-v1"
ABSENCE_KIND = "auth-uid-absence-proof-v1"
PARENT_EVIDENCE_KIND = "auth-parent-uncertain-create-v1"
LEGACY_PARENT_EVIDENCE_KIND = "auth-parent-legacy-200-unproven-v1"
LEGACY_PARENT_SOURCE_COMMIT = "2d7d9b76c0f8bf3e3716ac98b19b132d0b8e1f1f"
LEGACY_PARENT_CLAIM_DIGEST = "515fcaffc285efe7a0c7e6d4556a6427327f05e95a695f5f20ca43cdbf7af072"
LEGACY_PARENT_PLAN_DIGEST = "59d1b40a4d2b6e34dc8664470fa08d38eca0a11b35fce165649bc7b2554dc1cc"
LEGACY_PARENT_GATE_DIGEST = "6aae5fc3bde659f8b18eef8d2e58d9932c2f896a9fec1d230690cc54ee8827fe"
LEGACY_PARENT_EVENT_INDEX = 13
OPERATION_CLASS = "auth-custom-uid-lookup-only-v1"
GATE_JOB = "auth-credential-recovery"
PROJECT = "fireemu-35fe6"
IDENTITY = "identitytoolkit.googleapis.com/v1"
WORKER_ENTRY = "tools/compat-broad/auth-credential-tokens/credential_https_worker.py"
TRANSPORT_ENTRY = "tools/compat-broad/auth-credential-tokens/credential_remote_transport.py"
LAUNCHER_ENTRY = "tools/compat-broad/auth-credential-tokens/credential_bootstrap.py"
NONCE = re.compile(r"^[0-9a-f]{32}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
MAX_DEADLINE_SECONDS = 60
CHILD_BUDGET = {"requests": 1, "accounts": 1, "resources": 1, "costMicrousd": 50_000}
APPROVED_CHILD_SOURCE_EXTENSION = "recovery.py"
HOST = {"platform": platform.system().lower(), "machine": platform.machine()}


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
    return isinstance(value, str) and bool(value.strip()) and len(value) <= 1024


def _project(plan: Mapping[str, Any]) -> None:
    if plan.get("project") not in (None, PROJECT):
        _refuse("oracle project binding differs")


def _validate_generation(value: Mapping[str, Any], field: str = "generation") -> None:
    if not isinstance(value, Mapping) or set(value) != {"sourceCommit", "collectorSourceDigest", "sourceDigests"}:
        _refuse(f"{field} closure required")
    if not isinstance(value["sourceCommit"], str) or COMMIT.fullmatch(value["sourceCommit"]) is None:
        _refuse(f"{field} source commit required")
    _sha(value["collectorSourceDigest"], f"{field} collector")
    if not isinstance(value["sourceDigests"], Mapping) or not value["sourceDigests"]:
        _refuse(f"{field} source closure required")
    for name, value_hash in value["sourceDigests"].items():
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", name):
            _refuse(f"{field} source name differs")
        _sha(value_hash, f"{field} source")


def _validate_generation_transition(parent: Mapping[str, Any], child: Mapping[str, Any]) -> None:
    if child["sourceCommit"] != parent["sourceCommit"]:
        _refuse("child source generation must retain parent source commit")
    parent_sources = parent["sourceDigests"]
    child_sources = child["sourceDigests"]
    if any(child_sources.get(name) != value_hash for name, value_hash in parent_sources.items()):
        _refuse("child source generation must retain parent source closure")
    if set(child_sources) - set(parent_sources) != {APPROVED_CHILD_SOURCE_EXTENSION}:
        _refuse("child source generation contains an unapproved extension")
    if child_sources[APPROVED_CHILD_SOURCE_EXTENSION] != child["collectorSourceDigest"]:
        _refuse("approved child source extension is not collector-bound")


def _legacy_event_matches(gate_plan: Mapping[str, Any], gate: Mapping[str, Any], parent_job: str, claim_digest: str | None = None, source_commit: str | None = None) -> bool:
    if digest(gate_plan) != LEGACY_PARENT_PLAN_DIGEST or digest(gate) != LEGACY_PARENT_GATE_DIGEST or parent_job != "auth-credential":
        return False
    if claim_digest is not None and claim_digest != LEGACY_PARENT_CLAIM_DIGEST:
        return False
    if source_commit is not None and source_commit != LEGACY_PARENT_SOURCE_COMMIT:
        return False
    operations = gate_plan.get("jobs", {}).get(parent_job, {}).get("observation", [])
    if not isinstance(operations, list) or len(operations) <= LEGACY_PARENT_EVENT_INDEX:
        return False
    operation = operations[LEGACY_PARENT_EVENT_INDEX]
    expected_resource = f"projects/{PROJECT}/auth/accounts/custom-{gate_plan.get('nonce')}"
    if (
        not isinstance(operation, Mapping)
        or operation.get("kind") != "custom-sign-in"
        or operation.get("account") != "custom"
        or operation.get("service") != "auth"
        or operation.get("method") != "POST"
        or operation.get("path") != f"{IDENTITY}/accounts:signInWithCustomToken"
        or operation.get("form") is not False
        or operation.get("owner") is not False
        or operation.get("body") != {"token": "$binding:customToken", "returnSecureToken": True}
        or operation.get("resource") != expected_resource
        or operation.get("binds", {}).get("customUid") not in {"localId", "idToken.sub"}
    ):
        return False
    events = [
        event for event in gate.get("events", [])
        if isinstance(event, Mapping)
        and event.get("job") == parent_job
        and event.get("phase") == "observation"
        and event.get("index") == LEGACY_PARENT_EVENT_INDEX
    ]
    if len(events) != 1:
        return False
    event = events[0]
    evidence = event.get("authEvidence")
    return (
        event.get("requestDigest") == digest(operation)
        and event.get("completed") is True
        and event.get("creationOutcome") == "refused"
        and event.get("failure") is None
        and type(event.get("status")) is int
        and event.get("status") == 200
        and SHA256.fullmatch(event.get("responseDigest", "")) is not None
        and type(event.get("ended")) in (int, float)
        and isinstance(evidence, Mapping)
        and set(evidence) == {"kind", "account", "status", "creationOutcome"}
        and evidence.get("kind") == "custom-sign-in"
        and evidence.get("account") == "custom"
        and evidence.get("status") == 200
        and evidence.get("creationOutcome") == "refused"
    )


def _legacy_workers_exited(gate: Mapping[str, Any]) -> bool:
    jobs = gate.get("jobs")
    pids = [gate.get("coordinatorPid")]
    if isinstance(jobs, Mapping):
        pids.extend(job.get("pid") for job in jobs.values() if isinstance(job, Mapping))
    if any(type(pid) is not int or pid <= 0 for pid in pids):
        return False
    for pid in pids:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            continue
        except OSError:
            return False
        return False
    return True


def _parent_evidence(gate: Mapping[str, Any], job: str, index: int, operation: Mapping[str, Any], event: Mapping[str, Any], *, legacy: bool = False) -> dict[str, Any]:
    evidence = {
        "kind": LEGACY_PARENT_EVIDENCE_KIND if legacy else PARENT_EVIDENCE_KIND,
        "gateDigest": digest(gate),
        "gatePlanDigest": digest(gate["plan"]),
        "job": job,
        "eventIndex": index,
        "requestDigest": digest(operation),
        "resource": operation["resource"],
        "completed": True if legacy else False,
        "creationOutcome": "refused" if legacy else event["creationOutcome"],
    }
    if legacy:
        evidence.update(
            eventDigest=digest(event), responseDigest=event["responseDigest"],
            responsibility="unknown-custom-create", reason="legacy-200-without-creation-proof",
        )
    evidence["evidenceDigest"] = digest(evidence)
    return evidence


def _select_unresolved_custom_event(
    gate_plan: Mapping[str, Any], gate: Mapping[str, Any], parent_job: str, *, allow_legacy: bool = True
) -> tuple[int, Mapping[str, Any], Mapping[str, Any]]:
    jobs = gate_plan.get("jobs")
    job = jobs.get(parent_job) if isinstance(jobs, Mapping) else None
    operations = job.get("observation") if isinstance(job, Mapping) else None
    events = gate.get("events")
    if not isinstance(operations, list) or not isinstance(events, list):
        _refuse("parent observation events required")
    unresolved: list[tuple[int, Mapping[str, Any], Mapping[str, Any]]] = []
    for index, candidate in enumerate(operations):
        if not isinstance(candidate, Mapping) or candidate.get("kind") != "custom-sign-in" or candidate.get("account") != "custom":
            continue
        event = next(
            (
                item
                for item in events
                if isinstance(item, Mapping)
                and item.get("job") == parent_job
                and item.get("phase") == "observation"
                and item.get("index") == index
            ),
            None,
        )
        if (
            isinstance(event, Mapping)
            and event.get("requestDigest") == digest(candidate)
            and event.get("completed") is False
            and event.get("creationOutcome") in {"pending", "unknown"}
        ):
            unresolved.append((index, candidate, event))
    if len(unresolved) != 1:
        if allow_legacy and _legacy_event_matches(gate_plan, gate, parent_job):
            index = LEGACY_PARENT_EVENT_INDEX
            operation = gate_plan["jobs"][parent_job]["observation"][index]
            event = next(
                event for event in gate["events"]
                if event.get("job") == parent_job
                and event.get("phase") == "observation"
                and event.get("index") == index
            )
            return index, operation, event
        _refuse("one unresolved Auth custom event is required")
    return unresolved[0]


def _select_parent_event(gate_plan: Mapping[str, Any], gate: Mapping[str, Any], parent_job: str, *, claim_digest: str | None = None, source_commit: str | None = None) -> tuple[int, Mapping[str, Any], Mapping[str, Any], bool]:
    if _legacy_event_matches(gate_plan, gate, parent_job, claim_digest, source_commit):
        index = LEGACY_PARENT_EVENT_INDEX
        operation = gate_plan["jobs"][parent_job]["observation"][index]
        event = next(
            event for event in gate["events"]
            if event.get("job") == parent_job
            and event.get("phase") == "observation"
            and event.get("index") == index
        )
        return index, operation, event, True
    try:
        index, operation, event = _select_unresolved_custom_event(gate_plan, gate, parent_job, allow_legacy=False)
    except RecoveryRefusal:
        raise
    return index, operation, event, False


def _parent_snapshot(parent: Mapping[str, Any]) -> dict[str, Any]:
    """Validate the held packet and return only its canonical Gate projection."""
    if not isinstance(parent, Mapping) or parent.get("state") != "held":
        _refuse("parent is not held")
    claim, gate, receipt, responsibility = (
        parent.get("claim"), parent.get("gate"), parent.get("receipt"), parent.get("responsibility")
    )
    if not all(isinstance(value, Mapping) for value in (claim, gate, receipt, responsibility)):
        _refuse("immutable parent evidence required")
    gate_plan = gate.get("plan")
    if not isinstance(gate_plan, Mapping):
        _refuse("canonical parent Gate plan required")
    if gate_plan.get("campaignId") != CAMPAIGN or claim.get("campaignId") != CAMPAIGN:
        _refuse("parent campaign differs")
    _project(gate_plan)
    nonce = gate_plan.get("nonce")
    _nonce(nonce, "parent")
    if claim.get("nonceDigest") != digest(nonce) or claim.get("gatePlanDigest") != digest(gate_plan):
        _refuse("parent Gate binding differs")
    parent_job = claim.get("gateJob", "auth-credential")
    plan_job = gate_plan.get("jobs", {}).get(parent_job)
    runtime_job = gate.get("jobs", {}).get(parent_job)
    if not isinstance(plan_job, Mapping) or not isinstance(runtime_job, Mapping):
        _refuse("parent Gate job missing")
    if gate.get("coordinatorInflight") or runtime_job.get("inflight"):
        _refuse("parent worker is still active")
    if receipt.get("failure") is None or receipt.get("postflightComplete") is True:
        _refuse("unresolved parent failure required")
    immutable = parent.get("immutableParent")
    required_immutable = {"kind", "gateDigest", "gatePlanDigest", "nonce", "resource", "eventIndex", "requestDigest", "sourceCommit"}
    if not isinstance(immutable, Mapping) or set(immutable) != required_immutable or immutable.get("kind") != "auth-packet05-parent-binding-v1":
        _refuse("immutable packet05 parent binding required")
    _sha(immutable.get("gateDigest"), "parent Gate")
    _sha(immutable.get("gatePlanDigest"), "parent plan")
    _sha(immutable.get("requestDigest"), "parent request")
    if not isinstance(immutable.get("sourceCommit"), str) or COMMIT.fullmatch(immutable["sourceCommit"]) is None:
        _refuse("immutable parent source commit required")
    generation = parent.get("generation")
    _validate_generation(generation, "parent")
    if immutable["sourceCommit"] != generation["sourceCommit"]:
        _refuse("immutable parent source commit changed")
    if immutable["gateDigest"] != digest(gate) or immutable["gatePlanDigest"] != digest(gate_plan) or immutable["nonce"] != nonce or claim.get("gatePlanDigest") != immutable["gatePlanDigest"]:
        _refuse("immutable parent Gate changed")
    if type(immutable.get("eventIndex")) is not int or immutable["eventIndex"] < 0:
        _refuse("immutable parent event index required")
    event_index, operation, event, legacy = _select_parent_event(
        gate_plan, gate, parent_job,
        claim_digest=claim.get("claimDigest"),
        source_commit=generation.get("sourceCommit"),
    )
    if event_index != immutable["eventIndex"]:
        _refuse("immutable parent event index changed")
    expected_resource = f"projects/{PROJECT}/auth/accounts/custom-{nonce}"
    if not legacy and isinstance(operation.get("resource"), str):
        expected_resource = operation["resource"]
    expected_parent_path = f"{IDENTITY}/accounts:signInWithCustomToken"
    expected_parent_body = {"token": "$binding:customToken", "returnSecureToken": True}
    binds = operation.get("binds")
    if not isinstance(binds, Mapping) or binds.get("customUid") not in {"localId", "idToken.sub"}:
        _refuse("parent custom identity binding differs")
    if operation.get("service") != "auth" or operation.get("method") != "POST" or operation.get("path") != expected_parent_path or operation.get("form") is not False or operation.get("body") != expected_parent_body or operation.get("owner") is not False or operation.get("resource") != expected_resource or immutable["resource"] != expected_resource or immutable["requestDigest"] != digest(operation):
        _refuse("parent custom resource binding differs")
    if event.get("service") != operation["service"] or event.get("method") != operation["method"]:
        _refuse("parent custom event is not unresolved")
    _finite(event.get("ended"), "parent event end")
    if legacy:
        if not _legacy_event_matches(gate_plan, gate, parent_job, claim.get("claimDigest"), generation.get("sourceCommit")):
            _refuse("legacy Auth parent tuple changed")
        if not _legacy_workers_exited(gate):
            _refuse("legacy Auth parent workers are not reaped")
        accounts = runtime_job.get("authAccounts", {})
        proofs = runtime_job.get("creationProofs", {})
        if (not isinstance(accounts, Mapping) or not isinstance(proofs, Mapping)
                or "custom" in accounts or expected_resource in proofs):
            _refuse("legacy Auth custom ownership evidence changed")
    custom = responsibility.get("custom") or responsibility.get("custom-signin")
    if not isinstance(custom, Mapping) or custom.get("state") != "unknown" or custom.get("uid") is not None:
        _refuse("custom creation responsibility is not unresolved")
    return {
        "plan": copy.deepcopy(dict(gate_plan)), "claim": copy.deepcopy(dict(claim)), "gate": copy.deepcopy(dict(gate)),
        "job": parent_job, "eventIndex": event_index, "operation": copy.deepcopy(dict(operation)), "resource": expected_resource,
        "evidence": _parent_evidence(gate, parent_job, event_index, operation, event, legacy=legacy),
        "generation": copy.deepcopy(dict(generation)),
        "sourceCommit": immutable["sourceCommit"],
    }


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
    normalized: dict[str, Any] = {"sourceCommit": source_commit, "sourceInputs": normalized_inputs, "sourceInputsDigest": digest(normalized_inputs)}
    generation_paths = value.get("generationPaths")
    if generation_paths is not None:
        if not isinstance(generation_paths, Mapping):
            _refuse("source generation paths required")
        normalized_paths: dict[str, str] = {}
        for name, path in generation_paths.items():
            if not isinstance(name, str) or not isinstance(path, str) or not path.startswith("tools/") or ".." in path.split("/"):
                _refuse("source generation paths differ")
            normalized_paths[name] = path
        normalized["generationPaths"] = normalized_paths
    for name, expected_path in (("worker", WORKER_ENTRY), ("transport", TRANSPORT_ENTRY), ("launcher", LAUNCHER_ENTRY)):
        binding = value.get(name)
        if not isinstance(binding, Mapping) or set(binding) != {"path", "sha256"} or binding["path"] != expected_path:
            _refuse(f"{name} provenance differs")
        _sha(binding["sha256"], name)
        if normalized_inputs.get(expected_path) != binding["sha256"]:
            _refuse(f"{name} source digest differs")
        normalized[name] = {"path": expected_path, "sha256": binding["sha256"]}
    generation = value.get("generation")
    if not isinstance(generation, Mapping) or set(generation) != {"sourceCommit", "collectorSourceDigest", "sourceDigests"} or generation.get("sourceCommit") != source_commit:
        _refuse("source generation provenance required")
    _sha(generation.get("collectorSourceDigest"), "collector source")
    if not isinstance(generation.get("sourceDigests"), Mapping) or not generation["sourceDigests"]:
        _refuse("source generation closure required")
    for name, value_hash in generation["sourceDigests"].items():
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", name):
            _refuse("source generation path differs")
        _sha(value_hash, "source generation")
    normalized["generation"] = copy.deepcopy(dict(generation))
    return normalized


def _operation(resource: str) -> dict[str, Any]:
    project = resource.split("/")[1]
    return {"kind": "uid-absence", "service": "auth", "method": "POST", "path": f"{IDENTITY}/projects/{project}/accounts:lookup", "body": {"localId": ["$binding:customUid"]}, "account": "custom", "uidBinding": "customUid", "resource": resource, "form": False, "owner": True}


def _stable_plan(plan: Mapping[str, Any]) -> dict[str, Any]:
    value = copy.deepcopy(dict(plan))
    for key in ("planDigest", "permissionDigest", "o7Digest", "o8Digest", "sourceBindingDigest", "transportBindingDigest"):
        value.pop(key, None)
    gate = value.get("gatePlan")
    if isinstance(gate, dict):
        for key in ("sourceBindingDigest", "transportBindingDigest", "o7BindingDigest", "o8BindingDigest"):
            gate.pop(key, None)
    return value


def _validate_shape(plan: Mapping[str, Any]) -> None:
    if not isinstance(plan, Mapping) or plan.get("kind") != KIND or plan.get("campaignId") != CAMPAIGN or plan.get("operationClass") != OPERATION_CLASS:
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
    if type(plan.get("deadlineSeconds")) is not int or not 1 <= plan["deadlineSeconds"] <= MAX_DEADLINE_SECONDS or plan["deadlineAt"] != plan["issuedAt"] + plan["deadlineSeconds"]:
        _refuse("recovery deadline bound differs")
    if plan.get("budget") != CHILD_BUDGET:
        _refuse("recovery budget differs")
    resource = plan.get("resource")
    if not isinstance(resource, str) or not re.fullmatch(rf"projects/{re.escape(PROJECT)}/auth/accounts/custom-[0-9a-f]{{32}}", resource):
        _refuse("exact custom UID resource required")
    expected = _operation(resource)
    if not isinstance(plan.get("operation"), Mapping) or dict(plan["operation"]) != expected:
        _refuse("exact Auth UID lookup required")
    if plan.get("operationDigest") != digest(expected) or plan.get("customUid") != resource.rsplit("/", 1)[1] or plan.get("customUidDigest") != digest(plan["customUid"]):
        _refuse("custom UID operation binding differs")
    gate = plan.get("gatePlan")
    if not isinstance(gate, Mapping) or gate.get("campaignId") != CAMPAIGN or gate.get("project") != PROJECT or gate.get("nonce") != plan["recoveryNonce"]:
        _refuse("recovery Gate plan differs")
    job = gate.get("jobs", {}).get(GATE_JOB)
    expected_recovery_seconds = min(6, max(1, plan["deadlineSeconds"] // 2))
    if gate.get("contract") != "shared-local-v1" or gate.get("intervalSeconds") != 0.25 or gate.get("recoverySeconds") != expected_recovery_seconds or gate.get("observationRequests") != 0 or gate.get("dataRequests") != 1 or gate.get("managementRequests") != 0 or gate.get("recoveryRequests") != 1 or gate.get("costMicrousd") != gate.get("requestCostMicrousd") or gate.get("wallSeconds") != plan["deadlineSeconds"] or not isinstance(job, Mapping):
        _refuse("recovery Gate bounds differ")
    if job.get("observation") != [] or job.get("recovery") != [expected] or job.get("resources") != [resource] or job.get("accountBindings") != {"custom": {"resource": resource, "uidBinding": "customUid"}}:
        _refuse("recovery Gate is not lookup-only")
    schedule = job.get("schedule")
    if not isinstance(schedule, list) or len(schedule) != 1 or schedule[0].get("phase") != "recovery" or schedule[0].get("index") != 0:
        _refuse("recovery Gate schedule differs")
    _provenance(plan.get("provenance", {}))


def compile_recovery_plan(parent: Mapping[str, Any], *, recovery_nonce: str, provenance: Mapping[str, Any], now: float | None = None, deadline_seconds: int = 60) -> dict[str, Any]:
    """Compile a fresh child from the immutable held packet and no credentials."""
    snapshot = _parent_snapshot(parent)
    _nonce(recovery_nonce, "recovery")
    if recovery_nonce == snapshot["plan"]["nonce"]:
        _refuse("recovery nonce must be fresh")
    if type(deadline_seconds) is not int or not 1 <= deadline_seconds <= MAX_DEADLINE_SECONDS:
        _refuse("finite recovery deadline required")
    issued_at = time.time() if now is None else now
    _finite(issued_at, "recovery issue time")
    provenance_value = _provenance(provenance)
    parent_generation = snapshot["generation"]
    if provenance_value["sourceCommit"] != snapshot["sourceCommit"]:
        _refuse("source commit must remain immutable-parent-linked")
    child_generation = provenance_value["generation"]
    if child_generation == parent_generation:
        _refuse("child source generation must advance parent")
    _validate_generation_transition(parent_generation, child_generation)
    resource = snapshot["resource"]
    operation = _operation(resource)
    recovery_seconds = min(6, max(1, deadline_seconds // 2))
    gate_plan = {
        "contract": "shared-local-v1",
        "campaignId": CAMPAIGN,
        "nonce": recovery_nonce,
        "project": PROJECT,
        "signing": True,
        "jobSlots": 1,
        "requestSeconds": 5.0,
        "wallSeconds": deadline_seconds,
        "recoverySeconds": recovery_seconds,
        "intervalSeconds": 0.25,
        "observationRequests": 0,
        "dataRequests": 1,
        "managementRequests": 0,
        "recoveryRequests": 1,
        "requestCostMicrousd": 1,
        "costMicrousd": 1,
        "receiptKind": "auth-credential-recovery-receipt-v1",
        "plannedAccounts": ["custom"],
        "accountResources": [resource],
        "mintedBindings": [],
        "management": {
            "dispatchKind": "closed-v1",
            "observation": [],
            "recovery": [],
            "credentialIds": [],
            "credentialSlots": [],
            "slotSeconds": 0,
            "intervalSeconds": 0.25,
            "totalRequests": 0,
            "observationWindowSeconds": 0,
            "recoveryWindowSeconds": 0,
            "permissionExpiryBound": True,
        },
        "jobs": {
            GATE_JOB: {
                "observation": [],
                "recovery": [operation],
                "resources": [resource],
                "accountBindings": {"custom": {"resource": resource, "uidBinding": "customUid"}},
                "schedule": [{"phase": "recovery", "index": 0, "seconds": 5.0}],
            }
        },
    }
    if recovery_seconds < shared_gate._recovery_time(gate_plan, gate_plan["requestSeconds"]):
        _refuse("recovery deadline cannot fund Gate reserve")
    plan: dict[str, Any] = {"kind": KIND, "campaignId": CAMPAIGN, "operationClass": OPERATION_CLASS, "project": PROJECT, "recoveryNonce": recovery_nonce, "recoveryNonceDigest": digest(recovery_nonce), "issuedAt": issued_at, "deadlineSeconds": deadline_seconds, "deadlineAt": issued_at + deadline_seconds, "budget": copy.deepcopy(CHILD_BUDGET), "parent": {"ticketDigest": digest(parent.get("ticket")), "claimDigest": snapshot["claim"].get("claimDigest", digest(snapshot["claim"])), "planDigest": digest(snapshot["plan"]), "gateDigest": digest(snapshot["gate"]), "eventIndex": snapshot["eventIndex"], "requestDigest": digest(snapshot["operation"]), "resource": resource, "state": "held"}, "customUid": resource.rsplit("/", 1)[1], "customUidDigest": digest(resource.rsplit("/", 1)[1]), "resource": resource, "operationDigest": digest(operation), "operation": operation, "gatePlan": gate_plan, "provenance": provenance_value}
    plan["planDigest"] = digest(_stable_plan(plan))
    _validate_shape(plan)
    return plan


def _binding_digest(value: Mapping[str, Any], kind: str) -> str:
    if not isinstance(value, Mapping) or value.get("kind") != kind:
        _refuse("typed Auth recovery binding required")
    supplied = value.get("digest", value.get("bindingDigest")) or digest(value)
    _sha(supplied, kind)
    return supplied


def _bound_plan(plan: Mapping[str, Any], *, source_binding: Mapping[str, Any], transport_binding: Mapping[str, Any], o7_binding: Mapping[str, Any], o8_binding: Mapping[str, Any]) -> dict[str, Any]:
    value = copy.deepcopy(dict(plan))
    value["gatePlan"].update(sourceBindingDigest=_binding_digest(source_binding, "auth-source-binding-v1"), transportBindingDigest=_binding_digest(transport_binding, "auth-transport-binding-v1"), o7BindingDigest=_binding_digest(o7_binding, "auth-o7-binding-v1"), o8BindingDigest=_binding_digest(o8_binding, "auth-o8-binding-v1"))
    value["sourceBindingDigest"] = value["gatePlan"]["sourceBindingDigest"]
    value["transportBindingDigest"] = value["gatePlan"]["transportBindingDigest"]
    value["o7Digest"] = value["gatePlan"]["o7BindingDigest"]
    value["o8Digest"] = value["gatePlan"]["o8BindingDigest"]
    _validate_shape(value)
    return value


def _validate_child_source_binding(plan: Mapping[str, Any], snapshot: Mapping[str, Any]) -> None:
    provenance = plan.get("provenance")
    generation = provenance.get("generation") if isinstance(provenance, Mapping) else None
    if not isinstance(provenance, Mapping) or provenance.get("sourceCommit") != snapshot["sourceCommit"] or not isinstance(generation, Mapping) or generation.get("sourceCommit") != snapshot["sourceCommit"]:
        _refuse("child source commit must remain immutable-parent-linked")
    _validate_generation_transition(snapshot["generation"], generation)


def validate_plan(plan: Mapping[str, Any], parent: Mapping[str, Any]) -> dict[str, Any]:
    snapshot = _parent_snapshot(parent)
    _validate_shape(plan)
    _validate_child_source_binding(plan, snapshot)
    if plan.get("parent", {}).get("planDigest") != digest(snapshot["plan"]) or plan.get("parent", {}).get("gateDigest") != digest(snapshot["gate"]):
        _refuse("parent Gate evidence differs")
    if plan.get("parent", {}).get("requestDigest") != digest(snapshot["operation"]) or plan.get("parent", {}).get("eventIndex") != snapshot["eventIndex"] or plan.get("resource") != snapshot["resource"]:
        _refuse("parent event binding differs")
    return copy.deepcopy(dict(plan))


def validate_authority_bundle(plan: Mapping[str, Any], *, permission: Mapping[str, Any], o7: Mapping[str, Any], o8: Mapping[str, Any], now: float | None = None) -> None:
    _validate_shape(plan)
    if not isinstance(permission, Mapping) or permission.get("kind") != PERMISSION_KIND or permission.get("campaignId") != CAMPAIGN or permission.get("planDigest") != plan["planDigest"] or permission.get("parentClaimDigest") != plan["parent"]["claimDigest"] or permission.get("nonceDigest") != plan["recoveryNonceDigest"] or permission.get("sourceInputsDigest") != plan["provenance"]["sourceInputsDigest"] or permission.get("budget") != CHILD_BUDGET:
        _refuse("recovery permission binding differs")
    _finite(permission.get("issuedAt"), "permission issue time")
    _finite(permission.get("expiresAt"), "permission expiry")
    if permission["expiresAt"] < plan["deadlineAt"] or permission["expiresAt"] <= permission["issuedAt"]:
        _refuse("permission window does not cover child")
    permission_digest = digest(permission)
    for value, kind in ((o7, O7_KIND), (o8, O8_KIND)):
        if not isinstance(value, Mapping) or value.get("kind") != kind or value.get("campaignId") != CAMPAIGN or value.get("planDigest") != plan["planDigest"] or value.get("permissionDigest") != permission_digest or value.get("nonceDigest") != plan["recoveryNonceDigest"] or value.get("sourceInputsDigest") != plan["provenance"]["sourceInputsDigest"]:
            _refuse("fresh O7/O8 binding differs")
        _finite(value.get("issuedAt"), f"{kind} issue time")
        _finite(value.get("expiresAt"), f"{kind} expiry")
        if value["expiresAt"] < plan["deadlineAt"] or value["expiresAt"] <= value["issuedAt"] or value["issuedAt"] < plan["issuedAt"]:
            _refuse("fresh O7/O8 window does not cover child")
    if o7.get("status") != "approved" or o8.get("status") != "issued" or o8.get("oneShot") is not True or o8.get("consumed") is not False:
        _refuse("fresh O7/O8 status differs")
    if not (plan["issuedAt"] <= permission["issuedAt"] <= o7["issuedAt"] <= o8["issuedAt"]):
        _refuse("fresh authority issue ordering differs")
    current = time.time() if now is None else now
    _finite(current, "authority check time")
    if any(current < issued_at for issued_at in (permission["issuedAt"], o7["issuedAt"], o8["issuedAt"])):
        _refuse("fresh O7/O8 authority is not active")
    if current >= min(permission["expiresAt"], o7["expiresAt"], o8["expiresAt"]):
        _refuse("fresh O7/O8 authority expired")


def build_child_claim(parent: Mapping[str, Any], plan: Mapping[str, Any], *, permission: Mapping[str, Any], source_binding: Mapping[str, Any], transport_binding: Mapping[str, Any], o7_binding: Mapping[str, Any], o8_binding: Mapping[str, Any], parent_evidence: Mapping[str, Any], gate_path: str, owner_identity: str, recovery_owner: str, execution_host: Mapping[str, str] | None = None, now: float | None = None) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    snapshot = _parent_snapshot(parent)
    validate_plan(plan, parent)
    _validate_child_source_binding(plan, snapshot)
    authority_plan = _bound_plan(plan, source_binding=source_binding, transport_binding=transport_binding, o7_binding=o7_binding, o8_binding=o8_binding)
    decision_now = time.time() if now is None else now
    _finite(decision_now, "child allocation time")
    if not isinstance(o7_binding.get("authority"), Mapping) or not isinstance(o8_binding.get("authority"), Mapping):
        _refuse("fresh O7/O8 authority payload required")
    validate_authority_bundle(authority_plan, permission=permission, o7=o7_binding["authority"], o8=o8_binding["authority"], now=decision_now)
    if dict(parent_evidence) != snapshot["evidence"]:
        _refuse("parent evidence differs from canonical Gate")
    gate_path = str(Path(gate_path).resolve())
    host = dict(HOST if execution_host is None else execution_host)
    if not _text(owner_identity) or not _text(recovery_owner) or owner_identity == recovery_owner or host != HOST:
        _refuse("exact Auth recovery execution authority required")
    remaining = authority_plan["deadlineAt"] - decision_now
    if remaining < 1:
        _refuse("recovery deadline expired")
    duration = min(authority_plan["deadlineSeconds"], int(remaining))
    child_gate_plan = copy.deepcopy(authority_plan["gatePlan"])
    child_gate_plan["wallSeconds"] = duration
    child_gate_plan["jobs"][GATE_JOB]["schedule"][0]["seconds"] = min(5.0, float(duration))
    if (
        child_gate_plan["recoverySeconds"] >= child_gate_plan["wallSeconds"]
        or child_gate_plan["recoverySeconds"] < shared_gate._recovery_time(
            child_gate_plan, child_gate_plan["requestSeconds"]
        )
    ):
        _refuse("recovery deadline cannot fund child Gate reserve")
    resource = authority_plan["resource"]
    locks = [{"key": f"project/{PROJECT}/auth/accounts/{authority_plan['customUid']}", "mode": "WRITE"}]
    claim = {"kind": CHILD_KIND, "version": 1, "campaignId": CAMPAIGN, "manifestDigest": digest(child_gate_plan), "nonceDigest": authority_plan["recoveryNonceDigest"], "gatePath": gate_path, "gateJob": GATE_JOB, "parentGateJob": snapshot["job"], "gatePlanDigest": digest(child_gate_plan), "parentClaimDigest": snapshot["claim"].get("claimDigest", digest(snapshot["claim"])), "parentPlanDigest": digest(snapshot["plan"]), "parentGateDigest": snapshot["evidence"]["gateDigest"], "parentEvidenceDigest": snapshot["evidence"]["evidenceDigest"], "parentEventIndex": snapshot["eventIndex"], "parentRequestDigest": digest(snapshot["operation"]), "recoveryNonce": authority_plan["recoveryNonce"], "resourceDigest": digest([resource]), "ownedResources": [resource], "locks": locks, "budget": copy.deepcopy(CHILD_BUDGET), "durationSeconds": duration, "generation": copy.deepcopy(authority_plan["provenance"]["generation"]), "ownerIdentity": owner_identity, "recoveryOwner": recovery_owner, "operationClass": OPERATION_CLASS, "readCount": 1, "inspectionCount": 1, "absenceCount": 1, "deleteCount": 0, "expiresAt": authority_plan["deadlineAt"], "executionHost": host, "permissionDigest": digest(permission), "sourceBindingDigest": authority_plan["gatePlan"]["sourceBindingDigest"], "transportBindingDigest": authority_plan["gatePlan"]["transportBindingDigest"], "o7BindingDigest": authority_plan["gatePlan"]["o7BindingDigest"], "o8BindingDigest": authority_plan["gatePlan"]["o8BindingDigest"]}
    effective_authority_start = max(
        permission["issuedAt"],
        o7_binding["authority"]["issuedAt"],
        o8_binding["authority"]["issuedAt"],
    )
    envelope = {"permissionDigest": digest(permission), "issuedAt": effective_authority_start, "expiresAt": authority_plan["deadlineAt"], "limits": copy.deepcopy(CHILD_BUDGET), "concurrency": 1, "scopes": [{"key": f"project/{PROJECT}/auth/accounts/{authority_plan['customUid']}", "mode": "WRITE"}]}
    authority_plan["gatePlan"] = child_gate_plan
    return claim, envelope, authority_plan


def begin_child(ledger: Any, *, parent_ticket: Mapping[str, Any], parent: Mapping[str, Any], plan: Mapping[str, Any], permission: Mapping[str, Any], o7: Mapping[str, Any], o8: Mapping[str, Any], gate_path: str = "/tmp/auth-recovery-gate", owner_identity: str = "owner@example.invalid", recovery_owner: str = "recovery@example.invalid", execution_host: Mapping[str, str] | None = None, now: float | None = None) -> Any:
    validate_plan(plan, parent)
    validate_authority_bundle(plan, permission=permission, o7=o7, o8=o8, now=now)
    source_binding = {"kind": "auth-source-binding-v1", "digest": plan["provenance"]["sourceInputsDigest"]}
    transport_binding = {"kind": "auth-transport-binding-v1", "digest": digest(plan["provenance"]["transport"])}
    o7_binding = {"kind": "auth-o7-binding-v1", "digest": digest(o7), "authority": copy.deepcopy(dict(o7))}
    o8_binding = {"kind": "auth-o8-binding-v1", "digest": digest(o8), "authority": copy.deepcopy(dict(o8))}
    evidence = _parent_snapshot(parent)["evidence"]
    claim, envelope, bound_plan = build_child_claim(parent, plan, permission=permission, source_binding=source_binding, transport_binding=transport_binding, o7_binding=o7_binding, o8_binding=o8_binding, parent_evidence=evidence, gate_path=gate_path, owner_identity=owner_identity, recovery_owner=recovery_owner, execution_host=execution_host, now=now)
    method = getattr(ledger, "begin_auth_recovery_extension", None)
    if not callable(method):
        _refuse("Auth recovery Ledger API required")
    try:
        ticket = method(parent_ticket, claim, envelope, bound_plan["gatePlan"], source_binding=source_binding, transport_binding=transport_binding, o7_binding=o7_binding, o8_binding=o8_binding, parent_evidence=evidence, now=now)
    except RecoveryRefusal:
        raise
    except Exception as error:  # noqa: BLE001
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
    """Project creation facts without retaining UID or token values."""
    result: dict[str, Any] = {"status": status, "bodyType": _shape(body)}
    if not isinstance(body, Mapping):
        result.update(localId="missing", isNewUser="missing", tokens={"idToken": "missing", "refreshToken": "missing"})
        return result
    local_id = body.get("localId")
    result["localId"] = "present" if _text(local_id) else ("malformed" if "localId" in body else "missing")
    result["isNewUser"] = "boolean-true" if body.get("isNewUser") is True else "boolean-false" if body.get("isNewUser") is False else "missing" if "isNewUser" not in body else "malformed"
    result["tokens"] = {name: "present" if _text(body.get(name)) else ("malformed" if name in body else "missing") for name in ("idToken", "refreshToken")}
    return result


def _typed_empty(status: Any, body: Any) -> bool:
    return type(status) is int and status == 200 and isinstance(body, Mapping) and set(body) == {"kind", "users"} and body.get("kind") == "identitytoolkit#GetAccountInfoResponse" and body.get("users") == []


def execute_lookup(plan: Mapping[str, Any], parent: Mapping[str, Any], *, send: Callable[[Mapping[str, Any], float], tuple[Any, Any]], now: Callable[[], float] | float | None = None) -> dict[str, Any]:
    """Send one exact UID lookup and reject responses that arrive after deadline."""
    validated = validate_plan(plan, parent)
    clock = now if callable(now) else (lambda: time.time() if now is None else float(now))
    started = clock()
    _finite(started, "lookup clock")
    remaining = validated["deadlineAt"] - started
    if remaining <= 0:
        _refuse("recovery deadline expired")
    try:
        wire_operation = copy.deepcopy(validated["operation"])
        wire_operation["body"] = {"localId": [validated["customUid"]]}
        status, body = send(wire_operation, remaining)
    except TimeoutError:
        _refuse("lookup timeout")
    except Exception as error:  # noqa: BLE001
        raise RecoveryRefusal(f"lookup transport refused: {type(error).__name__}") from None
    if clock() >= validated["deadlineAt"]:
        _refuse("lookup completed after deadline")
    if not _typed_empty(status, body):
        if type(status) is int and status == 200 and isinstance(body, Mapping) and isinstance(body.get("users"), list):
            _refuse("present custom account" if body["users"] else "malformed custom account lookup response")
        _refuse("malformed custom account lookup response")
    response_digest = digest(body)
    return {"kind": "auth-credential-recovery-result-v1", "disposition": "typed-empty", "lookupCount": 1, "status": 200, "responseDigest": response_digest, "response": {"kind": body["kind"], "users": 0}}


def _derive_absence_proof(child_gate: Mapping[str, Any], plan: Mapping[str, Any]) -> tuple[dict[str, Any], str]:
    if not isinstance(child_gate, Mapping) or not isinstance(child_gate.get("plan"), Mapping) or child_gate.get("planDigest") != digest(child_gate["plan"]):
        _refuse("bound child Gate plan required")
    expected_gate = copy.deepcopy(plan["gatePlan"])
    for key in ("sourceBindingDigest", "transportBindingDigest", "o7BindingDigest", "o8BindingDigest"):
        expected_gate[key] = child_gate["plan"].get(key)
    expected_gate["wallSeconds"] = child_gate["plan"].get("wallSeconds")
    expected_gate["jobs"][GATE_JOB]["schedule"][0]["seconds"] = child_gate["plan"]["jobs"][GATE_JOB]["schedule"][0].get("seconds")
    wall_seconds = child_gate["plan"].get("wallSeconds")
    if type(wall_seconds) not in (int, float) or isinstance(wall_seconds, bool) or not 1 <= wall_seconds <= plan["deadlineSeconds"]:
        _refuse("child Gate deadline exceeds admitted bound")
    if child_gate["plan"] != expected_gate:
        _refuse("bound child Gate plan differs")
    job = child_gate.get("jobs", {}).get(GATE_JOB)
    operation = plan["operation"]
    if not isinstance(job, Mapping) or job.get("inflight") or job.get("complete") is not True or job.get("recovery") != 1 or job.get("observation") != 0 or job.get("absent") != [plan["resource"]] or child_gate.get("coordinatorInflight") or child_gate.get("skips"):
        _refuse("child Gate terminal evidence incomplete")
    events = child_gate.get("events")
    if not isinstance(events, list) or len(events) != 1:
        _refuse("child Gate terminal event required")
    event = events[0]
    body = {"kind": "identitytoolkit#GetAccountInfoResponse", "users": []}
    response_digest = digest(body)
    if not isinstance(event, Mapping) or event.get("job") != GATE_JOB or event.get("phase") != "recovery" or event.get("index") != 0 or event.get("requestDigest") != digest(operation) or event.get("service") != "auth" or event.get("method") != "POST" or event.get("completed") is not True or event.get("status") != 200 or event.get("responseDigest") != response_digest or job.get("creationProofs") not in (None, {}):
        _refuse("child Gate typed absence evidence changed")
    proof = {"kind": ABSENCE_KIND, "resource": plan["resource"], "status": 200, "bodyShape": body, "bodyDigest": response_digest, "responseDigest": response_digest, "eventIndex": 0, "requestDigest": digest(operation)}
    return proof, response_digest


def _worker_receipt(receipt: Mapping[str, Any], child_gate: Mapping[str, Any], response_digest: str) -> str:
    required = {"kind", "gateDigest", "gatePlanDigest", "responseDigest", "completed", "receiptDigest"}
    if not isinstance(receipt, Mapping) or set(receipt) != required or receipt.get("kind") != "auth-credential-recovery-worker-receipt-v1" or receipt.get("gateDigest") != digest(child_gate) or receipt.get("gatePlanDigest") != digest(child_gate["plan"]) or receipt.get("responseDigest") != response_digest or receipt.get("completed") is not True:
        _refuse("bound worker receipt required")
    supplied = receipt["receiptDigest"]
    _sha(supplied, "worker receipt")
    expected = digest({key: value for key, value in receipt.items() if key != "receiptDigest"})
    if supplied != expected:
        _refuse("worker receipt binding differs")
    return supplied


def settle_and_close(ledger: Any, *, parent_ticket: Mapping[str, Any], child_ticket: Mapping[str, Any], parent: Mapping[str, Any], plan: Mapping[str, Any], child_gate: Mapping[str, Any], worker_receipt: Mapping[str, Any], now: float | None = None) -> Any:
    """Derive absence from the bound Gate, then use the exact API924 contract."""
    validate_plan(plan, parent)
    proof, response_digest = _derive_absence_proof(child_gate, plan)
    receipt_digest = _worker_receipt(worker_receipt, child_gate, response_digest)
    settle = getattr(ledger, "settle_auth_recovery_child", None)
    close = getattr(ledger, "close_after_auth_recovery_child", None)
    if not callable(settle) or not callable(close):
        _refuse("Auth recovery close API required")
    try:
        settled = settle(child_ticket, absence_proof=proof, receipt_digest=receipt_digest, now=now)
        return close(parent_ticket, settled, receipt_digest=receipt_digest, now=now)
    except RecoveryRefusal:
        raise
    except Exception as error:  # noqa: BLE001
        raise RecoveryRefusal(f"Auth recovery close refused: {type(error).__name__}") from None


__all__ = ["ABSENCE_KIND", "CAMPAIGN", "CHILD_BUDGET", "GATE_JOB", "HOST", "KIND", "LAUNCHER_ENTRY", "O7_KIND", "O8_KIND", "PARENT_EVIDENCE_KIND", "PERMISSION_KIND", "TRANSPORT_ENTRY", "WORKER_ENTRY", "RecoveryRefusal", "begin_child", "build_child_claim", "compile_recovery_plan", "custom_sign_in_diagnostic", "execute_lookup", "settle_and_close", "validate_authority_bundle", "validate_plan"]
