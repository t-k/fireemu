"""Closed O7 admission boundary for a persisted request-byte recovery child."""

from __future__ import annotations

import copy
import hashlib
import math
import sys
import time
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "tools/compat-broad"))
sys.path.insert(0, str(ROOT / "tools/compat-broad/o8-core"))
sys.path.insert(0, str(ROOT / "tools/compat-broad/production-admission"))

import o8_admission
import request_bytes_compiler as parent_compiler
import request_bytes_descriptor as parent_descriptor
import request_bytes_recovery_campaign as recovery_campaign
from broad_contract import digest
from o8_campaign import CampaignDescriptor

CAMPAIGN = parent_descriptor.CAMPAIGN
CHILD_BUDGET = {
    "requests": 85,
    "accounts": 0,
    "resources": 51,
    "costMicrousd": 85,
}
CHILD_FIELDS = {
    "requests": 85,
    "inspection": 17,
    "delete": 17,
    "absence": 51,
    "costMicrousd": 85,
}
SENTINEL_CHILD_BUDGET = {
    "requests": 60,
    "accounts": 0,
    "resources": 20,
    "costMicrousd": 60,
}
SENTINEL_CHILD_FIELDS = {
    "requests": 60,
    "inspection": 20,
    "delete": 20,
    "absence": 20,
    "costMicrousd": 60,
}
_RECOVERY_SOURCE = "tools/compat-broad/fs-request-bytes-boundary/request_bytes_recovery_admission.py"


def _source_map() -> dict[str, str]:
    sources = parent_descriptor.source_map()
    path = ROOT / _RECOVERY_SOURCE
    sources[_RECOVERY_SOURCE] = hashlib.sha256(path.read_bytes()).hexdigest()
    return sources


def _plan_compiler(nonce: str, case_id: str | None = None) -> dict[str, Any]:
    if not isinstance(nonce, str) or len(nonce) != 32:
        raise ValueError("recovery nonce required")
    if case_id == parent_compiler.RAW_16MIB_OVER_CASE_ID:
        return {
            "campaignId": CAMPAIGN,
            "nonce": nonce,
            "caseId": case_id,
            **SENTINEL_CHILD_BUDGET,
        }
    if case_id is not None:
        raise ValueError("unsupported closed recovery case selector")
    return {
        "campaignId": CAMPAIGN,
        "nonce": nonce,
        "recoveryRequests": 85,
        "costMicrousd": 85,
        "resources": 51,
    }


def _permission_bindings(plan, source_commit, artifact_digest, inputs, baseline=None):
    if plan.get("campaignId") != CAMPAIGN:
        raise ValueError("recovery plan binding required")
    stable_plan = copy.deepcopy(plan)
    stable_plan.pop("childClaimDigest", None)
    stable_plan.pop("childTicketDigest", None)
    return {
        "kind": parent_descriptor.PERMISSION_KIND,
        "campaignId": CAMPAIGN,
        "nonce": plan["nonce"],
        "planDigest": digest(stable_plan),
        "sourceCommit": source_commit,
        "sourceInputs": inputs,
        "collectorSourceDigest": digest(inputs),
        "artifactSha256": artifact_digest,
        "budget": copy.deepcopy(
            SENTINEL_CHILD_BUDGET if plan.get("caseId") == parent_compiler.RAW_16MIB_OVER_CASE_ID else CHILD_BUDGET
        ),
        "wallSeconds": parent_descriptor.descriptor().campaign_seconds,
        "recoverySeconds": parent_descriptor.descriptor().recovery_seconds,
    }


def descriptor(case_id: str | None = None) -> CampaignDescriptor:
    base = parent_descriptor.descriptor()
    if case_id not in (None, parent_compiler.RAW_16MIB_OVER_CASE_ID):
        raise ValueError("unsupported closed recovery case selector")
    budget = SENTINEL_CHILD_BUDGET if case_id else CHILD_BUDGET
    fields = SENTINEL_CHILD_FIELDS if case_id else CHILD_FIELDS
    return CampaignDescriptor(
        campaign_id=CAMPAIGN,
        frozen_inputs_kind=base.frozen_inputs_kind,
        permission_kind=base.permission_kind,
        approval_kind=base.approval_kind,
        manifest_kind=base.manifest_kind,
        artifact_profile=base.artifact_profile,
        campaign_seconds=base.campaign_seconds,
        recovery_seconds=base.recovery_seconds,
        approval_fields=base.approval_fields,
        source_map=_source_map,
        plan_compiler=lambda nonce: _plan_compiler(nonce, case_id),
        lock_scopes=base.lock_scopes,
        collector=base.collector,
        comparator=base.comparator,
        cost_model=lambda: copy.deepcopy(budget),
        permission_bindings=_permission_bindings,
        transport_bound=base.transport_bound,
        binding_verifier=base.binding_verifier,
        retained_artifact_validator=base.retained_artifact_validator,
        forbidden_transports=base.forbidden_transports,
        frozen_bounds=copy.deepcopy(fields),
        budget=copy.deepcopy(budget),
        abort_closure_sources=(*base.abort_closure_sources, _RECOVERY_SOURCE),
        required_source_entries=(*base.required_source_entries, _RECOVERY_SOURCE),
    )


def validate_bound_child(bound: dict[str, Any], case_id: str | None = None) -> dict[str, Any]:
    """Validate the detached result of ``Ledger.bound_recovery_claim``."""
    required = {
        "ticket",
        "childClaim",
        "newEnvelope",
        "parentClaim",
        "parentIdentity",
        "deadline",
        "state",
    }
    if not isinstance(bound, dict) or set(bound) != required:
        raise ValueError("exact bound recovery claim required")
    ticket = bound["ticket"]
    claim = bound["childClaim"]
    envelope = bound["newEnvelope"]
    parent_claim = bound["parentClaim"]
    parent_identity = bound["parentIdentity"]
    if bound["state"] != "allocated":
        raise ValueError("allocated recovery child required")
    if (
        type(bound["deadline"]) not in (int, float)
        or isinstance(bound["deadline"], bool)
        or not math.isfinite(bound["deadline"])
    ):
        raise ValueError("recovery child deadline changed")
    now = time.time()
    if (
        bound["deadline"] <= now
        or type(claim.get("durationSeconds")) is not int
        or type(claim.get("expiresAt")) not in (int, float)
        or type(envelope.get("expiresAt")) not in (int, float)
        or bound["deadline"] - now > claim["durationSeconds"]
        or bound["deadline"] > claim["expiresAt"]
        or bound["deadline"] > envelope["expiresAt"]
    ):
        raise ValueError("recovery child deadline expired or changed")
    if digest(claim) != ticket.get("claimDigest"):
        raise ValueError("recovery child claim digest changed")
    if digest(envelope) != ticket.get("envelopeDigest"):
        raise ValueError("recovery child envelope digest changed")
    if ticket.get("parentReservation") != parent_identity.get("reservation"):
        raise ValueError("recovery parent identity changed")
    if claim.get("parentClaimDigest") != parent_identity.get("claimDigest"):
        raise ValueError("recovery parent claim binding changed")
    if claim.get("campaignId") != CAMPAIGN:
        raise ValueError("stable recovery campaign required")
    expected_budget = SENTINEL_CHILD_BUDGET if case_id else CHILD_BUDGET
    if claim.get("budget") != expected_budget:
        raise ValueError("exact recovery child budget required")
    if claim.get("permissionDigest") != envelope.get("permissionDigest"):
        raise ValueError("recovery permission binding changed")
    if not isinstance(parent_claim, dict) or not parent_claim:
        raise ValueError("parent claim required")
    if (
        ticket.get("ledgerPath") != parent_identity.get("ledgerPath")
        or ticket.get("ledgerIdentity") != parent_identity.get("ledgerIdentity")
        or ticket.get("parentReservation") != parent_identity.get("reservation")
        or digest(parent_claim) != parent_identity.get("claimDigest")
    ):
        raise ValueError("exact persisted parent identity required")
    generation = claim.get("generation")
    if not isinstance(generation, dict) or not isinstance(claim.get("executionHost"), dict):
        raise ValueError("recovery generation binding required")  # noqa: TRY004 -- admission collapses malformed persisted bindings
    return copy.deepcopy(bound)


def _validate_current_binding(bound, inputs, permission, plan):
    claim = bound["childClaim"]
    generation = claim["generation"]
    if generation.get("sourceCommit") != inputs.get("sourceCommit"):
        raise ValueError("recovery source commit differs")
    source_inputs = inputs.get("sourceInputs")
    if generation.get("collectorSourceDigest") != digest(source_inputs):
        raise ValueError("recovery source closure differs")
    expected_sources = parent_descriptor.generation_source_digests(source_inputs)
    expected_sources[Path(_RECOVERY_SOURCE).name] = source_inputs[_RECOVERY_SOURCE]
    if generation.get("sourceDigests") != expected_sources:
        raise ValueError("recovery source digests differ")
    if claim.get("executionHost") != o8_admission.execution_host():
        raise ValueError("recovery execution host differs")
    expected_permission = descriptor(plan.get("caseId")).permission_bindings(
        plan,
        inputs["sourceCommit"],
        inputs["artifactSha256"],
        source_inputs,
    )
    stable_permission = copy.deepcopy(expected_permission)
    if permission != stable_permission:
        raise ValueError("recovery permission semantics differ")
    if claim.get("permissionDigest") != digest(permission):
        raise ValueError("recovery permission digest differs")


def _canonical_plans(parent_plan, *, selected_probe: str, recovery_nonce: str):
    sentinel = selected_probe == parent_compiler.RAW_16MIB_OVER_LABEL
    if sentinel:
        actual_parent = parent_compiler.compile_request_bytes_sentinel_plan(
            parent_plan["project"], parent_plan["database"], parent_plan["nonce"]
        )
    else:
        actual_parent = parent_compiler.compile_request_bytes_plan(
            parent_plan["project"], parent_plan["database"], parent_plan["nonce"]
        )
    if digest(actual_parent) != digest(parent_plan):
        raise ValueError("canonical parent compiler plan differs")
    recovery_plan = recovery_campaign.compile_recovery_plan(
        actual_parent, selected_probe=selected_probe, recovery_nonce=recovery_nonce
    )
    gate_plan = recovery_campaign.compile_gate_plan(
        actual_parent,
        selected_probe=selected_probe,
        recovery_nonce=recovery_nonce,
        recovery_plan=recovery_plan,
    )
    # O8's canonical plan identity is the persisted recovery nonce; it is not
    # a caller-supplied second nonce and remains transitively child-bound. Keep
    # it out of the Gate compiler input, whose schema is independently frozen.
    recovery_plan["nonce"] = recovery_nonce
    return actual_parent, recovery_plan, gate_plan


def freeze_inputs(
    ledger,
    child_ticket: dict[str, Any],
    parent_plan: dict[str, Any],
    permission: dict[str, Any],
    *,
    selected_probe: str,
    source_commit: str,
    artifact_sha256: str,
) -> dict[str, Any]:
    sentinel = selected_probe == parent_compiler.RAW_16MIB_OVER_LABEL
    case_id = parent_compiler.RAW_16MIB_OVER_CASE_ID if sentinel else None
    bound = ledger.bound_recovery_claim(child_ticket)
    validated = validate_bound_child(bound, case_id)
    claim = validated["childClaim"]
    _, recovery_plan, expected_gate = _canonical_plans(
        parent_plan, selected_probe=selected_probe, recovery_nonce=claim["recoveryNonce"]
    )
    if digest(expected_gate) != claim.get("gatePlanDigest"):
        raise ValueError("child Gate plan digest differs")
    if digest(permission) != claim.get("permissionDigest"):
        raise ValueError("child permission digest differs")
    recovery_plan["childClaimDigest"] = digest(claim)
    recovery_plan["childTicketDigest"] = digest(validated["ticket"])
    return o8_admission.freeze_inputs(
        descriptor(case_id),
        permission,
        recovery_plan,
        source_commit=source_commit,
        artifact_sha256=artifact_sha256,
    )


def issue_production_capability(
    *,
    ledger,
    child_ticket: dict[str, Any],
    parent_plan: dict[str, Any],
    child_gate_plan: dict[str, Any],
    selected_probe: str,
    **bindings,
) -> Any:
    """Re-read the persisted child immediately before the real O7 issuer."""
    selected_probe = bindings["inputs"].get("plan", {}).get("selectedProbe", "under")
    sentinel = selected_probe == parent_compiler.RAW_16MIB_OVER_LABEL
    case_id = parent_compiler.RAW_16MIB_OVER_CASE_ID if sentinel else None
    bound = ledger.bound_recovery_claim(child_ticket)
    validated = validate_bound_child(bound, case_id)
    claim = validated["childClaim"]
    _, recovery_plan, expected_gate = _canonical_plans(
        parent_plan,
        selected_probe=selected_probe,
        recovery_nonce=claim["recoveryNonce"],
    )
    if digest(expected_gate) != claim.get("gatePlanDigest") or child_gate_plan != expected_gate:
        raise ValueError("authoritative child Gate plan differs")
    recovery_plan["childClaimDigest"] = digest(claim)
    recovery_plan["childTicketDigest"] = digest(validated["ticket"])
    inputs = bindings["inputs"]
    if inputs.get("plan") != recovery_plan:
        raise ValueError("frozen authoritative recovery plan differs")
    if inputs.get("permissionDigest") != claim.get("permissionDigest"):
        raise ValueError("frozen child permission binding differs")
    _validate_current_binding(validated, inputs, bindings["permission"], recovery_plan)
    return o8_admission.issue_production_capability(descriptor(case_id), **bindings)


__all__ = [
    "CAMPAIGN",
    "CHILD_BUDGET",
    "descriptor",
    "freeze_inputs",
    "issue_production_capability",
    "validate_bound_child",
]
