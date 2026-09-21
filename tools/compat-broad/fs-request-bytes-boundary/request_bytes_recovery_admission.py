"""Closed O7 admission boundary for a persisted request-byte recovery child."""

from __future__ import annotations

import copy
import hashlib
import math
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "tools/compat-broad"))
sys.path.insert(0, str(ROOT / "tools/compat-broad/o8-core"))
sys.path.insert(0, str(ROOT / "tools/compat-broad/production-admission"))

import o8_admission
import request_bytes_descriptor as parent_descriptor
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
_RECOVERY_SOURCE = "tools/compat-broad/fs-request-bytes-boundary/request_bytes_recovery_admission.py"


def _source_map() -> dict[str, str]:
    sources = parent_descriptor.source_map()
    path = ROOT / _RECOVERY_SOURCE
    sources[_RECOVERY_SOURCE] = hashlib.sha256(path.read_bytes()).hexdigest()
    return sources


def _plan_compiler(nonce: str) -> dict[str, Any]:
    if not isinstance(nonce, str) or len(nonce) != 32:
        raise ValueError("recovery nonce required")
    return {
        "campaignId": CAMPAIGN,
        "nonce": nonce,
        "recoveryRequests": 85,
        "costMicrousd": 85,
        "resources": 51,
    }


def _permission_bindings(plan, source_commit, artifact_digest, inputs, baseline=None):
    if plan.get("campaignId") != CAMPAIGN or plan.get("recoveryRequests") != 85:
        raise ValueError("recovery plan binding required")
    return {
        "kind": parent_descriptor.PERMISSION_KIND,
        "campaignId": CAMPAIGN,
        "nonce": plan["nonce"],
        "planDigest": digest(plan),
        "sourceCommit": source_commit,
        "sourceInputs": inputs,
        "collectorSourceDigest": digest(inputs),
        "artifactSha256": artifact_digest,
        "childClaimDigest": plan.get("childClaimDigest"),
        "childTicketDigest": plan.get("childTicketDigest"),
        "budget": copy.deepcopy(CHILD_BUDGET),
    }


def descriptor() -> CampaignDescriptor:
    base = parent_descriptor.descriptor()
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
        plan_compiler=_plan_compiler,
        lock_scopes=base.lock_scopes,
        collector=base.collector,
        comparator=base.comparator,
        cost_model=lambda: copy.deepcopy(CHILD_BUDGET),
        permission_bindings=_permission_bindings,
        transport_bound=base.transport_bound,
        binding_verifier=base.binding_verifier,
        retained_artifact_validator=base.retained_artifact_validator,
        forbidden_transports=base.forbidden_transports,
        frozen_bounds=copy.deepcopy(CHILD_FIELDS),
        budget=copy.deepcopy(CHILD_BUDGET),
        abort_closure_sources=(*base.abort_closure_sources, _RECOVERY_SOURCE),
        required_source_entries=(*base.required_source_entries, _RECOVERY_SOURCE),
    )


def validate_bound_child(bound: dict[str, Any]) -> dict[str, Any]:
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
    if claim.get("budget") != CHILD_BUDGET:
        raise ValueError("exact 85-request child budget required")
    if claim.get("permissionDigest") != envelope.get("permissionDigest"):
        raise ValueError("recovery permission binding changed")
    if not isinstance(parent_claim, dict) or not parent_claim:
        raise ValueError("parent claim required")
    return copy.deepcopy(bound)


def freeze_inputs(
    bound: dict[str, Any],
    child_plan: dict[str, Any],
    child_gate_plan: dict[str, Any],
    permission: dict[str, Any],
    *,
    source_commit: str,
    artifact_sha256: str,
) -> dict[str, Any]:
    validated = validate_bound_child(bound)
    claim = validated["childClaim"]
    if digest(child_gate_plan) != claim.get("gatePlanDigest"):
        raise ValueError("child Gate plan digest differs")
    if digest(permission) != claim.get("permissionDigest"):
        raise ValueError("child permission digest differs")
    if child_plan.get("campaignId") != CAMPAIGN:
        raise ValueError("stable recovery campaign required")
    child_plan = copy.deepcopy(child_plan)
    if child_plan.get("childClaimDigest") != digest(claim):
        raise ValueError("frozen child claim binding differs")
    if child_plan.get("childTicketDigest") != digest(validated["ticket"]):
        raise ValueError("frozen child ticket binding differs")
    return o8_admission.freeze_inputs(
        descriptor(),
        permission,
        child_plan,
        source_commit=source_commit,
        artifact_sha256=artifact_sha256,
    )


def issue_production_capability(**bindings):
    """Issue the opaque O7 capability only after bound-child validation."""
    bound = bindings.pop("bound")
    child_plan = bindings.pop("child_plan")
    child_gate_plan = bindings.pop("child_gate_plan")
    inputs = bindings["inputs"]
    if inputs.get("permissionDigest") != bound["childClaim"].get("permissionDigest"):
        raise ValueError("frozen child permission binding differs")
    if digest(inputs.get("plan")) != digest(child_plan):
        raise ValueError("frozen child plan differs")
    if inputs.get("plan", {}).get("childClaimDigest") != digest(bound["childClaim"]):
        raise ValueError("frozen child claim binding differs")
    if inputs.get("plan", {}).get("childTicketDigest") != digest(bound["ticket"]):
        raise ValueError("frozen child ticket binding differs")
    validate_bound_child(bound)
    if digest(child_gate_plan) != bound["childClaim"].get("gatePlanDigest"):
        raise ValueError("child Gate plan digest differs")
    return o8_admission.issue_production_capability(
        descriptor(), **bindings
    )


__all__ = [
    "CAMPAIGN",
    "CHILD_BUDGET",
    "descriptor",
    "freeze_inputs",
    "issue_production_capability",
    "validate_bound_child",
]
