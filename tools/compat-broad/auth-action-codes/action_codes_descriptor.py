"""Typed O8 descriptor for the bounded AUTH-ACTION action-code campaign."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "tools/compat-broad"))
sys.path.insert(0, str(ROOT / "tools/compat-broad/o8-core"))
sys.path.insert(0, str(HERE))

import action_codes_collector
import action_codes_comparator
import action_codes_plan as plan_module
import action_codes_remote_transport
from broad_contract import digest
from o8_campaign import CAMPAIGN_APPROVAL_FIELDS, CampaignDescriptor

CAMPAIGN = plan_module.CAMPAIGN_ID
AUTHORIZED_PROJECT = "fireemu-35fe6"
FROZEN_INPUTS_KIND = "auth-action-codes-frozen-inputs-v1"
PERMISSION_KIND = "auth-action-codes-owner-permission-v1"
APPROVAL_KIND = "auth-action-codes-o8-approval-v1"
MANIFEST_KIND = "auth-action-codes-o8-manifest-v1"
ARTIFACT_PROFILE = "auth-action-codes-local-shadow-v1"
IDENTITY_SCOPE = action_codes_remote_transport.IDENTITY_SCOPE
LANE_DIRECTORY = "tools/compat-broad/auth-action-codes"
COLLECTOR_ENTRY = f"{LANE_DIRECTORY}/action_codes_collector.py"
COMPARATOR_ENTRY = f"{LANE_DIRECTORY}/action_codes_comparator.py"
WORKER_ENTRY = "tools/compat-broad/auth-credential-tokens/credential_https_worker.py"
GATE_ENTRY = f"{LANE_DIRECTORY}/action_codes_plan.py"
SHARED_SOURCES = (
    "tools/compat-broad/broad_contract.py",
    "tools/compat-broad/shared_gate.py",
    "tools/compat-broad/production-admission/reservations.py",
    "tools/compat-broad/o8-core/o8_admission.py",
    "tools/compat-broad/o8-core/o8_campaign.py",
    "tools/compat-broad/auth-credential-tokens/credential_https_worker.py",
    "tools/compat-broad/auth-credential-tokens/credential_remote_transport.py",
)
ABORT_CLOSURE_SOURCES = (
    "tools/compat-broad/shared_gate.py",
    "tools/compat-broad/production-admission/reservations.py",
    "tools/compat-broad/o8-core/o8_admission.py",
    f"{LANE_DIRECTORY}/action_codes_plan.py",
    f"{LANE_DIRECTORY}/action_codes_admission.py",
    f"{LANE_DIRECTORY}/action_codes_gate.py",
    f"{LANE_DIRECTORY}/action_codes_o8.py",
    f"{LANE_DIRECTORY}/action_codes_descriptor.py",
    f"{LANE_DIRECTORY}/action_codes_remote_transport.py",
    f"{LANE_DIRECTORY}/action_codes_production.py",
    f"{LANE_DIRECTORY}/action_codes_collector.py",
)


def _source_files() -> tuple[str, ...]:
    return tuple(sorted(f"{LANE_DIRECTORY}/{path.name}" for path in HERE.glob("*.py")))


def source_map() -> dict[str, str]:
    values = {}
    for name in (*_source_files(), *SHARED_SOURCES):
        path = ROOT / name
        if path.is_symlink() or not path.is_file():
            raise ValueError("frozen campaign source missing")
        values[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    return values


def plan_compiler(nonce: str) -> dict:
    return plan_module.campaign_manifest(nonce, project=AUTHORIZED_PROJECT)


def lock_scopes(plan: dict) -> list[dict]:
    nonce = plan["nonce"]
    project = plan["localProject"]
    return [
        {
            "key": f"project/{project}/auth/accounts/o1-oob-{nonce}-a",
            "mode": "WRITE",
        },
        {
            "key": f"project/{project}/auth/accounts/o1-oob-{nonce}-b",
            "mode": "WRITE",
        },
    ]


def frozen_bounds() -> dict:
    return {
        "observationRequests": 26,
        "recoveryRequests": 6,
        "ownedAccountsMax": 2,
        "maxConcurrency": 1,
        "wallSeconds": 300,
        "recoverySeconds": 180,
    }


def budget() -> dict:
    return dict(plan_compiler(plan_module.NONCE_TEMPLATE)["budget"])


def cost_model() -> dict:
    plan = plan_compiler("0" * 32)
    rows = (*plan["stages"], *plan["recovery"])
    return {
        "campaignId": CAMPAIGN,
        "maximumCostMicrousd": round(plan["budget"]["planningCeilingUsd"] * 1_000_000),
        "requests": len(rows) + 2,
    }


def permission_bindings(plan, source_commit, artifact_digest, inputs, baseline=None):
    if plan_module.manifest_digest(plan) != plan_module.manifest_digest(
        plan_compiler(plan["nonce"])
    ):
        raise ValueError("authorized project plan differs")
    principal = _owner_principal(baseline)
    return {
        "kind": PERMISSION_KIND,
        "campaignId": CAMPAIGN,
        "projectId": AUTHORIZED_PROJECT,
        "logicalAccounts": {
            account: {"resource": f"projects/{AUTHORIZED_PROJECT}/auth/accounts/o1-oob-{plan['nonce']}-{'a' if account == 'accountA' else 'b'}"}
            for account in ("accountA", "accountB")
        },
        "role": plan["permissionEnvelope"]["role"],
        "scope": plan["permissionEnvelope"]["scope"],
        "credentialPrincipal": {
            **principal,
        },
        "methods": list(plan["permissionEnvelope"]["methods"]),
        "nonce": plan["nonce"],
        "planDigest": digest(plan),
        "sourceCommit": source_commit,
        "sourceInputs": inputs,
        "artifactSha256": artifact_digest,
        "wallSeconds": 300,
        "recoverySeconds": 180,
        "resourceLocks": lock_scopes(plan),
        "budget": budget(),
    }


def validate_permission(permission, plan, *, source_inputs=None, source_commit=None, artifact_sha256=None):
    """Validate authorization semantics, not only a digest over caller data."""
    envelope = plan["permissionEnvelope"]
    principal = _owner_principal(permission)
    expected = {
        "kind": PERMISSION_KIND,
        "campaignId": CAMPAIGN,
        "projectId": AUTHORIZED_PROJECT,
        "logicalAccounts": {
            account: {"resource": f"projects/{AUTHORIZED_PROJECT}/auth/accounts/o1-oob-{plan['nonce']}-{'a' if account == 'accountA' else 'b'}"}
            for account in ("accountA", "accountB")
        },
        "role": envelope["role"],
        "scope": envelope["scope"],
        "credentialPrincipal": {
            **principal,
        },
        "methods": list(envelope["methods"]),
        "nonce": plan["nonce"],
        "planDigest": digest(plan),
        "sourceCommit": source_commit if source_commit is not None else permission.get("sourceCommit"),
        "sourceInputs": source_inputs if source_inputs is not None else permission.get("sourceInputs"),
        "artifactSha256": artifact_sha256 if artifact_sha256 is not None else permission.get("artifactSha256"),
        "wallSeconds": 300,
        "recoverySeconds": 180,
        "resourceLocks": lock_scopes(plan),
        "budget": budget(),
    }
    if permission != expected:
        raise ValueError("semantic owner permission binding differs")


def _owner_principal(value):
    candidate = value.get("credentialPrincipal") if isinstance(value, dict) else None
    if not isinstance(candidate, dict) or set(candidate) != {
        "clientId", "verifiedEmail", "requiredScopes"
    }:
        raise ValueError("owner-approved credential principal required")
    client_id = candidate["clientId"]
    email = candidate["verifiedEmail"]
    scopes = candidate["requiredScopes"]
    if (
        not isinstance(client_id, str)
        or not client_id
        or not isinstance(email, str)
        or not email
        or not isinstance(scopes, list)
        or scopes != [action_codes_remote_transport.IDENTITY_SCOPE]
    ):
        raise ValueError("owner-approved credential principal differs")
    return {
        "clientId": client_id,
        "verifiedEmail": email,
        "requiredScopes": list(scopes),
    }


def transport_bound(value, *, binding, binding_digest, capability=None):
    if capability is None or not isinstance(value, dict):
        raise ValueError("closed Action wire call required")
    required = {"stageId", "project", "nonce", "body", "deadline", "inputsDigest"}
    if set(value) != required:
        raise ValueError("closed Action credential envelope required")
    return action_codes_remote_transport._transmit_bound(
        capability,
        value,
        binding=binding,
        binding_digest=binding_digest,
    )


def binding_verifier(binding, binding_digest, frozen):
    if not isinstance(binding, bytes) or hashlib.sha256(binding).hexdigest() != binding_digest:
        raise ValueError("reviewed worker binding differs")
    if frozen is not None and frozen.get(WORKER_ENTRY) != binding_digest:
        raise ValueError("worker source binding differs")


def retained_artifact_validator(artifact_path, manifest_path, profile):
    if profile != ARTIFACT_PROFILE:
        raise ValueError("retained artifact profile differs")
    values = {}
    for key, path in (("artifactSha256", artifact_path), ("retainedManifestSha256", manifest_path)):
        path = Path(path)
        if path.is_symlink() or not path.is_file() or path.stat().st_size == 0:
            raise ValueError("retained regular artifact required")
        values[key] = hashlib.sha256(path.read_bytes()).hexdigest()
    return values


def forbidden_transports():
    return (action_codes_remote_transport,)


def collector(*args, **kwargs):
    raise ValueError("production Action collector remains closed")


def comparator(result, shadow=None):
    return action_codes_comparator.compare(result, shadow)


def descriptor() -> CampaignDescriptor:
    return CampaignDescriptor(
        campaign_id=CAMPAIGN,
        frozen_inputs_kind=FROZEN_INPUTS_KIND,
        permission_kind=PERMISSION_KIND,
        approval_kind=APPROVAL_KIND,
        manifest_kind=MANIFEST_KIND,
        approval_fields=CAMPAIGN_APPROVAL_FIELDS,
        artifact_profile=ARTIFACT_PROFILE,
        campaign_seconds=300,
        recovery_seconds=180,
        source_map=source_map,
        abort_closure_sources=ABORT_CLOSURE_SOURCES,
        required_source_entries=(COLLECTOR_ENTRY, COMPARATOR_ENTRY, WORKER_ENTRY, GATE_ENTRY),
        frozen_bounds=frozen_bounds(),
        budget=budget(),
        plan_compiler=plan_compiler,
        lock_scopes=lock_scopes,
        collector=collector,
        comparator=comparator,
        cost_model=cost_model,
        permission_bindings=permission_bindings,
        transport_bound=transport_bound,
        binding_verifier=binding_verifier,
        retained_artifact_validator=retained_artifact_validator,
        forbidden_transports=forbidden_transports,
    )


__all__ = ["AUTHORIZED_PROJECT", "CAMPAIGN", "descriptor", "source_map"]
