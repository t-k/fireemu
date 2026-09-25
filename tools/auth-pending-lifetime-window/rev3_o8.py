"""Offline O7/O8 bindings for the exact pending-lifetime revision-3 plan.

This descriptor deliberately refuses collector and transport use: the rev3 Gate
dispatch/recovery facade has not yet been implemented. Validation fixtures can
exercise the shared O7 checks without implying owner approval or wire authority.
"""

from __future__ import annotations

import hashlib
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
for _path in (
    ROOT / "tools/compat-broad",
    ROOT / "tools/compat-broad/o8-core",
    ROOT / "tools/compat-broad/production-admission",
    Path(__file__).resolve().parent,
):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

import o8_admission
import reservations
import window_recorder
from broad_contract import digest
from o8_campaign import CAMPAIGN_APPROVAL_FIELDS, CampaignDescriptor
from rev3_gate import compile_gate_plan
from rev3_projection import (
    CAMPAIGN_ID,
    CASES_SHA256,
    MAX_ACCOUNTS,
    MAX_AUTH_REQUESTS,
    RECOVERY_SECONDS,
    SELECTOR,
    WALL_SECONDS,
    validate_budget,
    validate_selection,
)
from window_contract import CASES

FROZEN_INPUTS_KIND = "auth-pending-lifetime-rev3-frozen-v1"
PERMISSION_KIND = "auth-pending-lifetime-rev3-owner-permission-v1"
APPROVAL_KIND = "auth-pending-lifetime-rev3-o7-approval-v1"
MANIFEST_KIND = "auth-pending-lifetime-rev3-o7-manifest-v1"
ARTIFACT_PROFILE = "auth-pending-lifetime-rev3-owner-reviewed-artifact-v1"
JOB = "auth-pending-rev3"
PROJECT_NUMBER = str(window_recorder.NUMBER)
PRINCIPAL_SCOPE = "https://www.googleapis.com/auth/cloud-platform"
_LANE = "tools/auth-pending-lifetime-window"
_OWNED_SOURCES = (
    f"{_LANE}/window_contract.py",
    f"{_LANE}/window_recorder.py",
    f"{_LANE}/rev3_projection.py",
    f"{_LANE}/rev3_gate.py",
    f"{_LANE}/rev3_o8.py",
)
_RECORDER_DEPENDENCIES = (
    "tools/auth-pending-revocation/revocation_recorder.py",
    "tools/auth-pending-revocation/revocation_contract.py",
    "tools/auth-password-maximum/maximum_recorder.py",
    "tools/auth-password-maximum/maximum_contract.py",
)
_SHARED_SOURCES = (
    "tools/compat-broad/broad_contract.py",
    "tools/compat-broad/shared_gate.py",
    "tools/compat-broad/production-admission/reservations.py",
    "tools/compat-broad/o8-core/o8_admission.py",
    "tools/compat-broad/o8-core/o8_campaign.py",
)
_SOURCE_PATHS = (*_OWNED_SOURCES, *_RECORDER_DEPENDENCIES, *_SHARED_SOURCES)
_APPROVAL_REQUIRED_FIELDS = CAMPAIGN_APPROVAL_FIELDS
_SHA256 = re.compile(r"^[a-f0-9]{64}$")


def compile_plan(nonce: str, *, selector: str = SELECTOR) -> dict[str, Any]:
    """Compile only the canonical stable-task revision-3 Gate plan."""
    validate_budget()
    validate_selection(selector, CASES)
    return compile_gate_plan(nonce, selector=selector)


def source_map() -> dict[str, str]:
    """Digest the complete rev3 adapter and shared O7/Gate/Ledger dependency set."""
    values: dict[str, str] = {}
    for name in _SOURCE_PATHS:
        path = ROOT / name
        if path.is_symlink() or not path.is_file():
            raise ValueError("complete revision-3 source closure required")
        values[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    return values


def verify_source_snapshot(
    source_root: str | Path, expected_commit: str, expected_inputs: dict[str, str]
) -> None:
    """Require a clean commit whose working and committed closure match O7 inputs."""
    root = Path(source_root)
    if root.is_symlink() or not root.is_dir():
        raise ValueError("clean frozen source snapshot required")

    def git(*args: str) -> bytes:
        return subprocess.check_output(["git", "-C", str(root), *args])

    try:
        commit = git("rev-parse", "HEAD").decode().strip()
        status = git("status", "--porcelain", "--untracked-files=all")
    except (OSError, subprocess.CalledProcessError) as error:
        raise ValueError("clean frozen source snapshot required") from error
    if (
        commit != expected_commit
        or status
        or not isinstance(expected_inputs, dict)
        or set(expected_inputs) != set(_SOURCE_PATHS)
    ):
        raise ValueError("clean frozen source snapshot required")
    for name, expected_digest in expected_inputs.items():
        path = root / name
        if path.is_symlink() or not path.is_file():
            raise ValueError("frozen source input differs")
        observed = hashlib.sha256(path.read_bytes()).hexdigest()
        committed = hashlib.sha256(git("show", f"{expected_commit}:{name}")).hexdigest()
        if observed != expected_digest or committed != expected_digest:
            raise ValueError("frozen source input differs")


def _require_plan(plan: dict[str, Any]) -> None:
    if not isinstance(plan, dict) or plan.get("selector") != SELECTOR:
        raise ValueError("exact revision-3 selector required")
    if plan.get("campaignId") != CAMPAIGN_ID:
        raise ValueError("stable Auth task ID required")
    if plan.get("caseIds") != list(CASES) or plan.get("caseDigest") != CASES_SHA256:
        raise ValueError("exact revision-3 case set required")
    if (
        plan.get("wallSeconds") != WALL_SECONDS
        or plan.get("recoverySeconds") != RECOVERY_SECONDS
        or plan.get("maxObservationSeconds") != 1200
        or plan.get("maxAccounts") != MAX_ACCOUNTS
        or plan.get("maxAuthRequests") != MAX_AUTH_REQUESTS
    ):
        raise ValueError("closed revision-3 budget required")
    canonical = compile_gate_plan(plan.get("nonce", ""))
    if digest(plan) != digest(canonical):
        raise ValueError("frozen revision-3 plan differs")


def _budget(plan: dict[str, Any]) -> dict[str, int]:
    return {
        "requests": plan["maxAuthRequests"],
        "accounts": plan["maxAccounts"],
        "resources": plan["maxAccounts"],
        "costMicrousd": plan["costMicrousd"],
    }


def lock_scopes(plan: dict[str, Any]) -> list[dict[str, str]]:
    _require_plan(plan)
    scopes = [
        {
            "key": "project/" + resource.removeprefix("projects/"),
            "mode": "WRITE",
        }
        for resource in plan["accountResources"]
    ]
    scopes.extend(
        [
            {"key": f"project/{plan['project']}/auth/config", "mode": "EXCLUSIVE"},
            {"key": f"project/{plan['project']}/identity", "mode": "READ"},
        ]
    )
    return scopes


def permission_bindings(
    plan: dict[str, Any],
    source_commit: str,
    artifact_sha256: str,
    inputs: dict[str, str],
    baseline_digest: str | None = None,
    *,
    credential_principal: dict[str, Any] | None = None,
    api_key_project_number: str | None = None,
) -> dict[str, Any]:
    """Return typed owner-required values; no values here are owner approval."""
    _require_plan(plan)
    if not isinstance(source_commit, str) or len(source_commit) != 40:
        raise ValueError("frozen source commit required")
    if not isinstance(artifact_sha256, str) or len(artifact_sha256) != 64:
        raise ValueError("retained artifact digest required")
    if inputs != source_map():
        raise ValueError("revision-3 source closure differs")
    if (
        not isinstance(baseline_digest, str)
        or _SHA256.fullmatch(baseline_digest) is None
    ):
        raise ValueError("owner-frozen Auth configuration baseline SHA-256 required")
    if (
        not isinstance(credential_principal, dict)
        or credential_principal.get("requiredScopes") != [PRINCIPAL_SCOPE]
        or credential_principal.get("requiredRole") != "roles/firebaseauth.admin"
    ):
        raise ValueError("owner-supplied credential principal required")
    identity_fields = {"subject", "verifiedEmail"} & set(credential_principal)
    expected_principal_fields = {
        "clientId",
        "requiredScopes",
        "requiredRole",
        *identity_fields,
    }
    if (
        len(identity_fields) != 1
        or set(credential_principal) != expected_principal_fields
    ):
        raise ValueError("owner-supplied credential principal required")
    o8_admission.validate_owner_identity(
        credential_principal.get("clientId"), field="credential client ID"
    )
    o8_admission.validate_owner_identity(
        credential_principal.get(next(iter(identity_fields))),
        field="credential principal identity",
    )
    if api_key_project_number != PROJECT_NUMBER:
        raise ValueError("API key project number differs")
    return {
        "kind": PERMISSION_KIND,
        "campaignId": CAMPAIGN_ID,
        "project": plan["project"],
        "selector": SELECTOR,
        "caseIds": list(CASES),
        "caseDigest": CASES_SHA256,
        "nonce": plan["nonce"],
        "planDigest": digest(plan),
        "sourceCommit": source_commit,
        "sourceInputs": dict(inputs),
        "artifactSha256": artifact_sha256,
        "artifactProfile": ARTIFACT_PROFILE,
        "wallSeconds": WALL_SECONDS,
        "recoverySeconds": RECOVERY_SECONDS,
        "maxObservationSeconds": 1200,
        "maxAuthRequests": MAX_AUTH_REQUESTS,
        "maxAccounts": MAX_ACCOUNTS,
        "authConfigBaselineDigest": baseline_digest,
        "apiKeyProjectNumber": PROJECT_NUMBER,
        "credentialContract": {
            "principalRequired": True,
            "principal": dict(credential_principal),
            "handoff": "owner-private-token-and-api-key-after-o7-and-ledger-reserve",
            "tokeninfoSlot": "oauth-tokeninfo",
            "apiKeyProjectBindingRequired": True,
            "identitySource": "owner-frozen permission; never inferred from tokeninfo",
        },
        "recoveryContract": {
            "seconds": RECOVERY_SECONDS,
            "authRequestReserve": plan["recoveryAuthRequestReserve"],
            "releaseRequiresTypedAbsenceAndConfigRestore": True,
        },
    }


def _lock_scopes(plan: dict[str, Any]) -> list[dict[str, str]]:
    return lock_scopes(plan)


def _cost_model() -> dict[str, Any]:
    return {
        "campaignId": CAMPAIGN_ID,
        "basis": "one micro-USD per explicitly charged Gate slot",
        "perRequestMicrousd": 1,
    }


def _refuse_execution(*_args: Any, **_kwargs: Any) -> None:
    raise ValueError("revision-3 Gate dispatch and recovery adapter unavailable")


def _transport_bound(*_args: Any, **_kwargs: Any) -> None:
    raise ValueError("revision-3 production transport adapter unavailable")


def _binding_verifier(*_args: Any, **_kwargs: Any) -> None:
    raise ValueError("revision-3 production worker binding unavailable")


def _retained_artifact_validator(artifact_path, manifest_path, profile):
    artifact = Path(artifact_path)
    manifest = Path(manifest_path)
    if (
        profile != ARTIFACT_PROFILE
        or artifact.is_symlink()
        or manifest.is_symlink()
        or not artifact.is_file()
        or not manifest.is_file()
    ):
        raise ValueError("retained regular revision-3 artifacts required")
    artifact_digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    manifest_digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
    return {
        "artifactSha256": artifact_digest,
        "retainedManifestSha256": manifest_digest,
    }


def _descriptor(plan: dict[str, Any]) -> CampaignDescriptor:
    _require_plan(plan)
    bounds = {
        "campaignId": CAMPAIGN_ID,
        "selector": SELECTOR,
        "caseIds": list(CASES),
        "caseDigest": CASES_SHA256,
        "maxAccounts": MAX_ACCOUNTS,
        "maxAuthRequests": MAX_AUTH_REQUESTS,
        "wallSeconds": WALL_SECONDS,
        "recoverySeconds": RECOVERY_SECONDS,
        "maxObservationSeconds": 1200,
        "requestCounts": {
            "observation": plan["observationRequests"],
            "data": plan["dataRequests"],
            "management": plan["managementRequests"],
            "recoveryAuth": plan["recoveryAuthRequestReserve"],
        },
    }
    return CampaignDescriptor(
        campaign_id=CAMPAIGN_ID,
        frozen_inputs_kind=FROZEN_INPUTS_KIND,
        permission_kind=PERMISSION_KIND,
        approval_kind=APPROVAL_KIND,
        manifest_kind=MANIFEST_KIND,
        artifact_profile=ARTIFACT_PROFILE,
        approval_fields=_APPROVAL_REQUIRED_FIELDS,
        campaign_seconds=WALL_SECONDS,
        recovery_seconds=RECOVERY_SECONDS,
        source_map=source_map,
        abort_closure_sources=_SOURCE_PATHS,
        required_source_entries=(_OWNED_SOURCES[3], _OWNED_SOURCES[4]),
        frozen_bounds=bounds,
        budget=_budget(plan),
        plan_compiler=compile_plan,
        lock_scopes=_lock_scopes,
        collector=_refuse_execution,
        comparator=_refuse_execution,
        cost_model=_cost_model,
        permission_bindings=permission_bindings,
        transport_bound=_transport_bound,
        binding_verifier=_binding_verifier,
        retained_artifact_validator=_retained_artifact_validator,
        forbidden_transports=lambda: ("direct-urllib", "unbound-production-session"),
    )


def descriptor_for_plan(plan: dict[str, Any]) -> CampaignDescriptor:
    """Construct the exact immutable descriptor for a canonical rev3 plan."""
    return _descriptor(plan)


def freeze_inputs(
    descriptor: CampaignDescriptor,
    permission: dict[str, Any],
    plan: dict[str, Any],
    *,
    source_commit: str,
    source_root: str | Path,
    artifact_sha256: str,
) -> dict[str, Any]:
    _require_plan(plan)
    verify_source_snapshot(source_root, source_commit, descriptor.source_map())
    expected = permission_bindings(
        plan,
        source_commit,
        artifact_sha256,
        descriptor.source_map(),
        permission.get("authConfigBaselineDigest"),
        credential_principal=(
            permission.get("credentialContract", {}).get("principal")
            if isinstance(permission.get("credentialContract"), dict)
            else None
        ),
        api_key_project_number=permission.get("apiKeyProjectNumber"),
    )
    if permission != expected:
        raise ValueError("typed owner revision-3 permission binding differs")
    return o8_admission.freeze_inputs(
        descriptor,
        permission,
        plan,
        source_commit=source_commit,
        artifact_sha256=artifact_sha256,
    )


def validate_frozen_inputs(
    inputs: dict[str, Any], descriptor: CampaignDescriptor | None = None
) -> None:
    plan = inputs.get("plan") if isinstance(inputs, dict) else None
    _require_plan(plan)
    descriptor = descriptor or descriptor_for_plan(plan)
    o8_admission.validate_frozen_inputs(descriptor, inputs)
    if inputs.get("sourceInputs") != descriptor.source_map():
        raise ValueError("frozen revision-3 source closure differs")
    permission = inputs["permission"]
    expected = permission_bindings(
        plan,
        inputs["sourceCommit"],
        inputs["artifactSha256"],
        inputs["sourceInputs"],
        permission.get("authConfigBaselineDigest"),
        credential_principal=(
            permission.get("credentialContract", {}).get("principal")
            if isinstance(permission.get("credentialContract"), dict)
            else None
        ),
        api_key_project_number=permission.get("apiKeyProjectNumber"),
    )
    if permission != expected:
        raise ValueError("frozen revision-3 owner permission differs")


def validate_o7_admission(
    *,
    descriptor: CampaignDescriptor,
    inputs: dict[str, Any],
    approval: dict[str, Any],
    manifest: dict[str, Any],
    manifest_bytes: bytes,
    manifest_path: str | Path,
    permission: dict[str, Any],
    ledger_root: str | Path,
    artifact_path: str | Path,
    launcher_path: str | Path,
    source_root: str | Path,
) -> dict[str, Any]:
    """Run the shared complete O7 check set; synthetic fixtures convey no authority."""
    validate_frozen_inputs(inputs, descriptor)
    verify_source_snapshot(source_root, inputs["sourceCommit"], inputs["sourceInputs"])
    return o8_admission.validate_o7_admission(
        descriptor,
        inputs=inputs,
        approval=approval,
        manifest=manifest,
        manifest_bytes=manifest_bytes,
        manifest_path=manifest_path,
        permission=permission,
        ledger_root=ledger_root,
        artifact_path=artifact_path,
        launcher_path=launcher_path,
    )


def reservation_claim(
    inputs: dict[str, Any],
    *,
    gate_path: str | Path,
    gate_plan: dict[str, Any],
    descriptor: CampaignDescriptor,
    source_root: str | Path,
) -> dict[str, Any]:
    """Compile the stable-task Ledger claim without touching a Ledger instance."""
    validate_frozen_inputs(inputs, descriptor)
    verify_source_snapshot(source_root, inputs["sourceCommit"], inputs["sourceInputs"])
    _require_plan(gate_plan)
    if digest(gate_plan) != inputs["planDigest"]:
        raise ValueError("Gate plan differs from frozen O7 plan")
    claim = {
        "campaignId": CAMPAIGN_ID,
        "manifestDigest": inputs["planDigest"],
        "nonceDigest": digest(gate_plan["nonce"]),
        "gatePath": str(Path(gate_path).resolve(strict=False)),
        "gatePlanDigest": digest(gate_plan),
        "gateJob": JOB,
        "locks": lock_scopes(gate_plan),
        "budget": _budget(gate_plan),
        "durationSeconds": WALL_SECONDS,
    }
    reservations._claim(claim)
    return claim
