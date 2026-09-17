"""Compile the bounded, production-disabled account-linking case envelope."""

from __future__ import annotations

import hashlib
import re
from typing import Any

CONTRACT = "auth-settings-v1"
CAMPAIGN = "auth-settings-sdk-next-v10"
CASE_ID = "provider-collision-allow-duplicate-emails"
SDK_PINS = {"firebase": "12.18.0", "firebase-admin": "14.3.0"}
BOUNDS = {
    "concurrency": 1,
    "requestRate": 1,
    "elapsedSeconds": 90,
    "httpCredentialOperations": 12,
    "resources": 2,
    "accounts": 2,
    "documents": 0,
    "campaignElapsedSeconds": 180,
    "campaignHttpCredentialOperations": 40,
    "campaignResources": 8,
    "campaignAccounts": 8,
    "costMicrousd": 10_000_000,
}


def _sha(value: str, name: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise ValueError(f"{name} must be a SHA-256 digest")
    return value


def compile_case(project: str, tenant: str | None, nonce: str) -> dict[str, Any]:
    """Return a closed plan; nonce material is immediately reduced to a digest."""
    if (
        not isinstance(project, str)
        or re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", project) is None
    ):
        raise ValueError("project namespace is invalid")
    if tenant is not None and (
        not isinstance(tenant, str)
        or re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", tenant) is None
    ):
        raise ValueError("tenant namespace is invalid")
    if not isinstance(nonce, str) or len(nonce) < 16 or len(nonce) > 256:
        raise ValueError("fresh opaque nonce is required")
    nonce_digest = hashlib.sha256(nonce.encode()).hexdigest()
    namespace = {"projectId": project, "tenantId": tenant}
    operations = [
        {"id": "configuration-read", "phase": "setup", "mutation": False},
        {"id": "signup-a", "phase": "setup", "mutation": True},
        {"id": "signup-b", "phase": "setup", "mutation": True},
        {"id": "same-provider-signin", "phase": "control", "mutation": False},
        {"id": "password-signin-b", "phase": "control", "mutation": False},
        {"id": "provider-collision", "phase": "collision", "mutation": True},
        {"id": "readback-a", "phase": "readback", "mutation": False},
        {"id": "readback-b", "phase": "readback", "mutation": False},
        {"id": "delete-a", "phase": "cleanup", "mutation": True},
        {"id": "delete-b", "phase": "cleanup", "mutation": True},
        {"id": "absence-a", "phase": "cleanup", "mutation": False},
        {"id": "absence-b", "phase": "cleanup", "mutation": False},
    ]
    return {
        "contract": CONTRACT,
        "campaign": CAMPAIGN,
        "slice": "account-linking-duplicate-email",
        "caseId": CASE_ID,
        "status": "PREPARATION",
        "productionExecuted": False,
        "namespace": namespace,
        "nonceDigest": nonce_digest,
        "operations": operations,
        "bounds": BOUNDS.copy(),
        "provider": {
            "providerId": "google.com",
            "boundary": "owner-controlled-prerequisite",
        },
        "expectedProduction": None,
    }


def compile_manifest(
    plan: dict[str, Any],
    *,
    artifact_sha256: str,
    source_commit: str,
    sdk: dict[str, str],
    configuration_digest: str,
) -> dict[str, Any]:
    validate_plan(plan)
    if (
        plan.get("status") != "PREPARATION"
        or plan.get("productionExecuted") is not False
    ):
        raise ValueError("only production-disabled preparation plans are admissible")
    _sha(artifact_sha256, "artifact_sha256")
    if (
        not isinstance(source_commit, str)
        or re.fullmatch(r"[0-9a-f]{40}", source_commit) is None
    ):
        raise ValueError("source commit must be a full SHA-1")
    if sdk != SDK_PINS:
        raise ValueError("closed SDK pins are required")
    _sha(configuration_digest, "configuration_digest")
    return {
        "contract": CONTRACT,
        "campaign": CAMPAIGN,
        "caseId": CASE_ID,
        "status": "PREPARATION",
        "productionExecuted": False,
        "plan": plan,
        "artifactSha256": artifact_sha256,
        "sourceCommit": source_commit,
        "sdk": dict(sdk),
        "configurationDigest": configuration_digest,
        "nonceDigest": plan["nonceDigest"],
        "ownerBinding": None,
        "cleanup": {"required": True, "complete": False},
    }


def validate_manifest(manifest: Any) -> None:
    required = {
        "contract",
        "campaign",
        "caseId",
        "status",
        "productionExecuted",
        "plan",
        "artifactSha256",
        "sourceCommit",
        "sdk",
        "configurationDigest",
        "nonceDigest",
        "ownerBinding",
        "cleanup",
    }
    if not isinstance(manifest, dict) or set(manifest) != required:
        raise ValueError("manifest binding mismatch")
    if (
        manifest["contract"] != CONTRACT
        or manifest["campaign"] != CAMPAIGN
        or manifest["caseId"] != CASE_ID
        or manifest["status"] != "PREPARATION"
        or manifest["productionExecuted"] is not False
        or manifest["ownerBinding"] is not None
    ):
        raise ValueError("manifest must remain preparation-only")
    validate_plan(manifest["plan"])
    _sha(manifest["artifactSha256"], "artifactSha256")
    if re.fullmatch(r"[0-9a-f]{40}", manifest["sourceCommit"]) is None:
        raise ValueError("source commit must be a full SHA-1")
    if manifest["sdk"] != SDK_PINS:
        raise ValueError("SDK pins differ from reviewed versions")
    _sha(manifest["configurationDigest"], "configurationDigest")
    if manifest["nonceDigest"] != manifest["plan"]["nonceDigest"]:
        raise ValueError("manifest nonce binding mismatch")
    if manifest["cleanup"] != {"required": True, "complete": False}:
        raise ValueError("preparation cleanup state mismatch")


def validate_plan(plan: Any) -> None:
    required = {
        "contract",
        "campaign",
        "slice",
        "caseId",
        "status",
        "productionExecuted",
        "namespace",
        "nonceDigest",
        "operations",
        "bounds",
        "provider",
        "expectedProduction",
    }
    if not isinstance(plan, dict) or set(plan) != required:
        raise ValueError("plan binding mismatch")
    if (
        plan["contract"] != CONTRACT
        or plan["campaign"] != CAMPAIGN
        or plan["slice"] != "account-linking-duplicate-email"
        or plan["caseId"] != CASE_ID
        or plan["status"] != "PREPARATION"
        or plan["productionExecuted"] is not False
        or plan["expectedProduction"] is not None
    ):
        raise ValueError("plan must remain production-disabled preparation")
    namespace = plan["namespace"]
    if (
        not isinstance(namespace, dict)
        or set(namespace) != {"projectId", "tenantId"}
        or not isinstance(namespace["projectId"], str)
    ):
        raise ValueError("namespace binding missing")
    _sha(plan["nonceDigest"], "nonceDigest")
    if plan["bounds"] != BOUNDS:
        raise ValueError("bounded envelope mismatch")
    if plan["provider"] != {
        "providerId": "google.com",
        "boundary": "owner-controlled-prerequisite",
    }:
        raise ValueError("provider boundary mismatch")
    expected_ids = [
        "configuration-read",
        "signup-a",
        "signup-b",
        "same-provider-signin",
        "password-signin-b",
        "provider-collision",
        "readback-a",
        "readback-b",
        "delete-a",
        "delete-b",
        "absence-a",
        "absence-b",
    ]
    operations = plan["operations"]
    if not isinstance(operations, list) or len(operations) != len(expected_ids):
        raise ValueError("fixed operation sequence required")
    if [
        row.get("id") if isinstance(row, dict) else None for row in operations
    ] != expected_ids:
        raise ValueError("operation sequence binding mismatch")
    if any(
        not isinstance(row, dict)
        or set(row) != {"id", "phase", "mutation"}
        or type(row["mutation"]) is not bool
        for row in operations
    ):
        raise ValueError("operation shape mismatch")
