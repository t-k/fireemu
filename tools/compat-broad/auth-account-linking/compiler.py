"""Compile the bounded, production-disabled account-linking case envelope."""

from __future__ import annotations

import hashlib
import re
from typing import Any

CONTRACT = "auth-settings-v1"
CAMPAIGN = "account-linking-duplicate-email"
CASE_ID = "provider-collision-allow-duplicate-emails"
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
    if sdk != {
        "firebase": sdk.get("firebase"),
        "firebase-admin": sdk.get("firebase-admin"),
    } or any(not isinstance(v, str) for v in sdk.values()):
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
