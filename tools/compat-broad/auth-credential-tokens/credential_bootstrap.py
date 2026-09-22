"""Four-request, keyless Auth credential bootstrap.

This module is preparation only. It does not issue O7, reserve the canonical
Ledger, or approve the observation campaign. The caller must supply an
independently approved preparation permission and a private authorized-user
descriptor; secrets stay in memory and the returned handoff is for a later
observation permission whose digest is not created here.
"""

from __future__ import annotations

import copy
import hashlib
import math
import sys
import time
from dataclasses import dataclass
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE.parent / "fs-write-txn"))

from broad_contract import digest
import credential_remote_transport as remote
import credential_gate as gate_module

PROJECT = "fireemu-35fe6"
PROJECT_NUMBER = "592603257417"
SERVICE_ACCOUNT = "fireemu-oracle@fireemu-35fe6.iam.gserviceaccount.com"
SCOPE = "https://www.googleapis.com/auth/cloud-platform"
PERMISSION_KIND = "auth-credential-bootstrap-permission-v1"
HANDOFF_KIND = "auth-credential-handoff-v1"
ADC_FIELDS = frozenset({"type", "client_id", "client_secret", "refresh_token"})
PREP_REQUEST_SECONDS = 5.0
PREP_REQUESTS = 4
TASK_MAX_REQUESTS = 60
TASK_MAX_SECONDS = 600
TASK_MAX_COST_MICROUSD = 50_000
RECOVERY_SECONDS = 60
MIN_TASK_REQUESTS = 53

@dataclass(frozen=True)
class BootstrapBudget:
    max_requests: int = TASK_MAX_REQUESTS
    max_seconds: int = TASK_MAX_SECONDS
    cost_microusd: int = TASK_MAX_COST_MICROUSD

    def validate(self) -> None:
        if (
            self.max_requests < MIN_TASK_REQUESTS
            or self.max_requests > TASK_MAX_REQUESTS
            or self.max_seconds <= RECOVERY_SECONDS
            or self.max_seconds > TASK_MAX_SECONDS
            or self.cost_microusd <= 0
            or self.cost_microusd > TASK_MAX_COST_MICROUSD
        ):
            raise ValueError("bootstrap budget differs")


@dataclass(frozen=True)
class BootstrapResult:
    prepared: dict
    proof: dict
    charged_requests: int


def validate_deadline(seconds: float) -> None:
    if type(seconds) not in (int, float) or isinstance(seconds, bool) or not math.isfinite(seconds) or seconds <= PREP_REQUEST_SECONDS:
        raise ValueError("bootstrap deadline must cover four bounded requests")


def _validate_permission(permission: dict, adc: dict) -> None:
    if not isinstance(permission, dict) or permission.get("kind") != PERMISSION_KIND:
        raise ValueError("bootstrap permission required")
    principal = permission.get("credentialPrincipal")
    if not isinstance(principal, dict) or set(principal) != {"clientId", "subject", "requiredScopes"}:
        raise ValueError("bootstrap principal required")
    if not isinstance(principal["clientId"], str) or not principal["clientId"] or principal["requiredScopes"] != [SCOPE]:
        raise ValueError("bootstrap principal required")
    if principal["clientId"] != adc.get("client_id"):
        raise ValueError("bootstrap principal differs")
    if permission.get("project") != PROJECT or permission.get("projectNumber") != PROJECT_NUMBER:
        raise ValueError("bootstrap project differs")
    if permission.get("authorizedUserDigest") != digest(adc):
        raise ValueError("authorized-user binding differs")


def _validate_handoff_input(permission: dict, adc: dict) -> None:
    if not isinstance(adc, dict) or set(adc) != ADC_FIELDS or adc.get("type") != "authorized_user":
        raise ValueError("private bootstrap input required")
    if permission.get("authorizedUserDigest") != digest(adc):
        raise ValueError("private bootstrap input required")


def _origin_url(host: str, path: str, fixture_origin: str | None) -> str:
    return (fixture_origin + "/" if fixture_origin is not None else "https://") + host + path


def _request(slot: str, secret, *, fixture_origin: str | None, deadline: float | None = None):
    seconds = PREP_REQUEST_SECONDS if deadline is None else min(
        PREP_REQUEST_SECONDS, max(0.001, deadline - time.monotonic())
    )
    if slot == "refresh":
        status, body = remote.request(
            _origin_url("oauth2.googleapis.com", "/token", fixture_origin),
            {"grant_type": "refresh_token", "client_id": secret["client_id"], "client_secret": secret["client_secret"], "refresh_token": secret["refresh_token"]},
            headers={}, seconds=seconds, form=True, fixture_origin=fixture_origin,
        )
        return status, body
    if slot == "tokeninfo":
        return remote.request(
            _origin_url("oauth2.googleapis.com", "/tokeninfo?access_token=" + secret, fixture_origin),
            None, headers={}, seconds=seconds, fixture_origin=fixture_origin,
        )
    if slot == "project":
        return remote.request(
            _origin_url("cloudresourcemanager.googleapis.com", "/v1/projects/" + PROJECT, fixture_origin),
            None,
            headers={"Authorization": "Bearer " + secret, "x-goog-user-project": PROJECT},
            seconds=seconds,
            fixture_origin=fixture_origin,
        )
    return remote.request(
        _origin_url("identitytoolkit.googleapis.com", "/admin/v2/projects/" + PROJECT + "/config", fixture_origin),
        None,
        headers={"Authorization": "Bearer " + secret, "x-goog-user-project": PROJECT},
        seconds=seconds,
        fixture_origin=fixture_origin,
    )


def prepare(permission: dict, *, adc: dict, api_key: str, fixture_origin: str | None = None, budget: BootstrapBudget | None = None, gate=None) -> BootstrapResult:
    """Run exactly refresh, tokeninfo, project and Auth-config operations.

    `fixture_origin` is test-only; production leaves it unset so the pinned
    transport enforces its reviewed HTTPS allowlist. This function intentionally
    returns private prepared values and typed proof, not a finalized handoff or O7 capability.
    """
    budget = budget or BootstrapBudget()
    budget.validate()
    validate_deadline(budget.max_seconds - RECOVERY_SECONDS)
    _validate_permission(permission, adc)
    _validate_handoff_input(permission, adc)
    if not isinstance(api_key, str) or not api_key:
        raise ValueError("private Web API key required")
    if gate is not None:
        snapshot = gate.snapshot()
        bootstrap = snapshot.get("plan", {}).get("bootstrap")
        if not isinstance(bootstrap, dict) or bootstrap.get("permissionDigest") != digest(permission):
            raise ValueError("bootstrap Gate permission binding differs")
        if tuple(bootstrap.get("operationIds", ())) != gate_module.bootstrap_management_ids():
            raise ValueError("bootstrap Gate operation binding differs")

    def dispatch(slot: str, secret):
        request_slot = {
            "bootstrap-refresh": "refresh",
            "bootstrap-tokeninfo": "tokeninfo",
            "bootstrap-project": "project",
            "bootstrap-auth-config": "auth",
        }[slot]
        if gate is None:
            return _request(request_slot, secret, fixture_origin=fixture_origin)

        def send(deadline):
            status_, body_ = _request(request_slot, secret, fixture_origin=fixture_origin, deadline=deadline)
            return {"status": status_, "complete": status_ == 200, "workerReaped": True, "bodyKind": "json", "body": body_}

        receipt = gate.management_dispatch("observation", slot, send)
        return receipt.get("status"), receipt.get("body")

    status, refresh = dispatch("bootstrap-refresh", adc)
    if status != 200 or not isinstance(refresh, dict) or not isinstance(refresh.get("access_token"), str):
        raise ValueError("OAuth refresh refused")
    token = refresh["access_token"]
    status, tokeninfo = dispatch("bootstrap-tokeninfo", token)
    if status != 200 or not isinstance(tokeninfo, dict):
        raise ValueError("tokeninfo refused")
    principal = permission["credentialPrincipal"]
    expires_in = tokeninfo.get("expires_in")
    if isinstance(expires_in, str) and expires_in.isdecimal():
        expires_in = int(expires_in)
    if tokeninfo.get("azp") != principal["clientId"] or tokeninfo.get("aud") != principal["clientId"] or tokeninfo.get("sub") != principal["subject"] or SCOPE not in str(tokeninfo.get("scope", "")).split() or type(expires_in) is not int or expires_in <= TASK_MAX_SECONDS:
        raise ValueError("tokeninfo principal or lifetime differs")
    status, project = dispatch("bootstrap-project", token)
    if status != 200 or project != {"projectId": PROJECT, "projectNumber": PROJECT_NUMBER}:
        raise ValueError("project identity differs")
    status, auth = dispatch("bootstrap-auth-config", token)
    if status != 200 or not isinstance(auth, dict):
        raise ValueError("Auth config readback refused")
    proof = {"kind": "auth-credential-bootstrap-proof-v1", "permissionDigest": digest(permission), "principalDigest": digest(principal), "project": copy.deepcopy(project), "authConfigDigest": digest(auth), "tokeninfoExpiresInSeconds": expires_in, "requestCount": PREP_REQUESTS, "taskMaxRequests": TASK_MAX_REQUESTS, "taskMaxSeconds": TASK_MAX_SECONDS, "recoverySeconds": RECOVERY_SECONDS}
    if gate is not None:
        snapshot = gate.snapshot()
        used = snapshot.get("managementUsed", [])
        expected = ["observation:" + item for item in gate_module.bootstrap_management_ids()]
        if used[:PREP_REQUESTS] != expected:
            raise ValueError("bootstrap Gate completion differs")
        proof["gatePlanDigest"] = snapshot["planDigest"]
        proof["managementJournalDigest"] = digest(snapshot.get("managementEvents", [])[:PREP_REQUESTS])
    return BootstrapResult({"token": token, "apiKey": api_key, "signing": {"serviceAccount": SERVICE_ACCOUNT}}, proof, PREP_REQUESTS)


def finalize_handoff(prepared: dict, observation_permission_digest: str, proof: dict) -> dict:
    """Bind the private prepared values only after observation permission exists."""
    if not isinstance(observation_permission_digest, str) or len(observation_permission_digest) != 64:
        raise ValueError("observation permission digest required")
    if not isinstance(prepared, dict) or set(prepared) != {"token", "apiKey", "signing"}:
        raise ValueError("prepared credential required")
    if (
        not isinstance(proof, dict)
        or proof.get("kind") != "auth-credential-bootstrap-proof-v1"
        or proof.get("requestCount") != PREP_REQUESTS
        or proof.get("taskMaxRequests") != TASK_MAX_REQUESTS
        or proof.get("taskMaxSeconds") != TASK_MAX_SECONDS
        or proof.get("recoverySeconds") != RECOVERY_SECONDS
    ):
        raise ValueError("independent bootstrap proof required")
    return {"kind": HANDOFF_KIND, "permissionDigest": observation_permission_digest, **copy.deepcopy(prepared)}


__all__ = ["BootstrapBudget", "BootstrapResult", "HANDOFF_KIND", "PERMISSION_KIND", "PREP_REQUESTS", "SCOPE", "SERVICE_ACCOUNT", "finalize_handoff", "prepare", "validate_deadline"]
