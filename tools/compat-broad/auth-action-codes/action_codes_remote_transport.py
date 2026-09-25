"""Closed production-wire wrapper for frozen AUTH-ACTION observations.

The preparation collector remains loopback-only. This module accepts only an
O7-frozen plan, an independently maintained dynamic-binding map and a private
credential handoff already verified by the Auth hosting owner. It reuses the
existing credential worker envelope without changing that worker or transport.
The production host remains unavailable in this lane; this wrapper only proves
the six-row request contract through the existing closed credential worker.
"""

from __future__ import annotations

import copy
import urllib.parse
import re
import sys
import time
import urllib.parse
from collections.abc import Mapping
from pathlib import Path
from types import MappingProxyType
from typing import Any, Callable

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "auth-credential-tokens"))

import credential_remote_transport as credential_remote
from action_codes_plan import CAMPAIGN_ID, LOCAL_PROJECT, campaign_manifest
from broad_contract import digest

NONCE = re.compile(r"^[0-9a-f]{32}$")
AUTHORIZED_PROJECT = "fireemu-35fe6"
AUTHORIZED_PROJECT_NUMBER = "592603257417"
EMAIL = re.compile(r"^o1-oob-([0-9a-f]{32})-(?:a|b|absent)@example\.invalid$")
UID = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
SERVICE_PREFIX = "/identitytoolkit.googleapis.com/v1/"
IDENTITY_SCOPE = "https://www.googleapis.com/auth/identitytoolkit"
ENVELOPE_FIELDS = frozenset({"stageId", "project", "nonce", "body", "deadline"})
HANDOFF_FIELDS = frozenset({"token", "apiKey", "permissionDigest", "principal", "scope"})
_BOUND_TRANSPORTS: dict[str, Callable[..., tuple[int, dict[str, Any]]]] = {}
GENERATED_BINDINGS = frozenset({
    "resetCode", "resetCodeSecond", "verifyCode", "emailLinkCode",
    "emailLinkCodeSecond", "deletedUserCode", "accountA.localId", "accountB.localId",
})


def _freeze(value: Any) -> Any:
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    return value


def _private(value: Any) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        and len(value) <= 8192
        and value.isascii()
        and not any(char.isspace() or ord(char) < 33 or ord(char) == 127 for char in value)
    )


def _placeholders(value: Any) -> set[str]:
    if isinstance(value, str) and value.startswith("$binding:"):
        return {value.removeprefix("$binding:")}
    if isinstance(value, dict):
        result: set[str] = set()
        for item in value.values():
            result.update(_placeholders(item))
        return result
    if isinstance(value, list):
        result: set[str] = set()
        for item in value:
            result.update(_placeholders(item))
        return result
    return set()


def _stage(plan: dict | MappingProxyType, stage_id: str):
    for stage in (*plan["stages"], *plan["recovery"]):
        if stage["id"] == stage_id:
            return stage
    raise ValueError("unknown Action stage")


def _canonical_plan(project: str, nonce: str) -> dict[str, Any]:
    return campaign_manifest(nonce, project=project)


def _legacy_canonical_plan(project: str, nonce: str) -> dict[str, Any]:
    plan = campaign_manifest(nonce)
    plan["ownerInputs"]["projectId"] = project
    return plan


def _resource_map(project: str, nonce: str) -> dict[str, dict[str, str]]:
    return {
        name: {"resource": f"projects/{project}/auth/accounts/o1-oob-{nonce}-{suffix}"}
        for name, suffix in (("accountA", "a"), ("accountB", "b"))
    }


def _verified_fixture_origin(value: str) -> str:
    parsed = urllib.parse.urlsplit(value)
    if (
        parsed.scheme != "http"
        or parsed.hostname not in {"127.0.0.1", "::1"}
        or parsed.port is None
        or parsed.port == 0
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("verified loopback fixture origin required")
    return value


def _check_value(expected: Any, actual: Any, bindings: MappingProxyType, nonce: str, observed: dict[str, str]) -> None:
    if isinstance(expected, str) and expected.startswith("$binding:"):
        name = expected.removeprefix("$binding:")
        if name in observed:
            if actual != observed[name]:
                raise ValueError("observed dynamic binding differs")
            return
        if name in GENERATED_BINDINGS:
            marker = "$generated:" + name
            if bindings.get(name) == marker:
                if not _private(actual):
                    raise ValueError("generated dynamic binding required")
            elif name not in bindings or actual != bindings[name]:
                raise ValueError("declared dynamic binding differs")
            return
        if name not in bindings or actual != bindings[name]:
            raise ValueError("declared dynamic binding differs")
        if name.endswith(".email"):
            if not isinstance(actual, str):
                raise ValueError("declared email binding required")
            match = EMAIL.fullmatch(actual)
            if match is None or match.group(1) != nonce:
                raise ValueError("declared email binding differs from nonce")
        return
    if isinstance(expected, Mapping):
        if not isinstance(actual, dict) or set(actual) != set(expected):
            raise ValueError("body shape differs")
        for key, item in expected.items():
            _check_value(item, actual[key], bindings, nonce, observed)
        return
    if isinstance(expected, (list, tuple)):
        if not isinstance(actual, list) or len(actual) != len(expected):
            raise ValueError("body shape differs")
        for left, right in zip(expected, actual, strict=True):
            _check_value(left, right, bindings, nonce, observed)
        return
    if actual != expected or type(actual) is not type(expected):
        raise ValueError("body shape differs")


def _validate_handoff(handoff: dict, permission: dict) -> None:
    if set(handoff) != HANDOFF_FIELDS or any(not _private(handoff[key]) for key in ("token", "apiKey")):
        raise ValueError("private credential handoff required")
    principal = permission.get("credentialPrincipal")
    expected_principal = (
        principal.get("verifiedEmail")
        if isinstance(principal, dict) and "verifiedEmail" in principal
        else principal.get("subject") if isinstance(principal, dict) else None
    )
    if (
        not isinstance(principal, dict)
        or expected_principal != handoff["principal"]
        or principal.get("requiredScopes") != [IDENTITY_SCOPE]
        or handoff["scope"] != IDENTITY_SCOPE
        or handoff["permissionDigest"] != digest(permission)
    ):
        raise ValueError("credential handoff metadata differs")


def _validate_recovery_bindings(
    plan: MappingProxyType,
    bindings: MappingProxyType,
) -> None:
    for account in ("accountA", "accountB"):
        delete_id = "recover-delete-" + account
        absence_id = "recover-uid-absence-" + account
        delete_uid = bindings[delete_id].get(account + ".localId")
        absence_uid = bindings[absence_id].get(account + ".localId")
        if (
            not isinstance(delete_uid, str)
            or not UID.fullmatch(delete_uid)
            or delete_uid != absence_uid
        ):
            raise ValueError("immutable recovery UID binding required")
    for stage_id in ("recover-discover", "recover-absence"):
        expected = {
            "accountA.email",
            "accountB.email",
        }
        if set(bindings[stage_id]) != expected:
            raise ValueError("declared Action recovery binding map differs")


def _validate_inputs(value: dict):
    raw = copy.deepcopy(value)
    if not isinstance(raw, dict) or not isinstance(raw.get("plan"), dict) or not isinstance(raw.get("permission"), dict):
        raise ValueError("frozen Action inputs required")
    unsigned = {key: item for key, item in raw.items() if key != "inputsDigest"}
    if raw.get("inputsDigest") != digest(unsigned):
        raise ValueError("frozen Action inputs digest differs")
    plan = raw["plan"]
    permission = raw["permission"]
    if plan.get("campaignId") != CAMPAIGN_ID or raw.get("planDigest") != digest(plan):
        raise ValueError("frozen Action plan differs")
    project = permission.get("projectId")
    nonce = plan.get("nonce")
    if not isinstance(project, str) or not project or not isinstance(nonce, str) or NONCE.fullmatch(nonce) is None:
        raise ValueError("frozen Action project or nonce required")
    if project not in {LOCAL_PROJECT, AUTHORIZED_PROJECT}:
        raise ValueError("noncanonical Action project refused")
    if raw.get("permissionDigest") != digest(permission):
        raise ValueError("frozen Action permission digest differs")
    if plan not in (_canonical_plan(project, nonce), _legacy_canonical_plan(project, nonce)):
        raise ValueError("frozen Action plan is not the canonical compiler output")
    if permission.get("logicalAccounts") != _resource_map(project, nonce):
        raise ValueError("frozen Action logical account resources differ")
    return raw, plan, _freeze(plan), _freeze(permission), project, nonce


def make_transport(
    *,
    frozen_inputs: dict,
    declared_bindings: dict[str, dict[str, str]],
    credential_handoff: dict,
    verify_handoff: Callable[[dict, dict], None],
    fixture_origin: str | None = None,
    production: bool = False,
):
    """Build the Action transport for either an explicit fixture or production HTTPS."""
    raw, plan, frozen_plan, frozen_permission, project, nonce = _validate_inputs(frozen_inputs)
    if production and fixture_origin is not None:
        raise ValueError("production Action transport cannot use a fixture origin")
    if not production and fixture_origin is None:
        raise ValueError("trusted Action production hosting is unavailable")
    if fixture_origin is not None:
        fixture_origin = _verified_fixture_origin(fixture_origin)
    binding_maps = _freeze(copy.deepcopy(declared_bindings))
    if not isinstance(binding_maps, MappingProxyType):
        raise ValueError("declared Action bindings required")
    handoff = copy.deepcopy(credential_handoff)
    if not callable(verify_handoff):
        raise ValueError("trusted credential handoff verifier required")
    _validate_handoff(handoff, raw["permission"])
    try:
        verify_handoff(copy.deepcopy(handoff), copy.deepcopy(raw["permission"]))
    except Exception as error:  # noqa: BLE001 -- hosting owns verification.
        raise ValueError("credential handoff verification failed") from error
    expected_inputs_digest = raw["inputsDigest"]
    observed: dict[str, str] = {}

    for stage in plan["stages"]:
        stage_bindings = binding_maps.get(stage["id"])
        names = _placeholders(stage["body"])
        if not isinstance(stage_bindings, MappingProxyType) or set(stage_bindings) != names:
            raise ValueError("declared Action binding map differs")
        if any(not _private(value) for value in stage_bindings.values()):
            raise ValueError("declared Action binding value is not private")
    for stage in plan["recovery"]:
        stage_bindings = binding_maps.get(stage["id"])
        names = _placeholders(stage["body"])
        if not isinstance(stage_bindings, MappingProxyType) or set(stage_bindings) != names:
            raise ValueError("declared Action recovery binding map differs")
        if any(not _private(value) for value in stage_bindings.values()):
            raise ValueError("declared Action recovery binding value is not private")
    _validate_recovery_bindings(frozen_plan, binding_maps)

    def transport(value, *, binding, binding_digest, capability):
        if capability.inputs_digest != expected_inputs_digest:
            raise ValueError("production capability frozen inputs differ")
        if fixture_origin is None and isinstance(value, dict) and value.get("fixtureOrigin") is not None:
            raise ValueError("loopback fixture is test-only")
        if not isinstance(value, dict) or set(value) != ENVELOPE_FIELDS:
            raise ValueError("closed Action transport envelope required")
        stage_id, call_project, call_nonce = value["stageId"], value["project"], value["nonce"]
        if call_project != project:
            raise ValueError("project differs from frozen permission")
        if call_nonce != nonce:
            raise ValueError("nonce differs from frozen plan")
        stage = _stage(frozen_plan, stage_id)
        if not isinstance(value["body"], dict):
            raise ValueError("body shape differs")
        _check_value(stage["body"], value["body"], binding_maps[stage_id], nonce, observed)
        path = stage["path"].format(project=project)
        if not path.startswith(SERVICE_PREFIX) or "?" in path:
            raise ValueError("Action route differs")
        declared = {
            "kind": "action-recovery" if stage_id.startswith("recover-") else "action-stage",
            "path": path.lstrip("/"),
            "body": value["body"],
            "owner": stage["routeClass"] == "admin",
        }
        if stage_id.startswith("recover-"):
            account = stage.get("account")
            if account is not None:
                declared["resource"] = frozen_permission["logicalAccounts"][account]["resource"]
        result = credential_remote.transmit(
            declared,
            value["body"],
            token=handoff["token"],
            api_key=handoff["apiKey"],
            deadline=value["deadline"],
            capability=capability,
            binding=binding,
            binding_digest=binding_digest,
            fixture_origin=fixture_origin,
        )
        status, response = result
        if status == 200 and isinstance(response, dict):
            if stage_id == "account-a-create" and isinstance(response.get("localId"), str):
                observed["accountA.localId"] = response["localId"]
            elif stage_id == "account-b-create" and isinstance(response.get("localId"), str):
                observed["accountB.localId"] = response["localId"]
            code_binding = {
                "reset-link-generate": "resetCode",
                "reset-link-generate-second": "resetCodeSecond",
                "verify-link-generate": "verifyCode",
                "email-link-generate": "emailLinkCode",
                "email-link-generate-second": "emailLinkCodeSecond",
                "deleted-user-link-generate": "deletedUserCode",
            }.get(stage_id)
            if code_binding and isinstance(response.get("oobCode"), str):
                observed[code_binding] = response["oobCode"]
        return result

    _BOUND_TRANSPORTS[expected_inputs_digest] = transport
    return transport


def forget_transport(inputs_digest: str) -> None:
    _BOUND_TRANSPORTS.pop(inputs_digest, None)


def _principal_identity(principal: dict) -> tuple[str | None, str | None]:
    if isinstance(principal, dict):
        email = principal.get("verifiedEmail") or principal.get("subject")
        client_id = principal.get("clientId")
        if isinstance(email, str) and isinstance(client_id, str):
            return email, client_id
        return None, None
    return None, None


def _tokeninfo_valid(status, body, *, principal: dict, scope: str, required_seconds: float) -> tuple[bool, int | None]:
    expected_email, expected_client_id = _principal_identity(principal)
    scopes = set(str(body.get("scope", "")).split()) if isinstance(body, dict) else set()
    expires_value = body.get("expires_in") if isinstance(body, dict) else None
    try:
        expires = int(expires_value)
        if isinstance(expires_value, float) and expires != expires_value:
            raise ValueError
    except (TypeError, ValueError, OverflowError):
        expires = None
    valid = (
        status == 200
        and isinstance(body, dict)
        and body.get("email") == expected_email
        and body.get("email_verified") == "true"
        and scope in scopes
        and (
            expected_client_id is None
            or (body.get("azp") == expected_client_id and body.get("aud") == expected_client_id)
        )
        and type(expires) in (int, float)
        and expires >= required_seconds
    )
    return valid, expires


def management_receipt(*, slot_id, deadline, capability, binding, binding_digest, handoff, permission, required_seconds, fixture_origin=None):
    """Run one Action-specific live authority check through the pinned worker."""

    def config_project_id(body: Any) -> str | None:
        """Extract a project identity from an Auth Config response."""
        project_number = globals().get("AUTHORIZED_PROJECT_NUMBER", "592603257417")
        authorized_names = {AUTHORIZED_PROJECT, project_number}

        def canonical_name(value: str) -> str:
            return AUTHORIZED_PROJECT if value in authorized_names else value

        if not isinstance(body, dict):
            return None
        if "name" in body:
            name = body["name"]
            if not isinstance(name, str):
                return None
            parts = name.split("/")
            if (
                len(parts) != 3
                or parts[0] != "projects"
                or not parts[1]
                or parts[2] != "config"
            ):
                return None
            project_id = parts[1]
            declared_project_id = body.get("projectId")
            if not isinstance(declared_project_id, (str, type(None))):
                return None
            if (
                declared_project_id is not None
                and canonical_name(declared_project_id) != canonical_name(project_id)
            ):
                return None
            return canonical_name(project_id)
        if set(body) != {"projectId"}:
            return None
        project_id = body.get("projectId")
        return AUTHORIZED_PROJECT if project_id == AUTHORIZED_PROJECT else None

    credential_remote.authorize_transport(capability, binding=binding, binding_digest=binding_digest)
    credential_remote.verify_worker_binding(binding, binding_digest, None)
    token = handoff.get("token")
    if slot_id == "oauth-tokeninfo":
        base = fixture_origin.rstrip("/") if fixture_origin is not None else "https://oauth2.googleapis.com"
        url = base + "/tokeninfo?access_token=" + urllib.parse.quote(token, safe="")
        exchange = credential_remote.request_with_lifecycle(
            url,
            None,
            headers={},
            seconds=credential_remote._seconds(deadline),
            fixture_origin=fixture_origin,
        )
        status, body = exchange.status, exchange.body
        principal = permission["credentialPrincipal"]
        expected_email, expected_client_id = _principal_identity(principal)
        if expected_email is None or expected_client_id is None:
            raise ValueError("verified-email credential principal required")
        scope = principal["requiredScopes"][0]
        scopes = set(str(body.get("scope", "")).split()) if isinstance(body, dict) else set()
        valid, expires = _tokeninfo_valid(
            status, body, principal=principal, scope=scope, required_seconds=required_seconds
        )
        attestation = {
            "kind": "request-byte-token-attestation-v1",
            "principalDigest": digest(principal),
            "requiredScopeVerified": scope in scopes,
            "identityMode": "verified-email",
            "identityVerified": body.get("email") == expected_email if isinstance(body, dict) else False,
            "oauthClientVerified": (
                isinstance(body, dict)
                and body.get("azp") == expected_client_id
                and body.get("aud") == expected_client_id
            ),
            "expiresInSeconds": expires if type(expires) in (int, float) else 0,
            "remainingSecondsAtVerification": expires if type(expires) in (int, float) else 0,
            "requiredSeconds": required_seconds,
            "complete": valid,
            "workerReaped": exchange.worker_reaped,
        }
        return {"status": status, "complete": valid and exchange.worker_reaped, "workerReaped": exchange.worker_reaped, "bodyKind": "json", "body": attestation}
    if slot_id == "auth-project-readback":
        base = fixture_origin.rstrip("/") if fixture_origin is not None else "https://identitytoolkit.googleapis.com"
        url = base + "/admin/v2/projects/" + AUTHORIZED_PROJECT + "/config"
        exchange = credential_remote.request_with_lifecycle(
            url,
            None,
            headers={"Authorization": "Bearer " + token, "x-goog-user-project": AUTHORIZED_PROJECT},
            seconds=credential_remote._seconds(deadline),
            fixture_origin=fixture_origin,
        )
        status, body = exchange.status, exchange.body
        project_id = config_project_id(body)
        valid = status == 200 and project_id == AUTHORIZED_PROJECT
        return {
            "status": status,
            "complete": valid,
            "workerReaped": exchange.worker_reaped,
            "bodyKind": "json",
            "body": {"kind": "auth-project-readback-v1", "projectId": project_id, "authorized": valid},
        }
    raise ValueError("unknown Action management slot")


def send(
    capability,
    *,
    stage_id: str,
    project: str,
    nonce: str,
    body: dict[str, Any],
    deadline: float,
    binding: bytes,
    binding_digest: str,
    inputs_digest: str | None = None,
    token: str | None = None,
    api_key: str | None = None,
    fixture_origin: str | None = None,
) -> tuple[int, dict[str, Any]]:
    """Send one ordinary observation through one consumed O8 capability."""
    if not hasattr(capability, "_transmit"):
        raise ValueError("O8 capability required")
    if binding != capability._binding or binding_digest != capability.binding_digest:
        raise ValueError("production capability binding differs")
    envelope = {
            "stageId": stage_id,
            "project": project,
            "nonce": nonce,
            "body": body,
            "deadline": deadline,
    }
    if token is not None or api_key is not None or fixture_origin is not None:
        if not all(isinstance(value, str) and value for value in (token, api_key, fixture_origin)):
            raise ValueError("closed Action credential envelope required")
        envelope.update(token=token, apiKey=api_key, fixtureOrigin=fixture_origin)
    if inputs_digest is not None:
        if not isinstance(inputs_digest, str) or not inputs_digest:
            raise ValueError("frozen Action inputs digest required")
        envelope["inputsDigest"] = inputs_digest
    return capability._transmit(envelope)


def _transmit_bound(capability, value, *, binding, binding_digest):
    """Adapt the O8 envelope to the existing bounded credential worker."""
    if not isinstance(value, dict) or not isinstance(value.get("inputsDigest"), str):
        raise ValueError("closed Action credential envelope required")
    transport = _BOUND_TRANSPORTS.get(value["inputsDigest"])
    if transport is None:
        raise ValueError("issuer-owned Action transport context required")
    forwarded = dict(value)
    forwarded.pop("inputsDigest")
    return transport(forwarded, binding=binding, binding_digest=binding_digest, capability=capability)


__all__ = ["CAMPAIGN_ID", "IDENTITY_SCOPE", "make_transport", "send"]
