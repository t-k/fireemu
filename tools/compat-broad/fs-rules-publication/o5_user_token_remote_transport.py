"""Closed, plan-bound O5 transport boundary.

Ruleset and Release names are server-issued values.  This module only turns a
producer-issued, fully-qualified name into a request; it never treats a local
label or caller map as authority.
"""

from __future__ import annotations

import copy
import hashlib
import json
import math
import os
import re
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "o8-core"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from broad_contract import digest
from o5_user_token_identity_proof import IdentityProof
from o8_admission import authorize_transport

CAMPAIGN = "FS-RULES-USER-TOKEN-MATRIX-01"
PROJECT = "fireemu-35fe6"
DATABASE = "(default)"
LANE_DIRECTORY = "tools/compat-broad/fs-rules-publication"
WORKER_ENTRY = f"{LANE_DIRECTORY}/o5_user_token_https_worker.py"
FIRESTORE_ORIGIN = "https://firestore.googleapis.com"
IDENTITY_ORIGIN = "https://identitytoolkit.googleapis.com"
RULES_ORIGIN = "https://firebaserules.googleapis.com"
MAX_SECONDS = 8.0
_REAP_RESERVE_SECONDS = 0.5
MAX_ENVELOPE_BYTES = 1_048_576
MAX_OUTPUT_BYTES = 2 * 1024 * 1024
_NONCE = re.compile(r"^[0-9a-f]{32}$")
_TENANT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{3,35}$")
_DOCUMENT = re.compile(
    r"^projects/([a-z][a-z0-9-]{4,28}[a-z0-9])/databases/\(default\)/documents/"
    r"o5-user-token/n([0-9a-f]{32})/cases/([A-Za-z0-9_-]{1,128})$"
)
_RULESET_NAME = re.compile(
    r"^projects/fireemu-35fe6/rulesets/[A-Za-z0-9_-]{1,128}$"
)
_RELEASE_NAME = re.compile(
    r"^projects/fireemu-35fe6/releases/[A-Za-z0-9_.-]{1,128}$"
)
_WORKER_SHA256 = "437c7c9fb1796dca76bd0d81b4d50c690709bc219b05917b238a14461ff9e586"
_OWNED_CHILDREN: set[int] = set()


class WorkerExchangeError(ValueError):
    """A bounded worker failure with explicit process-reap status."""

    def __init__(self, reason: str, *, worker_reaped: bool) -> None:
        super().__init__(reason)
        self.worker_reaped = worker_reaped


@dataclass(frozen=True)
class SetupPublicReceipt:
    """Serializable setup provenance with all credential material removed."""

    item_id: str
    http_status: int
    endpoint: str
    wire_sequence: int
    local_id: str | None = None
    name: str | None = None
    fields_digest: str | None = None
    update_time: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            key: value
            for key, value in {
                "id": self.item_id,
                "httpStatus": self.http_status,
                "endpoint": self.endpoint,
                "wireSequence": self.wire_sequence,
                "localId": self.local_id,
                "name": self.name,
                "fieldsDigest": self.fields_digest,
                "updateTime": self.update_time,
            }.items()
            if value is not None
        }


class SetupPrivateHandoff:
    """Transient credential handoff; never use this object as a receipt."""

    __slots__ = ("_id_token", "_expires_in")

    def __init__(self, *, id_token: str | None = None, expires_in: str | None = None):
        self._id_token = id_token
        self._expires_in = expires_in

    def __repr__(self) -> str:
        return "SetupPrivateHandoff(<redacted>)"

    def token_for_followup(self) -> str | None:
        return self._id_token

    def expires_in_for_followup(self) -> str | None:
        return self._expires_in


class SetupResult:
    __slots__ = ("receipt", "private")

    def __init__(self, *, receipt: SetupPublicReceipt, private: SetupPrivateHandoff):
        self.receipt = receipt
        self.private = private

    def __repr__(self) -> str:
        return f"SetupResult(receipt={self.receipt!r}, private=<redacted>)"


def _reap_owned(
    child: subprocess.Popen[bytes], *, deadline: float | None = None
) -> bool:
    """Terminate only the process group this transport created."""
    if child.pid not in _OWNED_CHILDREN:
        return False

    def group_exists() -> bool:
        try:
            os.killpg(child.pid, 0)
            return True
        except ProcessLookupError:
            return False
        except OSError:
            return True

    if not group_exists():
        return child.poll() is not None
    def remaining() -> float | None:
        if deadline is None:
            return None
        return max(0.0, deadline - time.monotonic())

    def wait_for_child() -> bool:
        timeout = remaining()
        if timeout is None:
            child.wait(timeout=0.5)
        elif timeout > 0:
            child.wait(timeout=timeout)
        else:
            child.wait(timeout=0)
        return not group_exists()

    try:
        os.killpg(child.pid, signal.SIGTERM)
        return wait_for_child()
    except subprocess.TimeoutExpired:
        try:
            os.killpg(child.pid, signal.SIGKILL)
            return wait_for_child()
        except (OSError, subprocess.TimeoutExpired):
            return False
    except (OSError, ProcessLookupError):
        return child.poll() is not None and not group_exists()


def _compact(value: Any) -> bytes:
    return json.dumps(
        value, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode()


def worker_binding() -> tuple[bytes, str]:
    source = Path(__file__).with_name("o5_user_token_https_worker.py").read_bytes()
    return source, hashlib.sha256(source).hexdigest()


def verify_worker_binding(binding: Any, binding_digest: Any, frozen: Any) -> None:
    if not isinstance(binding, bytes) or not binding:
        raise ValueError("reviewed worker source required")
    observed = hashlib.sha256(binding).hexdigest()
    if observed != binding_digest or observed != _WORKER_SHA256:
        raise ValueError("worker source digest differs from reviewed transport")
    if frozen is not None and frozen.get(WORKER_ENTRY) != observed:
        raise ValueError("worker source digest differs from frozen inputs")


def _plan_identity(plan: dict[str, Any]) -> tuple[str, str]:
    if not isinstance(plan, dict) or plan.get("campaignId") != CAMPAIGN:
        raise ValueError("campaign identity required")
    if plan.get("project") != PROJECT or plan.get("database") != DATABASE:
        raise ValueError("project binding differs")
    nonce, tenant = plan.get("nonce"), plan.get("tenant")
    if not isinstance(nonce, str) or _NONCE.fullmatch(nonce) is None:
        raise ValueError("nonce binding required")
    if not isinstance(tenant, str) or _TENANT.fullmatch(tenant) is None:
        raise ValueError("tenant binding required")
    return nonce, tenant


def _frozen_inputs(plan: dict[str, Any], frozen: Any) -> dict[str, Any]:
    if not isinstance(frozen, dict) or not isinstance(frozen.get("plan"), dict):
        raise ValueError("complete frozen inputs required")  # noqa: TRY004
    snapshot = copy.deepcopy(frozen)
    if snapshot["plan"] != plan:
        raise ValueError("frozen plan differs")
    if snapshot.get("planDigest") != digest(snapshot["plan"]):
        raise ValueError("frozen plan digest differs")
    supplied = snapshot.pop("inputsDigest", None)
    if not isinstance(supplied, str) or supplied != digest(snapshot):
        raise ValueError("frozen inputs digest differs")
    snapshot["inputsDigest"] = supplied
    return snapshot


def _credential(
    credentials: dict[str, Any],
    reference: str,
    credential_class: str,
    identity_proofs: dict[str, IdentityProof] | None = None,
) -> str | None:
    if credential_class == "absent":
        return None
    value = credentials.get(reference)
    if (
        not isinstance(value, str)
        or len(value) > 8192
        or any(char.isspace() for char in value)
    ):
        raise ValueError("bounded credential required")
    if credential_class != "empty" and not value:
        raise ValueError("bounded credential required")
    if (
        credential_class == "user-id-token"
        and identity_proofs is not None
        and "expired" not in reference
    ):
        proof = identity_proofs.get(reference)
        if (
            not isinstance(proof, IdentityProof)
            or not proof.trusted()
            or proof.token != value
        ):
            raise ValueError("trusted identity proof required")
    return value


def _resource(path: Any, *, nonce: str) -> str:
    if not isinstance(path, str):
        raise ValueError("resource path required")  # noqa: TRY004
    match = _DOCUMENT.fullmatch(path)
    if match is None:
        raise ValueError("resource path binding differs")
    if match.group(1) != PROJECT:
        raise ValueError("project binding differs")
    if match.group(2) != nonce:
        raise ValueError("nonce binding differs")
    return "/v1/" + path


def _headers(token: str | None) -> dict[str, str]:
    headers = {"x-goog-user-project": PROJECT}
    if token is not None:
        headers["Authorization"] = "Bearer " + token
    return headers


def _typed(value: Any, account_bindings: dict[str, Any] | None) -> dict[str, Any]:
    if isinstance(value, dict) and set(value) == {"$principal"}:
        ref = value["$principal"]
        bound = (account_bindings or {}).get(ref)
        if not isinstance(bound, dict) or not isinstance(bound.get("uid"), str):
            raise ValueError("principal UID binding required")
        value = bound["uid"]
    if value is None:
        return {"nullValue": None}
    if isinstance(value, bool):
        return {"booleanValue": value}
    if isinstance(value, int) and not isinstance(value, bool):
        return {"integerValue": str(value)}
    if isinstance(value, float):
        return {"doubleValue": value}
    if isinstance(value, str):
        return {"stringValue": value}
    if isinstance(value, dict):
        return {
            "mapValue": {
                "fields": {
                    key: _typed(nested, account_bindings)
                    for key, nested in value.items()
                }
            }
        }
    if isinstance(value, list):
        return {
            "arrayValue": {
                "values": [_typed(nested, account_bindings) for nested in value]
            }
        }
    raise ValueError("unsupported Firestore field")


def _has_principal(value: Any) -> bool:
    if isinstance(value, dict):
        return (set(value) == {"$principal"}) or any(
            _has_principal(item) for item in value.values()
        )
    if isinstance(value, list):
        return any(_has_principal(item) for item in value)
    return False


def _write_resource(document: Any, plan: dict[str, Any]) -> str:
    if not isinstance(document, str):
        raise ValueError("write document required")  # noqa: TRY004
    for resource in plan.get("ownedResources", []):
        if isinstance(resource, str) and resource.endswith("/cases/" + document):
            return resource
    raise ValueError("write document outside owned namespace")


def _commit_writes(
    plan: dict[str, Any], writes: list[Any], account_bindings: dict[str, Any] | None
) -> list[dict[str, Any]]:
    converted = []
    for write in writes:
        if not isinstance(write, dict) or set(write) != {
            "document",
            "operation",
            "fields",
        }:
            raise ValueError("pseudo-write shape refused")
        operation = write["operation"]
        fields = write["fields"]
        if operation not in {"create", "update"} or not isinstance(fields, dict):
            raise ValueError("pseudo-write operation refused")
        entry: dict[str, Any] = {
            "update": {
                "name": _write_resource(write["document"], plan),
                "fields": {
                    key: _typed(value, account_bindings)
                    for key, value in fields.items()
                },
            }
        }
        if operation == "create":
            entry["currentDocument"] = {"exists": False}
        else:
            entry["updateMask"] = {"fieldPaths": sorted(fields)}
            entry["currentDocument"] = {"exists": True}
        converted.append(entry)
    return converted


def _check_observation(
    expected: dict[str, Any], operation: dict[str, Any], *, nonce: str
) -> tuple[str, str]:
    if operation.get("method") not in {"get", "commit"}:
        raise ValueError("operation shape refused")
    resources = operation.get("resources")
    if not isinstance(resources, list) or not resources:
        raise ValueError("observation resources required")
    for resource in resources:
        _resource(resource, nonce=nonce)
    credential = expected.get("credential")
    if not isinstance(credential, dict):
        raise ValueError("credential shape refused")  # noqa: TRY004
    expected_values = {
        "caseId": expected.get("caseId"),
        "index": expected.get("index"),
        "ruleset": expected.get("ruleset"),
        "method": expected.get("method"),
        "resources": expected.get("resources"),
        "writes": expected.get("writes"),
        "createdDocuments": expected.get("createdDocuments"),
        "credentialRef": credential.get("ref"),
        "credentialClass": credential.get("class"),
        "credentialFingerprint": digest(
            ["credential-ref", nonce, credential.get("ref")]
        )[:16],
    }
    keys = tuple(expected_values)
    for key in keys:
        if operation.get(key) != expected_values[key]:
            if key == "credentialClass":
                raise ValueError("credential class differs from frozen plan")
            if key == "credentialFingerprint":
                raise ValueError("credential fingerprint differs from frozen plan")
            raise ValueError("operation differs from frozen plan")
    return operation["credentialRef"], operation["credentialClass"]


def _observation(
    plan: dict[str, Any],
    operation: dict[str, Any],
    credentials: dict[str, Any],
    *,
    nonce: str,
    account_bindings: dict[str, Any] | None,
    identity_proofs: dict[str, IdentityProof] | None,
) -> dict[str, Any]:
    index = operation.get("index")
    observations = plan.get("observation")
    if (
        type(index) is not int
        or not isinstance(observations, list)
        or not 0 <= index < len(observations)
    ):
        raise ValueError("operation index outside plan")
    if "credentialClass" not in operation:
        raw = operation.get("credential")
        if not isinstance(raw, dict) or not isinstance(raw.get("ref"), str):
            raise ValueError("principal binding refused")
        expected_credential = observations[index].get("credential", {})
        if raw.get("ref") != expected_credential.get("ref"):
            raise ValueError("principal binding refused")
        operation = {
            **operation,
            "index": index,
            "credentialRef": raw["ref"],
            "credentialClass": raw.get("class"),
            "credentialFingerprint": digest(["credential-ref", nonce, raw["ref"]])[:16],
        }
    reference, credential_class = _check_observation(
        observations[index], operation, nonce=nonce
    )
    principal = observations[index].get("principal")
    if account_bindings is not None and credential_class != "absent":
        expected_account = next(
            (
                entry
                for entry in plan.get("ownedAccounts", [])
                if isinstance(entry, dict) and entry.get("ref") == principal
            ),
            None,
        )
        bound = account_bindings.get(principal) if isinstance(principal, str) else None
        if (
            identity_proofs is not None
            and credential_class == "user-id-token"
            and "expired" not in reference
        ):
            proof = identity_proofs.get(reference)
            if (
                not isinstance(proof, IdentityProof)
                or not proof.trusted()
                or proof.principal_ref != principal
            ):
                raise ValueError("trusted identity proof required")
        if expected_account is None and (
            reference in {"malformed-bearer", "empty-bearer", "expired-token"}
            or "expired" in str(principal)
        ):
            expected_account = None
        elif not isinstance(expected_account, dict) or not isinstance(bound, dict):
            raise ValueError("credential principal binding required")
        if expected_account is not None:
            expected_provider = (
                "anonymous"
                if expected_account.get("kind") == "anonymous"
                else "password"
            )
            if bound.get("provider") not in {None, expected_provider} or bound.get(
                "tenant"
            ) != expected_account.get("tenant"):
                raise ValueError("credential scope binding differs")
            expected_claims = digest(expected_account.get("claims", {}))
            if bound.get("claimsDigest") not in {None, expected_claims}:
                raise ValueError("credential claims scope differs")
            if not isinstance(bound.get("uid"), str):
                raise ValueError("credential UID binding required")
    token = _credential(credentials, reference, credential_class, identity_proofs)
    if (
        credential_class == "user-id-token"
        and ("expired" in reference or "expired" in str(principal))
        and (operation["method"] == "commit" or _has_principal(operation.get("writes")))
    ):
        raise ValueError("expired credential cannot authorize writes")
    path = _resource(operation["resources"][0], nonce=nonce)
    headers = _headers(token)
    if operation["method"] == "get":
        return {
            "service": "firestore",
            "route": "observation-get",
            "origin": FIRESTORE_ORIGIN,
            "path": path,
            "method": "GET",
            "headers": headers,
            "body": None,
        }
    return {
        "service": "firestore",
        "route": "observation-commit",
        "origin": FIRESTORE_ORIGIN,
        "path": f"/v1/projects/{PROJECT}/databases/(default)/documents:commit",
        "method": "POST",
        "headers": headers,
        "body": {"writes": _commit_writes(plan, operation["writes"], account_bindings)},
    }


def _rules_route(
    plan: dict[str, Any], operation: dict[str, Any], credentials: dict[str, Any]
) -> dict[str, Any]:
    """Build only the frozen Rules REST lifecycle routes."""
    if not isinstance(operation, dict) or operation.get("phase") != "ruleset":
        raise ValueError("rules lifecycle phase required")
    token = _credential(credentials, "administrator", "administrator")
    headers = _headers(token)
    action = operation.get("action")
    if action == "create":
        allowed = {"kind", "phase", "action", "label", "sourceDigest"}
        if frozenset(operation) not in {frozenset(allowed), frozenset(allowed | {"attachmentPoint"})} or operation.get("kind") != "rules-lifecycle":
            raise ValueError("ruleset create shape refused")
        label = operation["label"]
        source = plan.get("rulesets", {}).get(label, {}).get("source")
        if label not in {"A", "B"} or not isinstance(source, str) or digest(source) != operation["sourceDigest"]:
            raise ValueError("ruleset source binding differs")
        body: dict[str, Any] = {"source": {"files": [{"name": "firestore.rules", "content": source}]}}
        if "attachmentPoint" in operation:
            point = operation["attachmentPoint"]
            if point != f"projects/{PROJECT}/databases/(default)":
                raise ValueError("ruleset attachment point binding differs")
            body["attachmentPoint"] = point
        return {"service": "rules", "route": "ruleset-create", "origin": RULES_ORIGIN, "path": f"/v1/projects/{PROJECT}/rulesets", "method": "POST", "headers": headers, "body": body}
    if action in {"get", "delete"}:
        if set(operation) != {"kind", "phase", "action", "rulesetName"} or operation.get("kind") != "rules-lifecycle" or not isinstance(operation["rulesetName"], str) or not _RULESET_NAME.fullmatch(operation["rulesetName"]):
            raise ValueError("ruleset resource shape refused")
        return {"service": "rules", "route": f"ruleset-{action}", "origin": RULES_ORIGIN, "path": "/v1/" + operation["rulesetName"], "method": "GET" if action == "get" else "DELETE", "headers": headers, "body": None}
    if action in {"release-get", "release-patch", "release-get-executable"}:
        required = {"phase", "action", "releaseName"}
        if action == "release-patch":
            required |= {"rulesetName"}
        if set(operation) != required | {"kind"} or operation.get("kind") != "rules-lifecycle" or not isinstance(operation["releaseName"], str) or not _RELEASE_NAME.fullmatch(operation["releaseName"]):
            raise ValueError("release resource shape refused")
        release = operation["releaseName"]
        if action == "release-patch":
            ruleset = operation["rulesetName"]
            if not isinstance(ruleset, str) or not _RULESET_NAME.fullmatch(ruleset):
                raise ValueError("release ruleset binding refused")
            return {"service": "rules", "route": "release-patch", "origin": RULES_ORIGIN, "path": "/v1/" + release, "method": "PATCH", "headers": headers, "body": {"release": {"name": release, "rulesetName": ruleset}, "updateMask": "rulesetName"}}
        executable = action == "release-get-executable"
        return {"service": "rules", "route": "release-get-executable" if executable else "release-get", "origin": RULES_ORIGIN, "path": "/v1/" + release + (":getExecutable" if executable else ""), "method": "GET", "headers": headers, "body": None}
    raise ValueError("rules lifecycle action refused")


def _setup_item(plan: dict[str, Any], item: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(item, dict) or not isinstance(item.get("id"), str):
        raise ValueError("setup item shape refused")
    if item["id"].startswith("fixture/"):
        document = item["id"][len("fixture/") :]
        entry = next((row for row in plan.get("fixtures", []) if row.get("document") == document), None)
        if not isinstance(entry, dict):
            raise ValueError("setup fixture binding refused")
        expected = {
            "id": item["id"],
            "service": "firestore",
            "route": "document-create",
            "method": "PATCH",
            "path": "/v1/" + entry["resource"] + "?currentDocument.exists=false",
            "document": entry["document"],
            "resource": entry["resource"],
            "fields": entry["fields"],
            "fieldsDigest": digest(entry["fields"]),
            "precondition": {"exists": False},
            "response": {
                "name": entry["resource"],
                "fieldsDigest": digest(entry["fields"]),
                "updateTime": "response-bound",
            },
        }
    elif item["id"].startswith("account/"):
        parts = item["id"].split("/")
        if len(parts) != 3 or parts[0] != "account":
            raise ValueError("setup account binding refused")
        ref, action = parts[1], parts[2]
        account = next((row for row in plan.get("ownedAccounts", []) if row.get("ref") == ref), None)
        if not isinstance(account, dict):
            raise ValueError("setup account binding refused")
        if action == "signup":
            response = {"localId": "response-bound", "idToken": "response-bound", "expiresIn": "response-bound"}
            route = "accounts:signUp"
        elif action == "claim-update" and ref == "owner-a":
            response = {"localId": "response-bound"}
            route = "accounts:update"
        elif action == "signin" and ref == "owner-a":
            response = {"localId": "response-bound", "idToken": "response-bound", "expiresIn": "response-bound"}
            route = "accounts:signInWithPassword"
        else:
            raise ValueError("setup account route refused")
        expected = {
            "id": item["id"],
            "service": "identity",
            "route": route,
            "method": "POST",
            "accountRef": ref,
            "tenant": account.get("tenant"),
            "response": response,
        }
        if action == "claim-update":
            expected["claimsDigest"] = digest(account.get("claims", {}))
    else:
        raise ValueError("setup item id refused")
    if item != expected:
        raise ValueError("setup item differs from frozen plan")
    return expected


def prepare_setup_request(
    plan: dict[str, Any],
    item: dict[str, Any],
    *,
    credentials: dict[str, Any],
    account_bindings: dict[str, Any] | None = None,
    setup_secrets: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Build one compiler-owned setup request; never creates admission authority."""
    expected = _setup_item(plan, copy.deepcopy(item))
    admin = _credential(credentials, "administrator", "administrator")
    if expected["service"] == "firestore":
        resource = expected["resource"]
        return {
            "service": "firestore",
            "route": "document-create",
            "origin": FIRESTORE_ORIGIN,
            "path": expected["path"],
            "method": "PATCH",
            "headers": _headers(admin),
            "body": {"name": resource, "fields": {key: _typed(value, account_bindings) for key, value in expected["fields"].items()}},
        }
    account = next(row for row in plan["ownedAccounts"] if row["ref"] == expected["accountRef"])
    secret = (setup_secrets or {}).get(expected["accountRef"])
    if not isinstance(secret, str) or not secret or any(char.isspace() for char in secret):
        raise ValueError("transient setup secret required")
    tenant = expected["tenant"]
    headers = _headers(admin)
    if expected["route"] == "accounts:signUp":
        body = {"returnSecureToken": True}
        if account.get("email") is not None:
            body.update({"email": account["email"], "password": secret})
        if tenant is not None:
            body["tenantId"] = tenant
        api_key = _credential(credentials, "api-key", "api-key")
        return {"service": "identity", "route": expected["route"], "origin": IDENTITY_ORIGIN, "path": _client_account_path("signUp", api_key), "method": "POST", "headers": _headers(None), "body": body}
    if expected["route"] == "accounts:update":
        bound = (account_bindings or {}).get(expected["accountRef"], {})
        if not isinstance(bound, dict) or not isinstance(bound.get("uid"), str):
            raise ValueError("owner UID binding required")
        return {"service": "identity", "route": expected["route"], "origin": IDENTITY_ORIGIN, "path": _account_path(tenant, "update"), "method": "POST", "headers": headers, "body": {"localId": bound["uid"], "customAttributes": json.dumps(account["claims"], separators=(",", ":"))}}
    bound = (account_bindings or {}).get(expected["accountRef"], {})
    if not isinstance(bound, dict) or not isinstance(bound.get("uid"), str):
        raise ValueError("owner UID binding required")
    body = {"email": account["email"], "password": secret, "returnSecureToken": True}
    if tenant is not None:
        body["tenantId"] = tenant
    api_key = _credential(credentials, "api-key", "api-key")
    return {"service": "identity", "route": expected["route"], "origin": IDENTITY_ORIGIN, "path": _client_account_path("signInWithPassword", api_key), "method": "POST", "headers": _headers(None), "body": body}


def adapt_setup_result(
    item: dict[str, Any],
    result: dict[str, Any],
    *,
    endpoint: str,
    sequence: int,
    account_bindings: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if not isinstance(result, dict) or type(result.get("status")) is not int or not isinstance(result.get("body"), dict):
        raise ValueError("setup response envelope refused")
    status, body = result["status"], result["body"]
    if not 200 <= status < 300:
        raise ValueError("setup response status refused")
    wire = {"id": item["id"], "httpStatus": status, "endpoint": endpoint, "wireSequence": sequence}
    if item["service"] == "firestore":
        if body.get("name") != item["response"]["name"] or not isinstance(body.get("updateTime"), str) or not isinstance(body.get("fields"), dict):
            raise ValueError("setup Document response refused")
        fields = {key: _decode_firestore_value(value) for key, value in body["fields"].items()}
        expected_fields = {
            key: _decode_firestore_value(_typed(value, account_bindings))
            for key, value in item.get("fields", {}).items()
        }
        if digest(fields) != digest(expected_fields):
            raise ValueError("setup fields digest refused")
        return SetupResult(
            receipt=SetupPublicReceipt(
                item_id=wire["id"],
                http_status=wire["httpStatus"],
                endpoint=wire["endpoint"],
                wire_sequence=wire["wireSequence"],
                name=body["name"],
                fields_digest=item["response"]["fieldsDigest"],
                update_time=body["updateTime"],
            ),
            private=SetupPrivateHandoff(),
        )
    if not isinstance(body.get("localId"), str):
        raise ValueError("setup localId response refused")
    bound = (account_bindings or {}).get(item.get("accountRef"))
    if isinstance(bound, dict) and isinstance(bound.get("uid"), str) and body["localId"] != bound["uid"]:
        raise ValueError("setup localId binding refused")
    expected = item["response"]
    if item["route"] != "accounts:update" and (not isinstance(body.get("idToken"), str) or not isinstance(body.get("expiresIn"), str)):
        raise ValueError("setup token response refused")
    return SetupResult(
        receipt=SetupPublicReceipt(
            item_id=wire["id"],
            http_status=wire["httpStatus"],
            endpoint=wire["endpoint"],
            wire_sequence=wire["wireSequence"],
            local_id=body["localId"],
        ),
        private=SetupPrivateHandoff(
            id_token=body.get("idToken"), expires_in=body.get("expiresIn")
        ),
    )


def _account_path(tenant: str | None, suffix: str) -> str:
    prefix = f"/v1/projects/{PROJECT}"
    if tenant is not None:
        prefix += f"/tenants/{tenant}"
    return f"{prefix}/accounts:{suffix}"


def _client_account_path(suffix: str, api_key: str) -> str:
    return f"/v1/accounts:{suffix}?key={quote(api_key, safe='')}"


def _principal(
    plan: dict[str, Any],
    operation: dict[str, Any],
    credentials: dict[str, Any],
    account_bindings: dict[str, Any] | None,
    identity_proofs: dict[str, IdentityProof] | None = None,
) -> dict[str, Any]:
    required = {
        "kind",
        "phase",
        "principalRef",
        "action",
        "credentialRef",
        "credentialClass",
    }
    if (
        set(operation) != required
        or operation.get("phase") != "principal"
        or operation["credentialRef"] != "administrator"
        or operation["credentialClass"] != "administrator"
    ):
        raise ValueError("principal action phase or shape refused")
    ref, action = operation["principalRef"], operation["action"]
    if not any(
        isinstance(entry, dict) and entry.get("ref") == ref
        for entry in plan.get("ownedAccounts", [])
    ) or action not in {"revoke", "disable", "delete"}:
        raise ValueError("principal binding refused")
    bound = (account_bindings or {}).get(ref)
    account = next(
        (
            entry
            for entry in plan.get("ownedAccounts", [])
            if isinstance(entry, dict) and entry.get("ref") == ref
        ),
        None,
    )
    if (
        not isinstance(bound, dict)
        or not isinstance(account, dict)
        or not isinstance(bound.get("uid"), str)
        or bound.get("tenant") != account.get("tenant")
    ):
        raise ValueError("account binding required")
    token = _credential(credentials, "administrator", "administrator")
    body: dict[str, Any] = {"localId": bound["uid"]}
    if action == "disable":
        body["disableUser"] = True
    if action == "revoke":
        if type(bound.get("authTime")) is not int:
            raise ValueError("account authTime binding required")
        body["validSince"] = bound["authTime"] + 1
    suffix = "delete" if action == "delete" else "update"
    return {
        "service": "identity",
        "route": "principal-action",
        "origin": IDENTITY_ORIGIN,
        "path": _account_path(account.get("tenant"), suffix),
        "method": "POST",
        "headers": _headers(token),
        "body": body,
    }


def _recovery(
    plan: dict[str, Any],
    operation: dict[str, Any],
    credentials: dict[str, Any],
    *,
    nonce: str,
    account_bindings: dict[str, Any] | None,
) -> dict[str, Any]:
    required = {
        "kind",
        "phase",
        "resource",
        "accountRef",
        "credentialRef",
        "credentialClass",
        "precondition",
    }
    if (
        set(operation) != required
        or operation.get("phase") != "recovery"
        or operation["credentialRef"] != "administrator"
        or operation["credentialClass"] != "administrator"
    ):
        raise ValueError("recovery phase or shape refused")
    token = _credential(credentials, "administrator", "administrator")
    kind, precondition = operation["kind"], operation["precondition"]
    if kind.startswith("account-"):
        if operation.get("resource") is not None:
            raise ValueError("account recovery resource must be null")
        ref = operation.get("accountRef")
        bound = (account_bindings or {}).get(ref)
        account = next(
            (
                entry
                for entry in plan.get("ownedAccounts", [])
                if isinstance(entry, dict) and entry.get("ref") == ref
            ),
            None,
        )
        if (
            not isinstance(bound, dict)
            or not isinstance(account, dict)
            or not isinstance(bound.get("uid"), str)
            or bound.get("tenant") != account.get("tenant")
        ):
            raise ValueError("account binding required")
        if kind == "account-delete":
            if precondition != {"uid": bound["uid"]}:
                raise ValueError("account UID precondition differs")
            return {
                "service": "identity",
                "route": "account-recovery",
                "origin": IDENTITY_ORIGIN,
                "path": _account_path(account.get("tenant"), "delete"),
                "method": "POST",
                "headers": _headers(token),
                "body": {"localId": bound["uid"]},
            }
        if kind in {"account-readback", "account-absence"}:
            if precondition is not None:
                raise ValueError("account recovery precondition must be null")
            return {
                "service": "identity",
                "route": "account-recovery",
                "origin": IDENTITY_ORIGIN,
                "path": _account_path(account.get("tenant"), "lookup"),
                "method": "POST",
                "headers": _headers(token),
                "body": {"localId": [bound["uid"]]},
            }
        raise ValueError("recovery operation shape refused")
    path = _resource(operation.get("resource"), nonce=nonce)
    if kind in {"readback", "absence"}:
        if operation.get("accountRef") is not None or precondition is not None:
            raise ValueError("document recovery precondition differs")
        return {
            "service": "firestore",
            "route": "document-recovery-get",
            "origin": FIRESTORE_ORIGIN,
            "path": path,
            "method": "GET",
            "headers": _headers(token),
            "body": None,
        }
    if kind == "delete":
        if not isinstance(precondition, dict) or not isinstance(
            precondition.get("updateTime"), str
        ):
            raise ValueError("document updateTime precondition required")
        return {
            "service": "firestore",
            "route": "document-recovery-delete",
            "origin": FIRESTORE_ORIGIN,
            "path": path
            + "?currentDocument.updateTime="
            + quote(precondition["updateTime"], safe=""),
            "method": "DELETE",
            "headers": _headers(token),
            "body": None,
        }
    raise ValueError("recovery operation shape refused")


def prepare_request(
    plan: dict[str, Any],
    operation: dict[str, Any],
    *,
    credentials: dict[str, Any],
    account_bindings: dict[str, Any] | None = None,
    identity_proofs: dict[str, IdentityProof] | None = None,
) -> dict[str, Any]:
    nonce, _tenant = _plan_identity(plan)
    if not isinstance(operation, dict):
        raise ValueError("operation required")  # noqa: TRY004
    if operation.get("kind") == "ruleset-release":
        raise ValueError("ruleset release alias refused")
    if operation.get("kind") == "rules-lifecycle":
        return _rules_route(plan, operation, credentials)
    if operation.get("kind") == "principal-action":
        return _principal(plan, operation, credentials, account_bindings)
    if operation.get("phase") == "recovery":
        return _recovery(
            plan, operation, credentials, nonce=nonce, account_bindings=account_bindings
        )
    return _observation(
        plan,
        operation,
        credentials,
        nonce=nonce,
        account_bindings=account_bindings,
        identity_proofs=identity_proofs,
    )


def _run_worker(
    envelope: dict[str, Any],
    *,
    binding: bytes,
    binding_digest: str,
    fixture_origin: str | None,
) -> dict[str, Any]:
    verify_worker_binding(binding, binding_digest, None)
    if _OWNED_CHILDREN:
        raise WorkerExchangeError("unreaped worker ownership remains", worker_reaped=False)
    payload = _compact(envelope)
    if len(payload) > MAX_ENVELOPE_BYTES:
        raise ValueError("worker envelope exceeds bound")
    worker = Path(__file__).with_name("o5_user_token_https_worker.py")
    argv = [sys.executable, "-I", "-S", "-B", str(worker)]
    if fixture_origin is not None:
        argv.extend(("--fixture-origin", fixture_origin))
    started = time.monotonic()
    seconds = float(envelope.get("seconds", MAX_SECONDS))
    deadline = started + seconds
    child = subprocess.Popen(
        argv,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    _OWNED_CHILDREN.add(child.pid)
    reaped = False
    try:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise WorkerExchangeError(
                "worker walltime exceeded", worker_reaped=False
            )
        io_timeout = remaining - _REAP_RESERVE_SECONDS
        if io_timeout <= 0:
            raise WorkerExchangeError(
                "worker reap reserve exhausted", worker_reaped=False
            )
        stdout, _stderr = child.communicate(input=payload, timeout=io_timeout)
        reaped = child.poll() is not None
        if time.monotonic() > deadline:
            raise WorkerExchangeError("worker walltime exceeded", worker_reaped=reaped)
    except subprocess.TimeoutExpired:
        reaped = _reap_owned(child, deadline=deadline)
        raise WorkerExchangeError(
            "worker walltime exceeded", worker_reaped=reaped
        ) from None
    finally:
        if child.poll() is None:
            reaped = _reap_owned(child, deadline=deadline) or reaped
        if reaped or child.poll() is not None:
            _OWNED_CHILDREN.discard(child.pid)
    if not reaped:
        raise WorkerExchangeError("worker reap unconfirmed", worker_reaped=False)
    if child.returncode != 0 or len(stdout) > MAX_OUTPUT_BYTES:
        raise WorkerExchangeError("worker exchange refused", worker_reaped=True)
    try:
        result = json.loads(stdout)
    except (TypeError, json.JSONDecodeError):
        raise WorkerExchangeError(
            "worker response malformed", worker_reaped=True
        ) from None
    if (
        not isinstance(result, dict)
        or set(result) != {"status", "body"}
        or not isinstance(result["status"], int)
        or not isinstance(result["body"], dict)
    ):
        raise ValueError("worker response malformed")
    return result


def run_worker(
    envelope: dict[str, Any],
    *,
    binding: bytes,
    binding_digest: str,
    fixture_origin: str | None = None,
) -> dict[str, Any]:
    return _run_worker(
        envelope,
        binding=binding,
        binding_digest=binding_digest,
        fixture_origin=fixture_origin,
    )


_MAX_FIRESTORE_VALUE_DEPTH = 32


def _decode_firestore_value(value: Any, *, depth: int = 0) -> Any:
    if depth > _MAX_FIRESTORE_VALUE_DEPTH:
        raise ValueError("Firestore value depth refused")
    if not isinstance(value, dict) or len(value) != 1:
        raise ValueError("Firestore value shape refused")
    kind, payload = next(iter(value.items()))
    if kind == "nullValue":
        if payload is not None:
            raise ValueError("Firestore null value refused")
        return payload
    if kind == "booleanValue":
        if type(payload) is not bool:
            raise ValueError("Firestore boolean value refused")
        return payload
    if kind == "stringValue":
        if not isinstance(payload, str):
            raise ValueError("Firestore string value refused")
        return payload
    if kind == "doubleValue":
        if type(payload) not in {int, float} or not math.isfinite(payload):
            raise ValueError("Firestore double value refused")
        return payload
    if kind == "integerValue":
        if not isinstance(payload, str) or not re.fullmatch(r"-?(0|[1-9][0-9]*)", payload):
            raise ValueError("Firestore integer value refused")
        return int(payload)
    if kind == "mapValue":
        if not isinstance(payload, dict) or set(payload) - {"fields"}:
            raise ValueError("Firestore map value refused")
        fields = payload.get("fields", {})
        if not isinstance(fields, dict):
            raise ValueError("Firestore map value refused")
        return {
            key: _decode_firestore_value(nested, depth=depth + 1)
            for key, nested in fields.items()
        }
    if kind == "arrayValue":
        if not isinstance(payload, dict) or set(payload) - {"values"}:
            raise ValueError("Firestore array value refused")
        values = payload.get("values", [])
        if not isinstance(values, list):
            raise ValueError("Firestore array value refused")
        return [_decode_firestore_value(nested, depth=depth + 1) for nested in values]
    if kind in {"timestampValue", "bytesValue", "referenceValue"}:
        if not isinstance(payload, str):
            raise ValueError("Firestore scalar value refused")
        return payload
    if kind == "geoPointValue":
        if not isinstance(payload, dict) or set(payload) != {"latitude", "longitude"}:
            raise ValueError("Firestore geo point value refused")
        latitude = payload["latitude"]
        longitude = payload["longitude"]
        if (
            type(latitude) not in {int, float}
            or type(longitude) not in {int, float}
            or not math.isfinite(latitude)
            or not math.isfinite(longitude)
        ):
            raise ValueError("Firestore geo point value refused")
        return {"latitude": latitude, "longitude": longitude}
    raise ValueError("Firestore value kind refused")


def _adapt_firestore_result(
    prepared: dict[str, Any], result: dict[str, Any], *, sequence: int, endpoint: str
) -> dict[str, Any]:
    status = result.get("status")
    body = result.get("body")
    if type(status) is not int or not isinstance(body, dict):
        raise ValueError("REST response envelope refused")
    wire = {"endpoint": endpoint, "wireSequence": sequence}
    error = body.get("error")
    if status < 200 or status >= 300:
        if (
            not isinstance(error, dict)
            or type(error.get("code")) is not int
            or error["code"] != status
            or not isinstance(error.get("status"), str)
        ):
            raise ValueError("REST error response shape refused")
        if prepared["route"] == "document-recovery-get" and status == 404 and error["status"] == "NOT_FOUND":
            return {
                "status": "NOT_FOUND",
                "code": 5,
                "httpStatus": 404,
                "documentPresent": False,
                "version": None,
                "complete": True,
                **wire,
            }
        return {
            "status": error["status"],
            "code": error["code"],
            "httpStatus": status,
            "documentPresent": False,
            "fields": None,
            "complete": True,
            **wire,
        }
    route = prepared["route"]
    if route == "document-recovery-get":
        name = body.get("name")
        fields = body.get("fields")
        expected = prepared["path"][len("/v1/") :]
        if not isinstance(name, str) or name != expected or not isinstance(fields, dict) or not isinstance(body.get("updateTime"), str):
            raise ValueError("REST recovery Document response shape refused")
        for value in fields.values():
            _decode_firestore_value(value)
        return {
            "status": "OK",
            "code": 0,
            "httpStatus": status,
            "documentPresent": True,
            "version": body["updateTime"],
            "complete": True,
            **wire,
        }
    if route == "observation-get":
        name = body.get("name")
        fields = body.get("fields")
        expected = prepared["path"][len("/v1/") :]
        if not isinstance(name, str) or name != expected or not isinstance(fields, dict):
            raise ValueError("REST Document response shape refused")
        return {
            "status": "OK",
            "code": 0,
            "httpStatus": status,
            "documentPresent": True,
            "fields": {key: _decode_firestore_value(value) for key, value in fields.items()},
            "complete": True,
            **wire,
        }
    if route == "observation-commit":
        write_results = body.get("writeResults")
        writes = prepared.get("body", {}).get("writes")
        if (
            not isinstance(write_results, list)
            or not isinstance(writes, list)
            or len(write_results) != len(writes)
            or not isinstance(body.get("commitTime"), str)
            or any(
                not isinstance(result, dict)
                or (
                    not isinstance(result.get("updateTime"), str)
                    and not isinstance(result.get("transformResults"), list)
                )
                for result in write_results
            )
        ):
            raise ValueError("REST Commit response shape refused")
        return {
            "status": "OK",
            "code": 0,
            "httpStatus": status,
            "documentPresent": True,
            "fields": None,
            "complete": True,
            **wire,
        }
    if route == "document-recovery-delete" and body == {}:
        return {
            "status": "OK",
            "code": 0,
            "httpStatus": status,
            "documentPresent": False,
            "complete": True,
            **wire,
        }
    raise ValueError("REST response route shape refused")


def make_transport(
    plan: dict[str, Any],
    *,
    credentials: dict[str, Any],
    frozen_inputs: dict[str, Any] | None = None,
    account_bindings: dict[str, Any] | None = None,
    identity_proofs: dict[str, IdentityProof] | None = None,
    fixture_origin: str | None = None,
):
    _plan_identity(plan)
    frozen = copy.deepcopy(frozen_inputs)
    trusted_bindings = copy.deepcopy(account_bindings or {})
    if identity_proofs is not None:
        for ref, proof in identity_proofs.items():
            if (
                not isinstance(proof, IdentityProof)
                or not proof.trusted()
                or proof.principal_ref != ref
            ):
                raise ValueError("trusted identity proof map required")
            expected_mode = "fixture" if fixture_origin is not None else "production"
            expected_origin = (
                fixture_origin.rstrip("/")
                if fixture_origin is not None
                else "https://identitytoolkit.googleapis.com"
            )
            if (
                proof.issuance_mode != expected_mode
                or proof.issuance_origin != expected_origin
            ):
                raise ValueError("identity proof origin or mode differs")
            current = trusted_bindings.get(ref, {})
            if not isinstance(current, dict):
                raise ValueError("account binding shape required")  # noqa: TRY004
            supplied = {
                "uid": proof.uid,
                "provider": proof.provider,
                "tenant": proof.tenant,
                "claimsDigest": proof.claims_digest,
            }
            if any(
                key in current and current[key] != value
                for key, value in supplied.items()
            ):
                raise ValueError("identity proof conflicts with account binding")
            trusted_bindings[ref] = {**current, **supplied}
        required_refs = {entry["ref"] for entry in plan["ownedAccounts"]}
        if set(identity_proofs) != required_refs:
            raise ValueError("complete identity proof map required")
    sequence = 0

    def transmit(
        value: dict[str, Any],
        *,
        binding: bytes,
        binding_digest: str,
        capability: Any = None,
    ) -> dict[str, Any]:
        nonlocal sequence
        if capability is None:
            raise ValueError("active O8 production capability required")
        if identity_proofs is None:
            raise ValueError("complete identity proof map required")
        snapshot = _frozen_inputs(plan, frozen)
        if getattr(capability, "inputs_digest", None) != snapshot["inputsDigest"]:
            raise ValueError("capability inputs digest differs")
        authorize_transport(capability, binding=binding, binding_digest=binding_digest)
        prepared = prepare_request(
            plan,
            copy.deepcopy(value),
            credentials=credentials,
            account_bindings=trusted_bindings,
            identity_proofs=identity_proofs,
        )
        envelope = {
            key: prepared[key]
            for key in ("service", "route", "method", "path", "headers", "body")
        }
        envelope["seconds"] = MAX_SECONDS
        result = _run_worker(
            envelope,
            binding=binding,
            binding_digest=binding_digest,
            fixture_origin=fixture_origin,
        )
        sequence += 1
        origin = (
            fixture_origin.rstrip("/")
            if fixture_origin is not None
            else prepared["origin"]
        )
        endpoint = urlsplit(origin).netloc
        if prepared["service"] == "firestore":
            return _adapt_firestore_result(
                prepared, result, sequence=sequence, endpoint=endpoint
            )
        return {**result["body"], "endpoint": endpoint, "wireSequence": sequence}

    return transmit


__all__ = [
    "FIRESTORE_ORIGIN",
    "IDENTITY_ORIGIN",
    "RULES_ORIGIN",
    "WORKER_ENTRY",
    "make_transport",
    "prepare_request",
    "run_worker",
    "verify_worker_binding",
    "worker_binding",
]
