"""Closed, plan-bound transport boundary for the O5 user-token collector.

This module deliberately does not admit a campaign or acquire credentials. A
launcher supplies a compiled plan, a private credential mapping, and the O8
capability. The resulting callable validates every request against that plan,
then sends one bounded exchange through the digest-pinned HTTPS worker.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "o8-core"))

from o8_admission import authorize_transport

CAMPAIGN = "FS-RULES-USER-TOKEN-MATRIX-01"
PROJECT = "fireemu-35fe6"
DATABASE = "(default)"
LANE_DIRECTORY = "tools/compat-broad/fs-rules-publication"
WORKER_ENTRY = f"{LANE_DIRECTORY}/o5_user_token_https_worker.py"
FIRESTORE_ORIGIN = "https://firestore.googleapis.com"
IDENTITY_ORIGIN = "https://identitytoolkit.googleapis.com"
RULES_ORIGIN = "https://firebaserules.googleapis.com"
PRODUCTION_ORIGINS = {
    FIRESTORE_ORIGIN,
    IDENTITY_ORIGIN,
    RULES_ORIGIN,
}
MAX_SECONDS = 12.0
MAX_ENVELOPE_BYTES = 1_048_576
MAX_OUTPUT_BYTES = 2 * 1024 * 1024
_NONCE = re.compile(r"^[0-9a-f]{32}$")
_TENANT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{3,35}$")
_DOCUMENT = re.compile(
    r"^projects/([a-z][a-z0-9-]{4,28}[a-z0-9])/databases/\(default\)/documents/"
    r"o5-user-token/n([0-9a-f]{32})/cases/([A-Za-z0-9_-]{1,128})$"
)
_WORKER_SHA256 = "593c71ddadff7395dd7fb5c54c596c596afaa930157340236e2f6ea35ec87e6e"


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
    nonce = plan.get("nonce")
    tenant = plan.get("tenant")
    if not isinstance(nonce, str) or _NONCE.fullmatch(nonce) is None:
        raise ValueError("nonce binding required")
    if not isinstance(tenant, str) or _TENANT.fullmatch(tenant) is None:
        raise ValueError("tenant binding required")
    return nonce, tenant


def _credential(credentials: dict[str, Any], reference: str) -> str:
    value = credentials.get(reference)
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 8192
        or any(char.isspace() for char in value)
    ):
        raise ValueError("bounded credential required")
    return value


def _resource(path: Any, *, nonce: str) -> str:
    if not isinstance(path, str):
        raise ValueError("resource path required")  # noqa: TRY004 - malformed wire input is one refusal class
    match = _DOCUMENT.fullmatch(path)
    if match is None or match.group(1) != PROJECT or match.group(2) != nonce:
        if match is not None and match.group(1) != PROJECT:
            raise ValueError("project binding differs")
        raise ValueError("nonce binding differs")
    return "/v1/" + path


def _observation(
    plan: dict[str, Any],
    operation: dict[str, Any],
    credentials: dict[str, Any],
    *,
    nonce: str,
) -> dict[str, Any]:
    index = operation.get("index")
    observations = plan.get("observation")
    if (
        type(index) is not int
        or not isinstance(observations, list)
        or not 0 <= index < len(observations)
    ):
        raise ValueError("operation index outside plan")
    expected = observations[index]
    if operation.get("method") not in {"get", "commit"}:
        raise ValueError("operation shape refused")
    resources = operation.get("resources")
    if not isinstance(resources, list) or len(resources) != 1:
        raise ValueError("observation resources required")
    _resource(resources[0], nonce=nonce)
    raw_credential = operation.get("credential")
    raw_ref = raw_credential.get("ref") if isinstance(raw_credential, dict) else None
    expected_ref = expected["credential"]["ref"]
    if raw_ref is not None and raw_ref != expected_ref:
        raise ValueError("principal binding refused")
    operation_ref = operation.get("credentialRef", raw_ref)
    for key in ("caseId", "ruleset", "method", "resources", "writes", "credentialRef"):
        actual = operation.get(key)
        expected_value = (
            expected.get("caseId") if key == "caseId" else expected.get(key)
        )
        if key == "credentialRef":
            expected_value = expected_ref
            actual = operation_ref
        if actual != expected_value:
            raise ValueError("operation differs from frozen plan")
    credential = _credential(credentials, operation_ref)
    path = _resource(resources[0], nonce=nonce)
    method = operation.get("method")
    if method == "get":
        return {
            "origin": FIRESTORE_ORIGIN,
            "path": path,
            "method": "GET",
            "headers": {
                "Authorization": "Bearer " + credential,
                "x-goog-user-project": PROJECT,
            },
            "body": None,
        }
    if (
        method != "commit"
        or not isinstance(operation.get("writes"), list)
        or not operation["writes"]
    ):
        raise ValueError("operation shape refused")
    commit_path = path.rsplit("/documents/", 1)[0] + ":commit"
    return {
        "origin": FIRESTORE_ORIGIN,
        "path": commit_path,
        "method": "POST",
        "headers": {
            "Authorization": "Bearer " + credential,
            "x-goog-user-project": PROJECT,
        },
        "body": {"writes": operation["writes"]},
    }


def _ruleset(
    plan: dict[str, Any], operation: dict[str, Any], credentials: dict[str, Any]
) -> dict[str, Any]:
    if set(operation) != {
        "kind",
        "phase",
        "ruleset",
        "sourceDigest",
        "credentialRef",
        "credentialClass",
    }:
        raise ValueError("ruleset release shape refused")
    label = operation["ruleset"]
    rulesets = plan.get("rulesets")
    if (
        label not in {"A", "B"}
        or not isinstance(rulesets, dict)
        or label not in rulesets
    ):
        raise ValueError("ruleset binding required")
    source = rulesets[label].get("source")
    if (
        not isinstance(source, str)
        or hashlib.sha256(source.encode()).hexdigest() != operation["sourceDigest"]
    ):
        raise ValueError("ruleset source binding differs")
    token = _credential(credentials, "administrator")
    body = {"source": {"files": [{"name": "firestore.rules", "content": source}]}}
    return {
        "origin": RULES_ORIGIN,
        "path": f"/v1/projects/{PROJECT}/rulesets",
        "method": "POST",
        "headers": {"Authorization": "Bearer " + token},
        "body": body,
    }


def _principal(
    plan: dict[str, Any], operation: dict[str, Any], credentials: dict[str, Any]
) -> dict[str, Any]:
    required = {
        "kind",
        "phase",
        "principalRef",
        "action",
        "credentialRef",
        "credentialClass",
    }
    if set(operation) != required or operation["credentialRef"] != "administrator":
        raise ValueError("principal action shape refused")
    refs = {
        entry.get("ref")
        for entry in plan.get("ownedAccounts", [])
        if isinstance(entry, dict)
    }
    if operation["principalRef"] not in refs or operation["action"] not in {
        "revoke",
        "disable",
        "delete",
    }:
        raise ValueError("principal binding refused")
    token = _credential(credentials, "administrator")
    return {
        "origin": IDENTITY_ORIGIN,
        "path": f"/v1/projects/{PROJECT}/accounts:update",
        "method": "POST",
        "headers": {"Authorization": "Bearer " + token},
        "body": {"localId": operation["principalRef"], "action": operation["action"]},
    }


def _recovery(
    plan: dict[str, Any],
    operation: dict[str, Any],
    credentials: dict[str, Any],
    *,
    nonce: str,
) -> dict[str, Any]:
    if operation.get("credentialRef") != "administrator":
        raise ValueError("recovery credential binding refused")
    token = _credential(credentials, "administrator")
    kind = operation.get("kind")
    if kind.startswith("account-"):
        raise ValueError("account recovery requires launcher account binding")
    path = _resource(operation.get("resource"), nonce=nonce)
    if kind in {"readback", "absence"}:
        return {
            "origin": FIRESTORE_ORIGIN,
            "path": path,
            "method": "GET",
            "headers": {"Authorization": "Bearer " + token},
            "body": None,
        }
    if kind == "delete":
        return {
            "origin": FIRESTORE_ORIGIN,
            "path": path,
            "method": "DELETE",
            "headers": {"Authorization": "Bearer " + token},
            "body": None,
        }
    raise ValueError("recovery operation shape refused")


def prepare_request(
    plan: dict[str, Any], operation: dict[str, Any], *, credentials: dict[str, Any]
) -> dict[str, Any]:
    nonce, _tenant = _plan_identity(plan)
    if not isinstance(operation, dict):
        raise ValueError("operation required")  # noqa: TRY004 - malformed wire input is one refusal class
    if operation.get("kind") == "ruleset-release":
        return _ruleset(plan, operation, credentials)
    if operation.get("kind") == "principal-action":
        return _principal(plan, operation, credentials)
    if operation.get("phase") == "recovery":
        return _recovery(plan, operation, credentials, nonce=nonce)
    return _observation(plan, operation, credentials, nonce=nonce)


def _run_worker(
    envelope: dict[str, Any],
    *,
    binding: bytes,
    binding_digest: str,
    fixture_origin: str | None,
) -> dict[str, Any]:
    verify_worker_binding(binding, binding_digest, None)
    parsed = urlsplit(envelope.get("url", ""))
    origin = f"{parsed.scheme}://{parsed.netloc}"
    if fixture_origin is None and origin not in PRODUCTION_ORIGINS:
        raise ValueError("fixed service origin required")
    payload = _compact(envelope)
    if len(payload) > MAX_ENVELOPE_BYTES:
        raise ValueError("worker envelope exceeds bound")
    worker = Path(__file__).with_name("o5_user_token_https_worker.py")
    argv = [sys.executable, "-I", "-S", "-B", str(worker)]
    if fixture_origin is not None:
        argv.extend(("--fixture-origin", fixture_origin))
    try:
        completed = subprocess.run(
            argv,
            input=payload,
            capture_output=True,
            timeout=float(envelope["seconds"]),
            check=False,
        )
    except subprocess.TimeoutExpired:
        raise ValueError("worker walltime exceeded") from None
    if completed.returncode != 0 or len(completed.stdout) > MAX_OUTPUT_BYTES:
        raise ValueError("worker exchange refused")
    try:
        result = json.loads(completed.stdout)
    except (TypeError, json.JSONDecodeError):
        raise ValueError("worker response malformed") from None
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


def make_transport(
    plan: dict[str, Any],
    *,
    credentials: dict[str, Any],
    fixture_origin: str | None = None,
):
    _plan_identity(plan)
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
        authorize_transport(capability, binding=binding, binding_digest=binding_digest)
        prepared = prepare_request(plan, copy.deepcopy(value), credentials=credentials)
        origin = (
            fixture_origin.rstrip("/")
            if fixture_origin is not None
            else prepared["origin"]
        )
        envelope = {key: prepared[key] for key in ("method", "headers", "body")}
        envelope["url"] = origin + prepared["path"]
        envelope["seconds"] = MAX_SECONDS
        result = _run_worker(
            envelope,
            binding=binding,
            binding_digest=binding_digest,
            fixture_origin=fixture_origin,
        )
        sequence += 1
        endpoint = urlsplit(origin).netloc
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
