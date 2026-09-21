"""Credential preflight for the FS-CONFIG-LIFECYCLE production run.

Before OC-01 the collector charges one tokeninfo request and refuses to continue
unless the bearer belongs to the principal the owner froze in the permission, carries
the cloud-platform scope, and has at least the whole campaign window of lifetime left
(the 900 s wall plus the 360 s recovery reserve), so a token cannot expire between a
patch and its revert. The verifier is the request-byte lane's reviewed `verify_token`,
loaded by path; only an attestation of digests and booleans is ever persisted, never
the tokeninfo body or the token.
"""

from __future__ import annotations

import importlib.util
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "tools/compat-broad"))
sys.path.insert(0, str(ROOT / "tools/compat-broad/fs-write-txn"))

from broad_contract import digest

VERIFIER_MODULE = (
    "tools/compat-broad/fs-request-bytes-boundary/request_bytes_preflight.py"
)
ATTESTATION_KIND = "fs-config-lifecycle-credential-attestation-v1"
TOKENINFO_SECONDS = 12.0


def _verifier():
    spec = importlib.util.spec_from_file_location(
        "_lifecycle_credential_verifier", ROOT / VERIFIER_MODULE
    )
    if spec is None or spec.loader is None:
        raise ValueError("reviewed credential verifier unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def required_seconds() -> int:
    from fs_config_lifecycle.manifest import MAX_WALL_SECONDS, RECOVERY_RESERVE_SECONDS

    return int(MAX_WALL_SECONDS + RECOVERY_RESERVE_SECONDS)


def tokeninfo_receipt(token: str, *, deadline: float) -> dict:
    """The production tokeninfo exchange: an isolated worker, a bounded deadline."""
    from credential_prep import _private_request

    duration = min(TOKENINFO_SECONDS, deadline - time.monotonic())
    if duration <= 0:
        return {"complete": False, "workerReaped": True, "status": None, "body": None}
    result = _private_request("tokeninfo", token, deadline=duration)
    return {
        "complete": result.get("complete") is True,
        "workerReaped": result.get("workerReaped") is True,
        "status": result.get("status"),
        "body": result.get("body"),
    }


def attest(receipt: dict, principal: dict, *, sent: float, now: float, seconds: int):
    """Project the verifier's verdict into an attestation; never the raw body."""
    verifier = _verifier()
    try:
        verifier.validate_principal(principal)
        evidence = verifier.credential_evidence(
            receipt, principal, sent=sent, now=now, required_seconds=seconds
        )
    except (ValueError, TypeError, KeyError) as error:
        return {
            "kind": ATTESTATION_KIND,
            "verified": False,
            "reason": type(error).__name__ + ": " + str(error)[:120],
            "principalDigest": digest(principal)
            if isinstance(principal, dict)
            else None,
            "requiredSeconds": seconds,
        }
    return {
        "kind": ATTESTATION_KIND,
        "verified": True,
        "principalDigest": evidence["principalDigest"],
        "identityMode": evidence["identityMode"],
        "requiredScopeVerified": True,
        "expiresInSeconds": evidence["expiresInSeconds"],
        "remainingSecondsAtVerification": evidence["remainingSecondsAtVerification"],
        "requiredSeconds": seconds,
    }


def credential_preflight(token: str, principal: dict, *, tokeninfo=tokeninfo_receipt):
    """The `credential_preflight(deadline)` callable the collector charges first.

    The receipt it returns is a gate receipt whose body is the attestation. It is
    complete only when the credential verified, so a refusal stops the observation
    before OC-01 and the run ends with nothing patched.
    """
    seconds = required_seconds()

    def run(deadline: float) -> dict:
        sent = time.monotonic()
        receipt = tokeninfo(token, deadline=deadline)
        attestation = attest(
            receipt, principal, sent=sent, now=time.monotonic(), seconds=seconds
        )
        return {
            "status": receipt.get("status") if isinstance(receipt, dict) else None,
            "body": attestation,
            "complete": attestation["verified"],
            "failure": None if attestation["verified"] else "credential-preflight",
        }

    return run
