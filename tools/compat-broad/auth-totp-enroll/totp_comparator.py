"""Fail-closed comparison of typed preparation receipts, without parity claims."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from totp_plan import CAMPAIGN_ID, STAGE_IDS

_SENSITIVE = ("secret", "otp", "code", "password", "token", "session", "credential")


def _safe(value: Any, key: str = "") -> Any:
    if any(part in key.lower() for part in _SENSITIVE):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {name: _safe(item, name) for name, item in sorted(value.items())}
    if isinstance(value, list):
        return [_safe(item, key) for item in value]
    return value


def _valid(record: Any, side: str) -> bool:
    if (
        not isinstance(record, dict)
        or record.get("caseId") != CAMPAIGN_ID
        or record.get("side") != side
        or record.get("recordingComplete") is not True
    ):
        return False
    binding = record.get("sourceBinding")
    if (
        not isinstance(binding, dict)
        or not isinstance(binding.get("commit"), str)
        or not isinstance(binding.get("artifactSha256"), str)
    ):
        return False
    if not re.fullmatch(r"[0-9a-f]{40}", binding["commit"]) or not re.fullmatch(
        r"[0-9a-f]{64}", binding["artifactSha256"]
    ):
        return False
    stages = record.get("stages")
    if (
        not isinstance(stages, list)
        or [item.get("id") for item in stages if isinstance(item, dict)]
        != list(STAGE_IDS)
        or len(stages) != len(STAGE_IDS)
    ):
        return False
    if not all(
        isinstance(item.get("response"), dict)
        and type(item["response"].get("status")) is int
        for item in stages
    ):
        return False
    state, recovery = record.get("state"), record.get("recovery")
    if (
        not isinstance(state, dict)
        or not all(
            isinstance(state.get(key), dict) for key in ("afterWrong", "afterSuccess")
        )
        or not isinstance(recovery, dict)
    ):
        return False
    return (
        recovery.get("ownerVerified") is True
        and recovery.get("cleanupVerified") is True
        and type(recovery.get("remainingAccounts")) is int
        and recovery["remainingAccounts"] == 0
    )


def compare(left: dict, right: dict) -> dict:
    """Classify complete differences, withholding agreement until executable review."""
    structurally_complete = (
        left is not right
        and _valid(left, "local")
        and _valid(right, "production")
        and left["sourceBinding"] == right["sourceBinding"]
    )
    # Caller-supplied hashes do not independently prove source or artifact provenance.
    # No receipt in this preparation package can be promoted to semantic evidence.
    classification = "INDETERMINATE"
    digest = hashlib.sha256(
        json.dumps([_safe(left), _safe(right)], sort_keys=True, default=str).encode()
    ).hexdigest()
    return {
        "classification": classification,
        "receiptStatus": "STRUCTURALLY_COMPLETE_UNBOUND"
        if structurally_complete
        else "INCOMPLETE",
        "productionExecuted": False,
        "normalizedDigest": digest,
    }
