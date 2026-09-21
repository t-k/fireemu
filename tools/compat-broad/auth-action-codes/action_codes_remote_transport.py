"""Closed production-wire wrapper for the AUTH-ACTION stage matrix.

This module does not open production from the preparation collector. It maps one
already admitted Action stage to the existing credential worker envelope and
requires the caller to present the same live O8 capability binding on every send.
The shared worker and credential transport remain unchanged.
"""

from __future__ import annotations

import re
import sys
import time
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "auth-credential-tokens"))

import credential_remote_transport as credential_remote
from action_codes_plan import CAMPAIGN_ID, campaign_stages

NONCE = re.compile(r"^[0-9a-f]{32}$")
EMAIL = re.compile(r"^o1-oob-([0-9a-f]{32})-(?:a|b|absent)@example\.invalid$")
SERVICE_PREFIX = "/identitytoolkit.googleapis.com/v1/"
ENVELOPE_FIELDS = frozenset({"stageId", "project", "nonce", "body", "token", "apiKey", "deadline"})


def _private(value: Any) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        and len(value) <= 8192
        and value.isascii()
        and not any(char.isspace() or ord(char) < 33 or ord(char) == 127 for char in value)
    )


def _expected_stage(stage_id: str) -> dict[str, Any]:
    for stage in campaign_stages():
        if stage["id"] == stage_id:
            return stage
    raise ValueError("unknown Action stage")


def _check_value(expected: Any, actual: Any, nonce: str) -> None:
    if isinstance(expected, str) and expected.startswith("$binding:"):
        if expected.endswith(".email"):
            if not isinstance(actual, str):
                raise ValueError("email binding required")
            match = EMAIL.fullmatch(actual)
            if match is None or match.group(1) != nonce:
                raise ValueError("email binding differs from nonce")
        elif not _private(actual):
            raise ValueError("private binding required")
        return
    if isinstance(expected, dict):
        if not isinstance(actual, dict) or set(actual) != set(expected):
            raise ValueError("body shape differs")
        for key, item in expected.items():
            _check_value(item, actual[key], nonce)
        return
    if isinstance(expected, list):
        if not isinstance(actual, list) or len(actual) != len(expected):
            raise ValueError("body shape differs")
        for left, right in zip(expected, actual, strict=True):
            _check_value(left, right, nonce)
        return
    if actual != expected or type(actual) is not type(expected):
        raise ValueError("body shape differs")


def _validate(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != ENVELOPE_FIELDS:
        raise ValueError("closed Action transport envelope required")
    stage_id, project, nonce = value["stageId"], value["project"], value["nonce"]
    if not isinstance(stage_id, str):
        raise ValueError("unknown Action stage")
    stage = _expected_stage(stage_id)
    if not isinstance(project, str) or not project or "/" in project or "?" in project:
        raise ValueError("project differs")
    if not isinstance(nonce, str) or NONCE.fullmatch(nonce) is None:
        raise ValueError("fresh 32-hex nonce required")
    expected_path = stage["path"].format(project=project)
    if not expected_path.startswith(SERVICE_PREFIX) or "?" in expected_path:
        raise ValueError("Action route differs")
    if stage["routeClass"] not in ("admin", "end-user"):
        raise ValueError("Action route differs")
    if not isinstance(value["body"], dict):
        raise ValueError("body shape differs")
    _check_value(stage["body"], value["body"], nonce)
    if not _private(value["token"]) or not _private(value["apiKey"]):
        raise ValueError("private credential handoff required")
    deadline = value["deadline"]
    if type(deadline) not in (int, float) or isinstance(deadline, bool) or deadline <= time.monotonic():
        raise ValueError("bounded deadline required")
    return {
        "kind": "action-stage",
        # The Action manifest uses an HTTP path; the reviewed credential worker
        # contract deliberately carries a host/path without the leading slash.
        "path": expected_path.lstrip("/"),
        "body": value["body"],
        "owner": stage["routeClass"] == "admin",
    }


def make_transport(*, fixture_origin: str | None = None):
    """Build the capability transport; fixture origin is test-only and explicit."""

    def transport(value, *, binding, binding_digest, capability):
        if fixture_origin is None and isinstance(value, dict) and value.get("fixtureOrigin") is not None:
            raise ValueError("loopback fixture is test-only")
        declared = _validate(value)
        return credential_remote.transmit(
            declared,
            value["body"],
            token=value["token"],
            api_key=value["apiKey"],
            deadline=value["deadline"],
            capability=capability,
            binding=binding,
            binding_digest=binding_digest,
            fixture_origin=fixture_origin,
        )

    return transport


def send(
    capability,
    *,
    stage_id: str,
    project: str,
    nonce: str,
    body: dict[str, Any],
    token: str,
    api_key: str,
    deadline: float,
    binding: bytes,
    binding_digest: str,
) -> tuple[int, dict[str, Any]]:
    """Send one Action slot through a consumed capability and frozen binding."""
    if not hasattr(capability, "_transmit"):
        raise ValueError("O8 capability required")
    if binding != capability._binding or binding_digest != capability.binding_digest:
        raise ValueError("production capability binding differs")
    return capability._transmit(
        {
            "stageId": stage_id,
            "project": project,
            "nonce": nonce,
            "body": body,
            "token": token,
            "apiKey": api_key,
            "deadline": deadline,
        }
    )


__all__ = ["CAMPAIGN_ID", "make_transport", "send"]
