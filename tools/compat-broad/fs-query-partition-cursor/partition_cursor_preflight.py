"""Bearer-only identity and metadata attestation for the partition/cursor O8 run.

The management preflight is the request-byte lane's reviewed one: the same four
closed observation slots (`oauth-tokeninfo`, `project`, `database`, `auth`) and
the same three recovery slots, the same claim verification, the same digest-only
attestations. Those helpers are loaded from that lane by exact path and reused
unchanged. What this module adds is the session that drives them for this
campaign's own Gate and Ledger ticket, and the closed value one management wire
call carries, so this lane depends on no other lane's admission module.

Nothing here discovers, refreshes or stores a credential. The token arrives
from the launcher's private handoff, is verified once against the owner-frozen
principal, and is dropped from this object as soon as the verified credential
holds it.
"""

from __future__ import annotations

import importlib.util
import math
import sys
import time
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "tools/compat-broad"))

from broad_contract import digest


def _load(name: str, path: Path):
    """Load one reviewed module by exact path, without touching sys.path."""
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ValueError(f"reviewed module unavailable: {name}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


PREFLIGHT_MODULE = (
    "tools/compat-broad/fs-request-bytes-boundary/request_bytes_preflight.py"
)
request_bytes_preflight = _load(
    "_partition_cursor_request_bytes_preflight", ROOT / PREFLIGHT_MODULE
)

MANAGEMENT_OBSERVATION_IDS = ("oauth-tokeninfo", "project", "database", "auth")
MANAGEMENT_RECOVERY_IDS = ("project", "database", "auth")
SCOPE = request_bytes_preflight.SCOPE
MAX_TOKEN_BYTES = 8192

validate_principal = request_bytes_preflight.validate_principal
validate_frozen_baselines = request_bytes_preflight.validate_frozen_baselines
verify_token = request_bytes_preflight.verify_token
credential_evidence = request_bytes_preflight.credential_evidence
metadata_attestation = request_bytes_preflight.metadata_attestation
validate_metadata_attestation = request_bytes_preflight.validate_metadata_attestation
require_usable = request_bytes_preflight.require_usable
observe_status = request_bytes_preflight.observe_status


def management_transport(slot, token, *, deadline, capability, binding, binding_digest):
    """One charged fixed management operation; the reviewed lane's own worker."""
    return request_bytes_preflight.management_transport(
        slot,
        token,
        deadline=deadline,
        capability=capability,
        binding=binding,
        binding_digest=binding_digest,
    )


def management_call(
    phase: str, slot_id: str, secret: str, *, deadline: float
) -> dict[str, Any]:
    """The closed value one management wire call carries.

    This validates the slot coordinates and returns a value. It performs no
    transport, debits nothing and accepts no caller supplied charge marker; the
    shared Gate's `management_dispatch` charges the slot before the capability
    can carry this value to the wire.
    """
    if phase not in ("observation", "recovery"):
        raise ValueError("closed management phase required")
    allowed = (
        MANAGEMENT_OBSERVATION_IDS
        if phase == "observation"
        else MANAGEMENT_RECOVERY_IDS
    )
    if slot_id not in allowed:
        raise ValueError("undeclared management slot")
    if not isinstance(secret, str) or not secret or len(secret) > MAX_TOKEN_BYTES:
        raise ValueError("bounded management secret required")
    if (
        type(deadline) not in (int, float)
        or isinstance(deadline, bool)
        or not math.isfinite(deadline)
    ):
        raise ValueError("finite management deadline required")
    return {
        "kind": "management",
        "phase": phase,
        "slot": slot_id,
        "token": secret,
        "deadline": deadline,
    }


class ManagementSession:
    """Private verified credential plus seven durably charged management slots."""

    def __init__(self, *, gate, ledger, ticket, capability, permission, token):
        self.gate, self.ledger, self.ticket = gate, ledger, ticket
        self.capability, self.permission = capability, permission
        self._token = token
        self.credential = None
        self.evidence: list[dict[str, Any]] = []
        self.credential_evidence: list[dict[str, Any]] = []
        self.preflight_complete = False
        self.postflight_complete = False
        validate_principal(permission.get("credentialPrincipal"))
        validate_frozen_baselines(permission)

    def run(self, phase: str) -> None:
        if phase not in ("observation", "recovery"):
            raise ValueError("closed management phase required")
        slots = (
            MANAGEMENT_OBSERVATION_IDS
            if phase == "observation"
            else MANAGEMENT_RECOVERY_IDS
        )
        for slot in slots:

            def send(deadline, slot=slot):
                self.ledger.validate(self.ticket, duration=13)
                now = time.monotonic()
                if (
                    now >= deadline
                    or time.time() + (deadline - now) > self.permission["expiresAt"]
                ):
                    raise ValueError("management deadline after shared wait")
                token = (
                    self._token
                    if slot == "oauth-tokeninfo"
                    else require_usable(self.credential, deadline)
                )
                sent = time.monotonic()
                response = self.capability._transmit(
                    management_call(phase, slot, token, deadline=deadline)
                )
                if self.credential is not None:
                    observe_status(self.credential, response.get("status"))
                if slot == "oauth-tokeninfo":
                    # Only this closed call can establish the token/claims pairing.
                    # Nothing from the secret-bearing raw tokeninfo body is saved.
                    public = {
                        key: response.get(key)
                        for key in ("complete", "workerReaped", "status", "bodyKind")
                    }
                    public["body"] = None
                    try:
                        remaining = self.permission["wallSeconds"]
                        self.credential = verify_token(
                            token,
                            response,
                            self.permission["credentialPrincipal"],
                            sent=sent,
                            now=time.monotonic(),
                            required_seconds=remaining,
                        )
                        public["body"] = credential_evidence(
                            response,
                            self.permission["credentialPrincipal"],
                            sent=sent,
                            now=time.monotonic(),
                            required_seconds=remaining,
                        )
                        self.credential_evidence.append(
                            {
                                # The shape the shared Ledger's no-data abort
                                # reads: one row per declared credential slot.
                                "slot": "tokeninfo",
                                "status": 200,
                                "complete": True,
                                "workerReaped": True,
                                "verified": True,
                                "attestation": public["body"],
                            }
                        )
                    except (ValueError, TypeError):
                        public["complete"] = False
                    self._token = None
                    return public
                # Baseline comparison happens before the Gate records the slot,
                # so a drift is durable in the Gate state, not only in memory.
                return metadata_attestation(slot, response, self.permission)

            response = self.gate.management_dispatch(phase, slot, send)
            row = {
                "id": phase + ":" + slot,
                "response": response,
                "responseDigest": digest(response),
            }
            self.evidence.append(row)
            event = self.gate.snapshot()["managementEvents"][-1]
            if event.get("id") != row["id"] or event.get("completed") is not True:
                raise ValueError(
                    "management slot did not complete inside its reservation"
                )
            if slot == "oauth-tokeninfo":
                if self.credential is None or response.get("complete") is not True:
                    raise ValueError("credential attestation failed")
            else:
                validate_metadata_attestation(slot, response, self.permission)
        if phase == "observation":
            self.preflight_complete = True
        else:
            self.postflight_complete = True

    def data_token(self, deadline: float) -> str:
        if not self.preflight_complete:
            raise ValueError("preflight must precede data")
        return require_usable(self.credential, deadline)

    def metadata_rows(self) -> list[dict[str, Any]]:
        """The successful metadata attestations, the shape a no-data abort reads."""
        rows = []
        for row in self.evidence:
            slot = row["id"].split(":", 1)[1]
            response = row["response"]
            if slot == "oauth-tokeninfo" or response.get("status") != 200:
                continue
            rows.append(
                {
                    "id": row["id"],
                    "status": 200,
                    "responseDigest": row["responseDigest"],
                }
            )
        return rows


def validate_saved_management(
    receipt: dict[str, Any], snapshot: dict[str, Any], permission: dict[str, Any]
) -> None:
    """Bind saved pre/postflight evidence to charged Gate response digests."""
    expected = ["observation:" + slot for slot in MANAGEMENT_OBSERVATION_IDS] + [
        "recovery:" + slot for slot in MANAGEMENT_RECOVERY_IDS
    ]
    rows = receipt.get("managementEvidence")
    events = snapshot.get("managementEvents")
    if (
        receipt.get("preflightComplete") is not True
        or receipt.get("postflightComplete") is not True
        or not isinstance(rows, list)
        or not isinstance(events, list)
        or [row.get("id") for row in rows] != expected
        or [event.get("id") for event in events] != expected
    ):
        raise ValueError("complete charged management evidence required")
    for row, event in zip(rows, events, strict=True):
        response = row.get("response")
        if (
            not isinstance(response, dict)
            or row.get("responseDigest") != digest(response)
            or event.get("responseDigest") != digest(response)
            or event.get("bodyDigest") != digest(response.get("body"))
            or event.get("completed") is not True
            or type(event.get("status")) is not int
            or not 200 <= event["status"] < 300
            or event["status"] != response.get("status")
        ):
            raise ValueError("management response binding differs")
        slot = row["id"].split(":", 1)[1]
        if slot != "oauth-tokeninfo":
            validate_metadata_attestation(slot, response, permission)
            continue
        body = response.get("body")
        credential = receipt.get("credentialEvidence")
        if (
            response.get("status") != 200
            or response.get("complete") is not True
            or response.get("workerReaped") is not True
            or response.get("bodyKind") != "json"
            or not isinstance(body, dict)
            or body.get("principalDigest")
            != digest(permission.get("credentialPrincipal"))
            or body.get("requiredSeconds") != permission["wallSeconds"]
            or type(body.get("expiresInSeconds")) is not int
            or not 1 < body["expiresInSeconds"] <= 3600
            or type(body.get("remainingSecondsAtVerification")) not in (int, float)
            or not math.isfinite(body["remainingSecondsAtVerification"])
            or not permission["wallSeconds"]
            <= body["remainingSecondsAtVerification"]
            < body["expiresInSeconds"]
            or credential
            != [
                {
                    "slot": "tokeninfo",
                    "status": 200,
                    "complete": True,
                    "workerReaped": True,
                    "verified": True,
                    "attestation": body,
                }
            ]
        ):
            raise ValueError("saved credential attestation differs")
        validate_principal(permission["credentialPrincipal"])
