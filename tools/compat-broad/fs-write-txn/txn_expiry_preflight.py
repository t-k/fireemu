"""Bearer-only identity and metadata attestation for the transaction expiry O8.

The seven management slots are the request-byte lane's: one `tokeninfo` call
that binds the bearer to the owner-frozen principal, then project, database
and Auth configuration readbacks before any data request and again after
cleanup. The attestation, verification and transport functions are that
lane's reviewed ones, loaded by path; what is local here is the session that
drives them through this campaign's Gate and Ledger, because the request-byte
session builds its wire values through the request-byte admission module and
that module's closure is not this campaign's.

This module never discovers, refreshes or replaces a credential. Every slot is
charged by the shared Gate before its transport runs, and the raw tokeninfo
body is never journaled: only the projected attestation is.
"""

from __future__ import annotations

import math
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "tools/compat-broad"))
sys.path.insert(0, str(HERE))

from broad_contract import digest


def _load(name, path):
    """Load one reviewed module by exact path, without touching sys.path."""
    import importlib.util

    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ValueError(f"reviewed module unavailable: {name}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


PREFLIGHT_ENTRY = (
    "tools/compat-broad/fs-request-bytes-boundary/request_bytes_preflight.py"
)
preflight = _load("_txn_expiry_request_bytes_preflight", ROOT / PREFLIGHT_ENTRY)

SCOPE = preflight.SCOPE
OBSERVATION_SLOTS = ("oauth-tokeninfo", "project", "database", "auth")
RECOVERY_SLOTS = ("project", "database", "auth")
CREDENTIAL_IDS = ("oauth-tokeninfo",)
CREDENTIAL_SLOTS = ("tokeninfo",)
SLOT_SECONDS = 13.0
SLOT_DURATION_SECONDS = 12.0
VERSION = "txn-expiry-preflight-v1"

validate_principal = preflight.validate_principal
validate_frozen_baselines = preflight.validate_frozen_baselines
validate_metadata_attestation = preflight.validate_metadata_attestation
metadata_url = preflight.metadata_url


def management_call(phase, slot_id, secret, *, deadline):
    """Build one closed management value for a Gate-charged dispatch.

    This only validates the slot coordinates and returns a value. It performs
    no transport, debits nothing and accepts no caller supplied charge marker;
    the Gate's `management_dispatch` charges the slot and the admitted
    capability carries the value to the wire.
    """
    allowed = OBSERVATION_SLOTS if phase == "observation" else RECOVERY_SLOTS
    if phase not in ("observation", "recovery") or slot_id not in allowed:
        raise ValueError("undeclared management slot")
    if not isinstance(secret, str) or not secret or len(secret) > 8192:
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


def management_transport(value, *, capability, binding, binding_digest):
    """One charged fixed management operation through the reviewed transport."""
    if not isinstance(value, dict) or set(value) != {
        "kind",
        "phase",
        "slot",
        "token",
        "deadline",
    }:
        raise ValueError("closed management wire call required")
    if value["kind"] != "management" or value["phase"] not in (
        "observation",
        "recovery",
    ):
        raise ValueError("closed management wire call required")
    return preflight.management_transport(
        value["slot"],
        value["token"],
        deadline=value["deadline"],
        capability=capability,
        binding=binding,
        binding_digest=binding_digest,
    )


def contract():
    """The declarative management contract the permission and Gate plan carry."""
    return {
        "version": VERSION,
        "dispatchKind": "closed-v1",
        "observation": list(OBSERVATION_SLOTS),
        "recovery": list(RECOVERY_SLOTS),
        "credentialIds": list(CREDENTIAL_IDS),
        "credentialSlots": list(CREDENTIAL_SLOTS),
        "slotSeconds": SLOT_SECONDS,
        "durationSeconds": SLOT_DURATION_SECONDS,
        "totalRequests": len(OBSERVATION_SLOTS) + len(RECOVERY_SLOTS),
        "principal": {
            "alternatives": [
                ["clientId", "subject", "requiredScopes"],
                ["clientId", "verifiedEmail", "requiredScopes"],
            ],
            "requiredScopes": [SCOPE],
        },
        "source": PREFLIGHT_ENTRY,
    }


def gate_management(interval_seconds, *, observation_window, recovery_window):
    """The closed-v1 management block of the Gate plan."""

    def entries(slots):
        return [
            {
                "id": item,
                "seconds": SLOT_SECONDS,
                "duration": SLOT_DURATION_SECONDS,
                "timeout": SLOT_SECONDS,
            }
            for item in slots
        ]

    return {
        "dispatchKind": "closed-v1",
        "observation": entries(OBSERVATION_SLOTS),
        "recovery": entries(RECOVERY_SLOTS),
        "credentialIds": list(CREDENTIAL_IDS),
        "credentialSlots": list(CREDENTIAL_SLOTS),
        "slotSeconds": SLOT_SECONDS,
        "intervalSeconds": interval_seconds,
        "totalRequests": len(OBSERVATION_SLOTS) + len(RECOVERY_SLOTS),
        "phaseSeconds": {
            "observation": len(OBSERVATION_SLOTS) * (SLOT_SECONDS + interval_seconds),
            "recovery": len(RECOVERY_SLOTS) * (SLOT_SECONDS + interval_seconds),
        },
        "observationWindowSeconds": observation_window,
        "recoveryWindowSeconds": recovery_window,
        "principalBinding": {
            "alternatives": [
                ["clientId", "subject", "requiredScopes"],
                ["clientId", "verifiedEmail", "requiredScopes"],
            ],
            "claims": [
                "issued_to",
                "audience",
                "user_id",
                "email",
                "verified_email",
                "scope",
                "expires_in",
            ],
        },
        "permissionExpiryBound": True,
    }


def phase_seconds(interval_seconds):
    return {
        "observation": len(OBSERVATION_SLOTS) * (SLOT_SECONDS + interval_seconds),
        "recovery": len(RECOVERY_SLOTS) * (SLOT_SECONDS + interval_seconds),
    }


class ManagementSession:
    """Private verified credential plus seven durably charged management slots."""

    def __init__(self, *, gate, ledger, ticket, transmit, permission, token):
        """`transmit` is the admitted capability's bound wire in production and
        an injected, production-unreachable callable in the credential-free
        rehearsal; the session never chooses between them."""
        if not callable(transmit):
            raise ValueError("bound management transmit required")  # noqa: TRY004 -- admission boundary collapses malformed input to one refusal class
        self.gate, self.ledger, self.ticket = gate, ledger, ticket
        self.transmit, self.permission = transmit, permission
        self._token = token
        self.credential = None
        self.evidence = []
        self.credential_evidence = []
        self.preflight_complete = False
        self.postflight_complete = False
        validate_principal(permission.get("credentialPrincipal"))
        validate_frozen_baselines(permission)

    def run(self, phase):
        if phase not in ("observation", "recovery"):
            raise ValueError("closed management phase required")
        slots = OBSERVATION_SLOTS if phase == "observation" else RECOVERY_SLOTS
        for slot in slots:

            def send(deadline, slot=slot):
                self.ledger.validate(self.ticket, duration=int(SLOT_SECONDS))
                now = time.monotonic()
                if (
                    now >= deadline
                    or time.time() + (deadline - now) > self.permission["expiresAt"]
                ):
                    raise ValueError("management deadline after shared wait")
                token = (
                    self._token
                    if slot == "oauth-tokeninfo"
                    else preflight.require_usable(self.credential, deadline)
                )
                sent = time.monotonic()
                response = self.transmit(
                    management_call(phase, slot, token, deadline=deadline)
                )
                if self.credential is not None:
                    preflight.observe_status(self.credential, response.get("status"))
                if slot == "oauth-tokeninfo":
                    # Only this closed call can establish the token/claims
                    # pairing. Nothing from the secret-bearing raw body is kept.
                    public = {
                        key: response.get(key)
                        for key in ("complete", "workerReaped", "status", "bodyKind")
                    }
                    public["body"] = None
                    try:
                        remaining = self.permission["wallSeconds"]
                        self.credential = preflight.verify_token(
                            token,
                            response,
                            self.permission["credentialPrincipal"],
                            sent=sent,
                            now=time.monotonic(),
                            required_seconds=remaining,
                        )
                        public["body"] = preflight.credential_evidence(
                            response,
                            self.permission["credentialPrincipal"],
                            sent=sent,
                            now=time.monotonic(),
                            required_seconds=remaining,
                        )
                        self.credential_evidence.append(public["body"])
                    except (ValueError, TypeError):
                        public["complete"] = False
                    self._token = None
                    return public
                # The baseline comparison happens before the Gate records the
                # slot, so a drift is durable in the Gate state.
                return preflight.metadata_attestation(slot, response, self.permission)

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

    def data_token(self, deadline):
        if not self.preflight_complete:
            raise ValueError("preflight must precede data")
        return preflight.require_usable(self.credential, deadline)


def validate_saved_management(receipt, snapshot, permission):
    """Bind saved pre/postflight evidence to charged Gate response digests."""
    expected = ["observation:" + slot for slot in OBSERVATION_SLOTS] + [
        "recovery:" + slot for slot in RECOVERY_SLOTS
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
    attestations = []
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
        ):
            raise ValueError("saved credential attestation differs")
        attestations.append(body)
        validate_principal(permission["credentialPrincipal"])
    if receipt.get("credentialAttestations") != attestations:
        raise ValueError("saved credential attestation differs")
