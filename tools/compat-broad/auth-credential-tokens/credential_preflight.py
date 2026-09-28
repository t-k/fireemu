"""Closed management slots for the AUTH-CREDENTIAL production run.

Before any data request the run charges, through the shared Gate, an identity
attestation of the owner's bearer (tokeninfo), a project identity readback and an
Auth admin config readback whose digest the permission froze; after cleanup it
reads the Auth config back once more to show the run changed nothing. When the
handoff carries a signing capability, the three custom tokens the campaign needs are
minted through `signBlob` as further charged slots before the data phase, so every
wire call of the run is a Gate slot.

The tokeninfo, project and Auth-config slots are the request-byte lane's reviewed
attestations, reused rather than restated: their receipt shapes are what the shared
Gate admits for a management slot. The raw Auth config body is never published; only
its digest is compared and kept.
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
sys.path.insert(0, str(ROOT / "tools/compat-broad/o8-core"))
sys.path.insert(0, str(HERE))

import credential_shadow as shadow
from broad_contract import digest
from credential_gate import (
    SHARED_MANAGEMENT_IDS,
    SIGN_MANAGEMENT_IDS,
    account_identifier,
    management_ids,
)


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ValueError(f"reviewed module unavailable: {name}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


SHARED_PREFLIGHT_MODULE = (
    "tools/compat-broad/fs-request-bytes-boundary/request_bytes_preflight.py"
)
shared_preflight = _load("_credential_shared_preflight", ROOT / SHARED_PREFLIGHT_MODULE)

SCOPE = shared_preflight.SCOPE
PROJECT = shared_preflight.PROJECT
SHARED_SLOTS = SHARED_MANAGEMENT_IDS
SIGN_SLOTS = SIGN_MANAGEMENT_IDS
SIGN_KINDS = {
    "sign-developer": "developer",
    "sign-reserved": "reserved",
    "sign-expired": "expired",
}
SIGNATURE_KIND = "custom-token-signature-v1"


class CredentialRefused(ValueError):
    """The bearer was refused by a privileged call; no later slot may present it."""


class ApiKeyRefused(ValueError):
    """A Web API key call was refused; the bearer is untouched and cleanup may run."""


def validate_frozen_baseline(permission: Any) -> None:
    """The Auth config digest must be frozen before the slot that reads it is charged."""
    if not isinstance(permission, dict) or not isinstance(
        permission.get("authConfigDigest"), str
    ):
        raise ValueError("frozen Auth config digest required")  # noqa: TRY004 -- refusal class, not a type report
    if len(permission["authConfigDigest"]) != 64:
        raise ValueError("frozen Auth config digest required")


def validate_principal(principal: Any) -> None:
    shared_preflight.validate_principal(principal)


def modern_management_transport(slot, token, *, deadline, fixture_origin=None):
    """Use the pinned Auth worker and normalize the modern tokeninfo schema."""
    import credential_bootstrap as bootstrap
    import credential_remote_transport as remote

    operation = {
        "oauth-tokeninfo": "tokeninfo",
        "project": "project",
        "auth": "auth",
    }.get(slot)
    if operation is None:
        raise ValueError("closed management slot required")
    try:
        exchange = bootstrap._request(
            operation, token, deadline=deadline, fixture_origin=fixture_origin
        )
    except remote.WorkerFailure as error:
        if not error.worker_reaped:
            raise
        return {
            "status": None,
            "complete": False,
            "workerReaped": True,
            "bodyKind": None,
            "body": None,
        }
    body = exchange.body
    if slot == "oauth-tokeninfo" and exchange.status == 200:
        expiry = body.get("expires_in")
        if isinstance(expiry, str) and expiry.isascii() and expiry.isdecimal():
            expiry = int(expiry)
        body = {
            "issued_to": body.get("azp"),
            "audience": body.get("aud"),
            "user_id": body.get("sub"),
            "email": body.get("email"),
            "verified_email": body.get("email_verified") == "true",
            "scope": body.get("scope"),
            "expires_in": expiry,
        }
    return {
        "status": exchange.status,
        "complete": exchange.status == 200,
        "workerReaped": exchange.worker_reaped,
        "bodyKind": "json",
        "body": body,
    }


def signature_attestation(public: Any) -> dict[str, Any]:
    """What a signing slot publishes: the shape of the signature, never the token."""
    if (
        not isinstance(public, dict)
        or public.get("kind") != SIGNATURE_KIND
        or public.get("status") != 200
        or type(public.get("signatureBytes")) is not int
        or public["signatureBytes"] <= 0
        or not isinstance(public.get("payloadDigest"), str)
    ):
        raise ValueError("typed signature attestation required")
    return {
        "status": 200,
        "complete": True,
        "workerReaped": True,
        "bodyKind": "json",
        "body": {
            "kind": SIGNATURE_KIND,
            "algorithm": public.get("algorithm"),
            "signatureBytes": public["signatureBytes"],
            "keyIdPresent": public.get("keyIdPresent") is True,
            "payloadDigest": public["payloadDigest"],
        },
    }


class ManagementSession:
    """The bearer, the minted custom tokens and the charged management slots.

    The bearer is verified by the tokeninfo slot against the principal the owner
    froze; nothing from the raw tokeninfo body is kept. The minted custom tokens
    live in memory until the runner asks for them by kind and are never journaled.
    """

    def __init__(
        self,
        *,
        gate,
        ledger,
        ticket,
        capability,
        inputs,
        permission,
        handoff,
        binding,
        binding_digest,
        transmit=None,
        reservation_deadline=None,
        monotonic_deadline=None,
        source_check=None,
    ):
        self.gate, self.ledger, self.ticket = gate, ledger, ticket
        self.capability, self.inputs, self.permission = capability, inputs, permission
        self.binding, self.binding_digest = binding, binding_digest
        self._token = handoff["token"]
        self._api_key = handoff["apiKey"]
        self.signing = handoff.get("signing")
        self.credential = None
        self.evidence: list[dict[str, Any]] = []
        self.credential_evidence: list[dict[str, Any]] = []
        self.signature_evidence: list[dict[str, Any]] = []
        self.preflight_complete = False
        self.postflight_complete = False
        self._minted: dict[str, str] = {}
        self._transmit = transmit
        self.reservation_deadline = reservation_deadline
        self.monotonic_deadline = monotonic_deadline
        self.source_check = source_check
        validate_principal(permission.get("credentialPrincipal"))
        validate_frozen_baseline(permission)
        if bool(self.signing) != bool(inputs["plan"].get("signing")):
            raise ValueError("signing capability differs from the frozen plan")

    @property
    def signs(self) -> bool:
        return self.signing is not None

    def _shared_call(
        self, phase: str, slot: str, token: str, deadline: float
    ) -> dict[str, Any]:
        if self._transmit is not None:
            return self._transmit(
                {
                    "kind": "management",
                    "phase": phase,
                    "slot": slot,
                    "token": token,
                    "deadline": deadline,
                }
            )
        return self.capability._transmit(
            {
                "kind": "management",
                "phase": phase,
                "slot": slot,
                "token": token,
                "deadline": deadline,
            }
        )

    def _sign(self, slot: str, deadline: float) -> dict[str, Any]:
        kind = SIGN_KINDS[slot]
        payload = shadow.custom_token_payload(
            kind,
            self.signing["serviceAccount"],
            account_identifier(self.inputs["plan"]["nonce"], "custom"),
            int(time.time()),
        )
        value = {
            "kind": "sign",
            "payload": payload,
            "serviceAccount": self.signing["serviceAccount"],
            "token": shared_preflight.require_usable(self.credential, deadline),
            "deadline": deadline,
        }
        token, public = (
            self._transmit(value)
            if self._transmit is not None
            else self.capability._transmit(value)
        )
        if not isinstance(token, str) or token.count(".") != 2:
            raise ValueError("signing slot returned no compact token")
        self._minted[kind] = token
        return signature_attestation(public)

    def run(self, phase: str) -> None:
        if phase not in ("observation", "recovery"):
            raise ValueError("closed management phase required")
        slots = management_ids(self.signs)[phase]
        for slot in slots:

            def send(deadline, slot=slot):
                if self.source_check is not None:
                    self.source_check()
                self.ledger.validate(
                    self.ticket,
                    duration=13
                    + (
                        60
                        if self.reservation_deadline is not None
                        and phase == "observation"
                        else 0
                    ),
                )
                if self.reservation_deadline is not None:
                    remaining = min(
                        self.reservation_deadline - time.time(),
                        self.monotonic_deadline - time.monotonic(),
                    ) - (60 if phase == "observation" else 0)
                    deadline = min(deadline, time.monotonic() + remaining)
                    deadline = min(
                        deadline,
                        time.monotonic()
                        + self.capability.window_expires_at
                        - time.time(),
                    )
                now = time.monotonic()
                if (
                    now >= deadline
                    or time.time() + (deadline - now) > self.permission["expiresAt"]
                ):
                    raise ValueError("management deadline after shared wait")
                if slot in SIGN_SLOTS:
                    return self._sign(slot, deadline)
                token = (
                    self._token
                    if slot == "oauth-tokeninfo"
                    else shared_preflight.require_usable(self.credential, deadline)
                )
                sent = time.monotonic()
                response = self._shared_call(phase, slot, token, deadline)
                if self.credential is not None:
                    shared_preflight.observe_status(
                        self.credential, response.get("status")
                    )
                if slot == "oauth-tokeninfo":
                    public = {
                        key: response.get(key)
                        for key in ("complete", "workerReaped", "status", "bodyKind")
                    }
                    public["body"] = None
                    try:
                        verified_monotonic, verified_at = time.monotonic(), time.time()
                        remaining = (
                            self.permission["wallSeconds"]
                            if self.reservation_deadline is None
                            else max(
                                self.reservation_deadline - verified_at,
                                self.monotonic_deadline - verified_monotonic,
                            )
                        )
                        self.credential = shared_preflight.verify_token(
                            token,
                            response,
                            self.permission["credentialPrincipal"],
                            sent=sent,
                            now=verified_monotonic,
                            required_seconds=remaining,
                        )
                        public["body"] = shared_preflight.credential_evidence(
                            response,
                            self.permission["credentialPrincipal"],
                            sent=sent,
                            now=verified_monotonic,
                            required_seconds=remaining,
                        )
                        self.credential_evidence.append(public["body"])
                    except (ValueError, TypeError):
                        public["complete"] = False
                    self._token = None
                    return public
                return shared_preflight.metadata_attestation(
                    slot, response, self.permission
                )

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
            elif slot in SIGN_SLOTS:
                self.signature_evidence.append(response["body"])
            else:
                shared_preflight.validate_metadata_attestation(
                    slot, response, self.permission
                )
        if phase == "observation":
            self.preflight_complete = True
        else:
            self.postflight_complete = True

    def observe_status(self, declared: dict[str, Any], status: Any) -> None:
        """Classify a refusal by the credential the slot presented.

        Only an owner slot carries the bearer; a 401 or 403 there latches it, so no
        later slot, data or cleanup, presents it again. Every other slot carries the
        Web API key, and a refusal there is the key's: the observation stops, but the
        bearer is untouched and the cleanup that needs it still runs.
        """
        if type(status) is not int or status not in (401, 403):
            return
        if declared.get("owner") is True:
            if self.credential is not None:
                shared_preflight.observe_status(self.credential, status)
            raise CredentialRefused("privileged call refused; bearer latched")
        raise ApiKeyRefused("API-key call refused; observation stopped")

    def require_bearer(self, declared: dict[str, Any]) -> None:
        """Refuse an owner slot before it is charged when the bearer is latched."""
        if declared.get("owner") is True and (
            self.credential is None or self.credential.failed
        ):
            raise CredentialRefused("bearer latched; slot not attempted")

    def data_token(self, deadline: float) -> str:
        if not self.preflight_complete:
            raise ValueError("preflight must precede data")
        if self.credential is None or self.credential.failed:
            raise CredentialRefused("bearer latched; slot not attempted")
        return shared_preflight.require_usable(self.credential, deadline)

    def api_key(self) -> str:
        if not self.preflight_complete:
            raise ValueError("preflight must precede data")
        return self._api_key

    def signer(self, kind: str, _payload: dict[str, Any]) -> str:
        """The runner's signer: the token minted for this kind during preflight."""
        if not self.preflight_complete or kind not in self._minted:
            raise ValueError("custom token was not minted during preflight")
        return self._minted[kind]

    def forget(self) -> list[str]:
        """Drop every secret this session held; the values are returned only so the
        caller can refuse any evidence record that still carries one of them."""
        held = [
            value
            for value in (self._token, self._api_key, *self._minted.values())
            if value
        ]
        if self.credential is not None:
            if self.credential.token:
                held.append(self.credential.token)
            self.credential.fail()
        self._token = None
        self._api_key = None
        self._minted = {}
        return held


def validate_saved_management(
    receipt: dict[str, Any],
    snapshot: dict[str, Any],
    permission: dict[str, Any],
    *,
    signing: bool,
) -> None:
    """Bind saved pre/postflight evidence to the charged Gate response digests."""
    ids = management_ids(signing)
    expected = ["observation:" + slot for slot in ids["observation"]] + [
        "recovery:" + slot for slot in ids["recovery"]
    ]
    rows = receipt.get("managementEvidence")
    events = snapshot.get("managementEvents")
    proof = receipt.get("preparationProof")
    if proof is not None:
        from credential_gate import bootstrap_management_ids

        prefix = ["observation:" + slot for slot in bootstrap_management_ids()]
        if (
            not isinstance(events, list)
            or [event.get("id") for event in events[:4]] != prefix
            or proof.get("managementJournalDigest") != digest(events[:4])
        ):
            raise ValueError("saved preparation prefix differs")
        for row, event in zip(
            proof.get("managementEvidence", []), events[:4], strict=True
        ):
            response = row.get("response")
            if (
                row.get("id") != event.get("id")
                or event.get("responseDigest") != digest(response)
                or event.get("bodyDigest") != digest(response.get("body"))
                or event.get("completed") is not True
                or event.get("workerReaped") is not True
            ):
                raise ValueError("saved preparation response differs")
        events = events[4:]
    if (
        receipt.get("preflightComplete") is not True
        or receipt.get("postflightComplete") is not True
        or not isinstance(rows, list)
        or not isinstance(events, list)
        or [row.get("id") for row in rows] != expected
        or [event.get("id") for event in events] != expected
    ):
        raise ValueError("complete charged management evidence required")
    signatures = []
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
        if slot in SIGN_SLOTS:
            body = response.get("body")
            if not isinstance(body, dict) or body.get("kind") != SIGNATURE_KIND:
                raise ValueError("saved signature attestation differs")
            signatures.append(body)
            continue
        if slot != "oauth-tokeninfo":
            shared_preflight.validate_metadata_attestation(slot, response, permission)
            continue
        body = response.get("body")
        if (
            not isinstance(body, dict)
            or body.get("principalDigest")
            != digest(permission.get("credentialPrincipal"))
            or (
                proof is None
                and body.get("requiredSeconds") != permission["wallSeconds"]
            )
            or (
                proof is not None
                and (
                    type(body.get("requiredSeconds")) not in (int, float)
                    or not math.isfinite(body["requiredSeconds"])
                    or not proof["reservationMonotonicDeadline"] - event["ended"]
                    <= body["requiredSeconds"]
                    <= permission["wallSeconds"]
                    or body.get("remainingSecondsAtVerification", 0)
                    < body["requiredSeconds"]
                )
            )
            or type(body.get("remainingSecondsAtVerification")) not in (int, float)
            or not math.isfinite(body["remainingSecondsAtVerification"])
            or receipt.get("credentialEvidence") != [body]
        ):
            raise ValueError("saved credential attestation differs")
    if receipt.get("signatureEvidence") != signatures:
        raise ValueError("saved signature evidence differs")


__all__ = [
    "ApiKeyRefused",
    "CredentialRefused",
    "ManagementSession",
    "management_ids",
    "signature_attestation",
    "validate_frozen_baseline",
    "validate_saved_management",
]
