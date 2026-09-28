"""Closed bearer-only identity and metadata attestation for request-byte O8.

This module never discovers, refreshes or replaces credentials. Callers must
charge each management slot before invoking its capability-bound transport.
"""

from __future__ import annotations

import math
import re
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE.parent / "fs-write-txn"))
sys.path.insert(0, str(HERE.parent / "o8-core"))

from batch_contract import Credential, database_evidence
from broad_contract import digest
from credential_prep import private_string

SCOPE = "https://www.googleapis.com/auth/cloud-platform"
PROJECT = "fireemu-oracle-sbx"
_PROJECT_NUMBER = re.compile(r"^[1-9][0-9]{5,19}$")
DATABASE = f"projects/{PROJECT}/databases/(default)"
_ROUTES = {
    "project": f"https://cloudresourcemanager.googleapis.com/v1/projects/{PROJECT}",
    "database": f"https://firestore.googleapis.com/v1/{DATABASE}",
    "auth": f"https://identitytoolkit.googleapis.com/admin/v2/projects/{PROJECT}/config",
}


def metadata_url(slot):
    if slot not in _ROUTES:
        raise ValueError("closed metadata slot required")
    return _ROUTES[slot]


def validate_project_number(value):
    if not isinstance(value, str) or _PROJECT_NUMBER.fullmatch(value) is None:
        raise ValueError("owner-bound sandbox project number required")
    return value


def validate_principal(principal):
    if (
        not isinstance(principal, dict)
        or set(principal)
        not in (
            {"clientId", "subject", "requiredScopes"},
            {"clientId", "verifiedEmail", "requiredScopes"},
        )
        or not private_string(principal.get("clientId"), 512)
        or not private_string(
            principal.get("subject", principal.get("verifiedEmail")), 512
        )
        or principal.get("requiredScopes") != [SCOPE]
    ):
        raise ValueError("frozen OAuth client and subject required")


def verify_token(token, receipt, principal, *, sent, now, required_seconds):
    validate_principal(principal)
    if (
        not private_string(token, 8192)
        or not isinstance(receipt, dict)
        or receipt.get("complete") is not True
        or receipt.get("workerReaped") is not True
        or type(receipt.get("status")) is not int
        or receipt["status"] != 200
        or not isinstance(receipt.get("body"), dict)
    ):
        raise ValueError("complete typed token attestation required")
    body = receipt["body"]
    clients = [body[key] for key in ("issued_to", "audience") if key in body]
    seconds = body.get("expires_in")
    if (
        not clients
        or any(value != principal["clientId"] for value in clients)
        or not (
            body.get("user_id") == principal["subject"]
            if "subject" in principal
            else body.get("email") == principal["verifiedEmail"]
            and body.get("verified_email") is True
        )
        or not isinstance(body.get("scope"), str)
        or SCOPE not in body["scope"].split()
        or type(seconds) is not int
        or not 1 < seconds <= 3600
        or any(
            type(value) not in (int, float) or not math.isfinite(value)
            for value in (sent, now, required_seconds)
        )
        or sent > now
        or required_seconds <= 0
    ):
        raise ValueError("credential identity or lifetime differs")
    credential = Credential()
    credential.accept(token, body, sent)
    if not credential.usable(now, required_seconds):
        credential.fail()
        raise ValueError("credential lifetime cannot cover campaign")
    return credential


def observe_status(credential, status):
    if type(status) is int and status in (401, 403):
        credential.fail()


def verify_metadata(slot, body, permission):
    metadata_url(slot)
    if not isinstance(body, dict):
        raise TypeError("typed metadata object required")
    if slot == "project":
        project_number = validate_project_number(permission.get("projectNumber"))
        if (
            body.get("projectId") != PROJECT
            or body.get("projectNumber") != project_number
        ):
            raise ValueError("project identity differs")
    elif slot == "database":
        evidence = database_evidence(body)
        if (
            body["name"] != DATABASE
            or body["type"] != "FIRESTORE_NATIVE"
            or body["databaseEdition"] != "STANDARD"
            or evidence["projectionDigest"]
            != permission.get("databaseProjectionDigest")
        ):
            raise ValueError("database baseline differs")
    elif digest(body) != permission.get("authConfigDigest"):
        raise ValueError("Auth baseline differs")
    return {"slot": slot, "bodyDigest": digest(body), "body": body}


def validate_frozen_baselines(permission):
    """Both baseline digests must be frozen before any management slot is charged."""
    if not isinstance(permission, dict) or any(
        not isinstance(permission.get(key), str)
        or re.fullmatch(r"[a-f0-9]{64}", permission[key]) is None
        for key in ("databaseProjectionDigest", "authConfigDigest")
    ):
        raise ValueError("frozen database projection and Auth config digests required")


def require_usable(credential, deadline):
    now = time.monotonic()
    if (
        not math.isfinite(deadline)
        or deadline <= now
        or not credential.usable(now, deadline - now)
    ):
        raise ValueError("credential unavailable for reserved slot")
    return credential.token


def management_transport(slot, token, *, deadline, capability, binding, binding_digest):
    """One charged fixed management operation, with a whole-worker deadline."""
    from batch_adapter import wire
    from credential_prep import _private_request
    from o8_admission import authorize_transport

    authorize_transport(capability, binding=binding, binding_digest=binding_digest)
    if not private_string(token, 8192):
        raise ValueError("bounded credential required")
    if type(deadline) not in (int, float) or not math.isfinite(deadline):
        raise ValueError("absolute management deadline required")
    duration = min(12.0, deadline - time.monotonic())
    if duration <= 0:
        raise ValueError("management phase deadline")
    # A worker that failed before any HTTP status is a bounded receipt with
    # `status: None`, so the Gate records the charged slot as incomplete and
    # reaped instead of leaving the coordinator in-flight forever.
    if slot == "oauth-tokeninfo":
        result = _private_request("tokeninfo", token, deadline=duration)
        if result.get("complete") is not True:
            # `_management_receipt_valid` in shared_gate.py admits exactly
            # {status, complete, workerReaped, bodyKind, body} for a
            # management receipt -- body must be null when complete is
            # False -- so the failure kind and its diagnostics (declared
            # vs. received bytes, elapsed time, effective socket timeout)
            # cannot travel inside the receipt the Gate charges without a
            # Gate schema change (tracked separately; see the transport
            # diagnosability issue). Until that lands, log them here so a
            # stopped campaign is diagnosable from process output instead
            # of only from an opaque {status:200, complete:false, body:null}
            # receipt. None of these fields carry response or credential
            # bytes.
            print(
                "management_transport oauth-tokeninfo incomplete:"
                f" failure={result.get('failure')!r}"
                f" phase={result.get('phase')!r}"
                f" status={result.get('status')!r}"
                f" workerReaped={result.get('workerReaped')!r}"
                f" receivedBytes={result.get('receivedBytes')!r}"
                f" declaredLength={result.get('declaredLength')!r}"
                f" elapsedSeconds={result.get('elapsedSeconds')!r}"
                f" socketTimeoutSeconds={result.get('socketTimeoutSeconds')!r}"
                f" exceptionClass={result.get('exceptionClass')!r}",
                file=sys.stderr,
            )
        return {
            "complete": result.get("complete") is True,
            "workerReaped": result.get("workerReaped") is True,
            "status": result.get("status"),
            "body": result.get("body"),
            "bodyKind": "json" if isinstance(result.get("body"), dict) else None,
        }
    url = metadata_url(slot)
    try:
        response = wire(
            url,
            "GET",
            None,
            {"Authorization": "Bearer " + token, "x-goog-user-project": PROJECT},
            timeout=duration,
            receipt=True,
        )
    except ValueError:
        # `wire` raises only after `subprocess.run` returned or killed and
        # waited for its worker, so the worker is reaped in both cases.
        return {
            "complete": False,
            "workerReaped": True,
            "status": None,
            "body": None,
            "bodyKind": None,
        }
    http = response.get("http", {}) if isinstance(response, dict) else {}
    return {
        "complete": http.get("complete") is True and http.get("bodyKind") == "json",
        "workerReaped": True,
        "status": http.get("status"),
        "body": response.get("body") if isinstance(response, dict) else None,
        "bodyKind": http.get("bodyKind"),
    }


def credential_evidence(receipt, principal, *, sent, now, required_seconds):
    """Project verified claims; never publish tokeninfo's raw body or token hash."""
    credential = verify_token(
        "redacted",
        receipt,
        principal,
        sent=sent,
        now=now,
        required_seconds=required_seconds,
    )
    return {
        "kind": "request-byte-token-attestation-v1",
        "principalDigest": digest(principal),
        "requiredScopeVerified": True,
        "identityMode": "subject" if "subject" in principal else "verified-email",
        "identityVerified": True,
        "oauthClientVerified": True,
        "expiresInSeconds": receipt["body"]["expires_in"],
        "remainingSecondsAtVerification": credential.expiry - now,
        "requiredSeconds": required_seconds,
        "complete": True,
        "workerReaped": True,
    }


def verify_metadata_receipt(slot, receipt, permission):
    """Validate transport completion before inspecting baseline attributes."""
    if (
        not isinstance(receipt, dict)
        or receipt.get("complete") is not True
        or receipt.get("workerReaped") is not True
        or type(receipt.get("status")) is not int
        or receipt["status"] != 200
        or receipt.get("bodyKind") != "json"
        or not isinstance(receipt.get("body"), dict)
    ):
        raise ValueError("complete successful JSON metadata receipt required")
    return verify_metadata(slot, receipt["body"], permission)


def metadata_attestation(slot, receipt, permission):
    """Project a metadata receipt to what the receipt may publish.

    The raw project and Auth config bodies are never published: the Auth admin
    config carries API keys, SMTP settings and blocking-function URIs. What is
    kept is the slot, the body digest and, for the database, the same
    projection the shared execution records already publish. A baseline drift
    is reported as an incomplete attestation rather than raised, so the Gate
    records the failed slot durably before the coordinator stops.
    """
    public = {
        key: receipt.get(key) if isinstance(receipt, dict) else None
        for key in ("complete", "workerReaped", "status", "bodyKind")
    }
    body = {
        "kind": "request-byte-metadata-attestation-v1",
        "slot": slot,
        "bodyDigest": digest(receipt.get("body"))
        if isinstance(receipt, dict)
        else None,
        "baselineVerified": False,
    }
    try:
        verify_metadata_receipt(slot, receipt, permission)
    except (ValueError, TypeError, KeyError):
        public["complete"] = False
    else:
        body["baselineVerified"] = True
        if slot == "project":
            body["projectNumberDigest"] = digest(
                {"projectNumber": validate_project_number(permission.get("projectNumber"))}
            )
        elif slot == "database":
            body["projection"] = database_evidence(receipt["body"])["projection"]
    public["body"] = body
    return public


def validate_metadata_attestation(slot, response, permission):
    """A saved metadata attestation must name its slot and its frozen baseline."""
    body = response.get("body") if isinstance(response, dict) else None
    if (
        not isinstance(body, dict)
        or body.get("kind") != "request-byte-metadata-attestation-v1"
        or body.get("slot") != slot
        or body.get("baselineVerified") is not True
        or not isinstance(body.get("bodyDigest"), str)
        or response.get("status") != 200
        or type(response.get("status")) is not int
        or response.get("complete") is not True
        or response.get("workerReaped") is not True
        or response.get("bodyKind") != "json"
    ):
        raise ValueError("saved metadata attestation differs")
    if slot == "auth" and body["bodyDigest"] != permission.get("authConfigDigest"):
        raise ValueError("saved Auth baseline differs")
    if slot == "project":
        project_number = validate_project_number(permission.get("projectNumber"))
        if body.get("projectNumberDigest") != digest(
            {"projectNumber": project_number}
        ):
            raise ValueError("project metadata binding differs")
    elif slot == "database":
        projection = body.get("projection")
        if (
            not isinstance(projection, dict)
            or digest(projection) != permission.get("databaseProjectionDigest")
            or projection.get("name") != DATABASE
        ):
            raise ValueError("saved database baseline differs")
    elif "projection" in body:
        raise ValueError("saved metadata attestation differs")


class ManagementSession:
    """Private verified credential plus seven durably charged management slots."""

    def __init__(self, *, gate, ledger, ticket, capability, inputs, permission, token):
        self.gate, self.ledger, self.ticket = gate, ledger, ticket
        self.capability, self.inputs, self.permission = capability, inputs, permission
        self._token = token
        self.credential = None
        self.evidence = []
        self.credential_evidence = []
        self.preflight_complete = False
        self.postflight_complete = False
        validate_principal(permission.get("credentialPrincipal"))
        validate_frozen_baselines(permission)

    def run(self, phase):
        import request_bytes_admission as admission

        if phase not in ("observation", "recovery"):
            raise ValueError("closed management phase required")
        slots = (
            ("oauth-tokeninfo", "project", "database", "auth")
            if phase == "observation"
            else ("project", "database", "auth")
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
                    admission.management_call(
                        self.inputs, phase, slot, token, deadline=deadline
                    )
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
                        self.credential_evidence.append(public["body"])
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

    def data_token(self, deadline):
        if not self.preflight_complete:
            raise ValueError("preflight must precede data")
        return require_usable(self.credential, deadline)


def validate_saved_management(receipt, snapshot, permission):
    """Bind saved pre/postflight evidence to charged Gate response digests."""
    expected = [
        "observation:" + slot
        for slot in ("oauth-tokeninfo", "project", "database", "auth")
    ] + ["recovery:" + slot for slot in ("project", "database", "auth")]
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
        if (
            response.get("status") != 200
            or type(response.get("status")) is not int
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
            or receipt.get("credentialEvidence") != [body]
        ):
            raise ValueError("saved credential attestation differs")
        validate_principal(permission["credentialPrincipal"])
