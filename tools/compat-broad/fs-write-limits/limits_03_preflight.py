"""Closed bearer-only identity, metadata and index-exemption attestation for O8.

FS-WRITE-LIMITS-03 runs the request-byte lane's preflight, with one slot of its
own on top: a readback of the single-field index configuration of the exempt
collection group, taken before any data request and again after the last
cleanup. The campaign can only observe the document-name boundary under that
exemption, so the launcher refuses to start unless the readback proves it is in
force, and it records that the exemption still has to be restored afterwards.

This module never discovers, refreshes or replaces credentials. Every slot is
charged by the shared Gate's `management_dispatch` before its transport runs.
"""

from __future__ import annotations

import importlib.util
import math
import re
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "tools/compat-broad"))
sys.path.insert(0, str(ROOT / "tools/compat-broad/fs-write-txn"))
sys.path.insert(0, str(ROOT / "tools/compat-broad/o8-core"))
sys.path.insert(0, str(HERE))

from broad_contract import digest
from compiler_03 import (
    EXEMPT_COLLECTION,
    MANAGEMENT_OBSERVATION_IDS,
    MANAGEMENT_RECOVERY_IDS,
)
from credential_prep import private_string


def _load(name: str, path: Path):
    """Load one reviewed module by exact path, without touching sys.path."""
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ValueError(f"reviewed module unavailable: {name}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# The token attestation, the three metadata attestations and their saved-form
# validators are the request-byte lane's reviewed implementation. They are
# reused by path rather than copied: the shared Gate admits exactly the token
# attestation body that module produces, and the database projection contract
# is the one every shared execution record already publishes.
REQUEST_BYTES_PREFLIGHT = (
    "tools/compat-broad/fs-request-bytes-boundary/request_bytes_preflight.py"
)
shared = _load("_limits_03_request_bytes_preflight", ROOT / REQUEST_BYTES_PREFLIGHT)

SCOPE = shared.SCOPE
PROJECT = shared.PROJECT
NUMBER = shared.NUMBER
DATABASE = shared.DATABASE
INDEX_EXEMPTION_SLOT = "index-exemption"
INDEX_FIELD = f"{DATABASE}/collectionGroups/{EXEMPT_COLLECTION}/fields/*"
INDEX_FIELD_ROUTE = f"https://firestore.googleapis.com/v1/{INDEX_FIELD}"
# What the single-field configuration of the exempt group must read as while
# the declared exemption is deployed: no index of its own and no inherited
# default. Proto3 JSON omits empty and false members, so the projection below
# normalizes the readback before it is compared or digested.
EXPECTED_INDEX_EXEMPTION_PROJECTION = {
    "name": INDEX_FIELD,
    "indexes": [],
    "usesAncestorConfig": False,
    "ancestorField": None,
}
INDEX_EXEMPTION_ATTESTATION_KIND = "limits-03-index-exemption-attestation-v1"
SHARED_SLOTS = ("oauth-tokeninfo", "project", "database", "auth")

validate_principal = shared.validate_principal
verify_token = shared.verify_token
observe_status = shared.observe_status
require_usable = shared.require_usable
credential_evidence = shared.credential_evidence
validate_metadata_attestation = shared.validate_metadata_attestation


def metadata_url(slot):
    if slot == INDEX_EXEMPTION_SLOT:
        return INDEX_FIELD_ROUTE
    return shared.metadata_url(slot)


def index_exemption_projection(body):
    """Normalize one field readback to the members the exemption is judged on."""
    if not isinstance(body, dict) or body.get("name") != INDEX_FIELD:
        raise ValueError("typed index field readback required")
    configuration = body.get("indexConfig", {})
    if not isinstance(configuration, dict):
        raise ValueError("typed index field readback required")
    indexes = configuration.get("indexes", [])
    if not isinstance(indexes, list):
        raise ValueError("typed index field readback required")
    return {
        "name": body["name"],
        "indexes": indexes,
        "usesAncestorConfig": bool(configuration.get("usesAncestorConfig", False)),
        "ancestorField": configuration.get("ancestorField"),
    }


def expected_index_exemption_digest() -> str:
    """The digest of the after state the permission binds and the run requires."""
    return digest(EXPECTED_INDEX_EXEMPTION_PROJECTION)


def verify_index_exemption(body, permission):
    """The exempt group must carry the declared exemption and nothing else."""
    projection = index_exemption_projection(body)
    if (
        projection != EXPECTED_INDEX_EXEMPTION_PROJECTION
        or digest(projection) != permission.get("indexExemptionProjectionDigest")
        or digest(projection) != expected_index_exemption_digest()
    ):
        raise ValueError("index exemption differs from the declared after state")
    return {"slot": INDEX_EXEMPTION_SLOT, "bodyDigest": digest(body), "body": body}


def validate_frozen_baselines(permission):
    """Every baseline digest must be frozen before any management slot is charged."""
    shared.validate_frozen_baselines(permission)
    declared = permission.get("indexExemptionProjectionDigest")
    if not isinstance(declared, str) or re.fullmatch(r"[a-f0-9]{64}", declared) is None:
        raise ValueError("frozen index exemption projection digest required")
    if declared != expected_index_exemption_digest():
        raise ValueError("index exemption digest is not the declared after state")


def management_transport(slot, token, *, deadline, capability, binding, binding_digest):
    """One charged fixed management operation, with a whole-worker deadline."""
    if slot != INDEX_EXEMPTION_SLOT:
        return shared.management_transport(
            slot,
            token,
            deadline=deadline,
            capability=capability,
            binding=binding,
            binding_digest=binding_digest,
        )
    from batch_adapter import wire
    from o8_admission import authorize_transport

    authorize_transport(capability, binding=binding, binding_digest=binding_digest)
    if not private_string(token, 8192):
        raise ValueError("bounded credential required")
    if type(deadline) not in (int, float) or not math.isfinite(deadline):
        raise ValueError("absolute management deadline required")
    duration = min(12.0, deadline - time.monotonic())
    if duration <= 0:
        raise ValueError("management phase deadline")
    try:
        response = wire(
            INDEX_FIELD_ROUTE,
            "GET",
            None,
            {"Authorization": "Bearer " + token, "x-goog-user-project": PROJECT},
            timeout=duration,
            receipt=True,
        )
    except ValueError:
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


def index_exemption_attestation(receipt, permission):
    """Project the field readback to what the receipt may publish.

    A drift, the exemption missing or an index present, is reported as an
    incomplete attestation rather than raised, so the Gate records the failed
    slot durably before the coordinator stops.
    """
    public = {
        key: receipt.get(key) if isinstance(receipt, dict) else None
        for key in ("complete", "workerReaped", "status", "bodyKind")
    }
    body = {
        "kind": INDEX_EXEMPTION_ATTESTATION_KIND,
        "slot": INDEX_EXEMPTION_SLOT,
        "bodyDigest": digest(receipt.get("body"))
        if isinstance(receipt, dict)
        else None,
        "baselineVerified": False,
    }
    try:
        if (
            not isinstance(receipt, dict)
            or receipt.get("complete") is not True
            or receipt.get("workerReaped") is not True
            or type(receipt.get("status")) is not int
            or receipt["status"] != 200
            or receipt.get("bodyKind") != "json"
        ):
            raise ValueError("complete successful JSON field readback required")
        verify_index_exemption(receipt.get("body"), permission)
    except (ValueError, TypeError, KeyError):
        public["complete"] = False
    else:
        body["baselineVerified"] = True
        body["projection"] = index_exemption_projection(receipt["body"])
    public["body"] = body
    return public


def validate_index_exemption_attestation(response, permission):
    """A saved exemption attestation must name the frozen after state."""
    body = response.get("body") if isinstance(response, dict) else None
    if (
        not isinstance(body, dict)
        or body.get("kind") != INDEX_EXEMPTION_ATTESTATION_KIND
        or body.get("slot") != INDEX_EXEMPTION_SLOT
        or body.get("baselineVerified") is not True
        or not isinstance(body.get("bodyDigest"), str)
        or response.get("status") != 200
        or type(response.get("status")) is not int
        or response.get("complete") is not True
        or response.get("workerReaped") is not True
        or response.get("bodyKind") != "json"
        or body.get("projection") != EXPECTED_INDEX_EXEMPTION_PROJECTION
        or digest(body.get("projection"))
        != permission.get("indexExemptionProjectionDigest")
    ):
        raise ValueError("saved index exemption attestation differs")


def validate_attestation(slot, response, permission):
    if slot == INDEX_EXEMPTION_SLOT:
        validate_index_exemption_attestation(response, permission)
    else:
        validate_metadata_attestation(slot, response, permission)


def attestation(slot, response, permission):
    if slot == INDEX_EXEMPTION_SLOT:
        return index_exemption_attestation(response, permission)
    return shared.metadata_attestation(slot, response, permission)


def management_call(inputs, phase, slot_id, secret, *, deadline):
    """Build one closed management value for a Gate-charged dispatch.

    Validation only: it performs no transport, debits nothing and accepts no
    charge marker. The Gate's `management_dispatch` must charge and invoke the
    capability before this value can reach the wire.
    """
    if not isinstance(inputs, dict) or phase not in ("observation", "recovery"):
        raise ValueError("closed management phase required")
    allowed = (
        MANAGEMENT_OBSERVATION_IDS
        if phase == "observation"
        else MANAGEMENT_RECOVERY_IDS
    )
    if slot_id not in allowed:
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


class ManagementSession:
    """Private verified credential plus nine durably charged management slots."""

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
                    management_call(self.inputs, phase, slot, token, deadline=deadline)
                )
                if self.credential is not None:
                    observe_status(self.credential, response.get("status"))
                if slot == "oauth-tokeninfo":
                    # Only this closed call can establish the token/claims
                    # pairing. Nothing from the raw tokeninfo body is saved.
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
                return attestation(slot, response, self.permission)

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
                validate_attestation(slot, response, self.permission)
        if phase == "observation":
            self.preflight_complete = True
        else:
            self.postflight_complete = True

    def data_token(self, deadline):
        if not self.preflight_complete:
            raise ValueError("preflight must precede data")
        return require_usable(self.credential, deadline)


def expected_management_ids() -> list[str]:
    return ["observation:" + slot for slot in MANAGEMENT_OBSERVATION_IDS] + [
        "recovery:" + slot for slot in MANAGEMENT_RECOVERY_IDS
    ]


def validate_saved_management(receipt, snapshot, permission):
    """Bind saved pre/postflight evidence to charged Gate response digests."""
    expected = expected_management_ids()
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
            validate_attestation(slot, response, permission)
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
