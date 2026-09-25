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
DATABASE = shared.DATABASE
INDEX_EXEMPTION_SLOT = "index-exemption"
LIFECYCLE_OBSERVATION_SLOTS = (
    "index-lifecycle-before",
    "index-lifecycle-apply",
    "index-lifecycle-poll",
    "index-lifecycle-after",
)
LIFECYCLE_RECOVERY_SLOTS = (
    "index-lifecycle-restore",
    "index-lifecycle-poll-restore",
    "index-lifecycle-restored",
)
LIFECYCLE_SLOTS = LIFECYCLE_OBSERVATION_SLOTS + LIFECYCLE_RECOVERY_SLOTS
LIFECYCLE_FIELD = "projects/fireemu-35fe6/databases/(default)/collectionGroups/nx/fields/*"
LIFECYCLE_ROUTE = "https://firestore.googleapis.com/v1/" + LIFECYCLE_FIELD
INDEX_FIELD = f"{DATABASE}/collectionGroups/{EXEMPT_COLLECTION}/fields/*"
INDEX_FIELD_ROUTE = f"https://firestore.googleapis.com/v1/{INDEX_FIELD}"
# The field every collection group inherits its single-field configuration
# from. The Admin API populates `indexConfig.ancestorField` in both cases: the
# field the group inherits from while `usesAncestorConfig` is true, or the
# field it would inherit from once the override is removed. The observed
# production readback of `collectionGroups/pk/fields/*`, which carries the
# identical override (2026-09-21), is exactly the name and this ancestor, with
# `indexes` and `usesAncestorConfig` omitted as proto3 defaults.
DEFAULT_ANCESTOR_FIELD = f"{DATABASE}/collectionGroups/__default__/fields/*"
# What the single-field configuration of the exempt group must read as while
# the declared exemption is deployed: no index of its own (absent or empty),
# not inheriting the default (absent or false), and naming the default as the
# ancestor it would otherwise inherit from. Anything else is refused.
EXPECTED_INDEX_EXEMPTION_PROJECTION = {
    "name": INDEX_FIELD,
    "indexes": [],
    "usesAncestorConfig": False,
    "ancestorField": DEFAULT_ANCESTOR_FIELD,
}
# What the same field must read as once the exemption is restored: the
# inherited default again, named as such. The inherited index list is the
# project's default and is recorded, not judged.
EXPECTED_INDEX_RESTORED_PROJECTION = {
    "name": INDEX_FIELD,
    "usesAncestorConfig": True,
    "ancestorField": DEFAULT_ANCESTOR_FIELD,
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


def _field_readback(body, field=INDEX_FIELD):
    """The normalized members of one field readback, each checked on its own.

    Proto3 JSON omits an empty `indexes` list and a false `usesAncestorConfig`,
    so both are normalized from absent; the ancestor must be the database's
    default wildcard field, which the API names in either state.
    """
    if not isinstance(body, dict) or body.get("name") != field:
        raise ValueError("typed index field readback required")
    configuration = body.get("indexConfig", {})
    if not isinstance(configuration, dict):
        raise ValueError("typed index field readback required")  # noqa: TRY004
    indexes = configuration.get("indexes", [])
    if not isinstance(indexes, list):
        raise ValueError("typed index field readback required")  # noqa: TRY004
    uses_ancestor = configuration.get("usesAncestorConfig", False)
    if uses_ancestor is not True and uses_ancestor is not False:
        raise ValueError("typed index field readback required")
    ancestor = configuration.get("ancestorField")
    if ancestor != DEFAULT_ANCESTOR_FIELD:
        raise ValueError("index field does not name the default ancestor")
    return {
        "name": body["name"],
        "indexes": indexes,
        "usesAncestorConfig": uses_ancestor,
        "ancestorField": ancestor,
    }


def index_exemption_projection(body):
    """Normalize one field readback to the members the exemption is judged on.

    The exemption holds when the group has no index of its own, does not
    inherit the default, and names the default as its ancestor.
    """
    return _field_readback(body)


def index_restored_projection(body):
    """Normalize one field readback to the members the restore is judged on.

    Restored means the group inherits the default again and names it. The
    inherited index list is whatever the project's default is at the time; it
    is recorded by the restore evidence, not judged here.
    """
    readback = _field_readback(body)
    return {
        key: readback[key] for key in ("name", "usesAncestorConfig", "ancestorField")
    }


def expected_index_exemption_digest() -> str:
    """The digest of the after state the permission binds and the run requires."""
    return digest(EXPECTED_INDEX_EXEMPTION_PROJECTION)


def expected_index_restored_digest() -> str:
    """The digest of the before state the restore evidence must show."""
    return digest(EXPECTED_INDEX_RESTORED_PROJECTION)


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


def verify_index_restored(body):
    """The exempt group must inherit the default again, and say so."""
    projection = index_restored_projection(body)
    if projection != EXPECTED_INDEX_RESTORED_PROJECTION:
        raise ValueError("index field is not restored to the inherited default")
    return {
        "projection": projection,
        "projectionDigest": digest(projection),
        "inheritedIndexes": _field_readback(body)["indexes"],
        "bodyDigest": digest(body),
    }


def validate_frozen_baselines(permission):
    """Every baseline digest must be frozen before any management slot is charged."""
    shared.validate_frozen_baselines(permission)
    declared = permission.get("indexExemptionProjectionDigest")
    if not isinstance(declared, str) or re.fullmatch(r"[a-f0-9]{64}", declared) is None:
        raise ValueError("frozen index exemption projection digest required")
    if declared != expected_index_exemption_digest():
        raise ValueError("index exemption digest is not the declared after state")


def management_transport(slot, token, *, deadline, capability, binding, binding_digest, operation=None):
    """One charged fixed management operation, with a whole-worker deadline."""
    if slot in LIFECYCLE_SLOTS:
        if not isinstance(operation, dict) or set(operation) != {"method", "route", "body"}:
            raise ValueError("bound lifecycle operation required")
        from batch_adapter import wire
        from o8_admission import authorize_transport

        authorize_transport(capability, binding=binding, binding_digest=binding_digest)
        if not private_string(token, 8192):
            raise ValueError("bounded credential required")
        duration = min(12.0, deadline - time.monotonic())
        if duration <= 0:
            raise ValueError("management phase deadline")
        if operation["route"] not in (LIFECYCLE_ROUTE, LIFECYCLE_ROUTE + "?updateMask=indexConfig"):
            prefix = "https://firestore.googleapis.com/v1/projects/fireemu-35fe6/databases/(default)/operations/"
            if not operation["route"].startswith(prefix):
                raise ValueError("lifecycle route differs from bound project")
        response = wire(
            operation["route"],
            operation["method"],
            operation["body"],
            {"Authorization": "Bearer " + token, "x-goog-user-project": PROJECT},
            timeout=duration,
            receipt=True,
        )
        http = response.get("http", {}) if isinstance(response, dict) else {}
        return {
            "complete": http.get("complete") is True and http.get("bodyKind") == "json",
            "workerReaped": True,
            "status": http.get("status"),
            "body": response.get("body") if isinstance(response, dict) else None,
            "bodyKind": http.get("bodyKind"),
        }
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


def management_call(inputs, phase, slot_id, secret, *, deadline, operation=None):
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
    value = {
        "kind": "management",
        "phase": phase,
        "slot": slot_id,
        "token": secret,
        "deadline": deadline,
    }
    if slot_id in LIFECYCLE_SLOTS:
        if not isinstance(operation, dict) or set(operation) != {"method", "route", "body"}:
            raise ValueError("bound lifecycle operation required")
        value["operation"] = operation
    return value


class ManagementSession:
    """Private verified credential plus nine durably charged management slots."""

    def __init__(self, *, gate, ledger, ticket, capability, inputs, permission, token):
        self.gate, self.ledger, self.ticket = gate, ledger, ticket
        self.capability, self.inputs, self.permission = capability, inputs, permission
        self._token = token
        self.credential = None
        self.evidence = []
        self.credential_evidence = []
        self._lifecycle = {}
        self.lifecycle_failed = False
        self.preflight_complete = False
        self.postflight_complete = False
        self.recovery_validation_failures = []
        validate_principal(permission.get("credentialPrincipal"))
        validate_frozen_baselines(permission)

    def run(self, phase):
        if phase not in ("observation", "recovery"):
            raise ValueError("closed management phase required")
        if phase == "recovery":
            self.lifecycle_failed = False
            self.postflight_complete = False
            self.recovery_validation_failures = []
        slots = (
            MANAGEMENT_OBSERVATION_IDS
            if phase == "observation"
            else MANAGEMENT_RECOVERY_IDS
        )
        for slot in slots:
            wire_state = {}

            def send(deadline, slot=slot, wire_state=wire_state):
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
                operation = self._lifecycle_operation(phase, slot)
                response = self.capability._transmit(
                    management_call(self.inputs, phase, slot, token, deadline=deadline, operation=operation)
                )
                wire_state.update(
                    {
                        key: response.get(key)
                        for key in ("complete", "workerReaped", "status", "bodyKind")
                    }
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
                if slot in LIFECYCLE_SLOTS:
                    return self._lifecycle_attestation(slot, response)
                public = attestation(slot, response, self.permission)
                if (
                    phase == "recovery"
                    and slot in ("project", "database", "index-exemption", "auth")
                    and response.get("complete") is True
                    and response.get("workerReaped") is True
                    and type(response.get("status")) is int
                    and response["status"] == 200
                    and response.get("bodyKind") == "json"
                    and public.get("complete") is False
                ):
                    # Preserve the explicit failed baseline attestation, while
                    # letting Gate record that its HTTP worker completed. The
                    # validator still rejects baselineVerified=false below.
                    public = {**public, "complete": True}
                return public

            response = self.gate.management_dispatch(phase, slot, send)
            row = {
                "id": phase + ":" + slot,
                "response": response,
                "responseDigest": digest(response),
            }
            self.evidence.append(row)
            event = self.gate.snapshot()["managementEvents"][-1]
            try:
                if event.get("id") != row["id"]:
                    raise ValueError("management response event identity differs")
                if event.get("completed") is not True:
                    raise ValueError(
                        "management slot did not complete inside its reservation"
                    )
                if slot == "oauth-tokeninfo":
                    if self.credential is None or response.get("complete") is not True:
                        raise ValueError("credential attestation failed")
                elif slot in LIFECYCLE_SLOTS:
                    self._accept_lifecycle_response(slot, response)
                    if self.lifecycle_failed:
                        raise ValueError("lifecycle semantic validation failed")
                else:
                    validate_attestation(slot, response, self.permission)
            except ValueError as error:
                if not self._can_finish_recovery_reads(
                    phase, slot, response, event, wire_state
                ):
                    raise
                # Preserve this failed response and the Gate event as written.
                # Only the already reserved recovery suffix may continue.
                self.recovery_validation_failures.append(
                    {"slot": slot, "failure": type(error).__name__}
                )
        if self.recovery_validation_failures:
            self.lifecycle_failed = True
            raise ValueError("recovery checks failed; restoration evidence retained")
        if phase == "observation":
            self.preflight_complete = True
        else:
            self.postflight_complete = True

    def _can_finish_recovery_reads(self, phase, slot, response, event, wire_state):
        """Allow only successful JSON reads to reach reserved restore slots."""
        state = self._lifecycle
        before = state.get("before")
        if (
            phase != "recovery"
            or slot
            not in (
                "project",
                "database",
                "index-exemption",
                "auth",
                "index-lifecycle-poll-restore",
            )
            or not isinstance(before, dict)
            or before.get("name") != LIFECYCLE_FIELD
            or not isinstance(state.get("applyResponse"), dict)
            or event.get("id") != "recovery:" + slot
            or wire_state.get("complete") is not True
            or wire_state.get("workerReaped") is not True
            or type(wire_state.get("status")) is not int
            or wire_state["status"] != 200
            or wire_state.get("bodyKind") != "json"
            or response.get("workerReaped") is not True
            or event.get("workerReaped") is not True
            or type(response.get("status")) is not int
            or response["status"] != 200
            or type(event.get("status")) is not int
            or event["status"] != 200
            or response.get("bodyKind") != "json"
            or event.get("complete") != response.get("complete")
            or event.get("responseDigest") != digest(response)
            or event.get("bodyDigest") != digest(response.get("body"))
        ):
            return False
        ended, deadline = event.get("ended"), event.get("deadline")
        return (
            type(ended) in (int, float)
            and type(deadline) in (int, float)
            and math.isfinite(ended)
            and math.isfinite(deadline)
            and ended <= deadline
        )

    def _lifecycle_operation(self, phase, slot):
        state = getattr(self, "_lifecycle", {})
        if slot == "index-lifecycle-before":
            return {"method": "GET", "route": LIFECYCLE_ROUTE, "body": None}
        if slot == "index-lifecycle-apply":
            return {"method": "PATCH", "route": LIFECYCLE_ROUTE + "?updateMask=indexConfig", "body": {"name": LIFECYCLE_FIELD, "indexConfig": {"indexes": []}}}
        if slot == "index-lifecycle-poll":
            return {"method": "GET", "route": state.get("applyOperation"), "body": None}
        if slot == "index-lifecycle-after":
            return {"method": "GET", "route": LIFECYCLE_ROUTE, "body": None}
        if slot == "index-lifecycle-restore":
            return {"method": "PATCH", "route": LIFECYCLE_ROUTE + "?updateMask=indexConfig", "body": {"name": LIFECYCLE_FIELD}}
        if slot == "index-lifecycle-poll-restore":
            return {"method": "GET", "route": state.get("restoreOperation"), "body": None}
        if slot == "index-lifecycle-restored":
            return {"method": "GET", "route": LIFECYCLE_ROUTE, "body": None}
        return None

    def _lifecycle_attestation(self, slot, response):
        state = getattr(self, "_lifecycle", {})
        if slot == "index-lifecycle-apply":
            state["applyResponse"] = {
                key: response.get(key)
                for key in ("complete", "workerReaped", "status", "bodyKind")
            }
            state["applyResponseBodyDigest"] = digest(response.get("body"))
            body = response.get("body")
            error = body.get("error") if isinstance(body, dict) else None
            if isinstance(error, dict):
                state["applyError"] = {
                    "code": error.get("code"),
                    "status": error.get("status"),
                }
            self._lifecycle = state
        attestation = {
            key: response.get(key)
            for key in ("complete", "workerReaped", "status", "bodyKind", "body")
        }
        if slot == "index-lifecycle-restored":
            baseline = state.get("before")
            exact_restore = (
                response.get("complete") is True
                and response.get("workerReaped") is True
                and response.get("status") == 200
                and isinstance(baseline, dict)
                and response.get("body") == baseline
            )
            apply_response = state.get("applyResponse", {})
            if (
                exact_restore
                and apply_response.get("complete") is True
                and apply_response.get("workerReaped") is True
                and apply_response.get("bodyKind") == "json"
                and apply_response.get("status") == 400
                and state.get("applyError")
                == {"code": 400, "status": "INVALID_ARGUMENT"}
            ):
                disposition = "rejected-no-op-restored"
            elif exact_restore and state.get("afterVerified") is True:
                disposition = "deployed-exemption-restored"
            else:
                disposition = (
                    "uncertain-apply-restored" if exact_restore else "restore-unproven"
                )
            resource = response.get("body")
            if isinstance(resource, dict):
                attestation["body"] = {
                    **resource,
                    "_lifecycleApplyDisposition": disposition,
                }
        return attestation

    def _accept_lifecycle_response(self, slot, response):
        if response.get("complete") is not True or response.get("workerReaped") is not True or response.get("status") != 200:
            raise ValueError("lifecycle management response incomplete")
        body = response.get("body")
        state = getattr(self, "_lifecycle", {})
        if slot == "index-lifecycle-restored":
            if (
                not isinstance(body, dict)
                or body.get("_lifecycleApplyDisposition")
                not in {
                    "rejected-no-op-restored",
                    "deployed-exemption-restored",
                    "uncertain-apply-restored",
                    "restore-unproven",
                }
            ):
                raise ValueError("restored lifecycle disposition required")
            state["applyDisposition"] = body["_lifecycleApplyDisposition"]
            body = {
                key: value
                for key, value in body.items()
                if key != "_lifecycleApplyDisposition"
            }
        if slot == "index-lifecycle-before":
            config = body.get("indexConfig") if isinstance(body, dict) else None
            if (
                not isinstance(body, dict)
                or body.get("name") != LIFECYCLE_FIELD
                or not isinstance(config, dict)
                or not isinstance(config.get("indexes", []), list)
                or config.get("usesAncestorConfig") is not True
                or config.get("ancestorField") != DEFAULT_ANCESTOR_FIELD
                or config.get("reverting", False) is not False
            ):
                raise ValueError("lifecycle baseline is not the bound inherited field")
            state["before"] = body
        elif slot == "index-lifecycle-apply":
            name = body.get("name") if isinstance(body, dict) else None
            prefix = "projects/fireemu-35fe6/databases/(default)/operations/"
            if not isinstance(name, str) or not name.startswith(prefix) or re.fullmatch(r"[A-Za-z0-9._~-]+", name.removeprefix(prefix)) is None:
                self.lifecycle_failed = True
                self._lifecycle = state
                return
            state["applyOperation"] = "https://firestore.googleapis.com/v1/" + name
        elif slot == "index-lifecycle-poll":
            expected = state.get("applyOperation", "").removeprefix("https://firestore.googleapis.com/v1/")
            if not isinstance(body, dict) or body.get("name") != expected or body.get("done") is not True or body.get("error") is not None:
                raise ValueError("one-poll lifecycle apply identity or completion differs")
        elif slot == "index-lifecycle-after":
            config = body.get("indexConfig") if isinstance(body, dict) else None
            before = state.get("before", {})
            if (
                not isinstance(body, dict)
                or body.get("name") != LIFECYCLE_FIELD
                or not isinstance(config, dict)
                or config.get("indexes", []) != []
                or config.get("usesAncestorConfig", False) is not False
                or config.get("ancestorField") != DEFAULT_ANCESTOR_FIELD
                or config.get("reverting", False) is not False
                or body.get("ttlConfig") != before.get("ttlConfig")
            ):
                raise ValueError("lifecycle after projection or unrelated configuration differs")
            state["after"] = body
            state["afterVerified"] = True
        elif slot == "index-lifecycle-restore":
            name = body.get("name") if isinstance(body, dict) else None
            prefix = "projects/fireemu-35fe6/databases/(default)/operations/"
            if not isinstance(name, str) or not name.startswith(prefix) or re.fullmatch(r"[A-Za-z0-9._~-]+", name.removeprefix(prefix)) is None:
                self.lifecycle_failed = True
                self._lifecycle = state
                return
            state["restoreOperation"] = "https://firestore.googleapis.com/v1/" + name
        elif slot == "index-lifecycle-poll-restore":
            expected = state.get("restoreOperation", "").removeprefix("https://firestore.googleapis.com/v1/")
            if not isinstance(body, dict) or body.get("name") != expected or body.get("done") is not True or body.get("error") is not None:
                raise ValueError("one-poll lifecycle restore identity or completion differs")
        elif slot == "index-lifecycle-restored":
            if body != state.get("before"):
                self.lifecycle_failed = True
            state["restored"] = body
        self._lifecycle = state

    def data_token(self, deadline):
        if not self.preflight_complete:
            raise ValueError("preflight must precede data")
        return require_usable(self.credential, deadline)


def expected_management_ids() -> list[str]:
    return ["observation:" + slot for slot in MANAGEMENT_OBSERVATION_IDS] + [
        "recovery:" + slot for slot in MANAGEMENT_RECOVERY_IDS
    ]


def validate_saved_lifecycle_operation_poll(operation, poll):
    """Require a saved operation poll to name the operation that was created."""
    prefix = "projects/fireemu-35fe6/databases/(default)/operations/"
    name = operation.get("name") if isinstance(operation, dict) else None
    if (
        not isinstance(name, str)
        or not name.startswith(prefix)
        or re.fullmatch(r"[A-Za-z0-9._~-]+", name.removeprefix(prefix)) is None
        or operation.get("error") is not None
        or not isinstance(poll, dict)
        or poll.get("name") != name
        or poll.get("done") is not True
        or poll.get("error") is not None
    ):
        raise ValueError("saved lifecycle operation/poll identity differs")


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
        if slot in LIFECYCLE_SLOTS:
            if (
                response.get("status") != 200
                or response.get("complete") is not True
                or response.get("workerReaped") is not True
                or response.get("bodyKind") != "json"
                or not isinstance(response.get("body"), dict)
            ):
                raise ValueError("saved lifecycle response differs")
            continue
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

    lifecycle = {
        row["id"]: row["response"].get("body")
        for row in rows
        if row["id"].split(":", 1)[1] in LIFECYCLE_SLOTS
    }
    before = lifecycle.get("observation:index-lifecycle-before")
    after = lifecycle.get("observation:index-lifecycle-after")
    restored_attestation = lifecycle.get("recovery:index-lifecycle-restored")
    if (
        not isinstance(restored_attestation, dict)
        or restored_attestation.get("_lifecycleApplyDisposition")
        != "deployed-exemption-restored"
    ):
        raise ValueError("saved lifecycle restore disposition differs")
    restored = {
        key: value
        for key, value in restored_attestation.items()
        if key != "_lifecycleApplyDisposition"
    }
    for phase, operation_slot, poll_slot in (
        ("observation", "index-lifecycle-apply", "index-lifecycle-poll"),
        ("recovery", "index-lifecycle-restore", "index-lifecycle-poll-restore"),
    ):
        validate_saved_lifecycle_operation_poll(
            lifecycle.get(phase + ":" + operation_slot),
            lifecycle.get(phase + ":" + poll_slot),
        )
    if (
        not isinstance(before, dict)
        or not isinstance(after, dict)
        or restored != before
        or before.get("name") != LIFECYCLE_FIELD
        or not isinstance(before.get("indexConfig"), dict)
        or before["indexConfig"].get("usesAncestorConfig") is not True
        or before["indexConfig"].get("ancestorField") != DEFAULT_ANCESTOR_FIELD
        or before["indexConfig"].get("reverting", False) is not False
        or not isinstance(after.get("indexConfig"), dict)
        or after["indexConfig"].get("indexes", []) != []
        or after["indexConfig"].get("usesAncestorConfig", False) is not False
        or after["indexConfig"].get("ancestorField") != DEFAULT_ANCESTOR_FIELD
        or after["indexConfig"].get("reverting", False) is not False
        or after.get("ttlConfig") != before.get("ttlConfig")
    ):
        raise ValueError("saved lifecycle projection evidence differs")
