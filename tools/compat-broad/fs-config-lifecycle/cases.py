"""Observation cases for the FS-CONFIG-LIFECYCLE management-contract campaign.

Every case is an abstract request definition. Nothing here issues a request, resolves a
credential, or records a result. Expected local results are read from the classification
matrix, so they state what this checkout implements, never what production returned.

The plan carries twelve cases. The thirteen that created or deleted a named database
(OC-03..OC-12 and OC-23..OC-25 of the first preparation) are managed-infrastructure
surfaces excluded by the 2026-09-18 owner scope decision, so they are dropped rather
than renumbered: the surviving identifiers keep their meaning across both revisions.
"""

from __future__ import annotations

import json
import re
from typing import Any

from .surface_matrix import CASE_ID, build_matrix, digest, pinned_definition

NONCE_PATTERN = re.compile(r"^[0-9a-f]{32}$")
CASE_KINDS = ("control", "observation")
PROJECT = "fireemu-35fe6"
DEFAULT_DATABASE = "(default)"
_M = "firestore.projects."

# Dropped 2026-09-21 under the 2026-09-18 owner decision: every case that created,
# deleted or probed creation of a named database is managed infrastructure.
DROPPED_CASES = tuple(f"OC-{n:02d}" for n in (*range(3, 13), 23, 24, 25))

# The order a collector issues the cases in. A revert always follows the readback of
# the patch it reverts, so the readback observes the applied state.
EXECUTION_ORDER = (
    "OC-01",
    "OC-02",
    "OC-13",
    "OC-14",
    "OC-22",
    "OC-15",
    "OC-16",
    "OC-17",
    "OC-18",
    "OC-19",
    "OC-20",
    "OC-21",
)

# Each locked step is one configuration change modelled as: baseline read, patch,
# readback, revert, verify. The shared Ledger holds an EXCLUSIVE lock on the step's
# field key for the whole run, so no other campaign may touch the same field.
LOCKED_STEPS = (
    {
        "id": "ttl",
        "baseline": "OC-13",
        "apply": "OC-14",
        "poll": "OC-22",
        "readback": "OC-15",
        "revert": "OC-16",
        "updateMask": "ttlConfig",
    },
    {
        "id": "exemption",
        "baseline": "OC-17",
        "apply": "OC-18",
        "poll": None,
        "readback": "OC-19",
        "revert": "OC-20",
        "updateMask": "indexConfig",
    },
)

_SERVED = "served"
_NOT_SERVED = "not-served"
_SUCCESS = "success"
_REFUSAL = "refusal"

# The request-body alias each case uses, for methods whose Discovery entry declares a
# request body. A method absent from this map may carry query parameters only.
BODY_KEYS = {
    f"{_M}databases.collectionGroups.fields.patch": "field",
}


def declared_request_keys(method: str) -> set[str]:
    """Query parameters the pinned Discovery declares for a method, plus its body alias."""
    prefix = f"{method}/parameters/"
    keys = {
        surface["locator"][len(prefix) :]
        for surface in pinned_definition()["surfaces"]
        if surface["locator"].startswith(prefix)
        and "/" not in surface["locator"][len(prefix) :]
    }
    body = BODY_KEYS.get(method)
    if body is not None:
        locators = {surface["locator"] for surface in pinned_definition()["surfaces"]}
        if f"{method}/request" not in locators:
            raise ValueError(f"{method} declares no request body in the pinned input")
        keys.add(body)
    return keys


def _case(
    case_id: str,
    kind: str,
    method: str,
    intent: str,
    resources: tuple[str, ...],
    request: dict[str, Any],
    expected_production: str,
    mutates: bool = False,
    reverted_by: str | None = None,
    is_revert_of: str | None = None,
) -> dict[str, Any]:
    return {
        "id": case_id,
        "kind": kind,
        "method": f"{_M}{method}",
        "intent": intent,
        "resources": list(resources),
        "request": request,
        "expectedProductionOutcome": expected_production,
        "productionObserved": False,
        "mutates": mutates,
        "revertedBy": reverted_by,
        "isRevertOf": is_revert_of,
    }


# A partially served method serves some requests and refuses others. The matrix records the
# method; this records which requests fall on the refused side, so that collapsing "partial"
# to a served/not-served outcome per case never claims a refusal is an answer.
_PARTIAL_REFUSALS = {
    f"{_M}databases.collectionGroups.fields.patch": (
        lambda request: (
            "indexConfig" in str(request.get("updateMask", ""))
            or "indexConfig" in request.get("field", {})
        ),
        (
            "the local runtime refuses a fields.patch naming indexConfig with "
            "UNIMPLEMENTED: single-field exemptions are taken from the project's index "
            "configuration and have no runtime transition (FS-CONFIG-RT-004)"
        ),
    ),
}


def _expected_local(
    method: str, request: dict[str, Any], matrix_rows: dict[str, dict[str, Any]]
) -> dict[str, Any]:
    row = matrix_rows[method]
    served = row["local"]["status"] in {"implemented", "partial"}
    refusal = None
    if served and row["local"]["status"] == "partial":
        predicate = _PARTIAL_REFUSALS.get(method)
        if predicate is not None and predicate[0](request):
            served = False
            refusal = predicate[1]
    expected = {
        "outcome": _SERVED if served else _NOT_SERVED,
        "basis": "classification-matrix",
        "class": row["class"],
        "citations": list(row["local"]["citations"]),
    }
    if refusal is not None:
        expected["refusalReason"] = refusal
    return expected


def _field_names(nonce: str) -> dict[str, str]:
    short = nonce[:12]
    ttl_group = f"fsconfig_ttl_{short}"
    exempt_group = f"fsconfig_exempt_{short}"
    return {
        "ttlGroup": ttl_group,
        "exemptGroup": exempt_group,
        "ttlField": (
            f"projects/{PROJECT}/databases/{DEFAULT_DATABASE}/collectionGroups/"
            f"{ttl_group}/fields/expiresAt"
        ),
        "exemptField": (
            f"projects/{PROJECT}/databases/{DEFAULT_DATABASE}/collectionGroups/"
            f"{exempt_group}/fields/payload"
        ),
    }


def field_lock_key(field_resource: str) -> str:
    """The shared Ledger key for one field configuration.

    `project/<project>/firestore/<database>/fields/<collectionGroup>/<field>` uses the
    Ledger's segment grammar directly: every segment is letters, digits, parentheses,
    underscores or hyphens. A document lock under the same database is a sibling and
    does not overlap, so a data campaign is refused only when it names the same field.
    """
    parts = field_resource.split("/")
    if (
        len(parts) != 8
        or parts[0] != "projects"
        or parts[2] != "databases"
        or parts[4] != "collectionGroups"
        or parts[6] != "fields"
    ):
        raise ValueError("canonical field configuration resource required")
    return f"project/{parts[1]}/firestore/{parts[3]}/fields/{parts[5]}/{parts[7]}"


def compile_cases(nonce: str) -> list[dict[str, Any]]:
    """Bind the abstract case list to one nonce-owned namespace."""
    if not isinstance(nonce, str) or not NONCE_PATTERN.fullmatch(nonce):
        raise ValueError("nonce must be exactly 32 lowercase hexadecimal characters")
    names = _field_names(nonce)
    ttl_field = names["ttlField"]
    exempt_field = names["exemptField"]
    exempt_group = names["exemptGroup"]

    cases = [
        _case(
            "OC-01",
            "control",
            "databases.get",
            "Read the default database projection before anything is changed; the "
            "projection digest must equal the frozen baseline or the run stops here.",
            (DEFAULT_DATABASE,),
            {"name": f"projects/{PROJECT}/databases/{DEFAULT_DATABASE}"},
            _SUCCESS,
        ),
        _case(
            "OC-02",
            "control",
            "databases.list",
            "Enumerate databases so an unexpected change during the run is detected "
            "by the closing reconciliation.",
            (DEFAULT_DATABASE,),
            {"parent": f"projects/{PROJECT}", "showDeleted": False},
            _SUCCESS,
        ),
        _case(
            "OC-13",
            "control",
            "databases.collectionGroups.fields.get",
            "Capture the untouched field configuration before any patch.",
            (ttl_field,),
            {"name": ttl_field},
            _SUCCESS,
        ),
        _case(
            "OC-14",
            "observation",
            "databases.collectionGroups.fields.patch",
            "Enable a time-to-live policy on an owned collection group field.",
            (ttl_field,),
            {
                "name": ttl_field,
                "updateMask": "ttlConfig",
                "field": {"name": ttl_field, "ttlConfig": {}},
            },
            _SUCCESS,
            mutates=True,
            reverted_by="OC-16",
        ),
        _case(
            "OC-15",
            "observation",
            "databases.collectionGroups.fields.get",
            "Read back the time-to-live state the patch produced.",
            (ttl_field,),
            {"name": ttl_field},
            _SUCCESS,
        ),
        _case(
            "OC-16",
            "observation",
            "databases.collectionGroups.fields.patch",
            "Remove the time-to-live policy; this is the revert for OC-14.",
            (ttl_field,),
            {
                "name": ttl_field,
                "updateMask": "ttlConfig",
                "field": {"name": ttl_field},
            },
            _SUCCESS,
            is_revert_of="OC-14",
        ),
        _case(
            "OC-17",
            "control",
            "databases.collectionGroups.fields.get",
            "Capture the untouched index configuration before the exemption patch.",
            (exempt_field,),
            {"name": exempt_field},
            _SUCCESS,
        ),
        _case(
            "OC-18",
            "observation",
            "databases.collectionGroups.fields.patch",
            "Exempt one owned field from single-field indexing.",
            (exempt_field,),
            {
                "name": exempt_field,
                "updateMask": "indexConfig",
                "field": {"name": exempt_field, "indexConfig": {"indexes": []}},
            },
            _SUCCESS,
            mutates=True,
            reverted_by="OC-20",
        ),
        _case(
            "OC-19",
            "observation",
            "databases.collectionGroups.fields.get",
            "Read back the exemption, including whether the ancestor config is still used.",
            (exempt_field,),
            {"name": exempt_field},
            _SUCCESS,
        ),
        _case(
            "OC-20",
            "observation",
            "databases.collectionGroups.fields.patch",
            "Clear the exemption so the inherited configuration applies again; this is "
            "the revert for OC-18.",
            (exempt_field,),
            {
                "name": exempt_field,
                "updateMask": "indexConfig",
                "field": {"name": exempt_field, "indexConfig": {}},
            },
            _SUCCESS,
            is_revert_of="OC-18",
        ),
        _case(
            "OC-21",
            "observation",
            "databases.collectionGroups.fields.list",
            "Enumerate the non-default field configurations of one owned collection group.",
            (exempt_field,),
            {
                "parent": (
                    f"projects/{PROJECT}/databases/{DEFAULT_DATABASE}"
                    f"/collectionGroups/{exempt_group}"
                ),
                "filter": "indexConfig.usesAncestorConfig:false",
                "pageSize": 20,
            },
            _SUCCESS,
        ),
        _case(
            "OC-22",
            "observation",
            "databases.operations.get",
            "Poll the long-running operation the time-to-live patch returned until it "
            "is done or the bounded poll deadline stops the run.",
            (ttl_field,),
            {"name": "<bound at run time to the operation OC-14 returned>"},
            _SUCCESS,
        ),
    ]
    matrix_rows = {row["locator"]: row for row in build_matrix()["methods"]}
    for case in cases:
        case["caseId"] = CASE_ID
        case["expectedLocal"] = _expected_local(
            case["method"], case["request"], matrix_rows
        )
    return cases


def locked_steps(nonce: str) -> list[dict[str, Any]]:
    """The two configuration changes as locked steps bound to one nonce."""
    cases = {case["id"]: case for case in compile_cases(nonce)}
    steps = []
    for step in LOCKED_STEPS:
        resource = cases[step["baseline"]]["resources"][0]
        steps.append(
            {
                **step,
                "resource": resource,
                "lockKey": field_lock_key(resource),
                "lockMode": "EXCLUSIVE",
            }
        )
    return steps


def owned_resources(cases: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The ledger a run must recover: every field configuration it patches."""
    ledger: list[dict[str, Any]] = []
    for case in cases:
        if not case["mutates"]:
            continue
        ledger.append(
            {
                "kind": "fieldConfig",
                "name": case["resources"][0],
                "createdBy": case["id"],
                "revertCase": case["revertedBy"],
                "conditional": False,
                "recovered": False,
            }
        )
    return ledger


def cases_digest(nonce: str) -> str:
    return digest(compile_cases(nonce))


def validate_cases(cases: Any, nonce: str) -> bool:
    if not isinstance(cases, list) or not cases:
        return False
    try:
        expected = compile_cases(nonce)
    except ValueError:
        return False
    if len(cases) != len(expected):
        return False
    for case in cases:
        if not isinstance(case, dict) or case.get("kind") not in CASE_KINDS:
            return False
    return json.loads(json.dumps(cases)) == json.loads(json.dumps(expected))
