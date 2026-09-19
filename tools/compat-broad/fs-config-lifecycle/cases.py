"""Observation cases for the FS-CONFIG-LIFECYCLE management-contract campaign.

Every case is an abstract request definition. Nothing here issues a request, resolves a
credential, or records a result. Expected local results are read from the classification
matrix, so they state what this checkout implements, never what production returned.
"""

from __future__ import annotations

import json
import re
from typing import Any

from .surface_matrix import CASE_ID, build_matrix, digest, pinned_definition

NONCE_PATTERN = re.compile(r"^[0-9a-f]{32}$")
CASE_KINDS = ("control", "observation", "negative", "cleanup")
OWNED_DATABASE_PREFIX = "fsconfig-"
PROJECT = "fireemu-35fe6"
DEFAULT_DATABASE = "(default)"
_M = "firestore.projects."

_SERVED = "served"
_NOT_SERVED = "not-served"
_SUCCESS = "success"
_REFUSAL = "refusal"

# The request-body alias each case uses, for methods whose Discovery entry declares a
# request body. A method absent from this map may carry query parameters only.
BODY_KEYS = {
    f"{_M}databases.create": "database",
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


_CONDITIONAL_EXEMPT = (
    "This cleanup addresses the identifier a refused create used. It runs only if that "
    "create was unexpectedly accepted, so the identifier is the invalid one under test."
)


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
    namespace_exempt_reason: str | None = None,
    possibly_allocates: bool = False,
    conditional: bool = False,
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
        "possiblyAllocates": possibly_allocates,
        "conditional": conditional,
        "revertedBy": reverted_by,
        "isRevertOf": is_revert_of,
        "namespaceExemptReason": namespace_exempt_reason,
    }


# A partially served method serves some requests and refuses others. The matrix records the
# method; this records which requests fall on the refused side, so that collapsing "partial"
# to a served/not-served outcome per case never claims a refusal is an answer.
_PARTIAL_REFUSALS = {
    f"{_M}databases.collectionGroups.fields.patch": (
        lambda request: "indexConfig" in str(request.get("updateMask", ""))
        or "indexConfig" in request.get("field", {}),
        "the local runtime refuses a fields.patch naming indexConfig with UNIMPLEMENTED: "
        "single-field exemptions are taken from the project's index configuration and have "
        "no runtime transition (FS-CONFIG-RT-004)",
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


def compile_cases(nonce: str) -> list[dict[str, Any]]:
    """Bind the abstract case list to one nonce-owned namespace."""
    if not isinstance(nonce, str) or not NONCE_PATTERN.fullmatch(nonce):
        raise ValueError("nonce must be exactly 32 lowercase hexadecimal characters")
    short = nonce[:12]
    owned_db = f"{OWNED_DATABASE_PREFIX}{short}"
    absent_db = f"{OWNED_DATABASE_PREFIX}absent-{short}"
    absent_project = f"fireemu-absent-{short}"
    ttl_group = f"fsconfig_ttl_{short}"
    exempt_group = f"fsconfig_exempt_{short}"
    ttl_field = f"projects/{PROJECT}/databases/{DEFAULT_DATABASE}/collectionGroups/{ttl_group}/fields/expiresAt"
    exempt_field = f"projects/{PROJECT}/databases/{DEFAULT_DATABASE}/collectionGroups/{exempt_group}/fields/payload"

    cases = [
        _case(
            "OC-01",
            "control",
            "databases.get",
            "Read the default database projection before anything is changed.",
            (DEFAULT_DATABASE,),
            {"name": f"projects/{PROJECT}/databases/{DEFAULT_DATABASE}"},
            _SUCCESS,
        ),
        _case(
            "OC-02",
            "control",
            "databases.list",
            "Enumerate databases so an unexpected pre-existing one aborts the run.",
            (DEFAULT_DATABASE,),
            {"parent": f"projects/{PROJECT}", "showDeleted": False},
            _SUCCESS,
        ),
        _case(
            "OC-03",
            "observation",
            "databases.create",
            "Create one throwaway named database with delete protection disabled.",
            (owned_db,),
            {
                "parent": f"projects/{PROJECT}",
                "databaseId": owned_db,
                "database": {
                    "locationId": "us-central1",
                    "type": "FIRESTORE_NATIVE",
                    "databaseEdition": "STANDARD",
                    "deleteProtectionState": "DELETE_PROTECTION_DISABLED",
                    "pointInTimeRecoveryEnablement": "POINT_IN_TIME_RECOVERY_DISABLED",
                },
            },
            _SUCCESS,
            mutates=True,
            possibly_allocates=True,
            reverted_by="OC-06",
        ),
        _case(
            "OC-04",
            "observation",
            "databases.get",
            "Read back the created database to compare the full projection.",
            (owned_db,),
            {"name": f"projects/{PROJECT}/databases/{owned_db}"},
            _SUCCESS,
        ),
        _case(
            "OC-05",
            "observation",
            "databases.list",
            "Confirm the created database appears in enumeration exactly once.",
            (DEFAULT_DATABASE, owned_db),
            {"parent": f"projects/{PROJECT}", "showDeleted": False},
            _SUCCESS,
        ),
        _case(
            "OC-06",
            "observation",
            "databases.delete",
            "Delete the throwaway database; this is the revert for OC-03.",
            (owned_db,),
            {"name": f"projects/{PROJECT}/databases/{owned_db}"},
            _SUCCESS,
            is_revert_of="OC-03",
        ),
        _case(
            "OC-07",
            "negative",
            "databases.get",
            "A syntactically valid but never-created database id must be refused.",
            (absent_db,),
            {"name": f"projects/{PROJECT}/databases/{absent_db}"},
            _REFUSAL,
        ),
        _case(
            "OC-08",
            "negative",
            "databases.create",
            "An uppercase and underscored database id must be refused before creation.",
            (f"Invalid_Id_{short}",),
            {
                "parent": f"projects/{PROJECT}",
                "databaseId": f"Invalid_Id_{short}",
                "database": {
                    "locationId": "us-central1",
                    "type": "FIRESTORE_NATIVE",
                    "databaseEdition": "STANDARD",
                    "deleteProtectionState": "DELETE_PROTECTION_DISABLED",
                    "pointInTimeRecoveryEnablement": "POINT_IN_TIME_RECOVERY_DISABLED",
                },
            },
            _REFUSAL,
            possibly_allocates=True,
            reverted_by="OC-23",
        ),
        _case(
            "OC-09",
            "negative",
            "databases.create",
            "A database id shorter than the documented minimum must be refused.",
            (f"a{short[:1]}",),
            {
                "parent": f"projects/{PROJECT}",
                "databaseId": f"a{short[:1]}",
                "database": {
                    "locationId": "us-central1",
                    "type": "FIRESTORE_NATIVE",
                    "databaseEdition": "STANDARD",
                    "deleteProtectionState": "DELETE_PROTECTION_DISABLED",
                    "pointInTimeRecoveryEnablement": "POINT_IN_TIME_RECOVERY_DISABLED",
                },
            },
            _REFUSAL,
            possibly_allocates=True,
            reverted_by="OC-24",
            namespace_exempt_reason="An id short enough to be refused cannot also carry "
            "the nonce prefix; the request is refused before any resource exists.",
        ),
        _case(
            "OC-10",
            "negative",
            "databases.create",
            "A database id longer than sixty-three characters must be refused.",
            (f"{OWNED_DATABASE_PREFIX}{short}-{'x' * 50}",),
            {
                "parent": f"projects/{PROJECT}",
                "databaseId": f"{OWNED_DATABASE_PREFIX}{short}-{'x' * 50}",
                "database": {
                    "locationId": "us-central1",
                    "type": "FIRESTORE_NATIVE",
                    "databaseEdition": "STANDARD",
                    "deleteProtectionState": "DELETE_PROTECTION_DISABLED",
                    "pointInTimeRecoveryEnablement": "POINT_IN_TIME_RECOVERY_DISABLED",
                },
            },
            _REFUSAL,
            possibly_allocates=True,
            reverted_by="OC-25",
        ),
        _case(
            "OC-11",
            "negative",
            "databases.get",
            "A database id that is not lowercase hyphenated must be refused; this is the "
            "shape the local runtime deliberately answers NOT_FOUND for.",
            (f"Invalid_Id_{short}",),
            {"name": f"projects/{PROJECT}/databases/Invalid_Id_{short}"},
            _REFUSAL,
        ),
        _case(
            "OC-12",
            "negative",
            "databases.get",
            "A project the caller cannot see must be refused without leaking existence.",
            (f"{absent_project}:(default)",),
            {"name": f"projects/{absent_project}/databases/{DEFAULT_DATABASE}"},
            _REFUSAL,
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
            "Clear the exemption so the inherited configuration applies again; this is the revert for OC-18.",
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
            "Poll one long-running operation produced by an owned mutation.",
            (ttl_field,),
            {"name": "<bound at run time to the operation an owned mutation returned>"},
            _SUCCESS,
        ),
        _case(
            "OC-23",
            "cleanup",
            "databases.delete",
            "Delete the database OC-08 would have created if production accepted it.",
            (f"Invalid_Id_{short}",),
            {"name": f"projects/{PROJECT}/databases/Invalid_Id_{short}"},
            _REFUSAL,
            is_revert_of="OC-08",
            conditional=True,
            namespace_exempt_reason=_CONDITIONAL_EXEMPT,
        ),
        _case(
            "OC-24",
            "cleanup",
            "databases.delete",
            "Delete the database OC-09 would have created if production accepted it.",
            (f"a{short[:1]}",),
            {"name": f"projects/{PROJECT}/databases/a{short[:1]}"},
            _REFUSAL,
            is_revert_of="OC-09",
            conditional=True,
            namespace_exempt_reason=_CONDITIONAL_EXEMPT,
        ),
        _case(
            "OC-25",
            "cleanup",
            "databases.delete",
            "Delete the database OC-10 would have created if production accepted it.",
            (f"{OWNED_DATABASE_PREFIX}{short}-{'x' * 50}",),
            {
                "name": (
                    f"projects/{PROJECT}/databases/"
                    f"{OWNED_DATABASE_PREFIX}{short}-{'x' * 50}"
                )
            },
            _REFUSAL,
            is_revert_of="OC-10",
            conditional=True,
            namespace_exempt_reason=_CONDITIONAL_EXEMPT,
        ),
    ]
    matrix_rows = {row["locator"]: row for row in build_matrix()["methods"]}
    for case in cases:
        case["caseId"] = CASE_ID
        case["expectedLocal"] = _expected_local(
            case["method"], case["request"], matrix_rows
        )
    return cases


def owned_resources(cases: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The ledger a run must recover: everything it mutates or could allocate."""
    ledger: list[dict[str, Any]] = []
    for case in cases:
        if not (case["mutates"] or case["possiblyAllocates"]):
            continue
        creates = case["method"].endswith("databases.create")
        ledger.append(
            {
                "kind": "database" if creates else "fieldConfig",
                "name": case["resources"][0],
                "createdBy": case["id"],
                "revertCase": case["revertedBy"],
                "conditional": not case["mutates"],
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
