"""Observation cases for the FS-CONFIG-LIFECYCLE management-contract campaign.

Every case is an abstract request definition. Nothing here issues a request, resolves a
credential, or records a result. Expected local results are read from the classification
matrix, so they state what this checkout implements, never what production returned.
"""

from __future__ import annotations

import json
import re
from typing import Any

from .surface_matrix import CASE_ID, build_matrix, digest

NONCE_PATTERN = re.compile(r"^[0-9a-f]{32}$")
CASE_KINDS = ("control", "observation", "negative")
OWNED_DATABASE_PREFIX = "fsconfig-"
PROJECT = "fireemu-35fe6"
DEFAULT_DATABASE = "(default)"
_M = "firestore.projects."

_SERVED = "served"
_NOT_SERVED = "not-served"
_SUCCESS = "success"
_REFUSAL = "refusal"


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
        "namespaceExemptReason": namespace_exempt_reason,
    }


def _expected_local(
    method: str, matrix_rows: dict[str, dict[str, Any]]
) -> dict[str, Any]:
    row = matrix_rows[method]
    served = row["local"]["status"] in {"implemented", "partial"}
    return {
        "outcome": _SERVED if served else _NOT_SERVED,
        "basis": "classification-matrix",
        "class": row["class"],
        "citations": list(row["local"]["citations"]),
    }


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
            {"name": f"projects/{PROJECT}/databases/{owned_db}", "allowMissing": False},
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
            {"parent": f"projects/{PROJECT}", "databaseId": f"Invalid_Id_{short}"},
            _REFUSAL,
        ),
        _case(
            "OC-09",
            "negative",
            "databases.create",
            "A database id shorter than the documented minimum must be refused.",
            (f"a{short[:1]}",),
            {"parent": f"projects/{PROJECT}", "databaseId": f"a{short[:1]}"},
            _REFUSAL,
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
            },
            _REFUSAL,
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
            "Restore the inherited index configuration; this is the revert for OC-18.",
            (exempt_field,),
            {
                "name": exempt_field,
                "updateMask": "indexConfig",
                "field": {
                    "name": exempt_field,
                    "indexConfig": {"usesAncestorConfig": True},
                },
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
            (f"operations/{short}",),
            {"name": "<bound at run time to the operation an owned mutation returned>"},
            _SUCCESS,
        ),
    ]
    matrix_rows = {row["locator"]: row for row in build_matrix()["methods"]}
    for case in cases:
        case["caseId"] = CASE_ID
        case["expectedLocal"] = _expected_local(case["method"], matrix_rows)
    return cases


def owned_resources(cases: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The ledger a run must recover, derived only from mutating cases."""
    ledger: list[dict[str, Any]] = []
    for case in cases:
        if not case["mutates"]:
            continue
        kind = (
            "database" if case["method"].endswith("databases.create") else "fieldConfig"
        )
        name = case["resources"][0]
        ledger.append(
            {
                "kind": kind,
                "name": name,
                "createdBy": case["id"],
                "revertCase": case["revertedBy"],
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
