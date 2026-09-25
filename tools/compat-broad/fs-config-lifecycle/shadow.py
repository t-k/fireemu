"""Pure local shadow ledger for FS-CONFIG-LIFECYCLE.

It never opens a socket, starts fireemu, or issues a request. It states, per case, what
this checkout would serve according to the classification matrix, and it records the
command a future measurement run would use to replace that declaration with a recording.
"""

from __future__ import annotations

from typing import Any

from .cases import compile_cases
from .comparator import SCHEMA
from .manifest import compile_manifest
from .surface_matrix import CASE_ID, digest

_SHADOW_COMMAND = (
    "fireemu exec --config <profile> --firebase-json conformance/firebase.json "
    "--only firestore -- <collector>"
)

_LOCAL_REFUSAL = (
    "The Firestore REST port serves databases.get, databases.list, the "
    "collectionGroups.fields methods and the field-configuration operations among the "
    "management methods; every one of them requires an owner credential. A fields.patch "
    "naming indexConfig is refused with UNIMPLEMENTED rather than served. Every other "
    "path that is not a documents path is answered with a plain 404, so a collector must "
    "record that refusal rather than treat it as a transport failure."
)

_NOT_PROVEN = (
    (
        "This ledger proves no local behavior. It restates the classification matrix, "
        "which was read from source, not from a running process."
    ),
    "A served case is not shown to agree with production; production is unobserved.",
    (
        "A not-served case is not a repair ticket by itself; the tickets are enumerated "
        "in the classification matrix."
    ),
)


def run_shadow(nonce: str, scenario: str = "declared") -> dict[str, Any]:
    if scenario not in {"declared", "control"}:
        raise ValueError("unsupported shadow scenario")
    manifest = compile_manifest(nonce)
    cases = compile_cases(nonce)
    outcomes = [
        {
            "caseId": case["id"],
            "method": case["method"],
            "kind": case["kind"],
            "expectedLocalOutcome": case["expectedLocal"]["outcome"],
            "class": case["expectedLocal"]["class"],
            "citations": list(case["expectedLocal"]["citations"]),
            "executed": False,
        }
        for case in cases
    ]
    if scenario == "control":
        outcomes = [row for row in outcomes if row["kind"] == "control"]
    return {
        "schema": SCHEMA,
        "caseId": CASE_ID,
        "status": "PREPARATION_ONLY",
        "productionExecuted": False,
        "localExecuted": False,
        "manifestDigest": digest(manifest),
        "scenario": scenario,
        "sourceBinding": {"commit": None, "artifactSha256": None},
        "shadowCommand": _SHADOW_COMMAND,
        "localRefusalNote": _LOCAL_REFUSAL,
        "notProven": list(_NOT_PROVEN),
        "expectedCaseOutcomes": outcomes,
    }


def served_case_count(receipt: dict[str, Any]) -> int:
    return sum(
        1
        for row in receipt["expectedCaseOutcomes"]
        if row["expectedLocalOutcome"] == "served"
    )
