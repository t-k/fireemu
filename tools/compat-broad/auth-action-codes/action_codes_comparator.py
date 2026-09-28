"""Fail-closed comparison of one local and one production action-code receipt.

A verdict is only possible when both sides are complete, recovered, bound to
the same frozen manifest, and produced by different runs. Anything else is
`INDETERMINATE`: an infrastructure, binding or cleanup failure is never
reported as a compatibility result, in either direction.

Typed semantics decide the verdict. Diagnostic prose and the length of a
returned code stay visible as informational differences, because neither is a
documented part of the contract this campaign compares.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from action_codes_plan import CAMPAIGN_ID, CONTRACT, SECRET_FIELDS, STAGE_IDS

COMPARATOR_ID = "auth-action-codes-comparator-v1"

SEMANTIC_FIELDS = (
    "status",
    "errorCode",
    "keys",
    "requestType",
    "emailVerified",
    "isNewUser",
    "oobCodeReturned",
    "oobLinkReturned",
    "oobCodeCharacterClass",
    "idTokenReturned",
    "refreshTokenReturned",
    "userCount",
    "userEmailVerified",
    "accountCreated",
    "emailEchoesOwner",
    "emailMatchesRequest",
)

# Delivery is a property of the run, gated in `_shaped`, not of a stage: no
# response says whether a message left the building, so no stage row claims it.

# Visible, never decisive: diagnostic grammar and the opaque code length.
INFORMATIONAL_FIELDS = ("errorMessage", "oobCodeLength")

_COMMIT = re.compile(r"[0-9a-f]{40}")
_SHA256 = re.compile(r"[0-9a-f]{64}")


def _indeterminate(reason: str) -> dict[str, Any]:
    return {
        "comparatorId": COMPARATOR_ID,
        "classification": "INDETERMINATE",
        "productionCompared": False,
        "reason": reason,
        "stages": [],
        "differingStages": [],
        "comparedStages": 0,
    }


def _carries_secret(value: Any) -> bool:
    serialized = json.dumps(value, sort_keys=True, default=str)
    return any('"' + field + '":' in serialized for field in SECRET_FIELDS)


def _binding_complete(binding: Any) -> bool:
    """A complete binding names a commit and the artifact digest it produced."""
    return (
        isinstance(binding, dict)
        and isinstance(binding.get("commit"), str)
        and isinstance(binding.get("artifactSha256"), str)
        and bool(_COMMIT.fullmatch(binding["commit"]))
        and bool(_SHA256.fullmatch(binding["artifactSha256"]))
    )


def _built_from_source(binding: dict[str, Any]) -> bool:
    """The artifact must be the one this commit produces, not one kept nearby.

    A retained binary's digest says which bytes ran, not which source they came
    from. Only a receipt that records both, and agrees with itself, can carry a
    compatibility verdict.
    """
    return binding.get("binding") == "built-from-source" and binding.get(
        "builtFromSourceCommit"
    ) == binding.get("commit")


def _shaped(receipt: Any, side: str) -> str | None:
    """Return the reason this receipt cannot take part in a verdict."""
    if not isinstance(receipt, dict):
        return side + " receipt is not an object"
    if receipt.get("contract") != CONTRACT or receipt.get("campaignId") != CAMPAIGN_ID:
        return side + " receipt belongs to another campaign or contract"
    if receipt.get("side") != side:
        return side + " receipt is not labelled " + side
    if receipt.get("recordingComplete") is not True:
        return side + " recording is incomplete"
    if receipt.get("cleanupComplete") is not True:
        return side + " cleanup is incomplete"
    if receipt.get("remainingAccounts") != 0 or receipt.get("deleteFailures") not in (
        0,
        None,
    ):
        return side + " left an owned account behind"
    if not _binding_complete(receipt.get("sourceBinding")):
        return side + " source binding is incomplete"
    if not _built_from_source(receipt["sourceBinding"]):
        return side + " artifact was not built from the bound source"
    if receipt.get("deliveredMessages") != 0 or isinstance(
        receipt.get("deliveredMessages"), bool
    ):
        return side + " receipt records delivered messages"
    if receipt.get("absenceProven") is not True:
        return side + " did not prove the absence of its owned addresses"
    stages = receipt.get("stages")
    # Every element must be a typed row: a foreign receipt is classified, never
    # allowed to raise out of the comparison.
    if (
        not isinstance(stages, list)
        or len(stages) != len(STAGE_IDS)
        or not all(isinstance(stage, dict) for stage in stages)
        or [stage.get("id") for stage in stages] != list(STAGE_IDS)
    ):
        return side + " stages are missing, reordered or untyped"
    if side == "production":
        if receipt.get("productionExecuted") is not True:
            return "production receipt does not record an executed observation"
        if (
            not isinstance(receipt.get("permissionReference"), str)
            or not receipt["permissionReference"]
        ):
            return "production receipt carries no owner permission reference"
    return None


def _difference(left: dict, right: dict, fields: tuple[str, ...]) -> dict[str, Any]:
    differences: dict[str, Any] = {}
    for field in fields:
        if field in left or field in right:
            local, production = left.get(field), right.get(field)
            # Python equates True with 1; a boolean never satisfies an integer slot.
            if local != production or type(local) is not type(production):
                differences[field] = {"local": local, "production": production}
    return differences


def compare(local: Any, production: Any) -> dict[str, Any]:
    """Classify one bound pair as MATCH, SEMANTIC_MISMATCH or INDETERMINATE."""
    if local is production:
        return _indeterminate("both sides are the same recording")
    if _carries_secret(local) or _carries_secret(production):
        return _indeterminate("receipt carries a secret field")
    for receipt, side in ((local, "local"), (production, "production")):
        reason = _shaped(receipt, side)
        if reason is not None:
            return _indeterminate(reason)
    if local.get("manifestDigest") != production.get("manifestDigest"):
        return _indeterminate("the two sides executed different manifests")
    rows: list[dict[str, Any]] = []
    differing: list[str] = []
    for left, right in zip(local["stages"], production["stages"], strict=True):
        differences = _difference(left, right, SEMANTIC_FIELDS)
        rows.append(
            {
                "id": left["id"],
                "equal": not differences,
                "differences": differences,
                "informational": _difference(left, right, INFORMATIONAL_FIELDS),
            }
        )
        if differences:
            differing.append(left["id"])
    return {
        "comparatorId": COMPARATOR_ID,
        "classification": "SEMANTIC_MISMATCH" if differing else "MATCH",
        "productionCompared": True,
        "manifestDigest": local["manifestDigest"],
        "comparedStages": len(rows),
        "differingStages": differing,
        "stages": rows,
    }


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--local", type=Path, required=True)
    parser.add_argument("--production", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    arguments = parser.parse_args()
    result = compare(
        json.loads(arguments.local.read_bytes()),
        json.loads(arguments.production.read_bytes()),
    )
    if arguments.output is not None:
        arguments.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"classification": result["classification"]}))
    raise SystemExit(
        {"MATCH": 0, "SEMANTIC_MISMATCH": 1}.get(result["classification"], 2)
    )
