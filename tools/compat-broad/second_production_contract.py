"""Closed second45 production admission; prepared inputs are not permission."""

from __future__ import annotations

import hashlib
import math
import re
from pathlib import Path

from batch_contract import DATABASE_PROJECTION, NUMBER, PROJECT, validate_owner_baseline
from broad_contract import digest
from second_admission import manifest as local_manifest


def manifest():
    value = local_manifest()
    value.update(kind="second45-production-admission-v1", productionExecutable=True)
    value["transport"] = "second45-bounded-production-http-v1"
    value["mode"] = "mapped"
    value["localAdmissionDigest"] = digest(local_manifest())
    value["resources"] = {
        "ownedAccounts": 2,
        "concurrentDocuments": 1,
        "seedDocuments": 3,
        "requestBytes": 16384,
        "responseBytes": 65536,
    }
    value["cost"] = {
        "maximumUSD": 1,
        "currency": "USD",
        "planningUnitCeilings": {
            "documentReadUSD": 0.00001,
            "documentWriteUSD": 0.00002,
            "documentDeleteUSD": 0.00001,
            "authMauUSD": 0.01,
        },
        "maximumRetentionHours": 24,
        "ownerMustConfirmStorageAndNetwork": True,
    }
    return value


def binding():
    return {
        "kind": "second45-production-local-comparison-v1",
        "manifestDigest": digest(manifest()),
        "localAdmissionDigest": digest(local_manifest()),
        "normalization": "second45-scoped-values-original-version-v1",
        "independentRecipes": "second45-local-admission-v1",
        "receipt": "bounded-http-v1",
    }


def approve(value, permission, nonce, observer, now):
    if digest(value) != digest(manifest()) or not re.fullmatch(
        r"[0-9a-f]{32}", nonce or ""
    ):
        raise ValueError("closed second45 manifest and fresh nonce required")
    required = {
        "kind": "second45-owner-execution-permission-v1",
        "comparisonContractDigest": digest(binding()),
        "manifestSha256": digest(value),
        "observerSha256": observer,
        "nonce": nonce,
        "project": PROJECT,
        "projectNumber": NUMBER,
        "quotaProject": PROJECT,
        "tariffsConfirmedBelowPlanningCeilings": True,
        "databaseProjectionContractDigest": digest(DATABASE_PROJECTION),
    }
    validate_owner_baseline(permission, required, now)
    costs = permission.get("costAssumptions")
    if not isinstance(costs, dict):
        raise ValueError("explicit cost assumptions required")  # noqa: TRY004 -- Admission uses one refusal category.
    for key in (
        "retentionHours",
        "indexStorageUpperUSD",
        "networkUpperUSD",
        "computedUpperUSD",
    ):
        number = costs.get(key)
        if type(number) not in (int, float) or not math.isfinite(number) or number < 0:
            raise ValueError("finite nonnegative cost assumptions required")
    base = 100 * (0.00001 + 0.00002 + 0.00001) + 2 * 0.01
    if (
        not 0 < costs["retentionHours"] <= 24
        or costs["computedUpperUSD"]
        < base + costs["indexStorageUpperUSD"] + costs["networkUpperUSD"]
        or costs["computedUpperUSD"] > 1
        or costs.get("ownerConfirmed") is not True
    ):
        raise ValueError("cost or retention envelope not confirmed")


def observer_digest():
    from batch_adapter import observer_digest as python_digest

    here = Path(__file__).resolve().parent
    return digest(
        {
            "python": python_digest(),
            "javascript": {
                name: hashlib.sha256((here / name).read_bytes()).hexdigest()
                for name in ("record-http.mjs", "second_wire.mjs")
            },
        }
    )


def validate_receipt_environment(result):
    """Recheck successful metadata evidence independently of the runner flags."""
    from batch_contract import database_evidence

    if not isinstance(result, dict):
        return False
    if result.get("target") == "local":
        return result.get("productionExecuted") is False
    permission = result.get("permission", {})
    if not isinstance(permission, dict):
        return False
    if (
        result.get("target") != "production"
        or result.get("productionExecuted") is not True
    ):
        return False
    try:
        approve(
            manifest(),
            permission,
            result.get("nonce"),
            result.get("observerDigest"),
            result.get("approvalValidatedAt"),
        )
    except (ValueError, TypeError, KeyError):
        return False
    identity = result.get("runtimeIdentity")
    frozen = permission.get("frozenCommit")
    if (
        not isinstance(identity, dict)
        or not isinstance(frozen, str)
        or re.fullmatch(r"[0-9a-f]{40}", frozen) is None
        or identity.get("executionCommit") != frozen
    ):
        return False
    if (
        result.get("permissionDigest") != digest(permission)
        or result.get("configurationUnchanged") is not True
        or result.get("preflightComplete") is not True
    ):
        return False
    trace = result.get("metadataTrace", [])
    paths = [
        f"cloudresourcemanager.googleapis.com/v1/projects/{PROJECT}",
        f"firestore.googleapis.com/v1/projects/{PROJECT}/databases/(default)",
        f"identitytoolkit.googleapis.com/admin/v2/projects/{PROJECT}/config",
        "apikeys.googleapis.com/v2/keys:lookupKey",
    ]
    if [(e.get("phase"), e.get("operation")) for e in trace] != [
        (phase, path) for phase in ("preflight", "postflight") for path in paths
    ]:
        return False
    for index, entry in enumerate(trace):
        observation = entry.get("observation", {})
        body = observation.get("body")
        if observation.get("httpStatus") != 200 or not isinstance(body, dict):
            return False
        slot = index % 4
        if slot == 0 and (
            str(body.get("projectNumber")) != NUMBER or body.get("projectId") != PROJECT
        ):
            return False
        if slot == 1 and (
            database_evidence(body)["projectionDigest"]
            != permission.get("databaseProjectionDigest")
            or body.get("locationId") != permission.get("pricingLocation")
        ):
            return False
        if slot == 2 and digest(body) != permission.get("authConfigDigest"):
            return False
        if slot == 3 and (
            body.get("parent") != f"projects/{NUMBER}/locations/global"
            or not body.get("name", "").startswith(
                f"projects/{NUMBER}/locations/global/keys/"
            )
        ):
            return False
    return True
