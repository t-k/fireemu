"""Closed first-batch inputs, resource mapping and intersecting admission ceilings."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

from broad_cases import generated_programs
from broad_contract import digest, programs

PROJECT = "fireemu-35fe6"
NUMBER = "592603257417"
BASE = f"projects/{PROJECT}/databases/(default)/documents"
ABSTRACT = "projects/PROJECT/databases/(default)/documents"
LIMITS = {
    "total": 2400,
    "auth": 400,
    "firestore": 1600,
    "metadata": 100,
    "recovery": 300,
}


def candidate():
    selected = generated_programs() + [
        p for p in programs("firestore")[0] if p["id"] == "writes/transforms"
    ]
    # Conservative planning ceilings, NOT a claim that these are current SKU tariffs.
    # Includes all attempts, recovery, worst-case index storage, egress and Auth MAU.
    units = {
        "documentReads": 3200,
        "documentWrites": 1600,
        "documentDeletes": 200,
        "indexReadBatches": 2,
        "storageGiBMonths": 8 * (8 * 1024 * 1024 + 16384) / 2**30,
        "egressGiB": 2400 * 65536 / 2**30,
        "authMau": 3,
    }
    rates = {
        "documentReads": 0.00001,
        "documentWrites": 0.00002,
        "documentDeletes": 0.00001,
        "indexReadBatches": 0.00001,
        "storageGiBMonths": 1,
        "egressGiB": 1,
        "authMau": 0.01,
    }
    return {
        "schemaVersion": 1,
        "project": PROJECT,
        "projectNumber": NUMBER,
        "database": "(default)",
        "edition": "STANDARD",
        "databaseType": "FIRESTORE_NATIVE",
        "diagnosticRows": {"auth": 19, "firestore": 27},
        "firestorePrograms": selected,
        "authScenarioSha256": hashlib.sha256(
            Path(__file__).with_name("broad_cases.py").read_bytes()
        ).hexdigest(),
        "resources": {
            "documents": 8,
            "accounts": 3,
            "maxPayloadBytes": 16384,
            "maxResponseBytes": 65536,
        },
        "limits": dict(LIMITS),
        "wallSeconds": 1200,
        "recoverySeconds": 300,
        "cost": {
            "units": units,
            "planningCeilingRatesUsd": rates,
            "upperEstimateUsd": sum(units[k] * rates[k] for k in units),
            "scanDocumentsPerQuery": 1,
            "queries": 2,
            "collectionGroupQueries": 0,
            "pricingSource": "https://firebase.google.com/docs/firestore/pricing",
            "tariffsVerified": False,
            "approvalRequirement": "Owner must verify location/SKU tariffs do not exceed planning ceilings; no free quota deducted",
            "retentionLimit": "Estimate includes one month of worst-case index storage; unrecovered resources require owner follow-up",
        },
        "productionApproval": None,
        "excluded": [
            "configuration mutations",
            "global reset",
            "collection-group queries",
            "transactions/contention",
            "Rules",
            "SDK/Listen",
            "MFA",
            "OOB",
            "index changes",
        ],
    }


def compile_firestore(manifest, nonce):
    if digest(manifest) != digest(candidate()) or not re.fullmatch(
        r"[a-f0-9]{32}", nonce
    ):
        raise ValueError("unrecognized candidate or namespace")
    result = []
    for index, program in enumerate(manifest["firestorePrograms"]):
        parent = BASE + f"/broad_runs/{nonce}-{index}"
        targets = set()

        def remap(value, parent=parent, targets=targets):
            if isinstance(value, dict):
                return {k: remap(v) for k, v in value.items()}
            if isinstance(value, list):
                return [remap(v) for v in value]
            if not isinstance(value, str):
                return value
            bare = value.removeprefix("/v1/")
            if bare.startswith(ABSTRACT + "/"):
                suffix = bare[len(ABSTRACT) + 1 :]
                doc = suffix.split("?", 1)[0]
                if not re.fullmatch(r"(?:tf|broad)/[a-zA-Z0-9_-]+", doc):
                    raise ValueError("unsupported document reference")
                mapped = parent + "/" + suffix
                targets.add(parent + "/" + doc)
                return ("/v1/" if value.startswith("/v1/") else "") + mapped
            if bare == ABSTRACT + ":commit":
                return "/v1/" + BASE + ":commit"
            if bare == ABSTRACT + ":runQuery":
                return "/v1/" + parent + ":runQuery"
            if "PROJECT" in value or "projects/" in value or "://" in value:
                raise ValueError("unmapped reference")
            return value

        mapped = remap(program)
        mapped.update(
            parent=parent, targets=sorted(targets), abstractDigest=digest(program)
        )
        result.append(mapped)
    return result


class Budget:
    def __init__(self, start):
        self.start = start
        self.recovery = False
        self.counts = dict.fromkeys(LIMITS, 0)

    def reserve(self, service, now, duration=12):
        if service not in {"auth", "firestore", "metadata"} or duration <= 0:
            raise ValueError("invalid reservation")
        deadline = self.start + (1200 if self.recovery else 900)
        ceilings = {"total": 2400 if self.recovery else 2100, service: LIMITS[service]}
        if self.recovery:
            ceilings["recovery"] = 300
        if now + duration > deadline or any(
            self.counts[k] >= v for k, v in ceilings.items()
        ):
            raise ValueError("phase budget exhausted")
        for key in ceilings:
            self.counts[key] += 1


def approve(manifest, approval, nonce, observer_sha, now):
    compile_firestore(manifest, nonce)
    required = {
        "kind": "owner-execution-permission",
        "manifestSha256": digest(manifest),
        "observerSha256": observer_sha,
        "nonce": nonce,
        "project": PROJECT,
        "projectNumber": NUMBER,
        "tariffsConfirmedBelowPlanningCeilings": True,
        "databaseProjectionContractDigest": digest(DATABASE_PROJECTION),
    }
    if any(
        type(approval.get(k)) is not type(v) or approval.get(k) != v
        for k, v in required.items()
    ):
        raise ValueError("missing or mismatched owner approval")
    issued, expiry = approval.get("issuedAt"), approval.get("expiresAt")
    if (
        type(issued) not in (int, float)
        or type(expiry) not in (int, float)
        or not 0 <= now - issued <= 86400
        or not now + 1200 <= expiry <= issued + 86400
    ):
        raise ValueError("approval expired or too short for recovery")
    if not approval.get("ownerIdentity") or not approval.get("permissionReference"):
        raise ValueError("owner provenance required; AI review is not permission")
    for key in (
        "authConfigDigest",
        "databaseProjectionDigest",
        "pricingLocation",
        "pricingCheckedAt",
    ):
        if not isinstance(approval.get(key), str) or not approval[key]:
            raise ValueError("missing approved baseline or pricing provenance")

    approved_database = database_evidence(approval.get("databaseProjection"))
    if approved_database["projectionDigest"] != approval["databaseProjectionDigest"]:
        raise ValueError("approved database projection digest differs")


class Credential:
    def __init__(self):
        self.token = None
        self.expiry = 0
        self.failed = False
        self.attempts = 0

    def accept(self, token, info, sent):
        seconds = info.get("expires_in")
        if self.failed or not token or not str(seconds).isdigit() or int(seconds) <= 1:
            raise ValueError("unverified credential")
        self.token, self.expiry = token, sent + int(seconds) - 1

    def usable(self, now, duration=12):
        return not self.failed and bool(self.token) and now + duration <= self.expiry

    def fail(self):
        self.token, self.expiry, self.failed = None, 0, True


DATABASE_PROJECTION = {
    "version": "database-settings-v1",
    "excludedResponseFields": ["earliestVersionTime"],
    "retainedFields": "all other fields, including unknown fields and field presence/types",
    "requiredIdentityFields": ["name", "uid", "databaseEdition", "type", "locationId"],
    "hashEncoding": "canonical typed JSON SHA256",
}


def database_evidence(body):
    if not isinstance(body, dict) or any(
        not isinstance(body.get(key), str) or not body[key]
        for key in DATABASE_PROJECTION["requiredIdentityFields"]
    ):
        raise ValueError("database identity incomplete")
    projection = {
        k: v
        for k, v in body.items()
        if k not in DATABASE_PROJECTION["excludedResponseFields"]
    }
    return {
        "responseDigest": digest(body),
        "projection": projection,
        "projectionDigest": digest(projection),
        "contract": DATABASE_PROJECTION,
        "contractDigest": digest(DATABASE_PROJECTION),
    }


def recording_exit_code(report):
    return (
        0
        if report.get("completed") is True
        and report.get("failure") is None
        and report.get("unrecovered") == []
        else 2
    )


def wrapper_exit_code(report):
    owned = report.get("ownedProcess", {})
    return (
        0
        if (
            report.get("exitCode") == 0
            and not report.get("cleanupFailure")
            and not report.get("parentCleanupFailure")
            and owned.get("stopped") is True
            and owned.get("listenersClosed") is True
            and recording_exit_code(report.get("batch", {})) == 0
        )
        else 2
    )
