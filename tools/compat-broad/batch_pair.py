"""Bound same-input production/local observations; distinct from legacy local mapping checks."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

from batch_contract import (
    DATABASE_PROJECTION,
    PROJECT,
    candidate,
    compile_firestore,
    database_evidence,
    recording_exit_code,
)
from broad_contract import digest, first_difference

AUTH_ROLES = [
    ("create-a", "anonymous"),
    ("create-b", "anonymous"),
    ("short-password-refused", "anonymous"),
    ("refused-create-absent", "administrator"),
    ("self-admin-field", "self:a"),
    ("other-user-selector", "self:b"),
    ("unauthenticated-update", "anonymous"),
    ("refusal-state-a", "administrator"),
    ("refusal-state-b", "administrator"),
    ("admin-update", "administrator"),
    ("self-sees-admin-state", "self:a"),
    ("password-change", "self:a"),
    ("old-password", "password:a"),
    ("new-password", "password:a"),
    ("refresh-after-change", "refresh:a"),
    ("delete-a", "administrator"),
    ("deleted-absent-a", "administrator"),
    ("delete-b", "administrator"),
    ("deleted-absent-b", "administrator"),
]
NORMALIZATION = {
    "version": "batch-response-v1",
    "preserve": "JSON types, field presence, ordinary values, relative expiry, array order, mapped ownership",
    "opaqueAuthKeys": [
        "idToken",
        "id_token",
        "refreshToken",
        "refresh_token",
        "accessToken",
        "passwordHash",
        "salt",
        "passwordSalt",
    ],
    "authAbsoluteTimeKeys": [
        "createdAt",
        "lastLoginAt",
        "validSince",
        "passwordUpdatedAt",
    ],
    "authTimePaths": "only top-level and users/* fields; preserve JSON type and timestamp format validity",
    "firestoreTimePaths": [
        "createTime",
        "updateTime",
        "commitTime",
        "readTime",
        "writeResults/*/updateTime",
        "writeResults/*/transformResults/*/timestampValue",
        "*/readTime",
        "*/document/createTime",
        "*/document/updateTime",
        "fields/at/timestampValue",
    ],
    "errorProsePaths": ["error/message", "error/errors/*/message", "*/error/message"],
    "errorMachineCode": "leading uppercase underscore code retained; structured codes/status/shape retained",
    "namespace": "exact compiled parent mapping; known creation-ledger UID/email values only",
    "excludedClaims": [
        "token byte equality/rotation/cryptographic validity",
        "verifier contents",
        "exact server time/TTL",
        "error prose equality",
    ],
}


def row_table(manifest):
    rows = [
        {
            "id": "firestore:" + p["id"] + "#" + step["id"],
            "principal": "administrator",
            "programDigest": digest(p),
        }
        for p in manifest["firestorePrograms"]
        for step in p["steps"]
    ]
    rows += [
        {
            "id": "auth:broad/" + name,
            "principal": role,
            "programDigest": manifest["authScenarioSha256"],
        }
        for name, role in AUTH_ROLES
    ]
    return [{**row, "ordinal": index} for index, row in enumerate(rows)]


def binding(manifest):
    return {
        "version": "batch-pair-v1",
        "manifestDigest": digest(manifest),
        "rowTable": row_table(manifest),
        "abstractInputsDigest": digest(
            {
                "firestore": manifest["firestorePrograms"],
                "authSource": manifest["authScenarioSha256"],
            }
        ),
        "normalizerVersion": NORMALIZATION["version"],
        "normalizerSpec": NORMALIZATION,
        "normalizerImplementationDigest": hashlib.sha256(
            Path(__file__).read_bytes()
        ).hexdigest(),
        "databaseProjectionContractDigest": digest(DATABASE_PROJECTION),
        "transport": "REST",
        "edition": "Standard Native",
        "project": PROJECT,
    }


def namespace(manifest, nonce, accounts):
    parents = {p["id"]: p["parent"] for p in compile_firestore(manifest, nonce)}
    emails = {
        role: f"broad-{nonce}-{role}@example.invalid" for role in ("a", "b", "weak")
    }
    if not set(accounts) <= set(emails.values()):
        raise ValueError("unknown ownership email")
    uids = {
        role: accounts[email]
        for role, email in emails.items()
        if accounts.get(email) is not None
    }
    if any(not isinstance(uid, str) or not uid for uid in uids.values()) or len(
        set(uids.values())
    ) != len(uids):
        raise ValueError("invalid or duplicate ownership UID")
    return {
        "nonce": nonce,
        "firestoreParents": parents,
        "authEmails": emails,
        "authUids": uids,
    }


def json_type(value):
    return {
        str: "string",
        bool: "boolean",
        int: "number",
        float: "number",
        list: "array",
        dict: "object",
        type(None): "null",
    }[type(value)]


def matches(path, pattern):
    parts = pattern.split("/")
    return len(parts) == len(path) and all(
        a == "*" or a == b for a, b in zip(parts, path, strict=True)
    )


def normalize(value, names, *, service, path=()):
    key = path[-1] if path else ""
    if isinstance(value, str):
        if service == "auth":
            if key in {"localId", "user_id"}:
                for role, uid in names["authUids"].items():
                    if value == uid:
                        return {"$account": role}
            if key == "email":
                for role, email in names["authEmails"].items():
                    if value == email:
                        return {"$email": role}
            if key in NORMALIZATION["opaqueAuthKeys"] and value:
                return {"$opaque": key, "jsonType": "string", "nonempty": True}
        if service == "firestore":
            for role, parent in names["firestoreParents"].items():
                if value == parent or value.startswith(parent + "/"):
                    return "documents/" + role + value[len(parent) :]
        if any(matches(path, pattern) for pattern in NORMALIZATION["errorProsePaths"]):
            code = re.match(r"^([A-Z][A-Z0-9_]+)(?:\b|\s*:)", value)
            return {
                "$errorProse": True,
                "machineCode": code.group(1) if code else None,
                "empty": not value,
            }
    auth_time = (
        service == "auth"
        and key in NORMALIZATION["authAbsoluteTimeKeys"]
        and (len(path) == 1 or len(path) == 3 and path[0] == "users")
    )
    fs_time = service == "firestore" and any(
        matches(path, pattern) for pattern in NORMALIZATION["firestoreTimePaths"]
    )
    if auth_time or fs_time:
        valid = (
            (
                type(value) in (str, int, float)
                and bool(re.fullmatch(r"\d+(?:\.\d+)?", str(value)))
            )
            if auth_time
            else (
                isinstance(value, str)
                and bool(
                    re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z", value)
                )
            )
        )
        if valid:
            return {
                "$absoluteTime": True,
                "jsonType": json_type(value),
                "formatValid": True,
            }
    if isinstance(value, list):
        return [
            normalize(item, names, service=service, path=(*path, str(i)))
            for i, item in enumerate(value)
        ]
    if isinstance(value, dict):
        return {
            k: normalize(v, names, service=service, path=(*path, k))
            for k, v in value.items()
        }
    return value


def compare_pair(production, local):
    manifest = candidate()
    contract = binding(manifest)
    errors = []
    table = row_table(manifest)
    expected = [row["id"] for row in table]
    by_side = {}
    for side, report, is_production in [
        ("production", production, True),
        ("local", local, False),
    ]:
        if (
            report.get("schemaVersion") != 2
            or report.get("productionExecuted") is not is_production
            or report.get("manifestDigest") != digest(manifest)
            or digest(report.get("comparisonBinding")) != digest(contract)
        ):
            errors.append(side + ":report-binding")
        try:
            names = report["namespace"]
            accounts = {
                names["authEmails"][role]: uid
                for role, uid in names["authUids"].items()
            }
            if digest(namespace(manifest, names["nonce"], accounts)) != digest(names):
                errors.append(side + ":namespace")
        except (KeyError, TypeError, ValueError):
            errors.append(side + ":namespace")
        rows = report.get("rows", [])
        if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
            rows = []
            errors.append(side + ":row-shape")
        if any(not isinstance(row.get("id"), str) for row in rows):
            errors.append(side + ":row-id")
            rows = [row for row in rows if isinstance(row.get("id"), str)]
        ids = [row.get("id") for row in rows]
        if len(set(ids)) != len(ids):
            errors.append(side + ":duplicate-row")
        if any(id not in expected for id in ids):
            errors.append(side + ":unexpected-row")
        if ids != [id for id in expected if id in ids]:
            errors.append(side + ":row-order")
        by_side[side] = {
            row["id"]: row for row in rows if isinstance(row.get("id"), str)
        }
    if not production.get("observerDigest") or production.get(
        "observerDigest"
    ) != local.get("observerDigest"):
        errors.append("observer-difference")
    if production.get("configurationUnchanged") is not True:
        errors.append("production:configuration-unconfirmed")
    records = production.get("databaseObservations", [])
    try:
        valid_database = (
            isinstance(records, list)
            and len(records) == 2
            and all(
                r.get("contractDigest") == digest(DATABASE_PROJECTION)
                and database_evidence(r.get("projection"))["projectionDigest"]
                == r.get("projectionDigest")
                for r in records
            )
            and records[0].get("projectionDigest")
            == records[-1].get("projectionDigest")
        )
    except (TypeError, ValueError, AttributeError):
        valid_database = False
    if not valid_database:
        errors.append("production:database-projection")
    compared = []
    for spec in table:
        a, b = (by_side[s].get(spec["id"]) for s in ("production", "local"))
        state, difference = "missing", None
        if a is not None and b is not None:
            if (
                a.get("principal") != spec["principal"]
                or b.get("principal") != spec["principal"]
                or "operation" not in a
                or "operation" not in b
                or digest(a["operation"]) != digest(b["operation"])
            ):
                errors.append(spec["id"] + ":operation/principal")
            oa, ob = a.get("observation"), b.get("observation")
            valid = all(
                isinstance(o, dict)
                and type(o.get("httpStatus")) is int
                and 100 <= o["httpStatus"] <= 599
                and isinstance(o.get("mediaType"), str)
                and "body" in o
                for o in [oa, ob]
            )
            if valid:
                difference = first_difference(oa, ob)
                state = "match" if difference is None else "mismatch"
            else:
                state = "indeterminate"
        compared.append(
            {"id": spec["id"], "status": state, "firstDifference": difference}
        )
    complete = (
        not errors
        and all(row["status"] in {"match", "mismatch"} for row in compared)
        and not recording_exit_code(production)
        and not recording_exit_code(local)
    )
    compatibility = (
        "indeterminate"
        if not complete
        else "mismatch"
        if any(row["status"] == "mismatch" for row in compared)
        else "match"
    )
    return {
        "mode": "production-versus-local",
        "evidenceKind": "input-fixture"
        if production.get("fixtureOnly") or local.get("fixtureOnly")
        else "recorded-observations",
        "recordingComplete": complete,
        "bindingsValid": not errors,
        "bindingErrors": errors,
        "cleanupComplete": production.get("unrecovered") == []
        and local.get("unrecovered") == [],
        "compatibility": compatibility,
        "rows": compared,
        "manifestDigest": digest(manifest),
        "comparisonContractDigest": digest(contract),
    }


def exit_code(result, check=False):
    return (
        2
        if not result["recordingComplete"]
        else 1
        if check and result["compatibility"] != "match"
        else 0
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--production", type=Path, required=True)
    parser.add_argument("--local", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    result = compare_pair(
        json.loads(args.production.read_bytes()), json.loads(args.local.read_bytes())
    )
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(
        json.dumps(
            {k: v for k, v in result.items() if k not in {"rows", "bindingErrors"}}
        )
    )
    return exit_code(result, args.check)


if __name__ == "__main__":
    sys.exit(main())
