"""Closed local-only admission for the second 45 observations."""

from __future__ import annotations

import copy
import time
from urllib.parse import parse_qsl, urlsplit

from batch_contract import PROJECT
from broad_contract import digest, local_origin
from second_cases import auth_cases, firestore_cases

KIND = "second45-local-admission-v1"
BASE = f"projects/{PROJECT}/databases/(default)/documents"
FS_IDS = (
    "second/masks/ancestor-overlap-state",
    "second/preconditions/stale-delete-state",
    "second/transforms/invalid-path-state",
)
LIMITS = {"auth": 400, "firestore": 100, "metadata": 100, "recovery": 60, "total": 660}
RESERVED = {"auth": 12, "firestore": 12, "metadata": 36}


def manifest():
    return {
        "kind": KIND,
        "seed": 20260913,
        "project": PROJECT,
        "projectNumber": "592603257417",
        "authCases": auth_cases(),
        "firestorePrograms": [p for p in firestore_cases() if p["id"] in FS_IDS],
        "diagnosticRows": 45,
        "limits": LIMITS,
        "recoveryReservations": RESERVED,
        "wallSeconds": 1200,
        "recoverySeconds": 300,
        "productionExecutable": False,
        "productionApproval": None,
    }


class SecondBudget:
    def __init__(self, start=None):
        self.start = time.monotonic() if start is None else start
        self.recovery = False
        self.counts = dict.fromkeys(LIMITS, 0)

    def reserve(self, service, now, duration=12):
        if service not in RESERVED or duration <= 0:
            raise ValueError("invalid reservation")
        ceiling = LIMITS[service] - (0 if self.recovery else RESERVED[service])
        if (
            now + duration > self.start + (1200 if self.recovery else 900)
            or self.counts[service] >= ceiling
            or self.counts["total"] >= LIMITS["total"] - (0 if self.recovery else 60)
            or (self.recovery and self.counts["recovery"] >= 60)
        ):
            raise ValueError("second phase budget exhausted")
        for key in (service, "total") + (("recovery",) if self.recovery else ()):
            self.counts[key] += 1


def origins(value):
    if not isinstance(value, dict) or set(value) != {"auth", "firestore"}:
        raise ValueError("both exact local origins required")
    return {key: local_origin(origin) for key, origin in value.items()}


def operation(service, path, body=None, method="POST", privileged=False):
    parsed = urlsplit(path)
    return {
        "service": service,
        "path": parsed.path,
        "query": [list(p) for p in parse_qsl(parsed.query, keep_blank_values=True)],
        "body": copy.deepcopy(body),
        "method": method,
        "privileged": privileged,
    }


def equal(left, right):
    return digest(left) == digest(right)


def require_operation(actual, expected):
    if not equal(actual, expected):
        raise ValueError("closed operation differs from independent recipe")


# Independent explicit case recipe, deliberately not generated from auth_cases().
# actor, selector, fields; order is part of the contract.
def auth_recipe(index, users):
    s = "$sentinel"
    recipes = [
        ("b", "missing", {"displayName": s}),
        ("b", "self", {"displayName": s}),
        ("b", "other", {"displayName": s}),
        ("b", "null", {"displayName": s}),
        ("b", "number", {"displayName": s}),
        ("b", "object", {"displayName": s}),
        ("b", "array", {"displayName": s}),
        ("b", "missing", {}),
        ("b", "missing", {"displayName": None}),
        ("b", "missing", {"displayName": 0}),
        ("b", "missing", {"displayName": False}),
        ("b", "missing", {"displayName": []}),
        ("b", "missing", {"displayName": {}}),
        *[
            ("b", "missing", {"displayName": s, "emailVerified": v})
            for v in (True, False, None, "true", {})
        ],
        *[
            (
                "b",
                "missing",
                {"displayName": s, "emailVerified": True, "customAttributes": v},
            )
            for v in ('{"admin":true}', "", None, {})
        ],
        *[
            (a, "other", {"displayName": s})
            for a in ("missing", "null", "number", "invalid")
        ],
        *[
            ("admin", "self", {"displayName": s, "emailVerified": v})
            for v in (True, False)
        ],
        ("a", "self", {"displayName": s}),
        ("a", "other", {"displayName": s}),
        ("b", "missing", {"displayName": s, "disableUser": True}),
        ("b", "missing", {"displayName": s, "disableUser": None}),
    ]
    if not 0 <= index < 32:
        raise ValueError("unknown Auth row")
    actor, selector, fields = copy.deepcopy(recipes[index])
    row_id = f"second/auth/{index + 1:02d}"
    body = {k: "updated-" + row_id if v == s else v for k, v in fields.items()}
    role = actor if actor in ("a", "b") else "b"
    if selector in ("self", "other"):
        body["localId"] = users[
            role if selector == "self" else ("a" if role == "b" else "b")
        ]["uid"]
    elif selector != "missing":
        body["localId"] = {"null": None, "number": 0, "object": {}, "array": []}[
            selector
        ]
    if actor in ("a", "b"):
        body["idToken"] = users[actor]["token"]
    elif actor != "missing" and actor != "admin":
        body["idToken"] = {
            "null": None,
            "number": 0,
            "invalid": "controlled-invalid-token",
        }[actor]
    path = (
        f"identitytoolkit.googleapis.com/v1/projects/{PROJECT}/accounts:update"
        if actor == "admin"
        else "identitytoolkit.googleapis.com/v1/accounts:update?key=fake"
    )
    return operation("auth", path, body, privileged=actor == "admin")


def fs_recipe(program, step, name, versions):
    if program not in FS_IDS or not name.startswith(BASE + "/"):
        raise ValueError("unknown Firestore target")
    path = "/v1/" + name
    method, body = "GET", None
    relation = None
    if step not in (
        ("original", "normal", "before", "diagnostic", "after")
        if program == FS_IDS[1]
        else ("normal", "before", "diagnostic", "after")
    ):
        raise ValueError("unknown step")
    if step in ("normal", "diagnostic"):
        if program == FS_IDS[0]:
            method = "PATCH"
            path += "?updateMask.fieldPaths=" + (
                "a.b" if step == "normal" else "a&updateMask.fieldPaths=a.b"
            )
            body = {
                "fields": {
                    "n": {"integerValue": "999"},
                    "a": {
                        "mapValue": {
                            "fields": {
                                "b": {"integerValue": "8" if step == "normal" else "9"}
                            }
                        }
                    },
                }
            }
        elif program == FS_IDS[1]:
            if step == "normal":
                method, body = "PATCH", {"fields": {"n": {"integerValue": "9"}}}
            else:
                original, before = versions.get("original"), versions.get("before")
                if (
                    not isinstance(original, str)
                    or not original
                    or not isinstance(before, str)
                    or original == before
                ):
                    raise ValueError("distinct original and current versions required")
                from urllib.parse import urlencode

                method = "DELETE"
                path += "?" + urlencode({"currentDocument.updateTime": original})
                relation = {
                    "sourceStep": "original",
                    "field": "updateTime",
                    "differsFrom": "before",
                }
        else:
            method, path = "POST", "/v1/" + BASE + ":commit"
            body = {
                "writes": [
                    {
                        "transform": {
                            "document": name,
                            "fieldTransforms": [
                                {
                                    "fieldPath": "t0"
                                    if step == "normal"
                                    else "bad..path",
                                    "increment": {"integerValue": "1"},
                                }
                            ],
                        }
                    }
                ]
            }
    return operation("firestore", path, body, method, True), relation
