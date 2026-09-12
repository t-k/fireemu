"""Short seeded gaps in the existing corpus; real local HTTP, no stored-response backend."""

from __future__ import annotations

import json
import random
import time
import urllib.error
import urllib.parse
import urllib.request

from broad_contract import local_origin

PROJECT = "demo-firestore-probe"
SEED = 20260912


def generated_programs(seed=SEED):
    value = random.Random(seed).randint(1, 100)
    base = "/v1/projects/PROJECT/databases/(default)/documents"
    fields = {"n": {"integerValue": str(value)}}
    return [
        {
            "id": "broad/refusal-preserves-state",
            "area": "writes-and-queries",
            "seed": [{"path": base + "/broad/one", "fields": fields}],
            "steps": [
                {
                    "id": "read-normal",
                    "method": "GET",
                    "path": base + "/broad/one",
                    "expect": "original-fields",
                },
                {
                    "id": "refused-overwrite",
                    "method": "PATCH",
                    "path": base + "/broad/one?currentDocument.exists=false",
                    "body": {"fields": {"n": {"integerValue": str(value + 1)}}},
                    "expect": "refusal",
                },
                {
                    "id": "read-after-refusal",
                    "method": "GET",
                    "path": base + "/broad/one",
                    "expect": "original-fields",
                },
                {
                    "id": "empty-commit",
                    "method": "POST",
                    "path": base + ":commit",
                    "body": {"writes": []},
                    "expect": "success",
                },
                {
                    "id": "zero-limit",
                    "method": "POST",
                    "path": base + ":runQuery",
                    "body": {
                        "structuredQuery": {
                            "from": [{"collectionId": "broad"}],
                            "limit": 0,
                        }
                    },
                    "expect": "no-documents",
                },
                {
                    "id": "negative-limit",
                    "method": "POST",
                    "path": base + ":runQuery",
                    "body": {
                        "structuredQuery": {
                            "from": [{"collectionId": "broad"}],
                            "limit": -1,
                        }
                    },
                    "expect": "refusal",
                },
                {
                    "id": "read-after-query-refusal",
                    "method": "GET",
                    "path": base + "/broad/one",
                    "expect": "original-fields",
                },
            ],
        }
    ]


def check_generated(program, actual):
    rows = []
    for step in program["steps"]:
        got = actual.get("steps", {}).get(step["id"], {})
        status, body = got.get("status", 0), got.get("body")
        expectation = step["expect"]
        good = 200 <= status < 300 and got.get("code") == "OK"
        if expectation == "refusal":
            good = 400 <= status < 500
        elif expectation == "original-fields":
            good = (
                good
                and isinstance(body, dict)
                and body.get("fields") == program["seed"][0]["fields"]
            )
        elif expectation == "no-documents":
            good = (
                good
                and isinstance(body, list)
                and not any("document" in entry for entry in body)
            )
        rows.append(
            {
                "id": "firestore:" + program["id"] + "#" + step["id"],
                "family": "fs-queries"
                if "limit" in step["id"] or "query" in step["id"]
                else "fs-writes",
                "status": "pass" if good else "fail",
                "basis": "local-invariant",
                "expectation": expectation,
                "actual": got,
            }
        )
    return rows


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("redirect forbidden")


def auth_cases(origin, seed=SEED):
    origin = local_origin(origin)
    transport = urllib.request.build_opener(
        NoRedirect(), urllib.request.ProxyHandler({})
    )
    requests = 0
    deadline = time.monotonic() + 60
    results = []

    def call(path, body, admin=False, form=False):
        nonlocal requests
        requests += 1
        if requests > 80 or time.monotonic() + 5 > deadline:
            raise ValueError("short Auth request budget exhausted")
        headers = {
            "Content-Type": "application/x-www-form-urlencoded"
            if form
            else "application/json"
        }
        if admin:
            headers["Authorization"] = "Bearer owner"
        data = (
            urllib.parse.urlencode(body).encode() if form else json.dumps(body).encode()
        )
        req = urllib.request.Request(origin + path, data=data, headers=headers)
        try:
            response = transport.open(req, timeout=5)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            return response.status, json.loads(response.read())

    client = "/identitytoolkit.googleapis.com/v1/accounts:"
    admin_path = f"/identitytoolkit.googleapis.com/v1/projects/{PROJECT}/accounts:"

    def emit(name, family, good, status, body, checks):
        error = body.get("error", {}).get("message", "OK").split(" : ", 1)[0]
        # Machine codes and boolean relationships only. Never serialize accounts/tokens.
        code = (
            error
            if error.replace("_", "").isalnum() and len(error) < 80
            else "UNCLASSIFIED_ERROR"
        )
        results.append(
            {
                "id": "auth:broad/" + name,
                "family": family,
                "status": "pass" if good and all(checks.values()) else "fail",
                "basis": "local-invariant",
                "httpStatus": status,
                "code": code,
                "checks": checks,
            }
        )

    users = []
    for label in ("a", "b"):
        email = f"broad-{seed}-{label}@example.invalid"
        status, body = call(
            client + "signUp?key=fake",
            {"email": email, "password": "abc123", "returnSecureToken": True},
        )
        good = status == 200 and all(
            isinstance(body.get(k), str) and body[k]
            for k in ("localId", "idToken", "refreshToken")
        )
        emit(
            "create-" + label,
            "auth-accounts",
            good,
            status,
            body,
            {"sixCharacterPasswordAccepted": good},
        )
        if not good:
            return results
        users.append({"uid": body["localId"], "token": body["idToken"], "email": email})
    a, b = users
    status, body = call(
        client + "signUp?key=fake",
        {
            "email": f"broad-{seed}-weak@example.invalid",
            "password": "12345",
            "returnSecureToken": True,
        },
    )
    emit(
        "short-password-refused",
        "auth-accounts",
        status == 400,
        status,
        body,
        {"singleBoundaryRefusal": status == 400},
    )
    status, body = call(
        admin_path + "lookup",
        {"email": [f"broad-{seed}-weak@example.invalid"]},
        admin=True,
    )
    emit(
        "refused-create-absent",
        "auth-accounts",
        status == 200,
        status,
        body,
        {"noAccountCreated": body.get("users", []) == []},
    )
    for name, payload in [
        (
            "self-admin-field",
            {
                "idToken": a["token"],
                "emailVerified": True,
                "displayName": "must-not-apply",
            },
        ),
        (
            "other-user-selector",
            {
                "idToken": b["token"],
                "localId": a["uid"],
                "displayName": "must-not-apply",
            },
        ),
        ("unauthenticated-update", {"displayName": "must-not-apply"}),
    ]:
        status, body = call(client + "update?key=fake", payload)
        emit(
            name,
            "auth-authorization",
            status == 400,
            status,
            body,
            {"rejected": status == 400},
        )
    for user in users:
        status, body = call(
            admin_path + "lookup", {"localId": [user["uid"]]}, admin=True
        )
        records = body.get("users", [])
        record = records[0] if len(records) == 1 else {}
        emit(
            "refusal-state-" + ("a" if user is a else "b"),
            "auth-authorization",
            status == 200,
            status,
            body,
            {
                "sameUid": record.get("localId") == user["uid"],
                "sameOwnerEmail": record.get("email") == user["email"],
                "displayNameUnchanged": record.get("displayName", "") == "",
                "notVerified": record.get("emailVerified", False) is False,
            },
        )
    status, body = call(
        admin_path + "update", {"localId": a["uid"], "emailVerified": True}, admin=True
    )
    emit(
        "admin-update",
        "auth-authorization",
        status == 200,
        status,
        body,
        {"adminAccepted": status == 200},
    )
    status, body = call(client + "lookup?key=fake", {"idToken": a["token"]})
    records = body.get("users", [])
    emit(
        "self-sees-admin-state",
        "auth-authorization",
        status == 200,
        status,
        body,
        {
            "verifiedState": len(records) == 1
            and records[0].get("emailVerified") is True
        },
    )
    status, body = call(
        client + "update?key=fake",
        {"idToken": a["token"], "password": "newpass7", "returnSecureToken": True},
    )
    emit(
        "password-change",
        "auth-credentials",
        status == 200,
        status,
        body,
        {"sameUid": body.get("localId") == a["uid"]},
    )
    for password, accepted in (("abc123", False), ("newpass7", True)):
        status, body = call(
            client + "signInWithPassword?key=fake",
            {"email": a["email"], "password": password, "returnSecureToken": True},
        )
        emit(
            "new-password" if accepted else "old-password",
            "auth-credentials",
            status == (200 if accepted else 400),
            status,
            body,
            {
                "sameUid" if accepted else "oldPasswordRefused": body.get("localId")
                == a["uid"]
                if accepted
                else status == 400
            },
        )
        if accepted and status == 200:
            status, refreshed = call(
                "/securetoken.googleapis.com/v1/token?key=fake",
                {"grant_type": "refresh_token", "refresh_token": body["refreshToken"]},
                form=True,
            )
            emit(
                "refresh-after-change",
                "auth-credentials",
                status == 200,
                status,
                refreshed,
                {
                    "sameUid": refreshed.get("user_id") == a["uid"],
                    "tokenPresent": bool(refreshed.get("id_token")),
                },
            )
    for user in users:
        status, body = call(admin_path + "delete", {"localId": user["uid"]}, admin=True)
        emit(
            "delete-" + ("a" if user is a else "b"),
            "auth-accounts",
            status == 200,
            status,
            body,
            {"deleted": status == 200},
        )
        status, body = call(
            admin_path + "lookup", {"localId": [user["uid"]]}, admin=True
        )
        emit(
            "deleted-absent-" + ("a" if user is a else "b"),
            "auth-accounts",
            status == 200,
            status,
            body,
            {"absent": body.get("users", []) == []},
        )
    return results
