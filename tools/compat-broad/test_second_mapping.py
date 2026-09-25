"""Synthetic input receipts exercise mapping validity, never runtime compatibility."""

import copy
import hashlib
import json

import pytest
from broad_contract import digest
from second_admission import (
    BASE,
    FS_IDS,
    PROJECT,
    auth_recipe,
    fs_recipe,
    manifest,
    operation,
)
from second_mapping import compare_second


def receipt(mode):
    nonce = ("a" if mode == "direct" else "b") * 32
    users = {
        r: {
            "uid": nonce + r,
            "token": nonce + r + "-token",
            "email": f"broad-{nonce}-{r}@example.invalid",
        }
        for r in ("a", "b")
    }
    result = {
        "mode": mode,
        "nonce": nonce,
        "bindings": users,
        "documents": {},
        "rows": [],
        "trace": [],
        "recordingComplete": True,
        "cleanupComplete": True,
        "safety": True,
        "manifestDigest": digest(manifest()),
        "observerDigest": "a" * 64,
        "runtimeIdentity": {
            "artifactSha256": "b" * 64,
            "executionCommit": "c" * 40,
            "configurationDigest": "d" * 64,
        },
    }
    admin = f"identitytoolkit.googleapis.com/v1/projects/{PROJECT}/accounts:"

    def emit(phase, op, body, status=200):
        observation = {
            "httpStatus": status,
            "mediaType": "application/json",
            "body": copy.deepcopy(body),
        }
        raw = json.dumps(body).encode()
        observation["http"] = {
            "contract": "bounded-http-v1",
            "status": status,
            "complete": True,
            "failure": None,
            "truncated": False,
            "digestScope": "full",
            "bodyKind": "json",
            "contentType": "application/json",
            "contentTypeTruncated": False,
            "receivedBytes": len(raw),
            "retainedBytes": len(raw),
            "bodySha256": hashlib.sha256(raw).hexdigest(),
        }
        result["trace"].append(
            {
                "ordinal": len(result["trace"]),
                "phase": phase,
                "recovery": phase == "recovery",
                "sent": copy.deepcopy(op),
                "observation": observation,
            }
        )
        return copy.deepcopy(observation)

    states = {
        r: {"localId": u["uid"], "email": u["email"], "emailVerified": False}
        for r, u in users.items()
    }

    def lookup(phase, role, present=True):
        return emit(
            phase,
            operation(
                "auth",
                admin + "lookup",
                {"email": [users[role]["email"]]},
                privileged=True,
            ),
            {"users": [states[role]]} if present else {},
        )

    for role, user in users.items():
        lookup("setup", role, False)
        emit(
            "setup",
            operation(
                "auth",
                "identitytoolkit.googleapis.com/v1/accounts:signUp?key=fake",
                {
                    "email": user["email"],
                    "password": "abc123",
                    "returnSecureToken": True,
                },
            ),
            {"localId": user["uid"], "idToken": user["token"]},
        )
    for i in range(32):
        row_id = f"second/auth/{i + 1:02d}"
        for role in users:
            lookup("baseline", role)
            states[role]["displayName"] = role + "-before-" + row_id
            emit(
                "baseline",
                operation(
                    "auth",
                    admin + "update",
                    {
                        "localId": users[role]["uid"],
                        "displayName": states[role]["displayName"],
                        "emailVerified": False,
                    },
                    privileged=True,
                ),
                {},
            )
        for role in users:
            lookup("before", role)
        if i in (26, 27):
            lookup("before", "b")
        op = auth_recipe(i, users)
        observed = emit(
            "diagnostic",
            op,
            {"error": {"code": 400, "message": "FIXTURE_REFUSAL"}},
            400,
        )
        for role in users:
            lookup("after", role)
        result["rows"].append(
            {
                "id": row_id,
                "sent": op,
                "observation": observed,
                "before": copy.deepcopy(states),
                "after": copy.deepcopy(states),
                "relation": None,
            }
        )
    for role in users:
        lookup("recovery", role)
        lookup("recovery", role)
        emit(
            "recovery",
            operation(
                "auth",
                admin + "delete",
                {"localId": users[role]["uid"]},
                privileged=True,
            ),
            {},
        )
        lookup("recovery", role, False)
    for i, program in enumerate(FS_IDS):
        name = BASE + (
            "/cur/c" if mode == "direct" else f"/_fireemuBroad/{nonce}-{i}/cur/c"
        )
        result["documents"][program] = name
        get = operation("firestore", "/v1/" + name, method="GET", privileged=True)
        emit("absence", get, {}, 404)
        fields = {
            "n": {"integerValue": "2"},
            "g": {"stringValue": "q"},
            "a": {"mapValue": {"fields": {"b": {"integerValue": "7"}}}},
        }
        emit(
            "seed",
            operation(
                "firestore",
                "/v1/" + name + "?currentDocument.exists=false",
                {"fields": fields},
                "PATCH",
                True,
            ),
            {},
        )
        versions = {}
        for step in (
            ("original", "normal", "before", "diagnostic", "after")
            if i == 1
            else ("normal", "before", "diagnostic", "after")
        ):
            op, relation = fs_recipe(program, step, name, versions)
            body = {
                "name": name,
                "fields": fields,
                "updateTime": "2026-09-13T00:00:00Z"
                if step == "original"
                else "2026-09-13T00:00:01Z",
            }
            observed = emit(
                step,
                op,
                body if step != "diagnostic" else {"error": {"code": 400}},
                400 if step == "diagnostic" else 200,
            )
            if step in ("original", "before", "after"):
                versions[step] = body["updateTime"]
            result["rows"].append(
                {
                    "id": program + "/" + step,
                    "sent": op,
                    "observation": observed,
                    "versions": copy.deepcopy(versions),
                    "relation": relation,
                    "document": name,
                }
            )
        emit("recovery", get, body)
        from urllib.parse import urlencode

        emit(
            "recovery",
            operation(
                "firestore",
                "/v1/"
                + name
                + "?"
                + urlencode({"currentDocument.updateTime": body["updateTime"]}),
                method="DELETE",
                privileged=True,
            ),
            {},
        )
        emit("recovery", get, {}, 404)
    return result


def test_complete_synthetic_pair_is_mapping_only():
    comparison = compare_second(receipt("direct"), receipt("mapped"))
    assert comparison["mapping"] == "match", comparison["errors"]
    assert len(comparison["rows"]) == 45
    assert comparison["safety"] is True
    assert comparison["productionCompatibility"] == "unobserved"


@pytest.mark.parametrize(
    "mutation",
    [
        "query",
        "row-only",
        "latest",
        "missing",
        "duplicate",
        "order",
        "setup",
        "baseline",
        "before",
        "after",
        "recovery",
        "non-json",
        "partial",
        "budget",
        "artifact",
        "observer",
    ],
)
def test_symmetric_errors_cannot_become_mapping_success(mutation):
    sides = [receipt("direct"), receipt("mapped")]
    for result in sides:
        trace = result["trace"]
        if mutation in ("query", "row-only"):
            row = next(
                r for r in result["rows"] if r["id"] == FS_IDS[0] + "/diagnostic"
            )
            row["sent"]["query"] = row["sent"]["query"][:1]
            if mutation == "query":
                entry = next(
                    e
                    for e in trace
                    if e["sent"]["service"] == "firestore"
                    and e["phase"] == "diagnostic"
                )
                entry["sent"]["query"] = entry["sent"]["query"][:1]
        elif mutation == "latest":
            row = next(
                r for r in result["rows"] if r["id"] == FS_IDS[1] + "/diagnostic"
            )
            row["sent"]["query"][0][1] = row["versions"]["before"]
            row["versions"]["original"] = row["versions"]["before"]
        elif mutation == "missing":
            result["rows"].pop()
        elif mutation == "duplicate":
            result["rows"].append(copy.deepcopy(result["rows"][-1]))
        elif mutation == "order":
            result["rows"].reverse()
        elif mutation in ("setup", "baseline", "before", "after", "recovery"):
            entry = next(e for e in trace if e["phase"] == mutation)
            entry["sent"]["body"] = {"localId": "foreign"}
        elif mutation in ("non-json", "partial", "budget"):
            entry = trace[20]
            entry["observation"] = (
                None
                if mutation == "budget"
                else {"httpStatus": 404, "body": None, "mediaType": "text/plain"}
            )
            entry["failure"] = mutation
        elif mutation == "artifact":
            result["runtimeIdentity"] = {}
        else:
            result["observerDigest"] = None
    assert compare_second(*sides)["mapping"] == "invalid"


def test_cleanup_incomplete_is_not_recording_success():
    direct, mapped = receipt("direct"), receipt("mapped")
    mapped["cleanupComplete"] = False
    result = compare_second(direct, mapped)
    assert not result["recordingComplete"]
    assert result["mapping"] == "invalid"


def test_dynamic_wire_digests_are_not_semantic_response_values():
    left, right = receipt("direct"), receipt("mapped")
    assert (
        left["trace"][1]["observation"]["http"]["bodySha256"]
        != right["trace"][1]["observation"]["http"]["bodySha256"]
    )
    assert compare_second(left, right)["mapping"] == "match"


@pytest.mark.parametrize(
    "patch",
    [
        {"complete": False},
        {"bodyKind": "non-json"},
        {"bodySha256": None},
        {"retainedBytes": -1},
        {"failure": "body-interrupted"},
    ],
)
def test_http_receipt_integrity_is_required_independently_of_json_body(patch):
    left, right = receipt("direct"), receipt("mapped")
    for side in (left, right):
        side["trace"][1]["observation"]["http"].update(patch)
    assert compare_second(left, right)["mapping"] == "invalid"
