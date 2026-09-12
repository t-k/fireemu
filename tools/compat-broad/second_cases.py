"""Second, local-only exploration over existing bounded transports and historical sessions."""

# ruff: noqa: BLE001 -- Record sanitized transport failures and always unwind owned cleanup.
from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import signal
import sys
from pathlib import Path

from batch_adapter import Adapter, observer_digest
from batch_contract import NUMBER, PROJECT, candidate, wrapper_exit_code
from batch_pair import normalize
from broad import run, save, session
from broad_cases import PROJECT as FIRESTORE_PROJECT
from broad_contract import compare_program, digest, historical, local_origin
from owned_runner import control_get, local_addresses

SEED = 20260913
HISTORICAL_FS = [
    "queries/projection-and-listing",
    "queries/collection-group",
    "errors/rest-shapes",
    "reads/read-time",
]


def auth_cases():
    cases = []

    def add(dimension, actor="b", selector="missing", **fields):
        cases.append(
            {
                "id": f"second/auth/{len(cases) + 1:02d}",
                "dimension": dimension,
                "actor": actor,
                "selector": selector,
                "fields": fields,
                "productionExpectation": None,
            }
        )

    for selector in ["missing", "self", "other", "null", "number", "object", "array"]:
        add("selector", selector=selector, displayName="$sentinel")
    for value in ["$missing", None, 0, False, [], {}]:
        add("displayName-shape", displayName=value)
    for value in [True, False, None, "true", {}]:
        add("verification-shape", displayName="$sentinel", emailVerified=value)
    for value in ['{"admin":true}', "", None, {}]:
        add(
            "restricted-mix",
            displayName="$sentinel",
            emailVerified=True,
            customAttributes=value,
        )
    for actor in ["missing", "null", "number", "invalid"]:
        add("principal", actor=actor, selector="other", displayName="$sentinel")
    for value in [True, False]:
        add(
            "admin-control",
            actor="admin",
            selector="self",
            displayName="$sentinel",
            emailVerified=value,
        )
    for selector in ["self", "other"]:
        add("selector", actor="a", selector=selector, displayName="$sentinel")
    for value in [True, None]:
        add("restricted-mix", displayName="$sentinel", disableUser=value)
    return cases


def firestore_cases():
    base = "/v1/projects/PROJECT/databases/(default)/documents"
    name = base.removeprefix("/v1/") + "/cur/c"
    fields = {
        "n": {"integerValue": "2"},
        "g": {"stringValue": "q"},
        "a": {"mapValue": {"fields": {"b": {"integerValue": "7"}}}},
    }

    def get(id):
        return {"id": id, "method": "GET", "path": "/v1/" + name}

    def query(id, value):
        return {
            "id": id,
            "method": "POST",
            "path": base + ":runQuery",
            "body": {"structuredQuery": value},
        }

    def program(id, normal, diagnostic, seed=None):
        return {
            "id": "second/" + id,
            "area": id.split("/")[0],
            "seed": seed or [{"path": "/v1/" + name, "fields": fields}],
            "steps": [normal, get("before"), diagnostic, get("after")],
        }

    def operand(n):
        return {
            "from": [{"collectionId": "cur"}],
            "where": {
                "fieldFilter": {
                    "field": {"fieldPath": "n"},
                    "op": "IN",
                    "value": {
                        "arrayValue": {
                            "values": [{"integerValue": str(i)} for i in range(n)]
                        }
                    },
                }
            },
        }

    order = [{"field": {"fieldPath": p}, "direction": "ASCENDING"} for p in ["g", "n"]]

    def cursor(before):
        return {
            "from": [{"collectionId": "cur"}],
            "orderBy": order,
            "startAt": {"values": [{"stringValue": "q"}], "before": before},
        }

    def patch(id, mask):
        value = 8 if id == "normal" else 9
        return {
            "id": id,
            "method": "PATCH",
            "path": "/v1/" + name + "?" + mask,
            "body": {
                "fields": {
                    "n": {"integerValue": "999"},
                    "a": {"mapValue": {"fields": {"b": {"integerValue": str(value)}}}},
                }
            },
        }

    def transforms(id, count, invalid=False):
        items = [
            {"fieldPath": f"t{i}", "increment": {"integerValue": "1"}}
            for i in range(count)
        ]
        if invalid:
            items = [{"fieldPath": "bad..path", "increment": {"integerValue": "1"}}]
        return {
            "id": id,
            "method": "POST",
            "path": base + ":commit",
            "body": {
                "writes": [{"transform": {"document": name, "fieldTransforms": items}}]
            },
        }

    return [
        program(
            "filters/in-30-31-state",
            query("normal", operand(30)),
            query("diagnostic", operand(31)),
        ),
        program(
            "cursors/exclusive-prefix-state",
            query("normal", cursor(True)),
            query("diagnostic", cursor(False)),
            [
                {
                    "path": base + "/cur/a",
                    "fields": {"g": {"stringValue": "p"}, "n": {"integerValue": "1"}},
                },
                {"path": "/v1/" + name, "fields": fields},
                {
                    "path": base + "/cur/d",
                    "fields": {"g": {"stringValue": "r"}, "n": {"integerValue": "3"}},
                },
            ],
        ),
        program(
            "masks/ancestor-overlap-state",
            patch("normal", "updateMask.fieldPaths=a.b"),
            patch("diagnostic", "updateMask.fieldPaths=a&updateMask.fieldPaths=a.b"),
        ),
        {
            "id": "second/preconditions/stale-delete-state",
            "area": "preconditions",
            "seed": [{"path": "/v1/" + name, "fields": fields}],
            "steps": [
                get("original"),
                {
                    "id": "normal",
                    "method": "PATCH",
                    "path": "/v1/" + name,
                    "body": {"fields": {"n": {"integerValue": "9"}}},
                },
                get("before"),
                {
                    "id": "diagnostic",
                    "method": "DELETE",
                    "path": "/v1/"
                    + name
                    + "?currentDocument.updateTime={{original.updateTime}}",
                },
                get("after"),
            ],
        },
        program(
            "transforms/invalid-path-state",
            transforms("normal", 1),
            transforms("diagnostic", 1, True),
        ),
        program(
            "transforms/count-500-501-state",
            transforms("normal", 500),
            transforms("diagnostic", 501),
        ),
    ]


def manifest():
    return {
        "kind": "second-broad-local-v1",
        "seed": SEED,
        "project": PROJECT,
        "projectNumber": NUMBER,
        "firestoreHistoricalProject": "demo-firestore-probe",
        "edition": "STANDARD",
        "transport": "REST",
        "authCases": auth_cases(),
        "firestorePrograms": firestore_cases(),
        "historicalFirestorePrograms": HISTORICAL_FS,
        "productionApproval": None,
        "productionExecutable": False,
        "productionCandidate": {
            "authCases": [c["id"] for c in auth_cases()],
            "firestorePrograms": [p["id"] for p in firestore_cases()],
            "requires": "New closed admission review, owned namespace mapping, scan/cost bounds and explicit owner approval; no prior nonce or permission applies",
        },
        "localBounds": {
            "authRequests": 400,
            "authWallSeconds": 900,
            "authRecoverySeconds": 300,
            "accounts": 2,
            "firestoreSessionRequests": 1500,
            "firestoreSessionSeconds": 120,
            "ownedSupervisorSeconds": 240,
        },
        "deferred": [
            "signed anonymous update principal",
            "initially verified clients",
            "MFA/OOB/provider mutation",
            "password mutation matrix",
            "production compatibility for every new sequence",
            "production Rules/SDK/Listen",
        ],
    }


def same(a, b):
    return digest(a) == digest(b)


def auth_invariants(case, status, before, after):
    actor = case["actor"]
    target = "b" if actor == "admin" else actor
    checks = {
        "bothAccountsPresent": set(before) == set(after) == {"a", "b"},
        "identitiesPreserved": all(
            same(before[r].get("localId"), after[r].get("localId"))
            and same(before[r].get("email"), after[r].get("email"))
            for r in before
        ),
    }
    checks["nonTargetUnchanged"] = all(
        same(before[r], after[r]) for r in before if r != target
    )
    checks["refusalAtomic"] = status < 400 or same(before, after)
    if actor != "admin":
        checks["noPrivilegeChange"] = all(
            same(
                {
                    k: before[r][k]
                    for k in [
                        "emailVerified",
                        "disabled",
                        "customAttributes",
                        "mfaInfo",
                    ]
                    if k in before[r]
                },
                {
                    k: after[r][k]
                    for k in [
                        "emailVerified",
                        "disabled",
                        "customAttributes",
                        "mfaInfo",
                    ]
                    if k in after[r]
                },
            )
            for r in before
        )
    return checks


def state_invariant(status, before, after):
    return same(before, after) if status >= 400 else None


def execute_auth(origin, firestore_origin, output, nonce):
    # Reuse the first adapter's ownership journal/budget/cleanup, never its remote entry.
    a = Adapter(
        candidate(),
        nonce,
        output,
        local_origins={
            "auth": local_origin(origin),
            "firestore": local_origin(firestore_origin),
        },
    )
    rows = []
    failure = None
    users = {}
    admin = f"identitytoolkit.googleapis.com/v1/projects/{PROJECT}/accounts:"

    def snapshot():
        result = {}
        for role, user in users.items():
            records = a.lookup(user["email"])
            if len(records) != 1 or records[0].get("localId") != user["uid"]:
                raise ValueError("owned account readback incomplete")
            result[role] = records[0]
        return result

    def public_state(value):
        return {
            role: normalize({"users": [record]}, a.names(), service="auth")["users"][0]
            for role, record in value.items()
        }

    try:
        for role in ["a", "b"]:
            email = f"broad-{nonce}-{role}@example.invalid"
            status, body = a.auth_call(
                "identitytoolkit.googleapis.com/v1/accounts:signUp?key=fake",
                {"email": email, "password": "abc123", "returnSecureToken": True},
            )
            if status != 200 or not body.get("idToken"):
                raise ValueError("owned setup failed")
            users[role] = {
                "uid": body["localId"],
                "token": body["idToken"],
                "email": email,
            }
        for case in auth_cases():
            for role in ["a", "b"]:
                status, _ = a.auth_call(
                    admin + "update",
                    {
                        "localId": users[role]["uid"],
                        "displayName": role + "-before-" + case["id"],
                        "emailVerified": False,
                    },
                    admin=True,
                )
                if status != 200:
                    raise ValueError("baseline failed")
            before = snapshot()
            if any(
                before[role].get("displayName") != role + "-before-" + case["id"]
                or before[role].get("emailVerified") is not False
                for role in users
            ):
                raise ValueError("baseline readback mismatch")
            actor = case["actor"]
            role = actor if actor in users else "b"
            payload = {
                k: ("updated-" + case["id"] if v == "$sentinel" else v)
                for k, v in case["fields"].items()
                if v != "$missing"
            }
            selector = case["selector"]
            if selector != "missing":
                payload["localId"] = {
                    "self": users[role]["uid"],
                    "other": users["a" if role == "b" else "b"]["uid"],
                    "null": None,
                    "number": 0,
                    "object": {},
                    "array": [],
                }[selector]
            privileged = actor == "admin"
            if actor in users:
                payload["idToken"] = users[actor]["token"]
            elif actor in ["null", "number", "invalid"]:
                payload["idToken"] = {
                    "null": None,
                    "number": 0,
                    "invalid": "controlled-invalid-token",
                }[actor]
            path = (
                admin + "update"
                if privileged
                else "identitytoolkit.googleapis.com/v1/accounts:update?key=fake"
            )
            if privileged:
                # The only privileged diagnostics have the exact owned B UID and known fields.
                if payload["localId"] != users["b"]["uid"]:
                    raise ValueError("admin selector is not owned B")
                a.owner(payload["localId"])
            operation = a.normal_operation(path, "POST", payload, "auth")
            status, _ = a.request("auth", path, payload, privileged=privileged)
            observation = a.normal_observation("auth")
            after = snapshot()
            checks = auth_invariants(case, status, before, after)
            rows.append(
                {
                    "id": case["id"],
                    "family": "auth-update-matrix",
                    "basis": "local-safety-invariant",
                    "status": "pass" if all(checks.values()) else "fail",
                    "coverage": case,
                    "operation": operation,
                    "principal": actor,
                    "observation": observation,
                    "before": public_state(before),
                    "after": public_state(after),
                    "checks": checks,
                    "productionCompatibility": "unobserved",
                }
            )
            if not all(checks.values()):
                raise ValueError("safety invariant failed; stop affected Auth sequence")
    except Exception as error:
        failure = type(error).__name__
    finally:
        a.cleanup()
    result = {
        "kind": "second-auth-local-observations",
        "rows": rows,
        "completed": failure is None
        and not a.unrecovered
        and len(rows) == len(auth_cases()),
        "failure": failure,
        "unrecovered": a.unrecovered,
        "counts": a.budget.counts,
        "observerDigest": observer_digest(),
        "manifestDigest": digest(manifest()),
        "productionExecuted": False,
    }
    save(output / "result.json", result)
    return result


def valid_observation(value):
    return (
        isinstance(value, dict)
        and type(value.get("status")) is int
        and 100 <= value["status"] <= 599
        and value.get("code") not in {"no-response", "probe-error", "non-json"}
    )


def recording_complete(selected, actual):
    return set(actual) == {p["id"] for p in selected} and all(
        set(actual[p["id"]].get("steps", {})) == {s["id"] for s in p["steps"]}
        and all(
            valid_observation(actual[p["id"]]["steps"].get(s["id"])) for s in p["steps"]
        )
        for p in selected
    )


def exit_code(report):
    if wrapper_exit_code(
        {
            **report,
            "exitCode": 0 if report.get("status") == "completed" else 2,
            "batch": {
                **report.get("auth", {}),
                "completed": report.get("recordingComplete") is True
                and report.get("auth", {}).get("completed") is True,
            },
        }
    ):
        return 2
    return 1 if any(r["status"] == "fail" for r in report.get("cases", [])) else 0


def usable_readback(value, expected_name):
    """A state comparison requires the requested document, not merely HTTP200."""
    return (
        valid_observation(value)
        and value.get("status") == 200
        and value.get("code") == "OK"
        and isinstance(value.get("body"), dict)
        and value["body"].get("name") == expected_name
        and isinstance(value["body"].get("fields"), dict)
    )


def state_row(program, observations):
    reads = {s["id"]: s for s in program["steps"] if s["id"] in {"before", "after"}}
    usable = all(
        key in reads
        and reads[key].get("method") == "GET"
        and usable_readback(
            observations.get(key),
            reads[key]["path"]
            .split("?", 1)[0]
            .removeprefix("/v1/")
            .replace("PROJECT", FIRESTORE_PROJECT),
        )
        for key in ["before", "after"]
    )
    if not usable:
        return {
            "status": "indeterminate",
            "reason": "unusable-state-readback",
            "applies": None,
        }
    diagnostic = observations.get("diagnostic")
    if not valid_observation(diagnostic):
        return {
            "status": "indeterminate",
            "reason": "unusable-diagnostic",
            "applies": None,
        }
    before, after = (observations[k]["body"] for k in ["before", "after"])
    invariant = state_invariant(diagnostic["status"], before, after)
    if program["area"] in ["filters", "cursors"]:
        invariant = same(before, after)
    return {
        "status": "pass"
        if invariant is True
        else "observed"
        if invariant is None
        else "fail",
        "reason": None,
        "applies": invariant is not None,
    }


def firestore_rows(selected, actual, old, matrix):
    old_by_id = {p["id"]: p for p in old}
    expected = {p["id"]: p for p in matrix["programs"]}
    rows = []
    for program in selected:
        observations = actual.get(program["id"], {}).get("steps", {})
        if program["id"].startswith("second/"):
            for step in program["steps"]:
                value = observations.get(step["id"])
                rows.append(
                    {
                        "id": "firestore:" + program["id"] + "#" + step["id"],
                        "family": "fs-" + program["area"],
                        "status": "observed" if valid_observation(value) else "missing",
                        "basis": "local-observation",
                        "operation": step,
                        "actual": value,
                        "productionCompatibility": "unobserved",
                    }
                )
            rows.append(
                {
                    "id": "firestore:" + program["id"] + "#state-invariant",
                    "family": "fs-" + program["area"],
                    **state_row(program, observations),
                    "basis": "local-safety-invariant",
                    "productionCompatibility": "unobserved",
                }
            )
        else:
            rows.extend(
                {
                    **row,
                    "id": "firestore:" + row["id"],
                    "family": "fs-historical-expansion",
                    "basis": "historical-production-reference",
                }
                for row in compare_program(
                    program,
                    old_by_id.get(program["id"]),
                    actual.get(program["id"], {}),
                    expected.get(program["id"], {}).get("steps", {}),
                )
            )
    return rows


def child(output, nonce):
    auth = local_origin("http://" + os.environ["FIREBASE_AUTH_EMULATOR_HOST"])
    fs, control = local_addresses(
        os.environ["FIRESTORE_EMULATOR_HOST"], os.environ["FIREEMU_CONTROL_URL"]
    )
    local_origin(fs)
    token = os.environ["FIREEMU_CONTROL_TOKEN"]
    status, body = control_get(control, "/v1/sessions/default/resources", token)
    wrong, _ = control_get(control, "/v1/sessions/default/resources", token + "-wrong")
    if (
        status != 200
        or wrong != 403
        or body.get("project") != PROJECT
        or os.environ["GOOGLE_CLOUD_PROJECT"] != PROJECT
    ):
        raise ValueError("owned identity mismatch")
    save(
        output / "instance.json",
        {
            "pid": os.getpid(),
            "parentPid": os.getppid(),
            "argv": sys.argv,
            "nonce": nonce,
            "authOrigin": auth,
            "firestoreOrigin": fs,
            "controlOrigin": control,
            "wrongTokenStatus": wrong,
        },
    )
    old, matrix, reference = historical("firestore")
    selected = [p for p in old if p["id"] in HISTORICAL_FS] + firestore_cases()
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        auth_job = executor.submit(
            execute_auth, auth, fs, output / "auth-matrix", nonce
        )
        fs_job = executor.submit(session, "firestore", selected, fs, output)
        auth_result = auth_job.result()
        fs_result = fs_job.result()
    rows = auth_result["rows"] + firestore_rows(selected, fs_result, old, matrix)
    report = {
        "schemaVersion": 1,
        "kind": "second-broad-local-v1",
        "cases": rows,
        "manifest": manifest(),
        "manifestDigest": digest(manifest()),
        "auth": auth_result,
        "selectedPrograms": selected,
        "historicalSources": {"firestore": reference},
        "localObservations": {"firestore": fs_result},
        "productionExecuted": False,
        "recordingComplete": auth_result["completed"]
        and recording_complete(selected, fs_result),
        "requestStats": {
            "firestore": json.loads((output / "firestore-stats.json").read_bytes())
        },
    }
    save(output / "cases.json", report)
    if not report["recordingComplete"]:
        raise ValueError("second suite incomplete; see private observations")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--child", type=Path)
    parser.add_argument("--nonce")
    parser.add_argument("--write-manifest", type=Path)
    args = parser.parse_args()
    if args.write_manifest:
        save(args.write_manifest, manifest())
        return 0
    if args.child:
        child(args.child, args.nonce)
        return 0
    if not args.output:
        parser.error("--output required")
    report = run(
        args.output.resolve(),
        child_script=Path(__file__).resolve(),
        project=PROJECT,
        configuration={"daemon": {"authProjectNumbers": {PROJECT: NUMBER}}},
    )
    print(
        json.dumps(
            {
                "status": report["status"],
                "summary": report["summary"],
                "recordingComplete": report["recordingComplete"],
            }
        )
    )
    return exit_code(report)


if __name__ == "__main__":

    def interrupted(_signal, _frame):
        raise InterruptedError("stop requested; unwind owned cleanup")

    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGHUP, interrupted)
    sys.exit(main())
