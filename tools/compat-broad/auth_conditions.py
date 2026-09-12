"""Local-only verified-password and signed-anonymous update observations.

Each diagnostic reads both owned accounts before and after. HTTP outcomes remain
observations; ownership, privilege preservation and refusal atomicity are safety rules.
The original first46/second catalogs and production expectations are not modified.
"""

from __future__ import annotations

# ruff: noqa: BLE001 -- Preserve incomplete evidence and always attempt owned cleanup.
import argparse
import base64
import json
import os
import signal
import sys
import time
from pathlib import Path

from batch_adapter import Adapter
from batch_contract import PROJECT, candidate
from batch_pair import normalize
from broad import save
from broad_contract import digest, local_origin
from owned_runner import control_get, local_addresses
from second_cases import auth_invariants

CLIENT = "identitytoolkit.googleapis.com/v1/accounts:"
ADMIN = f"identitytoolkit.googleapis.com/v1/projects/{PROJECT}/accounts:"


def cases():
    return [
        {
            "id": f"auth-conditions/{principal}/{selector}/{str(verified).lower()}",
            "principal": principal,
            "actor": "b",
            "selector": selector,
            "emailVerified": verified,
            "productionExpectation": None,
        }
        for principal in ["verified-password", "signed-anonymous"]
        for selector in ["self", "foreign"]
        for verified in [True, False]
    ]


def assess(status, before, after):
    if set(before) != {"a", "b"} or set(after) != {"a", "b"}:
        return {"bothAccountsPresent": False}
    return {
        "httpResponsePresent": type(status) is int and 100 <= status <= 599,
        **auth_invariants({"actor": "b"}, status, before, after),
    }


def public_state(value, users):
    names = {
        "authUids": {role: user["uid"] for role, user in users.items()},
        "authEmails": {
            role: user["email"] for role, user in users.items() if "email" in user
        },
        "firestoreParents": {},
    }
    return {
        role: normalize({"users": [record]}, names, service="auth")["users"][0]
        for role, record in value.items()
    }


def signed_principal(token, uid, provider):
    """Inspect signed-token shape; server lookup separately verifies actual acceptance."""
    parts = token.split(".")
    if len(parts) != 3 or not parts[2]:
        return False

    def decoded(part):
        return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))

    header, payload = decoded(parts[0]), decoded(parts[1])
    return (
        header.get("alg") == "RS256"
        and payload.get("sub") == uid
        and payload.get("aud") == PROJECT
        and payload.get("firebase", {}).get("sign_in_provider") == provider
    )


def execute(origin, firestore_origin, output, nonce):
    adapter = Adapter(
        candidate(),
        nonce,
        output,
        local_origins={
            "auth": local_origin(origin),
            "firestore": local_origin(firestore_origin),
        },
    )
    users, rows, setups = {}, [], []
    anonymous_uid = None
    anonymous_attempted = False
    failure = None
    started = time.monotonic()

    def request(path, body, *, privileged=False):
        # Reserve room for recovery; the outer owned supervisor also bounds wall time.
        if not adapter.budget.recovery and (
            time.monotonic() - started > 180
            or sum(adapter.budget.counts.values()) >= 250
        ):
            raise ValueError("observation bound reached")
        return adapter.request("auth", path, body, privileged=privileged)

    def snapshot():
        result = {}
        for role, user in users.items():
            status, body = request(
                ADMIN + "lookup", {"localId": [user["uid"]]}, privileged=True
            )
            records = body.get("users", [])
            if (
                status != 200
                or len(records) != 1
                or records[0].get("localId") != user["uid"]
            ):
                raise ValueError("owned readback incomplete")
            if "email" in user and records[0].get("email") != user["email"]:
                raise ValueError("owned email changed")
            result[role] = records[0]
        return result

    try:
        for role in ["a", "b"]:
            email = f"broad-{nonce}-{role}@example.invalid"
            status, body = adapter.auth_call(
                CLIENT + "signUp?key=fake",
                {"email": email, "password": "abc123", "returnSecureToken": True},
            )
            if status != 200 or not signed_principal(
                body["idToken"], body["localId"], "password"
            ):
                raise ValueError("signed password setup failed")
            users[role] = {
                "uid": body["localId"],
                "email": email,
                "token": body["idToken"],
            }
        for case in cases():
            if case["principal"] == "signed-anonymous" and not anonymous_attempted:
                # The anonymous account has no email. Journal its returned UID separately;
                # never pretend an invented email can prove ownership or clean it up.
                anonymous_attempted = True
                adapter.record({"kind": "anonymous-attempt"})
                status, body = request(
                    CLIENT + "signUp?key=fake", {"returnSecureToken": True}
                )
                if status != 200 or not isinstance(body.get("localId"), str):
                    raise ValueError("anonymous creation incomplete")
                anonymous_uid = body["localId"]
                adapter.record({"kind": "anonymous-created", "uid": anonymous_uid})
                token = body.get("idToken", "")
                if not signed_principal(token, anonymous_uid, "anonymous"):
                    raise ValueError("signed anonymous credential absent")
                users["b"] = {"uid": anonymous_uid, "token": token}
            for role, user in users.items():
                if "email" in user:
                    adapter.owner(user["uid"])
                status, _ = request(
                    ADMIN + "update",
                    {
                        "localId": user["uid"],
                        "displayName": role + "-before-" + case["id"],
                        "emailVerified": "email" in user,
                    },
                    privileged=True,
                )
                if status != 200:
                    raise ValueError("baseline update failed")
            # Refresh the password credential after privileged verification setup; anonymous
            # uses its real signup credential and is never represented by missing auth.
            if case["principal"] == "verified-password":
                status, body = adapter.auth_call(
                    CLIENT + "signInWithPassword?key=fake",
                    {
                        "email": users["b"]["email"],
                        "password": "abc123",
                        "returnSecureToken": True,
                    },
                )
                if status != 200:
                    raise ValueError("verified password signin failed")
                users["b"]["token"] = body["idToken"]
            status, looked = request(
                CLIENT + "lookup?key=fake", {"idToken": users["b"]["token"]}
            )
            if (
                status != 200
                or len(looked.get("users", [])) != 1
                or looked["users"][0].get("localId") != users["b"]["uid"]
            ):
                raise ValueError("principal token not accepted for B")
            before = snapshot()
            verified = case["principal"] == "verified-password"
            if (
                any(
                    before[r].get("displayName") != r + "-before-" + case["id"]
                    for r in users
                )
                or before["a"].get("emailVerified") is not True
                or before["b"].get("emailVerified", False) is not verified
            ):
                raise ValueError("baseline readback mismatch")
            if not verified and (
                before["b"].get("email") or before["b"].get("providerUserInfo")
            ):
                raise ValueError("anonymous baseline is linked")
            setups.append(
                {
                    "id": case["id"],
                    "acceptedTokenOwner": "b",
                    "initialEmailVerified": verified,
                    "signupProvider": "password" if verified else "anonymous",
                }
            )
            payload = {
                "idToken": users["b"]["token"],
                "localId": users["b" if case["selector"] == "self" else "a"]["uid"],
                "displayName": "updated-" + case["id"],
                "emailVerified": case["emailVerified"],
            }
            status, body = request(CLIENT + "update?key=fake", payload)
            after = snapshot()
            checks = assess(status, before, after)
            rows.append(
                {
                    "id": case["id"],
                    "coverage": case,
                    "status": "pass" if all(checks.values()) else "fail",
                    "basis": "local-safety-invariant",
                    "httpStatus": status,
                    "observation": public_state({"response": body}, users)["response"],
                    "before": public_state(before, users),
                    "after": public_state(after, users),
                    "checks": checks,
                    "productionCompatibility": "unobserved",
                }
            )
            if not all(checks.values()):
                raise ValueError("safety failure; stop before runtime edits")
    except Exception as error:
        failure = type(error).__name__
    finally:
        adapter.budget.recovery = True
        if anonymous_attempted:
            try:
                if anonymous_uid is None:
                    raise ValueError("anonymous UID unknown")
                status, body = request(
                    ADMIN + "lookup", {"localId": [anonymous_uid]}, privileged=True
                )
                records = body.get("users", [])
                if (
                    status != 200
                    or len(records) != 1
                    or records[0].get("localId") != anonymous_uid
                    or records[0].get("email")
                    or records[0].get("providerUserInfo")
                ):
                    raise ValueError("anonymous ownership verification failed")
                status, _ = request(
                    ADMIN + "delete", {"localId": anonymous_uid}, privileged=True
                )
                if status != 200:
                    raise ValueError("anonymous deletion failed")
                status, body = request(
                    ADMIN + "lookup", {"localId": [anonymous_uid]}, privileged=True
                )
                if status != 200 or body.get("users", []):
                    raise ValueError("anonymous absence unconfirmed")
                adapter.record({"kind": "anonymous-absent", "uid": anonymous_uid})
            except Exception:
                adapter.unrecovered.append({"kind": "anonymous-account"})
        adapter.cleanup()
    result = {
        "kind": "auth-conditions-local-v1",
        "rows": rows,
        "setups": setups,
        "completed": failure is None
        and not adapter.unrecovered
        and len(rows) == len(cases()),
        "failure": failure,
        "unrecovered": [{"kind": x["kind"]} for x in adapter.unrecovered],
        "requestCounts": adapter.budget.counts,
        "manifestDigest": digest(cases()),
        "productionExecuted": False,
        "unknowns": [
            "production response parity",
            "MFA/OOB/provider mutations",
            "password mutation combinations",
            "anonymous emailVerified=true setup",
        ],
        "elapsedSeconds": time.monotonic() - started,
    }
    save(output / "result.json", result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--child", type=Path, required=True)
    parser.add_argument("--nonce", required=True)
    args = parser.parse_args()
    auth = local_origin("http://" + os.environ["FIREBASE_AUTH_EMULATOR_HOST"])
    fs, control = local_addresses(
        os.environ["FIRESTORE_EMULATOR_HOST"], os.environ["FIREEMU_CONTROL_URL"]
    )
    code, body = control_get(
        control, "/v1/sessions/default/resources", os.environ["FIREEMU_CONTROL_TOKEN"]
    )
    wrong, _ = control_get(
        control,
        "/v1/sessions/default/resources",
        os.environ["FIREEMU_CONTROL_TOKEN"] + "-wrong",
    )
    if (
        code != 200
        or wrong != 403
        or body.get("project") != PROJECT
        or os.environ.get("GOOGLE_CLOUD_PROJECT") != PROJECT
    ):
        raise ValueError("owned local identity mismatch")
    save(
        args.child / "instance.json",
        {
            "pid": os.getpid(),
            "parentPid": os.getppid(),
            "argv": sys.argv,
            "nonce": args.nonce,
            "authOrigin": auth,
            "firestoreOrigin": fs,
            "controlOrigin": control,
        },
    )
    return (
        0
        if execute(auth, fs, args.child / "observations", args.nonce)["completed"]
        else 1
    )


if __name__ == "__main__":

    def interrupted(_signal, _frame):
        raise InterruptedError("stop requested; unwind owned cleanup")

    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGHUP, interrupted)
    sys.exit(main())
