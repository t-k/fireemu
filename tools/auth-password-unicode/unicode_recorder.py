"""Bounded Unicode observations with isolated accounts and immutable private journals."""

# ruff: noqa: BLE001 -- Boundary failures expose exception classes only.

import argparse
import hashlib
import json
import secrets
import sys
import urllib.parse
from datetime import UTC, datetime
from pathlib import Path

from unicode_contract import (
    CASES,
    SHAPES,
    complete,
    generate,
    input_shape,
    require,
    validate_case,
)

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools/auth-password-maximum"))
import maximum_recorder as core
from maximum_contract import (
    POLICY_ERRORS,
    error_code,
    expiry_seconds,
    owned,
    selected_state,
    tokens,
    users,
)

PROJECT, NUMBER, PASSWORD_POLICY = core.PROJECT, core.NUMBER, core.PASSWORD_POLICY
digest, save, origins = core.digest, core.save, core.origins


def inputs():
    return {
        **core.inputs(),
        **{
            str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(Path(__file__).parent.glob("*.py"))
            if not p.name.startswith("test_")
        },
    }


def sample(name, output, admin, client, refresh):
    output.mkdir(mode=0o700)
    email = "fireemu-basic-" + secrets.token_hex(16) + "@example.test"
    marker = "fireemu-owned-" + secrets.token_hex(24)
    original = "Aa9!" + secrets.token_urlsafe(32)
    replacement = generate(name)
    row: dict = {
        "id": name,
        "inputShape": input_shape(name, replacement),
        "outcome": "inconclusive",
        "httpStatus": 0,
        "observedError": None,
        "checks": {},
        "tokenChecks": {},
        "cleanup": {},
    }
    uid = None
    attempted = False

    def lookup(selector):
        return users(*admin("lookup", selector))

    def token_check(label, status, value):
        is_refresh = label.endswith("refresh")
        checks = {"httpOk": status == 200, **tokens(value, uid, email, is_refresh)}
        row["tokenChecks"][label] = {
            "httpStatus": status,
            "checks": checks,
            "expirySeconds": expiry_seconds(value, is_refresh),
        }
        require(all(v is True for v in checks.values()))
        return value

    def state(token):
        records = users(*client("lookup", {"idToken": token}))
        owned(records, email, marker, uid)
        return selected_state(records[0])

    try:
        require(lookup({"email": [email]}) == [])
        save(
            output / "recovery.json",
            {
                "project": PROJECT,
                "email": email,
                "marker": marker,
                "creationAttempted": True,
            },
        )
        attempted = True
        status, signed = client(
            "signUp",
            {
                "email": email,
                "password": original,
                "displayName": marker,
                "returnSecureToken": True,
            },
        )
        uid = owned(lookup({"email": [email]}), email, marker)
        require(owned(lookup({"localId": [uid]}), email, marker, uid) == uid)
        save(
            output / "verified-account.json",
            {**json.loads((output / "recovery.json").read_bytes()), "uid": uid},
        )
        require(core.recovery_identity(output / "recovery.json")[1] == uid)
        token_check("signup", status, signed)
        initial = state(signed["idToken"])
        baseline = token_check(
            "baseline-signin",
            *client(
                "signInWithPassword",
                {"email": email, "password": original, "returnSecureToken": True},
            ),
        )
        row["checks"]["baselineLookup"] = state(baseline["idToken"]) == initial
        refreshed = token_check("baseline-refresh", *refresh(baseline["refreshToken"]))
        row["checks"]["baselineRefreshLookup"] = state(refreshed["id_token"]) == initial
        require(all(v is True for v in row["checks"].values()))
        status, updated = client(
            "update",
            {
                "idToken": baseline["idToken"],
                "password": replacement,
                "returnSecureToken": True,
            },
        )
        row["httpStatus"] = status
        row["observedError"] = (
            None if status == 200 and "error" not in updated else error_code(updated)
        )
        if status == 200:
            credentials = token_check("update", status, updated)
            password = replacement
            row["outcome"] = "accepted"
        else:
            require(status == 400 and row["observedError"] in POLICY_ERRORS)
            credentials, password = baseline, original
            row["outcome"] = "refused"
        row["checks"]["postLookup"] = state(credentials["idToken"]) == initial
        signed_after = token_check(
            "post-signin",
            *client(
                "signInWithPassword",
                {"email": email, "password": password, "returnSecureToken": True},
            ),
        )
        row["checks"]["postSigninLookup"] = state(signed_after["idToken"]) == initial
        refreshed_after = token_check(
            "post-refresh", *refresh(credentials["refreshToken"])
        )
        row["checks"]["postRefreshLookup"] = (
            state(refreshed_after["id_token"]) == initial
        )
        require(all(v is True for v in row["checks"].values()))
        owned(lookup({"localId": [uid]}), email, marker, uid)
        status, deleted = client("delete", {"idToken": signed_after["idToken"]})
        row["checks"]["deleted"] = status == 200 and "error" not in deleted
    except Exception as error:
        row["failure"] = type(error).__name__
    finally:
        if attempted:
            try:
                row["cleanup"] = core.cleanup_account(
                    admin, email, marker, uid, output / "recovery.json"
                )
            except Exception as error:
                row["cleanupFailure"] = type(error).__name__
        save(output / "sample.json", row)
    return row


def observe(output, origin=None):
    output.mkdir(parents=True, exist_ok=False, mode=0o700)
    identity, secure = origins(origin)
    production = origin is None
    before = inputs()
    report: dict = {
        "schemaVersion": 2,
        "acceptance": "candidate",
        "status": "incomplete",
        "target": "production" if production else "local",
        "recordedAt": datetime.now(UTC).isoformat(),
        "project": PROJECT,
        "projectNumber": NUMBER if production else None,
        "probeInputs": before,
        "probeSourceCommit": core.command(["git", "rev-parse", "HEAD"]),
        "corpus": {
            "slice": "auth-password-unicode",
            "revision": 1,
            "cases": list(CASES),
        },
        "inputShape": SHAPES,
        "cases": [],
        "cleanup": {},
    }
    report["corpusSha256"] = digest(report["corpus"])
    try:
        token, key = "owner", "local-test-key"
        if production:
            token, key, report["configReadback"] = core.production_preflight()
            require(report["configReadback"]["adminPasswordPolicyAbsent"] is True)
        policy_url = (
            f"{identity}/v2/passwordPolicy?key={urllib.parse.quote(key, safe='')}"
        )
        if production:
            status, policy = core.request(policy_url)
            require(status == 200 and digest(policy) == digest(PASSWORD_POLICY))
            report["configReadback"]["passwordPolicy"] = policy

        def admin(action, body):
            return core.request(
                f"{identity}/v1/projects/{PROJECT}/accounts:{action}",
                body,
                token,
                quota=production,
            )

        def client(action, body):
            require(
                action in {"signUp", "signInWithPassword", "lookup", "update", "delete"}
            )
            return core.request(
                f"{identity}/v1/accounts:{action}?key={urllib.parse.quote(key, safe='')}",
                body,
            )

        def refresh(value):
            return core.request(
                f"{secure}/v1/token?key={urllib.parse.quote(key, safe='')}",
                {"grant_type": "refresh_token", "refresh_token": value},
                form=True,
            )

        for name in CASES:
            row = sample(name, output / name, admin, client, refresh)
            report["cases"].append(row)
            validate_case(row, name)
        if production:
            current = core.config_projection(
                *core.request(
                    f"{identity}/admin/v2/projects/{PROJECT}/config",
                    token=token,
                    quota=True,
                )
            )
            status, policy = core.request(policy_url)
            require(status == 200 and digest(policy) == digest(PASSWORD_POLICY))
            current["passwordPolicy"] = policy
            require(current == report["configReadback"])
            report["configurationUnchanged"] = True
        require(inputs() == before)
        report["cleanup"] = {"uidAbsent": True, "emailAbsent": True}
        report["status"] = "observed"
    except Exception as error:
        report["failure"] = type(error).__name__
    finally:
        save(output / "observation.json", report)
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--production", action="store_true", required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--recover", type=Path)
    args = parser.parse_args()
    if args.recover:
        try:
            print(json.dumps(core.reconcile(args.recover)))
        except Exception:
            raise SystemExit("Recovery unresolved; retain private journal") from None
    else:
        if not args.output:
            parser.error("--output or --recover required")
        result = observe(args.output)
        print(
            json.dumps(
                {
                    "status": result["status"],
                    "complete": complete(result),
                    "sampleCount": len(result["cases"]),
                }
            )
        )
        raise SystemExit(0 if complete(result) else 2)
