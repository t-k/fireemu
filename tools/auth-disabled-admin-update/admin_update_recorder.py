"""Disable an owned account, update it administratively, observe, and always clean up.

No project configuration is changed. Tokens and passwords stay in memory; raw API
responses are never bound to the saved report. An aborted run keeps only the failing
step, HTTP status and error class.
"""

# ruff: noqa: BLE001 -- Never expose raw exceptions or credentials.
import argparse
import hashlib
import json
import secrets
import sys
import time
import urllib.parse
from datetime import UTC, datetime
from pathlib import Path

from admin_update_contract import (
    CORPUS,
    PHOTO_URL,
    complete,
    error_code,
    require,
    validate_row,
)

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools/auth-password-maximum"))
import maximum_recorder as core
from maximum_contract import owned, selected_state, tokens, users

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


def note(report, step, status, response):
    """Sanitized diagnostics for an aborted run: step, status and classified error."""
    report["lastStep"] = step
    report["lastStatus"] = status
    report["lastError"] = None if status == 200 else error_code(response)


def state_without_disabled(user):
    return selected_state(
        {k: v for k, v in user.items() if k not in {"disabled", "photoUrl"}}
    )


def observe(output, origin=None):
    output.mkdir(parents=True, exist_ok=False, mode=0o700)
    identity, secure = origins(origin)
    production = origin is None
    before = inputs()
    report: dict = {
        "schemaVersion": 1,
        "acceptance": "candidate",
        "status": "incomplete",
        "target": "production" if production else "local",
        "recordedAt": datetime.now(UTC).isoformat(),
        "project": PROJECT,
        "projectNumber": NUMBER if production else None,
        "probeInputs": before,
        "probeSourceCommit": core.command(["git", "rev-parse", "HEAD"]),
        "corpus": CORPUS,
        "cases": [],
        "setup": {},
        "transitions": [],
        "cleanup": {},
    }
    accounts = {}
    admin = None
    try:
        access, key = "owner", "local-test-key"
        if production:
            access, key, report["configReadback"] = core.production_preflight()
        query = f"?key={urllib.parse.quote(key, safe='')}"
        policy_url = f"{identity}/v2/passwordPolicy{query}"
        if production:
            status, policy = core.request(policy_url)
            require(status == 200 and digest(policy) == digest(PASSWORD_POLICY))
            report["configReadback"]["passwordPolicy"] = policy

        def admin(action, body):
            require(action in {"lookup", "update", "delete"})
            status, response = core.request(
                f"{identity}/v1/projects/{PROJECT}/accounts:{action}",
                body,
                access,
                quota=production,
            )
            note(report, f"admin:{action}", status, response)
            return status, response

        def client(action, body):
            require(action in {"signUp", "signInWithPassword", "lookup"})
            status, response = core.request(
                f"{identity}/v1/accounts:{action}{query}", body
            )
            note(report, action, status, response)
            return status, response

        def refresh(token):
            status, response = core.request(
                f"{secure}/v1/token{query}",
                {"grant_type": "refresh_token", "refresh_token": token},
                form=True,
            )
            note(report, "token", status, response)
            return status, response

        def lookup(account):
            records = users(*admin("lookup", {"localId": [account["uid"]]}))
            owned(records, account["email"], account["marker"], account["uid"])
            return records[0]

        def derived_lookup(account, id_token):
            records = users(*client("lookup", {"idToken": id_token}))
            owned(records, account["email"], account["marker"], account["uid"])
            return True

        def password_signin(account):
            return client(
                "signInWithPassword",
                {
                    "email": account["email"],
                    "password": account["password"],
                    "returnSecureToken": True,
                },
            )

        rows_started = time.monotonic()

        def row(name, status, response, checks=None):
            result = {
                "id": name,
                "httpStatus": status,
                "outcome": "accepted" if status == 200 else "refused",
                "observedError": None if status == 200 else error_code(response),
                "checks": checks if status == 200 else {},
                "elapsedMs": int((time.monotonic() - rows_started) * 1000),
                "skipped": False,
            }
            validate_row(result, name)
            report["cases"].append(result)
            return result

        def skipped(name):
            result = {
                "id": name,
                "httpStatus": None,
                "outcome": "skipped",
                "observedError": None,
                "checks": {},
                "elapsedMs": int((time.monotonic() - rows_started) * 1000),
                "skipped": True,
            }
            validate_row(result, name)
            report["cases"].append(result)

        def signin_checks(account, response):
            checks = tokens(response, account["uid"], account["email"])
            require(all(v is True for v in checks.values()))
            checks["derivedLookup"] = derived_lookup(account, response["idToken"])
            return checks

        def signin_row(name, account):
            status, response = password_signin(account)
            row(
                name,
                status,
                response,
                signin_checks(account, response) if status == 200 else None,
            )

        def transition(target, control, disabled):
            require(core.recovery_identity(target["journal"])[1] == target["uid"])
            lookup(target)
            status, response = admin(
                "update", {"localId": target["uid"], "disableUser": disabled}
            )
            require(status == 200 and "error" not in response)
            current, other = lookup(target), lookup(control)
            require(current.get("disabled", False) is disabled)
            require(state_without_disabled(current) == target["initial"])
            require(other.get("disabled", False) is False)
            require(state_without_disabled(other) == control["initial"])
            report["transitions"].append(
                {"disabled": disabled, "targetReadback": True, "controlUnchanged": True}
            )

        for label in ("a", "b"):
            directory = output / label
            directory.mkdir(mode=0o700)
            account = {
                "email": "fireemu-basic-" + secrets.token_hex(16) + "@example.test",
                "marker": "fireemu-owned-" + secrets.token_hex(24),
                "password": "Aa9!" + secrets.token_urlsafe(32),
                "uid": None,
                "journal": directory / "recovery.json",
            }
            require(users(*admin("lookup", {"email": [account["email"]]})) == [])
            save(
                account["journal"],
                {
                    "project": PROJECT,
                    "email": account["email"],
                    "marker": account["marker"],
                    "creationAttempted": True,
                },
            )
            accounts[label] = account
            status, _signed = client(
                "signUp",
                {
                    "email": account["email"],
                    "password": account["password"],
                    "displayName": account["marker"],
                    "returnSecureToken": True,
                },
            )
            require(status == 200)
            account["uid"] = owned(
                users(*admin("lookup", {"email": [account["email"]]})),
                account["email"],
                account["marker"],
            )
            save(
                directory / "verified-account.json",
                {**json.loads(account["journal"].read_bytes()), "uid": account["uid"]},
            )
            require(core.recovery_identity(account["journal"])[1] == account["uid"])
            initial = lookup(account)
            require(initial.get("disabled", False) is False)
            account["initial"] = state_without_disabled(initial)
            report["setup"][label] = True

        a, b = accounts["a"], accounts["b"]
        signin_row("baseline-a-signin", a)
        signin_row("baseline-b-signin", b)

        transition(a, b, True)

        # Administrative password replacement of the disabled account. Whether tokens come
        # back is the observation; if they do, they are tried for lookup and refresh.
        new_password = "Aa9!" + secrets.token_urlsafe(32)
        status, response = admin(
            "update", {"localId": a["uid"], "password": new_password}
        )
        issued = False
        checks = None
        if status == 200:
            record = lookup(a)
            issued = isinstance(response.get("idToken"), str) and bool(
                response["idToken"]
            )
            checks = {
                "noError": "error" not in response,
                "localIdMatches": response.get("localId") == a["uid"],
                "tokensReturned": issued,
                "readbackApplied": record.get("disabled") is True
                and state_without_disabled(record) == a["initial"],
            }
            a["password"] = new_password
        update = row("disabled-a-password-update", status, response, checks)
        if update["outcome"] != "accepted" or not issued:
            skipped("disabled-a-update-token-lookup")
            skipped("disabled-a-update-token-refresh")
        else:
            status, seen = client("lookup", {"idToken": response["idToken"]})
            checks = None
            if status == 200:
                checks = {
                    "ownerMatches": owned(
                        users(status, seen), a["email"], a["marker"], a["uid"]
                    )
                    == a["uid"]
                }
            row("disabled-a-update-token-lookup", status, seen, checks)
            checks = None
            status, renewed = (
                refresh(response["refreshToken"])
                if isinstance(response.get("refreshToken"), str)
                else (400, {"error": {"message": "INVALID_REFRESH_TOKEN"}})
            )
            if status == 200:
                checks = tokens(renewed, a["uid"], a["email"], True)
                require(all(v is True for v in checks.values()))
                checks["derivedLookup"] = derived_lookup(a, renewed["id_token"])
            row("disabled-a-update-token-refresh", status, renewed, checks)

        # Administrative attribute update of the disabled account.
        status, response = admin("update", {"localId": a["uid"], "photoUrl": PHOTO_URL})
        checks = None
        if status == 200:
            record = lookup(a)
            checks = {
                "noError": "error" not in response,
                "localIdMatches": response.get("localId") == a["uid"],
                "tokensReturned": isinstance(response.get("idToken"), str)
                and bool(response["idToken"]),
                "readbackApplied": record.get("photoUrl") == PHOTO_URL
                and record.get("disabled") is True,
            }
        row("disabled-a-photo-update", status, response, checks)

        signin_row("disabled-a-signin", a)
        signin_row("disabled-b-signin", b)

        transition(a, b, False)
        signin_row("reenabled-a-signin", a)
        signin_row("reenabled-b-signin", b)

        if production:
            current = core.config_projection(
                *core.request(
                    f"{identity}/admin/v2/projects/{PROJECT}/config",
                    token=access,
                    quota=True,
                )
            )
            status, policy = core.request(policy_url)
            require(status == 200 and digest(policy) == digest(PASSWORD_POLICY))
            current["passwordPolicy"] = policy
            require(current == report["configReadback"])
        report["configurationUnchanged"] = True
        require(inputs() == before)
        report["status"] = "observed"
    except Exception as error:
        report["failure"] = type(error).__name__
    finally:
        clean = []
        for account in accounts.values():
            try:
                clean.append(
                    core.cleanup_account(
                        admin,
                        account["email"],
                        account["marker"],
                        account["uid"],
                        account["journal"],
                    )
                )
            except Exception as error:
                report["cleanupFailure"] = type(error).__name__
        if len(clean) == 2 and all(
            c == {"uidAbsent": True, "emailAbsent": True} for c in clean
        ):
            report["cleanup"] = {"uidAbsent": True, "emailAbsent": True}
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
        require(args.output is not None)
        result = observe(args.output)
        print(json.dumps({"status": result["status"], "complete": complete(result)}))
        raise SystemExit(0 if complete(result) else 2)
