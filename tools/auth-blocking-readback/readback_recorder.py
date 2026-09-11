"""Deploy the disabling beforeSignIn function, refuse two claimed accounts, and read the
disabled flag back on a time axis; then remove the function.

The function is deployed only for the run and deleted in `finally`; the Identity
Platform trigger registration and the MFA, phone and SMS region settings it needs are
restored from the values read before the change. Tokens, codes and passwords stay in
memory and are never written.
"""

# ruff: noqa: BLE001 -- Never expose raw exceptions or credentials.
import argparse
import base64
import hashlib
import json
import secrets
import shutil
import subprocess
import sys
import time
import urllib.parse
from datetime import UTC, datetime
from pathlib import Path

from readback_contract import (
    CORPUS,
    DISABLING_CLAIM,
    complete,
    error_code,
    require,
    validate_row,
)

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools/auth-password-maximum"))
sys.path.insert(0, str(ROOT / "tools/auth-pending-revocation"))
import maximum_recorder as core
import revocation_recorder as revocation
from maximum_contract import owned, tokens, users

PROJECT, NUMBER = core.PROJECT, core.NUMBER
digest, save = core.digest, core.save
CONFIG_URL = revocation.CONFIG_URL
FUNCTION = "fireemuDisableOnSignIn"
REGION = "us-central1"
FUNCTION_SOURCE = Path(__file__).parent.parent / "auth-blocking-disable" / "function"
CONFIG_MASK = "blockingFunctions"
ERROR_DETAILS = {}


def inputs():
    return {
        **core.inputs(),
        **{
            str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(Path(__file__).parent.glob("*.py"))
            if not p.name.startswith("test_")
        },
        **{
            str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(FUNCTION_SOURCE.glob("*"))
            if p.is_file() and p.name != ".gitignore"
        },
    }


def note(report, step, status, response):
    """Sanitized diagnostics for an aborted run: step, status and classified error."""
    report["lastStep"] = step
    report["lastStatus"] = status
    report["lastError"] = None if status == 200 else error_code(response)
    message = (
        (response.get("error") or {}).get("message")
        if status != 200 and isinstance(response, dict)
        else None
    )
    report["lastErrorDetail"] = next(
        (
            code
            for text, code in ERROR_DETAILS.items()
            if isinstance(message, str) and text in message
        ),
        None,
    )


def claims(id_token):
    require(isinstance(id_token, str) and id_token.count(".") == 2)
    payload = id_token.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    value = json.loads(base64.urlsafe_b64decode(payload))
    require(isinstance(value, dict))
    return value


def firebase(args, timeout):
    """firebase-tools in the function directory; only the exit code is retained."""
    completed = subprocess.run(
        ["firebase", *args, f"--project={PROJECT}", "--non-interactive"],
        cwd=FUNCTION_BUILD,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    return completed.returncode


FUNCTION_BUILD = None


def deployed_functions():
    names = core.command(
        ["gcloud", "functions", "list", f"--project={PROJECT}", "--format=value(name)"]
    ).splitlines()
    return [n for n in names if n]


def restore_body(original):
    return {"blockingFunctions": original["blockingFunctions"]}


def restored(raw, original):
    blocking = raw.get("blockingFunctions") or {}
    return raw.get("mfa") == original["mfa"] and not blocking.get("triggers")


def restore_configuration(access, original):
    status, response = revocation.patch(
        f"{CONFIG_URL}?updateMask={CONFIG_MASK}", restore_body(original), access
    )
    require(status == 200 and "error" not in response)
    status, raw = core.request(CONFIG_URL, token=access, quota=True)
    require(status == 200 and restored(raw, original))
    return status, raw


def remove_function():
    """Delete the function if it exists; absence in the listing is authoritative."""
    if any(FUNCTION in name for name in deployed_functions()):
        firebase(["functions:delete", FUNCTION, f"--region={REGION}", "--force"], 600)
    require(not any(FUNCTION in name for name in deployed_functions()))
    return True


def observe(output, origin=None):
    """Production when `origin` is None; otherwise an owned local fireemu at `origin`,
    which already serves the local function fixture and needs no deployment, no
    configuration change and no test phone numbers (codes are read from the emulator
    inspection route)."""
    global FUNCTION_BUILD
    output.mkdir(parents=True, exist_ok=False, mode=0o700)
    FUNCTION_BUILD = output / "function-build"
    identity, secure = core.origins(origin)
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
        "hook": {},
        "cleanup": {},
    }
    accounts = {}
    admin = None
    access = None
    original = None
    change_attempted = False
    try:
        access, key = "owner", "local-test-key"
        if production:
            access, key, report["configReadback"] = core.production_preflight()
            status, raw = core.request(CONFIG_URL, token=access, quota=True)
            require(status == 200 and "error" not in raw)
            read = {
                "mfa": raw.get("mfa"),
                "blockingFunctions": raw.get("blockingFunctions"),
            }
            # Preconditions first: nothing is written or deployed on an unexpected project.
            require(not (read["blockingFunctions"] or {}).get("triggers"))
            require(deployed_functions() == [])
            original = read
            save(
                output / "hook-recovery.json",
                {
                    "project": PROJECT,
                    "original": original,
                    "function": FUNCTION,
                    "region": REGION,
                    "changeAttempted": True,
                },
            )
            change_attempted = True

            # Deploy the function from a private copy of the checked-in source.
            shutil.copytree(
                FUNCTION_SOURCE,
                FUNCTION_BUILD,
                ignore=shutil.ignore_patterns("node_modules"),
            )
            install = subprocess.run(
                ["npm", "install", "--no-audit", "--no-fund", "--loglevel=error"],
                cwd=FUNCTION_BUILD,
                capture_output=True,
                text=True,
                timeout=600,
                check=False,
            )
            require(install.returncode == 0)
            require(firebase(["deploy", "--only", "functions", "--force"], 900) == 0)
            require(any(FUNCTION in name for name in deployed_functions()))
            status, raw = core.request(CONFIG_URL, token=access, quota=True)
            trigger = (
                (raw.get("blockingFunctions") or {})
                .get("triggers", {})
                .get("beforeSignIn", {})
            )
            require(
                isinstance(trigger.get("functionUri"), str)
                and FUNCTION in trigger["functionUri"]
            )
            report["hook"] = {"deployed": True, "triggerReadback": True}

            time.sleep(30)

        else:
            report["hook"] = {"deployed": True, "triggerReadback": True}
            report["localFunctionFixture"] = (
                "tools/auth-blocking-disable/function-local"
            )
        query = f"?key={urllib.parse.quote(key, safe='')}"

        def admin(action, body):
            require(action in {"lookup", "update", "delete"})
            return core.request(
                f"{identity}/v1/projects/{PROJECT}/accounts:{action}",
                body,
                access,
                quota=production,
            )

        def client(action, body):
            require(action in {"signUp", "signInWithPassword", "lookup"})
            status, response = core.request(
                f"{identity}/v1/accounts:{action}{query}", body
            )
            note(report, action, status, response)
            return status, response

        def refresh(token):
            return core.request(
                f"{secure}/v1/token{query}",
                {"grant_type": "refresh_token", "refresh_token": token},
                form=True,
            )

        def lookup(account):
            status, response = admin("lookup", {"localId": [account["uid"]]})
            note(report, "admin:lookup", status, response)
            records = users(status, response)
            owned(records, account["email"], account["marker"], account["uid"])
            return records[0]

        def derived_lookup(account, id_token):
            records = users(*client("lookup", {"idToken": id_token}))
            owned(records, account["email"], account["marker"], account["uid"])
            return True

        def password(account):
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

        def pending_checks(account, response):
            """The MFA account's second sign-in may be accepted as a new pending
            credential: recorded without any token or credential value."""
            info = response.get("mfaInfo")
            return {
                "noError": "error" not in response,
                "pendingCredentialPresent": isinstance(
                    response.get("mfaPendingCredential"), str
                )
                and bool(response["mfaPendingCredential"]),
                "noIdToken": "idToken" not in response,
                "noRefreshToken": "refreshToken" not in response,
                "enrollmentMatches": isinstance(info, list)
                and len(info) == 1
                and info[0].get("mfaEnrollmentId") == account["enrollmentId"],
            }

        def new_account(label, claimed):
            directory = output / label
            directory.mkdir(mode=0o700)
            account = {
                "email": "fireemu-basic-" + secrets.token_hex(16) + "@example.test",
                "marker": "fireemu-owned-" + secrets.token_hex(24),
                "password": "Aa9!" + secrets.token_urlsafe(32),
                "uid": None,
                "journal": directory / "recovery.json",
                "refusedAt": None,
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
            update = {"localId": account["uid"], "emailVerified": True}
            if claimed:
                update["customAttributes"] = json.dumps({DISABLING_CLAIM: True})
            status, updated = admin("update", update)
            require(status == 200 and "error" not in updated)
            record = lookup(account)
            require(record.get("disabled", False) is False)
            if claimed:
                require(
                    json.loads(record.get("customAttributes", "{}")).get(
                        DISABLING_CLAIM
                    )
                    is True
                )
            report["setup"][label] = True
            return account

        def readback(name, account):
            record = lookup(account)
            since = (
                None
                if account["refusedAt"] is None
                else int(time.time() - account["refusedAt"])
            )
            row(
                name,
                200,
                {},
                {
                    "disabledPersisted": record.get("disabled") is True,
                    "secondsSinceRefusal": since,
                },
            )

        def signin_row(name, account):
            status, response = password(account)
            if status != 200 and account["refusedAt"] is None:
                account["refusedAt"] = time.time()
            row(
                name,
                status,
                response,
                signin_checks(account, response) if status == 200 else None,
            )

        x = new_account("x", True)
        y = new_account("y", True)
        z = new_account("z", False)

        signin_row("control-z-signin", z)
        readback("x-readback-before", x)
        signin_row("x-first-signin", x)
        readback("x-readback-immediate", x)
        time.sleep(5)
        readback("x-readback-after-5s", x)
        time.sleep(25)
        readback("x-readback-after-30s", x)
        signin_row("x-second-signin", x)
        # Y is refused and then left alone: no read for thirty seconds.
        signin_row("y-first-signin", y)
        time.sleep(30)
        readback("y-readback-after-30s-unread", y)
        signin_row("y-second-signin", y)
        signin_row("control-z-final-signin", z)
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
        if len(clean) == 3 and all(
            c == {"uidAbsent": True, "emailAbsent": True} for c in clean
        ):
            report["cleanup"] = {"uidAbsent": True, "emailAbsent": True}
        if not production:
            report["functionRemoved"] = True
            report["configRestored"] = True
            report["configDigestMatches"] = True
        if change_attempted:
            try:
                report["functionRemoved"] = remove_function()
            except Exception as error:
                report["functionRemovalFailure"] = type(error).__name__
            try:
                status, raw = restore_configuration(access, original)
                report["configRestored"] = True
                report["configRestoredReadback"] = {
                    "mfa": raw.get("mfa"),
                    "phoneNumber": raw.get("signIn", {}).get("phoneNumber") or {},
                    "smsRegionConfig": raw.get("smsRegionConfig"),
                    "blockingFunctions": raw.get("blockingFunctions"),
                }
                projection = core.config_projection(status, raw)
                report["configDigestMatches"] = (
                    projection["sha256"] == report["configReadback"]["sha256"]
                )
            except Exception as error:
                report["configRestoreFailure"] = type(error).__name__
        shutil.rmtree(FUNCTION_BUILD, ignore_errors=True)
        save(output / "observation.json", report)
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--production", action="store_true", required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--recover", type=Path)
    parser.add_argument("--restore", type=Path)
    args = parser.parse_args()
    if args.restore:
        value = json.loads(args.restore.read_bytes())
        require(
            value.get("project") == PROJECT and value.get("changeAttempted") is True
        )
        # The preflight would refuse a project with a deployed function, so the token is
        # taken directly for the restore.
        FUNCTION_BUILD = ROOT
        access = core.command(
            ["gcloud", "auth", "application-default", "print-access-token"]
        )
        remove_function()
        restore_configuration(access, value["original"])
        print(json.dumps({"functionRemoved": True, "configRestored": True}))
    elif args.recover:
        try:
            print(json.dumps(core.reconcile(args.recover)))
        except Exception:
            raise SystemExit("Recovery unresolved; retain private journal") from None
    else:
        require(args.output is not None)
        result = observe(args.output)
        print(json.dumps({"status": result["status"], "complete": complete(result)}))
        raise SystemExit(0 if complete(result) else 2)
