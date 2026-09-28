"""Deploy a beforeSignIn function that disables an account on the request that creates it,
observe, and remove it.

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

from create_contract import (
    CONTROL_PHOTO,
    CORPUS,
    SELECTOR,
    SELECTOR_PHOTO,
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
FUNCTION = "fireemuDisableOnCreate"
REGION = "us-central1"
FUNCTION_SOURCE = Path(__file__).parent / "function"
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
                "tools/auth-blocking-create-disable/function-local"
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

        def token_rows(account, label, first, response):
            # The raw response stays a local argument: it is never attached to a row or
            # to the report, so an interrupted follow-up cannot save it.
            if first["outcome"] != "accepted":
                skipped(f"target-{label}-token-lookup")
                skipped(f"target-{label}-token-refresh")
                return
            status, seen = client("lookup", {"idToken": response["idToken"]})
            checks = None
            if status == 200:
                checks = {
                    "ownerMatches": owned(
                        users(status, seen),
                        account["email"],
                        account["marker"],
                        account["uid"],
                    )
                    == account["uid"]
                }
            row(f"target-{label}-token-lookup", status, seen, checks)
            status, renewed = refresh(response["refreshToken"])
            checks = None
            if status == 200:
                checks = tokens(renewed, account["uid"], account["email"], True)
                require(all(v is True for v in checks.values()))
                checks["derivedLookup"] = derived_lookup(account, renewed["id_token"])
            row(f"target-{label}-token-refresh", status, renewed, checks)

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

        def new_account(label, selector):
            directory = output / label
            directory.mkdir(mode=0o700)
            # The target's local part starts with the selector prefix; the rest of the
            # thirty-two hex characters stays random.
            local = (
                SELECTOR[len("fireemu-basic-") :] if selector else ""
            ) + secrets.token_hex(16)
            local = local[:32]
            account = {
                "email": "fireemu-basic-" + local + "@example.test",
                "marker": "fireemu-owned-" + secrets.token_hex(24),
                "password": "Aa9!" + secrets.token_urlsafe(32),
                "uid": None,
                "journal": directory / "recovery.json",
                "selector": selector,
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
            return account

        def signup(account):
            body = {
                "email": account["email"],
                "password": account["password"],
                "displayName": account["marker"],
                "returnSecureToken": True,
            }
            # Both sign-ups carry a photo URL: the selector for the target, a plain one
            # for the control, so the control also observes whether sign-up persists it.
            body["photoUrl"] = SELECTOR_PHOTO if account["selector"] else CONTROL_PHOTO
            return client("signUp", body)

        def recover_uid(account):
            records = users(*admin("lookup", {"email": [account["email"]]}))
            if not records:
                return None
            account["uid"] = owned(records, account["email"], account["marker"])
            verified = account["journal"].parent / "verified-account.json"
            if not verified.exists():
                save(
                    verified,
                    {
                        **json.loads(account["journal"].read_bytes()),
                        "uid": account["uid"],
                    },
                )
            return records[0]

        # Control C: an ordinary sign-up under the registered function.
        c = new_account("c", False)
        status, response = signup(c)
        require(status == 200)
        require(recover_uid(c) is not None)
        row("control-c-signup", status, response, signin_checks(c, response))
        report["setup"]["c"] = True
        record = recover_uid(c)
        row(
            "control-c-signup-readback",
            200,
            {},
            {
                "recordExists": record is not None,
                "photoUrlPersisted": bool(
                    record and record.get("photoUrl") == CONTROL_PHOTO
                ),
                "notDisabled": bool(record and record.get("disabled", False) is False),
            },
        )
        status, response = password(c)
        row(
            "control-c-signin",
            status,
            response,
            signin_checks(c, response) if status == 200 else None,
        )

        # Target T: the creating request carries the selector, so the function disables
        # the account that this very request creates.
        t = new_account("t", True)
        status, response = signup(t)
        record = recover_uid(t)
        first = row(
            "target-t-signup",
            status,
            response,
            signin_checks(t, response)
            if status == 200 and record is not None
            else None,
        )
        token_rows(t, "t", first, response)
        record = recover_uid(t)
        row(
            "target-t-record-readback",
            200,
            {},
            {
                "recordExists": record is not None,
                "disabledPersisted": bool(record and record.get("disabled") is True),
            },
        )
        report["targetRecordExists"] = record is not None
        status, response = password(t)
        row(
            "target-t-signin",
            status,
            response,
            signin_checks(t, response) if status == 200 else None,
        )
        status, response = signup(t)
        if status == 200:
            recover_uid(t)
        row(
            "target-t-second-signup",
            status,
            response,
            signin_checks(t, response) if status == 200 else None,
        )

        status, response = password(c)
        row(
            "control-c-final-signin",
            status,
            response,
            signin_checks(c, response) if status == 200 else None,
        )
        require(inputs() == before)
        report["status"] = "observed"
    except Exception as error:
        report["failure"] = type(error).__name__
    finally:
        clean = {}
        for label, account in accounts.items():
            try:
                if (
                    account["uid"] is None
                    and report.get("targetRecordExists") is False
                    and label == "t"
                ):
                    # The creating request was answered and no record exists: the only
                    # identity is the email, whose absence is re-read here.
                    require(
                        users(*admin("lookup", {"email": [account["email"]]})) == []
                    )
                    clean[label] = {"recordNeverCreated": True, "emailAbsent": True}
                    continue
                clean[label] = core.cleanup_account(
                    admin,
                    account["email"],
                    account["marker"],
                    account["uid"],
                    account["journal"],
                )
            except Exception as error:
                report["cleanupFailure"] = type(error).__name__
        if set(clean) == set(accounts) and set(accounts) == {"c", "t"}:
            report["cleanup"] = clean
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
