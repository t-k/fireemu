"""Obtain an MFA pending credential while enabled, disable the account, attempt
mfaSignIn:start, then re-enable and start/finalize the same credential; observe, clean up.

Production needs phone MFA and test phone numbers, which the oracle project does not have;
the recorder enables them for the run and restores the recorded configuration in
`finally`. The pending credential is obtained before the disable so a disabled account's
mfaSignIn:start is exercised on an otherwise well-formed credential. Tokens, pending
credentials, session identifiers, codes and passwords stay in memory and are never
written.
"""

# ruff: noqa: BLE001 -- Never expose raw exceptions or credentials.
import argparse
import hashlib
import json
import secrets
import signal
import sys
import time
import urllib.parse
from datetime import UTC, datetime
from pathlib import Path

from start_disabled_contract import (
    CORPUS,
    TEST_CODE,
    TEST_PHONE,
    complete,
    error_code,
    require,
    validate_row,
)

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools/auth-pending-revocation"))
sys.path.insert(0, str(ROOT / "tools/auth-password-maximum"))
import maximum_recorder as core
import revocation_recorder as revocation
from maximum_contract import owned, users

PROJECT, NUMBER = core.PROJECT, core.NUMBER
digest, save = core.digest, core.save
CONFIG_URL, CONFIG_MASK = revocation.CONFIG_URL, revocation.CONFIG_MASK
MFA_ON, MFA_OFF, SMS_REGIONS_ON = (
    revocation.MFA_ON,
    revocation.MFA_OFF,
    revocation.SMS_REGIONS_ON,
)
ERROR_DETAILS = revocation.ERROR_DETAILS
restore_configuration, phone_config, claims = (
    revocation.restore_configuration,
    revocation.phone_config,
    revocation.claims,
)
require(
    TEST_PHONE in revocation.TEST_PHONES.values() and revocation.TEST_CODE == TEST_CODE
)

PROBE_TREES = (
    "tools/auth-mfa-start-disabled",
    "tools/auth-pending-revocation",
    "tools/auth-password-maximum",
    "tools/compat-inventory",
)


def patch(url, body, token):
    return revocation.patch(url, body, token)


class Terminated(BaseException):
    """SIGTERM or SIGHUP during a run: unwinds through `finally`."""


def terminate(signum, frame):
    raise Terminated(signum)


def committed_checkout():
    return core.command(["git", "status", "--porcelain", "--", *PROBE_TREES]) == ""


def begin(report, step):
    if "failure" in report:
        return
    report["lastStep"] = step
    report["lastStatus"] = None
    report["lastError"] = None
    report["lastErrorDetail"] = None


def note(report, step, status, response):
    if "failure" in report:
        return
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


def inputs():
    own = {
        str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted(Path(__file__).parent.glob("*.py"))
        if not p.name.startswith("test_")
    }
    return {**revocation.inputs(), **own}


def observe(output, origin=None):
    output.mkdir(parents=True, exist_ok=False, mode=0o700)
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
        "setup": False,
        "heldPendingBeforeDisable": False,
        "transitions": [],
        "cleanup": {},
    }
    account = {}
    admin = None
    access = None
    original = None
    change_attempted = False
    previous = {s: signal.signal(s, terminate) for s in (signal.SIGTERM, signal.SIGHUP)}
    try:
        access, key = "owner", "local-test-key"
        if production:
            require(committed_checkout())
            report["committedCheckout"] = True
            access, key, report["configReadback"] = core.production_preflight()

            def config(patch_body=None, mask=None):
                if patch_body is None:
                    return core.request(CONFIG_URL, token=access, quota=True)
                return patch(
                    f"{CONFIG_URL}?updateMask={urllib.parse.quote(mask, safe=',')}",
                    patch_body,
                    access,
                )

            status, raw = config()
            require(status == 200 and "error" not in raw)
            read = {
                "mfa": raw.get("mfa"),
                "phoneNumber": raw.get("signIn", {}).get("phoneNumber"),
                "smsRegionConfig": raw.get("smsRegionConfig"),
            }
            require(read["mfa"] == MFA_OFF and not read["phoneNumber"])
            require(read["smsRegionConfig"] == {"allowlistOnly": {}})
            original = read
            save(
                output / "config-recovery.json",
                {
                    "project": PROJECT,
                    "original": original,
                    "changeAttempted": True,
                    "configSha256": report["configReadback"]["sha256"],
                },
            )
            change_attempted = True
            status, patched = config(
                {
                    "mfa": MFA_ON,
                    "signIn": {"phoneNumber": phone_config(True)},
                    "smsRegionConfig": SMS_REGIONS_ON,
                },
                CONFIG_MASK,
            )
            require(status == 200 and "error" not in patched)
            status, raw = config()
            require(status == 200 and raw.get("mfa") == MFA_ON)
            require(raw.get("signIn", {}).get("phoneNumber") == phone_config(True))
            require("allowByDefault" in raw.get("smsRegionConfig", {}))
            report["configEnabled"] = True
            time.sleep(30)
        else:
            report["configEnabled"] = False
        query = f"?key={urllib.parse.quote(key, safe='')}"

        def admin(action, body):
            require(action in {"lookup", "update", "delete"})
            begin(report, f"admin:{action}")
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
            begin(report, action)
            status, response = core.request(
                f"{identity}/v1/accounts:{action}{query}", body
            )
            note(report, action, status, response)
            return status, response

        def mfa(action, body):
            require(action in {"mfaSignIn:start", "mfaSignIn:finalize"})
            begin(report, action)
            status, response = core.request(
                f"{identity}/v2/accounts/{action}{query}", body
            )
            note(report, action, status, response)
            return status, response

        def refresh(token):
            begin(report, "token")
            return core.request(
                f"{secure}/v1/token{query}",
                {"grant_type": "refresh_token", "refresh_token": token},
                form=True,
            )

        def lookup():
            records = users(*admin("lookup", {"localId": [account["uid"]]}))
            owned(records, account["email"], account["marker"], account["uid"])
            return records[0]

        def derived_lookup_ok(id_token):
            begin(report, "lookup")
            status, seen = client("lookup", {"idToken": id_token})
            if status != 200:
                return False
            try:
                owned(
                    users(status, seen),
                    account["email"],
                    account["marker"],
                    account["uid"],
                )
            except ValueError:
                return False
            return True

        def pending():
            status, response = client(
                "signInWithPassword",
                {
                    "email": account["email"],
                    "password": account["password"],
                    "returnSecureToken": True,
                },
            )
            require(status == 200 and "error" not in response)
            require("idToken" not in response and "refreshToken" not in response)
            credential = response.get("mfaPendingCredential")
            info = response.get("mfaInfo")
            require(isinstance(credential, str) and bool(credential))
            require(isinstance(info, list) and len(info) == 1)
            require(info[0].get("mfaEnrollmentId") == account["enrollmentId"])
            return credential

        def code_for(session):
            if production:
                return TEST_CODE
            begin(report, "emulator:verificationCodes")
            status, listing = core.request(
                f"{origin}/emulator/v1/projects/{PROJECT}/verificationCodes"
            )
            require(status == 200)
            return next(
                c["code"]
                for c in listing.get("verificationCodes", [])
                if c.get("sessionInfo") == session
            )

        def start(credential):
            return mfa(
                "mfaSignIn:start",
                {
                    "mfaPendingCredential": credential,
                    "mfaEnrollmentId": account["enrollmentId"],
                    "phoneSignInInfo": {
                        "phoneNumber": account["phone"],
                        "recaptchaToken": "fireemu-test-phone-number",
                    },
                },
            )

        def finalize(credential, session, code):
            return mfa(
                "mfaSignIn:finalize",
                {
                    "mfaPendingCredential": credential,
                    "phoneVerificationInfo": {"sessionInfo": session, "code": code},
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

        def token_checks(response, diagnostic=False):
            checks = {
                "noError": "error" not in response,
                "idTokenPresent": isinstance(response.get("idToken"), str)
                and bool(response["idToken"]),
                "refreshTokenPresent": isinstance(response.get("refreshToken"), str)
                and bool(response["refreshToken"]),
            }
            payload = {}
            if checks["idTokenPresent"]:
                try:
                    payload = claims(response["idToken"])
                except ValueError:
                    payload = {}
            checks["claimSubMatches"] = payload.get("sub") == account["uid"]
            checks["claimEmailMatches"] = payload.get("email") == account["email"]
            checks["secondFactorClaim"] = (
                isinstance(payload.get("firebase"), dict)
                and payload["firebase"].get("sign_in_second_factor") == "phone"
            )
            checks["derivedLookup"] = checks["idTokenPresent"] and derived_lookup_ok(
                response["idToken"]
            )
            if not diagnostic:
                require(all(v is True for v in checks.values()))
            return checks

        def fresh_finalize(name):
            credential = pending()
            status, started = start(credential)
            require(status == 200 and "error" not in started)
            session = started.get("phoneResponseInfo", {}).get("sessionInfo")
            require(isinstance(session, str) and bool(session))
            status, signed = finalize(credential, session, code_for(session))
            require(status == 200)
            row(name, status, signed, token_checks(signed))

        def transition(disabled):
            require(core.recovery_identity(account["journal"])[1] == account["uid"])
            status, updated = admin(
                "update", {"localId": account["uid"], "disableUser": disabled}
            )
            require(status == 200 and "error" not in updated)
            require(lookup().get("disabled", False) is disabled)
            report["transitions"].append({"disabled": disabled, "readback": True})

        def held_start_finalize(start_name, finalize_name, credential):
            """A diagnostic start of the held credential, and a finalize when the start
            was accepted; either outcome is recorded, never aborting the run."""
            status, started = start(credential)
            session = (
                started.get("phoneResponseInfo", {}).get("sessionInfo")
                if status == 200
                else None
            )
            started_row = row(
                start_name,
                status,
                started,
                {"sessionInfoPresent": isinstance(session, str) and bool(session)}
                if status == 200
                else None,
            )
            if started_row["outcome"] == "accepted" and session:
                status, signed = finalize(credential, session, code_for(session))
                row(
                    finalize_name,
                    status,
                    signed,
                    token_checks(signed, diagnostic=True) if status == 200 else None,
                )
            else:
                skipped(finalize_name)

        # --- Owned account setup -------------------------------------------------------
        directory = output / "account"
        directory.mkdir(mode=0o700)
        account.update(
            {
                "email": "fireemu-basic-" + secrets.token_hex(16) + "@example.test",
                "marker": "fireemu-owned-" + secrets.token_hex(24),
                "password": "Aa9!" + secrets.token_urlsafe(32),
                "phone": TEST_PHONE,
                "uid": None,
                "journal": directory / "recovery.json",
            }
        )
        require(users(*admin("lookup", {"email": [account["email"]]})) == [])
        require(users(*admin("lookup", {"phoneNumber": [account["phone"]]})) == [])
        save(
            account["journal"],
            {
                "project": PROJECT,
                "email": account["email"],
                "marker": account["marker"],
                "creationAttempted": True,
            },
        )
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
        status, updated = admin(
            "update",
            {
                "localId": account["uid"],
                "emailVerified": True,
                "mfa": {"enrollments": [{"phoneInfo": account["phone"]}]},
            },
        )
        require(status == 200 and "error" not in updated)
        record = lookup()
        enrollments = record.get("mfaInfo")
        require(isinstance(enrollments, list) and len(enrollments) == 1)
        require(enrollments[0].get("phoneInfo") == account["phone"])
        account["enrollmentId"] = enrollments[0]["mfaEnrollmentId"]
        require(record.get("emailVerified") is True)
        report["setup"] = True

        # --- Baseline control ----------------------------------------------------------
        fresh_finalize("baseline-fresh-finalize")

        # --- Hold a pending credential while enabled, then disable ---------------------
        held = pending()
        report["heldPendingBeforeDisable"] = True
        transition(True)
        held_start_finalize("disabled-start", "disabled-finalize", held)

        # --- Re-enable and present the same held credential ----------------------------
        transition(False)
        held_start_finalize("reenabled-start", "reenabled-finalize", held)

        # --- Final control -------------------------------------------------------------
        fresh_finalize("final-fresh-finalize")
        require(inputs() == before)
        report["status"] = "observed"
    except Exception as error:
        report["failure"] = type(error).__name__
    except (Terminated, KeyboardInterrupt) as error:
        report["failure"] = type(error).__name__
    finally:
        if not production:
            report["configRestored"] = True
            report["configDigestMatches"] = True
        if change_attempted:
            try:
                status, raw = restore_configuration(access, original)
                report["configRestored"] = True
                report["configRestoredReadback"] = {
                    "mfa": raw.get("mfa"),
                    "phoneNumber": raw.get("signIn", {}).get("phoneNumber") or {},
                    "smsRegionConfig": raw.get("smsRegionConfig"),
                }
                projection = core.config_projection(status, raw)
                report["configDigestMatches"] = (
                    projection["sha256"] == report["configReadback"]["sha256"]
                )
            except Exception as error:
                report["configRestoreFailure"] = type(error).__name__
        if account:
            try:
                core.cleanup_account(
                    admin,
                    account["email"],
                    account["marker"],
                    account.get("uid"),
                    account["journal"],
                )
                report["cleanup"] = {"uidAbsent": True, "emailAbsent": True}
            except Exception as error:
                report["cleanupFailure"] = type(error).__name__
        for signum, handler in previous.items():
            signal.signal(signum, handler)
        save(output / "observation.json", report)
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--production", action="store_true", required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--recover", type=Path)
    parser.add_argument("--restore-config", type=Path)
    args = parser.parse_args()
    if args.restore_config:
        value = json.loads(args.restore_config.read_bytes())
        require(
            value.get("project") == PROJECT and value.get("changeAttempted") is True
        )
        access, _, _ = core.production_preflight()
        restore_configuration(access, value["original"])
        print(json.dumps({"configRestored": True}))
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
