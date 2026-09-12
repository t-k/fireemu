"""Observe which refusal wins when two apply, then clean up and restore the configuration.

Production needs phone MFA and test phone numbers, which the oracle project does not
have. The recorder enables them for the run and restores the recorded configuration in
`finally`; the restore readback is part of the report. Tokens, pending credentials,
session identifiers, codes and passwords stay in memory and are never written.
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

from precedence_contract import (
    CLAIM_SENTINEL_KEY,
    CORPUS,
    DIAGNOSTIC_FINALIZES,
    PHOTO_SENTINEL_PREFIX,
    TEST_CODE,
    TEST_PHONES,
    WRONG_CODE,
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
# The configuration shape, preconditions, PATCH transport, restore and recovery are the
# ones already exercised by the pending-revocation runs.
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
require(set(revocation.TEST_PHONES.values()) == set(TEST_PHONES.values()))
require(revocation.TEST_CODE == TEST_CODE)


def patch(url, body, token):
    return revocation.patch(url, body, token)


class Terminated(BaseException):
    """SIGTERM or SIGHUP during a run: unwinds through `finally` so the accounts are
    deleted and the configuration restored before the process ends."""


def terminate(signum, frame):
    raise Terminated(signum)


RECOVERY_KEYS = {"project", "original", "changeAttempted", "configSha256"}


def recovery_record(path):
    """The private configuration record of an interrupted run, validated like an account
    journal: a regular private file whose original values have the one shape the
    recorder ever writes (the run preconditions)."""
    require(path.is_file() and not path.is_symlink())
    require(path.stat().st_mode & 0o077 == 0)
    value = json.loads(path.read_bytes())
    require(isinstance(value, dict) and set(value) == RECOVERY_KEYS)
    require(value["project"] == PROJECT and value["changeAttempted"] is True)
    original = value["original"]
    require(isinstance(original, dict))
    require(set(original) == {"mfa", "phoneNumber", "smsRegionConfig"})
    require(original["mfa"] == MFA_OFF and not original["phoneNumber"])
    require(original["smsRegionConfig"] == {"allowlistOnly": {}})
    sha = value["configSha256"]
    require(isinstance(sha, str) and len(sha) == 64)
    return value


def restore_from_record(path):
    """Restore the configuration of an interrupted run and compare the whole-configuration
    digest with the one recorded before the change."""
    value = recovery_record(path)
    access, _, _ = core.production_preflight()
    status, raw = restore_configuration(access, value["original"])
    matches = core.config_projection(status, raw)["sha256"] == value["configSha256"]
    return {"configRestored": True, "configDigestMatches": matches}


def begin(report, step):
    """The step about to be requested: a transport failure leaves it with no status."""
    if "failure" in report:
        return
    report["lastStep"] = step
    report["lastStatus"] = None
    report["lastError"] = None
    report["lastErrorDetail"] = None


def note(report, step, status, response):
    """Sanitized diagnostics for an aborted run: step, status and classified error. The
    failing step is kept: cleanup requests after a failure do not overwrite it."""
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


# Every source file the run's digests cover must be committed: a production run from a
# checkout with local edits would bind its receipt to code that is not in history.
PROBE_TREES = (
    "tools/auth-refusal-precedence",
    "tools/auth-pending-revocation",
    "tools/auth-password-maximum",
    "tools/compat-inventory",
)


def committed_checkout():
    """True when no probe tree has uncommitted changes or untracked files."""
    status = core.command(["git", "status", "--porcelain", "--", *PROBE_TREES])
    return status == ""


def inputs():
    own = {
        str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted(Path(__file__).parent.glob("*.py"))
        if not p.name.startswith("test_")
    }
    return {**revocation.inputs(), **own}


TAMPER_INDEX = 10
# Emulator-style ID tokens are unsigned (`alg: none`, empty third segment); the local run
# appends a signature segment that cannot verify instead of changing one. Production
# tokens are signed, so the production row always exercises the character change.
UNSIGNED_SIGNATURE = "A" * 43


def tampered(id_token):
    """The same JWT with one signature character replaced well inside the signature, where
    every bit is signature data (the final character may carry only padding bits):
    structurally a token, never verifiable. The token is never written."""
    require(isinstance(id_token, str) and id_token.count(".") == 2)
    head, payload, signature = id_token.split(".")
    if signature == "":
        return f"{head}.{payload}.{UNSIGNED_SIGNATURE}"
    require(len(signature) > TAMPER_INDEX + 1)
    replacement = "B" if signature[TAMPER_INDEX] != "B" else "C"
    return ".".join(
        [
            head,
            payload,
            signature[:TAMPER_INDEX] + replacement + signature[TAMPER_INDEX + 1 :],
        ]
    )


def observe(output, origin=None):
    """Production when `origin` is None; otherwise an owned local fireemu at `origin`,
    which needs no configuration change and prints its codes on the inspection route."""
    output.mkdir(parents=True, exist_ok=False, mode=0o700)
    identity, _secure = core.origins(origin)
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
        "held": {},
        "transitions": [],
        "cleanup": {},
    }
    accounts = {}
    admin = None
    access = None
    original = None
    change_attempted = False
    # A termination signal unwinds through `finally` instead of killing the process
    # with the configuration changed and the accounts in place.
    previous = {s: signal.signal(s, terminate) for s in (signal.SIGTERM, signal.SIGHUP)}
    try:
        access, key = "owner", "local-test-key"
        if production:
            # Refused before the preflight, so nothing is read or written from a
            # checkout whose recorder differs from the commit the report names.
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
            # Preconditions first: an unexpected configuration aborts before any write.
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
            # Configuration enforcement may lag the readback.
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
            require(action in {"signUp", "signInWithPassword", "lookup", "update"})
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

        def lookup(account):
            records = users(*admin("lookup", {"localId": [account["uid"]]}))
            owned(records, account["email"], account["marker"], account["uid"])
            return records[0]

        def pending(account):
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
            note(report, "emulator:verificationCodes", status, listing)
            require(status == 200)
            return next(
                c["code"]
                for c in listing.get("verificationCodes", [])
                if c.get("sessionInfo") == session
            )

        def start(account, credential):
            status, started = mfa(
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
            require(status == 200 and "error" not in started)
            session = started.get("phoneResponseInfo", {}).get("sessionInfo")
            require(isinstance(session, str) and bool(session))
            return session

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

        def derived_lookup_ok(account, id_token):
            """Whether the ID token resolves to the owned account; a refusal (for
            example USER_DISABLED for a token issued to a disabled account) is False."""
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

        def token_checks(account, response, diagnostic=False):
            """Control rows require every check; diagnostic rows record each as a
            boolean so an unexpected acceptance is kept as an observation."""
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
                account, response["idToken"]
            )
            if not diagnostic:
                require(all(v is True for v in checks.values()))
            return checks

        def fresh_finalize(name, account):
            credential = pending(account)
            session = start(account, credential)
            status, signed = finalize(credential, session, code_for(session))
            require(status == 200)
            row(name, status, signed, token_checks(account, signed))
            return signed

        def held_finalize(name, account, code):
            """A diagnostic finalize of the held credential and session: either outcome
            is recorded; an accepted one has its token checks recorded as booleans."""
            require(name in DIAGNOSTIC_FINALIZES)
            status, signed = finalize(account["held"], account["session"], code)
            return row(
                name,
                status,
                signed,
                token_checks(account, signed, diagnostic=True)
                if status == 200
                else None,
            )

        def transition(disabled):
            for account in accounts.values():
                require(core.recovery_identity(account["journal"])[1] == account["uid"])
                status, updated = admin(
                    "update", {"localId": account["uid"], "disableUser": disabled}
                )
                require(status == 200 and "error" not in updated)
            for account in accounts.values():
                require(lookup(account).get("disabled", False) is disabled)
            report["transitions"].append({"disabled": disabled, "targetReadback": True})

        for label in ("a", "b"):
            directory = output / label
            directory.mkdir(mode=0o700)
            account = {
                "email": "fireemu-basic-" + secrets.token_hex(16) + "@example.test",
                "marker": "fireemu-owned-" + secrets.token_hex(24),
                "password": "Aa9!" + secrets.token_urlsafe(32),
                "phone": TEST_PHONES[label],
                "uid": None,
                "journal": directory / "recovery.json",
            }
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
            status, updated = admin(
                "update",
                {
                    "localId": account["uid"],
                    "emailVerified": True,
                    "mfa": {"enrollments": [{"phoneInfo": account["phone"]}]},
                },
            )
            require(status == 200 and "error" not in updated)
            record = lookup(account)
            enrollments = record.get("mfaInfo")
            require(isinstance(enrollments, list) and len(enrollments) == 1)
            require(enrollments[0].get("phoneInfo") == account["phone"])
            account["enrollmentId"] = enrollments[0]["mfaEnrollmentId"]
            # Verified, as in the pending-revocation setup that production accepted for
            # phone MFA; the tampered-token row asks to unverify it.
            require(record.get("emailVerified") is True)
            require(record.get("displayName") == account["marker"])
            report["setup"][label] = True

        a, b = accounts["a"], accounts["b"]
        baseline = fresh_finalize("baseline-a-fresh-finalize", a)
        fresh_finalize("baseline-b-fresh-finalize", b)

        # Invalid signature against an administrator-only field, before any disable, so
        # that only these two conditions overlap. The privileged field is a custom claim
        # and the client field a photo URL: an unexpected acceptance cannot change A's
        # verified email, factor enrollment, ownership marker or MFA eligibility. The
        # readback is projected as booleans whatever the outcome; nothing here aborts.
        claim = {CLAIM_SENTINEL_KEY: secrets.token_hex(8)}
        photo = PHOTO_SENTINEL_PREFIX + secrets.token_hex(8) + ".png"
        fields = ("customAttributes", "photoUrl", "displayName", "emailVerified")
        before_update = {k: lookup(a).get(k) for k in fields}
        require(before_update["customAttributes"] is None)
        require(before_update["photoUrl"] is None)
        status, response = client(
            "update",
            {
                "idToken": tampered(baseline["idToken"]),
                "customAttributes": json.dumps(claim),
                "photoUrl": photo,
                "returnSecureToken": False,
            },
        )
        if status != 200:
            # Recorded before the readback so an aborting class stays in the report.
            row("invalid-token-admin-field-update", status, response)
        record = lookup(a)
        after_update = {k: record.get(k) for k in fields}
        try:
            stored_claims = json.loads(after_update["customAttributes"] or "{}")
        except (TypeError, ValueError):
            stored_claims = None
        claim_applied = stored_claims == claim
        photo_applied = after_update["photoUrl"] == photo
        if status == 200:
            row(
                "invalid-token-admin-field-update",
                status,
                response,
                {
                    "noError": "error" not in response,
                    "customAttributesApplied": claim_applied,
                    "photoUrlApplied": photo_applied,
                },
            )
        report["invalidTokenStateUnchanged"] = (
            after_update == before_update and not claim_applied and not photo_applied
        )

        # Both accounts hold a pending credential and an open SMS session before the
        # disable; the harness requires the start to succeed, the finalizes are observed.
        # The code is captured at start time so a later attempt reuses the same session.
        for label, account in accounts.items():
            account["held"] = pending(account)
            account["session"] = start(account, account["held"])
            account["code"] = code_for(account["session"])
            report["held"][label] = True

        transition(True)
        held_finalize("disabled-a-wrong-code-finalize", a, WRONG_CODE)
        held_finalize("disabled-b-correct-code-finalize", b, b["code"])

        transition(False)
        held_finalize("reenabled-a-held-finalize", a, a["code"])
        held_finalize("reenabled-b-held-finalize", b, b["code"])

        fresh_finalize("final-a-fresh-finalize", a)
        fresh_finalize("final-b-fresh-finalize", b)
        require(inputs() == before)
        report["status"] = "observed"
    except Exception as error:
        report["failure"] = type(error).__name__
    except (Terminated, KeyboardInterrupt) as error:
        report["failure"] = type(error).__name__
    finally:
        # The project-wide change is undone first; the owned accounts do not need it.
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
        report["cleanupAccounts"] = {}
        for label, account in accounts.items():
            try:
                core.cleanup_account(
                    admin,
                    account["email"],
                    account["marker"],
                    account["uid"],
                    account["journal"],
                )
                report["cleanupAccounts"][label] = "absent"
            except Exception as error:
                report["cleanupAccounts"][label] = "unresolved"
                report["cleanupFailure"] = type(error).__name__
        if len(accounts) == 2 and all(
            v == "absent" for v in report["cleanupAccounts"].values()
        ):
            report["cleanup"] = {"uidAbsent": True, "emailAbsent": True}
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
        outcome = restore_from_record(args.restore_config)
        print(json.dumps(outcome))
        raise SystemExit(0 if outcome["configDigestMatches"] else 2)
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
