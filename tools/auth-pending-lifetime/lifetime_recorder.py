"""Sample an MFA pending credential's usability at increasing ages, observe, clean up.

One independent owned account per sampled age; each account's pending credential is
obtained near a common origin and left untouched until its diagnostic, so no intermediate
access can extend it. The SMS session is opened fresh at the diagnostic, isolating the
pending age from the session age. Production ages by real waiting within a declared
observation budget; the owned local run ages by advancing the virtual clock through the
control API, so it can sample past the local pending lifetime deterministically. Tokens,
pending credentials, session identifiers, codes and passwords stay in memory.
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
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

from lifetime_contract import (
    AGE_SECONDS,
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
restore_configuration, phone_config, claims = (
    revocation.restore_configuration,
    revocation.phone_config,
    revocation.claims,
)
require(
    TEST_PHONE in revocation.TEST_PHONES.values() and revocation.TEST_CODE == TEST_CODE
)

PROBE_TREES = (
    "tools/auth-pending-lifetime",
    "tools/auth-pending-revocation",
    "tools/auth-password-maximum",
    "tools/compat-inventory",
)
# The declared observation budget. Production ages by real waiting up to totalBudgetSeconds
# (pendings age in parallel from a common origin, so the wall time is the largest age plus
# overhead), holds the temporary configuration no longer than configHoldMaxSeconds, and
# reserves cleanupReserveSeconds to restore configuration and delete accounts even if the
# budget is exhausted.
BUDGET = {
    "maxAccounts": len(AGE_SECONDS) + 2,
    "maxRequests": 200,
    "totalBudgetSeconds": max(AGE_SECONDS) + 300,
    "configHoldMaxSeconds": max(AGE_SECONDS) + 300,
    "cleanupReserveSeconds": 120,
}


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


def note(report, step, status, response):
    if "failure" in report:
        return
    report["lastStep"] = step
    report["lastStatus"] = status
    report["lastError"] = None if status == 200 else error_code(response)


def inputs():
    own = {
        str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted(Path(__file__).parent.glob("*.py"))
        if not p.name.startswith("test_")
    }
    return {**revocation.inputs(), **own}


def observe(output, origin=None, clock_control=None):
    """Production when origin is None (real-time aging); otherwise an owned local fireemu
    at origin, aged through clock_control=(control_origin, token) via the control clock."""
    output.mkdir(parents=True, exist_ok=False, mode=0o700)
    identity = core.origins(origin)[0]
    production = origin is None
    before = inputs()
    report: dict = {
        "schemaVersion": 1,
        "acceptance": "candidate",
        "status": "incomplete",
        "target": "production" if production else "local",
        "agingMode": "real-time" if production else "virtual-clock",
        "recordedAt": datetime.now(UTC).isoformat(),
        "project": PROJECT,
        "projectNumber": NUMBER if production else None,
        "probeInputs": before,
        "probeSourceCommit": core.command(["git", "rev-parse", "HEAD"]),
        "corpus": CORPUS,
        "budget": dict(BUDGET),
        "accountsUsed": 0,
        "cases": [],
        "setup": False,
        "cleanup": {},
    }
    accounts: dict = {}
    admin = None
    access = None
    original = None
    change_attempted = False
    request_count = 0
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

        def counted():
            nonlocal request_count
            request_count += 1
            require(request_count <= BUDGET["maxRequests"])  # request budget

        def admin(action, body):
            require(action in {"lookup", "update", "delete"})
            counted()
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
            counted()
            begin(report, action)
            status, response = core.request(
                f"{identity}/v1/accounts:{action}{query}", body
            )
            note(report, action, status, response)
            return status, response

        def mfa(action, body):
            require(action in {"mfaSignIn:start", "mfaSignIn:finalize"})
            counted()
            begin(report, action)
            status, response = core.request(
                f"{identity}/v2/accounts/{action}{query}", body
            )
            note(report, action, status, response)
            return status, response

        # --- Aging: measure age from each pending's own acquisition, not a fixed origin. ---
        # Production waits real time; the owned local run advances the shared virtual clock.
        # Either way the age is (elapsed_now - the pending's acquiredAt), so setup time before
        # acquisition never counts against a pending's measured age.
        origin_monotonic = time.monotonic()
        origin_clock = clock_now(clock_control) if not production else None

        def elapsed_now():
            if production:
                return time.monotonic() - origin_monotonic
            return clock_now(clock_control) - origin_clock

        def age_to(target):
            # Bring elapsed_now up to `target` seconds. Idempotent when already past it.
            require(target <= BUDGET["totalBudgetSeconds"])  # total time budget
            if production:
                deadline = origin_monotonic + target
                while time.monotonic() < deadline:
                    time.sleep(min(5.0, deadline - time.monotonic()))
            else:
                delta = target - elapsed_now()
                if delta > 0:
                    advance_clock(clock_control, delta)

        def lookup(account):
            records = users(*admin("lookup", {"localId": [account["uid"]]}))
            owned(records, account["email"], account["marker"], account["uid"])
            return records[0]

        def derived_lookup_ok(account, id_token):
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

        def new_account(label):
            directory = output / label
            directory.mkdir(mode=0o700)
            account = {
                "email": "fireemu-basic-" + secrets.token_hex(16) + "@example.test",
                "marker": "fireemu-owned-" + secrets.token_hex(24),
                "password": "Aa9!" + secrets.token_urlsafe(32),
                "phone": TEST_PHONE,
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
            report["accountsUsed"] = len(accounts)
            require(len(accounts) <= BUDGET["maxAccounts"])  # account budget
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
            account["enrollmentId"] = enrollments[0]["mfaEnrollmentId"]
            require(record.get("emailVerified") is True)
            return account

        def pending(account):
            status, response = client(
                "signInWithPassword",
                {
                    "email": account["email"],
                    "password": account["password"],
                    "returnSecureToken": True,
                },
            )
            require(status == 200 and "idToken" not in response)
            credential = response.get("mfaPendingCredential")
            info = response.get("mfaInfo")
            require(isinstance(credential, str) and bool(credential))
            require(
                isinstance(info, list)
                and len(info) == 1
                and info[0].get("mfaEnrollmentId") == account["enrollmentId"]
            )
            return credential

        def start(account, credential):
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

        def token_checks(account, response, diagnostic=False):
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
            status, started = start(account, credential)
            require(status == 200 and "error" not in started)
            session = started.get("phoneResponseInfo", {}).get("sessionInfo")
            require(isinstance(session, str) and bool(session))
            status, signed = finalize(credential, session, code_for(session))
            require(status == 200)
            row(name, status, signed, token_checks(account, signed))

        # --- Setup: baseline, one account per age, final ------------------------------
        baseline = new_account("baseline")
        age_accounts = {a: new_account(f"age-{a}") for a in AGE_SECONDS}
        final = new_account("final")
        report["setup"] = True

        # --- Baseline control ----------------------------------------------------------
        fresh_finalize("baseline-fresh-finalize", baseline)

        # --- Obtain each age account's held pending at the common origin ---------------
        held = {
            a: {"credential": pending(age_accounts[a]), "acquiredAt": elapsed_now()}
            for a in AGE_SECONDS
        }

        # --- Age to each target and diagnose (fresh session at the diagnostic) ---------
        for a in sorted(AGE_SECONDS):
            account, entry = age_accounts[a], held[a]
            age_to(entry["acquiredAt"] + a)
            pending_age = round(elapsed_now() - entry["acquiredAt"])
            session_opened = elapsed_now()
            status, started = start(account, entry["credential"])
            session = (
                started.get("phoneResponseInfo", {}).get("sessionInfo")
                if status == 200
                else None
            )
            session_present = isinstance(session, str) and bool(session)
            started_row = row(
                f"age-{a}s-start",
                status,
                started,
                {
                    "sessionInfoPresent": session_present,
                    "pendingAgeSeconds": pending_age,
                    "sessionAgeSeconds": round(elapsed_now() - session_opened),
                }
                if status == 200
                else None,
            )
            if started_row["outcome"] == "accepted" and session_present:
                status, signed = finalize(
                    entry["credential"], session, code_for(session)
                )
                row(
                    f"age-{a}s-finalize",
                    status,
                    signed,
                    token_checks(account, signed, diagnostic=True)
                    if status == 200
                    else None,
                )
            else:
                skipped(f"age-{a}s-finalize")

        # --- Final control -------------------------------------------------------------
        fresh_finalize("final-fresh-finalize", final)
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
                report["configDigestMatches"] = (
                    core.config_projection(status, raw)["sha256"]
                    == report["configReadback"]["sha256"]
                )
            except Exception as error:
                report["configRestoreFailure"] = type(error).__name__
        cleaned = []
        for account in accounts.values():
            try:
                cleaned.append(
                    core.cleanup_account(
                        admin,
                        account["email"],
                        account["marker"],
                        account.get("uid"),
                        account["journal"],
                    )
                )
            except Exception as error:
                report["cleanupFailure"] = type(error).__name__
        if (
            accounts
            and len(cleaned) == len(accounts)
            and all(c == {"uidAbsent": True, "emailAbsent": True} for c in cleaned)
        ):
            report["cleanup"] = {"uidAbsent": True, "emailAbsent": True}
        for signum, handler in previous.items():
            signal.signal(signum, handler)
        save(output / "observation.json", report)
    return report


def _control(clock_control, path, body=None):
    control_origin, token = clock_control
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        control_origin + path,
        data=data,
        headers={
            "Origin": "http://127.0.0.1",
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        method="POST" if body is not None else "GET",
    )
    with urllib.request.build_opener(
        core.NoRedirect(), urllib.request.ProxyHandler({})
    ).open(req, timeout=20) as resp:
        return json.loads(resp.read())


def clock_now(clock_control):
    value = _control(clock_control, "/v1/sessions/default")
    instant = (
        value["clock"]["clock"]
        if isinstance(value.get("clock"), dict)
        else value["clock"]
    )
    return datetime.fromisoformat(instant.replace("Z", "+00:00")).timestamp()


def advance_clock(clock_control, seconds):
    # Millisecond precision so a pending lands at least at its sampled age, never short.
    _control(
        clock_control,
        "/v1/sessions/default/clock:advance",
        {"millis": max(0, round(seconds * 1000))},
    )


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
