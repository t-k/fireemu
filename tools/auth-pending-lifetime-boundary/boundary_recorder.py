"""Sample an MFA pending credential's usability toward its boundary, observe, clean up.

Revision 2 of auth-pending-lifetime: same machinery as revision 1, but the sampled ages
extend past revision 1's 300-second lower bound to straddle the boundary where a pending
credential stops being usable, so a run can observe a refusal at a large age and record the
usability window as an interval. One independent owned account per sampled age; each
pending obtained near a common origin and left untouched until its diagnostic; a fresh SMS
session at the diagnostic; pending age and session age recorded as separate intervals.
Production ages by real waiting within a declared observation budget; the owned local run
ages by advancing the virtual clock, so it samples past the local pending lifetime
deterministically.

Two clocks are kept apart. The AGING clock measures a pending credential's age: real
monotonic time in production, the shared virtual clock locally. The WALL clock (always real
monotonic time) enforces the observation budget, so a local run's instantaneous virtual
aging never trips a wall-time budget, and a production run's real waiting does. Because a
~65-minute production run outlives one admin access token, the recorder refreshes the admin
credential when it ages and records each token age at use, which the contract checks against
the budget. Every row carries a timing region on the aging clock, saved on acceptance and
refusal alike. Tokens, pending credentials, session identifiers, codes and passwords stay in
memory.
"""

# ruff: noqa: BLE001 -- Never expose raw exceptions or credentials.
import argparse
import hashlib
import json
import math
import secrets
import signal
import sys
import time
import urllib.parse
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

from boundary_contract import (
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
    "tools/auth-pending-lifetime-boundary",
    "tools/auth-pending-lifetime",
    "tools/auth-pending-revocation",
    "tools/auth-password-maximum",
    "tools/compat-inventory",
)
# The declared observation budget. Revision 2 ages to about 3900 s (~65 min), which outlives
# a single admin access token, so the budget adds adminTokenMaxAgeSeconds and the run
# refreshes the token before it ages that far. totalBudgetSeconds covers the largest age plus
# setup and a larger cleanup reserve (deletions of more accounts after a long run);
# configHoldMaxSeconds bounds the time configuration stays enabled; observation stops early
# enough to leave cleanupReserveSeconds for restore and deletion before either deadline.
BUDGET = {
    "maxAccounts": len(AGE_SECONDS) + 2,
    "maxRequests": 300,
    "recoveryRequestReserve": 60,
    "totalBudgetSeconds": max(AGE_SECONDS) + 900,
    "configHoldMaxSeconds": max(AGE_SECONDS) + 900,
    "cleanupReserveSeconds": 300,
    "adminTokenMaxAgeSeconds": 3000,
}
# Refresh the admin access token once it is older than this, comfortably under both the
# ~1-hour ADC token lifetime and adminTokenMaxAgeSeconds, so no admin request is ever issued
# with a token older than the budget allows even across the long aging waits.
ADMIN_TOKEN_REFRESH_SECONDS = 2400
# The shared transport's socket timeout (maximum_recorder.request / revocation.patch open
# with timeout=20). Every request path reserves this before sending, so against the trusted
# oracle -- which responds in well under it, and to which each blocking socket operation is
# bounded by this timeout -- a request that starts finishes before its phase deadline. This
# approximates a response-inclusive deadline without a per-call dynamic timeout (the shared
# transport is not modified); it is not a hard total-request deadline, so a pathologically
# slow server could still exceed it, which is out of scope for the trusted-oracle model.
REQUEST_BUDGET_SECONDS = 20


def patch(url, body, token):
    return revocation.patch(url, body, token)


class Terminated(BaseException):
    """SIGTERM or SIGHUP during a run: unwinds through `finally`."""


class BudgetExhausted(Exception):
    """An observation budget guard fired: a clean early stop, not a crash. Cleanup still
    runs in the recovery reserve; the run is incomplete and records the guard."""

    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


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
        "stopReason": "error",
        "requestCount": {"observation": 0, "recovery": 0, "config": 0},
        "wallElapsedSeconds": 0.0,
        "configHoldSeconds": 0.0,
        "adminTokenAges": [],
    }
    accounts: dict = {}
    admin = None
    access = None
    original = None
    change_attempted = False
    phase = ["observation"]
    request_count = report["requestCount"]
    run_started = time.monotonic()
    # Wall time the current admin access token was acquired (production only); the token is
    # refreshed when it ages past ADMIN_TOKEN_REFRESH_SECONDS so a long run never uses one
    # older than the budget allows.
    admin_token_acquired = [None]
    config_enabled_wall = None
    previous = {s: signal.signal(s, terminate) for s in (signal.SIGTERM, signal.SIGHUP)}
    try:
        access, key = "owner", "local-test-key"

        def config_counted():
            request_count["config"] += 1

        # --- Budget guards on the WALL clock (real time), separate from the aging clock.
        # Defined before the configuration change so preflight and the enabling PATCH are
        # bounded too: configuration is never enabled once the deadline has passed. ---
        def deadline():
            # The wall time by which the current phase must be finished. Observation must
            # leave the cleanup reserve; recovery may spend it. The config-hold limit binds
            # only once configuration is enabled.
            total = run_started + BUDGET["totalBudgetSeconds"]
            if production and config_enabled_wall is not None:
                total = min(total, config_enabled_wall + BUDGET["configHoldMaxSeconds"])
            if phase[0] == "recovery":
                return total
            return total - BUDGET["cleanupReserveSeconds"]

        def config_binds():
            return (
                production
                and config_enabled_wall is not None
                and config_enabled_wall + BUDGET["configHoldMaxSeconds"]
                < run_started + BUDGET["totalBudgetSeconds"]
            )

        def time_guard():
            # Reserve the transport's worst-case timeout: only start a request (or continue
            # aging toward the next one) if it can finish before the phase deadline.
            if time.monotonic() + REQUEST_BUDGET_SECONDS > deadline():
                raise BudgetExhausted(
                    "config-hold-budget" if config_binds() else "time-budget"
                )

        if production:
            # Preflight is a budget-consuming phase: stop before it if the budget is already
            # spent, and again (via config()'s guard) before enabling configuration, so the
            # change is never applied past the deadline. The gcloud subprocesses inside
            # preflight carry their own timeouts; these checkpoints bound the phase entry.
            time_guard()
            require(committed_checkout())
            report["committedCheckout"] = True
            access, key, report["configReadback"] = core.production_preflight()
            admin_token_acquired[0] = time.monotonic()
            time_guard()

            def config(patch_body=None, mask=None):
                time_guard()
                config_counted()
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
            config_enabled_wall = time.monotonic()
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
            # Time first, then request count; check both before incrementing, so a rejected
            # request is never issued and the recorded count reflects requests actually sent.
            time_guard()
            current = phase[0]
            if current == "observation":
                if (
                    request_count["observation"] + 1
                    > BUDGET["maxRequests"] - BUDGET["recoveryRequestReserve"]
                ):
                    raise BudgetExhausted("request-budget")
            elif (
                request_count["observation"] + request_count["recovery"] + 1
                > BUDGET["maxRequests"]
            ):
                raise BudgetExhausted("request-budget")
            request_count[current] += 1

        def admin_access():
            # Production only: the ADC access token outlives neither ~1 hour nor a ~65-minute
            # aging run, so refresh it before it ages past the threshold and record its age at
            # each use, which complete() checks against adminTokenMaxAgeSeconds. Local uses the
            # fixed "owner" token, which never expires.
            nonlocal access
            if not production:
                return access
            age = time.monotonic() - admin_token_acquired[0]
            if age > ADMIN_TOKEN_REFRESH_SECONDS:
                access = core.command(
                    ["gcloud", "auth", "application-default", "print-access-token"]
                )
                admin_token_acquired[0] = time.monotonic()
                age = 0.0
            report["adminTokenAges"].append(age)
            return access

        def admin(action, body):
            require(action in {"lookup", "update", "delete"})
            token = admin_access()
            counted()
            begin(report, f"admin:{action}")
            status, response = core.request(
                f"{identity}/v1/projects/{PROJECT}/accounts:{action}",
                body,
                token,
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
        origin_monotonic = time.monotonic()
        origin_clock = clock_now(clock_control) if not production else None

        def elapsed_now():
            if production:
                return time.monotonic() - origin_monotonic
            return clock_now(clock_control) - origin_clock

        def age_to(target):
            # The wall-clock time_guard bounds real aging; a target beyond the budget stops
            # the run cleanly (BudgetExhausted), never as an unclassified error, and it
            # reserves the following start request's worst-case time too. Local aging is
            # instant on the virtual clock and does not spend the wall budget.
            if production:
                aging_deadline = origin_monotonic + target
                while time.monotonic() < aging_deadline:
                    time_guard()
                    time.sleep(min(5.0, aging_deadline - time.monotonic()))
            else:
                # Advance until the aging clock has reached at least the target, so the
                # measured pending age is never a rounding hair below the sampled age.
                # advance_clock rounds up, so each step makes progress; a few iterations
                # absorb any read/advance drift.
                for _ in range(8):
                    remaining = target - elapsed_now()
                    if remaining <= 0:
                        break
                    advance_clock(clock_control, remaining)

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
            require(len(accounts) <= BUDGET["maxAccounts"])
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

        def timed_pending(account):
            # Bracket the acquisition: the pending is issued between send and receive, so
            # both bounds are needed to cover the pending's true age including this latency.
            sent = elapsed_now()
            credential = pending(account)
            return credential, sent, elapsed_now()

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

        def timed_start(account, credential):
            sent = elapsed_now()
            status, started = start(account, credential)
            return status, started, sent, elapsed_now()

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

        def timed_finalize(credential, session, code):
            sent = elapsed_now()
            status, signed = finalize(credential, session, code)
            return status, signed, sent, elapsed_now()

        rows_started = time.monotonic()

        def start_timing(p_sent, p_recv, s_sent, s_recv):
            return {
                "pendingSent": p_sent,
                "pendingReceived": p_recv,
                "startSent": s_sent,
                "startReceived": s_recv,
                "pendingAgeAtStart": {
                    "lower": s_sent - p_recv,
                    "upper": s_recv - p_sent,
                },
            }

        def finalize_timing(p_sent, p_recv, s_sent, s_recv, f_sent, f_recv):
            return {
                "pendingSent": p_sent,
                "pendingReceived": p_recv,
                "startSent": s_sent,
                "startReceived": s_recv,
                "finalizeSent": f_sent,
                "finalizeReceived": f_recv,
                "sessionAgeAtFinalize": {
                    "lower": f_sent - s_recv,
                    "upper": f_recv - s_sent,
                },
                "pendingAgeAtFinalize": {
                    "lower": f_sent - p_recv,
                    "upper": f_recv - p_sent,
                },
            }

        def row(name, status, response, checks, timing):
            result = {
                "id": name,
                "httpStatus": status,
                "outcome": "accepted" if status == 200 else "refused",
                "observedError": None if status == 200 else error_code(response),
                "checks": checks if status == 200 else {},
                "timing": timing,
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
                "timing": {},
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
            credential, p_sent, p_recv = timed_pending(account)
            status, started, s_sent, s_recv = timed_start(account, credential)
            require(status == 200 and "error" not in started)
            session = started.get("phoneResponseInfo", {}).get("sessionInfo")
            require(isinstance(session, str) and bool(session))
            fstatus, signed, f_sent, f_recv = timed_finalize(
                credential, session, code_for(session)
            )
            require(fstatus == 200)
            row(
                name,
                fstatus,
                signed,
                token_checks(account, signed),
                finalize_timing(p_sent, p_recv, s_sent, s_recv, f_sent, f_recv),
            )

        # --- Setup: baseline, one account per age, final ------------------------------
        baseline = new_account("baseline")
        age_accounts = {a: new_account(f"age-{a}") for a in AGE_SECONDS}
        final = new_account("final")
        report["setup"] = True

        # --- Baseline control ----------------------------------------------------------
        fresh_finalize("baseline-fresh-finalize", baseline)

        # --- Obtain each age account's held pending at the common origin ---------------
        held = {}
        for a in AGE_SECONDS:
            credential, p_sent, p_recv = timed_pending(age_accounts[a])
            held[a] = {
                "credential": credential,
                "pendingSent": p_sent,
                "pendingReceived": p_recv,
            }

        # --- Age to each target and diagnose (fresh session at the diagnostic) ---------
        for a in sorted(AGE_SECONDS):
            account, entry = age_accounts[a], held[a]
            # Age from the pending's own acquisition (its received time), so the recorded
            # age is at least the sampled age even after acquisition latency.
            age_to(entry["pendingReceived"] + a)
            status, started, s_sent, s_recv = timed_start(account, entry["credential"])
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
                {"sessionInfoPresent": session_present} if status == 200 else None,
                start_timing(
                    entry["pendingSent"], entry["pendingReceived"], s_sent, s_recv
                ),
            )
            if started_row["outcome"] == "accepted" and session_present:
                fstatus, signed, f_sent, f_recv = timed_finalize(
                    entry["credential"], session, code_for(session)
                )
                row(
                    f"age-{a}s-finalize",
                    fstatus,
                    signed,
                    token_checks(account, signed, diagnostic=True)
                    if fstatus == 200
                    else None,
                    finalize_timing(
                        entry["pendingSent"],
                        entry["pendingReceived"],
                        s_sent,
                        s_recv,
                        f_sent,
                        f_recv,
                    ),
                )
            else:
                skipped(f"age-{a}s-finalize")

        # --- Final control -------------------------------------------------------------
        fresh_finalize("final-fresh-finalize", final)
        require(inputs() == before)
        report["status"] = "observed"
        report["stopReason"] = "completed"
    except BudgetExhausted as error:
        report["stopReason"] = error.reason
    except Exception as error:
        report["failure"] = type(error).__name__
        report["stopReason"] = "error"
    except (Terminated, KeyboardInterrupt) as error:
        report["failure"] = type(error).__name__
        report["stopReason"] = "terminated"
    finally:
        # Recovery runs under its own deadline (it may spend the cleanup reserve) and its own
        # request reserve. Restore and deletion are always attempted; each recovery request
        # is time-guarded and counted per attempt, so a request that fails partway is still
        # counted and the run never runs past the total budget. Whatever cannot be confirmed
        # within budget is left with its recovery journal for a later `--recover`.
        phase[0] = "recovery"
        # After a long aging run the admin token has expired; refresh it once so the config
        # restore and the account deletions below use a live credential. A failed refresh is
        # swallowed here; the restore and cleanup report their own failures.
        if production and admin_token_acquired[0] is not None:
            try:
                access = core.command(
                    ["gcloud", "auth", "application-default", "print-access-token"]
                )
                admin_token_acquired[0] = time.monotonic()
            except Exception as error:
                report["adminTokenRefreshFailure"] = type(error).__name__
        if not production:
            report["configRestored"] = True
            report["configDigestMatches"] = True
        if change_attempted:
            try:
                time_guard()
                config_counted()
                status, response = patch(
                    f"{CONFIG_URL}?updateMask={urllib.parse.quote(CONFIG_MASK, safe=',')}",
                    revocation.restore_body(original),
                    access,
                )
                require(status == 200 and "error" not in response)
                time_guard()
                config_counted()
                status, raw = core.request(CONFIG_URL, token=access, quota=True)
                require(status == 200 and revocation.restored(raw, original))
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
        if production and config_enabled_wall is not None:
            report["configHoldSeconds"] = time.monotonic() - config_enabled_wall
        cleaned = []
        unrecovered = 0
        stopped = False
        for account in accounts.values():
            if stopped:
                unrecovered += 1
                continue
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
            except BudgetExhausted:
                # No budget left to confirm this account; leave it and its recovery journal
                # for a later `--recover` rather than spin on the exhausted budget.
                unrecovered += 1
                stopped = True
            except Exception as error:
                report["cleanupFailure"] = type(error).__name__
        if unrecovered:
            report["recoveryIncomplete"] = True
            report["unrecoveredCount"] = unrecovered
        if (
            accounts
            and not unrecovered
            and len(cleaned) == len(accounts)
            and all(c == {"uidAbsent": True, "emailAbsent": True} for c in cleaned)
        ):
            report["cleanup"] = {"uidAbsent": True, "emailAbsent": True}
        report["requestCount"] = dict(request_count)
        report["wallElapsedSeconds"] = time.monotonic() - run_started
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
    # Round the advance UP to whole milliseconds so a pending lands at least at its sampled
    # age, never a rounding hair short; at least 1 ms so a top-up step always progresses.
    _control(
        clock_control,
        "/v1/sessions/default/clock:advance",
        {"millis": max(1, math.ceil(seconds * 1000))},
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
