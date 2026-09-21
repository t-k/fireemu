"""Run the campaign's observation cases against an owned local `fireemu` instance.

This is the local half of the campaign: it starts one strict Auth artifact on
OS-assigned ports, walks the same ordered cases the production collector would walk,
ages pending credentials and enrollment sessions by advancing the owned instance's
virtual clock, and writes a ledger of what fireemu actually answered. It never contacts
Firebase, never reads ambient Google credentials, and never records a shared secret, a
one-time code, a token, a pending credential or a session identifier.

    python mfa_local_shadow.py --output /absolute/private/o2-mfa-shadow
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import signal
import subprocess
import sys
import time
import urllib.parse
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from mfa_cases import (
    AGED_PENDING_SAMPLES,
    CAMPAIGN_ID,
    SAMPLED_AGES_SECONDS,
    observation_cases,
)
from mfa_collector import (
    assert_no_sensitive_material,
    cleanup_complete,
    outstanding_cleanup,
    initial_state,
    mark_deleted,
    record_step,
    register_owned,
    run_complete,
    skip_step,
)
from mfa_manifest import compile_campaign
from mfa_provenance import compute_provenance, describe_worktree, repository_root
from mfa_persistence import RunPersistence, complete_summary
from mfa_request_budget import RequestBudget, valid_summary as valid_request_summary
from mfa_totp import TotpParameters, totp_code, wrong_code
from mfa_wire import call as _bounded_call, origin as _local_origin, validate_url

PROJECT = "fireemu-35fe6"
API_KEY = "fireemu-local-shadow-key"
TEST_PHONE = "+15555550100"
# The local instance sends no SMS; the token is a placeholder the request shape requires.
PHONE_SIGN_IN_INFO = {"recaptchaToken": "fireemu-local-shadow"}
# The owned instance is reaped rather than abandoned when this deadline passes.
CHILD_TIMEOUT_SECONDS = 900
# Each aged sample is taken this long past its target age (see `_walk`).
AGE_SAMPLE_MARGIN_SECONDS = 1
CONFIG = {"schemaVersion": 1, "profile": "strict", "auth": {"totp": {}}}
SCHEMA = "o2-mfa-local-shadow-v1"
RUNTIME_IDENTITY_FILE = "runtime-identity.json"


class Refused(RuntimeError):
    """A local request answered with an error status."""

    def __init__(self, status: int, code: str | None) -> None:
        super().__init__(f"{status} {code}")
        self.status = status
        self.code = code


def _call(url: str, body: Any = None, token: str | None = None) -> tuple[int, dict]:
    # A socket inactivity timeout is not a whole-response deadline. The fixed,
    # isolated worker is killed/reaped by its caller if the full call expires.
    return _bounded_call(url, body, token)


def _code_of(payload: dict) -> str | None:
    error = payload.get("error") if isinstance(payload, dict) else None
    message = error.get("message") if isinstance(error, dict) else None
    return message.split(":", 1)[0].strip() if isinstance(message, str) else None


class Instance:
    """One owned local Auth instance addressed by its loopback origins."""

    def __init__(self, origin: str, control: str, token: str) -> None:
        # Every call through this instance is charged, so the budget reflects the run's
        # real HTTP traffic rather than one notional request per case.
        self._request_budget = RequestBudget()
        self.origin = _local_origin(origin)
        self.identity = self.origin + "/identitytoolkit.googleapis.com"
        # The control URL is handed over with its version prefix already attached.
        self.control = _local_origin(control, control=True)
        self.token = token

    @property
    def requests(self) -> int:
        return self._request_budget.requests

    def bind_plan(self, plan: dict) -> None:
        self._request_budget.bind(plan)

    def begin_recovery(self, owned_uids: tuple[str, ...]) -> None:
        self._request_budget.begin_recovery(owned_uids)

    def finish_requests(self) -> dict:
        self._request_budget.close()
        return self._request_budget.snapshot()

    def send(
        self, url: str, body: Any = None, token: str | None = None
    ) -> tuple[int, dict]:
        parsed = validate_url(url)
        if f"{parsed.scheme}://{parsed.netloc}" not in {self.origin, self.control}:
            raise ValueError("request is outside the owned loopback origins")
        # Count every attempt, including failure, before dispatch. This counter
        # includes inspection/control calls; it is not a new quota allowance.
        operation = uid = None
        if self._request_budget.snapshot()["phase"] == "recovery":
            # Validate and send the same private value snapshot; caller-owned
            # dictionaries/lists must not retarget a reserved UID after admission.
            body = copy.deepcopy(body)
            # Only this run's delete/lookup pair may spend the reserved tail.
            # No query-string alias, body extension or control request is admitted.
            prefix = f"{self.identity}/v1/projects/{PROJECT}/accounts:"
            if url == prefix + "delete" and type(body) is dict and set(body) == {"localId"}:
                operation, uid = "delete", body["localId"]
            elif (url == prefix + "lookup" and type(body) is dict and set(body) == {"localId"}
                    and type(body["localId"]) is list and len(body["localId"]) == 1):
                operation, uid = "lookup", body["localId"][0]
            if token != "owner":
                raise ValueError("recovery requires the local owner route")
        with self._request_budget.attempt(operation=operation, uid=uid):
            return _call(url, body, token)

    def public(self, path: str, body: Any) -> tuple[int, dict]:
        return self.send(f"{self.identity}{path}?key={API_KEY}", body)

    def admin(self, path: str, body: Any) -> tuple[int, dict]:
        return self.send(f"{self.identity}{path}", body, token="owner")

    def emulator(self, path: str) -> tuple[int, dict]:
        # The inspection routes are served at the instance root, not under the API host prefix.
        return self.send(
            f"{self.origin}/emulator/v1/projects/{PROJECT}{path}", token=self.token
        )

    def advance(self, seconds: float) -> None:
        status, _ = self.send(
            f"{self.control}/v1/sessions/default/clock:advance",
            {"millis": max(1, int(seconds * 1000) + 1)},
            token=self.token,
        )
        if status != 200:
            raise RuntimeError(f"clock advance refused with {status}")

    def now(self) -> int:
        """Return the owned instance's logical time, which the codes must be computed at."""
        status, payload = self.send(
            f"{self.control}/v1/sessions/default", token=self.token
        )
        if status != 200:
            raise RuntimeError(f"clock read refused with {status}")
        value = payload["clock"]
        instant = value["clock"] if isinstance(value, dict) else value
        return int(
            datetime.strptime(instant[:19], "%Y-%m-%dT%H:%M:%S")
            .replace(tzinfo=timezone.utc)
            .timestamp()
        )

    def require(self, status: int, payload: dict) -> dict:
        if type(status) is not int or status != 200:
            raise Refused(status, _code_of(payload))
        if not isinstance(payload, dict) or "error" in payload:
            raise ValueError("local Auth success response is malformed")
        return payload


def _row(case_id: str, status: int, code: str | None, **extra: Any) -> dict[str, Any]:
    """Build one published row, refusing any extra that names secret material.

    The row, not the collector observation, is what leaves the machine, so it gets the
    same screen rather than relying on the redaction that happens later.
    """
    row = {
        "id": case_id,
        "status": status,
        "errorCode": code,
        "outcome": "observed",
        **extra,
    }
    assert_no_sensitive_material(row, "published row")
    return row


def _observe(instance: Instance, path: str, body: Any) -> tuple[int, dict, str | None]:
    status, payload = instance.public(path, body)
    return status, payload, _code_of(payload)


def create_account(instance: Instance, email: str | None, verified: bool = True, *, on_created=None) -> dict:
    if email is None and verified:
        raise ValueError("anonymous account cannot use email verification setup")
    payload = instance.require(
        *instance.public(
            "/v1/accounts:signUp",
            ({"returnSecureToken": True} if email is None else
             {"email": email, "password": "Shadow-Passw0rd!", "returnSecureToken": True}),
        )
    )
    # Register a typed signup ACK before token parsing, email verification or
    # a second sign-in can fail. A callback failure stops all subsequent setup.
    uid = payload.get("localId") if isinstance(payload, dict) else None
    if (not isinstance(payload, dict) or "error" in payload
            or not isinstance(uid, str) or not uid or any(ord(c) < 32 or ord(c) == 127 for c in uid)
            or ("email" in payload and payload["email"] != email)):
        raise ValueError("signup did not acknowledge the requested account")
    account = {"localId": uid, "email": email}
    if on_created is not None:
        on_created(account)
    if not isinstance(payload.get("idToken"), str) or not payload["idToken"]:
        raise ValueError("signup token is missing or malformed")
    account["idToken"] = payload["idToken"]
    if verified:
        instance.require(
            *instance.admin(
                f"/v1/projects/{PROJECT}/accounts:update",
                {"localId": account["localId"], "emailVerified": True},
            )
        )
        signed = instance.require(
            *instance.public(
                "/v1/accounts:signInWithPassword",
                {
                    "email": email,
                    "password": "Shadow-Passw0rd!",
                    "returnSecureToken": True,
                },
            )
        )
        if (not isinstance(signed.get("idToken"), str) or not signed["idToken"]
                or ("localId" in signed and signed["localId"] != uid)):
            raise ValueError("verified sign-in did not return the owned account")
        account["idToken"] = signed["idToken"]
    return account


def enroll_totp(instance: Instance, account: dict) -> tuple[str, TotpParameters, str]:
    session = instance.require(
        *instance.public(
            "/v2/accounts/mfaEnrollment:start",
            {"idToken": account["idToken"], "totpEnrollmentInfo": {}},
        )
    )["totpSessionInfo"]
    parameters = TotpParameters(
        period_seconds=int(session.get("periodSec", 30)),
        digits=int(session.get("verificationCodeLength", 6)),
        algorithm=session.get("hashingAlgorithm", "HMAC_SHA1"),
    )
    return session["sharedSecretKey"], parameters, session["sessionInfo"]


def fresh_pending(instance: Instance, account: dict) -> dict:
    """Sign in again and return a newly issued pending credential for that account."""
    signed = instance.require(
        *instance.public(
            "/v1/accounts:signInWithPassword",
            {
                "email": account["email"],
                "password": "Shadow-Passw0rd!",
                "returnSecureToken": True,
            },
        )
    )
    return {
        "pending": signed["mfaPendingCredential"],
        "enrollmentId": signed["mfaInfo"][0]["mfaEnrollmentId"],
    }


def phone_pending(instance: Instance, account: dict) -> dict:
    """Enroll a phone factor once, then return a held pending credential."""
    if account.get("phoneEnrolled"):
        return fresh_pending(instance, account)
    started = instance.require(
        *instance.public(
            "/v2/accounts/mfaEnrollment:start",
            {
                "idToken": account["idToken"],
                "phoneEnrollmentInfo": {"phoneNumber": TEST_PHONE},
            },
        )
    )
    session = started["phoneSessionInfo"]["sessionInfo"]
    code = latest_code(instance)
    instance.require(
        *instance.public(
            "/v2/accounts/mfaEnrollment:finalize",
            {
                "idToken": account["idToken"],
                "phoneVerificationInfo": {"sessionInfo": session, "code": code},
                "displayName": "shadow phone",
            },
        )
    )
    account["phoneEnrolled"] = True
    return fresh_pending(instance, account)


def latest_code(instance: Instance) -> str:
    status, payload = instance.emulator("/verificationCodes")
    if status != 200 or not payload.get("verificationCodes"):
        raise RuntimeError("the owned instance returned no verification code")
    return payload["verificationCodes"][-1]["code"]


def _acquire_aged_resources(
    instance: Instance, account_for: Any
) -> tuple[dict[int, dict], dict[int, tuple[str, TotpParameters, str]]]:
    """Acquire every aged resource at one common origin.

    The manifest's aging schedule is `concurrent-acquisition`: all aged pending
    credentials and all aged enrollment sessions exist before any wait begins, so their
    ages elapse together and the run's critical path is the largest age rather than the
    sum. Acquiring each resource immediately before its own wait is the obvious reading
    and costs the serial total, which does not fit the wall budget.
    """
    pendings = {}
    sessions = {}
    acquired: dict[str, int] = {}
    for age in AGED_PENDING_SAMPLES:
        pendings[age] = phone_pending(instance, account_for(f"pending-age-{age}"))
        acquired[f"pending-{age}"] = instance.now()
    for age in SAMPLED_AGES_SECONDS:
        sessions[age] = enroll_totp(instance, account_for(f"enrollment-age-{age}"))
        acquired[f"session-{age}"] = instance.now()
    # Each resource remembers its own acquisition instant: the resources are
    # acquired one after another, so a row aged from a common origin would sample
    # every resource but the last one late by the acquisition tail.
    pendings["acquiredAt"] = acquired
    return pendings, sessions


def _complete_phone_mfa(
    instance: Instance, pending: dict
) -> tuple[int, dict, str | None]:
    """Offer a pending credential to start and, if accepted, finalize with a fresh code."""
    status, payload, code = _observe(
        instance,
        "/v2/accounts/mfaSignIn:start",
        {
            "mfaPendingCredential": pending["pending"],
            "mfaEnrollmentId": pending["enrollmentId"],
            "phoneSignInInfo": PHONE_SIGN_IN_INFO,
        },
    )
    if status != 200:
        return status, payload, code
    session = payload["phoneResponseInfo"]["sessionInfo"]
    return _observe(
        instance,
        "/v2/accounts/mfaSignIn:finalize",
        {
            "mfaPendingCredential": pending["pending"],
            "phoneVerificationInfo": {
                "sessionInfo": session,
                "code": latest_code(instance),
            },
        },
    )


def run_sequence(
    instance: Instance,
    output: Path,
    *,
    runtime_identity: dict[str, str] | None = None,
    run_id: str | None = None,
) -> dict[str, Any]:
    """Record creation intent before dispatch; retain uncertainty after failure."""
    plan = compile_campaign(uuid.uuid4().hex)
    state = initial_state(plan, time.time())
    checkpoint = output / "checkpoint.json"
    rows: dict[str, dict] = {}
    accounts: dict[str, dict] = {}
    # One fresh plan per instance; no old requests/counters can be rebound.
    instance.bind_plan(plan)
    # Exclusive persistence initialization happens before any service request.
    journal = RunPersistence(output, state, plan)
    primary: BaseException | None = None
    responsibility = None
    request_summary = None

    def failed(error: BaseException) -> None:
        nonlocal primary
        if primary is None:
            primary = error
        state["aborted"] = True
        state["abortReason"] = state["abortReason"] or "local-sequence-failed"

    try:
        _walk(instance, state, checkpoint, rows, accounts, journal=journal)
    except BaseException as error:
        failed(error)
    finally:
        try:
            # Only confirmed, in-process UIDs confer this existing authority.
            # A persisted intent with no ACK never creates deletion authority.
            instance.begin_recovery(tuple(item["id"] for item in state["ownedResources"]
                                          if item["kind"] == "account"))
            _delete_owned(instance, state, accounts)
        except BaseException as error:
            failed(error)
        # Transport is authoritative, not one notional charge per case.
        state["requests"] = instance.requests
        try:
            request_summary = instance.finish_requests()
            if not valid_request_summary(request_summary, plan, state["requests"]):
                state["aborted"] = True
                state["abortReason"] = state["abortReason"] or "local-request-budget-incomplete"
        except BaseException as error:
            failed(error)
        # A crash or journal failure during finalization must not leave a
        # checkpoint that independently reports DONE. Only the final outcome
        # publication below may remove this provisional abort.
        provisional = copy.deepcopy(state)
        if provisional["aborted"] is not True:
            provisional["aborted"] = True
            provisional["abortReason"] = "local-finalization-pending"
        try:
            journal.save_checkpoint(provisional)
        except BaseException as error:
            failed(error)
        try:
            responsibility = journal.finalize(state, request_budget=request_summary)
        except BaseException as error:
            failed(error)
        if responsibility is not None:
            if responsibility["resourceCleanupComplete"] is not True:
                state["aborted"] = True
                state["abortReason"] = state["abortReason"] or "local-responsibility-incomplete"
            try:
                journal.finish_checkpoint(state)
            except BaseException as error:
                failed(error)
        try:
            journal.close()
        except BaseException as error:
            failed(error)
    if primary is not None:
        raise primary
    report = build_report(rows, state, plan, runtime_identity, run_id)
    report["requestBudget"] = request_summary
    report["recovery"]["creationResponsibility"] = responsibility
    report["recovery"]["cleanupVerified"] = (
        report["recovery"]["cleanupVerified"] is True
        and responsibility["resourceCleanupComplete"] is True
    )
    report["recordingComplete"] = (
        report["recordingComplete"] is True
        and responsibility["journalComplete"] is True
        and responsibility["unresolvedCreations"] == 0
    )
    return report


def _create_owned_account(instance: Instance, state: dict,
                          accounts: dict, journal: RunPersistence, role: str,
                          verified: bool) -> dict:
    """The same path handles named and anonymous creation, including ACK loss."""
    journal.intent(role)

    def acknowledged(account: dict) -> None:
        if any(item.get("localId") == account["localId"] for item in accounts.values()):
            raise ValueError("signup UID was already owned by another role")
        register_owned(state, "account", account["localId"], time.time())
        # Keep in-process responsibility even if ACK publication or checkpoint fails.
        accounts[role] = account
        journal.acknowledge(role, account["localId"])
        journal.save_checkpoint(state)

    return create_account(instance, journal.email_for(role), verified,
                          on_created=acknowledged)


def _empty_account_reply(status: int, payload: Any, *, deletion: bool) -> bool:
    """Only the finite local success envelopes prove deletion or absence."""
    if type(status) is not int or status != 200 or not isinstance(payload, dict):
        return False
    kind = "identitytoolkit#DeleteAccountResponse" if deletion else "identitytoolkit#GetAccountInfoResponse"
    if deletion:
        return payload == {} or payload == {"kind": kind}
    if set(payload) - {"kind", "users"}:
        return False
    if "kind" in payload and payload["kind"] != kind:
        return False
    return ("users" in payload and type(payload["users"]) is list and not payload["users"]) or payload == {"kind": kind}


def _delete_owned(instance: Instance, state: dict[str, Any], accounts: dict) -> None:
    """Try each confirmed account once; one failed account must not skip the others.

    This consumes the existing per-instance request counter. It is not a restart
    authorization, a new transport budget, or proof about a timed-out create.
    """
    recorded = {
        item["id"] for item in state["ownedResources"]
        if item["kind"] == "account" and isinstance(item["id"], str) and item["id"]
    }
    seen = set()
    for record in accounts.values():
        uid = record.get("localId") if isinstance(record, dict) else None
        if not isinstance(uid, str) or uid not in recorded or uid in seen:
            continue
        seen.add(uid)
        # Invalidate an earlier in-memory readback before attempting a fresh one.
        mark_deleted(state, uid, absence_verified=False)
        resource = next(item for item in state["ownedResources"] if item["id"] == uid)
        resource["deleted"] = False
        try:
            delete_status, delete_body = instance.admin(
                f"/v1/projects/{PROJECT}/accounts:delete", {"localId": uid}
            )
            if not _empty_account_reply(delete_status, delete_body, deletion=True):
                continue
            resource["deleted"] = True
            status, payload = instance.admin(
                f"/v1/projects/{PROJECT}/accounts:lookup", {"localId": [uid]}
            )
            mark_deleted(state, uid, absence_verified=_empty_account_reply(status, payload, deletion=False))
        except Exception:  # noqa: BLE001 -- retain this account, attempt the remaining owned accounts
            # Do not serialize transport exceptions: they may contain credential bytes.
            # Unverified resource flags, rather than an error swallowed into success,
            # remain the durable reason this run cannot be complete.
            continue


def _walk(
    instance: Instance,
    state: dict[str, Any],
    checkpoint: Path,
    rows: dict[str, dict],
    accounts: dict[str, dict],
    *,
    journal: RunPersistence,
) -> None:
    charged = {"requests": instance.requests}

    def account_for(role: str, verified: bool = True) -> dict:
        if role not in accounts:
            _create_owned_account(instance, state, accounts, journal,
                                  role, verified)
        return accounts[role]

    def finish(case_id: str, status: int, code: str | None, **extra: Any) -> None:
        rows[case_id] = _row(case_id, status, code, **extra)
        spent = instance.requests - charged["requests"]
        charged["requests"] = instance.requests
        record_step(
            state,
            case_id,
            {"status": status, "errorCode": code},
            time.time(),
            requests=max(1, spent),
        )
        journal.save_checkpoint(state)

    control = account_for("pending-control")
    pendings, sessions = _acquire_aged_resources(instance, account_for)
    acquired = pendings.pop("acquiredAt")

    def sample(key: str, age: int) -> None:
        """Advance the owned clock to just past the resource's own target age."""
        target = acquired[key] + age + AGE_SAMPLE_MARGIN_SECONDS
        now = instance.now()
        if target > now:
            instance.advance(target - now)

    def observed(key: str) -> float:
        return float(instance.now() - acquired[key])

    status, _, code = _complete_phone_mfa(instance, phone_pending(instance, control))
    finish("baseline-fresh-finalize", status, code)

    for age in AGED_PENDING_SAMPLES:
        # A production run waits here; the owned local instance advances its own clock.
        # Either way the checkpoint written by the previous `finish` is what a resumed
        # process reloads, and every aged resource already exists.
        #
        # `now()` reads the instance clock truncated to whole seconds, so a resource's
        # recorded acquisition instant can sit up to a second before the instant it
        # was created; advancing by exactly the remaining age would then sample it
        # short of its target. One whole second of margin puts every sample just past
        # its target and still short of the next boundary, as the campaign document
        # says a sample is taken.
        sample(f"pending-{age}", age)
        aged = pendings[age]
        status, payload, code = _observe(
            instance,
            "/v2/accounts/mfaSignIn:start",
            {
                "mfaPendingCredential": aged["pending"],
                "mfaEnrollmentId": aged["enrollmentId"],
                "phoneSignInInfo": PHONE_SIGN_IN_INFO,
            },
        )
        finish(
            f"age-{age}s-start",
            status,
            code,
            pendingAgeSeconds=float(age),
            observedAgeSeconds=observed(f"pending-{age}"),
        )
        if status == 200:
            session = payload["phoneResponseInfo"]["sessionInfo"]
            final_status, _, final_code = _observe(
                instance,
                "/v2/accounts/mfaSignIn:finalize",
                {
                    "mfaPendingCredential": aged["pending"],
                    "phoneVerificationInfo": {
                        "sessionInfo": session,
                        "code": latest_code(instance),
                    },
                },
            )
            finish(
                f"age-{age}s-finalize",
                final_status,
                final_code,
                pendingAgeSeconds=float(age),
                observedAgeSeconds=observed(f"pending-{age}"),
            )
        else:
            skip_step(
                state, f"age-{age}s-finalize", "its start was refused", time.time()
            )
            rows[f"age-{age}s-finalize"] = {
                "id": f"age-{age}s-finalize",
                "status": status,
                "errorCode": code,
                "outcome": "skipped",
            }
        aged_account = accounts[f"pending-age-{age}"]
        fresh = fresh_pending(instance, aged_account)
        fresh_at = instance.now()
        status, _, code = _complete_phone_mfa(instance, fresh)
        finish(
            f"age-{age}s-same-account-fresh-control",
            status,
            code,
            pendingAgeSeconds=0.0,
            observedAgeSeconds=float(instance.now() - fresh_at),
        )
        if age in SAMPLED_AGES_SECONDS:
            sample(f"session-{age}", age)
            secret, parameters, session_info = sessions[age]
            aged_subject = accounts[f"enrollment-age-{age}"]
            status, _, code = _observe(
                instance,
                "/v2/accounts/mfaEnrollment:finalize",
                {
                    "idToken": aged_subject["idToken"],
                    "totpVerificationInfo": {
                        "sessionInfo": session_info,
                        "verificationCode": totp_code(
                            secret, instance.now(), parameters
                        ),
                    },
                    "displayName": "aged totp",
                },
            )
            finish(
                f"totp-enroll-session-age-{age}s",
                status,
                code,
                sessionAgeSeconds=float(age),
                observedAgeSeconds=observed(f"session-{age}"),
            )

    status, _, code = _complete_phone_mfa(instance, phone_pending(instance, control))
    finish("final-fresh-finalize", status, code)

    # --- TOTP lifecycle ---------------------------------------------------------------
    subject = account_for("totp-lifecycle")
    secret, parameters, session_info = enroll_totp(instance, subject)
    finish("totp-enroll-start", 200, None)
    status, payload, code = _observe(
        instance,
        "/v2/accounts/mfaEnrollment:finalize",
        {
            "idToken": subject["idToken"],
            "totpVerificationInfo": {
                "sessionInfo": session_info,
                "verificationCode": wrong_code(
                    secret, instance.now(), parameters, window_steps=1
                ),
            },
            "displayName": "shadow totp",
        },
    )
    finish("totp-enroll-wrong-code", status, code)
    status, payload, code = _observe(
        instance,
        "/v2/accounts/mfaEnrollment:finalize",
        {
            "idToken": subject["idToken"],
            "totpVerificationInfo": {
                "sessionInfo": session_info,
                "verificationCode": totp_code(secret, instance.now(), parameters),
            },
            "displayName": "shadow totp",
        },
    )
    finish("totp-enroll-retry-same-session", status, code)
    if status == 200:
        subject["idToken"] = payload.get("idToken", subject["idToken"])
        enrollment_id = payload.get("mfaEnrollmentId")
    else:
        enrollment_id = None
    status, payload, code = _observe(
        instance,
        "/v2/accounts/mfaEnrollment:finalize",
        {
            "idToken": subject["idToken"],
            "totpVerificationInfo": {
                "sessionInfo": session_info,
                "verificationCode": totp_code(secret, instance.now(), parameters),
            },
            "displayName": "shadow totp",
        },
    )
    finish("totp-enroll-replay-finalized-session", status, code)
    status, payload, code = _observe(
        instance, "/v1/accounts:lookup", {"idToken": subject["idToken"]}
    )
    factors = payload.get("users", [{}])[0].get("mfaInfo", []) if status == 200 else []
    if enrollment_id is None and factors:
        enrollment_id = factors[0].get("mfaEnrollmentId")
    finish("totp-enroll-factor-readback", status, code, factorCount=len(factors))
    status, payload, code = _observe(
        instance,
        "/v2/accounts/mfaEnrollment:start",
        {"idToken": subject["idToken"], "totpEnrollmentInfo": {}},
    )
    finish("second-factor-limit", status, code)
    signed = instance.require(
        *instance.public(
            "/v1/accounts:signInWithPassword",
            {
                "email": subject["email"],
                "password": "Shadow-Passw0rd!",
                "returnSecureToken": True,
            },
        )
    )
    status, payload, code = _observe(
        instance,
        "/v2/accounts/mfaSignIn:start",
        {
            "mfaPendingCredential": signed["mfaPendingCredential"],
            "mfaEnrollmentId": enrollment_id,
        },
    )
    finish("totp-signin-start", status, code)
    instance.advance(parameters.period_seconds)
    used = totp_code(secret, instance.now(), parameters)
    status, payload, code = _observe(
        instance,
        "/v2/accounts/mfaSignIn:finalize",
        {
            "mfaPendingCredential": signed["mfaPendingCredential"],
            "mfaEnrollmentId": enrollment_id,
            "totpVerificationInfo": {"verificationCode": used},
        },
    )
    if status == 200:
        subject["idToken"] = payload.get("idToken", subject["idToken"])
    finish("totp-signin-finalize", status, code)
    signed = instance.require(
        *instance.public(
            "/v1/accounts:signInWithPassword",
            {
                "email": subject["email"],
                "password": "Shadow-Passw0rd!",
                "returnSecureToken": True,
            },
        )
    )
    status, payload, code = _observe(
        instance,
        "/v2/accounts/mfaSignIn:finalize",
        {
            "mfaPendingCredential": signed["mfaPendingCredential"],
            "mfaEnrollmentId": enrollment_id,
            "totpVerificationInfo": {"verificationCode": used},
        },
    )
    finish("totp-signin-replay-same-code", status, code)
    status, payload, code = _observe(
        instance,
        "/v2/accounts/mfaEnrollment:withdraw",
        {"idToken": subject["idToken"], "mfaEnrollmentId": enrollment_id},
    )
    if status == 200:
        subject["idToken"] = payload.get("idToken", subject["idToken"])
    finish("totp-withdraw", status, code)
    status, payload, code = _observe(
        instance, "/v1/accounts:lookup", {"idToken": subject["idToken"]}
    )
    remaining = (
        payload.get("users", [{}])[0].get("mfaInfo", []) if status == 200 else []
    )
    finish("totp-withdraw-readback", status, code, factorCount=len(remaining))
    status, payload, code = _observe(
        instance,
        "/v2/accounts/mfaEnrollment:withdraw",
        {"idToken": subject["idToken"], "mfaEnrollmentId": enrollment_id},
    )
    finish("totp-withdraw-unknown", status, code)

    # --- interaction ------------------------------------------------------------------
    unverified = account_for("interaction-unverified", verified=False)
    status, payload, code = _observe(
        instance,
        "/v2/accounts/mfaEnrollment:start",
        {"idToken": unverified["idToken"], "totpEnrollmentInfo": {}},
    )
    finish("unverified-email-enroll-refusal", status, code)
    anonymous = account_for("interaction-anonymous", verified=False)
    status, payload, code = _observe(
        instance,
        "/v2/accounts/mfaEnrollment:start",
        {"idToken": anonymous["idToken"], "totpEnrollmentInfo": {}},
    )
    finish("ineligible-first-factor-refusal", status, code)
    status, payload, code = _observe(
        instance, "/v2/accounts/mfaEnrollment:start", {"totpEnrollmentInfo": {}}
    )
    finish("missing-id-token-refusal", status, code)
    status, payload = instance.admin(f"/admin/v2/projects/{PROJECT}/config", None)
    finish(
        "project-mfa-config-readback",
        status,
        _code_of(payload),
        mfaConfigPresent="mfaConfig" in payload,
    )


def build_runtime_identity(
    binary: Path, config: Path, execution_commit: str, run_id: str
) -> dict[str, str]:
    """Bind the local observation to the exact executable and launch configuration."""
    return {
        "artifactSha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        "executionCommit": execution_commit,
        "configurationDigest": hashlib.sha256(config.read_bytes()).hexdigest(),
        "runId": run_id,
    }


def build_report(
    rows: dict[str, dict],
    state: dict[str, Any],
    plan: dict[str, Any] | None = None,
    runtime_identity: dict[str, str] | None = None,
    run_id: str | None = None,
) -> dict[str, Any]:
    """Assemble the shadow ledger, refusing to publish a run with an unrecorded case."""
    missing = [case["id"] for case in observation_cases() if case["id"] not in rows]
    if missing:
        raise RuntimeError(f"the shadow recorded no row for: {', '.join(missing)}")
    ordered = [rows[case["id"]] for case in observation_cases()]
    expectations = [
        {
            "id": case["id"],
            "expected": case["expectedLocal"],
            "observed": {
                "status": rows[case["id"]]["status"],
                "errorCode": rows[case["id"]]["errorCode"],
            },
            "agrees": rows[case["id"]]["status"] == case["expectedLocal"]["status"]
            and (
                case["expectedLocal"]["errorCode"] is None
                or rows[case["id"]]["errorCode"] == case["expectedLocal"]["errorCode"]
            ),
        }
        for case in observation_cases()
    ]
    report = {
        "schema": SCHEMA,
        "campaignId": CAMPAIGN_ID,
        # The comparator recompiles this manifest and refuses a receipt that carries none,
        # so a row list cannot be judged against a plan nobody can reproduce.
        "campaign": plan if plan is not None else compile_campaign(uuid.uuid4().hex),
        "side": "local",
        "productionExecuted": False,
        "recordingComplete": run_complete(state),
        # The real number of calls the transport made, not one per case.
        "requestsCharged": state["requests"],
        "maxRequests": state["maxRequests"],
        "provenance": compute_provenance(repository_root()),
        "worktree": describe_worktree(repository_root()),
        "rows": ordered,
        "expectations": expectations,
        "disagreements": [item["id"] for item in expectations if not item["agrees"]],
        "recovery": {
            "cleanupVerified": cleanup_complete(state),
            "remainingOwnedResources": len(outstanding_cleanup(state)),
            # The owned instance is created for this run and discarded with it, so no
            # project configuration is mutated and nothing has to be restored. The
            # production side of this campaign does mutate configuration and must prove
            # the readback and digest equality the manifest requires.
            "configurationMutated": False,
            "configurationRestored": True,
            "ownedAccounts": len(state["ownedResources"]),
        },
    }
    if runtime_identity is not None:
        report["runtimeIdentity"] = copy.deepcopy(runtime_identity)
        report["recovery"]["runId"] = run_id
    return report


def child(output: Path) -> int:
    origin = "http://" + os.environ["FIREBASE_AUTH_EMULATOR_HOST"]
    instance = Instance(
        origin, os.environ["FIREEMU_CONTROL_URL"], os.environ["FIREEMU_CONTROL_TOKEN"]
    )
    (output / "instance.json").write_text(
        json.dumps({"childPid": os.getpid(), "parentPid": os.getppid()}),
        encoding="utf-8",
    )
    runtime = json.loads((output / RUNTIME_IDENTITY_FILE).read_text(encoding="utf-8"))
    report = run_sequence(
        instance,
        output,
        runtime_identity=runtime["runtimeIdentity"],
        run_id=runtime["runId"],
    )
    (output / "shadow.json").write_text(
        json.dumps(report, indent=2, sort_keys=True), "utf-8"
    )
    return 0


def _ps_field(pid: int, field: str) -> str | None:
    state = subprocess.run(
        ["ps", "-p", str(pid), "-o", f"{field}="],
        text=True,
        stdout=subprocess.PIPE,
        check=False,
    )
    if state.returncode != 0 or not state.stdout.strip():
        return None
    return state.stdout.strip()


def _proc_identity(pid: int) -> tuple[str, str] | None:
    """Read one process's identity from `/proc`, which is exact on Linux.

    `/proc/<pid>/cmdline` holds the argument vector the kernel recorded at `exec`,
    NUL-separated and never shortened to a terminal width, so it is preferred over `ps`
    where it exists. An empty read means the process has no argument vector any more,
    which is what a zombie looks like, and is reported as gone.
    """
    entry = Path("/proc") / str(pid)
    try:
        command = (entry / "comm").read_text(encoding="utf-8", errors="replace")
        raw = (entry / "cmdline").read_bytes()
    except OSError:
        return None
    if not raw.strip(b"\x00"):
        return None
    arguments = " ".join(
        part.decode("utf-8", errors="replace")
        for part in raw.rstrip(b"\x00").split(b"\x00")
    )
    return (command.strip(), arguments)


def process_identity(pid: int) -> tuple[str, str] | None:
    """Return one live process's command name and arguments, or None if it is gone.

    The value is whatever this operating system reports, not a rendering of an argument
    vector: Linux shortens `comm` to 15 characters and reports only the executable's base
    name, while macOS reports its whole path. Nothing here reconciles those two, because
    an identity is only ever compared with another identity read the same way.
    """
    if Path("/proc/self/cmdline").exists():
        return _proc_identity(pid)
    command = _ps_field(pid, "comm")
    arguments = _ps_field(pid, "args")
    if command is None or arguments is None:
        return None
    return (command, arguments)


def capture_child_identity(
    process: subprocess.Popen, settle_seconds: float = 2.0
) -> tuple[str, str] | None:
    """Read back what this operating system reports for a child that was just started.

    This is the identity the reaper will later require, so it must be taken from the OS
    rather than from the argument vector that was requested. `Popen` returns as soon as
    the child exists, which can be before its `exec` has replaced the image, and in that
    window the child still carries this process's own argument vector; the capture
    therefore waits for an identity that differs from this process's own. A missing
    identity can also be a transient procfs read failure; only waiting for the child
    proves that it exited. None means exited or unconfirmed, never signal authority.
    """
    own = process_identity(os.getpid())
    deadline = time.monotonic() + settle_seconds
    while True:
        if _has_exited(process):
            return None
        identity = process_identity(process.pid)
        if identity is not None and identity != own:
            return identity
        if time.monotonic() >= deadline:
            return None
        time.sleep(0.01)


def _has_exited(process: subprocess.Popen) -> bool:
    """Report whether the child has terminated, reaping it when it has.

    Reaping matters before any identity is read: an exited child that nothing has waited
    for is a zombie, and a zombie holds its PID while reporting no argument vector.
    """
    try:
        process.wait(timeout=0)
    except subprocess.TimeoutExpired:
        return False
    return True


def reap_owned_child(
    process: subprocess.Popen, spawn_identity: tuple[str, str] | None
) -> str:
    """Stop the owned instance, verifying identity before each signal and after the last.

    A PID can be reused between the check and the signal, so the identity the OS reports
    now is compared with `spawn_identity`, the identity the same OS reported for this
    child when it was started. Only that comparison is meaningful: comparing against the
    requested argument vector made the check platform-dependent and it refused to signal
    its own child on Linux. The process is confirmed gone afterwards rather than assumed.
    """
    for signal_number in (signal.SIGTERM, signal.SIGKILL):
        if _has_exited(process):
            break
        identity = process_identity(process.pid)
        if identity is None or spawn_identity is None or identity != spawn_identity:
            # A failed/empty OS identity read is not proof that this child exited.
            # Re-check waitpid to recognize an exit racing with the identity read;
            # otherwise retain the cleanup obligation without signalling the PID.
            if _has_exited(process):
                return "stopped"
            return "pid-reused-refusing-to-signal"
        try:
            os.kill(process.pid, signal_number)
        except ProcessLookupError:
            break
        try:
            process.wait(timeout=10)
            break
        except subprocess.TimeoutExpired:
            continue
    return "stopped" if _has_exited(process) else "survived"


def parent(output: Path) -> int:
    # Never let a failed new child inherit an old shadow ledger from this path.
    # Reserve the output before building or starting anything; failure stays an
    # incomplete generation and a retry must choose a fresh output directory.
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    root = repository_root()
    binary = root / "target" / "debug" / "fireemu"
    if not binary.is_file():
        subprocess.run(
            ["cargo", "build", "--locked", "-p", "fireemu"], cwd=root, check=True
        )
    config = output / "fireemu.json"
    config.write_text(json.dumps(CONFIG), encoding="utf-8")
    worktree = describe_worktree(root)
    if worktree.get("resolved") is not True or not isinstance(worktree.get("commit"), str):
        print("local runtime source commit could not be resolved", file=sys.stderr)
        return 1
    run_id = uuid.uuid4().hex
    (output / RUNTIME_IDENTITY_FILE).write_text(
        json.dumps(
            {
                "runtimeIdentity": build_runtime_identity(
                    binary, config, worktree["commit"], run_id
                ),
                "runId": run_id,
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(("GOOGLE_", "FIREBASE_", "GCLOUD_", "CLOUDSDK_"))
    }
    environment["GOOGLE_CLOUD_PROJECT"] = PROJECT
    argv = [
        str(binary),
        "exec",
        "--config",
        str(config),
        "--project",
        PROJECT,
        "--only",
        "auth",
        "--http-port",
        "0",
        "--log-verbosity",
        "quiet",
        "--",
        sys.executable,
        str(Path(__file__).resolve()),
        "--child",
        str(output),
    ]
    process = subprocess.Popen(argv, cwd=root, env=environment)
    # Taken now, while the PID is certainly this child's, so a later reap compares two
    # readings of the same kind instead of guessing how this OS renders an argv.
    identity = capture_child_identity(process)
    cleanup = "stopped"
    try:
        returncode = process.wait(timeout=CHILD_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        # The campaign's own aging can outlast this deadline, so a timeout is a reachable
        # path and must not leave an owned instance running.
        returncode = None
        cleanup = reap_owned_child(process, identity)
    finally:
        if process.poll() is None:
            cleanup = reap_owned_child(process, identity)
    if cleanup != "stopped":
        print(f"owned instance cleanup: {cleanup}", file=sys.stderr)
        return 1
    if returncode != 0:
        print(f"owned instance did not complete successfully (exit {returncode})", file=sys.stderr)
        return 1
    if not (output / "shadow.json").is_file():
        print(f"no shadow ledger was written (exit {returncode})", file=sys.stderr)
        return 1
    report = json.loads((output / "shadow.json").read_text(encoding="utf-8"))
    print(
        json.dumps(
            {
                key: report[key]
                for key in ("recordingComplete", "disagreements", "requestsCharged")
            },
            indent=2,
        )
    )
    recovery = report.get("recovery")
    return 0 if (
        report.get("recordingComplete") is True
        and report.get("disagreements") == []
        and isinstance(recovery, dict)
        and valid_request_summary(
            report.get("requestBudget"), report.get("campaign"), report.get("requestsCharged"))
        and ("creationResponsibility" not in recovery or complete_summary(
            recovery["creationResponsibility"], recovery.get("ownedAccounts")))
        and recovery.get("cleanupVerified") is True
        and type(recovery.get("remainingOwnedResources")) is int
        and recovery["remainingOwnedResources"] == 0
        and recovery.get("configurationRestored") is True
    ) else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--child", type=Path)
    parser.add_argument("--output", type=Path)
    arguments = parser.parse_args()
    if arguments.child:
        raise SystemExit(child(arguments.child))
    if not arguments.output or not arguments.output.is_absolute():
        parser.error("--output must be an absolute path")
    raise SystemExit(parent(arguments.output))
