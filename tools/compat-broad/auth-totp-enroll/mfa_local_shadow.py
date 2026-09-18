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
import json
import os
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from mfa_cases import CAMPAIGN_ID, SAMPLED_AGES_SECONDS, observation_cases
from mfa_collector import (
    checkpoint_bytes,
    initial_state,
    load_checkpoint,
    mark_deleted,
    record_step,
    register_owned,
    run_complete,
    skip_step,
)
from mfa_manifest import compile_campaign
from mfa_provenance import compute_provenance, describe_worktree, repository_root
from mfa_totp import TotpParameters, totp_code, wrong_code

PROJECT = "fireemu-35fe6"
API_KEY = "fireemu-local-shadow-key"
TEST_PHONE = "+15555550100"
# The local instance sends no SMS; the token is a placeholder the request shape requires.
PHONE_SIGN_IN_INFO = {"recaptchaToken": "fireemu-local-shadow"}
CONFIG = {"schemaVersion": 1, "profile": "strict", "auth": {"totp": {}}}
SCHEMA = "o2-mfa-local-shadow-v1"


class Refused(RuntimeError):
    """A local request answered with an error status."""

    def __init__(self, status: int, code: str | None) -> None:
        super().__init__(f"{status} {code}")
        self.status = status
        self.code = code


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_: Any) -> None:
        return None


def _call(url: str, body: Any = None, token: str | None = None) -> tuple[int, dict]:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "::1", "localhost"}:
        raise ValueError("the local shadow only talks to loopback")
    headers = {}
    payload = None
    if token:
        headers["Authorization"] = "Bearer " + token
    if body is not None:
        headers["Content-Type"] = "application/json"
        payload = json.dumps(body).encode()
    request = urllib.request.Request(url, data=payload, headers=headers)
    opener = urllib.request.build_opener(NoRedirect(), urllib.request.ProxyHandler({}))
    try:
        with opener.open(request, timeout=20) as response:
            return response.status, json.loads(response.read() or b"{}")
    except urllib.error.HTTPError as error:
        raw = error.read()
        try:
            return error.code, json.loads(raw or b"{}")
        except ValueError:
            return error.code, {"raw": raw[:200].decode("utf-8", "replace")}


def _code_of(payload: dict) -> str | None:
    message = payload.get("error", {}).get("message")
    return message.split(":", 1)[0].strip() if isinstance(message, str) else None


class Instance:
    """One owned local Auth instance addressed by its loopback origins."""

    def __init__(self, origin: str, control: str, token: str) -> None:
        self.origin = origin
        self.identity = origin + "/identitytoolkit.googleapis.com"
        # The control URL is handed over with its version prefix already attached.
        base = control.rstrip("/")
        self.control = base.removesuffix("/v1")
        self.token = token

    def public(self, path: str, body: Any) -> tuple[int, dict]:
        return _call(f"{self.identity}{path}?key={API_KEY}", body)

    def admin(self, path: str, body: Any) -> tuple[int, dict]:
        return _call(f"{self.identity}{path}", body, token="owner")

    def emulator(self, path: str) -> tuple[int, dict]:
        # The inspection routes are served at the instance root, not under the API host prefix.
        return _call(f"{self.origin}/emulator/v1/projects/{PROJECT}{path}", token=self.token)

    def advance(self, seconds: float) -> None:
        status, _ = _call(
            f"{self.control}/v1/sessions/default/clock:advance",
            {"millis": max(1, int(seconds * 1000) + 1)},
            token=self.token,
        )
        if status != 200:
            raise RuntimeError(f"clock advance refused with {status}")

    def now(self) -> int:
        """Return the owned instance's logical time, which the codes must be computed at."""
        status, payload = _call(f"{self.control}/v1/sessions/default", token=self.token)
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
        if status != 200:
            raise Refused(status, _code_of(payload))
        return payload


def _row(case_id: str, status: int, code: str | None, **extra: Any) -> dict[str, Any]:
    return {"id": case_id, "status": status, "errorCode": code, "outcome": "observed", **extra}


def _observe(instance: Instance, path: str, body: Any) -> tuple[int, dict, str | None]:
    status, payload = instance.public(path, body)
    return status, payload, _code_of(payload)


def create_account(instance: Instance, email: str, verified: bool = True) -> dict:
    payload = instance.require(
        *instance.public(
            "/v1/accounts:signUp",
            {"email": email, "password": "Shadow-Passw0rd!", "returnSecureToken": True},
        )
    )
    account = {"localId": payload["localId"], "idToken": payload["idToken"], "email": email}
    if verified:
        instance.require(
            *instance.admin(
                f"/v1/projects/{PROJECT}/accounts:update",
                {"localId": account["localId"], "emailVerified": True},
            )
        )
        account["idToken"] = instance.require(
            *instance.public(
                "/v1/accounts:signInWithPassword",
                {"email": email, "password": "Shadow-Passw0rd!", "returnSecureToken": True},
            )
        )["idToken"]
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
            {"idToken": account["idToken"], "phoneEnrollmentInfo": {"phoneNumber": TEST_PHONE}},
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


def run_sequence(instance: Instance, output: Path) -> dict[str, Any]:
    """Walk the ordered cases, checkpointing before each aged wait."""
    plan = compile_campaign(uuid.uuid4().hex)
    state = initial_state(plan, time.time())
    checkpoint = output / "checkpoint.json"
    rows: dict[str, dict] = {}
    accounts: dict[str, dict] = {}
    suffix = uuid.uuid4().hex[:12]

    def account_for(role: str, verified: bool = True) -> dict:
        if role not in accounts:
            created = create_account(instance, f"o2-{role}-{suffix}@example.com", verified)
            accounts[role] = created
            register_owned(state, "account", created["localId"], time.time())
        return accounts[role]

    def finish(case_id: str, status: int, code: str | None, **extra: Any) -> None:
        rows[case_id] = _row(case_id, status, code, **extra)
        record_step(state, case_id, {"status": status, "errorCode": code}, time.time())
        checkpoint.write_bytes(checkpoint_bytes(state))

    # --- pending-age causality, using a test phone number so no SMS is ever sent -------
    control = account_for("pending-control")
    held = phone_pending(instance, control)
    status, payload, code = _observe(
        instance,
        "/v2/accounts/mfaSignIn:start",
        {
            "mfaPendingCredential": held["pending"],
            "mfaEnrollmentId": held["enrollmentId"],
            "phoneSignInInfo": PHONE_SIGN_IN_INFO,
        },
    )
    if status == 200:
        session = payload["phoneResponseInfo"]["sessionInfo"]
        status, payload, code = _observe(
            instance,
            "/v2/accounts/mfaSignIn:finalize",
            {
                "mfaPendingCredential": held["pending"],
                "phoneVerificationInfo": {"sessionInfo": session, "code": latest_code(instance)},
            },
        )
    finish("baseline-fresh-finalize", status, code)

    for age in SAMPLED_AGES_SECONDS:
        role = f"pending-age-{age}"
        aged_account = account_for(role)
        aged = phone_pending(instance, aged_account)
        # A real production run waits here; the owned local instance ages by its own clock,
        # and the checkpoint written above is what a resumed production run would reload.
        instance.advance(age + 1)
        status, payload, code = _observe(
            instance,
            "/v2/accounts/mfaSignIn:start",
            {
                "mfaPendingCredential": aged["pending"],
                "mfaEnrollmentId": aged["enrollmentId"],
                "phoneSignInInfo": PHONE_SIGN_IN_INFO,
            },
        )
        finish(f"age-{age}s-start", status, code, pendingAgeSeconds=float(age))
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
            finish(f"age-{age}s-finalize", final_status, final_code, pendingAgeSeconds=float(age))
        else:
            skip_step(state, f"age-{age}s-finalize", "its start was refused", time.time())
            rows[f"age-{age}s-finalize"] = {
                "id": f"age-{age}s-finalize",
                "status": status,
                "errorCode": code,
                "outcome": "skipped",
            }
        fresh = phone_pending(instance, aged_account)
        status, payload, code = _observe(
            instance,
            "/v2/accounts/mfaSignIn:start",
            {
                "mfaPendingCredential": fresh["pending"],
                "mfaEnrollmentId": fresh["enrollmentId"],
                "phoneSignInInfo": PHONE_SIGN_IN_INFO,
            },
        )
        if status == 200:
            session = payload["phoneResponseInfo"]["sessionInfo"]
            status, payload, code = _observe(
                instance,
                "/v2/accounts/mfaSignIn:finalize",
                {
                    "mfaPendingCredential": fresh["pending"],
                    "phoneVerificationInfo": {
                        "sessionInfo": session,
                        "code": latest_code(instance),
                    },
                },
            )
        finish(f"age-{age}s-same-account-fresh-control", status, code, pendingAgeSeconds=0.0)

    held = phone_pending(instance, control)
    status, payload, code = _observe(
        instance,
        "/v2/accounts/mfaSignIn:start",
        {
            "mfaPendingCredential": held["pending"],
            "mfaEnrollmentId": held["enrollmentId"],
            "phoneSignInInfo": PHONE_SIGN_IN_INFO,
        },
    )
    if status == 200:
        session = payload["phoneResponseInfo"]["sessionInfo"]
        status, payload, code = _observe(
            instance,
            "/v2/accounts/mfaSignIn:finalize",
            {
                "mfaPendingCredential": held["pending"],
                "phoneVerificationInfo": {"sessionInfo": session, "code": latest_code(instance)},
            },
        )
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
    remaining = payload.get("users", [{}])[0].get("mfaInfo", []) if status == 200 else []
    finish("totp-withdraw-readback", status, code, factorCount=len(remaining))
    status, payload, code = _observe(
        instance,
        "/v2/accounts/mfaEnrollment:withdraw",
        {"idToken": subject["idToken"], "mfaEnrollmentId": enrollment_id},
    )
    finish("totp-withdraw-unknown", status, code)

    # --- enrollment session age -------------------------------------------------------
    for age in SAMPLED_AGES_SECONDS:
        aged = account_for(f"enrollment-age-{age}")
        secret, parameters, session_info = enroll_totp(instance, aged)
        instance.advance(age)
        status, payload, code = _observe(
            instance,
            "/v2/accounts/mfaEnrollment:finalize",
            {
                "idToken": aged["idToken"],
                "totpVerificationInfo": {
                    "sessionInfo": session_info,
                    "verificationCode": totp_code(secret, instance.now(), parameters),
                },
                "displayName": "aged totp",
            },
        )
        finish(f"totp-enroll-session-age-{age}s", status, code, sessionAgeSeconds=float(age))

    # --- interaction ------------------------------------------------------------------
    unverified = account_for("interaction-unverified", verified=False)
    status, payload, code = _observe(
        instance,
        "/v2/accounts/mfaEnrollment:start",
        {"idToken": unverified["idToken"], "totpEnrollmentInfo": {}},
    )
    finish("unverified-email-enroll-refusal", status, code)
    anonymous = instance.require(
        *instance.public("/v1/accounts:signUp", {"returnSecureToken": True})
    )
    register_owned(state, "account", anonymous["localId"], time.time())
    accounts["interaction-anonymous"] = {
        "localId": anonymous["localId"],
        "idToken": anonymous["idToken"],
        "email": None,
    }
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

    # --- cleanup ----------------------------------------------------------------------
    for record in accounts.values():
        instance.admin(
            f"/v1/projects/{PROJECT}/accounts:delete", {"localId": record["localId"]}
        )
        status, payload = instance.admin(
            f"/v1/projects/{PROJECT}/accounts:lookup", {"localId": [record["localId"]]}
        )
        absent = status == 200 and not payload.get("users")
        mark_deleted(state, record["localId"], absence_verified=absent)
    checkpoint.write_bytes(checkpoint_bytes(state))
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
    return {
        "schema": SCHEMA,
        "campaignId": CAMPAIGN_ID,
        "side": "local",
        "productionExecuted": False,
        "recordingComplete": run_complete(load_checkpoint(checkpoint.read_bytes())),
        "provenance": compute_provenance(repository_root()),
        "worktree": describe_worktree(repository_root()),
        "rows": ordered,
        "expectations": expectations,
        "disagreements": [item["id"] for item in expectations if not item["agrees"]],
        "recovery": {
            "cleanupVerified": all(
                resource["deleted"] and resource["absenceVerified"]
                for resource in state["ownedResources"]
            ),
            "remainingOwnedResources": sum(
                0 if resource["deleted"] and resource["absenceVerified"] else 1
                for resource in state["ownedResources"]
            ),
            "configurationRestored": True,
            "ownedAccounts": len(state["ownedResources"]),
        },
    }


def child(output: Path) -> int:
    origin = "http://" + os.environ["FIREBASE_AUTH_EMULATOR_HOST"]
    instance = Instance(
        origin, os.environ["FIREEMU_CONTROL_URL"], os.environ["FIREEMU_CONTROL_TOKEN"]
    )
    (output / "instance.json").write_text(
        json.dumps({"childPid": os.getpid(), "parentPid": os.getppid()}), encoding="utf-8"
    )
    report = run_sequence(instance, output)
    (output / "shadow.json").write_text(json.dumps(report, indent=2, sort_keys=True), "utf-8")
    return 0


def parent(output: Path) -> int:
    root = repository_root()
    binary = root / "target" / "debug" / "fireemu"
    if not binary.is_file():
        subprocess.run(
            ["cargo", "build", "--locked", "-p", "fireemu"], cwd=root, check=True
        )
    output.mkdir(parents=True, exist_ok=True)
    config = output / "fireemu.json"
    config.write_text(json.dumps(CONFIG), encoding="utf-8")
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(("GOOGLE_", "FIREBASE_", "GCLOUD_", "CLOUDSDK_"))
    }
    environment["GOOGLE_CLOUD_PROJECT"] = PROJECT
    completed = subprocess.run(
        [
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
        ],
        cwd=root,
        env=environment,
        check=False,
        timeout=600,
    )
    remaining = subprocess.run(
        ["pgrep", "-f", f"fireemu exec --config {config}"],
        text=True,
        stdout=subprocess.PIPE,
        check=False,
    )
    for pid in [line for line in remaining.stdout.split() if line.isdigit()]:
        os.kill(int(pid), signal.SIGTERM)
    if not (output / "shadow.json").is_file():
        print(f"no shadow ledger was written (exit {completed.returncode})", file=sys.stderr)
        return 1
    report = json.loads((output / "shadow.json").read_text(encoding="utf-8"))
    print(json.dumps({key: report[key] for key in ("recordingComplete", "disagreements")}, indent=2))
    return 0


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
