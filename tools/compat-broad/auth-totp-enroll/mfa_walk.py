"""The thirty-three cases as a resumable walk over an abstract Auth session.

This is the production-shaped counterpart of the walk in `mfa_local_shadow.py`. The
shadow ages an owned instance by advancing its virtual clock and reads one-time codes
from that instance's inspection route; this walk takes its time from a sleeper and its
codes from the session, so the same case order runs against production with real
wall-clock waits, against an injected transport with a virtual clock in a rehearsal,
and can be stopped and resumed between the two.

Resuming needs the material a case depends on: the pending credentials acquired at the
origin, the enrollment sessions, the shared secrets and the ID tokens. They are kept in
a private, mode-0600 file in the run directory and nowhere else. The collector
checkpoint, which is what the receipt is built from, refuses them by construction.
"""

from __future__ import annotations

import copy
import json
import os
import secrets
from collections.abc import Callable
from pathlib import Path
from typing import Any, Protocol

from mfa_cases import (
    AGED_PENDING_SAMPLES,
    SAMPLED_AGES_SECONDS,
    TOTP_STEP_ROLLOVER_SECONDS,
    observation_cases,
)
from mfa_collector import (
    BudgetError,
    assert_no_sensitive_material,
    checkpoint_bytes,
    initial_state,
    load_checkpoint,
    mark_deleted,
    next_action,
    record_step,
    register_owned,
    run_complete,
    skip_step,
    selected_case_ids,
)
from mfa_config_lock import CONFIG_PATH, TEST_PHONE
from mfa_timing import timing_mode
from mfa_totp import TotpParameters, totp_code, wrong_code

PROJECT = "fireemu-35fe6"
MATERIAL_FILE = "material.json"
CHECKPOINT_FILE = "checkpoint.json"
INTENT_FILE = "create-intents.jsonl"
# The service accepts a test phone number without a real reCAPTCHA assessment; the
# token is a placeholder the request shape requires, as the earlier production
# recorder for the same test number found.
RECAPTCHA_PLACEHOLDER = "fireemu-test-phone-number"
# Each aged sample is taken just past its target age, as the campaign document says
# and as the local shadow does by advancing one millisecond beyond it; a refusal is
# then attributed to the interval's upper endpoint rather than to the target itself.
AGE_SAMPLE_MARGIN_SECONDS = 1.0
#: The roles in the order the walk creates them, which is the order it cleans them.
CLEANUP_ORDER = (
    "pending-control",
    *[f"pending-age-{age}" for age in AGED_PENDING_SAMPLES],
    *[f"enrollment-age-{age}" for age in SAMPLED_AGES_SECONDS],
    "totp-lifecycle",
    "interaction-unverified",
    "interaction-anonymous",
)
ACCOUNT_ROLES_ANONYMOUS = ("interaction-anonymous",)
ACCOUNT_ROLES_UNVERIFIED = ("interaction-unverified", "interaction-anonymous")


class Refused(RuntimeError):
    """A request the walk needed to succeed answered with an error status."""

    def __init__(self, status: int, code: str | None) -> None:
        super().__init__(f"{status} {code}")
        self.status = status
        self.code = code


class StopRequested(RuntimeError):
    """The caller asked the walk to stop at the next safe point."""


class Session(Protocol):
    """What the walk needs from a transport. Every method returns (status, payload)."""

    def public(self, path: str, body: Any) -> tuple[int, dict]: ...

    def admin(self, path: str, body: Any) -> tuple[int, dict]: ...

    def sms_code(self) -> str: ...

    @property
    def requests(self) -> int: ...


def code_of(payload: Any) -> str | None:
    error = payload.get("error") if isinstance(payload, dict) else None
    message = error.get("message") if isinstance(error, dict) else None
    return message.split(":", 1)[0].strip() if isinstance(message, str) else None


def _require(status: int, payload: Any) -> dict:
    if type(status) is not int or status != 200:
        raise Refused(status, code_of(payload))
    if not isinstance(payload, dict) or "error" in payload:
        raise ValueError("Auth success response is malformed")
    return payload


def empty_account_reply(status: int, payload: Any, *, deletion: bool) -> bool:
    """Only the finite success envelopes prove deletion or absence."""
    if type(status) is not int or status != 200 or not isinstance(payload, dict):
        return False
    kind = (
        "identitytoolkit#DeleteAccountResponse"
        if deletion
        else "identitytoolkit#GetAccountInfoResponse"
    )
    if deletion:
        return payload == {} or payload == {"kind": kind}
    if set(payload) - {"kind", "users"}:
        return False
    if "kind" in payload and payload["kind"] != kind:
        return False
    return (
        "users" in payload and type(payload["users"]) is list and not payload["users"]
    ) or payload == {"kind": kind}


def _private_write(path: Path, data: bytes) -> None:
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(4)}")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            os.unlink(temporary)
    directory = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _private_read(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise FileNotFoundError(path.name)
    info = path.stat()
    if info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ValueError("private run file required")
    return path.read_bytes()


class MaterialStore:
    """Private credential material, persisted so a resumed process can finish a case."""

    def __init__(self, directory: Path) -> None:
        self.path = Path(directory) / MATERIAL_FILE
        self.value: dict[str, Any] = {
            "password": None,
            "accounts": {},
            "pendings": {},
            "sessions": {},
            "startSessions": {},
            "totp": {},
            "origin": None,
            "acquiredAt": {},
        }

    @classmethod
    def load(cls, directory: Path) -> MaterialStore:
        store = cls(directory)
        loaded = json.loads(_private_read(store.path))
        if not isinstance(loaded, dict) or set(loaded) != set(store.value):
            raise ValueError("private material store has an unexpected shape")
        store.value = loaded
        return store

    def save(self) -> None:
        _private_write(self.path, json.dumps(self.value, sort_keys=True).encode())

    def password(self) -> str:
        if self.value["password"] is None:
            self.value["password"] = "Aa9!" + secrets.token_urlsafe(24)
            self.save()
        return self.value["password"]


class Walk:
    """Drive the case list against a session, checkpointing after every case."""

    def __init__(
        self,
        *,
        plan: dict,
        session: Session,
        sleeper: Any,
        directory: Path,
        stop_requested: Callable[[], bool] | None = None,
        resume: bool = False,
    ) -> None:
        timing_mode(sleeper)
        self.plan = plan
        self.session = session
        self.sleeper = sleeper
        self.directory = Path(directory)
        self._stop_requested = stop_requested or (lambda: False)
        self.rows: dict[str, dict] = {}
        if resume:
            self.state = load_checkpoint(
                _private_read(self.directory / CHECKPOINT_FILE), plan=plan
            )
            self.material = MaterialStore.load(self.directory)
            self.rows = self._load_rows()
        else:
            if (self.directory / CHECKPOINT_FILE).exists():
                raise ValueError(
                    "a checkpoint exists; resume it or choose a fresh directory"
                )
            self.state = initial_state(plan, sleeper.now())
            self.material = MaterialStore(self.directory)
            self.material.save()
            self._save_checkpoint()
        self._charged = session.requests

    # -- persistence ---------------------------------------------------------------
    def _save_checkpoint(self) -> None:
        _private_write(self.directory / CHECKPOINT_FILE, checkpoint_bytes(self.state))
        _private_write(
            self.directory / "rows.json", json.dumps(self.rows, sort_keys=True).encode()
        )

    def _load_rows(self) -> dict[str, dict]:
        path = self.directory / "rows.json"
        rows = json.loads(_private_read(path)) if path.exists() else {}
        for row in rows.values():
            assert_no_sensitive_material(row, "published row")
        return rows

    def _intent(self, kind: str, body: dict) -> None:
        line = json.dumps({"kind": kind, **body}, sort_keys=True) + "\n"
        path = self.directory / INTENT_FILE
        fd = os.open(
            path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600
        )
        try:
            with os.fdopen(fd, "a") as stream:
                stream.write(line)
                stream.flush()
                os.fsync(stream.fileno())
        finally:
            pass

    # -- accounting ----------------------------------------------------------------
    def _finish(
        self, case_id: str, status: int, code: str | None, **extra: Any
    ) -> None:
        row = {
            "id": case_id,
            "status": status,
            "errorCode": code,
            "outcome": "observed",
            **extra,
        }
        assert_no_sensitive_material(row, "published row")
        self.rows[case_id] = row
        spent = self.session.requests - self._charged
        self._charged = self.session.requests
        record_step(
            self.state,
            case_id,
            {"status": status, "errorCode": code},
            self.sleeper.now(),
            requests=max(1, spent),
        )
        self._save_checkpoint()

    def _skip(self, case_id: str, reason: str, status: int, code: str | None) -> None:
        skip_step(self.state, case_id, reason, self.sleeper.now())
        self.rows[case_id] = {
            "id": case_id,
            "status": status,
            "errorCode": code,
            "outcome": "skipped",
        }
        self._save_checkpoint()

    def _check_stop(self) -> None:
        if self._stop_requested():
            raise StopRequested("stop requested")

    def _skip_planned(self, reason: str) -> None:
        """Tell a slot-hosting session that a planned finalize will not be sent."""
        skip = getattr(self.session, "skip_planned", None)
        if skip is not None:
            skip(reason)

    # -- accounts ------------------------------------------------------------------
    def _email(self, role: str) -> str | None:
        if role in ACCOUNT_ROLES_ANONYMOUS:
            return None
        for entry in self.plan["owner"]["accounts"]:
            if entry["role"] == role:
                return entry["email"]
        raise ValueError("account role is outside the frozen plan")

    def _account(self, role: str) -> dict:
        accounts = self.material.value["accounts"]
        email = self._email(role)
        verified = role not in ACCOUNT_ROLES_UNVERIFIED
        if role in accounts:
            account = accounts[role]
            if account.get("idToken") is None and verified and email is not None:
                # Adopted after a lost signup answer: the verification and the
                # sign-in that follow a signup in the frozen plan have not been
                # sent yet, so send them now and continue as after a signup.
                self._verify_and_sign_in(account)
            return account
        password = self.material.password()
        self._intent("create-intent", {"role": role, "email": email})
        payload = _require(
            *self.session.public(
                "/v1/accounts:signUp",
                {"returnSecureToken": True}
                if email is None
                else {"email": email, "password": password, "returnSecureToken": True},
            )
        )
        uid = payload.get("localId")
        if (
            not isinstance(uid, str)
            or not uid
            or any(ord(c) < 32 or ord(c) == 127 for c in uid)
            or ("email" in payload and payload["email"] != email)
        ):
            raise ValueError("signup did not acknowledge the requested account")
        register_owned(self.state, "account", uid, self.sleeper.now())
        account = {
            "localId": uid,
            "email": email,
            "idToken": payload.get("idToken"),
            "phoneEnrolled": False,
        }
        accounts[role] = account
        self.material.save()
        self._intent("create-ack", {"role": role, "uid": uid})
        self._save_checkpoint()
        if not isinstance(account["idToken"], str) or not account["idToken"]:
            raise ValueError("signup token is missing or malformed")
        if verified:
            self._verify_and_sign_in(account)
        return account

    def _verify_and_sign_in(self, account: dict) -> None:
        _require(
            *self.session.admin(
                f"/v1/projects/{PROJECT}/accounts:update",
                {"localId": account["localId"], "emailVerified": True},
            )
        )
        account["idToken"] = self._sign_in(account)["idToken"]
        self.material.save()

    def _sign_in(self, account: dict) -> dict:
        signed = _require(
            *self.session.public(
                "/v1/accounts:signInWithPassword",
                {
                    "email": account["email"],
                    "password": self.material.password(),
                    "returnSecureToken": True,
                },
            )
        )
        if "localId" in signed and signed["localId"] != account["localId"]:
            raise ValueError("sign-in did not return the owned account")
        return signed

    def _fresh_pending(self, account: dict) -> dict:
        signed = self._sign_in(account)
        return {
            "pending": signed["mfaPendingCredential"],
            "enrollmentId": signed["mfaInfo"][0]["mfaEnrollmentId"],
        }

    def _phone_pending(self, account: dict) -> dict:
        if not account.get("phoneEnrolled"):
            started = _require(
                *self.session.public(
                    "/v2/accounts/mfaEnrollment:start",
                    {
                        "idToken": account["idToken"],
                        "phoneEnrollmentInfo": {
                            "phoneNumber": TEST_PHONE,
                            "recaptchaToken": RECAPTCHA_PLACEHOLDER,
                        },
                    },
                )
            )
            session_info = started["phoneSessionInfo"]["sessionInfo"]
            _require(
                *self.session.public(
                    "/v2/accounts/mfaEnrollment:finalize",
                    {
                        "idToken": account["idToken"],
                        "phoneVerificationInfo": {
                            "sessionInfo": session_info,
                            "code": self.session.sms_code(),
                        },
                        "displayName": "campaign phone",
                    },
                )
            )
            account["phoneEnrolled"] = True
            self.material.save()
        return self._fresh_pending(account)

    def _enroll_totp(self, account: dict) -> dict:
        session_info = _require(
            *self.session.public(
                "/v2/accounts/mfaEnrollment:start",
                {"idToken": account["idToken"], "totpEnrollmentInfo": {}},
            )
        )["totpSessionInfo"]
        parameters = TotpParameters(
            period_seconds=int(session_info.get("periodSec", 30)),
            digits=int(session_info.get("verificationCodeLength", 6)),
            algorithm=session_info.get("hashingAlgorithm", "HMAC_SHA1"),
        )
        return {
            "secret": session_info["sharedSecretKey"],
            "period": parameters.period_seconds,
            "digits": parameters.digits,
            "algorithm": parameters.algorithm,
            "sessionInfo": session_info["sessionInfo"],
        }

    @staticmethod
    def _parameters(session: dict) -> TotpParameters:
        return TotpParameters(
            period_seconds=session["period"],
            digits=session["digits"],
            algorithm=session["algorithm"],
        )

    def _now_int(self) -> int:
        return int(self.sleeper.now())

    # -- phone MFA -----------------------------------------------------------------
    def _phone_start_body(self, pending: dict) -> dict:
        return {
            "mfaPendingCredential": pending["pending"],
            "mfaEnrollmentId": pending["enrollmentId"],
            "phoneSignInInfo": {
                "phoneNumber": TEST_PHONE,
                "recaptchaToken": RECAPTCHA_PLACEHOLDER,
            },
        }

    def _observe(self, path: str, body: Any) -> tuple[int, dict, str | None]:
        status, payload = self.session.public(path, body)
        return status, payload, code_of(payload)

    def _complete_phone_mfa(self, pending: dict) -> tuple[int, dict, str | None]:
        status, payload, code = self._observe(
            "/v2/accounts/mfaSignIn:start", self._phone_start_body(pending)
        )
        if status != 200:
            self._skip_planned("its start was refused")
            return status, payload, code
        session_info = payload["phoneResponseInfo"]["sessionInfo"]
        return self._observe(
            "/v2/accounts/mfaSignIn:finalize",
            {
                "mfaPendingCredential": pending["pending"],
                "phoneVerificationInfo": {
                    "sessionInfo": session_info,
                    "code": self.session.sms_code(),
                },
            },
        )

    # -- acquisition ---------------------------------------------------------------
    def _ensure_acquired(self) -> None:
        """Acquire every aged resource at one common origin, exactly once.

        Each resource records the instant it was acquired, and each aged row is
        scheduled from its own resource's instant plus its age: the resources are
        acquired one after another, so a row anchored to a common origin would
        sample every resource but the last one late by the acquisition tail.
        """
        material = self.material.value
        if material["origin"] is not None:
            return
        acquired = material["acquiredAt"]
        selected = self.plan.get("selector")
        selected_roles = (
            tuple(selected["accountRoles"])
            if isinstance(selected, dict)
            else None
        )
        if selected_roles is None or "pending-control" in selected_roles:
            self._account("pending-control")
        ages = (300,) if selected_roles is not None else AGED_PENDING_SAMPLES
        for age in ages:
            key = str(age)
            if key not in material["pendings"]:
                material["pendings"][key] = self._phone_pending(
                    self._account(f"pending-age-{age}")
                )
                acquired[f"pending-{key}"] = self.sleeper.now()
                self.material.save()
        session_ages = () if selected_roles is not None else SAMPLED_AGES_SECONDS
        for age in session_ages:
            key = str(age)
            if key not in material["sessions"]:
                material["sessions"][key] = self._enroll_totp(
                    self._account(f"enrollment-age-{age}")
                )
                acquired[f"session-{key}"] = self.sleeper.now()
                self.material.save()
        material["origin"] = self.sleeper.now()
        self.material.save()
        # Recording the schedule in the collector makes the checkpoint
        # self-describing: a resumed process waits for the recorded instant, not
        # for an instant it recomputes.
        selected_ids = set(selected_case_ids(self.plan))
        for case in observation_cases():
            if case["id"] not in selected_ids:
                continue
            offset = case["dueOffsetSeconds"]
            if not offset:
                continue
            step = next(s for s in self.state["steps"] if s["id"] == case["id"])
            if step["dueAt"] is None:
                step["dueAt"] = (
                    acquired[self._resource_key(case)]
                    + offset
                    + AGE_SAMPLE_MARGIN_SECONDS
                )
        self._save_checkpoint()

    @staticmethod
    def _resource_key(case: dict) -> str:
        """The aged resource a case samples: the enrollment session or the pending."""
        if case["id"].startswith("totp-enroll-session-age-"):
            return f"session-{case['ageSeconds']}"
        return f"pending-{case['dueOffsetSeconds']}"

    def _observed_age(self, key: str) -> float:
        """How old the resource actually is at this instant, in seconds."""
        return float(self.sleeper.now() - self.material.value["acquiredAt"][key])

    # -- the cases -----------------------------------------------------------------
    def _run_case(self, case: dict) -> None:
        case_id = case["id"]
        material = self.material.value
        if case_id == "baseline-fresh-finalize" or case_id == "final-fresh-finalize":
            control = self._account("pending-control")
            status, _, code = self._complete_phone_mfa(self._phone_pending(control))
            self._finish(case_id, status, code)
            return
        if case_id.startswith("age-"):
            age = int(case_id.split("-")[1].rstrip("s"))
            aged = material["pendings"][str(age)]
            if case_id.endswith("-start"):
                status, payload, code = self._observe(
                    "/v2/accounts/mfaSignIn:start", self._phone_start_body(aged)
                )
                material["startSessions"][str(age)] = (
                    payload["phoneResponseInfo"]["sessionInfo"]
                    if status == 200
                    else None
                )
                material["startSessions"][f"{age}-status"] = [status, code]
                self.material.save()
                self._finish(
                    case_id,
                    status,
                    code,
                    pendingAgeSeconds=float(age),
                    observedAgeSeconds=self._observed_age(f"pending-{age}"),
                )
                return
            if case_id.endswith("-finalize"):
                start_status, start_code = material["startSessions"][f"{age}-status"]
                session_info = material["startSessions"][str(age)]
                if start_status != 200 or session_info is None:
                    self._skip_planned("its start was refused")
                    self._skip(
                        case_id, "its start was refused", start_status, start_code
                    )
                    return
                status, _, code = self._observe(
                    "/v2/accounts/mfaSignIn:finalize",
                    {
                        "mfaPendingCredential": aged["pending"],
                        "phoneVerificationInfo": {
                            "sessionInfo": session_info,
                            "code": self.session.sms_code(),
                        },
                    },
                )
                self._finish(
                    case_id,
                    status,
                    code,
                    pendingAgeSeconds=float(age),
                    observedAgeSeconds=self._observed_age(f"pending-{age}"),
                )
                return
            if case_id.endswith("-same-account-fresh-control"):
                account = self._account(f"pending-age-{age}")
                fresh = self._fresh_pending(account)
                acquired = self.sleeper.now()
                status, _, code = self._complete_phone_mfa(fresh)
                self._finish(
                    case_id,
                    status,
                    code,
                    pendingAgeSeconds=0.0,
                    observedAgeSeconds=float(self.sleeper.now() - acquired),
                )
                return
        if case_id.startswith("totp-enroll-session-age-"):
            age = int(case_id.rsplit("-", 1)[1].rstrip("s"))
            session = material["sessions"][str(age)]
            subject = self._account(f"enrollment-age-{age}")
            status, _, code = self._observe(
                "/v2/accounts/mfaEnrollment:finalize",
                {
                    "idToken": subject["idToken"],
                    "totpVerificationInfo": {
                        "sessionInfo": session["sessionInfo"],
                        "verificationCode": totp_code(
                            session["secret"],
                            self._now_int(),
                            self._parameters(session),
                        ),
                    },
                    "displayName": "aged totp",
                },
            )
            self._finish(
                case_id,
                status,
                code,
                sessionAgeSeconds=float(age),
                observedAgeSeconds=self._observed_age(f"session-{age}"),
            )
            return
        if case_id.startswith("totp-") or case_id == "second-factor-limit":
            self._totp_case(case_id)
            return
        self._interaction_case(case_id)

    def _totp_case(self, case_id: str) -> None:
        material = self.material.value
        totp = material["totp"]
        subject = self._account("totp-lifecycle")

        def finalize_body(code: str) -> dict:
            return {
                "idToken": subject["idToken"],
                "totpVerificationInfo": {
                    "sessionInfo": totp["session"]["sessionInfo"],
                    "verificationCode": code,
                },
                "displayName": "campaign totp",
            }

        if case_id == "totp-enroll-start":
            totp["session"] = self._enroll_totp(subject)
            self.material.save()
            self._finish(case_id, 200, None)
            return
        parameters = self._parameters(totp["session"])
        secret = totp["session"]["secret"]
        if case_id == "totp-enroll-wrong-code":
            status, _, code = self._observe(
                "/v2/accounts/mfaEnrollment:finalize",
                finalize_body(
                    wrong_code(secret, self._now_int(), parameters, window_steps=1)
                ),
            )
            self._finish(case_id, status, code)
            return
        if case_id == "totp-enroll-retry-same-session":
            status, payload, code = self._observe(
                "/v2/accounts/mfaEnrollment:finalize",
                finalize_body(totp_code(secret, self._now_int(), parameters)),
            )
            if status == 200:
                subject["idToken"] = payload.get("idToken", subject["idToken"])
                totp["enrollmentId"] = payload.get("mfaEnrollmentId")
            else:
                totp["enrollmentId"] = None
            self.material.save()
            self._finish(case_id, status, code)
            return
        if case_id == "totp-enroll-replay-finalized-session":
            status, _, code = self._observe(
                "/v2/accounts/mfaEnrollment:finalize",
                finalize_body(totp_code(secret, self._now_int(), parameters)),
            )
            self._finish(case_id, status, code)
            return
        if case_id == "totp-enroll-factor-readback":
            status, payload, code = self._observe(
                "/v1/accounts:lookup", {"idToken": subject["idToken"]}
            )
            factors = (
                payload.get("users", [{}])[0].get("mfaInfo", [])
                if status == 200
                else []
            )
            if totp.get("enrollmentId") is None and factors:
                totp["enrollmentId"] = factors[0].get("mfaEnrollmentId")
                self.material.save()
            self._finish(case_id, status, code, factorCount=len(factors))
            return
        if case_id == "second-factor-limit":
            status, _, code = self._observe(
                "/v2/accounts/mfaEnrollment:start",
                {"idToken": subject["idToken"], "totpEnrollmentInfo": {}},
            )
            self._finish(case_id, status, code)
            return
        if case_id == "totp-signin-start":
            signed = self._sign_in(subject)
            totp["pending"] = signed.get("mfaPendingCredential")
            self.material.save()
            status, _, code = self._observe(
                "/v2/accounts/mfaSignIn:start",
                {
                    "mfaPendingCredential": totp["pending"],
                    "mfaEnrollmentId": totp["enrollmentId"],
                },
            )
            self._finish(case_id, status, code)
            return
        if case_id == "totp-signin-finalize":
            # The code that enrolled the factor must not be the code that signs in
            # with it, so one whole step has to roll over first: a real wait in
            # production, an instant advance under a virtual clock.
            now = self._now_int()
            period = parameters.period_seconds
            if period != TOTP_STEP_ROLLOVER_SECONDS:
                raise ValueError(
                    "TOTP period differs from the campaign's declared rollover"
                )
            self.sleeper.sleep_until((now // period + 1) * period + 1)
            totp["usedCode"] = totp_code(secret, self._now_int(), parameters)
            self.material.save()
            status, payload, code = self._observe(
                "/v2/accounts/mfaSignIn:finalize",
                {
                    "mfaPendingCredential": totp["pending"],
                    "mfaEnrollmentId": totp["enrollmentId"],
                    "totpVerificationInfo": {"verificationCode": totp["usedCode"]},
                },
            )
            if status == 200:
                subject["idToken"] = payload.get("idToken", subject["idToken"])
                self.material.save()
            self._finish(case_id, status, code)
            return
        if case_id == "totp-signin-replay-same-code":
            signed = self._sign_in(subject)
            status, _, code = self._observe(
                "/v2/accounts/mfaSignIn:finalize",
                {
                    "mfaPendingCredential": signed.get("mfaPendingCredential"),
                    "mfaEnrollmentId": totp["enrollmentId"],
                    "totpVerificationInfo": {"verificationCode": totp["usedCode"]},
                },
            )
            self._finish(case_id, status, code)
            return
        if case_id in ("totp-withdraw", "totp-withdraw-unknown"):
            status, payload, code = self._observe(
                "/v2/accounts/mfaEnrollment:withdraw",
                {
                    "idToken": subject["idToken"],
                    "mfaEnrollmentId": totp["enrollmentId"],
                },
            )
            if status == 200:
                subject["idToken"] = payload.get("idToken", subject["idToken"])
                self.material.save()
            self._finish(case_id, status, code)
            return
        if case_id == "totp-withdraw-readback":
            status, payload, code = self._observe(
                "/v1/accounts:lookup", {"idToken": subject["idToken"]}
            )
            remaining = (
                payload.get("users", [{}])[0].get("mfaInfo", [])
                if status == 200
                else []
            )
            self._finish(case_id, status, code, factorCount=len(remaining))
            return
        raise ValueError(f"unknown TOTP case: {case_id}")

    def _interaction_case(self, case_id: str) -> None:
        if case_id == "unverified-email-enroll-refusal":
            unverified = self._account("interaction-unverified")
            status, _, code = self._observe(
                "/v2/accounts/mfaEnrollment:start",
                {"idToken": unverified["idToken"], "totpEnrollmentInfo": {}},
            )
            self._finish(case_id, status, code)
            return
        if case_id == "ineligible-first-factor-refusal":
            anonymous = self._account("interaction-anonymous")
            status, _, code = self._observe(
                "/v2/accounts/mfaEnrollment:start",
                {"idToken": anonymous["idToken"], "totpEnrollmentInfo": {}},
            )
            self._finish(case_id, status, code)
            return
        if case_id == "missing-id-token-refusal":
            status, _, code = self._observe(
                "/v2/accounts/mfaEnrollment:start", {"totpEnrollmentInfo": {}}
            )
            self._finish(case_id, status, code)
            return
        if case_id == "project-mfa-config-readback":
            status, payload = self.session.admin(CONFIG_PATH, None)
            # The same predicate the local shadow records, so the row compares like
            # for like: the service spells its block `mfa`, the local artifact
            # `mfaConfig`, and the flag reports the local spelling on both sides.
            present = isinstance(payload, dict) and "mfaConfig" in payload
            self._finish(case_id, status, code_of(payload), mfaConfigPresent=present)
            return
        raise ValueError(f"unknown interaction case: {case_id}")

    # -- driver --------------------------------------------------------------------
    def run(self) -> dict:
        """Walk every pending case in order, waiting where the collector says to.

        Returns the collector state. A `StopRequested` or a transport failure
        propagates after the checkpoint for the last completed case was written; the
        caller decides whether to resume, or to clean up and abandon.
        """
        self._check_stop()
        self._ensure_acquired()
        cases = {
            case["id"]: case
            for case in observation_cases()
            if case["id"] in set(selected_case_ids(self.plan))
        }
        while True:
            self._check_stop()
            action = next_action(self.state, self.sleeper.now())
            if action["action"] == "WAIT":
                # The wait is interruptible: a stop requested during it is honoured
                # at the next slice, and the checkpoint already holds the absolute
                # due instant a resumed process waits for.
                self.sleeper.sleep_until(
                    action["dueAt"], on_tick=lambda _now: self._check_stop()
                )
                continue
            if action["action"] != "RUN":
                return self.state
            self._run_case(cases[action["stepId"]])

    def cleanup(self) -> dict:
        """Delete every owned account and prove absence by UID and by email.

        One failed account must not stop the others. This does not consult the
        collector's abort state: cleanup runs on every path.
        """
        accounts = self.material.value["accounts"]
        owned = {
            r["id"]: r for r in self.state["ownedResources"] if r["kind"] == "account"
        }
        # Cleanup runs in creation order whatever order the accounts were
        # registered in, because the frozen recovery slots are in that order and
        # an adopted account is registered late.
        for role in CLEANUP_ORDER:
            account = accounts.get(role)
            if account is None or account["localId"] not in owned:
                continue
            uid = account["localId"]
            resource = owned[uid]
            if resource["deleted"] and resource["absenceVerified"]:
                continue
            email = account["email"]
            # Every readback is sent whatever the delete answered: absence is what
            # they prove, and a delete that failed makes the readbacks the evidence
            # that the account is still there. Each call is guarded on its own so a
            # transport failure on one leaves the next slot reachable.
            deleted = self._admin_evidence(
                f"/v1/projects/{PROJECT}/accounts:delete",
                {"localId": uid},
                deletion=True,
            )
            uid_absent = self._admin_evidence(
                f"/v1/projects/{PROJECT}/accounts:lookup",
                {"localId": [uid]},
                deletion=False,
            )
            email_absent = True
            if email is not None:
                email_absent = self._admin_evidence(
                    f"/v1/projects/{PROJECT}/accounts:lookup",
                    {"email": [email]},
                    deletion=False,
                )
            if deleted or uid_absent:
                mark_deleted(
                    self.state, uid, absence_verified=uid_absent and email_absent
                )
            self._save_checkpoint()
        self.state["requests"] = self._charged = self.session.requests
        self._save_checkpoint()
        return self.state

    def _admin_evidence(self, path: str, body: dict, *, deletion: bool) -> bool:
        """One cleanup call; a transport failure is `False`, never a raised secret."""
        try:
            status, payload = self.session.admin(path, body)
        except Exception:  # noqa: BLE001 -- transport errors may carry credential bytes and are not logged
            return False
        return empty_account_reply(status, payload, deletion=deletion)

    def complete(self) -> bool:
        return run_complete(self.state)

    def ordered_rows(self) -> list[dict]:
        return [
            copy.deepcopy(self.rows[c["id"]])
            for c in observation_cases()
            if c["id"] in set(selected_case_ids(self.plan))
            if c["id"] in self.rows
        ]

    def unacknowledged_intents(self) -> list[dict]:
        """Signups an earlier process sent without recording an answer."""
        path = self.directory / INTENT_FILE
        if not path.exists():
            return []
        intents: dict[str, dict] = {}
        acknowledged: set[str] = set()
        for line in _private_read(path).decode().splitlines():
            entry = json.loads(line)
            if entry["kind"] == "create-intent":
                intents[entry["role"]] = entry
            elif entry["kind"] == "create-ack":
                acknowledged.add(entry["role"])
        return [entry for role, entry in intents.items() if role not in acknowledged]

    def adopt_account(self, role: str, uid: str) -> None:
        """Own an account an earlier process created and never acknowledged.

        The account has no ID token; the verification and sign-in the plan places
        after its signup are sent when the walk next needs it, and it is deleted
        with the others in cleanup order.
        """
        if (
            not isinstance(uid, str)
            or not uid
            or any(ord(c) < 32 or ord(c) == 127 for c in uid)
        ):
            raise ValueError("typed account identity required")
        if role in self.material.value["accounts"]:
            raise ValueError("account role already owned")
        register_owned(self.state, "account", uid, self.sleeper.now())
        self.material.value["accounts"][role] = {
            "localId": uid,
            "email": self._email(role),
            "idToken": None,
            "phoneEnrolled": False,
        }
        self.material.save()
        self._intent("create-ack", {"role": role, "uid": uid, "adopted": True})
        self._save_checkpoint()

    def settle_intent(self, role: str) -> None:
        """Record that a readback found no account for an unacknowledged signup."""
        self._intent("create-absent", {"role": role})


__all__ = [
    "CHECKPOINT_FILE",
    "MATERIAL_FILE",
    "BudgetError",
    "Refused",
    "StopRequested",
    "Walk",
    "code_of",
    "empty_account_reply",
]
