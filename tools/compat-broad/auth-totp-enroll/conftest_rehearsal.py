"""Test support: an in-memory Identity Toolkit and a complete rehearsal admission.

Nothing here reaches a network origin, a credential or the canonical Ledger. The
fake answers the campaign's endpoints with fireemu-like local policy, except that its
pending-credential lifetime is set so the 1800-second control is refused, which is
what production has already been observed to do and what exercises the skip path.
"""

from __future__ import annotations

import copy
import hashlib
import json
import secrets
import shutil
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
for entry in (
    ROOT / "tools/compat-broad",
    ROOT / "tools/compat-broad/production-admission",
    ROOT / "tools/compat-broad/o8-core",
    HERE,
):
    if str(entry) not in sys.path:
        sys.path.insert(0, str(entry))

import reservations
from broad_contract import digest

import mfa_admission as admission
import mfa_descriptor as campaign
from mfa_config_lock import PROJECT, PROJECT_NUMBER, TEST_CODE
from mfa_timing import VirtualClockSleeper
from mfa_totp import TotpParameters, totp_code

NONCE = "c" * 32
PENDING_TTL_SECONDS = 1000
ENROLLMENT_TTL_SECONDS = 300
TOTP = TotpParameters(period_seconds=30, digits=6, algorithm="HMAC_SHA1")
PRINCIPAL = {
    "clientId": "offline-client",
    "subject": "offline-subject",
    "requiredScopes": ["https://www.googleapis.com/auth/cloud-platform"],
}
BASELINE_CONFIG = {
    "name": f"projects/{PROJECT_NUMBER}/config",
    "signIn": {"email": {"enabled": True, "passwordRequired": True}},
    "mfa": {"state": "DISABLED"},
    "smsRegionConfig": {"allowlistOnly": {}},
    "emailPrivacyConfig": {"enableImprovedEmailPrivacy": True},
}


def _error(status: int, code: str) -> tuple[int, dict]:
    return status, {"error": {"code": status, "message": code, "errors": []}}


class FakeIdentityToolkit:
    """Enough of Identity Platform to walk the thirty-three cases."""

    def __init__(self, clock: VirtualClockSleeper, *, config=None) -> None:
        self.clock = clock
        self.config = copy.deepcopy(BASELINE_CONFIG if config is None else config)
        # What `GET /v1/projects?key=` answers with; a test simulating a key
        # minted for another project overrides this before the run.
        self.project_id = PROJECT
        self.accounts: dict[str, dict] = {}
        self.tokens: dict[str, str] = {}
        self.pendings: dict[str, dict] = {}
        self.enrollment_sessions: dict[str, dict] = {}
        self.signin_sessions: dict[str, dict] = {}
        self.counter = 0
        self.log: list[tuple[str, str]] = []
        # A restore of an absent phone block reads back as its disabled object.
        self.restore_reads_back_disabled_phone = True

    def _new(self, prefix: str) -> str:
        self.counter += 1
        return f"{prefix}-{self.counter:04d}"

    def _token(self, uid: str) -> str:
        token = self._new(f"idt-{uid}")
        self.tokens[token] = uid
        return token

    def _user(self, token) -> dict | None:
        uid = self.tokens.get(token) if isinstance(token, str) else None
        return self.accounts.get(uid) if uid else None

    def _mfa_info(self, account: dict) -> list[dict]:
        return [
            {
                "mfaEnrollmentId": f["id"],
                "displayName": f.get("displayName", ""),
                **(
                    {"phoneInfo": f["phone"]}
                    if f["kind"] == "phone"
                    else {"totpInfo": {}}
                ),
            }
            for f in account["factors"]
        ]

    def handle(self, kind: str, path: str, body, mask=None) -> tuple[int, dict]:
        self.log.append((kind, path))
        now = int(self.clock.now())
        if kind == "oauth-tokeninfo":
            return 200, {
                "issued_to": PRINCIPAL["clientId"],
                "audience": PRINCIPAL["clientId"],
                "user_id": PRINCIPAL["subject"],
                "scope": "https://www.googleapis.com/auth/cloud-platform openid",
                "expires_in": 3599,
            }
        if kind == "auth-config-patch":
            return self._patch_config(body, mask)
        if kind == "auth-key-project":
            return 200, {"projectId": self.project_id}
        if path.endswith("/config"):
            return 200, copy.deepcopy(self.config)
        action = path.rsplit(":", 1)[-1]
        if kind == "auth-admin":
            return self._admin(action, body)
        if path.startswith("/v1/"):
            return self._v1(action, body, now)
        return self._v2(path.rsplit("/", 1)[-1], body, now)

    # -- configuration -------------------------------------------------------------
    def _patch_config(self, body, mask):
        for field in mask.split(","):
            if field == "mfa":
                self.config["mfa"] = copy.deepcopy(body["mfa"])
            elif field == "signIn.phoneNumber":
                phone = copy.deepcopy(body["signIn"]["phoneNumber"])
                self.config.setdefault("signIn", {})["phoneNumber"] = phone
            elif field == "smsRegionConfig":
                self.config["smsRegionConfig"] = copy.deepcopy(body["smsRegionConfig"])
            else:
                return _error(400, "INVALID_ARGUMENT")
        return 200, copy.deepcopy(self.config)

    # -- admin ---------------------------------------------------------------------
    def _admin(self, action, body):
        if action == "update":
            account = self.accounts.get(body.get("localId"))
            if account is None:
                return _error(400, "USER_NOT_FOUND")
            if "emailVerified" in body:
                account["emailVerified"] = body["emailVerified"]
            return 200, {"localId": account["uid"]}
        if action == "lookup":
            users = []
            for uid in body.get("localId", []):
                if uid in self.accounts:
                    users.append(self._public_user(self.accounts[uid]))
            for email in body.get("email", []):
                for account in self.accounts.values():
                    if account["email"] == email:
                        users.append(self._public_user(account))
            payload = {"kind": "identitytoolkit#GetAccountInfoResponse"}
            if users:
                payload["users"] = users
            return 200, payload
        if action == "delete":
            if body.get("localId") not in self.accounts:
                return _error(400, "USER_NOT_FOUND")
            del self.accounts[body["localId"]]
            return 200, {"kind": "identitytoolkit#DeleteAccountResponse"}
        return _error(404, "NOT_FOUND")

    def _public_user(self, account):
        value = {
            "localId": account["uid"],
            "emailVerified": account["emailVerified"],
            "mfaInfo": self._mfa_info(account),
        }
        if account["email"]:
            value["email"] = account["email"]
        return value

    # -- v1 public -----------------------------------------------------------------
    def _v1(self, action, body, now):
        if action == "signUp":
            email = body.get("email")
            if email and any(a["email"] == email for a in self.accounts.values()):
                return _error(400, "EMAIL_EXISTS")
            uid = self._new("uid")
            self.accounts[uid] = {
                "uid": uid,
                "email": email,
                "password": body.get("password"),
                "emailVerified": False,
                "anonymous": email is None,
                "factors": [],
                "lastTotpStep": None,
            }
            payload = {"localId": uid, "idToken": self._token(uid)}
            if email:
                payload["email"] = email
            return 200, payload
        if action == "signInWithPassword":
            account = next(
                (a for a in self.accounts.values() if a["email"] == body.get("email")),
                None,
            )
            if account is None or account["password"] != body.get("password"):
                return _error(400, "INVALID_LOGIN_CREDENTIALS")
            if account["factors"]:
                pending = self._new("pending")
                self.pendings[pending] = {"uid": account["uid"], "issuedAt": now}
                return 200, {
                    "localId": account["uid"],
                    "mfaPendingCredential": pending,
                    "mfaInfo": self._mfa_info(account),
                }
            return 200, {
                "localId": account["uid"],
                "idToken": self._token(account["uid"]),
            }
        if action == "lookup":
            account = self._user(body.get("idToken"))
            if account is None:
                return _error(400, "INVALID_ID_TOKEN")
            return 200, {"users": [self._public_user(account)]}
        return _error(404, "NOT_FOUND")

    # -- v2 MFA --------------------------------------------------------------------
    def _v2(self, action, body, now):
        if action == "mfaEnrollment:start":
            if "idToken" not in body:
                return _error(400, "INVALID_ID_TOKEN")
            account = self._user(body["idToken"])
            if account is None:
                return _error(400, "INVALID_ID_TOKEN")
            if account["anonymous"]:
                return _error(400, "UNSUPPORTED_FIRST_FACTOR")
            if not account["emailVerified"]:
                return _error(400, "UNVERIFIED_EMAIL")
            if "totpEnrollmentInfo" in body:
                if any(f["kind"] == "totp" for f in account["factors"]):
                    return _error(400, "SECOND_FACTOR_EXISTS")
                session = self._new("enroll")
                secret = "".join(
                    secrets.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
                    for _ in range(32)
                )
                self.enrollment_sessions[session] = {
                    "uid": account["uid"],
                    "kind": "totp",
                    "secret": secret,
                    "createdAt": now,
                    "finalized": False,
                }
                return 200, {
                    "totpSessionInfo": {
                        "sharedSecretKey": secret,
                        "sessionInfo": session,
                        "periodSec": 30,
                        "verificationCodeLength": 6,
                        "hashingAlgorithm": "HMAC_SHA1",
                    }
                }
            session = self._new("enroll")
            self.enrollment_sessions[session] = {
                "uid": account["uid"],
                "kind": "phone",
                "phone": body["phoneEnrollmentInfo"]["phoneNumber"],
                "createdAt": now,
                "finalized": False,
            }
            return 200, {"phoneSessionInfo": {"sessionInfo": session}}
        if action == "mfaEnrollment:finalize":
            account = self._user(body.get("idToken"))
            if account is None:
                return _error(400, "INVALID_ID_TOKEN")
            if "totpVerificationInfo" in body:
                info = body["totpVerificationInfo"]
                session = self.enrollment_sessions.get(info.get("sessionInfo"))
                if (
                    session is None
                    or session["finalized"]
                    or session["uid"] != account["uid"]
                ):
                    return _error(400, "INVALID_SESSION_INFO")
                age = now - session["createdAt"]
                if age >= 2 * ENROLLMENT_TTL_SECONDS:
                    return _error(400, "INVALID_SESSION_INFO")
                if age > ENROLLMENT_TTL_SECONDS:
                    return _error(400, "SESSION_EXPIRED")
                if not self._totp_valid(
                    session["secret"], info.get("verificationCode"), now
                ):
                    return _error(400, "INVALID_CODE")
                session["finalized"] = True
                factor = {
                    "id": self._new("mfa"),
                    "kind": "totp",
                    "secret": session["secret"],
                    "displayName": body.get("displayName", ""),
                }
                account["factors"].append(factor)
                return 200, {
                    "idToken": self._token(account["uid"]),
                    "mfaEnrollmentId": factor["id"],
                }
            info = body["phoneVerificationInfo"]
            session = self.enrollment_sessions.get(info.get("sessionInfo"))
            if (
                session is None
                or session["finalized"]
                or session["uid"] != account["uid"]
            ):
                return _error(400, "INVALID_SESSION_INFO")
            if info.get("code") != TEST_CODE:
                return _error(400, "INVALID_CODE")
            session["finalized"] = True
            factor = {
                "id": self._new("mfa"),
                "kind": "phone",
                "phone": session["phone"],
                "displayName": body.get("displayName", ""),
            }
            account["factors"].append(factor)
            return 200, {
                "idToken": self._token(account["uid"]),
                "mfaEnrollmentId": factor["id"],
            }
        if action == "mfaEnrollment:withdraw":
            account = self._user(body.get("idToken"))
            if account is None:
                return _error(400, "INVALID_ID_TOKEN")
            factor = next(
                (
                    f
                    for f in account["factors"]
                    if f["id"] == body.get("mfaEnrollmentId")
                ),
                None,
            )
            if factor is None:
                return _error(400, "MFA_ENROLLMENT_NOT_FOUND")
            account["factors"].remove(factor)
            return 200, {"idToken": self._token(account["uid"])}
        if action == "mfaSignIn:start":
            pending = self.pendings.get(body.get("mfaPendingCredential"))
            if pending is None or now - pending["issuedAt"] > PENDING_TTL_SECONDS:
                return _error(400, "INVALID_MFA_PENDING_CREDENTIAL")
            if "phoneSignInInfo" not in body:
                return _error(400, "INVALID_ARGUMENT")
            session = self._new("signin")
            self.signin_sessions[session] = {"pending": body["mfaPendingCredential"]}
            return 200, {"phoneResponseInfo": {"sessionInfo": session}}
        if action == "mfaSignIn:finalize":
            pending_id = body.get("mfaPendingCredential")
            pending = self.pendings.get(pending_id)
            if pending is None or now - pending["issuedAt"] > PENDING_TTL_SECONDS:
                return _error(400, "INVALID_MFA_PENDING_CREDENTIAL")
            account = self.accounts[pending["uid"]]
            if "phoneVerificationInfo" in body:
                info = body["phoneVerificationInfo"]
                session = self.signin_sessions.get(info.get("sessionInfo"))
                if session is None or session["pending"] != pending_id:
                    return _error(400, "INVALID_SESSION_INFO")
                if info.get("code") != TEST_CODE:
                    return _error(400, "INVALID_CODE")
                del self.pendings[pending_id]
                return 200, {"idToken": self._token(account["uid"])}
            factor = next(
                (
                    f
                    for f in account["factors"]
                    if f["id"] == body.get("mfaEnrollmentId")
                ),
                None,
            )
            if factor is None or factor["kind"] != "totp":
                return _error(400, "MFA_ENROLLMENT_NOT_FOUND")
            code = body.get("totpVerificationInfo", {}).get("verificationCode")
            step = self._totp_step(factor["secret"], code, now)
            if step is None or step == account["lastTotpStep"]:
                return _error(400, "INVALID_CODE")
            account["lastTotpStep"] = step
            del self.pendings[pending_id]
            return 200, {"idToken": self._token(account["uid"])}
        return _error(404, "NOT_FOUND")

    def _totp_step(self, secret, code, now):
        current = now // TOTP.period_seconds
        for step in (current - 1, current, current + 1):
            if totp_code(secret, step * TOTP.period_seconds, TOTP) == code:
                return step
        return None

    def _totp_valid(self, secret, code, now) -> bool:
        return self._totp_step(secret, code, now) is not None


class FakeSession:
    """The walk's session over the fake, with an optional fault injector."""

    def __init__(self, fake: FakeIdentityToolkit, *, fault=None, after=None) -> None:
        self.fake = fake
        self.fault = fault
        # `after(kind, path, count, fake, status, body)` runs once the fake has
        # answered; raising there loses the answer after the service applied it.
        self.after = after
        self._requests = 0
        self.calls: list[tuple[str, str]] = []

    @property
    def requests(self) -> int:
        return self._requests

    def _call(self, kind, path, body, mask=None):
        self._requests += 1
        self.calls.append((kind, path))
        if self.fault is not None:
            self.fault(kind, path, self._requests, self.fake)
        status, answer = self.fake.handle(kind, path, body, mask)
        if self.after is not None:
            self.after(kind, path, self._requests, self.fake, status, answer)
        return status, answer

    def public(self, path, body, **_kwargs):
        return self._call("auth-public", path, body)

    def admin(self, path, body, **_kwargs):
        return self._call("auth-admin", path, body)

    def read_config(self, **_kwargs):
        return self._call("auth-admin", "/admin/v2/projects/fireemu-35fe6/config", None)

    def project_config(self, **_kwargs):
        return self._call("auth-key-project", "/v1/projects", None)

    def patch_config(self, body, mask, **_kwargs):
        return self._call(
            "auth-config-patch", "/admin/v2/projects/fireemu-35fe6/config", body, mask
        )

    def tokeninfo(self, **_kwargs):
        return self._call("oauth-tokeninfo", "", None)

    def sms_code(self) -> str:
        return TEST_CODE


def frozen_checkout(tmp_path: Path) -> Path:
    """A clean git checkout carrying byte-identical copies of the frozen sources."""
    source = tmp_path / "checkout"
    for name in campaign.source_map():
        target = source / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, target)
    for args in (
        ["init", "-q"],
        ["add", "-A"],
        [
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit",
            "-qm",
            "fixture",
        ],
    ):
        subprocess.run(["git", "-C", str(source), *args], check=True)
    return source


def owner_permission(
    descriptor, plan, commit, artifact_digest, inputs, baseline_digest
):
    return {
        **descriptor.permission_bindings(
            plan, commit, artifact_digest, inputs, baseline_digest
        ),
        "ownerIdentity": "offline-fixture-not-permission",
        "recoveryOwner": "offline-recovery",
        "permissionReference": "offline-fixture",
        "credentialPrincipal": dict(PRINCIPAL),
        "authConfigBaselineDigest": baseline_digest,
        "baselineProvenance": {
            "method": "admin-v2-getConfig-readback",
            "observedAt": "2026-09-21T00:00:00Z",
            "recordReference": "offline-fixture-baseline",
        },
        "configurationChangeAcknowledged": True,
        "issuedAt": time.time() - 1,
        "expiresAt": time.time() + 4800,
    }


class RehearsalAdmission:
    """A complete, locally built O7 artifact set with a temporary Ledger."""

    def __init__(self, tmp_path: Path, *, sleeper=None, descriptor=None, config=None):
        self.sleeper = sleeper or VirtualClockSleeper()
        self.descriptor = descriptor or campaign.rehearsal_descriptor(self.sleeper)
        self.fake = FakeIdentityToolkit(self.sleeper, config=config)
        self.source = frozen_checkout(tmp_path)
        self.commit = subprocess.check_output(
            ["git", "-C", str(self.source), "rev-parse", "HEAD"], text=True
        ).strip()
        self.artifact_path = tmp_path / "artifact"
        self.artifact_path.write_bytes(b"retained mfa artifact")
        self.plan = self.descriptor.plan_compiler(NONCE)
        self.baseline_digest = digest(self.fake.config)
        self.permission = owner_permission(
            self.descriptor,
            self.plan,
            self.commit,
            hashlib.sha256(self.artifact_path.read_bytes()).hexdigest(),
            campaign.source_map(),
            self.baseline_digest,
        )
        self.permission_path = tmp_path / "permission.json"
        self.permission_path.write_text(json.dumps(self.permission))
        self.inputs = admission.freeze_inputs(
            self.permission_path,
            self.plan,
            source_root=self.source,
            artifact_path=self.artifact_path,
            descriptor_=self.descriptor,
        )
        self.ledger = tmp_path / "ledger"
        reservations.Ledger.create(self.ledger)
        self.manifest = {
            "kind": campaign.MANIFEST_KIND,
            "inputsDigest": self.inputs["inputsDigest"],
        }
        self.manifest_bytes = json.dumps(self.manifest).encode()
        self.manifest_path = tmp_path / "manifest.json"
        self.manifest_path.write_bytes(self.manifest_bytes)
        self.manifest_path.chmod(0o600)
        self.launcher_path = HERE / "mfa_o8.py"
        self.approval = self._approval()
        self.approval_path = tmp_path / "approval.json"
        self.approval_path.write_text(json.dumps(self.approval))
        self.approval_path.chmod(0o600)
        self.output = tmp_path / "run"

    def _approval(self):
        now = time.time()
        return {
            "kind": campaign.APPROVAL_KIND,
            "status": "approved",
            "campaignId": campaign.CAMPAIGN,
            "manifestSha256": hashlib.sha256(self.manifest_bytes).hexdigest(),
            "inputsDigest": self.inputs["inputsDigest"],
            "permissionDigest": self.inputs["permissionDigest"],
            "sourceCommit": self.inputs["sourceCommit"],
            "sourceInputsDigest": digest(self.inputs["sourceInputs"]),
            "artifactSha256": self.inputs["artifactSha256"],
            "planDigest": self.inputs["planDigest"],
            "nonceDigest": digest(self.plan["nonce"]),
            "ledgerRoot": str(self.ledger.resolve(strict=False)),
            "launcherSha256": hashlib.sha256(
                self.launcher_path.read_bytes()
            ).hexdigest(),
            "artifactProfile": campaign.artifact_profile(),
            "windowStartsAt": now - 1,
            "windowExpiresAt": now + 4 * self.descriptor.window_seconds,
            "executionHost": admission.execution_host(),
        }

    def bindings(self, **overrides):
        value = {
            "inputs": self.inputs,
            "approval": self.approval,
            "manifest": self.manifest,
            "manifest_bytes": self.manifest_bytes,
            "manifest_path": self.manifest_path,
            "permission": self.permission,
            "ledger_root": self.ledger,
            "artifact_path": self.artifact_path,
            "launcher_path": self.launcher_path,
        }
        value.update(overrides)
        return value

    def capability(self):
        binding, binding_digest = campaign.worker_binding()
        return admission.issue_production_capability(
            self.descriptor,
            **self.bindings(),
            binding=binding,
            binding_digest=binding_digest,
        )

    def credentials(self):
        return {"token": "offline-fixture-token", "apiKey": "offline-fixture-key"}

    def session_factory(self, fault=None, after=None):
        def factory(_capability, _credentials, _deadline_for):
            return FakeSession(self.fake, fault=fault, after=after)

        return factory

    def run(
        self,
        *,
        fault=None,
        after=None,
        stop_requested=None,
        resume=False,
        abandon=False,
        credential_reader=None,
    ):
        from mfa_production import execute

        return execute(
            capability=self.capability(),
            inputs=self.inputs,
            permission=self.permission,
            credential_reader=credential_reader or self.credentials,
            ledger_root=self.ledger,
            output=self.output,
            sleeper=self.sleeper,
            descriptor_=self.descriptor,
            source_root=self.source,
            resume=resume,
            abandon=abandon,
            stop_requested=stop_requested,
            session_factory=self.session_factory(fault, after),
        )

    def ledger_row(self):
        state = reservations.Ledger(self.ledger).snapshot()
        return next(iter(state["reservations"].values()), None)
