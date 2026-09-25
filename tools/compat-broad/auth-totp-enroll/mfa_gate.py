"""Shared-Gate plan and typed facade for AUTH-MFA-AGE-TOTP-01.

The shared Gate admits one request per frozen slot and journals every send, but it
knows Firestore documents, not Auth accounts. This module projects the MFA walk onto
it the way the credential lane does: every request the walk sends is frozen here in
order with `$binding:` placeholders where a value is only known at run time, and a
facade over the Gate resolves those placeholders from this run's own responses,
settles each slot's creation outcome for an account rather than a document, and
records typed deletion and absence evidence per account.

An *observed* binding is a value a response of this run returned (an ID token, a
pending credential, a session identifier, a UID); a slot declares which response
field it records under which name, and a later slot may only carry that exact value.
A *minted* binding is a value the run itself chose (the password, a TOTP code computed
at submission time); the plan declares the names and the facade pins each on first
use. No binding value is written to the Gate journal.

Two things the walk does that a fixed queue does not: a finalize is skipped when its
start was refused, and the cleanup of an account that was never created has nothing to
send. Both are zero-wire skips the facade admits only for slots its own contract says
cannot create an account, and both are journaled with a reason.

Resources are canonical Auth account resources. Each account-bearing operation carries
the exact account resource and frozen UID binding for its kebab-case role; the
camel-cased binding is extracted from the signup `localId` and reused by cleanup.
Cleanup routes remain request paths, not substitute resources. The configuration lock
is still named separately in `configResource`.
"""

from __future__ import annotations

import copy
import json
import os
import re
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
if str(ROOT / "tools/compat-broad") not in sys.path:
    sys.path.insert(0, str(ROOT / "tools/compat-broad"))

from broad_contract import digest
from shared_gate import ZERO_WIRE_REASON, _save, job_schedule
from shared_gate import Gate as FrozenGate
from shared_gate import create as frozen_create

from mfa_cases import (
    AGED_PENDING_SAMPLES,
    CAMPAIGN_ID,
    SAMPLED_AGES_SECONDS,
    owned_accounts,
)
from mfa_config_lock import CONFIG_PATH, TEST_CODE, TEST_PHONE
from mfa_walk import CLEANUP_ORDER, RECAPTCHA_PLACEHOLDER

JOB = "mfa-accounts"
CONTRACT = "shared-local-v1"
PROJECT = "fireemu-35fe6"
HOST = "identitytoolkit.googleapis.com"
BINDING_PREFIX = "$binding:"
BINDINGS_FILE = "gate-bindings.json"
_NONCE = re.compile(r"^[0-9a-f]{32}$")
GATE_INTERVAL_SECONDS = 0.25
REQUEST_COST_MICROUSD = 1
#: The wire reservation per data slot; the driver gives each data request this
#: deadline. It is an owner planning bound, not a measurement.
DATA_SLOT_SECONDS = 5.0
MANAGEMENT_SLOT_SECONDS = 13.0
MANAGEMENT_DURATION_SECONDS = 12.0
MANAGEMENT_OBSERVATION_IDS = (
    "oauth-tokeninfo",
    "auth-config-readback",
    "auth-config-apply",
    "auth-config-apply-readback",
)
MANAGEMENT_RECOVERY_IDS = ("auth-config-restore", "auth-config-restore-readback")
#: Names the run may mint. Everything else must come from a response.
MINTED_BINDINGS = (
    "password",
    "totpWrong",
    "totpRetry",
    "totpReplay",
    "totpSignIn",
    *[f"totpEnrollAge{age}" for age in SAMPLED_AGES_SECONDS],
)
IMMUTABLE_SUFFIXES = ("Uid",)
#: The only slot kind that can bring an account into existence.
CREATING_KINDS = ("sign-up",)
#: Slot kinds a refused start makes unsendable; the facade may skip exactly these.
SKIPPABLE_KINDS = ("mfa-signin-finalize",)
#: The recovery slots run in the walk's cleanup order, which is its creation order.
ROLE_ORDER = CLEANUP_ORDER
ANONYMOUS_ROLES = ("interaction-anonymous",)
UNVERIFIED_ROLES = ("interaction-unverified", "interaction-anonymous")


def _binding(name: str) -> str:
    return BINDING_PREFIX + name


def _camel(role: str) -> str:
    head, *rest = role.split("-")
    return head + "".join(part.capitalize() for part in rest)


def owned_email(nonce: str, role: str) -> str | None:
    if role in ANONYMOUS_ROLES:
        return None
    return f"o2-mfa-{role}-{nonce}@example.com"


def account_identifier(nonce: str, role: str) -> str:
    """The campaign-chosen identifier an owned account carries, known at plan time."""
    return f"o2-mfa-{role}-{nonce}"


def account_resource(project: str, nonce: str, role: str) -> str:
    return f"projects/{project}/auth/accounts/{account_identifier(nonce, role)}"


def config_resource(project: str) -> str:
    """The exclusive lock target the campaign's configuration step names."""
    return f"projects/{project}/auth/config"


def route_resources(project: str) -> list[str]:
    """The cleanup routes the base Gate requires among the job's resources."""
    return [
        f"{HOST}/v1/projects/{project}/accounts:delete",
        f"{HOST}/v1/projects/{project}/accounts:lookup",
    ]


def plan_path(walk_path: str) -> str:
    """The frozen slot path for a walk path: host plus path, no scheme, no key."""
    return HOST + walk_path


def _op(
    kind: str,
    path: str,
    body: Any,
    *,
    account: str | None,
    owner: bool = False,
    method: str = "POST",
    binds: dict[str, str] | None = None,
) -> dict[str, Any]:
    return {
        "service": "auth",
        "method": method,
        "path": plan_path(path),
        "body": body,
        "form": False,
        "owner": owner,
        "kind": kind,
        "account": account,
        "binds": dict(binds or {}),
    }


def _admin(rpc: str) -> str:
    return f"/v1/projects/{PROJECT}/accounts:{rpc}"


def _create_account(nonce: str, role: str) -> list[dict[str, Any]]:
    """What `Walk._account` sends: signup, then verification for a verified role."""
    name = _camel(role)
    email = owned_email(nonce, role)
    ops = [
        _op(
            "sign-up",
            "/v1/accounts:signUp",
            {"returnSecureToken": True}
            if email is None
            else {
                "email": email,
                "password": _binding("password"),
                "returnSecureToken": True,
            },
            account=role,
            binds={f"{name}Uid": "localId", f"{name}IdToken": "idToken"},
        )
    ]
    if role not in UNVERIFIED_ROLES:
        ops.append(
            _op(
                "admin-update",
                _admin("update"),
                {"localId": _binding(f"{name}Uid"), "emailVerified": True},
                account=role,
                owner=True,
            )
        )
        ops.append(_sign_in(nonce, role, binds={f"{name}IdToken": "idToken"}))
    return ops


def _sign_in(nonce: str, role: str, *, binds: dict[str, str]) -> dict[str, Any]:
    return _op(
        "sign-in",
        "/v1/accounts:signInWithPassword",
        {
            "email": owned_email(nonce, role),
            "password": _binding("password"),
            "returnSecureToken": True,
        },
        account=role,
        binds=binds,
    )


def _pending_sign_in(nonce: str, role: str) -> dict[str, Any]:
    name = _camel(role)
    return _sign_in(
        nonce,
        role,
        binds={
            f"{name}Pending": "mfaPendingCredential",
            f"{name}EnrollmentId": "mfaInfo.0.mfaEnrollmentId",
        },
    )


def _phone_enroll(role: str) -> list[dict[str, Any]]:
    name = _camel(role)
    return [
        _op(
            "mfa-enroll-start",
            "/v2/accounts/mfaEnrollment:start",
            {
                "idToken": _binding(f"{name}IdToken"),
                "phoneEnrollmentInfo": {
                    "phoneNumber": TEST_PHONE,
                    "recaptchaToken": RECAPTCHA_PLACEHOLDER,
                },
            },
            account=role,
            binds={f"{name}PhoneSession": "phoneSessionInfo.sessionInfo"},
        ),
        _op(
            "mfa-enroll-finalize",
            "/v2/accounts/mfaEnrollment:finalize",
            {
                "idToken": _binding(f"{name}IdToken"),
                "phoneVerificationInfo": {
                    "sessionInfo": _binding(f"{name}PhoneSession"),
                    "code": TEST_CODE,
                },
                "displayName": "campaign phone",
            },
            account=role,
        ),
    ]


def _phone_pending(nonce: str, role: str, *, enrolled: bool) -> list[dict[str, Any]]:
    return ([] if enrolled else _phone_enroll(role)) + [_pending_sign_in(nonce, role)]


def _totp_enroll_start(role: str) -> dict[str, Any]:
    name = _camel(role)
    return _op(
        "mfa-enroll-start",
        "/v2/accounts/mfaEnrollment:start",
        {"idToken": _binding(f"{name}IdToken"), "totpEnrollmentInfo": {}},
        account=role,
        binds={f"{name}TotpSession": "totpSessionInfo.sessionInfo"},
    )


def _phone_start(role: str, session_name: str) -> dict[str, Any]:
    name = _camel(role)
    return _op(
        "mfa-signin-start",
        "/v2/accounts/mfaSignIn:start",
        {
            "mfaPendingCredential": _binding(f"{name}Pending"),
            "mfaEnrollmentId": _binding(f"{name}EnrollmentId"),
            "phoneSignInInfo": {
                "phoneNumber": TEST_PHONE,
                "recaptchaToken": RECAPTCHA_PLACEHOLDER,
            },
        },
        account=role,
        binds={session_name: "phoneResponseInfo.sessionInfo"},
    )


def _phone_finalize(role: str, session_name: str) -> dict[str, Any]:
    name = _camel(role)
    return _op(
        "mfa-signin-finalize",
        "/v2/accounts/mfaSignIn:finalize",
        {
            "mfaPendingCredential": _binding(f"{name}Pending"),
            "phoneVerificationInfo": {
                "sessionInfo": _binding(session_name),
                "code": TEST_CODE,
            },
        },
        account=role,
    )


def _complete_phone_mfa(role: str, label: str) -> list[dict[str, Any]]:
    session = f"{_camel(role)}{label}Session"
    return [_phone_start(role, session), _phone_finalize(role, session)]


def _totp_finalize(
    role: str, code_name: str, display: str, *, binds: dict[str, str] | None = None
) -> dict[str, Any]:
    name = _camel(role)
    return _op(
        "mfa-enroll-finalize",
        "/v2/accounts/mfaEnrollment:finalize",
        {
            "idToken": _binding(f"{name}IdToken"),
            "totpVerificationInfo": {
                "sessionInfo": _binding(f"{name}TotpSession"),
                "verificationCode": _binding(code_name),
            },
            "displayName": display,
        },
        account=role,
        binds=binds,
    )


def observation_operations(nonce: str) -> list[dict[str, Any]]:
    """Every observation request the walk sends, in the order it sends them."""
    if not isinstance(nonce, str) or _NONCE.fullmatch(nonce) is None:
        raise ValueError("a 32-character hexadecimal nonce is required")
    ops: list[dict[str, Any]] = []
    # acquisition at the common origin
    ops += _create_account(nonce, "pending-control")
    for age in AGED_PENDING_SAMPLES:
        role = f"pending-age-{age}"
        ops += _create_account(nonce, role)
        ops += _phone_pending(nonce, role, enrolled=False)
    for age in SAMPLED_AGES_SECONDS:
        role = f"enrollment-age-{age}"
        ops += _create_account(nonce, role)
        ops.append(_totp_enroll_start(role))
    # baseline: the control enrolls its phone here, then completes fresh
    ops += _phone_pending(nonce, "pending-control", enrolled=False)
    ops += _complete_phone_mfa("pending-control", "Baseline")
    # the aged rows, in due order
    for age in AGED_PENDING_SAMPLES:
        role = f"pending-age-{age}"
        aged = f"{_camel(role)}AgedSession"
        ops.append(_phone_start(role, aged))
        ops.append(_phone_finalize(role, aged))
        ops.append(_pending_sign_in(nonce, role))
        ops += _complete_phone_mfa(role, "Fresh")
        if age in SAMPLED_AGES_SECONDS:
            ops.append(
                _totp_finalize(
                    f"enrollment-age-{age}", f"totpEnrollAge{age}", "aged totp"
                )
            )
    # final fresh control
    ops += _phone_pending(nonce, "pending-control", enrolled=True)
    ops += _complete_phone_mfa("pending-control", "Final")
    # TOTP lifecycle
    role = "totp-lifecycle"
    name = _camel(role)
    ops += _create_account(nonce, role)
    ops.append(_totp_enroll_start(role))
    ops.append(_totp_finalize(role, "totpWrong", "campaign totp"))
    ops.append(
        _totp_finalize(
            role,
            "totpRetry",
            "campaign totp",
            binds={f"{name}IdToken": "idToken", "totpEnrollmentId": "mfaEnrollmentId"},
        )
    )
    ops.append(_totp_finalize(role, "totpReplay", "campaign totp"))
    ops.append(
        _op(
            "lookup",
            "/v1/accounts:lookup",
            {"idToken": _binding(f"{name}IdToken")},
            account=role,
            binds={"totpEnrollmentId": "users.0.mfaInfo.0.mfaEnrollmentId"},
        )
    )
    ops.append(_totp_enroll_start(role) | {"binds": {}})
    ops.append(_pending_sign_in(nonce, role))
    ops.append(
        _op(
            "mfa-signin-start",
            "/v2/accounts/mfaSignIn:start",
            {
                "mfaPendingCredential": _binding(f"{name}Pending"),
                "mfaEnrollmentId": _binding("totpEnrollmentId"),
            },
            account=role,
        )
    )
    totp_sign_in = {
        "mfaPendingCredential": _binding(f"{name}Pending"),
        "mfaEnrollmentId": _binding("totpEnrollmentId"),
        "totpVerificationInfo": {"verificationCode": _binding("totpSignIn")},
    }
    ops.append(
        _op(
            "mfa-signin-finalize",
            "/v2/accounts/mfaSignIn:finalize",
            copy.deepcopy(totp_sign_in),
            account=role,
            binds={f"{name}IdToken": "idToken"},
        )
    )
    ops.append(_pending_sign_in(nonce, role))
    ops.append(
        _op(
            "mfa-signin-finalize",
            "/v2/accounts/mfaSignIn:finalize",
            copy.deepcopy(totp_sign_in),
            account=role,
        )
    )
    withdraw = {
        "idToken": _binding(f"{name}IdToken"),
        "mfaEnrollmentId": _binding("totpEnrollmentId"),
    }
    ops.append(
        _op(
            "mfa-withdraw",
            "/v2/accounts/mfaEnrollment:withdraw",
            copy.deepcopy(withdraw),
            account=role,
            binds={f"{name}IdToken": "idToken"},
        )
    )
    ops.append(
        _op(
            "lookup",
            "/v1/accounts:lookup",
            {"idToken": _binding(f"{name}IdToken")},
            account=role,
        )
    )
    ops.append(
        _op(
            "mfa-withdraw",
            "/v2/accounts/mfaEnrollment:withdraw",
            copy.deepcopy(withdraw),
            account=role,
        )
    )
    # interaction
    ops += _create_account(nonce, "interaction-unverified")
    ops.append(_totp_enroll_start("interaction-unverified") | {"binds": {}})
    ops += _create_account(nonce, "interaction-anonymous")
    ops.append(_totp_enroll_start("interaction-anonymous") | {"binds": {}})
    ops.append(
        _op(
            "mfa-enroll-start",
            "/v2/accounts/mfaEnrollment:start",
            {"totpEnrollmentInfo": {}},
            account=None,
        )
    )
    ops.append(
        _op(
            "config-readback", CONFIG_PATH, None, account=None, owner=True, method="GET"
        )
    )
    return ops


def recovery_operations(nonce: str) -> list[dict[str, Any]]:
    """Reconcile every email address before the ordered per-account cleanup."""
    reconcile = []
    cleanup = []
    for role in ROLE_ORDER:
        name = _camel(role)
        email = owned_email(nonce, role)
        if email is not None:
            reconcile.append(
                _op(
                    "address-reconcile",
                    _admin("lookup"),
                    {"email": [email]},
                    account=role,
                    owner=True,
                )
            )
        uid = _binding(f"{name}Uid")
        cleanup.append(
            _op("delete", _admin("delete"), {"localId": uid}, account=role, owner=True)
        )
        cleanup.append(
            _op(
                "uid-absence",
                _admin("lookup"),
                {"localId": [uid]},
                account=role,
                owner=True,
            )
        )
        if email is not None:
            cleanup.append(
                _op(
                    "address-absence",
                    _admin("lookup"),
                    {"email": [email]},
                    account=role,
                    owner=True,
                )
            )
    return reconcile + cleanup


def gate_plan(
    nonce: str,
    *,
    wall_seconds: int,
    recovery_seconds: int,
    cost_microusd: int,
    project: str = PROJECT,
    selector: str | None = None,
) -> dict[str, Any]:
    """Project the campaign onto the shared Gate schema for one nonce."""
    if project != PROJECT:
        raise ValueError("the campaign is fixed to the oracle project")
    if selector not in (None, "pending-age-300-v1"):
        raise ValueError("unsupported MFA selector")
    observation = observation_operations(nonce)
    recovery = recovery_operations(nonce)
    if selector == "pending-age-300-v1":
        observation = [
            operation
            for operation in observation
            if operation.get("account") == "pending-age-300"
        ]
        recovery = [
            operation
            for operation in recovery
            if operation.get("account") == "pending-age-300"
        ]
        if len(observation) != 11 or len(recovery) != 4:
            raise ValueError("selected MFA operation closure differs")
    roles = ("pending-age-300",) if selector == "pending-age-300-v1" else ROLE_ORDER
    account_bindings = {
        role: {
            "resource": account_resource(project, nonce, role),
            "uidBinding": f"{_camel(role)}Uid",
        }
        for role in roles
    }
    for operation in (*observation, *recovery):
        account = operation.get("account")
        if account is not None:
            binding = account_bindings[account]
            operation["resource"] = binding["resource"]
            operation["uidBinding"] = binding["uidBinding"]
    schedule = [
        {"phase": "observation", "index": index, "seconds": DATA_SLOT_SECONDS}
        | ({"creates": False} if _known_noncreating(operation) else {})
        for index, operation in enumerate(observation)
    ] + [
        {"phase": "recovery", "index": index, "seconds": DATA_SLOT_SECONDS}
        for index in range(len(recovery))
    ]

    def management(ids: tuple[str, ...]) -> list[dict[str, Any]]:
        return [
            {
                "id": item,
                "seconds": MANAGEMENT_SLOT_SECONDS,
                "duration": MANAGEMENT_DURATION_SECONDS,
                "timeout": MANAGEMENT_SLOT_SECONDS,
            }
            for item in ids
        ]

    return {
        "contract": CONTRACT,
        "campaignId": CAMPAIGN_ID,
        "nonce": nonce,
        **({"selector": selector} if selector is not None else {}),
        "project": project,
        "jobSlots": 1,
        "requestSeconds": DATA_SLOT_SECONDS,
        "wallSeconds": wall_seconds,
        "recoverySeconds": recovery_seconds,
        "intervalSeconds": GATE_INTERVAL_SECONDS,
        "observationRequests": len(observation) + len(MANAGEMENT_OBSERVATION_IDS),
        "dataRequests": len(observation) + len(recovery),
        "managementRequests": len(MANAGEMENT_OBSERVATION_IDS)
        + len(MANAGEMENT_RECOVERY_IDS),
        "requestCostMicrousd": REQUEST_COST_MICROUSD,
        "costMicrousd": cost_microusd,
        "receiptKind": "mfa-acquisition-receipt-v1",
        "plannedAccounts": list(roles),
        "accountResources": [
            account_resource(project, nonce, role) for role in roles
        ],
        "configResource": config_resource(project),
        "mintedBindings": list(MINTED_BINDINGS),
        "management": {
            "dispatchKind": "closed-v1",
            "observation": management(MANAGEMENT_OBSERVATION_IDS),
            "recovery": management(MANAGEMENT_RECOVERY_IDS),
            "credentialIds": ["oauth-tokeninfo"],
            "credentialSlots": ["tokeninfo"],
            "slotSeconds": MANAGEMENT_SLOT_SECONDS,
            "intervalSeconds": GATE_INTERVAL_SECONDS,
            "totalRequests": len(MANAGEMENT_OBSERVATION_IDS)
            + len(MANAGEMENT_RECOVERY_IDS),
            "observationWindowSeconds": wall_seconds - recovery_seconds,
            "recoveryWindowSeconds": recovery_seconds,
            "principalBinding": {
                "alternatives": [
                    ["clientId", "subject", "requiredScopes"],
                    ["clientId", "verifiedEmail", "requiredScopes"],
                ],
                "claims": [
                    "issued_to",
                    "audience",
                    "user_id",
                    "email",
                    "verified_email",
                    "scope",
                    "expires_in",
                ],
            },
            "permissionExpiryBound": True,
        },
        "jobs": {
            JOB: {
                "resources": [entry["resource"] for entry in account_bindings.values()],
                "accountBindings": account_bindings,
                "observation": observation,
                "recovery": recovery,
                "schedule": schedule,
            }
        },
    }
def _known_noncreating(operation: dict[str, Any]) -> bool:
    """Slots the base Gate itself knows cannot create: password sign-in and lookup."""
    return operation["kind"] in ("sign-in", "lookup")


# --- typed responses ------------------------------------------------------------------


def _process_alive(pid: int) -> bool:
    """Whether a recorded process still exists; the base Gate's own liveness test."""
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _text(value: Any) -> bool:
    return (
        isinstance(value, str) and bool(value) and not value.startswith(BINDING_PREFIX)
    )


def deleted_response(status: Any, body: Any) -> bool:
    return (
        type(status) is int
        and status == 200
        and isinstance(body, dict)
        and (body == {} or body == {"kind": "identitytoolkit#DeleteAccountResponse"})
    )


def absent_response(status: Any, body: Any) -> bool:
    """A 200 lookup with no result; a refusal never counts as absence."""
    if (
        type(status) is not int
        or status != 200
        or not isinstance(body, dict)
        or not body
    ):
        return False
    if set(body) - {"kind", "users"}:
        return False
    if "kind" in body and body["kind"] != "identitytoolkit#GetAccountInfoResponse":
        return False
    if "users" in body:
        return isinstance(body["users"], list) and body["users"] == []
    return body == {"kind": "identitytoolkit#GetAccountInfoResponse"}


def typed_refusal(status: Any, body: Any) -> bool:
    return (
        type(status) is int
        and 400 <= status <= 499
        and isinstance(body, dict)
        and isinstance(body.get("error"), dict)
    )


def _field(body: Any, path: str) -> Any:
    node = body
    for segment in path.split("."):
        if isinstance(node, dict):
            node = node.get(segment)
        elif isinstance(node, list) and segment.isdigit() and int(segment) < len(node):
            node = node[int(segment)]
        else:
            return None
    return node


# --- the facade -------------------------------------------------------------------------


def create(path: Path, plan: dict[str, Any]) -> None:
    """Create the Gate directory for one plan compiled by `gate_plan`."""
    if not isinstance(plan, dict) or set(plan.get("jobs", {})) != {JOB}:
        raise ValueError("closed MFA Gate plan required")
    frozen_create(path, plan)


class MfaGate(FrozenGate):
    """The shared Gate, with bindings and account evidence for this campaign."""

    def __init__(self, path: Path, job: str = JOB):
        super().__init__(path, job)
        if job != JOB:
            raise ValueError("closed MFA job required")
        plan = self.snapshot()["plan"]
        self.nonce = plan["nonce"]
        self.minted = set(plan.get("mintedBindings", []))
        self.bindings: dict[str, str] = {}
        self._observed: dict[str, str] = {}
        # The bound values are this run's credentials. They never enter the Gate
        # journal; they live beside it in a private file so a resumed process can
        # carry on admitting the slots that reference them.
        self._bindings_path = self.path.parent / BINDINGS_FILE
        self._load_bindings()

    def _load_bindings(self) -> None:
        path = self._bindings_path
        if path.is_symlink() or not path.exists():
            return
        info = path.stat()
        if info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise ValueError("private Gate bindings file required")
        loaded = json.loads(path.read_bytes())
        if not isinstance(loaded, dict) or set(loaded) != {"bindings", "observed"}:
            raise ValueError("private Gate bindings file malformed")
        self.bindings = dict(loaded["bindings"])
        self._observed = dict(loaded["observed"])

    def _save_bindings(self) -> None:
        """Write the private bindings file so a reader never observes a partial one.

        Same shape and reason as `mfa_config_lock._private_write` and
        `mfa_production._write_private`: a truncate-then-write in place leaves a
        zero-byte file for a stop between the truncate and the write, and
        `_load_bindings` reads this file whole to resume the run's observed and
        minted values. A freshly created, uniquely named temporary file in the
        same directory, fsynced and renamed onto the target, keeps a reader from
        ever observing anything but the previous or the new complete record.
        """
        encoded = json.dumps(
            {"bindings": self.bindings, "observed": self._observed}, sort_keys=True
        ).encode()
        fd, temporary = tempfile.mkstemp(
            prefix=f".{self._bindings_path.name}.", dir=self._bindings_path.parent
        )
        replaced = False
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self._bindings_path)
            replaced = True
        finally:
            if not replaced:
                try:
                    os.unlink(temporary)
                except FileNotFoundError:
                    pass
        directory = os.open(self._bindings_path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)

    # --- adoption across processes ---

    def adopt(self) -> dict[str, Any]:
        """Re-pin the Gate's coordinator and job to this process.

        The shared Gate pins the coordinator and job process ids at `claim()` and
        refuses every later dispatch from another process. Adoption is admitted
        only when the recorded processes are gone (the liveness test the base
        Gate's no-data abort makes) and the Gate's monotonic clock still runs
        forward from the recorded start. That clock check is necessary, not
        sufficient: a reboot whose uptime already exceeds the previous one passes
        it, and the Gate's own phase deadline (`started + wallSeconds`) is then the
        backstop that refuses every dispatch, so the run fails closed.

        A request the dead process left in flight is settled here, because no
        answer can arrive for it any more: a creating slot becomes `unknown` and
        is discovered by the address readback, any other slot is recorded as
        interrupted, and an in-flight management slot is recorded as failed. A
        live process with a request in flight is refused. Every adoption is
        journaled in the Gate state.
        """
        with self.locked() as state:
            job = state["jobs"][self.job]
            recorded = [state["coordinatorPid"], job["pid"]]
            if state.get("noDataAbort") is not None:
                raise ValueError("terminal Gate abort")
            if any(pid is None for pid in recorded):
                raise ValueError("adoption refused: the job was never claimed")
            now = time.monotonic()
            if state["started"] > now or state["lastSent"] > now:
                raise ValueError("adoption refused: the Gate clock predates this boot")
            me = os.getpid()
            for pid in recorded:
                if pid != me and _process_alive(pid):
                    raise ValueError(f"adoption refused: process {pid} is still alive")
            if me in recorded and (state["coordinatorInflight"] or job["inflight"]):
                raise ValueError("adoption refused: a request is in flight")
            settled = self._settle_inflight(state, job)
            state["coordinatorPid"] = me
            job["pid"] = me
            record = {
                "from": recorded,
                "to": me,
                "at": time.time(),
                "settledInflight": settled,
            }
            state.setdefault("adoptions", []).append(record)
            _save(self.path, state)
            return record

    def _settle_inflight(self, state, job) -> list[dict[str, Any]]:
        """Close what a proven-dead process left open; the answer is unknowable."""
        settled = []
        recipe = state["plan"]["jobs"][self.job]
        if job["inflight"]:
            for event in reversed(state["events"]):
                if event.get("job") == self.job and not event.get("completed"):
                    operation = recipe[event["phase"]][event["index"]]
                    if (
                        event.get("phase") == "observation"
                        and operation["kind"] in CREATING_KINDS
                    ):
                        event["creationOutcome"] = "unknown"
                    event["failure"] = event.get("failure") or "InterruptedByDeath"
                    event["ended"] = time.monotonic()
                    settled.append(
                        {
                            "phase": event["phase"],
                            "index": event["index"],
                            "kind": operation["kind"],
                        }
                    )
                    break
            job["inflight"] = False
        if state["coordinatorInflight"]:
            for event in reversed(state["managementEvents"]):
                if not event.get("completed"):
                    event["failure"] = event.get("failure") or "InterruptedByDeath"
                    event["ended"] = time.monotonic()
                    settled.append({"management": event["id"]})
                    break
            state["coordinatorInflight"] = False
        return settled

    def unsettled_accounts(self) -> list[str]:
        """Roles whose signup was sent and whose answer never settled it."""
        state = self.snapshot()
        recipe = state["plan"]["jobs"][self.job]["observation"]
        return [
            recipe[event["index"]]["account"]
            for event in state["events"]
            if event.get("job") == self.job
            and event.get("phase") == "observation"
            and recipe[event["index"]]["kind"] in CREATING_KINDS
            and event.get("settlementOutcome") not in {"present", "absent"}
            and event.get("creationOutcome") in ("pending", "unknown")
        ]

    def settle_creation(self, role: str, uid: str | None, *, evidence: dict) -> None:
        """Settle a signup whose answer was lost, from a later owner readback.

        `uid` is the account the readback found under the role's nonce-derived
        address, or None when it found nothing. Found means created and owned;
        not found means the request never took effect. The readback body is kept
        as the evidence of the settlement, and the role's UID binding is recorded
        so its cleanup slots resolve.
        """
        raise ValueError("direct account settlement is not permitted")

    def _reconcile_uid(self, operation, status, body):
        if type(status) is not int or status != 200 or not isinstance(body, dict):
            raise ValueError("typed address reconciliation response required")
        if set(body) == {"kind"}:
            if body["kind"] != "identitytoolkit#GetAccountInfoResponse":
                raise ValueError("typed address reconciliation response required")
            return None
        if "kind" in body and body["kind"] != "identitytoolkit#GetAccountInfoResponse":
            raise ValueError("typed address reconciliation response required")
        if set(body) - {"kind", "users"} or not isinstance(body.get("users"), list):
            raise ValueError("typed address reconciliation response required")
        email = owned_email(self.nonce, operation["account"])
        users = body["users"]
        if not users:
            return None
        if len(users) != 1 or not isinstance(users[0], dict):
            raise ValueError("unique address reconciliation result required")
        user = users[0]
        uid = user.get("localId")
        if user.get("email") != email or not _text(uid) or len(uid) > 128:
            raise ValueError("address reconciliation identity differs")
        # An address readback selects an account but does not prove that this run
        # created it. Ownership is established only by the Gate's acknowledged UID
        # checkpoint, so email-only presence must remain held.
        return {"uid": uid, "ownership": "email-only-unproven"}

    def settle_reconciled_creation(self, role: str) -> dict[str, Any]:
        """Settle one pending signup from its frozen reconciliation event only."""
        with self.locked() as state:
            job = state["jobs"][self.job]
            recipe = state["plan"]["jobs"][self.job]["observation"]
            events = [
                event
                for event in state["events"]
                if event.get("job") == self.job
                and event.get("phase") == "observation"
            and recipe[event["index"]]["kind"] in CREATING_KINDS
            and recipe[event["index"]]["account"] == role
            and event.get("settlementOutcome") not in {"present", "absent"}
            ]
            if len(events) != 1 or events[0].get("creationOutcome") not in (
                "pending",
                "unknown",
            ):
                raise ValueError("no unsettled signup for this account")
            event = events[0]
            recovery_recipe = state["plan"]["jobs"][self.job]["recovery"]
            reconcile_events = [
                item
                for item in state["events"]
                if item.get("job") == self.job
                and item.get("phase") == "recovery"
                and item.get("completed") is True
                and recovery_recipe[item["index"]].get("kind") == "address-reconcile"
                and recovery_recipe[item["index"]].get("account") == role
            ]
            if len(reconcile_events) != 1:
                raise ValueError("frozen address reconciliation event required")
            reconcile = reconcile_events[0]
            evidence = reconcile.get("authEvidence")
            if not isinstance(evidence, dict) or evidence.get("account") != role:
                raise ValueError("address reconciliation evidence differs")
            uid = evidence.get("uid")
            accounts = job.setdefault("authAccounts", {})
            if role in accounts:
                raise ValueError("an owned account was created twice")
            if uid is None:
                event["settlementOutcome"] = "absent"
                event["settledBy"] = {
                    "kind": "address-readback-absent",
                    "responseDigest": reconcile.get("responseDigest"),
                }
            elif evidence.get("ownership") != "acknowledged":
                event["settlementOutcome"] = "present-unproven"
                event["settledBy"] = {
                    "kind": "address-readback-present-unproven",
                    "responseDigest": reconcile.get("responseDigest"),
                }
                _save(self.path, state)
                return {"role": role, "uid": uid, "adopted": False, "held": True}
            else:
                if not _text(uid) or len(uid) > 128:
                    raise ValueError("typed account identity required")
                position = state["events"].index(event)
                create_operation = recipe[event["index"]]
                accounts[role] = {
                    "uid": uid,
                    "createEvent": position,
                    "adopted": True,
                    "resource": create_operation.get("resource"),
                    "reconcileEvent": state["events"].index(reconcile),
                }
                # Settlement is separate from the lost wire outcome: failure,
                # completion and response digest stay intact.
                event["settlementOutcome"] = "present"
                event["settledBy"] = {
                    "kind": "address-readback-present",
                    "responseDigest": reconcile.get("responseDigest"),
                }
                name = _camel(role) + "Uid"
                if name in self._observed and self._observed[name] != uid:
                    raise ValueError("account identity binding is immutable")
                self._observed[name] = uid
                self.bindings[name] = uid
                self._save_bindings()
            _save(self.path, state)
            return {"role": role, "uid": uid}

    # --- slot resolution ---

    def next_operation(self, recovery: bool) -> dict[str, Any] | None:
        state = self.snapshot()
        phase = "recovery" if recovery else "observation"
        job = state["jobs"][self.job]
        operations = state["plan"]["jobs"][self.job][phase]
        index = job[phase]
        if index >= len(operations):
            return None
        return copy.deepcopy(operations[index])

    def _bind_minted(self, name: str, value: Any) -> None:
        if name not in self.minted or not _text(value) or len(value) > 8192:
            raise ValueError("runtime binding differs from the frozen slot")
        self.bindings[name] = value

    def _resolve(self, value: Any, declared: Any) -> None:
        if isinstance(declared, str) and declared.startswith(BINDING_PREFIX):
            name = declared.removeprefix(BINDING_PREFIX)
            if name in self.bindings:
                if type(value) is not str or value != self.bindings[name]:
                    raise ValueError("runtime binding differs from the frozen slot")
                return
            if name in self._observed:
                if type(value) is not str or value != self._observed[name]:
                    raise ValueError("runtime binding differs from the frozen slot")
                self.bindings[name] = value
                return
            self._bind_minted(name, value)
            return
        if isinstance(declared, dict):
            if not isinstance(value, dict) or set(value) != set(declared):
                raise ValueError("request outside closed scenario")
            for key, item in declared.items():
                self._resolve(value[key], item)
            return
        if isinstance(declared, list):
            if not isinstance(value, list) or len(value) != len(declared):
                raise ValueError("request outside closed scenario")
            for item, expected in zip(value, declared, strict=True):
                self._resolve(item, expected)
            return
        if json.dumps(value, sort_keys=True) != json.dumps(declared, sort_keys=True):
            raise ValueError("request outside closed scenario")

    def dispatch_runtime(
        self, path: str, body: Any, *, owner: bool, recovery: bool, send: Any
    ) -> Any:
        """Admit the walk's next request against its frozen slot, then send.

        In recovery, slots for accounts this run never created are consumed as
        zero-wire skips first, so the cleanup of the accounts that do exist stays
        reachable in its declared order.
        """
        if recovery:
            self._skip_uncreated_recovery()
        declared = self.next_operation(recovery)
        if declared is None:
            raise ValueError("scenario request capacity")
        method = "GET" if body is None else "POST"
        if (
            plan_path(path) != declared["path"]
            or bool(owner) != declared["owner"]
            or method != declared["method"]
        ):
            raise ValueError("request outside closed scenario")
        self._resolve(body, declared["body"])
        self._save_bindings()
        return super().dispatch(declared, recovery, send)

    def skip_planned(self, reason: str, *, recovery: bool = False) -> dict[str, Any]:
        """Consume the next slot without a wire send: a finalize whose start was refused."""
        declared = self.next_operation(recovery)
        if declared is None:
            raise ValueError("scenario request capacity")
        if declared["kind"] not in SKIPPABLE_KINDS:
            raise ValueError("only a finalize behind a refused start can be skipped")
        return self._skip_slot(recovery, declared, reason)

    def _skip_uncreated_recovery(self) -> None:
        unsettled = set(self.unsettled_accounts())
        while True:
            declared = self.next_operation(True)
            if declared is None:
                return
            accounts = self.snapshot()["jobs"][self.job].get("authAccounts", {})
            if declared["account"] in accounts:
                if declared["kind"] == "address-reconcile":
                    self._skip_slot(True, declared, "signup already settled")
                    continue
                return
            if declared["account"] in unsettled:
                # Only the frozen address-reconcile slot may settle it.
                if declared["kind"] == "address-reconcile":
                    return
                raise ValueError("unsettled signup must be discovered before cleanup")
            self._skip_slot(True, declared, "account never created")

    def drain_recovery(self) -> int:
        """Skip every remaining recovery slot of an account this run never created."""
        skipped = 0
        unsettled = set(self.unsettled_accounts())
        while True:
            declared = self.next_operation(True)
            if declared is None:
                return skipped
            accounts = self.snapshot()["jobs"][self.job].get("authAccounts", {})
            if declared["account"] in accounts or declared["account"] in unsettled:
                return skipped
            self._skip_slot(True, declared, "account never created")
            skipped += 1

    def _skip_slot(
        self, recovery: bool, declared: dict[str, Any], note: str
    ) -> dict[str, Any]:
        """The base Gate's zero-wire skip accounting, under this facade's creates rule."""
        if not isinstance(note, str) or not 0 < len(note) <= 128:
            raise ValueError("bounded skip reason required")
        if declared["kind"] in CREATING_KINDS:
            raise ValueError("a slot that could create an account cannot be skipped")
        with self.locked() as state:
            job, plan = state["jobs"][self.job], state["plan"]
            phase = "recovery" if recovery else "observation"
            schedule = job_schedule(plan["jobs"][self.job])
            if (
                job["pid"] is None
                or job["complete"]
                or job["inflight"]
                or state.get("noDataAbort") is not None
            ):
                raise ValueError("job or environment stopped/uncertain")
            index = job[phase]
            cursor = job["scheduleDone"]
            if job.get("stopReason") is not None:
                while (
                    cursor < len(schedule)
                    and schedule[cursor]["phase"] == "observation"
                ):
                    cursor += 1
                    job["skippedByStop"] += 1
                job["scheduleDone"] = cursor
            slot = schedule[cursor] if cursor < len(schedule) else None
            if slot is None or slot["phase"] != phase or slot["index"] != index:
                raise ValueError("dispatch outside the frozen execution schedule")
            if digest(plan["jobs"][self.job][phase][index]) != digest(declared):
                raise ValueError("request outside closed scenario")
            job["scheduleDone"] += 1
            job[phase] += 1
            if recovery:
                state["reservedRecovery"] -= 1
            state.setdefault("skips", []).append(
                {
                    "job": self.job,
                    "index": index,
                    "reason": ZERO_WIRE_REASON,
                    "note": note,
                    "phase": phase,
                }
            )
            _save(self.path, state)
            return {"skipped": ZERO_WIRE_REASON, "note": note}

    # --- evidence ---

    def _record_response(self, state, operation, recovery, event, status, body):
        job = state["jobs"][self.job]
        try:
            self._record_auth_response(state, operation, recovery, event, status, body)
        except ValueError:
            job["stopped"] = True
            event["failure"] = "InvalidMfaCampaignResponse"
            raise

    def _record_auth_response(self, state, operation, recovery, event, status, body):
        job = state["jobs"][self.job]
        accounts = job.setdefault("authAccounts", {})
        kind, account = operation["kind"], operation.get("account")
        position = len(state["events"]) - 1
        for name, field in operation.get("binds", {}).items():
            value = _field(body, field) if status == 200 else None
            if not _text(value) or len(value) > 8192:
                continue
            immutable = name.endswith(IMMUTABLE_SUFFIXES)
            if immutable and name in self._observed and self._observed[name] != value:
                raise ValueError("account identity binding is immutable")
            self._observed[name] = value
            if name in self.bindings and not immutable:
                self.bindings[name] = value
        self._save_bindings()
        evidence: dict[str, Any] = {"kind": kind, "account": account, "status": status}
        if recovery and kind == "address-reconcile":
            reconciliation = self._reconcile_uid(operation, status, body)
            uid = reconciliation["uid"] if reconciliation is not None else None
            evidence.update(uid=uid, email=owned_email(self.nonce, account))
            if reconciliation is not None:
                evidence["ownership"] = reconciliation["ownership"]
            evidence["responseDigest"] = event["responseDigest"]
            event["authEvidence"] = evidence
            return
        if not recovery:
            outcome = "refused"
            if kind in CREATING_KINDS:
                uid = body.get("localId") if isinstance(body, dict) else None
                created = (
                    status == 200
                    and isinstance(body, dict)
                    and "error" not in body
                    and _text(uid)
                    and len(uid) <= 128
                    and _text(body.get("idToken"))
                )
                if created:
                    if account in accounts:
                        raise ValueError("an owned account was created twice")
                    accounts[account] = {
                        "uid": uid,
                        "createEvent": position,
                        "resource": operation.get("resource"),
                    }
                    outcome = "created"
                    evidence["uid"] = uid
                elif not typed_refusal(status, body):
                    outcome = "unknown"
            elif status is None or (type(status) is int and status >= 500):
                outcome = "refused"
            if "creationOutcome" in event:
                event["creationOutcome"] = outcome
            evidence["creationOutcome"] = outcome
        else:
            record = accounts.get(account)
            if record is None:
                raise ValueError("cleanup of an account this run never created")
            if kind == "delete":
                record["deleteEvent"] = position
                record["deleted"] = deleted_response(status, body)
            elif kind == "uid-absence":
                if "deleteEvent" not in record:
                    raise ValueError("absence readback before deletion")
                record["absenceEvent"] = position
                record["uidAbsent"] = absent_response(status, body)
            elif kind == "address-absence":
                if "absenceEvent" not in record:
                    raise ValueError("address readback before the UID readback")
                record["addressAbsenceEvent"] = position
                record["addressAbsent"] = absent_response(status, body)
            else:
                raise ValueError("unsupported cleanup operation")
            evidence["body"] = copy.deepcopy(body)
            evidence["responseDigest"] = event["responseDigest"]
            if self._all_accounts_absent(state):
                for resource in job["resources"]:
                    if resource not in job["absent"]:
                        job["absent"].append(resource)
        event["authEvidence"] = evidence

    def _expected_accounts(self, state) -> dict[str, bool]:
        recipe = state["plan"]["jobs"][self.job]["recovery"]
        return {
            op["account"]: any(
                other["kind"] == "address-absence" and other["account"] == op["account"]
                for other in recipe
            )
            for op in recipe
            if op["kind"] == "delete"
        }

    def _all_accounts_absent(self, state) -> bool:
        """Every created account deleted and read back absent by UID and by address."""
        accounts = state["jobs"][self.job].get("authAccounts", {})
        expected = self._expected_accounts(state)
        if not accounts or any(name not in expected for name in accounts):
            return False
        return all(
            record.get("uidAbsent") is True
            and (not expected[name] or record.get("addressAbsent") is True)
            for name, record in accounts.items()
        )

    def _validate_finish_evidence(self, state):
        job = state["jobs"][self.job]
        accounts = job.get("authAccounts", {})
        if not self._all_accounts_absent(state):
            raise ValueError("account cleanup evidence incomplete")
        if len({record["uid"] for record in accounts.values()}) != len(accounts):
            raise ValueError("account identities collide")
        expected = self._expected_accounts(state)
        for name, record in accounts.items():
            order = [
                record["createEvent"],
                record["deleteEvent"],
                record["absenceEvent"],
            ]
            if expected[name]:
                order.append(record["addressAbsenceEvent"])
            if order != sorted(order) or len(set(order)) != len(order):
                raise ValueError("account cleanup event order differs")
            create_event = state["events"][record["createEvent"]]
            cleanup_events = order[1:]
            if record.get("adopted"):
                # The signup's answer was lost; the settlement readback stands in
                # for the missing acknowledgement and the event says so.
                if create_event.get("job") != self.job or not isinstance(
                    create_event.get("settledBy"), dict
                ):
                    raise ValueError("adopted account evidence binding differs")
                checked = cleanup_events
            else:
                checked = order
            for position in checked:
                event = state["events"][position]
                if (
                    event.get("job") != self.job
                    or event.get("completed") is not True
                    or event.get("failure") is not None
                    or not isinstance(event.get("authEvidence"), dict)
                    or event["authEvidence"].get("account") != name
                ):
                    raise ValueError("account evidence binding differs")
            if not (
                create_event.get("creationOutcome") == "created"
                or (
                    record.get("adopted")
                    and create_event.get("settlementOutcome") == "present"
                )
            ):
                raise ValueError("account creation event differs")
            for position in cleanup_events:
                event = state["events"][position]
                if (
                    event.get("phase") != "recovery"
                    or event["authEvidence"].get("responseDigest")
                    != digest(event["authEvidence"].get("body"))
                    or event.get("responseDigest")
                    != event["authEvidence"]["responseDigest"]
                ):
                    raise ValueError("account cleanup response differs")
        super()._validate_finish_evidence(state)


def account_evidence(snapshot: dict[str, Any]) -> dict[str, Any]:
    """The publishable account evidence of a Gate snapshot: counts, never identifiers."""
    job = snapshot["jobs"][JOB]
    accounts = job.get("authAccounts", {})
    recipe = snapshot["plan"]["jobs"][JOB]["observation"]
    unsettled = sum(
        1
        for event in snapshot["events"]
        if event.get("job") == JOB
        and event.get("phase") == "observation"
        and recipe[event["index"]]["kind"] in CREATING_KINDS
        and event.get("creationOutcome") in ("pending", "unknown")
        and event.get("settlementOutcome") not in {"present", "absent"}
    )
    return {
        "plannedAccounts": len(snapshot["plan"]["plannedAccounts"]),
        "createdAccounts": len(accounts),
        "unsettledSignups": unsettled,
        "deletedAccounts": sum(a.get("deleted") is True for a in accounts.values()),
        "uidAbsenceReadbacks": sum(
            a.get("uidAbsent") is True for a in accounts.values()
        ),
        "addressAbsenceReadbacks": sum(
            a.get("addressAbsent") is True for a in accounts.values()
        ),
        "routesAbsent": sorted(job["absent"]),
        "skips": len(snapshot.get("skips", [])),
        "complete": job["complete"],
    }


__all__ = [
    "CONTRACT",
    "DATA_SLOT_SECONDS",
    "JOB",
    "MANAGEMENT_OBSERVATION_IDS",
    "MANAGEMENT_RECOVERY_IDS",
    "MINTED_BINDINGS",
    "ROLE_ORDER",
    "MfaGate",
    "account_evidence",
    "account_resource",
    "config_resource",
    "create",
    "gate_plan",
    "observation_operations",
    "owned_accounts",
    "plan_path",
    "recovery_operations",
    "route_resources",
]
