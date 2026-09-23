"""Compile revision-3 recorder requests into the shared Auth Gate schema.

The plan is a complete worst-case slot schedule. Conditional branches retain a
typed slot and declare the recorder fact that permits its zero-wire skip.
"""

from __future__ import annotations

import re
from typing import Any

import window_recorder
from rev3_projection import (
    CAMPAIGN_ID,
    CASES_SHA256,
    MAX_ACCOUNTS,
    MAX_AUTH_REQUESTS,
    OBSERVATION_AUTH_LIMIT,
    RECOVERY_AUTH_RESERVE,
    RECOVERY_SECONDS,
    SELECTOR,
    WALL_SECONDS,
    recovery_auth_requests,
    validate_budget,
    validate_selection,
)
from window_contract import CASES, TEST_PHONE

CONTRACT = "shared-local-v1"
JOB = "auth-pending-rev3"
HOST = "identitytoolkit.googleapis.com"
GATE_INTERVAL_SECONDS = 0.25
DATA_SLOT_SECONDS = 5.0
MANAGEMENT_SLOT_SECONDS = 13.0
MANAGEMENT_DURATION_SECONDS = 12.0
MANAGEMENT_OBSERVATION_IDS = (
    "oauth-tokeninfo",
    "auth-project-read",
    "auth-config-preflight-read",
    "auth-config-baseline-read",
    "auth-config-apply",
    "auth-config-apply-readback",
)
MANAGEMENT_RECOVERY_IDS = (
    "auth-config-restore",
    "auth-config-restore-readback",
)
_NONCE = re.compile(r"^[0-9a-f]{32}$")
_BINDING_PREFIX = "$binding:"
_ROLES = ("baseline", "age-300", "age-450", "age-600", "final")
_AGES = (300, 450, 600)


def _binding(name: str) -> str:
    return _BINDING_PREFIX + name


def _camel(role: str) -> str:
    head, *tail = role.split("-")
    return head + "".join(part.capitalize() for part in tail)


def _uid_binding(role: str) -> str:
    return _camel(role) + "Uid"


def _account_resource(project: str, nonce: str, role: str) -> str:
    return f"projects/{project}/auth/accounts/pending-rev3-{role}-{nonce}"


def _path(value: str) -> str:
    return HOST + value


def _admin_path(project: str, action: str) -> str:
    return _path(f"/v1/projects/{project}/accounts:{action}")


def _operation(
    slot_id: str,
    kind: str,
    path: str,
    body: dict[str, Any],
    role: str,
    *,
    owner: bool = False,
    binds: dict[str, str] | None = None,
    skip_when: str | None = None,
) -> dict[str, Any]:
    operation = {
        "slotId": slot_id,
        "service": "auth",
        "method": "POST",
        "path": path,
        "body": body,
        "form": False,
        "owner": owner,
        "kind": kind,
        "account": role,
        "uidBinding": _uid_binding(role),
        "binds": dict(binds or {}),
    }
    if skip_when is not None:
        operation["skipWhen"] = skip_when
    return operation


def _account_setup(role: str) -> list[dict[str, Any]]:
    name = _camel(role)
    email = _binding(name + "Email")
    password = _binding(name + "Password")
    marker = _binding(name + "Marker")
    uid = _binding(_uid_binding(role))
    return [
        _operation(
            f"setup:{role}:email-absence",
            "admin-lookup",
            _admin_path(window_recorder.PROJECT, "lookup"),
            {"email": [email]},
            role,
            owner=True,
        ),
        _operation(
            f"setup:{role}:sign-up",
            "sign-up",
            _path("/v1/accounts:signUp"),
            {
                "email": email,
                "password": password,
                "displayName": marker,
                "returnSecureToken": True,
            },
            role,
            binds={_uid_binding(role): "localId"},
        ),
        _operation(
            f"setup:{role}:email-readback",
            "admin-lookup",
            _admin_path(window_recorder.PROJECT, "lookup"),
            {"email": [email]},
            role,
            owner=True,
        ),
        _operation(
            f"setup:{role}:enable-mfa",
            "admin-update",
            _admin_path(window_recorder.PROJECT, "update"),
            {
                "localId": uid,
                "emailVerified": True,
                "mfa": {"enrollments": [{"phoneInfo": TEST_PHONE}]},
            },
            role,
            owner=True,
        ),
        _operation(
            f"setup:{role}:state-readback",
            "admin-lookup",
            _admin_path(window_recorder.PROJECT, "lookup"),
            {"localId": [uid]},
            role,
            owner=True,
            binds={name + "EnrollmentId": "users.0.mfaInfo.0.mfaEnrollmentId"},
        ),
    ]


def _pending(role: str, slot_id: str, binding_name: str) -> dict[str, Any]:
    name = _camel(role)
    return _operation(
        slot_id,
        "sign-in",
        _path("/v1/accounts:signInWithPassword"),
        {
            "email": _binding(name + "Email"),
            "password": _binding(name + "Password"),
            "returnSecureToken": True,
        },
        role,
        binds={
            binding_name: "mfaPendingCredential",
            name + "EnrollmentId": "mfaInfo.0.mfaEnrollmentId",
        },
    )


def _start(
    role: str,
    slot_id: str,
    pending_binding: str,
    session_binding: str,
    *,
    skip_when: str | None = None,
) -> dict[str, Any]:
    name = _camel(role)
    return _operation(
        slot_id,
        "mfa-signin-start",
        _path("/v2/accounts/mfaSignIn:start"),
        {
            "mfaPendingCredential": _binding(pending_binding),
            "mfaEnrollmentId": _binding(name + "EnrollmentId"),
            "phoneSignInInfo": {
                "phoneNumber": TEST_PHONE,
                "recaptchaToken": "fireemu-test-phone-number",
            },
        },
        role,
        binds={session_binding: "phoneResponseInfo.sessionInfo"},
        skip_when=skip_when,
    )


def _finalize(
    role: str,
    slot_id: str,
    pending_binding: str,
    session_binding: str,
    token_binding: str,
    *,
    skip_when: str | None = None,
) -> dict[str, Any]:
    return _operation(
        slot_id,
        "mfa-signin-finalize",
        _path("/v2/accounts/mfaSignIn:finalize"),
        {
            "mfaPendingCredential": _binding(pending_binding),
            "phoneVerificationInfo": {
                "sessionInfo": _binding(session_binding),
                "code": _binding("testCode"),
            },
        },
        role,
        binds={token_binding: "idToken"},
        skip_when=skip_when,
    )


def _client_lookup(
    role: str,
    slot_id: str,
    token_binding: str,
    *,
    skip_when: str | None = None,
) -> dict[str, Any]:
    return _operation(
        slot_id,
        "lookup",
        _path("/v1/accounts:lookup"),
        {"idToken": _binding(token_binding)},
        role,
        skip_when=skip_when,
    )


def _fresh_control(role: str, label: str) -> list[dict[str, Any]]:
    name = _camel(role)
    pending = name + label + "Pending"
    session = name + label + "Session"
    token = name + label + "IdToken"
    return [
        _pending(role, f"{label}:pending", pending),
        _start(role, f"{label}:start", pending, session),
        _finalize(role, f"{label}:finalize", pending, session, token),
        _client_lookup(role, f"{label}:derived-lookup", token),
    ]


def _age_slots(age: int) -> list[dict[str, Any]]:
    role = f"age-{age}"
    name = _camel(role)
    old_pending = name + "HeldPending"
    old_session = name + "AgedSession"
    old_token = name + "AgedIdToken"
    fresh_pending = name + "FreshPending"
    fresh_session = name + "FreshSession"
    fresh_token = name + "FreshIdToken"
    return [
        _start(role, f"age-{age}:start", old_pending, old_session),
        _finalize(
            role,
            f"age-{age}:finalize",
            old_pending,
            old_session,
            old_token,
            skip_when="aged-start-refused-or-session-missing",
        ),
        _client_lookup(
            role,
            f"age-{age}:derived-lookup",
            old_token,
            skip_when="aged-finalize-not-accepted",
        ),
        _operation(
            f"age-{age}:post-refusal-state",
            "admin-lookup",
            _admin_path(window_recorder.PROJECT, "lookup"),
            {"localId": [_binding(_uid_binding(role))]},
            role,
            owner=True,
            skip_when="aged-attempt-not-refused",
        ),
        _pending(
            role,
            f"age-{age}:post-refusal-fresh-pending",
            fresh_pending,
        )
        | {"skipWhen": "aged-attempt-not-refused-or-state-readback-failed"},
        _start(
            role,
            f"age-{age}:post-refusal-fresh-start",
            fresh_pending,
            fresh_session,
            skip_when="aged-attempt-not-refused-or-state-readback-failed",
        ),
        _finalize(
            role,
            f"age-{age}:post-refusal-fresh-finalize",
            fresh_pending,
            fresh_session,
            fresh_token,
            skip_when=(
                "aged-attempt-not-refused-or-state-readback-failed-or-"
                "fresh-start-refused-or-session-missing"
            ),
        ),
        _client_lookup(
            role,
            f"age-{age}:post-refusal-fresh-derived-lookup",
            fresh_token,
            skip_when=(
                "aged-attempt-not-refused-or-state-readback-failed-or-"
                "fresh-start-refused-or-session-missing-or-"
                "fresh-finalize-not-accepted"
            ),
        ),
    ]


def _recovery_slots(role: str) -> list[dict[str, Any]]:
    email = _binding(_camel(role) + "Email")
    uid = _binding(_uid_binding(role))
    return [
        _operation(
            f"recovery:{role}:address-reconcile",
            "address-reconcile",
            _admin_path(window_recorder.PROJECT, "lookup"),
            {"email": [email]},
            role,
            owner=True,
        ),
        _operation(
            f"recovery:{role}:uid-reconcile",
            "uid-reconcile",
            _admin_path(window_recorder.PROJECT, "lookup"),
            {"localId": [uid]},
            role,
            owner=True,
        ),
        _operation(
            f"recovery:{role}:delete",
            "delete",
            _admin_path(window_recorder.PROJECT, "delete"),
            {"localId": uid},
            role,
            owner=True,
        ),
        _operation(
            f"recovery:{role}:address-absence",
            "address-absence",
            _admin_path(window_recorder.PROJECT, "lookup"),
            {"email": [email]},
            role,
            owner=True,
        ),
        _operation(
            f"recovery:{role}:uid-absence",
            "uid-absence",
            _admin_path(window_recorder.PROJECT, "lookup"),
            {"localId": [uid]},
            role,
            owner=True,
        ),
    ]


def _management_slots(ids: tuple[str, ...]) -> list[dict[str, Any]]:
    return [
        {
            "id": slot_id,
            "seconds": MANAGEMENT_SLOT_SECONDS,
            "duration": MANAGEMENT_DURATION_SECONDS,
            "timeout": MANAGEMENT_SLOT_SECONDS,
        }
        for slot_id in ids
    ]


def compile_gate_plan(
    nonce: str,
    *,
    selector: str = SELECTOR,
    cases: tuple[str, ...] = CASES,
    campaign_id: str = CAMPAIGN_ID,
    wall_seconds: int = WALL_SECONDS,
    recovery_seconds: int = RECOVERY_SECONDS,
    max_observation_seconds: int = 1200,
) -> dict[str, Any]:
    """Build one frozen Gate plan; no permission, credential, or Ledger I/O occurs."""
    validate_budget()
    validate_selection(selector, cases)
    if not isinstance(nonce, str) or _NONCE.fullmatch(nonce) is None:
        raise ValueError("fresh 32-character hexadecimal nonce required")
    if campaign_id != CAMPAIGN_ID:
        raise ValueError("stable Auth task ID required")
    if (
        type(wall_seconds) is not int
        or wall_seconds != WALL_SECONDS
        or type(recovery_seconds) is not int
        or recovery_seconds != RECOVERY_SECONDS
        or type(max_observation_seconds) is not int
        or max_observation_seconds != 1200
        or wall_seconds - recovery_seconds > max_observation_seconds
        or recovery_seconds < 300
    ):
        raise ValueError("closed revision-3 wall/recovery allocation required")

    project = window_recorder.PROJECT
    roles = tuple(_ROLES)
    bindings = {
        role: {
            "resource": _account_resource(project, nonce, role),
            "uidBinding": _uid_binding(role),
        }
        for role in roles
    }
    observation = [operation for role in roles for operation in _account_setup(role)]
    observation += _fresh_control("baseline", "baseline")
    observation += [
        _pending(
            f"age-{age}",
            f"age-{age}:held-pending",
            _camel(f"age-{age}") + "HeldPending",
        )
        for age in _AGES
    ]
    observation += [operation for age in _AGES for operation in _age_slots(age)]
    observation += _fresh_control("final", "final")
    recovery = [operation for role in roles for operation in _recovery_slots(role)]
    if len(observation) != 60 or len(recovery) != 25:
        raise ValueError("revision-3 operation slot projection changed")

    for operation in (*observation, *recovery):
        account = operation["account"]
        operation["resource"] = bindings[account]["resource"]

    schedule = [
        {"phase": "observation", "index": index, "seconds": DATA_SLOT_SECONDS}
        | ({"creates": False} if operation["kind"] in {"sign-in", "lookup"} else {})
        for index, operation in enumerate(observation)
    ] + [
        {"phase": "recovery", "index": index, "seconds": DATA_SLOT_SECONDS}
        for index in range(len(recovery))
    ]
    management_observation = _management_slots(MANAGEMENT_OBSERVATION_IDS)
    management_recovery = _management_slots(MANAGEMENT_RECOVERY_IDS)
    management_count = len(management_observation) + len(management_recovery)
    data_count = len(observation) + len(recovery)
    total_count = data_count + management_count
    expected_obs_auth = 57
    expected_recovery_auth = recovery_auth_requests()
    if expected_obs_auth > OBSERVATION_AUTH_LIMIT:
        raise ValueError("revision-3 observation request budget exceeded")
    if expected_recovery_auth > RECOVERY_AUTH_RESERVE:
        raise ValueError("revision-3 recovery request reserve insufficient")
    minted_bindings = [
        _camel(role) + suffix
        for role in roles
        for suffix in ("Email", "Password", "Marker")
    ] + ["testCode"]

    return {
        "contract": CONTRACT,
        "campaignId": CAMPAIGN_ID,
        "selector": SELECTOR,
        "nonce": nonce,
        "project": project,
        "jobSlots": 1,
        "requestSeconds": DATA_SLOT_SECONDS,
        "wallSeconds": wall_seconds,
        "recoverySeconds": recovery_seconds,
        "maxObservationSeconds": max_observation_seconds,
        "intervalSeconds": GATE_INTERVAL_SECONDS,
        "publishedAllocation": {
            "wallSeconds": WALL_SECONDS,
            "recoverySeconds": RECOVERY_SECONDS,
        },
        "caseIds": list(CASES),
        "caseDigest": CASES_SHA256,
        "maxAccounts": MAX_ACCOUNTS,
        "maxAuthRequests": MAX_AUTH_REQUESTS,
        "recoveryAuthRequestReserve": RECOVERY_AUTH_RESERVE,
        "observationAuthRequestLimit": OBSERVATION_AUTH_LIMIT,
        "observationRequests": len(observation) + len(management_observation),
        "dataRequests": data_count,
        "managementRequests": management_count,
        "requestCostMicrousd": 1,
        "costMicrousd": total_count,
        "fixedCostMicrousd": 0,
        "coordinatorRequests": 0,
        "receiptKind": "auth-pending-rev3-gate-receipt-v1",
        "plannedAccounts": list(roles),
        "accountResources": [binding["resource"] for binding in bindings.values()],
        "configResource": f"projects/{project}/auth/config",
        "mintedBindings": minted_bindings,
        "management": {
            "dispatchKind": "closed-v1",
            "observation": management_observation,
            "recovery": management_recovery,
            "credentialIds": ["oauth-tokeninfo"],
            "credentialSlots": ["tokeninfo"],
            "slotSeconds": MANAGEMENT_SLOT_SECONDS,
            "intervalSeconds": GATE_INTERVAL_SECONDS,
            "totalRequests": management_count,
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
                "resources": [binding["resource"] for binding in bindings.values()],
                "accountBindings": bindings,
                "observation": observation,
                "recovery": recovery,
                "schedule": schedule,
            }
        },
    }
