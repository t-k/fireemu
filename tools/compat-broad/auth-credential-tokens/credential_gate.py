"""Shared-Gate plan and typed facade for the AUTH-CREDENTIAL campaign.

The shared Gate admits one request per frozen slot and journals every send, but it
knows Firestore documents, not Auth accounts. This module projects the credential
campaign onto it the way the auth-list lane does: every request the case runner will
make is frozen here in order, with `$binding:` placeholders where a value is only
known at run time, and a facade over the Gate resolves those placeholders from this
run's own responses, settles each slot's creation outcome for an account rather than
a document, and records typed deletion and absence evidence per account.

Two kinds of run-time value exist and they are bound differently. An *observed*
binding is a value a response of this run returned (an ID token, a refresh token, a
UID, a reset code); the facade records it from the response under the name the slot
declares, and a later slot may only carry that exact value. A *minted* binding is a
value the run itself chose (a password, a custom token, a derived `validSince`); the
plan declares which names may be minted and the facade pins each on first use. No
binding value is ever written to the Gate journal: the journal holds the plan with
its placeholders and the digest of each request as sent.

Resources are the two cleanup routes rather than the accounts, because the base Gate
derives a cleanup target from the request path and requires it among the job's
resources. The accounts themselves are tracked in the facade's `authAccounts`
evidence, keyed by the campaign-chosen identifier each one carries, and both routes
are marked absent only once every created account has been deleted and read back
absent by UID and, where it has one, by address.

The shared Ledger does not admit this plan on the current tree: its reservation
requires every Gate resource to be a Firestore document. See the lane README.
"""

from __future__ import annotations

import copy
import json
import re
import sys
import time
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[0]))

from broad_contract import digest
from credential_cases import SIGNING_DEPENDENT_GROUPS, observation_cases
from credential_collector import (
    RECOVERY_PHASE,
    charge_elapsed,
    custom_signin_response_uid,
    reserve_request,
)
from shared_gate import Gate as FrozenGate
from shared_gate import _save as _save_state
from shared_gate import create as frozen_create

JOB = "auth-credential"
CONTRACT = "shared-local-v1"
SCHEMA_VERSION = 1
IDENTITY = "identitytoolkit.googleapis.com/v1"
SECURE = "securetoken.googleapis.com/v1/token"
#: The stand-in the case runner puts where the Web API key goes; the transport
#: replaces it, so neither the plan nor the journal carries the key.
API_KEY_PLACEHOLDER = "$apiKey"
BINDING_PREFIX = "$binding:"
OWNED_EMAIL_DOMAIN = "fireemu-credential.invalid"
_NONCE = re.compile(r"^[0-9a-f]{32}$")
_WHOLE_SECONDS = re.compile(r"^[0-9]{1,12}$")
#: Names the run may mint. Everything else must come from a response.
MINTED_BINDINGS = (
    "password",
    "resetPassword",
    "customToken",
    "customTokenReserved",
    "customTokenExpired",
    "acct1ValidSinceBelow",
    "acct1ValidSinceSame",
    "acct1ValidSinceExplicit",
)
#: Minted names whose value must be a whole-second decimal string.
SECOND_BINDINGS = (
    "acct1ValidSinceBelow",
    "acct1ValidSinceSame",
    "acct1ValidSinceExplicit",
)
#: Binding names that identify an account; once bound they never change.
IMMUTABLE_SUFFIXES = ("Uid",)
#: The only slot kinds that can bring an account into existence.
CREATING_KINDS = ("sign-up", "custom-sign-in")
GATE_INTERVAL_SECONDS = 0.25
REQUEST_COST_MICROUSD = 1
#: The wire reservation per data slot: the lane's five-second worker deadline.
DATA_SLOT_SECONDS = 5.0
MANAGEMENT_SLOT_SECONDS = 13.0
MANAGEMENT_DURATION_SECONDS = 12.0
#: The management slots charged before the data phase: the bearer attestation, the
#: project identity and the Auth config readback, then, for a signing run, one
#: signBlob slot per custom token the campaign needs. After cleanup the Auth config
#: is read back once more.
SHARED_MANAGEMENT_IDS = ("oauth-tokeninfo", "project", "auth")
SIGN_MANAGEMENT_IDS = ("sign-developer", "sign-reserved", "sign-expired")
MANAGEMENT_RECOVERY_IDS = ("auth",)
BOOTSTRAP_MANAGEMENT_IDS = (
    "bootstrap-refresh",
    "bootstrap-tokeninfo",
    "bootstrap-project",
    "bootstrap-auth-config",
)


def bootstrap_management_ids() -> tuple[str, ...]:
    """The four source-bound OAuth/Auth preparation slots.

    These are ordinary closed management slots, deliberately placed before the
    campaign's existing bearer and project preflight. The route metadata is
    descriptive plan input; the credential hosting worker remains the only
    component allowed to put private values on the wire.
    """
    return BOOTSTRAP_MANAGEMENT_IDS


def _bootstrap_management(ids: tuple[str, ...]) -> list[dict[str, Any]]:
    routes = {
        "bootstrap-refresh": {
            "method": "POST",
            "host": "oauth2.googleapis.com",
            "path": "https://oauth2.googleapis.com/token",
            "form": True,
        },
        "bootstrap-tokeninfo": {
            "method": "GET",
            "host": "oauth2.googleapis.com",
            "path": "https://oauth2.googleapis.com/tokeninfo?access_token=$binding:accessToken",
            "form": False,
        },
        "bootstrap-project": {
            "method": "GET",
            "host": "cloudresourcemanager.googleapis.com",
            "path": "https://cloudresourcemanager.googleapis.com/v1/projects/$project",
            "form": False,
        },
        "bootstrap-auth-config": {
            "method": "GET",
            "host": "identitytoolkit.googleapis.com",
            "path": "https://identitytoolkit.googleapis.com/admin/v2/projects/$project/config",
            "form": False,
        },
    }
    return [
        {
            "id": item,
            "seconds": MANAGEMENT_SLOT_SECONDS,
            "duration": MANAGEMENT_DURATION_SECONDS,
            "timeout": MANAGEMENT_SLOT_SECONDS,
            **routes[item],
        }
        for item in ids
    ]


def bootstrap_plan(plan: dict[str, Any], *, permission_digest: str) -> dict[str, Any]:
    """Return a Gate plan with the independent four-request preparation prefix."""
    if not isinstance(plan, dict) or not isinstance(permission_digest, str) or len(permission_digest) != 64:
        raise ValueError("bootstrap plan binding required")
    result = copy.deepcopy(plan)
    management = result.get("management")
    if not isinstance(management, dict) or management.get("dispatchKind") != "closed-v1":
        raise ValueError("closed management plan required")
    existing = management.get("observation")
    if not isinstance(existing, list) or [item.get("id") for item in existing[:4]] == list(BOOTSTRAP_MANAGEMENT_IDS):
        raise ValueError("bootstrap plan already prepared")
    result["bootstrap"] = {
        "kind": "auth-credential-bootstrap-v1",
        "permissionDigest": permission_digest,
        "operationIds": list(BOOTSTRAP_MANAGEMENT_IDS),
        "taskRequests": 4,
        "taskSeconds": 600,
        "recoverySeconds": 60,
    }
    result["permissionDigest"] = permission_digest
    result["management"]["observation"] = _bootstrap_management(BOOTSTRAP_MANAGEMENT_IDS) + existing
    result["management"]["credentialIds"] = ["oauth-tokeninfo"]
    result["management"]["totalRequests"] = len(result["management"]["observation"]) + len(result["management"].get("recovery", []))
    result["observationRequests"] += len(BOOTSTRAP_MANAGEMENT_IDS)
    result["managementRequests"] += len(BOOTSTRAP_MANAGEMENT_IDS)
    return result


def bootstrap_plan_digest(plan: dict[str, Any]) -> str:
    """Digest the preparation plan independently of its permission binding."""
    if not isinstance(plan, dict) or not isinstance(plan.get("bootstrap"), dict):
        raise ValueError("bootstrap plan required")
    value = copy.deepcopy(plan)
    value.pop("permissionDigest", None)
    value["bootstrap"].pop("permissionDigest", None)
    return digest(value)


def management_ids(signing: bool) -> dict[str, tuple[str, ...]]:
    """The closed management slots of a run, by phase."""
    observation = SHARED_MANAGEMENT_IDS + (SIGN_MANAGEMENT_IDS if signing else ())
    return {"observation": observation, "recovery": MANAGEMENT_RECOVERY_IDS}
CUSTOM_TOKEN_AUDIENCE = (
    "https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit"
)


def _binding(name: str) -> str:
    return BINDING_PREFIX + name


def owned_email(nonce: str, index: int) -> str:
    return f"fireemu-cred-{nonce[:8]}-{index}@{OWNED_EMAIL_DOMAIN}"


def account_identifier(nonce: str, account: str) -> str:
    """The campaign-chosen identifier an owned account carries, known at plan time."""
    if account == "acct0":
        return f"fireemu-cred-{nonce[:8]}-0"
    if account == "acct1":
        return f"fireemu-cred-{nonce[:8]}-1"
    if account == "custom":
        return f"custom-{nonce}"
    raise ValueError("unknown owned account")


def account_resource(project: str, nonce: str, account: str) -> str:
    """The canonical name an owned account would carry as a shared resource."""
    return f"projects/{project}/auth/accounts/{account_identifier(nonce, account)}"


def route_resources(project: str) -> list[str]:
    """The cleanup routes the base Gate requires among the job's resources."""
    return [
        f"{IDENTITY}/projects/{project}/accounts:delete",
        f"{IDENTITY}/projects/{project}/accounts:lookup",
    ]


def _op(
    kind: str,
    path: str,
    body: dict[str, Any],
    *,
    account: str | None,
    owner: bool = False,
    form: bool = False,
    binds: dict[str, str] | None = None,
) -> dict[str, Any]:
    return {
        "service": "auth",
        "method": "POST",
        "path": path,
        "body": body,
        "form": form,
        "owner": owner,
        "kind": kind,
        "account": account,
        "binds": dict(binds or {}),
    }


def _client(rpc: str) -> str:
    return f"{IDENTITY}/accounts:{rpc}"


def _admin(project: str, rpc: str) -> str:
    return f"{IDENTITY}/projects/{project}/accounts:{rpc}"


def _sign_up(nonce: str, account: str, index: int) -> dict[str, Any]:
    return _op(
        "sign-up",
        _client("signUp"),
        {
            "email": owned_email(nonce, index),
            "password": _binding("password"),
            "returnSecureToken": True,
        },
        account=account,
        binds={
            f"{account}Uid": "localId",
            f"{account}IdToken": "idToken",
            f"{account}Refresh": "refreshToken",
        },
    )


def _sign_in(nonce: str, account: str, index: int, label: str, password: str = "password") -> dict[str, Any]:
    return _op(
        "sign-in",
        _client("signInWithPassword"),
        {
            "email": owned_email(nonce, index),
            "password": _binding(password),
            "returnSecureToken": True,
        },
        account=account,
        binds={f"{account}{label}IdToken": "idToken", f"{account}{label}Refresh": "refreshToken"},
    )


def _refresh(account: str, token_binding: str) -> dict[str, Any]:
    return _op(
        "refresh",
        SECURE,
        {"grant_type": "refresh_token", "refresh_token": _binding(token_binding)},
        account=account,
        form=True,
        # A refresh may rotate the token; the latest value is what a later slot carries.
        binds={token_binding: "refresh_token"},
    )


def _lookup(account: str, token_binding: str) -> dict[str, Any]:
    return _op(
        "lookup", _client("lookup"), {"idToken": _binding(token_binding)}, account=account
    )


def _update(project: str, account: str, body: dict[str, Any]) -> dict[str, Any]:
    return _op("update", _admin(project, "update"), body, account=account, owner=True)


def _cookie(project: str, token_binding: str, duration: int | None) -> dict[str, Any]:
    body: dict[str, Any] = {"idToken": _binding(token_binding)}
    if duration is not None:
        body["validDuration"] = str(duration)
    return _op(
        "create-session-cookie",
        f"{IDENTITY}/projects/{project}:createSessionCookie",
        body,
        account="custom",
        owner=True,
    )


def _custom_sign_in(token_binding: str, *, binds: bool) -> dict[str, Any]:
    return _op(
        "custom-sign-in",
        _client("signInWithCustomToken"),
        {"token": _binding(token_binding), "returnSecureToken": True},
        account="custom",
        binds={
            "customUid": "idToken.sub",
            "customIdToken": "idToken",
            "customRefresh": "refreshToken",
        }
        if binds
        else {},
    )


def observation_operations(project: str, nonce: str, *, signing: bool) -> list[dict[str, Any]]:
    """Every observation request the case runner sends, in the order it sends them.

    The order is the runner's, group by group. Without signing the custom-token,
    session-cookie and claim-precedence groups are absent and the runner skips them.
    """
    ops = [
        # refresh
        _sign_up(nonce, "acct0", 0),
        _refresh("acct0", "acct0Refresh"),
        _refresh("acct0", "acct0Refresh"),
        _op(
            "refresh-unknown",
            SECURE,
            {
                "grant_type": "refresh_token",
                "refresh_token": "rt1.0.0.demo-app.unissued0000000000000",
            },
            account=None,
            form=True,
        ),
        # revocation
        _sign_up(nonce, "acct1", 1),
        _update(
            project,
            "acct1",
            {"localId": _binding("acct1Uid"), "validSince": _binding("acct1ValidSinceBelow")},
        ),
        _lookup("acct1", "acct1IdToken"),
        _sign_in(nonce, "acct1", 1, "Boundary"),
        _update(
            project,
            "acct1",
            {"localId": _binding("acct1Uid"), "validSince": _binding("acct1ValidSinceSame")},
        ),
        _op(
            "admin-lookup",
            _admin(project, "lookup"),
            {"localId": [_binding("acct1Uid")]},
            account="acct1",
            owner=True,
        ),
        _lookup("acct1", "acct1BoundaryIdToken"),
        _sign_in(nonce, "acct1", 1, "Later"),
        _lookup("acct1", "acct1LaterIdToken"),
    ]
    if signing:
        ops += [
            # custom token
            _custom_sign_in("customToken", binds=True),
            _custom_sign_in("customTokenReserved", binds=False),
            _custom_sign_in("customTokenExpired", binds=False),
            # session cookies
            _cookie(project, "customIdToken", None),
            _cookie(project, "customIdToken", 300),
            _cookie(project, "customIdToken", 299),
            _cookie(project, "customIdToken", 1209600),
            _cookie(project, "customIdToken", 1209601),
            _cookie(project, "customIdToken", 3600),
            _op(
                "create-session-cookie",
                f"{IDENTITY}/projects/{project}:createSessionCookie",
                {"idToken": _binding("acct1IdToken"), "validDuration": "3600"},
                account="acct1",
                owner=True,
            ),
            # claim precedence
            _update(
                project,
                "custom",
                {
                    "localId": _binding("customUid"),
                    "customAttributes": json.dumps({"role": "admin", "tier": "gold"}),
                },
            ),
            _refresh("custom", "customRefresh"),
        ]
    ops += [
        # refresh refusal class
        _op(
            "send-oob-code",
            _admin(project, "sendOobCode"),
            {
                "requestType": "PASSWORD_RESET",
                "email": owned_email(nonce, 0),
                "returnOobLink": True,
            },
            account="acct0",
            owner=True,
            binds={"acct0OobCode": "oobCode"},
        ),
        _op(
            "reset-password",
            _client("resetPassword"),
            {"oobCode": _binding("acct0OobCode"), "newPassword": _binding("resetPassword")},
            account="acct0",
        ),
        _refresh("acct0", "acct0Refresh"),
        _sign_in(nonce, "acct0", 0, "Fresh", password="resetPassword"),
        _refresh("acct0", "acct0FreshRefresh"),
        _update(
            project,
            "acct1",
            {"localId": _binding("acct1Uid"), "validSince": _binding("acct1ValidSinceExplicit")},
        ),
        _refresh("acct1", "acct1LaterRefresh"),
        _sign_in(nonce, "acct1", 1, "Fresh"),
        _refresh("acct1", "acct1FreshRefresh"),
    ]
    return ops


def recovery_operations(project: str, nonce: str, *, signing: bool) -> list[dict[str, Any]]:
    """The cleanup the collector performs per owned account, in creation order."""
    accounts = [("acct0", 0), ("acct1", 1)] + ([("custom", None)] if signing else [])
    ops = []
    for account, index in accounts:
        uid = _binding(f"{account}Uid")
        ops.append(
            _op("delete", _admin(project, "delete"), {"localId": uid}, account=account, owner=True)
        )
        ops.append(
            _op(
                "uid-absence",
                _admin(project, "lookup"),
                {"localId": [uid]},
                account=account,
                owner=True,
            )
        )
        if index is not None:
            ops.append(
                _op(
                    "address-absence",
                    _admin(project, "lookup"),
                    {"email": [owned_email(nonce, index)]},
                    account=account,
                    owner=True,
                )
            )
    return ops


def planned_accounts(signing: bool) -> tuple[str, ...]:
    return ("acct0", "acct1", "custom") if signing else ("acct0", "acct1")


def runnable_case_ids(signing: bool) -> list[str]:
    return [
        case["id"]
        for case in observation_cases()
        if signing or case["group"] not in SIGNING_DEPENDENT_GROUPS
    ]


def gate_plan(
    project: str,
    nonce: str,
    *,
    signing: bool,
    wall_seconds: int,
    recovery_seconds: int,
    cost_microusd: int,
    observation_window_seconds: int,
) -> dict[str, Any]:
    """Project the campaign onto the shared Gate schema for one nonce."""
    if not isinstance(nonce, str) or _NONCE.fullmatch(nonce) is None:
        raise ValueError("a 32-character hexadecimal nonce is required")
    if type(signing) is not bool:
        raise ValueError("signing capability must be declared")
    observation = observation_operations(project, nonce, signing=signing)
    recovery = recovery_operations(project, nonce, signing=signing)
    resources = {
        account: account_resource(project, nonce, account)
        for account in planned_accounts(signing)
    }
    for operation in observation + recovery:
        account = operation.get("account")
        if account is not None:
            operation["resource"] = resources[account]
    slots = management_ids(signing)
    schedule = [
        {"phase": "observation", "index": index, "seconds": DATA_SLOT_SECONDS}
        for index in range(len(observation))
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
        "campaignId": "AUTH-CREDENTIAL-TOKENS-01",
        "nonce": nonce,
        "project": project,
        "signing": signing,
        "jobSlots": 1,
        "requestSeconds": DATA_SLOT_SECONDS,
        "wallSeconds": wall_seconds,
        "recoverySeconds": recovery_seconds,
        "intervalSeconds": GATE_INTERVAL_SECONDS,
        "observationRequests": len(observation) + len(slots["observation"]),
        "dataRequests": len(observation) + len(recovery),
        "managementRequests": len(slots["observation"]) + len(slots["recovery"]),
        "requestCostMicrousd": REQUEST_COST_MICROUSD,
        "costMicrousd": cost_microusd,
        "receiptKind": "auth-credential-acquisition-receipt-v1",
        "plannedAccounts": list(planned_accounts(signing)),
        "accountResources": list(resources.values()),
        "mintedBindings": list(MINTED_BINDINGS),
        "management": {
            "dispatchKind": "closed-v1",
            "observation": management(slots["observation"]),
            "recovery": management(slots["recovery"]),
            "credentialIds": ["oauth-tokeninfo"],
            "credentialSlots": ["tokeninfo"],
            "slotSeconds": MANAGEMENT_SLOT_SECONDS,
            "intervalSeconds": GATE_INTERVAL_SECONDS,
            "totalRequests": len(slots["observation"]) + len(slots["recovery"]),
            "observationWindowSeconds": observation_window_seconds,
            "recoveryWindowSeconds": recovery_seconds,
            "principalBinding": {
                "alternatives": [
                    ["clientId", "subject", "requiredScopes"],
                    ["clientId", "verifiedEmail", "requiredScopes"],
                ],
                "claims": ["issued_to", "audience", "user_id", "email", "verified_email", "scope", "expires_in"],
            },
            "permissionExpiryBound": True,
        },
        "jobs": {
            JOB: {
                "resources": list(resources.values()),
                "observation": observation,
                "recovery": recovery,
                "schedule": schedule,
            }
        },
    }


def strip_api_key(path: str) -> str:
    """Remove the runner's API-key placeholder from a request path."""
    suffix = "?key=" + API_KEY_PLACEHOLDER
    return path.removesuffix(suffix)


# --- typed responses ----------------------------------------------------------------


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value) and not value.startswith(BINDING_PREFIX)


def deleted_response(status: Any, body: Any) -> bool:
    return type(status) is int and status == 200 and isinstance(body, dict) and (
        body == {} or body == {"kind": "identitytoolkit#DeleteAccountResponse"}
    )


def absent_response(status: Any, body: Any) -> bool:
    """A 200 lookup with no result; a refusal never counts as absence."""
    if type(status) is not int or status != 200 or not isinstance(body, dict) or not body:
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


# --- the facade ----------------------------------------------------------------------


def create(path: Path, plan: dict[str, Any]) -> None:
    """Create the Gate directory for one plan compiled by `gate_plan`."""
    if not isinstance(plan, dict) or set(plan.get("jobs", {})) != {JOB}:
        raise ValueError("closed credential Gate plan required")
    _validate_auth_account_plan(plan)
    frozen_create(path, plan)


def _validate_auth_account_plan(plan: dict[str, Any]) -> None:
    """Keep each logical account, resource, UID binding, and address closed."""
    job = plan["jobs"][JOB]
    accounts = planned_accounts(plan.get("signing") is True)
    resources = {
        account: account_resource(plan["project"], plan["nonce"], account)
        for account in accounts
    }
    if set(job.get("resources", [])) != set(resources.values()):
        raise ValueError("credential account/resource mapping differs")
    for operation in job.get("observation", []) + job.get("recovery", []):
        account = operation.get("account")
        if account is None:
            continue
        if account not in resources or operation.get("resource") != resources[account]:
            raise ValueError("credential account/resource mapping differs")
        if operation in job.get("recovery", []):
            kind = operation.get("kind")
            body = operation.get("body")
            if kind in {"delete", "uid-absence"}:
                if body != {"localId": _binding(f"{account}Uid")} and body != {
                    "localId": [_binding(f"{account}Uid")]
                }:
                    raise ValueError("credential UID binding differs from account")
            elif kind == "address-absence":
                index = {"acct0": 0, "acct1": 1}.get(account)
                if index is None or body != {"email": [owned_email(plan["nonce"], index)]}:
                    raise ValueError("credential address binding differs from account")


class CredentialGate(FrozenGate):
    """The shared Gate, with bindings and account evidence for this campaign."""

    def __init__(self, path: Path, job: str = JOB):
        super().__init__(path, job)
        if job != JOB:
            raise ValueError("closed credential job required")
        plan = self.snapshot()["plan"]
        self.project = plan["project"]
        self.minted = set(plan.get("mintedBindings", []))
        self.bindings: dict[str, str] = {}
        # Values returned by this run's own responses. A slot may carry a binding only
        # when the value it carries is exactly one of these, or a minted one.
        self._observed: dict[str, str] = {}

    # --- slot resolution ---

    def next_operation(self, recovery: bool) -> dict[str, Any]:
        state = self.snapshot()
        phase = "recovery" if recovery else "observation"
        job = state["jobs"][self.job]
        operations = state["plan"]["jobs"][self.job][phase]
        index = job[phase]
        if index >= len(operations):
            raise ValueError("scenario request capacity")
        return copy.deepcopy(operations[index])

    def _bind_minted(self, name: str, value: Any) -> None:
        if name not in self.minted or not _text(value) or len(value) > 8192:
            raise ValueError("runtime binding differs from the frozen slot")
        if name in SECOND_BINDINGS and _WHOLE_SECONDS.fullmatch(value) is None:
            raise ValueError("a validSince binding must be a whole second")
        self.bindings[name] = value

    def _resolve(self, value: Any, declared: Any) -> None:
        """Check a runtime value against its declared shape, binding on first use."""
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
        self, path: str, body: dict[str, Any], *, owner: bool, recovery: bool, send: Any
    ) -> Any:
        """Admit the runner's next request against its frozen slot, then send.

        `path` is the runner's own path with the API-key placeholder still in it;
        `body` carries the run-time values. Both are checked against the next
        declared slot; the Gate journals the declared slot, never the values.
        """
        declared = self.next_operation(recovery)
        if strip_api_key(path) != declared["path"] or bool(owner) != declared["owner"]:
            raise ValueError("request outside closed scenario")
        self._resolve(body, declared["body"])
        if recovery and declared.get("service") == "auth":
            state = self.snapshot()
            record = state["jobs"][self.job].get("authAccounts", {}).get(declared.get("account"))
            if not isinstance(record, dict) or "createEvent" not in record:
                raise ValueError("Auth cleanup requires creation ownership")
            if declared.get("resource") != record.get("resource"):
                raise ValueError("Auth cleanup resource differs from creation")
            expected_uid = record.get("uid")
            if declared.get("kind") == "delete":
                actual_uid = body.get("localId")
            elif declared.get("kind") == "uid-absence":
                actual_uid = body.get("localId")
                actual_uid = actual_uid[0] if isinstance(actual_uid, list) and len(actual_uid) == 1 else None
            else:
                actual_uid = expected_uid
            if declared.get("kind") in {"delete", "uid-absence"} and actual_uid != expected_uid:
                raise ValueError("Auth cleanup UID differs from creation")
        try:
            return super().dispatch(declared, recovery, send)
        except Exception:
            self._settle_failed_send(declared, recovery)
            raise

    def _settle_failed_send(self, declared: dict[str, Any], recovery: bool) -> None:
        """A send that raised before a typed answer cannot have created an account
        unless the slot was a sign-up; settle every other slot as no creation.

        The base Gate leaves the slot pending, which is right for a document write
        whose answer was lost. A refresh, a lookup or an update whose worker timed
        out created nothing, and leaving it pending would count it as an
        unconfirmed create for the rest of the run.
        """
        if recovery or declared["kind"] in CREATING_KINDS:
            return
        with self.locked() as state:
            events = state["events"]
            for event in reversed(events):
                if event.get("job") != self.job or event.get("phase") != "observation":
                    continue
                if event.get("creationOutcome") == "pending" and event.get("failure") is not None:
                    event["creationOutcome"] = "refused"
                    event["authEvidence"] = {
                        "kind": declared["kind"],
                        "account": declared.get("account"),
                        "status": None,
                        "creationOutcome": "refused",
                        "settled": "failed-send-cannot-create",
                    }
                    _save_state(self.path, state)
                break

    # --- evidence ---

    def _record_response(self, state, operation, recovery, event, status, body):
        job = state["jobs"][self.job]
        try:
            self._record_auth_response(state, operation, recovery, event, status, body)
        except ValueError:
            job["stopped"] = True
            event["failure"] = "InvalidCredentialCampaignResponse"
            raise

    def _record_auth_response(self, state, operation, recovery, event, status, body):
        job = state["jobs"][self.job]
        accounts = job.setdefault("authAccounts", {})
        kind, account = operation["kind"], operation.get("account")
        position = len(state["events"]) - 1
        custom_uid = None
        if kind == "custom-sign-in":
            custom_uid = custom_signin_response_uid(
                status,
                body,
                project=state["plan"]["project"],
                requested_uid=account_identifier(state["plan"]["nonce"], "custom"),
            )
        for name, field in operation.get("binds", {}).items():
            if kind == "custom-sign-in":
                if name == "customUid" and field != "idToken.sub":
                    raise ValueError("custom identity binding contract differs")
                if custom_uid is None:
                    continue
            value = (
                custom_uid
                if kind == "custom-sign-in"
                and name == "customUid"
                and field == "idToken.sub"
                else _field(body, field) if status == 200 else None
            )
            if not _text(value) or len(value) > 8192:
                continue
            immutable = name.endswith(IMMUTABLE_SUFFIXES)
            if immutable and name in self._observed and self._observed[name] != value:
                raise ValueError("account identity binding is immutable")
            self._observed[name] = value
            if name in self.bindings and not immutable:
                # A rotated credential replaces the value later slots must carry.
                self.bindings[name] = value
        evidence: dict[str, Any] = {"kind": kind, "account": account, "status": status}
        if not recovery:
            outcome = "refused"
            if kind in ("sign-up", "custom-sign-in"):
                uid = (
                    custom_uid
                    if kind == "custom-sign-in"
                    else body.get("localId") if isinstance(body, dict) else None
                )
                identified_success = (
                    type(status) is int
                    and status == 200
                    and isinstance(body, dict)
                    and "error" not in body
                    and _text(uid)
                    and len(uid) <= 128
                    and _text(body.get("idToken"))
                    and _text(body.get("refreshToken"))
                )
                created = identified_success and (
                    kind == "sign-up" or body.get("isNewUser") is True
                )
                if created:
                    if kind == "custom-sign-in" and uid != account_identifier(state["plan"]["nonce"], "custom"):
                        raise ValueError("custom sign-in created an account outside the plan")
                    if account in accounts:
                        raise ValueError("an owned account was created twice")
                    if any(other.get("uid") == uid for other in accounts.values()):
                        raise ValueError("owned account identities collide")
                    resource = operation.get("resource")
                    expected_resource = account_resource(
                        state["plan"]["project"], state["plan"]["nonce"], account
                    )
                    if resource != expected_resource:
                        raise ValueError("account creation resource differs")
                    accounts[account] = {
                        "uid": uid,
                        "resource": resource,
                        "createEvent": position,
                    }
                    # This is the validated creation projection consumed by
                    # shared Gate ownership checks. Never populate it for an
                    # unknown or typed-refused response.
                    evidence["uid"] = uid
                    evidence["resource"] = resource
                    outcome = "created"
                elif (
                    kind == "custom-sign-in"
                    and identified_success
                    and body.get("isNewUser") is False
                    and uid == account_identifier(state["plan"]["nonce"], "custom")
                ):
                    # Only an explicit, identified reuse ACK proves no creation.
                    # Missing identity/new-user evidence is unknown, not refusal.
                    outcome = "refused"
                elif not typed_refusal(status, body):
                    # No account was proven created and no typed refusal came back:
                    # the outcome is unknown and the slot stays unsettled.
                    outcome = "unknown"
            elif status is None or (type(status) is int and status >= 500):
                outcome = "refused" if kind != "sign-up" else "unknown"
            if "creationOutcome" in event:
                event["creationOutcome"] = outcome
            evidence["creationOutcome"] = outcome
        else:
            record = accounts.get(account)
            if record is None:
                raise ValueError("cleanup of an account this run never created")
            if kind == "delete":
                if not deleted_response(status, body):
                    raise ValueError("typed account deletion acknowledgement required")
                record["deleteEvent"] = position
            elif kind == "uid-absence":
                if "deleteEvent" not in record or not absent_response(status, body):
                    raise ValueError("typed post-delete account absence required")
                record["absenceEvent"] = position
            elif kind == "address-absence":
                if "absenceEvent" not in record or not absent_response(status, body):
                    raise ValueError("typed post-delete address absence required")
                record["addressAbsenceEvent"] = position
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
        """Every planned account, and whether its cleanup includes an address readback."""
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
        accounts = state["jobs"][self.job].get("authAccounts", {})
        expected = self._expected_accounts(state)
        if set(accounts) != set(expected):
            return False
        return all(
            "deleteEvent" in record
            and "absenceEvent" in record
            and (not expected[name] or "addressAbsenceEvent" in record)
            for name, record in accounts.items()
        )

    def _validate_finish_evidence(self, state):
        job = state["jobs"][self.job]
        recipe = state["plan"]["jobs"][self.job]
        if job["observation"] != len(recipe["observation"]):
            raise ValueError("campaign observations incomplete")
        accounts = job.get("authAccounts", {})
        expected = self._expected_accounts(state)
        if not self._all_accounts_absent(state):
            raise ValueError("account cleanup evidence incomplete")
        if len({record["uid"] for record in accounts.values()}) != len(accounts):
            raise ValueError("account identities collide")
        for name, record in accounts.items():
            order = [record["createEvent"], record["deleteEvent"], record["absenceEvent"]]
            if expected[name]:
                order.append(record["addressAbsenceEvent"])
            if order != sorted(order) or len(set(order)) != len(order):
                raise ValueError("account cleanup event order differs")
            for position in order:
                event = state["events"][position]
                if (
                    event.get("job") != self.job
                    or event.get("completed") is not True
                    or event.get("failure") is not None
                    or not isinstance(event.get("authEvidence"), dict)
                    or event["authEvidence"].get("account") != name
                ):
                    raise ValueError("account evidence binding differs")
            create_event = state["events"][record["createEvent"]]
            if create_event.get("creationOutcome") != "created":
                raise ValueError("account creation event differs")
            for position in order[1:]:
                event = state["events"][position]
                if event.get("phase") != "recovery" or event["authEvidence"].get("responseDigest") != digest(
                    event["authEvidence"].get("body")
                ) or event.get("responseDigest") != event["authEvidence"]["responseDigest"]:
                    raise ValueError("account cleanup response differs")
        super()._validate_finish_evidence(state)


def gate_environment(project: str, *, signing: bool) -> dict[str, Any]:
    """The endpoint part of a runner environment for a Gate-hosted run.

    Paths are the frozen slot paths: no scheme, no host, and the API-key placeholder
    where the runner puts the key. The caller adds the passwords and the signer.
    """
    identity = IDENTITY
    return {
        "project": project,
        "apiKey": API_KEY_PLACEHOLDER,
        "signing": signing,
        "endpoints": {
            "identity": identity,
            "secure": f"{SECURE}?key={API_KEY_PLACEHOLDER}",
            "admin": f"{identity}/projects/{project}",
        },
    }


def gate_poster(gate: CredentialGate, transmit: Any, *, before: Any = None, after: Any = None) -> Any:
    """A runner poster that admits every request through the facade first.

    The phase is the budget's: the runner observes while the budget is in its run
    phase, and the collector's cleanup runs once it has entered recovery. `transmit`
    receives the declared slot and the run-time body and returns `(status, body)`
    with the body already parsed; the Gate journals the status and the body digest.
    The budget is reserved before the Gate is asked, so an exhausted bound costs
    nothing, and the wall time is charged afterwards whatever the Gate answered.

    `before(declared)` runs before the budget or the Gate is charged and may refuse
    the slot (a latched credential); `after(declared, status, body)` runs once the
    Gate has journaled the answer and may stop the run on what it saw.
    """

    def poster(budget, base, path, body, *, owner=False):
        recovery = budget["phase"] == RECOVERY_PHASE
        declared = gate.next_operation(recovery)
        if before is not None:
            before(declared)
        started = time.monotonic()
        allowance = reserve_request(budget, started)
        timeout = min(DATA_SLOT_SECONDS, allowance)
        try:
            status, response = gate.dispatch_runtime(
                strip_base(base, path),
                body,
                owner=owner,
                recovery=recovery,
                send=lambda: transmit(declared, body, timeout),
            )
        finally:
            charge_elapsed(budget, time.monotonic() - started)
        if after is not None:
            after(declared, status, response)
        return status, response

    return poster


def strip_base(base: str, path: str) -> str:
    """Join the runner's base and path the way it does, without a scheme or host."""
    return base + path


def account_evidence(snapshot: dict[str, Any]) -> dict[str, Any]:
    """The publishable account evidence of a Gate snapshot: counts, never identifiers."""
    job = snapshot["jobs"][JOB]
    accounts = job.get("authAccounts", {})
    return {
        "createdAccounts": len(accounts),
        "deletedAccounts": sum("deleteEvent" in a for a in accounts.values()),
        "uidAbsenceReadbacks": sum("absenceEvent" in a for a in accounts.values()),
        "addressAbsenceReadbacks": sum("addressAbsenceEvent" in a for a in accounts.values()),
        "routesAbsent": sorted(job["absent"]),
        "complete": job["complete"],
    }


__all__ = [
    "API_KEY_PLACEHOLDER",
    "JOB",
    "CredentialGate",
    "account_evidence",
    "account_resource",
    "bootstrap_management_ids",
    "bootstrap_plan",
    "bootstrap_plan_digest",
    "create",
    "gate_environment",
    "gate_plan",
    "gate_poster",
    "management_ids",
    "observation_operations",
    "planned_accounts",
    "recovery_operations",
    "route_resources",
    "runnable_case_ids",
    "strip_api_key",
]
