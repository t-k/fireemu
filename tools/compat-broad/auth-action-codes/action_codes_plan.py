"""Frozen, credential-free preparation for one bounded OOB action-code observation.

This module is a plan, not an executable production entry. It names the finite
matrix of out-of-band (OOB) action-code transitions the `AUTH-ACTION` row still
records as production-unobserved, the owned resources each stage touches, the
budget the campaign may not exceed, and the conditions that stay unobserved on
purpose. Owner inputs stay unset and production execution stays closed here.

Every stage uses the link-return path, so no message is ever delivered: the
privileged `accounts:sendOobCode` request carries `returnOobLink: true` and the
response carries the code. The owned addresses use the reserved `.invalid`
top-level domain, so a delivery that happened despite that would still be
undeliverable.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

CONTRACT = "auth-action-codes-v1"
CAMPAIGN_ID = "AUTH-ACTION-OOB-DELIVERY-BOUNDARY-01"
NONCE_TEMPLATE = "{freshNonce}"
LOCAL_PROJECT = "demo-auth-action"
EMAIL_DOMAIN = "example.invalid"
_PROJECT = re.compile(r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$")

# Values that must never be written to a receipt, a log line or a process
# argument. The manifest may only reference them through a `$binding:` name.
SECRET_FIELDS = (
    "oobCode",
    "oobLink",
    "idToken",
    "refreshToken",
    "password",
    "newPassword",
    "passwordHash",
    "salt",
)

STAGE_IDS = (
    "account-a-create",
    "account-b-create",
    "reset-link-generate",
    "reset-code-lookup",
    "reset-weak-password",
    "reset-weak-password-retry",
    "reset-consume",
    "reset-reuse",
    "reset-wrong-code",
    "reset-link-generate-second",
    "admin-password-update",
    "reset-after-password-change",
    "account-a-readback",
    "verify-link-generate",
    "verify-apply",
    "verify-reuse",
    "verify-wrong-code",
    "email-link-generate",
    "email-link-signin",
    "email-link-reuse",
    "email-link-generate-second",
    "email-link-mismatched-email",
    "deleted-user-link-generate",
    "account-b-delete",
    "reset-after-delete",
    "link-generate-unknown-email",
)

_END_USER = "/identitytoolkit.googleapis.com/v1/accounts:{method}"
_ADMIN = "/identitytoolkit.googleapis.com/v1/projects/{project}/accounts:{method}"


def _accounts(nonce: str) -> dict[str, dict[str, str]]:
    return {
        "accountA": {
            "role": "primary owned account",
            "email": f"o1-oob-{nonce}-a@{EMAIL_DOMAIN}",
        },
        "accountB": {
            "role": "control owned account deleted mid-run",
            "email": f"o1-oob-{nonce}-b@{EMAIL_DOMAIN}",
        },
    }


def _stage(
    identifier: str,
    *,
    group: str,
    basis: str,
    route: str,
    method: str,
    body: dict[str, Any],
    expected: dict[str, Any],
    delivery: str = "none",
    note: str = "",
) -> dict[str, Any]:
    template = _ADMIN if route == "admin" else _END_USER
    return {
        "id": identifier,
        "group": group,
        "basis": basis,
        "routeClass": route,
        "method": "POST",
        "path": template.format(project="{project}", method=method),
        "body": body,
        "delivery": delivery,
        "expectedLocal": expected,
        "productionExpectation": "UNOBSERVED",
        "note": note,
    }


def _ok(keys: list[str], **extra: Any) -> dict[str, Any]:
    return {"status": 200, "keys": sorted(keys), **extra}


def _refused(message: str) -> dict[str, Any]:
    return {"status": 400, "keys": ["error"], "errorMessage": message}


_LINK_KEYS = ["email", "kind", "oobCode", "oobLink"]
_RESET_KEYS = ["email", "kind", "requestType"]
_SIGNUP_KEYS = ["email", "expiresIn", "idToken", "kind", "localId", "refreshToken"]


def _link(request_type: str, account: str) -> dict[str, Any]:
    return {
        "requestType": request_type,
        "email": "$binding:" + account + ".email",
        "returnOobLink": True,
    }


def campaign_stages() -> list[dict[str, Any]]:
    """Return the ordered wire stages of the finite matrix."""
    stages = [
        _stage(
            "account-a-create",
            group="setup",
            basis="setup",
            route="end-user",
            method="signUp",
            body={
                "email": "$binding:accountA.email",
                "password": "$binding:accountA.password",
                "returnSecureToken": True,
            },
            expected=_ok(_SIGNUP_KEYS),
            note="Creates the primary owned account for every action-code stage.",
        ),
        _stage(
            "account-b-create",
            group="setup",
            basis="setup",
            route="end-user",
            method="signUp",
            body={
                "email": "$binding:accountB.email",
                "password": "$binding:accountB.password",
                "returnSecureToken": True,
            },
            expected=_ok(_SIGNUP_KEYS),
            note="Control account for the mismatched-email and deleted-user stages.",
        ),
        _stage(
            "reset-link-generate",
            group="password-reset",
            basis="setup",
            route="admin",
            method="sendOobCode",
            body=_link("PASSWORD_RESET", "accountA"),
            expected=_ok(_LINK_KEYS, oobCodeReturn="present"),
            delivery="suppressed-by-returnOobLink",
            note="Privileged link return; the response carries the code and no mail is sent.",
        ),
        _stage(
            "reset-code-lookup",
            group="password-reset",
            basis="diagnostic",
            route="end-user",
            method="resetPassword",
            body={"oobCode": "$binding:resetCode"},
            expected=_ok(_RESET_KEYS, requestType="PASSWORD_RESET", consumed=False),
            note="Lookup without newPassword must describe the code without consuming it.",
        ),
        _stage(
            "reset-weak-password",
            group="password-reset",
            basis="diagnostic",
            route="end-user",
            method="resetPassword",
            body={
                "oobCode": "$binding:resetCode",
                "newPassword": "$binding:weakPassword",
            },
            expected=_refused("WEAK_PASSWORD"),
            note="A refused password policy must not consume the code.",
        ),
        _stage(
            "reset-weak-password-retry",
            group="password-reset",
            basis="control",
            route="end-user",
            method="resetPassword",
            body={"oobCode": "$binding:resetCode"},
            expected=_ok(_RESET_KEYS, requestType="PASSWORD_RESET", consumed=False),
            note="Positive control proving the refused stage left the code usable.",
        ),
        _stage(
            "reset-consume",
            group="password-reset",
            basis="diagnostic",
            route="end-user",
            method="resetPassword",
            body={
                "oobCode": "$binding:resetCode",
                "newPassword": "$binding:accountA.nextPassword",
            },
            expected=_ok(_RESET_KEYS, requestType="PASSWORD_RESET", consumed=True),
        ),
        _stage(
            "reset-reuse",
            group="password-reset",
            basis="diagnostic",
            route="end-user",
            method="resetPassword",
            body={
                "oobCode": "$binding:resetCode",
                "newPassword": "$binding:accountA.thirdPassword",
            },
            expected=_refused("INVALID_OOB_CODE"),
            note="Reuse after consumption is the central ownership transition.",
        ),
        _stage(
            "reset-wrong-code",
            group="password-reset",
            basis="control",
            route="end-user",
            method="resetPassword",
            body={
                "oobCode": "$binding:wrongCode",
                "newPassword": "$binding:accountA.thirdPassword",
            },
            expected=_refused("INVALID_OOB_CODE"),
            note="Negative control: a code that was never issued.",
        ),
        _stage(
            "reset-link-generate-second",
            group="password-reset",
            basis="setup",
            route="admin",
            method="sendOobCode",
            body=_link("PASSWORD_RESET", "accountA"),
            expected=_ok(_LINK_KEYS, oobCodeReturn="present"),
            delivery="suppressed-by-returnOobLink",
        ),
        _stage(
            "admin-password-update",
            group="password-reset",
            basis="setup",
            route="admin",
            method="update",
            body={
                "localId": "$binding:accountA.localId",
                "password": "$binding:accountA.fourthPassword",
            },
            expected=_ok(
                [
                    "email",
                    "emailVerified",
                    "expiresIn",
                    "idToken",
                    "kind",
                    "localId",
                    "passwordHash",
                    "providerUserInfo",
                    "refreshToken",
                ]
            ),
            note="The transition under test: the password changes after the code was issued.",
        ),
        _stage(
            "reset-after-password-change",
            group="password-reset",
            basis="diagnostic",
            route="end-user",
            method="resetPassword",
            body={
                "oobCode": "$binding:resetCodeSecond",
                "newPassword": "$binding:accountA.fifthPassword",
            },
            expected=_ok(_RESET_KEYS, requestType="PASSWORD_RESET", consumed=True),
            note=(
                "The local runtime still accepts the outstanding code after the "
                "password changed. Whether production invalidates it is the "
                "representative unobserved transition."
            ),
        ),
        _stage(
            "account-a-readback",
            group="password-reset",
            basis="control",
            route="admin",
            method="lookup",
            body={"localId": "$binding:accountA.localId"},
            expected=_ok(["kind", "users"]),
            note="Typed post-state readback; no password value is recorded.",
        ),
        _stage(
            "verify-link-generate",
            group="verify-email",
            basis="setup",
            route="admin",
            method="sendOobCode",
            body=_link("VERIFY_EMAIL", "accountA"),
            expected=_ok(_LINK_KEYS, oobCodeReturn="present"),
            delivery="suppressed-by-returnOobLink",
        ),
        _stage(
            "verify-apply",
            group="verify-email",
            basis="diagnostic",
            route="end-user",
            method="update",
            body={"oobCode": "$binding:verifyCode"},
            expected=_ok(
                ["email", "emailVerified", "kind", "localId"], emailVerified=True
            ),
        ),
        _stage(
            "verify-reuse",
            group="verify-email",
            basis="diagnostic",
            route="end-user",
            method="update",
            body={"oobCode": "$binding:verifyCode"},
            expected=_refused("INVALID_OOB_CODE"),
        ),
        _stage(
            "verify-wrong-code",
            group="verify-email",
            basis="control",
            route="end-user",
            method="update",
            body={"oobCode": "$binding:wrongCode"},
            expected=_refused("INVALID_OOB_CODE"),
        ),
        _stage(
            "email-link-generate",
            group="email-link",
            basis="setup",
            route="admin",
            method="sendOobCode",
            body=_link("EMAIL_SIGNIN", "accountA"),
            expected=_ok(_LINK_KEYS, oobCodeReturn="present"),
            delivery="suppressed-by-returnOobLink",
        ),
        _stage(
            "email-link-signin",
            group="email-link",
            basis="diagnostic",
            route="end-user",
            method="signInWithEmailLink",
            body={
                "email": "$binding:accountA.email",
                "oobCode": "$binding:emailLinkCode",
            },
            expected=_ok(
                [
                    "email",
                    "expiresIn",
                    "idToken",
                    "isNewUser",
                    "kind",
                    "localId",
                    "refreshToken",
                ],
                isNewUser=False,
            ),
        ),
        _stage(
            "email-link-reuse",
            group="email-link",
            basis="diagnostic",
            route="end-user",
            method="signInWithEmailLink",
            body={
                "email": "$binding:accountA.email",
                "oobCode": "$binding:emailLinkCode",
            },
            expected=_refused("INVALID_OOB_CODE"),
        ),
        _stage(
            "email-link-generate-second",
            group="email-link",
            basis="setup",
            route="admin",
            method="sendOobCode",
            body=_link("EMAIL_SIGNIN", "accountA"),
            expected=_ok(_LINK_KEYS, oobCodeReturn="present"),
            delivery="suppressed-by-returnOobLink",
        ),
        _stage(
            "email-link-mismatched-email",
            group="email-link",
            basis="control",
            route="end-user",
            method="signInWithEmailLink",
            body={
                "email": "$binding:accountB.email",
                "oobCode": "$binding:emailLinkCodeSecond",
            },
            expected=_refused("INVALID_OOB_CODE"),
            note="Negative control: a valid code presented with another owned address.",
        ),
        _stage(
            "deleted-user-link-generate",
            group="deleted-user",
            basis="setup",
            route="admin",
            method="sendOobCode",
            body=_link("PASSWORD_RESET", "accountB"),
            expected=_ok(_LINK_KEYS, oobCodeReturn="present"),
            delivery="suppressed-by-returnOobLink",
        ),
        _stage(
            "account-b-delete",
            group="deleted-user",
            basis="setup",
            route="admin",
            method="delete",
            body={"localId": "$binding:accountB.localId"},
            expected=_ok(["kind"]),
        ),
        _stage(
            "reset-after-delete",
            group="deleted-user",
            basis="diagnostic",
            route="end-user",
            method="resetPassword",
            body={
                "oobCode": "$binding:deletedUserCode",
                "newPassword": "$binding:accountB.nextPassword",
            },
            expected=_refused("USER_DISABLED"),
            note=(
                "The local runtime reports USER_DISABLED for a code whose owner was "
                "deleted. The production error class is unobserved."
            ),
        ),
        _stage(
            "link-generate-unknown-email",
            group="unknown-email",
            basis="diagnostic",
            route="admin",
            method="sendOobCode",
            body={
                "requestType": "PASSWORD_RESET",
                "email": "$binding:unknownEmail",
                "returnOobLink": True,
            },
            expected=_ok(["email", "kind"], oobCodeReturn="absent"),
            delivery="suppressed-by-returnOobLink",
            note=(
                "The local runtime answers 200 without a code for an address that "
                "never existed. Whether production refuses privileged link "
                "generation for an unknown address is unobserved."
            ),
        ),
    ]
    return stages


def _address_lookup(identifier: str, requires: str) -> dict[str, Any]:
    """Look both owned addresses up in one privileged request."""
    return {
        "id": identifier,
        "account": None,
        "operationType": "auth-lookup",
        "selector": "email",
        "routeClass": "admin",
        "method": "POST",
        "path": _ADMIN.format(project="{project}", method="lookup"),
        "body": {"email": ["$binding:accountA.email", "$binding:accountB.email"]},
        "requires": requires,
    }


def campaign_recovery() -> list[dict[str, Any]]:
    """Recover only identities owned by immutable create events.

    Email discovery is batched because it can recover a UID that was already
    learned by a create response, but an address alone never authorizes a
    delete. The two UID absence checks are separate typed proofs from the final
    batched address absence check.
    """
    rows: list[dict[str, Any]] = [
        _address_lookup("recover-discover", "the owned identifiers, however they arose")
    ]
    for account in ("accountA", "accountB"):
        rows.append(
            {
                "id": "recover-delete-" + account,
                "account": account,
                "operationType": "auth-delete",
                "selector": "localId",
                "routeClass": "admin",
                "method": "POST",
                "path": _ADMIN.format(project="{project}", method="delete"),
                "body": {"localId": "$binding:" + account + ".localId"},
                "tolerates": "already absent",
                "identifierSource": "the immutable create event, confirmed by discovery",
            }
        )
    for account in ("accountA", "accountB"):
        rows.append(
            {
                "id": "recover-uid-absence-" + account,
                "account": account,
                "operationType": "auth-lookup",
                "selector": "localId",
                "routeClass": "admin",
                "method": "POST",
                "path": _ADMIN.format(project="{project}", method="lookup"),
                "body": {"localId": "$binding:" + account + ".localId"},
                "requires": "typed users[] absence for the immutable UID",
            }
        )
    rows.append(_address_lookup("recover-absence", "typed absence of both addresses"))
    return rows


def unobserved_conditions() -> list[dict[str, Any]]:
    """Conditions this campaign deliberately does not observe."""
    return [
        {
            "id": "code-expiry",
            "reason": (
                "The published lifetime of an action code is measured in hours, so "
                "an expiry observation cannot fit a bounded single-iteration run."
            ),
            "wouldRequire": "an out-of-band wait outside this campaign envelope",
        },
        {
            "id": "delivered-message",
            "reason": (
                "Every stage uses the privileged link-return path, so no message "
                "reaches a delivery network and no mailbox is read."
            ),
            "wouldRequire": "a mailbox oracle and an accepted delivery cost",
        },
        {
            "id": "action-page-redirect",
            "reason": (
                "The hosted action page, continueUrl handling and dynamic-link "
                "rewriting are a separate browser-facing boundary."
            ),
            "wouldRequire": "a browser transport and a configured authorized domain",
        },
        {
            "id": "tenant-scoped-codes",
            "reason": "Tenant routing has its own declared campaign and configuration.",
            "wouldRequire": "a tenant fixture and tenant configuration approval",
        },
    ]


def campaign_cases() -> list[dict[str, Any]]:
    """The accepted functional cases and the explicitly excluded neighbours."""
    accepted = [
        ("action-code/password-reset-lifecycle", "password-reset"),
        ("action-code/password-reset-refused-policy", "password-reset"),
        ("action-code/password-change-transition", "password-reset"),
        ("action-code/verify-email-lifecycle", "verify-email"),
        ("action-code/email-link-lifecycle", "email-link"),
        ("action-code/deleted-owner", "deleted-user"),
    ]
    outside = [
        ("action-code/expiry", "Expiry needs an out-of-band wait; declared unobserved"),
        (
            "action-code/delivered-email",
            "Delivery is suppressed by the link-return path",
        ),
        ("action-code/tenant", "Tenant routing is a separate campaign"),
        ("action-code/blocking-function", "Blocking functions are a separate campaign"),
        (
            "action-code/continue-url-redirect",
            "The hosted action page and continueUrl are a browser boundary",
        ),
        ("action-code/sdk", "SDK surfaces are compared in their own lanes"),
        (
            "action-code/verify-and-change-email",
            "VERIFY_AND_CHANGE_EMAIL needs a second owned address and its own matrix",
        ),
    ]
    return [
        {"id": identifier, "admission": "accepted", "group": group}
        for identifier, group in accepted
    ] + [
        {"id": identifier, "admission": "outside", "reason": reason}
        for identifier, reason in outside
    ]


def _validate_project(project: Any) -> str:
    if not isinstance(project, str) or _PROJECT.fullmatch(project) is None:
        raise ValueError("canonical project required")
    return project


def compiled_methods(nonce: str = NONCE_TEMPLATE, *, project: str = LOCAL_PROJECT) -> tuple[str, ...]:
    """Return the exact Auth methods used by every compiled campaign row."""
    _validate_project(project)
    if nonce != NONCE_TEMPLATE and not re.fullmatch(r"[0-9a-f]{32}", nonce):
        raise ValueError("fresh 32-character hexadecimal nonce required")
    methods = []
    for row in (*campaign_stages(), *campaign_recovery()):
        method = row["path"].rsplit("accounts:", 1)[-1]
        if method not in methods:
            methods.append(method)
    return tuple(methods)


def campaign_manifest(
    nonce: str = NONCE_TEMPLATE, *, project: str = LOCAL_PROJECT
) -> dict[str, Any]:
    """Return the frozen campaign manifest for one fresh owned namespace."""
    if nonce != NONCE_TEMPLATE and not re.fullmatch(r"[0-9a-f]{32}", nonce):
        raise ValueError("fresh 32-character hexadecimal nonce required")
    project = _validate_project(project)
    stages = campaign_stages()
    recovery = campaign_recovery()
    return {
        "contract": CONTRACT,
        "campaignId": CAMPAIGN_ID,
        "nonce": nonce,
        "nonceStatus": "syntax-only; freshness and ownership unverified",
        "transport": "unbound",
        "localProject": project,
        "sourceBinding": {"commit": None, "artifactSha256": None},
        "uniqueObligation": (
            "code ownership, consumption, reuse and post-transition validity for "
            "PASSWORD_RESET, VERIFY_EMAIL and EMAIL_SIGNIN codes obtained without "
            "any message delivery"
        ),
        "deliveryBoundary": {
            "mechanism": "privileged accounts:sendOobCode with returnOobLink true",
            "messagesDelivered": 0,
            "addressDomain": EMAIL_DOMAIN,
            "rationale": (
                "The reserved .invalid domain cannot receive mail, so a delivery "
                "that happened despite the link-return path would still be inert."
            ),
        },
        "ownedAccounts": _accounts(nonce),
        "stages": stages,
        "recovery": recovery,
        "unobservedConditions": unobserved_conditions(),
        "secretFields": list(SECRET_FIELDS),
        "budget": {
            "observationRequests": len(stages) + 2,
            "recoveryRequests": len(recovery),
            "managementRequests": 2,
            "totalRequests": len(stages) + len(recovery) + 2,
            "maxConcurrency": 1,
            "requestRatePerSecondMax": 4,
            "requestRateEnforced": True,
            "wallSeconds": 300,
            "recoverySeconds": 180,
            "ownedAccountsMax": 2,
            "deliveredMessages": 0,
            "expectedMeteredUsd": 0.0,
            "planningCeilingUsd": 0.02,
            "costBasis": (
                "Identity Platform charges monthly active users, not action-code "
                "requests. Two ephemeral accounts are created and deleted inside "
                "the run; no message is delivered, so no messaging tariff applies."
            ),
        },
        "permissionEnvelope": {
            "role": "roles/firebaseauth.admin",
            "scope": "https://www.googleapis.com/auth/identitytoolkit",
            "projectId": project,
            "projectScope": "the single approved project",
            "methods": [f"accounts:{method}" for method in compiled_methods(nonce, project=project)],
            "notRequired": [
                "https://www.googleapis.com/auth/cloud-platform",
                "organization or folder level access",
                "any Firestore, Storage or Functions permission",
            ],
        },
        "ownerInputs": {
            "owner": None,
            "permissionReference": None,
            "projectId": None,
            "startsAt": None,
            "endsAt": None,
            "nonce": None,
            "credentialSource": None,
            "credentialRole": None,
        },
        "ownerPreconditions": [
            "A Google OAuth credential holding roles/firebaseauth.admin on the single approved project, with the identitytoolkit scope rather than cloud-platform.",
            "Confirmation that the target project has no blocking function or tenant that changes these routes.",
            "Acceptance that two accounts are created and deleted inside the approved window.",
            "A fresh, unused 32-character hexadecimal nonce supplied at approval time.",
            "A source commit and built artifact digest bound before the local side is recorded.",
            "Acceptance that the reserved example.invalid domain is usable for signUp and sendOobCode on the target project; a refusal stops the run at its first stage and fails closed, consuming the approved window without an observation.",
        ],
        "productionExecutable": False,
        "productionExecuted": False,
    }


def proposal() -> dict[str, Any]:
    """The reviewable package: a template plan plus its case admissions."""
    return {
        "kind": "production-campaign-auth-action-codes-01-v1",
        "status": "prepared-offline",
        "planTemplate": campaign_manifest(),
        "cases": campaign_cases(),
        "artifactSha256": None,
        "configurationDigest": None,
        "networkCalls": 0,
        "productionExecuted": False,
    }


def validate_proposal(value: Any) -> bool:
    """Reject drift, supplied owner inputs and any opened production entry."""
    if value != proposal():
        raise ValueError("campaign proposal drift or owner inputs supplied")
    plan = value["planTemplate"]
    if plan["productionExecutable"] or value["productionExecuted"]:
        raise ValueError("production entry is closed")
    if any(
        case.get("admission") == "accepted" and "expiry" in case["id"]
        for case in value["cases"]
    ):
        raise ValueError("unbounded case admitted")
    return True


def manifest_digest(value: dict[str, Any]) -> str:
    """Canonical digest used to bind a receipt to the plan it executed."""
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def write_manifest(path: Path) -> str:
    value = proposal()
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    return hashlib.sha256(path.read_bytes()).hexdigest()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--nonce", default=NONCE_TEMPLATE)
    parser.add_argument("--write", type=Path)
    arguments = parser.parse_args()
    if arguments.write is not None:
        print(write_manifest(arguments.write))
    else:
        print(json.dumps(campaign_manifest(arguments.nonce), indent=2, sort_keys=True))
