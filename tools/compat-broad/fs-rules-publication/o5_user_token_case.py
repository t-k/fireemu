"""Compile the finite FS-RULES user-token observation matrix offline.

This module describes an eventual bounded observation. It never obtains a
credential, publishes a Ruleset, starts a process, or sends a request. Every
value it returns is a design artifact.

The matrix evaluates Firestore Security Rules with end-user identity tokens.
An administrator REST observation cannot substitute for these rows, because an
administrator bypasses Rules evaluation entirely. The rows therefore fix the
principal for each request and keep the credential out of the compiled plan:
an operation carries a credential *reference* label only.

Every document the matrix reads or writes carries a typed payload, so an
executor never invents one. A field value is either a literal or the typed
reference ``{"$principal": "<ref>"}``, which resolves to the uid of the account
this campaign created for that principal reference.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from typing import Any

CAMPAIGN = "FS-RULES-USER-TOKEN-MATRIX-01"
CASE_CONTRACT = "fs-rules-user-token-case-v2"

_NONCE = re.compile(r"^[0-9a-f]{32}$")
_PROJECT = re.compile(r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$")
_DATABASE = re.compile(r"^[a-z][a-z0-9-]{2,61}[a-z0-9]$")
_TENANT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{3,35}$")

RULESET_A = "A"
RULESET_B = "B"

OK = "OK"
PERMISSION_DENIED = "PERMISSION_DENIED"
UNAUTHENTICATED = "UNAUTHENTICATED"

PRINCIPAL_OWNER = "owner-a"
PRINCIPAL_OTHER = "other-b"
PRINCIPAL_ANONYMOUS = "anonymous-c"
PRINCIPAL_TENANT = "tenant-d"
PRINCIPAL_UNAUTHENTICATED = "unauthenticated"
PRINCIPAL_EXPIRED = "expired-token"
PRINCIPAL_MALFORMED = "malformed-bearer"
PRINCIPAL_EMPTY = "empty-bearer"
# Revocation principals (RULES-REVOKE-005, phase 1). Each signs in, then an
# administrator action is applied to the account while the ID token is still
# unexpired: refresh tokens revoked (validSince advanced), account disabled, or
# account deleted. The compiled expectation is the current local decision; the
# production expectation is a stated hypothesis, not an observation.
PRINCIPAL_REVOKED = "revoked-e"
PRINCIPAL_DISABLED = "disabled-f"
PRINCIPAL_DELETED = "deleted-g"
PRINCIPAL_REVOKED_EXPIRED = "revoked-expired-token"

# Principals backed by an account this campaign creates and must delete again.
ACCOUNT_PRINCIPALS = (
    PRINCIPAL_OWNER,
    PRINCIPAL_OTHER,
    PRINCIPAL_ANONYMOUS,
    PRINCIPAL_TENANT,
    PRINCIPAL_REVOKED,
    PRINCIPAL_DISABLED,
    PRINCIPAL_DELETED,
)

# The administrator action applied to an account after its token was minted.
POST_SIGN_IN_REVOKE = "revoke"
POST_SIGN_IN_DISABLE = "disable"
POST_SIGN_IN_DELETE = "delete"

_CREDENTIAL_CLASS = {
    PRINCIPAL_OWNER: "user-id-token",
    PRINCIPAL_OTHER: "user-id-token",
    PRINCIPAL_ANONYMOUS: "user-id-token",
    PRINCIPAL_TENANT: "user-id-token",
    PRINCIPAL_UNAUTHENTICATED: "absent",
    PRINCIPAL_EXPIRED: "user-id-token",
    PRINCIPAL_MALFORMED: "malformed",
    PRINCIPAL_EMPTY: "empty",
    PRINCIPAL_REVOKED: "user-id-token",
    PRINCIPAL_DISABLED: "user-id-token",
    PRINCIPAL_DELETED: "user-id-token",
    PRINCIPAL_REVOKED_EXPIRED: "user-id-token",
}

# What production is expected to do with an unexpired ID token whose account
# was revoked, disabled or deleted after sign-in. Firebase verifies ID tokens
# statelessly; revocation is detected only when a verifier asks for it
# (`checkRevoked`, `validSince`), so Security Rules are expected to keep
# accepting the token until `exp`. This is a hypothesis to be observed, and it
# differs from the current local decision, which refuses such tokens.
PRODUCTION_HYPOTHESIS_ALLOWED_UNTIL_EXP = {
    "status": OK,
    "basis": (
        "Firebase documentation, Manage user sessions / Detect ID token "
        "revocation: an ID token stays valid until exp unless the verifier "
        "checks revocation; Rules evaluation is not documented to check it"
    ),
}

OWNER_FIELD = "ownerUid"
CLAIM_NAME = "o5role"
CLAIM_VALUE = "editor"
EMAIL_DOMAIN = "o5-user-token.invalid"

# Guards the Rules reference but nothing ever creates. Their absence is the
# point of the control rows that depend on them.
_NEVER_CREATED = ("exists-guard-absent", "getafter-control-guard")


def digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode()
    ).hexdigest()


def principal_reference(ref: str) -> dict[str, str]:
    """A typed placeholder for the uid of the account created for ``ref``."""
    return {"$principal": ref}


def _scope_segment(nonce: str) -> str:
    # A Rules path segment is written literally; a leading digit is avoided.
    return "n" + nonce


def _document_path(nonce: str, document: str) -> str:
    return f"o5-user-token/{_scope_segment(nonce)}/cases/{document}"


def _resource(project: str, database: str, suffix: str) -> str:
    return f"projects/{project}/databases/{database}/documents/{suffix}"


def _rules_source(nonce: str, tenant: str, *, owner_read: bool) -> str:
    scope = _scope_segment(nonce)
    base = f"/databases/$(database)/documents/o5-user-token/{scope}/cases"
    authed = "request.auth != null"
    owns = f"request.auth.uid == resource.data.{OWNER_FIELD}"
    writes_own = f"request.resource.data.{OWNER_FIELD} == request.auth.uid"
    owner_condition = f"{authed} && {owns}" if owner_read else "false"
    claim = f"request.auth.token.{CLAIM_NAME} == '{CLAIM_VALUE}'"
    tenant_clause = (
        f"allow get: if {authed}"
        + f" && request.auth.token.firebase.tenant == '{tenant}';"
    )
    exists_present = f"allow get: if {authed} && exists({base}/exists-guard-present);"
    exists_absent = f"allow get: if {authed} && exists({base}/exists-guard-absent);"
    get_clause = (
        f"allow get: if {authed}"
        + f" && get({base}/owned-a).data.{OWNER_FIELD} == request.auth.uid;"
    )
    getafter_target = (
        f"allow create: if {authed}"
        + f" && getAfter({base}/getafter-guard).data.{OWNER_FIELD}"
        + " == request.auth.uid;"
    )
    getafter_control_target = (
        f"allow create: if {authed}"
        + f" && getAfter({base}/getafter-control-guard).data.{OWNER_FIELD}"
        + " == request.auth.uid;"
    )
    clauses: list[tuple[str, str]] = [
        ("{document}", "allow read, write: if false;"),
        ("owned-a", f"allow get: if {owner_condition};"),
        ("owned-b", f"allow get: if {authed} && {owns};"),
        ("public-open", "allow get: if request.auth == null;"),
        ("claim-gated", f"allow get: if {authed} && {claim};"),
        ("tenant-gated", tenant_clause),
        ("exists-guarded", exists_present),
        ("exists-guarded-missing", exists_absent),
        ("get-guarded", get_clause),
        ("getafter-target", getafter_target),
        ("getafter-control-target", getafter_control_target),
        ("getafter-guard", f"allow create: if {authed} && {writes_own};"),
        ("multiwrite-x", f"allow get, update: if {authed} && {owns};"),
        ("multiwrite-y", "allow create: if false;"),
    ]
    lines = [
        "rules_version = '2';",
        "service cloud.firestore {",
        "  match /databases/{database}/documents {",
    ]
    for document, clause in clauses:
        lines.append(f"    match /o5-user-token/{scope}/cases/{document} {{")
        lines.append(f"      {clause}")
        lines.append("    }")
    lines.extend(["  }", "}"])
    return "\n".join(lines)


def _fixture_fields(nonce: str, document: str) -> dict[str, Any]:
    fields: dict[str, Any] = {"nonce": nonce, "document": document}
    owner = {
        "owned-a": PRINCIPAL_OWNER,
        "get-guarded": PRINCIPAL_OWNER,
        "multiwrite-x": PRINCIPAL_OWNER,
        "owned-b": PRINCIPAL_OTHER,
    }.get(document)
    if owner is not None:
        fields[OWNER_FIELD] = principal_reference(owner)
    if document == "multiwrite-x":
        fields["generation"] = "initial"
    return fields


# Fixture documents created by the owner's administrator credential before any
# user-token row runs. Administrator setup is allowed; administrator evidence is
# not allowed to stand in for a user-token authorization result.
_FIXTURES = (
    "owned-a",
    "owned-b",
    "public-open",
    "claim-gated",
    "tenant-gated",
    "exists-guard-present",
    "exists-guarded",
    "exists-guarded-missing",
    "get-guarded",
    "multiwrite-x",
)

# Documents an observation row attempts to create. They are owned resources for
# cleanup purposes from the moment the request is attempted, response or not.
_OBSERVATION_CREATED = (
    "getafter-target",
    "getafter-guard",
    "getafter-control-target",
    "multiwrite-y",
)


def _owned_payload(nonce: str, document: str) -> dict[str, Any]:
    return {
        "nonce": nonce,
        "document": document,
        OWNER_FIELD: principal_reference(PRINCIPAL_OWNER),
    }


def _operation(
    case_id: str,
    *,
    role: str,
    ruleset: str,
    principal: str,
    method: str,
    targets: tuple[str, ...],
    condition: str,
    status: str,
    detail: str,
    writes: tuple[dict[str, Any], ...] = (),
    expect_fields: dict[str, Any] | None = None,
    production_hypothesis: dict[str, Any] | None = None,
    principal_action: dict[str, str] | None = None,
) -> dict[str, Any]:
    expect: dict[str, Any] = {"status": status, "detail": detail}
    if expect_fields is not None:
        expect["fields"] = expect_fields
    if production_hypothesis is not None:
        expect["productionHypothesis"] = dict(production_hypothesis)
    operation = {
        "caseId": case_id,
        "role": role,
        "ruleset": ruleset,
        "principal": principal,
        "credential": {"class": _CREDENTIAL_CLASS[principal], "ref": principal},
        "transport": "firestore-rest-v1",
        "method": method,
        "targets": list(targets),
        "writes": [dict(write) for write in writes],
        "createdDocuments": [
            write["document"] for write in writes if write["operation"] == "create"
        ],
        "condition": condition,
        "expect": expect,
    }
    if principal_action is not None:
        # An administrator step the collector performs immediately before
        # this row, after the row's principal has already been accepted by an
        # earlier row: the record proves accept-then-refuse, not refuse alone.
        operation["principalAction"] = dict(principal_action)
    return operation


def principal_actions(plan: Mapping[str, Any]) -> list[dict[str, Any]]:
    """The administrator steps the matrix performs between rows, in order."""
    return [
        {"beforeIndex": row["index"], **row["principalAction"]}
        for row in plan["observation"]
        if row.get("principalAction")
    ]


def _matrix(nonce: str, tenant: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    add = rows.append

    # Principal separation on one resource, ruleset A.
    add(
        _operation(
            "a-owner-reads-own-document",
            role="primary",
            ruleset=RULESET_A,
            principal=PRINCIPAL_OWNER,
            method="get",
            targets=("owned-a",),
            condition="principal-separation",
            status=OK,
            detail="owner-uid-matches-resource-owner",
            expect_fields=_fixture_fields(nonce, "owned-a"),
        )
    )
    add(
        _operation(
            "a-second-user-denied-on-foreign-document",
            role="primary",
            ruleset=RULESET_A,
            principal=PRINCIPAL_OTHER,
            method="get",
            targets=("owned-a",),
            condition="principal-separation",
            status=PERMISSION_DENIED,
            detail="uid-mismatch",
        )
    )
    add(
        _operation(
            "a-second-user-reads-own-document",
            role="control",
            ruleset=RULESET_A,
            principal=PRINCIPAL_OTHER,
            method="get",
            targets=("owned-b",),
            condition="principal-separation",
            status=OK,
            detail="second-principal-is-authenticated-and-owns-its-document",
            expect_fields=_fixture_fields(nonce, "owned-b"),
        )
    )
    add(
        _operation(
            "a-anonymous-principal-denied-on-owned-document",
            role="primary",
            ruleset=RULESET_A,
            principal=PRINCIPAL_ANONYMOUS,
            method="get",
            targets=("owned-a",),
            condition="principal-separation",
            status=PERMISSION_DENIED,
            detail="anonymous-provider-user-has-a-uid-but-not-the-owner-uid",
        )
    )

    # request.auth null explicitness, including anonymous versus unauthenticated.
    add(
        _operation(
            "a-unauthenticated-denied-on-owned-document",
            role="primary",
            ruleset=RULESET_A,
            principal=PRINCIPAL_UNAUTHENTICATED,
            method="get",
            targets=("owned-a",),
            condition="request-auth-null",
            status=PERMISSION_DENIED,
            detail="request-auth-is-null-so-the-owner-clause-is-false",
        )
    )
    add(
        _operation(
            "a-unauthenticated-allowed-by-explicit-null-clause",
            role="primary",
            ruleset=RULESET_A,
            principal=PRINCIPAL_UNAUTHENTICATED,
            method="get",
            targets=("public-open",),
            condition="request-auth-null",
            status=OK,
            detail="rule-requires-request-auth-to-be-explicitly-null",
            expect_fields=_fixture_fields(nonce, "public-open"),
        )
    )
    add(
        _operation(
            "a-anonymous-denied-by-explicit-null-clause",
            role="control",
            ruleset=RULESET_A,
            principal=PRINCIPAL_ANONYMOUS,
            method="get",
            targets=("public-open",),
            condition="request-auth-null",
            status=PERMISSION_DENIED,
            detail="an-anonymous-provider-principal-is-not-an-absent-principal",
        )
    )
    add(
        _operation(
            "a-authenticated-denied-by-explicit-null-clause",
            role="control",
            ruleset=RULESET_A,
            principal=PRINCIPAL_OWNER,
            method="get",
            targets=("public-open",),
            condition="request-auth-null",
            status=PERMISSION_DENIED,
            detail="an-authenticated-principal-must-not-satisfy-request-auth-null",
        )
    )

    # Custom claim.
    add(
        _operation(
            "a-custom-claim-principal-allowed",
            role="primary",
            ruleset=RULESET_A,
            principal=PRINCIPAL_OWNER,
            method="get",
            targets=("claim-gated",),
            condition="custom-claim",
            status=OK,
            detail=f"token-carries-{CLAIM_NAME}-{CLAIM_VALUE}",
            expect_fields=_fixture_fields(nonce, "claim-gated"),
        )
    )
    add(
        _operation(
            "a-principal-without-custom-claim-denied",
            role="control",
            ruleset=RULESET_A,
            principal=PRINCIPAL_OTHER,
            method="get",
            targets=("claim-gated",),
            condition="custom-claim",
            status=PERMISSION_DENIED,
            detail="claim-absent-from-token",
        )
    )

    # Tenant.
    add(
        _operation(
            "a-tenant-principal-allowed",
            role="primary",
            ruleset=RULESET_A,
            principal=PRINCIPAL_TENANT,
            method="get",
            targets=("tenant-gated",),
            condition="tenant",
            status=OK,
            detail=f"token-firebase-tenant-equals-{tenant}",
            expect_fields=_fixture_fields(nonce, "tenant-gated"),
        )
    )
    add(
        _operation(
            "a-non-tenant-principal-denied",
            role="control",
            ruleset=RULESET_A,
            principal=PRINCIPAL_OWNER,
            method="get",
            targets=("tenant-gated",),
            condition="tenant",
            status=PERMISSION_DENIED,
            detail="project-level-principal-has-no-tenant-member",
        )
    )

    # exists / get / getAfter.
    add(
        _operation(
            "a-exists-guard-present-allows-read",
            role="primary",
            ruleset=RULESET_A,
            principal=PRINCIPAL_OWNER,
            method="get",
            targets=("exists-guarded",),
            condition="exists",
            status=OK,
            detail="guard-document-exists",
            expect_fields=_fixture_fields(nonce, "exists-guarded"),
        )
    )
    add(
        _operation(
            "a-exists-guard-absent-denies-read",
            role="control",
            ruleset=RULESET_A,
            principal=PRINCIPAL_OWNER,
            method="get",
            targets=("exists-guarded-missing",),
            condition="exists",
            status=PERMISSION_DENIED,
            detail="guard-document-exists-guard-absent-is-never-created",
        )
    )
    add(
        _operation(
            "a-get-guard-matches-principal",
            role="primary",
            ruleset=RULESET_A,
            principal=PRINCIPAL_OWNER,
            method="get",
            targets=("get-guarded",),
            condition="get",
            status=OK,
            detail="guard-document-owner-equals-request-auth-uid",
            expect_fields=_fixture_fields(nonce, "get-guarded"),
        )
    )
    add(
        _operation(
            "a-get-guard-rejects-other-principal",
            role="control",
            ruleset=RULESET_A,
            principal=PRINCIPAL_OTHER,
            method="get",
            targets=("get-guarded",),
            condition="get",
            status=PERMISSION_DENIED,
            detail="guard-document-owner-differs-from-request-auth-uid",
        )
    )
    add(
        _operation(
            "a-getafter-satisfied-by-same-commit-write",
            role="primary",
            ruleset=RULESET_A,
            principal=PRINCIPAL_OWNER,
            method="commit",
            targets=("getafter-target", "getafter-guard"),
            condition="getAfter",
            status=OK,
            detail="partner-write-in-the-same-atomic-commit-satisfies-getAfter",
            writes=(
                {
                    "document": "getafter-target",
                    "operation": "create",
                    "fields": _owned_payload(nonce, "getafter-target"),
                },
                {
                    "document": "getafter-guard",
                    "operation": "create",
                    "fields": _owned_payload(nonce, "getafter-guard"),
                },
            ),
        )
    )
    add(
        _operation(
            "a-getafter-unsatisfied-without-partner-write",
            role="control",
            ruleset=RULESET_A,
            principal=PRINCIPAL_OWNER,
            method="commit",
            targets=("getafter-control-target",),
            condition="getAfter",
            status=PERMISSION_DENIED,
            detail=(
                "getafter-control-guard-is-never-created-by-any-row-so-the-"
                "guard-is-absent-after-this-commit"
            ),
            writes=(
                {
                    "document": "getafter-control-target",
                    "operation": "create",
                    "fields": _owned_payload(nonce, "getafter-control-target"),
                },
            ),
        )
    )

    # Atomic multiwrite refusal and its post-state.
    add(
        _operation(
            "a-atomic-multiwrite-refused-as-a-whole",
            role="primary",
            ruleset=RULESET_A,
            principal=PRINCIPAL_OWNER,
            method="commit",
            targets=("multiwrite-x", "multiwrite-y"),
            condition="atomic-multiwrite",
            status=PERMISSION_DENIED,
            detail="one-denied-write-refuses-the-whole-commit",
            writes=(
                {
                    "document": "multiwrite-x",
                    "operation": "update",
                    "fields": {"generation": "updated"},
                },
                {
                    "document": "multiwrite-y",
                    "operation": "create",
                    "fields": {"nonce": nonce, "document": "multiwrite-y"},
                },
            ),
        )
    )
    add(
        _operation(
            "a-multiwrite-poststate-is-unchanged",
            role="poststate",
            ruleset=RULESET_A,
            principal=PRINCIPAL_OWNER,
            method="get",
            targets=("multiwrite-x",),
            condition="atomic-multiwrite",
            status=OK,
            detail="allowed-half-of-the-refused-commit-was-not-applied",
            expect_fields=_fixture_fields(nonce, "multiwrite-x"),
        )
    )

    # Negative credential classes. These must not be confused with a Rules
    # denial: an unusable credential is an authentication refusal.
    for principal, case_id in (
        (PRINCIPAL_EXPIRED, "a-expired-token-is-unauthenticated"),
        (PRINCIPAL_MALFORMED, "a-malformed-bearer-is-unauthenticated"),
        (PRINCIPAL_EMPTY, "a-empty-bearer-is-unauthenticated"),
    ):
        add(
            _operation(
                case_id,
                role="negative",
                ruleset=RULESET_A,
                principal=principal,
                method="get",
                targets=("owned-a",),
                condition="credential-refusal",
                status=UNAUTHENTICATED,
                detail="authentication-refusal-precedes-rules-evaluation",
            )
        )

    # Credential revocation within the token lifetime (RULES-REVOKE-005 phase
    # 1). The target clause admits any authenticated principal, so the only
    # variable is whether the runtime still honors a token whose account was
    # revoked, disabled or deleted after it was minted. Each principal is
    # first accepted (the positive control), then the administrator action is
    # performed by the collector as a step, then the same token is presented
    # again. The compiled status of the second row is the current local
    # decision; production is a stated hypothesis.
    for principal, action, slug, detail in (
        (
            PRINCIPAL_REVOKED,
            POST_SIGN_IN_REVOKE,
            "revoked-refresh-tokens",
            "local-refuses-a-token-issued-before-validSince",
        ),
        (
            PRINCIPAL_DISABLED,
            POST_SIGN_IN_DISABLE,
            "disabled-account",
            "local-refuses-a-token-of-a-disabled-account",
        ),
        (
            PRINCIPAL_DELETED,
            POST_SIGN_IN_DELETE,
            "deleted-account",
            "local-refuses-a-token-of-a-deleted-account",
        ),
    ):
        add(
            _operation(
                f"a-{slug}-accepted-before-the-action",
                role="control",
                ruleset=RULESET_A,
                principal=principal,
                method="get",
                targets=("exists-guarded",),
                condition="credential-revocation",
                status=OK,
                detail="the-same-token-is-accepted-before-the-administrator-action",
                expect_fields=_fixture_fields(nonce, "exists-guarded"),
                production_hypothesis={
                    "status": OK,
                    "basis": "an unrevoked, unexpired ID token is accepted",
                },
            )
        )
        add(
            _operation(
                f"a-{slug}-within-exp",
                role="primary",
                ruleset=RULESET_A,
                principal=principal,
                method="get",
                targets=("exists-guarded",),
                condition="credential-revocation",
                status=UNAUTHENTICATED,
                detail=detail,
                production_hypothesis=PRODUCTION_HYPOTHESIS_ALLOWED_UNTIL_EXP,
                principal_action={"ref": principal, "action": action},
            )
        )
    add(
        _operation(
            "a-revoked-account-expired-token-control",
            role="control",
            ruleset=RULESET_A,
            principal=PRINCIPAL_REVOKED_EXPIRED,
            method="get",
            targets=("exists-guarded",),
            condition="credential-revocation",
            status=UNAUTHENTICATED,
            detail="an-expired-token-is-refused-regardless-of-revocation",
            production_hypothesis={
                "status": UNAUTHENTICATED,
                "basis": "an expired ID token is refused before Rules evaluation",
            },
        )
    )

    # Ruleset transition. Only the owner clause differs between A and B.
    add(
        _operation(
            "b-owner-denied-after-ruleset-transition",
            role="primary",
            ruleset=RULESET_B,
            principal=PRINCIPAL_OWNER,
            method="get",
            targets=("owned-a",),
            condition="ruleset-transition",
            status=PERMISSION_DENIED,
            detail="same-principal-same-resource-decision-changes-with-the-ruleset",
        )
    )
    add(
        _operation(
            "b-unchanged-null-clause-still-allows-unauthenticated",
            role="control",
            ruleset=RULESET_B,
            principal=PRINCIPAL_UNAUTHENTICATED,
            method="get",
            targets=("public-open",),
            condition="ruleset-transition",
            status=OK,
            detail="clauses-outside-the-transition-are-unaffected",
            expect_fields=_fixture_fields(nonce, "public-open"),
        )
    )
    add(
        _operation(
            "b-unchanged-claim-clause-still-allows-owner",
            role="control",
            ruleset=RULESET_B,
            principal=PRINCIPAL_OWNER,
            method="get",
            targets=("claim-gated",),
            condition="ruleset-transition",
            status=OK,
            detail="the-denied-principal-is-still-authenticated-under-ruleset-B",
            expect_fields=_fixture_fields(nonce, "claim-gated"),
        )
    )
    return rows


def _accounts(nonce: str, tenant: str) -> list[dict[str, Any]]:
    return [
        {
            "ref": PRINCIPAL_OWNER,
            "kind": "email-password",
            "email": f"o5a-{nonce}@{EMAIL_DOMAIN}",
            "tenant": None,
            "claims": {CLAIM_NAME: CLAIM_VALUE},
        },
        {
            "ref": PRINCIPAL_OTHER,
            "kind": "email-password",
            "email": f"o5b-{nonce}@{EMAIL_DOMAIN}",
            "tenant": None,
            "claims": {},
        },
        {
            "ref": PRINCIPAL_ANONYMOUS,
            "kind": "anonymous",
            "email": None,
            "tenant": None,
            "claims": {},
        },
        {
            "ref": PRINCIPAL_TENANT,
            "kind": "email-password",
            "email": f"o5d-{nonce}@{EMAIL_DOMAIN}",
            "tenant": tenant,
            "claims": {},
        },
        {
            "ref": PRINCIPAL_REVOKED,
            "kind": "email-password",
            "email": f"o5e-{nonce}@{EMAIL_DOMAIN}",
            "tenant": None,
            "claims": {},
            "postSignIn": POST_SIGN_IN_REVOKE,
        },
        {
            "ref": PRINCIPAL_DISABLED,
            "kind": "email-password",
            "email": f"o5f-{nonce}@{EMAIL_DOMAIN}",
            "tenant": None,
            "claims": {},
            "postSignIn": POST_SIGN_IN_DISABLE,
        },
        {
            "ref": PRINCIPAL_DELETED,
            "kind": "email-password",
            "email": f"o5g-{nonce}@{EMAIL_DOMAIN}",
            "tenant": None,
            "claims": {},
            "postSignIn": POST_SIGN_IN_DELETE,
        },
    ]


def _principals(nonce: str, tenant: str) -> list[dict[str, Any]]:
    accounts = {entry["ref"]: entry for entry in _accounts(nonce, tenant)}
    rows = [
        {
            "ref": ref,
            "kind": accounts[ref]["kind"],
            "tenant": accounts[ref]["tenant"],
            "claims": accounts[ref]["claims"],
            "account": True,
            "postSignIn": accounts[ref].get("postSignIn"),
        }
        for ref in ACCOUNT_PRINCIPALS
    ]
    rows.extend(
        {"ref": ref, "kind": kind, "tenant": None, "claims": {}, "account": False}
        for ref, kind in (
            (PRINCIPAL_UNAUTHENTICATED, "absent"),
            (PRINCIPAL_EXPIRED, "expired-id-token"),
            (PRINCIPAL_REVOKED_EXPIRED, "expired-id-token"),
            (PRINCIPAL_MALFORMED, "malformed"),
            (PRINCIPAL_EMPTY, "empty"),
        )
    )
    return rows


def _compile(project: str, database: str, nonce: str, tenant: str) -> dict[str, Any]:
    if not isinstance(project, str) or not _PROJECT.fullmatch(project):
        raise ValueError("malformed project")
    if not isinstance(database, str) or (
        database != "(default)" and not _DATABASE.fullmatch(database)
    ):
        raise ValueError("malformed database")
    if not isinstance(nonce, str) or not _NONCE.fullmatch(nonce):
        raise ValueError("nonce must be 32 lowercase hexadecimal characters")
    if not isinstance(tenant, str) or not _TENANT.fullmatch(tenant):
        raise ValueError("malformed tenant")

    observation = _matrix(nonce, tenant)
    scope = _resource(project, database, f"o5-user-token/{_scope_segment(nonce)}/cases")
    owned = [
        _resource(project, database, _document_path(nonce, document))
        for document in (*_FIXTURES, *_OBSERVATION_CREATED)
    ]
    plan = {
        "schemaVersion": 2,
        "contract": CASE_CONTRACT,
        "campaignId": CAMPAIGN,
        "status": "PREPARATION_ONLY",
        "productionExecuted": False,
        "productionReady": False,
        "project": project,
        "database": database,
        "nonce": nonce,
        "tenant": tenant,
        "tenantIsPlaceholder": True,
        "ownedScope": scope,
        "ownedResources": owned,
        "ownedAccounts": _accounts(nonce, tenant),
        "neverCreatedDocuments": [
            _resource(project, database, _document_path(nonce, document))
            for document in _NEVER_CREATED
        ],
        "fieldResolution": {
            "$principal": (
                "resolves to the uid of the account this campaign created for "
                "that principal reference"
            ),
            "ownerField": OWNER_FIELD,
        },
        "fixtures": [
            {
                "document": document,
                "resource": _resource(
                    project, database, _document_path(nonce, document)
                ),
                "fields": _fixture_fields(nonce, document),
                "createdBy": "administrator-setup",
            }
            for document in _FIXTURES
        ],
        "observationCreatedDocuments": [
            {
                "document": document,
                "resource": _resource(
                    project, database, _document_path(nonce, document)
                ),
                "createdBy": "user-token-observation",
            }
            for document in _OBSERVATION_CREATED
        ],
        "principals": _principals(nonce, tenant),
        "rulesets": {
            RULESET_A: {
                "label": RULESET_A,
                "source": _rules_source(nonce, tenant, owner_read=True),
                "ownerClause": "allow",
            },
            RULESET_B: {
                "label": RULESET_B,
                "source": _rules_source(nonce, tenant, owner_read=False),
                "ownerClause": "deny",
            },
        },
        "observation": observation,
        "conditions": sorted({row["condition"] for row in observation}),
        "evidenceBoundary": (
            "administrator-rest-evidence-cannot-substitute-for-a-user-token-"
            "rules-decision"
        ),
    }
    for index, row in enumerate(plan["observation"]):
        row["index"] = index
        row["resources"] = [
            _resource(project, database, _document_path(nonce, document))
            for document in row["targets"]
        ]
    plan["planDigest"] = digest({key: plan[key] for key in plan if key != "planDigest"})
    return plan


def compile_case(
    project: str, database: str, nonce: str, tenant: str = "o5-user-token-tenant"
) -> dict[str, Any]:
    plan = _compile(project, database, nonce, tenant)
    validate_case(plan)
    return plan


def validate_case(plan: Any) -> None:
    if not isinstance(plan, dict) or plan.get("campaignId") != CAMPAIGN:
        raise ValueError("campaign binding drift")
    if plan.get("contract") != CASE_CONTRACT:
        raise ValueError("case contract drift")
    try:
        expected = _compile(
            plan["project"], plan["database"], plan["nonce"], plan["tenant"]
        )
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError("invalid case identity") from error
    if plan != expected:
        raise ValueError("compiled case drift")
    _validate_paths(plan)
    _validate_payloads(plan)


def _validate_paths(plan: dict[str, Any]) -> None:
    scope = plan["ownedScope"]
    for resource in plan["ownedResources"]:
        suffix = resource.split("/documents/", 1)[1]
        if len(suffix.split("/")) % 2 != 0:
            raise ValueError("document path must have an even segment count")
        if not resource.startswith(scope + "/"):
            raise ValueError("owned resource escapes the owned scope")
    for row in plan["observation"]:
        for resource in row["resources"]:
            if resource not in plan["ownedResources"]:
                raise ValueError("observation targets an unowned resource")


def _validate_payloads(plan: dict[str, Any]) -> None:
    """Every document the matrix touches must have a frozen payload.

    Without this an executor would invent field names, and a compiled row whose
    expectation depends on ``resource.data`` would not be reproducible.
    """
    fixtures = {entry["document"]: entry["fields"] for entry in plan["fixtures"]}
    accounts = {entry["ref"] for entry in plan["ownedAccounts"]}
    created: set[str] = set()
    for row in plan["observation"]:
        for write in row["writes"]:
            if write["operation"] not in ("create", "update"):
                raise ValueError("unknown write operation")
            if not isinstance(write.get("fields"), dict) or not write["fields"]:
                raise ValueError("write without a frozen payload")
            if write["operation"] == "create":
                if write["document"] in fixtures or write["document"] in created:
                    raise ValueError("create targets an existing document")
                created.add(write["document"])
            elif write["document"] not in fixtures:
                raise ValueError("update targets a document with no fixture")
        for document in row["targets"]:
            if document not in fixtures and document not in created:
                raise ValueError("row targets a document with no frozen payload")
    for entry in plan["fixtures"]:
        _validate_references(entry["fields"], accounts)
    for row in plan["observation"]:
        for write in row["writes"]:
            _validate_references(write["fields"], accounts)
        if "fields" in row["expect"]:
            _validate_references(row["expect"]["fields"], accounts)


def _validate_references(fields: Any, accounts: set[str]) -> None:
    if not isinstance(fields, dict):
        raise ValueError("payload must be a mapping")  # noqa: TRY004
    for value in fields.values():
        if isinstance(value, dict):
            if set(value) != {"$principal"}:
                raise ValueError("unknown typed payload value")
            if value["$principal"] not in accounts:
                raise ValueError("payload references an unknown principal")
        elif not isinstance(value, str):
            raise ValueError(  # noqa: TRY004
                "payload values must be strings or typed references"
            )
