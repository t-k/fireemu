"""Compile the finite FS-RULES user-token observation matrix offline.

This module describes an eventual bounded production observation. It never
obtains a credential, publishes a Ruleset, starts a process, or sends a
request. Every value it returns is a design artifact.

The matrix evaluates Firestore Security Rules with end-user identity tokens.
An administrator REST observation cannot substitute for these rows, because an
administrator bypasses Rules evaluation entirely. The rows therefore fix the
principal for each request and keep the credential out of the compiled plan:
an operation carries a credential *reference* label only.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

CAMPAIGN = "FS-RULES-USER-TOKEN-MATRIX-01"
CASE_CONTRACT = "fs-rules-user-token-case-v1"

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

_CREDENTIAL_CLASS = {
    PRINCIPAL_OWNER: "user-id-token",
    PRINCIPAL_OTHER: "user-id-token",
    PRINCIPAL_ANONYMOUS: "user-id-token",
    PRINCIPAL_TENANT: "user-id-token",
    PRINCIPAL_UNAUTHENTICATED: "absent",
    PRINCIPAL_EXPIRED: "user-id-token",
    PRINCIPAL_MALFORMED: "malformed",
    PRINCIPAL_EMPTY: "empty",
}

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
_OBSERVATION_CREATED = ("getafter-target", "getafter-guard", "multiwrite-y")

CLAIM_NAME = "o5role"
CLAIM_VALUE = "editor"


def digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode()
    ).hexdigest()


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
    owns = "request.auth.uid == resource.data.ownerUid"
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
        + f" && get({base}/owned-a).data.ownerUid == request.auth.uid;"
    )
    getafter_target = (
        f"allow create: if {authed}"
        + f" && getAfter({base}/getafter-guard).data.ownerUid == request.auth.uid;"
    )
    getafter_guard = (
        f"allow create: if {authed}"
        + " && request.resource.data.ownerUid == request.auth.uid;"
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
        ("getafter-guard", getafter_guard),
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
    writes: tuple[str, ...] = (),
) -> dict[str, Any]:
    return {
        "caseId": case_id,
        "role": role,
        "ruleset": ruleset,
        "principal": principal,
        "credential": {"class": _CREDENTIAL_CLASS[principal], "ref": principal},
        "transport": "firestore-rest-v1",
        "method": method,
        "targets": list(targets),
        "createdDocuments": list(writes),
        "condition": condition,
        "expect": {"status": status, "detail": detail},
    }


def _matrix(tenant: str) -> list[dict[str, Any]]:
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

    # request.auth null explicitness.
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
            detail="guard-document-does-not-exist",
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
            writes=("getafter-target", "getafter-guard"),
        )
    )
    add(
        _operation(
            "a-getafter-unsatisfied-without-partner-write",
            role="control",
            ruleset=RULESET_A,
            principal=PRINCIPAL_OWNER,
            method="commit",
            targets=("getafter-target",),
            condition="getAfter",
            status=PERMISSION_DENIED,
            detail="guard-document-is-absent-after-the-commit",
            writes=("getafter-target",),
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
            writes=("multiwrite-y",),
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
        )
    )
    return rows


def _principals(nonce: str, tenant: str) -> list[dict[str, Any]]:
    return [
        {
            "ref": PRINCIPAL_OWNER,
            "kind": "email-password",
            "uidLabel": f"o5a-{nonce}",
            "tenant": None,
            "claims": {CLAIM_NAME: CLAIM_VALUE},
            "ownedFixtures": ["owned-a", "get-guarded", "multiwrite-x"],
        },
        {
            "ref": PRINCIPAL_OTHER,
            "kind": "email-password",
            "uidLabel": f"o5b-{nonce}",
            "tenant": None,
            "claims": {},
            "ownedFixtures": ["owned-b"],
        },
        {
            "ref": PRINCIPAL_ANONYMOUS,
            "kind": "anonymous",
            "uidLabel": f"o5c-{nonce}",
            "tenant": None,
            "claims": {},
            "ownedFixtures": [],
        },
        {
            "ref": PRINCIPAL_TENANT,
            "kind": "email-password",
            "uidLabel": f"o5d-{nonce}",
            "tenant": tenant,
            "claims": {},
            "ownedFixtures": [],
        },
        {
            "ref": PRINCIPAL_UNAUTHENTICATED,
            "kind": "absent",
            "claims": {},
            "ownedFixtures": [],
        },
        {
            "ref": PRINCIPAL_EXPIRED,
            "kind": "expired-id-token",
            "claims": {},
            "ownedFixtures": [],
        },
        {
            "ref": PRINCIPAL_MALFORMED,
            "kind": "malformed",
            "claims": {},
            "ownedFixtures": [],
        },
        {"ref": PRINCIPAL_EMPTY, "kind": "empty", "claims": {}, "ownedFixtures": []},
    ]


def _fixture_fields(nonce: str, document: str) -> dict[str, Any]:
    fields: dict[str, Any] = {"nonce": nonce, "document": document}
    owner = {
        "owned-a": PRINCIPAL_OWNER,
        "get-guarded": PRINCIPAL_OWNER,
        "multiwrite-x": PRINCIPAL_OWNER,
        "owned-b": PRINCIPAL_OTHER,
    }.get(document)
    if owner is not None:
        fields["ownerUidRef"] = owner
    if document == "multiwrite-x":
        fields["generation"] = "initial"
    return fields


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

    observation = _matrix(tenant)
    scope = _resource(project, database, f"o5-user-token/{_scope_segment(nonce)}/cases")
    owned = [
        _resource(project, database, _document_path(nonce, document))
        for document in (*_FIXTURES, *_OBSERVATION_CREATED)
    ]
    plan = {
        "schemaVersion": 1,
        "contract": CASE_CONTRACT,
        "campaignId": CAMPAIGN,
        "status": "PREPARATION_ONLY",
        "productionExecuted": False,
        "productionReady": False,
        "project": project,
        "database": database,
        "nonce": nonce,
        "tenant": tenant,
        "ownedScope": scope,
        "ownedResources": owned,
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
