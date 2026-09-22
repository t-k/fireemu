"""Campaign manifest for the FS-RULES user-token observation matrix.

The manifest freezes the inputs an execution would have to reproduce, states a
budget estimate and a permission envelope, and lists the owner preconditions
that this repository cannot satisfy. It grants no authority: ``admit`` always
raises, and the status never leaves ``PREPARATION_ONLY``.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from o5_user_token_case import CAMPAIGN, compile_case, digest, validate_case

CAMPAIGN_CONTRACT = "fs-rules-user-token-campaign-v1"

_SOURCE_FILES = (
    "o5_user_token_case.py",
    "o5_user_token_collector.py",
    "o5_user_token_campaign.py",
    "o5_user_token_comparator.py",
    "o5_user_token_comparator_v2.py",
    "o5_user_token_semantics.py",
    "o5_user_token_shadow.py",
    "o5_user_token_local_run.py",
    "o5_user_token_descriptor.py",
)

# Unit prices are the public Firestore Standard edition list prices used only to
# show that the campaign is small. They are an estimate, not a quoted tariff,
# and the owner accepts the real bill.
_PRICE_PER_DOCUMENT_READ_USD = 0.06 / 100_000
_PRICE_PER_DOCUMENT_WRITE_USD = 0.18 / 100_000

RULES_MANAGEMENT_OBSERVATION = (
    "baseline-release-get",
    "baseline-ruleset-get",
    "baseline-executable-get",
    "create-a",
    "create-a-get",
    "patch-a",
    "patch-a-get",
    "patch-a-executable",
    "create-b",
    "create-b-get",
    "patch-b",
    "patch-b-get",
    "patch-b-executable",
)
RULES_MANAGEMENT_RECOVERY = (
    "restore-patch",
    "restore-get",
    "restore-executable",
    "restore-get-executable",
    "delete-a-get",
    "delete-a",
    "delete-a-absence",
    "delete-b-get",
    "delete-b",
    "delete-b-absence",
)


def rules_management_plan() -> dict[str, Any]:
    """Compiler-owned fixed Gate slots for response-derived Rules operations."""
    return {
        "dispatchKind": "closed-v1",
        "observation": [
            {"id": value, "timeout": 12.0} for value in RULES_MANAGEMENT_OBSERVATION
        ],
        "recovery": [
            {"id": value, "timeout": 12.0} for value in RULES_MANAGEMENT_RECOVERY
        ],
        "totalRequests": len(RULES_MANAGEMENT_OBSERVATION)
        + len(RULES_MANAGEMENT_RECOVERY),
        "requestCostMicrousd": 1,
        "wallClockDeadlineSeconds": 600.0,
        "recoveryDeadlineSeconds": 300.0,
    }


def gate_management_plan(plan: dict[str, Any]) -> dict[str, Any]:
    """Compile every wire exchange, preserving publication and action boundaries."""
    setup = setup_plan(plan)
    value = rules_management_plan()
    entries = [
        {"id": "setup/" + item["id"], "timeout": 2.0} for item in setup["operations"]
    ]
    entries.extend(value["observation"][:3])
    active = None
    for row in plan["observation"]:
        if row["ruleset"] != active:
            label = row["ruleset"].lower()
            entries.extend(
                {"id": slot, "timeout": 12.0}
                for slot in (
                    f"create-{label}",
                    f"create-{label}-get",
                    f"patch-{label}",
                    f"patch-{label}-get",
                    f"patch-{label}-executable",
                )
            )
            active = row["ruleset"]
        if row.get("principalAction"):
            entries.extend(
                {"id": f"action/{row['index']}/{stage}", "timeout": 2.0}
                for stage in ("mutation", "readback")
            )
        entries.append({"id": f"data/{row['index']}", "timeout": 2.0})
    cleanup = [
        {
            "id": f"cleanup/document/{resource.rsplit('/', 1)[-1]}/{stage}",
            "timeout": 2.0,
        }
        for resource in plan["ownedResources"]
        for stage in ("read", "delete", "absence")
    ] + [
        {"id": f"cleanup/account/{account['ref']}/{stage}", "timeout": 2.0}
        for account in plan["ownedAccounts"]
        for stage in ("read", "delete", "absence")
    ]
    value["observation"] = entries
    value["recovery"] = cleanup + value["recovery"]
    value["totalRequests"] = len(entries) + len(value["recovery"])
    effects = {}
    for item in setup["operations"]:
        subject = (
            "document/" + item["document"]
            if item["service"] == "firestore"
            else "account/" + item["accountRef"]
        )
        action = (
            "write"
            if item["id"].endswith("/claim-update")
            else "read"
            if item["id"].endswith("/signin")
            else "create"
        )
        effects["setup/" + item["id"]] = [{"subject": subject, "action": action}]
    documents = {resource.rsplit("/", 1)[-1] for resource in plan["ownedResources"]}
    for row in plan["observation"]:
        effects[f"data/{row['index']}"] = (
            [
                {
                    "subject": "document/" + write["document"],
                    "action": {"create": "create", "delete": "delete"}.get(
                        write["operation"], "write"
                    ),
                }
                for write in row["writes"]
            ]
            if row["writes"]
            else [
                {"subject": "document/" + document, "action": "read"}
                for document in row["targets"]
                if document in documents
            ]
        )
        if action := row.get("principalAction"):
            subject = "account/" + action["ref"]
            effects[f"action/{row['index']}/mutation"] = [
                {
                    "subject": subject,
                    "action": "delete" if action["action"] == "delete" else "write",
                }
            ]
            effects[f"action/{row['index']}/readback"] = [
                {"subject": subject, "action": "read"}
            ]
    for entry in value["observation"]:
        entry["effects"] = effects.get(entry["id"], [])
    for entry in value["recovery"]:
        slot = entry["id"]
        if slot.startswith("cleanup/"):
            subject, step = slot.removeprefix("cleanup/").rsplit("/", 1)
        else:
            subject = (
                "release/baseline"
                if slot.startswith("restore-")
                else "ruleset/" + slot.split("-")[1]
            )
            step = slot
        entry["dependency"] = {"subject": subject, "step": step}
    return value


def rules_management_contract(plan: dict[str, Any]) -> dict[str, Any]:
    """Bind cleanup authority to the exact subjects and their compiled effects."""
    observation = gate_management_plan(plan)["observation"]
    subjects = [
        {
            "id": "document/" + resource.rsplit("/", 1)[-1],
            "kind": "document",
            "resource": resource,
        }
        for resource in plan["ownedResources"]
    ] + [
        {
            "id": "account/" + account["ref"],
            "kind": "account",
            "resource": account["ref"],
        }
        for account in plan["ownedAccounts"]
    ]
    for subject in subjects:
        subject["creationSlots"] = [
            slot["id"]
            for slot in observation
            if any(
                effect == {"subject": subject["id"], "action": "create"}
                for effect in slot["effects"]
            )
        ]
        subject["mutationSlots"] = [
            slot["id"]
            for slot in observation
            if any(
                effect["subject"] == subject["id"]
                and effect["action"] in {"write", "delete"}
                for effect in slot["effects"]
            )
        ]
    return {
        "kind": "rules-management-dependencies-v1",
        "subjects": subjects,
        "rulesets": {
            label.lower(): digest(value["source"])
            for label, value in plan["rulesets"].items()
        },
        "tenantId": plan["tenant"],
    }


OWNER_PRECONDITIONS = (
    "project and database identity confirmed by the owner",
    "a fresh nonce reserved for this campaign only",
    "an execution window with a named owner present for the whole window",
    "an administrator credential for fixture setup, custom-claim minting and cleanup",
    "Identity Platform multi-tenancy enabled with the named tenant already created",
    (
        "the two Rulesets already released by the owner, or an owner-held "
        "publication lock plus the captured bytes and version of the "
        "preexisting release"
    ),
    "a recovery owner who restores the preexisting release if the window ends early",
    "accepted cost ceiling and data-retention decision for the run directory",
)

PERMISSION_ENVELOPE = {
    "services": ["identitytoolkit.googleapis.com", "firestore.googleapis.com"],
    "firestoreScope": "the campaign nonce subtree only",
    "authScope": (
        "seven throwaway accounts created by this campaign only, three of "
        "which are revoked, disabled or deleted by the administrator credential "
        "after sign-in"
    ),
    "rulesScope": "read the active release; publish only the two campaign Rulesets",
    "forbidden": [
        "any document outside the nonce subtree",
        "any preexisting Auth account",
        "database, index, TTL or backup configuration changes",
        "concurrent execution with any other campaign in the same database",
    ],
    "concurrency": 1,
    "networkEgress": "the two listed Google APIs only",
}


def source_digests() -> dict[str, str]:
    """SHA-256 of every lane module, read from disk now.

    The collector records these as its observer identity and the acquisition
    comparator recomputes them, so a bundle produced by other bytes than the
    ones under review is named as drift rather than accepted.
    """
    here = Path(__file__).resolve().parent
    digests = {}
    for name in _SOURCE_FILES:
        path = here / name
        digests[name] = (
            hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else ""
        )
    return digests


def budget(plan: dict[str, Any]) -> dict[str, Any]:
    observation = len(plan["observation"])
    resources = len(plan["ownedResources"])
    fixtures = len(plan["fixtures"])
    accounts = plan["ownedAccounts"]
    # Per account: sign-up, plus a claim write and a re-sign-in when it carries
    # a custom claim, plus one administrator action and one lookup readback
    # when the account is revoked, disabled or deleted between two rows.
    auth_requests = sum(3 if entry["claims"] else 1 for entry in accounts) + sum(
        2 for entry in accounts if entry.get("postSignIn")
    )
    # Rules management includes baseline reads, response-derived create/read,
    # activation/readback, exact restore, and guarded delete/absence proof.
    rules_requests = len(RULES_MANAGEMENT_OBSERVATION) + len(RULES_MANAGEMENT_RECOVERY)
    # Recovery: read back, delete and verify absence for every document and
    # every account.
    recovery_requests = 3 * (resources + len(accounts))
    schedule = gate_management_plan(plan)
    total = schedule["totalRequests"]
    reads = observation + resources + len(accounts)
    writes = fixtures + resources + 4
    cost = reads * _PRICE_PER_DOCUMENT_READ_USD + writes * _PRICE_PER_DOCUMENT_WRITE_USD
    return {
        "observationRequests": observation,
        "fixtureRequests": fixtures,
        "authRequests": auth_requests,
        "rulesRequests": rules_requests,
        "recoveryRequests": recovery_requests,
        "requestUpperBound": total,
        "concurrencyUpperBound": 1,
        "perRequestTimeoutSeconds": 12.0,
        "wallClockDeadlineSeconds": 600.0,
        "recoveryDeadlineSeconds": 300.0,
        "billedDocumentReads": reads,
        "billedDocumentWrites": writes,
        "estimatedCostUsd": round(cost, 6),
        "costCeilingUsd": 1.0,
        "estimateBasis": "public Firestore Standard list prices; not a quoted tariff",
    }


def setup_plan(plan: dict[str, Any]) -> dict[str, Any]:
    """Describe only setup operations that the source-backed local runner performs.

    This is a transport contract, not production authority. Tenant lifecycle
    is deliberately absent because the campaign precondition requires the
    named tenant to exist. The three post-sign-in administrator actions belong
    to compiled observation rows and are not setup operations.
    """
    validate_case(plan)
    fixtures = [
        {
            "id": "fixture/" + entry["document"],
            "service": "firestore",
            "route": "document-create",
            "method": "PATCH",
            "path": "/v1/" + entry["resource"] + "?currentDocument.exists=false",
            "document": entry["document"],
            "resource": entry["resource"],
            "fields": entry["fields"],
            "fieldsDigest": digest(entry["fields"]),
            "precondition": {"exists": False},
            "response": {
                "name": entry["resource"],
                "fieldsDigest": digest(entry["fields"]),
                "updateTime": "response-bound",
            },
        }
        for entry in plan["fixtures"]
    ]
    auth = []
    for entry in plan["ownedAccounts"]:
        auth.append(
            {
                "id": f"account/{entry['ref']}/signup",
                "service": "identity",
                "route": "accounts:signUp",
                "method": "POST",
                "accountRef": entry["ref"],
                "tenant": entry["tenant"],
                "response": {
                    "localId": "response-bound",
                    "idToken": "response-bound",
                    "expiresIn": "response-bound",
                },
            }
        )
    owner = next(entry for entry in plan["ownedAccounts"] if entry["ref"] == "owner-a")
    auth.extend(
        [
            {
                "id": "account/owner-a/claim-update",
                "service": "identity",
                "route": "accounts:update",
                "method": "POST",
                "accountRef": owner["ref"],
                "tenant": owner["tenant"],
                "claimsDigest": digest(owner["claims"]),
                "response": {"localId": "response-bound"},
            },
            {
                "id": "account/owner-a/signin",
                "service": "identity",
                "route": "accounts:signInWithPassword",
                "method": "POST",
                "accountRef": owner["ref"],
                "tenant": owner["tenant"],
                "response": {
                    "localId": "response-bound",
                    "idToken": "response-bound",
                    "expiresIn": "response-bound",
                },
            },
        ]
    )
    return {
        "contract": "o5-user-token-setup-plan-v1",
        "fixtures": fixtures,
        "auth": auth,
        "operations": [*auth, *fixtures],
        "totalRequests": len(fixtures) + len(auth),
    }


def manifest(
    project: str, database: str, nonce: str, tenant: str = "o5-user-token-tenant"
) -> dict[str, Any]:
    plan = compile_case(project, database, nonce, tenant)
    value = {
        "contract": CAMPAIGN_CONTRACT,
        "schemaVersion": 1,
        "campaignId": CAMPAIGN,
        "status": "PREPARATION_ONLY",
        "productionExecuted": False,
        "productionReady": False,
        "frozenInputs": {
            "caseDigest": plan["planDigest"],
            "sources": source_digests(),
            "rulesetDigests": {
                label: digest(body["source"])
                for label, body in plan["rulesets"].items()
            },
        },
        "budget": budget(plan),
        "permissionEnvelope": PERMISSION_ENVELOPE,
        "ownerPreconditions": list(OWNER_PRECONDITIONS),
        "blockers": [
            "owner-permission",
            "nonce-reservation",
            "ruleset-release-authority",
            "tenant-provisioning",
            "cost-and-retention",
        ],
        "observationCase": plan,
    }
    value["manifestDigest"] = digest(
        {key: value[key] for key in value if key != "manifestDigest"}
    )
    return value


def admitted_manifest_digest(project: str, database: str, nonce: str) -> str:
    """The digest of the manifest a run of this nonce is admitted under.

    The tenant identifier is assigned by Identity Platform (or by the local
    Auth emulator) only once the run has started, so the admitted manifest is
    the one compiled with the placeholder tenant. Both sides of a comparison
    bind this digest; the tenant-specific plan digests are bound separately.
    """
    return manifest(project, database, nonce)["manifestDigest"]


def validate_manifest(value: Any) -> None:
    if not isinstance(value, dict) or value.get("contract") != CAMPAIGN_CONTRACT:
        raise ValueError("manifest contract drift")
    if value.get("status") != "PREPARATION_ONLY":
        raise ValueError("manifest status drift")
    if (
        value.get("productionExecuted") is not False
        or value.get("productionReady") is not False
    ):
        raise ValueError("manifest cannot claim production authority")
    case = value.get("observationCase")
    if not isinstance(case, dict):
        raise TypeError("invalid observation case")
    identity = [case.get(key) for key in ("project", "database", "nonce", "tenant")]
    if not all(isinstance(part, str) for part in identity):
        raise ValueError("invalid case identity")
    expected = manifest(*identity)
    if value != expected:
        raise ValueError("manifest preparation drift")


def admission(value: dict[str, Any]) -> dict[str, Any]:
    """Describe why execution is closed, without offering a way to open it."""
    validate_manifest(value)

    def admit() -> None:
        raise PermissionError(
            "no owner permission exists for "
            + CAMPAIGN
            + "; this repository cannot grant one"
        )

    return {
        "campaignId": CAMPAIGN,
        "productionReady": False,
        "blockers": list(value["blockers"]),
        "ownerPreconditions": list(value["ownerPreconditions"]),
        "admit": admit,
    }


def validate_production_packet(
    plan: dict[str, Any],
    *,
    approval: dict[str, Any],
    permission: dict[str, Any],
    capability_inputs: dict[str, Any],
    credentials: dict[str, Any],
    account_bindings: dict[str, Any],
    identity_proofs: dict[str, Any],
    gate: Any,
    ledger: Any,
    ticket: dict[str, Any],
) -> dict[str, Any]:
    """Validate commander material before O7 capability issuance.

    This is a readiness check, not an authority grant. O8 admission remains
    the only issuer, and the campaign's preparation manifest stays closed.
    """
    estimate = budget(plan)
    if estimate["requestUpperBound"] != gate_management_plan(plan)["totalRequests"]:
        raise ValueError("production packet budget differs")
    if (
        capability_inputs.get("plan") != plan
        or capability_inputs.get("planDigest") != digest(plan)
        or approval.get("status") != "approved"
        or permission.get("campaignId") != CAMPAIGN
        or permission.get("planDigest") != plan.get("planDigest")
        or not isinstance(credentials, dict)
        or not isinstance(account_bindings, dict)
        or not isinstance(identity_proofs, dict)
        or bool(identity_proofs)
        or bool(account_bindings)
        or not isinstance(ticket, dict)
        or gate is None
        or ledger is None
        or not callable(getattr(gate, "snapshot", None))
        or not callable(getattr(ledger, "snapshot", None))
    ):
        raise ValueError("production packet bindings differ")
    return estimate
