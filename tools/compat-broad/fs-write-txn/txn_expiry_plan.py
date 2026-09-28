"""Compile the frozen transaction cases into a bounded, owner-blocked campaign plan.

The plan is the complete script of what the campaign would send, how long it
would wait, what it may spend and which resources it locks. It is pure data and
contacts nothing. Without an owner permission the proposal stays BLOCKED_OWNER.
"""

from __future__ import annotations

import hashlib
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1]))

import txn_expiry_cases as cases
from batch_contract import NUMBER, PROJECT
from broad_contract import digest

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent

CONTRACT = "txn-expiry-retry-plan-v1"
DATABASE = "(default)"

PHASES = (
    "preflight",
    "setup",
    "idle-expiry",
    "finished-token",
    "retry-token",
    "readback",
    "cleanup",
)

#: Hard per-response ceiling. Every reply in this campaign is a single small
#: document, a transaction token or a status; nothing streams.
MAX_RESPONSE_BYTES = 65_536
MAX_REQUEST_BYTES = 8_192

#: Slots reserved beyond the compiled operations. Recovery may have to roll back
#: every transaction the run holds before it can delete anything. That is one
#: per BeginTransaction the plan sends, not one per transaction it expects to
#: get: a begin the case table expects to be refused can still issue a token,
#: and the collector takes responsibility for releasing it.
DATA_SLOT_HEADROOM = 20

#: Per-request time bound. Every request in this campaign is a small unary call.
DEFAULT_REQUEST_TIMEOUT_SECONDS = 10
#: The single request that is expected to block: production does not refuse an
#: out-of-band write to a locked document immediately, it waits for the lock.
CONTENDED_REQUEST_TIMEOUT_SECONDS = 120
METADATA_REQUESTS = 8
CREDENTIAL_REQUESTS = 2

#: Wall-clock envelope for the observation phase. It must cover every
#: per-request timeout plus every scheduled wait, with headroom; a test
#: enforces that.
WALL_SECONDS = 1200

#: Recovery runs on its own deadline after the observation envelope is spent,
#: so an exhausted observation budget still leaves room to give owned documents
#: back. The run can therefore occupy the project for the two windows in
#: sequence, and the permission the owner grants has to say so rather than
#: naming the observation window alone.
RECOVERY_SECONDS = 180

REQUEST_COST_MICROUSD = 100
#: Conservative fixed network reserve. Every response is capped at 64 KiB and
#: the campaign sends fewer than 80 requests, so the real transfer is a few
#: MiB; the reserve adds a 32 MiB framing and buffering allowance on top.
NETWORK_RESERVE_MIB = 32
NETWORK_RATE_MICROUSD_PER_GIB = 230_000

SOURCE_FILES = (
    "txn_expiry_cases.py",
    "txn_expiry_plan.py",
    "txn_expiry_collector.py",
    "txn_expiry_comparison.py",
    "txn_expiry_shadow.py",
    "txn_wire.py",
    "../batch_wire.py",
)

NONCE_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{15,63}$")
OWNER_PATTERN = re.compile(r"^[0-9a-f]{32}$")


def _validate_identity(nonce, owner_id):
    if not isinstance(nonce, str) or not NONCE_PATTERN.match(nonce):
        raise ValueError("nonce must be 16-64 url-safe characters")
    if not isinstance(owner_id, str) or not OWNER_PATTERN.match(owner_id):
        raise ValueError("owner identity must be 32 lowercase hex characters")


#: The owned collection namespace. Production campaigns keep their documents
#: below `oracle/<nonce>/<campaign>` so the shared Ledger's document lock,
#: `project/<project>/firestore/<database>/documents/oracle/<nonce>/txn-expiry-04/*`,
#: covers exactly what the run creates and nothing else.
CAMPAIGN_SEGMENT = "txn-expiry-04"


def document_prefix(nonce):
    return f"oracle/{nonce}/{CAMPAIGN_SEGMENT}"


def _op(
    slot,
    phase,
    rpc,
    *,
    case_id=None,
    role=None,
    wait=0,
    opens=None,
    closes=None,
    idle_of=None,
    timeout=DEFAULT_REQUEST_TIMEOUT_SECONDS,
    detail=None,
    verifies=None,
):
    return {
        "slot": slot,
        "phase": phase,
        "rpc": rpc,
        "caseId": case_id,
        "verifiesCase": verifies,
        "role": role,
        "waitSeconds": wait,
        "opensTransaction": opens,
        "closesTransaction": closes,
        "idleOfTransaction": idle_of,
        "timeoutSeconds": timeout,
        "detail": detail,
        "maxRequestBytes": MAX_REQUEST_BYTES,
        "maxResponseBytes": MAX_RESPONSE_BYTES,
    }


def _with_post_state_readbacks(steps):
    """Read each observed document back before anything can overwrite it.

    A case's response code says what the backend answered, not what it did. The
    readback goes immediately after the case it verifies, so a refusal that
    nevertheless changed the document, and a success that changed nothing, are
    both visible. Placed any later, the next write to the same role would hide
    the difference.
    """
    placed = []
    for step in steps:
        placed.append(step)
        if not step["caseId"] or not step["role"]:
            continue
        placed.append(
            _op(
                f"verify/{step['slot']}",
                "readback",
                "GetDocument",
                role=step["role"],
                verifies=step["caseId"],
                detail="post-state readback for the case immediately before it",
            )
        )
    return placed


def _operations():
    steps = []
    roles = cases.RESOURCE_ROLES

    for role in roles:
        steps.append(
            _op(f"preflight/absence/{role}", "preflight", "GetDocument", role=role)
        )
    for role in roles:
        steps.append(
            _op(
                f"setup/create/{role}",
                "setup",
                "Commit",
                role=role,
                detail="conditional create with exists:false and an owner marker",
            )
        )

    # --- idle expiry -------------------------------------------------------
    holders = (
        ("a", "locked-a"),
        ("b", "locked-b"),
        ("c", "locked-c"),
        ("d", "locked-d"),
    )
    for tag, role in holders:
        steps.append(
            _op(f"idle/begin/{tag}", "idle-expiry", "BeginTransaction", opens=tag)
        )
        steps.append(
            _op(
                f"idle/read/{tag}",
                "idle-expiry",
                "GetDocument",
                role=role,
                detail="transactional read that takes the document lock",
            )
        )
    steps.append(
        _op(
            "idle/lock-held",
            "idle-expiry",
            "Commit",
            case_id="idle-expiry/lock-held-before-idle",
            role="locked-c",
            timeout=CONTENDED_REQUEST_TIMEOUT_SECONDS,
            detail="out-of-band commit while transaction c still holds the lock",
        )
    )
    steps.append(
        _op(
            "idle/commit-before",
            "idle-expiry",
            "Commit",
            case_id="idle-expiry/commit-before-idle",
            role="locked-d",
            wait=20,
            closes="d",
            idle_of="d",
        )
    )
    steps.append(
        _op(
            "idle/commit-after",
            "idle-expiry",
            "Commit",
            case_id="idle-expiry/commit-after-idle",
            role="locked-a",
            wait=cases.maximum_elapsed_seconds() - 20,
            closes="a",
            idle_of="a",
        )
    )
    steps.append(
        _op(
            "idle/rollback-after",
            "idle-expiry",
            "Rollback",
            case_id="idle-expiry/rollback-after-idle",
            role="locked-b",
            closes="b",
            idle_of="b",
        )
    )
    steps.append(
        _op(
            "idle/lock-released",
            "idle-expiry",
            "Commit",
            case_id="idle-expiry/lock-released-after-idle",
            role="locked-a",
            idle_of="a",
            timeout=CONTENDED_REQUEST_TIMEOUT_SECONDS,
            detail="out-of-band commit after the holding transaction expired",
        )
    )
    steps.append(
        _op(
            "idle/release/c",
            "idle-expiry",
            "Rollback",
            closes="c",
            detail="best-effort release of the contention holder",
        )
    )

    # --- finished tokens ---------------------------------------------------
    steps.append(
        _op("finished/begin/e", "finished-token", "BeginTransaction", opens="e")
    )
    steps.append(
        _op(
            "finished/rollback-after-begin",
            "finished-token",
            "Rollback",
            case_id="finished-token/rollback-after-begin",
            closes="e",
        )
    )
    steps.append(
        _op(
            "finished/rollback-after-rollback",
            "finished-token",
            "Rollback",
            case_id="finished-token/rollback-after-rollback",
        )
    )
    steps.append(
        _op("finished/begin/f", "finished-token", "BeginTransaction", opens="f")
    )
    steps.append(
        _op(
            "finished/commit/f",
            "finished-token",
            "Commit",
            role="control",
            closes="f",
            detail="commit inside the transaction so its token is finished",
        )
    )
    steps.append(
        _op(
            "finished/rollback-after-commit",
            "finished-token",
            "Rollback",
            case_id="finished-token/rollback-after-commit",
        )
    )

    # --- retry tokens ------------------------------------------------------
    steps.append(_op("retry/begin/g", "retry-token", "BeginTransaction", opens="g"))
    steps.append(_op("retry/rollback/g", "retry-token", "Rollback", closes="g"))
    steps.append(
        _op(
            "retry/rolled-back-previous",
            "retry-token",
            "BeginTransaction",
            case_id="retry-token/retry-with-rolled-back-previous",
            opens="h",
        )
    )
    steps.append(_op("retry/rollback/h", "retry-token", "Rollback", closes="h"))
    steps.append(_op("retry/begin/i", "retry-token", "BeginTransaction", opens="i"))
    steps.append(
        _op("retry/commit/i", "retry-token", "Commit", role="control", closes="i")
    )
    steps.append(
        _op(
            "retry/committed-previous",
            "retry-token",
            "BeginTransaction",
            case_id="retry-token/retry-with-committed-previous",
        )
    )
    steps.append(
        _op(
            "retry/begin/j",
            "retry-token",
            "BeginTransaction",
            opens="j",
            detail="read-only transaction used as an ineligible retry source",
        )
    )
    steps.append(
        _op(
            "retry/read-only-previous",
            "retry-token",
            "BeginTransaction",
            case_id="retry-token/retry-with-read-only-previous",
        )
    )
    steps.append(_op("retry/rollback/j", "retry-token", "Rollback", closes="j"))
    steps.append(
        _op(
            "retry/unissued-previous",
            "retry-token",
            "BeginTransaction",
            case_id="retry-token/retry-with-unissued-previous",
        )
    )
    steps.append(
        _op(
            "retry/malformed-previous",
            "retry-token",
            "BeginTransaction",
            case_id="retry-token/retry-with-malformed-previous",
        )
    )

    steps = _with_post_state_readbacks(steps)

    # --- final post-state readback ------------------------------------------
    for role in ("locked-a", "locked-d", "control"):
        steps.append(_op(f"readback/{role}", "readback", "GetDocument", role=role))

    # --- cleanup -----------------------------------------------------------
    for role in roles:
        steps.append(
            _op(f"cleanup/owned-read/{role}", "cleanup", "GetDocument", role=role)
        )
        steps.append(
            _op(
                f"cleanup/conditional-delete/{role}",
                "cleanup",
                "Commit",
                role=role,
                detail="delete guarded by the observed updateTime",
            )
        )
        steps.append(
            _op(f"cleanup/typed-absence/{role}", "cleanup", "GetDocument", role=role)
        )
    return tuple(steps)


#: The same eight zero bytes the recorded production corpus used for
#: `rollback-unknown` and `commit-with-unknown-transaction`, where production
#: answered `Invalid transaction.` rather than a decoding error. Reusing the
#: published constant keeps this row directly comparable to that corpus.
UNISSUED_RETRY_TOKEN = bytes(8)


def unissued_retry_token(nonce):
    """A well-formed retry token this database never issued."""
    return UNISSUED_RETRY_TOKEN


def compile_plan(nonce, owner_id, *, project=PROJECT, database=DATABASE):
    _validate_identity(nonce, owner_id)
    prefix = document_prefix(nonce)
    operations = _operations()
    resources = [
        {"role": role, "path": f"{prefix}/{role}"} for role in cases.RESOURCE_ROLES
    ]
    data_requests = len(operations) + DATA_SLOT_HEADROOM
    requests = data_requests + METADATA_REQUESTS + CREDENTIAL_REQUESTS
    network_microusd = round(NETWORK_RESERVE_MIB * NETWORK_RATE_MICROUSD_PER_GIB / 1024)
    cost = requests * REQUEST_COST_MICROUSD + network_microusd
    return {
        "contract": CONTRACT,
        "campaign": cases.CAMPAIGN,
        "casesDigest": cases.cases_digest(),
        "projectId": project,
        "projectNumber": NUMBER,
        "database": database,
        "nonce": nonce,
        "ownerId": owner_id,
        "documentPrefix": prefix,
        "resources": resources,
        "operations": [dict(step) for step in operations],
        "bounds": {
            "maxRequestBytes": MAX_REQUEST_BYTES,
            "maxResponseBytes": MAX_RESPONSE_BYTES,
            "deadlineSeconds": WALL_SECONDS,
            "recoverySeconds": RECOVERY_SECONDS,
            "defaultRequestTimeoutSeconds": DEFAULT_REQUEST_TIMEOUT_SECONDS,
            "worstCaseSeconds": (
                sum(step["timeoutSeconds"] for step in operations)
                + sum(step["waitSeconds"] for step in operations)
            ),
            "concurrency": 1,
        },
        "budget": {
            "requests": requests,
            "dataRequests": data_requests,
            "metadataRequests": METADATA_REQUESTS,
            "credentialRequests": CREDENTIAL_REQUESTS,
            "accounts": 0,
            "resources": len(resources),
            "concurrency": 1,
            "observationSeconds": WALL_SECONDS,
            "recoverySeconds": RECOVERY_SECONDS,
            "wallSeconds": WALL_SECONDS + RECOVERY_SECONDS,
            "costMicrousd": cost,
            "networkMicrousd": network_microusd,
        },
    }


def budget_estimate(plan):
    budget = plan["budget"]
    return {
        "kind": "txn-expiry-conservative-pricing-v1",
        "requestSlots": budget["requests"],
        "requestCostMicrousd": REQUEST_COST_MICROUSD,
        "requestPlanningMicrousd": budget["requests"] * REQUEST_COST_MICROUSD,
        "maxResponseBytes": MAX_RESPONSE_BYTES,
        "networkPlanningMiB": NETWORK_RESERVE_MIB,
        "networkRateMicrousdPerGiB": NETWORK_RATE_MICROUSD_PER_GIB,
        "networkPlanningMicrousd": budget["networkMicrousd"],
        "totalPlanningMicrousd": budget["costMicrousd"],
        "basis": (
            "Every reply is one small document, a transaction token or a "
            "status, capped at 64 KiB. The network line is a reserve, not a "
            "measurement."
        ),
        "isExpectedInvoice": False,
    }


def resource_locks(plan):
    prefix = plan["documentPrefix"]
    return [
        {
            "key": f"firestore:documents:{plan['database']}:{prefix}",
            "mode": "EXCLUSIVE",
        },
        {"key": "firestore:indexes", "mode": "READ"},
        {"key": "firestore:rules", "mode": "READ"},
        {"key": "firestore:database-configuration", "mode": "READ"},
        {"key": "auth:configuration", "mode": "READ"},
        {"key": "project:api-key-binding", "mode": "READ"},
    ]


def source_inputs():
    values = {}
    for name in SOURCE_FILES:
        path = HERE / name
        if not path.exists():
            raise FileNotFoundError(f"declared campaign source {name} is missing")
        values[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    return values


def source_digest():
    return digest(source_inputs())


def manifest(nonce, owner_id):
    plan = compile_plan(nonce, owner_id)
    return {
        "kind": "txn-expiry-prepared-manifest-v1",
        "campaign": plan["campaign"],
        "casesDigest": plan["casesDigest"],
        "sourceDigest": source_digest(),
        "plan": plan,
        "resourceLocks": resource_locks(plan),
        "pricing": budget_estimate(plan),
        "notPrepared": [dict(entry) for entry in cases.NOT_PREPARED],
    }


OWNER_FIELDS_REQUIRED = (
    "issuedAt",
    "expiresAt",
    "ownerIdentity",
    "permissionReference",
    "apiKeyDigest",
    "authConfigDigest",
    "databaseProjectionDigest",
    "pricingLocation",
    "pricingCheckedAt",
    "recoveryOwner",
    "recoveryDiagnostics",
    "credentialPrincipal",
)


def required_permission(plan, manifest_digest=None):
    budget = plan["budget"]
    return {
        "kind": "txn-expiry-required-permission-v1",
        "campaign": plan["campaign"],
        "nonce": plan["nonce"],
        "ownerId": plan["ownerId"],
        "project": plan["projectId"],
        "projectNumber": plan["projectNumber"],
        "database": plan["database"],
        "casesDigest": plan["casesDigest"],
        "collectorSourceDigest": source_digest(),
        "manifestSha256": manifest_digest,
        "resourceLocks": resource_locks(plan),
        "requestUpperBound": budget["requests"],
        "accountUpperBound": 0,
        "resourceUpperBound": budget["resources"],
        "concurrencyUpperBound": 1,
        "timeUpperBound": budget["wallSeconds"],
        "costUpperMicrousd": budget["costMicrousd"],
        "allowedReobservations": 0,
    }


def proposal(nonce, owner_id):
    """The credential-free owner proposal. It never carries a permission."""
    value = manifest(nonce, owner_id)
    return {
        "kind": "txn-expiry-owner-proposal-v1",
        "status": "BLOCKED_OWNER",
        "permissionGranted": False,
        "manifest": value,
        "manifestDigest": digest(value),
        "requiredPermission": required_permission(value["plan"], digest(value)),
        "ownerFieldsRequired": list(OWNER_FIELDS_REQUIRED),
        "note": (
            "Preparation only. No credential, endpoint or production request is "
            "bound here. Execution needs a separate owner permission, a fresh "
            "nonce and admission review."
        ),
    }
