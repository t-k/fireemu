"""Frozen observation cases for the next Firestore transaction campaign.

This table is the campaign's scope. It covers the transaction conditions that no
recorded production observation has established yet: idle expiry, the state of a
token after the transaction finished, and the read-write retry token. Conditions
that a recorded production observation already established are only admitted as
in-run controls, and each such control names the evidence it repeats.

Nothing here contacts Firebase production. The table is data; the collector, the
plan and the comparator read it.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1]))

from broad_contract import digest

CAMPAIGN = "FS-TRANSACTION-EXPIRY-RETRY-04"
CONTRACT = "txn-expiry-retry-cases-v1"

#: The idle limit the local emulator enforces, from the declared limit catalog.
#: Production's actual limit is the thing this campaign observes; the number is
#: only used to place the waits safely on either side of it.
DECLARED_IDLE_LIMIT_SECONDS = 60

GROUPS = ("idle-expiry", "finished-token", "retry-token")

#: Owned document roles. The collector creates exactly these, below its own
#: nonce prefix, and deletes them again under an ownership proof.
RESOURCE_ROLES = ("control", "locked-a", "locked-b", "locked-c", "locked-d")

RPCS = (
    "BeginTransaction",
    "Commit",
    "Rollback",
    "GetDocument",
)

#: The closed set of gRPC codes any case may expect, with their canonical names.
CODES = {
    0: "OK",
    3: "INVALID_ARGUMENT",
    10: "ABORTED",
}

EXPIRED = "The referenced transaction has expired or is no longer valid."
CONTENTION = "Too much contention on these documents. Please try again."
INVALID_RETRY = "Invalid retry transaction."
INVALID_TRANSACTION = "Invalid transaction."
READ_ONLY_RETRY = "read-only transaction cannot be retried as read-write"
#: What the local emulator actually says today. It follows production's recorded
#: grammar, `Invalid value at '<proto field>' (TYPE_BYTES), Base64 decoding
#: failed for "<value>"`, naming the proto path of the field this request
#: actually carries the bad value in. Production's recorded observation of that
#: grammar is on the commit path's `transaction` field, which is a different
#: request; whether production names this field the same way is what the
#: campaign's malformed control is here to settle.
MALFORMED_BASE64 = (
    "Invalid value at 'options.read_write.retry_transaction' (TYPE_BYTES), "
    'Base64 decoding failed for "not base64!"'
)

#: A control that genuinely has no recorded production observation says so
#: explicitly rather than leaving the citation empty.
NO_PRIOR_OBSERVATION = "none-recorded"


def _case(
    identifier,
    *,
    group,
    kind,
    intent,
    rpc,
    code,
    message=None,
    resources=(),
    controls=(),
    elapsed=0,
    post_state=None,
    previously_observed=None,
):
    return {
        "id": identifier,
        "group": group,
        "kind": kind,
        "intent": intent,
        "expectedLocal": {
            "rpc": rpc,
            "code": code,
            "status": CODES[code],
            "message": message,
        },
        "resources": tuple(resources),
        "controls": tuple(controls),
        "requiresElapsedSeconds": elapsed,
        "postState": post_state,
        "previouslyObserved": previously_observed,
        "mutatesConfiguration": False,
    }


CASES = (
    # --- idle expiry -------------------------------------------------------
    _case(
        "idle-expiry/commit-before-idle",
        group="idle-expiry",
        kind="control",
        intent=(
            "A read-write transaction that holds a document read lock for less "
            "than the idle limit still commits."
        ),
        rpc="Commit",
        code=0,
        resources=("locked-d",),
        elapsed=20,
        post_state={"locked-d": "committed-before-idle"},
        previously_observed="conformance:transactions/lifecycle#commit-in-transaction",
    ),
    _case(
        "idle-expiry/commit-after-idle",
        group="idle-expiry",
        kind="observation",
        intent=(
            "Committing a read-write transaction that sat idle well past the "
            "idle limit is refused, and the document it read is unchanged."
        ),
        rpc="Commit",
        code=10,
        message=EXPIRED,
        resources=("locked-a",),
        controls=("idle-expiry/commit-before-idle",),
        elapsed=90,
        post_state={"locked-a": "created"},
    ),
    _case(
        "idle-expiry/rollback-after-idle",
        group="idle-expiry",
        kind="observation",
        intent=(
            "Rolling back a transaction that already expired on idle time is "
            "refused with the same finished-token refusal as a commit."
        ),
        rpc="Rollback",
        code=10,
        message=EXPIRED,
        resources=("locked-b",),
        controls=("finished-token/rollback-after-begin",),
        elapsed=90,
    ),
    _case(
        "idle-expiry/lock-held-before-idle",
        group="idle-expiry",
        kind="control",
        intent=(
            "While a read-write transaction holds its lock, an out-of-band "
            "commit on the same document is refused. This is the in-run proof "
            "that the lock exists; it repeats an already observed condition."
        ),
        rpc="Commit",
        code=10,
        message=CONTENTION,
        resources=("locked-c",),
        elapsed=0,
        previously_observed="conformance:transactions/lifecycle#out-of-band-write",
    ),
    _case(
        "idle-expiry/lock-released-after-idle",
        group="idle-expiry",
        kind="observation",
        intent=(
            "After the holding transaction expired on idle time, an "
            "out-of-band commit on the same document succeeds, so expiry "
            "released the lock."
        ),
        rpc="Commit",
        code=0,
        resources=("locked-a",),
        controls=("idle-expiry/lock-held-before-idle",),
        elapsed=90,
        post_state={"locked-a": "written-after-expiry"},
    ),
    # --- finished tokens ---------------------------------------------------
    _case(
        "finished-token/rollback-after-begin",
        group="finished-token",
        kind="control",
        intent="A transaction that only began can be rolled back.",
        rpc="Rollback",
        code=0,
        resources=(),
        previously_observed="conformance:transactions/lifecycle#rollback",
    ),
    _case(
        "finished-token/rollback-after-commit",
        group="finished-token",
        kind="observation",
        intent=(
            "Rolling back a transaction that already committed is refused. "
            "Only the commit-after-commit direction was observed before."
        ),
        rpc="Rollback",
        code=10,
        message=EXPIRED,
        resources=("control",),
        controls=("finished-token/rollback-after-begin",),
    ),
    _case(
        "finished-token/rollback-after-rollback",
        group="finished-token",
        kind="observation",
        intent="Rolling back the same transaction twice is refused.",
        rpc="Rollback",
        code=10,
        message=EXPIRED,
        resources=(),
        controls=("finished-token/rollback-after-begin",),
    ),
    # --- retry tokens ------------------------------------------------------
    _case(
        "retry-token/retry-with-rolled-back-previous",
        group="retry-token",
        kind="control",
        intent=(
            "Beginning a read-write transaction that names a rolled-back "
            "transaction as its retry token succeeds."
        ),
        rpc="BeginTransaction",
        code=0,
        resources=(),
        previously_observed=(
            "conformance:transactions/lifecycle#begin-read-write-with-retry-transaction"
        ),
    ),
    _case(
        "retry-token/retry-with-committed-previous",
        group="retry-token",
        kind="observation",
        intent=(
            "Naming an already committed transaction as the retry token is "
            "refused. Only the happy retry path was observed before."
        ),
        rpc="BeginTransaction",
        code=3,
        message=INVALID_RETRY,
        resources=("control",),
        controls=("retry-token/retry-with-rolled-back-previous",),
    ),
    _case(
        "retry-token/retry-with-read-only-previous",
        group="retry-token",
        kind="observation",
        intent=(
            "Naming a read-only transaction as the retry token of a read-write "
            "transaction is refused."
        ),
        rpc="BeginTransaction",
        code=3,
        message=READ_ONLY_RETRY,
        resources=(),
        controls=("retry-token/retry-with-rolled-back-previous",),
    ),
    _case(
        "retry-token/retry-with-unissued-previous",
        group="retry-token",
        kind="observation",
        intent=(
            "A well-formed retry token this database never issued is refused "
            "without starting a transaction."
        ),
        rpc="BeginTransaction",
        code=3,
        message=INVALID_TRANSACTION,
        resources=(),
        controls=(
            "retry-token/retry-with-rolled-back-previous",
            "retry-token/retry-with-malformed-previous",
        ),
    ),
    _case(
        "retry-token/retry-with-malformed-previous",
        group="retry-token",
        kind="control",
        intent=(
            "A retry token that is not valid base64 is refused during request "
            "decoding, before any transaction semantics. This separates a "
            "decoding refusal from a semantic one."
        ),
        rpc="BeginTransaction",
        code=3,
        message=MALFORMED_BASE64,
        resources=(),
        previously_observed=(
            "conformance:transactions/lifecycle#commit-with-malformed-transaction"
        ),
    ),
)

#: Conditions inside the FS-TRANSACTION row that this campaign deliberately does
#: not prepare. They are recorded so the preparation cannot be read as complete.
NOT_PREPARED = (
    {
        "condition": "Transaction total-lifetime expiry (locally 270 seconds)",
        "reason": (
            "A production observation would have to hold one transaction open "
            "for more than 270 seconds of real time while refreshing it below "
            "the idle limit. That does not fit this campaign's time envelope "
            "and needs its own long-window budget."
        ),
    },
    {
        "condition": "Transaction token replayed against another database",
        "reason": (
            "The observation needs a second named database in the oracle "
            "project. Creating one is a configuration change, and this "
            "campaign holds only a read lock on database configuration."
        ),
    },
    {
        "condition": (
            "Read-only transaction at a read_time outside the retention window"
        ),
        "reason": (
            "The refusal depends on the project's retention window, which is a "
            "configuration property this campaign does not read or change. It "
            "belongs with the read-time retention campaign."
        ),
    },
    {
        "condition": "Query-range (phantom) lock precedence",
        "reason": (
            "The one production attempt at conformance "
            "transactions/lifecycle#phantom-write timed out and is recorded as "
            "unverified. Re-attempting it needs a query-shaped collector, not "
            "this document-shaped one."
        ),
    },
    {
        "condition": "Client SDK transaction retry semantics",
        "reason": (
            "Observing what a declared SDK does on ABORTED needs a pinned SDK "
            "version and an SDK-driven collector. This campaign observes the "
            "backend contract the SDK reacts to, not the SDK."
        ),
    },
)


def validate_cases():
    """Raise ValueError when the checked-in table is not internally closed."""
    identifiers = [case["id"] for case in CASES]
    if len(identifiers) != len(set(identifiers)):
        raise ValueError("duplicate case identifier")
    controls = {case["id"] for case in CASES if case["kind"] == "control"}
    referenced = set()
    for case in CASES:
        if case["group"] not in GROUPS:
            raise ValueError(f"unknown group for {case['id']}")
        if not case["id"].startswith(case["group"] + "/"):
            raise ValueError(f"{case['id']} is not inside its group")
        if case["kind"] not in ("observation", "control"):
            raise ValueError(f"unknown kind for {case['id']}")
        expected = case["expectedLocal"]
        if expected["rpc"] not in RPCS:
            raise ValueError(f"unknown rpc for {case['id']}")
        if expected["code"] not in CODES:
            raise ValueError(f"unknown code for {case['id']}")
        if CODES[expected["code"]] != expected["status"]:
            raise ValueError(f"status does not match code for {case['id']}")
        if expected["code"] == 0:
            if expected["message"] is not None:
                raise ValueError(f"{case['id']} expects a message with OK")
        elif not expected["message"]:
            raise ValueError(f"{case['id']} expects a refusal without a message")
        for role in case["resources"]:
            if role not in RESOURCE_ROLES:
                raise ValueError(f"{case['id']} names unowned resource {role}")
        for control in case["controls"]:
            if control not in controls:
                raise ValueError(f"{case['id']} names unknown control {control}")
        referenced.update(case["controls"])
        if case["kind"] == "observation" and not case["controls"]:
            raise ValueError(f"{case['id']} has no control")
        prior = case["previouslyObserved"]
        if prior is not None and case["kind"] != "control":
            raise ValueError(f"{case['id']} re-observes recorded evidence")
        if case["kind"] == "control" and prior is None:
            raise ValueError(f"{case['id']} is a control that cites no evidence")
        if case["mutatesConfiguration"]:
            raise ValueError(f"{case['id']} mutates configuration")
        elapsed = case["requiresElapsedSeconds"]
        if case["group"] != "idle-expiry":
            if elapsed != 0:
                raise ValueError(f"{case['id']} must not depend on elapsed time")
        elif elapsed and case["kind"] == "observation":
            if elapsed < DECLARED_IDLE_LIMIT_SECONDS + 30:
                raise ValueError(f"{case['id']} waits too close to the idle limit")
        elif elapsed and elapsed > DECLARED_IDLE_LIMIT_SECONDS - 30:
            raise ValueError(f"{case['id']} controls too close to the idle limit")
    for case in CASES:
        if case["kind"] == "control" and case["id"] not in referenced:
            raise ValueError(f"{case['id']} is an unused control")
    if not NOT_PREPARED:
        raise ValueError("the unprepared conditions must stay recorded")
    return True


def _serializable():
    return {
        "campaign": CAMPAIGN,
        "contract": CONTRACT,
        "declaredIdleLimitSeconds": DECLARED_IDLE_LIMIT_SECONDS,
        "resourceRoles": list(RESOURCE_ROLES),
        "cases": [
            {
                **case,
                "resources": list(case["resources"]),
                "controls": list(case["controls"]),
            }
            for case in CASES
        ],
        "notPrepared": [dict(entry) for entry in NOT_PREPARED],
    }


def cases_digest():
    """SHA-256 over the canonical serialization of the whole frozen table."""
    return digest(_serializable())


def maximum_elapsed_seconds():
    """The longest single wait any case needs."""
    return max(case["requiresElapsedSeconds"] for case in CASES)


CASE_BY_ID = {case["id"]: case for case in CASES}
