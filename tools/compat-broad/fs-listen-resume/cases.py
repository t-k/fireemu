"""Observation Cases for the FS-LISTEN-SDK production campaign.

This module is a declarative catalog. It opens no socket, reads no credential
and executes nothing. Each observation case declares the listener it needs, the
ordered mutations a collector must apply, the expected local (fireemu) result
and the discriminating fields that make the case worth observing in production.

Every observation case is paired with at least one control or negative case so
that a production run cannot report agreement from a listener that never
delivered anything.
"""

from __future__ import annotations

from copy import deepcopy
from types import MappingProxyType
from typing import Any

from .manifest import digest

SCHEMA = "o6-listen-sdk-cases-v1"

# Owned data lives under a run document scoped first by the authenticated
# principal and then by the run nonce, so the Rules precondition can be written
# once without embedding a per-run nonce and still refuse one principal access
# to another principal's runs.
RUN_COLLECTION = "o6_listen"
DOCS_SUBCOLLECTION = "docs"
PRIVATE_COLLECTION = "o6_listen_private"

# Additive Rules fragment the owner must merge into the oracle project before a
# campaign. It grants nothing to unauthenticated callers and nothing outside the
# two owned prefixes. It deliberately contains no catch-all deny, because the
# oracle project is shared with other lanes.
REQUIRED_RULES_FRAGMENT = """\
match /o6_listen/{uid}/runs/{runId}/docs/{docId} {
  allow read, write: if request.auth != null && uid == request.auth.uid;
}
match /o6_listen_private/{uid} {
  allow read, write: if request.auth != null && request.auth.uid == uid;
}
"""

ROLE_OBSERVATION = "observation"
ROLE_CONTROL = "control"
ROLE_NEGATIVE = "negative"
_ROLES = (ROLE_OBSERVATION, ROLE_CONTROL, ROLE_NEGATIVE)

# Listener callbacks the collector is allowed to register.
LISTENER_KINDS = ("document", "query")

# Comparison modes. "ordered-events" compares the full event sequence position
# by position. "aggregate-changes" compares the multiset union of document
# changes plus declared invariants, and is used where the SDK is free to batch
# deliveries differently between runs.
COMPARISON_ORDERED = "ordered-events"
COMPARISON_AGGREGATE = "aggregate-changes"

# Fields compared position by position. `fromCache` and `hasPendingWrites` are
# metadata: a listener that did not ask for metadata changes still reports them,
# but their value there reflects delivery timing rather than a semantic
# difference, so those cases drop them from the compared projection and keep
# them in the raw receipt.
DEFAULT_COMPARED_FIELDS = (
    "listener",
    "snapshotKind",
    "changes",
    "docs",
    "exists",
    "fromCache",
    "hasPendingWrites",
    "error",
)
# The default-mode cases compare the raw callback sequence, snapshot kind
# included: in default mode the SDK raises a callback only when data changes, so
# the first delivery is the initial snapshot and every later one is a delta
# regardless of whether the first was cache-served.
RAW_CALLBACK_FIELDS = (
    "listener",
    "snapshotKind",
    "changes",
    "docs",
    "exists",
    "error",
)
SEMANTIC_ONLY_FIELDS = (
    "listener",
    "snapshotKind",
    "changes",
    "docs",
    "exists",
    "error",
)


def _change(
    kind: str, doc: str, old_index: int | None, new_index: int | None
) -> dict[str, Any]:
    return {"type": kind, "doc": doc, "oldIndex": old_index, "newIndex": new_index}


def _event(
    listener: str,
    kind: str,
    *,
    changes: list[dict[str, Any]] | None = None,
    docs: list[str] | None = None,
    exists: bool | None = None,
    from_cache: bool = False,
    pending: bool = False,
    error: str | None = None,
) -> dict[str, Any]:
    return {
        "listener": listener,
        "snapshotKind": kind,
        "changes": list(changes or []),
        "docs": list(docs or []),
        "exists": exists,
        "fromCache": from_cache,
        "hasPendingWrites": pending,
        "error": error,
    }


def _case(
    case_id: str,
    *,
    role: str,
    dimension: str,
    title: str,
    listeners: list[dict[str, Any]],
    steps: list[dict[str, Any]],
    expected_local: list[dict[str, Any]],
    comparison: str,
    discriminators: list[str],
    invariants: list[str] | None = None,
    control_for: str | None = None,
    compared_fields: list[str] | None = None,
    ignore_cached_prefix: bool = False,
    collapse_metadata_only: bool = True,
    requires_auth: bool = True,
    requires_rules: bool = False,
    documents: list[str] | None = None,
) -> dict[str, Any]:
    if role not in _ROLES:
        raise ValueError(f"unknown case role: {role}")
    if (role == ROLE_OBSERVATION) != (control_for is None):
        raise ValueError("control and negative cases must name their observation case")
    for listener in listeners:
        if listener["kind"] not in LISTENER_KINDS:
            raise ValueError(f"unknown listener kind: {listener['kind']}")
    return {
        "caseId": case_id,
        "role": role,
        "controlFor": control_for,
        "dimension": dimension,
        "title": title,
        "listeners": listeners,
        "steps": steps,
        "expectedLocal": expected_local,
        "comparison": comparison,
        "comparedFields": list(compared_fields or DEFAULT_COMPARED_FIELDS),
        "ignoreCachedPrefix": ignore_cached_prefix,
        "collapseMetadataOnly": collapse_metadata_only,
        "discriminators": discriminators,
        "invariants": list(invariants or []),
        "requiresAuth": requires_auth,
        "requiresRules": requires_rules,
        "documents": list(documents or []),
    }


def _default_mode_listener(name: str, doc: str) -> dict[str, Any]:
    """A listener that subscribes exactly as an ordinary application would.

    It does not request metadata changes, so the SDK raises a callback only when
    document data changes. Nothing is collapsed afterwards: this case exists to
    observe the default path itself rather than a reconstruction of it.
    """
    return {
        "name": name,
        "kind": "document",
        "target": doc,
        "includeMetadataChanges": False,
        "metadataIsCompared": False,
    }


def _doc_listener(
    name: str, doc: str, *, metadata: bool = False, client: str | None = None
) -> dict[str, Any]:
    # `metadata` records whether the case treats metadata as a compared signal.
    # The listener always subscribes with includeMetadataChanges because the
    # collector needs the cache-to-server transition to know the listener is
    # ready; cases that do not compare metadata collapse those events back out.
    # `client` names the SDK client that subscribes; the case client (signed
    # in as the first principal) when absent.
    listener = {
        "name": name,
        "kind": "document",
        "target": doc,
        "includeMetadataChanges": True,
        "metadataIsCompared": metadata,
    }
    if client is not None:
        listener["client"] = client
    return listener


def _query_listener(name: str, *, metadata: bool = False) -> dict[str, Any]:
    return {
        "name": name,
        "kind": "query",
        "target": DOCS_SUBCOLLECTION,
        "where": ["rank", "<", 10],
        "orderBy": ["rank", "asc"],
        "limit": 10,
        "includeMetadataChanges": True,
        "metadataIsCompared": metadata,
    }


def _step(kind: str, **payload: Any) -> dict[str, Any]:
    return {"kind": kind, **payload}


_CASE_101 = _case(
    "FS-LISTEN-SDK-101",
    role=ROLE_OBSERVATION,
    dimension="document-event-order",
    title="Document listener delivers one server snapshot for an existing document",
    listeners=[_doc_listener("primary", "alpha")],
    steps=[
        _step("seed", doc="alpha", fields={"rank": 1, "value": "a0"}),
        _step("listen", listener="primary"),
        _step("awaitServer", listener="primary"),
    ],
    expected_local=[
        _event("primary", "initial", docs=["alpha"], exists=True),
    ],
    comparison=COMPARISON_ORDERED,
    compared_fields=list(SEMANTIC_ONLY_FIELDS),
    discriminators=["snapshotKind", "exists"],
    documents=["alpha"],
)

_CASE_101C = _case(
    "FS-LISTEN-SDK-101C",
    role=ROLE_CONTROL,
    control_for="FS-LISTEN-SDK-101",
    dimension="document-event-order",
    title="Document listener on an absent document still delivers a non-existent snapshot",
    listeners=[_doc_listener("primary", "absent")],
    steps=[
        _step("listen", listener="primary"),
        _step("awaitServer", listener="primary"),
    ],
    expected_local=[
        _event("primary", "initial", docs=[], exists=False),
    ],
    comparison=COMPARISON_ORDERED,
    compared_fields=list(SEMANTIC_ONLY_FIELDS),
    discriminators=["exists"],
    documents=["absent"],
)

_CASE_102 = _case(
    "FS-LISTEN-SDK-102",
    role=ROLE_OBSERVATION,
    dimension="pending-writes",
    title="Local write raises hasPendingWrites before the acknowledged snapshot",
    listeners=[_doc_listener("primary", "beta", metadata=True)],
    steps=[
        _step("listen", listener="primary"),
        _step("awaitServer", listener="primary"),
        _step("baseline"),
        _step("write", client="primary", doc="beta", fields={"rank": 2, "value": "b0"}),
        _step("await", listener="primary", events=2),
    ],
    expected_local=[
        _event(
            "primary",
            "delta",
            docs=["beta"],
            exists=True,
            from_cache=False,
            pending=True,
        ),
        _event("primary", "delta", docs=["beta"], exists=True),
    ],
    comparison=COMPARISON_ORDERED,
    discriminators=["hasPendingWrites"],
    documents=["beta"],
)

_CASE_102C = _case(
    "FS-LISTEN-SDK-102C",
    role=ROLE_CONTROL,
    control_for="FS-LISTEN-SDK-102",
    dimension="pending-writes",
    title="A write from a second client never raises hasPendingWrites on this listener",
    listeners=[_doc_listener("primary", "beta", metadata=True)],
    steps=[
        _step("listen", listener="primary"),
        _step("awaitServer", listener="primary"),
        _step("baseline"),
        _step("write", client="witness", doc="beta", fields={"rank": 2, "value": "b0"}),
        _step("await", listener="primary", events=1),
    ],
    expected_local=[
        _event("primary", "delta", docs=["beta"], exists=True),
    ],
    comparison=COMPARISON_ORDERED,
    discriminators=["hasPendingWrites"],
    documents=["beta"],
)

_CASE_103 = _case(
    "FS-LISTEN-SDK-103",
    role=ROLE_OBSERVATION,
    dimension="query-change-order",
    title="Query listener reports added, modified with reordering, and removed",
    listeners=[_query_listener("primary")],
    steps=[
        _step("seed", doc="alpha", fields={"rank": 1, "value": "a0"}),
        _step("listen", listener="primary"),
        _step("awaitServer", listener="primary"),
        _step("baseline"),
        _step("write", client="witness", doc="beta", fields={"rank": 0, "value": "b0"}),
        _step("await", listener="primary", events=1),
        _step("write", client="witness", doc="beta", fields={"rank": 3, "value": "b1"}),
        _step("await", listener="primary", events=2),
        _step("delete", client="witness", doc="alpha"),
        _step("await", listener="primary", events=3),
    ],
    expected_local=[
        _event(
            "primary",
            "delta",
            changes=[_change("added", "beta", -1, 0)],
            docs=["beta", "alpha"],
        ),
        _event(
            "primary",
            "delta",
            changes=[_change("modified", "beta", 0, 1)],
            docs=["alpha", "beta"],
        ),
        _event(
            "primary",
            "delta",
            changes=[_change("removed", "alpha", 0, -1)],
            docs=["beta"],
        ),
    ],
    comparison=COMPARISON_ORDERED,
    discriminators=["changes", "docs"],
    documents=["alpha", "beta"],
)

_CASE_103C = _case(
    "FS-LISTEN-SDK-103C",
    role=ROLE_CONTROL,
    control_for="FS-LISTEN-SDK-103",
    dimension="query-change-order",
    title="A document outside the query predicate produces no event in the quiet window",
    listeners=[_query_listener("primary")],
    steps=[
        _step("seed", doc="alpha", fields={"rank": 1, "value": "a0"}),
        _step("listen", listener="primary"),
        _step("awaitServer", listener="primary"),
        _step("baseline"),
        _step(
            "write", client="witness", doc="gamma", fields={"rank": 99, "value": "g0"}
        ),
        _step("quiet", listener="primary", seconds=3),
    ],
    expected_local=[],
    comparison=COMPARISON_ORDERED,
    discriminators=["docs"],
    invariants=["no-event-after-quiet-window"],
    documents=["alpha", "gamma"],
)

_CASE_104 = _case(
    "FS-LISTEN-SDK-104",
    role=ROLE_OBSERVATION,
    dimension="resume-after-break",
    title="Resume after a forced stream break delivers only the documents that changed",
    listeners=[_query_listener("primary", metadata=True)],
    steps=[
        _step("seed", doc="alpha", fields={"rank": 1, "value": "a0"}),
        _step("seed", doc="beta", fields={"rank": 2, "value": "b0"}),
        _step("listen", listener="primary"),
        _step("awaitServer", listener="primary"),
        _step("baseline"),
        _step("break", client="primary", mode="disable-network"),
        _step(
            "write", client="witness", doc="gamma", fields={"rank": 5, "value": "g0"}
        ),
        _step(
            "write", client="witness", doc="alpha", fields={"rank": 4, "value": "a1"}
        ),
        _step("resume", client="primary", mode="enable-network"),
        _step("settle", listener="primary", seconds=5),
    ],
    expected_local=[
        _event(
            "primary",
            "aggregate",
            changes=[
                _change("modified", "alpha", None, None),
                _change("added", "gamma", None, None),
            ],
            docs=["beta", "alpha", "gamma"],
        ),
    ],
    comparison=COMPARISON_AGGREGATE,
    compared_fields=list(SEMANTIC_ONLY_FIELDS),
    discriminators=["changes", "docs", "fromCacheTransitions"],
    invariants=[
        "no-duplicate-added-for-unchanged-document",
        "from-cache-true-then-false-across-break",
        "terminal-document-set-complete",
    ],
    documents=["alpha", "beta", "gamma"],
)

_CASE_104C = _case(
    "FS-LISTEN-SDK-104C",
    role=ROLE_CONTROL,
    control_for="FS-LISTEN-SDK-104",
    dimension="resume-after-break",
    title="The same mutations without a break reach the same terminal set with no cache transition",
    listeners=[_query_listener("primary", metadata=True)],
    steps=[
        _step("seed", doc="alpha", fields={"rank": 1, "value": "a0"}),
        _step("seed", doc="beta", fields={"rank": 2, "value": "b0"}),
        _step("listen", listener="primary"),
        _step("awaitServer", listener="primary"),
        _step("baseline"),
        _step(
            "write", client="witness", doc="gamma", fields={"rank": 5, "value": "g0"}
        ),
        _step(
            "write", client="witness", doc="alpha", fields={"rank": 4, "value": "a1"}
        ),
        _step("settle", listener="primary", seconds=5),
    ],
    expected_local=[
        _event(
            "primary",
            "aggregate",
            changes=[
                _change("modified", "alpha", None, None),
                _change("added", "gamma", None, None),
            ],
            docs=["beta", "alpha", "gamma"],
        ),
    ],
    comparison=COMPARISON_AGGREGATE,
    compared_fields=list(SEMANTIC_ONLY_FIELDS),
    discriminators=["changes", "docs"],
    invariants=[
        "no-duplicate-added-for-unchanged-document",
        "no-from-cache-transition",
    ],
    documents=["alpha", "beta", "gamma"],
)

_CASE_105 = _case(
    "FS-LISTEN-SDK-105",
    role=ROLE_OBSERVATION,
    dimension="unsubscribe",
    title="Unsubscribe stops callbacks while a witness listener still observes the write",
    listeners=[
        _doc_listener("primary", "alpha"),
        _doc_listener("witness", "alpha"),
    ],
    steps=[
        _step("seed", doc="alpha", fields={"rank": 1, "value": "a0"}),
        _step("listen", listener="primary"),
        _step("listen", listener="witness"),
        _step("awaitServer", listener="primary"),
        _step("awaitServer", listener="witness"),
        _step("baseline"),
        _step("unsubscribe", listener="primary"),
        _step("unsubscribe", listener="primary", repeat=True),
        _step(
            "write", client="witness", doc="alpha", fields={"rank": 1, "value": "a1"}
        ),
        _step("await", listener="witness", events=1),
        _step("quiet", listener="primary", seconds=3),
    ],
    expected_local=[
        _event("witness", "delta", docs=["alpha"], exists=True),
    ],
    comparison=COMPARISON_ORDERED,
    compared_fields=list(SEMANTIC_ONLY_FIELDS),
    discriminators=["listener", "snapshotKind"],
    invariants=["no-event-after-unsubscribe", "repeated-unsubscribe-is-a-no-op"],
    documents=["alpha"],
)

_CASE_105C = _case(
    "FS-LISTEN-SDK-105C",
    role=ROLE_CONTROL,
    control_for="FS-LISTEN-SDK-105",
    dimension="unsubscribe",
    title="Without unsubscribe the same listener observes the same write",
    listeners=[
        _doc_listener("primary", "alpha"),
        _doc_listener("witness", "alpha"),
    ],
    steps=[
        _step("seed", doc="alpha", fields={"rank": 1, "value": "a0"}),
        _step("listen", listener="primary"),
        _step("listen", listener="witness"),
        _step("awaitServer", listener="primary"),
        _step("awaitServer", listener="witness"),
        _step("baseline"),
        _step(
            "write", client="witness", doc="alpha", fields={"rank": 1, "value": "a1"}
        ),
        _step("await", listener="primary", events=1),
        _step("await", listener="witness", events=1),
    ],
    expected_local=[
        _event("primary", "delta", docs=["alpha"], exists=True),
        _event("witness", "delta", docs=["alpha"], exists=True),
    ],
    comparison=COMPARISON_ORDERED,
    compared_fields=list(SEMANTIC_ONLY_FIELDS),
    discriminators=["listener"],
    documents=["alpha"],
)

_CASE_106 = _case(
    "FS-LISTEN-SDK-106",
    role=ROLE_OBSERVATION,
    dimension="auth-switch",
    title="Signing out mid-listen terminates a Rules-protected listener with permission-denied",
    listeners=[_doc_listener("primary", "private")],
    steps=[
        _step("signIn", client="primary", account="throwaway"),
        _step("seed", doc="private", fields={"value": "p0"}),
        _step("listen", listener="primary"),
        _step("awaitServer", listener="primary"),
        _step("baseline"),
        _step("signOut", client="primary"),
        _step("awaitError", listener="primary"),
        _step("signIn", client="primary", account="throwaway"),
        _step("listen", listener="recovered"),
        _step("awaitServer", listener="recovered"),
    ],
    expected_local=[
        _event("primary", "error", error="permission-denied"),
        _event("recovered", "initial", docs=["private"], exists=True),
    ],
    comparison=COMPARISON_ORDERED,
    compared_fields=list(SEMANTIC_ONLY_FIELDS),
    discriminators=["error", "snapshotKind"],
    invariants=["no-event-after-listener-error"],
    requires_rules=True,
    documents=["private"],
)

_CASE_106N = _case(
    "FS-LISTEN-SDK-106N",
    role=ROLE_NEGATIVE,
    control_for="FS-LISTEN-SDK-106",
    dimension="auth-switch",
    title="A listener started while signed out fails without ever reading the server",
    listeners=[_doc_listener("primary", "private")],
    steps=[
        _step("signOut", client="primary"),
        _step("listen", listener="primary"),
        _step("awaitError", listener="primary"),
    ],
    expected_local=[
        _event("primary", "error", error="permission-denied"),
    ],
    comparison=COMPARISON_ORDERED,
    compared_fields=list(SEMANTIC_ONLY_FIELDS),
    ignore_cached_prefix=True,
    discriminators=["error"],
    invariants=["no-server-snapshot-before-error"],
    requires_auth=False,
    requires_rules=True,
    documents=["private"],
)

_CASE_107 = _case(
    "FS-LISTEN-SDK-107",
    role=ROLE_OBSERVATION,
    dimension="default-subscription",
    title="A default-mode listener raises one callback per data change",
    listeners=[_default_mode_listener("primary", "alpha")],
    steps=[
        _step("seed", doc="alpha", fields={"rank": 1, "value": "a0"}),
        _step("listen", listener="primary"),
        _step("settle", listener="primary", seconds=3),
        _step(
            "write", client="witness", doc="alpha", fields={"rank": 1, "value": "a1"}
        ),
        _step("settle", listener="primary", seconds=3),
    ],
    expected_local=[
        _event("primary", "initial", docs=["alpha"], exists=True),
        _event("primary", "delta", docs=["alpha"], exists=True),
    ],
    comparison=COMPARISON_ORDERED,
    compared_fields=list(RAW_CALLBACK_FIELDS),
    collapse_metadata_only=False,
    discriminators=["docs", "exists"],
    documents=["alpha"],
)

_CASE_107C = _case(
    "FS-LISTEN-SDK-107C",
    role=ROLE_CONTROL,
    control_for="FS-LISTEN-SDK-107",
    dimension="default-subscription",
    title="A default-mode listener raises no callback for a write that changes no data",
    listeners=[_default_mode_listener("primary", "alpha")],
    steps=[
        _step("seed", doc="alpha", fields={"rank": 1, "value": "a0"}),
        _step("listen", listener="primary"),
        _step("settle", listener="primary", seconds=3),
        _step(
            "write", client="witness", doc="alpha", fields={"rank": 1, "value": "a0"}
        ),
        _step("quiet", listener="primary", seconds=3),
    ],
    expected_local=[
        _event("primary", "initial", docs=["alpha"], exists=True),
    ],
    comparison=COMPARISON_ORDERED,
    compared_fields=list(RAW_CALLBACK_FIELDS),
    collapse_metadata_only=False,
    discriminators=["docs"],
    invariants=["no-event-after-quiet-window"],
    documents=["alpha"],
)

# Two principals. The case client and the witness client are signed in as the
# first throwaway account ("throwaway"); the `secondary` client is signed in as
# the second one ("second"), whose only owned document is `privateB`.
SECOND_ACCOUNT = "second"

_CASE_108 = _case(
    "FS-LISTEN-SDK-108",
    role=ROLE_OBSERVATION,
    dimension="cross-identity",
    title="A listener on another principal's private document fails without a server snapshot",
    listeners=[_doc_listener("primary", "privateB")],
    steps=[
        _step("signIn", client="primary", account="throwaway"),
        _step("write", client="secondary", doc="privateB", fields={"value": "b0"}),
        _step("listen", listener="primary"),
        _step("awaitError", listener="primary"),
    ],
    expected_local=[
        _event("primary", "error", error="permission-denied"),
    ],
    comparison=COMPARISON_ORDERED,
    compared_fields=list(SEMANTIC_ONLY_FIELDS),
    ignore_cached_prefix=True,
    discriminators=["error"],
    invariants=["no-server-snapshot-before-error", "no-event-after-listener-error"],
    requires_rules=True,
    documents=["privateB"],
)

_CASE_108C = _case(
    "FS-LISTEN-SDK-108C",
    role=ROLE_CONTROL,
    control_for="FS-LISTEN-SDK-108",
    dimension="cross-identity",
    title="The owning principal's listener on the same document receives the server snapshot",
    listeners=[_doc_listener("secondary", "privateB", client="secondary")],
    steps=[
        _step("write", client="secondary", doc="privateB", fields={"value": "b0"}),
        _step("listen", listener="secondary"),
        _step("awaitServer", listener="secondary"),
    ],
    expected_local=[
        _event("secondary", "initial", docs=["privateB"], exists=True),
    ],
    comparison=COMPARISON_ORDERED,
    compared_fields=list(SEMANTIC_ONLY_FIELDS),
    discriminators=["snapshotKind", "exists"],
    requires_rules=True,
    documents=["privateB"],
)

# Revocation while a listener is attached. The expected local result records
# what fireemu does: it re-verifies the credential on every commit-triggered
# refresh, so the Listen stream ends with UNAUTHENTICATED ("token revoked") at
# the next commit on the database and the SDK surfaces that to the listener as
# a terminal `unauthenticated` error. The production hypothesis (recorded in
# the preparation document, not asserted here) is that the listener keeps
# working until the ID token expires, because Firestore does not consult
# revocation for an already-issued token.
_CASE_109 = _case(
    "FS-LISTEN-SDK-109",
    role=ROLE_OBSERVATION,
    dimension="token-revocation",
    title="Revoking the principal's sessions mid-listen: local fireemu ends the listener at the next commit",
    listeners=[_doc_listener("primary", "private")],
    steps=[
        _step("signIn", client="primary", account="throwaway"),
        # validSince has whole-second precision: the session must be older than
        # the revocation instant for the revocation to cover it.
        _step("settle", listener="primary", seconds=1.2),
        _step("seed", doc="private", fields={"value": "p0"}),
        _step("listen", listener="primary"),
        _step("awaitServer", listener="primary"),
        _step("baseline"),
        _step("revoke", client="primary"),
        # An unrelated commit by the other principal triggers the refresh.
        _step("write", client="secondary", doc="privateB", fields={"value": "b1"}),
        _step("awaitError", listener="primary"),
    ],
    expected_local=[
        _event("primary", "error", error="unauthenticated"),
    ],
    comparison=COMPARISON_ORDERED,
    compared_fields=list(SEMANTIC_ONLY_FIELDS),
    discriminators=["error", "snapshotKind"],
    invariants=["no-event-after-listener-error"],
    requires_rules=True,
    documents=["private", "privateB"],
)

_CASE_109C = _case(
    "FS-LISTEN-SDK-109C",
    role=ROLE_CONTROL,
    control_for="FS-LISTEN-SDK-109",
    dimension="token-revocation",
    title="Without revocation the same listener survives the other principal's commit and sees its own",
    listeners=[_doc_listener("primary", "private")],
    steps=[
        _step("signIn", client="primary", account="throwaway"),
        _step("settle", listener="primary", seconds=1.2),
        _step("seed", doc="private", fields={"value": "p0"}),
        _step("listen", listener="primary"),
        _step("awaitServer", listener="primary"),
        _step("baseline"),
        _step("write", client="secondary", doc="privateB", fields={"value": "b1"}),
        _step("quiet", listener="primary", seconds=3),
        _step("write", client="witness", doc="private", fields={"value": "p1"}),
        _step("await", listener="primary", events=1),
    ],
    expected_local=[
        _event("primary", "delta", docs=["private"], exists=True),
    ],
    comparison=COMPARISON_ORDERED,
    compared_fields=list(SEMANTIC_ONLY_FIELDS),
    discriminators=["snapshotKind"],
    invariants=["no-event-after-quiet-window"],
    requires_rules=True,
    documents=["private", "privateB"],
)

CASES: tuple[dict[str, Any], ...] = (
    _CASE_101,
    _CASE_101C,
    _CASE_102,
    _CASE_102C,
    _CASE_103,
    _CASE_103C,
    _CASE_104,
    _CASE_104C,
    _CASE_105,
    _CASE_105C,
    _CASE_106,
    _CASE_106N,
    _CASE_107,
    _CASE_107C,
    _CASE_108,
    _CASE_108C,
    _CASE_109,
    _CASE_109C,
)

# Paths the campaign explicitly cannot observe from a Node process. Each entry
# records why, and the concrete step that would close it.
UNOBSERVED_PATHS = (
    MappingProxyType(
        {
            "path": "browser-webchannel",
            "reason": "The Node SDK build selects the gRPC transport; this campaign does not "
            "exercise WebChannel framing, long polling, the streamed backchannel "
            "or browser tab lifecycle in production. A local browser shadow "
            "(listen_browser_adapter.mjs) runs the same catalog through headless "
            "Chromium, but that is local evidence only.",
            "plan": "A separate browser campaign driving the same case catalog through the "
            "existing headless Chromium adapter against the same oracle project, "
            "with the WebChannel request log captured from the page rather than "
            "from Node.",
        }
    ),
    MappingProxyType(
        {
            "path": "android-sdk",
            "reason": "No Android runtime, Gradle toolchain or device is available to this lane.",
            "plan": "An instrumented Android test module that replays the same case catalog and "
            "emits the same normalized event rows for comparison.",
        }
    ),
    MappingProxyType(
        {
            "path": "apple-sdk",
            "reason": "No iOS or macOS SDK harness exists in this repository.",
            "plan": "An XCTest target replaying the same case catalog and emitting the same "
            "normalized event rows.",
        }
    ),
    MappingProxyType(
        {
            "path": "tenant-isolation",
            "reason": "Cases 108/108C observe one principal being refused another "
            "principal's private document within one project. Identity Platform "
            "tenants are not exercised: both accounts live in the default tenant, "
            "so a MATCH says nothing about cross-tenant isolation under Rules.",
            "plan": "A tenant-scoped throwaway account and a listener case whose principal "
            "carries a tenant claim, expecting permission-denied across the tenant "
            "boundary, once the oracle project has a second tenant.",
        }
    ),
    MappingProxyType(
        {
            "path": "raw-resume-token",
            "reason": "The Node client SDK owns the resume token; it is not exposed to "
            "application code, so RESET and stale-token behavior cannot be driven here.",
            "plan": "A direct gRPC Listen probe that supplies a chosen resume token and records "
            "the TargetChange response, kept as a separate case from SDK-level resume.",
        }
    ),
)


def case_ids() -> tuple[str, ...]:
    return tuple(case["caseId"] for case in CASES)


def get_case(case_id: str) -> dict[str, Any]:
    for case in CASES:
        if case["caseId"] == case_id:
            return deepcopy(case)
    raise KeyError(case_id)


def catalog() -> dict[str, Any]:
    """Return the frozen, digestible catalog."""
    return {
        "schema": SCHEMA,
        "runCollection": RUN_COLLECTION,
        "docsSubcollection": DOCS_SUBCOLLECTION,
        "privateCollection": PRIVATE_COLLECTION,
        "requiredRulesFragment": REQUIRED_RULES_FRAGMENT,
        "requiredRulesDigest": digest(REQUIRED_RULES_FRAGMENT),
        "cases": [deepcopy(case) for case in CASES],
        "unobservedPaths": [dict(entry) for entry in UNOBSERVED_PATHS],
    }


def catalog_digest() -> str:
    return digest(catalog())
