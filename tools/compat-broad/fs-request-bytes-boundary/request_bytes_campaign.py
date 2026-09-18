"""Offline campaign artifact for the 10 MiB API request-byte boundary.

This module composes the already reviewed compiler plan into a bounded campaign
description: boundary cases, the typed refusal expectation, the post-state
readback obligation, cleanup with absence proofs, a budget with an explicit
recovery window, a cost estimate and the local shadow expectation.

It performs no I/O, holds no credentials, acquires no reservation and does not
authorize production execution. `validate_request_bytes_campaign` checks a
supplied artifact independently instead of rebuilding a replacement.
"""

from __future__ import annotations

import hashlib
import re
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from request_bytes_compiler import (
    CAMPAIGN,
    DOCUMENT_COUNT,
    REQUEST_LIMIT,
    REQUEST_TARGETS,
    compact_utf8,
    compile_request_bytes_plan,
    validate_request_bytes_plan,
)
from request_bytes_remote_transport import (
    NON_UPLOAD_RESERVE_SECONDS,
)
from request_bytes_remote_transport import (
    TIMEOUT as TRANSPORT_TIMEOUT_SECONDS,
)

SCHEMA = "fs-request-bytes-campaign-v1"
CATALOG_SOURCE = "spec/limits/firestore-standard-2026-08-25.json"

CASE_IDS = (
    "FS-LIMIT-API-REQUEST-BYTES-UNDER",
    "FS-LIMIT-API-REQUEST-BYTES-EXACT",
    "FS-LIMIT-API-REQUEST-BYTES-OVER",
)

# Firestore Native us-central1 published unit prices, used only to bound the
# campaign. They are a planning input, not a billing record.
READ_USD_PER_UNIT = 0.06 / 100_000
WRITE_USD_PER_UNIT = 0.18 / 100_000
DELETE_USD_PER_UNIT = 0.02 / 100_000

# Request bodies are ingress. Firestore does not bill ingress, and the response
# bodies for this campaign are kilobytes, so the network component is zero to
# the published precision. The uploaded volume is still recorded because it is
# the quantity that makes this campaign unusual.
EGRESS_NOTE = (
    "About 30 MiB is uploaded across the three Commits and under 1 MiB is "
    "returned. Ingress is not billed and the returned volume is negligible, so "
    "the network component of this campaign is zero to the published precision."
)

#: The refusal shape the over-boundary Commit is expected to produce, and the
#: outcomes that must never be read as a refusal proof. `expected` and
#: `semantic-discrepancy` are the two classifications the reviewed collector
#: already emits through `over_refusal_classification`.
REFUSAL_EXPECTATION: dict[str, Any] = {
    "metric": "REST raw HTTP body UTF-8 bytes",
    "metricStatus": "observation hypothesis",
    "typed": [
        {
            "httpStatus": 400,
            "errorCode": 400,
            "errorStatus": "INVALID_ARGUMENT",
            "classification": "expected",
            "note": "A typed Firestore error refusing the request before any document is evaluated.",
        },
        {
            "httpStatus": 413,
            "errorCode": 413,
            "errorStatus": "INVALID_ARGUMENT",
            "classification": "semantic-discrepancy",
            "note": "A typed refusal, but not the catalog-expected code; it requires owner adjudication before the catalog is amended.",
        },
    ],
    "requires": [
        "complete receipt",
        "integer HTTP status",
        "integer error code equal to the HTTP status",
        "raw response bytes matching the parsed body",
    ],
    "notRefusal": [
        "HTTP 200 with or without write results",
        "a complete receipt whose raw bytes contradict the parsed body",
        "an incomplete or timed-out receipt",
        "a non-JSON body, including a front-end HTML 413 page",
        "a connection reset with no response",
    ],
    "untypedTransportRefusal": {
        "classification": "untyped-transport-refusal",
        "resultKey": "untypedOverRefusal",
        "state": "commit-uncertain",
        "isRefusalProof": False,
        "handling": "A non-JSON refusal, such as a front-end HTML 413 or a reset, is not Firestore's answer and is never upgraded to a typed row. The collector records it as its own outcome with the HTTP status, the content type and the response bytes verbatim, and keeps the refusal shape unproven.",
        "recoveryAuthority": "read-only; it grants no cleanup ownership, so every version-bound delete is a zero-wire skip",
        "stillProven": "The post-state readback and the recovery absence proofs still establish that the refused request wrote nothing.",
        "ownerAction": "Adjudicate the recorded status, content type and bytes. The primary boundary question stays open and needs a second run once the intermediary is identified.",
    },
}

#: The shared Gate's own contract, from `shared_gate.create`. It charges every
#: slot `requestSeconds + intervalSeconds`, refuses an interval below the floor
#: and refuses a wall above the cap. The campaign's windows have to close under
#: that arithmetic, so it is computed here rather than assumed compatible.
GATE_INTERVAL_FLOOR_SECONDS = 0.25
GATE_WALL_CAP_SECONDS = 1200

#: What one small read or delete may reserve, and time out at. The reservation
#: is only a plan unless the request is also bounded by it, so this is both.
#: Three seconds is roughly an order of magnitude over a few-hundred-millisecond
#: round trip, which is the shape a bound should have.
SMALL_REQUEST_SECONDS = 3.0


#: The fields that make up a refusal shape. A classification claiming the shape
#: matched must compare every one of them; comparing a subset while saying
#: "status, code and message" is a false report, not a shortcut.
BASELINE_COMPARISON_FIELDS = ("httpStatus", "errorCode", "errorStatus", "message")


#: What the local fireemu runtime does today, as observed by the local shadow
#: rather than assumed. The limits layer now implements this condition: every
#: Firestore transport applies the same bound at its own decode boundary, and
#: the strict profile answers one refusal shape everywhere.
#:
#: That shape agrees with what this campaign expects of production. The
#: agreement is not confirmation: the expected production shape is itself
#: documented rather than observed, which is exactly what the campaign exists to
#: settle. Local agreement removes a known difference; it does not answer the
#: question.
LOCAL_EXPECTATION: dict[str, Any] = {
    "localEnforcement": "each transport's decode boundary, strict profile",
    "enforcementSource": "crates/fireemu-adapter-grpc/src/serve.rs, API_REQUEST_BYTES = 10 * 1024 * 1024, refused by api_request_too_large()",
    "catalogState": "implemented",
    "catalogNote": "The limits catalog records FS-LIMIT-API-REQUEST-BYTES as implemented, enforced before the request is parsed on the REST body, the WebChannel form body and a gRPC message, unary or streamed. The refusal shape is documented, production observation pending.",
    "observedProbeOutcomes": {
        "under": "accepted",
        "exact": "accepted",
        "over": "refused",
    },
    "observedRefusal": {
        "httpStatus": 400,
        "errorCode": 400,
        "errorStatus": "INVALID_ARGUMENT",
        "message": "Request payload size exceeds the limit: 10485760 bytes.",
        "classification": "expected",
    },
    #: Per transport, because a reader comparing a future production receipt
    #: needs the status, the code and the message separately, and because only
    #: the REST row is observed by this campaign.
    "observedRefusalByTransport": {
        "rest": {
            "transport": "REST Commit",
            "httpStatus": 400,
            "errorCode": 400,
            "errorStatus": "INVALID_ARGUMENT",
            "message": "Request payload size exceeds the limit: 10485760 bytes.",
            "observedBy": "this campaign's local shadow",
        },
        "grpc": {
            "transport": "gRPC unary, Write stream and WebChannel",
            "httpStatus": None,
            "errorCode": 3,
            "errorStatus": "INVALID_ARGUMENT",
            "message": "Request payload size exceeds the limit: 10485760 bytes.",
            "observedBy": "the runtime's own tests, not this campaign",
            "note": "The gRPC code follows from google.rpc.Code, where INVALID_ARGUMENT maps to HTTP 400. This campaign compiles REST bodies only, so it does not observe this row.",
        },
    },
    #: The other profile's refusal. The boundary is identical under both; only
    #: the shape differs. A strict-profile build answering this is a regression.
    "emulatorProfileRefusal": {
        "profile": "emulator",
        "rest": {
            "httpStatus": 413,
            "errorCode": 413,
            "errorStatus": "INVALID_ARGUMENT",
            "message": "request body too large",
        },
        "grpc": {
            "errorStatus": "OUT_OF_RANGE",
            "message": "tonic's own wording, left unrewritten",
        },
        "note": "What the local runtime answered before the limits layer implemented this condition. The strict profile is what the campaign compares against.",
    },
    "differenceFromProductionExpectation": "None in shape or boundary. The local runtime answers the same status, code and message this campaign expects of production. That expectation is documented rather than observed, so the agreement removes a known difference and does not confirm the production shape; only a production receipt can do that.",
    "expectedCollectorFailures": [],
    "expectedCompleted": True,
    "expectedResourceAbsence": True,
    "classification": "local-shape-matches-production-expectation",
    "supersededBaseline": "Until the limits layer landed, the local runtime refused with HTTP 413 `request body too large` from a transport body cap, which the shadow classified as `local-boundary-enforced-shape-differs`. That classification is retained as a regression outcome: a strict-profile build answering 413 has lost the implemented shape.",
    "note": "A local run in which the over probe is accepted means the bound was removed or raised; the shadow reports that as `local-boundary-not-enforced` rather than passing.",
}


#: The one total wire deadline every probe must finish inside, and what happens
#: when it is missed. The transport enforces this ceiling independently and the
#: worker re-checks it, so the campaign cannot raise it at run time. O7 binds
#: this block along with the rest of the artifact.
TRANSPORT_DEADLINE: dict[str, Any] = {
    "perRequestSeconds": TRANSPORT_TIMEOUT_SECONDS,
    "covers": "connection setup, TLS, the request upload, server processing and the bounded response read",
    "enforcedBy": [
        "request_bytes_remote_transport.TIMEOUT, rejecting any larger timeout argument",
        "request_bytes_https_worker, re-checking the same ceiling independently",
    ],
    "derivation": {
        "uploadBits": max(REQUEST_TARGETS) * 8,
        "assumedSustainedBitsPerSecond": 5_000_000,
        "uploadSeconds": 16.8,
        "connectionSetupSeconds": 1.5,
        "serverProcessingSeconds": 8.0,
        "responseReadSeconds": 0.5,
        "derivedRequirementSeconds": 26.8,
        "marginNote": "The published ceiling is that requirement with roughly a 2x margin.",
    },
    "nonUploadReserveSeconds": NON_UPLOAD_RESERVE_SECONDS,
    "slowestUsableUpstreamBitsPerSecond": round(
        max(REQUEST_TARGETS)
        * 8
        / (TRANSPORT_TIMEOUT_SECONDS - NON_UPLOAD_RESERVE_SECONDS)
    ),
    "consequenceIfMissed": "The receipt is incomplete, the Commit is uncertain, and the run holds no conditional-creation proof. The version-bound delete is then a zero-wire skip by design, so cleanup detects the residue as `cleanup-not-absent` but cannot remove it: up to 17 documents stay in the project pending manual owner action.",
    "detection": "Detected, never silent. The absence proofs are only recorded on a typed NOT_FOUND, so an unremovable residue fails the run rather than passing it.",
    "ownerAction": "Run from a link that sustains the rate above. If a probe times out, the owner removes the residue under the recorded owned scope; the campaign never retries a Commit to compensate.",
}


def _nonce_digest(nonce: str) -> str:
    return hashlib.sha256(nonce.encode("ascii")).hexdigest()


def _request_accounting() -> dict[str, int]:
    """The billable unit counts under the outcome this campaign expects.

    This is a forecast, not a bound. It counts writes and deletes for the two
    probes production is expected to accept. `_maximum_usage` is what the
    permission and the reservation must cover, because an unexpected acceptance
    of the over-boundary probe is exactly the outcome the campaign is run to
    detect and must therefore be affordable.
    """
    probes = len(REQUEST_TARGETS)
    accepted = sum(1 for target in REQUEST_TARGETS if target <= REQUEST_LIMIT)
    return {
        "documentReads": probes * DOCUMENT_COUNT * 4,
        "documentWrites": accepted * DOCUMENT_COUNT,
        "documentDeletes": accepted * DOCUMENT_COUNT,
        # Four reads and one delete slot per owned resource, plus one Commit per
        # probe. Delete slots on a refused probe are consumed as zero-wire
        # skips, so the request figure is the same under every outcome.
        "httpRequests": probes * DOCUMENT_COUNT * 5 + probes,
        "uploadedBytes": sum(REQUEST_TARGETS),
    }


def _maximum_usage() -> dict[str, int]:
    """The largest usage any legitimate outcome of this schedule can reach.

    Every probe is accepted, including the over-boundary one. The collector
    records that as a failure and still creates and recovers all 51 documents,
    so the reservation has to cover 51 writes and 51 deletes. What does not
    rise: the documents coexist 17 at a time because each probe is cleaned up
    before the next begins, and the request count is fixed by the schedule.
    """
    probes = len(REQUEST_TARGETS)
    return {
        "documentReads": probes * DOCUMENT_COUNT * 4,
        "documentWrites": probes * DOCUMENT_COUNT,
        "documentDeletes": probes * DOCUMENT_COUNT,
        "httpRequests": probes * DOCUMENT_COUNT * 5 + probes,
        "uploadedBytes": sum(REQUEST_TARGETS),
        "peakLiveDocuments": DOCUMENT_COUNT,
        "distinctResources": probes * DOCUMENT_COUNT,
        "basis": "every probe accepted, which is the outcome the campaign exists to detect",
    }


def _accept_combinations() -> list[tuple[bool, ...]]:
    """Every accept/refuse combination of the three probes."""
    return [
        tuple(bool(index >> position & 1) for position in range(len(REQUEST_TARGETS)))
        for index in range(2 ** len(REQUEST_TARGETS))
    ]


def probe_usage(accepted: tuple[bool, ...]) -> dict[str, int]:
    """Creates and recovery deletes for one accept/refuse combination.

    The schedule is positional, so a refused probe still consumes its delete
    slots as zero-wire skips. Only the documents an accepted probe creates need
    a write and a version-bound delete.
    """
    if len(accepted) != len(REQUEST_TARGETS):
        raise ValueError("one flag per compiled probe is required")
    live = sum(1 for flag in accepted if flag)
    return {
        "documentWrites": live * DOCUMENT_COUNT,
        "documentDeletes": live * DOCUMENT_COUNT,
        "documentReads": len(REQUEST_TARGETS) * DOCUMENT_COUNT * 4,
        "httpRequests": len(REQUEST_TARGETS) * DOCUMENT_COUNT * 5
        + len(REQUEST_TARGETS),
        "peakLiveDocuments": DOCUMENT_COUNT if live else 0,
    }


def _usage_cost(usage: dict[str, int]) -> float:
    return (
        usage["documentReads"] * READ_USD_PER_UNIT
        + usage["documentWrites"] * WRITE_USD_PER_UNIT
        + usage["documentDeletes"] * DELETE_USD_PER_UNIT
    )


def _cost(accounting: dict[str, int]) -> dict[str, Any]:
    return {
        "estimatedCostUsd": round(_usage_cost(accounting), 6),
        # What the run can cost if every probe is accepted. The ceiling has to
        # clear this figure, not the forecast.
        "maximumCostUsd": round(_usage_cost(_maximum_usage()), 6),
        "hardCostCeilingUsd": 0.5,
        "networkCostUsd": 0.0,
        "networkNote": EGRESS_NOTE,
        "unitPricesUsd": {
            "documentRead": READ_USD_PER_UNIT,
            "documentWrite": WRITE_USD_PER_UNIT,
            "documentDelete": DELETE_USD_PER_UNIT,
        },
        "basis": "Firestore Native published unit prices; a planning bound, not a billing record.",
    }


def _scheduling_reservation() -> dict[str, Any]:
    """Close the campaign's wall-clock arithmetic under the Gate's own formula.

    Recovery is the binding phase: it is the largest block of small requests and
    its failure mode, stopping part way through cleanup, is the worst one. The
    numbers below are what the Gate will charge, not an estimate of what the run
    will take.
    """
    probes = len(REQUEST_TARGETS)
    recovery_slots = probes * DOCUMENT_COUNT * 3
    observation_small = probes * (DOCUMENT_COUNT * 2)
    per_small = SMALL_REQUEST_SECONDS + GATE_INTERVAL_FLOOR_SECONDS
    per_commit = TRANSPORT_TIMEOUT_SECONDS + GATE_INTERVAL_FLOOR_SECONDS
    recovery_seconds = recovery_slots * per_small
    observation_seconds = observation_small * per_small + probes * per_commit
    return {
        "intervalSeconds": GATE_INTERVAL_FLOOR_SECONDS,
        "smallRequestSeconds": SMALL_REQUEST_SECONDS,
        "boundaryCommitSeconds": TRANSPORT_TIMEOUT_SECONDS,
        "recoverySlots": recovery_slots,
        "observationSmallSlots": observation_small,
        "observationCommitSlots": probes,
        "recoverySeconds": round(recovery_seconds, 3),
        "observationSeconds": round(observation_seconds, 3),
        "totalSeconds": round(recovery_seconds + observation_seconds, 3),
        "gateWallCapSeconds": GATE_WALL_CAP_SECONDS,
        "basis": "shared_gate.create charges each slot requestSeconds plus intervalSeconds, refuses an interval below 0.25 and a wall above 1200, and refuses a recovery reservation below the recovery slots' cost.",
        "enforcement": "smallRequestSeconds is also the per-request timeout for a small read or delete, so a slot cannot outrun its own reservation; the boundary Commits keep the 60-second transport deadline.",
    }


def _budget(accounting: dict[str, int]) -> dict[str, Any]:
    # Permission and reservation are sized by the maximum, never by the
    # forecast. Budgeting the expected outcome would make the campaign unable
    # to pay for the one result it exists to detect.
    maximum = _maximum_usage()
    return {
        "maxRuns": 1,
        "maxConcurrency": 1,
        "maxInFlightRequests": 1,
        "maxAccounts": 1,
        "maxDocuments": maximum["documentWrites"],
        "maxDistinctResources": maximum["distinctResources"],
        "maxPeakLiveDocuments": maximum["peakLiveDocuments"],
        "maxReads": maximum["documentReads"],
        "maxWrites": maximum["documentWrites"],
        "maxDeletes": maximum["documentDeletes"],
        "maxHttpRequests": maximum["httpRequests"],
        "expectedWrites": accounting["documentWrites"],
        "expectedDeletes": accounting["documentDeletes"],
        "budgetBasis": "maxima cover every probe being accepted; expectedWrites and expectedDeletes are the forecast under the expected outcome and bind nothing",
        "maxRequestBytes": max(REQUEST_TARGETS),
        "maxResponseBytes": 2 * 1024 * 1024,
        "perRequestTimeoutSeconds": TRANSPORT_TIMEOUT_SECONDS,
        "smallRequestTimeoutSeconds": SMALL_REQUEST_SECONDS,
        "maxDurationSeconds": 1100,
        "schedulingReservation": _scheduling_reservation(),
        "recoveryWindow": {
            "reserveSeconds": 500,
            "reserveReads": len(REQUEST_TARGETS) * DOCUMENT_COUNT * 2,
            "reserveDeletes": len(REQUEST_TARGETS) * DOCUMENT_COUNT,
            "trigger": "any probe that reaches an observation failure, an uncertain Commit or an interrupted run",
            "authority": "read-only unless the same run holds a conditional-creation proof and a matching version-bound ownership read",
            "exitCondition": "typed NOT_FOUND for every one of the 51 owned resources",
            "onExhaustion": "stop, leave the remaining resources recorded as unresolved, and escalate to the owner; never widen the scope or retry a Commit",
        },
    }


def _owner_preconditions(project: str, database: str) -> list[dict[str, str]]:
    return [
        {
            "id": "o7-admission",
            "requirement": "An O7 admission decision that binds this campaign artifact digest, the frozen source and the credential holder.",
            "verifiable": "the admission record names this campaign digest",
        },
        {
            "id": "credential",
            "requirement": f"A bearer token for a principal that can write under the owned scope in {project}/{database} and nothing else it could damage.",
            "verifiable": "the runner acquires the token through the shared Ledger; this module never holds one",
        },
        {
            "id": "empty-owned-scope",
            "requirement": "Every one of the 51 owned resources is absent before the run. A preexisting document with the same marker is not owned by this run.",
            "verifiable": "all 51 preflight reads return typed NOT_FOUND; the run stops otherwise",
        },
        {
            "id": "quiet-project",
            "requirement": "No other campaign writes under the oracle scope for the duration of the run.",
            "verifiable": "campaign scheduling record",
        },
        {
            "id": "collector-untyped-refusal",
            "requirement": "Accept that an untyped transport refusal leaves the run inconclusive on the refusal shape, or extend the collector first.",
            "verifiable": "REFUSAL_EXPECTATION.untypedTransportRefusal is acknowledged in the admission record",
        },
    ]


def compile_request_bytes_campaign(
    project: str, database: str, nonce: str
) -> dict[str, Any]:
    """Compose the bounded campaign artifact around the reviewed compiler plan."""
    plan = compile_request_bytes_plan(project, database, nonce)
    validate_request_bytes_plan(plan)
    accounting = _request_accounting()
    if accounting["httpRequests"] != plan["bounds"]["totalRequestBound"]:
        raise AssertionError("campaign accounting disagrees with the compiled schedule")
    cases = []
    for case_id, probe, target in zip(CASE_IDS, plan["probes"], REQUEST_TARGETS):
        refused = target > REQUEST_LIMIT
        cases.append(
            {
                "id": case_id,
                "family": "firestore",
                "probe": probe["label"],
                "operation": "Commit",
                "requestBytes": target,
                "relationToLimit": target - REQUEST_LIMIT,
                "productionExpectation": "refused" if refused else "accepted",
                "refusalShape": REFUSAL_EXPECTATION if refused else None,
                "postState": {
                    "readbackCount": DOCUMENT_COUNT,
                    "expected": "every owned resource absent"
                    if refused
                    else "every owned resource present with its expected field digest and the version the Commit returned",
                    "proves": "the refused request wrote nothing"
                    if refused
                    else "the accepted request wrote exactly its own resource set",
                },
                "cleanup": {
                    "ownershipRead": DOCUMENT_COUNT,
                    "versionBoundDeletes": 0 if refused else DOCUMENT_COUNT,
                    "absenceProofs": DOCUMENT_COUNT,
                    "authority": "a version-bound DELETE requires this run's conditional-creation proof and a matching ownership read; every other path is a zero-wire skip",
                },
            }
        )
    campaign = {
        "schema": SCHEMA,
        "campaignId": CAMPAIGN,
        "catalogId": CAMPAIGN,
        "catalogSource": CATALOG_SOURCE,
        "catalogMaximum": REQUEST_LIMIT,
        "condition": "FS-LIMIT-API-REQUEST-BYTES",
        "parent": "FS-DATA-WRITE",
        "protocol": "REST",
        "operations": ["Commit"],
        "excludedOperations": [
            {
                "operation": "BatchWrite",
                "reason": "The reviewed compiler emits only the Commit endpoint and the collector's transport admits only `documents:commit`. A BatchWrite boundary needs its own compiler, transport admission and receipt shape.",
            },
            {
                "operation": "gRPC Commit",
                "reason": "Protobuf message encoding is a different metric and needs a separate compiler and receipt.",
            },
        ],
        "boundary": {
            "limit": REQUEST_LIMIT,
            "acceptedBytes": [t for t in REQUEST_TARGETS if t <= REQUEST_LIMIT],
            "refusedBytes": [t for t in REQUEST_TARGETS if t > REQUEST_LIMIT],
            "metric": plan["metric"],
            "metricStatus": plan["metricStatus"],
        },
        "caseIds": list(CASE_IDS),
        "cases": cases,
        "refusalExpectation": REFUSAL_EXPECTATION,
        "localExpectation": LOCAL_EXPECTATION,
        "owner": {
            "project": project,
            "database": database,
            "nonce": nonce,
            "nonceDigest": _nonce_digest(nonce),
            "scope": plan["ownedScope"],
            "scopes": plan["ownedScopes"],
            "resourceCount": len(plan["ownedResources"]),
            "nonceHandling": "The nonce is a scope label, not a secret; it appears in every owned resource path and is published with this artifact. It is fresh for this campaign and must not be reused. A document that already exists under it is not owned by this run and stops the run at preflight.",
        },
        "ownerPreconditions": _owner_preconditions(project, database),
        "accounting": accounting,
        "maximumUsage": _maximum_usage(),
        "planBounds": plan["bounds"],
        "transportDeadline": TRANSPORT_DEADLINE,
        "cost": _cost(accounting),
        "budget": _budget(accounting),
        "planDigest": hashlib.sha256(compact_utf8(plan)).hexdigest(),
        "boundSources": [
            "tools/compat-broad/fs-request-bytes-boundary/request_bytes_compiler.py",
            "tools/compat-broad/fs-request-bytes-boundary/request_bytes_collector.py",
            "tools/compat-broad/fs-request-bytes-boundary/request_bytes_campaign.py",
            "tools/compat-broad/fs-request-bytes-boundary/request_bytes_local_transport.py",
            "tools/compat-broad/fs-request-bytes-boundary/request_bytes_remote_transport.py",
            "tools/compat-broad/fs-request-bytes-boundary/request_bytes_https_worker.py",
            "tools/compat-broad/fs-request-bytes-boundary/request_bytes_process_exchange.py",
        ],
        "productionExecuted": False,
        "formalCompatibilityClaim": False,
        "authorizesProductionExecution": False,
        "claims": list(plan["claims"]),
    }
    return campaign


def validate_request_bytes_campaign(campaign: dict[str, Any]) -> None:
    """Independently check the campaign artifact; never repair it."""
    if not isinstance(campaign, dict):
        raise TypeError("campaign must be an object")
    for key, value in (
        ("schema", SCHEMA),
        ("campaignId", CAMPAIGN),
        ("catalogId", CAMPAIGN),
        ("catalogMaximum", REQUEST_LIMIT),
        ("protocol", "REST"),
        ("productionExecuted", False),
        ("formalCompatibilityClaim", False),
        ("authorizesProductionExecution", False),
    ):
        if campaign.get(key) != value:
            raise ValueError(f"campaign contract drift: {key}")
    if campaign.get("operations") != ["Commit"]:
        raise ValueError("only the Commit operation is in scope")
    excluded = {item["operation"] for item in campaign.get("excludedOperations", [])}
    if "BatchWrite" not in excluded:
        raise ValueError("BatchWrite must be explicitly excluded with a reason")

    boundary = campaign.get("boundary")
    if not isinstance(boundary, dict):
        raise TypeError("missing boundary")
    accepted = boundary.get("acceptedBytes")
    refused = boundary.get("refusedBytes")
    if not isinstance(accepted, list) or not isinstance(refused, list):
        raise TypeError("boundary byte lists malformed")
    if REQUEST_LIMIT - 1 not in accepted or REQUEST_LIMIT not in accepted:
        raise ValueError("boundary must accept the limit and one byte below it")
    if refused != [REQUEST_LIMIT + 1]:
        raise ValueError("boundary must refuse exactly one byte above the limit")
    if set(accepted) | set(refused) != set(REQUEST_TARGETS):
        raise ValueError("boundary does not cover the compiled probe targets")
    if boundary.get("metricStatus") != "observation hypothesis":
        raise ValueError("the request-byte metric must stay an observation hypothesis")

    cases = campaign.get("cases")
    if not isinstance(cases, list) or len(cases) != len(REQUEST_TARGETS):
        raise ValueError("one case per compiled probe is required")
    if [case.get("id") for case in cases] != list(CASE_IDS):
        raise ValueError("case identities drifted")
    seen_bytes = []
    for case in cases:
        size = case.get("requestBytes")
        if size not in REQUEST_TARGETS:
            raise ValueError("case byte size outside the compiled targets")
        seen_bytes.append(size)
        if case.get("relationToLimit") != size - REQUEST_LIMIT:
            raise ValueError("case limit relation is wrong")
        over = size > REQUEST_LIMIT
        expected = "refused" if over else "accepted"
        if case.get("productionExpectation") != expected:
            raise ValueError(f"case {case.get('id')} has the wrong expectation")
        shape = case.get("refusalShape")
        if over:
            if shape != REFUSAL_EXPECTATION:
                raise ValueError("the refused case must carry the typed refusal shape")
        elif shape is not None:
            raise ValueError("an accepted case must not carry a refusal shape")
        post = case.get("postState")
        if not isinstance(post, dict) or post.get("readbackCount") != DOCUMENT_COUNT:
            raise ValueError("every case must read back all its owned resources")
        if over and post.get("expected") != "every owned resource absent":
            raise ValueError("the refused case must require an absent post state")
        cleanup = case.get("cleanup")
        if not isinstance(cleanup, dict):
            raise TypeError("missing cleanup contract")
        if cleanup.get("absenceProofs") != DOCUMENT_COUNT:
            raise ValueError("cleanup must prove absence for every owned resource")
        if cleanup.get("versionBoundDeletes") != (0 if over else DOCUMENT_COUNT):
            raise ValueError("a refused probe must not schedule a delete")
    if sorted(seen_bytes) != sorted(REQUEST_TARGETS):
        raise ValueError("cases do not cover each compiled target exactly once")

    if campaign.get("refusalExpectation") != REFUSAL_EXPECTATION:
        raise ValueError("refusal expectation drifted")
    untyped = REFUSAL_EXPECTATION["untypedTransportRefusal"]
    if untyped.get("isRefusalProof") is not False:
        raise ValueError("an untyped transport refusal is never a refusal proof")
    if "read-only" not in untyped.get("recoveryAuthority", ""):
        raise ValueError("an untyped refusal must keep recovery read-only")
    local = campaign.get("localExpectation")
    if not isinstance(local, dict):
        raise TypeError("missing local expectation")
    if not local.get("localEnforcement"):
        raise ValueError("the local expectation must record the observed enforcement")
    if not local.get("enforcementSource"):
        raise ValueError("the local enforcement source must be named")
    if local.get("catalogState") != "implemented":
        raise ValueError("the catalog records this condition as implemented")
    observed = local.get("observedRefusal")
    if not isinstance(observed, dict):
        raise TypeError("the local expectation must record the observed refusal")
    expected = next(
        item
        for item in REFUSAL_EXPECTATION["typed"]
        if item["classification"] == "expected"
    )
    if (
        observed.get("httpStatus") != expected["httpStatus"]
        or observed.get("errorCode") != expected["errorCode"]
        or observed.get("errorStatus") != expected["errorStatus"]
    ):
        raise ValueError(
            "the observed local refusal no longer matches the expected shape"
        )
    if observed.get("classification") != "expected":
        raise ValueError("a local refusal equal to the expected shape is `expected`")
    if not observed.get("message"):
        raise ValueError("the observed refusal message must be recorded")

    # Per transport, because a reader comparing a production receipt needs the
    # status, the code and the message separately, and because this campaign
    # observes only the REST row.
    by_transport = local.get("observedRefusalByTransport")
    if not isinstance(by_transport, dict) or set(by_transport) != {"rest", "grpc"}:
        raise ValueError("the local refusal must be recorded per transport")
    rest = by_transport["rest"]
    if (
        rest.get("httpStatus") != observed["httpStatus"]
        or rest.get("errorCode") != observed["errorCode"]
        or rest.get("errorStatus") != observed["errorStatus"]
        or rest.get("message") != observed["message"]
    ):
        raise ValueError("the REST row disagrees with the observed refusal")
    grpc = by_transport["grpc"]
    if grpc.get("httpStatus") is not None:
        raise ValueError("a gRPC refusal carries no HTTP status")
    if grpc.get("errorStatus") != "INVALID_ARGUMENT" or grpc.get("errorCode") != 3:
        raise ValueError("the gRPC refusal code drifted from google.rpc.Code")
    if not grpc.get("message") or not grpc.get("observedBy"):
        raise ValueError("the gRPC row must say what it says and who saw it")
    if "not this campaign" not in grpc.get("observedBy", ""):
        raise ValueError("this campaign observes REST only; the gRPC row must say so")

    legacy = local.get("emulatorProfileRefusal")
    if not isinstance(legacy, dict) or legacy.get("profile") != "emulator":
        raise ValueError("the other profile's refusal must be recorded")
    if legacy.get("rest", {}).get("httpStatus") != 413:
        raise ValueError("the emulator profile's REST refusal drifted")

    if not local.get("differenceFromProductionExpectation"):
        raise ValueError("the local difference must be stated, not absorbed")
    if "does not confirm" not in local["differenceFromProductionExpectation"]:
        raise ValueError(
            "local agreement with a documented expectation is not confirmation of it"
        )
    if not local.get("supersededBaseline"):
        raise ValueError("the superseded local baseline must stay on the record")
    if local.get("expectedCompleted") is not True:
        raise ValueError("the observed local run completes; say so")
    if local.get("expectedResourceAbsence") is not True:
        raise ValueError("a local run must still prove resource absence")
    if local.get("expectedCollectorFailures") != []:
        raise ValueError("the observed local run records no collector failure")

    owner = campaign.get("owner")
    if not isinstance(owner, dict):
        raise TypeError("missing owner block")
    nonce = owner.get("nonce")
    if not isinstance(nonce, str) or not re.fullmatch(r"[0-9a-f]{32}", nonce):
        raise ValueError("owner nonce malformed")
    if owner.get("nonceDigest") != _nonce_digest(nonce):
        raise ValueError("owner nonce digest does not bind the nonce")
    if not owner.get("nonceHandling"):
        raise ValueError("the nonce handling rule must be stated")
    if owner.get("resourceCount") != len(REQUEST_TARGETS) * DOCUMENT_COUNT:
        raise ValueError("owned resource count drifted")
    scopes = owner.get("scopes")
    scope = owner.get("scope")
    if not isinstance(scopes, list) or len(set(scopes)) != len(REQUEST_TARGETS):
        raise ValueError("each probe needs its own disjoint scope")
    if not isinstance(scope, str) or any(
        not isinstance(item, str) or not item.startswith(scope + "/") for item in scopes
    ):
        raise ValueError("probe scopes must sit under the owned scope")

    preconditions = campaign.get("ownerPreconditions")
    if not isinstance(preconditions, list) or not preconditions:
        raise ValueError("owner preconditions are required")
    required = {"o7-admission", "credential", "empty-owned-scope"}
    if not required.issubset({item.get("id") for item in preconditions}):
        raise ValueError("a required owner precondition is missing")

    accounting = campaign.get("accounting")
    if accounting != _request_accounting():
        raise ValueError("request accounting drifted from the fixed schedule shape")
    maximum = campaign.get("maximumUsage")
    if maximum != _maximum_usage():
        raise ValueError("maximum usage drifted from the fixed schedule shape")
    # The campaign must be able to pay for the outcome it exists to detect: an
    # over-boundary probe that production unexpectedly accepts creates and then
    # recovers all 51 documents.
    if maximum["documentWrites"] != len(REQUEST_TARGETS) * DOCUMENT_COUNT:
        raise ValueError("the maximum must cover every probe being accepted")
    if maximum["documentDeletes"] != maximum["documentWrites"]:
        raise ValueError("every document the maximum creates must be recoverable")
    for key in ("documentReads", "documentWrites", "documentDeletes", "httpRequests"):
        if maximum[key] < accounting[key]:
            raise ValueError(f"the maximum is below the forecast for {key}")
    # These two do not rise with the outcome: probes are cleaned up one at a
    # time, and a refused probe's delete slots are consumed as zero-wire skips.
    if maximum["peakLiveDocuments"] != DOCUMENT_COUNT:
        raise ValueError("peak coexisting documents must stay at one probe's set")
    if maximum["httpRequests"] != accounting["httpRequests"]:
        raise ValueError("the request bound does not depend on the outcome")
    bounds = campaign.get("planBounds")
    if not isinstance(bounds, dict):
        raise TypeError("missing compiled schedule bounds")
    if bounds.get("totalRequestBound") != accounting["httpRequests"]:
        raise ValueError("accounting disagrees with the compiled schedule bound")
    if bounds.get("maxInFlight") != 1 or bounds.get("probeCount") != len(
        REQUEST_TARGETS
    ):
        raise ValueError("compiled schedule bounds drifted")
    if bounds.get("distinctDocumentCount") != len(REQUEST_TARGETS) * DOCUMENT_COUNT:
        raise ValueError("distinct document count drifted")
    cost = campaign.get("cost")
    if not isinstance(cost, dict):
        raise TypeError("missing cost estimate")
    estimate = cost.get("estimatedCostUsd")
    ceiling = cost.get("hardCostCeilingUsd")
    worst = cost.get("maximumCostUsd")
    if not isinstance(worst, (int, float)) or isinstance(worst, bool):
        raise TypeError("the maximum cost must be published alongside the forecast")
    if abs(worst - round(_usage_cost(_maximum_usage()), 6)) > 1e-9:
        raise ValueError("the maximum cost does not follow from the maximum usage")
    if worst < estimate:
        raise ValueError("the maximum cost cannot be below the forecast")
    # The ceiling has to clear what the run can actually cost, not what it is
    # expected to cost. Only the forecast was checked against it before.
    if ceiling < worst:
        raise ValueError("the hard ceiling must clear the maximum cost")
    if not isinstance(estimate, (int, float)) or isinstance(estimate, bool):
        raise TypeError("cost estimate malformed")
    if not isinstance(ceiling, (int, float)) or estimate >= ceiling:
        raise ValueError("the estimate must sit strictly under the hard ceiling")
    if abs(estimate - _cost(accounting)["estimatedCostUsd"]) > 1e-9:
        raise ValueError("cost estimate does not follow from the accounting")

    budget = campaign.get("budget")
    if not isinstance(budget, dict):
        raise TypeError("missing budget")
    if budget.get("maxRuns") != 1 or budget.get("maxConcurrency") != 1:
        raise ValueError("this campaign is a single serial run")
    if budget.get("maxRequestBytes") != max(REQUEST_TARGETS):
        raise ValueError("budget request cap drifted")
    # Sized by the maximum, never by the forecast.
    for key, source in (
        ("maxReads", "documentReads"),
        ("maxWrites", "documentWrites"),
        ("maxDeletes", "documentDeletes"),
        ("maxHttpRequests", "httpRequests"),
        ("maxDocuments", "documentWrites"),
        ("maxDistinctResources", "distinctResources"),
        ("maxPeakLiveDocuments", "peakLiveDocuments"),
    ):
        if budget.get(key) != maximum[source]:
            raise ValueError(f"budget {key} is not the maximum for {source}")
    if budget.get("expectedWrites") != accounting["documentWrites"]:
        raise ValueError("the forecast writes drifted")
    if budget.get("expectedDeletes") != accounting["documentDeletes"]:
        raise ValueError("the forecast deletes drifted")
    if not budget.get("budgetBasis"):
        raise ValueError("the budget must say what its maxima cover")
    for combination in _accept_combinations():
        usage = probe_usage(combination)
        for key, source in (
            ("maxWrites", "documentWrites"),
            ("maxDeletes", "documentDeletes"),
            ("maxReads", "documentReads"),
            ("maxHttpRequests", "httpRequests"),
            ("maxPeakLiveDocuments", "peakLiveDocuments"),
        ):
            if usage[source] > budget[key]:
                raise ValueError(
                    f"outcome {combination} needs more {source} than the budget allows"
                )
    deadline = campaign.get("transportDeadline")
    if not isinstance(deadline, dict):
        raise TypeError("the campaign must publish the transport deadline")
    published = deadline.get("perRequestSeconds")
    if published != TRANSPORT_TIMEOUT_SECONDS:
        raise ValueError("the published deadline is not the transport's ceiling")
    # The transport rejects any larger timeout argument, so a budget that
    # promised more than the ceiling could never be honoured.
    if budget.get("perRequestTimeoutSeconds") != published:
        raise ValueError("the budget timeout does not match the transport ceiling")
    if budget.get("perRequestTimeoutSeconds") > TRANSPORT_TIMEOUT_SECONDS:
        raise ValueError("the budget timeout exceeds what the transport can honour")
    derivation = deadline.get("derivation")
    if not isinstance(derivation, dict):
        raise TypeError("the deadline needs a written derivation")
    if derivation.get("uploadBits") != max(REQUEST_TARGETS) * 8:
        raise ValueError("the derivation does not use the boundary request size")
    required = derivation.get("derivedRequirementSeconds")
    if not isinstance(required, (int, float)) or required <= 0:
        raise ValueError("the derived requirement is malformed")
    if published < required:
        raise ValueError("the published deadline is below its own derivation")
    reserve = deadline.get("nonUploadReserveSeconds")
    if not isinstance(reserve, (int, float)) or not 0 < reserve < published:
        raise ValueError("the non-upload reserve must fit inside the deadline")
    rate = deadline.get("slowestUsableUpstreamBitsPerSecond")
    if rate != round(max(REQUEST_TARGETS) * 8 / (published - reserve)):
        raise ValueError("the slowest usable upstream rate does not follow")
    for key in ("covers", "consequenceIfMissed", "detection", "ownerAction"):
        if not deadline.get(key):
            raise ValueError(f"the deadline block is missing {key}")
    if not isinstance(deadline.get("enforcedBy"), list) or not deadline["enforcedBy"]:
        raise ValueError("the deadline must name what enforces it")

    window = budget.get("recoveryWindow")
    if not isinstance(window, dict):
        raise TypeError("the budget must declare a recovery window")
    for key in (
        "reserveSeconds",
        "reserveReads",
        "reserveDeletes",
        "trigger",
        "authority",
        "exitCondition",
        "onExhaustion",
    ):
        if not window.get(key):
            raise ValueError(f"recovery window is missing {key}")
    if window["reserveSeconds"] >= budget.get("maxDurationSeconds", 0):
        raise ValueError("the recovery reserve must fit inside the run duration")

    # The wall-clock arithmetic has to close under the shared Gate's own
    # formula. This is where the published windows and the runner's reservation
    # previously drifted: a 300-second reserve admitted at most 1.71 seconds a
    # recovery slot, which nothing in the artifact said.
    reservation = budget.get("schedulingReservation")
    if reservation != _scheduling_reservation():
        raise ValueError("the scheduling reservation drifted from the Gate's formula")
    if reservation["intervalSeconds"] < GATE_INTERVAL_FLOOR_SECONDS:
        raise ValueError("the interval is below the Gate's floor")
    if reservation["recoverySlots"] != len(REQUEST_TARGETS) * DOCUMENT_COUNT * 3:
        raise ValueError("the recovery slot count drifted from the schedule")
    if window["reserveSeconds"] < reservation["recoverySeconds"]:
        raise ValueError(
            "the recovery reserve cannot pay for its own slots at the reserved rate"
        )
    if reservation["totalSeconds"] > budget["maxDurationSeconds"]:
        raise ValueError("the reserved schedule does not fit the published wall")
    if budget["maxDurationSeconds"] > GATE_WALL_CAP_SECONDS:
        raise ValueError("the wall exceeds the shared Gate's cap")
    if (
        reservation["observationSeconds"]
        > budget["maxDurationSeconds"] - window["reserveSeconds"]
    ):
        raise ValueError("observation does not fit outside the recovery reserve")
    # A reservation nothing enforces is a wish. The small-request timeout has to
    # be the reserved figure, and within what the transport will accept.
    if budget.get("smallRequestTimeoutSeconds") != reservation["smallRequestSeconds"]:
        raise ValueError("a small slot's timeout must equal its reservation")
    if budget["smallRequestTimeoutSeconds"] > TRANSPORT_TIMEOUT_SECONDS:
        raise ValueError("the small-request timeout exceeds the transport ceiling")
    # The reserve exists for the worst legitimate outcome, so it is sized by the
    # maximum. Checking it against the forecast let reserveDeletes 34 stand
    # beside maxDeletes 51.
    if window["reserveDeletes"] < maximum["documentDeletes"]:
        raise ValueError(
            "the recovery reserve cannot cover fewer deletes than the maximum"
        )
    # Recovery reads each owned resource twice: one ownership read and one
    # absence proof. Without this guard any positive number was accepted.
    if window["reserveReads"] < maximum["distinctResources"] * 2:
        raise ValueError(
            "the recovery reserve must cover an ownership read and an absence "
            "proof for every owned resource"
        )

    digest_plan = campaign.get("planDigest")
    if not isinstance(digest_plan, str) or len(digest_plan) != 64:
        raise ValueError("plan digest malformed")
    sources = campaign.get("boundSources")
    if not isinstance(sources, list) or len(set(sources)) != len(sources):
        raise ValueError("bound sources malformed")
    if not any(name.endswith("request_bytes_compiler.py") for name in sources):
        raise ValueError("the compiler must be a bound source")


def campaign_digest(campaign: dict[str, Any]) -> str:
    return hashlib.sha256(compact_utf8(campaign)).hexdigest()
