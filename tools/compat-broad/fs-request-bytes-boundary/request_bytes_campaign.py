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
        "state": "commit-uncertain",
        "handling": "The reviewed collector cannot classify a non-JSON transport refusal as a typed refusal. Such a receipt leaves the probe uncertain, recovery stays read-only, and the campaign is inconclusive on the refusal shape.",
        "stillProven": "The post-state readback and the recovery absence proofs still establish that the refused request wrote nothing.",
        "ownerAction": "If production answers with an untyped transport refusal, the collector needs an explicit untyped-refusal classification before a second run can conclude the boundary.",
    },
}

#: What the local fireemu runtime does today, as observed by the local shadow on
#: 2026-09-18 rather than assumed. The limits layer does not implement this
#: condition, but the REST transport already caps the request body at exactly
#: 10 MiB, so the boundary is enforced and the refusal shape differs from the
#: one expected of production. The shadow reports that difference; it does not
#: relax the production expectation to absorb it.
LOCAL_EXPECTATION: dict[str, Any] = {
    "localEnforcement": "transport body cap",
    "enforcementSource": "crates/fireemu-adapter-grpc/src/serve.rs, MAX_REST_BODY_BYTES = 10 * 1024 * 1024",
    "catalogState": "unsupported",
    "catalogNote": "The limits catalog still records FS-LIMIT-API-REQUEST-BYTES as unsupported, and the limits layer does indeed not implement it. The boundary is nonetheless enforced, one layer earlier.",
    "observedProbeOutcomes": {
        "under": "accepted",
        "exact": "accepted",
        "over": "refused",
    },
    "observedRefusal": {
        "httpStatus": 413,
        "errorCode": 413,
        "errorStatus": "INVALID_ARGUMENT",
        "message": "request body too large",
        "classification": "semantic-discrepancy",
    },
    "differenceFromProductionExpectation": "The boundary byte count agrees with the catalog maximum. The refusal code does not: the local runtime answers 413, while the expected production shape is 400. Under the collector's rules 413 is a typed refusal classified as a semantic discrepancy, so this difference is recorded rather than waived.",
    "expectedCollectorFailures": [],
    "expectedCompleted": True,
    "expectedResourceAbsence": True,
    "classification": "local-boundary-enforced-shape-differs",
    "pendingLimitsImplementation": "A separate Rust lane is implementing this condition in the limits layer. The transport cap already refuses at the same boundary, so a limits-layer check will never be reached on the REST path unless it runs before the body cap or the cap is raised. That lane needs this observation.",
    "note": "A local run in which the over probe is accepted would mean the transport cap was removed or raised; the shadow reports that as `local-boundary-not-enforced` rather than passing.",
}


def _nonce_digest(nonce: str) -> str:
    return hashlib.sha256(nonce.encode("ascii")).hexdigest()


def _request_accounting() -> dict[str, int]:
    """Derive the billable unit counts from the fixed schedule shape.

    Per probe the schedule is 17 preflight reads, one Commit, 17 post-state
    readbacks, then 17 ownership reads, 17 deletes and 17 absence reads.
    """
    probes = len(REQUEST_TARGETS)
    accepted = sum(1 for target in REQUEST_TARGETS if target <= REQUEST_LIMIT)
    reads = probes * DOCUMENT_COUNT * 4
    writes = accepted * DOCUMENT_COUNT
    deletes = accepted * DOCUMENT_COUNT
    # Four reads and one delete slot per owned resource, plus one Commit per
    # probe. Delete slots on a refused probe are consumed as zero-wire skips,
    # so this is a ceiling rather than the number that will be sent.
    requests = probes * DOCUMENT_COUNT * 5 + probes
    return {
        "documentReads": reads,
        "documentWrites": writes,
        "documentDeletes": deletes,
        "httpRequests": requests,
        "uploadedBytes": sum(REQUEST_TARGETS),
    }


def _cost(accounting: dict[str, int]) -> dict[str, Any]:
    usd = (
        accounting["documentReads"] * READ_USD_PER_UNIT
        + accounting["documentWrites"] * WRITE_USD_PER_UNIT
        + accounting["documentDeletes"] * DELETE_USD_PER_UNIT
    )
    return {
        "estimatedCostUsd": round(usd, 6),
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


def _budget(accounting: dict[str, int]) -> dict[str, Any]:
    return {
        "maxRuns": 1,
        "maxConcurrency": 1,
        "maxInFlightRequests": 1,
        "maxAccounts": 1,
        "maxDocuments": accounting["documentWrites"],
        "maxDistinctResources": len(REQUEST_TARGETS) * DOCUMENT_COUNT,
        "maxPeakLiveDocuments": DOCUMENT_COUNT,
        "maxReads": accounting["documentReads"],
        "maxWrites": accounting["documentWrites"],
        "maxDeletes": accounting["documentDeletes"],
        "maxHttpRequests": accounting["httpRequests"],
        "maxRequestBytes": max(REQUEST_TARGETS),
        "maxResponseBytes": 2 * 1024 * 1024,
        "perRequestTimeoutSeconds": 12,
        "maxDurationSeconds": 900,
        "recoveryWindow": {
            "reserveSeconds": 300,
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
        "planBounds": plan["bounds"],
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
    local = campaign.get("localExpectation")
    if not isinstance(local, dict):
        raise TypeError("missing local expectation")
    if local.get("localEnforcement") != "transport body cap":
        raise ValueError("the local expectation must record the observed enforcement")
    if not local.get("enforcementSource"):
        raise ValueError("the local enforcement source must be named")
    if local.get("catalogState") != "unsupported":
        raise ValueError("the catalog state for this condition is unsupported")
    observed = local.get("observedRefusal")
    if not isinstance(observed, dict):
        raise TypeError("the local expectation must record the observed refusal")
    if observed.get("httpStatus") != 413 or observed.get("errorCode") != 413:
        raise ValueError("the observed local refusal code drifted")
    if observed.get("classification") != "semantic-discrepancy":
        raise ValueError(
            "a local refusal code unlike production is a semantic discrepancy"
        )
    if not local.get("differenceFromProductionExpectation"):
        raise ValueError("the local difference must be stated, not absorbed")
    if not local.get("pendingLimitsImplementation"):
        raise ValueError("the pending limits-layer implementation must be recorded")
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
    for key in ("maxReads", "maxWrites", "maxDeletes", "maxHttpRequests"):
        if (
            budget.get(key)
            != accounting[
                {
                    "maxReads": "documentReads",
                    "maxWrites": "documentWrites",
                    "maxDeletes": "documentDeletes",
                    "maxHttpRequests": "httpRequests",
                }[key]
            ]
        ):
            raise ValueError(f"budget {key} does not match the accounting")
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
    if window["reserveDeletes"] < accounting["documentDeletes"]:
        raise ValueError("the recovery reserve cannot cover fewer deletes than planned")

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
