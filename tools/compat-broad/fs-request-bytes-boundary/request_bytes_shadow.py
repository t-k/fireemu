"""Bounded local artifact shadow for the 10 MiB request-byte boundary.

The shadow runs the reviewed compiler plan and collector against an owned local
fireemu artifact built from this checkout. The observed local behaviour is that
the boundary is enforced at exactly 10 MiB by the limits layer, and that the
strict profile's refusal carries the same status, code and message this campaign
expects of production. That expectation is documented rather than observed, so
the shadow records agreement with it and never reads it as confirmation.

No production request, credential or reservation is involved.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import statistics
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
for entry in (str(HERE), str(HERE.parent), str(ROOT / "tools/compat-inventory")):
    if entry not in sys.path:
        sys.path.insert(0, entry)

from request_bytes_campaign import (
    BASELINE_COMPARISON_FIELDS,
    LOCAL_EXPECTATION,
    SMALL_REQUEST_SECONDS,
    campaign_digest,
    compile_request_bytes_campaign,
    validate_request_bytes_campaign,
)
from request_bytes_collector import collect_local
from request_bytes_compiler import (
    CAMPAIGN,
    DOCUMENT_COUNT,
    compile_request_bytes_plan,
    validate_request_bytes_plan,
)

PROJECT = "demo-firestore-probe"
DATABASE = "(default)"
SHADOW_KIND = "fs-request-bytes-local-shadow-v1"

#: A repo-relative marker, never an absolute path. This record is published, so
#: an absolute path would leak the operator's filesystem and could never hold
#: from another checkout. The path-independent binding is runtimeInputsDigest.
REPOSITORY_ROOT_MARKER = "repository-root"

#: The modules that produce the observation. Test files are deliberately out of
#: this binding: editing a test must not invalidate a recorded run.
OBSERVATION_MODULES = (
    "request_bytes_campaign.py",
    "request_bytes_collector.py",
    "request_bytes_compiler.py",
    "request_bytes_https_worker.py",
    "request_bytes_local_transport.py",
    "request_bytes_process_exchange.py",
    "request_bytes_remote_transport.py",
    "request_bytes_shadow.py",
)

#: Response bodies at or below this size are republished verbatim in the record.
#: A successful Commit response is larger and is represented by its digest.
RESPONSE_EXCERPT_BYTES = 4096

#: Why the published timings are a floor and not an estimate. This travels with
#: the numbers so a reader cannot pick them up without it.
LOOPBACK_TIMING_DISCLAIMER = (
    "Loopback service time against an owned local emulator on the same machine. "
    "It excludes the network round trip, TLS and production server time, so it "
    "is a floor for a production per-slot figure and never an estimate of one. "
    "A production reservation needs a production measurement; the production "
    "transport now records elapsed time per request so one can be taken."
)

#: Slot classes. The boundary Commits carry a 10 MiB body; everything else is a
#: small read or delete, and the two have nothing to do with each other.
COMMIT_SLOT = "boundaryCommit"
SMALL_SLOT = "smallRequest"

PUBLICATION_NOTE = (
    "Owned local artifact shadow. No production request was sent, no credential "
    "was used and no parent group is promoted. The raw REST body byte count "
    "remains an observation hypothesis about production's enforcement metric."
)


def save(path: Path, value: Any) -> None:
    """Create an immutable receipt, refusing an existing file or a symlink."""
    with path.open("x") as stream:
        json.dump(value, stream, indent=2, allow_nan=False, sort_keys=True)
        stream.write("\n")


def source_inputs() -> dict[str, str]:
    return {
        str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(HERE.glob("*.py"))
    }


def observation_source_digest() -> str:
    """One digest over the modules that produced an observation."""
    import hashlib as _hashlib

    inputs = {
        name: _hashlib.sha256((HERE / name).read_bytes()).hexdigest()
        for name in OBSERVATION_MODULES
    }
    return _hashlib.sha256(
        json.dumps(inputs, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def runtime_binding(artifact: Path) -> dict[str, Any]:
    """Bind the executed artifact to the Rust source it was built from."""
    import subprocess

    sys.path.insert(0, str(ROOT / "tools/compat-inventory"))
    from broad_contract import digest
    from evidence_common import runtime_inputs

    commit = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
    ).strip()
    dirty = subprocess.check_output(
        ["git", "status", "--porcelain", "--", "Cargo.toml", "Cargo.lock", "crates"],
        cwd=ROOT,
        text=True,
    ).strip()
    inputs = runtime_inputs(ROOT)
    return {
        "artifactSha256": hashlib.sha256(Path(artifact).read_bytes()).hexdigest(),
        "sourceCommit": commit,
        "sourceRoot": REPOSITORY_ROOT_MARKER,
        "runtimeInputsDigest": digest(inputs),
        "runtimeInputCount": len(inputs),
        "runtimeInputsClean": dirty == "",
    }


def probe_outcomes(collection: Path, plan: dict[str, Any]) -> list[dict[str, Any]]:
    """Read each probe's Commit outcome back out of the immutable row files.

    The per-probe HTTP status is the observation this lane exists to record, and
    it lives only in the multi-megabyte row directory otherwise.
    """
    by_probe: dict[str, dict[str, Any]] = {}
    for path in sorted(collection.glob("row-*.json")):
        row = json.loads(path.read_bytes())
        if row.get("kind") != "conditional-create-commit":
            continue
        receipt = row.get("receipt") or {}
        # Bounded rows carry no response body; the verbatim bytes live in the
        # sidecar next to them. A refusal body is small, so it is republished
        # here, which is the whole point of this record.
        body: Any = None
        sidecar = row.get("responseBodyFile")
        raw = b""
        if isinstance(sidecar, str):
            candidate = collection / sidecar
            if (
                candidate.is_file()
                and candidate.stat().st_size <= RESPONSE_EXCERPT_BYTES
            ):
                raw = candidate.read_bytes()
                try:
                    body = json.loads(raw)
                except ValueError:
                    body = None
        error = body.get("error") if isinstance(body, dict) else None
        by_probe[row["probe"]] = {
            "probe": row["probe"],
            "requestBytes": row.get("requestBytes"),
            "httpStatus": receipt.get("status"),
            "complete": receipt.get("complete"),
            "responseBytes": row.get("responseBytes"),
            "responseSha256": row.get("responseSha256"),
            "errorCode": error.get("code") if isinstance(error, dict) else None,
            "errorStatus": error.get("status") if isinstance(error, dict) else None,
            "errorMessage": error.get("message") if isinstance(error, dict) else None,
            "responseBody": raw.decode("utf-8", errors="replace")
            if raw and receipt.get("status") != 200
            else None,
        }
    return [
        by_probe[probe["label"]]
        for probe in plan["probes"]
        if probe["label"] in by_probe
    ]


def _percentile(values: list[float], percent: float) -> float:
    """Nearest-rank percentile. Exact on the sample, no interpolation."""
    ordered = sorted(values)
    rank = max(1, math.ceil(percent / 100 * len(ordered)))
    return ordered[min(rank, len(ordered)) - 1]


def slot_timings(collection: Path) -> dict[str, Any]:
    """Summarise the per-slot elapsed times the local transport already records.

    The collector copies the whole receipt into each row, and the local
    transport puts `elapsedSeconds` on it, so this reads a measurement that
    already exists rather than adding one. Skipped slots send nothing and are
    excluded: a zero-wire skip costs no time and would drag every percentile
    toward zero.
    """
    samples: dict[str, list[float]] = {COMMIT_SLOT: [], SMALL_SLOT: []}
    for path in sorted(collection.glob("row-*.json")):
        row = json.loads(path.read_bytes())
        elapsed = (row.get("receipt") or {}).get("elapsedSeconds")
        if row.get("skipped") is not None or not isinstance(elapsed, (int, float)):
            continue
        key = (
            COMMIT_SLOT
            if row.get("kind") == "conditional-create-commit"
            else SMALL_SLOT
        )
        samples[key].append(float(elapsed))
    classes = {}
    for name, values in samples.items():
        if not values:
            classes[name] = {"count": 0}
            continue
        classes[name] = {
            "count": len(values),
            "medianSeconds": round(statistics.median(values), 6),
            "p95Seconds": round(_percentile(values, 95), 6),
            "p99Seconds": round(_percentile(values, 99), 6),
            "maxSeconds": round(max(values), 6),
            "totalSeconds": round(sum(values), 6),
        }
    return {
        "measurement": "loopback-floor",
        "disclaimer": LOOPBACK_TIMING_DISCLAIMER,
        "isProductionEstimate": False,
        "dispatchedCount": sum(len(v) for v in samples.values()),
        "classes": classes,
    }


def validate_slot_timings(timings: Any, dispatched: int) -> None:
    """Reject a timing block that cannot have come from a run."""
    if not isinstance(timings, dict):
        raise TypeError("slot timings must be an object")
    if timings.get("measurement") != "loopback-floor":
        raise ValueError("the timings must be labelled a loopback floor")
    if timings.get("isProductionEstimate") is not False:
        raise ValueError("a loopback figure is never a production estimate")
    if "floor" not in timings.get("disclaimer", ""):
        raise ValueError("the timings must carry their disclaimer")
    classes = timings.get("classes")
    if not isinstance(classes, dict) or set(classes) != {COMMIT_SLOT, SMALL_SLOT}:
        raise ValueError("the two slot classes must be reported separately")
    total = 0
    for name, entry in classes.items():
        count = entry.get("count")
        if type(count) is not int or count < 0:
            raise ValueError(f"{name} count malformed")
        total += count
        if count == 0:
            continue
        median, p95 = entry.get("medianSeconds"), entry.get("p95Seconds")
        p99, largest = entry.get("p99Seconds"), entry.get("maxSeconds")
        if not all(
            isinstance(value, (int, float)) and value >= 0
            for value in (median, p95, p99, largest, entry.get("totalSeconds"))
        ):
            raise ValueError(f"{name} timings malformed")
        if not median <= p95 <= p99 <= largest:
            raise ValueError(f"{name} percentiles are not ordered")
        if entry["totalSeconds"] < largest:
            raise ValueError(f"{name} total is below its own maximum")
    if total != timings.get("dispatchedCount"):
        raise ValueError("the class counts do not sum to the dispatched count")
    if total != dispatched:
        raise ValueError("the timings do not cover every dispatched request")


def build_shadow_document(
    *,
    before: str,
    after: str,
    runtime: dict[str, Any],
    nonce: str,
    plan_digest: str,
    campaign_digest_value: str,
    probes: list[dict[str, Any]],
    timings: dict[str, Any],
    collector: dict[str, Any],
    shadow: dict[str, Any],
    gates: dict[str, bool],
    cases: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build the published shadow record.

    This is the only place the record's shape is decided, so the checked-in
    evidence is something the tool produces rather than something a person
    assembled afterwards.
    """
    result = {
        "kind": SHADOW_KIND,
        "campaignId": CAMPAIGN,
        "target": "owned-local-artifact",
        "project": PROJECT,
        "database": DATABASE,
        "sourceDigestBefore": before,
        "sourceDigestAfter": after,
        "artifactSha256": runtime["artifactSha256"],
        "runtime": runtime,
        # The run's own nonce, so a reader can recompute planDigest and
        # campaignDigest instead of taking them on trust. It is a scope label
        # for an owned local project, not a secret.
        "nonce": nonce,
        "planDigest": plan_digest,
        "campaignDigest": campaign_digest_value,
        "probeOutcomes": probes,
        "slotTimings": timings,
        "observation": collector,
        "shadow": shadow,
        "recordingComplete": gates["recordingComplete"],
        "stateValidation": gates["stateValidation"],
        "cases": cases,
        "productionExecuted": False,
        "formalCompatibilityClaim": False,
        "rawHttpMetricStatus": "observation hypothesis",
        "note": PUBLICATION_NOTE,
    }
    result["complete"] = bool(
        before == after
        and runtime["runtimeInputsClean"]
        and gates["recordingComplete"]
        and gates["stateValidation"]
        and collector.get("resourceAbsence") is True
        and shadow.get("classification") != "shadow-failure"
    )
    return result


def classify_local_result(result: dict[str, Any]) -> dict[str, Any]:
    """Classify a collector result against the observed local baseline.

    Four outcomes are recognised, and none of them relaxes the production
    expectation:

    - `local-shape-matches-production-expectation` is the observed baseline. The
      limits layer refuses the over-boundary Commit at exactly 10 MiB, and every
      field in `BASELINE_COMPARISON_FIELDS` equals what this campaign expects of
      production. That expectation is documented rather than observed, so this
      is agreement with an expectation, not confirmation of it.
    - `local-boundary-enforced-shape-differs` means the boundary held but the
      refusal shape did not match. That covers the emulator profile's legacy
      413, which from a strict-profile build is a regression, and any refusal
      whose code, status or message differs from the expected one. The differing
      fields are listed in `refusalFieldMismatches`. The run's recording and
      recovery facts stand; only `matchesBaseline` goes false.
    - `local-boundary-not-enforced` means the over-boundary Commit was accepted,
      so the bound was removed or raised.
    - `local-untyped-transport-refusal` covers every complete refusal that is
      not the typed over-boundary envelope: a status outside 400 and 413, such
      as 500, 429 or 403, an HTML error page, or a body that is not a Firestore
      error at all. The collector cannot read any of these as a refusal proof,
      so the boundary question stays unanswered, recovery stays read-only, and
      the run reports `recordingComplete` false with `stateValidation` true.

    `shadow-failure` is not the bucket for an unfamiliar status. It is reached
    only by a result the collector could not have produced, such as an
    `overRefusal` block naming a status the typed predicate never accepts, which
    means the record was assembled rather than observed.
    """
    if not isinstance(result, dict):
        raise TypeError("result must be an object")
    failures = result.get("failures")
    if not isinstance(failures, list):
        raise TypeError("result failures malformed")
    absence = result.get("resourceAbsence") is True
    refusal = result.get("overRefusal")
    completed = result.get("completed") is True
    observed = LOCAL_EXPECTATION["observedRefusal"]
    legacy = LOCAL_EXPECTATION["emulatorProfileRefusal"]["rest"]
    clean_refusal = not failures and completed and absence and isinstance(refusal, dict)
    mismatches = refusal_field_mismatches(refusal) if clean_refusal else []
    if clean_refusal and not mismatches:
        classification = "local-shape-matches-production-expectation"
        summary = (
            "The limits layer refused the over-boundary Commit at exactly the "
            "10 MiB boundary with the status, code and message this campaign "
            "expects of production. That expectation is documented rather than "
            "observed, so this is agreement with it, not confirmation of it."
        )
    elif clean_refusal and refusal.get("httpStatus") == legacy["httpStatus"]:
        classification = "local-boundary-enforced-shape-differs"
        summary = (
            "The over-boundary Commit was refused with the emulator profile's "
            "legacy 413. From a strict-profile build that is a regression: the "
            "implemented refusal shape was lost. The boundary itself still holds."
        )
    elif clean_refusal and refusal.get("httpStatus") == observed["httpStatus"]:
        classification = "local-boundary-enforced-shape-differs"
        summary = (
            "The over-boundary Commit was refused at the right boundary, but the "
            "refusal shape is not the expected one: "
            + ", ".join(
                f"{item['field']} was {item['observed']!r}, expected "
                f"{item['expected']!r}"
                for item in mismatches
            )
            + "."
        )
    elif (
        _is_untyped_refusal_failure_set(failures)
        and refusal is None
        and isinstance(result.get("untypedOverRefusal"), dict)
        and absence
    ):
        classification = "local-untyped-transport-refusal"
        summary = (
            "The over-boundary Commit was refused without a typed Firestore "
            "envelope. The refusal shape is unproven and nothing was written."
        )
    elif failures == ["over:unexpected-success"] and refusal is None and absence:
        classification = "local-boundary-not-enforced"
        summary = (
            "The local runtime accepted the over-boundary Commit. The "
            "request-byte bound was removed or raised."
        )
    else:
        classification = "shadow-failure"
        summary = (
            "The local run matched none of the four recognised local outcomes, "
            "so this result is not one the collector could have produced."
        )
    return {
        "classification": classification,
        "summary": summary,
        "expectedClassification": LOCAL_EXPECTATION["classification"],
        "matchesBaseline": classification == LOCAL_EXPECTATION["classification"],
        "localEnforcement": LOCAL_EXPECTATION["localEnforcement"],
        "enforcementSource": LOCAL_EXPECTATION["enforcementSource"],
        "expectedRefusal": observed,
        "comparedFields": list(BASELINE_COMPARISON_FIELDS),
        "refusalFieldMismatches": mismatches,
        "observedFailures": failures,
        "resourceAbsence": absence,
        "overRefusal": refusal,
        "untypedOverRefusal": result.get("untypedOverRefusal"),
        "productionRefusalExpectation": "400 INVALID_ARGUMENT",
        "differenceMasked": False,
        "productionExecuted": False,
        "formalCompatibilityClaim": False,
    }


def _is_untyped_refusal_failure_set(failures: list[Any]) -> bool:
    """Recognise exactly the failures an unproven over-boundary refusal leaves.

    An untyped refusal proves nothing, so the collector records the missing
    commit proof and then refuses every version-bound delete for want of a
    creation proof. Those 17 skips are the read-only recovery working, not extra
    damage, but they are still failures and the run is still incomplete.
    """
    if not failures or failures[0] != "over:commit-proof-missing":
        return False
    rest = failures[1:]
    return len(rest) == DOCUMENT_COUNT and all(
        isinstance(entry, str)
        and entry.startswith("recovery:")
        and entry.endswith(":creation-and-current-version-not-proven")
        for entry in rest
    )


def _message_comparison(
    refusal: dict[str, Any], expected: str
) -> dict[str, Any] | None:
    """Compare the refusal message against the whole text, never a prefix.

    When the message was too long to carry in the final result the collector
    keeps an excerpt plus the digest of the whole thing, so the comparison moves
    to the digest. A matching excerpt is not a matching message, and this must
    never quietly become one.
    """
    if refusal.get("messageTruncated") is True:
        digest = hashlib.sha256(expected.encode("utf-8")).hexdigest()
        if refusal.get("messageSha256") == digest:
            return None
        return {
            "field": "message",
            "comparedBy": "sha256",
            "observed": {
                "sha256": refusal.get("messageSha256"),
                "bytes": refusal.get("messageBytes"),
                "excerpt": refusal.get("messageExcerpt"),
                "note": "truncated in the result; the full text is in the response sidecar",
                "responseBodyFile": refusal.get("responseBodyFile"),
            },
            "expected": expected,
        }
    observed = refusal.get("message", "<absent>")
    if observed == expected:
        return None
    return {
        "field": "message",
        "comparedBy": "text",
        "observed": observed,
        "expected": expected,
    }


def refusal_field_mismatches(refusal: Any) -> list[dict[str, Any]]:
    """Compare every declared field of the refusal shape, not just the status.

    A classification that says the status, the code and the message matched has
    to have compared all three. Comparing only the status and reporting a match
    is how a differently worded or message-less refusal was previously read as
    the baseline.
    """
    expected = LOCAL_EXPECTATION["observedRefusal"]
    if not isinstance(refusal, dict):
        return [
            {"field": field, "observed": None, "expected": expected[field]}
            for field in BASELINE_COMPARISON_FIELDS
        ]
    mismatches = [
        {
            # An absent field is a mismatch, never a pass. The sentinel keeps a
            # recorded null distinguishable from a field that is not there.
            "field": field,
            "comparedBy": "value",
            "observed": refusal.get(field, "<absent>"),
            "expected": expected[field],
        }
        for field in BASELINE_COMPARISON_FIELDS
        if field != "message" and refusal.get(field, "<absent>") != expected[field]
    ]
    message = _message_comparison(refusal, expected["message"])
    if message is not None:
        mismatches.append(message)
    return mismatches


def shadow_cases(
    campaign_cases: list[dict[str, Any]], shadow: dict[str, Any]
) -> list[dict[str, Any]]:
    """Derive the published case table from the compiled cases and the verdict.

    Every field follows from an input that is itself bound: the case identity,
    request size and production expectation come from the compiled campaign, and
    the local column comes from the declared expectation and the classification.
    Nothing here is free text a person could edit without the evidence suite
    noticing.
    """
    return [
        {
            "id": case["id"],
            "family": "firestore",
            "requestBytes": case["requestBytes"],
            "productionExpectation": case["productionExpectation"],
            "localObserved": LOCAL_EXPECTATION["observedProbeOutcomes"][case["probe"]],
            "status": "refusal-shape-difference"
            if case["productionExpectation"] == "refused"
            and shadow["classification"] == "local-boundary-enforced-shape-differs"
            else "local-only",
            "basis": "Local typed state invariants and version-bound cleanup; no production comparison.",
        }
        for case in campaign_cases
    ]


def shadow_gates(
    result: dict[str, Any], shadow: dict[str, Any], *, source_bound: bool
) -> dict[str, bool]:
    """Decide the two gates the supervisor reads before calling a run complete.

    A recognised local outcome with full absence proofs and an unchanged source
    binding is a proof of the declared state invariants. A `shadow-failure` is
    not, and keeps the run incomplete rather than handing over a receipt that
    proved nothing.
    """
    absence = result.get("resourceAbsence") is True
    return {
        "recordingComplete": result.get("cleanupComplete") is True and absence,
        "stateValidation": (
            source_bound
            and absence
            and shadow.get("classification") != "shadow-failure"
        ),
    }


def _commit_request_caps(plan: dict[str, Any]) -> dict[str, int]:
    return {probe["label"]: probe["bodyBytes"] for probe in plan["probes"]}


def _executor(origin: str, plan: dict[str, Any]):
    from request_bytes_local_transport import RESPONSE_BYTES, request

    caps = _commit_request_caps(plan)

    def execute(operation: dict[str, Any]) -> dict[str, Any]:
        # Run under the policy the budget publishes: a small read or delete gets
        # the reserved small-request figure, so a local run demonstrates that
        # the reservation is generous rather than merely asserted. The local
        # transport caps everything at its own 12 seconds, which is well above
        # a loopback Commit.
        if operation.get("kind") == "conditional-create-commit":
            limit = caps[operation["probe"]]
            timeout = 12.0
        else:
            limit = 1
            timeout = SMALL_REQUEST_SECONDS
        return request(
            origin,
            operation,
            request_byte_limit=limit,
            response_byte_limit=RESPONSE_BYTES,
            timeout=timeout,
        )

    return execute


def _child(output: Path, nonce: str) -> None:
    from broad import local_origin
    from owned_runner import control_get, local_addresses

    before = source_inputs()
    firestore, control = local_addresses(
        os.environ["FIRESTORE_EMULATOR_HOST"], os.environ["FIREEMU_CONTROL_URL"]
    )
    token = os.environ["FIREEMU_CONTROL_TOKEN"]
    status, resources = control_get(control, "/v1/sessions/default/resources", token)
    wrong, _ = control_get(control, "/v1/sessions/default/resources", token + "-wrong")
    project = os.environ["GOOGLE_CLOUD_PROJECT"]
    if (
        project != PROJECT
        or status != 200
        or wrong != 403
        or resources.get("project") != project
    ):
        raise ValueError("owned artifact identity mismatch")
    local_origin(firestore)
    auth = local_origin("http://" + os.environ["FIREBASE_AUTH_EMULATOR_HOST"])
    # The supervisor reads argv, nonce and all three origins from this record to
    # stop the owned process and to verify its listeners closed. Dropping any of
    # them leaves the run incomplete even when the observation itself succeeded.
    save(
        output / "instance.json",
        {
            "parentPid": os.getppid(),
            "pid": os.getpid(),
            "argv": sys.argv,
            "nonce": nonce,
            "project": project,
            "authOrigin": auth,
            "firestoreOrigin": firestore,
            "controlOrigin": control,
            "wrongTokenStatus": wrong,
        },
    )

    plan = compile_request_bytes_plan(project, DATABASE, nonce)
    validate_request_bytes_plan(plan)
    campaign = compile_request_bytes_campaign(project, DATABASE, nonce)
    validate_request_bytes_campaign(campaign)

    result = collect_local(plan, _executor(firestore, plan), output / "collection")
    shadow = classify_local_result(result)
    after = source_inputs()
    bound = before == after
    if not bound:
        shadow = {**shadow, "classification": "shadow-failure", "sourceBinding": False}
    gates = shadow_gates(result, shadow, source_bound=bound)

    save(
        output / "result.json",
        {
            "kind": SHADOW_KIND,
            "campaignId": CAMPAIGN,
            "campaignDigest": campaign_digest(campaign),
            "planDigest": result["planDigest"],
            "target": "owned-local-artifact",
            "project": project,
            "database": DATABASE,
            "productionExecuted": False,
            "formalCompatibilityClaim": False,
            "rawHttpMetricStatus": "observation hypothesis",
            "collector": result,
            "shadow": shadow,
            "recordingComplete": gates["recordingComplete"],
            "stateValidation": gates["stateValidation"],
            "sourceInputs": before,
            "sourceInputsAfter": after,
            "sourceBinding": bound,
        },
    )
    recording_complete = gates["recordingComplete"]
    state_validation = gates["stateValidation"]
    save(
        output / "cases.json",
        {
            "schemaVersion": 1,
            "kind": SHADOW_KIND,
            "target": "owned-local-artifact",
            "project": project,
            "productionExecuted": False,
            "formalCompatibilityClaim": False,
            "recordingComplete": recording_complete,
            "stateValidation": state_validation,
            "cases": shadow_cases(campaign["cases"], shadow),
            "shadow": shadow,
        },
    )

    # The publishable record. `broad.run` copies the artifact next to the output
    # as `fireemu`, and the child observes the same bytes the supervisor did.
    artifact = output / "fireemu"
    if artifact.exists():
        cases = json.loads((output / "cases.json").read_bytes())["cases"]
        probes = probe_outcomes(output / "collection", plan)
        timings = slot_timings(output / "collection")
        # Validated here, before the record is written, for the same reason the
        # plan and the campaign are: a record that cannot be validated must not
        # reach the tree in the first place.
        validate_slot_timings(timings, result["requestCount"])
        document = build_shadow_document(
            before=observation_source_digest(),
            after=observation_source_digest(),
            runtime=runtime_binding(artifact),
            nonce=nonce,
            plan_digest=result["planDigest"],
            campaign_digest_value=campaign_digest(campaign),
            probes=probes,
            timings=timings,
            collector=result,
            shadow=shadow,
            gates=gates,
            cases=cases,
        )
        save(output / "local-shadow.json", document)


def run(output: Path) -> dict[str, Any]:
    import broad

    before = source_inputs()
    report = broad.run(
        output,
        child_script=Path(__file__).resolve(),
        project=PROJECT,
        configuration={"daemon": {"authProjectNumbers": {}}},
        execution_timeout=900,
        recovery_grace=1,
        retain_executed_artifact=True,
    )
    after = source_inputs()
    child_inputs = report.get("manifest", {}).get("sourceInputs")
    bound = before == after
    save(
        output / "shadow-binding.json",
        {
            "sourceInputsBefore": before,
            "sourceInputsAfter": after,
            "childSourceInputs": child_inputs,
            "bound": bound,
        },
    )
    if not bound:
        report = {**report, "status": "incomplete", "shadowBindingFailure": True}
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--output", type=Path)
    mode.add_argument("--child", type=Path)
    parser.add_argument("--nonce")
    args = parser.parse_args(argv)
    if args.child is not None:
        if not args.nonce:
            parser.error("--nonce is required with --child")
        _child(args.child.resolve(), args.nonce)
        return 0
    report = run(args.output.resolve())
    print(json.dumps({"status": report.get("status")}))
    return 0 if report.get("status") == "completed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
