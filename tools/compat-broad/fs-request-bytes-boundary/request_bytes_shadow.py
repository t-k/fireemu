"""Bounded local artifact shadow for the 11 MiB strict REST Commit boundary.

The shadow runs the reviewed compiler plan and collector against an owned local
fireemu artifact built from this checkout. The observed local behaviour is that
the strict REST Commit boundary is enforced at exactly 11 MiB, and that the
strict profile's refusal carries the same status, code and message recorded in
saved production evidence. The evidence remains scoped to its concrete REST
recipes and does not establish behavior for other transports.

No production request, credential or reservation is involved.
"""

from __future__ import annotations

import argparse
import contextlib
import copy
import fcntl
import hashlib
import json
import math
import os
import stat
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
    compile_request_bytes_sentinel_plan,
    validate_request_bytes_plan,
    validate_request_bytes_sentinel_plan,
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
SENTINEL_SELECTOR_CONTENT = b"fs-request-bytes-sentinel-local-shadow-v1\n"

#: Why the published timings are a floor and not an estimate. This travels with
#: the numbers so a reader cannot pick them up without it.
LOOPBACK_TIMING_DISCLAIMER = (
    "Loopback service time against an owned local emulator on the same machine. "
    "It excludes the network round trip, TLS and production server time, so it "
    "is a floor for a production per-slot figure and never an estimate of one. "
    "A production reservation needs a production measurement; the production "
    "transport now records elapsed time per request so one can be taken."
)

#: Slot classes. The boundary Commits carry an 11 MiB body; everything else is a
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


def _sentinel_selector_path(output: Path) -> Path:
    return output.parent / f".{output.name}.request-bytes-sentinel"


def write_sentinel_selector(output: Path) -> Path:
    """Create an exclusive private marker that survives child env sanitizing."""
    marker = _sentinel_selector_path(output)
    descriptor = os.open(marker, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(SENTINEL_SELECTOR_CONTENT)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        marker.unlink(missing_ok=True)
        raise
    return marker


def sentinel_selector_enabled(output: Path) -> bool:
    """Recognize only the private regular marker for this exact output path."""
    marker = _sentinel_selector_path(output)
    try:
        descriptor = os.open(marker, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError:
        return False
    with os.fdopen(descriptor, "rb") as stream:
        metadata = os.fstat(stream.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o077:
            return False
        return (
            stream.read(len(SENTINEL_SELECTOR_CONTENT) + 1) == SENTINEL_SELECTOR_CONTENT
        )


def remove_sentinel_selector(output: Path, marker: Path) -> None:
    """Remove only the marker created for this output, if it remains unchanged."""
    if marker != _sentinel_selector_path(output):
        raise ValueError("sentinel selector path mismatch")
    if sentinel_selector_enabled(output):
        marker.unlink()


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


#: The preparation document's evidence citation is generated from the published
#: record between these markers. Everything outside them is hand-written.
CITATION_BEGIN = "<!-- BEGIN generated evidence citation -->"
CITATION_END = "<!-- END generated evidence citation -->"

#: Named in the pairing test's failure message and in the lane README.
REBIND_COMMAND = (
    "uv run --offline --project tools/compat-inventory --locked python "
    "tools/compat-broad/fs-request-bytes-boundary/request_bytes_shadow.py "
    "--output <fresh-directory> --publish"
)

PREPARATION_DOC = "docs/compatibility/fs-request-bytes-campaign-preparation.md"
PUBLISHED_RECORD = "spec/compatibility/broad-runs/fs-request-bytes-local-shadow-11mib.json"


def citation_block(record: dict[str, Any]) -> str:
    """Render the document's evidence citation from the published record.

    The document and the record drifted once, because a rebind updated the
    record and left the prose describing a run that was no longer published.
    Generating this block from the record makes that impossible rather than
    merely detectable.
    """
    observation = record["observation"]
    timings = record["slotTimings"]["classes"]
    small, commit = timings["smallRequest"], timings["boundaryCommit"]
    bound = record["cases"] and observation["requestCount"]
    return "\n".join(
        [
            CITATION_BEGIN,
            "",
            "The recorded run is published as",
            f"`{PUBLISHED_RECORD}`, at source",
            f"`{record['runtime']['sourceCommit']}`, artifact SHA-256",
            f"`{record['artifactSha256']}`, nonce `{record['nonce']}`.",
            "",
            "| Property | Value |",
            "| --- | --- |",
            f"| Supervisor status | `{'completed' if record['complete'] else 'incomplete'}` |",
            f"| Classification | `{record['shadow']['classification']}` |",
            f"| Recording complete | {str(record['recordingComplete']).lower()} |",
            f"| State validation | {str(record['stateValidation']).lower()} |",
            f"| Observation rows | {observation['rowCount']} |",
            f"| Recovery rows | {observation['recoveryRowCount']} |",
            f"| Requests sent | {bound} |",
            f"| Every owned resource absent | {str(observation['resourceAbsence']).lower()} |",
            f"| Small-request median, p99 | {small['medianSeconds']:.4f} s, {small['p99Seconds']:.4f} s |",
            f"| Boundary Commit median | {commit['medianSeconds']:.4f} s |",
            "",
            "The timings are a loopback floor, not a production estimate; see the",
            "section above. This block is generated from the record, so it cannot",
            "describe a run that is not the published one. Regenerate it with the",
            "command in the lane README.",
            "",
            CITATION_END,
        ]
    )


def rewrite_citation(doc: str, record: dict[str, Any]) -> str:
    """Replace the generated block, leaving the hand-written document alone."""
    if CITATION_BEGIN not in doc or CITATION_END not in doc:
        raise ValueError(
            f"the preparation document has no citation markers; expected "
            f"{CITATION_BEGIN} and {CITATION_END}"
        )
    head, rest = doc.split(CITATION_BEGIN, 1)
    _generated, tail = rest.split(CITATION_END, 1)
    return head + citation_block(record) + tail


#: Serializes publishers of the same target. Gitignored, following the
#: convention already used by `verification/quint`: a lock file that appeared in
#: `git status` would make the next `broad.run` refuse the checkout as dirty.
PUBLICATION_LOCK = (
    "spec/compatibility/broad-runs/.fireemu-request-bytes-publication.lock"
)


@contextlib.contextmanager
def _publication_lock(root: Path):
    """Hold an exclusive lock for the whole read-generate-commit sequence.

    Two publishers racing used to leave one run's record beside the other run's
    citation, each having succeeded. The lock covers the reads as well as the
    writes, so the pair a publisher commits is the pair it built.
    """
    path = root / PUBLICATION_LOCK
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(handle, fcntl.LOCK_EX)
        _sweep_stale_temporaries(root)
        yield
    finally:
        try:
            fcntl.flock(handle, fcntl.LOCK_UN)
        finally:
            os.close(handle)


#: Suffix of the side file a publication writes before replacing its target.
#: Gitignored: a survivor of a killed publisher would otherwise make the next
#: `broad.run` refuse the checkout as dirty.
TEMPORARY_SUFFIX = ".publish-tmp"

#: Everything a publication replaces, and therefore everything it may leave a
#: temporary beside.
PUBLISHED_PATHS = (PUBLISHED_RECORD, PREPARATION_DOC)


def _temporary_for(target: Path) -> Path:
    return target.with_name(target.name + TEMPORARY_SUFFIX)


def _write_temporary(target: Path, data: bytes) -> Path:
    """Write the side file in binary.

    Bytes rather than text throughout, because the restore path carries a
    pre-image read from disk: decoding it to write it back could raise
    `UnicodeDecodeError`, which is a `ValueError` and would escape the handler
    doing the restoring, skipping the remaining restores and the cleanup.
    """
    temporary = _temporary_for(target)
    with open(temporary, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    return temporary


def _sweep_stale_temporaries(root: Path) -> list[str]:
    """Remove side files a killed publisher left behind.

    Called while holding the lock, so nothing being swept can belong to a
    publication still in progress. Without this a publisher killed between
    writing a temporary and replacing its target leaves an untracked file that
    makes the next artifact run refuse the checkout.
    """
    swept = []
    for relative in PUBLISHED_PATHS:
        temporary = _temporary_for(root / relative)
        if temporary.exists():
            temporary.unlink()
            swept.append(str(temporary.relative_to(root)))
    return swept


def _commit_generation(writes: list[tuple[Path, bytes]]) -> None:
    """Replace every file, or none of them.

    Both outputs are already built, so nothing here can fail for a reason the
    caller could have detected earlier. What remains is the filesystem, and a
    failure part way through must not leave one run's record beside another
    run's document: the replaced files are restored from their pre-images.
    """
    pre_images = {
        path: (path.read_bytes() if path.exists() else None) for path, _ in writes
    }
    temporaries: list[tuple[Path, Path]] = []
    try:
        for path, data in writes:
            temporaries.append((path, _write_temporary(path, data)))
    except BaseException:
        for _, temporary in temporaries:
            temporary.unlink(missing_ok=True)
        raise

    replaced: list[Path] = []
    try:
        for path, temporary in temporaries:
            os.replace(temporary, path)
            replaced.append(path)
    except BaseException:
        unrestored = []
        for path in replaced:
            original = pre_images[path]
            try:
                if original is None:
                    path.unlink(missing_ok=True)
                else:
                    # The pre-image is replaced as the bytes it was read as;
                    # decoding it here could raise out of this handler.
                    os.replace(_write_temporary(path, original), path)
            except OSError:
                unrestored.append(str(path))
        for _, temporary in temporaries:
            temporary.unlink(missing_ok=True)
        if unrestored:
            # Nothing else can be done here, so say exactly which files are in
            # doubt rather than leaving a silent half-generation.
            raise RuntimeError(
                "publication left an incomplete generation; these files could "
                f"not be restored and must be checked out again: {unrestored}"
            )
        raise


def publish_run(output: Path, root: Path | None = None) -> dict[str, Any]:
    """Publish a completed run: the record, and the document's citation.

    One command, because the two drifted apart when they were two. One
    generation, because publishing them in sequence left the record replaced
    and the document untouched whenever the second step could not proceed.
    """
    root = Path(root) if root is not None else ROOT
    record_path = root / PUBLISHED_RECORD
    document_path = root / PREPARATION_DOC
    with _publication_lock(root):
        # Every input read and validated, and both outputs built, before any
        # existing file is touched. `rewrite_citation` refuses a document
        # without markers, and it refuses it while the tree is still intact.
        record = json.loads((Path(output) / "local-shadow.json").read_bytes())
        record_text = json.dumps(record, indent=2, sort_keys=True) + "\n"
        document_text = rewrite_citation(document_path.read_text(), record)
        _commit_generation(
            [
                (record_path, record_text.encode("utf-8")),
                (document_path, document_text.encode("utf-8")),
            ]
        )
    return record


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
    published_collector = copy.deepcopy(collector)
    journal = published_collector.get("localJournal")
    if isinstance(journal, dict):
        # Keep the complete private journal under the run directory; the checked
        # in receipt binds it by digest and counts without duplicating hundreds
        # of verbose operation records into public evidence.
        journal.pop("rowEntries", None)
        journal.pop("sidecarEntries", None)
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
        "observation": published_collector,
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
      strict REST Commit path refuses the over-boundary body at 11 MiB, and
      every field in `BASELINE_COMPARISON_FIELDS` matches the saved production
      comparison's typed refusal shape.
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
            "The strict REST Commit path refused the over-boundary body at the "
            "11 MiB boundary with the status, code and message recorded in the "
            "saved production comparison. The evidence remains limited to its "
            "concrete REST recipes."
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
    journal = result.get("localJournal")
    journal_complete = (
        isinstance(journal, dict) and journal.get("captureComplete") is True
    )
    return {
        "recordingComplete": (
            journal_complete
            and result.get("cleanupComplete") is True
            and absence
        ),
        "stateValidation": (
            source_bound
            and journal_complete
            and absence
            and shadow.get("classification") != "shadow-failure"
        ),
    }


def sentinel_parent_handoff(
    result: dict[str, Any], plan: dict[str, Any], *, source_bound: bool
) -> dict[str, Any]:
    """Build the supervisor's one-case handoff without making a parity claim."""
    journal = result.get("localJournal")
    journal_complete = (
        isinstance(journal, dict) and journal.get("captureComplete") is True
    )
    no_production_claim = (
        result.get("productionExecuted") is False
        and result.get("localOnly") is True
        and result.get("formalCompatibilityClaim") is False
    )
    recording_complete = (
        journal_complete
        and source_bound
        and no_production_claim
        and result.get("cleanupComplete") is True
        and result.get("resourceAbsence") is True
    )
    recognized_outcome = result.get("semanticOutcome") in {
        "sentinel-accepted",
        "sentinel-typed-refusal",
    }
    state_validation = (
        recording_complete
        and source_bound
        and result.get("completed") is True
        and recognized_outcome
    )
    status = "local-only" if state_validation else "indeterminate"
    return {
        "schemaVersion": 1,
        "kind": f"{SHADOW_KIND}-sentinel-handoff-v1",
        "target": "owned-local-artifact",
        "project": plan.get("project"),
        "productionExecuted": False,
        "formalCompatibilityClaim": False,
        "recordingComplete": recording_complete,
        "stateValidation": state_validation,
        "cases": [
            {
                "id": plan.get("caseId", "request-bytes-raw-16mib-over"),
                "family": "firestore",
                "status": status,
                "basis": "Sentinel outcome recorded locally; production behavior remains unobserved.",
            }
        ],
    }


def write_sentinel_parent_handoff(
    output: Path, result: dict[str, Any], plan: dict[str, Any], *, source_bound: bool
) -> dict[str, Any]:
    handoff = sentinel_parent_handoff(result, plan, source_bound=source_bound)
    save(output / "cases.json", handoff)
    return handoff


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

    if sentinel_selector_enabled(output):
        plan = compile_request_bytes_sentinel_plan(project, DATABASE, nonce)
        validate_request_bytes_sentinel_plan(plan)
        result = collect_local(plan, _executor(firestore, plan), output / "collection")
        after = source_inputs()
        bound = before == after
        handoff = write_sentinel_parent_handoff(
            output, result, plan, source_bound=bound
        )
        artifact = output / "fireemu"
        save(
            output / "sentinel-shadow.json",
            {
                "kind": "fs-request-bytes-sentinel-local-shadow-v1",
                "caseId": plan["caseId"],
                "caseMode": plan["caseMode"],
                "target": "owned-local-artifact",
                "project": project,
                "database": DATABASE,
                "productionExecuted": False,
                "formalCompatibilityClaim": False,
                "semanticOutcome": result.get(
                    "semanticOutcome", "sentinel-inconclusive"
                ),
                "outcomeIsPrediction": False,
                "metricStatus": plan["metricStatus"],
                "requestBytes": plan["bounds"]["requestBytes"],
                "distinctDocumentCount": plan["bounds"]["distinctDocumentCount"],
                "observationRequestBound": plan["bounds"]["observationRequests"],
                "recoveryRequestBound": plan["bounds"]["recoveryRequests"],
                "collector": result,
                "planSha256": hashlib.sha256(
                    json.dumps(plan, sort_keys=True, separators=(",", ":")).encode()
                ).hexdigest(),
                "sourceInputs": before,
                "sourceInputsAfter": after,
                "sourceBinding": bound,
                "artifact": runtime_binding(artifact),
                "cleanupComplete": result.get("cleanupComplete") is True,
                "resourceAbsence": result.get("resourceAbsence") is True,
                "recordingComplete": handoff["recordingComplete"],
                "stateValidation": handoff["stateValidation"],
            },
        )
        return

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


def run(output: Path, *, sentinel: bool = False) -> dict[str, Any]:
    import broad

    before = source_inputs()
    selector = write_sentinel_selector(output) if sentinel else None
    try:
        report = broad.run(
            output,
            child_script=Path(__file__).resolve(),
            project=PROJECT,
            configuration={"daemon": {"authProjectNumbers": {}}},
            execution_timeout=900,
            recovery_grace=1,
            retain_executed_artifact=True,
        )
    finally:
        if selector is not None:
            remove_sentinel_selector(output, selector)
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
    mode.add_argument(
        "--sentinel-raw-16mib-over",
        dest="sentinel_output",
        type=Path,
        help="run only the finite 16,777,217-byte local sentinel case",
    )
    parser.add_argument("--nonce")
    parser.add_argument(
        "--publish",
        action="store_true",
        help="after a completed run, publish the record and regenerate the "
        "preparation document's evidence citation from it",
    )
    args = parser.parse_args(argv)
    if args.child is not None:
        if not args.nonce:
            parser.error("--nonce is required with --child")
        _child(args.child.resolve(), args.nonce)
        return 0
    sentinel = args.sentinel_output is not None
    if sentinel and args.publish:
        parser.error("--publish is not available for the outcome-neutral sentinel")
    output = args.sentinel_output if sentinel else args.output
    report = run(output.resolve(), sentinel=sentinel)
    status = report.get("status")
    published = False
    if args.publish and status == "completed":
        publish_run(args.output.resolve())
        published = True
    print(json.dumps({"status": status, "published": published}))
    return 0 if status == "completed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
