"""Bounded local artifact shadow for the 10 MiB request-byte boundary.

The shadow runs the reviewed compiler plan and collector against an owned local
fireemu artifact built from this checkout. The observed local behaviour is that
the boundary is enforced at exactly 10 MiB by the REST transport body cap, not
by the limits layer, and that the refusal is a typed 413 where production is
expected to answer 400. The shadow records that difference explicitly instead of
relaxing the expectation to make the run look clean.

No production request, credential or reservation is involved.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
for entry in (str(HERE), str(HERE.parent), str(ROOT / "tools/compat-inventory")):
    if entry not in sys.path:
        sys.path.insert(0, entry)

from request_bytes_campaign import (
    LOCAL_EXPECTATION,
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
        body = receipt.get("body")
        error = body.get("error") if isinstance(body, dict) else None
        by_probe[row["probe"]] = {
            "probe": row["probe"],
            "requestBytes": row.get("requestBytes"),
            "httpStatus": receipt.get("status"),
            "complete": receipt.get("complete"),
            "responseBytes": row.get("responseBytes"),
            "errorCode": error.get("code") if isinstance(error, dict) else None,
            "errorStatus": error.get("status") if isinstance(error, dict) else None,
            "errorMessage": error.get("message") if isinstance(error, dict) else None,
        }
    return [
        by_probe[probe["label"]]
        for probe in plan["probes"]
        if probe["label"] in by_probe
    ]


def build_shadow_document(
    *,
    before: str,
    after: str,
    runtime: dict[str, Any],
    plan_digest: str,
    campaign_digest_value: str,
    probes: list[dict[str, Any]],
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
        "planDigest": plan_digest,
        "campaignDigest": campaign_digest_value,
        "probeOutcomes": probes,
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

    Three outcomes are recognised, and none of them relaxes the production
    expectation:

    - `local-boundary-enforced-shape-differs` is the observed baseline. The
      local transport refuses the over-boundary Commit at exactly 10 MiB with a
      typed 413, where production is expected to answer 400. The boundary
      agrees; the refusal shape does not.
    - `local-shape-matches-production-expectation` means a typed 400 was
      returned, so the limits-layer implementation has landed ahead of the
      transport cap and this baseline is stale.
    - `local-boundary-not-enforced` means the over-boundary Commit was accepted,
      so the transport cap was removed or raised.
    - `local-untyped-transport-refusal` means something refused the Commit
      without Firestore's typed envelope. The boundary question stays
      unanswered and recovery stays read-only.

    Anything else is a shadow failure and is reported as such.
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
    clean_refusal = not failures and completed and absence and isinstance(refusal, dict)
    if clean_refusal and refusal.get("httpStatus") == observed["httpStatus"]:
        classification = "local-boundary-enforced-shape-differs"
        summary = (
            "The local transport refused the over-boundary Commit at exactly the "
            "10 MiB boundary with a typed 413. Production is expected to answer "
            "400, so the boundary agrees and the refusal shape does not."
        )
    elif clean_refusal and refusal.get("httpStatus") == 400:
        classification = "local-shape-matches-production-expectation"
        summary = (
            "The local runtime refused the over-boundary Commit with a typed 400. "
            "The limits-layer implementation has landed and this baseline is stale."
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
            "The local runtime accepted the over-boundary Commit. The transport "
            "body cap was removed or raised."
        )
    else:
        classification = "shadow-failure"
        summary = "The local run matched none of the three recognised local outcomes."
    return {
        "classification": classification,
        "summary": summary,
        "expectedClassification": LOCAL_EXPECTATION["classification"],
        "matchesBaseline": classification == LOCAL_EXPECTATION["classification"],
        "localEnforcement": LOCAL_EXPECTATION["localEnforcement"],
        "enforcementSource": LOCAL_EXPECTATION["enforcementSource"],
        "expectedRefusal": observed,
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
        if operation.get("kind") == "conditional-create-commit":
            limit = caps[operation["probe"]]
        else:
            limit = 1
        return request(
            origin,
            operation,
            request_byte_limit=limit,
            response_byte_limit=RESPONSE_BYTES,
            timeout=12.0,
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
            "cases": [
                {
                    "id": case["id"],
                    "family": "firestore",
                    "requestBytes": case["requestBytes"],
                    "productionExpectation": case["productionExpectation"],
                    "localObserved": LOCAL_EXPECTATION["observedProbeOutcomes"][
                        case["probe"]
                    ],
                    "status": "refusal-shape-difference"
                    if case["productionExpectation"] == "refused"
                    and shadow["classification"]
                    == "local-boundary-enforced-shape-differs"
                    else "local-only",
                    "basis": "Local typed state invariants and version-bound cleanup; no production comparison.",
                }
                for case in campaign["cases"]
            ],
            "shadow": shadow,
        },
    )

    # The publishable record. `broad.run` copies the artifact next to the output
    # as `fireemu`, and the child observes the same bytes the supervisor did.
    artifact = output / "fireemu"
    if artifact.exists():
        cases = json.loads((output / "cases.json").read_bytes())["cases"]
        document = build_shadow_document(
            before=observation_source_digest(),
            after=observation_source_digest(),
            runtime=runtime_binding(artifact),
            plan_digest=result["planDigest"],
            campaign_digest_value=campaign_digest(campaign),
            probes=probe_outcomes(output / "collection", plan),
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
