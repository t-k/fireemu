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
    compile_request_bytes_plan,
    validate_request_bytes_plan,
)

PROJECT = "demo-firestore-probe"
DATABASE = "(default)"
SHADOW_KIND = "fs-request-bytes-local-shadow-v1"


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
        "productionRefusalExpectation": "400 INVALID_ARGUMENT",
        "differenceMasked": False,
        "productionExecuted": False,
        "formalCompatibilityClaim": False,
    }


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
    save(
        output / "instance.json",
        {
            "parentPid": os.getppid(),
            "pid": os.getpid(),
            "project": project,
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
