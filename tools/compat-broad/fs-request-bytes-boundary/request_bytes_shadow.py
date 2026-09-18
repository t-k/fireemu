"""Bounded local artifact shadow for the 10 MiB request-byte boundary.

The shadow runs the reviewed compiler plan and collector against an owned local
fireemu artifact built from this checkout. The local runtime does not implement
FS-LIMIT-API-REQUEST-BYTES yet, so the over-boundary probe is expected to be
accepted locally. The shadow records that difference explicitly instead of
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
    """Compare a collector result against the declared pending-implementation expectation.

    An `expected-local-difference` means the local runtime accepted the
    over-boundary Commit, which is exactly what an unimplemented limit looks
    like. `local-enforcement-observed` means the local runtime refused it, which
    would mean the pending implementation landed and this expectation is stale.
    Everything else is a shadow failure and is reported as such.
    """
    if not isinstance(result, dict):
        raise TypeError("result must be an object")
    failures = result.get("failures")
    if not isinstance(failures, list):
        raise TypeError("result failures malformed")
    absence = result.get("resourceAbsence") is True
    refusal = result.get("overRefusal")
    expected_failures = list(LOCAL_EXPECTATION["expectedCollectorFailures"])
    if failures == expected_failures and refusal is None and absence:
        classification = "expected-local-difference"
        summary = (
            "The local runtime accepted the over-boundary Commit. "
            "FS-LIMIT-API-REQUEST-BYTES is not implemented locally yet."
        )
    elif not failures and refusal is not None and result.get("completed") is True:
        classification = "local-enforcement-observed"
        summary = (
            "The local runtime refused the over-boundary Commit with a typed error. "
            "The pending-implementation expectation in this lane is now stale."
        )
    else:
        classification = "shadow-failure"
        summary = "The local run matched neither the pending-implementation expectation nor a clean local refusal."
    return {
        "classification": classification,
        "summary": summary,
        "localEnforcement": LOCAL_EXPECTATION["localEnforcement"],
        "expectedCollectorFailures": expected_failures,
        "observedFailures": failures,
        "resourceAbsence": absence,
        "overRefusal": refusal,
        "differenceMasked": False,
        "productionExecuted": False,
        "formalCompatibilityClaim": False,
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
            "sourceInputs": before,
            "sourceInputsAfter": after,
            "sourceBinding": bound,
        },
    )
    save(
        output / "cases.json",
        {
            "schemaVersion": 1,
            "kind": SHADOW_KIND,
            "target": "owned-local-artifact",
            "project": project,
            "productionExecuted": False,
            "formalCompatibilityClaim": False,
            "cases": [
                {
                    "id": case["id"],
                    "family": "firestore",
                    "requestBytes": case["requestBytes"],
                    "productionExpectation": case["productionExpectation"],
                    "localExpectation": LOCAL_EXPECTATION["expectedProbeOutcomes"][
                        case["probe"]
                    ],
                    "status": "difference"
                    if case["productionExpectation"] == "refused"
                    and shadow["classification"] == "expected-local-difference"
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
