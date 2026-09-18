"""Bounded local artifact observation for FS-WRITE-LIMITS-03.

This runs the compiled campaign against a freshly built owned fireemu artifact
on loopback. It sends no production request, holds no credential, and its
success is local evidence only: it establishes what the current artifact does,
which is the other half of the comparison a later production observation would
complete.
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
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(ROOT / "tools/compat-inventory"))

from broad_contract import digest
from compiler_03 import _CATALOG, CAMPAIGN, compile_limits_plan
from expectations_03 import (
    evaluate_rows,
    pending_rows,
    validate_cleanup,
    validate_local_receipt,
)
from shadow import save


def source_inputs() -> dict[str, str]:
    return {
        str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted([*HERE.glob("*.py"), _CATALOG])
    }


def _real_child(output: Path, nonce: str) -> None:
    from broad import local_origin
    from owned_runner import control_get, local_addresses
    from shared_gate import Gate, create
    from transport import request

    before = source_inputs()
    firestore, control = local_addresses(
        os.environ["FIRESTORE_EMULATOR_HOST"], os.environ["FIREEMU_CONTROL_URL"]
    )
    auth = local_origin("http://" + os.environ["FIREBASE_AUTH_EMULATOR_HOST"])
    token = os.environ["FIREEMU_CONTROL_TOKEN"]
    status, resources = control_get(control, "/v1/sessions/default/resources", token)
    wrong, _ = control_get(control, "/v1/sessions/default/resources", token + "-wrong")
    project = os.environ["GOOGLE_CLOUD_PROJECT"]
    if (
        project != "demo-firestore-probe"
        or status != 200
        or wrong != 403
        or resources.get("project") != project
    ):
        raise ValueError("owned artifact identity mismatch")
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
    plan = compile_limits_plan(project, "(default)", nonce)
    gate_plan = plan["localGatePlan"]
    create(output / "gate", gate_plan)
    gate = Gate(output / "gate", "limits")
    gate.claim()
    from collector_03 import collect

    def wire(operation, _recovery, _index, request_index):
        body = operation["body"]
        return request(
            firestore,
            operation,
            request_byte_limit=max(
                1, len(json.dumps(body).encode()) if body is not None else 0
            ),
            response_byte_limit=plan["requests"][request_index]["responseByteLimit"],
            timeout=12,
        )

    collected = collect(gate, plan, output / "collection", wire)
    rows, cleanup = collected["rows"], collected["cleanup"]
    infrastructure = collected["infrastructureFailures"]
    after = source_inputs()
    if before != after:
        infrastructure.append(
            {"phase": "provenance", "failure": "source inputs changed"}
        )
    mismatches = collected["expectationMismatches"]
    # Limits the catalog still declares unsupported carry the documented
    # production expectation. A difference there is recorded, never discarded,
    # but it does not fail the local campaign.
    pending = evaluate_rows(rows, plan, pending=True)
    recording = collected["recordingComplete"]
    cleanup_complete = collected["cleanupComplete"]
    state_valid = recording and not mismatches
    result: dict[str, Any] = {
        "campaignId": CAMPAIGN,
        "productionExecuted": False,
        "formalCompatibilityClaim": False,
        "recordingComplete": recording,
        "stateValidation": state_valid,
        "cleanupComplete": cleanup_complete,
        "completed": state_valid and cleanup_complete and not infrastructure,
        "rows": rows,
        "cleanup": cleanup,
        "resourceAbsence": collected["resourceAbsence"],
        "semanticMismatches": mismatches,
        "pendingDifferences": pending,
        "pendingRows": pending_rows(plan),
        "infrastructureFailures": infrastructure,
        "gate": collected["gate"],
        "planDigest": digest(plan),
        "manifest": {
            "sourceInputs": before,
            "sourceInputsAfter": after,
            "nonce": nonce,
        },
    }
    result["cleanupValidated"] = validate_cleanup(result, plan)
    result["receiptValidated"] = validate_local_receipt(result, plan)
    save(output / "result.json", result)
    save(
        output / "cases.json",
        {
            "schemaVersion": 1,
            "kind": "fs-write-limits-03-local-shadow-v1",
            "target": "owned-local-artifact",
            "project": project,
            "productionExecuted": False,
            "formalCompatibilityClaim": False,
            "recordingComplete": recording and cleanup_complete and not infrastructure,
            "stateValidation": state_valid,
            "manifest": result["manifest"],
            "manifestDigest": digest(result["manifest"]),
            "localObservations": rows,
            "cases": [
                {
                    "id": case["id"],
                    "family": "firestore",
                    "residue": case["residue"],
                    "status": "pass"
                    if result["completed"]
                    else "mismatch"
                    if mismatches
                    else "fail",
                    "basis": "Local typed state invariants and versioned cleanup; no production comparison.",
                }
                for case in plan["cases"]
            ],
        },
    )


def run(output: Path) -> dict:
    import broad

    before = source_inputs()
    report = broad.run(
        output,
        child_script=Path(__file__).resolve(),
        project="demo-firestore-probe",
        configuration={"daemon": {"authProjectNumbers": {}}},
        execution_timeout=900,
        recovery_grace=1,
        retain_executed_artifact=True,
    )
    after = source_inputs()
    child_inputs = report.get("manifest", {}).get("sourceInputs")
    bound = before == after == child_inputs
    save(
        output / "shadow-binding.json",
        {
            "campaignId": CAMPAIGN,
            "sourceInputsBefore": before,
            "sourceInputsAfter": after,
            "childSourceInputs": child_inputs,
            "bound": bound,
            "supervisorManifestSha256": hashlib.sha256(
                (output / "manifest.json").read_bytes()
            ).hexdigest(),
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
        _real_child(args.child.resolve(), args.nonce)
        return 0
    result = run(args.output.resolve())
    print(json.dumps({"status": result.get("status")}))
    return 0 if result.get("status") == "completed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
