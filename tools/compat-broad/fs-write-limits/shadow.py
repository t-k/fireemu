"""Bounded local artifact observation; never authorizes production access."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any
from urllib.parse import quote

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(ROOT / "tools/compat-inventory"))

from broad_contract import digest
from compiler import _CATALOG, compile_limits_plan

REHEARSAL = "stop-after-controls"


def rehearsal_fault(rehearsal: str | None) -> dict | None:
    if rehearsal is None:
        return None
    if rehearsal != REHEARSAL:
        raise ValueError("unsupported rehearsal")
    return {"name": REHEARSAL, "afterObservationIndex": 7, "triggered": False}


def should_interrupt(rehearsal: str | None, rows: list[dict], plan: dict) -> bool:
    return (
        rehearsal == REHEARSAL
        and len(rows) == 8
        and all(
            row.get("complete") is True
            and row.get("failure") is None
            and type(row.get("status")) is int
            for row in rows
        )
        and not evaluate_rows(rows, plan)
    )


def save(path: Path, value: Any) -> None:
    """Create an immutable receipt, refusing existing files and symlinks."""
    with path.open("x") as stream:
        json.dump(value, stream, indent=2, allow_nan=False)
        stream.write("\n")


def source_inputs() -> dict[str, str]:
    return {
        str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted([*HERE.glob("*.py"), _CATALOG])
    }


def typed_absence(status: Any, body: Any) -> bool:
    return (
        type(status) is int
        and status == 404
        and isinstance(body, dict)
        and isinstance(body.get("error"), dict)
        and body["error"].get("status") == "NOT_FOUND"
        and body["error"].get("code") == 404
    )


def evaluate_rows(rows: list[dict], plan: dict) -> list[dict]:
    """Evaluate a prefix against typed state invariants, including control versions."""
    problems = []
    versions = {}
    documents = {d["resource"]: d for d in plan["documents"].values()}
    operations = plan["localGatePlan"]["jobs"]["limits"]["observation"]
    for index, row in enumerate(rows):
        reason = None
        if (
            index >= len(operations)
            or row.get("index") != index
            or row.get("request") != operations[index]
        ):
            problems.append(
                {"index": index, "basis": "request identity/order mismatch"}
            )
            continue
        request = plan["requests"][index]
        status, body = row.get("status"), row.get("body")
        resource = request["path"].split("?", 1)[0].removeprefix("/v1/")
        kind = request["kind"]
        if (
            row.get("complete") is not True
            or row.get("failure") is not None
            or type(status) is not int
        ):
            continue  # Infrastructure failures are not API semantic mismatches.
        elif (
            kind == "preflight-typed-absence" or request["expect"].get("status") == 404
        ):
            if not typed_absence(status, body):
                reason = "typed resource absence not proven"
        elif kind == "create-only-patch" and request["expect"]["positive"] is False:
            if not (
                status == 400
                and isinstance(body, dict)
                and isinstance(body.get("error"), dict)
                and body["error"].get("status") == "INVALID_ARGUMENT"
                and body["error"].get("code") == 400
            ):
                reason = "negative boundary was not refused with INVALID_ARGUMENT"
        else:
            if (
                status != 200
                or not isinstance(body, dict)
                or body.get("name") != resource
                or body.get("fields") != documents[resource]["fields"]
                or not isinstance(body.get("updateTime"), str)
                or not body["updateTime"]
            ):
                reason = "exact typed document/version not returned"
            elif kind == "create-only-patch":
                versions[resource] = body["updateTime"]
            elif body["updateTime"] != versions.get(resource):
                reason = "readback changed the creation version"
        if reason:
            problems.append({"index": index, "basis": reason})
    return problems


def validate_local_receipt(receipt: dict, plan: dict) -> bool:
    if receipt.get("productionExecuted") is not False or any(
        receipt.get(key) is not True
        for key in (
            "recordingComplete",
            "stateValidation",
            "cleanupComplete",
            "completed",
        )
    ):
        return False
    rows = receipt.get("rows")
    return (
        isinstance(rows, list)
        and len(rows) == len(plan["localGatePlan"]["jobs"]["limits"]["observation"])
        and all(
            row.get("complete") is True
            and row.get("failure") is None
            and type(row.get("status")) is int
            for row in rows
        )
        and not evaluate_rows(rows, plan)
        and _validate_cleanup(receipt, plan)
        and receipt.get("resourceAbsence")
        == {d["resource"]: True for d in plan["documents"].values()}
    )


def _validate_cleanup(
    receipt: dict, plan: dict, *, observed_prefix: int | None = None
) -> bool:
    """Check ordered cleanup against creation receipts and the final Gate journal."""
    gate_plan = plan["localGatePlan"]
    declared_job = gate_plan["jobs"]["limits"]
    operations = declared_job["recovery"]
    expected_observations = len(declared_job["observation"])
    if observed_prefix is not None:
        if type(observed_prefix) is not int or observed_prefix != 8:
            return False
        expected_observations = observed_prefix
    cleanup = receipt.get("cleanup")
    gate = receipt.get("gate")
    if (
        not isinstance(cleanup, list)
        or len(cleanup) != len(operations)
        or not isinstance(gate, dict)
        or gate.get("plan") != gate_plan
        or gate.get("planDigest") != digest(gate_plan)
    ):
        return False
    jobs = gate.get("jobs")
    job = jobs.get("limits") if isinstance(jobs, dict) else None
    if (
        not isinstance(job, dict)
        or job.get("complete") is not True
        or job.get("inflight") is not False
        or job.get("observation") != expected_observations
        or job.get("recovery") != len(operations)
        or job.get("resources") != declared_job["resources"]
        or not isinstance(job.get("absent"), list)
        or sorted(job["absent"]) != sorted(declared_job["resources"])
    ):
        return False
    creations = {
        row["body"]["name"]: row
        for row in receipt["rows"]
        if row["request"]["method"] == "PATCH" and row["status"] == 200
    }
    proofs = {
        name: {
            "name": name,
            "updateTime": row["body"]["updateTime"],
            "fieldsDigest": digest(row["body"]["fields"]),
            "requestDigest": digest(row["request"]),
            "responseDigest": digest(row["body"]),
        }
        for name, row in creations.items()
    }
    if job.get("creationProofs") != proofs:
        return False
    for index, (row, declared) in enumerate(zip(cleanup, operations, strict=True)):
        if (
            not isinstance(row, dict)
            or row.get("index") != index
            or row.get("request") != resolve_recovery(declared, cleanup[:index])
            or row.get("complete") is not True
            or row.get("failure") is not None
            or row.get("dispatchFailure") is not None
        ):
            return False
        status, body = row.get("status"), row.get("body")
        resource = declared["path"].removeprefix("/v1/")
        source = declared.get("versionFrom")
        if source is not None:
            previous = cleanup[source]
            if typed_absence(previous.get("status"), previous.get("body")):
                if (
                    status is not None
                    or row.get("skipped") is not True
                    or body != {"skipped": "absent-or-unavailable-cleanup-read"}
                ):
                    return False
            elif (
                type(status) is not int
                or status != 200
                or row.get("skipped")
                or resource not in creations
                or previous["body"].get("updateTime") != proofs[resource]["updateTime"]
            ):
                return False
        elif index % 3 == 2 or resource not in creations:
            if not typed_absence(status, body) or row.get("skipped"):
                return False
        else:
            created = creations[resource]["body"]
            if (
                type(status) is not int
                or status != 200
                or row.get("skipped")
                or not isinstance(body, dict)
                or any(
                    body.get(key) != created.get(key)
                    for key in ("name", "fields", "updateTime")
                )
            ):
                return False
    return True


def resolve_recovery(declared: dict, cleanup: list[dict]) -> dict:
    operation = dict(declared)
    source = operation.pop("versionFrom", None)
    if source is not None and source < len(cleanup):
        prior = cleanup[source]
        body = prior.get("body")
        if prior.get("status") == 200 and isinstance(body, dict):
            version = body.get("updateTime")
            if isinstance(version, str) and version:
                operation["path"] += "?currentDocument.updateTime=" + quote(
                    version, safe=""
                )
    return operation


def _real_child(output: Path, nonce: str, *, rehearsal: str | None = None) -> None:
    injected_fault = rehearsal_fault(rehearsal)
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
    from collector import collect

    def wire(operation, _recovery, _index, request_index):
        return request(
            firestore,
            operation,
            request_byte_limit=max(
                1,
                len(json.dumps(operation["body"]).encode())
                if operation["body"] is not None
                else 0,
            ),
            response_byte_limit=plan["requests"][request_index]["responseByteLimit"],
            timeout=12,
        )

    collected = collect(gate, plan, output / "collection", wire, rehearsal=rehearsal)
    rows, cleanup = collected["rows"], collected["cleanup"]
    infrastructure = collected["infrastructureFailures"]
    after = source_inputs()
    if before != after:
        infrastructure.append(
            {"phase": "provenance", "failure": "source inputs changed"}
        )
    mismatches = collected["expectationMismatches"]
    recording = collected["recordingComplete"]
    cleanup_complete = collected["cleanupComplete"]
    state_valid = recording and not mismatches
    injected_fault = collected["injectedFault"]
    result = {
        "productionExecuted": False,
        "formalCompatibilityClaim": False,
        "injectedFault": injected_fault,
        "recordingComplete": recording,
        "stateValidation": state_valid,
        "cleanupComplete": cleanup_complete,
        "completed": state_valid and cleanup_complete and not infrastructure,
        "rows": rows,
        "cleanup": cleanup,
        "resourceAbsence": collected["resourceAbsence"],
        "semanticMismatches": mismatches,
        "infrastructureFailures": infrastructure,
        "gate": collected["gate"],
        "planDigest": digest(plan),
        "manifest": {
            "sourceInputs": before,
            "sourceInputsAfter": after,
            "nonce": nonce,
            "injectedFault": injected_fault,
        },
    }
    save(output / "result.json", result)
    save(
        output / "cases.json",
        {
            "schemaVersion": 1,
            "kind": "fs-write-limits-local-shadow-v1",
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
                    "id": plan["campaignId"],
                    "family": "firestore",
                    "status": "pass"
                    if result["completed"]
                    else "mismatch"
                    if mismatches
                    else "fail",
                    "basis": "Local typed state invariants and versioned cleanup; no production comparison.",
                }
            ],
        },
    )


def run(output: Path, *, rehearsal: str | None = None) -> dict:
    rehearsal_fault(rehearsal)
    import broad

    before = source_inputs()
    report = broad.run(
        output,
        child_script=HERE / "rehearsal.py"
        if rehearsal == REHEARSAL
        else Path(__file__).resolve(),
        project="demo-firestore-probe",
        configuration={"daemon": {"authProjectNumbers": {}}},
        execution_timeout=600,
        recovery_grace=1,
        retain_executed_artifact=True,
    )
    after = source_inputs()
    child_inputs = report.get("manifest", {}).get("sourceInputs")
    bound = before == after == child_inputs
    receipt = {
        "sourceInputsBefore": before,
        "sourceInputsAfter": after,
        "childSourceInputs": child_inputs,
        "bound": bound,
        "supervisorManifestSha256": hashlib.sha256(
            (output / "manifest.json").read_bytes()
        ).hexdigest(),
    }
    save(output / "shadow-binding.json", receipt)
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
