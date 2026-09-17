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
from compiler import compile_limits_plan


def save(path: Path, value: Any) -> None:
    """Create an immutable receipt, refusing existing files and symlinks."""
    with path.open("x") as stream:
        json.dump(value, stream, indent=2, allow_nan=False)
        stream.write("\n")


def source_inputs() -> dict[str, str]:
    return {
        str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(HERE.glob("*.py"))
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
        and receipt.get("resourceAbsence")
        == {d["resource"]: True for d in plan["documents"].values()}
    )


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
    observation = gate_plan["jobs"]["limits"]["observation"]
    rows, cleanup, infrastructure = [], [], []

    def dispatch(operation, recovery, index, request_index):
        entry = {"index": index, "request": operation}
        phase = "cleanup" if recovery else "observation"

        def send():
            result = request(
                firestore,
                operation,
                request_byte_limit=max(
                    1,
                    len(json.dumps(operation["body"]).encode())
                    if operation["body"] is not None
                    else 0,
                ),
                response_byte_limit=plan["requests"][request_index][
                    "responseByteLimit"
                ],
                timeout=12,
            )
            entry.update(result)
            # Preserve complete unexpected responses even if Gate rejects their identity.
            save(output / f"{phase}-{index:02d}-wire.json", entry)
            if result["complete"] is not True:
                raise ValueError(
                    "incomplete bounded transport:"
                    + str(result.get("failure", result.get("kind")))
                )
            return result["status"], result["body"]

        try:
            status, body = gate.dispatch(operation, recovery, send)
            if "complete" not in entry:
                entry.update(
                    status=status, body=body, complete=True, failure=None, skipped=True
                )
        except Exception as error:  # noqa: BLE001 -- Persist failures and retain cleanup ownership.
            entry["dispatchFailure"] = type(error).__name__ + ":" + str(error)
            infrastructure.append(
                {"phase": phase, "index": index, "failure": entry["dispatchFailure"]}
            )
        save(output / f"{phase}-{index:02d}.json", entry)
        return entry

    try:
        for index, operation in enumerate(observation):
            # Finish current readback group, but never write after an unproven invariant.
            if operation["method"] == "PATCH" and evaluate_rows(rows, plan):
                break
            entry = dispatch(operation, False, index, index)
            rows.append(entry)
            if entry.get("dispatchFailure"):
                break
            if index < 4 and evaluate_rows(rows, plan):
                break
    except Exception as error:  # noqa: BLE001 -- Persist failures and retain cleanup ownership.
        infrastructure.append(
            {"phase": "observation", "failure": type(error).__name__ + ":" + str(error)}
        )
    finally:
        gate.stop()
        for index, declared in enumerate(gate_plan["jobs"]["limits"]["recovery"]):
            operation = resolve_recovery(declared, cleanup)
            cleanup.append(dispatch(operation, True, index, len(observation) + index))
        absence = {}
        for index, declared in enumerate(gate_plan["jobs"]["limits"]["recovery"]):
            if (
                plan["requests"][len(observation) + index]["kind"]
                == "cleanup-verify-absence"
            ):
                row = cleanup[index]
                resource = declared["path"].removeprefix("/v1/")
                absence[resource] = row.get("complete") is True and typed_absence(
                    row.get("status"), row.get("body")
                )
        cleanup_complete = False
        try:
            gate.finish()
            cleanup_complete = all(absence.values()) and not any(
                row.get("dispatchFailure") for row in cleanup
            )
        except Exception as error:  # noqa: BLE001 -- Persist failures and retain cleanup ownership.
            infrastructure.append(
                {"phase": "finish", "failure": type(error).__name__ + ":" + str(error)}
            )
        after = source_inputs()
        if before != after:
            infrastructure.append(
                {"phase": "provenance", "failure": "source inputs changed"}
            )
        mismatches = evaluate_rows(rows, plan)
        recording = len(rows) == len(observation) and all(
            row.get("complete") is True for row in rows
        )
        state_valid = recording and not mismatches
        result = {
            "productionExecuted": False,
            "formalCompatibilityClaim": False,
            "recordingComplete": recording,
            "stateValidation": state_valid,
            "cleanupComplete": cleanup_complete,
            "completed": state_valid and cleanup_complete and not infrastructure,
            "rows": rows,
            "cleanup": cleanup,
            "resourceAbsence": absence,
            "semanticMismatches": mismatches,
            "infrastructureFailures": infrastructure,
            "gate": gate.snapshot(),
            "planDigest": digest(plan),
            "manifest": {
                "sourceInputs": before,
                "sourceInputsAfter": after,
                "nonce": nonce,
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
                "recordingComplete": recording
                and cleanup_complete
                and not infrastructure,
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


def run(output: Path) -> dict:
    import broad

    before = source_inputs()
    report = broad.run(
        output,
        child_script=Path(__file__).resolve(),
        project="demo-firestore-probe",
        configuration={"daemon": {"authProjectNumbers": {}}},
        execution_timeout=600,
        recovery_grace=1,
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
