"""Fixed local interruption rehearsal; a passing rehearsal is not a completed campaign."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from compiler import compile_limits_plan
from shadow import (
    REHEARSAL, _real_child, _validate_cleanup, evaluate_rows, exact_json, run, save,
)


def validate_rehearsal(receipt: dict, report: dict, binding: dict, plan: dict) -> bool:
    try:
        return _validate_rehearsal(receipt, report, binding, plan)
    except (KeyError, TypeError, ValueError, IndexError, AttributeError, RecursionError):
        return False


def _validate_rehearsal(receipt: dict, report: dict, binding: dict, plan: dict) -> bool:
    fault = {"name": REHEARSAL, "afterObservationIndex": 7, "triggered": True}
    rows = receipt.get("rows")
    manifest = receipt.get("manifest", {})
    return (
        receipt.get("productionExecuted") is False
        and receipt.get("formalCompatibilityClaim") is False
        and receipt.get("recordingComplete") is False
        and receipt.get("completed") is False
        and receipt.get("stateValidation") is False
        and receipt.get("cleanupComplete") is True
        and receipt.get("semanticMismatches") == []
        and receipt.get("infrastructureFailures") == []
        and exact_json(receipt.get("injectedFault"), fault)
        and exact_json(manifest.get("injectedFault"), fault)
        and exact_json(report.get("manifest", {}).get("injectedFault"), fault)
        and isinstance(rows, list)
        and len(rows) == 8
        and all(
            row.get("complete") is True
            and row.get("failure") is None
            and type(row.get("status")) is int
            for row in rows
        )
        and not evaluate_rows(rows, plan)
        and _validate_cleanup(receipt, plan, observed_prefix=8)
        and exact_json(
            receipt.get("resourceAbsence"),
            {d["resource"]: True for d in plan["documents"].values()},
        )
        and binding.get("bound") is True
        and report.get("status") == "incomplete"
        and report.get("productionExecuted") is False
        and report.get("stopReason") == "child-completed"
        and type(report.get("exitCode")) is int
        and report["exitCode"] == 0
        and report.get("ownedProcess", {}).get("stopped") is True
        and report.get("ownedProcess", {}).get("listenersClosed") is True
        and not any(
            report.get(key)
            for key in (
                "cleanupFailure",
                "parentCleanupFailure",
                "terminationVerificationFailure",
                "partialResultFailure",
                "shadowBindingFailure",
            )
        )
    )


def execute(output: Path) -> dict:
    report = run(output, rehearsal=REHEARSAL)
    receipt = json.loads((output / "result.json").read_bytes())
    binding = json.loads((output / "shadow-binding.json").read_bytes())
    plan = compile_limits_plan(
        "demo-firestore-probe", "(default)", receipt["manifest"]["nonce"]
    )
    result = {
        "kind": "fs-write-limits-recovery-rehearsal-v1",
        "productionExecuted": False,
        "formalCompatibilityClaim": False,
        "campaignCompleted": False,
        "rehearsalPassed": validate_rehearsal(receipt, report, binding, plan),
        "injectedFault": receipt.get("injectedFault"),
        "artifactSha256": report.get("artifactSha256"),
        "executionCommit": report.get("executionCommit"),
        "receiptFiles": {
            name: hashlib.sha256((output / name).read_bytes()).hexdigest()
            for name in ("result.json", "manifest.json", "shadow-binding.json")
        },
    }
    save(output / "rehearsal.json", result)
    return result


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
        _real_child(args.child.resolve(), args.nonce, rehearsal=REHEARSAL)
        return 0
    result = execute(args.output.resolve())
    print(json.dumps(result))
    return 0 if result["rehearsalPassed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
