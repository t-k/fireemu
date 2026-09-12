"""Run bounded partition invariants on a retained, input-matched local artifact."""

# ruff: noqa: BLE001 -- Preserve independent final checks after any execution/cleanup failure.
from __future__ import annotations

import argparse
import hashlib
import json
import os
import signal
import subprocess
import sys
import uuid
from pathlib import Path

from broad import ROOT, cleanup_run, save, source_inputs
from evidence_common import runtime_inputs
from owned_runner import (
    control_get,
    local_addresses,
    sanitized_environment,
    socket_closed,
    validate_build,
)

HERE = Path(__file__).resolve().parent
PROJECT = "demo-partition"


def retained_artifact(binary, receipt, inputs):
    build = json.loads(receipt.read_bytes())["build"]
    validate_build(build, hashlib.sha256(binary.read_bytes()).hexdigest(), inputs)
    return build


def child(output, nonce):
    firestore, control = local_addresses(
        os.environ["FIRESTORE_EMULATOR_HOST"], os.environ["FIREEMU_CONTROL_URL"]
    )
    token = os.environ["FIREEMU_CONTROL_TOKEN"]
    status, body = control_get(control, "/v1/sessions/default/resources", token)
    wrong, _ = control_get(control, "/v1/sessions/default/resources", token + "-wrong")
    if (
        status != 200
        or body.get("project") != PROJECT
        or wrong != 403
        or os.environ["GOOGLE_CLOUD_PROJECT"] != PROJECT
    ):
        raise ValueError("owned partition instance mismatch")
    save(
        output / "instance.json",
        {
            "pid": os.getpid(),
            "parentPid": os.getppid(),
            "argv": sys.argv,
            "nonce": nonce,
            "origins": [firestore, control],
        },
    )
    env = sanitized_environment(dict(os.environ))
    env.update(
        BROAD_ORIGIN=firestore,
        BROAD_STATS=str(output / "stats.json"),
        GOOGLE_CLOUD_PROJECT=PROJECT,
    )
    command = [
        "node",
        "--import",
        str(HERE / "local-guard.mjs"),
        str(HERE / "partition.mjs"),
        str(output / "cases.json"),
    ]
    with (output / "session-stderr.log").open("w") as errors:
        process = subprocess.Popen(
            command, env=env, stdout=subprocess.DEVNULL, stderr=errors
        )
        save(output / "partition-process.json", {"pid": process.pid, "argv": command})
        try:
            return process.wait(timeout=125)
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)


def supervise_partition(command, output, nonce, report, verify_inputs, *, timeout=150):
    """Always persist the final failure, owned cleanup and input-verification evidence."""
    process = None
    result = {}
    report.update(status="incomplete", recordingComplete=False, inputsStable=False)
    try:
        with (output / "stderr.log").open("w") as errors:
            process = subprocess.Popen(
                command,
                cwd=output,
                env=sanitized_environment(dict(os.environ)),
                stdout=subprocess.DEVNULL,
                stderr=errors,
            )
            report["exitCode"] = process.wait(timeout=timeout)
    except (Exception, KeyboardInterrupt) as error:
        report["executionFailure"] = type(error).__name__
    finally:
        try:
            if process is not None:
                cleanup_run(process, output, nonce, report)
        except Exception as error:
            report["cleanupFailure"] = type(error).__name__
        report["ownedProcess"] = {
            "pid": process.pid if process else None,
            "stopped": process is not None and process.poll() is not None,
            "listenersClosed": False,
        }
        try:
            instance = json.loads((output / "instance.json").read_bytes())
            report["ownedProcess"]["listenersClosed"] = bool(
                instance["origins"]
            ) and all(socket_closed(origin) for origin in instance["origins"])
        except Exception as error:
            report["listenerVerificationFailure"] = type(error).__name__
        try:
            report["inputsStable"] = bool(verify_inputs())
        except Exception as error:
            report["inputVerificationFailure"] = type(error).__name__
        try:
            result = json.loads((output / "cases.json").read_bytes())
            report["recordingComplete"] = (
                report.get("exitCode") == 0
                and result.get("status") == "pass"
                and len(result.get("cases", [])) == 30
                and all(row.get("status") == "pass" for row in result["cases"])
            )
        except Exception as error:
            report["recordingFailure"] = type(error).__name__
        if (
            report["recordingComplete"]
            and report["inputsStable"]
            and all(
                report["ownedProcess"][key] for key in ("stopped", "listenersClosed")
            )
            and not any(key.endswith("Failure") for key in report)
        ):
            report["status"] = "pass"
        save(output / "manifest.json", report)
    return result


def run(binary, receipt, output):
    inputs = runtime_inputs(ROOT)
    build = retained_artifact(binary, receipt, inputs)
    observers = source_inputs()
    # This helper is outside the shared source-input set and must also be bound.
    helper = ROOT / "conformance/src/firestore-probe/partition-reconstruction.mjs"
    observers[str(helper.relative_to(ROOT))] = hashlib.sha256(
        helper.read_bytes()
    ).hexdigest()
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    config = {
        "schemaVersion": 1,
        "profile": "strict",
        "firestore": {"edition": "standard", "apiMode": "native"},
    }
    save(output / "config.json", config)
    nonce = uuid.uuid4().hex
    command = [
        str(binary),
        "exec",
        "--config",
        str(output / "config.json"),
        "--project",
        PROJECT,
        "--only",
        "firestore",
        "--firestore-port",
        "0",
        "--http-port",
        "0",
        "--hub-port",
        "0",
        "--ui-port",
        "0",
        "--logging-port",
        "0",
        "--log-verbosity",
        "silent",
        "--",
        sys.executable,
        str(Path(__file__).resolve()),
        "--child",
        str(output),
        "--nonce",
        nonce,
    ]
    report = {
        "status": "incomplete",
        "productionExecuted": False,
        "executionCommit": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip(),
        "build": build,
        "artifactSha256": build["artifactSha256"],
        "runtimeInputs": inputs,
        "executionInputs": observers,
        "configuration": config,
        "command": command,
    }

    def verify_inputs():
        current_observers = source_inputs()
        current_observers[str(helper.relative_to(ROOT))] = hashlib.sha256(
            helper.read_bytes()
        ).hexdigest()
        return (
            inputs == runtime_inputs(ROOT)
            and observers == current_observers
            and hashlib.sha256(binary.read_bytes()).hexdigest()
            == build["artifactSha256"]
        )

    result = supervise_partition(command, output, nonce, report, verify_inputs)
    print(
        json.dumps(
            {
                "status": report["status"],
                "ownedProcess": report["ownedProcess"],
                "cases": len(result.get("cases", [])),
                "requests": result.get("requests"),
            }
        )
    )
    return 0 if report["status"] == "pass" else 1


def interrupted(_signum, _frame):
    raise InterruptedError("stop requested; unwind owned cleanup")


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGHUP, interrupted)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--receipt", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--child", type=Path)
    parser.add_argument("--nonce")
    args = parser.parse_args()
    if args.child:
        sys.exit(child(args.child, args.nonce))
    if not all((args.binary, args.receipt, args.output)):
        parser.error("--binary, --receipt and --output required")
    sys.exit(run(args.binary.resolve(), args.receipt.resolve(), args.output.resolve()))
