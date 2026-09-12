"""Exercise the production-style mapped adapter on a newly owned local artifact only."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import signal
import subprocess
import sys
import uuid
from pathlib import Path

from batch_adapter import Adapter, candidate
from batch_contract import PROJECT, wrapper_exit_code
from broad import cleanup_run, save, source_inputs
from broad_contract import ROOT, local_origin
from owned_runner import (
    build_artifact,
    control_get,
    local_addresses,
    sanitized_environment,
    socket_closed,
)


def child(output, nonce):
    origins = {
        "auth": local_origin("http://" + os.environ["FIREBASE_AUTH_EMULATOR_HOST"]),
        "firestore": local_origin("http://" + os.environ["FIRESTORE_EMULATOR_HOST"]),
    }
    _, control = local_addresses(
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
        raise ValueError("owned instance identity mismatch")
    save(
        output / "instance.json",
        {
            "pid": os.getpid(),
            "parentPid": os.getppid(),
            "argv": sys.argv,
            "nonce": nonce,
            "origins": [*origins.values(), control],
        },
    )
    adapter = Adapter(candidate(), nonce, output / "batch", local_origins=origins)
    result = adapter.execute()
    if not result["completed"]:
        raise ValueError("local batch incomplete; see private report")


def run(output):
    if subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT).strip():
        raise ValueError("freeze checkout before local batch")
    before = source_inputs()
    binary, build = build_artifact()
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    artifact = output / "fireemu"
    shutil.copyfile(binary, artifact)
    artifact.chmod(0o500)
    if hashlib.sha256(artifact.read_bytes()).hexdigest() != build["artifactSha256"]:
        raise ValueError("artifact copy changed")
    config = output / "config.json"
    save(
        config,
        {
            "schemaVersion": 1,
            "profile": "strict",
            "firestore": {"edition": "standard", "apiMode": "native"},
        },
    )
    nonce = uuid.uuid4().hex
    command = [
        str(artifact),
        "exec",
        "--config",
        str(config),
        "--project",
        PROJECT,
        "--only",
        "auth,firestore",
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
        "productionExecuted": False,
        "executionCommit": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip(),
        "artifactSha256": build["artifactSha256"],
        "executionInputs": before,
        "build": build,
    }
    with (output / "stderr.log").open("w") as errors:
        process = subprocess.Popen(
            command,
            cwd=output,
            env=sanitized_environment(dict(os.environ)),
            stdout=subprocess.DEVNULL,
            stderr=errors,
        )
        try:
            report["exitCode"] = process.wait(timeout=180)
        finally:
            cleanup_run(process, output, nonce, report)
    if before != source_inputs():
        raise ValueError("observer changed during execution")
    if not (output / "instance.json").exists():
        raise ValueError(
            "owned child failed before identity confirmation; see private stderr"
        )
    instance = json.loads((output / "instance.json").read_bytes())
    report["ownedProcess"] = {
        "pid": process.pid,
        "stopped": process.poll() is not None,
        "listenersClosed": all(socket_closed(origin) for origin in instance["origins"]),
    }
    if (output / "batch/result.json").exists():
        report["batch"] = json.loads((output / "batch/result.json").read_bytes())
    save(output / "manifest.json", report)
    print(
        json.dumps(
            {"exitCode": report["exitCode"], "ownedProcess": report["ownedProcess"]}
        )
    )

    return wrapper_exit_code(report)


def interrupted(_signum, _frame):
    raise InterruptedError("stop requested; unwind owned cleanup")


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGHUP, interrupted)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--child", type=Path)
    parser.add_argument("--nonce")
    args = parser.parse_args()
    if args.child:
        child(args.child, args.nonce)
    elif args.output:
        sys.exit(run(args.output.resolve()))
    else:
        parser.error("--output required")
