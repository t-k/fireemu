"""Exercise the production-style mapped adapter on a newly owned local artifact only."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import uuid
from pathlib import Path

from batch_adapter import Adapter, candidate
from batch_contract import NUMBER, PROJECT, wrapper_exit_code
from broad import cleanup_run, save, source_inputs
from broad_contract import ROOT, local_origin
from owned_runner import (
    build_artifact,
    control_get,
    local_addresses,
    sanitized_environment,
    socket_closed,
    validate_build,
)


RETAINED_648_SOURCE_COMMIT = "648aabe56cf6147128ffadf565d93ca7a92013c1"
RETAINED_648_ARTIFACT_SHA256 = (
    "7737f6c389aff0a0f280757591af3b81f11edfbc8438cb69268da0f4c2237026"
)
RETAINED_648_INPUT_MAP_SHA256 = (
    "7e2b0bc7037e0caf9f979f052c69a3820a398c8df72de8dbd19f1aac2f524331"
)


def _runtime_input_map_sha256(inputs: dict) -> str:
    encoded = json.dumps(inputs, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def adopted_artifact(binary: Path, receipt_path: Path, source_commit: str) -> dict:
    """Validate an immutable previously built binary without rebuilding or relabeling it."""
    if not binary.is_absolute() or binary.is_symlink() or not binary.is_file():
        raise ValueError("adopted artifact must be an absolute regular file")
    if (
        not receipt_path.is_absolute()
        or receipt_path.is_symlink()
        or not receipt_path.is_file()
    ):
        raise ValueError("build receipt must be an absolute regular file")
    if not re.fullmatch(r"[0-9a-f]{40}", source_commit):
        raise ValueError("invalid artifact source commit")
    receipt = json.loads(receipt_path.read_bytes())
    build = receipt.get("build")
    runtime = receipt.get("runtimeSource")
    inputs = runtime.get("files") if isinstance(runtime, dict) else None
    if runtime.get("commit") != source_commit if isinstance(runtime, dict) else True:
        raise ValueError("artifact source commit mismatch")
    if not isinstance(inputs, dict) or build.get("inputs") != inputs:
        raise ValueError("runtime input map mismatch")
    artifact_sha = hashlib.sha256(binary.read_bytes()).hexdigest()
    if len(inputs) == 429:
        pass
    elif len(inputs) == 430:
        if source_commit != RETAINED_648_SOURCE_COMMIT:
            raise ValueError("artifact source commit mismatch")
        if artifact_sha != RETAINED_648_ARTIFACT_SHA256:
            raise ValueError("artifact hash mismatch")
        if _runtime_input_map_sha256(inputs) != RETAINED_648_INPUT_MAP_SHA256:
            raise ValueError("runtime input map mismatch")
    else:
        raise ValueError("runtime input map mismatch")
    validate_build(build, artifact_sha, inputs)
    return {
        "artifactSha256": artifact_sha,
        "sourceCommit": source_commit,
        "runtimeInputCount": len(inputs),
        "build": build,
    }


def child(output, nonce, *, shared=False):
    if shared:
        from shared_cases import manifest
        from shared_gate import create

    origins = {
        "auth": local_origin("http://" + os.environ["FIREBASE_AUTH_EMULATOR_HOST"]),
        "firestore": local_origin("http://" + os.environ["FIRESTORE_EMULATOR_HOST"]),
    }
    if shared:
        create(output / "gate", {**manifest(nonce), "localOrigins": origins})
    _, control = local_addresses(
        os.environ["FIRESTORE_EMULATOR_HOST"], os.environ["FIREEMU_CONTROL_URL"]
    )
    token = os.environ["FIREEMU_CONTROL_TOKEN"]
    if shared:
        from shared_gate import Gate

        gate = Gate(output / "gate", "partial")
        status, body = gate.coordinator_call(
            0, lambda: control_get(control, "/v1/sessions/default/resources", token)
        )
        wrong, _ = gate.coordinator_call(
            1,
            lambda: control_get(
                control, "/v1/sessions/default/resources", token + "-wrong"
            ),
        )
    else:
        status, body = control_get(control, "/v1/sessions/default/resources", token)
        wrong, _ = control_get(
            control, "/v1/sessions/default/resources", token + "-wrong"
        )
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
    if shared:
        from shared_cases import execute

        if not execute(output, origins):
            raise ValueError("shared scenarios incomplete")
        return
    adapter = Adapter(candidate(), nonce, output / "batch", local_origins=origins)
    result = adapter.execute()
    if not result["completed"]:
        raise ValueError("local batch incomplete; see private report")


def run(
    output,
    *,
    shared=False,
    binary=None,
    build=None,
    artifact_source_commit=None,
    build_receipt=None,
):
    if subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT).strip():
        raise ValueError("freeze checkout before local batch")
    before = source_inputs()
    if binary is None:
        binary, build = build_artifact()
    else:
        adopted = adopted_artifact(binary, build_receipt, artifact_source_commit)
        build = adopted["build"]
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
            "daemon": {"authProjectNumbers": {PROJECT: NUMBER}},
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
    if shared:
        command.append("--shared")
    report = {
        "productionExecuted": False,
        "configurationSha256": hashlib.sha256(config.read_bytes()).hexdigest(),
        "stopReason": "not-started",
        "executionCommit": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip(),
        "artifactSha256": build["artifactSha256"],
        "artifactSourceCommit": artifact_source_commit,
        "artifactProvenance": "retained-build-receipt" if artifact_source_commit else "fresh-build",
        "harnessDigest": hashlib.sha256(
            (Path(__file__).with_name("batch_adapter.py")).read_bytes()
        ).hexdigest(),
        "executionInputs": before,
        "build": build,
    }
    save(output / "manifest.json", report)
    with (output / "stderr.log").open("w") as errors:
        process = subprocess.Popen(
            command,
            cwd=output,
            env=sanitized_environment(dict(os.environ)),
            stdout=subprocess.DEVNULL,
            stderr=errors,
        )
        try:
            report["exitCode"] = process.wait(timeout=360 if shared else 180)
            report["stopReason"] = (
                "child-completed" if report["exitCode"] == 0 else "child-nonzero"
            )
        except subprocess.TimeoutExpired:
            report.update(exitCode=None, stopReason="child-timeout")
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
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--binary", type=Path)
    source.add_argument("--build", action="store_true")
    parser.add_argument("--build-receipt", type=Path)
    parser.add_argument("--artifact-source-commit")
    parser.add_argument("--child", type=Path)
    parser.add_argument("--nonce")
    parser.add_argument("--shared", action="store_true")
    args = parser.parse_args()
    if args.child:
        child(args.child, args.nonce, shared=args.shared)
    elif args.output and args.build:
        sys.exit(run(args.output.resolve(), shared=args.shared))
    elif args.output and args.binary:
        if not args.build_receipt or not args.artifact_source_commit:
            parser.error("--binary requires --build-receipt and --artifact-source-commit")
        sys.exit(
            run(
                args.output.resolve(),
                shared=args.shared,
                binary=args.binary,
                artifact_source_commit=args.artifact_source_commit,
                build_receipt=args.build_receipt,
            )
        )
    else:
        parser.error("--output required")
