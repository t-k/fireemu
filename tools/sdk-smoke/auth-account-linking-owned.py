"""Own one local Auth artifact execution and persist measured cleanup evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
JS = Path(__file__).with_name("auth-account-linking-local.mjs")
EXPECTED_SDK = {"firebase": "12.18.0", "firebase-admin": "14.3.0"}
OPERATION_IDS = [
    "signup-a",
    "signup-b",
    "same-provider-signin",
    "cross-provider-same-email-collision",
    "distinct-provider-link",
    "provider-unlink",
]


def sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def load_json(path: Path) -> dict:
    value = json.loads(path.read_bytes())
    require(isinstance(value, dict), f"{path} must contain an object")
    return value


def validate_manifest(manifest: dict, artifact: Path) -> tuple[str, str]:
    require(manifest.get("status") == "completed", "retained manifest is not completed")
    require(manifest.get("productionExecuted") is False, "production manifest cannot be adopted")
    source = manifest.get("executionCommit")
    expected = manifest.get("artifactSha256")
    require(isinstance(source, str) and re.fullmatch(r"[0-9a-f]{40}", source), "manifest source binding missing")
    require(isinstance(expected, str) and re.fullmatch(r"[0-9a-f]{64}", expected), "manifest artifact binding missing")
    require(artifact.is_file() and artifact.name == "fireemu", "artifact must be a regular fireemu file")
    actual = sha(artifact)
    require(actual == expected, "artifact does not match retained manifest")
    return source, actual


def validate_sdk_pins(package: dict) -> dict:
    dependencies = package.get("dependencies", {})
    actual = {name: dependencies.get(name) for name in EXPECTED_SDK}
    require(actual == EXPECTED_SDK, "installed SDK package pins differ from reviewed pins")
    return actual


def socket_closed(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.5):
            return False
    except OSError:
        return True


def descendant_group_gone(pgid: int) -> bool:
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return True
    except PermissionError:
        return False
    return False


def terminate_group(process: subprocess.Popen[bytes], attempts: list[dict]) -> None:
    if process.poll() is not None:
        return
    pgid = os.getpgid(process.pid)
    for name, sig in (("SIGTERM", signal.SIGTERM), ("SIGKILL", signal.SIGKILL)):
        try:
            os.killpg(pgid, sig)
            attempts.append({"signal": name, "sent": True})
        except ProcessLookupError:
            attempts.append({"signal": name, "sent": False, "reason": "group-gone"})
            break
        try:
            process.wait(timeout=10 if sig == signal.SIGTERM else 5)
            break
        except subprocess.TimeoutExpired:
            attempts.append({"signal": name, "wait": "timeout"})
    require(process.poll() is not None, "owned fireemu process did not terminate")
    require(descendant_group_gone(pgid), "owned process group remains alive")


def ports_from_output(raw: bytes) -> list[int]:
    text = raw.decode("utf-8", errors="replace")
    return [int(port) for port in re.findall(r"auth \(REST\):\s+127\.0\.0\.1:(\d+)", text)]


def run(output: Path, manifest_path: Path, artifact: Path) -> dict:
    output = output.resolve()
    output.mkdir(mode=0o700, exist_ok=False)
    report: dict = {"status": "owned-run-failed", "productionExecuted": False}
    cleanup_attempts: list[dict] = []
    process: subprocess.Popen[bytes] | None = None
    ports: list[int] = []
    try:
        manifest = load_json(manifest_path)
        source_commit, artifact_hash = validate_manifest(manifest, artifact)
        package = load_json(ROOT / "tools/sdk-smoke/package.json")
        sdk = validate_sdk_pins(package)
        with tempfile.TemporaryDirectory(prefix="auth-linking-owned-") as private_name:
            private = Path(private_name)
            owned_artifact = private / "fireemu"
            shutil.copyfile(artifact, owned_artifact)
            owned_artifact.chmod(0o500)
            require(sha(owned_artifact) == artifact_hash, "owned artifact copy changed")
            child_receipt = output / "child-observation.json"
            child_receipt.touch(mode=0o600, exist_ok=False)
            child_receipt.unlink()
            log_path = output / "owned-output.log"
            with log_path.open("xb") as log:
                env = {key: value for key, value in os.environ.items() if key in {"PATH", "HOME", "TMPDIR", "LANG", "LC_ALL"}}
                env.update(
                    {
                        "GOOGLE_CLOUD_PROJECT": "demo-app",
                        "AUTH_LINKING_RECEIPT": str(child_receipt),
                        "NODE_PATH": str(ROOT / "tools/sdk-smoke/node_modules"),
                    }
                )
                argv = [
                    str(owned_artifact),
                    "exec",
                    "--project",
                    "demo-app",
                    "--only",
                    "auth",
                    "--http-port",
                    "0",
                    "--hub-port",
                    "0",
                    "--ui-port",
                    "0",
                    "--logging-port",
                    "0",
                    "--log-verbosity",
                    "info",
                    "--",
                    "node",
                    str(JS),
                ]
                process = subprocess.Popen(
                    argv,
                    cwd=ROOT,
                    env=env,
                    stdin=subprocess.DEVNULL,
                    stdout=log,
                    stderr=subprocess.STDOUT,
                    start_new_session=True,
                )
                try:
                    process.wait(timeout=180)
                except subprocess.TimeoutExpired:
                    terminate_group(process, cleanup_attempts)
                    raise
                log.flush()
            raw_output = log_path.read_bytes()
            ports = ports_from_output(raw_output)
            require(ports, "owned output did not expose Auth listener")
            listener_closed = all(socket_closed(port) for port in ports)
            require(listener_closed, "Auth listener remained open after process exit")
            child = load_json(child_receipt)
            require(child.get("status") == "completed", "child observation incomplete")
            require(child.get("productionExecuted") is False, "child attempted production")
            require(child.get("providerBoundary") == "local-emulator-fixture", "provider boundary missing")
            require([row.get("id") for row in child.get("operations", [])] == OPERATION_IDS, "operation sequence incomplete")
            report = {
                **child,
                "sourceCommit": source_commit,
                "artifact": {"path": str(artifact), "sha256": artifact_hash, "manifest": str(manifest_path)},
                "sdk": sdk,
                "ownedProcess": {"pid": process.pid, "exitCode": process.returncode, "stopped": process.poll() is not None, "listenersClosed": listener_closed},
                "cleanup": {"ownedResources": 0, "listenersClosed": listener_closed, "processStopped": process.poll() is not None, "attempts": cleanup_attempts},
                "status": "completed",
            }
            require(report["ownedProcess"]["stopped"] and report["ownedProcess"]["listenersClosed"], "measured process cleanup incomplete")
        with (output / "receipt.json").open("x", encoding="utf-8") as stream:
            json.dump(report, stream, indent=2)
            stream.write("\n")
        return report
    except Exception as error:
        if process is not None:
            try:
                terminate_group(process, cleanup_attempts)
            except Exception as cleanup_error:
                cleanup_attempts.append({"cleanupFailure": type(cleanup_error).__name__, "message": str(cleanup_error)})
        failure = {
            "status": "owned-run-failed",
            "productionExecuted": False,
            "failure": {"type": type(error).__name__, "message": str(error)},
            "cleanup": {"attempts": cleanup_attempts, "listenersChecked": bool(ports), "listenersClosed": all(socket_closed(port) for port in ports) if ports else None, "processStopped": process is None or process.poll() is not None},
        }
        with (output / "failure.json").open("x", encoding="utf-8") as stream:
            json.dump(failure, stream, indent=2)
            stream.write("\n")
        return failure


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--artifact", type=Path, required=True)
    args = parser.parse_args()
    result = run(args.output, args.manifest, args.artifact)
    print(json.dumps({"status": result["status"], "output": str(args.output)}, indent=2))
    raise SystemExit(0 if result["status"] == "completed" else 2)
