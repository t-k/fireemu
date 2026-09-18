"""Owned local rehearsal of the transaction expiry / retry campaign.

The parent copies the built `fireemu` artifact into a private directory, runs it
as `fireemu exec --only firestore`, and launches itself as the child inside that
owned instance. The child drives the bounded collector over the emulator's REST
surface and reaches the idle limit by advancing the emulator's virtual clock,
because that clock does not follow wall time.

This is local evidence. It proves the collector, the plan, the cleanup contract
and the frozen expected local results against the real runtime. It is not a
production observation and establishes no parity.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shlex
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "compat-inventory"))

import txn_expiry_cases as cases
import txn_expiry_collector as collector
import txn_expiry_comparison as comparison
import txn_expiry_plan as plan_module
from broad_contract import digest
from evidence_common import runtime_inputs
from owned_runner import control_get, local_addresses

CONTRACT = "txn-expiry-local-shadow-v1"
PROJECT = "fireemu-test"
CONFIG = {
    "schemaVersion": 1,
    "profile": "strict",
    "firestore": {"edition": "standard", "apiMode": "native"},
    "daemon": {"clockStart": "2026-09-18T00:00:00Z"},
}

#: REST status names mapped to the gRPC codes the case table speaks.
STATUS_TO_CODE = {
    "OK": 0,
    "CANCELLED": 1,
    "UNKNOWN": 2,
    "INVALID_ARGUMENT": 3,
    "DEADLINE_EXCEEDED": 4,
    "NOT_FOUND": 5,
    "ALREADY_EXISTS": 6,
    "PERMISSION_DENIED": 7,
    "RESOURCE_EXHAUSTED": 8,
    "FAILED_PRECONDITION": 9,
    "ABORTED": 10,
    "OUT_OF_RANGE": 11,
    "UNIMPLEMENTED": 12,
    "INTERNAL": 13,
    "UNAVAILABLE": 14,
    "UNAUTHENTICATED": 16,
}

REQUEST_TIMEOUT_SECONDS = 45
CHILD_TIMEOUT_SECONDS = 420


def runtime_binding(artifact, root):
    """Bind the built artifact to the Rust source it was produced from.

    A binary built somewhere else describes somewhere else. The shadow records
    the commit, the hashed Rust inputs and whether those inputs were clean, so a
    later reader can tell which source the local evidence actually describes.
    """
    artifact = Path(artifact)
    commit = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=root, text=True
    ).strip()
    dirty = subprocess.check_output(
        [
            "git",
            "status",
            "--porcelain",
            "--",
            "Cargo.toml",
            "Cargo.lock",
            "rust-toolchain.toml",
            ".cargo",
            "crates",
        ],
        cwd=root,
        text=True,
    ).strip()
    inputs = runtime_inputs(Path(root))
    return {
        "artifactSha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
        "sourceCommit": commit,
        "sourceRoot": str(root),
        "runtimeInputsDigest": digest(inputs),
        "runtimeInputCount": len(inputs),
        "runtimeInputsClean": dirty == "",
    }


def save(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def rest_transport(origin, *, timeout=REQUEST_TIMEOUT_SECONDS):
    """Build a bounded REST transport for one Firestore origin."""

    def send(request):
        database = request["database"]
        project = request["projectId"]
        base = f"{origin}/v1/projects/{project}/databases/{database}/documents"
        rpc = request["rpc"]
        if rpc == "GetDocument":
            url = f"{origin}/v1/{request['name']}"
            query = request.get("query") or {}
            if "transaction" in query:
                url += "?transaction=" + urllib.parse.quote(
                    query["transaction"], safe=""
                )
            http = urllib.request.Request(url, method="GET")
            payload = None
        else:
            suffix = {
                "BeginTransaction": ":beginTransaction",
                "Commit": ":commit",
                "Rollback": ":rollback",
            }[rpc]
            payload = json.dumps(request["body"]).encode()
            http = urllib.request.Request(base + suffix, data=payload, method="POST")
            http.add_header("Content-Type", "application/json")
        http.add_header("Authorization", "Bearer owner")
        limit = request["maxResponseBytes"]
        try:
            with urllib.request.urlopen(http, timeout=timeout) as response:
                raw = response.read(limit + 1)
                if len(raw) > limit:
                    return {
                        "complete": False,
                        "code": None,
                        "status": None,
                        "message": "response-exceeds-bound",
                    }
                return {
                    "complete": True,
                    "code": 0,
                    "status": "OK",
                    "message": None,
                    "body": json.loads(raw or b"{}"),
                }
        except urllib.error.HTTPError as error:
            raw = error.read(limit + 1)
            if len(raw) > limit:
                return {
                    "complete": False,
                    "code": None,
                    "status": None,
                    "message": "response-exceeds-bound",
                }
            try:
                body = json.loads(raw or b"{}")
            except ValueError:
                return {
                    "complete": False,
                    "code": None,
                    "status": None,
                    "message": "response-not-json",
                }
            detail = body.get("error") or {}
            status = detail.get("status")
            if status not in STATUS_TO_CODE:
                return {
                    "complete": False,
                    "code": None,
                    "status": status,
                    "message": "unmapped-status",
                }
            return {
                "complete": True,
                "code": STATUS_TO_CODE[status],
                "status": status,
                "message": detail.get("message"),
                "body": body,
            }
        except (urllib.error.URLError, TimeoutError, ValueError) as error:
            return {
                "complete": False,
                "code": None,
                "status": None,
                "message": type(error).__name__,
            }

    return send


def clock_advance(control_origin, token, *, timeout=15):
    """Advance the emulator's virtual clock by whole seconds."""

    def advance(seconds):
        payload = json.dumps({"seconds": int(seconds)}).encode()
        request = urllib.request.Request(
            f"{control_origin}/v1/sessions/default/clock:advance",
            data=payload,
            method="POST",
        )
        request.add_header("Content-Type", "application/json")
        request.add_header("Authorization", "Bearer " + token)
        with urllib.request.urlopen(request, timeout=timeout) as response:
            if response.status != 200:
                raise RuntimeError("clock advance refused")

    return advance


def child(output, nonce, owner_id):
    firestore, control = local_addresses(
        os.environ["FIRESTORE_EMULATOR_HOST"], os.environ["FIREEMU_CONTROL_URL"]
    )
    token = os.environ["FIREEMU_CONTROL_TOKEN"]
    status, resources = control_get(control, "/v1/sessions/default/resources", token)
    wrong, _ = control_get(control, "/v1/sessions/default/resources", token + "-wrong")
    if status != 200 or wrong != 403 or resources.get("project") != PROJECT:
        raise ValueError("owned instance identity is not proven")
    argv = shlex.split(
        subprocess.check_output(
            ["ps", "-ww", "-p", str(os.getppid()), "-o", "args="], text=True
        ).strip()
    )
    host, _, port = firestore.rpartition("//")[2].partition(":")
    options = {
        "target": "local",
        "host": host,
        "port": int(port),
        "projectId": PROJECT,
        "database": plan_module.DATABASE,
        "nonce": nonce,
        "ownerId": owner_id,
        "timing": collector.CONTROL_CLOCK,
        "deadlineSeconds": 300,
    }
    receipt = collector.collect(
        options,
        rest_transport(firestore),
        advance=clock_advance(control, token),
    )
    receipt["instance"] = {
        "pid": os.getpid(),
        "parentPid": os.getppid(),
        "firestoreOrigin": firestore,
        "controlOrigin": control,
        "wrongTokenStatus": wrong,
        "artifactPath": argv[0],
        "artifactSha256": hashlib.sha256(Path(argv[0]).read_bytes()).hexdigest(),
    }
    save(Path(output) / "receipt.json", receipt)
    save(
        Path(output) / "self-contract.json",
        comparison.local_self_contract(receipt),
    )


def stop_child(process, artifact):
    """Stop the owned instance by PID after verifying it is the one we started."""
    if process.poll() is not None:
        return {"stopped": True, "signal": None, "exitCode": process.returncode}
    try:
        argv = subprocess.check_output(
            ["ps", "-ww", "-p", str(process.pid), "-o", "args="], text=True
        ).strip()
    except subprocess.CalledProcessError:
        return {"stopped": True, "signal": None, "exitCode": process.poll()}
    if str(artifact) not in argv:
        raise RuntimeError("refusing to signal a process we did not start")
    process.send_signal(signal.SIGTERM)
    try:
        process.wait(timeout=20)
        return {"stopped": True, "signal": "SIGTERM", "exitCode": process.returncode}
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=20)
        return {"stopped": True, "signal": "SIGKILL", "exitCode": process.returncode}


def run_shadow(artifact, output):
    artifact = Path(artifact).resolve(strict=True)
    source_root = Path(__file__).resolve().parents[3]
    binding = runtime_binding(artifact, source_root)
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    output.chmod(0o700)
    before = plan_module.source_digest()
    retained = output / "fireemu"
    retained.write_bytes(artifact.read_bytes())
    retained.chmod(0o500)
    artifact_sha = hashlib.sha256(retained.read_bytes()).hexdigest()
    config = output / "config.json"
    save(config, CONFIG)
    config.chmod(0o400)
    nonce = "o3expiry-" + os.urandom(8).hex()
    owner_id = os.urandom(16).hex()
    argv = [
        str(retained),
        "exec",
        "--config",
        str(config),
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
        "--owner",
        owner_id,
    ]
    started = time.time()
    process = subprocess.Popen(argv, cwd=output)
    try:
        process.wait(timeout=CHILD_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        pass
    stopped = stop_child(process, retained)
    receipt_path = output / "receipt.json"
    receipt = json.loads(receipt_path.read_bytes()) if receipt_path.exists() else None
    contract_path = output / "self-contract.json"
    contract = (
        json.loads(contract_path.read_bytes()) if contract_path.exists() else None
    )
    result = {
        "kind": CONTRACT,
        "campaign": cases.CAMPAIGN,
        "casesDigest": cases.cases_digest(),
        "sourceDigestBefore": before,
        "sourceDigestAfter": plan_module.source_digest(),
        "artifactSha256": artifact_sha,
        "runtime": binding,
        "nonce": nonce,
        "ownerId": owner_id,
        "elapsedSeconds": round(time.time() - started, 3),
        "child": stopped,
        "receipt": receipt,
        "selfContract": contract,
        "acquisitionValidated": False,
        "promotionReady": False,
    }
    result["complete"] = bool(
        binding["artifactSha256"] == artifact_sha
        and binding["runtimeInputsClean"]
        and receipt
        and receipt.get("complete")
        and contract
        and contract.get("classification") == comparison.MATCH
        and result["sourceDigestBefore"] == result["sourceDigestAfter"]
    )
    save(output / "shadow.json", result)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--child", type=Path)
    parser.add_argument("--nonce")
    parser.add_argument("--owner")
    args = parser.parse_args(argv)
    if args.child is not None:
        child(args.child, args.nonce, args.owner)
        return 0
    if args.artifact is None or args.output is None:
        parser.error("--artifact and --output are required")
    result = run_shadow(args.artifact, args.output)
    print(json.dumps({k: v for k, v in result.items() if k != "receipt"}, indent=2))
    return 0 if result["complete"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
