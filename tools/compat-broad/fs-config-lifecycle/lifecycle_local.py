"""Local rehearsal of the FS-CONFIG-LIFECYCLE campaign against an owned fireemu.

The supervisor starts one fireemu built from the committed tree in `exec` mode, with
this module as the child. The child drives the twelve cases through the same collector
and gate the production launcher uses, over a loopback transport that carries the
emulator's fixed owner token, and writes a record whose runtime binding names the
artifact digest and the source commit. Nothing here contacts Google, and the record
can never be read as production evidence: its execution kind is the injected local
transport and the comparator refuses to classify two local records as a match.

The local database projection cannot equal the saved production one (uid, createTime
and updateTime are local values), so the child reads the local projection once,
outside the gate, to derive the baseline digest the gate then enforces. The record
states both digests and that they differ.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "tools/compat-broad"))
sys.path.insert(0, str(ROOT / "tools/compat-inventory"))
sys.path.insert(0, str(HERE))

import _lane

_lane.ensure_package()

from batch_contract import database_evidence
from broad_contract import digest, local_origin
from fs_config_lifecycle.cases import PROJECT, compile_cases
from fs_config_lifecycle.fake_admin import saved_projection
from fs_config_lifecycle.lifecycle_collector import (
    collect,
    http_request,
    request_url_path,
)
from fs_config_lifecycle.lifecycle_gate import ConfigurationGate, create, gate_plan
from fs_config_lifecycle.surface_matrix import CASE_ID

RECORD_KIND = "fs-config-lifecycle-local-rehearsal-v1"
EXECUTION_KIND = "injected-local-transport"
OWNER_TOKEN = "owner"
RESPONSE_CAP = 256 * 1024
BOUND_MODULES = (
    "cases.py",
    "manifest.py",
    "comparator.py",
    "lifecycle_gate.py",
    "lifecycle_collector.py",
    "lifecycle_local.py",
)


def save(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n")


def bound_module_digests() -> dict[str, str]:
    return {
        f"tools/compat-broad/fs-config-lifecycle/{name}": hashlib.sha256(
            (HERE / name).read_bytes()
        ).hexdigest()
        for name in BOUND_MODULES
    }


def loopback_transport(origin: str):
    """One bounded loopback request per call; the owner token is the emulator's constant."""
    local_origin(origin)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def transmit(request: dict[str, Any], *, deadline: float) -> dict[str, Any]:
        import time

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return {
                "status": None,
                "body": None,
                "complete": False,
                "failure": "deadline",
            }
        body = None
        headers = {"Authorization": f"Bearer {OWNER_TOKEN}"}
        if request.get("body") is not None:
            body = json.dumps(request["body"], separators=(",", ":")).encode()
            headers["Content-Type"] = "application/json"
        wire = urllib.request.Request(
            origin + request_url_path(request),
            data=body,
            method=request["method"],
            headers=headers,
        )
        try:
            with opener.open(wire, timeout=remaining) as response:
                status, raw = response.status, response.read(RESPONSE_CAP + 1)
        except urllib.error.HTTPError as error:
            status, raw = error.code, error.read(RESPONSE_CAP + 1)
        except (urllib.error.URLError, OSError, TimeoutError) as error:
            return {
                "status": None,
                "body": None,
                "complete": False,
                "failure": type(error).__name__,
            }
        if len(raw) > RESPONSE_CAP:
            return {
                "status": status,
                "body": None,
                "complete": False,
                "failure": "oversize",
            }
        try:
            parsed = json.loads(raw) if raw else None
        except ValueError:
            return {
                "status": status,
                "body": None,
                "complete": False,
                "failure": "non-json",
                "raw": raw,
            }
        return {
            "status": status,
            "body": parsed,
            "complete": True,
            "failure": None,
            "raw": raw,
        }

    return transmit


def local_baseline(origin: str, nonce: str) -> dict[str, Any]:
    """Read the local projection once, outside the gate, to derive the gate baseline."""
    import time

    case = next(c for c in compile_cases(nonce) if c["id"] == "OC-01")
    receipt = loopback_transport(origin)(
        http_request(case), deadline=time.monotonic() + 10
    )
    if receipt["status"] != 200 or not isinstance(receipt["body"], dict):
        raise ValueError("local projection unavailable")
    local = database_evidence(receipt["body"])
    production = database_evidence(saved_projection())
    return {
        "source": "local-preflight-read",
        "localProjectionDigest": local["projectionDigest"],
        "productionFixtureProjectionDigest": production["projectionDigest"],
        "equal": local["projectionDigest"] == production["projectionDigest"],
        "localProjectionShape": sorted(local["projection"]),
        "productionProjectionShape": sorted(production["projection"]),
    }


def child(output: Path, nonce: str) -> None:
    origin = local_origin("http://" + os.environ["FIRESTORE_EMULATOR_HOST"])
    save(
        output / "instance.json",
        {
            "parentPid": os.getppid(),
            "pid": os.getpid(),
            "argv": sys.argv,
            "nonce": nonce,
            "project": PROJECT,
            "firestoreOrigin": origin,
        },
    )
    baseline = local_baseline(origin, nonce)
    plan = gate_plan(
        nonce, baseline_projection_digest=baseline["localProjectionDigest"]
    )
    create(output / "gate", plan)
    gate = ConfigurationGate(output / "gate")
    result = collect(
        nonce, loopback_transport(origin), output / "collection", gate=gate
    )
    save(
        output / "child-result.json",
        {
            "kind": "fs-config-lifecycle-local-child-v1",
            "campaignId": CASE_ID,
            "nonce": nonce,
            "baseline": baseline,
            "gatePlanDigest": digest(plan),
            "gateSnapshot": gate.snapshot(),
            "collection": result,
        },
    )


def run(output: Path, artifact: Path, *, timeout: int = 900) -> dict[str, Any]:
    import broad

    if subprocess.check_output(
        ["git", "status", "--porcelain"], cwd=ROOT, text=True
    ).strip():
        raise ValueError("local rehearsal requires a committed tree")
    commit = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
    ).strip()
    artifact = artifact.resolve()
    if (
        artifact.is_symlink()
        or not artifact.is_file()
        or not os.access(artifact, os.X_OK)
    ):
        raise ValueError("executable fireemu artifact required")
    artifact_sha = hashlib.sha256(artifact.read_bytes()).hexdigest()
    output.mkdir(parents=True, exist_ok=False, mode=0o700)
    import uuid

    nonce = uuid.uuid4().hex
    config = output / "config.json"
    save(
        config,
        {
            "schemaVersion": 1,
            "profile": "strict",
            "firestore": {"edition": "standard", "apiMode": "native"},
        },
    )
    command = [
        str(artifact),
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
    ]
    report: dict[str, Any] = {
        "kind": RECORD_KIND,
        "campaignId": CASE_ID,
        "productionExecuted": False,
        "executionKind": EXECUTION_KIND,
        "formalCompatibilityClaim": False,
        "runtime": {
            "sourceCommit": commit,
            "artifactSha256": artifact_sha,
            "artifactPath": str(artifact.relative_to(ROOT))
            if artifact.is_relative_to(ROOT)
            else "<outside-repository>",
            "nonce": nonce,
            "transport": "loopback",
        },
        "sourceInputs": bound_module_digests(),
    }
    broad.supervise(command, output, nonce, report, timeout=timeout, recovery_grace=1)
    # The shared supervisor verifies the Auth and control listeners of a full run;
    # this run starts Firestore only, so its listener is verified here and the
    # supervisor's partial-result and cases bookkeeping is dropped from the record.
    for key in (
        "cases",
        "recordingComplete",
        "parentManifestSha256",
        "terminationVerificationFailure",
        "partialResultFailure",
        "partialResultSha256",
    ):
        report.pop(key, None)
    owned = report.get("ownedProcess") or {}
    closed = None
    try:
        instance = json.loads((output / "instance.json").read_bytes())
        if instance["nonce"] != nonce:
            raise ValueError("owned process identity mismatch")
        closed = broad.socket_closed(local_origin(instance["firestoreOrigin"]))
    except Exception as error:  # noqa: BLE001 -- recorded, never hidden
        report["listenerVerificationFailure"] = type(error).__name__
    report["ownedProcess"] = {
        "pid": owned.get("pid"),
        "stopped": owned.get("stopped"),
        "firestoreListenerClosed": closed,
    }
    child_path = output / "child-result.json"
    if not child_path.is_file() or not (owned.get("stopped") and closed):
        report["status"] = "incomplete"
        save(output / "local-rehearsal.json", report)
        return report
    child_result = json.loads(child_path.read_bytes())
    collection = child_result["collection"]
    expected = {case["id"]: case["expectedLocal"] for case in compile_cases(nonce)}
    report.update(
        status="completed" if collection["cleanupComplete"] else "incomplete",
        baseline=child_result["baseline"],
        gatePlanDigest=child_result["gatePlanDigest"],
        collection=collection,
        expectedLocalDeviations=[
            {
                "case": case_id,
                "reason": item.get("refusalReason"),
                "observed": next(
                    (
                        row["typedError"]
                        for row in collection["rows"]
                        if row["case"] == case_id and row["role"] == "case"
                    ),
                    None,
                ),
            }
            for case_id, item in expected.items()
            if item["outcome"] == "not-served"
        ],
        summary={
            "observedCases": collection["observedCases"],
            "refusedApplies": collection["refusedApplies"],
            "restore": {
                name: step["restore"] for name, step in collection["steps"].items()
            },
            "chargedRequests": collection["chargedRequests"],
            "cleanupComplete": collection["cleanupComplete"],
            "stopPoint": collection["stopPoint"],
        },
    )
    save(output / "local-rehearsal.json", report)
    return report


def publish(output: Path, target: Path) -> Path:
    record = json.loads((output / "local-rehearsal.json").read_bytes())
    if record.get("status") != "completed":
        raise ValueError("only a completed rehearsal is published")
    if target.exists() or target.is_symlink():
        raise ValueError(
            "versioned records are never overwritten; choose a new version"
        )
    if bound_module_digests() != record["sourceInputs"]:
        raise ValueError("lane modules changed since the rehearsal ran")
    target.write_text(
        json.dumps(record, indent=2, sort_keys=True, allow_nan=False) + "\n"
    )
    return target


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--output", type=Path)
    mode.add_argument("--child", type=Path)
    parser.add_argument("--nonce")
    parser.add_argument("--artifact", type=Path)
    parser.add_argument("--timeout", type=int, default=900)
    parser.add_argument("--publish-as", type=Path)
    args = parser.parse_args(argv)
    if args.child is not None:
        if not args.nonce:
            parser.error("--nonce is required with --child")
        child(args.child.resolve(), args.nonce)
        return 0
    if args.artifact is None:
        parser.error("--artifact is required with --output")
    report = run(args.output.resolve(), args.artifact, timeout=args.timeout)
    published = None
    if args.publish_as is not None and report.get("status") == "completed":
        published = str(publish(args.output.resolve(), args.publish_as))
    print(
        json.dumps(
            {
                "status": report.get("status"),
                "stopReason": report.get("stopReason"),
                "summary": report.get("summary"),
                "published": published,
            }
        )
    )
    return 0 if report.get("status") == "completed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
