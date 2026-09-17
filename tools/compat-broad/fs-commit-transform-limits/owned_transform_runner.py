"""Execute the fixed O3 plan on one pinned retained artifact, on owned loopback."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import uuid
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(ROOT / "tools/compat-inventory"))

import broad
from broad_contract import digest, local_origin
from local_collector import collect_local
from local_transport import TRANSPORT, local_executor, save_new, verify_wire_journal
from owned_runner import control_get, local_addresses
from transform_comparator import _exact, compare_rows
from transform_compiler import compile_plan

ARTIFACT_SHA = "be2771b9f2093cced55e8158d8d5a72ed35e6ac5e32edddb068daa45511e12ae"
RUNTIME_COMMIT = "cce4a4f9b7369938c89bd32a5106e8d3cab59f83"
PROJECT = "demo-firestore-probe"
CONFIGURATION = {
    "schemaVersion": 1,
    "profile": "strict",
    "firestore": {"edition": "standard", "apiMode": "native"},
    "daemon": {"authProjectNumbers": {}},
}


def sha_file(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def validate_retained_artifact(artifact: Path, manifest_path: Path) -> dict:
    """Validate the authorized saved artifact, never build or accept arbitrary code."""
    if artifact.is_symlink() or manifest_path.is_symlink():
        raise ValueError("retained inputs must be regular files")
    manifest = json.loads(manifest_path.read_bytes())
    build = manifest.get("build", {})
    if (
        manifest.get("sourceCommit") != RUNTIME_COMMIT
        or manifest.get("artifactSha256") != ARTIFACT_SHA
        or build.get("artifactSha256") != ARTIFACT_SHA
        or type(build.get("exitCode")) is not int
        or build["exitCode"] != 0
        or build.get("command")
        != ["cargo", "build", "--locked", "-p", "fireemu", "--message-format=json"]
        or not isinstance(build.get("inputs"), dict)
        or not build["inputs"]
        or sha_file(artifact) != ARTIFACT_SHA
    ):
        raise ValueError("retained artifact/build/source binding differs")
    return {
        "artifactSha256": ARTIFACT_SHA,
        "runtimeSourceCommit": RUNTIME_COMMIT,
        "retainedManifestSha256": sha_file(manifest_path),
        "runtimeInputsDigest": digest(build["inputs"]),
    }


def source_inputs() -> dict:
    inputs = broad.source_inputs()
    inputs.update(
        {
            str(path.relative_to(ROOT)): sha_file(path)
            for path in sorted(HERE.glob("*.py"))
        }
    )
    inputs[str(TRANSPORT.relative_to(ROOT))] = sha_file(TRANSPORT)
    return inputs


def child(output: Path, nonce: str) -> None:
    inputs = json.loads((output / "run-inputs.json").read_bytes())
    plan = compile_plan(PROJECT, "(default)", nonce)
    if (
        inputs["nonce"] != nonce
        or inputs["project"] != PROJECT
        or inputs["sourceInputs"] != source_inputs()
        or not _exact(json.loads((output / "plan.json").read_bytes()), plan)
        or inputs["planDigest"] != plan["planDigest"]
        or inputs["configurationDigest"] != sha_file(output / "config.json")
        or not _exact(json.loads((output / "config.json").read_bytes()), CONFIGURATION)
    ):
        raise ValueError("child source/plan/configuration binding differs")
    auth = local_origin("http://" + os.environ["FIREBASE_AUTH_EMULATOR_HOST"])
    firestore, control = local_addresses(
        os.environ["FIRESTORE_EMULATOR_HOST"], os.environ["FIREEMU_CONTROL_URL"]
    )
    local_origin(firestore)
    local_origin(control)
    save_new(
        output / "instance.json",
        {
            "parentPid": os.getppid(),
            "pid": os.getpid(),
            "argv": sys.argv,
            "nonce": nonce,
            "project": PROJECT,
            "authOrigin": auth,
            "firestoreOrigin": firestore,
            "controlOrigin": control,
        },
    )
    token = os.environ["FIREEMU_CONTROL_TOKEN"]
    status, resources = control_get(control, "/v1/sessions/default/resources", token)
    wrong, _ = control_get(control, "/v1/sessions/default/resources", token + "-wrong")
    if (
        status != 200
        or wrong != 403
        or resources.get("project") != PROJECT
        or os.environ.get("GOOGLE_CLOUD_PROJECT") != PROJECT
    ):
        raise ValueError("owned local instance identity differs")
    save_new(
        output / "identity.json",
        {
            "project": PROJECT,
            "status": status,
            "wrongTokenStatus": wrong,
            "controlRequests": 2,
        },
    )
    binding = digest(inputs)
    result = collect_local(
        plan, local_executor(plan, firestore, output / "wire", binding)
    )
    save_new(output / "result.json", result)
    count = verify_wire_journal(plan, result, output / "wire", binding)
    contract = compare_rows(
        plan,
        result["rows"],
        plan,
        result["rows"],
        left_recovery=result["cleanup"],
        right_recovery=result["cleanup"],
    )
    save_new(
        output / "local-contract.json",
        {
            "basis": "Self-validation against the local contract; not an independent or production comparison.",
            "comparison": contract,
        },
    )
    complete = (
        result["recordingComplete"]
        and result["cleanupComplete"]
        and source_inputs() == inputs["sourceInputs"]
    )
    save_new(
        output / "cases.json",
        {
            "schemaVersion": 1,
            "kind": "o3-commit-transform-owned-local-v1",
            "target": "owned-retained-local-artifact",
            "project": PROJECT,
            "productionExecuted": False,
            "formalCompatibilityClaim": False,
            "recordingComplete": complete,
            "stateValidation": complete,
            "manifest": {
                "binding": binding,
                "sourceInputs": inputs["sourceInputs"],
                "dataRequests": count,
            },
            "manifestDigest": binding,
            "cases": [
                {
                    "id": plan["campaignId"],
                    "family": "firestore",
                    "status": "fail"
                    if not complete
                    else "mismatch"
                    if contract["classification"] != "MATCH"
                    else "pass",
                    "basis": "Local contract self-validation, with independent acquisition and promotion still false.",
                }
            ],
        },
    )


def run(output: Path, artifact: Path, retained_manifest: Path) -> dict:
    """Own all listeners and the child through the existing supervisor (OS port 0)."""
    runtime = validate_retained_artifact(artifact, retained_manifest)
    if subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT).strip():
        raise ValueError("freeze the collector checkout before execution")
    before = source_inputs()
    commit = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
    ).strip()
    output.mkdir(parents=True, mode=0o700, exist_ok=False)
    nonce = uuid.uuid4().hex
    plan = compile_plan(PROJECT, "(default)", nonce)
    save_new(output / "plan.json", plan)
    save_new(output / "config.json", CONFIGURATION)
    inputs = {
        **runtime,
        "collectorSourceCommit": commit,
        "sourceInputs": before,
        "nonce": nonce,
        "project": PROJECT,
        "planDigest": plan["planDigest"],
        "configurationDigest": sha_file(output / "config.json"),
        "dataRequestUpperBound": 17,
        "identityControlRequests": 2,
        "productionExecuted": False,
    }
    save_new(output / "run-inputs.json", inputs)
    command = [
        str(artifact),
        "exec",
        "--config",
        str(output / "config.json"),
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
    save_new(output / "command.json", {"argv": command, "binding": digest(inputs)})
    report = {
        **runtime,
        "collectorSourceCommit": commit,
        "productionExecuted": False,
        "formalCompatibilityClaim": False,
    }
    broad.supervise(command, output, nonce, report, timeout=270, recovery_grace=30)
    save_new(output / "supervisor-final.json", report)
    stable = (
        source_inputs() == before
        and validate_retained_artifact(artifact, retained_manifest) == runtime
    )
    files = {
        str(path.relative_to(output)): sha_file(path)
        for path in sorted(output.rglob("*"))
        if path.is_file()
    }
    sealed = {
        "kind": "o3-commit-transform-local-evidence-v1",
        "binding": digest(inputs),
        "files": files,
        "sourceStable": stable,
        "recordingComplete": report["recordingComplete"],
        "ownedProcess": report["ownedProcess"],
        "status": report["status"] if stable else "incomplete",
        "productionExecuted": False,
        "acquisitionValidated": False,
        "promotionReady": False,
    }
    save_new(output / "evidence.json", sealed)
    return sealed


def main() -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--output", type=Path)
    mode.add_argument("--child", type=Path)
    parser.add_argument("--artifact", type=Path)
    parser.add_argument("--retained-manifest", type=Path)
    parser.add_argument("--nonce")
    args = parser.parse_args()
    if args.child:
        if not args.nonce or args.artifact or args.retained_manifest:
            parser.error("child requires only --nonce")
        child(args.child.resolve(), args.nonce)
        return 0
    if not args.artifact or not args.retained_manifest or args.nonce:
        parser.error("output requires --artifact and --retained-manifest")
    result = run(
        args.output.resolve(),
        args.artifact.absolute(),
        args.retained_manifest.absolute(),
    )
    print(
        json.dumps({"status": result["status"], "ownedProcess": result["ownedProcess"]})
    )
    return 0 if result["status"] == "completed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
