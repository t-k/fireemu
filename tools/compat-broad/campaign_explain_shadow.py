"""Collect the six-case offline campaign from an owned, built fireemu process."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shlex
import signal
import subprocess
import sys
from pathlib import Path

# Import broad first: it installs the repository's inventory helper search path.
import broad
from batch_adapter import Adapter, candidate
from batch_contract import NUMBER, PROJECT
from broad_contract import digest, local_origin
from campaign_explain import (
    Gate,
    bind_receipt,
    binding,
    campaign_manifest,
    campaign_observer_digest,
    configuration,
    manifest_digest,
    shadow_hashes,
    validate_envelope,
)
from owned_runner import control_get, local_addresses
from shared_cases import run_scenario, save
from shared_gate import create


def child(output: Path, nonce: str) -> None:
    auth = local_origin("http://" + os.environ["FIREBASE_AUTH_EMULATOR_HOST"])
    firestore, control = local_addresses(
        os.environ["FIRESTORE_EMULATOR_HOST"], os.environ["FIREEMU_CONTROL_URL"]
    )
    token = os.environ["FIREEMU_CONTROL_TOKEN"]
    status, resources = control_get(control, "/v1/sessions/default/resources", token)
    wrong, _ = control_get(control, "/v1/sessions/default/resources", token + "-wrong")
    if (
        status != 200
        or wrong != 403
        or resources.get("project") != PROJECT
        or os.environ["GOOGLE_CLOUD_PROJECT"] != PROJECT
    ):
        raise ValueError("owned campaign instance identity mismatch")
    argv = shlex.split(
        subprocess.check_output(
            ["ps", "-ww", "-p", str(os.getppid()), "-o", "args="], text=True
        ).strip()
    )
    config_path = Path(argv[argv.index("--config") + 1])
    actual_config = json.loads(config_path.read_bytes())
    save(
        output / "instance.json",
        {
            "pid": os.getpid(),
            "parentPid": os.getppid(),
            "argv": sys.argv,
            "nonce": nonce,
            "project": PROJECT,
            "authOrigin": auth,
            "firestoreOrigin": firestore,
            "controlOrigin": control,
            "wrongTokenStatus": wrong,
            "parentArgv": argv,
            "artifactPath": argv[0],
            "artifactSha256": hashlib.sha256(Path(argv[0]).read_bytes()).hexdigest(),
            "configurationPath": str(config_path),
            "configuration": actual_config,
            "indexSha256": hashlib.sha256(
                Path(actual_config["firestore"]["indexFile"]).read_bytes()
            ).hexdigest(),
        },
    )
    origins = {"auth": auth, "firestore": firestore}
    plan = {**campaign_manifest(nonce), "localOrigins": origins}
    create(output / "gate", plan)
    gate = Gate(output / "gate", "query-explain")
    gate.claim()
    adapter = Adapter(candidate(), nonce, output / "worker", local_origins=origins)
    adapter.shared_gate = gate
    receipt = run_scenario(adapter, plan, "query-explain")
    bind_receipt(receipt, gate.snapshot(), adapter)
    complete = (
        receipt["recordingComplete"]
        and receipt["cleanupComplete"]
        and receipt["lifecycleStateVerified"]
    )
    save(
        output / "cases.json",
        {
            # Preserve each receipt invariant independently.  The supervisor
            # uses stateValidation to distinguish a complete observation from
            # an incomplete handoff, while semantic mismatches remain eligible
            # for comparison when recording and cleanup are complete.
            "recordingComplete": receipt["recordingComplete"],
            "collectionComplete": receipt["collectionComplete"],
            "cleanupComplete": receipt["cleanupComplete"],
            "stateValidation": receipt["stateValidation"],
            "stateVerified": receipt["stateVerified"],
            "lifecycleStateVerified": receipt["lifecycleStateVerified"],
            "safety": receipt["safety"],
            "cases": [
                {"id": row["id"], "status": "observed", "family": "query-explain"}
                for row in receipt["rows"]
            ],
        },
    )
    if not complete:
        raise ValueError("campaign collection/state/cleanup incomplete")


def run(output: Path) -> dict:
    accepted = configuration()
    report = broad.run(
        output,
        child_script=Path(__file__).resolve(),
        project=PROJECT,
        configuration={"daemon": {"authProjectNumbers": {PROJECT: NUMBER}}},
        execution_timeout=1200,
        recovery_grace=300,
    )
    envelope = {
        "kind": "production-campaign-explain-01-local-v2",
        "productionExecuted": False,
        "executionCommit": report["executionCommit"],
        "runtime": report,
        "manifestDigest": manifest_digest(),
        "observerSha256": campaign_observer_digest(),
        "comparisonContractDigest": digest(binding()),
        "configuration": accepted,
        "configurationDigest": digest(accepted),
        "configurationUnchanged": digest(accepted) == digest(configuration())
        and report.get("status") == "completed",
    }
    try:
        envelope.update(
            instance=json.loads((output / "instance.json").read_bytes()),
            gate=json.loads((output / "gate/state.json").read_bytes()),
            receipt=json.loads((output / "worker/result.json").read_bytes()),
        )
        envelope["nonce"] = envelope["instance"]["nonce"]
        envelope["fileDigests"] = {
            name: digest(envelope[key])
            for name, key in (
                ("manifest.json", "runtime"),
                ("instance.json", "instance"),
                ("gate/state.json", "gate"),
                ("worker/result.json", "receipt"),
            )
        }
        envelope.update(
            cleanupComplete=envelope["receipt"]["cleanupComplete"],
            recordingComplete=envelope["receipt"]["recordingComplete"],
            stateVerified=envelope["receipt"]["stateVerified"],
            completed=report["status"] == "completed",
            failure=envelope["receipt"]["failure"],
        )
        validate_envelope(envelope, local=True, directory=output)
    except (ValueError, KeyError, OSError) as error:
        envelope.update(completed=False, cleanupComplete=False, failure=str(error))
    save(output / "result.json", envelope)
    save(output / "artifact.json", report["build"])
    save(output / "process.json", report["ownedProcess"])
    (output / "batch").mkdir(mode=0o700, exist_ok=True)
    save(output / "batch/result.json", envelope.get("receipt", {}))
    save(output / "shadow-hashes.json", shadow_hashes(output))
    return envelope


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--child", type=Path)
    parser.add_argument("--nonce")
    args = parser.parse_args()
    if args.child and args.nonce:
        child(args.child.resolve(), args.nonce)
        return 0
    if not args.output or args.nonce:
        parser.error("--output required; nonce is generated by the owned supervisor")
    result = run(args.output.resolve())
    print(
        json.dumps(
            {
                "completed": result["completed"],
                "ownedProcess": result["runtime"]["ownedProcess"],
                "failure": result.get("failure"),
            }
        )
    )
    return 0 if result["completed"] else 2


if __name__ == "__main__":

    def interrupted(_signum, _frame):
        raise InterruptedError("stop requested; unwind owned campaign cleanup")

    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGHUP, interrupted)
    raise SystemExit(main())
