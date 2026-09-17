"""Own one retained artifact and record a complete local stream outer acquisition."""

from __future__ import annotations

import argparse
import contextlib
import http.server
import json
import os
import shutil
import signal
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path

# ruff: noqa: I001 -- Production bootstraps sibling imports for direct CLI execution.
import stream_production as production
import stream_bridge
from batch_contract import NUMBER, PROJECT, Credential, database_evidence
from broad_contract import digest
from evidence_common import runtime_inputs
from owned_runner import (
    control_get,
    local_addresses,
    reject_mutation_artifact,
    sanitized_environment,
    socket_closed,
    validate_build,
)
from reservations import Ledger

CONFIG = {"schemaVersion": 1, "profile": "strict"}


@contextlib.contextmanager
def metadata_fixture():
    """Owned HTTP fixture; never used by the fixed production entrypoint."""
    payloads = {
        "project": {"projectId": PROJECT, "projectNumber": NUMBER},
        "database": {
            "name": f"projects/{PROJECT}/databases/(default)",
            "uid": "stream-local-metadata",
            "databaseEdition": "STANDARD",
            "type": "FIRESTORE_NATIVE",
            "locationId": "us-central1",
        },
        "auth": {
            "name": f"projects/{PROJECT}/config",
            "signIn": {"email": {"enabled": True}},
        },
        "key": {
            "parent": f"projects/{NUMBER}/locations/global",
            "name": f"projects/{NUMBER}/locations/global/keys/stream-local",
        },
    }

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            body = json.dumps(payloads[self.path.removeprefix("/")]).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", payloads
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        if thread.is_alive():
            raise ValueError("owned metadata listener did not close")


def child(output, nonce):
    stream_bridge.write_private_json(
        output / "child-identity.json",
        {
            "parentPid": os.getppid(),
            "childPid": os.getpid(),
            "argv": [sys.executable, *sys.argv],
            "nonce": nonce,
        },
    )
    firestore, control = local_addresses(
        os.environ["FIRESTORE_EMULATOR_HOST"], os.environ["FIREEMU_CONTROL_URL"]
    )
    token = os.environ["FIREEMU_CONTROL_TOKEN"]
    good, resources = control_get(control, "/v1/sessions/default/resources", token)
    bad, _ = control_get(control, "/v1/sessions/default/resources", token + "-wrong")
    caps_status, caps = control_get(control, "/v1/capabilities", token)
    if (
        good != 200
        or bad != 403
        or resources.get("project") != PROJECT
        or os.environ["GOOGLE_CLOUD_PROJECT"] != PROJECT
        or caps_status != 200
        or caps.get("profile") != "strict"
    ):
        raise ValueError("owned artifact challenge failed")
    with metadata_fixture() as (origin, payloads):
        instance = {
            "parentPid": os.getppid(),
            "childPid": os.getpid(),
            "argv": [sys.executable, *sys.argv],
            "nonce": nonce,
            "project": PROJECT,
            "profile": caps["profile"],
            "version": caps["version"],
            "authorizedStatus": good,
            "wrongTokenStatus": bad,
            "firestoreOrigin": firestore,
            "controlOrigin": control,
            "metadataOrigin": origin,
        }
        stream_bridge.write_private_json(output / "instance.json", instance)
        permission = {
            "kind": "local-stream-shadow-only",
            "project": PROJECT,
            "nonce": nonce,
            "expiresAt": time.time() + 1800,
            "collectorSourceDigest": stream_bridge.source_digest(),
            "authConfigDigest": digest(payloads["auth"]),
            "databaseProjectionDigest": database_evidence(payloads["database"])[
                "projectionDigest"
            ],
            "pricingLocation": "us-central1",
        }
        plan = production.prepared_plan(nonce, "shadow-" + nonce, digest(permission))
        execution = output / "execution"
        execution.mkdir(mode=0o700)
        ledger = Ledger.create(output / "ledger")
        scope = {
            "key": f"project/{PROJECT}/firestore/(default)/documents/{plan['documentPrefix']}",
            "mode": "EXCLUSIVE",
        }
        budget = {"requests": 33, "accounts": 0, "resources": 3, "costMicrousd": 3300}
        envelope = {
            "permissionDigest": digest(permission),
            "issuedAt": time.time() - 1,
            "expiresAt": permission["expiresAt"],
            "limits": budget,
            "concurrency": 1,
            "scopes": [scope],
        }
        claim = {
            "campaignId": nonce,
            "manifestDigest": digest(plan),
            "nonceDigest": digest(nonce),
            "gatePath": str(execution / "gate"),
            "gatePlanDigest": digest(plan),
            "locks": [scope],
            "budget": budget,
            "durationSeconds": 1100,
        }
        ticket = ledger.reserve(envelope, claim, plan)
        credential = Credential()
        credential.accept("local-shadow-only", {"expires_in": 1800}, time.monotonic())
        result = production.execute_session(
            plan,
            permission,
            execution,
            ledger,
            ticket,
            "local-shadow-only",
            credential,
            shadow={"metadataOrigin": origin, "port": int(firestore.rsplit(":", 1)[1])},
        )
        if not result["acquisitionValidated"]:
            raise ValueError("owned stream acquisition failed")


def stop_child(instance, parent_pid):
    if (
        instance.get("parentPid") != parent_pid
        or type(instance.get("childPid")) is not int
        or instance["childPid"] <= 1
    ):
        raise ValueError("owned child identity differs")
    pid = instance["childPid"]
    expected = " ".join(instance["argv"])
    for signum in (signal.SIGTERM, signal.SIGKILL):
        result = subprocess.run(
            ["ps", "-p", str(pid), "-o", "comm=", "-o", "args="],
            text=True,
            capture_output=True,
            check=False,
        )
        fields = result.stdout.strip().split(maxsplit=1)
        if not fields:
            return
        if (
            len(fields) != 2
            or fields[1] != expected
            or Path(fields[0]).name.lower() != Path(instance["argv"][0]).name.lower()
        ):
            raise ValueError("owned child process changed")
        os.kill(pid, signum)
        time.sleep(0.2)


def validate_owned_receipt(receipt, artifact_sha):
    owned = receipt.get("ownedArtifact", {})
    instance = owned.get("instance", {})
    if (
        receipt.get("acquisitionValidated") is not True
        or receipt.get("productionExecuted") is not False
        or owned.get("artifactSha256") != artifact_sha
        or owned.get("sourceDigestBefore") != stream_bridge.source_digest()
        or owned.get("sourceDigestAfter") != owned.get("sourceDigestBefore")
        or owned.get("exitCode") != 0
        or owned.get("stopped") is not True
        or owned.get("listenersClosed") is not True
        or instance.get("parentPid") != owned.get("pid")
        or instance.get("nonce") != receipt.get("gate", {}).get("plan", {}).get("nonce")
        or instance.get("authorizedStatus") != 200
        or instance.get("wrongTokenStatus") != 403
        or instance.get("project") != PROJECT
        or instance.get("profile") != "strict"
        or instance.get("version") != owned.get("version")
        or owned.get("configuration") != CONFIG
        or owned.get("configurationDigest") != digest(CONFIG)
    ):
        raise ValueError("owned artifact acquisition binding incomplete")
    validate_build(
        owned.get("build", {}), artifact_sha, runtime_inputs(production.ROOT)
    )


def run_shadow(artifact, build_manifest, output):
    artifact = Path(artifact).resolve(strict=True)
    reject_mutation_artifact(artifact)
    artifact_sha = production.sha_file(artifact)
    build = production.load_json(build_manifest)["build"]
    inputs = runtime_inputs(production.ROOT)
    validate_build(build, artifact_sha, inputs)
    commit = production.checkout_binding()
    source = stream_bridge.source_digest()
    output = Path(output).resolve()
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    retained = output / "fireemu"
    shutil.copyfile(artifact, retained)
    retained.chmod(0o500)
    config = output / "config.json"
    stream_bridge.write_private_json(config, CONFIG)
    config.chmod(0o400)
    nonce = uuid.uuid4().hex
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
    ]
    environment = sanitized_environment(dict(os.environ))
    version = (
        subprocess.check_output(
            [str(retained), "--version"], env=environment, text=True, timeout=10
        )
        .strip()
        .split()[-1]
    )
    process = None
    instance = {}
    result = {"acquisitionValidated": False, "productionExecuted": False}
    try:
        process = subprocess.Popen(
            argv,
            cwd=output,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        code = process.wait(timeout=1150)
        result["supervisor"] = {
            "exitCode": code,
            "childStarted": (output / "child-identity.json").is_file(),
            "controlVerified": (output / "instance.json").is_file(),
        }
        if not (output / "instance.json").is_file():
            raise ValueError("owned supervisor or child initialization failed")
        instance = production.load_json(output / "instance.json")
        result = production.load_json(output / "execution" / "receipt.json")
        closed = all(
            socket_closed(instance[key])
            for key in ("firestoreOrigin", "controlOrigin", "metadataOrigin")
        )
        owned = {
            "artifactSha256": artifact_sha,
            "version": version,
            "build": build,
            "executionCommit": commit,
            "sourceDigestBefore": source,
            "sourceDigestAfter": stream_bridge.source_digest(),
            "configuration": CONFIG,
            "configurationDigest": digest(CONFIG),
            "instance": instance,
            "pid": process.pid,
            "exitCode": code,
            "stopped": process.poll() is not None,
            "listenersClosed": closed,
        }
        result["ownedArtifact"] = owned
        if (
            production.sha_file(retained) != artifact_sha
            or production.load_json(config) != CONFIG
            or runtime_inputs(production.ROOT) != inputs
        ):
            raise ValueError("owned launch inputs changed")
        validate_owned_receipt(result, artifact_sha)
    except Exception as error:  # noqa: BLE001 -- Preserve sanitized diagnostics and always reap owned processes.
        result["acquisitionValidated"] = False
        result["shadowFailure"] = type(error).__name__
    finally:
        if process is not None:
            try:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=20)
                    except subprocess.TimeoutExpired:
                        pass
                if (output / "child-identity.json").exists():
                    stop_child(
                        production.load_json(output / "child-identity.json"),
                        process.pid,
                    )
            except Exception as error:  # noqa: BLE001 -- Retain cleanup uncertainty.
                result["acquisitionValidated"] = False
                result["cleanupFailure"] = type(error).__name__
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=5)
        stream_bridge.write_private_json(output / "receipt.json", result)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact", type=Path)
    parser.add_argument("--build-manifest", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--child", type=Path)
    parser.add_argument("--nonce")
    args = parser.parse_args(argv)
    if args.child:
        child(args.child.resolve(), args.nonce)
        return 0
    if not all((args.artifact, args.build_manifest, args.output)):
        parser.error("artifact, build-manifest and output are required")
    return (
        0
        if run_shadow(args.artifact, args.build_manifest, args.output)[
            "acquisitionValidated"
        ]
        else 1
    )


if __name__ == "__main__":

    def interrupted(_signum, _frame):
        raise InterruptedError("owned shadow interrupted")

    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGHUP, interrupted)
    raise SystemExit(main())
