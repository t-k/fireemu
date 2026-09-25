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
import credential_prep
from batch_contract import NUMBER, PROJECT, database_evidence
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
SHADOW_ADC = {
    "type": "authorized_user",
    "client_id": "local-client.apps.googleusercontent.com",
    "client_secret": "synthetic-client-secret",
    "refresh_token": "synthetic-refresh-secret",
}
SHADOW_PRINCIPAL = {
    "clientId": SHADOW_ADC["client_id"],
    "requiredScopes": [credential_prep.SCOPE],
}


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

    payloads["credentialRequests"] = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            from urllib.parse import parse_qs, urlsplit

            target = urlsplit(self.path)
            count = len(payloads["credentialRequests"])
            size = int(self.headers.get("Content-Length", "0"))
            if size > credential_prep.MAX_BYTES:
                self.send_error(413)
                return
            form = parse_qs(self.rfile.read(size).decode())
            if (
                count == 0
                and target.path == "/token"
                and form
                == {
                    "grant_type": ["refresh_token"],
                    "client_id": [SHADOW_ADC["client_id"]],
                    "client_secret": [SHADOW_ADC["client_secret"]],
                    "refresh_token": [SHADOW_ADC["refresh_token"]],
                }
            ):
                result = {
                    "access_token": "synthetic-access-secret",
                    "token_type": "Bearer",
                    "expires_in": 3600,
                }
            elif (
                count == 1
                and target.path == "/oauth2/v1/tokeninfo"
                and parse_qs(target.query)
                == {"access_token": ["synthetic-access-secret"]}
                and not form
            ):
                result = {
                    "issued_to": SHADOW_ADC["client_id"],
                    "scope": credential_prep.SCOPE,
                    "expires_in": 3599,
                }
            else:
                self.send_error(400)
                return
            payloads["credentialRequests"].append(target.path)
            body = json.dumps(result).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

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


def validate_kernel_addresses(addresses, port):
    import ipaddress

    if not isinstance(addresses, list) or not addresses:
        raise ValueError("kernel listener addresses required")
    for address in addresses:
        host, separator, observed_port = address.rpartition(":")
        if (
            not separator
            or observed_port != str(port)
            or not ipaddress.ip_address(host.strip("[]")).is_loopback
        ):
            raise ValueError("kernel listener must be loopback on the exact port")


def listener_owner(origin, pid):
    """Retain a live kernel listener observation for the exact owned process."""
    from urllib.parse import urlsplit

    port = urlsplit(origin).port
    if type(pid) is not int or pid <= 1 or port is None:
        raise ValueError("owned listener identity required")
    result = subprocess.run(
        [
            "lsof",
            "-nP",
            "-a",
            "-p",
            str(pid),
            "-iTCP:" + str(port),
            "-sTCP:LISTEN",
            "-Fpn",
        ],
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )
    records = result.stdout.splitlines()
    if (
        result.returncode != 0
        or "p" + str(pid) not in records
        or not any(
            line.startswith("n") and line.endswith(":" + str(port)) for line in records
        )
    ):
        raise ValueError("owned process does not hold the expected listener")
    addresses = [line[1:] for line in records if line.startswith("n")]
    validate_kernel_addresses(addresses, port)
    return {
        "pid": pid,
        "kernelAddresses": addresses,
        "origin": origin,
        "port": port,
        "listening": True,
        "observedAt": time.time(),
    }


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
        instance["listenerOwners"] = {
            "firestoreOrigin": listener_owner(firestore, os.getppid()),
            "controlOrigin": listener_owner(control, os.getppid()),
            "metadataOrigin": listener_owner(origin, os.getpid()),
        }
        stream_bridge.write_private_json(output / "instance.json", instance)
        permission = {
            "kind": "local-stream-shadow-only",
            "credentialMode": credential_prep.MODE,
            "credentialPreparationDigest": digest(credential_prep.contract()),
            "credentialPrincipal": SHADOW_PRINCIPAL,
            "authorizedUserDigest": digest(SHADOW_ADC),
            "apiKeyDigest": digest("local-shadow-only"),
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
        locks = production.resource_locks(plan)
        budget = {
            "requests": 35,
            "accounts": 0,
            "resources": 3,
            "costMicrousd": credential_prep.OUTER_COST_MICROUSD,
        }
        envelope = {
            "permissionDigest": digest(permission),
            "issuedAt": time.time() - 1,
            "expiresAt": permission["expiresAt"],
            "limits": budget,
            "concurrency": 1,
            "scopes": locks,
        }
        claim = {
            "campaignId": "FS-WRITE-TXN-PRECEDENCE-01",
            "manifestDigest": digest(plan),
            "nonceDigest": digest(nonce),
            "gatePath": str(execution / "gate"),
            "gatePlanDigest": digest(plan),
            "locks": locks,
            "budget": budget,
            "durationSeconds": credential_prep.OUTER_SECONDS,
        }
        ticket = ledger.reserve(envelope, claim, plan)
        stream_bridge.write_private_json(
            execution / "inputs.json",
            {
                "permission": permission,
                "plan": plan,
                "claim": claim,
                "envelope": envelope,
                "ticket": ticket,
            },
        )
        try:
            credential, preparation_proof = credential_prep.prepare_credentials(
                execution,
                ledger,
                ticket,
                permission,
                plan,
                {
                    "kind": "stream-o8-authorized-user-v1",
                    "permissionDigest": digest(permission),
                    "adc": SHADOW_ADC,
                    "apiKey": "local-shadow-only",
                },
                fixture_origin=origin,
            )
        except Exception as error:  # noqa: BLE001 -- Local synthetic setup retains reservation responsibility.
            production.retained_failure(
                execution, ledger, ticket, error, production=False
            )
            raise ValueError("owned synthetic preparation failed") from None
        result = production.execute_session(
            plan,
            permission,
            execution,
            ledger,
            ticket,
            "local-shadow-only",
            credential,
            shadow={"metadataOrigin": origin, "port": int(firestore.rsplit(":", 1)[1])},
            preparation_proof=preparation_proof,
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
    if owned.get("pricingSdk") != production.pricing_sdk_binding():
        raise ValueError("owned pricing SDK source binding differs")
    listeners = instance.get("listenerOwners", {})
    if set(listeners) != {"firestoreOrigin", "controlOrigin", "metadataOrigin"}:
        raise ValueError("all owned listener observations required")
    for key, proof in listeners.items():
        expected_pid = instance["childPid"] if key == "metadataOrigin" else owned["pid"]
        if (
            proof.get("pid") != expected_pid
            or proof.get("origin") != instance[key]
            or proof.get("listening") is not True
            or type(proof.get("observedAt")) not in (float, int)
        ):
            raise ValueError("live owned listener binding differs")
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
    pricing_sdk = production.pricing_sdk_binding()
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
            "pricingSdk": pricing_sdk,
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
        production.write_atomic_receipt(output / "receipt.json", result)
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
