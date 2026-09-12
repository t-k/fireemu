"""Own the exact local artifact/configuration/process measured by the aggregation probe.

The OS process relationship and fresh control-token challenge prevent accidental
daemon mixups. They are not a signature or a defence against a malicious executable.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

from evidence_common import (
    ROOT,
    fingerprint,
    probe_inputs,
    require,
    runtime_inputs,
    save,
    sha,
)

# Generic, dependency-free primitives inlined here so the owned-runner helpers the Auth
# corpora use (build_artifact, control_get, local_addresses) do not transitively import
# the Firestore observation modules (aggregation_corpus/aggregation_probe/probe). The
# Firestore-specific run below imports those lazily, inside the functions that use them.
PROJECT = "fireemu-35fe6"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("credential-bearing requests never follow redirects")


def endpoint(target: str, origin: str | None) -> str:
    """A fixed production endpoint or a bare loopback HTTP origin, nothing else."""
    if target == "production" and origin is None:
        return "https://firestore.googleapis.com"
    url = urllib.parse.urlsplit(origin or "")
    if (
        target != "local"
        or url.scheme != "http"
        or url.hostname not in {"localhost", "127.0.0.1", "::1"}
        or url.username
        or url.password
        or url.path
        or url.query
        or url.fragment
    ):
        raise ValueError(
            "use the fixed production endpoint or a bare loopback HTTP origin"
        )
    return str(origin)

BUILD_COMMAND = ["cargo", "build", "--locked", "-p", "fireemu", "--message-format=json"]


def child_identity_matches(command: str, argv: list[str]) -> bool:
    return command.strip() == " ".join(argv)


def stop_owned_child(output: Path, nonce: str, parent: int) -> None:
    path = output / "instance.json"
    if not path.exists():
        return
    instance = json.loads(path.read_bytes())
    require(
        instance.get("parentPid") == parent and instance.get("nonce") == nonce,
        "refusing cleanup of a different child",
    )
    pid = instance["childPid"]
    require(type(pid) is int and pid > 1, "invalid child PID")
    argv = [
        sys.executable,
        str(Path(__file__).resolve()),
        "--owned-child",
        str(output),
        "--nonce",
        nonce,
    ]
    for sig in [signal.SIGTERM, signal.SIGKILL]:
        state = subprocess.run(
            ["ps", "-p", str(pid), "-o", "comm=", "-o", "args="],
            text=True,
            stdout=subprocess.PIPE,
            check=False,
        )
        if state.returncode != 0 or not state.stdout.strip():
            return
        fields = state.stdout.strip().split(maxsplit=1)
        require(
            len(fields) == 2
            and Path(fields[0]).name.lower().startswith("python")
            and child_identity_matches(fields[1], argv),
            "child PID was reused; refusing to signal",
        )
        try:
            os.kill(pid, sig)
        except ProcessLookupError:
            return
        time.sleep(0.2)
    state = subprocess.run(
        ["ps", "-p", str(pid), "-o", "stat="],
        text=True,
        stdout=subprocess.PIPE,
        check=False,
    )
    require(
        not state.stdout.strip() or state.stdout.strip().startswith("Z"),
        "owned child is still running",
    )


def validate_build(receipt: dict, artifact: str, inputs: dict) -> None:
    require(
        receipt.get("command") == BUILD_COMMAND
        and receipt.get("exitCode") == 0
        and receipt.get("artifactSha256") == artifact
        and receipt.get("inputs") == inputs,
        "build/artifact/runtime input mismatch",
    )


def build_artifact() -> tuple[Path, dict]:
    inputs = runtime_inputs(ROOT)
    completed = subprocess.run(
        BUILD_COMMAND,
        cwd=ROOT,
        env=sanitized_environment(dict(os.environ)),
        text=True,
        stdout=subprocess.PIPE,
        check=True,
        timeout=300,
    )
    messages = [json.loads(line) for line in completed.stdout.splitlines()]
    paths = [
        Path(message["executable"])
        for message in messages
        if message.get("reason") == "compiler-artifact"
        and message.get("target", {}).get("name") == "fireemu"
        and message.get("executable")
    ]
    require(
        len(paths) == 1 and inputs == runtime_inputs(ROOT),
        "build output or input stability mismatch",
    )
    return paths[0], {
        "command": BUILD_COMMAND,
        "exitCode": 0,
        "artifactSha256": sha(paths[0].read_bytes()),
        "inputs": inputs,
        "rustc": subprocess.check_output(
            ["rustc", "--version"], cwd=ROOT, text=True
        ).strip(),
    }


def socket_closed(origin: str) -> bool:
    parsed = urllib.parse.urlsplit(origin)
    try:
        with socket.create_connection((parsed.hostname, parsed.port), timeout=1):
            return False
    except OSError:
        return True


def validate_config(value: dict) -> None:
    from aggregation_corpus import CONFIG

    require(
        value == CONFIG,
        "only the dependency-free reviewed strict configuration is permitted",
    )


def sanitized_environment(environment: dict) -> dict:
    return {
        key: environment[key]
        for key in ["PATH", "HOME", "TMPDIR", "SYSTEMROOT", "LANG", "LC_ALL"]
        if key in environment
    }


def local_addresses(firestore: str, control: str) -> tuple[str, str]:
    origin = endpoint("local", f"http://{firestore}")
    parsed = urllib.parse.urlsplit(control)
    require(parsed.path == "/v1/", "unexpected control path")
    control_origin = endpoint(
        "local",
        urllib.parse.urlunsplit(
            (parsed.scheme, parsed.netloc, "", parsed.query, parsed.fragment)
        ),
    )
    require(
        bool(urllib.parse.urlsplit(origin).port) and bool(parsed.port),
        "missing bound ephemeral port",
    )
    return origin, control_origin


def control_get(origin: str, path: str, token: str) -> tuple[int, dict]:
    req = urllib.request.Request(
        origin + path,
        headers={"Origin": "http://127.0.0.1", "Authorization": f"Bearer {token}"},
    )
    try:
        response = urllib.request.build_opener(
            NoRedirect(), urllib.request.ProxyHandler({})
        ).open(req, timeout=10)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        raw = response.read(1024 * 1024 + 1)
        require(len(raw) <= 1024 * 1024, "control response exceeds budget")
        value = json.loads(raw)
        require(isinstance(value, dict), "control response is not an object")
        if not isinstance(response.status, int):
            raise TypeError("missing HTTP status")
        return response.status, value


def observation_complete(report: dict) -> bool:
    """Completion is separate from agreement with the immutable corpus expectations."""
    from aggregation_corpus import corpus

    template = corpus()
    ids = [case["id"] for case in template["queries"]] + template["stateCases"]
    cases = report.get("cases", [])
    cleanup = report.get("cleanup", [])
    if (
        "failure" in report
        or not isinstance(cases, list)
        or not all(
            isinstance(case, dict) and type(case.get("passed")) is bool
            for case in cases
        )
        or [case.get("id") for case in cases] != ids
        or not isinstance(cleanup, list)
        or len(cleanup) != 4
        or not all(
            isinstance(row, dict) and row.get("confirmedMissing") is True
            for row in cleanup
        )
    ):
        return False
    return report.get("status") == (
        "passed" if all(case["passed"] for case in cases) else "failed"
    )


def owned_child(directory: Path, nonce: str) -> None:
    from aggregation_probe import observe

    instance = {"parentPid": os.getppid(), "childPid": os.getpid(), "nonce": nonce}
    save(directory / "instance.json", instance)
    firestore, control = local_addresses(
        os.environ["FIRESTORE_EMULATOR_HOST"], os.environ["FIREEMU_CONTROL_URL"]
    )
    require(os.environ["GOOGLE_CLOUD_PROJECT"] == PROJECT, "wrong inherited project")
    token = os.environ["FIREEMU_CONTROL_TOKEN"]
    status, resources = control_get(control, "/v1/sessions/default/resources", token)
    wrong, _ = control_get(
        control, "/v1/sessions/default/resources", token + "-invalid"
    )
    require(
        status == 200 and wrong == 403 and resources.get("project") == PROJECT,
        "fresh control instance challenge failed",
    )
    status, caps = control_get(control, "/v1/capabilities", token)
    require(
        status == 200 and caps.get("profile") == "strict", "runtime profile mismatch"
    )
    instance.update(
        {
            "authorizedStatus": 200,
            "wrongTokenStatus": 403,
            "profile": caps["profile"],
            "version": caps.get("version"),
            "project": resources["project"],
            "firestoreOrigin": firestore,
            "controlOrigin": control,
        }
    )
    save(directory / "instance.json", instance)
    report = observe(
        "local", directory / "observation.json", firestore, "compat_" + nonce
    )
    if not observation_complete(report):
        raise SystemExit(2)


def run_owned(binary: Path, output: Path, build: dict | None = None) -> dict:
    from aggregation_corpus import CONFIG, index_definition

    binary = binary.resolve(strict=True)
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    inputs = runtime_inputs(ROOT)
    tools_before = probe_inputs()
    nonce = uuid.uuid4().hex
    result = {
        "schemaVersion": 2,
        "status": "launch-incomplete",
        "acceptance": "candidate",
    }
    child = None
    with tempfile.TemporaryDirectory(prefix="fireemu-owned-artifact-") as temporary:
        private = Path(temporary)
        artifact = private / "fireemu"
        shutil.copyfile(binary, artifact)
        artifact.chmod(0o500)
        artifact_hash = sha(artifact.read_bytes())
        if build is not None:
            validate_build(build, artifact_hash, inputs)
        config = private / "config.json"
        indexes = {
            "indexes": [{"collectionGroup": "compat_" + nonce, **index_definition()}],
            "fieldOverrides": [],
        }
        save(private / "indexes.json", indexes)
        index_hash = sha((private / "indexes.json").read_bytes())
        (private / "indexes.json").chmod(0o400)
        validate_config(CONFIG)
        save(config, CONFIG)
        config_hash = sha(config.read_bytes())
        config.chmod(0o400)
        environment = sanitized_environment(dict(os.environ))
        argv = [
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
            "--owned-child",
            str(output),
            "--nonce",
            nonce,
        ]
        try:
            version = (
                subprocess.check_output(
                    [str(artifact), "--version"],
                    cwd=private,
                    env=environment,
                    text=True,
                    timeout=10,
                    stderr=subprocess.DEVNULL,
                )
                .strip()
                .split()[-1]
            )
            # Local child logs are suppressed; errors in receipts are sanitized identifiers.
            child = subprocess.Popen(
                argv,
                cwd=private,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            code = child.wait(timeout=180)
            if (output / "observation.json").exists():
                result = json.loads((output / "observation.json").read_text())
            instance = json.loads((output / "instance.json").read_text())
            require(
                instance["parentPid"] == child.pid and instance["nonce"] == nonce,
                "child belongs to another daemon",
            )
            require(
                instance["version"] == version
                and instance["profile"] == CONFIG["profile"],
                "artifact/runtime identity mismatch",
            )
            require(
                sha(artifact.read_bytes()) == artifact_hash
                and sha(config.read_bytes()) == config_hash
                and sha((private / "indexes.json").read_bytes()) == index_hash,
                "launch input changed during measurement",
            )
            require(
                inputs == runtime_inputs(ROOT) and tools_before == probe_inputs(),
                "source changed during measurement",
            )
            closed = all(
                socket_closed(instance[key])
                for key in ["firestoreOrigin", "controlOrigin"]
            )
            require(
                closed, "owned listener still accepts connections after supervisor exit"
            )
            result.update(
                {
                    "connection": "owned-artifact",
                    "instance": instance,
                    "artifact": {
                        "sha256": artifact_hash,
                        "version": version,
                        "kind": "local-binary",
                        "platform": sys.platform,
                        "python": sys.version.split()[0],
                    },
                    "build": build,
                    "runtimeSource": {
                        "commit": subprocess.check_output(
                            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
                        ).strip(),
                        "files": inputs,
                        "relationship": "built-by-recorder"
                        if build is not None
                        else "source-inputs-recorded; build attestation is separate",
                    },
                    "configuration": {
                        "value": CONFIG,
                        "sha256": fingerprint(CONFIG),
                        "fileSha256": config_hash,
                        "indexes": indexes,
                        "indexFileSha256": index_hash,
                        "effectiveProfile": instance["profile"],
                        "basis": "owned immutable launch inputs plus runtime profile readback",
                    },
                    "ownedProcess": {
                        "pid": child.pid,
                        "exitCode": code,
                        "stopped": child.poll() is not None,
                        "listenersClosed": closed,
                        "launch": {
                            "command": "exec",
                            "project": PROJECT,
                            "only": "firestore",
                            "ports": "OS-assigned",
                            "configurationSha256": fingerprint(CONFIG),
                        },
                    },
                }
            )
            require(
                code == 0 and observation_complete(result),
                "owned corpus did not complete",
            )
        except Exception as error:  # noqa: BLE001 -- preserve sanitized failure and stop the owned process.
            result["status"] = "owned-run-failed"
            result["failure"] = type(error).__name__
        finally:
            if child is not None and child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=20)
                except subprocess.TimeoutExpired:
                    try:
                        stop_owned_child(output, nonce, child.pid)
                    except Exception as error:  # noqa: BLE001 -- still reap our supervisor on identity refusal.
                        result["childCleanupFailure"] = type(error).__name__
                    finally:
                        child.kill()
                        child.wait(timeout=10)
                    result["cleanupFailure"] = (
                        "supervisor did not finish graceful descendant cleanup"
                    )
            if child is not None:
                try:
                    stop_owned_child(output, nonce, child.pid)
                except Exception as error:  # noqa: BLE001 -- do not hide the recovery receipt.
                    result["cleanupFailure"] = type(error).__name__
                    result["status"] = "owned-run-failed"
            save(output / "local.json", result)
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--build", action="store_true")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--owned-child", type=Path)
    parser.add_argument("--nonce")
    args = parser.parse_args()
    if args.owned_child:
        try:
            owned_child(args.owned_child, args.nonce)
        except Exception:  # noqa: BLE001 -- control token errors must never reach logs.
            raise SystemExit("Owned child failed before completing evidence") from None
    elif (args.binary or args.build) and args.output:
        if args.binary and args.build:
            parser.error(
                "--build selects its own artifact; do not also specify --binary"
            )
        binary, build = build_artifact() if args.build else (args.binary, None)
        result = run_owned(binary, args.output, build)
        if result["status"] != "passed":
            raise SystemExit("Owned artifact run failed; inspect private candidate")
        print(
            f"Owned artifact: {len(result['cases'])} cases passed; process stopped and fixtures absent"
        )
    else:
        parser.error("use --binary/--output or --owned-child/--nonce")


if __name__ == "__main__":
    main()
