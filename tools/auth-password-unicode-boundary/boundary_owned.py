"""Build and own the strict Auth artifact; never attach to an external daemon."""

# ruff: noqa: BLE001 -- Always reap owned processes and sanitize boundary failures.

import argparse
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

from boundary_recorder import (
    PROJECT,
    ROOT,
    complete,
    digest,
    inputs,
    observe,
    origins,
    require,
    save,
)

sys.path.insert(0, str(ROOT / "tools" / "compat-inventory"))
from evidence_common import runtime_inputs, sha
from owned_runner import (
    build_artifact,
    control_get,
    local_addresses,
    sanitized_environment,
    socket_closed,
)

CONFIG = {"schemaVersion": 1, "profile": "strict"}


def child(directory, nonce):
    origin, control = local_addresses(
        os.environ["FIREBASE_AUTH_EMULATOR_HOST"], os.environ["FIREEMU_CONTROL_URL"]
    )
    origins(origin)
    require(os.environ["GOOGLE_CLOUD_PROJECT"] == PROJECT)
    token = os.environ["FIREEMU_CONTROL_TOKEN"]
    status, resources = control_get(control, "/v1/sessions/default/resources", token)
    wrong, _ = control_get(
        control, "/v1/sessions/default/resources", token + "-invalid"
    )
    require(status == 200 and wrong == 403 and resources.get("project") == PROJECT)
    status, caps = control_get(control, "/v1/capabilities", token)
    require(status == 200 and caps.get("profile") == "strict")
    instance = {
        "parentPid": os.getppid(),
        "childPid": os.getpid(),
        "nonce": nonce,
        "profile": caps["profile"],
        "version": caps.get("version"),
        "wrongTokenStatus": wrong,
        "authOrigin": origin,
        "controlOrigin": control,
    }
    save(directory / "instance.json", instance)
    return observe(directory / "observation", origin)


def stop_child(directory, nonce, parent):
    path = directory / "instance.json"
    if not path.exists():
        return
    instance = json.loads(path.read_bytes())
    require(instance["nonce"] == nonce and instance["parentPid"] == parent)
    pid = instance["childPid"]
    require(type(pid) is int and pid > 1)
    expected = " ".join(
        [
            sys.executable,
            str(Path(__file__).resolve()),
            "--child",
            str(directory),
            "--nonce",
            nonce,
        ]
    )
    for attempt in range(22):
        state = subprocess.run(
            ["ps", "-p", str(pid), "-o", "comm=", "-o", "args="],
            text=True,
            stdout=subprocess.PIPE,
            check=False,
        )
        if not state.stdout.strip():
            return
        fields = state.stdout.strip().split(maxsplit=1)
        require(
            len(fields) == 2
            and Path(fields[0]).name.lower().startswith("python")
            and fields[1] == expected
        )
        if attempt in {0, 20}:
            try:
                os.kill(pid, signal.SIGTERM if attempt == 0 else signal.SIGKILL)
            except ProcessLookupError:
                return
        time.sleep(0.1)
    raise ValueError("Owned child did not stop")


def run(output):
    binary, build = build_artifact()
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=False, mode=0o700)
    before = inputs()
    runtime = runtime_inputs(ROOT)
    nonce = uuid.uuid4().hex
    report = {"status": "owned-run-failed", "acceptance": "candidate"}
    process = None
    with tempfile.TemporaryDirectory(prefix="fireemu-boundary-owned-") as temporary:
        private = Path(temporary)
        artifact = private / "fireemu"
        shutil.copyfile(binary, artifact)
        artifact.chmod(0o500)
        artifact_hash = sha(artifact.read_bytes())
        require(artifact_hash == build["artifactSha256"] and runtime == build["inputs"])
        config = private / "config.json"
        save(config, CONFIG)
        config.chmod(0o400)
        config_hash = sha(config.read_bytes())
        environment = sanitized_environment(dict(os.environ))
        argv = [
            str(artifact),
            "exec",
            "--config",
            str(config),
            "--project",
            PROJECT,
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
            "silent",
            "--",
            sys.executable,
            str(Path(__file__).resolve()),
            "--child",
            str(output),
            "--nonce",
            nonce,
        ]
        try:
            version = (
                subprocess.check_output(
                    [str(artifact), "--version"],
                    env=environment,
                    cwd=private,
                    text=True,
                    timeout=10,
                )
                .strip()
                .split()[-1]
            )
            process = subprocess.Popen(
                argv,
                cwd=private,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            code = process.wait(timeout=180)
            report["ownedProcess"] = {
                "pid": process.pid,
                "exitCode": code,
                "stopped": True,
            }
            report = json.loads(
                (output / "observation" / "observation.json").read_bytes()
            )
            instance = json.loads((output / "instance.json").read_bytes())
            require(
                instance["parentPid"] == process.pid
                and instance["nonce"] == nonce
                and instance["version"] == version
                and instance["profile"] == "strict"
            )
            closed = all(
                socket_closed(instance[key]) for key in ["authOrigin", "controlOrigin"]
            )
            require(
                closed
                and sha(artifact.read_bytes()) == artifact_hash
                and sha(config.read_bytes()) == config_hash
                and inputs() == before
                and runtime_inputs(ROOT) == runtime
            )
            report.update(
                {
                    "connection": "owned-artifact",
                    "instance": instance,
                    "artifact": {
                        "sha256": artifact_hash,
                        "version": version,
                        "kind": "local-build",
                    },
                    "configuration": {
                        "value": CONFIG,
                        "sha256": digest(CONFIG),
                        "fileSha256": config_hash,
                    },
                    "build": build,
                    "runtimeSourceCommit": subprocess.check_output(
                        ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
                    ).strip(),
                    "ownedProcess": {
                        "pid": process.pid,
                        "exitCode": code,
                        "stopped": True,
                        "listenersClosed": closed,
                    },
                }
            )
            require(code == 0 and complete(report))
        except Exception as error:
            report["status"] = "owned-run-failed"
            report["failure"] = type(error).__name__
        finally:
            if process is not None:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=20)
                    except subprocess.TimeoutExpired:
                        try:
                            stop_child(output, nonce, process.pid)
                        except Exception as error:
                            report["childCleanupFailure"] = type(error).__name__
                        process.kill()
                        process.wait(timeout=10)
                        report["cleanupFailure"] = "SupervisorTimeout"
                try:
                    stop_child(output, nonce, process.pid)
                    instance_path = output / "instance.json"
                    if instance_path.exists():
                        recorded = json.loads(instance_path.read_bytes())
                        require(
                            all(
                                socket_closed(recorded[key])
                                for key in ["authOrigin", "controlOrigin"]
                            )
                        )
                except Exception as error:
                    report["childCleanupFailure"] = type(error).__name__
            save(output / "local.json", report)
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--child", type=Path)
    parser.add_argument("--nonce")
    args = parser.parse_args()
    try:
        result = child(args.child, args.nonce) if args.child else run(args.output)
        print(json.dumps({"status": result["status"], "complete": complete(result)}))
        raise SystemExit(0 if complete(result) else 2)
    except Exception:
        raise SystemExit("Auth owned observation did not complete") from None
