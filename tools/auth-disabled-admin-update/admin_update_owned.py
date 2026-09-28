"""Build and own the strict Auth artifact; run the same disabled-account administrative
update corpus against it. Never attaches to an external daemon."""

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

from admin_update_recorder import (
    PROJECT,
    ROOT,
    complete,
    inputs,
    observe,
    require,
    save,
)

sys.path.insert(0, str(ROOT / "tools" / "compat-inventory"))
sys.path.insert(0, str(ROOT / "tools" / "auth-password-maximum"))
import maximum_recorder as core
from evidence_common import runtime_inputs, sha
from owned_runner import (
    build_artifact,
    control_get,
    local_addresses,
    sanitized_environment,
    socket_closed,
)

CONFIG = {"schemaVersion": 1, "profile": "strict"}


def owned_complete(report):
    """An owned local run is complete only when the corpus contract is satisfied and
    the owned child process was confirmed stopped; a child cleanup failure is a failure
    of the run, not a footnote."""
    return complete(report) and "childCleanupFailure" not in report


def child(directory, nonce):
    origin, control = local_addresses(
        os.environ["FIREBASE_AUTH_EMULATOR_HOST"], os.environ["FIREEMU_CONTROL_URL"]
    )
    core.origins(origin)
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
    with tempfile.TemporaryDirectory(prefix="fireemu-admin-update-owned-") as temporary:
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
            # stderr goes to a private file in the owned output: the artifact runs with
            # silent logging, and the Functions runtime's startup diagnostics are the
            # only way to see why a local run could not start.
            with (output / "fireemu-stderr.log").open("wb") as stderr:
                process = subprocess.Popen(
                    argv,
                    cwd=private,
                    env=environment,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=stderr,
                )
                code = process.wait(timeout=300)
            code = process.wait(timeout=300)
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
            require(closed)
            report["connection"] = "owned-artifact"
            report["artifact"] = {
                "sha256": artifact_hash,
                "version": version,
                "kind": "local-build",
            }
            report["configuration"] = {
                "value": CONFIG,
                "sha256": core.digest(CONFIG),
                "fileSha256": config_hash,
            }
            report["ownedProcess"] = {
                "pid": process.pid,
                "exitCode": code,
                "stopped": True,
                "listenersClosed": closed,
            }
            report["instance"] = {
                k: instance[k]
                for k in [
                    "parentPid",
                    "childPid",
                    "nonce",
                    "profile",
                    "version",
                    "wrongTokenStatus",
                ]
            }
            report["build"] = build
            report["runtimeSourceCommit"] = subprocess.check_output(
                ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
            ).strip()
            require(inputs() == before)
        except Exception as error:
            report["failure"] = type(error).__name__
        finally:
            if process is not None and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=20)
                except subprocess.TimeoutExpired:
                    process.kill()
            try:
                stop_child(output, nonce, process.pid if process else 0)
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
        done = owned_complete(result)
        print(json.dumps({"status": result["status"], "complete": done}))
        raise SystemExit(0 if done else 2)
    except Exception:
        raise SystemExit("Admin-update owned observation did not complete") from None
