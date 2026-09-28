"""Run the action-code matrix against an owned local fireemu artifact.

The shadow owns the process it measures: it copies the artifact into a private
directory, starts it with OS-assigned loopback ports, runs the collector as its
child, and then requires the child to be gone, the listeners to be closed and
the artifact bytes to be unchanged. It never attaches to a daemon somebody else
started, and it never contacts anything but loopback.

The artifact binding is recorded, not assumed. An artifact supplied with
`--artifact` is labelled `retained-external`: its digest is recorded, but this
package does not claim it was built from the current source commit.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import urllib.parse
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from action_codes_collector import CollectorError, _http_send, collect

CONFIG = {"schemaVersion": 1, "profile": "strict"}
LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}
# Variables that could redirect a request away from the owned loopback instance.
STRIPPED = (
    "GOOGLE_APPLICATION_CREDENTIALS",
    "GOOGLE_CLOUD_PROJECT",
    "CLOUDSDK_AUTH_ACCESS_TOKEN",
    "FIRESTORE_EMULATOR_HOST",
    "FIREBASE_AUTH_EMULATOR_HOST",
    "FIREEMU_CONTROL_URL",
    "FIREEMU_CONTROL_TOKEN",
    "PRODUCTION_ORACLE_API_KEY",
)


class ShadowError(RuntimeError):
    """The owned instance, its ports or its artifact could not be trusted."""


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def loopback_origin(host: str) -> str:
    """Turn the emulator host variable into a bare loopback origin."""
    url = urllib.parse.urlsplit("http://" + host)
    if url.hostname not in LOOPBACK_HOSTS or url.port is None:
        raise ShadowError("the owned instance must listen on a loopback port")
    return f"http://{url.hostname}:{url.port}"


def parent_environment(environment: dict[str, str]) -> dict[str, str]:
    """Strip every credential and redirect before the artifact is started."""
    return {key: value for key, value in environment.items() if key not in STRIPPED}


def artifact_command(
    artifact: Path,
    config: Path,
    project: str,
    output: Path,
    nonce: str,
    fail_after: str | None,
    digest: str,
    built_from_source_commit: str | None,
) -> list[str]:
    """The exact argv of the owned instance; it carries no secret."""
    command = [
        str(artifact),
        "exec",
        "--config",
        str(config),
        "--project",
        project,
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
        "--project",
        project,
        "--artifact-sha256",
        digest,
    ]
    if fail_after is not None:
        command.extend(["--fail-after", fail_after])
    if built_from_source_commit is not None:
        command.extend(["--built-from-source-commit", built_from_source_commit])
    return command


def socket_closed(origin: str) -> bool:
    url = urllib.parse.urlsplit(origin)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.settimeout(2)
        return probe.connect_ex((url.hostname, url.port)) != 0


def child_complete(receipt: dict[str, Any], rehearsal: bool) -> bool:
    """A rehearsal only has to recover; a real shadow also has to record."""
    if receipt.get("cleanupComplete") is not True:
        return False
    return rehearsal or receipt.get("recordingComplete") is True


def artifact_source_binding(
    digest: str, built_from_source_commit: str | None
) -> dict[str, Any]:
    """Say honestly how the executed bytes relate to a commit.

    A binary this package did not build is `retained-external`: its digest says
    which bytes ran, not which source produced them, and the comparator refuses
    a verdict on it.
    """
    if built_from_source_commit is None:
        return {
            "commit": None,
            "artifactSha256": None,
            "binding": "unbound",
            "builtFromSourceCommit": None,
        }
    return {
        "commit": built_from_source_commit,
        "artifactSha256": digest,
        "binding": "built-from-source",
        "builtFromSourceCommit": built_from_source_commit,
    }


def _child(
    output: Path,
    nonce: str,
    project: str,
    fail_after: str | None,
    source_binding: dict[str, Any] | None = None,
) -> int:
    origin = loopback_origin(os.environ["FIREBASE_AUTH_EMULATOR_HOST"])
    output.mkdir(parents=True, exist_ok=True)
    send = _http_send
    if fail_after is not None:
        seen: list[str] = []

        def send(method, url, headers, body):
            answer = _http_send(method, url, headers, body)
            seen.append(url)
            if url.endswith(fail_after):
                raise ConnectionError("rehearsed transport failure")
            return answer

    (output / "instance.json").write_text(
        json.dumps(
            {
                "childPid": os.getpid(),
                "parentPid": os.getppid(),
                "authOrigin": origin,
                "nonce": nonce,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )
    try:
        receipt = collect(
            origin=origin,
            project=project,
            nonce=nonce,
            send=send,
            tolerate_failure=fail_after is not None,
            source_binding=source_binding,
        )
    except CollectorError as error:
        receipt = getattr(error, "receipt", {"collectorError": str(error)})
    (output / "receipt.json").write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n"
    )
    return 0 if child_complete(receipt, fail_after is not None) else 3


def run(
    output: Path,
    artifact: Path,
    project: str,
    nonce: str,
    *,
    timeout: int = 240,
    fail_after: str | None = None,
    built_from_source_commit: str | None = None,
) -> dict[str, Any]:
    """Own one artifact for the length of one collection and prove it stopped."""
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    artifact = artifact.resolve()
    if not artifact.is_file():
        raise ShadowError("no artifact at " + str(artifact))
    report: dict[str, Any] = {"status": "shadow-failed", "productionExecuted": False}
    process = None
    with tempfile.TemporaryDirectory(prefix="fireemu-action-codes-") as temporary:
        private = Path(temporary)
        copied = private / "fireemu"
        shutil.copyfile(artifact, copied)
        copied.chmod(0o500)
        digest = sha256(copied)
        config = private / "config.json"
        config.write_text(json.dumps(CONFIG, sort_keys=True))
        config.chmod(0o400)
        binding = artifact_source_binding(digest, built_from_source_commit)
        environment = parent_environment(dict(os.environ))
        command = artifact_command(
            copied,
            config,
            project,
            output,
            nonce,
            fail_after,
            digest,
            built_from_source_commit,
        )
        try:
            version = (
                subprocess.check_output(
                    [str(copied), "--version"],
                    env=environment,
                    cwd=private,
                    text=True,
                    timeout=30,
                )
                .strip()
                .split()[-1]
            )
            process = subprocess.Popen(
                command,
                cwd=private,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            code = process.wait(timeout=timeout)
            instance = json.loads((output / "instance.json").read_bytes())
            receipt = json.loads((output / "receipt.json").read_bytes())
            if instance["parentPid"] != process.pid or instance["nonce"] != nonce:
                raise ShadowError("the recorded child is not the process we started")
            closed = socket_closed(instance["authOrigin"])
            if sha256(copied) != digest:
                raise ShadowError("the artifact changed while it was running")
            report = {
                "status": "shadow-complete"
                if code == 0 and closed
                else "shadow-failed",
                "rehearsal": fail_after,
                "productionExecuted": False,
                "artifact": {
                    "sha256": digest,
                    "version": version,
                    # The same word the receipt uses, so the two cannot disagree.
                    "binding": binding["binding"],
                    "builtFromSourceCommit": built_from_source_commit,
                    # Where the file came from, which is not a provenance claim:
                    # this package never builds, so a commit passed on the
                    # command line is the caller's assertion, not our evidence.
                    "provenance": (
                        "built-elsewhere, commit asserted by the caller"
                        if built_from_source_commit
                        else "retained-external"
                    ),
                },
                "configuration": CONFIG,
                "instance": instance,
                "ownedProcess": {
                    "pid": process.pid,
                    "exitCode": code,
                    "stopped": True,
                    "listenersClosed": closed,
                },
                "receipt": receipt,
            }
        except Exception as error:  # noqa: BLE001 -- the report must survive.
            report["status"] = "shadow-failed"
            report["failure"] = type(error).__name__
        finally:
            if process is not None and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=20)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=10)
                    report["cleanupFailure"] = "SupervisorTimeout"
            # Written inside the finally, so a timed-out wait still leaves
            # evidence of what this run owned and how it ended.
            (output / "shadow.json").write_text(
                json.dumps(report, indent=2, sort_keys=True) + "\n"
            )
    return report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--artifact", type=Path)
    parser.add_argument("--project", default="demo-auth-action")
    parser.add_argument("--nonce", required=True)
    parser.add_argument("--child", type=Path)
    parser.add_argument("--artifact-sha256", default="")
    parser.add_argument("--fail-after")
    parser.add_argument(
        "--built-from-source-commit",
        help="the commit this artifact was built from, when it was built here",
    )
    return parser


if __name__ == "__main__":
    arguments = build_parser().parse_args()
    if arguments.child is not None:
        raise SystemExit(
            _child(
                arguments.child,
                arguments.nonce,
                arguments.project,
                arguments.fail_after,
                artifact_source_binding(
                    arguments.artifact_sha256, arguments.built_from_source_commit
                ),
            )
        )
    result = run(
        arguments.output,
        arguments.artifact,
        arguments.project,
        arguments.nonce,
        fail_after=arguments.fail_after,
        built_from_source_commit=arguments.built_from_source_commit,
    )
    print(json.dumps({"status": result["status"]}))
    raise SystemExit(0 if result["status"] == "shadow-complete" else 2)
