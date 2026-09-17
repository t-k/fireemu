"""Own one local Auth artifact execution and persist measured cleanup evidence."""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
import re
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
JS = Path(__file__).with_name("auth-account-linking-local.mjs")
EXPECTED_SDK = {"firebase": "12.18.0", "firebase-admin": "14.3.0"}
OPERATION_IDS = [
    "signup-a",
    "signup-b",
    "same-provider-signin",
    "cross-provider-same-email-collision",
    "distinct-provider-link",
    "provider-unlink",
]


def sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def load_json(path: Path) -> dict:
    value = json.loads(path.read_bytes())
    require(isinstance(value, dict), f"{path} must contain an object")
    return value


def validate_manifest(manifest: dict, artifact: Path) -> tuple[str, str]:
    require(manifest.get("status") == "completed", "retained manifest is not completed")
    require(
        manifest.get("productionExecuted") is False,
        "production manifest cannot be adopted",
    )
    source = manifest.get("executionCommit")
    expected = manifest.get("artifactSha256")
    require(
        isinstance(source, str) and re.fullmatch(r"[0-9a-f]{40}", source),
        "manifest source binding missing",
    )
    require(
        isinstance(expected, str) and re.fullmatch(r"[0-9a-f]{64}", expected),
        "manifest artifact binding missing",
    )
    require(
        artifact.is_file() and artifact.name == "fireemu",
        "artifact must be a regular fireemu file",
    )
    actual = sha(artifact)
    require(actual == expected, "artifact does not match retained manifest")
    return source, actual


def verify_harness_source(root: Path, expected_commit: str) -> dict:
    require(
        isinstance(expected_commit, str)
        and re.fullmatch(r"[0-9a-f]{40}", expected_commit),
        "full expected harness commit required",
    )

    def git(*args: str) -> bytes:
        return subprocess.check_output(["git", "-C", str(root), *args])

    require(
        git("rev-parse", "HEAD").decode().strip() == expected_commit,
        "harness source commit drift",
    )
    require(
        not git("status", "--porcelain", "--untracked-files=no"),
        "harness source checkout is dirty",
    )
    digests = {}
    for relative in (
        "tools/sdk-smoke/auth-account-linking-owned.py",
        "tools/sdk-smoke/auth-account-linking-local.mjs",
    ):
        committed = hashlib.sha256(
            git("show", f"{expected_commit}:{relative}")
        ).hexdigest()
        actual = sha(root / relative)
        require(actual == committed, f"harness source digest mismatch: {relative}")
        digests[relative] = actual
    return {"commit": expected_commit, "sha256": digests}


def validate_prepared_paths(manifest_path: Path, artifact: Path) -> None:
    common = Path(
        subprocess.check_output(
            ["git", "rev-parse", "--path-format=absolute", "--git-common-dir"],
            cwd=ROOT,
            text=True,
        ).strip()
    ).parent
    prepared = common / "docs.local/logs/2026-09-17/limits-repair-shadow-8b33aac4d"
    require(
        manifest_path.resolve() == prepared / "manifest.json"
        and artifact.resolve() == prepared / "fireemu",
        "only the prepared artifact and manifest are accepted",
    )


def validate_installed_sdk(installed: dict) -> dict:
    require(
        {name: installed.get(name, {}).get("version") for name in EXPECTED_SDK}
        == EXPECTED_SDK,
        "installed SDK versions differ from reviewed pins",
    )
    return installed


def observe_listener(port: int, parent: int) -> dict:
    result = subprocess.run(
        ["lsof", "-nP", f"-iTCP:{port}", "-sTCP:LISTEN", "-FpFn"],
        capture_output=True,
        text=True,
        check=False,
    )
    owners = [int(row[1:]) for row in result.stdout.splitlines() if row.startswith("p")]
    addresses = [row[1:] for row in result.stdout.splitlines() if row.startswith("n")]
    require(
        result.returncode == 0
        and owners == [parent]
        and addresses
        and all(address == f"127.0.0.1:{port}" for address in addresses),
        "listener owner or loopback address mismatch",
    )
    return {"port": port, "pid": parent, "addresses": addresses}


def read_local_config(origin: str, output: Path) -> dict:
    from urllib.parse import urlsplit

    parsed = urlsplit(origin)
    require(
        parsed.scheme == "http"
        and parsed.hostname == "127.0.0.1"
        and parsed.port
        and not parsed.path
        and not parsed.query
        and not parsed.fragment
        and not parsed.username,
        "configuration endpoint must be an owned loopback origin",
    )
    path = "/emulator/v1/projects/demo-app/config"
    connection = http.client.HTTPConnection("127.0.0.1", parsed.port, timeout=10)
    record = {"origin": origin, "project": "demo-app", "path": path}
    try:
        # The emulator Owner credential is local-only; HTTPConnection never follows redirects.
        connection.request("GET", path, headers={"Authorization": "Bearer owner"})
        response = connection.getresponse()
        raw = response.read(1024 * 1024 + 1)
        record["status"] = response.status
        require(len(raw) <= 1024 * 1024, "configuration readback exceeds budget")
        record["body"] = json.loads(raw)
    except (OSError, ValueError, http.client.HTTPException) as error:
        record["readFailure"] = type(error).__name__
        raise
    finally:
        connection.close()
        with output.open("x") as stream:
            json.dump(record, stream, indent=2)
            stream.flush()
            os.fsync(stream.fileno())
    return record


def validate_config_readbacks(before: dict, after: dict, origin: str) -> dict:
    values = []
    for record in (before, after):
        require(
            record.get("origin") == origin
            and record.get("project") == "demo-app"
            and record.get("path") == "/emulator/v1/projects/demo-app/config",
            "configuration namespace mismatch",
        )
        require(
            record.get("status") == 200 and "readFailure" not in record,
            "configuration management readback failed",
        )
        body = record.get("body")
        sign_in = body.get("signIn") if isinstance(body, dict) else None
        value = (
            sign_in.get("allowDuplicateEmails") if isinstance(sign_in, dict) else None
        )
        require(
            type(value) is bool, "effective allowDuplicateEmails is absent or invalid"
        )
        values.append(value)
    require(values[0] == values[1], "effective configuration changed during SDK flow")
    return {
        "allowDuplicateEmails": values[0],
        "before": before,
        "after": after,
        "unchanged": True,
    }


def owned_child(output: Path, nonce: str) -> None:
    sys.path.insert(0, str(ROOT / "tools/compat-inventory"))
    from urllib.parse import urlsplit

    from owned_runner import control_get, local_addresses

    source = verify_harness_source(ROOT, os.environ["AUTH_LINKING_HARNESS_COMMIT"])
    auth, control = local_addresses(
        os.environ["FIREBASE_AUTH_EMULATOR_HOST"], os.environ["FIREEMU_CONTROL_URL"]
    )
    require(os.environ["GOOGLE_CLOUD_PROJECT"] == "demo-app", "project mismatch")
    token = os.environ["FIREEMU_CONTROL_TOKEN"]
    status, resources = control_get(control, "/v1/sessions/default/resources", token)
    wrong, _ = control_get(
        control, "/v1/sessions/default/resources", token + "-invalid"
    )
    require(
        status == 200 and wrong == 403 and resources.get("project") == "demo-app",
        "fresh control identity challenge failed",
    )
    parent = os.getppid()
    listeners = [
        observe_listener(urlsplit(origin).port, parent) for origin in (auth, control)
    ]
    sdk = validate_installed_sdk(
        json.loads(
            subprocess.check_output(
                ["node", str(JS), "--sdk-info"], cwd=ROOT, text=True
            )
        )
    )
    instance = {
        "parentPid": parent,
        "childPid": os.getpid(),
        "nonce": nonce,
        "authOrigin": auth,
        "controlOrigin": control,
        "listeners": listeners,
        "authorizedStatus": status,
        "wrongTokenStatus": wrong,
        "sdk": sdk,
    }
    with (output / "instance.json").open("x") as stream:
        json.dump(instance, stream)
    before = read_local_config(auth, output / "config-before.json")
    validate_config_readbacks(before, before, auth)
    subprocess.run(["node", str(JS)], cwd=ROOT, check=True, timeout=120)
    after = read_local_config(auth, output / "config-after.json")
    validate_config_readbacks(before, after, auth)
    require(
        verify_harness_source(ROOT, source["commit"]) == source,
        "child harness source drift",
    )
    # Recheck the same live listeners after the SDK has finished.
    for listener in listeners:
        observe_listener(listener["port"], parent)


def socket_closed(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.5):
            return False
    except OSError:
        return True


def descendant_group_gone(pgid: int) -> bool:
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return True
    except PermissionError:
        return False
    return False


def terminate_group(process: subprocess.Popen[bytes], attempts: list[dict]) -> None:
    if process.poll() is not None:
        require(
            descendant_group_gone(process.pid),
            "owned process group remains alive after supervisor exit",
        )
        return
    pgid = os.getpgid(process.pid)
    for name, sig in (("SIGTERM", signal.SIGTERM), ("SIGKILL", signal.SIGKILL)):
        try:
            os.killpg(pgid, sig)
            attempts.append({"signal": name, "sent": True})
        except ProcessLookupError:
            attempts.append({"signal": name, "sent": False, "reason": "group-gone"})
            break
        try:
            process.wait(timeout=10 if sig == signal.SIGTERM else 5)
            break
        except subprocess.TimeoutExpired:
            attempts.append({"signal": name, "wait": "timeout"})
    require(process.poll() is not None, "owned fireemu process did not terminate")
    require(descendant_group_gone(pgid), "owned process group remains alive")


def run(
    output: Path, manifest_path: Path, artifact: Path, harness_commit: str | None = None
) -> dict:
    output = output.resolve()
    output.mkdir(mode=0o700, exist_ok=False)
    report: dict = {"status": "owned-run-failed", "productionExecuted": False}
    cleanup_attempts: list[dict] = []
    process: subprocess.Popen[bytes] | None = None
    ports: list[int] = []
    try:
        harness_source = verify_harness_source(ROOT, harness_commit)
        validate_prepared_paths(manifest_path, artifact)
        manifest = load_json(manifest_path)
        source_commit, artifact_hash = validate_manifest(manifest, artifact)
        require(
            source_commit == "8b33aac4ddd09e6b945cc8701a7e757a948223ac"
            and artifact_hash
            == "76f855367910ad237de6ffd491091f20bcdccdb2e5eb8ee417e80b94bf6ac397",
            "prepared build identity mismatch",
        )
        nonce = secrets.token_hex(16)
        with tempfile.TemporaryDirectory(prefix="auth-linking-owned-") as private_name:
            private = Path(private_name)
            owned_artifact = private / "fireemu"
            shutil.copyfile(artifact, owned_artifact)
            owned_artifact.chmod(0o500)
            require(sha(owned_artifact) == artifact_hash, "owned artifact copy changed")
            child_receipt = output / "child-observation.json"
            child_receipt.touch(mode=0o600, exist_ok=False)
            child_receipt.unlink()
            log_path = output / "owned-output.log"
            with log_path.open("xb") as log:
                env = {
                    key: value
                    for key, value in os.environ.items()
                    if key in {"PATH", "HOME", "TMPDIR", "LANG", "LC_ALL"}
                }
                env.update(
                    {
                        "GOOGLE_CLOUD_PROJECT": "demo-app",
                        "AUTH_LINKING_RECEIPT": str(child_receipt),
                        "AUTH_LINKING_HARNESS_COMMIT": harness_commit,
                    }
                )
                argv = [
                    str(owned_artifact),
                    "exec",
                    "--project",
                    "demo-app",
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
                    "info",
                    "--",
                    sys.executable,
                    str(Path(__file__).resolve()),
                    "--child",
                    str(output),
                    nonce,
                ]
                process = subprocess.Popen(
                    argv,
                    cwd=ROOT,
                    env=env,
                    stdin=subprocess.DEVNULL,
                    stdout=log,
                    stderr=subprocess.STDOUT,
                    start_new_session=True,
                )
                try:
                    process.wait(timeout=180)
                except subprocess.TimeoutExpired:
                    terminate_group(process, cleanup_attempts)
                    raise
                log.flush()
            instance = load_json(output / "instance.json")
            require(
                instance["parentPid"] == process.pid and instance["nonce"] == nonce,
                "child process binding mismatch",
            )
            require(process.returncode == 0, "owned child failed")
            ports = [row["port"] for row in instance["listeners"]]
            sdk = validate_installed_sdk(instance["sdk"])
            listener_closed = all(socket_closed(port) for port in ports)
            require(listener_closed, "Auth listener remained open after process exit")
            child = load_json(child_receipt)
            require(
                child.get("sdk") == sdk
                and child.get("authOrigin") == instance["authOrigin"],
                "collector SDK or endpoint binding mismatch",
            )
            require(child.get("status") == "completed", "child observation incomplete")
            require(
                child.get("productionExecuted") is False, "child attempted production"
            )
            require(
                child.get("providerBoundary") == "local-emulator-fixture",
                "provider boundary missing",
            )
            require(
                [row.get("id") for row in child.get("operations", [])] == OPERATION_IDS,
                "operation sequence incomplete",
            )
            configuration = validate_config_readbacks(
                load_json(output / "config-before.json"),
                load_json(output / "config-after.json"),
                instance["authOrigin"],
            )
            report = {
                **child,
                "effectiveConfiguration": configuration,
                "sourceCommit": source_commit,
                "harnessSource": harness_source,
                "artifact": {
                    "path": str(artifact),
                    "sha256": artifact_hash,
                    "manifest": str(manifest_path),
                },
                "sdk": sdk,
                "instance": instance,
                "ownedProcess": {
                    "pid": process.pid,
                    "exitCode": process.returncode,
                    "processGroupGone": descendant_group_gone(process.pid),
                    "listenersClosed": listener_closed,
                },
                "cleanup": {
                    "ownedResources": 0,
                    "listenersClosed": listener_closed,
                    "processGroupGone": descendant_group_gone(process.pid),
                    "attempts": cleanup_attempts,
                },
                "status": "completed",
            }
            require(
                report["ownedProcess"]["processGroupGone"]
                and report["ownedProcess"]["listenersClosed"],
                "measured process cleanup incomplete",
            )
        require(
            verify_harness_source(ROOT, harness_commit) == harness_source,
            "harness source drift invalidates observation",
        )
        pending = output / "receipt.pending.json"
        with pending.open("x", encoding="utf-8") as stream:
            json.dump(report, stream, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.link(pending, output / "receipt.json")
        return report
    except Exception as error:  # noqa: BLE001 -- persist failure and clean owned resources.
        if process is not None:
            try:
                terminate_group(process, cleanup_attempts)
            except Exception as cleanup_error:  # noqa: BLE001 -- retain cleanup failures.
                cleanup_attempts.append(
                    {
                        "cleanupFailure": type(cleanup_error).__name__,
                        "message": str(cleanup_error),
                    }
                )
        failure = {
            "status": "owned-run-failed",
            "productionExecuted": False,
            "failure": {"type": type(error).__name__, "message": str(error)},
            "cleanup": {
                "attempts": cleanup_attempts,
                "listenersChecked": bool(ports),
                "listenersClosed": all(socket_closed(port) for port in ports)
                if ports
                else None,
                "processGroupGone": descendant_group_gone(process.pid)
                if process
                else None,
            },
        }
        try:
            with (output / "failure.json").open("x", encoding="utf-8") as stream:
                json.dump(failure, stream, indent=2)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
        except OSError as persistence_error:
            failure["failureArtifactError"] = type(persistence_error).__name__
            print(json.dumps(failure), file=sys.stderr)
            try:
                with (output / "failure-recovery.json").open("x") as stream:
                    json.dump(failure, stream)
                    stream.flush()
                    os.fsync(stream.fileno())
            except OSError as recovery_error:
                message = (
                    f"CRITICAL: no durable failure artifact could be persisted; "
                    f"runner owner PID={os.getpid()} must recover the stderr failure record "
                    f"to {output / 'failure-recovery.json'}; "
                    f"persistence error={type(recovery_error).__name__}"
                )
                print(message, file=sys.stderr, flush=True)
                raise RuntimeError(message) from recovery_error
        return failure


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "--child":
        owned_child(Path(sys.argv[2]), sys.argv[3])
        raise SystemExit(0)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument(
        "--harness-commit",
        required=True,
        help="Reviewed full commit for the clean harness checkout",
    )
    args = parser.parse_args()
    result = run(args.output, args.manifest, args.artifact, args.harness_commit)
    print(
        json.dumps({"status": result["status"], "output": str(args.output)}, indent=2)
    )
    raise SystemExit(0 if result["status"] == "completed" else 2)
