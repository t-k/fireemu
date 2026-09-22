"""Own the exact local artifact/configuration/process measured by the aggregation probe.

The OS process relationship and fresh control-token challenge prevent accidental
daemon mixups. They are not a signature or a defence against a malicious executable.
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import socket
import stat
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

# The limit below is a hang guard, not a performance budget: a cold worktree with an
# empty target/ legitimately needs many minutes to build fireemu from scratch, so the
# default is generous enough that a slow first build never looks like a failure.
BUILD_TIMEOUT_VARIABLE = "FIREEMU_BUILD_TIMEOUT_SECONDS"
DEFAULT_BUILD_TIMEOUT_SECONDS = 1800


def build_timeout(environment: dict) -> int:
    """Seconds allowed for the artifact build, overridable per environment."""
    raw = environment.get(BUILD_TIMEOUT_VARIABLE)
    if raw is None:
        return DEFAULT_BUILD_TIMEOUT_SECONDS
    value = raw.strip()
    if not (value.isascii() and value.isdigit()) or int(value) <= 0:
        raise ValueError(
            f"{BUILD_TIMEOUT_VARIABLE} must be a positive whole number of seconds, "
            f"got {raw!r}"
        )
    return int(value)


def run_build(
    command: list[str], environment: dict, limit: int
) -> subprocess.CompletedProcess:
    """Run the build, translating a hang into an actionable error."""
    try:
        return subprocess.run(
            command,
            cwd=ROOT,
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            check=True,
            timeout=limit,
        )
    except subprocess.TimeoutExpired as error:
        # subprocess.run kills and reaps the child before re-raising, so no cargo
        # process survives this path.
        raise TimeoutError(
            f"the artifact build did not finish within {limit} seconds; warm the "
            "build with `cargo build -p fireemu` in this worktree, or raise "
            f"{BUILD_TIMEOUT_VARIABLE}"
        ) from error


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


def artifact_binding(
    source: Path,
    launch_copy: Path,
    build: dict,
    inputs: dict,
    launch_fd: int | None = None,
) -> dict:
    """Bind the built executable and return a caller-owned verified launch FD."""
    os_module = __import__("os")
    stat_module = __import__("stat")

    def open_anchored(path: Path, role: str) -> tuple[Path, int]:
        require(".." not in path.parts, f"artifact binding {role} path contains '..'")
        absolute = path.absolute()
        try:
            resolved = absolute.resolve(strict=True)
        except OSError as exc:
            raise ValueError(f"artifact binding {role} path is unavailable") from exc
        require(
            resolved == absolute,
            f"artifact binding {role} path must be canonical and must not use a symlink parent",
        )
        parts = absolute.parts
        require(len(parts) >= 2, f"artifact binding {role} path must name a file")
        directory_flags = (
            os_module.O_RDONLY
            | getattr(os_module, "O_DIRECTORY", 0)
            | getattr(os_module, "O_CLOEXEC", 0)
            | getattr(os_module, "O_NOFOLLOW", 0)
        )
        file_flags = os_module.O_RDONLY | getattr(os_module, "O_CLOEXEC", 0) | getattr(
            os_module, "O_NOFOLLOW", 0
        )

        def identity(metadata):
            return metadata.st_dev, metadata.st_ino, stat_module.S_IFMT(metadata.st_mode)

        expected_directories = []
        prefix = Path(absolute.anchor)
        try:
            root_metadata = os_module.stat(prefix, follow_symlinks=False)
            require(
                stat_module.S_ISDIR(root_metadata.st_mode),
                f"artifact binding {role} root is not a directory",
            )
            for component in parts[1:-1]:
                prefix /= component
                metadata = os_module.stat(prefix, follow_symlinks=False)
                require(
                    stat_module.S_ISDIR(metadata.st_mode),
                    f"artifact binding {role} path component is not a directory",
                )
                expected_directories.append(metadata)
            expected_file = os_module.stat(absolute, follow_symlinks=False)
        except OSError as exc:
            raise ValueError(f"artifact binding {role} path is unavailable") from exc
        require(
            stat_module.S_ISREG(expected_file.st_mode),
            f"artifact binding {role} path must be a regular file",
        )
        require(
            expected_file.st_nlink == 1,
            f"artifact binding {role} path must not be a hardlink",
        )
        try:
            directory_descriptor = os_module.open(absolute.anchor, directory_flags)
        except OSError as exc:
            raise ValueError(
                f"artifact binding {role} root is unavailable or is a symlink"
            ) from exc
        try:
            opened_root = os_module.fstat(directory_descriptor)
            require(
                stat_module.S_ISDIR(opened_root.st_mode)
                and identity(opened_root) == identity(root_metadata),
                f"artifact binding {role} root changed before opening",
            )
            for index, component in enumerate(parts[1:-1]):
                next_descriptor = os_module.open(
                    component, directory_flags, dir_fd=directory_descriptor
                )
                try:
                    opened = os_module.fstat(next_descriptor)
                    require(
                        stat_module.S_ISDIR(opened.st_mode)
                        and identity(opened) == identity(expected_directories[index]),
                        f"artifact binding {role} path component changed before opening",
                    )
                except BaseException:
                    os_module.close(next_descriptor)
                    raise
                os_module.close(directory_descriptor)
                directory_descriptor = next_descriptor
            descriptor = os_module.open(
                parts[-1], file_flags, dir_fd=directory_descriptor
            )
            try:
                opened = os_module.fstat(descriptor)
                require(
                    stat_module.S_ISREG(opened.st_mode)
                    and opened.st_nlink == 1
                    and identity(opened) == identity(expected_file),
                    f"artifact binding {role} path changed before opening",
                )
            except BaseException:
                os_module.close(descriptor)
                raise
        except OSError as exc:
            raise ValueError(
                f"artifact binding {role} path is unavailable or is a symlink"
            ) from exc
        finally:
            os_module.close(directory_descriptor)
        return absolute, descriptor

    def read_stable(
        path: Path, role: str, supplied_fd: int | None = None
    ) -> tuple[Path, str, tuple[int, int], int]:
        resolved, descriptor = open_anchored(path, role)
        if supplied_fd is not None:
            try:
                supplied = os_module.fstat(supplied_fd)
                opened = os_module.fstat(descriptor)
                require(
                    (supplied.st_dev, supplied.st_ino) == (opened.st_dev, opened.st_ino),
                    f"artifact binding {role} descriptor does not match its path",
                )
            except OSError as exc:
                os_module.close(descriptor)
                raise ValueError(f"artifact binding {role} descriptor is unavailable") from exc
            except BaseException:
                os_module.close(descriptor)
                raise
        try:
            before = os_module.fstat(descriptor)
            require(
                stat_module.S_ISREG(before.st_mode),
                f"artifact binding {role} path must be a regular file",
            )
            require(
                before.st_nlink == 1,
                f"artifact binding {role} path must not be a hardlink",
            )
            chunks = []
            while True:
                chunk = os_module.read(descriptor, 1024 * 1024)
                if not chunk:
                    break
                chunks.append(chunk)
            after = os_module.fstat(descriptor)
        finally:
            os_module.close(descriptor)
        def identity(metadata):
            return (
                metadata.st_dev,
                metadata.st_ino,
                metadata.st_mode,
                metadata.st_nlink,
                metadata.st_size,
                metadata.st_mtime_ns,
                metadata.st_ctime_ns,
            )
        require(
            identity(before) == identity(after),
            f"artifact binding {role} changed while reading",
        )
        try:
            current = os_module.stat(path, follow_symlinks=False)
        except OSError as exc:
            raise ValueError(f"artifact binding {role} path disappeared") from exc
        require(
            stat_module.S_ISREG(current.st_mode)
            and current.st_nlink == 1
            and identity(current) == identity(after),
            f"artifact binding {role} path changed while reading",
        )
        try:
            final = os_module.stat(path, follow_symlinks=False)
        except OSError as exc:
            raise ValueError(f"artifact binding {role} path disappeared") from exc
        require(
            stat_module.S_ISREG(final.st_mode)
            and final.st_nlink == 1
            and identity(final) == identity(after),
            f"artifact binding {role} path changed after verification",
        )
        bound_resolved, bound_descriptor = open_anchored(path, role)
        try:
            bound = os_module.fstat(bound_descriptor)
            require(
                stat_module.S_ISREG(bound.st_mode)
                and bound.st_nlink == 1
                and identity(bound) == identity(after),
                f"artifact binding {role} path changed before use",
            )
            require(
                bound_resolved == resolved,
                f"artifact binding {role} path changed before use",
            )
        except BaseException:
            os_module.close(bound_descriptor)
            raise
        return resolved, sha(b"".join(chunks)), (after.st_dev, after.st_ino), bound_descriptor

    source, source_sha256, source_identity, source_descriptor = read_stable(source, "source")
    try:
        launch_copy, launch_copy_sha256, launch_identity, verified_launch_fd = read_stable(
            launch_copy, "launch", launch_fd
        )
    except BaseException:
        os_module.close(source_descriptor)
        raise
    try:
        os_module.close(source_descriptor)
        require(
            source_identity != launch_identity,
            "artifact binding source and launch paths must have independent inodes",
        )
        validate_build(build, source_sha256, inputs)
        require(launch_copy_sha256 == source_sha256, "artifact launch copy mismatch")
    except BaseException:
        os_module.close(verified_launch_fd)
        raise
    return {
        "sourcePath": str(source),
        "sourceSha256": source_sha256,
        "launchCopyPath": str(launch_copy),
        "launchCopySha256": launch_copy_sha256,
        "_launchFd": verified_launch_fd,
    }


def open_verified_artifact(path: Path) -> int:
    """Open a canonical, regular, independently linked artifact for FD use."""
    require(".." not in path.parts, "artifact path contains '..'")
    path = path.absolute()
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise ValueError("artifact path is unavailable") from exc
    require(
        resolved == path.absolute(),
        "artifact path must be canonical and must not use a symlink parent",
    )
    parts = path.parts
    require(len(parts) >= 2, "artifact path must name a file")
    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    file_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)

    def identity(metadata):
        return metadata.st_dev, metadata.st_ino, stat.S_IFMT(metadata.st_mode)

    expected_directories = []
    prefix = Path(path.anchor)
    try:
        root_metadata = os.stat(prefix, follow_symlinks=False)
        require(stat.S_ISDIR(root_metadata.st_mode), "artifact root is not a directory")
        for component in parts[1:-1]:
            prefix /= component
            metadata = os.stat(prefix, follow_symlinks=False)
            require(
                stat.S_ISDIR(metadata.st_mode),
                "artifact path component is not a directory",
            )
            expected_directories.append(metadata)
        expected_file = os.stat(path, follow_symlinks=False)
    except OSError as exc:
        raise ValueError("artifact path is unavailable") from exc
    require(stat.S_ISREG(expected_file.st_mode), "artifact path is not a regular file")
    require(expected_file.st_nlink == 1, "artifact path must name an independent file")

    try:
        directory_descriptor = os.open(path.anchor, directory_flags)
    except OSError as exc:
        raise ValueError("artifact root is unavailable or is a symlink") from exc
    try:
        root_opened = os.fstat(directory_descriptor)
        require(
            stat.S_ISDIR(root_opened.st_mode) and identity(root_opened) == identity(root_metadata),
            "artifact root changed before opening",
        )
        for index, component in enumerate(parts[1:-1]):
            next_descriptor = os.open(
                component, directory_flags, dir_fd=directory_descriptor
            )
            try:
                opened = os.fstat(next_descriptor)
                require(
                    stat.S_ISDIR(opened.st_mode)
                    and identity(opened) == identity(expected_directories[index]),
                    "artifact path component changed before opening",
                )
            except BaseException:
                os.close(next_descriptor)
                raise
            os.close(directory_descriptor)
            directory_descriptor = next_descriptor
        descriptor = os.open(parts[-1], file_flags, dir_fd=directory_descriptor)
        try:
            metadata = os.fstat(descriptor)
            require(
                stat.S_ISREG(metadata.st_mode)
                and metadata.st_nlink == 1
                and identity(metadata) == identity(expected_file),
                "artifact descriptor changed before opening",
            )
        except BaseException:
            os.close(descriptor)
            raise
    except OSError as exc:
        raise ValueError("artifact path is unavailable or is a symlink") from exc
    except BaseException:
        raise
    finally:
        os.close(directory_descriptor)
    return descriptor


def copy_verified_artifact(
    source: Path, destination: Path, verified_fd: int
) -> None:
    """Copy only from a previously verified descriptor; ``source`` is provenance only."""
    before = os.fstat(verified_fd)
    require(
        stat.S_ISREG(before.st_mode),
        "verified artifact descriptor is not a regular file",
    )
    require(
        before.st_nlink == 1,
        "verified artifact descriptor must name an independent file",
    )
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(destination, flags, 0o600)
    try:
        offset = 0
        while True:
            chunk = os.pread(verified_fd, 1024 * 1024, offset)
            if not chunk:
                break
            written = 0
            while written < len(chunk):
                written += os.write(descriptor, chunk[written:])
            offset += len(chunk)
        after = os.fstat(verified_fd)
    finally:
        os.close(descriptor)
    require(
        (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
        == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
        "verified artifact changed while copying",
    )


MUTATION_OUTPUT_MARKER = ".fireemu-mutation-output"


def reject_mutation_artifact(path: Path) -> None:
    for parent in (path.resolve(), *path.resolve().parents):
        if (parent / MUTATION_OUTPUT_MARKER).exists():
            raise ValueError("mutation output cannot be adopted by normal verification")


def validate_normal_build(workspace: Path, environment: dict) -> None:
    metadata = subprocess.run(
        [
            "cargo",
            "metadata",
            "--offline",
            "--locked",
            "--no-deps",
            "--format-version",
            "1",
        ],
        cwd=workspace,
        env=environment,
        capture_output=True,
        text=True,
        check=True,
        timeout=60,
    )
    value = json.loads(metadata.stdout)
    for key in ("target_directory", "build_directory"):
        reject_mutation_artifact(Path(value[key]))


def build_artifact() -> tuple[Path, dict]:
    inputs = runtime_inputs(ROOT)
    # Read the limit from the full environment: it steers this Python supervisor, so the
    # sanitized child environment deliberately never carries it into cargo.
    limit = build_timeout(dict(os.environ))
    validate_normal_build(ROOT, sanitized_environment(dict(os.environ)))
    completed = run_build(BUILD_COMMAND, sanitized_environment(dict(os.environ)), limit)
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
    reject_mutation_artifact(paths[0])
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

    require(".." not in binary.parts, "owned artifact path contains '..'")
    try:
        resolved_binary = binary.resolve(strict=True)
    except OSError as exc:
        raise ValueError("owned artifact path is unavailable") from exc
    require(
        resolved_binary == binary.absolute(),
        "owned artifact path must be canonical and must not use a symlink parent",
    )
    binary = resolved_binary
    reject_mutation_artifact(binary)
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    inputs = runtime_inputs(ROOT)
    tools_before = probe_inputs("aggregation-v1")
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
        verified_fd = open_verified_artifact(binary)
        try:
            copy_verified_artifact(binary, artifact, verified_fd)
        finally:
            os.close(verified_fd)
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
                inputs == runtime_inputs(ROOT)
                and tools_before == probe_inputs("aggregation-v1"),
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
