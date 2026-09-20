"""Owned local daemon startup and bounded stdout draining (POSIX).

This proves only the directly owned process and the sampled direct-child set,
not an OS-wide process census, escaped descendants, or binary authenticity.
"""
from __future__ import annotations

import json
import os
import re
import selectors
import signal
import subprocess
import threading
import time
from pathlib import Path
from typing import Any

from credential_wire import validate_url

PROJECT = "demo-app"
STARTUP_SECONDS = 60.0
STOP_SECONDS = 20.0
CENSUS_SECONDS = 2.0
MAX_STARTUP_BYTES = 262144
MAX_STARTUP_LINE_BYTES = 8192
READY_PATTERN = re.compile(rb"auth \(REST\):\s+(\S+)")


class StartupError(Exception):
    """Fixed diagnostics only; daemon output may contain credentials."""


def _auth_origin(address: bytes) -> str:
    try:
        text = address.decode("utf-8", errors="strict")
        if any(char in text for char in "/?#"):
            raise ValueError("not a bare address")
        value = "http://" + text
        validate_url(value + "/")
        return value
    except (ValueError, UnicodeError):
        raise StartupError("daemon reported an invalid local auth address") from None


class _OutputMonitor:
    def __init__(self, stream: Any):
        self.stream = stream
        self.ready = threading.Event()
        self.halt = threading.Event()
        self.origin: str | None = None
        self.failure: str | None = None
        self.thread = threading.Thread(target=self._run, daemon=True,
                                       name="credential-daemon-output")

    def _run(self) -> None:
        selector = None
        pending = bytearray()
        received = 0
        try:
            fd = self.stream.fileno()
            os.set_blocking(fd, False)
            selector = selectors.DefaultSelector()
            selector.register(fd, selectors.EVENT_READ)
            while not self.halt.is_set():
                if not selector.select(0.05):
                    continue
                try:
                    chunk = os.read(fd, 65536)
                except BlockingIOError:
                    continue
                if not chunk:
                    if self.origin is None:
                        self.failure = "startup-output-ended"
                    return
                # After ready, keep draining but retain no daemon output.
                if self.origin is not None or self.failure is not None:
                    continue
                received += len(chunk)
                if received > MAX_STARTUP_BYTES:
                    raise StartupError("startup-output-limit")
                pending.extend(chunk)
                while b"\n" in pending:
                    end = pending.index(b"\n")
                    if end > MAX_STARTUP_LINE_BYTES:
                        raise StartupError("startup-line-limit")
                    line = bytes(pending[:end])
                    del pending[:end + 1]
                    match = READY_PATTERN.search(line)
                    if match:
                        self.origin = _auth_origin(match.group(1))
                        pending.clear()
                        self.ready.set()
                        break
                if len(pending) > MAX_STARTUP_LINE_BYTES:
                    raise StartupError("startup-line-limit")
        except Exception as error:
            self.failure = (str(error) if isinstance(error, StartupError)
                            else "output-monitor-" + type(error).__name__)
        finally:
            self.ready.set()
            if selector is not None:
                try:
                    selector.close()
                except Exception:
                    self.failure = self.failure or "output-selector-close-failed"

    def stop(self) -> bool:
        self.halt.set()
        if self.thread.ident is not None:
            self.thread.join(timeout=1.0)
        return not self.thread.is_alive()


def _children_of(pid: int) -> list[int]:
    result = subprocess.run(["/usr/bin/pgrep", "-P", str(pid)], capture_output=True,
                            text=True, timeout=CENSUS_SECONDS, check=False)
    if result.returncode == 1 and not result.stdout.strip():
        return []
    if result.returncode != 0 or any(not line.isdigit() for line in result.stdout.split()):
        raise StartupError("child census unavailable")
    return [int(line) for line in result.stdout.split()]


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True  # Cannot prove absence.
    return True


def stop_daemon(process: subprocess.Popen[bytes]) -> dict[str, Any]:
    """Always try leader shutdown, even when child census or pipe cleanup fails."""
    problems: list[str] = []
    children: list[int] | None = None
    try:
        children = _children_of(process.pid)
    except Exception as error:
        problems.append("child-census-" + type(error).__name__)
    try:
        if process.poll() is None:
            # Only a group whose still-owned leader is alive is eligible for signals.
            if getattr(process, "_credential_owned_group", False):
                os.killpg(process.pid, signal.SIGTERM)
            else:
                process.send_signal(signal.SIGTERM)
        try:
            process.wait(timeout=STOP_SECONDS)
        except subprocess.TimeoutExpired:
            if process.poll() is None:
                if getattr(process, "_credential_owned_group", False):
                    os.killpg(process.pid, signal.SIGKILL)
                else:
                    process.kill()
            process.wait(timeout=STOP_SECONDS)
    except ProcessLookupError:
        process.wait(timeout=STOP_SECONDS)
    except Exception as error:
        problems.append("process-stop-" + type(error).__name__)
    remaining = None
    if children is not None:
        try:
            remaining = sum(_alive(pid) for pid in children)
        except Exception as error:
            problems.append("child-check-" + type(error).__name__)
    monitor = getattr(process, "_credential_output_monitor", None)
    drained = True
    if monitor is not None:
        try:
            drained = monitor.stop()
            if monitor.failure:
                problems.append("daemon-output-unconfirmed")
        except Exception as error:
            drained = False
            problems.append("monitor-stop-" + type(error).__name__)
    if drained and process.stdout is not None:
        try:
            process.stdout.close()
        except Exception as error:
            drained = False
            problems.append("stdout-close-" + type(error).__name__)
    return {
        "exitCode": process.poll(), "processStopped": process.poll() is not None,
        "childrenBeforeStop": None if children is None else len(children),
        "remainingChildren": remaining, "outputDrainerStopped": drained,
        "failures": problems,
    }


def start_daemon(binary: Path, workdir: Path) -> tuple[subprocess.Popen[bytes], str]:
    """Start once, fail closed on readiness errors, and drain output through shutdown."""
    binary = binary.resolve(strict=True)
    config = workdir / "fireemu.shadow.json"
    with config.open("x", encoding="utf-8") as stream:
        json.dump({"schemaVersion": 1, "profile": "strict"}, stream)
    env = {key: os.environ[key] for key in ("PATH", "SYSTEMROOT", "LANG", "LC_ALL")
           if key in os.environ}
    env.update(HOME=str(workdir), NO_COLOR="1")
    process = subprocess.Popen(
        [str(binary), "up", "--config", str(config), "--project", PROJECT, "--only", "auth",
         "--http-port", "0", "--hub-port", "0", "--ui-port", "0", "--logging-port", "0"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
        bufsize=0, cwd=str(workdir), env=env, start_new_session=True,
    )
    process._credential_owned_group = True
    try:
        if process.stdout is None:
            raise StartupError("daemon output pipe unavailable")
        monitor = _OutputMonitor(process.stdout)
        process._credential_output_monitor = monitor
        monitor.thread.start()
        deadline = time.monotonic() + STARTUP_SECONDS
        while True:
            if monitor.failure is not None:
                raise StartupError("daemon readiness output invalid")
            if process.poll() is not None:
                raise StartupError("daemon exited before readiness")
            if monitor.origin is not None:
                return process, monitor.origin
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise StartupError("daemon startup deadline exceeded")
            monitor.ready.wait(timeout=min(0.05, remaining))
    except BaseException:
        # The caller has not received process ownership yet; do not leak it here.
        shutdown = stop_daemon(process)
        if not shutdown["processStopped"]:
            raise StartupError("daemon startup failed; leader stop unconfirmed") from None
        raise
