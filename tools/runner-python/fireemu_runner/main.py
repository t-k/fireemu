"""The runner process: load the codebase, say hello, serve frames until told to stop."""

import argparse
import os
import platform
import sys
import traceback

from . import appcheck, blocking
from .dispatch import Dispatcher
from .environment import EnvironmentGate, load_local_secrets
from .framing import FrameWriter, ProtocolError, read_frame
from .manifest import build_manifest
from .serve import HTTP_TRIGGERS, start_server


def _parse(argv):
    parser = argparse.ArgumentParser(prog="runner.py")
    parser.add_argument("--source", required=True)
    parser.add_argument("--codebase", default="default")
    return parser.parse_args(argv)


def load_codebase(source: str) -> dict:
    """Imports the codebase's `main.py` the way the SDK's own admin server does and returns its functions."""
    os.chdir(source)
    from firebase_functions.private import serving

    return serving.get_functions()


def serve(
    functions: dict, codebase: str, secret: str, stdin, writer: FrameWriter, gate: EnvironmentGate | None = None, app_check_verified: bool = False, blocking_verified: bool = False
) -> int:
    """Says hello, then serves frames from `stdin` until `shutdown` or the end of the stream."""
    manifest = build_manifest(functions, app_check_verified)
    if not blocking_verified and any(spec["trigger"]["type"] == "blockingAuth" for spec in manifest["functions"]):
        blocking.announce_default_note(sys.stderr)
    server = None
    port = None
    if any(spec["trigger"]["type"] in HTTP_TRIGGERS for spec in manifest["functions"]):
        server, port = start_server(functions, manifest, secret, gate)
    writer.write(
        {
            "type": "hello",
            "runner": "python",
            "codebase": codebase,
            "version": platform.python_version(),
            "httpPort": port,
            "manifest": manifest,
        }
    )
    dispatcher = Dispatcher(functions, manifest, writer, gate)
    try:
        while True:
            message = read_frame(stdin)
            if message is None or message["type"] == "shutdown":
                return 0
            if not dispatcher.reserve():
                sys.stderr.write("[functions] too many active invocations\n")
                return 2
            dispatcher.start(message)
    except ProtocolError as error:
        sys.stderr.write(f"[functions] {error}\n")
        return 2
    finally:
        if server is not None:
            server.shutdown()


def run(argv) -> int:
    args = _parse(argv)
    # The protocol owns the original stdout. Everything that writes to file descriptor 1 afterwards
    # (print, C extensions, child processes, the SDK logger) goes to stderr instead.
    protocol = os.fdopen(os.dup(1), "wb", buffering=0)
    os.dup2(2, 1)
    writer = FrameWriter(protocol)
    secret = os.environ.get("FIREEMU_RUNNER_SECRET", "")
    # The daemon's local secrets are put back into the environment, a function at a time, by the gate; user code
    # does not see the channel that carried them, nor the key to this runner's HTTP port.
    os.environ.pop("FIREEMU_RUNNER_SECRET", None)
    try:
        gate = EnvironmentGate(load_local_secrets(os.environ))
    except ValueError as error:
        sys.stderr.write(f"[functions] {error}\n")
        return 1
    # Before any user code runs, so the Admin SDK's App Check service is built against the emulator's keys.
    app_check_verified = appcheck.install_from_environment(os.environ)
    blocking_verified = blocking.install_from_environment(os.environ)
    try:
        functions = load_codebase(args.source)
    except BaseException:  # a failing import in user code is reported with its traceback
        traceback.print_exc()
        return 1
    if blocking_verified:
        return serve(functions, args.codebase, secret, sys.stdin.buffer, writer, gate, app_check_verified, blocking_verified=True)
    return serve(functions, args.codebase, secret, sys.stdin.buffer, writer, gate, app_check_verified)
