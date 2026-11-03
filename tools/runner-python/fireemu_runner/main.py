"""The runner process: load the codebase, say hello, serve frames until told to stop."""

import argparse
import os
import platform
import sys
import traceback

from .dispatch import Dispatcher
from .framing import FrameWriter, ProtocolError, read_frame
from .manifest import build_manifest
from .serve import start_server


def _parse(argv):
    parser = argparse.ArgumentParser(prog="runner.py")
    parser.add_argument("--source", required=True)
    parser.add_argument("--codebase", default="default")
    return parser.parse_args(argv)


def run(argv) -> int:
    args = _parse(argv)
    # The protocol owns the original stdout. Everything that writes to file descriptor 1 afterwards
    # (print, C extensions, child processes, the SDK logger) goes to stderr instead.
    protocol = os.fdopen(os.dup(1), "wb", buffering=0)
    os.dup2(2, 1)
    writer = FrameWriter(protocol)
    secret = os.environ.get("FIREEMU_RUNNER_SECRET", "")
    # The daemon's local secrets are for the SDK's parameter lookup; user code does not see the channel
    # that carried them, nor the key to this runner's HTTP port.
    os.environ.pop("FIREEMU_LOCAL_SECRETS_JSON", None)
    os.environ.pop("FIREEMU_RUNNER_SECRET", None)
    os.chdir(args.source)
    try:
        from firebase_functions.private import serving

        functions = serving.get_functions()
    except BaseException:  # a failing import in user code is reported with its traceback
        traceback.print_exc()
        return 1
    manifest = build_manifest(functions)
    server = None
    port = None
    if any(spec["trigger"]["type"] == "http" for spec in manifest["functions"]):
        server, port = start_server(functions, manifest, secret)
    writer.write(
        {
            "type": "hello",
            "runner": "python",
            "codebase": args.codebase,
            "version": platform.python_version(),
            "httpPort": port,
            "manifest": manifest,
        }
    )
    dispatcher = Dispatcher(functions, manifest, writer)
    try:
        while True:
            message = read_frame(sys.stdin.buffer)
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
