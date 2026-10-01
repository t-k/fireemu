#!/usr/bin/env python3
"""A stand-in for the pinned fireemu binary in the launch-accounting harness tests (offline only).

It mimics only what harness H observes of `fireemu exec`: the Functions runner in a process group
of its own, discovery, the refusal path (SIGKILL of the runner's group, the refusal line, exit 1),
and on a valid time zone the exec child with a loopback control API, then shutdown with the
child's exit status. Usage: fake-fireemu.py NODE exec ... --functions DIR --http-port PORT ... -- CHILD...
"""
import json
import os
import secrets
import signal
import subprocess
import sys
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from zoneinfo import ZoneInfo


def nanos(instant):
    """RFC 3339 UTC instant to integer nanoseconds."""
    base, _, fraction = instant.rstrip("Z").partition(".")
    seconds = datetime.strptime(base, "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc).timestamp()
    return int(seconds) * 10**9 + int((fraction or "0").ljust(9, "0")[:9])


class Runner:
    def __init__(self, node, script, fixture):
        self.process = subprocess.Popen(
            [node, script, "--source", fixture, "--protocol", "lines"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            preexec_fn=lambda: os.setpgid(0, 0),
        )
        self.lock = threading.Lock()

    def read(self):
        return json.loads(self.process.stdout.readline())

    def call(self, request):
        with self.lock:
            self.process.stdin.write((json.dumps(request) + "\n").encode())
            self.process.stdin.flush()
            return self.read()

    def stop(self, kind):
        try:
            os.killpg(self.process.pid, kind)
        except ProcessLookupError:
            pass
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(self.process.pid, signal.SIGKILL)
            self.process.wait()


def serve(port, token, runner, names, schedule_time):
    state = {"fired": False}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def answer(self, status, value):
            body = json.dumps(value).encode()
            self.send_response(status)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def authorized(self):
            if self.headers.get("authorization") != "Bearer " + token:
                self.answer(401, {"error": "unauthenticated"})
                return False
            return True

        def do_GET(self):
            if self.path == "/v1/sessions/default/functions":
                if self.authorized():
                    alive = runner.process.poll() is None
                    self.answer(200, {"runnerAlive": alive, "functions": names})
            elif self.path == "/demo-scheduled-calendar/us-central1/calendarReceipt":
                self.answer(200, runner.call({"receipts": True}))
            else:
                self.answer(404, {"error": "not found"})

        def do_POST(self):
            length = int(self.headers.get("content-length") or 0)
            body = json.loads(self.rfile.read(length) or b"{}")
            if not self.authorized():
                return
            if self.path == "/v1/sessions/default:awaitIdle":
                self.answer(200, {"idle": True})
            elif self.path == "/v1/sessions/default/clock:advanceTo":
                if nanos(body["instant"]) >= nanos(schedule_time) and not state["fired"]:
                    state["fired"] = True
                    event = {"scheduleTime": schedule_time, "jobName": None}
                    runner.call({"invoke": "calendarProbe", "event": event})
                self.answer(200, {"instant": body["instant"]})
            else:
                self.answer(404, {"error": "not found"})

    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    return server


def main(argv):
    node, args = argv[1], argv[2:]
    split = args.index("--")
    options, child = args[:split], args[split + 1 :]

    def option(name):
        return options[options.index(name) + 1]

    fixture, port = option("--functions"), int(option("--http-port"))
    token = secrets.token_hex(16)
    runner = Runner(node, os.environ["FIREEMU_RUNNER_NODE"], fixture)
    # The port is held from startup, as the daemon's listener is.
    server = serve(port, token, runner, [], "")
    manifest = runner.read()
    for function in manifest:
        if function.get("kind") != "schedule":
            continue
        try:
            ZoneInfo(function["timeZone"])
        except Exception:
            runner.stop(signal.SIGKILL)
            name, zone = json.dumps(function["name"]), json.dumps(function["timeZone"])
            print(f"error: manifest: function {name}: time zone: unknown time zone {zone}", file=sys.stderr)
            server.server_close()
            return 1
    names = [function["name"] for function in manifest]
    print("functions loaded: " + ", ".join(names), file=sys.stderr, flush=True)
    with open(child[-1]) as handle:
        schedule_time = json.load(handle)["input"]["scheduleTime"]
    server.server_close()
    server = serve(port, token, runner, names, schedule_time)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    process = subprocess.Popen(
        child,
        env={
            **os.environ,
            "FIREEMU_CONTROL_URL": f"http://127.0.0.1:{port}/v1/",
            "FIREEMU_FUNCTIONS_HOST": f"127.0.0.1:{port}",
            "FIREEMU_CONTROL_TOKEN": token,
        },
        stdin=subprocess.DEVNULL,
        preexec_fn=lambda: os.setpgid(0, 0),
    )
    code = process.wait()
    runner.stop(signal.SIGTERM)
    server.shutdown()
    server.server_close()
    return code


if __name__ == "__main__":
    sys.exit(main(sys.argv))
