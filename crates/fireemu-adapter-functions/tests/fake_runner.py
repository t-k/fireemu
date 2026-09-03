#!/usr/bin/env python3
"""A runner that speaks the fireemu protocol: succeeds unless the function name
contains "fail" (fails), "slow" (never answers) or "crash" (exits).

It also hosts an HTTP server that echoes what the daemon's proxy actually forwarded --
method, path and every header instance in wire order -- which is how the callable trust
boundary of specification section 13.4 is checked from the outside: a test asserts on the
bytes that reach the runner, not on the daemon's intent.

FIREEMU_FAKE_CONSUME=enabled|undetermined makes the guarded callable declare that
consumeAppCheckToken value, for the fail-closed discovery tests.
"""
import http.server
import json
import os
import pathlib
import sys
import threading
import time


def send(msg):
    payload = json.dumps(msg).encode()
    sys.stdout.buffer.write(f"{len(payload)}\n".encode())
    sys.stdout.buffer.write(payload)
    sys.stdout.buffer.flush()


def read_frame():
    line = sys.stdin.buffer.readline()
    if not line:
        return None
    n = int(line.strip())
    return json.loads(sys.stdin.buffer.read(n))


class Echo(http.server.BaseHTTPRequestHandler):
    hold_condition = threading.Condition()
    hold_entries = 0

    def do_POST(self):  # noqa: N802 - the stdlib spelling
        length = int(self.headers.get("content-length") or 0)
        body = self.rfile.read(length) if length else b""
        task_probe = os.environ.get("FIREEMU_FAKE_TASK_PROBE")
        if task_probe and self.path.rsplit("/", 1)[-1] in {"taskA", "taskB"}:
            queue = self.path.rsplit("/", 1)[-1]
            task_name = self.headers.get("x-cloudtasks-taskname", "")
            failing = "failing" in task_name
            entry = queue
            if failing:
                entry = (
                    f"{queue}:{self.headers.get('x-cloudtasks-taskretrycount')}:"
                    f"{self.headers.get('x-cloudtasks-taskexecutioncount')}"
                )
            with self.hold_condition:
                with open(task_probe, "a", encoding="utf-8") as probe:
                    probe.write(f"{entry}\n")
                    probe.flush()
                self.hold_condition.notify_all()
            if failing:
                self.send_response(500)
                self.end_headers()
                return
            release = pathlib.Path(f"{task_probe}.{queue}.release")
            while not release.exists():
                time.sleep(0.01)
            self.send_response(204)
            self.end_headers()
            return
        if self.path.endswith("/beforeCreate"):
            time.sleep(int(os.environ.get("FIREEMU_FAKE_BLOCKING_HANG_MS", "0")) / 1000)
        if self.path == "/hold":
            with self.hold_condition:
                type(self).hold_entries += 1
                self.hold_condition.notify_all()
                self.hold_condition.wait_for(lambda: type(self).hold_entries >= 2, timeout=2)
            self.send_response(204)
            self.end_headers()
            return
        payload = json.dumps(
            {
                "method": self.command,
                "path": self.path,
                # Every instance, in wire order: what the proxy actually sent.
                "headers": [[k.lower(), v] for k, v in self.headers.items()],
                "body": body.decode("utf-8", "replace"),
            }
        ).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    do_GET = do_POST
    do_PUT = do_POST

    def log_message(self, *_args):
        pass


echo = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Echo)
threading.Thread(target=echo.serve_forever, daemon=True).start()

consume = os.environ.get("FIREEMU_FAKE_CONSUME", "disabled")
time.sleep(int(os.environ.get("FIREEMU_FAKE_HELLO_DELAY_MS", "0")) / 1000)

send({
    "type": "hello",
    "runner": "fake",
    "httpPort": echo.server_address[1],
    "appCheck": {
        "firebaseFunctionsVersion": "0.0.0-fake",
        "instrumentation": "ok",
        "debugFeatures": "verified",
        "debugMode": os.environ.get("FIREBASE_DEBUG_MODE") == "true",
        "authHeaders": ["x-callable-context-auth", "x-original-auth"],
    },
    "manifest": {
        "functions": [
            {"name": "ok", "trigger": {"type": "firestore", "eventType": "google.cloud.firestore.document.v1.created", "document": "items/{id}"}},
            {"name": "fail", "trigger": {"type": "firestore", "eventType": "google.cloud.firestore.document.v1.written", "document": "items/{id}"}, "retry": True},
            {"name": "slow", "trigger": {"type": "storage", "eventType": "google.cloud.storage.object.v1.finalized"}, "timeoutSeconds": 1},
            {"name": "tick", "trigger": {"type": "schedule", "schedule": "every 5 minutes"}},
            # A cron schedule (03:00 UTC daily). The tests start at 12:01 UTC, so it only
            # comes due for clock advances of a day or more.
            {"name": "nightly", "trigger": {"type": "schedule", "schedule": "0 3 * * *"}},
            {"name": "failSchedule", "trigger": {"type": "schedule", "schedule": "0 3 * * *", "retryConfig": {"retryCount": 2, "minBackoffSeconds": 3, "maxBackoffSeconds": 30, "maxDoublings": 1, "maxRetrySeconds": 60}}, "retry": True},
            {"name": "onJob", "trigger": {"type": "pubsub", "topic": "jobs"}},
            {"name": "onUser", "trigger": {"type": "auth", "eventType": "google.firebase.auth.user.v1.created"}},
            {"name": "onGone", "trigger": {"type": "auth", "eventType": "providers/firebase.auth/eventTypes/user.delete"}},
            {"name": "withAuth", "trigger": {"type": "firestore", "eventType": "google.cloud.firestore.document.v1.written.withAuthContext", "document": "audited/{id}"}},
            {"name": "echo", "trigger": {"type": "http", "callable": False}},
            {"name": "hold", "generation": 2, "concurrency": None, "platformOptions": {"availableMemoryMb": 2048}, "trigger": {"type": "http", "callable": False}},
            {"name": "add", "trigger": {"type": "http", "callable": True, "enforceAppCheck": False, "consumeAppCheckToken": "disabled"}},
            {"name": "guarded", "trigger": {"type": "http", "callable": True, "enforceAppCheck": True, "consumeAppCheckToken": consume}},
        ]
    },
})
while True:
    msg = read_frame()
    if msg is None or msg.get("type") == "shutdown":
        break
    if msg.get("type") != "invoke":
        continue
    name = msg["function"]
    if "crash" in name:
        sys.exit(3)
    if "slow" in name:
        continue
    send({"type": "log", "level": "info", "message": f"invoked {name}", "invocationId": msg["invocationId"]})
    if "fail" in name:
        send({"type": "result", "invocationId": msg["invocationId"], "ok": False, "error": f"{name} failed"})
    else:
        send({"type": "result", "invocationId": msg["invocationId"], "ok": True})
