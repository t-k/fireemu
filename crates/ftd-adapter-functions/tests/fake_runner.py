#!/usr/bin/env python3
"""A runner that speaks the firebase-testd protocol: succeeds unless the function name
contains "fail" (fails), "slow" (never answers) or "crash" (exits)."""
import json
import sys


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


send({
    "type": "hello",
    "runner": "fake",
    "manifest": {
        "functions": [
            {"name": "ok", "trigger": {"type": "firestore", "eventType": "google.cloud.firestore.document.v1.created", "document": "items/{id}"}},
            {"name": "fail", "trigger": {"type": "firestore", "eventType": "google.cloud.firestore.document.v1.written", "document": "items/{id}"}, "retry": True},
            {"name": "slow", "trigger": {"type": "storage", "eventType": "google.cloud.storage.object.v1.finalized"}, "timeoutSeconds": 1},
            {"name": "tick", "trigger": {"type": "schedule", "schedule": "every 5 minutes"}},
            # A cron schedule (03:00 UTC daily). The tests start at 12:01 UTC, so it only
            # comes due for clock advances of a day or more.
            {"name": "nightly", "trigger": {"type": "schedule", "schedule": "0 3 * * *"}},
            {"name": "onJob", "trigger": {"type": "pubsub", "topic": "jobs"}},
            {"name": "onUser", "trigger": {"type": "auth", "eventType": "google.firebase.auth.user.v1.created"}},
            {"name": "onGone", "trigger": {"type": "auth", "eventType": "providers/firebase.auth/eventTypes/user.delete"}},
            {"name": "withAuth", "trigger": {"type": "firestore", "eventType": "google.cloud.firestore.document.v1.written.withAuthContext", "document": "audited/{id}"}},
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
