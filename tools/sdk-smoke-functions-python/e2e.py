"""End-to-end checks of the Python runner, run by `fireemu exec` under the fixture's own interpreter.

    fireemu exec --project demo-py ... -- venv/bin/python e2e.py

The environment is what `exec` gives a test command (`FIREEMU_FUNCTIONS_HOST`, `FIRESTORE_EMULATOR_HOST`,
`FIREBASE_AUTH_EMULATOR_HOST`); `E2E_PROFILE` is `emulator` or `strict`. The standard library only.
"""

import json
import os
import sys
import time
import urllib.error
import urllib.request

PROJECT = os.environ.get("GCLOUD_PROJECT", "demo-py")
FUNCTIONS = f"http://{os.environ['FIREEMU_FUNCTIONS_HOST']}/{PROJECT}/us-central1"
FIRESTORE = f"http://{os.environ['FIRESTORE_EMULATOR_HOST']}/v1/projects/{PROJECT}/databases/(default)/documents"
AUTH = f"http://{os.environ['FIREBASE_AUTH_EMULATOR_HOST']}/identitytoolkit.googleapis.com/v1"
PROFILE = os.environ.get("E2E_PROFILE", "emulator")


OWNER = {"Authorization": "Bearer owner"}  # the emulators' admin credential: Firestore rules are not under test


def call(method, url, body=None, headers=None):
    data = None if body is None else json.dumps(body).encode()
    request = urllib.request.Request(url, data=data, method=method, headers={"Content-Type": "application/json", **(headers or {})})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


def seen():
    status, body = call("GET", f"{FUNCTIONS}/seen")
    assert status == 200, (status, body)
    return json.loads(body)


def wait_for(predicate, what):
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        entries = seen()
        found = [entry for entry in entries if predicate(entry)]
        if found:
            return found[-1]
        time.sleep(0.2)
    raise AssertionError(f"timed out waiting for {what}; saw {seen()}")


def main():
    status, body = call("GET", f"{FUNCTIONS}/hello/a/b?q=1")
    assert status == 200, (status, body)
    answer = json.loads(body)
    assert answer["path"] == "/a/b" and answer["args"] == {"q": "1"}, answer

    # A Firestore write fires the Python trigger.
    status, body = call("POST", f"{FIRESTORE}/items?documentId=e1", {"fields": {"n": {"integerValue": "1"}}}, OWNER)
    assert status == 200, (status, body)
    created = wait_for(lambda e: e["function"] == "fs_created" and e["snapshot"]["path"] == "items/e1", "fs_created")
    assert created["snapshot"]["data"] == {"n": 1} and created["params"] == {"id": "e1"}, created
    status, body = call("PATCH", f"{FIRESTORE}/items/e1?updateMask.fieldPaths=n", {"fields": {"n": {"integerValue": "2"}}}, OWNER)
    assert status == 200, (status, body)
    updated = wait_for(lambda e: e["function"] == "fs_updated" and e["after"]["path"] == "items/e1", "fs_updated")
    assert updated["before"]["data"] == {"n": 1} and updated["after"]["data"] == {"n": 2}, updated
    status, body = call("DELETE", f"{FIRESTORE}/items/e1", None, OWNER)
    assert status == 200, (status, body)
    deleted = wait_for(lambda e: e["function"] == "fs_deleted" and e["snapshot"]["path"] == "items/e1", "fs_deleted")
    assert deleted["snapshot"]["data"] == {"n": 2}, deleted
    # A literal document path.
    status, body = call("POST", f"{FIRESTORE}/settings?documentId=global", {"fields": {"k": {"stringValue": "v"}}}, OWNER)
    assert status == 200, (status, body)
    wait_for(lambda e: e["function"] == "fs_literal" and e["after"]["data"] == {"k": "v"}, "fs_literal")

    # A callable, anonymous and with a user the Auth emulator created.
    status, body = call("POST", f"{FUNCTIONS}/add", {"data": {"a": 2, "b": 3}})
    assert (status, json.loads(body)) == (200, {"result": {"sum": 5, "uid": None}}), (status, body)
    status, body = call("POST", f"{AUTH}/accounts:signUp?key=fake", {"returnSecureToken": True})
    assert status == 200, (status, body)
    user = json.loads(body)
    status, body = call("POST", f"{FUNCTIONS}/add", {"data": {"a": 2, "b": 3}}, {"Authorization": f"Bearer {user['idToken']}"})
    assert (status, json.loads(body)) == (200, {"result": {"sum": 5, "uid": user["localId"]}}), (status, body)
    if PROFILE == "strict":
        # The strict ingress verifies the Bearer before the SDK sees it.
        status, body = call("POST", f"{FUNCTIONS}/add", {"data": {"a": 1, "b": 1}}, {"Authorization": "Bearer not-a-token"})
        assert status == 401, (status, body)
    print(json.dumps({"ok": True, "profile": PROFILE}))


if __name__ == "__main__":
    try:
        main()
    except AssertionError as error:
        print(f"e2e failed: {error}", file=sys.stderr)
        sys.exit(1)
