"""End-to-end checks of the Python runner, run by `fireemu exec` under the fixture's own interpreter.

    fireemu exec --project demo-py ... -- venv/bin/python e2e.py

The environment is what `exec` gives a test command (`FIREEMU_FUNCTIONS_HOST`, `FIRESTORE_EMULATOR_HOST`,
`FIREBASE_AUTH_EMULATOR_HOST`); `E2E_PROFILE` is `emulator` or `strict`. The standard library only.
"""

import base64
import http.client
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
PUBSUB = f"http://{os.environ['PUBSUB_EMULATOR_HOST']}/v1/projects/{PROJECT}"
STORAGE = f"http://{os.environ['FIREBASE_STORAGE_EMULATOR_HOST'].removeprefix('http://')}"
DATABASE = f"http://{os.environ['FIREBASE_DATABASE_EMULATOR_HOST']}"
CONTROL = f"http://{os.environ['FIREBASE_AUTH_EMULATOR_HOST']}/v1/sessions/default"
TASKS = "http://" + os.environ["CLOUD_TASKS_EMULATOR_HOST"].removeprefix("http://")
EVENTARC = "http://" + os.environ["CLOUD_EVENTARC_EMULATOR_HOST"].removeprefix("http://")
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


def b64(value):
    return base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip("=")


def call_with_two_authorizations(first, second):
    """POST to the callable `add` with the `Authorization` header twice (urllib cannot send it twice)."""
    connection = http.client.HTTPConnection(os.environ["FIREEMU_FUNCTIONS_HOST"], timeout=30)
    body = json.dumps({"data": {"a": 1, "b": 1}}).encode()
    connection.putrequest("POST", f"/{PROJECT}/us-central1/add")
    connection.putheader("Content-Type", "application/json")
    connection.putheader("Content-Length", str(len(body)))
    connection.putheader("Authorization", first)
    connection.putheader("Authorization", second)
    connection.endheaders(body)
    response = connection.getresponse()
    result = (response.status, response.read())
    connection.close()
    return result


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


def call_raw(method, url, data, headers):
    request = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


def other_families():
    """Pub/Sub, Storage, Eventarc and Realtime Database events reach their Python handlers."""
    # Pub/Sub: a plain message, then one with an ordering key.
    status, body = call("PUT", f"{PUBSUB}/topics/orders", {})
    assert status in (200, 409), (status, body)
    message = {"data": base64.b64encode(b"hello").decode(), "attributes": {"k": "v"}}
    status, body = call("POST", f"{PUBSUB}/topics/orders:publish", {"messages": [message]})
    assert status == 200, (status, body)
    plain = wait_for(lambda e: e["function"] == "ps_orders" and e["ordering_key"] is None, "ps_orders")
    assert plain["text"] == "hello" and plain["attributes"] == {"k": "v"} and plain["message_id"], plain
    assert plain["publish_time"] and plain["type"] == "google.cloud.pubsub.topic.v1.messagePublished", plain
    status, body = call("POST", f"{PUBSUB}/topics/orders:publish", {"messages": [{**message, "orderingKey": "customer-7"}]})
    assert status == 200, (status, body)
    wait_for(lambda e: e["function"] == "ps_orders" and e["ordering_key"] == "customer-7", "ps_orders with an ordering key")

    # Storage: an upload finalizes, a metadata change updates, a delete deletes.
    bucket = "demo-bucket"
    status, body = call_raw(
        "POST", f"{STORAGE}/upload/storage/v1/b/{bucket}/o?uploadType=media&name=photos%2Fa.txt", b"abc",
        {"Content-Type": "text/plain", **OWNER},
    )
    assert status == 200, (status, body)
    finalized = wait_for(lambda e: e["function"] == "st_finalized" and e["object"] == "photos/a.txt", "st_finalized")
    assert (finalized["bucket"], finalized["size"], finalized["content_type"]) == (bucket, "3", "text/plain"), finalized
    status, body = call("PATCH", f"{STORAGE}/storage/v1/b/{bucket}/o/photos%2Fa.txt", {"metadata": {"colour": "red"}}, OWNER)
    assert status == 200, (status, body)
    wait_for(lambda e: e["function"] == "st_metadata" and e["metadata"] == {"colour": "red"}, "st_metadata")
    status, body = call("DELETE", f"{STORAGE}/storage/v1/b/{bucket}/o/photos%2Fa.txt", None, OWNER)
    assert status in (200, 204), (status, body)
    wait_for(lambda e: e["function"] == "st_deleted" and e["object"] == "photos/a.txt", "st_deleted")
    # A function with no bucket listens to the default bucket.
    status, body = call_raw(
        "POST", f"{STORAGE}/upload/storage/v1/b/{PROJECT}.appspot.com/o?uploadType=media&name=default.txt", b"d",
        {"Content-Type": "text/plain", **OWNER},
    )
    assert status == 200, (status, body)
    wait_for(lambda e: e["function"] == "st_default_bucket" and e["object"] == "default.txt", "st_default_bucket")

    # Eventarc: a custom event, and a filtered one.
    def publish(event_type, channel, data, attributes=None):
        proto = {
            "@type": "type.googleapis.com/io.cloudevents.v1.CloudEvent",
            "id": "evt-" + event_type,
            "source": "https://example.com/things",
            "specVersion": "1.0",
            "type": event_type,
            # The emulator profile asks for both, as the official emulator does.
            "attributes": {
                "datacontenttype": {"ceString": "application/json"},
                "time": {"ceTimestamp": "2026-01-01T00:00:02.500Z"},
                **(attributes or {}),
            },
            "textData": json.dumps(data),
        }
        return call("POST", f"{EVENTARC}/projects/{PROJECT}/locations/us-central1/channels/{channel}:publishEvents", {"events": [proto]}, OWNER)

    status, body = publish("acme.thing.v1.happened", "firebase", {"thing": 7})
    assert status == 200, (status, body)
    custom = wait_for(lambda e: e["function"] == "ea_plain", "ea_plain")
    assert custom["data"] == {"thing": 7} and custom["type"] == "acme.thing.v1.happened", custom
    status, body = publish("acme.thing.v1.filtered", "acme", {"thing": 8}, {"colour": {"ceString": "blue"}})
    assert status == 200, (status, body)
    status, body = publish("acme.thing.v1.filtered", "acme", {"thing": 9}, {"colour": {"ceString": "red"}})
    assert status == 200, (status, body)
    filtered = wait_for(lambda e: e["function"] == "ea_filtered", "ea_filtered")
    assert filtered["data"] == {"thing": 9}, filtered
    assert [e["data"] for e in seen() if e["function"] == "ea_filtered"] == [{"thing": 9}], "the filter admitted a blue event"

    # Realtime Database: create, update, delete.
    namespace = f"{PROJECT}-default-rtdb"
    path = f"{DATABASE}/messages/r1/m1.json?ns={namespace}"
    status, body = call("PUT", path, {"text": "hi", "n": 1}, OWNER)
    assert status == 200, (status, body)
    created = wait_for(lambda e: e["function"] == "db_created" and e["reference"] == "messages/r1/m1", "db_created")
    assert created["value"] == {"text": "hi", "n": 1} and created["params"] == {"room": "r1", "id": "m1"}, created
    status, body = call("PATCH", path, {"n": 2}, OWNER)
    assert status == 200, (status, body)
    updated = wait_for(lambda e: e["function"] == "db_updated" and e["reference"] == "messages/r1/m1", "db_updated")
    assert updated["before"] == {"text": "hi", "n": 1} and updated["after"] == {"text": "hi", "n": 2}, updated
    status, body = call("DELETE", path, None, OWNER)
    assert status == 200, (status, body)
    deleted = wait_for(lambda e: e["function"] == "db_deleted" and e["reference"] == "messages/r1/m1", "db_deleted")
    assert deleted["value"] == {"text": "hi", "n": 2}, deleted


def await_idle():
    status, body = call("POST", f"{CONTROL}:awaitIdle", {"timeoutSeconds": 60})
    assert status == 200, (status, body)


def request_families():
    """Scheduler, task queue and Auth blocking functions: the daemon calls the Python SDK's HTTP wrappers."""
    # Scheduler: the daemon's clock runs the five-minute schedule; a manual run works too.
    status, body = call("POST", f"{CONTROL}/clock:advance", {"seconds": 6 * 60})
    assert status == 200, (status, body)
    await_idle()
    ran = wait_for(lambda e: e["function"] == "sch_ok", "sch_ok")
    assert ran["job_name"] == "firebase-schedule-sch_ok-us-central1" and ran["schedule_time"], ran
    wait_for(lambda e: e["function"] == "sch_boom", "sch_boom (it raises; the attempt fails and is not retried)")
    before = len([e for e in seen() if e["function"] == "sch_ok"])
    status, body = call("POST", f"{CONTROL}/functions/sch_ok:run", {})
    assert status == 200, (status, body)
    await_idle()
    assert len([e for e in seen() if e["function"] == "sch_ok"]) == before + 1

    # Task queue: the Cloud Tasks emulator posts the callable-format body to the function.
    task = {"httpRequest": {"url": "", "headers": {"Content-Type": "application/json"}, "body": base64.b64encode(json.dumps({"data": {"n": 5}}).encode()).decode()}}
    status, body = call("POST", f"{TASKS}/projects/{PROJECT}/locations/us-central1/queues/tk_echo/tasks", {"task": task})
    assert status == 200, (status, body)
    await_idle()
    wait_for(lambda e: e["function"] == "tk_echo" and e["data"] == {"n": 5}, "tk_echo")

    # Auth blocking: beforeCreate runs when the Auth emulator creates the account, beforeSignIn when it signs in.
    status, body = call("POST", f"{AUTH}/accounts:signUp?key=fake", {"email": "plain@example.com", "password": "secret1", "returnSecureToken": True})
    assert status == 200, (status, body)
    created = wait_for(lambda e: e["function"] == "bc_user" and e["email"] == "plain@example.com", "bc_user")
    assert created["uid"] and created["event_type"].endswith("beforeCreate"), created
    status, body = call("POST", f"{AUTH}/accounts:signUp?key=fake", {"email": "blocked@example.com", "password": "secret1", "returnSecureToken": True})
    assert status == 400 and b"no accounts for you" in body, (status, body)
    status, body = call("POST", f"{AUTH}/accounts:signUp?key=fake", {"email": "claims@example.com", "password": "secret1", "returnSecureToken": True})
    assert status == 200, (status, body)
    assert json.loads(base64.urlsafe_b64decode(json.loads(body)["idToken"].split(".")[1] + "==")).get("tier") == "gold", body
    status, body = call("POST", f"{AUTH}/accounts:signInWithPassword?key=fake", {"email": "plain@example.com", "password": "secret1", "returnSecureToken": True})
    assert status == 200, (status, body)
    wait_for(lambda e: e["function"] == "bs_user" and e["email"] == "plain@example.com", "bs_user")


def secrets_by_function():
    """`.secret.local` holds API_KEY and TOKEN; a function sees only the ones it declares."""
    def env(path):
        status, body = call("GET", f"{FUNCTIONS}/{path}")
        assert status == 200, (path, status, body)
        return json.loads(body)["env"]

    assert env("reads_key") == {"API_KEY": "e2e-key-value", "TOKEN": None}
    assert env("reads_nothing") == {"API_KEY": None, "TOKEN": None}
    status, body = call("GET", f"{FUNCTIONS}/reads_token")
    assert status == 200 and json.loads(body)["param"] == "e2e-token-value", (status, body)
    call("POST", f"{FIRESTORE}/secret?documentId=s1", {"fields": {}}, OWNER)
    call("POST", f"{FIRESTORE}/plain?documentId=p1", {"fields": {}}, OWNER)
    assert wait_for(lambda e: e["function"] == "fs_secret", "fs_secret")["env"] == {"API_KEY": "e2e-key-value", "TOKEN": None}
    assert wait_for(lambda e: e["function"] == "fs_plain", "fs_plain")["env"] == {"API_KEY": None, "TOKEN": None}


def negative_ingress():
    """What the public Functions URL and the Auth emulator refuse for the new function kinds."""
    ran = lambda: len([e for e in seen() if e["function"] == "tk_echo"])  # noqa: E731
    before = ran()
    body = {"data": {"n": 9}}
    unsigned = b64({"alg": "none", "typ": "JWT"}) + "." + b64({"iss": "https://accounts.google.com", "aud": "x", "exp": 4102444800}) + "."
    attempts = [("no credentials", {}), ("a forged bearer", {"Authorization": f"Bearer {unsigned}"}), ("the queue header alone", {"x-cloudtasks-queuename": "tk_echo"})]
    for label, headers in attempts:
        status, response = call("POST", f"{FUNCTIONS}/tk_echo", body, headers)
        if PROFILE == "strict":
            assert status in (401, 403) and b'"result"' not in response, (label, status, response)
        else:
            assert status == 200, (label, status, response)  # the official emulator serves a task function to anyone
    assert ran() == before + (0 if PROFILE == "strict" else len(attempts)), (before, ran())
    # A blocking function has no public URL, whoever asks.
    for headers in ({}, OWNER):
        status, response = call("POST", f"{FUNCTIONS}/bc_user", {"data": {"jwt": unsigned}}, headers)
        assert status == 404, (status, response)
    # The SDK refuses a reserved claim name and an oversized payload.
    for email, fragment in (("reserved@example.com", b""), ("oversized@example.com", b"")):
        status, response = call("POST", f"{AUTH}/accounts:signUp?key=fake", {"email": email, "password": "secret1", "returnSecureToken": True})
        assert status == 400 and fragment in response and b"idToken" not in response, (email, status, response)
    # A `sub` claim passes the SDK, and the daemon keeps the protocol's own subject when it assembles the token.
    status, response = call("POST", f"{AUTH}/accounts:signUp?key=fake", {"email": "subclaim@example.com", "password": "secret1", "returnSecureToken": True})
    assert status == 200, (status, response)
    answer = json.loads(response)
    subject = json.loads(base64.urlsafe_b64decode(answer["idToken"].split(".")[1] + "=="))["sub"]
    assert subject == answer["localId"] and subject != "someone-else", (subject, answer["localId"])
    # Every refusal code a blocking function can use reaches the caller with its message.
    status, response = call("POST", f"{AUTH}/accounts:signUp?key=fake", {"email": "code:permission-denied@example.com", "password": "secret1"})
    assert status == 400 and b"refused with permission-denied" in response, (status, response)


APP_ID = "1:1234567890:web:pyapp"


def app_check_token():
    """A token the App Check emulator signs, from a debug token it accepts."""
    status, body = call(
        "POST", f"http://{os.environ['FIREEMU_APP_CHECK_EMULATOR_HOST']}/v1/projects/{PROJECT}/apps/{APP_ID}:exchangeDebugToken",
        {"debug_token": "0f6a8e1c-5b3d-4c7e-9a2f-1d4b6c8e0a3f"},
    )
    assert status == 200, (status, body)
    return json.loads(body)["token"]


def callable_with(name, token=None, extra=None):
    headers = {} if token is None else {"X-Firebase-AppCheck": token}
    status, body = call("POST", f"{FUNCTIONS}/{name}", {"data": {"a": 1, "b": 2}}, {**headers, **(extra or {})})
    return status, json.loads(body)


def app_check():
    """SECURITY: an enforcing callable runs only for a token the emulator signed; a forged or foreign one never reaches it."""
    if "FIREEMU_APP_CHECK_EMULATOR_HOST" not in os.environ:
        # No App Check emulator in this run (the emulator profile does not start one unless asked): nothing can verify a
        # token, so the daemon removes the header and no callable ever sees one, whatever it presents.
        looks_real = b64({"alg": "RS256", "typ": "JWT", "kid": "k"}) + "." + b64({"aud": [f"projects/{PROJECT}"], "sub": APP_ID, "exp": 4102444800}) + "." + base64.urlsafe_b64encode(b"\x05" * 256).decode().rstrip("=")
        status, body = callable_with("add_enforced", looks_real)
        assert status == 401 and "result" not in body, (status, body)
        status, body = callable_with("add_enforced_off", looks_real)
        assert status == 200 and body["result"]["app"] is None, (status, body)
        return
    token = app_check_token()
    status, body = callable_with("add_enforced", token)
    assert status == 200 and body["result"] == {"sum": 3, "app": APP_ID}, (status, body)
    status, body = callable_with("add_enforced_off", token)
    assert status == 200 and body["result"]["app"] == APP_ID, (status, body)
    header, payload, signature = token.split(".")
    forged_claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    forged_claims["sub"] = "1:1:web:forged"
    forged = f"{header}.{b64(forged_claims)}.{signature}"
    unsigned = b64({"alg": "none", "typ": "JWT"}) + "." + payload + "."
    foreign = b64({"alg": "RS256", "typ": "JWT", "kid": json.loads(base64.urlsafe_b64decode(header + "=" * (-len(header) % 4)))["kid"]}) + "." + payload + "." + base64.urlsafe_b64encode(b"\x05" * 256).decode().rstrip("=")
    for label, bad in (("a tampered payload", forged), ("alg none", unsigned), ("a foreign signature", foreign), ("junk", "not-a-token"), ("a doubled header", token + ", " + foreign)):
        status, body = callable_with("add_enforced", bad)
        assert status == 401 and "result" not in body, (label, status, body)
        status, body = callable_with("add_enforced_off", bad)
        assert status == 200 and body["result"]["app"] is None, (label, status, body)
    status, body = callable_with("add_enforced")
    assert status == 401 and "result" not in body, (status, body)


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
        # The strict ingress verifies the Bearer before the SDK sees it. The SDK itself, under the Auth emulator,
        # accepts any structurally valid ID token, so each of these would reach the handler as a forged identity.
        header, payload, _ = user["idToken"].split(".")
        forged_header = b64({"alg": "RS256", "typ": "JWT", "kid": "forged"})
        claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        claims.update(user_id="forged-admin", sub="forged-admin")
        unsigned_forged = b64({"alg": "none", "typ": "JWT"}) + "." + b64(claims) + "."
        bad_signature = forged_header + "." + payload + "." + base64.urlsafe_b64encode(b"\x07" * 256).decode().rstrip("=")
        for label, token in (("a token of a user that does not exist", unsigned_forged), ("a real user's claims under a forged signature", bad_signature)):
            status, body = call("POST", f"{FUNCTIONS}/add", {"data": {"a": 1, "b": 1}}, {"Authorization": f"Bearer {token}"})
            assert status == 401 and b"result" not in body, (label, status, body)
        # Two Authorization headers: a server that merges them gives the SDK `Bearer <forged>, AAAA`.
        for first, second in ((f"Bearer {unsigned_forged}", "AAAA"), (f"Bearer {user['idToken']}", "AAAA"), ("AAAA", f"Bearer {unsigned_forged}")):
            status, body = call_with_two_authorizations(first, second)
            assert status == 401 and b"result" not in body, ("two Authorization headers", status, body)
    other_families()
    # Before the clock moves: Python code runs on real time, and the emulator signs tokens on its own clock.
    app_check()
    request_families()
    secrets_by_function()
    negative_ingress()
    print(json.dumps({"ok": True, "profile": PROFILE}))


if __name__ == "__main__":
    try:
        main()
    except AssertionError as error:
        import traceback

        traceback.print_exc()
        print(f"e2e failed: {error}", file=sys.stderr)
        sys.exit(1)
