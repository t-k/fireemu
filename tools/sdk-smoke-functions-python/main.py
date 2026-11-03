"""A Python Functions codebase for the real-SDK tests of the Python runner.

Every handler records what it was given in SEEN; the `seen` HTTP function returns that list, so
a test can see what an event handler received through the same process that ran it.
"""

import base64
import datetime
import json
import os
import subprocess
import sys
import threading
import time

from firebase_admin import initialize_app
from firebase_functions import firestore_fn, https_fn, logger
from flask import Response, jsonify

initialize_app()

SEEN: list = []
_LOCK = threading.Lock()


def _record(entry) -> None:
    with _LOCK:
        SEEN.append(entry)


def _snapshot(snapshot):
    return None if snapshot is None else {"id": snapshot.id, "path": snapshot.reference.path, "data": snapshot.to_dict()}


def _firestore_entry(name, event):
    data = event.data
    if hasattr(data, "before") and hasattr(data, "after"):
        shape = {"before": _snapshot(data.before), "after": _snapshot(data.after)}
    else:
        shape = {"snapshot": _snapshot(data)}
    return {"function": name, "params": dict(event.params), "type": event.type, "id": event.id, **shape}


@https_fn.on_request()
def hello(request):
    return jsonify(
        path=request.path,
        script_root=request.script_root,
        method=request.method,
        args=request.args.to_dict(),
        body=request.get_data(as_text=True),
        secret_header=request.headers.get("x-fireemu-runner-secret"),
        k_service=os.environ.get("K_SERVICE"),
        function_target=os.environ.get("FUNCTION_TARGET"),
        function_signature_type=os.environ.get("FUNCTION_SIGNATURE_TYPE"),
    )


@https_fn.on_request()
def boom(request):
    raise RuntimeError("kaboom")


def _jsonable(value):
    """What a Firestore value turns into when a test reads it back over HTTP."""
    if isinstance(value, datetime.datetime):
        return {"timestamp": value.isoformat(), "nanosecond": getattr(value, "nanosecond", None)}
    if isinstance(value, bytes):
        return {"bytes": base64.b64encode(value).decode()}
    if hasattr(value, "latitude") and hasattr(value, "longitude"):
        return {"geopoint": [value.latitude, value.longitude]}
    if hasattr(value, "path") and hasattr(value, "id"):
        return {"reference": value.path}
    return repr(value)


@https_fn.on_request()
def seen(request):
    with _LOCK:
        body = json.dumps(SEEN, default=_jsonable)
    return Response(body, mimetype="application/json")


@https_fn.on_request()
def slow(request):
    time.sleep(float(request.args.get("seconds", "0.2")))
    return jsonify(done=request.args.get("tag"))


@https_fn.on_request()
def noisy(request):
    print("python print")
    os.write(1, b"raw fd write\n")
    subprocess.run(["echo", "child process"], check=False)
    sys.stdout.write("sys.stdout write\n")
    logger.info("sdk logger line")
    return "ok"


@https_fn.on_call()
def add(req: https_fn.CallableRequest):
    return {"sum": req.data["a"] + req.data["b"], "uid": req.auth.uid if req.auth else None}


@https_fn.on_call()
def refuse(req: https_fn.CallableRequest):
    raise https_fn.HttpsError(https_fn.FunctionsErrorCode.NOT_FOUND, "nope")


@firestore_fn.on_document_written(document="items/{id}")
def fs_written(event):
    _record(_firestore_entry("fs_written", event))


@firestore_fn.on_document_created(document="items/{id}")
def fs_created(event):
    _record(_firestore_entry("fs_created", event))


@firestore_fn.on_document_updated(document="items/{id}")
def fs_updated(event):
    _record(_firestore_entry("fs_updated", event))


@firestore_fn.on_document_deleted(document="items/{id}")
def fs_deleted(event):
    _record(_firestore_entry("fs_deleted", event))


@firestore_fn.on_document_written(document="settings/global")
def fs_literal(event):
    _record(_firestore_entry("fs_literal", event))


@firestore_fn.on_document_created_with_auth_context(document="items/{id}")
def fs_created_auth(event):
    entry = _firestore_entry("fs_created_auth", event)
    entry.update(auth_type=event.auth_type, auth_id=event.auth_id)
    _record(entry)


@firestore_fn.on_document_written(document="items/{id}", database="other", region="europe-west1", memory=512, timeout_sec=90)
def fs_options(event):
    _record(_firestore_entry("fs_options", event))
