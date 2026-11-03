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
from firebase_functions import db_fn, eventarc_fn, firestore_fn, https_fn, logger, pubsub_fn, storage_fn
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


def _time(value):
    return None if value is None else value.isoformat()


def _event_entry(name, event):
    return {"function": name, "type": event.type, "id": event.id, "source": event.source, "subject": event.subject, "time": _time(event.time)}


@pubsub_fn.on_message_published(topic="orders")
def ps_orders(event):
    message = event.data.message
    entry = _event_entry("ps_orders", event)
    entry.update(
        subscription=event.data.subscription,
        message_id=message.message_id,
        publish_time=_time(message.publish_time),
        ordering_key=message.ordering_key,
        attributes=dict(message.attributes),
        text=base64.b64decode(message.data).decode() if message.data else None,
    )
    _record(entry)


@pubsub_fn.on_message_published(topic="retried", retry=True, region="europe-west1")
def ps_retried(event):
    _record(_event_entry("ps_retried", event))


def _object_entry(name, event):
    data = event.data
    entry = _event_entry(name, event)
    entry.update(
        bucket=data.bucket,
        object=data.name,
        generation=data.generation,
        metageneration=data.metageneration,
        size=data.size,
        content_type=data.content_type,
        storage_class=data.storage_class,
        metadata=data.metadata,
        time_deleted=data.time_deleted,
        time_created=data.time_created,
    )
    return entry


@storage_fn.on_object_finalized(bucket="demo-bucket")
def st_finalized(event):
    _record(_object_entry("st_finalized", event))


@storage_fn.on_object_deleted(bucket="demo-bucket")
def st_deleted(event):
    _record(_object_entry("st_deleted", event))


@storage_fn.on_object_archived(bucket="demo-bucket")
def st_archived(event):
    _record(_object_entry("st_archived", event))


@storage_fn.on_object_metadata_updated(bucket="demo-bucket")
def st_metadata(event):
    _record(_object_entry("st_metadata", event))


@storage_fn.on_object_finalized()
def st_default_bucket(event):
    _record(_object_entry("st_default_bucket", event))


@eventarc_fn.on_custom_event_published(event_type="acme.thing.v1.happened")
def ea_plain(event):
    entry = _event_entry("ea_plain", event)
    entry["data"] = event.data
    _record(entry)


@eventarc_fn.on_custom_event_published(
    event_type="acme.thing.v1.filtered", channel="locations/us-central1/channels/acme", filters={"colour": "red"}
)
def ea_filtered(event):
    entry = _event_entry("ea_filtered", event)
    entry["data"] = event.data
    _record(entry)


def _database_entry(name, event):
    data = event.data
    if hasattr(data, "before") and hasattr(data, "after"):
        shape = {"before": data.before, "after": data.after}
    else:
        shape = {"value": data}
    entry = _event_entry(name, event)
    entry.update(
        instance=event.instance,
        reference=event.reference,
        location=event.location,
        host=event.firebase_database_host,
        params=dict(event.params),
        auth_type=event.auth_type,
        auth_id=event.auth_id,
        **shape,
    )
    return entry


@db_fn.on_value_created(reference="/messages/{room}/{id}")
def db_created(event):
    _record(_database_entry("db_created", event))


@db_fn.on_value_updated(reference="/messages/{room}/{id}")
def db_updated(event):
    _record(_database_entry("db_updated", event))


@db_fn.on_value_deleted(reference="/messages/{room}/{id}")
def db_deleted(event):
    _record(_database_entry("db_deleted", event))


@db_fn.on_value_written(reference="/messages/{room}/{id}")
def db_written(event):
    _record(_database_entry("db_written", event))


@db_fn.on_value_written(reference="/config/mode", instance="demo-proj-*")
def db_literal_glob(event):
    _record(_database_entry("db_literal_glob", event))
