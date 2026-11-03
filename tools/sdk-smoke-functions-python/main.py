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
from firebase_functions import db_fn, eventarc_fn, firestore_fn, https_fn, identity_fn, logger, pubsub_fn, scheduler_fn, storage_fn, tasks_fn
from firebase_functions.options import RateLimits, RetryConfig
from firebase_functions.params import SecretParam

TOKEN = SecretParam("TOKEN")
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


@scheduler_fn.on_schedule(schedule="every 5 minutes")
def sch_ok(event):
    _record({"function": "sch_ok", "job_name": event.job_name, "schedule_time": _time(event.schedule_time)})


@scheduler_fn.on_schedule(schedule="0 0 * * *", timezone=scheduler_fn.Timezone("UTC"), retry_count=3, max_retry_seconds=60, region="europe-west1")
def sch_retry(event):
    _record({"function": "sch_retry", "job_name": event.job_name, "schedule_time": _time(event.schedule_time)})


@scheduler_fn.on_schedule(schedule="every 1 minutes")
def sch_boom(event):
    _record({"function": "sch_boom", "job_name": event.job_name})
    raise RuntimeError("scheduled boom")


@tasks_fn.on_task_dispatched(retry_config=RetryConfig(max_attempts=3, min_backoff_seconds=2), rate_limits=RateLimits(max_concurrent_dispatches=2))
def tk_echo(request):
    _record({"function": "tk_echo", "data": request.data})
    return {"echo": request.data}


@tasks_fn.on_task_dispatched()
def tk_code(request):
    """Refuses with the error code the request names, to read the status table."""
    raise https_fn.HttpsError(https_fn.FunctionsErrorCode(request.data["code"]), "refused with " + request.data["code"])


@tasks_fn.on_task_dispatched()
def tk_refuse(request):
    raise https_fn.HttpsError(https_fn.FunctionsErrorCode.FAILED_PRECONDITION, "not now")


def _blocking_entry(name, event):
    return {
        "function": name,
        "event_type": event.event_type,
        "uid": event.data.uid,
        "email": event.data.email,
        "ip": event.ip_address,
        "has_id_token": getattr(event.credential, "id_token", None) is not None if event.credential else False,
        "provider": event.credential.provider_id if event.credential else None,
    }


@identity_fn.before_user_created()
def bc_user(event):
    _record(_blocking_entry("bc_user", event))
    email = event.data.email or ""
    if email.startswith("code:"):
        raise https_fn.HttpsError(https_fn.FunctionsErrorCode(email[5:].split("@")[0]), "refused with " + email[5:].split("@")[0])
    if email.startswith("reserved"):
        return identity_fn.BeforeCreateResponse(custom_claims={"iss": "https://elsewhere.example"})
    if email.startswith("subclaim"):
        return identity_fn.BeforeCreateResponse(custom_claims={"sub": "someone-else"})
    if email.startswith("oversized"):
        return identity_fn.BeforeCreateResponse(custom_claims={"big": "x" * 1100})
    if email.startswith("blocked"):
        raise https_fn.HttpsError(https_fn.FunctionsErrorCode.PERMISSION_DENIED, "no accounts for you")
    if email.startswith("claims"):
        return identity_fn.BeforeCreateResponse(display_name="Renamed", custom_claims={"tier": "gold"})
    return None


@identity_fn.before_user_signed_in(id_token=True, access_token=True)
def bs_user(event):
    _record(_blocking_entry("bs_user", event))
    return identity_fn.BeforeSignInResponse(session_claims={"seen": "yes"})


def _secrets_in_environment():
    return {name: os.environ.get(name) for name in ("API_KEY", "TOKEN")}


@https_fn.on_request(secrets=["API_KEY"])
def reads_key(request):
    if request.args.get("hold"):
        time.sleep(float(request.args["hold"]))
    return jsonify(env=_secrets_in_environment(), param=None)


@https_fn.on_request(secrets=[TOKEN])
def reads_token(request):
    if request.args.get("hold"):
        time.sleep(float(request.args["hold"]))
    return jsonify(env=_secrets_in_environment(), param=TOKEN.value)


@https_fn.on_request()
def reads_nothing(request):
    if request.args.get("hold"):
        time.sleep(float(request.args["hold"]))
    return jsonify(env=_secrets_in_environment())


@https_fn.on_request(secrets=["API_KEY"])
def closes_badly(request):
    response = jsonify(env=_secrets_in_environment())
    response.call_on_close(lambda: 1 / 0)
    return response


@https_fn.on_request(secrets=["API_KEY"])
def streams_key(request):
    def generate():
        yield "first "
        time.sleep(0.4)
        yield json.dumps(_secrets_in_environment())

    return Response(generate(), mimetype="text/plain")


@firestore_fn.on_document_created(document="secret/{id}", secrets=["API_KEY"])
def fs_secret(event):
    _record({"function": "fs_secret", "env": _secrets_in_environment()})


@firestore_fn.on_document_created(document="plain/{id}")
def fs_plain(event):
    _record({"function": "fs_plain", "env": _secrets_in_environment()})


@https_fn.on_call(enforce_app_check=True)
def add_enforced(req: https_fn.CallableRequest):
    return {"sum": req.data["a"] + req.data["b"], "app": req.app.app_id if req.app else None}


@https_fn.on_call(enforce_app_check=False)
def add_enforced_off(req: https_fn.CallableRequest):
    return {"sum": req.data["a"] + req.data["b"], "app": req.app.app_id if req.app else None}
