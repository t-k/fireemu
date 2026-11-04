"""Observation fixture for the Python Functions slice 2 sandbox check.

Every function prints one line `PYCHECK_FRAME <json>` per delivery and nothing else: what it was given, as the
SDK shows it (the `sdk` members) or as the request reached it (the `raw` members). Cloud Logging carries the
lines to the recorder. Nothing here writes to any service, and no credential or token value is printed:
`Authorization` is reduced to its scheme and segment count, and every header outside a short list keeps only its name.

A `...raw` function has the trigger of the SDK function beside it but takes the delivery before the SDK parses it,
so what production sent is recorded even when the SDK would refuse it (the SDK wrappers raise on a shape they do
not expect, and the handler never runs).
"""

import base64
import dataclasses
import datetime
import importlib.metadata
import json
import re

import flask
from firebase_functions import eventarc_fn, firestore_fn, pubsub_fn, scheduler_fn, storage_fn, tasks_fn
from firebase_functions.options import RetryConfig

MARK = "PYCHECK_FRAME "
RUN_PATTERN = re.compile(r"pcrun-[0-9a-f]{16}")
TOPIC = "pycheck-orders"
COLLECTION = "pycheck-src"
EVENT_TYPE = "pycheck.thing.v1.happened"
SCHEDULE = "0 0 1 1 *"  # once a year: only the forced run delivers during the recording
PACKAGES = ("firebase-functions", "functions-framework", "cloudevents", "flask", "werkzeug", "google-events", "protobuf", "firebase-admin", "PyJWT", "gunicorn")
SHOWN_HEADERS = ("content-type", "content-length", "user-agent", "host", "accept-encoding", "x-forwarded-proto")
SHOWN_PREFIXES = ("ce-", "x-cloudscheduler", "x-cloudtasks-", "x-goog-")
MAX_TEXT = 8192
MAX_BYTES = 16384


def _versions():
    found = {}
    for name in PACKAGES:
        try:
            found[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            found[name] = None
    return found


def _run_of(*parts):
    for part in parts:
        match = RUN_PATTERN.search(json.dumps(part, default=str, sort_keys=True))
        if match:
            return match.group(0)
    return None


def _emit(function, kind, run, **members):
    frame = {
        "function": function,
        "kind": kind,
        "at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "run": run,
        "versions": _versions(),
        **members,
    }
    print(MARK + json.dumps(frame, sort_keys=True, default=str), flush=True)


def _request_view():
    """What the request carried, or None outside a request (the emulator's event path has none)."""
    if not flask.has_request_context():
        return None
    request = flask.request
    headers = {name.lower(): value for name, value in request.headers.items()}
    authorization = headers.get("authorization")
    shown = {
        name: value
        for name, value in headers.items()
        if name in SHOWN_HEADERS or name.startswith(SHOWN_PREFIXES)
    }
    body = request.get_data()
    view = {
        "method": request.method,
        "path": request.path,
        "header_names": sorted(headers),
        "headers": shown,
        "authorization": None
        if authorization is None
        else {"scheme": authorization.split(" ", 1)[0], "segments": len(authorization.split(" ", 1)[-1].split("."))},
        "body_length": len(body),
        "body_text": body.decode("utf-8", "replace")[:MAX_TEXT] if _is_text(headers.get("content-type", "")) else None,
        "body_base64": base64.b64encode(body[:MAX_BYTES]).decode() if not _is_text(headers.get("content-type", "")) else None,
    }
    return view


def _is_text(content_type):
    media = content_type.split(";", 1)[0].strip().lower()
    return media == "application/json" or media.startswith("text/") or media.endswith("+json")


def _data_view(data):
    if isinstance(data, (bytes, bytearray)):
        view = {"kind": "bytes", "length": len(data), "base64": base64.b64encode(bytes(data[:MAX_BYTES])).decode()}
        try:
            from google.events.cloud import firestore as firestore_events

            message = firestore_events.DocumentEventData.deserialize(bytes(data))
            view["protobuf"] = json.loads(firestore_events.DocumentEventData.to_json(message))
        except Exception as error:  # not a Firestore document event, or not protobuf
            view["protobuf_error"] = type(error).__name__
        return view
    if isinstance(data, str):
        return {"kind": "str", "text": data[:MAX_TEXT]}
    if data is None:
        return {"kind": "none"}
    return {"kind": "json", "value": data}


def _time(value):
    return None if value is None else value.isoformat()


# ---- raw functions: the delivery before the SDK parses it ----------------------------------------------------


def _raw_event(name):
    def observe(raw):
        attributes = raw._get_attributes()
        data = raw.get_data()
        view = _data_view(data)
        _emit(name, "raw-event", _run_of(view, attributes), attributes=attributes, data=view, request=_request_view())

    return observe


def _raw_request(name):
    def observe(request):
        body = request.get_data(as_text=True)
        view = _request_view()
        _emit(name, "raw-request", _run_of(body), request=view)
        return flask.make_response("", 200)

    return observe


def _with_trigger(name, prototype, observe):
    """`observe` registered under `name` with the trigger of the SDK function `prototype`."""
    observe.__name__ = name
    observe.__firebase_endpoint__ = dataclasses.replace(prototype.__firebase_endpoint__, entryPoint=name)
    required = getattr(prototype, "__required_apis", None)
    if required is not None:
        setattr(observe, "__required_apis", required)
    return observe


def _prototype(decorator):
    def stand_in(event):
        return None

    return decorator(stand_in)


_PROTOTYPES = {
    "fs": _prototype(firestore_fn.on_document_created(document=f"{COLLECTION}/{{id}}", region="us-central1")),
    "ps": _prototype(pubsub_fn.on_message_published(topic=TOPIC, region="us-central1")),
    "st": _prototype(storage_fn.on_object_finalized(region="us-central1")),
    "ea": _prototype(eventarc_fn.on_custom_event_published(event_type=EVENT_TYPE, region="us-central1")),
    "sched": _prototype(scheduler_fn.on_schedule(schedule=SCHEDULE, timezone=scheduler_fn.Timezone("UTC"), region="us-central1")),
    "task": _prototype(tasks_fn.on_task_dispatched(retry_config=RetryConfig(max_attempts=1), region="us-central1")),
}

pcfscraw = _with_trigger("pcfscraw", _PROTOTYPES["fs"], _raw_event("pcfscraw"))
pcpsraw = _with_trigger("pcpsraw", _PROTOTYPES["ps"], _raw_event("pcpsraw"))
pcstraw = _with_trigger("pcstraw", _PROTOTYPES["st"], _raw_event("pcstraw"))
pcearaw = _with_trigger("pcearaw", _PROTOTYPES["ea"], _raw_event("pcearaw"))
pcschraw = _with_trigger("pcschraw", _PROTOTYPES["sched"], _raw_request("pcschraw"))
pctaskraw = _with_trigger("pctaskraw", _PROTOTYPES["task"], _raw_request("pctaskraw"))


# ---- SDK functions: what the SDK's own wrappers hand the handler ------------------------------------------------


def _snapshot(snapshot):
    return None if snapshot is None else {"path": snapshot.reference.path, "data": snapshot.to_dict()}


@firestore_fn.on_document_created(document=f"{COLLECTION}/{{id}}", region="us-central1")
def pcfsc(event):
    snapshot = _snapshot(event.data)
    _emit("pcfsc", "sdk-event", _run_of(snapshot), type=event.type, id=event.id, params=dict(event.params), time=_time(event.time), snapshot=snapshot)


@firestore_fn.on_document_updated(document=f"{COLLECTION}/{{id}}", region="us-central1")
def pcfsu(event):
    before, after = _snapshot(event.data.before), _snapshot(event.data.after)
    _emit("pcfsu", "sdk-event", _run_of(after, before), type=event.type, id=event.id, params=dict(event.params), time=_time(event.time), before=before, after=after)


@pubsub_fn.on_message_published(topic=TOPIC, region="us-central1")
def pcps(event):
    message = event.data.message
    attributes = dict(message.attributes)
    _emit(
        "pcps",
        "sdk-event",
        _run_of(attributes),
        type=event.type,
        id=event.id,
        time=_time(event.time),
        message_id=message.message_id,
        publish_time=_time(message.publish_time),
        ordering_key=message.ordering_key,
        attributes=attributes,
        subscription=event.data.subscription,
    )


@storage_fn.on_object_finalized(region="us-central1")
def pcst(event):
    data = event.data
    _emit("pcst", "sdk-event", _run_of(data.name), type=event.type, id=event.id, time=_time(event.time), bucket=data.bucket, name=data.name, size=data.size, content_type=data.content_type, generation=data.generation)


@eventarc_fn.on_custom_event_published(event_type=EVENT_TYPE, region="us-central1")
def pcea(event):
    _emit("pcea", "sdk-event", _run_of(event.data), type=event.type, id=event.id, source=event.source, subject=event.subject, time=_time(event.time), data=event.data)


@scheduler_fn.on_schedule(schedule=SCHEDULE, timezone=scheduler_fn.Timezone("UTC"), region="us-central1")
def pcsch(event):
    _emit("pcsch", "sdk-event", None, job_name=event.job_name, schedule_time=_time(event.schedule_time))


@tasks_fn.on_task_dispatched(retry_config=RetryConfig(max_attempts=1), region="us-central1")
def pctask(request):
    _emit("pctask", "sdk-event", _run_of(request.data), data=request.data, has_auth=request.auth is not None, has_app=request.app is not None)
    return {"ok": True}
