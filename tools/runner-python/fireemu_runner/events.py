"""Event adapters: the daemon's structured event as the CloudEvent the Python SDK expects.

Production delivers a Firestore event as a binary-mode CloudEvent (`ce-*` headers) whose body is a
protobuf `DocumentEventData`; the SDK's JSON branch needs a JSON *string* and fails on a decoded
dict (`firestore_fn.py:108-131`). The adapter therefore builds the production form and lets
`cloudevents.http.from_http` produce the object, exactly the path functions-framework takes
(`functions_framework/__init__.py:174-188`).
"""

import json
import os
import re

from cloudevents.http import from_http
from google.events.cloud import firestore as firestore_events

_NOT_AN_ATTRIBUTE = frozenset({"data", "datacontenttype"})
# The daemon's strict 2nd gen frame names a `traceparent` for the Node runner's event. Production sends the trace context as an
# ordinary HTTP header (Cloud Run's), never as a `ce-` attribute, so the Python event has none (sandbox run
# PYCHECK-EVENTS-20261104-01, the raw twins of the Pub/Sub, Storage and Eventarc events).
_HTTP_HEADER_ONLY = frozenset({"traceparent"})
# Eventarc sends `ce-dataschema` with every Firestore event (recorded for `created`; the schema is the same document for the family).
_FIRESTORE_DATASCHEMA = (
    "https://github.com/googleapis/google-cloudevents/blob/main/proto/google/events/cloud/firestore/v1/data.proto"
)


_WHOLE_SECOND_TIME = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(Z|[+-]\d{2}:\d{2})$")


def _attribute_headers(event: dict) -> dict:
    """The binary-mode `ce-*` headers of an event: its string members, except the data and the content type."""
    if not isinstance(event.get("specversion"), str):
        # Without it `from_http` would read the body as a structured JSON event and fail on the body.
        raise ValueError("the event has no specversion")
    return {
        f"ce-{name}": value
        for name, value in event.items()
        if name not in _NOT_AN_ATTRIBUTE and name not in _HTTP_HEADER_ONLY and isinstance(value, str)
    }


def _is_json(content_type: str) -> bool:
    media = content_type.split(";", 1)[0].strip().lower()
    return media == "application/json" or media.endswith("+json")


def _json_cloud_event(event: dict):
    """The `CloudEvent` for an event whose data is JSON (or text, with a text content type).

    Eventarc delivers these in binary content mode: attributes as `ce-*` headers and the data as the body,
    which functions-framework hands to `cloudevents.http.from_http` (`functions_framework/__init__.py:174-188`).
    A delivery without a content type is JSON.
    """
    headers = _attribute_headers(event)
    declared = event.get("datacontenttype")
    content_type = declared if isinstance(declared, str) and declared else "application/json"
    headers["content-type"] = content_type
    if "data" not in event:
        body = b""
    elif isinstance(event["data"], str) and not _is_json(content_type):
        body = event["data"].encode()
    else:
        body = json.dumps(event["data"]).encode()
    return from_http(headers, body)


def _lenient_time(event: dict) -> dict:
    """The emulator profile gives a whole-second `time` a fraction.

    `storage_fn` and `eventarc_fn` parse `time` with `%f` (`storage_fn.py:249-252`, `eventarc_fn.py:65-68`) and
    fail on `2026-01-01T00:00:02Z`. The official emulator always prints milliseconds, so what it served the
    emulator profile must serve; the strict profile delivers the time as production's event has it.
    """
    time = event.get("time")
    if os.environ.get("FIREEMU_HTTP_PROFILE", "emulator") == "strict" or not isinstance(time, str):
        return event
    match = _WHOLE_SECOND_TIME.match(time)
    return event if match is None else {**event, "time": f"{match.group(1)}.000{match.group(2)}"}


def pubsub_cloud_event(event: dict):
    """The `CloudEvent` for a Pub/Sub message event.

    The SDK reads `message_id` and `publish_time` (`pubsub_fn.py:98-160`), the snake-case spellings Pub/Sub's
    push body carries next to `messageId` and `publishTime`. `orderingKey` has no alternative: the SDK pops
    it and passes `ordering_key=` itself, so a copied key would be passed twice (`TypeError`).
    """
    data = event.get("data")
    message = data.get("message") if isinstance(data, dict) else None
    if not isinstance(message, dict):
        return _json_cloud_event(event)
    message = dict(message)
    for camel, snake in (("messageId", "message_id"), ("publishTime", "publish_time")):
        if snake not in message and camel in message and message[camel] is not None:
            message[snake] = message[camel]
    return _json_cloud_event({**event, "data": {**data, "message": message}})


def storage_cloud_event(event: dict):
    """The `CloudEvent` for a Storage object event."""
    return _json_cloud_event(_lenient_time(event))


def eventarc_cloud_event(event: dict):
    """The `CloudEvent` for a custom Eventarc event."""
    return _json_cloud_event(_lenient_time(event))


def database_cloud_event(event: dict):
    """The `CloudEvent` for a Realtime Database event."""
    return _json_cloud_event(event)


def firestore_cloud_event(event: dict):
    """The `CloudEvent` for a Firestore event frame (`created`, `updated`, `deleted`, `written`)."""
    headers = _attribute_headers(event)
    headers.setdefault("ce-dataschema", _FIRESTORE_DATASCHEMA)
    data = event.get("data")
    message = firestore_events.DocumentEventData.from_json(json.dumps(data if isinstance(data, dict) else {}))
    headers["content-type"] = "application/protobuf"
    return from_http(headers, firestore_events.DocumentEventData.serialize(message))
