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
from typing import NamedTuple

from cloudevents.http import from_http
from google.events.cloud import firestore as firestore_events

from . import bodies

_NOT_AN_ATTRIBUTE = frozenset({"data", "datacontenttype"})
# The daemon's strict 2nd gen frame names a `traceparent` for the Node runner's event. Production sends the trace context as an
# ordinary HTTP header (Cloud Run's), never as a `ce-` attribute, so the strict Python event has none (sandbox run
# PYCHECK-EVENTS-20261104-01, the raw twins of the Pub/Sub, Storage, Eventarc and Firestore events). The emulator profile
# stamps no such member, so a `traceparent` there is the publisher's own tracing extension and stays an attribute.
_HTTP_HEADER_ONLY = frozenset({"traceparent"})
# Eventarc sends `ce-dataschema` with every Firestore event. Recorded for `created` only; for `updated`, `deleted`, `written`
# and any other type routed here it is UNRECORDED (the schema is one document for the family in google-cloudevents). The strict
# profile delivers it; the emulator profile keeps the official emulator's attributes, which have none.
_FIRESTORE_DATASCHEMA = (
    "https://github.com/googleapis/google-cloudevents/blob/main/proto/google/events/cloud/firestore/v1/data.proto"
)


_WHOLE_SECOND_TIME = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(Z|[+-]\d{2}:\d{2})$")


def _attribute_headers(event: dict) -> dict:
    """The binary-mode `ce-*` headers of an event: its string members, except the data and the content type."""
    if not isinstance(event.get("specversion"), str):
        # Without it `from_http` would read the body as a structured JSON event and fail on the body.
        raise ValueError("the event has no specversion")
    header_only = _HTTP_HEADER_ONLY if is_strict() else frozenset()
    return {
        f"ce-{name}": value
        for name, value in event.items()
        if name not in _NOT_AN_ATTRIBUTE and name not in header_only and isinstance(value, str)
    }


def _is_json(content_type: str) -> bool:
    media = content_type.split(";", 1)[0].strip().lower()
    return media == "application/json" or media.endswith("+json")


class Delivery(NamedTuple):
    """One delivery: the headers, the body the event is built from, and the body the request carries.

    The two bodies are the same bytes for a Firestore event. For the JSON families the event is built from the encoding of
    the data the adapters have always used (`event_body`), and the request shows the layout the recorded delivery had
    (`request_body`); the function is given the same event whichever layout the request has.
    """

    headers: dict
    event_body: bytes
    request_body: bytes


def _json_delivery(event: dict, request_text: str | None = None) -> Delivery:
    """The delivery of an event whose data is JSON (or text, with a text content type).

    Eventarc delivers these in binary content mode: attributes as `ce-*` headers and the data as the body,
    which functions-framework hands to `cloudevents.http.from_http` (`functions_framework/__init__.py:174-188`).
    A delivery without a content type is JSON. `request_text` is the body text of the request when it differs from the
    compact encoding of the data (see `bodies.py`).
    """
    headers = _attribute_headers(event)
    declared = event.get("datacontenttype")
    content_type = declared if isinstance(declared, str) and declared else "application/json"
    headers["content-type"] = content_type
    if "data" not in event:
        return Delivery(headers, b"", b"")
    if isinstance(event["data"], str) and not _is_json(content_type):
        body = event["data"].encode()
        return Delivery(headers, body, body)
    request = request_text if request_text is not None else bodies.compact(event["data"])
    return Delivery(headers, json.dumps(event["data"]).encode(), request.encode())


def _delivered_value(event: dict, raw_data: str | None):
    """The data with its numbers as the daemon wrote them, or the event's own data when there is no text or it does not parse."""
    if raw_data is not None:
        try:
            return bodies.parse_keeping_numbers(raw_data)
        except ValueError:
            pass
    return event.get("data")


def is_strict() -> bool:
    return os.environ.get("FIREEMU_HTTP_PROFILE") == "strict"


def _lenient_time(event: dict) -> dict:
    """The emulator profile gives a whole-second `time` a fraction.

    `storage_fn` and `eventarc_fn` parse `time` with `%f` (`storage_fn.py:249-252`, `eventarc_fn.py:65-68`) and
    fail on `2026-01-01T00:00:02Z`. The official emulator always prints milliseconds, so what it served the
    emulator profile must serve; the strict profile delivers the time as production's event has it.
    """
    time = event.get("time")
    if is_strict() or not isinstance(time, str):
        return event
    match = _WHOLE_SECOND_TIME.match(time)
    return event if match is None else {**event, "time": f"{match.group(1)}.000{match.group(2)}"}


def _with_snake_case_keys(data):
    """A Pub/Sub push body with `message_id` and `publish_time` next to `messageId` and `publishTime` (`pubsub_fn.py:98-160`)."""
    message = data.get("message") if isinstance(data, dict) else None
    if not isinstance(message, dict):
        return data
    message = dict(message)
    for camel, snake in (("messageId", "message_id"), ("publishTime", "publish_time")):
        if snake not in message and camel in message and message[camel] is not None:
            message[snake] = message[camel]
    return {**data, "message": message}


def pubsub_request(event: dict, raw_data: str | None = None) -> Delivery:
    """The delivery of a Pub/Sub message event.

    The SDK reads `message_id` and `publish_time` (`pubsub_fn.py:98-160`), the snake-case spellings Pub/Sub's
    push body carries next to `messageId` and `publishTime`. `orderingKey` has no alternative: the SDK pops
    it and passes `ordering_key=` itself, so a copied key would be passed twice (`TypeError`).
    The strict request carries the recorded layout: sorted compact JSON and a newline.
    """
    data = event.get("data")
    if not isinstance(data, dict) or not isinstance(data.get("message"), dict):
        return _json_delivery(event)
    event = {**event, "data": _with_snake_case_keys(data)}
    value = _with_snake_case_keys(_delivered_value(event, raw_data))
    text = bodies.pubsub_layout(value) if is_strict() else bodies.compact(value)
    return _json_delivery(event, text)


def storage_request(event: dict, raw_data: str | None = None) -> Delivery:
    """The delivery of a Storage object event: the text the daemon sent, and in the strict profile the recorded layout."""
    event = _lenient_time(event)
    if is_strict() and "data" in event:
        return _json_delivery(event, bodies.storage_layout(_delivered_value(event, raw_data)))
    return _json_delivery(event, raw_data)


def eventarc_request(event: dict, raw_data: str | None = None) -> Delivery:
    """The delivery of a custom Eventarc event: the text of the data as the daemon framed it (the publisher's own in the strict profile)."""
    return _json_delivery(_lenient_time(event), raw_data)


def database_request(event: dict, raw_data: str | None = None) -> Delivery:
    """The delivery of a Realtime Database event: the text the daemon sent (no raw delivery was recorded; UNRECORDED)."""
    return _json_delivery(event, raw_data)


def firestore_request(event: dict, raw_data: str | None = None) -> Delivery:
    """The delivery of a Firestore event frame (`created`, `updated`, `deleted`, `written`): a protobuf body."""
    headers = _attribute_headers(event)
    if is_strict():
        headers.setdefault("ce-dataschema", _FIRESTORE_DATASCHEMA)
    data = event.get("data")
    message = firestore_events.DocumentEventData.from_json(json.dumps(data if isinstance(data, dict) else {}))
    headers["content-type"] = "application/protobuf"
    body = firestore_events.DocumentEventData.serialize(message)
    return Delivery(headers, body, body)


def pubsub_cloud_event(event: dict):
    """The `CloudEvent` for a Pub/Sub message event (see `pubsub_request`)."""
    delivery = pubsub_request(event)
    return from_http(delivery.headers, delivery.event_body)


def storage_cloud_event(event: dict):
    """The `CloudEvent` for a Storage object event."""
    delivery = storage_request(event)
    return from_http(delivery.headers, delivery.event_body)


def eventarc_cloud_event(event: dict):
    """The `CloudEvent` for a custom Eventarc event."""
    delivery = eventarc_request(event)
    return from_http(delivery.headers, delivery.event_body)


def database_cloud_event(event: dict):
    """The `CloudEvent` for a Realtime Database event."""
    delivery = database_request(event)
    return from_http(delivery.headers, delivery.event_body)


def firestore_cloud_event(event: dict):
    """The `CloudEvent` for a Firestore event frame (`created`, `updated`, `deleted`, `written`)."""
    delivery = firestore_request(event)
    return from_http(delivery.headers, delivery.event_body)
