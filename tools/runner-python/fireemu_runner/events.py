"""Event adapters: the daemon's structured event as the CloudEvent the Python SDK expects.

Production delivers a Firestore event as a binary-mode CloudEvent (`ce-*` headers) whose body is a
protobuf `DocumentEventData`; the SDK's JSON branch needs a JSON *string* and fails on a decoded
dict (`firestore_fn.py:108-131`). The adapter therefore builds the production form and lets
`cloudevents.http.from_http` produce the object, exactly the path functions-framework takes
(`functions_framework/__init__.py:174-188`).
"""

import json

from cloudevents.http import from_http
from google.events.cloud import firestore as firestore_events

_NOT_AN_ATTRIBUTE = frozenset({"data", "datacontenttype"})


def firestore_cloud_event(event: dict):
    """The `CloudEvent` for a Firestore event frame (`created`, `updated`, `deleted`, `written`)."""
    if not isinstance(event.get("specversion"), str):
        # Without it `from_http` would read the body as a structured JSON event and fail on protobuf bytes.
        raise ValueError("the event has no specversion")
    data = event.get("data")
    message = firestore_events.DocumentEventData.from_json(json.dumps(data if isinstance(data, dict) else {}))
    headers = {
        f"ce-{name}": value
        for name, value in event.items()
        if name not in _NOT_AN_ATTRIBUTE and isinstance(value, str)
    }
    headers["content-type"] = "application/protobuf"
    return from_http(headers, firestore_events.DocumentEventData.serialize(message))
