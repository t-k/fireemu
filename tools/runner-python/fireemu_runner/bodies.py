"""The text of an event's JSON body in the layouts the recorded deliveries had.

Recorded 2026-11-04 (sandbox run PYCHECK-EVENTS-20261104-01, the raw twins; `tests/recorded_bodies.json`):

- an Eventarc custom event: the publisher's own compact text, member order as published (51 and 48 bytes);
- a Pub/Sub message: sorted compact JSON followed by a newline (348 and 382 bytes);
- a Cloud Storage object: the object resource indented by two spaces, in the Cloud Storage JSON API member order, followed by a
  newline (963 bytes).

A Realtime Database event was not recorded. Numbers keep the spelling they have in the text the daemon framed (`1e-7`, `1e20`,
`-0.0`): `Number` is a number as written. Characters are written as UTF-8, not as `\\u` escapes (the recorded bodies hold none).
"""

import json


class Number(str):
    """A JSON number as it was written."""


def parse_keeping_numbers(text: str):
    """The value of a JSON text with every number kept as `Number`."""
    return json.loads(text, parse_int=Number, parse_float=Number)


def write(value, *, sort_keys: bool = False, indent: int | None = None, level: int = 0) -> str:
    """JSON text of `value`: compact, or with each member on its own line indented by `indent` spaces."""
    if isinstance(value, Number):
        return str(value)
    if isinstance(value, dict):
        members = sorted(value.items()) if sort_keys else list(value.items())
        if not members:
            return "{}"
        parts = [f"{json.dumps(str(k), ensure_ascii=False)}{': ' if indent else ':'}{write(v, sort_keys=sort_keys, indent=indent, level=level + 1)}" for k, v in members]
        return _join("{", parts, "}", indent, level)
    if isinstance(value, list):
        if not value:
            return "[]"
        return _join("[", [write(v, sort_keys=sort_keys, indent=indent, level=level + 1) for v in value], "]", indent, level)
    return json.dumps(value, ensure_ascii=False)


def _join(open_: str, parts: list, close: str, indent: int | None, level: int) -> str:
    if not indent:
        return open_ + ",".join(parts) + close
    inner = "\n" + " " * (indent * (level + 1))
    return open_ + inner + ("," + inner).join(parts) + "\n" + " " * (indent * level) + close


def compact(value) -> str:
    return write(value)


def pubsub_layout(value) -> str:
    """Sorted compact JSON and a newline: what Pub/Sub's push delivery sent (recorded)."""
    return write(value, sort_keys=True) + "\n"


# The member order of a Cloud Storage object resource as the recorded body had it. Members the recording does not show are
# UNRECORDED: they follow the known ones in alphabetical order.
_GCS_OBJECT_ORDER = (
    "kind",
    "id",
    "selfLink",
    "name",
    "bucket",
    "generation",
    "metageneration",
    "contentType",
    "timeCreated",
    "updated",
    "storageClass",
    "timeStorageClassUpdated",
    "size",
    "md5Hash",
    "mediaLink",
    "crc32c",
    "etag",
)


def _sorted_deep(value):
    if isinstance(value, dict):
        return {k: _sorted_deep(v) for k, v in sorted(value.items())}
    if isinstance(value, list):
        return [_sorted_deep(v) for v in value]
    return value


def storage_layout(value) -> str:
    """The object resource in the API's member order, indented by two spaces, and a newline (recorded for the known members)."""
    if isinstance(value, dict):
        known = [(k, _sorted_deep(value[k])) for k in _GCS_OBJECT_ORDER if k in value]
        rest = [(k, _sorted_deep(v)) for k, v in sorted(value.items()) if k not in _GCS_OBJECT_ORDER]
        value = dict(known + rest)
    return write(value, indent=2) + "\n"
