"""The events the functions are given, pinned to what the adapters of `main` produced (before the request view was added).

`golden_events.json` holds, for eleven events over the five triggers, the input event and, for the unset, emulator and strict
profiles, the attributes and the data of the `CloudEvent` the adapters built (protobuf bytes as base64). It was generated once
from `origin/main` at 1f24a8bfd, not by the code under test, so a change in how the request body is written cannot move the
event unnoticed. Numbers are compared by value; `-0.0` and `0.0` are equal in Python and are not told apart here.
"""

import base64
import json
from pathlib import Path

import pytest

from google.events.cloud import firestore as firestore_events

from fireemu_runner import dispatch
from fireemu_runner.events import (
    database_cloud_event,
    eventarc_cloud_event,
    firestore_cloud_event,
    pubsub_cloud_event,
    storage_cloud_event,
)

GOLDEN = json.loads((Path(__file__).parent / "golden_events.json").read_text(encoding="utf-8"))
ADAPTERS = {
    "firestore": firestore_cloud_event,
    "pubsub": pubsub_cloud_event,
    "storage": storage_cloud_event,
    "eventarc": eventarc_cloud_event,
    "database": database_cloud_event,
}
CASES = [(name, profile) for name in sorted(GOLDEN) for profile in ("unset", "emulator", "strict")]


def set_profile(monkeypatch, profile):
    if profile == "unset":
        monkeypatch.delenv("FIREEMU_HTTP_PROFILE", raising=False)
    else:
        monkeypatch.setenv("FIREEMU_HTTP_PROFILE", profile)


def canonical(data: bytes) -> dict:
    """The protobuf bytes with map entries in key order, and their length.

    Protobuf leaves the order of map entries unspecified and Python's library orders them by a per-process hash seed,
    so the same message serialises to differently ordered (equal-length) bytes in two runs. The golden bytes are
    compared after re-serialising both with `deterministic=True`.
    """
    message = firestore_events.DocumentEventData.deserialize(data)
    return {
        "length": len(data),
        "base64": base64.b64encode(type(message).pb(message).SerializeToString(deterministic=True)).decode(),
    }


def data_of(event):
    data = event.get_data()
    return canonical(data) if isinstance(data, bytes) else {"json": data}


def golden_data(expected):
    rest = {k: v for k, v in expected.items() if k != "attributes"}
    return canonical(base64.b64decode(rest["base64"])) if "base64" in rest else rest


@pytest.mark.parametrize("name, profile", CASES)
def test_the_adapters_build_the_event_main_built(name, profile, monkeypatch):
    set_profile(monkeypatch, profile)
    entry = GOLDEN[name]
    expected = entry["profiles"][profile]
    event = ADAPTERS[entry["trigger"]](entry["event"])
    assert dict(event._get_attributes()) == expected["attributes"]
    assert data_of(event) == golden_data(expected)


@pytest.mark.parametrize("raw", [False, True])
@pytest.mark.parametrize("name, profile", CASES)
def test_the_function_is_given_the_event_main_built_whatever_text_the_daemon_delivered(name, profile, raw, monkeypatch):
    set_profile(monkeypatch, profile)
    entry = GOLDEN[name]
    expected = entry["profiles"][profile]
    seen = []
    delivered = json.dumps(entry["event"].get("data"), sort_keys=True, separators=(",", ":")) if raw and "data" in entry["event"] else None
    dispatch._deliver(entry["trigger"], seen.append, entry["event"], delivered)
    assert dict(seen[0]._get_attributes()) == expected["attributes"]
    assert data_of(seen[0]) == golden_data(expected)
