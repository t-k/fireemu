"""The request a CloudEvent function runs inside.

functions-framework serves a CloudEvent function from a Flask view and calls the function inside the request context, so
`flask.request` shows the delivered HTTP request (method, path, the `ce-*` headers, the content type, the body bytes).
Production's raw twins were recorded on 2026-11-04 (sandbox run PYCHECK-EVENTS-20261104-01): `POST /`, binary-mode
`ce-*` headers, `content-type`, `content-length`, and in the strict profile the constants `user-agent: APIs-Google; ...`,
`accept-encoding: gzip, deflate, br`, `x-forwarded-proto: https`, plus Cloud Run's plain `traceparent` header.
"""

import json
import threading

import flask
import pytest
from cloudevents.http import from_http

from fireemu_runner import dispatch
from fireemu_runner.events import (
    database_cloud_event,
    eventarc_cloud_event,
    firestore_cloud_event,
    pubsub_cloud_event,
    storage_cloud_event,
)

APIS_GOOGLE = "APIs-Google; (+https://developers.google.com/webmasters/APIs-Google.html)"
TRACEPARENT = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"
PARENT = "projects/demo-proj/databases/(default)/documents"


def base(**overrides):
    event = {
        "specversion": "1.0",
        "id": "e-1",
        "source": "//example.googleapis.com/x",
        "type": "acme.thing",
        "time": "2026-01-01T00:00:02.250Z",
        "datacontenttype": "application/json",
        "data": {"run": "pcrun-1", "label": "l"},
    }
    event.update(overrides)
    return event


EVENTS = {
    "firestore": base(
        type="google.cloud.firestore.document.v1.created",
        subject="documents/items/a",
        location="nam5",
        project="demo-proj",
        namespace="(default)",
        document="items/a",
        database="(default)",
        data={"value": {"name": f"{PARENT}/items/a", "fields": {"n": {"integerValue": "1"}}}},
    ),
    "pubsub": base(
        type="google.cloud.pubsub.topic.v1.messagePublished",
        data={"message": {"messageId": "1", "data": "aGk="}, "subscription": "projects/demo-proj/subscriptions/s"},
    ),
    "storage": base(type="google.cloud.storage.object.v1.finalized", data={"bucket": "b", "name": "o"}),
    "eventarc": base(),
    "database": base(type="google.firebase.database.ref.v1.created", data={"data": {"a": 1}}),
}
ADAPTERS = {
    "firestore": firestore_cloud_event,
    "pubsub": pubsub_cloud_event,
    "storage": storage_cloud_event,
    "eventarc": eventarc_cloud_event,
    "database": database_cloud_event,
}
TRIGGERS = sorted(EVENTS)


def record_request(sink):
    """A function that notes the request it runs inside and the event it was given."""

    def handler(event):
        entry = {"event": event}
        entry["has_context"] = flask.has_request_context()
        if entry["has_context"]:
            entry.update(
                method=flask.request.method,
                path=flask.request.path,
                headers={k.lower(): v for k, v in flask.request.headers.items()},
                body=flask.request.get_data(),
                content_type=flask.request.content_type,
                content_length=flask.request.content_length,
            )
        sink.append(entry)

    return handler


def deliver(trigger, event, monkeypatch, profile=None):
    if profile is None:
        monkeypatch.delenv("FIREEMU_HTTP_PROFILE", raising=False)
    else:
        monkeypatch.setenv("FIREEMU_HTTP_PROFILE", profile)
    sink = []
    dispatch._deliver(trigger, record_request(sink), event)
    assert len(sink) == 1
    return sink[0]


@pytest.mark.parametrize("profile", [None, "emulator", "strict"])
@pytest.mark.parametrize("trigger", TRIGGERS)
def test_a_cloudevent_function_runs_inside_a_post_to_the_root(trigger, profile, monkeypatch):
    seen = deliver(trigger, EVENTS[trigger], monkeypatch, profile)
    assert seen["has_context"] is True
    assert (seen["method"], seen["path"]) == ("POST", "/")


@pytest.mark.parametrize("profile", [None, "strict"])
@pytest.mark.parametrize("trigger", TRIGGERS)
def test_the_request_carries_the_events_attributes_as_binary_mode_headers_and_the_events_body(trigger, profile, monkeypatch):
    seen = deliver(trigger, EVENTS[trigger], monkeypatch, profile)
    expected = ADAPTERS[trigger](EVENTS[trigger])
    for name, value in expected._get_attributes().items():
        if name == "datacontenttype":
            continue
        assert seen["headers"][f"ce-{name}"] == value, name
    assert seen["content_type"] == expected["datacontenttype"]
    assert seen["content_length"] == len(seen["body"]) > 0
    assert seen["body"] == (expected.get_data() if isinstance(expected.get_data(), bytes) else json.dumps(expected.get_data(), separators=(",", ":"), ensure_ascii=False).encode())


@pytest.mark.parametrize("trigger", TRIGGERS)
def test_the_function_is_given_the_event_the_request_describes(trigger, monkeypatch):
    seen = deliver(trigger, EVENTS[trigger], monkeypatch, "strict")
    rebuilt = from_http(seen["headers"], seen["body"])
    assert rebuilt._get_attributes() == seen["event"]._get_attributes()
    assert rebuilt.get_data() == seen["event"].get_data()


def test_a_json_body_is_the_compact_text_the_publisher_sends(monkeypatch):
    event = base(data={"run": "pcrun-1", "label": "é", "n": [1, 2]})
    seen = deliver("eventarc", event, monkeypatch)
    assert seen["body"] == '{"run":"pcrun-1","label":"é","n":[1,2]}'.encode()
    assert seen["headers"]["content-length"] == str(len(seen["body"]))


def test_a_firestore_request_is_protobuf(monkeypatch):
    seen = deliver("firestore", EVENTS["firestore"], monkeypatch)
    assert seen["content_type"] == "application/protobuf"
    assert seen["headers"]["ce-type"].endswith("created")
    assert isinstance(seen["event"].get_data(), bytes) and seen["body"] == seen["event"].get_data()


@pytest.mark.parametrize("trigger", TRIGGERS)
def test_the_strict_profile_adds_the_recorded_constants_and_the_plain_traceparent(trigger, monkeypatch):
    seen = deliver(trigger, {**EVENTS[trigger], "traceparent": TRACEPARENT}, monkeypatch, "strict")
    assert seen["headers"]["user-agent"] == APIS_GOOGLE
    assert seen["headers"]["accept-encoding"] == "gzip, deflate, br"
    assert seen["headers"]["x-forwarded-proto"] == "https"
    assert seen["headers"]["traceparent"] == TRACEPARENT
    assert "ce-traceparent" not in seen["headers"]


@pytest.mark.parametrize("profile", [None, "emulator", ""])
@pytest.mark.parametrize("trigger", TRIGGERS)
def test_the_emulator_profile_adds_no_constants_and_keeps_a_traceparent_extension_as_an_attribute(trigger, profile, monkeypatch):
    seen = deliver(trigger, {**EVENTS[trigger], "traceparent": TRACEPARENT}, monkeypatch, profile)
    assert not {"user-agent", "accept-encoding", "x-forwarded-proto"} & set(seen["headers"])
    assert seen["headers"]["ce-traceparent"] == TRACEPARENT
    assert "traceparent" not in seen["headers"]


def test_a_header_value_with_a_newline_reaches_the_request_without_one_and_the_event_keeps_its_text(monkeypatch):
    seen = deliver("eventarc", base(subject="a\nb\r\nc"), monkeypatch)
    assert seen["headers"]["ce-subject"] == "a b  c"
    assert seen["event"]["subject"] == "a\nb\r\nc"


def test_non_ascii_attributes_survive_the_request(monkeypatch):
    seen = deliver("eventarc", base(subject="é日本"), monkeypatch)
    assert seen["headers"]["ce-subject"] == "é日本"
    assert seen["event"]["subject"] == "é日本"


def test_the_request_exists_only_during_the_invocation_and_a_raising_function_leaves_none(monkeypatch):
    monkeypatch.delenv("FIREEMU_HTTP_PROFILE", raising=False)
    assert not flask.has_request_context()
    dispatch._deliver("eventarc", lambda event: None, base())
    assert not flask.has_request_context()

    def fails(event):
        raise RuntimeError("boom")

    with pytest.raises(RuntimeError):
        dispatch._deliver("eventarc", fails, base())
    assert not flask.has_request_context()


def test_each_concurrent_invocation_sees_its_own_request(monkeypatch):
    monkeypatch.delenv("FIREEMU_HTTP_PROFILE", raising=False)
    both_inside = threading.Barrier(2, timeout=10)
    seen = {}

    def handler(event):
        both_inside.wait()
        seen[event["id"]] = flask.request.headers["ce-id"]

    threads = [
        threading.Thread(target=dispatch._deliver, args=("eventarc", handler, base(id=f"e-{n}"))) for n in (1, 2)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(15)
    assert seen == {"e-1": "e-1", "e-2": "e-2"}


def test_a_scheduled_function_still_runs_in_its_own_request(monkeypatch):
    monkeypatch.delenv("FIREEMU_HTTP_PROFILE", raising=False)
    seen = []

    def scheduled(request):
        seen.append(request.headers["x-cloudscheduler-jobname"])
        return flask.make_response("", 200)

    dispatch._deliver(
        "schedule",
        scheduled,
        {"data": {"jobName": "projects/p/locations/l/jobs/j", "scheduleTime": "2026-01-01T00:00:00Z"}},
    )
    assert seen == ["j"]
