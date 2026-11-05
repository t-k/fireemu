"""The request a CloudEvent function runs inside.

functions-framework serves a CloudEvent function from a Flask view and calls the function inside the request context, so
`flask.request` shows the delivered HTTP request (method, path, the `ce-*` headers, the content type, the body bytes).
Production's raw twins were recorded on 2026-11-04 (sandbox run PYCHECK-EVENTS-20261104-01): `POST /`, binary-mode
`ce-*` headers, `content-type`, `content-length`, and in the strict profile the constants `user-agent: APIs-Google; ...`,
`accept-encoding: gzip, deflate, br`, `x-forwarded-proto: https`, plus Cloud Run's plain `traceparent` header.
"""

import json
import threading
from pathlib import Path

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

RECORDED = json.loads((Path(__file__).parent / "recorded_bodies.json").read_text(encoding="utf-8"))
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


def deliver(trigger, event, monkeypatch, profile=None, raw=None):
    if profile is None:
        monkeypatch.delenv("FIREEMU_HTTP_PROFILE", raising=False)
    else:
        monkeypatch.setenv("FIREEMU_HTTP_PROFILE", profile)
    sink = []
    dispatch._deliver(trigger, record_request(sink), event, raw)
    assert len(sink) == 1
    return sink[0]


@pytest.mark.parametrize("profile", [None, "emulator", "strict"])
@pytest.mark.parametrize("trigger", TRIGGERS)
def test_a_cloudevent_function_runs_inside_a_post_to_the_root(trigger, profile, monkeypatch):
    seen = deliver(trigger, EVENTS[trigger], monkeypatch, profile)
    assert seen["has_context"] is True
    assert (seen["method"], seen["path"]) == ("POST", "/")


@pytest.mark.parametrize("trigger", TRIGGERS)
def test_the_function_is_given_the_event_the_request_describes(trigger, monkeypatch):
    seen = deliver(trigger, EVENTS[trigger], monkeypatch, "strict")
    rebuilt = from_http(seen["headers"], seen["body"])
    assert rebuilt._get_attributes() == seen["event"]._get_attributes()
    assert rebuilt.get_data() == seen["event"].get_data()


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


def test_a_traceparent_with_a_line_break_reaches_the_strict_request_without_one(monkeypatch):
    seen = deliver("eventarc", {**base(), "traceparent": "00-a\nb"}, monkeypatch, "strict")
    assert seen["headers"]["traceparent"] == "00-a b"


@pytest.mark.parametrize("value", [None, 5, ["00-a"]])
def test_a_traceparent_that_is_not_text_is_not_a_header(value, monkeypatch):
    seen = deliver("eventarc", {**base(), "traceparent": value}, monkeypatch, "strict")
    assert "traceparent" not in seen["headers"]


def test_an_event_without_data_has_an_empty_body(monkeypatch):
    event = base()
    del event["data"]
    seen = deliver("eventarc", event, monkeypatch)
    assert seen["body"] == b"" and seen["content_length"] in (0, None)
    assert seen["event"].get_data() in (None, b"")


# ---- the body: literal bytes of the recorded shapes -------------------------------------------------------------------------
# Recorded 2026-11-04 (tests/recorded_bodies.json): an Eventarc custom event arrives as the publisher's compact text (51 and 48
# bytes); Pub/Sub as sorted compact JSON plus a newline (348 and 382 bytes); Storage as the object resource, indented by two
# spaces, in the Cloud Storage JSON API member order, plus a newline (963 bytes). The daemon's frame orders members
# alphabetically (serde_json) and, for a custom Eventarc event in the strict profile only, keeps the publisher's text.


def frame_text(value):
    """What the daemon's frame carries for a value: alphabetical members, compact."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def daemon_pubsub(recorded):
    """A Pub/Sub event as the daemon frames it: no snake-case members, members alphabetical."""
    data = json.loads(recorded)
    for key in ("message_id", "publish_time"):
        data["message"].pop(key)
    return base(type="google.cloud.pubsub.topic.v1.messagePublished", data=data), frame_text(data)


@pytest.mark.parametrize("name, text", [("EVENTARC_FRACTION", 51), ("EVENTARC_WHOLE", 48)])
@pytest.mark.parametrize("profile", [None, "strict"])
def test_a_custom_eventarc_event_is_delivered_as_the_publishers_text(name, text, profile, monkeypatch):
    recorded = RECORDED[name]
    assert len(recorded.encode()) == text
    seen = deliver("eventarc", base(data=json.loads(recorded)), monkeypatch, profile, raw=recorded)
    assert seen["body"] == recorded.encode()
    assert seen["content_length"] == text and seen["headers"]["content-length"] == str(text)


def test_the_emulator_profile_delivers_the_text_the_daemon_sent_whatever_its_order(monkeypatch):
    sent = '{"label":"fraction","run":"pcrun-1"}'
    seen = deliver("eventarc", base(data=json.loads(sent)), monkeypatch, "emulator", raw=sent)
    assert seen["body"] == sent.encode()


@pytest.mark.parametrize("profile", [None, "emulator", "strict"])
def test_number_and_character_forms_in_the_delivered_text_are_not_rewritten(profile, monkeypatch):
    sent = '{"a":1e-7,"b":1e20,"c":"\u00e9","d":-0.0,"e":9007199254740993,"f":1.0,"g":[1E3,0.10]}'
    seen = deliver("eventarc", base(data=json.loads(sent)), monkeypatch, profile, raw=sent)
    assert seen["body"] == sent.encode()


def test_without_the_delivered_text_the_body_is_the_compact_encoding_of_the_data(monkeypatch):
    seen = deliver("eventarc", base(data={"run": "r", "n": [1, 2], "s": "é"}), monkeypatch)
    assert seen["body"] == '{"run":"r","n":[1,2],"s":"é"}'.encode()


@pytest.mark.parametrize("name, length", [("PUBSUB_PLAIN", 348), ("PUBSUB_ORDERED", 382)])
def test_the_strict_pubsub_body_is_the_recorded_sorted_text_with_a_newline(name, length, monkeypatch):
    recorded = RECORDED[name]
    event, frame = daemon_pubsub(recorded)
    seen = deliver("pubsub", event, monkeypatch, "strict", raw=json.dumps(event["data"], sort_keys=True, separators=(",", ":")))
    assert len(recorded.encode()) == length
    assert seen["body"] == recorded.encode()
    assert seen["content_length"] == length


@pytest.mark.parametrize("profile", [None, "emulator"])
def test_the_emulator_pubsub_body_is_compact_in_the_frames_order_with_the_two_snake_case_members(profile, monkeypatch):
    event, frame = daemon_pubsub(RECORDED["PUBSUB_PLAIN"])
    seen = deliver("pubsub", event, monkeypatch, profile, raw=frame)
    body = json.loads(seen["body"])
    assert list(body["message"]) == ["attributes", "data", "messageId", "publishTime", "message_id", "publish_time"]
    assert seen["body"] == json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode()
    assert not seen["body"].endswith(b"\n")


def test_pubsub_number_forms_are_kept_and_members_are_sorted_in_strict(monkeypatch):
    data = {"subscription": "s", "message": {"data": "aGk=", "n": 1e-7, "m": 1e20, "attributes": {"b": "1", "a": "é"}}}
    raw = '{"message":{"attributes":{"a":"é","b":"1"},"data":"aGk=","m":1e20,"n":1e-7},"subscription":"s"}'
    seen = deliver("pubsub", base(data=data), monkeypatch, "strict", raw=raw)
    text = seen["body"].decode()
    assert text.startswith('{"message":{"attributes":{"a":"é","b":"1"},"data":"aGk=","m":1e20,') and text.endswith(',"n":1e-7},"subscription":"s"}\n')


def test_the_strict_storage_body_is_the_recorded_indented_text_in_the_api_member_order(monkeypatch):
    recorded = RECORDED["STORAGE"]
    data = json.loads(recorded)
    event = base(type="google.cloud.storage.object.v1.finalized", data=data)
    seen = deliver("storage", event, monkeypatch, "strict", raw=frame_text(data))
    assert len(recorded.encode()) == 963
    assert seen["body"] == recorded.encode()
    assert seen["content_length"] == 963


def test_storage_members_the_recording_does_not_show_follow_in_sorted_order_in_strict(monkeypatch):
    # UNRECORDED: only the recorded members have a known place; the rest are appended alphabetically.
    data = {"etag": "e", "zeta": 1, "kind": "storage#object", "alpha": {"y": 1, "x": 2}}
    seen = deliver("storage", base(type="google.cloud.storage.object.v1.finalized", data=data), monkeypatch, "strict", raw=frame_text(data))
    assert seen["body"].decode() == '{\n  "kind": "storage#object",\n  "etag": "e",\n  "alpha": {\n    "x": 2,\n    "y": 1\n  },\n  "zeta": 1\n}\n'


@pytest.mark.parametrize("profile", [None, "emulator"])
def test_the_emulator_storage_body_is_the_text_the_daemon_sent(profile, monkeypatch):
    data = json.loads(RECORDED["STORAGE"])
    sent = frame_text(data)
    seen = deliver("storage", base(type="google.cloud.storage.object.v1.finalized", data=data), monkeypatch, profile, raw=sent)
    assert seen["body"] == sent.encode()


@pytest.mark.parametrize("profile", [None, "emulator", "strict"])
def test_a_realtime_database_body_is_the_delivered_text_UNRECORDED(profile, monkeypatch):
    # No raw Realtime Database delivery was recorded: nothing is claimed beyond keeping the text the daemon sent.
    sent = '{"data":{"a":1e-7},"delta":null}'
    seen = deliver("database", base(type="google.firebase.database.ref.v1.created", data=json.loads(sent)), monkeypatch, profile, raw=sent)
    assert seen["body"] == sent.encode()


def test_a_text_event_without_a_json_content_type_keeps_its_text_as_the_body(monkeypatch):
    seen = deliver("eventarc", base(datacontenttype="text/plain", data="plain é text"), monkeypatch, "strict", raw='"plain \u00e9 text"')
    assert seen["body"] == "plain é text".encode()
    assert seen["event"].get_data() == "plain é text".encode()


# ---- the header policy -------------------------------------------------------------------------------------------------------


def test_a_control_character_in_a_value_other_than_tab_becomes_a_space_in_the_request(monkeypatch):
    seen = deliver("eventarc", base(subject="a\x00b\x1fc\x7fd\te\u0085f"), monkeypatch)
    assert seen["headers"]["ce-subject"] == "a b c d\te\u0085f"
    assert seen["event"]["subject"] == "a\x00b\x1fc\x7fd\te\u0085f"


@pytest.mark.parametrize("name", ["bad name", "bad:name", "bad\nname", "bad\x00", "über", "a(b)", "a/b", 'a"b', "a@b"])
def test_an_attribute_that_is_not_a_header_name_is_left_out_of_the_request_and_kept_in_the_event(name, monkeypatch):
    seen = deliver("eventarc", base(**{name: "v"}), monkeypatch)
    assert f"ce-{name}" not in seen["headers"]
    assert {k for k in seen["headers"] if k.startswith("ce-")} == {"ce-specversion", "ce-id", "ce-source", "ce-type", "ce-time"}
    assert seen["event"][name] == "v"


def test_an_attribute_with_an_underscore_is_left_out_of_the_request_and_kept_in_the_event(monkeypatch):
    # UNRECORDED: the usual servers drop header names with an underscore; the event keeps the attribute.
    seen = deliver("eventarc", base(foo_bar="u", **{"foo-bar": "h"}), monkeypatch)
    assert seen["headers"]["ce-foo-bar"] == "h"
    assert "ce-foo_bar" not in seen["headers"]
    assert seen["event"]["foo_bar"] == "u" and seen["event"]["foo-bar"] == "h"


def test_two_attributes_that_differ_only_in_case_give_one_header_the_first_and_the_event_is_the_one_main_built(monkeypatch):
    seen = deliver("eventarc", {**base(), "Colour": "first", "colour": "second"}, monkeypatch)
    assert seen["headers"]["ce-colour"] == "first"
    assert [k for k in seen["headers"] if k == "ce-colour"] == ["ce-colour"]
    # The SDK's event lower-cases attribute names and keeps the last (main's behaviour, unchanged by the view).
    assert seen["event"]["colour"] == "second"


def test_a_very_long_value_reaches_the_request_whole(monkeypatch):
    seen = deliver("eventarc", base(subject="x" * 70000), monkeypatch)
    assert seen["headers"]["ce-subject"] == "x" * 70000


def test_the_strict_storage_body_keeps_the_number_spelling_the_daemon_framed(monkeypatch):
    raw = '{"extra":1e20,"kind":"storage#object","size":"1"}'
    data = json.loads(raw)
    seen = deliver("storage", base(type="google.cloud.storage.object.v1.finalized", data=data), monkeypatch, "strict", raw=raw)
    assert seen["body"].decode() == '{\n  "kind": "storage#object",\n  "size": "1",\n  "extra": 1e20\n}\n'
