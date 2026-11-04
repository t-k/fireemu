"""The adapters of the JSON CloudEvent families (Pub/Sub, Storage, Eventarc, Realtime Database) on their own.

The daemon's structured event becomes the CloudEvent the SDK receives from functions-framework:
binary-mode `ce-*` attributes and the data as the body, read back by `cloudevents.http.from_http`.
"""

import json

import pytest

from fireemu_runner.events import (
    database_cloud_event,
    eventarc_cloud_event,
    pubsub_cloud_event,
    storage_cloud_event,
)

ADAPTERS = {
    "pubsub": pubsub_cloud_event,
    "storage": storage_cloud_event,
    "eventarc": eventarc_cloud_event,
    "database": database_cloud_event,
}


def event(**overrides):
    base = {
        "specversion": "1.0",
        "id": "e-1",
        "source": "//example.googleapis.com/x",
        "type": "acme.thing",
        "time": "2026-01-01T00:00:02.250Z",
        "data": {"k": "v"},
    }
    base.update(overrides)
    return base


@pytest.fixture(params=sorted(ADAPTERS))
def adapter(request):
    return ADAPTERS[request.param]


def test_every_string_member_but_the_data_and_content_type_is_an_attribute(adapter):
    attributes = adapter(event(subject="s/1", colour="red", datacontenttype="application/json"))._get_attributes()
    for name, value in (("specversion", "1.0"), ("id", "e-1"), ("source", "//example.googleapis.com/x"), ("type", "acme.thing"),
                        ("time", "2026-01-01T00:00:02.250Z"), ("subject", "s/1"), ("colour", "red")):
        assert attributes[name] == value, name
    assert "data" not in attributes
    assert attributes["datacontenttype"] == "application/json"


def test_non_string_members_are_not_attributes(adapter):
    attributes = adapter(event(count=3, flag=True, nothing=None, nested={"a": 1}))._get_attributes()
    assert not {"count", "flag", "nothing", "nested"} & set(attributes)


def test_the_data_is_the_parsed_json_body(adapter):
    assert adapter(event(data={"a": [1, {"b": None}], "c": "é"})).get_data() == {"a": [1, {"b": None}], "c": "é"}


def test_a_missing_content_type_is_json_as_production_delivers_it(adapter):
    # The strict profile's events carry no `datacontenttype`; Eventarc delivers JSON in binary mode.
    attributes = adapter(event())._get_attributes()
    assert attributes["datacontenttype"] == "application/json"


@pytest.mark.parametrize("content_type", ["application/json", "application/json; charset=utf-8", "application/vnd.api+json"])
def test_a_json_content_type_keeps_the_data_an_object(adapter, content_type):
    delivered = adapter(event(datacontenttype=content_type))
    assert delivered.get_data() == {"k": "v"}
    assert delivered._get_attributes()["datacontenttype"] == content_type


def test_text_data_with_a_text_content_type_arrives_as_bytes_the_way_functions_framework_gives_it(adapter):
    delivered = adapter(event(datacontenttype="text/plain", data="hello"))
    assert delivered.get_data() == b"hello"
    assert delivered._get_attributes()["datacontenttype"] == "text/plain"


def test_an_event_without_data_has_no_data(adapter):
    body = event()
    del body["data"]
    assert adapter(body).get_data() is None


def test_json_scalars_and_arrays_survive(adapter):
    for value in (None, 3, "text", [1, 2], True):
        assert adapter(event(data=value)).get_data() == value


def test_an_event_without_a_specversion_string_is_refused_with_a_plain_message(adapter):
    body = event()
    del body["specversion"]
    with pytest.raises(ValueError) as error:
        adapter(body)
    assert str(error.value) == "the event has no specversion"
    with pytest.raises(ValueError, match="no specversion"):
        adapter(event(specversion=1))


# --- Pub/Sub -------------------------------------------------------------------------------------


def published(**message):
    base = {"messageId": "m-1", "data": "aGk=", "attributes": {"a": "b"}, "publishTime": "2026-01-01T00:00:02.250Z"}
    base.update(message)
    return event(
        type="google.cloud.pubsub.topic.v1.messagePublished",
        data={"message": base, "subscription": "projects/demo-proj/subscriptions/s"},
    )


def test_pubsub_adds_only_the_two_snake_case_keys_the_sdk_reads():
    message = pubsub_cloud_event(published()).get_data()["message"]
    assert message == {
        "messageId": "m-1",
        "message_id": "m-1",
        "data": "aGk=",
        "attributes": {"a": "b"},
        "publishTime": "2026-01-01T00:00:02.250Z",
        "publish_time": "2026-01-01T00:00:02.250Z",
    }


def test_pubsub_keeps_the_ordering_key_as_it_is_and_never_adds_a_snake_case_copy():
    # The SDK pops `orderingKey` and passes `ordering_key=` itself; a copied `ordering_key` key would be passed twice.
    message = pubsub_cloud_event(published(orderingKey="k1")).get_data()["message"]
    assert message["orderingKey"] == "k1"
    assert "ordering_key" not in message


def test_pubsub_does_not_replace_a_snake_case_key_the_event_already_has():
    message = pubsub_cloud_event(published(message_id="kept", publish_time="2026-02-02T00:00:00.5Z")).get_data()["message"]
    assert (message["message_id"], message["publish_time"]) == ("kept", "2026-02-02T00:00:00.5Z")


def test_pubsub_leaves_alone_a_message_that_lacks_the_camel_case_keys():
    message = pubsub_cloud_event(published(messageId=None, publishTime=None)).get_data()["message"]
    assert "message_id" not in message and "publish_time" not in message
    data_only = event(data={"message": {"data": "aGk="}})
    assert pubsub_cloud_event(data_only).get_data() == {"message": {"data": "aGk="}}


def test_pubsub_leaves_data_that_is_not_a_message_alone():
    assert pubsub_cloud_event(event(data="plain")).get_data() == "plain"
    assert pubsub_cloud_event(event(data={"message": "not a dict"})).get_data() == {"message": "not a dict"}


def test_the_callers_event_is_not_modified():
    original = published(orderingKey="k")
    snapshot = json.dumps(original, sort_keys=True)
    pubsub_cloud_event(original)
    assert json.dumps(original, sort_keys=True) == snapshot


# --- the lenient time of the emulator profile -----------------------------------------------------


@pytest.mark.parametrize("family", ["storage", "eventarc"])
@pytest.mark.parametrize("time, padded", [
    ("2026-01-01T00:00:02Z", "2026-01-01T00:00:02.000Z"),
    ("2026-01-01T00:00:02+09:00", "2026-01-01T00:00:02.000+09:00"),
    ("2026-01-01T00:00:02.5Z", "2026-01-01T00:00:02.5Z"),
    ("not a time", "not a time"),
])
def test_the_emulator_profile_gives_a_whole_second_time_a_fraction_the_sdk_can_parse(monkeypatch, family, time, padded):
    # `storage_fn` and `eventarc_fn` parse `time` with `%f`, which a whole-second time lacks. The official
    # emulator always prints milliseconds, so the emulator profile must not refuse what it served.
    monkeypatch.setenv("FIREEMU_HTTP_PROFILE", "emulator")
    assert ADAPTERS[family](event(time=time))._get_attributes()["time"] == padded


@pytest.mark.parametrize("family", ["storage", "eventarc"])
def test_the_strict_profile_delivers_the_time_as_it_is(monkeypatch, family):
    monkeypatch.setenv("FIREEMU_HTTP_PROFILE", "strict")
    assert ADAPTERS[family](event(time="2026-01-01T00:00:02Z"))._get_attributes()["time"] == "2026-01-01T00:00:02Z"


@pytest.mark.parametrize("family", ["pubsub", "database"])
def test_pubsub_and_database_times_are_never_changed(monkeypatch, family):
    monkeypatch.setenv("FIREEMU_HTTP_PROFILE", "emulator")
    assert ADAPTERS[family](event(time="2026-01-01T00:00:02Z"))._get_attributes()["time"] == "2026-01-01T00:00:02Z"


def test_no_profile_is_the_emulator_profile(monkeypatch):
    monkeypatch.delenv("FIREEMU_HTTP_PROFILE", raising=False)
    assert storage_cloud_event(event(time="2026-01-01T00:00:02Z"))._get_attributes()["time"] == "2026-01-01T00:00:02.000Z"


# --- survivors of the first mutation run on slice 2a ---------------------------------------------------


@pytest.mark.parametrize("content_type", ["application/json", "application/json; charset=utf-8", "APPLICATION/JSON", "application/json; charset=utf-8; boundary=x", "application/vnd.api+json", "application/x.thing+JSON"])
def test_text_data_with_a_json_content_type_is_a_json_string(adapter, content_type):
    # A JSON content type means the body is the JSON text of the data: a string becomes a JSON string literal.
    assert adapter(event(datacontenttype=content_type, data="hello")).get_data() == "hello"


@pytest.mark.parametrize("content_type", ["text/plain", "text/plain; charset=utf-8", "application/octet-stream", "application/jsonx"])
def test_text_data_with_another_content_type_is_the_raw_text(adapter, content_type):
    assert adapter(event(datacontenttype=content_type, data="hello")).get_data() == b"hello"


@pytest.mark.parametrize("declared", [5, True, ["application/json"], {"a": 1}])
def test_a_content_type_that_is_not_a_string_is_ignored_for_the_default(adapter, declared):
    delivered = adapter(event(datacontenttype=declared, data="hello"))
    assert delivered._get_attributes()["datacontenttype"] == "application/json"
    assert delivered.get_data() == "hello"


def test_an_empty_content_type_is_the_default(adapter):
    assert adapter(event(datacontenttype=""))._get_attributes()["datacontenttype"] == "application/json"


# Production (recorded 2026-11-04, sandbox run PYCHECK-EVENTS-20261104-01): the raw CloudEvent of a Pub/Sub, Storage and
# Eventarc delivery has no `traceparent` attribute. The trace context is an ordinary HTTP header of the request there.
TRACEPARENT = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"


def test_a_traceparent_member_is_not_a_cloudevent_attribute(adapter):
    attributes = adapter(event(traceparent=TRACEPARENT))._get_attributes()
    assert "traceparent" not in attributes
    assert attributes["id"] == "e-1"


def test_a_traceparent_member_does_not_change_the_data_or_the_other_attributes(adapter):
    with_trace = adapter(event(traceparent=TRACEPARENT))
    without = adapter(event())
    assert with_trace._get_attributes() == without._get_attributes()
    assert with_trace.get_data() == without.get_data()
