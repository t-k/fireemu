"""The Firestore adapter on its own: the structured event becomes the CloudEvent production delivers."""

import pytest

from fireemu_runner.events import firestore_cloud_event

PARENT = "projects/demo-proj/databases/(default)/documents"


def structured(**overrides):
    event = {
        "specversion": "1.0",
        "id": "e-1",
        "source": "//firestore.googleapis.com/projects/demo-proj/databases/(default)",
        "subject": "documents/items/a",
        "type": "google.cloud.firestore.document.v1.created",
        "time": "2026-01-01T00:00:02.25Z",
        "datacontenttype": "application/json",
        "location": "nam5",
        "project": "demo-proj",
        "namespace": "(default)",
        "document": "items/a",
        "database": "(default)",
        "data": {
            "value": {
                "name": f"{PARENT}/items/a",
                "fields": {"n": {"integerValue": "1"}},
                "createTime": "2026-01-01T00:00:00Z",
                "updateTime": "2026-01-01T00:00:01Z",
            }
        },
    }
    event.update(overrides)
    return event


def test_every_string_attribute_becomes_a_ce_header_and_the_body_is_protobuf():
    event = firestore_cloud_event(structured(authtype="unauthenticated", authid="anon"))
    attributes = event._get_attributes()
    for name in ("specversion", "id", "source", "subject", "type", "time", "location", "project", "namespace", "document", "database", "authtype", "authid"):
        assert attributes[name] == structured(authtype="unauthenticated", authid="anon")[name], name
    # The content type is protobuf, never the structured event's JSON: the SDK's JSON branch needs text.
    assert attributes["datacontenttype"] == "application/protobuf"
    body = event.get_data()
    assert isinstance(body, bytes)
    from google.events.cloud import firestore as g

    message = g.DocumentEventData.deserialize(body)
    assert message.value.name == f"{PARENT}/items/a"
    assert message.value.fields["n"].integer_value == 1


def test_data_and_the_declared_content_type_are_not_attributes():
    attributes = firestore_cloud_event(structured())._get_attributes()
    assert "data" not in attributes
    assert attributes["datacontenttype"] != "application/json"


def test_non_string_members_are_not_attributes():
    attributes = firestore_cloud_event(structured(count=3, flag=True, nothing=None))._get_attributes()
    assert not {"count", "flag", "nothing"} & set(attributes)


def test_an_event_without_data_is_an_empty_document_event():
    event = structured()
    del event["data"]
    assert firestore_cloud_event(event).get_data() is None
    event["data"] = "not an object"
    assert firestore_cloud_event(event).get_data() is None


@pytest.mark.parametrize("specversion", [None, 1, ""])
def test_an_event_without_a_specversion_string_is_refused_with_a_plain_message(specversion):
    event = structured()
    del event["specversion"]
    if specversion is not None:
        event["specversion"] = specversion
    if specversion == "":
        # An empty string is still a string: the cloudevents library rejects its value.
        with pytest.raises(Exception):
            firestore_cloud_event(event)
        return
    with pytest.raises(ValueError, match="no specversion"):
        firestore_cloud_event(event)


def test_the_refusal_without_a_specversion_has_this_exact_message():
    event = structured()
    del event["specversion"]
    with pytest.raises(ValueError) as error:
        firestore_cloud_event(event)
    assert str(error.value) == "the event has no specversion"


# Production (recorded 2026-11-04, sandbox run PYCHECK-EVENTS-20261104-01, the raw twin of a created event): Eventarc sends
# `ce-dataschema` with the Firestore events, and no other attribute beyond the ones the daemon already names.
DATASCHEMA = "https://github.com/googleapis/google-cloudevents/blob/main/proto/google/events/cloud/firestore/v1/data.proto"


# Only `created` was recorded; the other three follow the one schema document of the family and are UNRECORDED.
@pytest.mark.parametrize(
    "kind",
    ["created", pytest.param("updated", id="updated-UNRECORDED"), pytest.param("deleted", id="deleted-UNRECORDED"), pytest.param("written", id="written-UNRECORDED")],
)
def test_the_strict_profile_gives_a_firestore_event_the_dataschema_production_sends(monkeypatch, kind):
    monkeypatch.setenv("FIREEMU_HTTP_PROFILE", "strict")
    attributes = firestore_cloud_event(structured(type=f"google.cloud.firestore.document.v1.{kind}"))._get_attributes()
    assert attributes["dataschema"] == DATASCHEMA


@pytest.mark.parametrize("profile", [None, "emulator", ""])
def test_the_emulator_profile_keeps_the_official_emulators_attributes_without_a_dataschema(monkeypatch, profile):
    if profile is None:
        monkeypatch.delenv("FIREEMU_HTTP_PROFILE", raising=False)
    else:
        monkeypatch.setenv("FIREEMU_HTTP_PROFILE", profile)
    assert "dataschema" not in firestore_cloud_event(structured())._get_attributes()


def test_a_dataschema_the_daemon_names_is_kept_in_both_profiles(monkeypatch):
    for profile in ("strict", "emulator"):
        monkeypatch.setenv("FIREEMU_HTTP_PROFILE", profile)
        attributes = firestore_cloud_event(structured(dataschema="https://example.com/schema"))._get_attributes()
        assert attributes["dataschema"] == "https://example.com/schema", profile


def test_the_dataschema_is_added_to_nothing_but_the_attributes(monkeypatch):
    monkeypatch.setenv("FIREEMU_HTTP_PROFILE", "strict")
    event = structured()
    firestore_cloud_event(event)
    assert "dataschema" not in event


TRACEPARENT = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"


def test_the_strict_profile_does_not_make_a_traceparent_member_a_firestore_attribute(monkeypatch):
    monkeypatch.setenv("FIREEMU_HTTP_PROFILE", "strict")
    attributes = firestore_cloud_event(structured(traceparent=TRACEPARENT))._get_attributes()
    assert "traceparent" not in attributes
    assert attributes["id"] == "e-1"


@pytest.mark.parametrize("profile", [None, "emulator", ""])
def test_the_emulator_profile_keeps_a_traceparent_member_as_a_firestore_attribute(monkeypatch, profile):
    if profile is None:
        monkeypatch.delenv("FIREEMU_HTTP_PROFILE", raising=False)
    else:
        monkeypatch.setenv("FIREEMU_HTTP_PROFILE", profile)
    assert firestore_cloud_event(structured(traceparent=TRACEPARENT))._get_attributes()["traceparent"] == TRACEPARENT
