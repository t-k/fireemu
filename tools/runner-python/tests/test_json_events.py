"""Pub/Sub, Storage, Eventarc and Realtime Database events through the real runner and the real SDK.

The event frames have the shapes the daemon sends (`crates/fireemu-adapter-functions/src/events.rs`: `pubsub_event`,
`storage_event`, `database_event_payload`; `eventarc.rs`: `convert`).
"""

import base64

import pytest

from harness import Runner

PS = "google.cloud.pubsub.topic.v1.messagePublished"
ST = "google.cloud.storage.object.v1."
DB = "google.firebase.database.ref.v1."


@pytest.fixture(scope="module")
def runner():
    process = Runner()
    process.hello()
    yield process
    process.kill()


@pytest.fixture(scope="module")
def strict_runner():
    process = Runner(extra_env={"FIREEMU_HTTP_PROFILE": "strict"})
    process.hello()
    yield process
    process.kill()


def run(process, name, trigger, ev):
    result = process.invoke(f"{name}-{len(process.frames)}", name, trigger, ev)
    return result, [entry for entry in process.seen() if entry["function"] == name]


def delivered(process, name, trigger, ev):
    result, entries = run(process, name, trigger, ev)
    assert result["ok"] is True, result
    return entries[-1]


# --- Pub/Sub ---------------------------------------------------------------------------------------


def published(message_id="1111", *, ordering_key=None, text="hello", attributes=None, publish_time="2026-01-01T00:00:02.250Z"):
    message = {
        "messageId": message_id,
        "data": base64.b64encode(text.encode()).decode(),
        "attributes": attributes if attributes is not None else {},
        "publishTime": publish_time,
    }
    if ordering_key is not None:
        message["orderingKey"] = ordering_key
    return {
        "specversion": "1.0",
        "id": message_id,
        "source": "//pubsub.googleapis.com/projects/demo-proj/topics/orders",
        "type": PS,
        "time": publish_time,
        "data": {"message": message, "subscription": "projects/demo-proj/subscriptions/eventarc-us-central1-ps_orders-123456-sub-123"},
    }


def test_a_pubsub_message_reaches_the_handler_with_its_ids_times_and_attributes(runner):
    entry = delivered(runner, "ps_orders", "pubsub", published("m-100", attributes={"k": "v"}))
    assert entry["message_id"] == "m-100"
    assert entry["publish_time"] == "2026-01-01T00:00:02.250000+00:00"
    assert entry["attributes"] == {"k": "v"}
    assert entry["text"] == "hello"
    assert entry["ordering_key"] is None
    assert entry["subscription"].startswith("projects/demo-proj/subscriptions/")
    assert entry["type"] == PS and entry["id"] == "m-100"


def test_an_ordering_key_reaches_the_handler_without_being_passed_twice(runner):
    entry = delivered(runner, "ps_orders", "pubsub", published("m-101", ordering_key="customer-7"))
    assert entry["ordering_key"] == "customer-7"


def test_a_publish_time_without_a_fraction_is_accepted_by_the_sdk(runner):
    entry = delivered(runner, "ps_orders", "pubsub", published("m-102", publish_time="2026-01-01T00:00:02Z"))
    assert entry["publish_time"] == "2026-01-01T00:00:02+00:00"


def test_an_empty_message_has_empty_attributes_and_no_text(runner):
    event = published("m-103", text="")
    del event["data"]["message"]["attributes"]
    entry = delivered(runner, "ps_orders", "pubsub", event)
    assert entry["attributes"] == {} and entry["text"] is None


def test_a_retrying_regional_pubsub_function_is_delivered_the_same_way(runner):
    delivered(runner, "ps_retried", "pubsub", published("m-104"))


def test_a_pubsub_event_the_sdk_cannot_read_is_a_failed_result_with_a_log(runner):
    event = published("m-105")
    del event["data"]["message"]["publishTime"]
    result, entries = run(runner, "ps_orders", "pubsub", event)
    assert result["ok"] is False and "publish_time" in result["error"]
    assert not [entry for entry in entries if entry["message_id"] == "m-105"]


# --- Storage ---------------------------------------------------------------------------------------


def stored(kind, name="photos/a.png", *, time="2026-01-01T00:00:02.250000Z", bucket="demo-bucket", **extra):
    data = {
        "kind": "storage#object",
        "id": f"{bucket}/{name}/1767225600000000",
        "selfLink": f"https://www.googleapis.com/storage/v1/b/{bucket}/o/{name}",
        "mediaLink": f"https://storage.googleapis.com/download/storage/v1/b/{bucket}/o/{name}?generation=1&alt=media",
        "name": name,
        "bucket": bucket,
        "generation": "1767225600000000",
        "metageneration": "1",
        "contentType": "image/png",
        "storageClass": "STANDARD",
        "size": "1234",
        "md5Hash": "AAAAAAAAAAAAAAAAAAAAAA==",
        "crc32c": "AAAAAA==",
        "etag": "CNj+kd3kmIsDEAE=",
        "timeCreated": "2026-01-01T00:00:00.000Z",
        "updated": "2026-01-01T00:00:00.000Z",
        "timeStorageClassUpdated": "2026-01-01T00:00:00.000Z",
    }
    data.update(extra)
    return {
        "specversion": "1.0",
        "id": "12345678901234567",
        "source": f"//storage.googleapis.com/projects/_/buckets/{bucket}",
        "subject": f"objects/{name}",
        "type": ST + kind,
        "time": time,
        "bucket": bucket,
        "data": data,
    }


@pytest.mark.parametrize(
    "function, kind",
    [("st_finalized", "finalized"), ("st_deleted", "deleted"), ("st_archived", "archived"), ("st_metadata", "metadataUpdated")],
)
def test_each_storage_event_kind_reaches_its_handler_with_the_object(runner, function, kind):
    entry = delivered(runner, function, "storage", stored(kind))
    assert (entry["bucket"], entry["object"], entry["size"], entry["content_type"]) == ("demo-bucket", "photos/a.png", "1234", "image/png")
    assert (entry["generation"], entry["metageneration"], entry["storage_class"]) == ("1767225600000000", "1", "STANDARD")
    assert entry["type"] == ST + kind and entry["subject"] == "objects/photos/a.png"
    assert entry["time"] == "2026-01-01T00:00:02.250000+00:00"


def test_object_metadata_and_the_deletion_time_are_kept(runner):
    entry = delivered(
        runner, "st_archived", "storage",
        stored("archived", metadata={"colour": "red"}, timeDeleted="2026-01-01T00:00:01.000Z"),
    )
    assert entry["metadata"] == {"colour": "red"} and entry["time_deleted"] == "2026-01-01T00:00:01.000Z"


def test_a_function_with_no_bucket_listens_to_the_default_bucket(runner):
    entry = delivered(runner, "st_default_bucket", "storage", stored("finalized", bucket="demo-proj.appspot.com"))
    assert entry["bucket"] == "demo-proj.appspot.com"


def test_the_emulator_profile_serves_a_whole_second_time_the_sdk_cannot_parse(runner):
    entry = delivered(runner, "st_finalized", "storage", stored("finalized", time="2026-01-01T00:00:02Z"))
    assert entry["time"] == "2026-01-01T00:00:02+00:00"


def test_the_strict_profile_fails_a_whole_second_time_as_the_sdk_does_with_production_data(strict_runner):
    result, _ = run(strict_runner, "st_finalized", "storage", stored("finalized", time="2026-01-01T00:00:02Z"))
    assert result["ok"] is False and "does not match format" in result["error"]
    delivered(strict_runner, "st_finalized", "storage", stored("finalized", time="2026-01-01T00:00:02.000001Z"))


def test_a_storage_object_without_a_required_field_is_a_failed_result(runner):
    event = stored("finalized")
    del event["data"]["storageClass"]
    result, _ = run(runner, "st_finalized", "storage", event)
    assert result["ok"] is False and "storageClass" in result["error"]


# --- Eventarc --------------------------------------------------------------------------------------


def custom(event_type="acme.thing.v1.happened", data=None, **extra):
    event = {
        "specversion": "1.0",
        "id": "evt-1",
        "type": event_type,
        "source": "//acme.example/things/7",
        "time": "2026-01-01T00:00:02.500Z",
        "data": {"thing": 7} if data is None else data,
    }
    event.update(extra)
    return event


def test_a_custom_event_reaches_its_handler_with_its_data(runner):
    entry = delivered(runner, "ea_plain", "eventarc", custom(subject="things/7"))
    assert entry["data"] == {"thing": 7}
    assert (entry["type"], entry["id"], entry["source"], entry["subject"]) == ("acme.thing.v1.happened", "evt-1", "//acme.example/things/7", "things/7")
    assert entry["time"] == "2026-01-01T00:00:02.500000+00:00"


def test_the_extension_attributes_of_a_custom_event_are_attributes_not_data(runner):
    entry = delivered(runner, "ea_filtered", "eventarc", custom("acme.thing.v1.filtered", colour="red", datacontenttype="application/json"))
    assert entry["data"] == {"thing": 7}


def test_an_emulator_event_with_a_json_content_type_and_a_production_event_without_one_both_arrive(runner, strict_runner):
    delivered(runner, "ea_plain", "eventarc", custom(datacontenttype="application/json"))
    delivered(strict_runner, "ea_plain", "eventarc", custom())


@pytest.mark.parametrize("data", [None, "text", 4, [1, 2]])
def test_data_that_is_not_an_object_fails_the_invocation_as_the_sdk_does(runner, data):
    # The SDK merges the data into the attributes with `**`, which only an object survives.
    result, _ = run(runner, "ea_plain", "eventarc", custom(data=data) if data is not None else {**custom(), "data": None})
    assert result["ok"] is False


def test_the_emulator_profile_serves_a_custom_event_with_a_whole_second_time(runner):
    delivered(runner, "ea_plain", "eventarc", custom(time="2026-01-01T00:00:02Z"))


# --- Realtime Database -----------------------------------------------------------------------------


def changed(kind, path, before, delta, *, auth=("app_user", "uid-1"), emulator_shape=True, instance="demo-proj-default-rtdb"):
    event = {
        "specversion": "1.0",
        "id": "db-evt-1",
        "type": DB + kind,
        "source": f"//firebasedatabase.googleapis.com/projects/demo-proj/locations/us-central1/instances/{instance}",
        "subject": f"refs/{path}",
        "time": "2026-01-01T00:00:02.250Z",
        "firebasedatabasehost": "firebaseio.com",
        "instance": instance,
        "location": "us-central1",
        "ref": path,
        "data": {"@type": "type.googleapis.com/google.events.firebase.database.v1.ReferenceEventData", "data": before, "delta": delta},
    }
    if emulator_shape:
        event["datacontenttype"] = "application/json"
    if auth is not None:
        event["authtype"], event["authid"] = auth
    return event


def test_a_created_value_is_the_delta(runner):
    entry = delivered(runner, "db_created", "database", changed("created", "messages/r1/m1", None, {"text": "hi"}))
    assert entry["value"] == {"text": "hi"}
    assert entry["params"] == {"room": "r1", "id": "m1"}
    assert (entry["instance"], entry["reference"], entry["location"], entry["host"]) == ("demo-proj-default-rtdb", "messages/r1/m1", "us-central1", "firebaseio.com")
    assert (entry["auth_type"], entry["auth_id"]) == ("app_user", "uid-1")
    assert entry["type"] == DB + "created" and entry["subject"] == "refs/messages/r1/m1"


def test_a_deleted_value_is_the_old_data(runner):
    entry = delivered(runner, "db_deleted", "database", changed("deleted", "messages/r1/m2", {"text": "bye"}, None))
    assert entry["value"] == {"text": "bye"}


def test_an_updated_value_merges_the_delta_into_the_old_data(runner):
    entry = delivered(runner, "db_updated", "database", changed("updated", "messages/r1/m3", {"text": "a", "n": 1}, {"n": 2}))
    assert entry["before"] == {"text": "a", "n": 1}
    assert entry["after"] == {"text": "a", "n": 2}


@pytest.mark.parametrize(
    "before, delta, expected_after",
    [(None, {"v": 1}, {"v": 1}), ({"v": 1}, None, None), ({"v": 1}, {"v": 2}, {"v": 2})],
)
def test_a_written_value_has_both_sides_for_every_kind_of_change(runner, before, delta, expected_after):
    entry = delivered(runner, "db_written", "database", changed("written", "messages/r1/m4", before, delta))
    assert entry["before"] == before and entry["after"] == expected_after


def test_a_literal_reference_and_an_instance_glob_deliver_without_parameters(runner):
    entry = delivered(runner, "db_literal_glob", "database", changed("written", "config/mode", {"m": "a"}, {"m": "b"}))
    assert entry["params"] == {} and entry["after"] == {"m": "b"}


def test_a_production_shaped_event_has_no_content_type_and_may_have_no_auth(runner):
    event = changed("created", "messages/r2/m1", None, {"text": "hi"}, auth=None, emulator_shape=False)
    entry = delivered(runner, "db_created", "database", event)
    assert entry["auth_type"] == "unknown" and entry["auth_id"] is None and entry["value"] == {"text": "hi"}


def test_scalar_values_survive(runner):
    entry = delivered(runner, "db_created", "database", changed("created", "messages/r3/m1", None, 42))
    assert entry["value"] == 42
