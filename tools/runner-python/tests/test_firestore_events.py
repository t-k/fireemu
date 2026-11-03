"""Firestore events: the daemon's structured event becomes the CloudEvent production delivers."""

import pytest

from harness import Runner

FS = "google.cloud.firestore.document.v1."
PARENT = "projects/demo-proj/databases/(default)/documents"


@pytest.fixture(scope="module")
def runner():
    process = Runner()
    process.hello()
    yield process
    process.kill()


def document(path, fields, create="2026-01-01T00:00:00.5Z", update="2026-01-01T00:00:01.5Z"):
    return {"name": f"{PARENT}/{path}", "fields": fields, "createTime": create, "updateTime": update}


def event(kind, path, *, before=None, after=None, mask=None, auth=None, time="2026-01-01T00:00:02.25Z", database="(default)"):
    """The structured event the daemon sends (`fireemu-adapter-functions/src/events.rs`, `firestore_event`)."""
    data = {}
    if after is not None:
        data["value"] = after
    if before is not None:
        data["oldValue"] = before
    if mask is not None:
        data["updateMask"] = {"fieldPaths": mask}
    message = {
        "specversion": "1.0",
        "id": "0a1b2c3d-0000-4000-8000-000000000001",
        "source": f"//firestore.googleapis.com/projects/demo-proj/databases/{database}",
        "subject": f"documents/{path}",
        "type": FS + kind + (".withAuthContext" if auth else ""),
        "time": time,
        "datacontenttype": "application/json",
        "data": data,
        "location": "nam5",
        "project": "demo-proj",
        "namespace": database,
        "document": path,
        "database": database,
    }
    if auth:
        message["authtype"], message["authid"] = auth
    return message


def run(runner, name, ev, trigger="firestore"):
    result = runner.invoke(f"{name}-{len(runner.frames)}", name, trigger, ev)
    assert result["ok"] is True, result
    return [entry for entry in runner.seen() if entry["function"] == name][-1]


def test_a_created_event_gives_the_handler_the_new_snapshot_and_the_path_parameters(runner):
    after = document("items/a1", {"n": {"integerValue": "1"}})
    entry = run(runner, "fs_created", event("created", "items/a1", after=after))
    assert entry["params"] == {"id": "a1"}
    assert entry["type"] == FS + "created"
    assert entry["snapshot"] == {"id": "a1", "path": "items/a1", "data": {"n": 1}}


def test_a_deleted_event_gives_the_old_snapshot(runner):
    before = document("items/a2", {"s": {"stringValue": "gone"}})
    entry = run(runner, "fs_deleted", event("deleted", "items/a2", before=before))
    assert entry["snapshot"]["data"] == {"s": "gone"}


def test_an_updated_event_gives_before_and_after(runner):
    before = document("items/a3", {"n": {"integerValue": "1"}})
    after = document("items/a3", {"n": {"integerValue": "2"}})
    entry = run(runner, "fs_updated", event("updated", "items/a3", before=before, after=after, mask=["n"]))
    assert entry["before"]["data"] == {"n": 1}
    assert entry["after"]["data"] == {"n": 2}


@pytest.mark.parametrize("kind, before, after", [("created", False, True), ("updated", True, True), ("deleted", True, False)])
def test_a_written_trigger_receives_each_kind_with_the_matching_sides(runner, kind, before, after):
    path = f"items/w-{kind}"
    old = document(path, {"v": {"stringValue": "old"}}) if before else None
    new = document(path, {"v": {"stringValue": "new"}}) if after else None
    entry = run(runner, "fs_written", event(kind, path, before=old, after=new, mask=["v"] if before and after else None))
    assert (entry["before"] is not None, entry["after"] is not None) == (before, after)
    assert entry["params"] == {"id": f"w-{kind}"}


def test_every_firestore_value_type_survives_the_protobuf_round_trip(runner):
    fields = {
        "s": {"stringValue": "x"},
        "i": {"integerValue": "42"},
        "d": {"doubleValue": 1.5},
        "b": {"booleanValue": True},
        "n": {"nullValue": None},
        "t": {"timestampValue": "2026-01-01T00:00:00.123456789Z"},
        "r": {"referenceValue": f"{PARENT}/items/other"},
        "g": {"geoPointValue": {"latitude": 1.5, "longitude": -2.5}},
        "y": {"bytesValue": "AQID"},
        "a": {"arrayValue": {"values": [{"integerValue": "1"}, {"stringValue": "z"}]}},
        "m": {"mapValue": {"fields": {"k": {"integerValue": "7"}}}},
    }
    entry = run(runner, "fs_created", event("created", "items/types", after=document("items/types", fields)))
    data = entry["snapshot"]["data"]
    assert data["s"] == "x" and data["i"] == 42 and data["d"] == 1.5 and data["b"] is True and data["n"] is None
    # `DocumentSnapshot.to_dict()` deep-copies the value, which drops the digits below a microsecond: that is
    # the SDK's own behaviour, the same in production.
    assert data["t"]["timestamp"] == "2026-01-01T00:00:00.123456+00:00"
    assert data["r"] == {"reference": "items/other"}
    assert data["g"] == {"geopoint": [1.5, -2.5]}
    assert data["y"] == {"bytes": "AQID"}
    assert data["a"] == [1, "z"] and data["m"] == {"k": 7}


def test_an_event_with_an_auth_context_reaches_the_with_auth_context_function(runner):
    after = document("items/auth1", {"n": {"integerValue": "1"}})
    entry = run(runner, "fs_created_auth", event("created", "items/auth1", after=after, auth=("unauthenticated", "anon")))
    assert (entry["auth_type"], entry["auth_id"]) == ("unauthenticated", "anon")
    assert entry["type"] == FS + "created.withAuthContext"


def test_a_literal_document_path_and_a_named_database_are_matched_by_the_manifest_only(runner):
    entry = run(runner, "fs_literal", event("created", "settings/global", after=document("settings/global", {"k": {"stringValue": "v"}})))
    assert entry["params"] == {}
    entry = run(runner, "fs_options", event("created", "items/o1", after=document("items/o1", {}), database="other"))
    assert entry["params"] == {"id": "o1"}


def test_a_time_without_fractional_seconds_is_accepted(runner):
    entry = run(runner, "fs_created", event("created", "items/t1", after=document("items/t1", {}), time="2026-01-01T00:00:02Z"))
    assert entry["id"] == "0a1b2c3d-0000-4000-8000-000000000001"


def test_a_handler_that_raises_is_a_failed_result_with_its_message_and_a_log_frame(runner):
    # fs_created reads event.data; an event without any document makes the SDK itself raise.
    result = runner.invoke("bad-1", "fs_created", "firestore", {"type": FS + "created", "data": {}})
    assert result["ok"] is False
    assert result["error"]
    assert any(frame["type"] == "log" and frame["level"] == "error" and frame.get("invocationId") == "bad-1" for frame in runner.frames)


def test_overlapping_events_each_get_their_own_result(runner):
    from concurrent.futures import ThreadPoolExecutor

    def one(n):
        path = f"items/c{n}"
        return runner.invoke(f"conc-{n}", "fs_created", "firestore", event("created", path, after=document(path, {"n": {"integerValue": str(n)}})))

    with ThreadPoolExecutor(8) as pool:
        results = list(pool.map(one, range(16)))
    assert all(result["ok"] for result in results)
    mine = {entry["snapshot"]["path"]: entry["snapshot"]["data"]["n"] for entry in runner.seen() if entry["function"] == "fs_created" and entry["snapshot"]["path"].startswith("items/c")}
    assert mine == {f"items/c{n}": n for n in range(16)}
