"""Firestore binary IPC data reaches the SDK without a JSON conversion."""

import base64
import json
import os
from pathlib import Path
import pytest
from firebase_functions import firestore_fn
from fireemu_runner.events import firestore_cloud_event

from google.events.cloud import firestore

from fireemu_runner.events import firestore_request


def test_binary_ipc_keeps_the_original_document_bytes(monkeypatch):
    monkeypatch.setenv("FIREEMU_HTTP_PROFILE", "strict")
    message = firestore.DocumentEventData.from_json(
        '{"value":{"name":"projects/demo-proj/databases/(default)/documents/items/a",'
        '"fields":{"n":{"integerValue":"9223372036854775807"}}}}'
    )
    body = firestore.DocumentEventData.serialize(message)
    delivery = firestore_request({
        "specversion": "1.0", "id": "test", "source": "test", "type": "test",
        "datacontenttype": "application/protobuf",
        "data": base64.b64encode(body).decode(),
    })
    assert delivery.request_body == body
    assert delivery.event_body == body
    assert delivery.headers["content-type"] == "application/protobuf"




@pytest.mark.parametrize("profile", ["strict", "emulator"])
@pytest.mark.parametrize("auth", [False, True])
def test_rust_documents_reach_the_real_sdk(profile, auth, monkeypatch):
    import firebase_admin
    monkeypatch.setenv("FIREEMU_HTTP_PROFILE", profile)
    monkeypatch.setenv("FIRESTORE_EMULATOR_HOST", "127.0.0.1:1")
    if not firebase_admin._apps:
        firebase_admin.initialize_app(options={"projectId": "demo-proj"})
    corpus = json.loads(Path(os.environ["FE_FIRESTORE_CORPUS"]).read_text())
    for row in corpus:
        kind = row["kind"].split("-")[0]
        received = []
        decorator = getattr(firestore_fn, "on_document_" + kind + ("_with_auth_context" if auth else ""))
        function = decorator(document="items/{id}")(received.append)
        event = {
            "specversion": "1.0", "id": "local-test", "time": "2026-01-01T00:00:00.000Z",
            "type": "google.cloud.firestore.document.v1." + kind + (".withAuthContext" if auth else ""),
            "source": "//firestore.googleapis.com/projects/demo-proj/databases/(default)",
            "subject": "documents/items/a", "project": "demo-proj", "database": "(default)",
            "namespace": "(default)", "location": "local", "document": "items/a",
            "datacontenttype": "application/protobuf" if profile == "strict" else "application/json",
            "data": row["protobuf" if profile == "strict" else "json"],
        }
        if auth:
            event.update(authtype="system", authid="local")
        function(firestore_cloud_event(event))
        result = received.pop()
        assert result.params == {"id": "a"}
        if auth:
            assert (result.auth_type, result.auth_id) == ("system", "local")
        changed = kind in ("updated", "written")
        old = result.data.before if changed else result.data if kind == "deleted" else None
        new = result.data.after if changed else result.data if kind == "created" else None
        for snapshot, key, n in ((old, "oldValue", 41), (new, "value", 42)):
            if key not in row["json"]:
                assert snapshot is None
                continue
            assert snapshot.reference.path == "items/a"
            data = snapshot.to_dict()
            assert len(data) == 12
            assert data["integer"] == n
            assert data["null"] is None and data["boolean"] is True and data["double"] == 1.5
            assert data["string"] == "é snow 雪" and data["bytes"] == bytes([0, 1, 255])
            assert data["reference"].path == "items/ref"
            assert (data["geo"].latitude, data["geo"].longitude) == (-90, 180)
            assert data["array"] == [n, {"nested": "value"}]
            assert data["map"] == {"a.b": [False]}
            assert data["vector"].to_map_value() == {"__type__": "__vector__", "value": (1.0, -2.5)}
            # Snapshot.to_dict deep-copy preserves the SDK's microsecond datetime view.
            assert data["timestamp"].microsecond == 123456
        print(f"PICT\tPython\t{profile}\t{row['kind']}\t{'context' if auth else 'ordinary'}")


@pytest.mark.parametrize("data", [None, {}, "!not-base64!", "AAAA!!!!"])
def test_malformed_binary_ipc_is_refused(data):
    with pytest.raises(ValueError):
        firestore_request({"specversion": "1.0", "datacontenttype": "application/protobuf", "data": data})
