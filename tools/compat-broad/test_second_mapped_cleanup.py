"""Cleanup proofs require exact admitted diagnostic and after-readback evidence."""

import copy
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

import pytest
from broad_contract import digest
from second_admission import BASE, FS_IDS, fs_recipe, origins
from second_mapped import LocalAdapter, acknowledged_diagnostic_cleanup_proof

BEFORE_FIELDS = {
    "a": {"mapValue": {"fields": {"b": {"integerValue": "8"}}}},
    "g": {"stringValue": "q"},
    "n": {"integerValue": "2"},
}
DIAGNOSTIC_FIELDS = {
    "a": {"mapValue": {"fields": {"b": {"integerValue": "9"}}}},
    "g": {"stringValue": "q"},
    "n": {"integerValue": "2"},
}
DOCUMENT = BASE + "/cur/c"
BEFORE_VERSION = "2026-09-23T03:44:16.131073Z"
DIAGNOSTIC_VERSION = "2026-09-23T03:44:16.641541Z"


def diagnostic_operation():
    return fs_recipe(FS_IDS[0], "diagnostic", DOCUMENT, {})[0]


def document(fields, update_time):
    return {
        "name": DOCUMENT,
        "fields": copy.deepcopy(fields),
        "updateTime": update_time,
    }


class FirestoreState:
    def __init__(self, fields, update_time):
        self.fields = copy.deepcopy(fields)
        self.update_time = update_time
        self.exists = True
        self.operations = []
        self.delete_conditions = []


@pytest.fixture
def firestore_server():
    state = FirestoreState(BEFORE_FIELDS, BEFORE_VERSION)

    class Handler(BaseHTTPRequestHandler):
        def send_json(self, status, value):
            raw = json.dumps(value).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self):
            state.operations.append(("GET", self.path))
            if state.exists:
                self.send_json(200, document(state.fields, state.update_time))
            else:
                self.send_json(404, {"error": {"code": 404}})

        def do_DELETE(self):
            state.operations.append(("DELETE", self.path))
            condition = parse_qs(urlsplit(self.path).query).get(
                "currentDocument.updateTime", []
            )
            state.delete_conditions.append(condition)
            if state.exists and condition == [state.update_time]:
                state.exists = False
                self.send_json(200, {})
            else:
                self.send_json(412, {"error": {"code": 412}})

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        origin = f"http://127.0.0.1:{server.server_port}"
        yield state, origins({"auth": origin, "firestore": origin})
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive()


def adapter_for_cleanup(tmp_path, local_origins, proof):
    adapter = LocalAdapter(local_origins, "a" * 32, tmp_path / "adapter", mode="direct")
    adapter.documents.add(DOCUMENT)
    adapter.creation_proofs[DOCUMENT] = copy.deepcopy(proof)
    return adapter


def test_acknowledged_diagnostic_state_allows_conditional_delete_and_typed_absence(
    tmp_path, firestore_server
):
    state, local_origins = firestore_server
    diagnostic = diagnostic_operation()
    ack = document(DIAGNOSTIC_FIELDS, DIAGNOSTIC_VERSION)
    after = document(DIAGNOSTIC_FIELDS, DIAGNOSTIC_VERSION)

    proof = acknowledged_diagnostic_cleanup_proof(
        FS_IDS[0], DOCUMENT, diagnostic, 200, ack, 200, after
    )

    assert proof == {
        "name": DOCUMENT,
        "updateTime": DIAGNOSTIC_VERSION,
        "fieldsDigest": digest(DIAGNOSTIC_FIELDS),
        "responseDigest": digest(after),
    }
    state.fields = copy.deepcopy(DIAGNOSTIC_FIELDS)
    state.update_time = DIAGNOSTIC_VERSION
    adapter = adapter_for_cleanup(tmp_path, local_origins, proof)

    adapter.recover()

    assert state.operations[0][0] == "GET"
    assert state.operations[1][0] == "DELETE"
    assert state.delete_conditions == [[DIAGNOSTIC_VERSION]]
    assert state.operations[2][0] == "GET"
    assert not state.exists
    assert not adapter.unrecovered
    final_observation = adapter.trace[-1]["observation"]
    assert final_observation["http"]["status"] == 404
    assert final_observation["http"]["bodyKind"] == "json"
    assert final_observation["body"] == {"error": {"code": 404}}


def test_diagnostic_refusal_keeps_prior_proof_and_cleans_only_unchanged_state(
    tmp_path, firestore_server
):
    state, local_origins = firestore_server
    old_proof = {
        "name": DOCUMENT,
        "updateTime": BEFORE_VERSION,
        "fieldsDigest": digest(BEFORE_FIELDS),
        "responseDigest": digest(document(BEFORE_FIELDS, BEFORE_VERSION)),
    }
    after = document(BEFORE_FIELDS, BEFORE_VERSION)

    assert (
        acknowledged_diagnostic_cleanup_proof(
            FS_IDS[0],
            DOCUMENT,
            diagnostic_operation(),
            400,
            {"error": {"code": 400}},
            200,
            after,
        )
        is None
    )
    adapter = adapter_for_cleanup(tmp_path, local_origins, old_proof)

    adapter.recover()

    assert adapter.creation_proofs[DOCUMENT] == old_proof
    assert [operation for operation, _path in state.operations] == [
        "GET",
        "DELETE",
        "GET",
    ]
    assert state.delete_conditions == [[BEFORE_VERSION]]
    assert not state.exists
    assert not adapter.unrecovered


@pytest.mark.parametrize(
    "case",
    [
        "missing-ack",
        "ack-fields",
        "ack-name",
        "ack-version",
        "after-version",
        "after-fields",
        "wrong-operation",
        "wrong-program",
    ],
)
def test_unproven_diagnostic_state_retains_old_proof_and_never_deletes(
    tmp_path, firestore_server, case
):
    state, local_origins = firestore_server
    old_proof = {
        "name": DOCUMENT,
        "updateTime": BEFORE_VERSION,
        "fieldsDigest": digest(BEFORE_FIELDS),
        "responseDigest": digest(document(BEFORE_FIELDS, BEFORE_VERSION)),
    }
    ack = document(DIAGNOSTIC_FIELDS, DIAGNOSTIC_VERSION)
    after = document(DIAGNOSTIC_FIELDS, DIAGNOSTIC_VERSION)
    program = FS_IDS[0]
    operation = diagnostic_operation()
    if case == "missing-ack":
        ack = None
    elif case == "ack-fields":
        ack["fields"]["n"] = {"integerValue": "999"}
    elif case == "ack-name":
        ack["name"] = BASE + "/cur/foreign"
    elif case == "ack-version":
        ack.pop("updateTime")
    elif case == "after-version":
        after["updateTime"] = "2026-09-23T03:44:17.000000Z"
    elif case == "after-fields":
        after["fields"]["external"] = {"booleanValue": True}
    elif case == "wrong-operation":
        operation["query"].pop()
    elif case == "wrong-program":
        program = FS_IDS[1]
    state.fields = copy.deepcopy(after["fields"])
    state.update_time = after["updateTime"]

    assert (
        acknowledged_diagnostic_cleanup_proof(
            program, DOCUMENT, operation, 200, ack, 200, after
        )
        is None
    )
    adapter = adapter_for_cleanup(tmp_path, local_origins, old_proof)

    with pytest.raises(ValueError, match="incomplete recovery"):
        adapter.recover()

    assert adapter.creation_proofs[DOCUMENT] == old_proof
    assert [operation for operation, _path in state.operations] == ["GET"]
    assert state.delete_conditions == []
    assert adapter.unrecovered == [{"kind": "document", "name": DOCUMENT}]
