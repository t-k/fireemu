"""Safety contracts for the bounded production observation tool."""

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from itertools import product
from threading import Thread

import pytest
from probe import (
    cleanup_resources,
    endpoint,
    has_ownership_marker,
    owned_name,
    summarize_aggregation,
)


def test_production_has_exact_project_and_endpoint_allowlist():
    assert endpoint("production", None) == "https://firestore.googleapis.com"
    with pytest.raises(ValueError):
        endpoint("production", "https://evil.example")
    for host in ["http://localhost:9000", "http://127.0.0.1:9000"]:
        assert endpoint("local", host) == host
    for host in [
        "https://127.0.0.1:9000",
        "http://evil.example",
        "http://localhost:9000/path",
        "http://user@localhost:9000",
    ]:
        with pytest.raises(ValueError):
            endpoint("local", host)


def test_cleanup_paths_are_exact_uuid_namespace_document_names():
    namespace = "compat_" + "a" * 32
    assert owned_name(namespace, "A").endswith(f"/{namespace}/A")
    for collection, doc in [
        ("existing", "A"),
        (namespace, "../other"),
        (namespace, "A/sub/doc"),
    ]:
        with pytest.raises(ValueError):
            owned_name(collection, doc)


def test_aggregation_summary_preserves_wire_types_and_consumes_all_results():
    assert summarize_aggregation(
        [
            {
                "result": {
                    "aggregateFields": {
                        "count": {"integerValue": "3"},
                        "sum": {"integerValue": "30"},
                    }
                }
            }
        ]
    ) == {"count": {"integerValue": "3"}, "sum": {"integerValue": "30"}}
    for body in [
        [],
        [{"readTime": "now"}],
        [{"result": {"aggregateFields": {}}}, {"result": {"aggregateFields": {}}}],
    ]:
        with pytest.raises(ValueError):
            summarize_aggregation(body)


@pytest.mark.parametrize("position", [0, 1])
@pytest.mark.parametrize(
    "invalid",
    [
        {"error": {"code": 13, "status": "INTERNAL", "message": "stream failed"}},
        None,
        False,
        42,
        "unexpected",
        [],
        {},
        {"readTime": None},
        {"readTime": "now"},
        {"readTime": "2026-02-30T00:00:00Z"},
        {"readTime": "2026-09-09T00:00:00+00:60"},
        {"readTime": "2026-09-09T00:00:00+01:99"},
        {"readTime": "2026-09-09T00:00:00-00:60"},
        {"readTime": "2026-09-09T00:00:00+24:00"},
        {"result": None},
        {"result": []},
        {"result": {}},
        {"result": {"aggregateFields": None}},
        {"result": {"aggregateFields": []}},
        {"result": {"aggregateFields": {"count": {"integerValue": "4"}}, "error": {}}},
        {"readTime": "2026-09-09T00:00:00Z", "error": {}},
        {"transaction": "dHg="},
        {"explainMetrics": {}},
    ],
)
def test_aggregation_rejects_invalid_elements_anywhere_in_the_response(
    invalid, position
):
    body = [{"result": {"aggregateFields": {"count": {"integerValue": "4"}}}}]
    body.insert(position, invalid)
    with pytest.raises((TypeError, ValueError)):
        summarize_aggregation(body)


def test_aggregation_allows_only_read_time_progress_for_this_nontransactional_corpus():
    fields = {"count": {"integerValue": "4"}}
    assert (
        summarize_aggregation(
            [
                {"readTime": "2026-09-09T00:00:00.123456789Z"},
                {
                    "result": {"aggregateFields": fields},
                    "readTime": "2026-09-09T00:00:01Z",
                },
                {"readTime": "2026-09-09T00:00:02+00:00"},
            ]
        )
        == fields
    )
    with pytest.raises(ValueError):
        summarize_aggregation([{"readTime": "2026-09-09T00:00:00Z"}])


def test_bounded_response_model_never_discards_an_invalid_element():
    # Exhaust every stream of length 0..3 over five row classes (156 streams).
    fields = {"count": {"integerValue": "4"}}
    alphabet = [
        {"result": {"aggregateFields": fields}},
        {"readTime": "2026-09-09T00:00:00Z"},
        {"error": {"status": "INTERNAL"}},
        None,
        {},
    ]
    for length in range(4):
        for sequence in product(range(len(alphabet)), repeat=length):
            body = [alphabet[i] for i in sequence]
            valid = sequence.count(0) == 1 and all(i < 2 for i in sequence)
            if valid:
                assert summarize_aggregation(body) == fields
            else:
                with pytest.raises((TypeError, ValueError)):
                    summarize_aggregation(body)


def test_uncertain_creates_need_exact_persisted_ownership_marker():
    marker = "a" * 32
    assert has_ownership_marker(
        {"fields": {"__fireemuOracleOwner": {"stringValue": marker}}}, marker
    )
    assert not has_ownership_marker(
        {"fields": {"__fireemuOracleOwner": {"stringValue": "other"}}}, marker
    )
    assert not has_ownership_marker({"fields": {}}, marker)
    assert not has_ownership_marker([], marker)


def test_cleanup_recovers_uncertain_ownership_and_survives_real_transport_failure():
    calls = []
    deleted = set()
    marker = "a" * 32
    names = [owned_name("compat_" + "a" * 32, key) for key in ["A", "B", "C"]]

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            pass

        def do_DELETE(self):
            calls.append(("DELETE", self.path))
            if self.path.endswith("/A"):
                self.wfile.write(b"invalid HTTP status line\r\n\r\n")
                self.close_connection = True
                return
            deleted.add(self.path)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"{}")

        def do_GET(self):
            calls.append(("GET", self.path))
            self.send_response(404 if self.path in deleted else 200)
            self.end_headers()
            owner = marker if self.path.endswith("/B") else "someone-else"
            self.wfile.write(
                json.dumps(
                    {"fields": {"__fireemuOracleOwner": {"stringValue": owner}}}
                ).encode()
            )

    # OS-assigned port, one real local HTTP server, always closed and joined.
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever)
    thread.start()
    try:
        result = cleanup_resources(
            f"http://127.0.0.1:{server.server_port}", "owner", names, [names[0]], marker
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
    assert len(result) == 3
    assert result[0]["error"] == "BadStatusLine"
    assert result[1]["confirmedMissing"] and result[1]["recoveredOwnership"]
    assert not result[2]["confirmedMissing"]
    assert ("DELETE", f"/v1/{names[2]}") not in calls
