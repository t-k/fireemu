"""Real bounded loopback responses exercise anonymous recovery failure handling."""

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest


@pytest.mark.parametrize(
    "outcome", ["deleted", "delete-refused", "still-present", "unknown-uid"]
)
def test_anonymous_recovery_requires_deletion_and_confirmed_absence(tmp_path, outcome):
    import auth_conditions
    from batch_adapter import Adapter
    from batch_contract import candidate

    assert hasattr(auth_conditions, "recover_anonymous"), (
        "independent recovery required"
    )
    calls = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: object) -> None:
            pass

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            calls.append((self.path.rsplit(":", 1)[-1], body))
            assert (
                body == {"localId": "owned-anonymous"}
                if calls[-1][0] == "delete"
                else body == {"localId": ["owned-anonymous"]}
            )
            status = 400 if outcome == "delete-refused" and len(calls) == 2 else 200
            value = (
                {"users": [{"localId": "owned-anonymous"}]}
                if len(calls) == 1 or (outcome == "still-present" and len(calls) == 3)
                else {}
            )
            data = json.dumps(value).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever)
    thread.start()
    try:
        origin = f"http://127.0.0.1:{server.server_port}"
        adapter = Adapter(
            candidate(),
            "a" * 32,
            tmp_path / "run",
            local_origins={"auth": origin, "firestore": origin},
        )
        adapter.budget.recovery = True
        auth_conditions.recover_anonymous(
            adapter, None if outcome == "unknown-uid" else "owned-anonymous"
        )
        assert bool(adapter.unrecovered) is (outcome != "deleted")
        events = (
            [
                json.loads(line)["kind"]
                for line in adapter.journal.read_text().splitlines()
            ]
            if adapter.journal.exists()
            else []
        )
        assert ("anonymous-absent" in events) is (outcome == "deleted")
        assert [call[0] for call in calls] == {
            "deleted": ["lookup", "delete", "lookup"],
            "delete-refused": ["lookup", "delete"],
            "still-present": ["lookup", "delete", "lookup"],
            "unknown-uid": [],
        }[outcome]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
        assert not thread.is_alive()
