import pytest
import time
from pathlib import Path
import http.client
import json
import threading
import socketserver
from urllib.parse import urlsplit


def _permission(nonce="b" * 32):
    now = time.time()
    return {
        "kind": "limits-03-baseline-preparation-v1",
        "campaignId": "FS-WRITE-LIMITS-03",
        "preparationId": "c" * 32,
        "nonce": nonce,
        "issuedAt": now - 1,
        "expiresAt": now + 600,
        "ownerIdentity": "owner",
        "recoveryOwner": "recovery",
        "project": "fireemu-35fe6",
        "projectNumber": "592603257417",
        "database": "(default)",
    }


def test_preparation_plan_reserves_only_metadata_prefix_and_same_campaign_family():
    import limits_03_baseline_prep as prep

    plan = prep.preparation_plan("a" * 32)

    assert plan["campaignId"] == "FS-WRITE-LIMITS-03"
    assert plan["preparationKind"] == "limits-03-baseline-preparation-v1"
    assert plan["managementIds"] == [
        "observation:access-command",
        "observation:tokeninfo",
        "observation:project",
        "observation:database",
        "observation:auth",
        "observation:key",
    ]
    assert plan["dataDispatchAllowed"] is False
    assert plan["indexMutationAllowed"] is False
    assert plan["gatePlan"]["campaignId"] == "FS-WRITE-LIMITS-03"


def test_preparation_plan_rejects_non_nonce():
    import limits_03_baseline_prep as prep

    with pytest.raises(ValueError):
        prep.preparation_plan("not-a-nonce")


@pytest.mark.parametrize(
    "change",
    [
        {"project": "other-project"},
        {"projectNumber": "1"},
        {"expiresAt": time.time() + 299},
    ],
)
def test_reservation_rejects_wrong_project_or_expired_permission(tmp_path, change):
    import limits_03_baseline_prep as prep
    from reservations import Ledger

    permission = _permission()
    permission.update(change)
    Ledger.create(tmp_path / "ledger")
    with pytest.raises(ValueError):
        prep.reserve_preparation(
            permission, ledger_root=tmp_path / "ledger", output=tmp_path / "run"
        )


def test_metadata_packet_rejects_malformed_api_key_readback(tmp_path):
    import limits_03_baseline_prep as prep

    evidence = [
        {"id": "observation:project", "status": 200, "value": {"projectId": "fireemu-35fe6", "projectNumber": "592603257417"}},
        {"id": "observation:database", "status": 200, "value": {"projection": {"name": "projects/fireemu-35fe6/databases/(default)", "type": "FIRESTORE_NATIVE", "databaseEdition": "STANDARD"}, "projectionDigest": "d" * 64}},
        {"id": "observation:auth", "status": 200, "responseDigest": "e" * 64, "value": {}},
        {"id": "observation:key", "status": 200, "value": {"parent": "projects/other/locations/global", "name": "x"}},
    ]
    with pytest.raises(ValueError):
        prep._metadata_packet(_permission(), "b" * 32, "ticket", {}, evidence)


def test_metadata_packet_rejects_tampered_project_readback():
    import limits_03_baseline_prep as prep

    evidence = [
        {"id": "observation:project", "status": 200, "value": {"projectId": "tampered", "projectNumber": "592603257417"}},
        {"id": "observation:database", "status": 200, "value": {"projection": {"name": "projects/fireemu-35fe6/databases/(default)", "type": "FIRESTORE_NATIVE", "databaseEdition": "STANDARD"}, "projectionDigest": "d" * 64}},
        {"id": "observation:auth", "status": 200, "responseDigest": "e" * 64, "value": {}},
        {"id": "observation:key", "status": 200, "value": {"parent": "projects/592603257417/locations/global", "name": "x"}},
    ]
    with pytest.raises(ValueError):
        prep._metadata_packet(_permission(), "b" * 32, "ticket", {}, evidence)


def test_preparation_reserves_real_temporary_ledger_and_gate(tmp_path):
    import limits_03_baseline_prep as prep
    from reservations import Ledger

    ledger_root = tmp_path / "ledger"
    Ledger.create(ledger_root)
    ledger, ticket, allocation, gate_plan = prep.reserve_preparation(
        _permission(), ledger_root=ledger_root, output=tmp_path / "run"
    )

    assert ledger.validate(ticket, duration=1)
    assert gate_plan["permissionDigest"]
    assert (tmp_path / "run" / "gate" / "state.json").is_file()
    assert allocation["dataDispatchAllowed"] is False

    with pytest.raises(ValueError):
        prep.reserve_preparation(
            _permission(), ledger_root=ledger_root, output=tmp_path / "run"
        )


def test_capture_uses_real_loopback_worker_for_all_four_metadata_reads(
    tmp_path, monkeypatch
):
    import batch_adapter
    import limits_03_baseline_prep as prep

    database = {
        "name": "projects/fireemu-35fe6/databases/(default)",
        "uid": "db-uid",
        "databaseEdition": "STANDARD",
        "type": "FIRESTORE_NATIVE",
        "locationId": "us-central1",
    }

    class Handler(socketserver.StreamRequestHandler):
        seen = []

        def handle(self):
            request = self.rfile.readline().decode().split()
            path = request[1]
            length = 0
            for _ in range(32):
                line = self.rfile.readline()
                if line in (b"\r\n", b"\n", b""):
                    break
                if line.lower().startswith(b"content-length:"):
                    length = int(line.split(b":", 1)[1].strip())
            if length:
                self.rfile.read(length)
            type(self).seen.append(path)
            if "tokeninfo" in path:
                body = {"expires_in": 1200}
            elif path.startswith("/v1/projects/fireemu-35fe6/databases/"):
                body = database
            elif path.startswith("/v2/keys:lookupKey"):
                body = {"parent": "projects/592603257417/locations/global", "name": "projects/592603257417/locations/global/keys/test"}
            elif path.endswith("/config"):
                body = {"name": "projects/592603257417/config", "signIn": {}}
            elif path.startswith("/v1/projects/fireemu-35fe6"):
                body = {"projectId": "fireemu-35fe6", "projectNumber": "592603257417"}
            else:
                body = {"name": "projects/592603257417/config", "signIn": {}}
            encoded = json.dumps(body).encode()
            self.wfile.write(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                + f"Content-Length: {len(encoded)}\r\nConnection: close\r\n\r\n".encode()
                + encoded
            )

    server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    origin = f"http://127.0.0.1:{server.server_address[1]}"
    real_wire = batch_adapter.wire

    def loopback_wire(url, method, body, headers, **kwargs):
        parsed = urlsplit(url)
        connection = http.client.HTTPConnection(
            "127.0.0.1", server.server_address[1], timeout=kwargs.get("timeout", 12)
        )
        try:
            path = parsed.path + (("?" + parsed.query) if parsed.query else "")
            connection.request(method, path, body=json.dumps(body).encode() if body else None, headers=headers)
            response = connection.getresponse()
            return response.status, json.loads(response.read()), response.getheader("Content-Type", "application/json")
        finally:
            connection.close()

    monkeypatch.setattr(batch_adapter, "wire", loopback_wire)
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    fake_gcloud = fake_bin / "gcloud"
    fake_gcloud.write_text("#!/bin/sh\nprintf 'loopback-token\\n'\n")
    fake_gcloud.chmod(0o700)
    monkeypatch.setenv("PATH", str(fake_bin))
    try:
        ledger_root = tmp_path / "ledger"
        from reservations import Ledger

        Ledger.create(ledger_root)
        packet = prep.capture_baseline(
            _permission(),
            ledger_root=ledger_root,
            output=tmp_path / "run",
            api_key="private-test-key",
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    assert packet["completed"] is True
    assert packet["database"]["projectionDigest"]
    assert packet["authConfigDigest"]
    assert packet["slots"] == [
        "observation:access-command",
        "observation:tokeninfo",
        "observation:project",
        "observation:database",
        "observation:auth",
        "observation:key",
    ]
    assert len(Handler.seen) == 5
