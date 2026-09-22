import copy
import hashlib
import json
import os
import socketserver
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from typing import ClassVar

import pytest

ADC = {
    "type": "authorized_user",
    "client_id": "fixture-client",
    "client_secret": "fixture-secret",
    "refresh_token": "fixture-refresh",
}


def test_prepared_final_permission_cannot_omit_terminal_baseline():
    import limits_03_admission as admission

    with pytest.raises(ValueError, match="terminal PREP baseline"):
        admission._validate_preparation_permission(
            {"kind": "limits-03-prepared-owner-execution-permission-v1"}
        )


def test_public_database_identity_keeps_full_baseline_digest_without_private_fields():
    import limits_03_baseline_prep as prep
    from batch_contract import database_evidence
    from broad_contract import digest

    body = {
        "name": "projects/fireemu-35fe6/databases/(default)",
        "uid": "fixture-uid",
        "type": "FIRESTORE_NATIVE",
        "databaseEdition": "STANDARD",
        "locationId": "us-central1",
        "unknownPrivateField": "fixture-private-value",
    }
    response = {
        "status": 200,
        "complete": True,
        "workerReaped": True,
        "bodyKind": "json",
        "body": body,
    }
    public = prep._public_metadata("database", response)["value"]
    assert public["projectionDigest"] == database_evidence(body)["projectionDigest"]
    assert set(public["projection"]) == {
        "name",
        "uid",
        "type",
        "databaseEdition",
        "locationId",
    }
    assert public["identityProjectionDigest"] == digest(public["projection"])
    assert "fixture-private-value" not in json.dumps(public)


def test_private_handoff_rejects_pipe_and_duplicate_json_keys():
    import limits_03_baseline_prep as prep

    read_fd, write_fd = os.pipe()
    try:
        with pytest.raises(ValueError):
            prep._read_private_json(read_fd)
    finally:
        os.close(read_fd)
        os.close(write_fd)
    with tempfile.TemporaryFile() as private:
        private.write(b'{"kind":1,"kind":2}')
        private.seek(0)
        with pytest.raises(ValueError, match="duplicate"):
            prep._read_private_json(private.fileno())


def _approved(tmp_path, *, fixture_origin=None):
    import limits_03_baseline_prep as prep
    import o8_admission
    from broad_contract import digest
    from reservations import Ledger
    from test_limits_03_o8 import frozen_checkout

    source = frozen_checkout(tmp_path)
    commit = subprocess.check_output(
        ["git", "-C", str(source), "rev-parse", "HEAD"], text=True
    ).strip()
    artifact = tmp_path / "artifact"
    artifact.write_bytes(b"synthetic fixture artifact; not production approval")
    plan = prep.preparation_plan("b" * 32)
    permission = prep.permission_bindings(
        plan,
        source_commit=commit,
        artifact_sha256=hashlib.sha256(artifact.read_bytes()).hexdigest(),
    )
    permission.update(
        ownerIdentity="fixture-owner",
        recoveryOwner="fixture-recovery",
        issuedAt=time.time() - 1,
        expiresAt=time.time() + 900,
        credentialPrincipal={
            "clientId": "fixture-client",
            "subject": "fixture-subject",
            "requiredScopes": [prep.campaign.PRINCIPAL_SCOPE],
        },
        authorizedUserDigest=digest(ADC),
        apiKeyDigest=digest("fixture-key"),
        fixtureOrigin=fixture_origin,
    )
    descriptor = prep.descriptor()
    inputs = o8_admission.freeze_inputs(
        descriptor,
        permission,
        plan,
        source_commit=commit,
        artifact_sha256=permission["artifactSha256"],
    )
    ledger_root = tmp_path / "ledger"
    Ledger.create(ledger_root)
    manifest = {
        "kind": descriptor.manifest_kind,
        "inputsDigest": inputs["inputsDigest"],
    }
    manifest_bytes = json.dumps(manifest).encode()
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_bytes(manifest_bytes)
    manifest_path.chmod(0o600)
    launcher = Path(prep.__file__)
    approval = {
        "kind": descriptor.approval_kind,
        "status": "approved",
        "campaignId": prep.CAMPAIGN,
        "manifestSha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "inputsDigest": inputs["inputsDigest"],
        "permissionDigest": inputs["permissionDigest"],
        "sourceCommit": commit,
        "sourceInputsDigest": digest(inputs["sourceInputs"]),
        "artifactSha256": inputs["artifactSha256"],
        "planDigest": inputs["planDigest"],
        "nonceDigest": digest(plan["nonce"]),
        "ledgerRoot": str(ledger_root.resolve()),
        "launcherSha256": hashlib.sha256(launcher.read_bytes()).hexdigest(),
        "artifactProfile": descriptor.artifact_profile,
        "windowStartsAt": time.time() - 1,
        "windowExpiresAt": time.time() + 900,
        "executionHost": o8_admission.execution_host(),
    }
    return {
        "source_root": source,
        "inputs": inputs,
        "approval": approval,
        "manifest": manifest,
        "manifest_bytes": manifest_bytes,
        "manifest_path": manifest_path,
        "permission": permission,
        "ledger_root": ledger_root,
        "artifact_path": artifact,
        "launcher_path": launcher,
    }


def test_real_generic_issuer_accepts_independent_prep_without_final_baselines(tmp_path):
    import limits_03_baseline_prep as prep
    import o8_admission

    fixture = _approved(tmp_path)
    capability = prep.approve_preparation(**fixture)
    try:
        assert o8_admission.issued_capability(capability)
        assert "authConfigDigest" not in fixture["permission"]
        assert "databaseProjectionDigest" not in fixture["permission"]
        assert fixture["permission"]["preparationLedgerBudget"] == {
            "requests": 6,
            "accounts": 0,
            "resources": 0,
            "costMicrousd": 600,
        }
    finally:
        o8_admission.revoke_production_capability(capability)


def test_prep_rejects_rehashed_four_row_plan_before_reservation(tmp_path):
    import limits_03_baseline_prep as prep
    from broad_contract import digest
    from reservations import Ledger

    fixture = _approved(tmp_path)
    plan = fixture["inputs"]["plan"]
    plan["gatePlan"]["management"]["observation"] = plan["gatePlan"]["management"][
        "observation"
    ][2:]
    plan["gatePlan"]["observationRequests"] = 4
    plan["gatePlan"]["costMicrousd"] = 400
    fixture["inputs"]["planDigest"] = digest(plan)
    fixture["permission"]["planDigest"] = digest(plan)
    fixture["inputs"]["permissionDigest"] = digest(fixture["permission"])
    fixture["inputs"]["inputsDigest"] = digest(
        {
            key: value
            for key, value in fixture["inputs"].items()
            if key != "inputsDigest"
        }
    )
    ledger = Ledger(fixture["ledger_root"])
    before = ledger.snapshot()
    with pytest.raises(ValueError):
        prep.approve_preparation(**fixture)
    assert ledger.snapshot() == before


@pytest.mark.parametrize(
    "damage",
    ["project", "source", "permission", "nonce", "deadline", "key", "principal"],
)
def test_prep_o7_refuses_drift_before_reservation(tmp_path, damage):
    import limits_03_baseline_prep as prep
    from reservations import Ledger

    fixture = _approved(tmp_path)
    if damage == "project":
        fixture["permission"]["project"] = "wrong-project"
    elif damage == "source":
        fixture["inputs"]["sourceInputs"][
            next(iter(fixture["inputs"]["sourceInputs"]))
        ] = "0" * 64
    elif damage == "permission":
        fixture["permission"]["ownerIdentity"] = "different-owner"
    elif damage == "nonce":
        fixture["permission"]["nonce"] = "a" * 32
    elif damage == "deadline":
        fixture["approval"]["windowExpiresAt"] = time.time() - 1
    elif damage == "key":
        fixture["permission"]["apiKeyDigest"] = "0" * 64
    elif damage == "principal":
        fixture["permission"]["credentialPrincipal"]["subject"] = "wrong-subject"
    ledger = Ledger(fixture["ledger_root"])
    before = ledger.snapshot()
    with pytest.raises(ValueError):
        prep.approve_preparation(**fixture)
    assert ledger.snapshot() == before


def test_approved_transport_runs_actual_isolated_oauth_and_metadata_workers(tmp_path):
    import limits_03_baseline_prep as prep
    import o8_admission

    class Handler(socketserver.StreamRequestHandler):
        seen: ClassVar[list] = []

        def handle(self):
            method, path, _ = self.rfile.readline().decode().split()
            length = 0
            while line := self.rfile.readline():
                if line == b"\r\n":
                    break
                if line.lower().startswith(b"content-length:"):
                    length = int(line.split(b":", 1)[1])
            self.rfile.read(length)
            self.seen.append((method, path.split("?")[0]))
            body = {"fixture": True}
            raw = json.dumps(body).encode()
            self.wfile.write(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                + f"Content-Length: {len(raw)}\r\nConnection: close\r\n\r\n".encode()
                + raw
            )

    with socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        capability = None
        try:
            fixture = _approved(
                tmp_path, fixture_origin=f"http://127.0.0.1:{server.server_address[1]}"
            )
            capability = prep.approve_preparation(**fixture)
            capability._consume(
                campaign_id=prep.CAMPAIGN,
                inputs_digest=fixture["inputs"]["inputsDigest"],
                ledger_root=fixture["ledger_root"],
            )
            with pytest.raises(ValueError, match="deadline"):
                capability._transmit(
                    {"slot": "refresh", "secret": ADC, "deadline": time.monotonic() - 1}
                )
            assert Handler.seen == []
            adc = {
                "type": "authorized_user",
                "client_id": "fixture-client",
                "client_secret": "fixture-secret",
                "refresh_token": "fixture-refresh",
            }
            for slot in (
                "refresh",
                "oauth-tokeninfo",
                "project",
                "database",
                "auth",
                "key",
            ):
                secret = (
                    adc
                    if slot == "refresh"
                    else {"token": "fixture-token", "apiKey": "fixture-key"}
                    if slot == "key"
                    else "fixture-token"
                )
                result = capability._transmit(
                    {"slot": slot, "secret": secret, "deadline": time.monotonic() + 12}
                )
                assert result["complete"] is True
                assert result["workerReaped"] is True
                assert result["status"] == 200
        finally:
            if capability is not None:
                o8_admission.revoke_production_capability(capability)
            server.shutdown()
            thread.join(timeout=2)
        assert not thread.is_alive()
    assert len(Handler.seen) == 6
    assert Handler.seen[:2] == [("POST", "/token"), ("POST", "/oauth2/v1/tokeninfo")]


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


def test_handcrafted_permission_cannot_reserve_without_independent_prep_o7(tmp_path):
    import limits_03_baseline_prep as prep
    from reservations import Ledger

    ledger = Ledger.create(tmp_path / "ledger")
    before = ledger.snapshot()
    with pytest.raises(ValueError, match="independent PREP O7"):
        prep.reserve_preparation(
            _permission(), ledger_root=tmp_path / "ledger", output=tmp_path / "run"
        )
    assert ledger.snapshot() == before
    assert not (tmp_path / "run").exists()


def test_preparation_plan_reserves_only_metadata_prefix_and_same_campaign_family():
    import limits_03_baseline_prep as prep

    plan = prep.preparation_plan("a" * 32)

    assert plan["campaignId"] == "FS-WRITE-LIMITS-03"
    assert plan["preparationKind"] == "limits-03-baseline-preparation-v1"
    assert plan["managementIds"] == [
        "observation:refresh",
        "observation:oauth-tokeninfo",
        "observation:project",
        "observation:database",
        "observation:auth",
        "observation:key",
    ]
    assert plan["dataDispatchAllowed"] is False
    assert plan["indexMutationAllowed"] is False
    assert plan["gatePlan"]["campaignId"] == "FS-WRITE-LIMITS-03"
    assert plan["gatePlan"]["jobs"]["limits"]["resources"] == []
    assert all(lock["mode"] == "READ" for lock in plan["resourceLocks"])
    assert plan["gatePlan"]["management"]["dispatchKind"] == "closed-v1"


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
        {
            "id": "observation:project",
            "status": 200,
            "value": {"projectId": "fireemu-35fe6", "projectNumber": "592603257417"},
        },
        {
            "id": "observation:database",
            "status": 200,
            "value": {
                "projection": {
                    "name": "projects/fireemu-35fe6/databases/(default)",
                    "type": "FIRESTORE_NATIVE",
                    "databaseEdition": "STANDARD",
                },
                "projectionDigest": "d" * 64,
            },
        },
        {
            "id": "observation:auth",
            "status": 200,
            "responseDigest": "e" * 64,
            "value": {},
        },
        {
            "id": "observation:key",
            "status": 200,
            "value": {"parent": "projects/other/locations/global", "name": "x"},
        },
    ]
    with pytest.raises(ValueError):
        prep._public_metadata(
            "key",
            {
                "status": 200,
                "complete": True,
                "workerReaped": True,
                "bodyKind": "json",
                "body": evidence[-1]["value"],
            },
        )


def test_metadata_packet_rejects_tampered_project_readback():
    import limits_03_baseline_prep as prep

    evidence = [
        {
            "id": "observation:project",
            "status": 200,
            "value": {"projectId": "tampered", "projectNumber": "592603257417"},
        },
        {
            "id": "observation:database",
            "status": 200,
            "value": {
                "projection": {
                    "name": "projects/fireemu-35fe6/databases/(default)",
                    "type": "FIRESTORE_NATIVE",
                    "databaseEdition": "STANDARD",
                },
                "projectionDigest": "d" * 64,
            },
        },
        {
            "id": "observation:auth",
            "status": 200,
            "responseDigest": "e" * 64,
            "value": {},
        },
        {
            "id": "observation:key",
            "status": 200,
            "value": {"parent": "projects/592603257417/locations/global", "name": "x"},
        },
    ]
    with pytest.raises(ValueError):
        prep._public_metadata(
            "project",
            {
                "status": 200,
                "complete": True,
                "workerReaped": True,
                "bodyKind": "json",
                "body": evidence[0]["value"],
            },
        )


def test_preparation_reserves_real_temporary_ledger_and_gate(tmp_path):
    import limits_03_baseline_prep as prep

    fixture = _approved(tmp_path)
    ledger_root = fixture["ledger_root"]
    capability = prep.approve_preparation(**fixture)
    ledger, ticket, allocation, gate_plan = prep.reserve_preparation(
        fixture["permission"],
        ledger_root=ledger_root,
        output=tmp_path / "run",
        capability=capability,
        inputs=fixture["inputs"],
    )

    assert ledger.validate(ticket, duration=1)
    assert gate_plan["permissionDigest"]
    assert (tmp_path / "run" / "gate" / "state.json").is_file()
    assert allocation["dataDispatchAllowed"] is False
    before = ledger.snapshot()
    replay = prep.approve_preparation(**fixture)
    try:
        with pytest.raises(ValueError, match="nonce/Gate reuse"):
            prep.reserve_preparation(
                fixture["permission"],
                ledger_root=ledger_root,
                output=tmp_path / "different-output",
                capability=replay,
                inputs=fixture["inputs"],
            )
    finally:
        prep.o8_admission.revoke_production_capability(replay)
        prep.o8_admission.revoke_production_capability(capability)
    assert ledger.snapshot() == before

    with pytest.raises(ValueError):
        prep.reserve_preparation(
            _permission(), ledger_root=ledger_root, output=tmp_path / "run"
        )


@pytest.mark.parametrize(
    "fault",
    [
        None,
        "project",
        "database",
        "auth",
        "key",
        "principal",
        "key-handoff",
        "timeout",
        "unauthorized",
    ],
)
def test_capture_uses_real_loopback_worker_for_all_four_metadata_reads(tmp_path, fault):
    import limits_03_baseline_prep as prep

    database = {
        "name": "projects/fireemu-35fe6/databases/(default)",
        "uid": "db-uid",
        "databaseEdition": "STANDARD",
        "type": "FIRESTORE_NATIVE",
        "locationId": "us-central1",
    }

    class Handler(socketserver.StreamRequestHandler):
        seen: ClassVar[list] = []

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
            if path == "/token":
                body = {
                    "access_token": "fixture-token",
                    "token_type": "Bearer",
                    "expires_in": 3600,
                }
            elif "tokeninfo" in path:
                body = {
                    "expires_in": 3600,
                    "issued_to": "fixture-client",
                    "user_id": "fixture-subject",
                    "scope": prep.campaign.PRINCIPAL_SCOPE,
                }
                if fault == "principal":
                    body["user_id"] = "wrong-subject"
            elif path.startswith("/v1/projects/fireemu-35fe6/databases/"):
                body = (
                    {**database, "name": "projects/wrong-project/databases/(default)"}
                    if fault == "database"
                    else database
                )
            elif path.startswith("/v2/keys:lookupKey"):
                if fault == "timeout":
                    time.sleep(13)
                    return
                body = {
                    "parent": "projects/592603257417/locations/global",
                    "name": "projects/592603257417/locations/global/keys/test",
                }
                if fault == "key":
                    body["name"] = "projects/other/locations/global/keys/test"
            elif path.endswith("/config"):
                body = {
                    "name": "projects/wrong/config"
                    if fault == "auth"
                    else "projects/592603257417/config",
                    "signIn": {},
                }
            elif path.startswith("/v1/projects/fireemu-35fe6"):
                body = {"projectId": "fireemu-35fe6", "projectNumber": "592603257417"}
                if fault == "project":
                    body["projectNumber"] = "1"
            else:
                body = {"name": "projects/592603257417/config", "signIn": {}}
            encoded = json.dumps(body).encode()
            status = (
                401 if fault == "unauthorized" and path.endswith("/config") else 200
            )
            self.wfile.write(
                f"HTTP/1.1 {status} Result\r\nContent-Type: application/json\r\n".encode()
                + f"Content-Length: {len(encoded)}\r\nConnection: close\r\n\r\n".encode()
                + encoded
            )

    server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    origin = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        from broad_contract import digest

        fixture = _approved(tmp_path, fixture_origin=origin)
        with tempfile.TemporaryFile() as handoff:
            handoff.write(
                json.dumps(
                    {
                        "kind": "limits-03-preparation-handoff-v1",
                        "permissionDigest": digest(fixture["permission"]),
                        "adc": ADC,
                        "apiKey": "wrong-key"
                        if fault == "key-handoff"
                        else "fixture-key",
                    }
                ).encode()
            )
            handoff.seek(0)
            packet = prep.capture_baseline(
                bindings=fixture, output=tmp_path / "run", handoff_fd=handoff.fileno()
            )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    for evidence_file in (tmp_path / "run").rglob("*"):
        if evidence_file.is_file():
            retained = evidence_file.read_bytes()
            assert all(
                secret.encode() not in retained
                for secret in (
                    "fixture-token",
                    "fixture-secret",
                    "fixture-refresh",
                    "fixture-key",
                )
            ), evidence_file.name

    if fault is not None:
        from reservations import Ledger, task_spent_microusd

        assert packet["completed"] is False
        assert packet["failed"] is True
        assert packet["reservationReleased"] is True
        assert (
            len(Handler.seen)
            == {
                "principal": 2,
                "project": 3,
                "database": 4,
                "auth": 5,
                "key": 6,
                "key-handoff": 0,
                "timeout": 6,
                "unauthorized": 5,
            }[fault]
        )
        state = Ledger(fixture["ledger_root"]).snapshot()
        assert [row["state"] for row in state["reservations"].values()] == [
            "aborted-no-data"
        ]
        assert task_spent_microusd(state, prep.CAMPAIGN) == 600
        return

    assert packet["completed"] is True
    assert packet["database"]["projectionDigest"]
    assert packet["authConfigDigest"]
    assert packet["slots"] == [
        "observation:refresh",
        "observation:oauth-tokeninfo",
        "observation:project",
        "observation:database",
        "observation:auth",
        "observation:key",
    ]
    assert len(Handler.seen) == 6
    assert packet["reservationReleased"] is True
    from reservations import Ledger, task_spent_microusd

    ledger_state = Ledger(fixture["ledger_root"]).snapshot()
    assert task_spent_microusd(ledger_state, prep.CAMPAIGN) == 600
    assert [row["state"] for row in ledger_state["reservations"].values()] == [
        "released"
    ]
    public = json.dumps(packet)
    assert all(
        secret not in public
        for secret in (
            "fixture-token",
            "fixture-secret",
            "fixture-refresh",
            "fixture-key",
        )
    )
    assert (
        prep.retire_preparation(
            ledger_root=fixture["ledger_root"], output=tmp_path / "run"
        )
        == packet
    )
    assert len(Handler.seen) == 6
    _prove_final_freeze_and_downgrade_refusal(tmp_path, fixture, packet)


def _prove_final_freeze_and_downgrade_refusal(tmp_path, fixture, packet):
    import limits_03_admission as admission
    import limits_03_descriptor as campaign
    import o8_admission
    from broad_contract import digest
    from test_limits_03_o8 import owner_permission

    artifact_digest = hashlib.sha256(fixture["artifact_path"].read_bytes()).hexdigest()
    plan = campaign.plan_compiler("a" * 32)
    permission = owner_permission(
        plan, fixture["inputs"]["sourceCommit"], artifact_digest, campaign.source_map()
    )
    receipt_path = (tmp_path / "run" / "receipt.json").resolve()
    receipt = json.loads(receipt_path.read_bytes())
    permission.update(
        kind=admission.PREPARED_PERMISSION_KIND,
        credentialPrincipal=fixture["permission"]["credentialPrincipal"],
        databaseProjectionDigest=packet["database"]["projectionDigest"],
        authConfigDigest=packet["authConfigDigest"],
        baselinePreparation={
            "packet": packet,
            "ticket": receipt["ticket"],
            "receiptPath": str(receipt_path),
        },
    )
    permission_path = tmp_path / "final-permission.json"
    permission_path.write_text(json.dumps(permission))
    inputs = admission.freeze_prepared_inputs(
        permission_path,
        plan,
        source_root=fixture["source_root"],
        artifact_path=fixture["artifact_path"],
    )
    admission.validate_frozen_inputs(inputs)
    descriptor = admission.descriptor(permission)
    manifest = {
        "kind": descriptor.manifest_kind,
        "inputsDigest": inputs["inputsDigest"],
    }
    manifest_bytes = json.dumps(manifest).encode()
    manifest_path = tmp_path / "final-manifest.json"
    manifest_path.write_bytes(manifest_bytes)
    launcher = Path(admission.__file__).with_name("limits_03_o8.py")
    approval = {
        **fixture["approval"],
        "kind": descriptor.approval_kind,
        "inputsDigest": inputs["inputsDigest"],
        "permissionDigest": inputs["permissionDigest"],
        "planDigest": inputs["planDigest"],
        "nonceDigest": digest(plan["nonce"]),
        "manifestSha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "launcherSha256": hashlib.sha256(launcher.read_bytes()).hexdigest(),
        "windowExpiresAt": time.time() + 4 * descriptor.window_seconds,
    }
    binding, binding_digest = campaign.worker_binding()
    bindings = {
        "inputs": inputs,
        "permission": permission,
        "approval": approval,
        "manifest": manifest,
        "manifest_bytes": manifest_bytes,
        "manifest_path": manifest_path,
        "ledger_root": fixture["ledger_root"],
        "artifact_path": fixture["artifact_path"],
        "launcher_path": launcher,
        "binding": binding,
        "binding_digest": binding_digest,
    }
    capability = admission.issue_production_capability(**bindings)
    from limits_03_production import _envelope
    from reservations import Ledger, task_spent_microusd

    gate_plan = admission.gate_plan_for(inputs, permission)
    claim = admission.reservation_claim(
        inputs, gate_path=tmp_path / "final-gate", gate_plan=gate_plan
    )
    capability._consume(
        campaign_id=campaign.CAMPAIGN,
        inputs_digest=inputs["inputsDigest"],
        ledger_root=fixture["ledger_root"],
    )
    ledger = Ledger(fixture["ledger_root"])
    ledger.reserve(
        _envelope(permission, claim),
        claim,
        gate_plan,
        generation=admission.abort_generation(inputs),
    )
    assert (
        task_spent_microusd(ledger.snapshot(), campaign.CAMPAIGN)
        == 600 + claim["budget"]["costMicrousd"]
    )
    o8_admission.revoke_production_capability(capability)
    for damage in (
        "missing-packet",
        "modified-packet",
        "same-nonce",
        "downgrade",
        "four-rows",
    ):
        changed = copy.deepcopy(permission)
        if damage == "missing-packet":
            del changed["baselinePreparation"]
        elif damage == "modified-packet":
            changed["baselinePreparation"]["packet"]["authConfigDigest"] = "0" * 64
        elif damage == "same-nonce":
            changed["nonce"] = packet["nonce"]
        elif damage == "four-rows":
            damaged_packet = changed["baselinePreparation"]["packet"]
            for name in ("evidence", "slots", "requestDigests"):
                damaged_packet[name] = damaged_packet[name][2:]
            damaged_packet["chargedCalls"] = 4
            damaged_packet["packetDigest"] = digest(
                {
                    key: value
                    for key, value in damaged_packet.items()
                    if key != "packetDigest"
                }
            )
        else:
            changed["kind"] = campaign.PERMISSION_KIND
            del changed["baselinePreparation"]
        altered = copy.deepcopy(inputs)
        altered["permission"] = changed
        altered["permissionDigest"] = digest(changed)
        altered["inputsDigest"] = digest(
            {key: value for key, value in altered.items() if key != "inputsDigest"}
        )
        with pytest.raises(ValueError):
            admission.issue_production_capability(
                **{**bindings, "inputs": altered, "permission": changed}
            )
