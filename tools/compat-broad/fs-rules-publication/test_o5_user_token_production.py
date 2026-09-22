"""Tests for the externally approved O5 production launcher boundary."""

from __future__ import annotations

import hashlib
import json
import os
import socketserver
import sys
import threading
import time
from contextlib import nullcontext
from pathlib import Path
from typing import ClassVar

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE.parent / "o8-core"))
sys.path.insert(0, str(HERE))

import o5_user_token_collector as collector_module
import o5_user_token_descriptor as lane
import o5_user_token_production as production
import o5_user_token_production_bridge as bridge
import o5_user_token_remote_transport as remote
import shared_gate
from o5_user_token_campaign import digest, setup_plan
from o5_user_token_collector import ROLE_PRODUCTION
from reservations import Ledger
from test_o5_user_token_collector_bound import acquisition_for
from test_o5_user_token_descriptor import synthetic
from test_o5_user_token_remote_transport import (
    _fixture_capability,
    _fixture_proofs,
    _FixtureHandler,
    account_bindings,
)


def _producer_server():
    server = socketserver.TCPServer(
        ("127.0.0.1", int(os.environ.get("PORT", "0"))),
        _ProducerHandler,
        bind_and_activate=False,
    )
    server.allow_reuse_address = True
    server.server_bind()
    server.server_activate()
    return server


class _ProducerHandler(_FixtureHandler):
    """Stateful loopback Rules API plus the shared Auth fixture endpoint."""

    active = "projects/fireemu-35fe6/rulesets/pre-existing"
    deleted: ClassVar[set[str]] = set()
    recovered_documents: ClassVar[set[str]] = set()
    deleted_accounts: ClassVar[set[str]] = set()
    requests: ClassVar[list[dict[str, object]]] = []
    setup_uids: ClassVar[dict[str, str]] = {}
    setup_account_order: ClassVar[list[str]] = []
    fail_setup_after: ClassVar[int | None] = None

    def do_any(self) -> None:
        size = int(self.headers.get("Content-Length", "0"))
        body = json.loads(self.rfile.read(size) or b"{}")
        path = self.path
        self.__class__.requests.append(
            {"method": self.command, "path": path, "body": body}
        )
        status = 200
        setup_request_count = sum(
            "currentDocument.exists=false" in request["path"]
            or "/v1/projects/" in request["path"]
            and "/accounts:" in request["path"]
            or request["path"].startswith("/v1/accounts:")
            for request in self.__class__.requests
        )
        if (
            self.__class__.fail_setup_after is not None
            and setup_request_count > self.__class__.fail_setup_after
            and (
                "currentDocument.exists=false" in path
                or "/v1/projects/" in path
                and "/accounts:" in path
                or path.startswith("/v1/accounts:")
            )
        ):
            status, payload = 500, {"error": {"code": 500, "status": "INTERNAL"}}
            raw = json.dumps(payload, separators=(",", ":")).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
            return
        if "currentDocument.exists=false" in path:
            # The worker has already checked the compiler-owned conditional
            # path and request shape. Echo the materialized Firestore fields
            # so adapt_setup_result can bind the response to the request.
            payload = {
                "name": body["name"],
                "fields": body["fields"],
                "updateTime": "2026-09-22T00:00:00Z",
            }
        elif path.startswith("/v1/accounts:signUp?key="):
            email = body.get("email")
            ref = next(
                (
                    row["ref"]
                    for row in self._plan["ownedAccounts"]
                    if row.get("email") == email
                ),
                None,
            )
            if ref is None:
                remaining = [
                    row["ref"]
                    for row in self._plan["ownedAccounts"]
                    if row["ref"] not in self.__class__.setup_uids
                ]
                ref = remaining[0]
            uid = "uid-" + str(ref)
            self.__class__.setup_uids[str(ref)] = uid
            payload = {
                "localId": uid,
                "idToken": "setup-token-" + str(ref),
                "expiresIn": "3600",
            }
        elif "/v1/projects/" in path and "/accounts:update" in path:
            payload = {"localId": body["localId"]}
        elif path.startswith("/v1/accounts:signInWithPassword?key="):
            ref = next(
                ref
                for ref, uid in self.__class__.setup_uids.items()
                if uid == "uid-owner-a"
            )
            payload = {
                "localId": self.__class__.setup_uids[ref],
                "idToken": "setup-token-owner-a",
                "expiresIn": "3600",
            }
        elif path.startswith("/v1/accounts:"):
            payload = self.__class__.issuance_body or {}
        elif path.endswith(":getExecutable"):
            payload = {"rulesetName": self.__class__.active}
        elif path.endswith("/releases/cloud.firestore"):
            if self.command == "PATCH":
                self.__class__.active = body["release"]["rulesetName"]
            payload = {
                "name": "projects/fireemu-35fe6/releases/cloud.firestore",
                "rulesetName": self.__class__.active,
            }
        elif path == "/v1/projects/fireemu-35fe6/rulesets" and self.command == "POST":
            label = (
                "A"
                if body["source"]["files"][0]["content"]
                == self._plan["rulesets"]["A"]["source"]
                else "B"
            )
            payload = {
                "name": f"projects/fireemu-35fe6/rulesets/server-{label.lower()}"
            }
        elif "/rulesets/" in path:
            name = (
                "projects/fireemu-35fe6/"
                + path.split("/v1/projects/fireemu-35fe6/", 1)[1]
            )
            if name in self.__class__.deleted:
                status, payload = 404, {"error": {"code": 404}}
            elif self.command == "DELETE":
                self.__class__.deleted.add(name)
                payload = {}
            else:
                label = (
                    "A"
                    if name.endswith("server-a")
                    else "B"
                    if name.endswith("server-b")
                    else None
                )
                source = (
                    self._plan["rulesets"][label]["source"] if label else "pre-existing"
                )
                payload = {
                    "name": name,
                    "source": {
                        "files": [{"name": "firestore.rules", "content": source}]
                    },
                }
        elif "/documents:commit" in path:
            payload = {
                "status": "OK",
                "httpStatus": 200,
                "complete": True,
                "documentPresent": True,
                "fields": {},
            }
        elif "/documents/" in path:
            if self.command == "DELETE":
                self.__class__.recovered_documents.add(path.split("?", 1)[0])
                payload = {
                    "status": "OK",
                    "httpStatus": 200,
                    "complete": True,
                    "documentPresent": False,
                }
            elif "fixture-admin" in self.headers.get("Authorization", ""):
                present = (
                    path.split("?", 1)[0] not in self.__class__.recovered_documents
                )
                payload = {
                    "status": "OK",
                    "httpStatus": 200,
                    "complete": True,
                    "documentPresent": present,
                }
                if present:
                    payload["version"] = "fixture-version"
            else:
                payload = {
                    "status": "OK",
                    "httpStatus": 200,
                    "complete": True,
                    "documentPresent": True,
                    "fields": {},
                }
        elif "/accounts:" in path:
            local_id = body.get("localId") if isinstance(body, dict) else None
            if isinstance(local_id, list):
                local_id = local_id[0] if local_id else "fixture-uid"
            principal_delete = (
                path.endswith(":delete")
                and str(local_id).removeprefix("uid-") == "deleted-g"
                and str(local_id) not in self.__class__.deleted_accounts
            )
            if path.endswith(":update") or principal_delete:
                ref = str(local_id).removeprefix("uid-")
                action = (
                    "revoke"
                    if "validSince" in body
                    else "disable"
                    if body.get("disableUser")
                    else "delete"
                )
                if action == "delete":
                    self.__class__.deleted_accounts.add(str(local_id))
                payload = {
                    "status": "OK",
                    "httpStatus": 200,
                    "complete": True,
                    "action": action,
                    "authTime": 1,
                    "validSince": body.get("validSince"),
                    "present": action != "delete",
                    "disabled": None if action == "delete" else action == "disable",
                    "uidFingerprint": digest(
                        ["uid", self._plan["nonce"], "production", ref]
                    )[:16],
                }
                raw = json.dumps(payload, separators=(",", ":")).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)
                return
            if path.endswith(":delete"):
                self.__class__.deleted_accounts.add(str(local_id))
            absent = str(local_id) in self.__class__.deleted_accounts
            payload = {
                "status": "OK",
                "httpStatus": 200,
                "complete": True,
                "accountPresent": not absent,
                "uid": local_id if not absent else None,
            }
        else:
            payload = {"complete": True, "status": "OK"}
        raw = json.dumps(payload, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    do_GET = do_any
    do_POST = do_any
    do_PATCH = do_any
    do_DELETE = do_any


def test_launcher_requires_an_externally_materialized_approved_packet() -> None:
    with pytest.raises(ValueError, match="approved O5 packet"):
        production.run_approved({})


def test_setup_plan_is_source_backed_and_excludes_precreated_tenant_and_row_actions() -> (
    None
):
    plan = lane.plan_compiler("a" * 32)
    setup = setup_plan(plan)
    assert len(setup["fixtures"]) == 10
    assert len(setup["auth"]) == 9
    assert setup["totalRequests"] == 19
    assert all(item["service"] == "firestore" for item in setup["fixtures"])
    assert all(item["route"] == "document-create" for item in setup["fixtures"])
    assert all(item["method"] == "PATCH" for item in setup["fixtures"])
    assert all(
        item["path"].startswith("/v1/projects/fireemu-35fe6/")
        for item in setup["fixtures"]
    )
    assert all(item["precondition"] == {"exists": False} for item in setup["fixtures"])
    assert all(
        item["response"]["updateTime"] == "response-bound" for item in setup["fixtures"]
    )
    assert [item["id"] for item in setup["auth"]] == [
        "account/owner-a/signup",
        "account/other-b/signup",
        "account/anonymous-c/signup",
        "account/tenant-d/signup",
        "account/revoked-e/signup",
        "account/disabled-f/signup",
        "account/deleted-g/signup",
        "account/owner-a/claim-update",
        "account/owner-a/signin",
    ]
    assert not any(
        item["route"] in {"tenants:create", "tenants:delete"} for item in setup["auth"]
    )
    assert not any("post-signin" in item["id"] for item in setup["auth"])
    assert next(item for item in setup["auth"] if item["route"] == "accounts:update")[
        "response"
    ] == {"localId": "response-bound"}


@pytest.mark.parametrize(
    "field", ["approval", "manifest", "permission", "capabilityInputs"]
)
def test_launcher_refuses_missing_authority_material_before_any_wire(
    field: str,
) -> None:
    packet = {key: object() for key in production.REQUIRED_PACKET_KEYS}
    packet.pop(field)
    with pytest.raises(ValueError, match="approved O5 packet"):
        production.run_approved(packet)


def test_launcher_requires_canonical_ledger_and_gate_objects() -> None:
    packet = {key: object() for key in production.REQUIRED_PACKET_KEYS}
    packet["ledger"] = object()
    packet["gate"] = object()
    with pytest.raises(ValueError, match="approved O5 packet"):
        production.run_approved(packet)


def test_approved_packet_runs_real_loopback_producer_and_records_bounded_counts(
    tmp_path, monkeypatch
) -> None:
    _ProducerHandler._plan = None
    _ProducerHandler.setup_uids = {}
    _ProducerHandler.requests = []
    _ProducerHandler.fail_setup_after = None
    server = _producer_server()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    origin = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        record = lane.shadow_record()
        synthetic_sha = hashlib.sha256(b"synthetic artifact").hexdigest()
        record = json.loads(json.dumps(record))
        record["artifact"]["artifactSha256"] = synthetic_sha
        record["bundle"]["acquisition"]["artifact"]["artifactSha256"] = synthetic_sha
        monkeypatch.setattr(lane, "shadow_record", lambda: record)
        descriptor = lane.descriptor()
        bindings = synthetic(tmp_path, descriptor)
        plan = bindings["inputs"]["plan"]
        _ProducerHandler._plan = plan
        proofs = _fixture_proofs(plan, origin)
        accounts = account_bindings(plan)
        for ref, proof in proofs.items():
            accounts[ref]["uid"] = proof.uid
            accounts[ref]["authTime"] = proof.auth_time
        credentials = {ref: proof.token for ref, proof in proofs.items()}
        credentials["administrator"] = "fixture-admin"
        credentials["api-key"] = "fixture-key"
        credentials.update(
            {
                "expired-token": "expired-fixture-token",
                "revoked-expired-token": "expired-fixture-token",
                "malformed-bearer": "malformed-fixture-token",
                "empty-bearer": "",
            }
        )
        expires_at = bindings["approval"]["windowExpiresAt"]
        gate_plan = lane.gate_plan(plan, permission_expires_at=expires_at)
        gate_path = tmp_path / "gate"
        ledger = Ledger.create(tmp_path / "ledger")
        envelope = {
            "permissionDigest": digest(bindings["permission"]),
            "issuedAt": time.time() - 1,
            "expiresAt": expires_at,
            "limits": {
                "requests": 146,
                "accounts": 7,
                "resources": 21,
                "costMicrousd": 1_000_000,
            },
            "concurrency": 1,
            "scopes": lane.lock_scopes(plan),
        }
        claim = {
            "campaignId": plan["campaignId"],
            "manifestDigest": digest(plan),
            "nonceDigest": digest(plan["nonce"]),
            "gatePath": str(gate_path.resolve()),
            "gatePlanDigest": digest(gate_plan),
            "locks": lane.lock_scopes(plan),
            "budget": dict(envelope["limits"]),
            "durationSeconds": 600,
        }
        ticket = ledger.reserve(envelope, claim, gate_plan)
        shared_gate.create(gate_path, gate_plan)
        gate = shared_gate.Gate(gate_path, plan["campaignId"])
        binding, binding_digest = remote.worker_binding()
        packet = {
            "approval": bindings["approval"],
            "manifest": bindings["manifest"],
            "manifestBytes": bindings["manifest_bytes"],
            "manifestPath": bindings["manifest_path"],
            "permission": bindings["permission"],
            "artifactPath": bindings["artifact_path"],
            "launcherPath": bindings["launcher_path"],
            "ledgerRoot": bindings["ledger_root"],
            "plan": plan,
            "capabilityInputs": bindings["inputs"],
            "binding": binding,
            "bindingDigest": binding_digest,
            "credentials": credentials,
            "setupSecrets": {ref: "fixture-password" for ref in accounts},
            "frozenInputs": bindings["inputs"],
            "accountBindings": accounts,
            "identityProofs": proofs,
            "fixtureOrigin": origin,
            "gate": gate,
            "ledger": ledger,
            "ticket": ticket,
            "acquisition": acquisition_for(plan, ROLE_PRODUCTION),
            "runId": "approved-loopback-producer",
        }
        # This is a loopback execution, not a production-oracle claim. Keep
        # the launcher path and real worker intact while selecting the
        # collector's explicit local environment for every recorded receipt.
        packet["acquisition"]["environment"]["kind"] = (
            collector_module.ENVIRONMENT_LOCAL
        )
        monkeypatch.setitem(
            collector_module._ENVIRONMENT_FOR_ROLE,
            ROLE_PRODUCTION,
            collector_module.ENVIRONMENT_LOCAL,
        )
        bundle = production.run_approved(packet)
        assert bundle["recordingComplete"] is True, repr(
            {
                "abort": bundle["abort"],
                "failures": bundle["infrastructureFailures"],
                "budget": bundle["budget"],
                "rules": bundle["transport"].get("rulesManagement"),
                "managementUsed": len(gate.snapshot().get("managementUsed", [])),
                "cleanup": {
                    key: bundle["cleanup"].get(key)
                    for key in (
                        "cleanupComplete",
                        "outstandingResources",
                        "outstandingAccounts",
                    )
                },
                "documentFailures": [
                    (
                        step.get("kind"),
                        step.get("failure"),
                        (step.get("observed") or {}).get("documentPresent"),
                    )
                    for step in bundle["cleanup"].get("documentSteps", [])
                    if step.get("failure") is not None
                ][:5],
            }
        )
        assert bundle["abort"] is None
        assert len(bundle["rows"]) == 33
        assert len(proofs) == 7
        assert bundle["productionExecuted"] is False
        assert bundle["budget"]["observationSpent"] == 33
        # The compiler reserves three recovery slots per account. The deleted-g
        # principal action already proves absence, so cleanup correctly spends
        # one typed lookup slot instead of issuing a redundant delete pair.
        assert bundle["budget"]["recoverySpent"] == 61
        assert bundle["budget"]["principalActionSpent"] == 3
        assert len(gate.snapshot()["managementUsed"]) == 42
        assert bundle["setup"]["recordingComplete"] is True
        assert bundle["setup"]["requestCount"] == 19
        assert all(
            "idToken" not in receipt and "password" not in repr(receipt)
            for receipt in bundle["setup"]["receipts"]
        )
        assert bundle["transport"]["receipts"] == 97
        assert (
            bundle["budget"]["observationSpent"]
            + bundle["budget"]["recoverySpent"]
            + bundle["budget"]["principalActionSpent"]
            == 97
        )
        assert bundle["cleanup"]["cleanupComplete"] is True
        assert ledger.snapshot()["reservations"]
    finally:
        server.shutdown()
        server.server_close()


@pytest.mark.parametrize("failure_after", range(20))
def test_setup_failure_stops_gate_and_preserves_ledger_reservation(
    tmp_path, failure_after
) -> None:
    """A failed setup slot remains durably owned for recovery, never closes it."""
    plan = lane.plan_compiler("a" * 32)
    journal = collector_module.open_ownership_journal(
        tmp_path / "ownership.jsonl",
        run_id="partial-setup",
        plan_digest=plan["planDigest"],
    )
    ownership = {}
    private_handoffs = {}
    origin_server = _producer_server()
    thread = threading.Thread(target=origin_server.serve_forever, daemon=True)
    thread.start()
    origin = f"http://127.0.0.1:{origin_server.server_address[1]}"
    try:
        _ProducerHandler._plan = plan
        _ProducerHandler.requests = []
        _ProducerHandler.setup_uids = {}
        _ProducerHandler.fail_setup_after = failure_after
        bindings = synthetic(tmp_path, lane.descriptor())
        binding, binding_digest = remote.worker_binding()
        gate_path = tmp_path / "gate"
        expires_at = time.time() + 1200
        frozen_gate = lane.gate_plan(plan, permission_expires_at=expires_at)
        ledger = Ledger.create(tmp_path / "ledger")
        envelope = {
            "permissionDigest": digest(bindings["permission"]),
            "issuedAt": time.time() - 1,
            "expiresAt": expires_at,
            "limits": {
                "requests": 146,
                "accounts": 7,
                "resources": 21,
                "costMicrousd": 1_000_000,
            },
            "concurrency": 1,
            "scopes": lane.lock_scopes(plan),
        }
        claim = {
            "campaignId": plan["campaignId"],
            "manifestDigest": digest(plan),
            "nonceDigest": digest(plan["nonce"]),
            "gatePath": str(gate_path.resolve()),
            "gatePlanDigest": digest(frozen_gate),
            "locks": lane.lock_scopes(plan),
            "budget": dict(envelope["limits"]),
            "durationSeconds": 600,
        }
        ticket = ledger.reserve(envelope, claim, frozen_gate)
        shared_gate.create(gate_path, frozen_gate)
        gate = shared_gate.Gate(gate_path, plan["campaignId"])
        capability = _fixture_capability(
            plan, binding, binding_digest, bindings["inputs"]
        )
        with (
            pytest.raises(ValueError, match="setup")
            if failure_after < 19
            else nullcontext()
        ):
            receipts = bridge.run_bound_setup(
                plan=plan,
                gate=gate,
                credentials={
                    "administrator": "fixture-admin",
                    "api-key": "fixture-key",
                },
                setup_secrets={
                    row["ref"]: "fixture-password" for row in plan["ownedAccounts"]
                },
                account_bindings={},
                capability=capability,
                fixture_origin=origin,
                binding=binding,
                binding_digest=binding_digest,
                journal=journal,
                ownership=ownership,
                private_handoffs=private_handoffs,
            )
        snapshot = gate.snapshot()
        if failure_after == 19:
            assert len(receipts) == 19
            assert set(private_handoffs) == {
                account["ref"] for account in plan["ownedAccounts"]
            }
            assert "setup-token" not in json.dumps(receipts)
            assert "setup-token" not in repr(private_handoffs)
            assert all(state["phase"] == "acknowledged" for state in ownership.values())
            for account in plan["ownedAccounts"]:
                assert ownership[account["ref"]]["tenantId"] == account.get("tenant")
            assert len(snapshot["managementUsed"]) == 19
            session = bridge.management_session(
                plan=plan,
                gate=gate,
                ledger=ledger,
                ticket=ticket,
                execute=None,
                journal=journal,
                ownership=ownership,
            )
            assert session.lifecycle_slice["observationIds"] == list(
                bridge.RULES_MANAGEMENT_OBSERVATION
            )
            assert gate.snapshot() == snapshot
            return
        assert snapshot["stopped"] is True
        assert len(snapshot["managementUsed"]) == failure_after + 1
        assert snapshot["managementEvents"][-1]["status"] == 500
        assert snapshot["managementEvents"][-1]["workerReaped"] is True
        assert ledger.snapshot()["reservations"]
        operations = setup_plan(plan)["operations"]
        creates = [
            item["service"] == "firestore" or item["id"].endswith("/signup")
            for item in operations
        ]
        assert sum(
            state["phase"] == "acknowledged" for state in ownership.values()
        ) == sum(creates[:failure_after])
        assert sum(
            state["phase"] == "creation-unconfirmed" for state in ownership.values()
        ) == int(creates[failure_after])
        serialized = json.dumps(snapshot)
        assert "fixture-password" not in serialized
        assert "idToken" not in serialized
        gate.cancel_management_observation()
        assert gate.snapshot()["managementAbort"] is not None
        if failure_after == 0:
            before = gate.snapshot()
            bridge.skip_unused_recovery(gate)
            after = gate.snapshot()
            assert after["total"] == before["total"]
            assert after["costMicrousd"] == before["costMicrousd"]
            assert (
                len(
                    [
                        entry
                        for entry in after["managementSkipped"]
                        if entry["phase"] == "recovery"
                    ]
                )
                == 73
            )
            assert after["reservedRecovery"] == 0
            with pytest.raises(ValueError, match="ownership"):
                gate.finish()
            assert gate.snapshot() == after
    finally:
        journal.close()
        _ProducerHandler.fail_setup_after = None
        origin_server.shutdown()
        origin_server.server_close()
