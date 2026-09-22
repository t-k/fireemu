"""Bound collection: the collector records what the acquisition comparator
verifies, through an injected transport, with no socket and no credential."""

from __future__ import annotations

import copy
import atexit
import json
import tempfile
import time
import sys
from typing import Any
from pathlib import Path

import pytest
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "o8-core"))
sys.path.insert(0, str(ROOT / "production-admission"))
from o5_user_token_campaign import admitted_manifest_digest, source_digests
from o5_user_token_case import compile_case, digest
from o5_user_token_collector import (
    COLLECTOR_CONTRACT,
    ENVIRONMENT_LOCAL,
    ENVIRONMENT_PRODUCTION,
    READBACK_PUBLISH_ECHO,
    READBACK_RELEASE_GET,
    ROLE_LOCAL_SHADOW,
    ROLE_PRODUCTION,
    collect as _collect,
    RulesManagementReceipt,
    RulesManagementSession,
    RULES_MANAGEMENT_OBSERVATION,
    RULES_MANAGEMENT_RECOVERY,
    open_ownership_journal,
    start_context,
    _rules_management_proof,
    _management_cursor,
    recover_owned,
    _scan_management_receipt,
)
from o5_user_token_descriptor import gate_plan
from reservations import Ledger
import shared_gate
from test_o5_user_token_collector import Transport

PROJECT = "fireemu-35fe6"
NONCE = "a" * 32
LOCAL_TENANT = "fireemu-00000000000000000001"
PRODUCTION_ENDPOINT = "firestore.googleapis.com:443"
LOCAL_ENDPOINT = "127.0.0.1:52879"
_LIVE_FIXTURES: list[tempfile.TemporaryDirectory] = []


@atexit.register
def _close_live_fixtures() -> None:
    while _LIVE_FIXTURES:
        _LIVE_FIXTURES.pop().cleanup()


def plan_for(role: str) -> dict:
    tenant = LOCAL_TENANT if role == ROLE_LOCAL_SHADOW else "o5-user-token-tenant"
    return compile_case(PROJECT, "(default)", NONCE, tenant)


def principals_for(plan: dict, salt: str) -> dict:
    return {
        entry["ref"]: {
            "uidFingerprint": digest(["uid", plan["nonce"], salt, entry["ref"]])[:16],
            "provider": "anonymous" if entry["kind"] == "anonymous" else "email",
            "tenant": entry["tenant"],
            "claimsDigest": digest(entry["claims"]),
        }
        for entry in plan["ownedAccounts"]
    }


def acquisition_for(plan: dict, role: str) -> dict:
    """The launcher bindings a bound run of ``role`` carries."""
    manifest_digest = admitted_manifest_digest(PROJECT, "(default)", plan["nonce"])
    now = time.time()
    if role == ROLE_PRODUCTION:
        return {
            "environment": {"kind": ENVIRONMENT_PRODUCTION},
            "campaignManifestDigest": manifest_digest,
            "nonceReservation": {
                "reservationId": "reservation-1",
                "campaignId": plan["campaignId"],
                "nonceDigest": digest(plan["nonce"]),
            },
            "ownerPermission": {
                "kind": "owner-permission",
                "permissionDigest": "a" * 64,
            },
            "artifact": None,
            "principals": principals_for(plan, "production"),
            "window": {"startsAt": now - 60, "expiresAt": now + 3600},
        }
    return {
        "environment": {"kind": ENVIRONMENT_LOCAL},
        "campaignManifestDigest": manifest_digest,
        "nonceReservation": None,
        "ownerPermission": None,
        "artifact": {"artifactSha256": "b" * 64, "sourceCommit": "c" * 40},
        "principals": principals_for(plan, "local"),
        "window": None,
    }


def fingerprints_for(plan: dict, role: str) -> dict[str, str]:
    """The uid fingerprints a bound transport of ``role`` reports on readback."""
    salt = "production" if role == ROLE_PRODUCTION else "local"
    return {
        ref: entry["uidFingerprint"]
        for ref, entry in principals_for(plan, salt).items()
    }


def bound_transport(plan: dict, role: str, **kwargs) -> Transport:
    endpoint = PRODUCTION_ENDPOINT if role == ROLE_PRODUCTION else LOCAL_ENDPOINT
    return Transport(
        plan, endpoint=endpoint, fingerprints=fingerprints_for(plan, role), **kwargs
    )


def bound(
    role: str, transport: Transport | None = None, **kwargs
) -> tuple[dict, Transport]:
    plan = plan_for(role)
    transport = transport or bound_transport(plan, role)
    acquisition = acquisition_for(plan, role)
    if role != ROLE_PRODUCTION:
        bundle = collect(plan, transport, role=role, run_id=f"{role}-run", acquisition=acquisition, **kwargs)
        return bundle, transport
    # Canonical production fixture: run the real 19-slot setup bridge against
    # the loopback producer, then enter the Rules collector with its durable
    # setup proof and shared context.
    from test_o5_user_token_production import _ProducerHandler, _producer_server
    import o5_user_token_production_bridge as bridge
    import o5_user_token_descriptor as descriptor
    from test_o5_user_token_descriptor import synthetic
    from test_o5_user_token_remote_transport import account_bindings
    from test_o5_user_token_remote_transport import _fixture_capability as fixture_capability

    fixture = tempfile.TemporaryDirectory(prefix="o5-bound-rules-")
    _LIVE_FIXTURES.append(fixture)
    try:
        root = __import__("pathlib").Path(fixture.name)
        server = _producer_server()
        server_thread = __import__("threading").Thread(target=server.serve_forever, daemon=True)
        server_thread.start()
        origin = f"http://127.0.0.1:{server.server_address[1]}"
        gate_path = root / "gate"
        ledger = Ledger.create(root / "ledger")
        plan_gate = gate_plan(plan, permission_expires_at=time.time() + 3600)
        plan_gate["jobs"]["rules-management"]["resources"] = []
        required_requests = plan_gate["observationRequests"] + sum(
            len(job["recovery"]) for job in plan_gate["jobs"].values()
        ) + len(plan_gate["management"]["recovery"]) + plan_gate.get("coordinatorRequests", 0)
        limits = {
            "requests": required_requests,
            "accounts": 0,
            "resources": 1,
            "costMicrousd": plan_gate["costMicrousd"],
        }
        envelope = {"permissionDigest": digest({"kind": "bound-test"}), "issuedAt": time.time() - 1, "expiresAt": time.time() + 3600, "limits": limits, "concurrency": 1, "scopes": [{"key": f"project/{PROJECT}", "mode": "EXCLUSIVE"}]}
        claim = {"campaignId": plan["campaignId"], "manifestDigest": digest(plan), "nonceDigest": digest(plan["nonce"]), "gatePath": str(gate_path.resolve()), "gatePlanDigest": digest(plan_gate), "locks": [{"key": f"project/{PROJECT}", "mode": "EXCLUSIVE"}], "budget": limits, "durationSeconds": 600}
        ticket = ledger.reserve(envelope, claim, plan_gate)
        shared_gate.create(gate_path, plan_gate)
        gate = shared_gate.Gate(gate_path, plan["campaignId"])
        bindings = synthetic(root, descriptor.descriptor())
        binding, binding_digest = __import__("o5_user_token_remote_transport").worker_binding()
        capability = fixture_capability(
            plan,
            binding,
            binding_digest,
            bindings["inputs"],
            window_seconds=float(claim["durationSeconds"]),
        )
        _ProducerHandler._plan = plan
        _ProducerHandler.requests = []
        _ProducerHandler.setup_uids = {}
        _ProducerHandler.active = "projects/fireemu-35fe6/rulesets/pre-existing"
        _ProducerHandler.deleted = set()
        _ProducerHandler.recovered_documents = set()
        _ProducerHandler.deleted_accounts = set()
        _ProducerHandler.setup_account_order = []
        _ProducerHandler.documents = {}
        _ProducerHandler.account_state = {}
        _ProducerHandler.observation_index = 0
        _ProducerHandler.fail_setup_after = None
        _ProducerHandler.malformed_setup_failure = False
        journal = open_ownership_journal(root / "ownership.jsonl", run_id=f"{role}-run", plan_digest=plan["planDigest"])
        ownership: dict[str, dict[str, Any]] = {}
        handoffs: dict[str, Any] = {}
        try:
            bridge.run_bound_setup(
                plan=plan,
                gate=gate,
                credentials={"administrator": "fixture-admin", "api-key": "fixture-key"},
                setup_secrets={entry["ref"]: "fixture-password" for entry in plan["ownedAccounts"]},
                account_bindings=account_bindings(plan),
                capability=capability,
                fixture_origin=origin,
                binding=binding,
                binding_digest=binding_digest,
                journal=journal,
                ownership=ownership,
                identity_handoffs=handoffs,
            )
            identity_proofs = bridge.setup_identity_proofs(
                plan, gate, handoffs, fixture_origin=origin
            )
            acquisition["principals"] = {
                ref: {
                    "uidFingerprint": digest(["uid", plan["nonce"], proof.uid])[:16],
                    "provider": "anonymous" if proof.provider == "anonymous" else "email",
                    "tenant": proof.tenant,
                    "claimsDigest": proof.claims_digest,
                }
                for ref, proof in identity_proofs.items()
            }
            credentials = {
                "administrator": "fixture-admin",
                "api-key": "fixture-key",
                "expired-token": "expired-fixture-token",
                "revoked-expired-token": "expired-fixture-token",
                "malformed-bearer": "malformed-fixture-token",
                "empty-bearer": "",
                **{ref: proof.token for ref, proof in identity_proofs.items()},
            }
            account_map = account_bindings(plan)
            for ref, proof in identity_proofs.items():
                account_map[ref] = {
                    "uid": proof.uid,
                    "provider": proof.provider,
                    "tenant": proof.tenant,
                    "claimsDigest": proof.claims_digest,
                    "authTime": proof.auth_time,
                }
            real_execute = bridge.bound_execute(
                plan,
                credentials=credentials,
                frozen_inputs=bindings["inputs"],
                account_bindings=account_map,
                identity_proofs=identity_proofs,
                capability=capability,
                fixture_origin=origin,
            )

            def production_wire(receipt):
                """Keep loopback I/O while reporting the fixture's production lane.

                The producer is deliberately loopback-only, but this helper is
                the production acquisition fixture. Endpoint identity is a
                transport fact consumed by the comparator; the response body,
                status, sequence, and Gate proof remain those returned by the
                real bounded worker.
                """
                if not isinstance(receipt, dict):
                    return receipt
                normalized = dict(receipt)
                normalized["endpoint"] = PRODUCTION_ENDPOINT
                return normalized

            def execute_management(request, *, deadline=None):
                operation = {
                    key: value
                    for key, value in request.items()
                    if key not in {"managementSlot", "managementPhase"}
                }
                return bridge.rules_gate_receipt(
                    plan, request, production_wire(real_execute(operation, deadline=deadline))
                )

            def execute_production(request, *, deadline=None):
                return production_wire(real_execute(request, deadline=deadline))
            raw_dispatch = bridge.collection_dispatch(
                plan, gate, execute_production,
                credentials=credentials,
                account_bindings=account_map,
                identity_proofs=identity_proofs,
                ownership=ownership,
            )
            dispatch = raw_dispatch
            bridge.refresh_ownership(gate, ownership)
            session = bridge.management_session(
                plan=plan, gate=gate, ledger=ledger, ticket=ticket,
                execute=execute_management, journal=journal, ownership=ownership,
            )
            context = start_context(
                plan, environment=ENVIRONMENT_PRODUCTION, journal=journal,
                deadline_seconds=300.0, recovery_deadline_seconds=600.0,
            )
            bundle = collect(
                plan, dispatch, role=role, run_id=f"{role}-run",
                acquisition=acquisition, management_session=session,
                context=context, ownership=ownership, recovery_dispatch=dispatch, **kwargs,
            )
        finally:
            journal.close()
            server.shutdown()
            server.server_close()
        transport.production_cleanup_gate = gate
    except BaseException:
        fixture.cleanup()
        _LIVE_FIXTURES.remove(fixture)
        raise
    return bundle, transport


def _management_executor(plan: dict, transport):
    names = {"A": f"projects/{PROJECT}/rulesets/server-a", "B": f"projects/{PROJECT}/rulesets/server-b"}
    baseline = f"projects/{PROJECT}/rulesets/pre-existing"
    release = f"projects/{PROJECT}/releases/cloud.firestore"
    active = baseline
    deleted: set[str] = set()
    def execute(request, **_kwargs):
        nonlocal active
        action = request["action"]
        label = request.get("label") or ("A" if request.get("rulesetName") == names["A"] else "B")
        source_digest = digest(plan["rulesets"][label]["source"])
        scripted = transport({"phase": "ruleset", "managementPhase": request.get("managementPhase", "observation"), "action": action, "ruleset": label, "rulesetName": request.get("rulesetName"), "sourceDigest": source_digest})
        endpoint = scripted.get("endpoint")
        wire_sequence = scripted.get("wireSequence")
        scripted_name = scripted.get("releaseName")
        mutated_name = (
            scripted_name
            if isinstance(scripted_name, str)
            and not scripted_name.startswith(f"projects/{PROJECT}/releases/scripted-")
            else release
        )
        def typed(body, *, complete=True, status=200):
            proof = _rules_management_proof(
                request.get("managementSlot", ""), request, body, status
            )
            return RulesManagementReceipt(
                {
                    "status": status,
                    "complete": complete,
                    "workerReaped": True,
                    "bodyKind": "json",
                    "body": proof,
                },
                endpoint=endpoint,
                wire_sequence=wire_sequence,
                response_body=body,
            )
        if scripted.get("complete") is False:
            return typed({}, complete=False)
        if action == "release-get":
            body = {"name": mutated_name, "rulesetName": active}
        elif action == "release-get-executable":
            body = {"rulesetName": active}
        elif action == "create":
            body = {"name": names[request["label"]]}
        elif action == "get":
            name = request["rulesetName"]
            if name in deleted:
                return typed({"error": {"code": 404}}, status=404)
            label = "A" if name == names["A"] else "B"
            body = {"name": name, "source": {"files": [{"name": "firestore.rules", "content": plan["rulesets"][label]["source"]}]}}
        elif action == "release-patch":
            active = request["rulesetName"]
            body = {"name": mutated_name, "rulesetName": active}
        elif action == "delete":
            deleted.add(request["rulesetName"])
            body = {}
        else:
            raise AssertionError(action)
        return typed(body)
    return execute


def collect(plan, execute, *, role, run_id, acquisition=None, management_session=None, **kwargs):
    """Bind every production fixture call to the same real session helper."""
    if role != ROLE_PRODUCTION or acquisition is None or management_session is not None:
        return _collect(
            plan,
            execute,
            role=role,
            run_id=run_id,
            acquisition=acquisition,
            management_session=management_session,
            **kwargs,
        )
    with tempfile.TemporaryDirectory(prefix="o5-bound-rules-") as directory:
        root = Path(directory)
        gate_path = root / "gate"
        ledger = Ledger.create(root / "ledger")
        plan_gate = gate_plan(plan, permission_expires_at=time.time() + 3600)
        plan_gate["jobs"]["rules-management"]["resources"] = []
        required_requests = plan_gate["observationRequests"] + sum(
            len(job["recovery"]) for job in plan_gate["jobs"].values()
        ) + len(plan_gate["management"]["recovery"]) + plan_gate.get("coordinatorRequests", 0)
        limits = {
            "requests": required_requests,
            "accounts": 0,
            "resources": 1,
            "costMicrousd": plan_gate["costMicrousd"],
        }
        envelope = {"permissionDigest": digest({"kind": "bound-test"}), "issuedAt": time.time() - 1, "expiresAt": time.time() + 3600, "limits": limits, "concurrency": 1, "scopes": [{"key": f"project/{PROJECT}", "mode": "EXCLUSIVE"}]}
        claim = {"campaignId": plan["campaignId"], "manifestDigest": digest(plan), "nonceDigest": digest(plan["nonce"]), "gatePath": str(gate_path.resolve()), "gatePlanDigest": digest(plan_gate), "locks": [{"key": f"project/{PROJECT}", "mode": "EXCLUSIVE"}], "budget": limits, "durationSeconds": 600}
        ticket = ledger.reserve(envelope, claim, plan_gate)
        shared_gate.create(gate_path, plan_gate)
        gate = shared_gate.Gate(gate_path, plan["campaignId"])
        management_plan = gate.snapshot()["plan"]["management"]
        setup_prefix = {
            "observationIds": [
                entry["id"] for entry in management_plan["observation"]
                if entry["id"] not in RULES_MANAGEMENT_OBSERVATION
            ],
            "recoveryIds": [
                entry["id"] for entry in management_plan["recovery"]
                if entry["id"] not in RULES_MANAGEMENT_RECOVERY
            ],
            "planDigest": plan["planDigest"],
            "journalDigest": digest({"fixture": "scripted-prefix"}),
            "proofDigest": digest({"fixture": "scripted-prefix-proof"}),
        }
        management = _management_executor(plan, execute)
        def routed(request, **_kwargs):
            if request.get("kind") == "rules-lifecycle":
                return management(request)
            return execute(request)
        session = RulesManagementSession(
            gate=gate,
            ledger=ledger,
            ticket=ticket,
            execute=routed,
            plan=plan,
            lifecycle_slice={
                "observationIds": list(RULES_MANAGEMENT_OBSERVATION),
                "recoveryIds": list(RULES_MANAGEMENT_RECOVERY),
            },
            setup_prefix=setup_prefix,
        )
        return _collect(plan, routed, role=role, run_id=run_id, acquisition=acquisition, management_session=session, **kwargs)


def test_a_bound_run_records_releases_wire_facts_and_observer_identity() -> None:
    bundle, transport = bound(ROLE_PRODUCTION)
    assert bundle["contract"] == COLLECTOR_CONTRACT
    assert bundle["recordingComplete"] is True
    assert bundle["abort"] is None
    releases = bundle["transport"]["rulesetReleases"]
    assert [release["label"] for release in releases] == ["A", "B"]
    assert [release["beforeIndex"] for release in releases] == [0, 30]
    actions = bundle["transport"]["principalActions"]
    assert [(a["ref"], a["action"], a["beforeIndex"]) for a in actions] == [
        ("revoked-e", "revoke", 24),
        ("disabled-f", "disable", 26),
        ("deleted-g", "delete", 28),
    ]
    for action in actions:
        assert bundle["rows"][action["beforeIndex"] - 1]["at"] <= action["at"]
        assert action["at"] <= bundle["rows"][action["beforeIndex"]]["at"]
        assert action["endpoint"] == PRODUCTION_ENDPOINT
    assert bundle["budget"]["principalActionCeiling"] == 3
    assert bundle["budget"]["principalActionSpent"] == 3
    for release in releases:
        assert release["readback"]["kind"] == READBACK_RELEASE_GET
        assert release["readback"]["digest"] == release["sourceDigest"]
        assert release["endpoint"] == PRODUCTION_ENDPOINT
        first_dependent = bundle["rows"][release["beforeIndex"]]
        assert release["activeFrom"] <= first_dependent["at"]
    assert bundle["budget"]["rulesetCeiling"] == 2
    assert bundle["budget"]["rulesetSpent"] == 2
    assert bundle["transport"]["endpoints"] == [PRODUCTION_ENDPOINT]
    assert bundle["transport"]["sequenceMonotonic"] is True
    assert bundle["transport"]["receipts"] == len(transport.requests)
    assert bundle["transport"]["firstSequence"] == 1
    assert bundle["transport"]["lastSequence"] == len(transport.requests)
    stamps = [row["at"] for row in bundle["rows"]]
    assert stamps == sorted(stamps)
    sequences = [row["wireSequence"] for row in bundle["rows"]]
    assert sequences == sorted(sequences)
    assert all(row["endpoint"] == PRODUCTION_ENDPOINT for row in bundle["rows"])
    for step in bundle["cleanup"]["documentSteps"] + bundle["cleanup"]["accountSteps"]:
        assert step["endpoint"] == PRODUCTION_ENDPOINT
        assert isinstance(step["wireSequence"], int)
    assert bundle["observer"]["sourceDigests"] == source_digests()
    assert bundle["observer"]["observerDigest"] == digest(source_digests())
    clock = bundle["transport"]["clock"]
    assert clock["started"] <= clock["observationFinished"] <= clock["finished"]
    wall = bundle["transport"]["wallClock"]
    assert wall["startedAt"] <= wall["finishedAt"]
    assert bundle["provenance"]["case"]["tenant"] == "o5-user-token-tenant"


def test_partial_create_readback_keeps_unverified_ownership_held(tmp_path) -> None:
    plan = plan_for(ROLE_PRODUCTION)
    base = bound_transport(plan, ROLE_PRODUCTION)

    def lost_create_readback(request: dict) -> dict:
        receipt = base(request)
        if request.get("managementPhase") == "observation" and request.get("action") == "get" and request.get("ruleset") == "A":
            receipt["complete"] = False
        return receipt

    journal_path = tmp_path / "rules-management.jsonl"
    bundle = bound(
        ROLE_PRODUCTION,
        transport=lost_create_readback,
        journal_path=journal_path,
    )[0]
    management = bundle["transport"]["rulesManagement"]
    assert bundle["recordingComplete"] is False
    assert management["owned"]["A"]["phase"] == "created-unverified"
    assert management["recovery"]["held"] == [management["owned"]["A"]["name"]]
    assert not any(request.get("phase") == "ruleset" and request.get("action") == "delete" for request in base.requests)
    ownership = [
        json.loads(line)
        for line in journal_path.read_text().splitlines()
        if json.loads(line)["kind"] == "rules-management-ownership"
    ]
    kinds = [json.loads(line)["kind"] for line in journal_path.read_text().splitlines()]
    assert "rules-management-intent" in kinds
    assert "rules-management-baseline" in kinds
    assert ownership[-1]["phase"] == "created-unverified"


def test_lost_patch_restores_only_after_current_release_proves_owned_target() -> None:
    plan = plan_for(ROLE_PRODUCTION)
    base = bound_transport(plan, ROLE_PRODUCTION)

    def lost_patch(request: dict) -> dict:
        receipt = base(request)
        if request.get("managementPhase") == "observation" and request.get("action") == "release-patch" and request.get("ruleset") == "A":
            receipt["complete"] = False
        return receipt

    bundle = bound(ROLE_PRODUCTION, transport=lost_patch)[0]
    management = bundle["transport"]["rulesManagement"]
    assert bundle["recordingComplete"] is False
    assert management["owned"]["A"]["phase"] == "patch-uncertain"
    assert management["recovery"]["restored"] is True
    assert management["recovery"]["held"] == []


def test_foreign_current_release_refuses_partial_restore_and_retains_owned_names() -> None:
    plan = plan_for(ROLE_PRODUCTION)
    base = bound_transport(plan, ROLE_PRODUCTION)

    def foreign_after_patch(request: dict) -> dict:
        receipt = base(request)
        if request.get("managementPhase") == "recovery" and request.get("action") == "release-get":
            receipt["body"]["rulesetName"] = f"projects/{PROJECT}/rulesets/foreign"
        return receipt

    bundle = bound(ROLE_PRODUCTION, transport=foreign_after_patch)[0]
    management = bundle["transport"]["rulesManagement"]
    assert bundle["recordingComplete"] is False
    assert bundle["abort"] == "rules-management-recovery"
    assert management["recovery"]["held"]
    assert not any(request.get("phase") == "ruleset" and request.get("action") == "delete" for request in base.requests)


def test_management_worker_exception_at_first_slot_keeps_uncertain_gate_state() -> None:
    plan = plan_for(ROLE_PRODUCTION)
    base = bound_transport(plan, ROLE_PRODUCTION)

    def raises(request: dict) -> dict:
        if request.get("phase") == "ruleset" and request.get("managementPhase") == "observation":
            raise RuntimeError("worker lost")
        return base(request)

    bundle = bound(ROLE_PRODUCTION, transport=raises)[0]
    management = bundle["transport"]["rulesManagement"]
    assert bundle["recordingComplete"] is False
    assert bundle["abort"] == "collector:RuntimeError"
    assert management["recovery"]["cleanupComplete"] is False
    assert management["recovery"]["held"] == []
    assert not any(request.get("managementPhase") == "recovery" for request in base.requests)


def test_management_worker_exception_after_create_retains_issued_name_without_delete() -> None:
    plan = plan_for(ROLE_PRODUCTION)
    base = bound_transport(plan, ROLE_PRODUCTION)

    def raises_after_create(request: dict) -> dict:
        if request.get("phase") == "ruleset" and request.get("managementPhase") == "observation" and request.get("action") == "get" and request.get("ruleset") == "A":
            raise RuntimeError("readback lost")
        return base(request)

    bundle = bound(ROLE_PRODUCTION, transport=raises_after_create)[0]
    management = bundle["transport"]["rulesManagement"]
    assert management["owned"]["A"]["phase"] == "created-unverified"
    assert management["recovery"]["held"] == [management["owned"]["A"]["name"]]
    assert not any(request.get("phase") == "ruleset" and request.get("action") == "delete" for request in base.requests)


def test_baseline_recovery_uses_patch_slot_then_release_readback() -> None:
    bundle, transport = bound(ROLE_PRODUCTION)
    management = bundle["transport"]["rulesManagement"]
    recovery = [
        request
        for request in transport.requests
        if request.get("phase") == "ruleset" and request.get("managementPhase") == "recovery"
    ]
    assert [request["action"] for request in recovery[:4]] == [
        "release-get",
        "release-patch",
        "release-get",
        "release-get-executable",
    ]
    assert recovery[1]["rulesetName"] == management["baseline"]["rulesetName"]


def test_session_accepts_only_a_compiler_bound_setup_observation_and_recovery_prefix(tmp_path) -> None:
    plan = plan_for(ROLE_PRODUCTION)
    compiled = gate_plan(plan)
    observation_prefix = ["setup/fixture/setup-doc"]
    recovery_prefix = ["setup-recovery/fixture/setup-doc/read"]
    compiled["management"]["observation"] = [
        {"id": observation_prefix[0], "timeout": 8.0},
        *compiled["management"]["observation"],
    ]
    compiled["management"]["recovery"] = [
        {"id": recovery_prefix[0], "timeout": 8.0},
        *compiled["management"]["recovery"],
    ]
    gate_path = tmp_path / "gate"
    ledger_path = tmp_path / "ledger"
    claim = {
        "campaignId": plan["campaignId"],
        "manifestDigest": digest(plan),
        "nonceDigest": digest(plan["nonce"]),
        "gatePath": str(gate_path.resolve()),
        "gatePlanDigest": digest(compiled),
    }
    gate = type("Gate", (), {"path": gate_path, "snapshot": lambda self: {"plan": compiled}})()
    ledger = type(
        "Ledger",
        (),
        {
            "path": ledger_path,
            "snapshot": lambda self: {"reservations": {"reservation-1": {"claim": claim}}},
        },
    )()
    ticket = {"reservation": "reservation-1", "ledgerPath": str(ledger_path)}
    proof = {
        "observationIds": observation_prefix,
        "recoveryIds": recovery_prefix,
        "planDigest": plan["planDigest"],
        "journalDigest": "journal-proof",
        "proofDigest": "ownership-proof",
    }
    session = RulesManagementSession(
        gate=gate,
        ledger=ledger,
        ticket=ticket,
        execute=lambda *_args, **_kwargs: {},
        plan=plan,
        setup_prefix=proof,
        lifecycle_slice={
            "observationIds": list(RULES_MANAGEMENT_OBSERVATION),
            "recoveryIds": list(RULES_MANAGEMENT_RECOVERY),
        },
    )
    assert session.setup_observation_prefix == observation_prefix
    assert session.setup_recovery_prefix == recovery_prefix
    with pytest.raises(ValueError, match="compiled setup prefix proof"):
        RulesManagementSession(
            gate=gate,
            ledger=ledger,
            ticket=ticket,
            execute=lambda *_args, **_kwargs: {},
            plan=plan,
        )


def test_management_scan_allows_only_validated_endpoint_domains() -> None:
    assert _scan_management_receipt({"endpoint": PRODUCTION_ENDPOINT}) is None
    assert _scan_management_receipt({"endpoint": LOCAL_ENDPOINT}) is None
    assert _scan_management_receipt({"note": "firestore.googleapis.com"}) == "credential-leak:token-shaped-value"


def test_rules_management_proof_persists_only_typed_projection() -> None:
    raw = {
        "name": "projects/fireemu-35fe6/rulesets/server-a",
        "source": {"files": [{"name": "firestore.rules", "content": "allow read;"}]},
        "privateToken": "must-not-cross-gate",
    }
    proof = _rules_management_proof(
        "create-a-get",
        {"action": "get", "rulesetName": raw["name"]},
        raw,
        200,
    )
    receipt = RulesManagementReceipt(
        {"status": 200, "complete": True, "workerReaped": True, "body": proof},
        response_body=raw,
    )
    assert receipt["body"]["kind"] == "rules-management-proof-v1"
    assert "privateToken" not in json.dumps(receipt["body"])
    assert receipt.response_body == raw


def test_start_context_is_reused_without_budget_reset(tmp_path) -> None:
    plan = plan_for(ROLE_LOCAL_SHADOW)
    journal = open_ownership_journal(
        tmp_path / "run.jsonl", run_id="context-run", plan_digest=plan["planDigest"]
    )
    context = start_context(plan, environment=ENVIRONMENT_LOCAL, journal=journal)
    assert context.journal is journal
    assert context.attempted == []
    budget = context.budget
    context.attempted.append(plan["ownedResources"][0])
    assert context.budget is budget
    journal.close()


def test_management_cursor_keeps_gate_skips_separate_from_receipts() -> None:
    gate = type(
        "Gate",
        (),
        {
            "snapshot": lambda self: {
                "managementUsed": ["observation:setup/one", "recovery:cleanup/document/x/read"],
                "managementSkipped": [
                    {"id": "recovery:cleanup/document/x/delete", "disposition": "held"}
                ],
            }
        },
    )()
    cursor = _management_cursor(gate)
    assert cursor == {
        "used": ["observation:setup/one", "recovery:cleanup/document/x/read"],
        "skipped": ["recovery:cleanup/document/x/delete"],
        "ordered": [],
    }


def test_recover_owned_does_not_dispatch_unacknowledged_subjects(tmp_path) -> None:
    plan = plan_for(ROLE_LOCAL_SHADOW)
    calls: list[dict] = []

    def execute(request: dict) -> dict:
        calls.append(request)
        receipt = {
            "complete": True,
            "status": "OK",
            "documentPresent": False,
            "endpoint": LOCAL_ENDPOINT,
            "wireSequence": len(calls),
        }
        if request.get("account") is not None:
            receipt.pop("documentPresent")
            receipt["accountPresent"] = False
        return receipt

    from o5_user_token_collector import _Budget, _Journal, _Wire

    budget = _Budget(
        requests=1,
        recovery=3 * (len(plan["ownedResources"]) + len(plan["ownedAccounts"])),
        rulesets=0,
        actions=0,
        deadline_seconds=600,
        recovery_deadline_seconds=900,
        clock=time.monotonic,
    )
    journal = _Journal(tmp_path / "owned.jsonl")
    try:
        result = recover_owned(
            plan,
            execute,
            budget,
            _Wire(ENVIRONMENT_LOCAL),
            [],
            journal,
            ownership={plan["ownedResources"][0]: {"phase": "acknowledged"}},
        )
    finally:
        journal.close()
    assert calls
    assert all(request.get("resource") == plan["ownedResources"][0] for request in calls)
    assert result["held"]
    assert result["notAttempted"] == []


def test_a_bound_run_is_admitted_by_the_acquisition_comparator() -> None:
    from o5_user_token_comparator_v2 import MATCH, compare

    production, _ = bound(ROLE_PRODUCTION)
    local, _ = bound(ROLE_LOCAL_SHADOW)
    result = compare(production, local, plan_for(ROLE_PRODUCTION))
    assert result["errors"] == []
    assert result["classification"] == MATCH
    assert len(result["rows"]) == 33
    assert result["hypotheses"] == {
        "credential-revocation": {"rows": 7, "asHypothesized": 4, "contrary": 3}
    }


def test_the_ruleset_release_is_requested_and_journaled_before_the_first_row(
    tmp_path,
) -> None:
    path = tmp_path / "journal.jsonl"
    bundle, transport = bound(ROLE_LOCAL_SHADOW, journal_path=path)
    kinds = [request.get("phase") for request in transport.requests]
    assert kinds[0] == "ruleset"
    assert kinds[34] == "ruleset"
    assert [k for k in kinds if k == "principal"] == ["principal"] * 3
    assert kinds[25] == "principal"
    assert transport.requests[0]["ruleset"] == "A"
    assert transport.requests[34]["ruleset"] == "B"
    assert transport.requests[0]["sourceDigest"] == digest(
        plan_for(ROLE_LOCAL_SHADOW)["rulesets"]["A"]["source"]
    )
    entries = [json.loads(line) for line in path.read_text().splitlines()]
    journaled = [entry["kind"] for entry in entries]
    assert journaled[:3] == ["run", "acquisition", "accounts"]
    assert journaled.index("ruleset-request") < journaled.index("request")
    assert journaled.index("ruleset-release") < journaled.index("request")
    assert "principal-action-request" in journaled
    assert journaled.index("principal-action-request") < journaled.index(
        "principal-action"
    )
    acquisition = next(entry for entry in entries if entry["kind"] == "acquisition")
    assert acquisition["environment"] == ENVIRONMENT_LOCAL
    assert acquisition["observerDigest"] == bundle["observer"]["observerDigest"]
    assert bundle["transport"]["rulesetReleases"][0]["readback"]["kind"] == (
        READBACK_PUBLISH_ECHO
    )


def test_an_unbound_run_issues_no_release_and_records_no_acquisition() -> None:
    plan = plan_for(ROLE_PRODUCTION)
    transport = Transport(plan)
    bundle = collect(plan, transport, role=ROLE_PRODUCTION, run_id="unbound")
    assert all(request.get("phase") != "ruleset" for request in transport.requests)
    assert bundle["acquisition"] is None
    assert bundle["transport"]["rulesetReleases"] == []
    assert bundle["transport"]["principalActions"] == []
    assert all(request.get("phase") != "principal" for request in transport.requests)
    assert bundle["transport"]["endpoints"] == []
    assert bundle["budget"]["rulesetCeiling"] == 0
    assert bundle["rows"][0]["endpoint"] is None
    assert bundle["productionExecuted"] is False
    assert bundle["recordingComplete"] is True


def test_production_executed_is_derived_from_the_endpoints_reached() -> None:
    production, _ = bound(ROLE_PRODUCTION)
    assert production["productionExecuted"] is True
    assert production["productionReady"] is False
    local, _ = bound(ROLE_LOCAL_SHADOW)
    assert local["productionExecuted"] is False


def test_a_receipt_without_wire_facts_aborts_a_bound_run() -> None:
    plan = plan_for(ROLE_PRODUCTION)
    transport = bound_transport(plan, ROLE_PRODUCTION)

    def forgetful(request: dict) -> dict:
        receipt = transport(request)
        if request.get("phase") != "recovery" and request.get("index") == 2:
            del receipt["endpoint"]
            del receipt["wireSequence"]
        return receipt

    bundle = collect(
        plan,
        forgetful,
        role=ROLE_PRODUCTION,
        run_id="forgetful",
        acquisition=acquisition_for(plan, ROLE_PRODUCTION),
    )
    assert bundle["abort"] == "unbound-receipt"
    assert len(bundle["rows"]) == 3
    assert bundle["rows"][2]["observed"] is None
    assert bundle["recordingComplete"] is False
    assert bundle["cleanup"]["cleanupComplete"] is True


@pytest.mark.parametrize(
    "role,endpoint,failure",
    [
        (ROLE_PRODUCTION, "example.com:443", "endpoint-not-allowlisted"),
        (ROLE_PRODUCTION, LOCAL_ENDPOINT, "endpoint-outside-environment"),
        (ROLE_LOCAL_SHADOW, PRODUCTION_ENDPOINT, "endpoint-outside-environment"),
        (ROLE_LOCAL_SHADOW, "http://127.0.0.1:1", "invalid-endpoint"),
    ],
)
def test_an_endpoint_outside_the_environment_is_recorded_and_refused(
    role, endpoint, failure
) -> None:
    plan = plan_for(role)
    transport = Transport(
        plan,
        endpoint=endpoint,
        readback_kind=READBACK_RELEASE_GET,
        fingerprints=fingerprints_for(plan, role),
    )
    bundle = collect(
        plan,
        transport,
        role=role,
        run_id="foreign",
        acquisition=acquisition_for(plan, role),
    )
    # The first receipt is the Ruleset release, so the run stops there.
    assert bundle["abort"] == failure
    assert bundle["rows"] == []
    assert bundle["transport"]["rulesetReleases"] == []
    assert bundle["infrastructureFailures"] == [f"ruleset:A:{failure}"]
    assert bundle["productionExecuted"] is False
    assert bundle["recordingComplete"] is False
    # Recovery still runs; its receipts are refused for the same reason and
    # nothing is deleted on the strength of a foreign endpoint.
    assert bundle["cleanup"]["cleanupComplete"] is False
    assert not any(request.get("kind") == "delete" for request in transport.requests)


def test_a_wire_sequence_that_regresses_aborts_a_bound_run() -> None:
    plan = plan_for(ROLE_LOCAL_SHADOW)
    transport = bound_transport(plan, ROLE_LOCAL_SHADOW)

    def replaying(request: dict) -> dict:
        receipt = transport(request)
        if request.get("phase") != "recovery" and request.get("index") == 4:
            receipt["wireSequence"] = 1
        return receipt

    bundle = collect(
        plan,
        replaying,
        role=ROLE_LOCAL_SHADOW,
        run_id="replay",
        acquisition=acquisition_for(plan, ROLE_LOCAL_SHADOW),
    )
    assert bundle["abort"] == "wire-sequence-regressed"
    assert bundle["transport"]["sequenceMonotonic"] is False
    assert bundle["recordingComplete"] is False


@pytest.mark.parametrize(
    "mutation,failure",
    [
        ({"readbackDigest": "0" * 64}, "ruleset-readback-mismatch"),
        ({"readbackKind": "guessed"}, "ruleset-readback-unknown"),
        ({"releaseName": ""}, "ruleset-release-unnamed"),
        (
            {"complete": False, "failure": "publish-refused"},
            "incomplete-ruleset-receipt",
        ),
        ({"rules": "content"}, "unknown-receipt-key:rules"),
    ],
)
def test_a_release_whose_readback_is_not_the_plan_source_stops_the_run(
    mutation, failure
) -> None:
    plan = plan_for(ROLE_LOCAL_SHADOW)
    transport = bound_transport(plan, ROLE_LOCAL_SHADOW)

    def drifting(request: dict) -> dict:
        receipt = transport(request)
        if request.get("phase") == "ruleset" and request["ruleset"] == "B":
            receipt.update(mutation)
        return receipt

    bundle = collect(
        plan,
        drifting,
        role=ROLE_LOCAL_SHADOW,
        run_id="drift",
        acquisition=acquisition_for(plan, ROLE_LOCAL_SHADOW),
    )
    assert bundle["abort"] == failure
    assert len(bundle["rows"]) == 30
    assert [r["label"] for r in bundle["transport"]["rulesetReleases"]] == ["A"]
    assert bundle["infrastructureFailures"] == [f"ruleset:B:{failure}"]
    assert bundle["cleanup"]["cleanupComplete"] is True


def test_a_release_step_counts_against_its_own_ceiling_only() -> None:
    bundle, _ = bound(ROLE_LOCAL_SHADOW)
    assert bundle["budget"]["observationSpent"] == 33
    assert bundle["budget"]["rulesetSpent"] == 2
    assert bundle["budget"]["principalActionSpent"] == 3
    assert bundle["budget"]["recoverySpent"] == len(
        bundle["cleanup"]["documentSteps"] + bundle["cleanup"]["accountSteps"]
    )


@pytest.mark.parametrize(
    "flag,marker",
    [
        ("leak", "credential-leak:idToken"),
        ("nested_leak", "credential-leak:refreshToken"),
        ("token_value", "credential-leak:token-shaped-value"),
    ],
)
def test_structural_redaction_still_aborts_a_bound_run(flag, marker) -> None:
    plan = plan_for(ROLE_PRODUCTION)
    transport = bound_transport(plan, ROLE_PRODUCTION, **{flag: True})
    bundle = collect(
        plan,
        transport,
        role=ROLE_PRODUCTION,
        run_id="leaky",
        acquisition=acquisition_for(plan, ROLE_PRODUCTION),
    )
    assert bundle["abort"] == marker
    assert len(bundle["rows"]) == 1
    assert bundle["rows"][0]["observed"] is None
    assert bundle["recordingComplete"] is False
    assert "secret" not in repr(bundle)


@pytest.mark.parametrize(
    "value", ["ya29.a0AfH6SMBexample", "AIzaSyDexampleexample", "1//0gexample-refresh"]
)
def test_a_google_credential_prefix_in_any_receipt_aborts_the_run(value) -> None:
    plan = plan_for(ROLE_PRODUCTION)
    transport = bound_transport(plan, ROLE_PRODUCTION)

    def leaking(request: dict) -> dict:
        receipt = transport(request)
        if request.get("phase") == "ruleset":
            receipt["releaseName"] = value
        return receipt

    bundle = collect(
        plan,
        leaking,
        role=ROLE_PRODUCTION,
        run_id="leaky-prefix",
        acquisition=acquisition_for(plan, ROLE_PRODUCTION),
    )
    assert bundle["abort"] == "credential-leak:token-shaped-value"
    assert bundle["rows"] == []
    assert value[4:] not in repr(bundle)


def test_the_collector_replaces_every_uid_its_readbacks_returned() -> None:
    """Redaction is the collector's, not the publishing runner's: a bundle
    carries principal labels wherever a readback uid appeared, in rows and
    in recovery steps, in bound and unbound runs alike."""
    plan = plan_for(ROLE_LOCAL_SHADOW)
    uids = {
        entry["ref"]: f"L7fNfbBctFzloK39kcvtQpS{i:05d}"
        for i, entry in enumerate(plan["ownedAccounts"])
    }
    transport = bound_transport(plan, ROLE_LOCAL_SHADOW)

    def with_uids(request: dict) -> dict:
        receipt = transport(request)
        if request.get("kind") == "account-readback" and receipt.get("uid"):
            receipt["uid"] = uids[request["accountRef"]]
        if request.get("phase") != "recovery" and request.get("index") == 0:
            receipt["fields"] = {"ownerUid": uids["owner-a"], "document": "owned-a"}
        return receipt

    for acquisition in (acquisition_for(plan, ROLE_LOCAL_SHADOW), None):
        bundle = collect(
            plan,
            with_uids,
            role=ROLE_LOCAL_SHADOW,
            run_id="redact",
            acquisition=acquisition,
        )
        assert (
            bundle["rows"][0]["observed"]["fields"]["ownerUid"] == "principal:owner-a"
        )
        readbacks = [
            step
            for step in bundle["cleanup"]["accountSteps"]
            if step["kind"] == "account-readback"
        ]
        assert {
            step["observed"]["uid"]
            for step in readbacks
            if step["observed"]["accountPresent"]
        } == {
            f"principal:{step['accountRef']}"
            for step in readbacks
            if step["observed"]["accountPresent"]
        }
        # A bound run deletes deleted-g between rows, so its recovery
        # readback returns no uid to redact; an unbound run performs no
        # action and reads every account back.
        expected = {f"principal:{ref}" for ref in uids}
        if acquisition is not None:
            expected.discard("principal:deleted-g")
        assert bundle["redactedPrincipals"] == sorted(expected)
        assert not any(uid in repr(bundle) for uid in uids.values())
        # The delete precondition still carried the real identifier to the transport.
        deletes = [r for r in transport.requests if r.get("kind") == "account-delete"]
        assert all(r["precondition"]["uid"] in uids.values() for r in deletes)
        transport.requests.clear()
        transport.present = {resource: True for resource in plan["ownedResources"]}
        transport.accounts = {entry["ref"]: True for entry in plan["ownedAccounts"]}


def test_a_token_shaped_value_in_a_release_receipt_aborts_before_any_row() -> None:
    plan = plan_for(ROLE_PRODUCTION)
    transport = bound_transport(plan, ROLE_PRODUCTION)

    def leaking(request: dict) -> dict:
        receipt = transport(request)
        if request.get("phase") == "ruleset":
            receipt["releaseName"] = "aaaaaa.bbbbbb.cccccc"
        return receipt

    bundle = collect(
        plan,
        leaking,
        role=ROLE_PRODUCTION,
        run_id="leaky-release",
        acquisition=acquisition_for(plan, ROLE_PRODUCTION),
    )
    assert bundle["abort"] == "credential-leak:token-shaped-value"
    assert bundle["rows"] == []
    assert "bbbbbb" not in repr(bundle)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda a: a.__setitem__("environment", {"kind": ENVIRONMENT_LOCAL}),
        lambda a: a.__setitem__("campaignManifestDigest", "short"),
        lambda a: a["nonceReservation"].__setitem__("nonceDigest", digest("b" * 32)),
        lambda a: a["nonceReservation"].__setitem__("campaignId", "OTHER"),
        lambda a: a.__setitem__(
            "ownerPermission", {"kind": "x", "permissionDigest": "y"}
        ),
        lambda a: (
            a.__setitem__(
                "artifact", {"artifactSha256": "b" * 64, "sourceCommit": "c" * 40}
            )
            or a.__setitem__("principals", {"stranger": a["principals"]["owner-a"]})
        ),
        lambda a: a.__setitem__("window", {"startsAt": 5.0, "expiresAt": 1.0}),
        lambda a: a.__setitem__("idToken", "value"),
        lambda a: a.__setitem__("extra", None),
        lambda a: a["principals"]["owner-a"].__setitem__(
            "uidFingerprint", "aaaaaa.bbbbbb.cccccc"
        ),
    ],
)
def test_malformed_or_contradicting_bindings_are_refused_before_any_request(
    mutate,
) -> None:
    plan = plan_for(ROLE_PRODUCTION)
    acquisition = acquisition_for(plan, ROLE_PRODUCTION)
    mutate(acquisition)
    transport = bound_transport(plan, ROLE_PRODUCTION)
    with pytest.raises((TypeError, ValueError)):
        collect(
            plan,
            transport,
            role=ROLE_PRODUCTION,
            run_id="refused",
            acquisition=acquisition,
        )
    assert transport.requests == []


def test_the_recorded_bindings_are_a_copy_not_the_launcher_object() -> None:
    plan = plan_for(ROLE_LOCAL_SHADOW)
    acquisition = acquisition_for(plan, ROLE_LOCAL_SHADOW)
    original = copy.deepcopy(acquisition)
    bundle = collect(
        plan,
        bound_transport(plan, ROLE_LOCAL_SHADOW),
        role=ROLE_LOCAL_SHADOW,
        run_id="copy",
        acquisition=acquisition,
    )
    assert acquisition == original
    recorded = bundle["acquisition"]
    assert recorded["environment"] == original["environment"]
    assert recorded["artifact"] == original["artifact"]
    assert recorded["observerDigest"] == bundle["observer"]["observerDigest"]
    assert recorded["endpoint"] == [LOCAL_ENDPOINT]
    assert recorded["wireCounts"]["receipts"] == bundle["transport"]["receipts"]
    recorded["principals"]["owner-a"]["uidFingerprint"] = "changed"
    assert acquisition == original


def test_a_broken_wall_clock_is_recorded_as_absent_not_invented() -> None:
    def broken() -> float:
        raise OSError("no wall clock")

    bundle, _ = bound(ROLE_LOCAL_SHADOW, wall_clock=broken)
    assert bundle["transport"]["wallClock"] == {"startedAt": None, "finishedAt": None}
    assert bundle["recordingComplete"] is True


@pytest.mark.parametrize(
    "mutation,failure",
    [
        ({"action": "disable"}, "principal-action-mismatch"),
        ({"authTime": "soon"}, "principal-action-unproven:authTime"),
        ({"validSince": 1_700_000_000}, "principal-action-unproven:validSince"),
        ({"validSince": None}, "principal-action-unproven:validSince"),
        ({"present": False}, "principal-action-unproven:readback"),
        ({"disabled": True}, "principal-action-unproven:readback"),
        ({"uidFingerprint": "0" * 16}, "principal-action-unproven:principal"),
        ({"complete": False, "failure": "refused"}, "incomplete-principal-action"),
        ({"localId": "raw-uid"}, "unknown-receipt-key:localId"),
        ({"idToken": "x"}, "credential-leak:idToken"),
    ],
)
def test_an_unproven_principal_action_stops_the_run_before_its_row(
    mutation, failure
) -> None:
    plan = plan_for(ROLE_PRODUCTION)
    transport = bound_transport(plan, ROLE_PRODUCTION)

    def drifting(request: dict) -> dict:
        receipt = transport(request)
        if request.get("phase") == "principal" and request["action"] == "revoke":
            receipt.update(mutation)
        return receipt

    bundle = collect(
        plan,
        drifting,
        role=ROLE_PRODUCTION,
        run_id="unproven",
        acquisition=acquisition_for(plan, ROLE_PRODUCTION),
    )
    assert bundle["abort"] == failure
    # The positive control for the revoked principal ran; its refusal row did not.
    assert len(bundle["rows"]) == 24
    assert bundle["rows"][23]["credentialRef"] == "revoked-e"
    assert bundle["transport"]["principalActions"] == []
    assert bundle["infrastructureFailures"] == [f"principal-action:revoked-e:{failure}"]
    assert bundle["cleanup"]["cleanupComplete"] is True


def test_a_deleted_principal_is_absent_at_recovery_and_the_others_present() -> None:
    bundle, _ = bound(ROLE_LOCAL_SHADOW)
    readbacks = {
        step["accountRef"]: step["observed"]["accountPresent"]
        for step in bundle["cleanup"]["accountSteps"]
        if step["kind"] == "account-readback"
    }
    assert readbacks["deleted-g"] is False
    assert all(present for ref, present in readbacks.items() if ref != "deleted-g")
