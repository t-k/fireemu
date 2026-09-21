"""Offline dry run of the user-token O8 descriptor.

Nothing here reaches production: no credential, no origin, no Ledger and no
process. The synthetic approval is built from local files in tmp_path, and
the members that would reach a wire are left refusing.
"""

from __future__ import annotations

import hashlib
import http.server
import json
import os
import socketserver
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "tools/compat-broad"))
sys.path.insert(0, str(ROOT / "tools/compat-broad/o8-core"))
sys.path.insert(0, str(ROOT / "tools/compat-broad/production-admission"))
sys.path.insert(0, str(HERE))

import o5_user_token_descriptor as lane
import o5_user_token_remote_transport as remote
import o8_admission
from broad_contract import digest
from o5_user_token_campaign import (
    _SOURCE_FILES,
    admission,
    admitted_manifest_digest,
    manifest,
)
from o5_user_token_case import CAMPAIGN, compile_case
from o5_user_token_collector import ROLE_LOCAL_SHADOW, ROLE_PRODUCTION, RulesManagementSession, collect
from reservations import Ledger
import shared_gate
from o5_user_token_comparator_v2 import REFUSED
from o8_campaign import REQUIRED_MEMBERS, CampaignDescriptor
from test_o5_user_token_collector import Transport
from test_o5_user_token_collector_bound import (
    acquisition_for,
    bound,
    bound_transport,
)

NONCE = "a" * 32


def with_synthetic_build(monkeypatch, artifact_sha256: str) -> dict:
    """Point the lane's shadow record at a synthetic build for a dry run.

    The retained artifact validator pins the retained bytes to the shadow's
    build, which no test can reproduce, so a dry run substitutes a record that
    names the synthetic artifact instead. Everything else in the record is the
    real one.
    """
    real = lane.shadow_record()
    record = json.loads(json.dumps(real))
    record["artifact"]["artifactSha256"] = artifact_sha256
    record["bundle"]["acquisition"]["artifact"]["artifactSha256"] = artifact_sha256
    monkeypatch.setattr(lane, "shadow_record", lambda: record)
    return record


def synthetic(tmp_path, descriptor):
    """A complete O7 artifact set for the dry run, built from local files only."""
    plan = descriptor.plan_compiler(NONCE)
    artifact_path = tmp_path / "artifact"
    artifact_path.write_bytes(b"synthetic artifact")
    artifact_sha256 = hashlib.sha256(artifact_path.read_bytes()).hexdigest()
    inputs_seed = descriptor.source_map()
    permission = descriptor.permission_bindings(
        plan, "0" * 40, artifact_sha256, inputs_seed
    )
    inputs = o8_admission.freeze_inputs(
        descriptor,
        permission,
        plan,
        source_commit="0" * 40,
        artifact_sha256=artifact_sha256,
    )
    manifest_value = {
        "kind": lane.MANIFEST_KIND,
        "inputsDigest": inputs["inputsDigest"],
    }
    manifest_bytes = json.dumps(manifest_value).encode()
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_bytes(manifest_bytes)
    launcher_path = tmp_path / "launcher.py"
    launcher_path.write_bytes(b"# synthetic launcher\n")
    ledger = tmp_path / "ledger"
    now = time.time()
    approval = {
        "kind": lane.APPROVAL_KIND,
        "status": "approved",
        "campaignId": descriptor.campaign_id,
        "manifestSha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "inputsDigest": inputs["inputsDigest"],
        "permissionDigest": inputs["permissionDigest"],
        "sourceCommit": inputs["sourceCommit"],
        "sourceInputsDigest": digest(inputs["sourceInputs"]),
        "artifactSha256": inputs["artifactSha256"],
        "planDigest": inputs["planDigest"],
        "nonceDigest": digest(plan["nonce"]),
        "ledgerRoot": str(ledger.resolve(strict=False)),
        "launcherSha256": hashlib.sha256(launcher_path.read_bytes()).hexdigest(),
        "artifactProfile": descriptor.artifact_profile,
        "windowStartsAt": now - 1,
        "windowExpiresAt": now + 4 * descriptor.window_seconds,
        "executionHost": o8_admission.execution_host(),
    }
    return {
        "inputs": inputs,
        "approval": approval,
        "manifest": manifest_value,
        "manifest_bytes": manifest_bytes,
        "manifest_path": manifest_path,
        "permission": permission,
        "ledger_root": ledger,
        "artifact_path": artifact_path,
        "launcher_path": launcher_path,
    }


def test_the_descriptor_constructs_with_every_required_member() -> None:
    descriptor = lane.descriptor()
    assert descriptor.campaign_id == CAMPAIGN
    assert descriptor.binds_campaign_id
    assert descriptor.window_seconds == 900
    assert descriptor.artifact_profile.startswith("o5-user-token-")
    for name in REQUIRED_MEMBERS:
        assert getattr(descriptor, name) is not None


@pytest.mark.parametrize("member", REQUIRED_MEMBERS)
def test_a_descriptor_missing_any_member_is_refused_at_construction(member) -> None:
    members = lane.descriptor().members()
    members[member] = None
    with pytest.raises(ValueError, match="requires every member"):
        CampaignDescriptor(**members)


def test_the_frozen_inputs_cover_the_lane_and_the_shared_closure(tmp_path) -> None:
    descriptor = lane.descriptor()
    bindings = synthetic(tmp_path, descriptor)
    inputs = bindings["inputs"]
    sources = inputs["sourceInputs"]
    assert inputs["kind"] == lane.FROZEN_INPUTS_KIND
    for name in _SOURCE_FILES:
        assert f"{lane.LANE_DIRECTORY}/{name}" in sources
    for name in (*lane.SHARED_SOURCES, *lane.ABORT_CLOSURE_SOURCES):
        assert sources[name] == hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
    assert inputs["bounds"]["observationRequests"] == 33
    assert inputs["bounds"]["totalRequests"] == descriptor.budget["requests"]
    o8_admission.validate_frozen_inputs(descriptor, inputs)
    generation = o8_admission.abort_generation(descriptor, inputs)
    assert set(generation["sourceDigests"]) == {
        "shared_gate.py",
        "reservations.py",
        "o8_admission.py",
        "o5_user_token_collector.py",
        "o5_user_token_comparator_v2.py",
        "o5_user_token_descriptor.py",
        "o5_user_token_remote_transport.py",
        "o5_user_token_https_worker.py",
    }


def test_the_frozen_plan_is_the_lane_compiled_case_for_the_nonce(tmp_path) -> None:
    descriptor = lane.descriptor()
    inputs = synthetic(tmp_path, descriptor)["inputs"]
    assert inputs["plan"]["campaignId"] == CAMPAIGN
    assert inputs["plan"]["nonce"] == NONCE
    assert inputs["plan"] == lane.plan_compiler(NONCE)
    assert o8_admission.campaign_identity(descriptor, inputs) == CAMPAIGN


def test_a_synthetic_approval_passes_the_shared_o7_check_set(
    tmp_path, monkeypatch
) -> None:
    with_synthetic_build(monkeypatch, hashlib.sha256(b"synthetic artifact").hexdigest())
    descriptor = lane.descriptor()
    bindings = synthetic(tmp_path, descriptor)
    admitted = o8_admission.validate_o7_admission(descriptor, **bindings)
    assert admitted["campaignId"] == CAMPAIGN
    assert admitted["ledgerRoot"] == str(bindings["ledger_root"].resolve(strict=False))
    assert (
        admitted["retained"]["artifactSha256"] == bindings["inputs"]["artifactSha256"]
    )


@pytest.mark.parametrize(
    "override",
    [
        {"campaignId": "FS-LIMIT-API-REQUEST-BYTES"},
        {"kind": "request-bytes-o8-approval-v1"},
        {"artifactProfile": "request-bytes-000000000"},
        {"status": "pending"},
    ],
)
def test_another_campaign_approval_cannot_be_admitted(tmp_path, override) -> None:
    descriptor = lane.descriptor()
    bindings = synthetic(tmp_path, descriptor)
    with pytest.raises(ValueError):
        o8_admission.validate_o7_admission(
            descriptor,
            **{**bindings, "approval": {**bindings["approval"], **override}},
        )


def test_a_permission_with_another_window_is_refused(tmp_path) -> None:
    descriptor = lane.descriptor()
    bindings = synthetic(tmp_path, descriptor)
    permission = {**bindings["permission"], "wallSeconds": 1200}
    with pytest.raises(ValueError):
        o8_admission.validate_o7_admission(
            descriptor, **{**bindings, "permission": permission}
        )


def test_the_permission_bindings_name_the_collector_and_the_comparator(
    tmp_path,
) -> None:
    descriptor = lane.descriptor()
    permission = synthetic(tmp_path, descriptor)["permission"]
    assert permission["kind"] == lane.PERMISSION_KIND
    assert (
        permission["collectorSha256"]
        == hashlib.sha256((ROOT / lane.COLLECTOR_ENTRY).read_bytes()).hexdigest()
    )
    assert (
        permission["comparatorSha256"]
        == hashlib.sha256((ROOT / lane.COMPARATOR_ENTRY).read_bytes()).hexdigest()
    )
    assert permission["campaignManifestDigest"] == admitted_manifest_digest(
        lane.PROJECT, lane.DATABASE, NONCE
    )
    assert permission["wallSeconds"] == 600
    assert permission["recoverySeconds"] == 300
    assert permission["budget"]["accounts"] == 7
    assert permission["budget"]["costMicrousd"] == 1_000_000


def test_lock_scopes_hold_the_ruleset_exclusively_and_the_nonce_subtree() -> None:
    plan = lane.plan_compiler(NONCE)
    scopes = lane.lock_scopes(plan)
    modes = {scope["key"]: scope["mode"] for scope in scopes}
    assert modes[f"project/{lane.PROJECT}/firestore/(default)/ruleset"] == "EXCLUSIVE"
    assert (
        modes[
            f"project/{lane.PROJECT}/firestore/(default)/documents/o5-user-token/n{NONCE}/cases/*"
        ]
        == "WRITE"
    )
    assert len(modes) == len(scopes)
    from reservations import _locks, conflicts

    _locks(scopes)
    # Another campaign's read of the ruleset conflicts with this exclusive hold.
    other = {
        "key": f"project/{lane.PROJECT}/firestore/(default)/ruleset",
        "mode": "READ",
    }
    assert conflicts(scopes[1], other)


def test_every_unwired_member_refuses() -> None:
    descriptor = lane.descriptor()
    for member in ("transport_bound", "binding_verifier"):
        with pytest.raises(PermissionError, match="not wired"):
            getattr(descriptor, member)()
    assert descriptor.forbidden_transports() == (lane.transport_bound,)


def test_a_retained_artifact_that_is_not_the_shadow_build_is_refused(
    tmp_path,
) -> None:
    """Without the synthetic-build substitution, the real record pins the
    retained bytes to the fireemu build the shadow ran, which a synthetic
    artifact is not."""
    descriptor = lane.descriptor()
    bindings = synthetic(tmp_path, descriptor)
    with pytest.raises(ValueError, match="not the shadow's build"):
        o8_admission.validate_o7_admission(descriptor, **bindings)
    with pytest.raises(ValueError, match="not the shadow's build"):
        descriptor.retained_artifact_validator(
            bindings["artifact_path"],
            bindings["manifest_path"],
            descriptor.artifact_profile,
        )


def test_a_capability_cannot_be_issued_without_a_worker_binding(
    tmp_path, monkeypatch
) -> None:
    with_synthetic_build(monkeypatch, hashlib.sha256(b"synthetic artifact").hexdigest())
    descriptor = lane.descriptor()
    bindings = synthetic(tmp_path, descriptor)
    with pytest.raises(PermissionError, match="worker archive closure"):
        o8_admission.issue_production_capability(
            descriptor, binding=b"worker", binding_digest="c" * 64, **bindings
        )


def test_the_lane_admission_stays_closed() -> None:
    gate = admission(manifest(lane.PROJECT, lane.DATABASE, NONCE))
    assert gate["productionReady"] is False
    with pytest.raises(PermissionError):
        gate["admit"]()


def test_an_injected_local_transport_is_accepted_and_the_wire_member_is_not() -> None:
    descriptor = lane.descriptor()
    plan = lane.plan_compiler(NONCE)
    local = bound_transport(plan, ROLE_PRODUCTION)
    assert o8_admission.reject_production_transport(descriptor, local) is local

    def reaching(request):
        return lane.transport_bound(request)

    with pytest.raises(ValueError, match="must not reach the production wire"):
        o8_admission.reject_production_transport(descriptor, reaching)


def test_the_collector_member_runs_the_lane_collector_bound() -> None:
    descriptor = lane.descriptor()
    plan = lane.plan_compiler(NONCE)
    transport = bound_transport(plan, ROLE_PRODUCTION)
    bundle = descriptor.collector(
        plan,
        transport,
        run_id="dry-run",
        acquisition=acquisition_for(plan, ROLE_PRODUCTION),
    )
    assert bundle["provenance"]["role"] == ROLE_PRODUCTION
    # A bound run without the production Rules management session is held
    # before mutation; this prevents the legacy receipt contract from being
    # mistaken for production lifecycle evidence.
    assert bundle["recordingComplete"] is False
    assert bundle["abort"] == "collector:ValueError"
    assert bundle["budget"]["deadlineSeconds"] == 600.0
    assert bundle["budget"]["recoveryDeadlineSeconds"] == 900.0
    assert bundle["productionReady"] is False
    unbound = Transport(plan)
    refused = descriptor.collector(
        plan,
        unbound,
        run_id="unbound",
        acquisition=acquisition_for(plan, ROLE_PRODUCTION),
    )
    assert refused["abort"] == "collector:ValueError"


def test_the_comparator_member_compares_against_the_published_shadow() -> None:
    """The reference is the checked-in local shadow. A bound production bundle
    of another nonce is refused against it; one of the shadow's own nonce is
    compared row by row, and its statuses agree with what the shadow saw."""
    descriptor = lane.descriptor()
    record = lane.shadow_record()
    plan = lane.plan_compiler(NONCE)
    production, _ = bound(ROLE_PRODUCTION)
    result = descriptor.comparator(production, plan)
    assert result["classification"] == REFUSED
    assert "local:campaign-identity-drift" in result["errors"]
    shadow_plan = lane.plan_compiler(record["nonce"])
    production = descriptor.collector(
        shadow_plan,
        bound_transport(shadow_plan, ROLE_PRODUCTION),
        run_id="dry-run",
        acquisition=acquisition_for(shadow_plan, ROLE_PRODUCTION),
    )
    result = descriptor.comparator(production, shadow_plan)
    # The published local shadow is a valid reference, while this side is only
    # a preparation bundle with no production management session. The
    # comparator must preserve that uncertainty rather than call it refusal.
    assert result["classification"] == "INDETERMINATE"
    assert "production:recording-incomplete" in result["errors"]
    assert "production:recording-aborted" in result["errors"]


def test_descriptor_collector_runs_complete_rules_lifecycle_with_real_gate_and_ledger(tmp_path) -> None:
    plan = lane.plan_compiler(NONCE)
    gate_plan = lane.gate_plan(plan, permission_expires_at=time.time() + 3600)
    gate_path = tmp_path / "gate"
    ledger = Ledger.create(tmp_path / "ledger")
    now = time.time()
    permission = {"kind": "o5-test"}
    envelope = {"permissionDigest": digest(permission), "issuedAt": now - 1, "expiresAt": now + 3600, "limits": {"requests": 56, "accounts": 0, "resources": 1, "costMicrousd": 23}, "concurrency": 1, "scopes": [{"key": "project/fireemu-35fe6", "mode": "EXCLUSIVE"}]}
    claim = {"campaignId": CAMPAIGN, "manifestDigest": digest(plan), "nonceDigest": digest(plan["nonce"]), "gatePath": str(gate_path.resolve()), "gatePlanDigest": digest(gate_plan), "locks": [{"key": "project/fireemu-35fe6", "mode": "EXCLUSIVE"}], "budget": dict(envelope["limits"]), "durationSeconds": 600}
    ticket = ledger.reserve(envelope, claim, gate_plan)
    shared_gate.create(gate_path, gate_plan)
    gate = shared_gate.Gate(gate_path, CAMPAIGN)
    acquisition = acquisition_for(plan, ROLE_PRODUCTION)
    data = Transport(plan, endpoint="firestore.googleapis.com:443", fingerprints={ref: value["uidFingerprint"] for ref, value in acquisition["principals"].items()})
    names = {"A": "projects/fireemu-35fe6/rulesets/server-a", "B": "projects/fireemu-35fe6/rulesets/server-b"}
    baseline = "projects/fireemu-35fe6/rulesets/pre-existing"
    class Handler(http.server.BaseHTTPRequestHandler):
        active = baseline
        deleted: set[str] = set()
        requests: list[tuple[str, str, dict]] = []
        def do_any(self):
            size = int(self.headers.get("Content-Length", "0"))
            body = json.loads(self.rfile.read(size) or b"{}")
            path = self.path
            self.__class__.requests.append((self.command, path, body))
            status = 200
            if path.endswith(":getExecutable"):
                payload = {"rulesetName": self.__class__.active}
            elif path.endswith("/releases/cloud.firestore"):
                if self.command == "PATCH":
                    self.__class__.active = body["release"]["rulesetName"]
                payload = {"name": "projects/fireemu-35fe6/releases/cloud.firestore", "rulesetName": self.__class__.active}
            elif path == "/v1/projects/fireemu-35fe6/rulesets" and self.command == "POST":
                label = "A" if body["source"]["files"][0]["content"] == plan["rulesets"]["A"]["source"] else "B"
                payload = {"name": names[label]}
            elif "/rulesets/" in path:
                name = "projects/fireemu-35fe6/" + path.split("/v1/projects/fireemu-35fe6/", 1)[1]
                if name in self.__class__.deleted:
                    status, payload = 404, {"error": {"code": 404}}
                elif self.command == "DELETE":
                    self.__class__.deleted.add(name)
                    payload = {}
                else:
                    label = "A" if name == names["A"] else "B"
                    payload = {"name": name, "source": {"files": [{"name": "firestore.rules", "content": plan["rulesets"][label]["source"]}]}}
            else:
                status, payload = 404, {"error": {"code": 404}}
            raw = json.dumps(payload, separators=(",", ":")).encode()
            self.send_response(status); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(raw))); self.end_headers(); self.wfile.write(raw)
        do_GET = do_any; do_POST = do_any; do_PATCH = do_any; do_DELETE = do_any
        def log_message(self, *_args):
            return

    reservation = None
    portctl = os.environ.get("FIREEMU_PORTCTL")
    if portctl:
        claim = subprocess.run([sys.executable, portctl, "claim", "--service", "o5-user-token-rules-management", "--preferred", "10000", "--range", "10000-19999", "--ttl", "10m", "--format", "json"], check=True, capture_output=True, text=True)
        reservation = json.loads(claim.stdout)
        server = socketserver.TCPServer(("127.0.0.1", int(reservation["port"])), Handler)
    else:
        server = socketserver.TCPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    source, source_digest = remote.worker_binding()
    origin = f"http://127.0.0.1:{server.server_address[1]}"
    def execute(operation, **_kwargs):
        if operation.get("kind") != "rules-lifecycle":
            return data(operation)
        prepared = remote.prepare_request(plan, operation, credentials={"administrator": "fixture-admin"})
        envelope = {key: prepared[key] for key in ("service", "route", "method", "path", "headers", "body")}; envelope["seconds"] = 8.0
        result = remote.run_worker(envelope, binding=source, binding_digest=source_digest, fixture_origin=origin)
        return {"status": result["status"], "body": result["body"]}

    assert gate.snapshot()["managementUsed"] == []
    wrong_ticket = dict(ticket)
    wrong_ticket["reservation"] = "foreign-reservation"
    with pytest.raises(ValueError, match="Ledger claim binding"):
        RulesManagementSession(gate=gate, ledger=ledger, ticket=wrong_ticket, execute=execute, plan=plan)
    wrong_plan = json.loads(json.dumps(plan))
    wrong_plan["nonce"] = "b" * 32
    with pytest.raises(ValueError, match="Ledger claim binding"):
        RulesManagementSession(gate=gate, ledger=ledger, ticket=ticket, execute=execute, plan=wrong_plan)
    assert gate.snapshot()["managementUsed"] == []
    assert Handler.requests == []
    session = RulesManagementSession(gate=gate, ledger=ledger, ticket=ticket, execute=execute, plan=plan)
    try:
        bundle = lane.collector(plan, execute, run_id="real-o5", acquisition=acquisition, management_session=session)
        assert bundle["recordingComplete"] is True, (bundle["abort"], bundle["infrastructureFailures"], bundle["transport"].get("rulesManagement"))
        assert bundle["transport"]["rulesManagement"]["recovery"]["restored"] is True
        assert len(gate.snapshot()["managementUsed"]) == 23
        release = "projects/fireemu-35fe6/releases/cloud.firestore"
        expected = [
            ("GET", f"/v1/{release}", {}),
            ("GET", "/v1/projects/fireemu-35fe6/rulesets/pre-existing", {}),
            ("GET", f"/v1/{release}:getExecutable", {}),
            ("POST", "/v1/projects/fireemu-35fe6/rulesets", {"source": {"files": [{"name": "firestore.rules", "content": plan["rulesets"]["A"]["source"]}]}}),
            ("GET", "/v1/projects/fireemu-35fe6/rulesets/server-a", {}),
            ("PATCH", f"/v1/{release}", {"release": {"name": release, "rulesetName": names["A"]}, "updateMask": "rulesetName"}),
            ("GET", f"/v1/{release}", {}),
            ("GET", f"/v1/{release}:getExecutable", {}),
            ("POST", "/v1/projects/fireemu-35fe6/rulesets", {"source": {"files": [{"name": "firestore.rules", "content": plan["rulesets"]["B"]["source"]}]}}),
            ("GET", "/v1/projects/fireemu-35fe6/rulesets/server-b", {}),
            ("PATCH", f"/v1/{release}", {"release": {"name": release, "rulesetName": names["B"]}, "updateMask": "rulesetName"}),
            ("GET", f"/v1/{release}", {}),
            ("GET", f"/v1/{release}:getExecutable", {}),
            ("GET", f"/v1/{release}", {}),
            ("PATCH", f"/v1/{release}", {"release": {"name": release, "rulesetName": baseline}, "updateMask": "rulesetName"}),
            ("GET", f"/v1/{release}", {}),
            ("GET", f"/v1/{release}:getExecutable", {}),
            ("GET", "/v1/projects/fireemu-35fe6/rulesets/server-a", {}),
            ("DELETE", "/v1/projects/fireemu-35fe6/rulesets/server-a", {}),
            ("GET", "/v1/projects/fireemu-35fe6/rulesets/server-a", {}),
            ("GET", "/v1/projects/fireemu-35fe6/rulesets/server-b", {}),
            ("DELETE", "/v1/projects/fireemu-35fe6/rulesets/server-b", {}),
            ("GET", "/v1/projects/fireemu-35fe6/rulesets/server-b", {}),
        ]
        assert Handler.requests == expected
    finally:
        server.shutdown()
        server.server_close()
        if reservation is not None:
            subprocess.run([sys.executable, portctl, "release", "--token", reservation["token"]], check=True)


def test_preserved_local_runner_acquisition_remains_accepted_without_management_session() -> None:
    raw_path = Path("/Users/tk/work/firebase-emulator/docs.local/runs/o5-rules-shadow-fd4.84Jpkk/local-shadow.json")
    if not raw_path.is_file():
        pytest.skip("preserved local runner receipt is unavailable")
    raw = json.loads(raw_path.read_bytes())
    recorded = raw["bundle"]["acquisition"]
    acquisition = {key: recorded[key] for key in ("environment", "campaignManifestDigest", "nonceReservation", "ownerPermission", "artifact", "principals", "window")}
    plan = compile_case("fireemu-35fe6", "(default)", raw["nonce"], raw["tenant"])
    fingerprints = {
        ref: value["uidFingerprint"]
        for ref, value in acquisition["principals"].items()
    }
    transport = Transport(
        plan,
        endpoint="127.0.0.1:52879",
        fingerprints=fingerprints,
    )
    bundle = collect(
        plan,
        transport,
        role=ROLE_LOCAL_SHADOW,
        deadline_seconds=600.0,
        recovery_deadline_seconds=900.0,
        run_id="preserved-local-runner-acquisition",
        acquisition=acquisition,
    )
    assert bundle["recordingComplete"] is True
    assert bundle["abort"] is None
    assert len(bundle["rows"]) == 33
    assert bundle["productionExecuted"] is False


def test_a_local_shadow_bundle_fails_closed_as_production_evidence() -> None:
    """The saved local record cannot be passed off as the production side."""
    descriptor = lane.descriptor()
    record = lane.shadow_record()
    plan = lane.plan_compiler(record["nonce"])
    forged = json.loads(json.dumps(record["bundle"]))
    forged["provenance"]["role"] = ROLE_PRODUCTION
    forged["provenance"]["runId"] = "relabelled"
    forged["productionExecuted"] = True
    result = descriptor.comparator(forged, plan)
    assert result["classification"] == REFUSED
    assert result["rows"] == []
    assert "production:local-mislabelled-as-production" in result["errors"]


def test_a_reference_bundle_of_another_build_is_refused() -> None:
    """The comparator member compares only against the build the record names."""
    descriptor = lane.descriptor()
    record = lane.shadow_record()
    plan = lane.plan_compiler(record["nonce"])
    production, _ = bound(ROLE_PRODUCTION)
    other = json.loads(json.dumps(record["bundle"]))
    other["acquisition"]["artifact"]["artifactSha256"] = "0" * 64
    result = descriptor.comparator(production, plan, other)
    assert result["classification"] == REFUSED
    assert result["errors"] == ["local:reference-artifact-mismatch"]
    assert result["rows"] == []
    stripped = json.loads(json.dumps(record["bundle"]))
    stripped["acquisition"]["artifact"] = None
    assert (
        descriptor.comparator(production, plan, stripped)["classification"] == REFUSED
    )


def test_the_descriptor_module_is_bound_by_the_campaign_manifest() -> None:
    assert "o5_user_token_descriptor.py" in _SOURCE_FILES
    assert "o5_user_token_comparator_v2.py" in _SOURCE_FILES
