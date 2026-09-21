"""Offline O8 integration for the partition/cursor campaign.

Real capabilities, real Gate journals and a temporary shared Ledger, never the
canonical one. The wire is an injected offline oracle: no socket is opened, no
credential is read, no production origin is contacted.
"""

import copy
import hashlib
import json
import multiprocessing
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "tools/compat-broad"))
sys.path.insert(0, str(ROOT / "tools/compat-broad/production-admission"))
sys.path.insert(0, str(ROOT / "tools/compat-broad/o8-core"))
sys.path.insert(0, str(HERE))

import o4_partition_cursor_descriptor as campaign
import partition_cursor_admission as admission
import partition_cursor_gate as gate_projection
import partition_cursor_o8 as launcher
import partition_cursor_preflight as preflight
import partition_cursor_production as production
import partition_cursor_wire as wire
import reservations
import shared_gate
from broad_contract import digest
from partition_cursor_collector import collect_local
from partition_cursor_comparator import compare_evidence
from partition_cursor_offline_fixture import TIME, Transport

commit_baseline = campaign.commit_baseline

NONCE = "b" * 32
LOCAL_NONCE = "c" * 32
CAMPAIGN_ID = "FS-QUERY-PARTITION-CURSOR-04"
PROJECT_BODY = {"projectId": "fireemu-35fe6", "projectNumber": "592603257417"}
DATABASE_BODY = {
    "name": "projects/fireemu-35fe6/databases/(default)",
    "uid": "fixture-uid",
    "type": "FIRESTORE_NATIVE",
    "databaseEdition": "STANDARD",
    "locationId": "us-central1",
}
AUTH_BODY = {"name": "projects/592603257417/config", "mfa": {"state": "DISABLED"}}
BASELINE_BODIES = [
    (commit_baseline.ROUTES["projectIdentity"], PROJECT_BODY),
    (commit_baseline.ROUTES["database"], DATABASE_BODY),
    (commit_baseline.ROUTES["authConfig"], AUTH_BODY),
]
TOKEN = "offline-fixture-token"


class Clock:
    def __init__(self):
        self.now = 1000.0

    def monotonic(self):
        return self.now

    def time(self):
        return time.time()

    def sleep(self, seconds):
        self.now += seconds


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    clock = Clock()
    monkeypatch.setattr(shared_gate, "time", clock)
    monkeypatch.setattr(production, "time", clock)
    monkeypatch.setattr(preflight, "time", clock)
    monkeypatch.setattr(preflight.request_bytes_preflight, "time", clock)

    def management_fixture(slot, token, **_kwargs):
        assert token == TOKEN
        body = {
            "project": PROJECT_BODY,
            "database": DATABASE_BODY,
            "auth": AUTH_BODY,
        }.get(slot)
        if slot == "oauth-tokeninfo":
            body = {
                "issued_to": "offline-client",
                "user_id": "offline-subject",
                "scope": preflight.SCOPE,
                "expires_in": 3600,
            }
        return {
            "status": 200,
            "complete": True,
            "workerReaped": True,
            "bodyKind": "json",
            "body": body,
        }

    monkeypatch.setattr(preflight, "management_transport", management_fixture)

    def forbidden(*_args, **_kwargs):
        raise AssertionError("network forbidden in O8 regression")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(wire, "_spawn", forbidden)
    return clock


class ProductionOracle(Transport):
    """A stateful offline stand-in for the production database.

    Documents exist only after this run creates them, disappear only when this
    run deletes them, and every read, query and typed absence follows that
    state, so the ladder and the residual scans answer as production would.
    """

    def __init__(self, value, *, partitions=1, page_token="offline-page-token"):
        super().__init__(value, partitions=partitions, page_token=page_token)
        self.live: dict[str, dict] = {}
        self.calls: list[dict] = []
        self.fail_kind: str | None = None

    def _root(self):
        return self.plan["ownedScope"]

    def _doc(self, name):
        return {
            "name": name,
            "fields": self.live[name],
            "createTime": TIME,
            "updateTime": TIME,
        }

    def _stream(self, names):
        return [{"document": self._doc(name)} for name in names] or [{"readTime": TIME}]

    def _body(self, request):
        kind = request["kind"]
        path = request["path"].split("?", 1)[0]
        target = path.removeprefix("/v1/")
        if request["method"] == "GET":
            if target in self.live:
                return 200, self._doc(target)
            return 404, {"error": {"code": 404, "status": "NOT_FOUND"}}
        if request["method"] == "DELETE":
            assert "?currentDocument.updateTime=" + TIME in request["path"]
            assert target in self.live
            del self.live[target]
            return 200, {}
        if kind == "create-only-patch":
            assert self._root() not in self.live
            self.live[self._root()] = {
                "marker": {"stringValue": self.plan["campaignId"]}
            }
            return 200, self._doc(self._root())
        if kind == "seed-commit":
            for write in request["body"]["writes"]:
                assert write["update"]["name"] not in self.live
                self.live[write["update"]["name"]] = write["update"]["fields"]
            return super()._body(request)
        if kind == "cleanup-seed-delete":
            for write in request["body"]["writes"]:
                assert write["currentDocument"] == {"updateTime": TIME}
                assert write["delete"] in self.live
                del self.live[write["delete"]]
            return super()._body(request)
        if kind in ("cleanup-verify-group-absence", "residual-group-scan"):
            names = [
                name for name in self.plan["ownedResources"][1:13] if name in self.live
            ]
            return 200, self._stream(names)
        if kind in ("cleanup-verify-collection-absence", "residual-cursor-scan"):
            names = [
                name for name in self.plan["ownedResources"][13:] if name in self.live
            ]
            return 200, self._stream(names)
        return super()._body(request)

    def __call__(self, request):
        self.calls.append(copy.deepcopy(request))
        if self.fail_kind is not None and request["kind"] == self.fail_kind:
            # The server applied the request; only the answer was lost.
            self._body(request)
            raise ConnectionError("offline transport failure")
        return super().__call__(request)


def baseline_record(tmp_path):
    """A recorded production observation journal and the run evidence beside it."""
    evidence = tmp_path / "baseline-evidence"
    evidence.mkdir()
    journal = evidence / "responses.jsonl"
    journal.write_text(
        "\n".join(
            json.dumps(
                {
                    "service": "metadata",
                    "route": route,
                    "phase": "observation",
                    "response": {
                        "httpStatus": 200,
                        "mediaType": "application/json",
                        "body": body,
                    },
                    "digest": digest(body),
                }
            )
            for route, body in BASELINE_BODIES
        )
        + "\n"
    )
    receipt = evidence / "receipt.json"
    receipt.write_text(
        json.dumps(
            {
                "kind": "commit-acquisition-receipt-v2",
                "executionKind": "fixed-production-wire",
                "productionExecuted": False,
                "metadata": [
                    {
                        "id": "observation:" + commit_baseline.ROUTE_ACTIONS[route],
                        "status": 200,
                        "responseDigest": digest(body),
                        "value": {},
                    }
                    for route, body in BASELINE_BODIES
                ],
            }
        )
    )
    journal_sha = hashlib.sha256(journal.read_bytes()).hexdigest()
    receipt_sha = hashlib.sha256(receipt.read_bytes()).hexdigest()
    record = tmp_path / "baseline.json"
    record.write_text(
        json.dumps(
            {
                "kind": commit_baseline.RECORD_KIND,
                "observations": [
                    {
                        "route": route,
                        "path": "responses.jsonl",
                        "sha256": journal_sha,
                        "index": index,
                        "production": {
                            "path": "receipt.json",
                            "sha256": receipt_sha,
                            "mode": "live",
                        },
                    }
                    for index, (route, _body) in enumerate(BASELINE_BODIES)
                ],
            }
        )
    )
    return commit_baseline.baseline_from_record(
        record, evidence_root=evidence, production_roots=(evidence.resolve().parts,)
    )


def frozen_checkout(tmp_path):
    """A clean git checkout carrying byte-identical copies of the frozen sources."""
    source = tmp_path / "checkout"
    for name in campaign.source_map():
        target = source / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, target)
    for args in (
        ["init", "-q"],
        ["add", "-A"],
        [
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit",
            "-qm",
            "fixture",
        ],
    ):
        subprocess.run(["git", "-C", str(source), *args], check=True)
    return source


def owner_permission(plan, commit, artifact_digest, inputs, baseline):
    return {
        **campaign.permission_bindings(plan, commit, artifact_digest, inputs, baseline),
        "ownerIdentity": "offline-fixture-not-permission",
        "permissionReference": "offline-fixture",
        "recoveryOwner": "offline-recovery",
        "credentialPrincipal": {
            "clientId": "offline-client",
            "subject": "offline-subject",
            "requiredScopes": ["https://www.googleapis.com/auth/cloud-platform"],
        },
        "gateReservationSeconds": {
            "slot": 6.0,
            "slotBasis": admission.PLANNING_ASSUMPTION,
        },
        "issuedAt": time.time() - 1,
        "expiresAt": time.time() + 4800,
    }


class Admission:
    """A complete, locally built O7 artifact set for the partition/cursor campaign."""

    def __init__(self, tmp_path, *, ledger=True):
        self.descriptor = campaign.descriptor()
        self.source = frozen_checkout(tmp_path)
        self.commit = subprocess.check_output(
            ["git", "-C", str(self.source), "rev-parse", "HEAD"], text=True
        ).strip()
        self.artifact_path = tmp_path / "artifact"
        self.artifact_path.write_bytes(b"retained partition-cursor artifact")
        self.plan = self.descriptor.plan_compiler(NONCE)
        self.baseline = baseline_record(tmp_path)
        self.permission = owner_permission(
            self.plan,
            self.commit,
            hashlib.sha256(self.artifact_path.read_bytes()).hexdigest(),
            campaign.source_map(),
            self.baseline,
        )
        self.permission_path = tmp_path / "permission.json"
        self.permission_path.write_text(json.dumps(self.permission))
        self.inputs = admission.freeze_inputs(
            self.permission_path,
            self.plan,
            source_root=self.source,
            artifact_path=self.artifact_path,
            baseline=self.baseline,
        )
        self.ledger = tmp_path / "ledger"
        if ledger:
            reservations.Ledger.create(self.ledger)
        self.manifest = {
            "kind": campaign.MANIFEST_KIND,
            "inputsDigest": self.inputs["inputsDigest"],
        }
        self.manifest_bytes = json.dumps(self.manifest).encode()
        self.manifest_path = tmp_path / "manifest.json"
        self.manifest_path.write_bytes(self.manifest_bytes)
        self.manifest_path.chmod(0o600)
        self.launcher_path = HERE / "partition_cursor_o8.py"
        self.approval = self._approval()
        self.approval_path = tmp_path / "approval.json"
        self.approval_path.write_text(json.dumps(self.approval))
        self.approval_path.chmod(0o600)
        self.handoff_path = tmp_path / "handoff.json"
        self.write_handoff(digest(self.permission))

    def write_handoff(self, permission_digest):
        self.handoff_path.write_text(
            json.dumps(
                {
                    "kind": launcher.HANDOFF_KIND,
                    "permissionDigest": permission_digest,
                    "token": TOKEN,
                }
            )
        )
        self.handoff_path.chmod(0o600)

    def _approval(self):
        now = time.time()
        return {
            "kind": campaign.APPROVAL_KIND,
            "status": "approved",
            "campaignId": CAMPAIGN_ID,
            "manifestSha256": hashlib.sha256(self.manifest_bytes).hexdigest(),
            "inputsDigest": self.inputs["inputsDigest"],
            "permissionDigest": self.inputs["permissionDigest"],
            "sourceCommit": self.inputs["sourceCommit"],
            "sourceInputsDigest": digest(self.inputs["sourceInputs"]),
            "artifactSha256": self.inputs["artifactSha256"],
            "planDigest": self.inputs["planDigest"],
            "nonceDigest": digest(self.plan["nonce"]),
            "ledgerRoot": str(self.ledger.resolve(strict=False)),
            "launcherSha256": hashlib.sha256(
                self.launcher_path.read_bytes()
            ).hexdigest(),
            "artifactProfile": campaign.artifact_profile(),
            "windowStartsAt": now - 1,
            "windowExpiresAt": now + 4 * self.descriptor.window_seconds,
            "executionHost": admission.execution_host(),
        }

    def bindings(self, **overrides):
        value = {
            "inputs": self.inputs,
            "approval": self.approval,
            "manifest": self.manifest,
            "manifest_bytes": self.manifest_bytes,
            "manifest_path": self.manifest_path,
            "permission": self.permission,
            "ledger_root": self.ledger,
            "artifact_path": self.artifact_path,
            "launcher_path": self.launcher_path,
        }
        value.update(overrides)
        return value

    def argv(self, tmp_path):
        inputs_path = tmp_path / "inputs.json"
        inputs_path.write_text(json.dumps(self.inputs))
        return [
            "--inputs", str(inputs_path),
            "--approval", str(self.approval_path),
            "--manifest", str(self.manifest_path),
            "--permission", str(self.permission_path),
            "--source", str(self.source),
            "--artifact", str(self.artifact_path),
            "--ledger", str(self.ledger),
            "--output", str(tmp_path / "output"),
            "--credential-file", str(self.handoff_path),
        ]  # fmt: skip


@pytest.fixture
def built(tmp_path):
    return Admission(tmp_path)


def oracle_wire(monkeypatch, plan, **options):
    oracle = ProductionOracle(plan, **options)

    def request(operation, token, *, origin=wire.PRODUCTION_ORIGIN, timeout, deadline):
        assert token == TOKEN
        assert origin == wire.PRODUCTION_ORIGIN
        assert 0 < timeout <= wire.PRODUCTION_REQUEST_SECONDS
        return oracle(operation)

    monkeypatch.setattr(wire, "production_request", request)
    return oracle


def run(built, tmp_path):
    return launcher.execute(launcher.build_parser().parse_args(built.argv(tmp_path)))


def _stopped_pid():
    child = multiprocessing.get_context("spawn").Process(target=time.sleep, args=(0,))
    child.start()
    pid = child.pid
    child.join(timeout=10)
    assert child.exitcode == 0
    return pid


def _prove_workers_exited(gate_path):
    """Test scaffolding: the in-process coordinator is alive, a real run's is not."""
    gate = shared_gate.Gate(gate_path, gate_projection.JOB)
    with gate.locked() as state:
        pid = _stopped_pid()
        state["coordinatorPid"] = pid
        state["jobs"][gate_projection.JOB]["pid"] = pid
        shared_gate._save(gate.path, state)
    return gate.snapshot()


def local_bundle(tmp_path):
    """An offline local bundle with another nonce, for the comparator."""
    plan = campaign.compile_plan("fireemu-35fe6", "(default)", LOCAL_NONCE)
    return collect_local(
        plan,
        Transport(plan, partitions=1, page_token="local-token"),
        tmp_path / "local",
    )


def test_the_complete_run_reaches_every_slot_and_releases_the_temporary_ledger(
    built, tmp_path, monkeypatch
):
    oracle = oracle_wire(monkeypatch, built.plan)
    read = launcher._read_handoff

    def read_after_reservation(args):
        state = reservations.Ledger(built.ledger).snapshot()
        assert len(state["reservations"]) == 1
        row = next(iter(state["reservations"].values()))
        assert row["state"] == "held"
        snapshot = shared_gate.Gate(
            tmp_path / "output/gate", row["claim"]["gateJob"]
        ).snapshot()
        assert snapshot["jobs"][gate_projection.JOB]["pid"] is not None
        return read(args)

    monkeypatch.setattr(launcher, "_read_handoff", read_after_reservation)
    result = run(built, tmp_path)
    assert result["failure"] is None
    assert result["reservationReleased"] is True
    output = tmp_path / "output"
    receipt = json.loads((output / "receipt.json").read_bytes())
    release = json.loads((output / "release.json").read_bytes())
    gate = shared_gate.Gate(output / "gate", gate_projection.JOB).snapshot()
    bundle = receipt["collection"]
    # Every one of the 37 compiled slots was dispatched and passed.
    assert [row["status"] for row in bundle["rows"] + bundle["cleanup"]["rows"]] == [
        "pass"
    ] * 37
    assert bundle["raw"] == {"complete": True, "bindings": 37}
    assert bundle["reconstruction"]["matches"] is True
    assert bundle["productionExecuted"] is True
    assert bundle["target"] == "fixed-production-wire"
    # The ladder found every document already absent and deleted nothing.
    assert receipt["ladderSummary"] == {
        "slots": 63,
        "reads": 21,
        "absentAtRead": 21,
        "deleted": 0,
        "provenAbsent": 21,
        "failed": 0,
    }
    assert receipt["ladderAbsenceComplete"] is True
    assert receipt["residualSummary"] == {"complete": True, "documents": 0}
    assert not oracle.live
    assert (
        len(oracle.calls)
        == campaign.FROZEN_BOUNDS["expectedWireRequests"] - campaign.MANAGEMENT_REQUESTS
    )
    assert gate["jobs"][gate_projection.JOB]["complete"] is True
    assert gate["jobs"][gate_projection.JOB]["scheduleDone"] == 102
    assert gate["total"] == campaign.FROZEN_BOUNDS["expectedWireRequests"]
    shared_gate.validate_absence_proofs(gate, gate_projection.JOB)
    assert receipt["releaseEligible"] is True
    assert receipt["productionExecuted"] is True
    assert receipt["gateDigest"] == digest(gate)
    assert release["receiptDigest"] == digest(receipt)
    final = reservations.Ledger(built.ledger).snapshot()["reservations"][
        receipt["ticket"]["reservation"]
    ]
    assert final == release["reservationFinal"]
    assert final["state"] == "released"
    assert final["finalGateDigest"] == receipt["gateDigest"]
    production.verify_saved(
        output,
        expected_inputs_digest=built.inputs["inputsDigest"],
        ledger_root=built.ledger,
    )
    comparison = compare_evidence(
        bundle,
        local_bundle(tmp_path),
        production_directory=output / "collection",
        local_directory=tmp_path / "local",
    )
    assert comparison["classification"] == "EQUIVALENT"
    assert comparison["productionExecuted"] is True
    assert comparison["promotionReady"] is False


def test_a_binding_drift_is_refused_before_any_wire(built, tmp_path, monkeypatch):
    oracle = oracle_wire(monkeypatch, built.plan)
    other = b"# not the reviewed worker\n"
    monkeypatch.setattr(
        campaign, "worker_binding", lambda: (other, hashlib.sha256(other).hexdigest())
    )
    with pytest.raises(ValueError, match="worker source digest differs"):
        run(built, tmp_path)
    assert oracle.calls == []
    assert not (tmp_path / "output").exists()
    assert reservations.Ledger(built.ledger).snapshot()["reservations"] == {}


def test_a_transport_call_with_other_bytes_is_refused_after_issuance(
    built, tmp_path, monkeypatch
):
    oracle = oracle_wire(monkeypatch, built.plan)
    binding, binding_digest = campaign.worker_binding()
    capability = admission.issue_production_capability(
        **built.bindings(), binding=binding, binding_digest=binding_digest
    )
    try:
        other = b"# other\n"
        value = admission.transport_call(
            {"path": "/v1/x", "method": "GET", "body": None}, TOKEN, deadline=10.0
        )
        with pytest.raises(ValueError, match="unadmitted"):
            campaign.transport_bound(
                value,
                binding=binding,
                binding_digest=binding_digest,
                capability=capability,
            )
        capability._consume(
            campaign_id=CAMPAIGN_ID,
            inputs_digest=built.inputs["inputsDigest"],
            ledger_root=built.ledger,
        )
        with pytest.raises(ValueError, match="binding differs"):
            campaign.transport_bound(
                value,
                binding=other,
                binding_digest=hashlib.sha256(other).hexdigest(),
                capability=capability,
            )
        with pytest.raises(ValueError, match="binding differs"):
            campaign.transport_bound(
                value,
                binding=other,
                binding_digest=binding_digest,
                capability=capability,
            )
        # The lane's own check runs even when the core's binding is satisfied.
        with pytest.raises(ValueError, match="worker source digest differs"):
            campaign.verify_worker_binding(
                other, hashlib.sha256(other).hexdigest(), None
            )
    finally:
        admission.revoke_production_capability(capability)
    assert oracle.calls == []


def test_an_early_stop_before_any_create_retires_as_no_data(
    built, tmp_path, monkeypatch
):
    """A baseline drift at the database slot stops the run with nothing sent."""
    oracle = oracle_wire(monkeypatch, built.plan)
    drifted = {**DATABASE_BODY, "uid": "another-database"}
    monkeypatch.setitem(globals(), "DATABASE_BODY", drifted)
    original = preflight.management_transport

    def drift(slot, token, **kwargs):
        response = original(slot, token, **kwargs)
        if slot == "database":
            response["body"] = drifted
        return response

    monkeypatch.setattr(preflight, "management_transport", drift)
    result = run(built, tmp_path)
    assert result["reservationReleased"] is False
    assert result["failure"] == "ValueError"
    assert oracle.calls == []
    output = tmp_path / "output"
    receipt = json.loads((output / "receipt.json").read_bytes())
    assert receipt["stopPoint"] == "schedule-not-started"
    assert receipt["collection"] is None
    assert receipt["productionExecuted"] is False
    assert receipt["mayHaveCreated"] is False
    assert receipt["preflightComplete"] is False
    assert [row["id"] for row in receipt["managementEvidence"]] == [
        "observation:oauth-tokeninfo",
        "observation:project",
        "observation:database",
    ]
    assert receipt["managementEvidence"][-1]["response"]["complete"] is False
    verdict = admission.classify_stop(receipt)
    assert verdict["disposition"] == "aborted-no-data"
    ledger = reservations.Ledger(built.ledger)
    row = ledger.snapshot()["reservations"][receipt["ticket"]["reservation"]]
    assert row["state"] == "held"
    snapshot = _prove_workers_exited(output / "gate")
    record = admission.no_data_abort_record(receipt, output / "receipt.json", snapshot)
    ledger.abort_no_data(receipt["ticket"], record)
    row = ledger.snapshot()["reservations"][receipt["ticket"]["reservation"]]
    assert row["state"] == "aborted-no-data"
    assert (
        shared_gate.Gate(output / "gate", gate_projection.JOB).snapshot()["stopped"]
        is True
    )


def test_a_credential_refusal_is_named_and_sends_nothing(built, tmp_path, monkeypatch):
    oracle = oracle_wire(monkeypatch, built.plan)
    built.write_handoff("0" * 64)
    result = run(built, tmp_path)
    assert result["failure"] == "CredentialHandoffRefused"
    assert result["reservationReleased"] is False
    assert oracle.calls == []
    receipt = json.loads((tmp_path / "output/receipt.json").read_bytes())
    assert receipt["stopPoint"] == "schedule-not-started"
    assert receipt["managementEvidence"] == []
    assert receipt["chargedCalls"] == 0
    assert admission.classify_stop(receipt)["retirableAsNoData"] is True


def test_a_later_stop_recovers_every_created_document(built, tmp_path, monkeypatch):
    """A transport failure at a cursor slot: the ladder removes what the seed made."""
    oracle = oracle_wire(monkeypatch, built.plan)
    oracle.fail_kind = "cursor-start-at-value"
    result = run(built, tmp_path)
    assert result["reservationReleased"] is False
    assert result["failure"] == "collection-incomplete"
    output = tmp_path / "output"
    receipt = json.loads((output / "receipt.json").read_bytes())
    bundle = receipt["collection"]
    by_kind = {row["kind"]: row for row in bundle["rows"]}
    assert by_kind["cursor-start-at-value"]["status"] == "failed"
    assert by_kind["cursor-start-at-value"]["failure"] == "ConnectionError"
    assert by_kind["cursor-negative-offset"]["skipReason"] == "aborted-after-failure"
    cleanup = {row["kind"]: row for row in bundle["cleanup"]["rows"]}
    assert cleanup["cleanup-ownership-read"]["status"] == "pass"
    # The batch delete addresses no single resource, so after the observation
    # ended the Gate refused it by name; the ladder deleted the documents.
    assert cleanup["cleanup-seed-delete"]["status"] == "failed"
    assert cleanup["cleanup-seed-delete"]["failure"] == "ObservationAbandoned"
    assert cleanup["cleanup-root-delete"]["status"] == "pass"
    assert cleanup["cleanup-verify-root-absence"]["status"] == "pass"
    assert receipt["ladderSummary"]["deleted"] == 20
    assert receipt["ladderSummary"]["provenAbsent"] == 21
    assert receipt["ladderSummary"]["failed"] == 0
    assert receipt["ladderAbsenceComplete"] is True
    assert receipt["residualSummary"]["complete"] is False
    assert receipt["stopPoint"] == "observation-incomplete"
    assert receipt["mayHaveCreated"] is True
    assert not oracle.live
    verdict = admission.classify_stop(receipt)
    assert verdict["disposition"] == "abandoned-cleanup-close"
    gate = shared_gate.Gate(output / "gate", gate_projection.JOB).snapshot()
    assert gate["jobs"][gate_projection.JOB]["stopReason"] == "observation-incomplete"
    assert gate["jobs"][gate_projection.JOB]["scheduleDone"] == 102
    assert shared_gate.abandoned_cleanup_complete(gate) == sorted(
        built.plan["ownedResources"]
    )
    ledger = reservations.Ledger(built.ledger)
    snapshot = _prove_workers_exited(output / "gate")
    ledger.close_after_abandon(
        receipt["ticket"],
        {
            "kind": reservations.ABANDON_KIND,
            "ticket": receipt["ticket"],
            "gateDigest": digest(snapshot),
            "receiptPath": str((output / "receipt.json").resolve()),
            "receiptDigest": digest(receipt),
        },
    )
    assert (
        ledger.snapshot()["reservations"][receipt["ticket"]["reservation"]]["state"]
        == "closed-after-abandon"
    )


def test_a_lost_create_answer_is_never_retired_as_no_data(built, tmp_path, monkeypatch):
    oracle = oracle_wire(monkeypatch, built.plan)
    oracle.fail_kind = "create-only-patch"
    result = run(built, tmp_path)
    assert result["reservationReleased"] is False
    receipt = json.loads((tmp_path / "output/receipt.json").read_bytes())
    assert receipt["stopPoint"] == "create-uncertain"
    verdict = admission.classify_stop(receipt)
    assert verdict["disposition"] == "owner-escalation"
    with pytest.raises(ValueError, match="not a no-data stop"):
        admission.validate_no_data_receipt(receipt)
    # The oracle applied the create before the answer was lost, as production could.
    assert oracle.live == {
        built.plan["ownedScope"]: {"marker": {"stringValue": CAMPAIGN_ID}}
    }


def test_the_comparator_is_indeterminate_on_an_incomplete_bundle(
    built, tmp_path, monkeypatch
):
    oracle = oracle_wire(monkeypatch, built.plan)
    oracle.fail_kind = "cursor-start-at-value"
    run(built, tmp_path)
    receipt = json.loads((tmp_path / "output/receipt.json").read_bytes())
    comparison = compare_evidence(receipt["collection"], local_bundle(tmp_path))
    assert comparison["classification"] == "INDETERMINATE"
    assert comparison["promotionReady"] is False


def test_production_refuses_loopback_and_local_refuses_non_loopback():
    with pytest.raises(PermissionError):
        production.validate_collector_options(
            {"target": "production", "origin": "http://127.0.0.1:8080"}
        )
    with pytest.raises(PermissionError):
        production.validate_collector_options(
            {"target": "local", "origin": wire.PRODUCTION_ORIGIN}
        )
    with pytest.raises(PermissionError):
        wire.production_request(
            {
                "method": "GET",
                "path": "/v1/projects/p/databases/(default)/documents/a/b",
                "body": None,
            },
            TOKEN,
            origin="http://127.0.0.1:8080",
        )
    assert (
        production.validate_collector_options(
            {"target": "production", "origin": wire.PRODUCTION_ORIGIN}
        )["target"]
        == "production"
    )


def test_the_saved_evidence_chain_refuses_a_replaced_row(built, tmp_path, monkeypatch):
    oracle_wire(monkeypatch, built.plan)
    run(built, tmp_path)
    output = tmp_path / "output"
    production.verify_saved(
        output,
        expected_inputs_digest=built.inputs["inputsDigest"],
        ledger_root=built.ledger,
    )
    row = output / "collection/row-observation-05.json"
    row.chmod(0o600)
    row.write_text(row.read_text() + " ")
    with pytest.raises(ValueError, match="saved evidence file differs"):
        production.verify_saved(
            output,
            expected_inputs_digest=built.inputs["inputsDigest"],
            ledger_root=built.ledger,
        )
