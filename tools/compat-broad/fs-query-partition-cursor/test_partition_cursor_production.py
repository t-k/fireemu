"""Offline O8 integration for the partition/cursor campaign.

Real capabilities, real Gate journals and a temporary shared Ledger, never the
canonical one. The wire is an injected offline oracle: no socket is opened, no
credential is read, no production origin is contacted.
"""

import copy
import hashlib
import json
import os
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
import partition_cursor_collector as collector
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


def _prove_workers_exited(gate_path, monkeypatch):
    """Test scaffolding: the in-process coordinator is alive, a real run's is not.

    The Gate state is left untouched, so the receipt's Gate digest and the
    terminal record's agree exactly as they do after a real process exit; only
    the liveness probe is answered as the kernel would for an exited worker.
    """
    snapshot = shared_gate.Gate(gate_path, gate_projection.JOB).snapshot()
    recorded = {
        snapshot["coordinatorPid"],
        snapshot["jobs"][gate_projection.JOB]["pid"],
    }
    real_kill = os.kill

    def exited(pid, signal):
        if pid in recorded and signal == 0:
            raise ProcessLookupError(pid)
        return real_kill(pid, signal)

    monkeypatch.setattr(os, "kill", exited)
    return snapshot


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
    assert receipt["ladderEvidenceComplete"] is True
    assert receipt["ladder"]["raw"]["complete"] is True
    assert receipt["ladder"]["raw"]["complete"] == receipt["ladderEvidenceComplete"]
    assert receipt["residualSummary"] == {"complete": True, "documents": 0}
    assert receipt["residualEvidenceComplete"] is True
    assert receipt["residual"]["raw"]["complete"] is True
    assert receipt["residual"]["raw"]["complete"] == receipt["residualEvidenceComplete"]
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
    snapshot = _prove_workers_exited(output / "gate", monkeypatch)
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
    snapshot = _prove_workers_exited(output / "gate", monkeypatch)
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


def _rewrite_receipt_and_release(output, mutate):
    """Test scaffolding: a consistent receipt/release rewrite by someone who
    controls the evidence directory but not the Ledger-anchored Gate digest."""
    receipt = json.loads((output / "receipt.json").read_bytes())
    mutate(receipt)
    for name in ("receipt.json", "release.json"):
        (output / name).chmod(0o600)
        (output / name).unlink()
    production._write_receipt(output / "receipt.json", receipt)
    release = {
        "receiptDigest": digest(receipt),
        "ticket": receipt["ticket"],
        "failure": None,
        "reservationFinal": reservations.Ledger(output.parent / "ledger").snapshot()[
            "reservations"
        ][receipt["ticket"]["reservation"]],
    }
    production._write_receipt(output / "release.json", release)


def test_the_slot_eight_early_end_is_zero_wire_skipped_and_recovered(
    built, tmp_path, monkeypatch
):
    """A missing page token is a zero-wire skip for a non-creating read."""
    oracle = oracle_wire(monkeypatch, built.plan, partitions=0, page_token="")
    result = run(built, tmp_path)
    assert result["reservationReleased"] is True
    assert result["failure"] is None
    output = tmp_path / "output"
    receipt = json.loads((output / "receipt.json").read_bytes())
    bundle = receipt["collection"]
    statuses = {
        row["kind"]: (row["status"], row.get("skipReason"), row.get("failure"))
        for row in bundle["rows"]
    }
    assert statuses["partition-count-4-page-size-2"] == ("pass", None, None)
    assert statuses["partition-page-token-continuation"] == (
        "skipped",
        "no-page-token",
        None,
    )
    assert statuses["partition-not-collection-group"] == ("pass", None, None)
    assert statuses["cursor-start-at-value"] == ("pass", None, None)
    assert receipt["scheduleStall"] is None
    cleanup = {row["kind"]: row for row in bundle["cleanup"]["rows"]}
    assert cleanup["cleanup-seed-delete"]["status"] == "pass"
    assert cleanup["cleanup-root-delete"]["status"] == "pass"
    assert cleanup["cleanup-verify-root-absence"]["status"] == "pass"
    assert receipt["ladderSummary"]["deleted"] == 0
    assert receipt["ladderSummary"]["provenAbsent"] == 21
    assert receipt["ladderSummary"]["failed"] == 0
    assert receipt["ladderAbsenceComplete"] is True
    assert receipt["residualSummary"]["complete"] is True
    assert receipt["stopPoint"] is None
    assert receipt["mayHaveCreated"] is True
    assert bundle["status"] == "pass"
    assert not oracle.live
    # 14 observation slots sent (one continuation skipped), ownership read,
    # root delete/absence, 20 ladder reads/deletes/absences, root read/absence.
    assert len(oracle.calls) == 14 + 3 + 60 + 2
    assert receipt["chargedCalls"] == len(oracle.calls) + 7
    comparison = compare_evidence(bundle, local_bundle(tmp_path))
    assert comparison["classification"] == "SEMANTIC_MISMATCH"
    assert admission.classify_stop(receipt)["disposition"] == "owner-escalation"
    assert (
        reservations.Ledger(built.ledger)
        .snapshot()["reservations"][receipt["ticket"]["reservation"]]["state"]
        == "released"
    )


def test_a_partial_creation_closes_after_typed_absence_proof(
    built, tmp_path, monkeypatch
):
    """A partial create closes after every assigned resource has typed absence.

    Only the root has a creation proof; the updated Shared Gate requires proof
    for created resources and typed absence for every assigned resource.
    """
    oracle = oracle_wire(monkeypatch, built.plan)
    original = oracle._body

    def refuse_seed(request):
        if request["kind"] == "seed-commit":
            return 400, {"error": {"code": 400, "status": "INVALID_ARGUMENT"}}
        return original(request)

    monkeypatch.setattr(oracle, "_body", refuse_seed)
    result = run(built, tmp_path)
    assert result["reservationReleased"] is False
    output = tmp_path / "output"
    receipt = json.loads((output / "receipt.json").read_bytes())
    assert receipt["ladderAbsenceComplete"] is True
    assert receipt["creationProofCount"] == 1
    assert receipt["resourceCount"] == 21
    assert receipt["stopPoint"] == "observation-incomplete"
    verdict = admission.classify_stop(receipt)
    assert verdict["disposition"] == "owner-escalation"
    assert "partially created" in verdict["reason"]
    assert not oracle.live
    ledger = reservations.Ledger(built.ledger)
    snapshot = _prove_workers_exited(output / "gate", monkeypatch)
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


def test_a_foreign_root_at_the_preflight_read_is_never_deleted_and_not_no_data(
    built, tmp_path, monkeypatch
):
    """The root already exists: one non-creating read was sent, the collector
    stops, the ladder refuses to delete a document without a creation proof,
    and the stop is the owner's, not a no-data abort."""
    oracle = oracle_wire(monkeypatch, built.plan)
    foreign = {"marker": {"stringValue": "someone-else"}}
    oracle.live[built.plan["ownedScope"]] = foreign
    result = run(built, tmp_path)
    assert result["reservationReleased"] is False
    receipt = json.loads((tmp_path / "output/receipt.json").read_bytes())
    assert receipt["stopPoint"] == "preflight-absence"
    assert receipt["dataDispatches"] >= 1
    assert receipt["productionExecuted"] is True
    verdict = admission.classify_stop(receipt)
    assert verdict["disposition"] == "owner-escalation"
    assert verdict["retirableAsNoData"] is False
    with pytest.raises(ValueError, match="not a no-data stop"):
        admission.validate_no_data_receipt(receipt)
    assert oracle.live == {built.plan["ownedScope"]: foreign}
    # The Gate itself skipped every cleanup slot: no creation proof, nothing
    # to delete, and the one request sent was the preflight read.
    assert len(oracle.calls) == 1
    assert not any(call["method"] == "DELETE" for call in oracle.calls)
    ladder = {row["index"]: row for row in receipt["ladder"]["rows"]}
    assert ladder[1]["skipReason"] == "creating-slot-never-dispatched"
    assert receipt["ladderSummary"]["absentAtRead"] == 0
    assert receipt["ladderAbsenceComplete"] is False


def test_a_no_data_receipt_with_a_dispatch_is_not_retirable(
    built, tmp_path, monkeypatch
):
    """A03: `dataDispatches` is load-bearing in the no-data classification."""
    oracle_wire(monkeypatch, built.plan)
    built.write_handoff("0" * 64)
    run(built, tmp_path)
    receipt = json.loads((tmp_path / "output/receipt.json").read_bytes())
    assert admission.classify_stop(receipt)["retirableAsNoData"] is True
    assert (
        admission.classify_stop({**receipt, "dataDispatches": 1})["retirableAsNoData"]
        is False
    )
    with pytest.raises(ValueError, match="not a no-data stop"):
        admission.validate_no_data_receipt({**receipt, "dataDispatches": 1})


def test_a_document_that_reappears_after_its_delete_refuses_release(
    built, tmp_path, monkeypatch
):
    """P02: the root answers 200 at its typed-absence read, the last slot of
    the schedule, after both residual scans found nothing; every other
    predicate holds, and the reservation stays held."""
    oracle = oracle_wire(monkeypatch, built.plan)
    ghost = built.plan["ownedResources"][0]
    original = oracle._body

    def revive(request):
        if (
            request["kind"] == "ladder-typed-absence"
            and request["path"] == "/v1/" + ghost
        ):
            oracle.live[ghost] = {"marker": {"stringValue": "revived"}}
        return original(request)

    monkeypatch.setattr(oracle, "_body", revive)
    result = run(built, tmp_path)
    assert result["reservationReleased"] is False
    assert result["failure"] == "collection-incomplete"
    receipt = json.loads((tmp_path / "output/receipt.json").read_bytes())
    assert receipt["collection"]["status"] == "pass"
    assert receipt["ladderSummary"]["failed"] == 0
    assert receipt["ladderSummary"]["provenAbsent"] == 20
    assert receipt["ladderAbsenceComplete"] is False
    assert receipt["residualSummary"] == {"complete": True, "documents": 0}
    assert receipt["stopPoint"] == "recovery-incomplete"
    assert admission.classify_stop(receipt)["disposition"] == "owner-escalation"
    # The predicate refused before the postflight and before Gate.finish: no
    # recovery management slot was charged for a run that cannot release.
    assert receipt["postflightComplete"] is False
    assert [row["id"] for row in receipt["managementEvidence"]] == [
        "observation:oauth-tokeninfo",
        "observation:project",
        "observation:database",
        "observation:auth",
    ]
    assert (
        reservations.Ledger(built.ledger).snapshot()["reservations"][
            receipt["ticket"]["reservation"]
        ]["state"]
        == "held"
    )


def test_a_residual_document_under_the_owned_scope_refuses_release(
    built, tmp_path, monkeypatch
):
    """P03: the residual scan finds a document this run never created; the
    ladder and the collection are clean, and the reservation stays held."""
    oracle = oracle_wire(monkeypatch, built.plan)
    original = oracle._body
    stranger = built.plan["ownedScope"] + "/cur/stranger"

    def stranger_in_scan(request):
        status, body = original(request)
        if request["kind"] == "residual-cursor-scan":
            body = [
                {
                    "document": {
                        "name": stranger,
                        "fields": {"n": {"integerValue": "99"}},
                        "createTime": TIME,
                        "updateTime": TIME,
                    }
                }
            ]
        return status, body

    monkeypatch.setattr(oracle, "_body", stranger_in_scan)
    result = run(built, tmp_path)
    assert result["reservationReleased"] is False
    receipt = json.loads((tmp_path / "output/receipt.json").read_bytes())
    assert receipt["collection"]["status"] == "pass"
    assert receipt["ladderAbsenceComplete"] is True
    assert receipt["residualSummary"] == {"complete": True, "documents": 1}
    verdict = admission.classify_stop(receipt)
    assert verdict["disposition"] == "owner-escalation"
    assert "residual scan" in verdict["reason"]


def test_a_broken_reconstruction_refuses_release(built, tmp_path, monkeypatch):
    """P04: every row passes but the ranges do not rebuild the baseline; the
    collector reports `incomplete` and the reservation stays held."""
    oracle = oracle_wire(monkeypatch, built.plan)
    original = oracle._body

    def truncate(request):
        status, body = original(request)
        if request["kind"] == "partition-reconstruction-range-1":
            body = body[:2]
        return status, body

    monkeypatch.setattr(oracle, "_body", truncate)
    result = run(built, tmp_path)
    assert result["reservationReleased"] is False
    receipt = json.loads((tmp_path / "output/receipt.json").read_bytes())
    bundle = receipt["collection"]
    assert all(
        row["status"] in ("pass", "skipped")
        for row in bundle["rows"] + bundle["cleanup"]["rows"]
    )
    assert bundle["reconstruction"]["matches"] is False
    assert bundle["status"] == "incomplete"
    assert receipt["ladderAbsenceComplete"] is True
    assert receipt["residualSummary"] == {"complete": True, "documents": 0}
    assert not oracle.live


@pytest.mark.parametrize(
    "field,value",
    [
        ("ladderAbsenceComplete", False),
        ("residualSummary", {"complete": True, "documents": 1}),
        ("ladderEvidenceComplete", False),
        ("residualEvidenceComplete", False),
    ],
    ids=[
        "P06-ladder-absence",
        "P07-residual",
        "P06b-ladder-evidence",
        "P07b-residual-evidence",
    ],
)
def test_the_saved_chain_refuses_a_receipt_that_withdraws_a_release_predicate(
    built, tmp_path, monkeypatch, field, value
):
    """P06/P07: a receipt and release rewritten consistently, without the
    Ledger-anchored Gate digest changing, must still be refused when the
    receipt no longer claims the predicate the release depended on."""
    oracle_wire(monkeypatch, built.plan)
    run(built, tmp_path)
    output = tmp_path / "output"
    production.verify_saved(
        output,
        expected_inputs_digest=built.inputs["inputsDigest"],
        ledger_root=built.ledger,
    )
    _rewrite_receipt_and_release(
        output, lambda receipt: receipt.__setitem__(field, value)
    )
    with pytest.raises(ValueError, match="saved route journal differs"):
        production.verify_saved(
            output,
            expected_inputs_digest=built.inputs["inputsDigest"],
            ledger_root=built.ledger,
        )


def test_a_credential_that_cannot_cover_a_slot_is_refused_before_the_gate_charges_it(
    built, tmp_path, monkeypatch
):
    """The data token is fetched before `dispatch_slot`, so an unusable
    credential is a refusal, not a lost answer that leaves a create uncertain."""
    oracle = oracle_wire(monkeypatch, built.plan)
    original = preflight.management_transport

    def short_lived(slot, token, **kwargs):
        response = original(slot, token, **kwargs)
        if slot == "oauth-tokeninfo":
            response["body"]["expires_in"] = 3600
        return response

    monkeypatch.setattr(preflight, "management_transport", short_lived)
    real_data_token = preflight.ManagementSession.data_token

    def failing_token(self, deadline):
        if self.credential is not None and any(
            call["kind"] == "seed-commit" for call in oracle.calls
        ):
            self.credential.fail()
        return real_data_token(self, deadline)

    monkeypatch.setattr(preflight.ManagementSession, "data_token", failing_token)
    result = run(built, tmp_path)
    assert result["reservationReleased"] is False
    receipt = json.loads((tmp_path / "output/receipt.json").read_bytes())
    bundle = receipt["collection"]
    failed = [row for row in bundle["rows"] if row["status"] == "failed"]
    assert failed[0]["kind"] == "baseline-group-name-order"
    assert failed[0]["failure"] == "CredentialUnavailable"
    gate = shared_gate.Gate(tmp_path / "output/gate", gate_projection.JOB).snapshot()
    assert [
        event["index"] for event in gate["events"] if event["phase"] == "observation"
    ] == [0, 1, 2]
    assert shared_gate.unconfirmed_creates(gate, gate_projection.JOB) == 0
    assert receipt["stopPoint"] == "recovery-incomplete"


def test_a_request_outside_the_frozen_slot_map_is_refused_by_name(
    built, tmp_path, monkeypatch
):
    """P12: a collector that sent a request the projection never froze, such
    as the local shadow's `verification` residual reads, is refused before
    the Gate sees it; the refusal is named, not an indexing error."""
    oracle = oracle_wire(monkeypatch, built.plan)
    real_collector = campaign.collector
    seen = {}

    def probing_collector(plan, transmit, output):
        stray = {
            "phase": "verification",
            "index": 0,
            "kind": "residual-scan",
            "method": "POST",
            "path": "/v1/" + plan["databaseRoot"] + ":runQuery",
            "body": {
                "structuredQuery": {
                    "from": [
                        {
                            "collectionId": plan["groupCollection"],
                            "allDescendants": True,
                        }
                    ]
                }
            },
        }
        try:
            transmit(stray)
        except Exception as error:  # noqa: BLE001 -- the class name is the assertion
            seen["error"] = error
        return real_collector(plan, transmit, output)

    monkeypatch.setattr(campaign, "collector", probing_collector)
    result = run(built, tmp_path)
    assert type(seen["error"]).__name__ == "GateRefusal"
    assert "outside the frozen slot map" in str(seen["error"])
    assert not any(call["kind"] == "residual-scan" for call in oracle.calls)
    assert result["reservationReleased"] is True


def _ladder_row_zero_index(built):
    """The Gate's own recovery-schedule index for the ladder's first slot.

    `dispatch_native` names each row and its raw sidecar by this native Gate
    index, not by a ladder-local counter, so the target filename for the
    ladder's first dispatched slot must come from the same frozen slot map
    `execute()` itself builds from the plan.
    """
    return gate_projection.slot_map(built.plan)[("ladder", 0)][1]


def _break_raw_write(monkeypatch, target_filename):
    """Fail exactly one raw sidecar write, by its published filename."""
    original = collector._publish_bytes

    def failing(directory_fd, filename, payload):
        if filename == target_filename:
            raise OSError("injected raw sidecar write failure")
        return original(directory_fd, filename, payload)

    monkeypatch.setattr(collector, "_publish_bytes", failing)


def _break_row_write(monkeypatch, target_filename):
    """Fail exactly one JSON row write, by its published filename."""
    original = collector._publish

    def failing(directory_fd, filename, value):
        if filename == target_filename:
            raise OSError("injected row write failure")
        return original(directory_fd, filename, value)

    monkeypatch.setattr(collector, "_publish", failing)


def test_a_ladder_raw_write_failure_blocks_readiness_but_cleanup_continues(
    built, tmp_path, monkeypatch
):
    """P13: the ladder journal's raw sidecar write fails on one dispatched
    row; the recovery ladder still proves every seeded document absent, but
    the run must not be released as ready with that evidence missing."""
    oracle = oracle_wire(monkeypatch, built.plan)
    _break_raw_write(monkeypatch, f"ladder-{_ladder_row_zero_index(built):02d}.raw")
    result = run(built, tmp_path)
    assert result["failure"] == "collection-incomplete"
    assert result["reservationReleased"] is False
    output = tmp_path / "output"
    receipt = json.loads((output / "receipt.json").read_bytes())
    assert receipt["ladderSummary"]["failed"] == 0
    assert receipt["ladderAbsenceComplete"] is True
    assert receipt["ladderEvidenceComplete"] is False
    # The journal's own summary must report the same verified verdict as
    # `ladderEvidenceComplete`, never the bare publication flag: a raw
    # sidecar write can fail without ever touching `publication["complete"]`.
    assert receipt["ladder"]["raw"]["complete"] is False
    assert receipt["ladder"]["raw"]["complete"] == receipt["ladderEvidenceComplete"]
    assert not (output / "release.json").exists()
    assert not oracle.live
    with pytest.raises(ValueError):
        production.verify_saved(
            output,
            expected_inputs_digest=built.inputs["inputsDigest"],
            ledger_root=built.ledger,
        )


def test_a_ladder_row_write_failure_blocks_readiness_but_cleanup_continues(
    built, tmp_path, monkeypatch
):
    """P14: the ladder journal's JSON row write fails on one dispatched row;
    cleanup still runs to completion, but the run must not be released."""
    oracle = oracle_wire(monkeypatch, built.plan)
    _break_row_write(
        monkeypatch, f"row-ladder-{_ladder_row_zero_index(built):02d}.json"
    )
    result = run(built, tmp_path)
    assert result["failure"] == "collection-incomplete"
    assert result["reservationReleased"] is False
    output = tmp_path / "output"
    receipt = json.loads((output / "receipt.json").read_bytes())
    assert receipt["ladderSummary"]["failed"] == 0
    assert receipt["ladderAbsenceComplete"] is True
    assert receipt["ladderEvidenceComplete"] is False
    assert not (output / "release.json").exists()
    assert not oracle.live
    with pytest.raises(ValueError):
        production.verify_saved(
            output,
            expected_inputs_digest=built.inputs["inputsDigest"],
            ledger_root=built.ledger,
        )


def test_a_residual_raw_write_failure_blocks_readiness_but_cleanup_continues(
    built, tmp_path, monkeypatch
):
    """P15: the residual journal's raw sidecar write fails; the residual
    scans still ran and found nothing, but the run must not be released as
    ready with that evidence missing."""
    oracle = oracle_wire(monkeypatch, built.plan)
    _break_raw_write(monkeypatch, "residual-00.raw")
    result = run(built, tmp_path)
    assert result["failure"] == "collection-incomplete"
    assert result["reservationReleased"] is False
    output = tmp_path / "output"
    receipt = json.loads((output / "receipt.json").read_bytes())
    assert receipt["residualSummary"] == {"complete": True, "documents": 0}
    assert receipt["residualEvidenceComplete"] is False
    # Same verified verdict as `residualEvidenceComplete`, not the bare
    # publication flag (see the ladder raw-write-failure test above).
    assert receipt["residual"]["raw"]["complete"] is False
    assert receipt["residual"]["raw"]["complete"] == receipt["residualEvidenceComplete"]
    assert not (output / "release.json").exists()
    assert not oracle.live
    with pytest.raises(ValueError):
        production.verify_saved(
            output,
            expected_inputs_digest=built.inputs["inputsDigest"],
            ledger_root=built.ledger,
        )


def test_a_residual_row_write_failure_blocks_readiness_but_cleanup_continues(
    built, tmp_path, monkeypatch
):
    """P16: the residual journal's JSON row write fails; the residual scans
    still ran and found nothing, but the run must not be released."""
    oracle = oracle_wire(monkeypatch, built.plan)
    _break_row_write(monkeypatch, "row-residual-00.json")
    result = run(built, tmp_path)
    assert result["failure"] == "collection-incomplete"
    assert result["reservationReleased"] is False
    output = tmp_path / "output"
    receipt = json.loads((output / "receipt.json").read_bytes())
    assert receipt["residualSummary"] == {"complete": True, "documents": 0}
    assert receipt["residualEvidenceComplete"] is False
    assert not (output / "release.json").exists()
    assert not oracle.live
    with pytest.raises(ValueError):
        production.verify_saved(
            output,
            expected_inputs_digest=built.inputs["inputsDigest"],
            ledger_root=built.ledger,
        )


def _journal_row(monkeypatch, tmp_path, *, break_raw_write=False):
    """Record one dispatched row on a fresh `_Journal`, optionally with a
    failing raw sidecar write, and return the journal before it is closed."""
    if break_raw_write:
        _break_raw_write(monkeypatch, "observation-00.raw")
    journal = production._Journal(tmp_path / "journal")
    row = collector._row("observation", 0, {"kind": "test-kind"})
    row["status"] = "pass"
    receipt = {"rawBody": b"{}", "complete": True, "byteCount": 2}
    journal.record(row, receipt)
    return journal


def test_a_journal_raw_write_failure_makes_raw_complete_false_and_matches_evidence_complete(
    tmp_path, monkeypatch
):
    """The journal's own summary must not claim complete raw evidence when a
    raw sidecar write failed: `raw.complete` must equal `evidence_complete()`,
    never the bare `publication["complete"]` flag (which a raw write failure
    never touches)."""
    journal = _journal_row(monkeypatch, tmp_path, break_raw_write=True)
    evidence_complete = journal.evidence_complete()
    summary = journal.summary()
    journal.close()
    assert evidence_complete is False
    assert summary["raw"]["complete"] is False
    assert summary["raw"]["complete"] == evidence_complete
    # The bug this guards against: `publication["complete"]` alone would
    # still read True here, since a raw sidecar write failure is recorded on
    # the row, not on `publication`.
    assert summary["publication"]["complete"] is True


def test_a_journal_with_clean_raw_writes_reports_raw_complete_true(tmp_path):
    """Happy path: unchanged. A clean dispatched row makes `raw.complete`
    true and equal to `evidence_complete()`."""
    journal = production._Journal(tmp_path / "journal")
    row = collector._row("observation", 0, {"kind": "test-kind"})
    row["status"] = "pass"
    receipt = {"rawBody": b"{}", "complete": True, "byteCount": 2}
    journal.record(row, receipt)
    evidence_complete = journal.evidence_complete()
    summary = journal.summary()
    journal.close()
    assert evidence_complete is True
    assert summary["raw"]["complete"] is True
    assert summary["raw"]["complete"] == evidence_complete


def test_a_journal_summary_before_evidence_complete_refuses_to_guess(tmp_path):
    """`summary()` must not report a raw-evidence verdict it never verified;
    calling it before `evidence_complete()` is a caller error, not a silent
    True."""
    journal = production._Journal(tmp_path / "journal")
    try:
        with pytest.raises(RuntimeError):
            journal.summary()
    finally:
        journal.close()
