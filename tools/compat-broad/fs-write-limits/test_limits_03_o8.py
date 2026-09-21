"""Offline O8 admission and execution tests for FS-WRITE-LIMITS-03.

Every artifact here is built locally. No production request is made, no
credential is read, no origin outside the process is contacted, and the shared
Ledger is only ever a temporary one under the test's own directory. The wire is
the independent limit model of `test_campaign_03`, driven through the real
capability, the real Gate and the real Ledger.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
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

import compiler_03
import limits_03_admission as admission
import limits_03_descriptor as campaign
import limits_03_o8 as launcher
import limits_03_preflight as preflight
import limits_03_production as production
import limits_03_remote_transport as remote
import reservations
import shared_gate
from batch_contract import database_evidence
from broad_contract import digest
from o8_campaign import CAMPAIGN_APPROVAL_FIELDS, REQUIRED_MEMBERS, CampaignDescriptor
from test_campaign_03 import (
    Responder,
    _commit_error,
    _invalid,
    _path_error,
    _undecodable,
)

NONCE = "b" * 32
PROJECT_BODY = {"projectId": "fireemu-35fe6", "projectNumber": "592603257417"}
DATABASE_BODY = {
    "name": "projects/fireemu-35fe6/databases/(default)",
    "uid": "fixture-uid",
    "type": "FIRESTORE_NATIVE",
    "databaseEdition": "STANDARD",
    "locationId": "us-central1",
}
AUTH_BODY = {"name": "projects/592603257417/config", "mfa": {"state": "DISABLED"}}
# Proto3 JSON omits empty and false members, so a deployed exemption reads as
# an empty index configuration.
EXEMPT_FIELD_BODY = {"name": preflight.INDEX_FIELD, "indexConfig": {}}
DEFAULT_FIELD_BODY = {
    "name": preflight.INDEX_FIELD,
    "indexConfig": {
        "indexes": [
            {
                "queryScope": "COLLECTION",
                "fields": [{"fieldPath": "*", "order": "ASCENDING"}],
                "state": "READY",
            }
        ],
        "usesAncestorConfig": True,
        "ancestorField": (
            "projects/fireemu-35fe6/databases/(default)/collectionGroups/"
            "__default__/fields/*"
        ),
    },
}
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
    monkeypatch.setattr(preflight, "time", clock)
    monkeypatch.setattr(preflight.shared, "time", clock)
    monkeypatch.setattr(production, "time", clock)

    def management_fixture(slot, token, **_kwargs):
        assert token == TOKEN
        body = {
            "project": PROJECT_BODY,
            "database": DATABASE_BODY,
            "auth": AUTH_BODY,
            "index-exemption": EXEMPT_FIELD_BODY,
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
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-qm",
            "fixture",
        ],
    ):
        subprocess.run(["git", "-C", str(source), *args], check=True)
    return source


def owner_permission(plan, commit, artifact_digest, inputs):
    return {
        **campaign.permission_bindings(plan, commit, artifact_digest, inputs),
        "ownerIdentity": "offline-fixture-not-permission",
        "permissionReference": "offline-fixture",
        "recoveryOwner": "offline-recovery",
        "credentialPrincipal": {
            "clientId": "offline-client",
            "subject": "offline-subject",
            "requiredScopes": [campaign.PRINCIPAL_SCOPE],
        },
        "databaseProjectionDigest": database_evidence(DATABASE_BODY)[
            "projectionDigest"
        ],
        "authConfigDigest": digest(AUTH_BODY),
        "indexExemptionDeployedBy": "offline-fixture-commander",
        "issuedAt": time.time() - 1,
        "expiresAt": time.time() + 4800,
    }


class Admission:
    """A complete, locally built O7 artifact set for the limits-03 campaign."""

    def __init__(self, tmp_path, *, permission_overrides=None):
        self.descriptor = campaign.descriptor()
        self.source = frozen_checkout(tmp_path)
        self.commit = subprocess.check_output(
            ["git", "-C", str(self.source), "rev-parse", "HEAD"], text=True
        ).strip()
        self.artifact_path = tmp_path / "artifact"
        self.artifact_path.write_bytes(b"retained limits-03 artifact")
        self.plan = self.descriptor.plan_compiler(NONCE)
        self.permission = owner_permission(
            self.plan,
            self.commit,
            hashlib.sha256(self.artifact_path.read_bytes()).hexdigest(),
            campaign.source_map(),
        )
        self.permission.update(permission_overrides or {})
        self.permission_path = tmp_path / "permission.json"
        self.permission_path.write_text(json.dumps(self.permission))
        self.inputs = admission.freeze_inputs(
            self.permission_path,
            self.plan,
            source_root=self.source,
            artifact_path=self.artifact_path,
        )
        self.ledger = tmp_path / "ledger"
        reservations.Ledger.create(self.ledger)
        self.manifest = {
            "kind": campaign.MANIFEST_KIND,
            "inputsDigest": self.inputs["inputsDigest"],
        }
        self.manifest_bytes = json.dumps(self.manifest).encode()
        self.manifest_path = tmp_path / "manifest.json"
        self.manifest_path.write_bytes(self.manifest_bytes)
        self.manifest_path.chmod(0o600)
        self.launcher_path = HERE / "limits_03_o8.py"
        self.approval = self._approval()
        self.approval_path = tmp_path / "approval.json"
        self.approval_path.write_text(json.dumps(self.approval))
        self.approval_path.chmod(0o600)
        self.handoff_path = tmp_path / "handoff.json"
        self.handoff_path.write_text(
            json.dumps(
                {
                    "kind": launcher.HANDOFF_KIND,
                    "permissionDigest": digest(self.permission),
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
            "campaignId": compiler_03.CAMPAIGN,
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
            "--inputs",
            str(inputs_path),
            "--approval",
            str(self.approval_path),
            "--manifest",
            str(self.manifest_path),
            "--permission",
            str(self.permission_path),
            "--source",
            str(self.source),
            "--artifact",
            str(self.artifact_path),
            "--ledger",
            str(self.ledger),
            "--output",
            str(tmp_path / "output"),
            "--credential-file",
            str(self.handoff_path),
        ]


@pytest.fixture
def built(tmp_path):
    return Admission(tmp_path)


class ExemptResponder(Responder):
    """The limit model with the declared single-field exemption deployed.

    A document under the exempt collection group generates no index entries,
    so the three index-entry limits do not apply to it; every other limit does.
    The local shadow cannot apply the exemption and excuses those rows, but a
    production run under the deployed exemption excuses nothing.
    """

    def _respond(self, operation):
        path, method = operation["path"], operation["method"]
        resource = path.removeprefix("/v1/").partition("?")[0]
        if method != "PATCH" or f"/{compiler_03.EXEMPT_COLLECTION}/" not in resource:
            return super()._respond(operation)
        error = _path_error(resource)
        if error:
            return 400, _invalid(error)
        fields = operation["body"]["fields"]
        if _undecodable(fields):
            return 400, _invalid("cannot decode value")
        error = _commit_error(resource, fields)
        if error and not error.startswith("FS-LIMIT-INDEX-"):
            return 400, _invalid(error)
        if resource in self.documents:
            return 409, _invalid("already exists")
        self._create(resource, fields)
        return 200, copy.deepcopy(self.documents[resource])


def wire_fixture(monkeypatch, *, fault=None):
    """Drive the independent limit model through the lane transport's slot binding."""
    calls = []
    responder = ExemptResponder()

    class StrictNames(ExemptResponder):
        """Refuses the accepted collection-id boundary one byte early."""

        def _respond(self, operation):
            if operation["method"] == "PATCH":
                resource = operation["path"].split("?", 1)[0].removeprefix("/v1/")
                segments = resource.split("/documents/", 1)[1].split("/")
                if any(
                    len(segment.encode()) >= compiler_03.COLLECTION_ID_MAX
                    for index, segment in enumerate(segments)
                    if index % 2 == 0
                ):
                    return 400, _invalid("collection id is too long")
            return super()._respond(operation)

    if fault == "mismatch":
        responder = StrictNames()

    def request(plan, phase, index, operation, token, *, deadline, **_kwargs):
        assert token == TOKEN
        remote.operation_for_slot(plan, phase, index, operation)
        calls.append((phase, index, copy.deepcopy(operation)))
        if fault == "preflight" and len(calls) == 1:
            return {"complete": False, "failure": "offline-preflight-failure"}
        if fault == "create" and operation["method"] in ("PATCH", "POST"):
            return {"complete": False, "failure": "offline-lost-response"}
        result = responder(operation, phase == "recovery", index, 0)
        raw = json.dumps(result["body"], separators=(",", ":")).encode()
        return {
            **result,
            "rawBodyBase64": base64.b64encode(raw).decode(),
            "bodyBytes": len(raw),
        }

    monkeypatch.setattr(remote, "request", request)
    return calls, responder


def test_the_descriptor_is_complete_and_its_figures_come_from_the_compiler():
    descriptor = campaign.descriptor()
    assert descriptor.campaign_id == compiler_03.CAMPAIGN
    assert descriptor.approval_fields == CAMPAIGN_APPROVAL_FIELDS
    assert len(descriptor.approval_fields) == 17
    assert descriptor.binds_campaign_id is True
    figures = campaign.budget_figures()
    plan = campaign.figure_plan()
    assert descriptor.campaign_seconds == plan["localGatePlan"]["wallSeconds"]
    assert descriptor.recovery_seconds == plan["localGatePlan"]["recoverySeconds"]
    assert descriptor.campaign_seconds <= compiler_03.GATE_WALL_SECONDS_MAX
    assert figures["requestUpperBound"] == 176 + 9
    assert figures["managementObservationRequests"] == 5
    assert figures["managementRecoveryRequests"] == 4
    assert figures["envelopeCostMicrousd"] == 40_000 + 185 * 100
    assert figures["dataCostMicrousd"] == 176 * 100
    assert campaign.ledger_budget() == {
        "requests": 185,
        "accounts": 1,
        "resources": 29,
        "costMicrousd": figures["envelopeCostMicrousd"],
    }
    assert descriptor.artifact_profile == (
        "limits-03-" + campaign.shadow_record()["sourceCommit"][:9]
    )
    assert (
        descriptor.window_seconds
        == figures["maxWallSeconds"] + (figures["recoveryReserveSeconds"])
    )


def test_the_figures_do_not_depend_on_the_nonce():
    for nonce in ("1" * 32, "f" * 32):
        plan = compiler_03.compile_limits_plan(campaign.PROJECT, "(default)", nonce)
        assert plan["localGatePlan"]["wallSeconds"] == campaign.campaign_seconds()
        assert plan["localGatePlan"]["recoverySeconds"] == campaign.recovery_seconds()
        assert plan["budgetAccounting"]["requestUpperBound"] == 176


@pytest.mark.parametrize("member", sorted(REQUIRED_MEMBERS))
def test_the_descriptor_refuses_a_missing_member(member):
    members = campaign.descriptor_members()
    del members[member]
    with pytest.raises(ValueError, match="requires every member"):
        CampaignDescriptor(**members)


def test_the_gate_charges_management_around_the_schedule():
    """The published wall and reserve cover what the Gate itself charges."""
    plan = campaign.figure_plan()
    job = plan["localGatePlan"]["jobs"]["limits"]
    charge = compiler_03.gate_charge(
        job["schedule"], job["recovery"], job["observation"] + job["recovery"]
    )
    gate = campaign.gate_plan(plan, permission_expires_at=time.time() + 4800)
    assert gate["observationRequests"] == 89 + 5
    assert gate["management"]["dispatchKind"] == "closed-v1"
    assert [slot["id"] for slot in gate["management"]["observation"]] == [
        "oauth-tokeninfo",
        "project",
        "database",
        "index-exemption",
        "auth",
    ]
    assert [slot["id"] for slot in gate["management"]["recovery"]] == [
        "project",
        "database",
        "index-exemption",
        "auth",
    ]
    assert gate["recoverySeconds"] >= charge["recoverySeconds"] + 4 * 13.25
    assert gate["wallSeconds"] - gate["recoverySeconds"] >= (
        charge["observationSeconds"] + 5 * 13.25
    )
    assert gate["costMicrousd"] == 185 * 100
    assert "ownershipMarker" not in gate


def test_slot_reservations_follow_the_body_and_the_response_ceiling():
    plan = campaign.figure_plan()
    for row, entry in zip(
        plan["requests"],
        plan["localGatePlan"]["jobs"]["limits"]["schedule"],
        strict=True,
    ):
        if row["body"] is not None:
            assert entry["seconds"] == compiler_03.TRANSPORT_CEILING_SECONDS
        elif row["responseByteLimit"] > compiler_03.DEFAULT_RESPONSE_BYTES:
            assert entry["seconds"] == compiler_03.READBACK_SECONDS
        else:
            assert entry["seconds"] == compiler_03.SMALL_REQUEST_SECONDS
    assert remote.slot_timeout({"body": None}, 65536) == 3.0
    assert remote.slot_timeout({"body": None}, 65537) == 5.0
    assert remote.slot_timeout({"body": {}}, 65536) == 12.0


def test_the_lock_scopes_serialize_the_index_configuration():
    descriptor = campaign.descriptor()
    plan = descriptor.plan_compiler(NONCE)
    locks = descriptor.lock_scopes(plan)
    write = [lock for lock in locks if lock["mode"] == "WRITE"]
    assert len(write) == 2
    assert any(
        NONCE in lock["key"] and lock["key"].endswith("/limits-03/*") for lock in write
    )
    assert {
        "key": "project/fireemu-35fe6/firestore/(default)/indexes",
        "mode": "WRITE",
    } in (write)
    # A campaign reading the index configuration cannot be admitted beside it.
    assert reservations.conflicts(
        {"key": "project/fireemu-35fe6/firestore/(default)/indexes", "mode": "READ"},
        write[1],
    )


def test_the_source_map_sweeps_the_lane_and_names_every_entry():
    sources = campaign.source_map()
    for entry in (
        campaign.COLLECTOR_ENTRY,
        campaign.COMPARATOR_ENTRY,
        campaign.COMPILER_ENTRY,
        campaign.WORKER_ENTRY,
        campaign.PREFLIGHT_ENTRY,
        campaign.TRANSPORT_ENTRY,
    ):
        assert sources[entry] == hashlib.sha256((ROOT / entry).read_bytes()).hexdigest()
    assert any(Path(name).name.startswith("test_") for name in sources)
    assert sources[campaign.WORKER_ENTRY] == remote._WORKER_SHA256
    for name in campaign.ABORT_CLOSURE_SOURCES:
        assert name in sources


def test_the_index_precondition_is_declared_with_both_digests_and_a_restore():
    precondition = campaign.index_exemption_precondition()
    assert precondition["conformanceIndexesSha256Before"] == campaign.indexes_digest()
    assert (
        hashlib.sha256(campaign.indexes_after_bytes()).hexdigest()
        == precondition["conformanceIndexesSha256After"]
    )
    assert precondition["override"] == {
        "collectionGroup": "nx",
        "fieldPath": "*",
        "indexes": [],
    }
    assert precondition["restoreRequiredAfterRun"] is True
    assert any("--force" in step for step in precondition["restore"])
    assert precondition["readback"]["projectionDigest"] == (
        preflight.expected_index_exemption_digest()
    )
    projection = preflight.index_exemption_projection(EXEMPT_FIELD_BODY)
    assert projection == preflight.EXPECTED_INDEX_EXEMPTION_PROJECTION
    with pytest.raises(ValueError, match="declared after state"):
        preflight.verify_index_exemption(
            DEFAULT_FIELD_BODY,
            {"indexExemptionProjectionDigest": digest(projection)},
        )


def test_freeze_and_validate_pass_on_a_synthetic_approval(built):
    admitted = admission.validate_o7_admission(**built.bindings())
    assert admitted["campaignId"] == compiler_03.CAMPAIGN
    assert built.inputs["kind"] == campaign.FROZEN_INPUTS_KIND
    assert built.inputs["bounds"] == campaign.frozen_bounds()
    generation = admission.abort_generation(built.inputs)
    assert set(generation["sourceDigests"]) == {
        Path(name).name for name in campaign.ABORT_CLOSURE_SOURCES
    }


@pytest.mark.parametrize(
    "damage",
    [
        {"status": "pending"},
        {"artifactProfile": "limits-03-000000000"},
        {"launcherSha256": "0" * 64},
        {"campaignId": "FS-LIMIT-API-REQUEST-BYTES"},
        {"nonceDigest": "0" * 64},
    ],
)
def test_validate_refuses_a_damaged_approval(built, damage):
    approval = {**built.approval, **damage}
    with pytest.raises(ValueError):
        admission.validate_o7_admission(**built.bindings(approval=approval))


@pytest.mark.parametrize("field", sorted(CAMPAIGN_APPROVAL_FIELDS))
def test_validate_refuses_an_approval_missing_any_field(built, field):
    approval = {key: value for key, value in built.approval.items() if key != field}
    with pytest.raises(ValueError, match="O7 approval artifact required"):
        admission.validate_o7_admission(**built.bindings(approval=approval))


@pytest.mark.parametrize(
    ("override", "message"),
    [
        ({"indexExemptionProjectionDigest": "0" * 64}, "binding differs"),
        ({"indexExemptionDeployedBy": ""}, "acknowledgement"),
        ({"indexExemptionPrecondition": {"kind": "other"}}, "binding differs"),
        (
            {"databaseProjectionDigest": "not-a-digest"},
            "binding differs|digests required",
        ),
    ],
)
def test_freeze_refuses_a_permission_without_the_index_precondition(
    tmp_path, override, message
):
    with pytest.raises(ValueError, match=message):
        Admission(tmp_path, permission_overrides=override)


def _run_full(built, tmp_path, monkeypatch):
    calls, responder = wire_fixture(monkeypatch)
    read = launcher._read_handoff

    def read_after_reservation(args):
        state = reservations.Ledger(built.ledger).snapshot()
        assert len(state["reservations"]) == 1
        row = next(iter(state["reservations"].values()))
        assert row["state"] == "held"
        snapshot = shared_gate.Gate(tmp_path / "output/gate", "limits").snapshot()
        assert snapshot["jobs"]["limits"]["pid"] is not None
        assert calls == []
        return read(args)

    monkeypatch.setattr(launcher, "_read_handoff", read_after_reservation)
    result = launcher.execute(launcher.build_parser().parse_args(built.argv(tmp_path)))
    output = tmp_path / "output"
    receipt = json.loads((output / "receipt.json").read_bytes())
    creates = [op for _, _, op in calls if op["method"] in ("PATCH", "POST")]
    assert len(creates) == 28
    created = set(receipt["createdResources"])
    deleted = {
        op["path"].split("?", 1)[0].removeprefix("/v1/")
        for _, _, op in calls
        if op["method"] == "DELETE"
    }
    # Every accepted side is created once and deleted once; a refused side is
    # never created, so its delete slot is a zero-wire skip while both of its
    # reads still run and prove it absent.
    assert deleted == created
    assert len(created) == 13
    assert len(calls) == 176 - (29 - len(created))
    assert responder.documents == {}
    assert receipt["preflightComplete"] is True
    assert receipt["indexExemption"]["verifiedAtPreflight"] is True
    assert receipt["indexExemption"]["restoreRequired"] is True
    assert receipt["indexExemption"]["restoreTo"] == campaign.INDEXES_SHA256_BEFORE
    assert [row["id"] for row in receipt["managementEvidence"]][:5] == [
        "observation:oauth-tokeninfo",
        "observation:project",
        "observation:database",
        "observation:index-exemption",
        "observation:auth",
    ]
    assert TOKEN not in (output / "receipt.json").read_text()
    assert receipt["collection"]["expectationMismatches"] == []
    assert receipt["collection"]["recordingComplete"] is True
    assert all(receipt["collection"]["resourceAbsence"].values())
    return result, receipt, output


def test_a_full_run_finishes_the_gate_and_releases_the_temporary_ledger(
    built, tmp_path, monkeypatch, gate_accounts_the_empty_batch_item
):
    """K.3: the whole schedule, the postflight, the release and the saved chain."""
    result, receipt, output = _run_full(built, tmp_path, monkeypatch)
    assert result["failure"] is None
    assert result["reservationReleased"] is True
    release = json.loads((output / "release.json").read_bytes())
    gate = shared_gate.Gate(output / "gate", "limits").snapshot()
    assert receipt["releaseEligible"] is True
    assert receipt["postflightComplete"] is True
    assert receipt["indexExemption"]["verifiedAtPostflight"] is True
    assert [row["id"] for row in receipt["managementEvidence"]][5:] == [
        "recovery:project",
        "recovery:database",
        "recovery:index-exemption",
        "recovery:auth",
    ]
    assert gate["jobs"]["limits"]["complete"] is True
    # The 16 zero-wire delete skips of the refused sides are not charged.
    assert gate["total"] == 176 - 16 + 9
    assert gate["costMicrousd"] == (176 - 16 + 9) * 100
    assert len(gate["skips"]) == 16
    shared_gate.validate_absence_proofs(gate, "limits")
    assert release["receiptDigest"] == digest(receipt)
    final = reservations.Ledger(built.ledger).snapshot()["reservations"][
        receipt["ticket"]["reservation"]
    ]
    assert final["state"] == "released"
    assert final["finalGateDigest"] == receipt["gateDigest"]
    for name, expected in receipt["evidenceFiles"].items():
        assert hashlib.sha256((output / name).read_bytes()).hexdigest() == expected
    production.verify_saved(
        output,
        expected_inputs_digest=built.inputs["inputsDigest"],
        ledger_root=built.ledger,
    )
    with pytest.raises(ValueError, match="differs"):
        production.verify_saved(
            output, expected_inputs_digest="0" * 64, ledger_root=built.ledger
        )


def test_head_gate_leaves_the_malformed_item_batch_unconfirmed(
    built, tmp_path, monkeypatch
):
    """Pinned: on HEAD the run cleans everything but cannot close.

    The malformed-item BatchWrite is the R3 condition the campaign exists to
    observe, and HEAD's shared Gate settles it as an unknown create. Every
    owned document is still deleted and proven absent; only the terminal
    bookkeeping is refused, and the Ledger row stays held.
    """
    result, receipt, output = _run_full(built, tmp_path, monkeypatch)
    gate = shared_gate.Gate(output / "gate", "limits").snapshot()
    assert result["reservationReleased"] is False
    assert shared_gate.unconfirmed_creates(gate, "limits") == 1
    unsettled = [
        event for event in gate["events"] if event.get("creationOutcome") == "unknown"
    ]
    assert len(unsettled) == 1
    operation = gate["plan"]["jobs"]["limits"]["observation"][unsettled[0]["index"]]
    assert operation["path"].endswith(":batchWrite")
    assert {} in operation["body"]["writes"]
    assert receipt["collection"]["cleanupComplete"] is False
    assert receipt["collection"]["infrastructureFailures"] == [
        {"phase": "finish", "failure": "ValueError"}
    ]
    assert receipt["stopPoint"] == "create-deadline"
    assert (
        reservations.Ledger(built.ledger).snapshot()["reservations"][
            receipt["ticket"]["reservation"]
        ]["state"]
        == "held"
    )


def test_a_stop_before_any_create_is_a_no_data_stop(built, tmp_path, monkeypatch):
    calls, responder = wire_fixture(monkeypatch, fault="preflight")
    assert launcher.main(built.argv(tmp_path)) == 2
    receipt = json.loads((tmp_path / "output/receipt.json").read_bytes())
    assert receipt["stopPoint"] == "namespace-preflight"
    assert receipt["productionExecuted"] is True
    assert receipt["mayHaveCreated"] is False
    assert receipt["createdResources"] == []
    assert not [op for _, _, op in calls if op["method"] in ("PATCH", "POST", "DELETE")]
    assert responder.documents == {}
    verdict = admission.validate_no_data_receipt(receipt)
    assert verdict["disposition"] == "aborted-no-data"
    row = reservations.Ledger(built.ledger).snapshot()["reservations"][
        receipt["ticket"]["reservation"]
    ]
    assert row["state"] == "held"
    gate = shared_gate.Gate(tmp_path / "output/gate", "limits").snapshot()
    assert gate["jobs"]["limits"]["observation"] == 1
    assert gate["jobs"]["limits"]["stopReason"]
    assert shared_gate.creating_outcome(gate, "limits") == "none"
    # The collector still walks the recovery schedule after the abandon, and
    # the Gate consumes every slot as a zero-wire skip: no request is sent,
    # but the job's recovery count is no longer zero, so the Gate's own no-data
    # predicate no longer holds for this journal. Pinned; see the report.
    assert not [op for _, _, op in calls if op["method"] == "DELETE"]
    assert gate["events"] == gate["events"][:1]
    assert shared_gate.non_creating_dispatches(gate) is None


def test_a_lost_create_response_is_never_retired_as_no_data(
    built, tmp_path, monkeypatch
):
    calls, _responder = wire_fixture(monkeypatch, fault="create")
    assert launcher.main(built.argv(tmp_path)) == 1
    receipt = json.loads((tmp_path / "output/receipt.json").read_bytes())
    assert receipt["stopPoint"] == "create-deadline"
    assert receipt["mayHaveCreated"] is True
    verdict = admission.classify_stop(receipt)
    assert verdict["disposition"] == "owner-escalation"
    with pytest.raises(ValueError, match="not a no-data stop"):
        admission.validate_no_data_receipt(receipt)
    assert not [op for _, _, op in calls if op["method"] == "DELETE"]
    row = reservations.Ledger(built.ledger).snapshot()["reservations"][
        receipt["ticket"]["reservation"]
    ]
    assert row["state"] == "held"


def test_a_stop_after_a_create_recovers_exactly_the_created_documents(
    built, tmp_path, monkeypatch, gate_accounts_the_empty_batch_item
):
    """K.6: an expectation mismatch past a create abandons and deletes what it made."""
    calls, responder = wire_fixture(monkeypatch, fault="mismatch")
    assert launcher.main(built.argv(tmp_path)) == 1
    receipt = json.loads((tmp_path / "output/receipt.json").read_bytes())
    assert receipt["stopPoint"] == "observation-incomplete"
    assert receipt["collection"]["expectationMismatches"]
    created = set(receipt["createdResources"])
    assert created
    deleted = {
        op["path"].split("?", 1)[0].removeprefix("/v1/")
        for _, _, op in calls
        if op["method"] == "DELETE"
    }
    assert deleted == created
    assert responder.documents == {}
    assert all(receipt["collection"]["resourceAbsence"][name] for name in created)
    gate = shared_gate.Gate(tmp_path / "output/gate", "limits").snapshot()
    assert gate["jobs"]["limits"]["stopReason"]
    # With at least one confirmed create the Gate still dispatches the reads
    # of every uncreated resource after the abandon, so absence is proven for
    # the whole assignment and the abandoned close is reachable.
    assert set(gate["jobs"]["limits"]["absent"]) == set(
        gate["jobs"]["limits"]["resources"]
    )
    assert receipt["collection"]["cleanupComplete"] is True
    # The abandoned close itself is still out of reach: the shared Gate
    # compares the creation proofs, not only the absence proofs, against every
    # declared resource, and this campaign declares resources it expects
    # production to refuse. Pinned so the Gate change is visible when it lands.
    assert shared_gate.abandoned_cleanup_complete(gate) is None
    assert receipt["abandonedCleanupComplete"] is False
    verdict = admission.classify_stop(receipt)
    assert verdict["disposition"] == "owner-escalation"
    assert "every declared resource" in verdict["reason"]
    row = reservations.Ledger(built.ledger).snapshot()["reservations"][
        receipt["ticket"]["reservation"]
    ]
    assert row["state"] == "held"


def test_a_missing_exemption_stops_before_any_data_call(built, tmp_path, monkeypatch):
    calls, _responder = wire_fixture(monkeypatch)
    real = preflight.management_transport

    def without_exemption(slot, token, **kwargs):
        response = real(slot, token, **kwargs)
        if slot == "index-exemption":
            response = {**response, "body": DEFAULT_FIELD_BODY}
        return response

    monkeypatch.setattr(preflight, "management_transport", without_exemption)
    assert launcher.main(built.argv(tmp_path)) == 2
    assert calls == []
    receipt = json.loads((tmp_path / "output/receipt.json").read_bytes())
    assert receipt["preflightComplete"] is False
    assert receipt["indexExemption"]["verifiedAtPreflight"] is False
    rows = receipt["managementEvidence"]
    assert [row["id"] for row in rows][-1] == "observation:index-exemption"
    assert rows[-1]["response"]["complete"] is False
    assert rows[-1]["response"]["body"]["baselineVerified"] is False
    gate = shared_gate.Gate(tmp_path / "output/gate", "limits").snapshot()
    assert gate["stopped"] is True
    assert gate["events"] == []
    assert receipt["stopPoint"] == "schedule-not-started"


def test_a_refused_credential_stops_before_any_data_call(built, tmp_path, monkeypatch):
    calls, _responder = wire_fixture(monkeypatch)
    real = preflight.management_transport

    def refused(slot, token, **kwargs):
        response = real(slot, token, **kwargs)
        if slot == "project":
            response = {**response, "status": 403, "body": {"error": {"code": 403}}}
        return response

    monkeypatch.setattr(preflight, "management_transport", refused)
    assert launcher.main(built.argv(tmp_path)) == 2
    assert calls == []
    gate = shared_gate.Gate(tmp_path / "output/gate", "limits").snapshot()
    assert gate["credentialRejected"] is True
    assert gate["events"] == []


def test_an_invalid_handoff_is_refused_after_admission_and_before_any_call(
    built, tmp_path, monkeypatch
):
    calls, _responder = wire_fixture(monkeypatch)
    built.handoff_path.write_text("{}")
    assert launcher.main(built.argv(tmp_path)) == 2
    assert calls == []
    receipt = json.loads((tmp_path / "output/receipt.json").read_bytes())
    assert receipt["productionExecuted"] is False
    assert receipt["managementEvidence"] == []
    assert receipt["stopPoint"] == "schedule-not-started"
    row = reservations.Ledger(built.ledger).snapshot()["reservations"][
        receipt["ticket"]["reservation"]
    ]
    assert row["state"] == "held"


@pytest.mark.parametrize("refusal", ["output", "reserve"])
def test_refusable_checks_precede_the_credential_reader(
    built, tmp_path, monkeypatch, refusal
):
    reads = []
    monkeypatch.setattr(launcher, "_read_handoff", lambda _args: reads.append("read"))
    if refusal == "output":
        (tmp_path / "output").mkdir()
    else:
        binding, sha = campaign.worker_binding()
        capability = admission.issue_production_capability(
            **built.bindings(), binding=binding, binding_digest=sha
        )
        plan = admission.gate_plan_for(built.inputs, built.permission)
        claim = admission.reservation_claim(
            built.inputs, gate_path=tmp_path / "prior-gate", gate_plan=plan
        )
        reservations.Ledger(built.ledger).reserve(
            production._envelope(built.permission, claim),
            claim,
            plan,
            generation=admission.abort_generation(built.inputs),
        )
        admission.revoke_production_capability(capability)
        monkeypatch.setattr(admission, "validate_fresh_admission", lambda *_: None)
    assert launcher.main(built.argv(tmp_path)) == 2
    assert reads == []


def test_the_transport_binds_every_call_to_the_compiled_slot():
    plan = remote.compiled_plan(NONCE)
    job = plan["localGatePlan"]["jobs"]["limits"]
    expected, ceiling = remote.operation_for_slot(
        plan, "observation", 0, job["observation"][0]
    )
    assert expected == job["observation"][0]
    assert ceiling == plan["requests"][0]["responseByteLimit"]
    with pytest.raises(ValueError, match="differs from frozen plan slot"):
        remote.operation_for_slot(plan, "observation", 1, job["observation"][0])
    delete = next(
        (index, op)
        for index, op in enumerate(job["recovery"])
        if op["method"] == "DELETE"
    )
    index, operation = delete
    resolved = {k: v for k, v in operation.items() if k != "versionFrom"}
    resolved["path"] += "?currentDocument.updateTime=2026-01-01T00%3A00%3A00Z"
    remote.operation_for_slot(plan, "recovery", index, resolved)
    with pytest.raises(ValueError, match="resolved cleanup version required"):
        remote.operation_for_slot(
            plan, "recovery", index, resolved | {"path": operation["path"]}
        )
    url, method, body, headers, cap = remote.prepare(
        plan, "observation", 0, job["observation"][0], TOKEN
    )
    assert url.startswith(remote.ORIGIN + "/v1/projects/fireemu-35fe6/")
    assert headers["x-goog-user-project"] == "fireemu-35fe6"
    assert body is None and method == "GET"
    with pytest.raises(ValueError, match="active O7 production capability"):
        remote.request(
            plan, "observation", 0, job["observation"][0], TOKEN, deadline=1.0
        )


def test_the_worker_source_is_pinned_and_scoped_to_the_campaign():
    source = campaign.worker_binding()[0]
    assert hashlib.sha256(source).hexdigest() == remote._WORKER_SHA256
    namespace = {}
    exec(compile(source, "limits_03_https_worker", "exec"), namespace)  # noqa: S102 -- reviewed lane source
    path = namespace["_PATH"]
    plan = remote.compiled_plan(NONCE)
    for row in plan["requests"]:
        assert path.fullmatch(row["path"]) is not None, row["path"][:80]
    assert (
        path.fullmatch(
            "/v1/projects/fireemu-35fe6/databases/(default)/documents/oracle/"
            + NONCE
            + "/request-bytes-01/probe-u01/items/control"
        )
        is None
    )
    assert (
        path.fullmatch(
            "/v1/projects/fireemu-35fe6/databases/(default)/documents:commit"
        )
        is None
    )
