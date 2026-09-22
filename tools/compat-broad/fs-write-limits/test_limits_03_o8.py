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
# The observed production readback of `collectionGroups/pk/fields/*`, which
# carries the identical `fieldPath: "*"`, `indexes: []` override (read-only GET,
# HTTP 200, 2026-09-21 07:05 UTC), verbatim: `indexes` and `usesAncestorConfig`
# are omitted as proto3 defaults and the ancestor is the database's default.
OBSERVED_PRODUCTION_PK_FIELD_BODY = {
    "name": "projects/fireemu-35fe6/databases/(default)/collectionGroups/pk/fields/*",
    "indexConfig": {
        "ancestorField": (
            "projects/fireemu-35fe6/databases/(default)/collectionGroups/"
            "__default__/fields/*"
        )
    },
}
# The same shape on the exempt group, which is what the preflight must see.
EXEMPT_FIELD_BODY = {
    "name": preflight.INDEX_FIELD,
    "indexConfig": {"ancestorField": preflight.DEFAULT_ANCESTOR_FIELD},
}
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


def _assert_lifecycle_operation(slot, operation, lifecycle_ops):
    """Bind the fixture to the exact Firestore REST operation shape."""
    assert isinstance(operation, dict)
    expected_route = preflight.LIFECYCLE_ROUTE
    expected_mask_route = expected_route + "?updateMask=indexConfig"
    if slot in {"index-lifecycle-before", "index-lifecycle-after", "index-lifecycle-restored"}:
        assert operation == {"method": "GET", "route": expected_route, "body": None}
    elif slot == "index-lifecycle-apply":
        assert operation == {
            "method": "PATCH",
            "route": expected_mask_route,
            "body": {"name": preflight.LIFECYCLE_FIELD, "indexConfig": {"indexes": []}},
        }
    elif slot == "index-lifecycle-restore":
        assert operation == {
            "method": "PATCH",
            "route": expected_mask_route,
            "body": {"name": preflight.LIFECYCLE_FIELD},
        }
    elif slot == "index-lifecycle-poll":
        assert operation == {
            "method": "GET",
            "route": "https://firestore.googleapis.com/v1/" + lifecycle_ops["apply"],
            "body": None,
        }
    elif slot == "index-lifecycle-poll-restore":
        assert operation == {
            "method": "GET",
            "route": "https://firestore.googleapis.com/v1/" + lifecycle_ops["restore"],
            "body": None,
        }


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
    lifecycle_field = "projects/fireemu-35fe6/databases/(default)/collectionGroups/nx/fields/*"
    lifecycle_before = {
        "name": lifecycle_field,
        "indexConfig": {"indexes": [], "usesAncestorConfig": True, "ancestorField": "projects/fireemu-35fe6/databases/(default)/collectionGroups/__default__/fields/*", "reverting": False},
        "ttlConfig": {"state": "ENABLED"},
    }
    lifecycle_after = {**lifecycle_before, "indexConfig": {"indexes": [], "usesAncestorConfig": False, "ancestorField": "projects/fireemu-35fe6/databases/(default)/collectionGroups/__default__/fields/*", "reverting": False}}
    lifecycle_ops = {"apply": "projects/fireemu-35fe6/databases/(default)/operations/op-apply", "restore": "projects/fireemu-35fe6/databases/(default)/operations/op-restore"}
    monkeypatch.setattr(shared_gate, "time", clock)
    monkeypatch.setattr(preflight, "time", clock)
    monkeypatch.setattr(preflight.shared, "time", clock)
    monkeypatch.setattr(production, "time", clock)

    def management_fixture(slot, token, *, operation=None, **_kwargs):
        assert token == TOKEN
        if slot.startswith("index-lifecycle-"):
            _assert_lifecycle_operation(slot, operation, lifecycle_ops)
        body = {
            "project": PROJECT_BODY,
            "database": DATABASE_BODY,
            "auth": AUTH_BODY,
            "index-exemption": EXEMPT_FIELD_BODY,
        }.get(slot)
        if slot == "index-lifecycle-before":
            body = lifecycle_before
        elif slot == "index-lifecycle-apply":
            body = {"name": lifecycle_ops["apply"]}
        elif slot == "index-lifecycle-poll":
            body = {"name": lifecycle_ops["apply"], "done": True}
        elif slot == "index-lifecycle-after":
            body = lifecycle_after
        elif slot == "index-lifecycle-restore":
            body = {"name": lifecycle_ops["restore"]}
        elif slot == "index-lifecycle-poll-restore":
            body = {"name": lifecycle_ops["restore"], "done": True}
        elif slot == "index-lifecycle-restored":
            body = lifecycle_before
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
        if (
            fault == "semantic-mismatch"
            and phase == "observation"
            and operation["method"] == "GET"
            and result["status"] == 400
        ):
            result = copy.deepcopy(result)
            result["body"]["error"]["status"] = "FAILED_PRECONDITION"
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
    assert figures["requestUpperBound"] == 192
    assert figures["managementObservationRequests"] == 9
    assert figures["managementRecoveryRequests"] == 7
    assert figures["envelopeCostMicrousd"] == 40_000 + 192 * 100
    assert figures["dataCostMicrousd"] == 176 * 100
    assert campaign.ledger_budget() == {
        "requests": 192,
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


@pytest.mark.parametrize(
    "mutation",
    [
        lambda operation: {**operation, "route": operation["route"].replace("firestore", "other")},
        lambda operation: {**operation, "body": {"name": preflight.LIFECYCLE_FIELD}},
    ],
)
def test_lifecycle_fixture_rejects_wrong_route_or_patch_body(mutation):
    operation = {
        "method": "PATCH",
        "route": preflight.LIFECYCLE_ROUTE + "?updateMask=indexConfig",
        "body": {"name": preflight.LIFECYCLE_FIELD, "indexConfig": {"indexes": []}},
    }
    with pytest.raises(AssertionError):
        _assert_lifecycle_operation(
            "index-lifecycle-apply",
            mutation(operation),
            {"apply": "projects/fireemu-35fe6/databases/(default)/operations/op-apply", "restore": "projects/fireemu-35fe6/databases/(default)/operations/op-restore"},
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
    assert gate["observationRequests"] == 89 + 9
    assert gate["management"]["dispatchKind"] == "closed-v1"
    assert [slot["id"] for slot in gate["management"]["observation"]] == [
        "oauth-tokeninfo",
        "project",
        "database",
        "index-lifecycle-before",
        "index-lifecycle-apply",
        "index-lifecycle-poll",
        "index-lifecycle-after",
        "index-exemption",
        "auth",
    ]
    assert [slot["id"] for slot in gate["management"]["recovery"]] == [
        "project",
        "database",
        "index-exemption",
        "auth",
        "index-lifecycle-restore",
        "index-lifecycle-poll-restore",
        "index-lifecycle-restored",
    ]
    assert gate["recoverySeconds"] >= charge["recoverySeconds"] + 4 * 13.25
    assert gate["wallSeconds"] - gate["recoverySeconds"] >= (
        charge["observationSeconds"] + 5 * 13.25
    )
    assert gate["costMicrousd"] == 192 * 100
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
        "observation:index-lifecycle-before",
        "observation:index-lifecycle-apply",
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
    assert [row["id"] for row in receipt["managementEvidence"]][9:] == [
        "recovery:project",
        "recovery:database",
        "recovery:index-exemption",
        "recovery:auth",
        "recovery:index-lifecycle-restore",
        "recovery:index-lifecycle-poll-restore",
        "recovery:index-lifecycle-restored",
    ]
    assert gate["jobs"]["limits"]["complete"] is True
    # The 16 zero-wire delete skips of the refused sides are not charged.
    assert gate["total"] == 176 - 16 + 16
    assert gate["costMicrousd"] == (176 - 16 + 16) * 100
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


def test_a_complete_semantic_difference_is_safe_and_repairable(
    built, tmp_path, monkeypatch, gate_accounts_the_empty_batch_item
):
    """Safety completion survives a genuine mismatch and missing release repair."""
    calls, responder = wire_fixture(monkeypatch, fault="semantic-mismatch")
    result = launcher.execute(launcher.build_parser().parse_args(built.argv(tmp_path)))
    output = tmp_path / "output"
    receipt = json.loads((output / "receipt.json").read_bytes())
    assert result["failure"] is None
    assert result["reservationReleased"] is True
    assert receipt["collection"]["expectationMismatches"]
    assert responder.documents == {}
    assert calls

    saved = production.verify_saved(
        output,
        expected_inputs_digest=built.inputs["inputsDigest"],
        ledger_root=built.ledger,
    )
    assert saved["collection"]["expectationMismatches"]
    assert production.semantic_classification(saved) == "SEMANTIC_MISMATCH"

    (output / "release.json").unlink()
    repaired = production.recover_release(
        output,
        expected_inputs_digest=built.inputs["inputsDigest"],
        ledger_root=built.ledger,
    )
    assert repaired["receiptDigest"] == digest(receipt)
    assert json.loads((output / "release.json").read_bytes()) == repaired

    (output / "release.json").unlink()
    routes = json.loads((output / "routes.json").read_bytes())
    routes["rows"][0]["route"] += "/tampered"
    (output / "routes.json").write_text(json.dumps(routes))
    with pytest.raises(ValueError, match="saved evidence file differs"):
        production.recover_release(
            output,
            expected_inputs_digest=built.inputs["inputsDigest"],
            ledger_root=built.ledger,
        )
    assert not (output / "release.json").exists()


def test_collection_failure_after_index_apply_still_runs_reserved_recovery(
    built, tmp_path, monkeypatch
):
    calls, _responder = wire_fixture(monkeypatch)

    def fail_after_preflight(*_args, **_kwargs):
        raise RuntimeError("collector fixture failure")

    monkeypatch.setattr(production, "collect", fail_after_preflight)
    result = launcher.execute(launcher.build_parser().parse_args(built.argv(tmp_path)))

    assert result["failure"] == "RuntimeError"
    assert calls == []
    receipt = json.loads((tmp_path / "output/receipt.json").read_bytes())
    management_ids = [row["id"] for row in receipt["managementEvidence"]]
    assert "observation:auth" in management_ids
    assert "recovery:index-lifecycle-restore" in management_ids
    assert "recovery:index-lifecycle-poll-restore" in management_ids
    assert "recovery:index-lifecycle-restored" in management_ids
    assert management_ids[-1] == "recovery:index-lifecycle-restored"
    assert receipt["recoveryAttempted"] is True
    assert receipt["recoveryFailure"] is None
    assert receipt["postflightComplete"] is True
    assert receipt["reservationStateAtPublication"] == "held"


def test_incomplete_collection_enters_reserved_recovery_and_reads_restored_state(
    built, tmp_path, monkeypatch
):
    calls, _responder = wire_fixture(monkeypatch)

    def incomplete_collection(*_args, **_kwargs):
        return {"collectionComplete": False, "cleanupComplete": False}

    monkeypatch.setattr(production, "collect", incomplete_collection)
    result = launcher.execute(launcher.build_parser().parse_args(built.argv(tmp_path)))

    assert result["failure"] == "ValueError"
    assert calls == []
    receipt = json.loads((tmp_path / "output/receipt.json").read_bytes())
    management_ids = [row["id"] for row in receipt["managementEvidence"]]
    assert "recovery:index-lifecycle-restore" in management_ids
    assert "recovery:index-lifecycle-poll-restore" in management_ids
    assert management_ids[-1] == "recovery:index-lifecycle-restored"
    assert receipt["recoveryAttempted"] is True
    assert receipt["recoveryFailure"] is None
    assert receipt["postflightComplete"] is True
    assert receipt["reservationStateAtPublication"] == "held"


def test_restore_readback_failure_is_held_after_actual_recovery_attempt(
    built, tmp_path, monkeypatch
):
    """A failed REC readback leaves the real reservation held."""
    wire_fixture(monkeypatch)
    original_transport = preflight.management_transport

    def corrupt_restored_readback(slot, token, **kwargs):
        response = original_transport(slot, token, **kwargs)
        if slot == "index-lifecycle-restored":
            response = copy.deepcopy(response)
            response["body"] = copy.deepcopy(response["body"])
            response["body"]["indexConfig"]["usesAncestorConfig"] = False
        return response

    monkeypatch.setattr(preflight, "management_transport", corrupt_restored_readback)
    result = launcher.execute(launcher.build_parser().parse_args(built.argv(tmp_path)))

    assert result["failure"] == "ValueError"
    receipt = json.loads((tmp_path / "output/receipt.json").read_bytes())
    management_ids = [row["id"] for row in receipt["managementEvidence"]]
    assert "recovery:index-lifecycle-restore" in management_ids
    assert "recovery:index-lifecycle-poll-restore" in management_ids
    restored = next(
        row
        for row in receipt["managementEvidence"]
        if row["id"] == "recovery:index-lifecycle-restored"
    )
    assert restored["response"]["body"]["indexConfig"]["usesAncestorConfig"] is False
    assert receipt["recoveryAttempted"] is True
    assert receipt["recoveryFailure"] == "ValueError"
    assert receipt["postflightComplete"] is False
    assert receipt["reservationStateAtPublication"] == "held"


def test_head_gate_settles_the_malformed_item_batch(
    built, tmp_path, monkeypatch
):
    """A typed empty BatchWrite item settles without fabricating ownership."""
    result, receipt, output = _run_full(built, tmp_path, monkeypatch)
    gate = shared_gate.Gate(output / "gate", "limits").snapshot()
    assert result["reservationReleased"] is True
    assert shared_gate.unconfirmed_creates(gate, "limits") == 0
    assert not [
        event for event in gate["events"] if event.get("creationOutcome") == "unknown"
    ]
    assert receipt["collection"]["cleanupComplete"] is True
    assert receipt["collection"]["infrastructureFailures"] == []
    assert receipt["postflightComplete"] is True
    assert (
        reservations.Ledger(built.ledger).snapshot()["reservations"][
            receipt["ticket"]["reservation"]
        ]["state"]
        == "released"
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


def test_a_real_incomplete_collector_restores_index_before_holding(
    built, tmp_path, monkeypatch
):
    """A real DATA event still attempts REC before retaining ownership."""
    calls, _responder = wire_fixture(monkeypatch, fault="create")
    result = launcher.execute(launcher.build_parser().parse_args(built.argv(tmp_path)))

    assert result["failure"] in ("RuntimeError", "ValueError")
    assert any(op["method"] in ("PATCH", "POST") for _, _, op in calls)
    receipt = json.loads((tmp_path / "output/receipt.json").read_bytes())
    management_ids = [row["id"] for row in receipt["managementEvidence"]]
    assert "recovery:index-lifecycle-restore" in management_ids
    assert "recovery:index-lifecycle-poll-restore" in management_ids
    assert "recovery:index-lifecycle-restored" in management_ids
    assert receipt["postflightComplete"] is True
    assert receipt["reservationStateAtPublication"] == "held"


def test_a_real_cleanup_complete_mismatch_restores_index_before_holding(
    built, tmp_path, monkeypatch, gate_accounts_the_empty_batch_item
):
    """A real DATA mismatch with completed cleanup still performs REC."""
    calls, responder = wire_fixture(monkeypatch, fault="mismatch")
    result = launcher.execute(launcher.build_parser().parse_args(built.argv(tmp_path)))

    assert result["failure"] in ("RuntimeError", "ValueError")
    assert responder.documents == {}
    assert any(op["method"] in ("PATCH", "POST") for _, _, op in calls)
    receipt = json.loads((tmp_path / "output/receipt.json").read_bytes())
    assert receipt["collection"]["cleanupComplete"] is True
    management_ids = [row["id"] for row in receipt["managementEvidence"]]
    assert "recovery:index-lifecycle-restore" in management_ids
    assert "recovery:index-lifecycle-poll-restore" in management_ids
    assert management_ids[-1] == "recovery:index-lifecycle-restored"
    assert receipt["postflightComplete"] is True
    assert receipt["reservationStateAtPublication"] == "held"
    with pytest.raises(ValueError, match="saved acquisition binding differs"):
        production.recover_release(
            tmp_path / "output",
            expected_inputs_digest=built.inputs["inputsDigest"],
            ledger_root=built.ledger,
        )
    assert not (tmp_path / "output" / "release.json").exists()


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
    assert shared_gate.abandoned_cleanup_complete(gate) == sorted(created)
    assert receipt["abandonedCleanupComplete"] is True
    verdict = admission.classify_stop(receipt)
    assert verdict["disposition"] == "abandoned-cleanup-close"
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


def test_the_observed_production_override_body_is_the_expected_shape():
    """The production readback, verbatim, normalizes to the exempt shape."""
    body = OBSERVED_PRODUCTION_PK_FIELD_BODY
    assert set(body) == {"name", "indexConfig"}
    assert set(body["indexConfig"]) == {"ancestorField"}
    assert body["indexConfig"]["ancestorField"] == preflight.DEFAULT_ANCESTOR_FIELD
    normalized = preflight._field_readback(body, field=body["name"])
    assert normalized == {
        **preflight.EXPECTED_INDEX_EXEMPTION_PROJECTION,
        "name": body["name"],
    }
    # The exempt group differs from pk only in its name; the same body on the
    # nx field is the after state the permission binds.
    nx = {**body, "name": preflight.INDEX_FIELD}
    assert nx == EXEMPT_FIELD_BODY
    projection = preflight.index_exemption_projection(nx)
    assert projection == preflight.EXPECTED_INDEX_EXEMPTION_PROJECTION
    preflight.verify_index_exemption(
        nx, {"indexExemptionProjectionDigest": digest(projection)}
    )
    # The verbatim body under its own name is refused for the nx slot.
    with pytest.raises(ValueError, match="typed index field readback"):
        preflight.verify_index_exemption(
            body, {"indexExemptionProjectionDigest": digest(projection)}
        )


@pytest.mark.parametrize(
    ("configuration", "accepted"),
    [
        ({"ancestorField": preflight.DEFAULT_ANCESTOR_FIELD}, True),
        (
            {
                "indexes": [],
                "usesAncestorConfig": False,
                "ancestorField": preflight.DEFAULT_ANCESTOR_FIELD,
            },
            True,
        ),
        # The API always names the ancestor; a body without it is not a
        # readback of a deployed override.
        ({}, False),
        ({"indexes": [], "usesAncestorConfig": False}, False),
        # A partial override: an index of its own is not the exemption.
        (
            {
                "indexes": DEFAULT_FIELD_BODY["indexConfig"]["indexes"][:1],
                "ancestorField": preflight.DEFAULT_ANCESTOR_FIELD,
            },
            False,
        ),
        # No override at all: the group still inherits the default.
        (
            {
                "usesAncestorConfig": True,
                "ancestorField": preflight.DEFAULT_ANCESTOR_FIELD,
            },
            False,
        ),
        (
            {
                "indexes": [],
                "usesAncestorConfig": True,
                "ancestorField": preflight.DEFAULT_ANCESTOR_FIELD,
            },
            False,
        ),
        # An ancestor other than the documented default.
        ({"ancestorField": preflight.INDEX_FIELD.replace("/nx/", "/pk/")}, False),
        (
            {
                "ancestorField": preflight.DEFAULT_ANCESTOR_FIELD.replace(
                    "(default)", "other"
                )
            },
            False,
        ),
        (
            {
                "usesAncestorConfig": "false",
                "ancestorField": preflight.DEFAULT_ANCESTOR_FIELD,
            },
            False,
        ),
        ({"indexes": "none", "ancestorField": preflight.DEFAULT_ANCESTOR_FIELD}, False),
    ],
    ids=[
        "ancestor-named",
        "explicit-false-with-ancestor",
        "omitted-ancestor",
        "explicit-false-without-ancestor",
        "partial-override",
        "inherits-default",
        "empty-but-inherits",
        "other-ancestor",
        "other-database-ancestor",
        "string-flag",
        "string-indexes",
    ],
)
def test_the_exemption_readback_is_judged_member_by_member(configuration, accepted):
    body = {"name": preflight.INDEX_FIELD, "indexConfig": configuration}
    permission = {
        "indexExemptionProjectionDigest": preflight.expected_index_exemption_digest()
    }
    if accepted:
        preflight.verify_index_exemption(body, permission)
        attestation = preflight.index_exemption_attestation(
            {
                "complete": True,
                "workerReaped": True,
                "status": 200,
                "bodyKind": "json",
                "body": body,
            },
            permission,
        )
        assert attestation["complete"] is True
        assert attestation["body"]["baselineVerified"] is True
        assert attestation["body"]["projection"]["ancestorField"] == (
            preflight.DEFAULT_ANCESTOR_FIELD
        )
        preflight.validate_index_exemption_attestation(attestation, permission)
    else:
        with pytest.raises(ValueError):
            preflight.verify_index_exemption(body, permission)


def test_the_exemption_readback_requires_the_field_name_and_a_200():
    permission = {
        "indexExemptionProjectionDigest": preflight.expected_index_exemption_digest()
    }
    with pytest.raises(ValueError, match="typed index field readback"):
        preflight.verify_index_exemption(
            {"name": preflight.DEFAULT_ANCESTOR_FIELD, "indexConfig": {}}, permission
        )
    for status, body in (
        (403, {"error": {"code": 403, "status": "PERMISSION_DENIED"}}),
        (404, {"error": {"code": 404, "status": "NOT_FOUND"}}),
        # A non-2xx answer whose body happens to be the exempt shape is still
        # not an attestation of the deployed state.
        (500, EXEMPT_FIELD_BODY),
        (299, EXEMPT_FIELD_BODY),
    ):
        attestation = preflight.index_exemption_attestation(
            {
                "complete": True,
                "workerReaped": True,
                "status": status,
                "bodyKind": "json",
                "body": body,
            },
            permission,
        )
        assert attestation["complete"] is False
        assert attestation["body"]["baselineVerified"] is False
        with pytest.raises(ValueError, match="saved index exemption attestation"):
            preflight.validate_index_exemption_attestation(attestation, permission)


def _production_receipt(
    *,
    reservation="fs-write-limits-03-reservation-1",
    postflight_complete=True,
    verified_at_postflight=True,
    gate_digest=None,
):
    """The narrow slice of a production receipt.json the restore binds to."""
    return {
        "ticket": {"reservation": reservation},
        "gateDigest": gate_digest or ("7" * 64),
        "postflightComplete": postflight_complete,
        "indexExemption": {"verifiedAtPostflight": verified_at_postflight},
    }


def test_the_restored_readback_is_judged_and_recorded(tmp_path):
    import limits_03_indexes as indexes

    restored = preflight.verify_index_restored(DEFAULT_FIELD_BODY)
    assert restored["projection"] == preflight.EXPECTED_INDEX_RESTORED_PROJECTION
    assert restored["inheritedIndexes"] == DEFAULT_FIELD_BODY["indexConfig"]["indexes"]
    for body in (
        EXEMPT_FIELD_BODY,
        {"name": preflight.INDEX_FIELD, "indexConfig": {"usesAncestorConfig": True}},
        {
            "name": preflight.INDEX_FIELD,
            "indexConfig": {
                "usesAncestorConfig": True,
                "ancestorField": preflight.INDEX_FIELD.replace("/nx/", "/pk/"),
            },
        },
    ):
        with pytest.raises(ValueError):
            preflight.verify_index_restored(body)
    readback = tmp_path / "restored.json"
    readback.write_text(json.dumps(DEFAULT_FIELD_BODY))
    receipt_path = tmp_path / "receipt.json"
    receipt_path.write_text(json.dumps(_production_receipt()))
    record_path = tmp_path / "restore.json"

    # --verify-restored refuses without --receipt: a restore record cannot be
    # produced without binding it to the production run it restores.
    assert (
        indexes.main(["--verify-restored", str(readback), "--record", str(record_path)])
        == 2
    )
    assert not record_path.exists()

    # A receipt whose postflight never confirmed the exemption also refuses.
    for damage in (
        {"postflight_complete": False},
        {"verified_at_postflight": False},
    ):
        incomplete = tmp_path / f"receipt-{len(damage)}-{list(damage)[0]}.json"
        incomplete.write_text(json.dumps(_production_receipt(**damage)))
        assert (
            indexes.main(
                [
                    "--verify-restored",
                    str(readback),
                    "--receipt",
                    str(incomplete),
                    "--record",
                    str(record_path),
                ]
            )
            == 2
        )
        assert not record_path.exists()

    assert (
        indexes.main(
            [
                "--verify-restored",
                str(readback),
                "--receipt",
                str(receipt_path),
                "--record",
                str(record_path),
            ]
        )
        == 0
    )
    record = json.loads(record_path.read_text())
    assert record["kind"] == campaign.RESTORE_RECORD_KIND
    assert record["projectionDigest"] == preflight.expected_index_restored_digest()
    assert record["conformanceIndexesSha256"] == campaign.INDEXES_SHA256_BEFORE
    receipt = json.loads(receipt_path.read_text())
    assert record["receiptDigest"] == digest(receipt)
    assert record["reservationTicket"] == receipt["ticket"]["reservation"]
    assert record["gateDigest"] == receipt["gateDigest"]
    indexes.validate_restore_record(record)
    for damage in (
        {"verified": False},
        {"projection": preflight.EXPECTED_INDEX_EXEMPTION_PROJECTION},
        {"campaignId": "FS-LIMIT-API-REQUEST-BYTES"},
        {"conformanceIndexesSha256": campaign.INDEXES_SHA256_AFTER},
        # An unbound record: the receipt binding fields are missing entirely.
        {"receiptDigest": None},
        {"reservationTicket": None},
        {"gateDigest": None},
    ):
        with pytest.raises(ValueError, match="restore record"):
            indexes.validate_restore_record({**record, **damage})
    # A record is written once; the exempt readback is refused as restored.
    assert (
        indexes.main(
            [
                "--verify-restored",
                str(readback),
                "--receipt",
                str(receipt_path),
                "--record",
                str(record_path),
            ]
        )
        == 2
    )
    exempt = tmp_path / "exempt.json"
    exempt.write_text(json.dumps(EXEMPT_FIELD_BODY))
    assert (
        indexes.main(
            [
                "--verify-restored",
                str(exempt),
                "--receipt",
                str(receipt_path),
                "--record",
                str(tmp_path / "x"),
            ]
        )
        == 2
    )
    assert indexes.main(["--verify-deployed", str(exempt)]) == 0
    assert indexes.main(["--verify-deployed", str(readback)]) == 2


def test_the_package_binds_the_restore_evidence_only_when_verified(tmp_path):
    import limits_03_indexes as indexes
    import package_03

    unbound = package_03.restore_binding(None)
    assert unbound["required"] is True
    assert unbound["verified"] is False
    assert unbound["record"] is None
    readback = tmp_path / "restored.json"
    readback.write_text(json.dumps(DEFAULT_FIELD_BODY))
    receipt_path = tmp_path / "receipt.json"
    receipt_path.write_text(json.dumps(_production_receipt()))
    # The record is written entirely under tmp_path: an interrupted run never
    # dirties the tracked spec/compatibility/broad-runs/ tree.
    record_path = tmp_path / "limits-03-restore.json"
    assert (
        indexes.main(
            [
                "--verify-restored",
                str(readback),
                "--receipt",
                str(receipt_path),
                "--record",
                str(record_path),
            ]
        )
        == 0
    )
    bound = package_03.restore_binding(
        record_path, root=tmp_path, production_receipt=receipt_path
    )
    assert bound["verified"] is True
    assert bound["record"]["path"] == "limits-03-restore.json"
    assert (
        bound["record"]["sha256"]
        == hashlib.sha256(record_path.read_bytes()).hexdigest()
    )
    assert bound["record"]["projectionDigest"] == (
        preflight.expected_index_restored_digest()
    )
    receipt = json.loads(receipt_path.read_text())
    assert bound["record"]["receiptDigest"] == digest(receipt)
    assert bound["record"]["reservationTicket"] == receipt["ticket"]["reservation"]

    # Bound without cross-checking a receipt: the record's self-carried
    # binding is still required, but nothing is compared against it.
    self_bound = package_03.restore_binding(record_path, root=tmp_path)
    assert self_bound["verified"] is True

    # A record bound to another ticket (a different production receipt) is
    # refused by the cross-check.
    other_receipt_path = tmp_path / "other-receipt.json"
    other_receipt_path.write_text(
        json.dumps(_production_receipt(reservation="a-different-reservation"))
    )
    with pytest.raises(ValueError, match="not bound to the given production receipt"):
        package_03.restore_binding(
            record_path, root=tmp_path, production_receipt=other_receipt_path
        )

    precondition = campaign.index_exemption_precondition()
    assert precondition["deploy"][-2].startswith("git checkout -- conformance/")
    assert "--verify-restored" in " ".join(precondition["restore"])
    assert "--receipt" in " ".join(precondition["restore"])
    assert precondition["restoreEvidence"]["expectedProjectionDigest"] == (
        preflight.expected_index_restored_digest()
    )


def test_a_stop_before_any_data_call_classifies_as_no_data(
    built, tmp_path, monkeypatch
):
    """The empty Gate journal proves nothing was written; the receipt says so."""
    calls, _responder = wire_fixture(monkeypatch)
    built.handoff_path.write_text("{}")
    assert launcher.main(built.argv(tmp_path)) == 2
    receipt = json.loads((tmp_path / "output/receipt.json").read_bytes())
    assert calls == []
    verdict = admission.validate_no_data_receipt(receipt)
    assert verdict["disposition"] == "aborted-no-data"
    assert receipt["kind"] == admission.NO_DATA_RECEIPT_SHAPE["kind"]
    expected = admission.NO_DATA_RECEIPT_SHAPE["scheduleNotStarted"]
    assert {key: receipt[key] for key in expected} == expected
    # A data row, a create or an uncertain create each withdraw the verdict.
    for damage in (
        {"metadata": [{"responseDigest": "0" * 64}]},
        {"createdResources": ["x"]},
        {"mayHaveCreated": True},
        {"productionExecuted": True},
    ):
        assert admission.classify_stop({**receipt, **damage})["retirableAsNoData"] is (
            False
        )


def test_a_missing_exemption_stop_classifies_as_no_data(built, tmp_path, monkeypatch):
    calls, _responder = wire_fixture(monkeypatch)
    real = preflight.management_transport

    def without_exemption(slot, token, **kwargs):
        response = real(slot, token, **kwargs)
        if slot == "index-exemption":
            response = {**response, "body": DEFAULT_FIELD_BODY}
        return response

    monkeypatch.setattr(preflight, "management_transport", without_exemption)
    assert launcher.main(built.argv(tmp_path)) == 2
    receipt = json.loads((tmp_path / "output/receipt.json").read_bytes())
    assert calls == []
    assert admission.validate_no_data_receipt(receipt)["disposition"] == (
        "aborted-no-data"
    )


def test_the_launcher_rechecks_the_index_precondition_clause_by_clause(built):
    """Defense in depth behind the permission binding: each clause on its own."""
    good = copy.deepcopy(built.permission)
    admission._validate_index_precondition(good)
    precondition = good["indexExemptionPrecondition"]
    for damage, message in (
        ({"indexExemptionPrecondition": None}, "precondition differs"),
        (
            {
                "indexExemptionPrecondition": {
                    **precondition,
                    "conformanceIndexesSha256After": "0" * 64,
                }
            },
            "precondition differs",
        ),
        (
            {
                "indexExemptionPrecondition": {
                    **precondition,
                    "restoreRequiredAfterRun": False,
                }
            },
            "precondition differs",
        ),
        ({"indexExemptionProjectionDigest": "0" * 64}, "declared after state"),
        ({"indexExemptionProjectionDigest": None}, "declared after state"),
        ({"indexExemptionDeployedBy": " "}, "acknowledgement"),
        ({"indexExemptionDeployedBy": None}, "acknowledgement"),
    ):
        with pytest.raises(ValueError, match=message):
            admission._validate_index_precondition({**good, **damage})
    # The restore flag is checked on the declaration the descriptor produces,
    # so a descriptor that stopped declaring it would be refused here.
    monkey = {**precondition, "restoreRequiredAfterRun": False}
    with pytest.raises(ValueError, match="precondition differs"):
        admission._validate_index_precondition(
            {**good, "indexExemptionPrecondition": monkey}
        )


def test_the_transport_recompiles_the_plan_from_the_nonce():
    """A caller's plan is not the authority: the slot is the compiler's."""
    plan = copy.deepcopy(remote.compiled_plan(NONCE))
    job = plan["localGatePlan"]["jobs"]["limits"]
    index = next(i for i, op in enumerate(job["observation"]) if op.get("body"))
    altered = copy.deepcopy(job["observation"][index])
    altered["body"] = {"fields": {"forged": {"stringValue": "x"}}}
    job["observation"][index] = altered
    plan["requests"][index]["body"] = altered["body"]
    with pytest.raises(ValueError, match="differs from frozen plan slot"):
        remote.operation_for_slot(plan, "observation", index, altered)
    # A referenced body must be handed in as the exact frozen bytes.
    index = next(i for i, op in enumerate(job["observation"]) if "bodyRef" in op)
    canonical = compiler_03.dispatched_operations(remote.compiled_plan(NONCE))
    remote.operation_for_slot(plan, "observation", index, canonical[index])
    forged = copy.deepcopy(canonical[index])
    forged["body"]["fields"]["v"] = {"integerValue": "999"}
    with pytest.raises(ValueError, match="differs from frozen plan slot"):
        remote.operation_for_slot(plan, "observation", index, forged)


def test_the_wire_deadline_is_the_slot_reservation(monkeypatch):
    plan = remote.compiled_plan(NONCE)
    operations = compiler_03.dispatched_operations(plan)
    seen = {}

    def exchange(url, method, body, headers, deadline, response_cap):
        seen.update(url=url, method=method, deadline=deadline, cap=response_cap)
        return 200, "application/json", b"{}", None

    class Capability:
        pass

    monkeypatch.setattr(remote, "_exchange", exchange)
    monkeypatch.setattr(remote, "authorize_transport", lambda *a, **k: None)
    clock = {"now": 5000.0}
    monkeypatch.setattr(remote.time, "monotonic", lambda: clock["now"])
    for index, operation in enumerate(operations):
        ceiling = plan["requests"][index]["responseByteLimit"]
        expected = remote.slot_timeout(operation, ceiling)
        receipt = remote.request(
            plan,
            "observation",
            index,
            operation,
            TOKEN,
            deadline=clock["now"] + 10_000,
            capability=Capability(),
            binding=b"",
            binding_digest="",
        )
        assert receipt["complete"] is True
        assert seen["deadline"] == clock["now"] + expected
        assert seen["cap"] == ceiling
        assert expected in (
            compiler_03.SMALL_REQUEST_SECONDS,
            compiler_03.READBACK_SECONDS,
            compiler_03.TRANSPORT_CEILING_SECONDS,
        )
    # An absolute deadline nearer than the reservation wins.
    remote.request(
        plan,
        "observation",
        0,
        operations[0],
        TOKEN,
        deadline=clock["now"] + 1,
        capability=Capability(),
        binding=b"",
        binding_digest="",
    )
    assert seen["deadline"] == clock["now"] + 1
    monkeypatch.setattr(remote, "slot_timeout", lambda *a: 60.0)
    with pytest.raises(ValueError, match="slot reservation outside"):
        remote.request(
            plan,
            "observation",
            0,
            operations[0],
            TOKEN,
            deadline=clock["now"] + 10_000,
            capability=Capability(),
            binding=b"",
            binding_digest="",
        )


def _run_worker(message: dict, body: bytes = b"") -> bytes:
    """Run the real worker bytes on a message; it must refuse before connecting."""
    source = campaign.worker_binding()[0].decode()
    payload = json.dumps(message, separators=(",", ":")).encode() + b"\n" + body
    completed = subprocess.run(
        [sys.executable, "-I", "-S", "-B", "-c", source],
        input=payload,
        capture_output=True,
        timeout=30,
        env={"PATH": "/usr/bin:/bin"},
        check=False,
    )
    return completed.stdout


@pytest.mark.parametrize(
    "damage",
    [
        {"path": "/v1/projects/fireemu-35fe6/databases/other/documents:batchWrite"},
        {"path": "/v1/projects/other-project/databases/(default)/documents:batchWrite"},
        {
            "path": "/v1/projects/fireemu-35fe6/databases/(default)/documents/oracle/"
            + NONCE
            + "/request-bytes-01/probe-u01/items/control"
        },
        {
            "method": "PUT",
            "path": "/v1/projects/fireemu-35fe6/databases/(default)/documents/oracle/"
            + NONCE
            + "/limits-03/x",
            "bodyBytes": 0,
        },
        {"deadline": 60.0},
        {
            "method": "GET",
            "path": "/v1/projects/fireemu-35fe6/databases/(default)/documents/oracle/"
            + NONCE
            + "/limits-03/x",
            "bodyBytes": 2,
        },
        {"authorization": "Basic abc"},
        {"project": "other-project"},
    ],
    ids=[
        "other-database",
        "other-project-path",
        "other-namespace",
        "put",
        "sixty-second-deadline",
        "body-on-get",
        "not-bearer",
        "other-project-header",
    ],
)
def test_the_worker_refuses_out_of_scope_messages_before_connecting(damage):
    import time as real_time

    message = {
        "method": "POST",
        "path": "/v1/projects/fireemu-35fe6/databases/(default)/documents:batchWrite",
        "authorization": "Bearer " + TOKEN,
        "project": "fireemu-35fe6",
        "bodyBytes": 2,
        "deadline": real_time.monotonic() + 5,
    }
    message.update(damage)
    if "deadline" in damage:
        message["deadline"] = real_time.monotonic() + damage["deadline"]
    frames = _run_worker(message, b"{}" if message["bodyBytes"] else b"")
    assert frames == b"F" + (14).to_bytes(4, "big") + b"worker-failure"
