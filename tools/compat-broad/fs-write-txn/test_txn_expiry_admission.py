"""O8 admission tests for the transaction expiry campaign.

Every artifact here is built locally. No production request is made, no
credential is read, no origin outside the process is contacted, and the shared
Ledger is only ever a temporary directory under the test's own tmp_path.
"""

import copy
import hashlib
import json
import shutil
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

import txn_expiry_admission as admission
import txn_expiry_descriptor as campaign
import txn_expiry_o8
import txn_expiry_plan as plan_module
from batch_contract import database_evidence
from broad_contract import digest
from o8_campaign import CAMPAIGN_APPROVAL_FIELDS

commit_baseline = campaign.commit_baseline

NONCE = "b" * 32
CAMPAIGN_ID = "FS-TRANSACTION-EXPIRY-RETRY-04"
PROJECT_BODY = {"projectId": "fireemu-35fe6", "projectNumber": "592603257417"}
DATABASE_BODY = {
    "name": "projects/fireemu-35fe6/databases/(default)",
    "uid": "fixture-uid",
    "type": "FIRESTORE_NATIVE",
    "databaseEdition": "STANDARD",
    "locationId": "us-central1",
}
AUTH_BODY = {"name": "projects/592603257417/config", "mfa": {"state": "DISABLED"}}
TOKEN = "offline-fixture-token"


def test_the_descriptor_is_complete_and_plan_bound():
    descriptor = campaign.descriptor()
    assert descriptor.campaign_id == CAMPAIGN_ID
    assert descriptor.approval_fields == CAMPAIGN_APPROVAL_FIELDS
    assert descriptor.binds_campaign_id is True
    assert (descriptor.campaign_seconds, descriptor.recovery_seconds) == (1200, 180)
    assert descriptor.window_seconds == 1380
    assert campaign.ledger_budget() == {
        "requests": 95,
        "accounts": 0,
        "resources": 5,
        "costMicrousd": 16688,
    }
    assert descriptor.artifact_profile == (
        "txn-expiry-" + campaign.shadow_record()["runtime"]["sourceCommit"][:9]
    )
    assert descriptor.frozen_bounds["timing"] == "wall-clock"


def test_the_descriptor_refuses_a_missing_member():
    from o8_campaign import CampaignDescriptor

    members = campaign.descriptor().members()
    members.pop("collector")
    with pytest.raises(ValueError, match="missing"):
        CampaignDescriptor(**members)


def test_the_lock_scopes_are_one_exclusive_and_five_read():
    descriptor = campaign.descriptor()
    plan = descriptor.plan_compiler(NONCE)
    locks = descriptor.lock_scopes(plan)
    assert [lock["mode"] for lock in locks].count("EXCLUSIVE") == 1
    assert [lock["mode"] for lock in locks].count("READ") == 5
    exclusive = next(lock for lock in locks if lock["mode"] == "EXCLUSIVE")
    assert exclusive["key"] == (
        f"project/fireemu-35fe6/firestore/(default)/documents/oracle/{NONCE}/txn-expiry-04/*"
    )
    # The Ledger grammar accepts every key, and every owned document is
    # covered by the exclusive scope.
    import reservations

    for lock in locks:
        reservations._scope(lock)
    for name in plan["ownedResources"]:
        assert reservations._ancestor(
            reservations._scope(exclusive), reservations._firestore_resource_scope(name)
        )


def test_the_plan_reference_names_exactly_one_compiled_plan():
    reference = campaign.plan_compiler(NONCE)
    plan = campaign.execution_plan(reference)
    assert plan["documentPrefix"] == f"oracle/{NONCE}/txn-expiry-04"
    assert plan["ownerId"] == campaign.owner_id_for(NONCE)
    with pytest.raises(ValueError):
        campaign.execution_plan({**reference, "ownerId": "0" * 32})
    with pytest.raises(ValueError):
        campaign.plan_compiler("not-hex")


def test_the_source_map_names_every_campaign_entry():
    sources = campaign.source_map()
    for entry in (
        campaign.COLLECTOR_ENTRY,
        campaign.COMPARATOR_ENTRY,
        campaign.WORKER_ENTRY,
        campaign.GATE_ENTRY,
    ):
        assert sources[entry] == hashlib.sha256((ROOT / entry).read_bytes()).hexdigest()
    assert any(Path(name).name.startswith("test_") for name in sources)
    import txn_expiry_remote_transport as remote

    assert sources[campaign.WORKER_ENTRY] == remote.WORKER_SHA256


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


def owner_permission(plan, commit, artifact_digest, inputs):
    provenance = {
        key: {"route": route, "sha256": hashlib.sha256(route.encode()).hexdigest()}
        for key, route in commit_baseline.ROUTES.items()
    }
    return {
        **campaign.permission_bindings(plan, commit, artifact_digest, inputs),
        "ownerIdentity": "offline-fixture-not-permission",
        "permissionReference": "offline-fixture",
        "recoveryOwner": "offline-recovery",
        "credentialPrincipal": {
            "clientId": "offline-client",
            "subject": "offline-subject",
            "requiredScopes": ["https://www.googleapis.com/auth/cloud-platform"],
        },
        "databaseProjectionDigest": database_evidence(DATABASE_BODY)[
            "projectionDigest"
        ],
        "authConfigDigest": digest(AUTH_BODY),
        "baselineProvenance": provenance,
        "issuedAt": time.time() - 1,
        "expiresAt": time.time() + 4800,
    }


class Admission:
    """A complete, locally built O7 artifact set for the campaign."""

    def __init__(self, tmp_path, *, nonce=NONCE):
        self.descriptor = campaign.descriptor()
        self.source = frozen_checkout(tmp_path)
        self.commit = subprocess.check_output(
            ["git", "-C", str(self.source), "rev-parse", "HEAD"], text=True
        ).strip()
        self.artifact_path = tmp_path / "artifact"
        self.artifact_path.write_bytes(b"retained transaction expiry artifact")
        self.plan = self.descriptor.plan_compiler(nonce)
        self.execution_plan = campaign.execution_plan(self.plan)
        self.permission = owner_permission(
            self.plan,
            self.commit,
            hashlib.sha256(self.artifact_path.read_bytes()).hexdigest(),
            campaign.source_map(),
        )
        self.permission_path = tmp_path / "permission.json"
        self.permission_path.write_text(json.dumps(self.permission))
        self.inputs = admission.freeze_inputs(
            self.permission_path,
            self.plan,
            source_root=self.source,
            artifact_path=self.artifact_path,
        )
        self.ledger = tmp_path / "ledger"
        self.ledger.mkdir()
        (self.ledger / "state.json").write_text(
            json.dumps({"kind": "shared-ledger", "envelopes": {}, "reservations": {}})
        )
        self.manifest = {
            "kind": campaign.MANIFEST_KIND,
            "inputsDigest": self.inputs["inputsDigest"],
        }
        self.manifest_bytes = json.dumps(self.manifest).encode()
        self.manifest_path = tmp_path / "manifest.json"
        self.manifest_path.write_bytes(self.manifest_bytes)
        self.manifest_path.chmod(0o600)
        self.launcher_path = HERE / "txn_expiry_o8.py"
        self.approval = self._approval()
        self.approval_path = tmp_path / "approval.json"
        self.approval_path.write_text(json.dumps(self.approval))
        self.approval_path.chmod(0o600)
        self.handoff_path = tmp_path / "handoff.json"
        self.handoff_path.write_text(
            json.dumps(
                {
                    "kind": txn_expiry_o8.HANDOFF_KIND,
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
            "campaignId": CAMPAIGN_ID,
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


def test_frozen_inputs_bind_the_plan_permission_and_source_snapshot(tmp_path):
    built = Admission(tmp_path)
    inputs = built.inputs
    assert inputs["kind"] == campaign.FROZEN_INPUTS_KIND
    assert inputs["plan"]["campaignId"] == CAMPAIGN_ID
    assert inputs["bounds"]["totalRequests"] == 95
    assert inputs["bounds"]["contendedRequestTimeoutSeconds"] == 120
    assert inputs["sourceCommit"] == built.commit
    admission.validate_frozen_inputs(inputs)
    generation = admission.abort_generation(inputs)
    assert set(generation["sourceDigests"]) == {
        "shared_gate.py",
        "reservations.py",
        "o8_admission.py",
        "txn_expiry_admission.py",
        "txn_expiry_descriptor.py",
        "txn_expiry_gate.py",
    }


def test_the_synthetic_approval_passes_the_shared_o7_check_set(tmp_path):
    built = Admission(tmp_path)
    admitted = admission.validate_o7_admission(**built.bindings())
    assert admitted["campaignId"] == CAMPAIGN_ID
    assert admitted["ledgerRoot"] == str(built.ledger.resolve())


@pytest.mark.parametrize(
    "damage",
    [
        {"ownerIdentity": "agent"},
        {"recoveryOwner": "<<fill me in>>"},
        {"permissionReference": "  "},
        {"wallSeconds": 1380},
        {"recoverySeconds": 240},
        {"timing": "control-clock"},
        {"ownedResourceCount": 4},
        {"planDigest": "0" * 64},
        {"authConfigDigest": "not-a-digest"},
        {"baselineProvenance": None},
    ],
    ids=[
        "placeholder-owner",
        "placeholder-recovery",
        "blank-reference",
        "wrong-wall",
        "wrong-recovery",
        "simulated-timing",
        "wrong-resource-count",
        "wrong-plan-digest",
        "malformed-auth-baseline",
        "missing-provenance",
    ],
)
def test_a_permission_that_does_not_bind_the_campaign_is_refused(tmp_path, damage):
    built = Admission(tmp_path)
    built.permission_path.write_text(json.dumps({**built.permission, **damage}))
    with pytest.raises(ValueError):
        admission.freeze_inputs(
            built.permission_path,
            built.plan,
            source_root=built.source,
            artifact_path=built.artifact_path,
        )


def test_another_campaigns_approval_is_refused(tmp_path):
    built = Admission(tmp_path)
    foreign = {**built.approval, "campaignId": "FS-LIMIT-API-REQUEST-BYTES"}
    with pytest.raises(ValueError, match="another campaign"):
        admission.validate_o7_admission(**built.bindings(approval=foreign))
    foreign_kind = {**built.approval, "kind": "request-bytes-o8-approval-v1"}
    with pytest.raises(ValueError):
        admission.validate_o7_admission(**built.bindings(approval=foreign_kind))
    foreign_plan = copy.deepcopy(built.inputs)
    foreign_plan["plan"]["campaignId"] = "FS-LIMIT-API-REQUEST-BYTES"
    with pytest.raises(ValueError):
        admission.validate_o7_admission(**built.bindings(inputs=foreign_plan))


@pytest.mark.parametrize(
    "damage",
    [
        {"status": "pending-independent-o7-review"},
        {"artifactProfile": "request-bytes-000000000"},
        {"ledgerRoot": "/nonexistent/ledger"},
        {"launcherSha256": "0" * 64},
        {"windowExpiresAt": lambda now: now + 60},
        {"executionHost": {"platform": "other", "machine": "other"}},
    ],
    ids=[
        "not-approved",
        "wrong-profile",
        "wrong-ledger",
        "wrong-launcher",
        "short-window",
        "wrong-host",
    ],
)
def test_an_approval_binding_that_differs_is_refused(tmp_path, damage):
    built = Admission(tmp_path)
    # Window cases are resolved now, not at import: a long suite would
    # otherwise leave a "future" window already in the past by the time the
    # case runs, and a literal offset computed at collection time is not
    # deterministic relative to the test's own clock. The host case uses a
    # platform/machine pair that cannot equal any real `execution_host()`
    # value, so it refuses on every runner instead of only ones that are not
    # linux/x86_64.
    now = time.time()
    damage = {
        key: value(now) if callable(value) else value for key, value in damage.items()
    }
    with pytest.raises(ValueError):
        admission.validate_o7_admission(
            **built.bindings(approval={**built.approval, **damage})
        )


def test_the_current_host_binding_is_accepted(tmp_path):
    """The positive twin of the wrong-host case above: this runner's own
    platform/machine pair, whatever it is, passes."""
    built = Admission(tmp_path)
    approval = {**built.approval, "executionHost": admission.execution_host()}
    admitted = admission.validate_o7_admission(**built.bindings(approval=approval))
    assert admitted["campaignId"] == CAMPAIGN_ID


def test_a_drifted_source_is_refused_before_any_wire(tmp_path):
    built = Admission(tmp_path)
    drifted = built.source / campaign.GATE_ENTRY
    drifted.write_bytes(drifted.read_bytes() + b"\n# drift\n")
    with pytest.raises(ValueError, match="clean frozen source snapshot"):
        admission._provenance(built.source, built.commit, built.inputs["sourceInputs"])


def test_fresh_admission_refuses_a_reserved_nonce_or_spent_permission(tmp_path):
    built = Admission(tmp_path)
    admission.validate_fresh_admission(built.ledger, built.plan, built.permission)
    state = json.loads((built.ledger / "state.json").read_text())
    state["reservations"]["x"] = {"claim": {"nonceDigest": digest(NONCE), "locks": []}}
    (built.ledger / "state.json").write_text(json.dumps(state))
    with pytest.raises(ValueError, match="nonce already reserved"):
        admission.validate_fresh_admission(built.ledger, built.plan, built.permission)
    state["reservations"] = {}
    state["envelopes"]["e"] = {
        "envelope": {"permissionDigest": digest(built.permission)}
    }
    (built.ledger / "state.json").write_text(json.dumps(state))
    with pytest.raises(ValueError, match="permission already spent"):
        admission.validate_fresh_admission(built.ledger, built.plan, built.permission)


def test_the_gate_plan_fits_the_shared_gate_and_the_ledger_claim(tmp_path):
    import reservations
    import shared_gate

    built = Admission(tmp_path)
    gate_plan = admission.gate_plan_for(built.inputs, built.permission)
    job = gate_plan["jobs"][campaign.JOB]
    assert len(job["observation"]) == 50
    assert len(job["recovery"]) == 29
    assert gate_plan["wallSeconds"] == 1200
    assert gate_plan["recoverySeconds"] == 240
    assert sum(1 for entry in job["schedule"] if entry.get("creates") is False) == 27
    shared_gate.create(tmp_path / "gate", gate_plan)
    claim = admission.reservation_claim(
        built.inputs, gate_path=tmp_path / "claimed-gate", gate_plan=gate_plan
    )
    assert claim["durationSeconds"] == 1200
    assert claim["gateJob"] == campaign.JOB
    reservations._claim(claim)


def test_the_handoff_must_bind_the_permission(tmp_path):
    built = Admission(tmp_path)
    assert (
        txn_expiry_o8.validate_handoff(
            json.loads(built.handoff_path.read_text()), built.permission
        )
        == TOKEN
    )
    with pytest.raises(ValueError):
        txn_expiry_o8.validate_handoff(
            {
                "kind": txn_expiry_o8.HANDOFF_KIND,
                "permissionDigest": "0" * 64,
                "token": TOKEN,
            },
            built.permission,
        )
    with pytest.raises(ValueError):
        txn_expiry_o8.validate_handoff(
            {
                "kind": "request-bytes-bearer-token-v1",
                "permissionDigest": digest(built.permission),
                "token": TOKEN,
            },
            built.permission,
        )


def test_the_plan_reference_documents_stay_below_the_nonce(tmp_path):
    built = Admission(tmp_path)
    for name in built.plan["ownedResources"]:
        assert f"/oracle/{NONCE}/txn-expiry-04/" in name
    assert plan_module.document_prefix(NONCE) in built.plan["ownedScope"]
