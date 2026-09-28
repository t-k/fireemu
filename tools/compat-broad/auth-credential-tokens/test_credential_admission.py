"""Offline O7 admission for the AUTH-CREDENTIAL campaign: freeze, validate, refuse."""

from __future__ import annotations

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
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT / "tools/compat-broad"))
sys.path.insert(0, str(ROOT / "tools/compat-broad/o8-core"))
sys.path.insert(0, str(ROOT / "tools/compat-broad/production-admission"))

import credential_admission as admission
import credential_descriptor as campaign
import credential_gate as gate_module
import o8_admission
import o8_campaign
import reservations
from broad_contract import digest
from credential_cases import CAMPAIGN_ID

NONCE = "5b3f9c1e7a2d4f608c1b2a3d4e5f6071"
AUTH_BODY = {"name": "projects/592603257417/config", "mfa": {"state": "DISABLED"}}
PROJECT_BODY = {"projectId": "fireemu-35fe6", "projectNumber": "592603257417"}


def frozen_checkout(tmp_path: Path) -> Path:
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


def owner_permission(plan, commit, artifact_digest, inputs) -> dict:
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
        "authConfigDigest": digest(AUTH_BODY),
        "issuedAt": time.time() - 1,
        "expiresAt": time.time() + 4800,
    }


class Admission:
    """A complete, locally built O7 artifact set for the credential campaign."""

    def __init__(
        self,
        tmp_path: Path,
        *,
        signing: bool = True,
        preparation: bool = False,
        fixture_origin=None,
    ):
        self.descriptor = (
            campaign.preparation_descriptor() if preparation else campaign.descriptor()
        )
        self.source = frozen_checkout(tmp_path)
        self.commit = subprocess.check_output(
            ["git", "-C", str(self.source), "rev-parse", "HEAD"], text=True
        ).strip()
        self.artifact_path = tmp_path / "artifact"
        self.artifact_path.write_bytes(b"retained credential artifact")
        self.plan = self.descriptor.plan_compiler(NONCE, signing=signing)
        self.permission = owner_permission(
            self.plan,
            self.commit,
            hashlib.sha256(self.artifact_path.read_bytes()).hexdigest(),
            campaign.source_map(),
        )
        if preparation:
            self.permission = {
                **campaign.preparation_permission_bindings(
                    self.plan,
                    self.commit,
                    hashlib.sha256(self.artifact_path.read_bytes()).hexdigest(),
                    campaign.source_map(),
                ),
                "ownerIdentity": "offline-fixture-not-production-permission",
                "recoveryOwner": "offline-fixture-recovery",
                "permissionReference": "synthetic-preparation-fixture-only",
                "credentialPrincipal": {
                    "clientId": "client-1",
                    "verifiedEmail": "fixture@example.invalid",
                    "requiredScopes": [campaign.PRINCIPAL_SCOPE],
                },
                "authorizedUserDigest": digest(
                    {
                        "type": "authorized_user",
                        "client_id": "client-1",
                        "client_secret": "fixture-secret",
                        "refresh_token": "fixture-refresh",
                    }
                ),
                "apiKeyDigest": digest("fixture-bootstrap-api-key"),
                "issuedAt": time.time() - 1,
                "expiresAt": time.time() + 4800,
                "fixtureOrigin": fixture_origin,
            }
        self.permission_path = tmp_path / "permission.json"
        self.permission_path.write_text(json.dumps(self.permission))
        freeze = (
            admission.freeze_preparation_inputs
            if preparation
            else admission.freeze_inputs
        )
        self.inputs = freeze(
            self.permission_path,
            self.plan,
            source_root=self.source,
            artifact_path=self.artifact_path,
        )
        self.ledger = tmp_path / "ledger"
        reservations.Ledger.create(self.ledger)
        self.manifest = {
            "kind": self.descriptor.manifest_kind,
            "inputsDigest": self.inputs["inputsDigest"],
        }
        self.manifest_bytes = json.dumps(self.manifest).encode()
        self.manifest_path = tmp_path / "manifest.json"
        self.manifest_path.write_bytes(self.manifest_bytes)
        self.manifest_path.chmod(0o600)
        self.launcher_path = HERE / "credential_o8.py"
        self.approval = self._approval()
        self.approval_path = tmp_path / "approval.json"
        self.approval_path.write_text(json.dumps(self.approval))
        self.approval_path.chmod(0o600)
        self.handoff = {
            "kind": admission.HANDOFF_KIND,
            "permissionDigest": digest(self.permission),
            "token": "offline-fixture-token",
            "apiKey": "offline-fixture-key",
            "signing": {"serviceAccount": campaign.SERVICE_ACCOUNT}
            if signing
            else None,
        }
        self.handoff_path = tmp_path / "handoff.json"
        self.handoff_path.write_text(json.dumps(self.handoff))
        self.handoff_path.chmod(0o600)

    def _approval(self) -> dict:
        now = time.time()
        return {
            "kind": self.descriptor.approval_kind,
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

    def bindings(self, **overrides) -> dict:
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

    def argv(self, tmp_path: Path) -> list[str]:
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


# --- the descriptor ------------------------------------------------------------------


def test_the_descriptor_constructs_with_every_member_real() -> None:
    descriptor = campaign.descriptor()
    assert descriptor.campaign_id == CAMPAIGN_ID
    assert descriptor.window_seconds == 600 + 60
    assert descriptor.binds_campaign_id
    assert descriptor.artifact_profile.startswith("auth-credential-")
    assert set(descriptor.required_source_entries) <= set(descriptor.source_map())
    members = descriptor.members()
    assert all(members[name] is not None for name in o8_campaign.REQUIRED_MEMBERS)
    # Dropping any member is refused at construction, not at admission time.
    for name in o8_campaign.REQUIRED_MEMBERS:
        with pytest.raises(ValueError, match="requires every member"):
            o8_campaign.CampaignDescriptor(
                **{k: v for k, v in members.items() if k != name}
            )


def test_preparation_descriptor_is_separate_but_reuses_campaign_members() -> None:
    prep = campaign.preparation_descriptor()
    assert prep.campaign_id == campaign.CAMPAIGN
    assert prep.permission_kind == "auth-credential-bootstrap-permission-v1"
    assert prep.frozen_inputs_kind == "auth-credential-bootstrap-frozen-inputs-v1"
    assert prep.approval_kind == "auth-credential-bootstrap-approval-v1"
    assert prep.manifest_kind == "auth-credential-bootstrap-manifest-v1"
    assert prep.transport_bound is campaign.preparation_transport_bound


def test_preparation_real_issuer_binds_independent_fixture_authority(tmp_path):
    fixture = Admission(tmp_path, preparation=True)
    binding, binding_digest = campaign.remote.worker_binding()
    capability = admission.issue_preparation_capability(
        **fixture.bindings(), binding=binding, binding_digest=binding_digest
    )
    try:
        assert admission.issued_capability(capability)
        plan = admission.preparation_gate_plan_for(fixture.inputs, fixture.permission)
        assert plan["bootstrap"]["permissionDigest"] == digest(fixture.permission)
        assert plan["wallSeconds"] == 600 and plan["recoverySeconds"] == 60
        assert plan["dataRequests"] + plan["managementRequests"] == 53
    finally:
        admission.revoke_production_capability(capability)


def test_the_budget_is_the_lane_budget_with_management_slots_inside_it() -> None:
    ledger = campaign.ledger_budget()
    assert ledger == {
        "requests": 60,
        "accounts": 4,
        "resources": 4,
        "costMicrousd": 50_000,
    }
    bounds = campaign.frozen_bounds()
    assert bounds["dataRequests"] == 42
    assert bounds["managementRequests"] == 7
    assert bounds["dataRequests"] + bounds["managementRequests"] <= ledger["requests"]
    assert bounds["caseCount"] == 19 and bounds["signingDependentCases"] == 11
    for signing, management in ((True, 7), (False, 4)):
        reference = campaign.plan_compiler(NONCE, signing=signing)
        assert reference["bounds"]["managementRequests"] == management
        assert (
            reference["bounds"]["observationRequests"]
            + reference["bounds"]["cleanupRequests"]
            + management
            <= 60
        )


def test_the_plan_reference_names_exactly_one_gate_plan() -> None:
    reference = campaign.plan_compiler(NONCE, signing=True)
    plan = campaign.execution_plan(reference)
    assert plan["nonce"] == NONCE and plan["signing"] is True
    assert len(reference["runnableCases"]) == 19
    without = campaign.plan_compiler(NONCE, signing=False)
    assert len(without["runnableCases"]) == 8
    assert without["planDigest"] != reference["planDigest"]
    for drift in (
        {"signing": False},
        {"planDigest": "0" * 64},
        {"nonce": "f" * 32},
        {"runnableCases": []},
    ):
        with pytest.raises(ValueError, match="plan reference"):
            campaign.execution_plan({**reference, **drift})


def test_lock_scopes_name_the_accounts_the_config_reads_and_the_signer() -> None:
    reference = campaign.plan_compiler(NONCE, signing=True)
    locks = campaign.lock_scopes(reference)
    keys = {lock["key"]: lock["mode"] for lock in locks}
    assert (
        keys[f"project/fireemu-35fe6/auth/accounts/fireemu-cred-{NONCE[:8]}-0"]
        == "WRITE"
    )
    assert keys[f"project/fireemu-35fe6/auth/accounts/custom-{NONCE}"] == "WRITE"
    assert keys["project/fireemu-35fe6/auth/config"] == "READ"
    assert keys["project/fireemu-35fe6/api-key-binding"] == "READ"
    assert (
        keys[
            f"project/fireemu-35fe6/iam/serviceAccounts/{campaign.SERVICE_ACCOUNT}/signBlob"
        ]
        == "READ"
    )
    for lock in locks:
        reservations._scope(lock)  # every key parses under the Ledger grammar
    without = campaign.lock_scopes(campaign.plan_compiler(NONCE, signing=False))
    assert not any(
        "signBlob" in lock["key"] or "custom-" in lock["key"] for lock in without
    )


# --- freeze and validate ---------------------------------------------------------------


def test_frozen_inputs_pass_the_shared_admission_check_set(built) -> None:
    admitted = admission.validate_o7_admission(**built.bindings())
    assert admitted["campaignId"] == CAMPAIGN_ID
    assert admitted["retained"]["artifactSha256"] == built.inputs["artifactSha256"]
    cap = admission.issue_production_capability(
        **built.bindings(),
        binding=campaign.remote.worker_binding()[0],
        binding_digest=campaign.remote.worker_binding()[1],
    )
    assert o8_admission.issued_capability(cap)
    admission.revoke_production_capability(cap)


def test_an_approval_for_another_campaign_is_refused(built) -> None:
    with pytest.raises(ValueError, match="another campaign"):
        admission.validate_o7_admission(
            **built.bindings(
                approval={**built.approval, "campaignId": "FS-LIMIT-API-REQUEST-BYTES"}
            )
        )


@pytest.mark.parametrize(
    "field,value,match",
    [
        ("planDigest", "0" * 64, "binding differs"),
        ("launcherSha256", "0" * 64, "binding differs"),
        ("ledgerRoot", "/nowhere", "binding differs"),
        ("status", "pending", "not approved"),
        ("artifactProfile", "auth-credential-000000000", "profile differs"),
    ],
)
def test_binding_drift_in_the_approval_is_refused(built, field, value, match) -> None:
    with pytest.raises(ValueError, match=match):
        admission.validate_o7_admission(
            **built.bindings(approval={**built.approval, field: value})
        )


def test_a_permission_missing_the_frozen_auth_config_digest_is_refused(
    tmp_path,
) -> None:
    built = Admission(tmp_path)
    broken = dict(built.permission)
    del broken["authConfigDigest"]
    built.permission_path.write_text(json.dumps(broken))
    with pytest.raises(ValueError, match="Auth config digest"):
        admission.freeze_inputs(
            built.permission_path,
            built.plan,
            source_root=built.source,
            artifact_path=built.artifact_path,
        )


def test_a_modified_frozen_source_is_refused_by_provenance(built) -> None:
    (built.source / campaign.GATE_ENTRY).write_text("# drift\n")
    with pytest.raises(ValueError, match="clean frozen source"):
        admission._provenance(
            built.source, built.inputs["sourceCommit"], built.inputs["sourceInputs"]
        )


def test_the_frozen_inputs_name_the_collector_comparator_worker_and_transport(
    built,
) -> None:
    sources = built.inputs["sourceInputs"]
    for entry in (
        campaign.COLLECTOR_ENTRY,
        campaign.COMPARATOR_ENTRY,
        campaign.WORKER_ENTRY,
        campaign.TRANSPORT_ENTRY,
        campaign.GATE_ENTRY,
    ):
        assert entry in sources
    assert sources[campaign.WORKER_ENTRY] == campaign.remote.WORKER_SHA256
    generation = admission.abort_generation(built.inputs)
    assert set(generation["sourceDigests"]) == {
        "shared_gate.py",
        "reservations.py",
        "o8_admission.py",
        "credential_admission.py",
        "credential_descriptor.py",
    }


# --- the handoff ------------------------------------------------------------------------


def test_the_handoff_shape_carries_bearer_key_and_optional_signing(built) -> None:
    accepted = admission.validate_handoff(built.handoff, built.permission, built.plan)
    assert set(accepted) == {"kind", "token", "apiKey", "signing"}
    assert accepted["signing"] == {"serviceAccount": campaign.SERVICE_ACCOUNT}


@pytest.mark.parametrize(
    "mutate,match",
    [
        (
            lambda h: h.update(kind="request-bytes-bearer-token-v1"),
            "bound credential handoff",
        ),
        (lambda h: h.update(permissionDigest="0" * 64), "bound credential handoff"),
        (lambda h: h.update(token="has space"), "bound credential handoff"),
        (lambda h: h.pop("apiKey"), "bound credential handoff"),
        (
            lambda h: h.update(signing={"serviceAccount": "other@example.invalid"}),
            "campaign service account",
        ),
        (
            lambda h: h.update(
                signing={"serviceAccount": campaign.SERVICE_ACCOUNT, "key": "x"}
            ),
            "campaign service account",
        ),
        (lambda h: h.update(signing=None), "differs from the frozen plan"),
    ],
)
def test_a_malformed_or_mismatched_handoff_is_refused(built, mutate, match) -> None:
    handoff = json.loads(json.dumps(built.handoff))
    mutate(handoff)
    with pytest.raises(ValueError, match=match):
        admission.validate_handoff(handoff, built.permission, built.plan)


def test_a_signing_declaration_is_refused_against_a_plan_frozen_without_it(
    tmp_path,
) -> None:
    built = Admission(tmp_path, signing=False)
    assert built.plan["signing"] is False
    with pytest.raises(ValueError, match="differs from the frozen plan"):
        admission.validate_handoff(
            {**built.handoff, "signing": {"serviceAccount": campaign.SERVICE_ACCOUNT}},
            built.permission,
            built.plan,
        )
    accepted = admission.validate_handoff(built.handoff, built.permission, built.plan)
    assert accepted["signing"] is None


# --- the claim --------------------------------------------------------------------------


def test_the_reservation_claim_binds_the_gate_plan_and_the_lane_budget(
    built, tmp_path
) -> None:
    gate_plan = admission.gate_plan_for(built.inputs, built.permission)
    claim = admission.reservation_claim(
        built.inputs, gate_path=tmp_path / "gate", gate_plan=gate_plan
    )
    assert claim["campaignId"] == CAMPAIGN_ID
    assert claim["gateJob"] == gate_module.JOB
    assert claim["budget"] == campaign.ledger_budget()
    assert claim["gatePlanDigest"] == digest(gate_plan)
    assert claim["durationSeconds"] == 600
    reservations._claim(claim)


def test_bootstrap_permission_has_a_separate_typed_claim_contract(tmp_path) -> None:
    built = Admission(tmp_path, preparation=True)
    prep = built.permission
    plan = admission.preparation_gate_plan_for(built.inputs, prep)
    plan["collectorSourceDigest"] = digest(built.inputs["sourceInputs"])
    validated = admission.validate_bootstrap_permission(prep, plan=plan)
    assert validated["kind"] == "auth-credential-bootstrap-permission-v1"
    claim = admission.bootstrap_reservation_claim(
        built.inputs,
        permission=validated,
        gate_plan=plan,
        gate_path=tmp_path / "bootstrap-gate",
    )
    reservations._claim(claim)
    envelope = {
        "permissionDigest": digest(validated),
        "issuedAt": validated["issuedAt"],
        "expiresAt": validated["expiresAt"],
        "limits": dict(claim["budget"]),
        "concurrency": 1,
        "scopes": list(claim["locks"]),
    }
    ticket = reservations.Ledger(built.ledger).reserve(envelope, claim, plan)
    assert (
        ticket["reservation"]
        in reservations.Ledger(built.ledger).snapshot()["reservations"]
    )
    assert claim["manifestDigest"] == built.inputs["planDigest"]
    short = {**prep, "expiresAt": prep["issuedAt"] + 599}
    short_plan = {**plan, "permissionExpiresAt": short["expiresAt"]}
    with pytest.raises(ValueError, match="window"):
        admission.validate_bootstrap_permission(short, plan=short_plan)
    altered = {**plan, "wallSeconds": 599}
    with pytest.raises(ValueError, match="Gate plan"):
        admission.bootstrap_reservation_claim(
            built.inputs,
            permission=prep,
            gate_plan=altered,
            gate_path=tmp_path / "other",
        )


def test_minimal_bootstrap_permission_cannot_replace_independent_authority(tmp_path):
    built = Admission(tmp_path, preparation=True)
    plan = admission.preparation_gate_plan_for(built.inputs, built.permission)
    stripped = {
        key: built.permission[key]
        for key in (
            "kind",
            "project",
            "projectNumber",
            "nonce",
            "credentialPrincipal",
            "authorizedUserDigest",
            "preparationPlanDigest",
            "issuedAt",
            "expiresAt",
        )
    }
    with pytest.raises(ValueError):
        admission.validate_bootstrap_permission(stripped, plan=plan)


def test_the_shared_ledger_hosts_the_account_shaped_gate_plan(built, tmp_path) -> None:
    gate_plan = admission.gate_plan_for(built.inputs, built.permission)
    claim = admission.reservation_claim(
        built.inputs, gate_path=tmp_path / "gate", gate_plan=gate_plan
    )
    envelope = {
        "permissionDigest": digest(built.permission),
        "issuedAt": built.permission["issuedAt"],
        "expiresAt": built.permission["expiresAt"],
        "limits": dict(claim["budget"]),
        "concurrency": 1,
        "scopes": list(claim["locks"]),
    }
    ticket = reservations.Ledger(built.ledger).reserve(envelope, claim, gate_plan)
    assert (
        ticket["reservation"]
        in reservations.Ledger(built.ledger).snapshot()["reservations"]
    )
