"""O8 admission tests for the request-byte boundary campaign.

Every artifact here is built locally. No production request is made, no
credential is read, no origin outside the process is contacted, and the shared
Ledger is only ever a temporary copy.
"""

import copy
import hashlib
import json
import os
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

import request_bytes_admission as admission
import request_bytes_descriptor as campaign
import request_bytes_o8
import request_bytes_remote_transport
from broad_contract import digest
from o8_campaign import CAMPAIGN_APPROVAL_FIELDS, CampaignDescriptor

# The baseline derivation is the Commit lane's reviewed module, reached the way
# the descriptor reaches it: by path, never by prepending that lane to sys.path.
commit_baseline = campaign.commit_baseline

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
BASELINE_BODIES = [
    (commit_baseline.ROUTES["projectIdentity"], PROJECT_BODY),
    (commit_baseline.ROUTES["database"], DATABASE_BODY),
    (commit_baseline.ROUTES["authConfig"], AUTH_BODY),
]


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
        record,
        evidence_root=evidence,
        production_roots=(evidence.resolve().parts,),
    )


CAMPAIGN_ID = "FS-LIMIT-API-REQUEST-BYTES"


def test_the_descriptor_is_complete_and_published_budget_bound():
    descriptor = campaign.descriptor()
    assert descriptor.campaign_id == CAMPAIGN_ID
    assert descriptor.approval_fields == CAMPAIGN_APPROVAL_FIELDS
    assert len(descriptor.approval_fields) == 17
    assert descriptor.binds_campaign_id is True
    assert descriptor.budget == campaign.budget_document()["budget"]
    assert descriptor.budget["maxRequestBytes"] == 11_534_337
    assert (
        descriptor.budget["maxRequestBytes"]
        == request_bytes_remote_transport.MAX_REQUEST_BYTES
    )
    assert descriptor.budget["maxHttpRequests"] == 265
    assert descriptor.budget["maxDataRequests"] == 258
    assert campaign.ledger_budget() == {
        "requests": 265,
        "accounts": 1,
        "resources": 51,
        # The maximum, every probe accepted, plus the declared recovery reserve.
        "costMicrousd": 303,
    }
    # Derived from the published shadow's own Rust SHA, so it rebinds with it.
    assert (
        descriptor.artifact_profile
        == "request-bytes-" + campaign.shadow_record()["runtime"]["sourceCommit"][:9]
    )
    assert (descriptor.campaign_seconds, descriptor.recovery_seconds) == (1150, 550)
    # The permission window is the campaign wall plus its recovery reserve, so
    # it moved with them. It is not the Gate's wall, which stays under the
    # under the Gate's 1200 cap.
    assert descriptor.window_seconds == 1700


def test_the_descriptor_targets_the_disposable_firestore_oracle():
    assert campaign.PROJECT == "fireemu-oracle-sbx"
    assert not hasattr(campaign, "NUMBER")
    descriptor = campaign.descriptor()
    assert descriptor.plan_compiler(NONCE)["project"] == "fireemu-oracle-sbx"


def test_o7_rejects_an_unbound_project_number_before_shared_admission(monkeypatch):
    def unexpected_shared_admission(*args, **kwargs):
        raise AssertionError("O7 must reject the missing project number first")

    monkeypatch.setattr(
        admission.o8_admission,
        "validate_o7_admission",
        unexpected_shared_admission,
    )
    for permission in (
        {},
        {"projectNumber": None},
        {"projectNumber": 1},
        {"projectNumber": "<project-number>"},
    ):
        with pytest.raises(ValueError, match="project number"):
            admission.validate_o7_admission(permission=permission)


def test_the_descriptor_rejects_a_historical_ten_mib_shadow_receipt():
    historical = json.loads(
        (
            ROOT / "spec/compatibility/broad-runs/fs-request-bytes-local-shadow.json"
        ).read_text()
    )
    assert [row["requestBytes"] for row in historical["probeOutcomes"]] == [
        10_485_759,
        10_485_760,
        10_485_761,
    ]
    from request_bytes_shadow import observation_source_digest

    current_source = observation_source_digest()
    historical["sourceDigestBefore"] = current_source
    historical["sourceDigestAfter"] = current_source
    with pytest.raises(ValueError, match="current 11 MiB boundary"):
        campaign.validate_shadow_record(historical)
    published = campaign.shadow_record()
    assert published["sourceDigestBefore"] == current_source
    assert published["sourceDigestAfter"] == current_source
    assert len(published["runtime"]["sourceCommit"]) == 40
    assert [row["requestBytes"] for row in published["probeOutcomes"]] == [
        11_534_335,
        11_534_336,
        11_534_337,
    ]


@pytest.mark.parametrize(
    "mutate",
    [
        lambda record: record["probeOutcomes"][1].update(requestBytes=11_534_335),
        lambda record: record["probeOutcomes"][1].update(httpStatus=400),
        lambda record: record["probeOutcomes"][2].update(errorStatus="OUT_OF_RANGE"),
        lambda record: record["probeOutcomes"][2].update(
            responseBody='{"error":{"code":400,"message":"wrong","status":"INVALID_ARGUMENT"}}'
        ),
        lambda record: record["observation"]["localJournal"].update(skippedCount=16),
        lambda record: record.update(sourceDigestAfter="0" * 64),
    ],
)
def test_shadow_binding_rejects_stale_or_mutated_boundary_observations(mutate):
    current = copy.deepcopy(campaign.shadow_record())
    mutate(current)
    with pytest.raises(ValueError):
        campaign.validate_shadow_record(current)


def test_the_transport_deadline_is_the_published_one_and_the_enforced_one():
    assert campaign.transport_deadline_seconds() == 60.0
    assert request_bytes_remote_transport.TIMEOUT == 60.0
    published = campaign.budget_document()
    assert published["transportDeadline"]["perRequestSeconds"] == 60.0
    assert published["budget"]["perRequestTimeoutSeconds"] == 60.0


def test_the_lock_scopes_cover_the_nonce_unique_owned_namespace():
    descriptor = campaign.descriptor()
    plan = descriptor.plan_compiler(NONCE)
    locks = descriptor.lock_scopes(plan)
    write = [lock for lock in locks if lock["mode"] == "WRITE"]
    assert len(write) == 1
    assert NONCE in write[0]["key"]
    assert write[0]["key"].endswith("/request-bytes-01/*")
    assert plan["ownedResourceCount"] == 51
    assert f"/oracle/{NONCE}/request-bytes-01" in plan["ownedScope"]
    assert {lock["mode"] for lock in locks} == {"WRITE", "READ"}


def test_the_source_map_names_the_collector_comparator_and_worker():
    sources = campaign.source_map()
    for entry in (
        campaign.COLLECTOR_ENTRY,
        campaign.COMPARATOR_ENTRY,
        campaign.WORKER_ENTRY,
    ):
        assert sources[entry] == hashlib.sha256((ROOT / entry).read_bytes()).hexdigest()
    # The sweep is deliberate: a test edit moves the frozen digest rather than
    # sitting outside it, and every published bound source is covered.
    assert any(Path(name).name.startswith("test_") for name in sources)
    assert all(name in sources for name in campaign.budget_document()["boundSources"])
    assert sources[campaign.WORKER_ENTRY] == (
        request_bytes_remote_transport._WORKER_SHA256
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
        **campaign.permission_bindings(
            plan,
            commit,
            artifact_digest,
            inputs,
            baseline,
            project_number="1" * 12,
        ),
        "ownerIdentity": "offline-fixture-not-permission",
        "permissionReference": "offline-fixture",
        "recoveryOwner": "offline-recovery",
        "credentialPrincipal": {
            "clientId": "offline-client",
            "subject": "offline-subject",
            "requiredScopes": ["https://www.googleapis.com/auth/cloud-platform"],
        },
        "gateReservationSeconds": {
            "upload": 60.0,
            "observationSlot": 3.0,
            "recoverySlot": 3.0,
            "slotBasis": admission.PLANNING_ASSUMPTION,
        },
        "issuedAt": time.time() - 1,
        "expiresAt": time.time() + 4800,
    }


class Admission:
    """A complete, locally built O7 artifact set for the request-byte campaign."""

    def __init__(self, tmp_path, *, nonce=NONCE, ledger=None):
        self.descriptor = campaign.descriptor()
        self.source = frozen_checkout(tmp_path)
        self.commit = subprocess.check_output(
            ["git", "-C", str(self.source), "rev-parse", "HEAD"], text=True
        ).strip()
        self.artifact_path = tmp_path / "artifact"
        self.artifact_path.write_bytes(b"retained request-byte artifact")
        self.plan = self.descriptor.plan_compiler(nonce)
        self.execution_plan = campaign.execution_plan(self.plan)
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
        # A second campaign may share the Ledger of a first one; a fresh
        # fixture otherwise gets a placeholder that `built` replaces.
        self.ledger = tmp_path / "ledger" if ledger is None else Path(ledger)
        if ledger is None:
            self.ledger.mkdir()
            (self.ledger / "state.json").write_text(
                json.dumps(
                    {"kind": "shared-ledger", "envelopes": {}, "reservations": {}}
                )
            )
        self.manifest = {
            "kind": campaign.MANIFEST_KIND,
            "inputsDigest": self.inputs["inputsDigest"],
        }
        self.manifest_bytes = json.dumps(self.manifest).encode()
        self.manifest_path = tmp_path / "manifest.json"
        self.manifest_path.write_bytes(self.manifest_bytes)
        self.manifest_path.chmod(0o600)
        self.launcher_path = HERE / "request_bytes_o8.py"
        self.approval = self._approval()
        self.approval_path = tmp_path / "approval.json"
        self.approval_path.write_text(json.dumps(self.approval))
        self.approval_path.chmod(0o600)
        self.handoff_path = tmp_path / "handoff.json"
        self.handoff_path.write_text(
            json.dumps(
                {
                    "kind": request_bytes_o8.HANDOFF_KIND,
                    "permissionDigest": digest(self.permission),
                    "token": "offline-fixture-token",
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
    assert inputs["bounds"]["totalRequests"] == 265
    assert inputs["bounds"]["perRequestTimeoutSeconds"] == 60.0
    assert inputs["sourceCommit"] == built.commit
    admission.validate_frozen_inputs(inputs)
    generation = admission.abort_generation(inputs)
    assert set(generation["sourceDigests"]) == {
        "shared_gate.py",
        "reservations.py",
        "o8_admission.py",
        "request_bytes_admission.py",
        "request_bytes_descriptor.py",
        "request_bytes_preflight.py",
        "credential_prep.py",
        "batch_adapter.py",
        "batch_wire.py",
    }
    for path in campaign.TRANSPORT_CLOSURE_SOURCES:
        assert (
            generation["sourceDigests"][Path(path).name] == inputs["sourceInputs"][path]
        )


@pytest.mark.parametrize("path", campaign.TRANSPORT_CLOSURE_SOURCES)
def test_transport_source_mutation_is_outside_frozen_generation(tmp_path, path):
    built = Admission(tmp_path)
    source = built.source / path
    source.write_bytes(source.read_bytes() + b"\n# mutation")
    with pytest.raises(ValueError):
        admission._provenance(built.source, built.commit, built.inputs["sourceInputs"])


def test_noncurrent_source_map_cannot_downgrade_generation_closure(tmp_path):
    built = Admission(tmp_path)
    inputs = copy.deepcopy(built.inputs)
    inputs["sourceInputs"].pop(
        "tools/compat-broad/fs-request-bytes-boundary/request_bytes_campaign.py"
    )
    generation = admission.abort_generation(built.inputs)
    generation["sourceDigests"].pop("batch_wire.py")
    with pytest.raises(ValueError, match="source map differs"):
        campaign.validate_generation(generation, inputs)


def test_unallowlisted_legacy_generation_is_rejected(tmp_path):
    built = Admission(tmp_path)
    generation = admission.abort_generation(built.inputs)
    generation["sourceDigests"] = {
        Path(name).name: built.inputs["sourceInputs"][name]
        for name in campaign.LEGACY_CLOSURE_SOURCES
    }
    with pytest.raises(ValueError, match="source closure incomplete"):
        campaign.validate_generation(generation, built.inputs)


def test_current_generation_cannot_select_legacy_closure(tmp_path):
    built = Admission(tmp_path)
    generation = admission.abort_generation(built.inputs)
    generation["sourceDigests"] = {
        Path(name).name: built.inputs["sourceInputs"][name]
        for name in campaign.LEGACY_CLOSURE_SOURCES
    }
    with pytest.raises(ValueError, match="source closure incomplete"):
        campaign.validate_generation(generation, built.inputs)


def test_retained_historical_generation_uses_allowlisted_metadata():
    record_path = os.environ.get("FIREEMU_REQUEST_BYTES_HISTORICAL_METADATA")
    if record_path is None:
        pytest.skip("retained request-byte metadata is unavailable")
    record = Path(record_path)
    assert (record / "inputs.json").is_file(), (
        f"configured request-byte metadata is unavailable: {record}"
    )
    inputs = json.loads((record / "inputs.json").read_bytes())
    generation = json.loads((record / "receipt.json").read_bytes())["generation"]
    campaign.validate_generation(generation, inputs)
    damaged = copy.deepcopy(generation)
    damaged["sourceCommit"] = "0" * 40
    with pytest.raises(ValueError):
        campaign.validate_generation(damaged, inputs)


@pytest.mark.parametrize(
    "damage",
    [
        {"ownerIdentity": "agent"},
        {"ownerIdentity": ""},
        {"recoveryOwner": "<<fill me in>>"},
        {"permissionReference": "  "},
        {"wallSeconds": 1200},
        {"perRequestTimeoutSeconds": 12.0},
        {"ownedResourceCount": 50},
        {"planDigest": "0" * 64},
        {"projectNumber": None},
        {"projectNumber": "<project-number>"},
    ],
    ids=[
        "placeholder-owner",
        "empty-owner",
        "placeholder-recovery",
        "blank-reference",
        "wrong-wall",
        "wrong-deadline",
        "wrong-resource-count",
        "wrong-plan-digest",
        "missing-project-number",
        "placeholder-project-number",
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
            baseline=built.baseline,
        )


def test_the_frozen_plan_is_a_reference_that_recompiles_to_one_plan():
    """The compiled plan is 63 MB of request bodies; a record binds its digest."""
    reference = campaign.plan_compiler(NONCE)
    assert len(json.dumps(reference)) < 4096
    assert set(reference) == {
        "schemaVersion",
        "campaignId",
        "catalogId",
        "project",
        "database",
        "nonce",
        "planDigest",
        "ownedScope",
        "ownedResourceCount",
        "bounds",
    }
    plan = campaign.execution_plan(reference)
    assert len(plan["executionSchedule"]) == 258
    assert plan["nonce"] == NONCE
    for damaged in (
        {},
        {**reference, "planDigest": "0" * 64},
        {**reference, "ownedResourceCount": 50},
        {**reference, "nonce": "c" * 32},
    ):
        with pytest.raises(ValueError, match="plan reference"):
            campaign.execution_plan(damaged)


def test_bind_execute_refuses_the_reference_instead_of_the_compiled_plan(tmp_path):
    built = Admission(tmp_path)
    capability = consumed(built)
    with pytest.raises(ValueError, match="compiled plan"):
        admission.bind_execute(capability, built.plan, "offline-token")


def test_a_complete_o7_binding_is_admitted(tmp_path):
    built = Admission(tmp_path)
    admitted = admission.validate_o7_admission(**built.bindings())
    assert admitted["campaignId"] == CAMPAIGN_ID
    assert admitted["ledgerRoot"] == str(built.ledger.resolve(strict=False))


@pytest.mark.parametrize(
    "override",
    [
        {"status": "pending"},
        {"kind": "commit-o8-approval-v1"},
        {"inputsDigest": "0" * 64},
        {"planDigest": "0" * 64},
        {"nonceDigest": "0" * 64},
        {"sourceInputsDigest": "0" * 64},
        {"launcherSha256": "0" * 64},
        {"artifactProfile": "repaired-567565bdd"},
        {"ledgerRoot": "/nonexistent/private/ledger"},
        {"windowStartsAt": lambda now: now + 600},
        {"windowExpiresAt": lambda now: now + 10},
        {"executionHost": {"platform": "other", "machine": "other"}},
    ],
)
def test_an_incomplete_o7_binding_is_refused(tmp_path, override):
    built = Admission(tmp_path)
    # Window cases are resolved now, not at import: a long suite would otherwise
    # leave a "future" window already in the past by the time the case runs.
    now = time.time()
    override = {
        key: value(now) if callable(value) else value for key, value in override.items()
    }
    with pytest.raises(ValueError):
        admission.validate_o7_admission(
            **built.bindings(approval={**built.approval, **override})
        )


def test_the_window_must_hold_the_campaign_and_its_recovery(tmp_path):
    built = Admission(tmp_path)
    now = time.time()
    for margin in (built.descriptor.campaign_seconds, 1199):
        with pytest.raises(ValueError, match="window expired"):
            admission.validate_o7_admission(
                **built.bindings(
                    approval={
                        **built.approval,
                        "windowStartsAt": now - 1,
                        "windowExpiresAt": now - 1 + margin,
                    }
                )
            )


def test_another_campaigns_descriptor_cannot_admit_this_approval(tmp_path):
    built = Admission(tmp_path)
    other = CampaignDescriptor(
        **{**built.descriptor.members(), "campaign_id": "FS-DATA-WRITE-COMMIT-03"}
    )
    with pytest.raises(ValueError, match="another campaign"):
        admission.o8_admission.validate_o7_admission(other, **built.bindings())


def issued(built):
    binding, binding_digest = campaign.worker_binding()
    return admission.issue_production_capability(
        **built.bindings(), binding=binding, binding_digest=binding_digest
    )


def test_a_capability_is_issued_against_the_reviewed_worker_source(tmp_path):
    built = Admission(tmp_path)
    capability = issued(built)
    try:
        assert capability.campaign_id == CAMPAIGN_ID
        assert capability.binding_digest == (
            request_bytes_remote_transport._WORKER_SHA256
        )
        assert capability.window_seconds == 1700
    finally:
        admission.revoke_production_capability(capability)


@pytest.mark.parametrize(
    "binding",
    [b"not the reviewed worker", b"", "not bytes", None],
    ids=["other-bytes", "empty", "not-bytes", "missing"],
)
def test_a_capability_is_refused_for_worker_bytes_that_are_not_reviewed(
    tmp_path, binding
):
    built = Admission(tmp_path)
    source, pinned = campaign.worker_binding()
    binding_digest = (
        hashlib.sha256(binding).hexdigest() if isinstance(binding, bytes) else pinned
    )
    assert binding != source
    with pytest.raises(ValueError, match="worker source"):
        admission.issue_production_capability(
            **built.bindings(), binding=binding, binding_digest=binding_digest
        )


def test_the_bound_transport_refuses_anything_but_one_closed_slot_call():
    source, pinned = campaign.worker_binding()
    for value in ({}, {"plan": {}}, "not a dict", {"plan": 1, "phase": 2, "index": 3}):
        with pytest.raises(ValueError, match="closed request-byte wire call"):
            campaign.transport_bound(value, binding=source, binding_digest=pinned)


def test_the_bound_transport_refuses_a_binding_that_is_not_the_reviewed_worker():
    call = {
        "plan": {},
        "phase": "observation",
        "index": 0,
        "operation": {},
        "token": "t",
        "deadline": 1002.5,
    }
    with pytest.raises(ValueError, match="active O7 production capability"):
        campaign.transport_bound(
            call, binding=b"other", binding_digest=hashlib.sha256(b"other").hexdigest()
        )


@pytest.mark.parametrize("phase", ["observation", "recovery"])
@pytest.mark.parametrize(
    ("operation", "expected_timeout"),
    [
        ({"method": "GET"}, 2.5),
        ({"method": "DELETE"}, 2.5),
        ({"method": "POST", "body": b"commit"}, 60.0),
    ],
    ids=["get-small", "delete-small", "commit"],
)
def test_the_bound_transport_uses_operation_timeout_in_every_phase(
    monkeypatch, phase, operation, expected_timeout
):
    source, pinned = campaign.worker_binding()
    calls = []

    monkeypatch.setattr(
        campaign,
        "authorize_transport",
        lambda *args, **kwargs: None,
    )
    monkeypatch.setattr(
        campaign.request_bytes_remote_transport,
        "request",
        lambda *args, **kwargs: calls.append((args, kwargs)) or {"status": 200},
    )

    campaign.transport_bound(
        {
            "plan": {},
            "phase": phase,
            "index": 0,
            "operation": operation,
            "token": "t",
            "deadline": 1002.5,
        },
        binding=source,
        binding_digest=pinned,
        capability=object(),
    )

    assert calls[0][1]["timeout"] == expected_timeout


def consumed(built):
    capability = issued(built)
    capability._consume(
        campaign_id=CAMPAIGN_ID,
        inputs_digest=built.inputs["inputsDigest"],
        ledger_root=built.ledger,
    )
    return capability


def test_the_collector_callable_walks_the_frozen_schedule_in_order(tmp_path):
    built = Admission(tmp_path)
    sent = []

    class FixtureCapability:
        consumed = True

        def _transmit(self, value, **_):
            sent.append(value)
            return {"status": 200}

    capability = FixtureCapability()
    execute = admission.bind_execute(capability, built.execution_plan, "offline-token")
    schedule = built.execution_plan["executionSchedule"]
    for expected in schedule[:4]:
        assert execute({"slot": expected["index"]}, deadline=1002.5) == {"status": 200}
    assert [(item["phase"], item["index"]) for item in sent] == [
        (item["phase"], item["index"]) for item in schedule[:4]
    ]
    assert sent[0]["token"] == "offline-token"
    assert sent[0]["plan"]["campaignId"] == CAMPAIGN_ID


def test_the_collector_callable_cannot_outrun_the_schedule(tmp_path):
    built = Admission(tmp_path)

    class FixtureCapability:
        consumed = True

        def _transmit(self, value, **_):
            return {"status": 200}

    capability = FixtureCapability()
    execute = admission.bind_execute(
        capability,
        built.plan,
        "offline-token",
        schedule=[{"phase": "observation", "index": 0}],
    )
    assert execute({}, deadline=1002.5) == {"status": 200}
    with pytest.raises(ValueError, match="schedule exhausted"):
        execute({}, deadline=1002.5)


def test_a_reused_nonce_or_a_respent_permission_is_refused(tmp_path):
    built = Admission(tmp_path)
    state = {
        "kind": "shared-ledger",
        "envelopes": {},
        "reservations": {
            "row": {"claim": {"nonceDigest": digest(built.plan["nonce"]), "locks": []}}
        },
    }
    (built.ledger / "state.json").write_text(json.dumps(state))
    with pytest.raises(ValueError, match="nonce already reserved"):
        admission.validate_fresh_admission(built.ledger, built.plan, built.permission)

    state["reservations"] = {}
    state["envelopes"] = {
        "e": {"envelope": {"permissionDigest": digest(built.permission)}}
    }
    (built.ledger / "state.json").write_text(json.dumps(state))
    with pytest.raises(ValueError, match="permission already spent"):
        admission.validate_fresh_admission(built.ledger, built.plan, built.permission)

    state["envelopes"] = {}
    (built.ledger / "state.json").write_text(json.dumps(state))
    fresh = admission.validate_fresh_admission(
        built.ledger, built.plan, built.permission
    )
    assert fresh["nonceDigest"] == digest(built.plan["nonce"])


def test_a_lock_key_carrying_the_nonce_also_counts_as_reuse(tmp_path):
    built = Admission(tmp_path)
    locks = built.descriptor.lock_scopes(built.plan)
    (built.ledger / "state.json").write_text(
        json.dumps(
            {
                "kind": "shared-ledger",
                "envelopes": {},
                "reservations": {"row": {"claim": {"locks": locks}}},
            }
        )
    )
    with pytest.raises(ValueError, match="nonce already reserved"):
        admission.validate_fresh_admission(built.ledger, built.plan, built.permission)


def test_an_approval_naming_another_campaign_is_refused(tmp_path):
    """The 17-key schema exists so a cross-campaign replay is refused by name."""
    built = Admission(tmp_path)
    assert built.approval["campaignId"] == CAMPAIGN_ID
    for other in ("FS-DATA-WRITE-COMMIT-TRANSFORMS-03", "", None):
        with pytest.raises(ValueError, match="another campaign|approval artifact"):
            admission.validate_o7_admission(
                **built.bindings(approval={**built.approval, "campaignId": other})
            )
    without = {
        key: value for key, value in built.approval.items() if key != "campaignId"
    }
    with pytest.raises(ValueError, match="approval artifact"):
        admission.validate_o7_admission(**built.bindings(approval=without))


def test_a_commit_frozen_record_cannot_be_admitted_by_this_campaign(tmp_path):
    """Neither direction: the four schema kinds differ from the Commit lane's."""
    built = Admission(tmp_path)
    assert campaign.FROZEN_INPUTS_KIND != "commit-frozen-inputs-v2"
    assert campaign.PERMISSION_KIND != "commit-owner-execution-permission-v1"
    assert campaign.APPROVAL_KIND != "commit-o8-approval-v1"
    assert campaign.MANIFEST_KIND != "commit-o8-manifest-v1"
    foreign = {**built.inputs, "kind": "commit-frozen-inputs-v2"}
    with pytest.raises(ValueError, match="frozen approval binding"):
        admission.validate_frozen_inputs(foreign)
    foreign_permission = {
        **built.inputs["permission"],
        "kind": "commit-owner-execution-permission-v1",
    }
    with pytest.raises(ValueError, match="frozen approval binding"):
        admission.validate_frozen_inputs(
            {**built.inputs, "permission": foreign_permission}
        )


def test_an_approval_one_second_short_of_the_minimum_window_is_refused(tmp_path):
    """The carried-over defect: a window sized to the wall budget alone."""
    built = Admission(tmp_path)
    assert campaign.MINIMUM_WINDOW_SECONDS == 1200
    assert built.descriptor.window_seconds == 1700
    assert built.descriptor.window_seconds >= campaign.MINIMUM_WINDOW_SECONDS
    now = time.time()
    short = admission.o8_admission  # the check lives in the shared core
    assert short is not None
    with pytest.raises(ValueError, match="window expired"):
        admission.validate_o7_admission(
            **built.bindings(
                approval={
                    **built.approval,
                    "windowStartsAt": now - 1,
                    "windowExpiresAt": now - 1 + campaign.MINIMUM_WINDOW_SECONDS - 1,
                }
            )
        )
    admitted = admission.validate_o7_admission(
        **built.bindings(
            approval={
                **built.approval,
                "windowStartsAt": now - 60,
                "windowExpiresAt": now + 3600,
            }
        )
    )
    assert admitted["campaignId"] == CAMPAIGN_ID


def test_an_owner_permission_outside_its_own_day_is_refused(tmp_path):
    built = Admission(tmp_path)
    for damage in (
        {"issuedAt": time.time() - 90000},
        {"expiresAt": time.time() + 60},
        {"expiresAt": time.time() + 200000},
    ):
        built.permission_path.write_text(json.dumps({**built.permission, **damage}))
        with pytest.raises(ValueError, match="expired or too short"):
            admission.freeze_inputs(
                built.permission_path,
                built.plan,
                source_root=built.source,
                artifact_path=built.artifact_path,
                baseline=built.baseline,
            )


def test_a_permission_without_baseline_provenance_is_refused(tmp_path):
    built = Admission(tmp_path)
    stripped = {
        key: value
        for key, value in built.permission.items()
        if key != "baselineProvenance"
    }
    built.permission_path.write_text(json.dumps(stripped))
    with pytest.raises(ValueError):
        admission.freeze_inputs(
            built.permission_path,
            built.plan,
            source_root=built.source,
            artifact_path=built.artifact_path,
            baseline=built.baseline,
        )


@pytest.mark.parametrize(
    "damage",
    [
        pytest.param(lambda p: p.pop("authConfigDigest"), id="no-auth-digest"),
        pytest.param(
            lambda p: p.pop("databaseProjectionDigest"), id="no-database-digest"
        ),
        pytest.param(
            lambda p: p.__setitem__("authConfigDigest", "ABC"), id="short-digest"
        ),
        pytest.param(
            lambda p: p["credentialPrincipal"].__setitem__("subject", "with space"),
            id="subject-whitespace",
        ),
        pytest.param(
            lambda p: p["credentialPrincipal"].__setitem__("clientId", "\u30af"),
            id="client-non-ascii",
        ),
    ],
)
def test_baselines_and_principal_are_refused_at_freeze_time_not_in_production(
    tmp_path, damage
):
    """A gap the first management slot would hit is a preparation blocker."""
    built = Admission(tmp_path)
    damaged = copy.deepcopy(built.permission)
    damage(damaged)
    built.permission_path.write_text(json.dumps(damaged))
    with pytest.raises(ValueError):
        admission.freeze_inputs(
            built.permission_path,
            built.plan,
            source_root=built.source,
            artifact_path=built.artifact_path,
        )


def stopped_receipt(built, stop_point, *, rows=2, may_have_created=False, **collection):
    """A receipt shaped as the launcher persists one for a stopped run.

    Two ownership reads were sent by default. The collection summary counts
    requests, not documents, so `rowCount` follows the route journal; whether a
    creating slot was dispatched is `mayHaveCreated`, read from the Gate.
    """
    routes = [
        {
            "phase": "observation",
            "index": index,
            "route": f"/v1/{built.plan['ownedScope']}/probe-u01/items/control",
            "status": 404,
            "responseDigest": digest({"index": index}),
        }
        for index in range(rows)
    ]
    result = (
        None
        if not routes
        else {
            "completed": False,
            "rowCount": len(routes),
            "recoveryRowCount": 0,
            "cleanupComplete": False,
            **collection,
        }
    )
    return admission.build_receipt(
        built.inputs,
        result,
        capability=None,
        rows=routes,
        generation=admission.abort_generation(built.inputs),
        failure="ValueError",
        stop_point=stop_point,
    ) | {"productionExecuted": bool(routes), "mayHaveCreated": may_have_created}


@pytest.mark.parametrize("stop", admission.NO_DATA_STOP_POINTS)
@pytest.mark.parametrize("rows", [0, 2], ids=["no-route", "ownership-reads"])
def test_every_no_data_stop_point_is_retirable(tmp_path, stop, rows):
    """The v10 lesson: a stop the retirement path cannot express strands a row.

    The launcher-driven counterpart, which retires a real held row through the
    real Ledger, is in `test_request_bytes_production.py`.
    """
    built = Admission(tmp_path)
    receipt = stopped_receipt(built, stop, rows=rows)
    verdict = admission.validate_no_data_receipt(receipt)
    assert verdict["disposition"] == "aborted-no-data"
    assert verdict["retirableAsNoData"] is True


@pytest.mark.parametrize("stop", admission.UNCERTAIN_STOP_POINTS)
def test_a_transport_deadline_stop_is_never_retired_as_no_data(tmp_path, stop):
    """A Commit whose receipt was lost may have been applied; that is not no-data."""
    built = Admission(tmp_path)
    receipt = stopped_receipt(built, stop)
    verdict = admission.classify_stop(receipt)
    assert verdict["disposition"] == "owner-escalation"
    assert verdict["retirableAsNoData"] is False
    assert "may have been applied" in verdict["reason"]
    with pytest.raises(ValueError, match="not a no-data stop"):
        admission.validate_no_data_receipt(receipt)


@pytest.mark.parametrize(
    "damage",
    [
        {"may_have_created": True},
        {"may_have_created": None},
        {"recoveryRowCount": 1},
        {"completed": True},
        {"untypedOverRefusal": {"httpStatus": 413}},
        {"overRefusal": {"httpStatus": 400}},
    ],
    ids=[
        "creating-slot-dispatched",
        "creation-unknown",
        "recovery-ran",
        "collection-completed",
        "untyped-refusal",
        "over-refusal",
    ],
)
def test_a_stop_that_may_have_written_is_never_retired_as_no_data(tmp_path, damage):
    built = Admission(tmp_path)
    receipt = stopped_receipt(built, admission.NO_DATA_STOP_POINTS[0], **damage)
    with pytest.raises(ValueError, match="not a no-data stop"):
        admission.validate_no_data_receipt(receipt)


@pytest.mark.parametrize(
    "damage",
    [
        {"productionExecuted": False},
        {"collection": None},
        {"metadata": [], "routeDigest": digest([]), "productionExecuted": False},
    ],
    ids=["executed-flag-contradicts-routes", "collection-dropped", "routes-dropped"],
)
def test_a_receipt_whose_journal_contradicts_itself_is_not_no_data(tmp_path, damage):
    """The route journal, the collection and the flag must tell one story."""
    built = Admission(tmp_path)
    receipt = {**stopped_receipt(built, admission.NO_DATA_STOP_POINTS[0]), **damage}
    with pytest.raises(ValueError, match="not a no-data stop"):
        admission.validate_no_data_receipt(receipt)


def test_every_reachable_stop_point_is_named(tmp_path):
    points = admission.stop_points()
    assert len(points["noData"]) == 4
    assert len(points["uncertain"]) == 3
    assert set(points["noData"]) & set(points["uncertain"]) == set()
    built = Admission(tmp_path)
    with pytest.raises(ValueError, match="unknown request-byte stop point"):
        admission.classify_stop(stopped_receipt(built, "invented-stop"))


def test_a_no_data_receipt_must_carry_its_generation_and_route_journal(tmp_path):
    built = Admission(tmp_path)
    receipt = stopped_receipt(built, admission.NO_DATA_STOP_POINTS[0])
    for damage in (
        {"generation": None},
        {"generation": {"sourceCommit": "0" * 40}},
        {"routeDigest": "0" * 64},
    ):
        with pytest.raises(ValueError):
            admission.validate_no_data_receipt({**receipt, **damage})


def test_the_gate_plan_hosts_three_interleaved_probes(tmp_path):
    """The shared Gate hosts the campaign once the descriptor declares its shape."""
    from shared_gate import create

    built = Admission(tmp_path)
    plan = admission.gate_plan_for(built.inputs, built.permission)
    assert plan["jobSlots"] == 3
    assert len(plan["jobs"]) == 3
    assert plan["receiptKind"] == campaign.RECEIPT_KIND
    assert [item["id"] for item in plan["management"]["observation"]] == [
        "oauth-tokeninfo",
        "project",
        "database",
        "auth",
    ]
    assert [item["id"] for item in plan["management"]["recovery"]] == [
        "project",
        "database",
        "auth",
    ]
    assert plan["management"]["credentialIds"] == ["oauth-tokeninfo"]
    assert plan["management"]["credentialSlots"] == ["tokeninfo"]
    assert plan["management"]["dispatchKind"] == "closed-v1"
    assert plan["permissionExpiresAt"] == built.permission["expiresAt"]
    for job in plan["jobs"].values():
        assert len(job["observation"]) == 35
        assert len(job["recovery"]) == 51
        assert len(job["resources"]) == 17
        covered = sorted((item["phase"], item["index"]) for item in job["schedule"])
        assert covered == sorted(
            (phase, index)
            for phase, count in (("observation", 35), ("recovery", 51))
            for index in range(count)
        )
        phases = [item["phase"] for item in job["schedule"]]
        # Within one probe the order is its 35 observations then its 51
        # recovery slots, so the one-way recovery rule is satisfied per job.
        assert phases == ["observation"] * 35 + ["recovery"] * 51
        # Each slot declares its own reservation, and whether it can write.
        uploads = [item for item in job["schedule"] if item["seconds"] == 60.0]
        assert uploads == [{"phase": "observation", "index": 17, "seconds": 60.0}]
        assert all(
            item["seconds"] == 3.0 for item in job["schedule"] if item not in uploads
        )
        # Absent means creating, so only the one Commit per probe omits it.
        creating = [item for item in job["schedule"] if "creates" not in item]
        assert creating == uploads
        assert all(
            item["creates"] is False for item in job["schedule"] if item not in creating
        )
    # The ceiling every body-carrying slot must reserve, so the 60 is checkable.
    assert plan["transportCeilingSeconds"] == 60.0
    assert sum(len(job["resources"]) for job in plan["jobs"].values()) == 51
    # The campaign-wide schedule does interleave the two phases, which is what
    # the three-job split resolves: each probe finishes before the next begins.
    campaign_phases = [
        entry["phase"]
        for entry in campaign.execution_plan(built.plan)["executionSchedule"]
    ]
    assert "observation" in campaign_phases[campaign_phases.index("recovery") :]
    create(tmp_path / "gate", plan)
    assert (tmp_path / "gate" / "state.json").is_file()


def test_the_gate_reservations_are_owner_declared_and_must_fit(tmp_path):
    """No single reservation covers a 60 second upload and a 1.71 second slot."""
    built = Admission(tmp_path)
    declared = admission.gate_reservations(built.permission)
    assert declared["upload"] == 60.0
    assert declared["observationSlot"] == 3.0
    assert declared["recoverySlot"] == 3.0
    # The small-slot figure has no measurement behind it and says so.
    assert declared["slotBasis"] == admission.PLANNING_ASSUMPTION
    assert "slotBasisRecord" not in declared
    assumption = {
        "upload": 60.0,
        "observationSlot": 3.0,
        "recoverySlot": 3.0,
        "slotBasis": "owner-planning-assumption",
    }
    for damage in (
        {"gateReservationSeconds": None},
        {"gateReservationSeconds": {"upload": 60.0}},
        {"gateReservationSeconds": {**assumption, "upload": 12.0}},
        {"gateReservationSeconds": {**assumption, "recoverySlot": 0}},
        {"gateReservationSeconds": {**assumption, "recoverySlot": 2.99}},
        {"gateReservationSeconds": {**assumption, "observationSlot": 2.99}},
        {"gateReservationSeconds": {**assumption, "observationSlot": True}},
        # A figure with no declared basis is the v10 failure in a new costume.
        {
            "gateReservationSeconds": {
                "upload": 60.0,
                "observationSlot": 3.0,
                "recoverySlot": 3.0,
            }
        },
        {"gateReservationSeconds": {**assumption, "slotBasis": "measured"}},
        # A measured figure must name the record it was read from.
        {
            "gateReservationSeconds": {
                **assumption,
                "slotBasis": admission.MEASURED_SHADOW,
            }
        },
        # A planning assumption may not claim one.
        {"gateReservationSeconds": {**assumption, "slotBasisRecord": "somewhere"}},
    ):
        with pytest.raises(ValueError):
            admission.gate_reservations({**built.permission, **damage})
    execution = campaign.execution_plan(built.plan)
    # A slot reservation that cannot fit 153 recovery slots in the window is
    # refused by arithmetic, not by a comment.
    fitting = {
        "upload_seconds": 60.0,
        "observation_slot_seconds": 3.0,
        "recovery_slot_seconds": 3.0,
    }
    with pytest.raises(ValueError, match="do not fit"):
        campaign.gate_plan(execution, **{**fitting, "recovery_slot_seconds": 13.0})
    with pytest.raises(ValueError, match="above the enforced transport ceiling"):
        campaign.gate_plan(execution, **{**fitting, "upload_seconds": 61.0})
    with pytest.raises(ValueError, match="declared upload_seconds required"):
        campaign.gate_plan(execution, **{**fitting, "upload_seconds": None})


def test_a_three_second_recovery_slot_now_fits_the_published_wall(
    tmp_path,
):
    """The reservation a production round trip deserves now fits.

    It did not when this test was written: at 2.0 seconds the recovery phase
    reserved 344.25 against a published 300, so a single slot slower than about
    2.005 seconds made the Gate refuse mid-cleanup, which is the worst place to
    stop because the run holds no creation proof for what it has not deleted
    yet. The preparation lane has since raised the windows to 1100 and 500, so
    three seconds a slot is admissible. The guard stays: a figure the published
    wall still cannot carry is refused with its deficit named rather than
    rounded away.
    """
    built = Admission(tmp_path)
    execution = campaign.execution_plan(built.plan)
    published = campaign.budget_document()["budget"]
    assert published["maxDurationSeconds"] == 1150
    assert published["recoveryWindow"]["reserveSeconds"] == 550

    fitting = campaign.gate_plan(
        execution,
        upload_seconds=60.0,
        observation_slot_seconds=3.0,
        recovery_slot_seconds=3.0,
    )
    recovery = sum(
        slot["seconds"] + campaign.GATE_INTERVAL_SECONDS
        for job in fitting["jobs"].values()
        for slot in job["schedule"]
        if slot["phase"] == "recovery"
    )
    # Real headroom now, rather than under a second across the whole phase.
    assert fitting["recoverySeconds"] >= recovery
    assert fitting["recoverySeconds"] <= published["recoveryWindow"]["reserveSeconds"]

    # A figure the published wall still cannot carry names its own deficit.
    with pytest.raises(
        ValueError, match="recovery 1263 s exceeds published reserve 550 s"
    ):
        campaign.gate_plan(
            execution,
            upload_seconds=60.0,
            observation_slot_seconds=8.0,
            recovery_slot_seconds=8.0,
        )


def test_both_owner_fields_refuse_every_placeholder_shape(tmp_path):
    """The recovery owner answers for a campaign that stops mid-flight."""
    built = Admission(tmp_path)
    for field in ("ownerIdentity", "recoveryOwner"):
        for value in ("<<fill me in>>", "TBD", "agent", "claude", "  ", "", None):
            built.permission_path.write_text(
                json.dumps({**built.permission, field: value})
            )
            with pytest.raises(ValueError, match=f"owner supplied {field} required"):
                admission.freeze_inputs(
                    built.permission_path,
                    built.plan,
                    source_root=built.source,
                    artifact_path=built.artifact_path,
                    baseline=built.baseline,
                )


def test_every_lane_module_the_launcher_imports_is_in_the_source_map():
    """The closure rule, enforced rather than described."""
    sources = campaign.source_map()
    lane = HERE.name
    imported = {
        name: module
        for name, module in sys.modules.items()
        if getattr(module, "__file__", None) and Path(module.__file__).parent == HERE
    }
    assert imported, "the launcher's lane modules are loaded by this test"
    for module in imported.values():
        relative = f"tools/compat-broad/{lane}/{Path(module.__file__).name}"
        assert relative in sources, relative
    # The Commit lane's baseline module is executed too, and is named as well.
    assert campaign.BASELINE_MODULE in sources


def test_the_artifact_profile_states_what_it_does_not_establish(tmp_path):
    built = Admission(tmp_path)
    basis = built.permission["artifactProfileBasis"]
    assert basis["profile"] == campaign.artifact_profile()
    assert basis["registry"] == "none"
    assert basis["ownerAcceptanceRequired"] is True
    assert "not that the build was reviewed" in basis["doesNotEstablish"].replace(
        "that the build was reviewed", "not that the build was reviewed", 1
    )
    assert basis["sourceCommit"] == campaign.shadow_record()["runtime"]["sourceCommit"]


def test_the_launcher_reads_no_credential_until_every_check_has_passed(
    tmp_path, monkeypatch
):
    """A run that was going to be refused never touches the owner's token."""
    built = Admission(tmp_path)
    reads = []
    monkeypatch.setattr(
        request_bytes_o8,
        "_read_handoff",
        lambda args: reads.append(args) or {"kind": "x"},
    )
    built.approval_path.write_text(json.dumps({**built.approval, "status": "pending"}))
    built.approval_path.chmod(0o600)
    assert request_bytes_o8.main(built.argv(tmp_path)) == 2
    assert reads == []


def test_the_shared_evidence_contract_reads_this_campaigns_gate_plan(tmp_path):
    """The retirement contract reads this campaign's plan, not Commit literals.

    Only the plan-derived readings are asserted here. How the contract then
    judges a receipt is the Ledger owner's, and this campaign has an open item
    with them: it acquires no credential and makes no metadata preflight
    request, so its plan declares no management slots at all, and a contract
    that measures a stop by preflight slots consumed cannot express one. The
    lane contract below classifies all four of its stop points today.
    """
    import reservations

    built = Admission(tmp_path)
    plan = admission.gate_plan_for(built.inputs, built.permission)
    gate = {"plan": plan}
    assert reservations._receipt_kind(gate) == campaign.RECEIPT_KIND
    assert reservations._receipt_kind(gate) != "commit-acquisition-receipt-v2"
    assert reservations._credential_slots(gate) == ["tokeninfo"]
    assert reservations._management(gate)[0] == ["observation:oauth-tokeninfo"]
    assert reservations._management(gate)[1] == [
        "observation:project",
        "observation:database",
        "observation:auth",
    ]


def test_the_reservation_claim_binds_its_gate(tmp_path):
    built = Admission(tmp_path)
    gate_plan = admission.gate_plan_for(built.inputs, built.permission)
    claim = admission.reservation_claim(
        built.inputs, gate_path=tmp_path / "gate", gate_plan=gate_plan
    )
    assert claim["gatePlanDigest"] == digest(gate_plan)
    assert claim["gateJob"] == "request-bytes-probe-u01"
    assert claim["gateJob"] in gate_plan["jobs"]
    for foreign in (
        {**gate_plan, "nonce": "c" * 32},
        {**gate_plan, "campaignId": "FS-DATA-WRITE-COMMIT-TRANSFORMS-03"},
    ):
        with pytest.raises(ValueError, match="another campaign or nonce"):
            admission.reservation_claim(
                built.inputs, gate_path=tmp_path / "other", gate_plan=foreign
            )
    assert claim["campaignId"] == CAMPAIGN_ID
    assert claim["budget"] == campaign.ledger_budget()
    # 258 already covers observation and recovery; no reserve is added on top.
    assert claim["budget"]["requests"] == 265
    assert claim["budget"]["accounts"] == 1
    assert claim["budget"]["costMicrousd"] == 303
    assert claim["nonceDigest"] == digest(built.plan["nonce"])
    assert claim["durationSeconds"] == 1150
    assert any(lock["mode"] == "WRITE" for lock in claim["locks"])


def test_the_receipt_binds_every_route_it_observed(tmp_path):
    built = Admission(tmp_path)
    capability = issued(built)
    try:
        rows = [
            {
                "phase": "observation",
                "index": index,
                "route": f"/v1/{built.plan['ownedScope']}/probe-u01/items/p{index}",
                "status": 200,
                "responseDigest": digest({"index": index}),
            }
            for index in range(3)
        ]
        receipt = admission.build_receipt(
            built.inputs,
            {"completed": True},
            capability=capability,
            rows=rows,
            generation=admission.abort_generation(built.inputs),
        )
        assert receipt["kind"] == "request-bytes-acquisition-receipt-v1"
        assert receipt["executionKind"] == "fixed-production-wire"
        assert receipt["productionExecuted"] is True
        assert receipt["workerSha256"] == capability.binding_digest
        assert receipt["transportDeadlineSeconds"] == 60.0
        assert [item["responseDigest"] for item in receipt["metadata"]] == [
            row["responseDigest"] for row in rows
        ]
        assert receipt["routeDigest"] == digest(receipt["metadata"])
    finally:
        admission.revoke_production_capability(capability)


def test_the_launcher_refuses_an_uninitialized_ledger_before_handoff(
    tmp_path, monkeypatch
):
    """An O7-shaped fixture is not an initialized shared Ledger."""
    built = Admission(tmp_path)
    reads = []
    monkeypatch.setattr(
        request_bytes_o8, "_read_handoff", lambda _args: reads.append(True)
    )
    before = len(admission.o8_admission._ISSUED)
    assert request_bytes_o8.main(built.argv(tmp_path)) == 2
    assert reads == []
    # The admission that will not be executed is not left issued.
    assert len(admission.o8_admission._ISSUED) == before
    assert not (tmp_path / "output").exists()


@pytest.mark.parametrize(
    "damage",
    [
        {"status": "pending"},
        {"launcherSha256": "0" * 64},
        {"executionHost": {"platform": "other", "machine": "other"}},
    ],
    ids=["not-approved", "other-launcher", "other-host"],
)
def test_the_launcher_refuses_an_incomplete_approval_before_anything_else(
    tmp_path, damage
):
    built = Admission(tmp_path)
    built.approval_path.write_text(json.dumps({**built.approval, **damage}))
    built.approval_path.chmod(0o600)
    before = len(admission.o8_admission._ISSUED)
    assert request_bytes_o8.main(built.argv(tmp_path)) == 2
    assert len(admission.o8_admission._ISSUED) == before


def test_the_launcher_refuses_a_world_readable_approval(tmp_path):
    built = Admission(tmp_path)
    built.approval_path.chmod(0o644)
    assert request_bytes_o8.main(built.argv(tmp_path)) == 2


def test_the_launcher_refuses_a_handoff_that_is_not_bound_to_the_permission(tmp_path):
    built = Admission(tmp_path)
    built.handoff_path.write_text(
        json.dumps(
            {
                "kind": request_bytes_o8.HANDOFF_KIND,
                "permissionDigest": "0" * 64,
                "token": "offline-fixture-token",
            }
        )
    )
    built.handoff_path.chmod(0o600)
    before = len(admission.o8_admission._ISSUED)
    assert request_bytes_o8.main(built.argv(tmp_path)) == 2
    assert len(admission.o8_admission._ISSUED) == before


def test_the_launcher_has_no_injected_transport_or_preparation_mode():
    parser = request_bytes_o8.build_parser()
    options = {action.dest for action in parser._actions}
    assert "injected_transport" not in options
    assert "transmit" not in options


def test_the_wall_deficit_refusal_fires_under_any_published_wall(tmp_path):
    """A refusal that a larger budget silences stops being evidence.

    The existing deficit test pins the exact figures the 900 second wall
    produces, so it will stop firing once the preparation lane publishes the
    1100 second wall and the 500 second reserve. This one is wall independent:
    the reservation cannot fit either wall, so the refusal stays reachable and
    keeps naming its deficit.
    """
    built = Admission(tmp_path)
    execution = campaign.execution_plan(built.plan)
    for wall in (900, 1100):
        with pytest.raises(ValueError, match="do not fit the campaign wall"):
            campaign.gate_plan(
                execution,
                upload_seconds=60.0,
                observation_slot_seconds=2.0,
                recovery_slot_seconds=10.0,
                wall_seconds=wall,
            )


def test_three_second_slots_fit_the_rebalanced_wall(tmp_path):
    """What the rebalanced budget buys, stated executably rather than in prose."""
    built = Admission(tmp_path)
    execution = campaign.execution_plan(built.plan)
    rebalanced = campaign.gate_plan(
        execution,
        upload_seconds=60.0,
        observation_slot_seconds=3.0,
        recovery_slot_seconds=3.0,
    )
    assert rebalanced["wallSeconds"] == 1150
    assert rebalanced["recoverySeconds"] == 550
    management = rebalanced["management"]["phaseSeconds"]
    sums = {
        phase: sum(
            slot["seconds"] + campaign.GATE_INTERVAL_SECONDS
            for job in rebalanced["jobs"].values()
            for slot in job["schedule"]
            if slot["phase"] == phase
        )
        for phase in ("observation", "recovery")
    }
    assert sums["observation"] + management["observation"] <= 600
    assert sums["recovery"] + management["recovery"] <= 550
    assert 600 == rebalanced["wallSeconds"] - rebalanced["recoverySeconds"]
    # The previous 1100-second wall cannot carry the four preflight slots.
    with pytest.raises(ValueError, match="do not fit the campaign wall"):
        campaign.gate_plan(
            execution,
            upload_seconds=60.0,
            observation_slot_seconds=3.0,
            recovery_slot_seconds=3.0,
            wall_seconds=1100,
        )


def test_bound_executor_carries_deadline_through_real_capability(monkeypatch, tmp_path):
    built = Admission(tmp_path)
    capability = consumed(built)
    calls = []
    monkeypatch.setattr(
        campaign.request_bytes_remote_transport,
        "request",
        lambda *args, **kwargs: calls.append((args, kwargs)) or {"status": 200},
    )
    try:
        execute = admission.bind_execute(
            capability, built.execution_plan, "offline-token"
        )
        operation = built.execution_plan["observation"][0]
        with pytest.raises(TypeError, match="deadline"):
            execute(operation)
        for invalid in (None, True, float("inf"), float("nan")):
            with pytest.raises(ValueError, match="absolute deadline"):
                execute(operation, deadline=invalid)
        deadline = time.monotonic() + 2.5
        assert execute(operation, deadline=deadline) == {"status": 200}
        assert calls[0][0][1:3] == ("observation", 0)
        assert calls[0][1]["deadline"] == deadline
        assert calls[0][1]["timeout"] == 2.5
        assert len(calls) == 1
    finally:
        admission.revoke_production_capability(capability)
