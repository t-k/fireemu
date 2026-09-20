"""Fixed Query Explain campaign contract and production boundary fixtures."""

import copy
import json

import pytest
from broad_contract import digest
from campaign_explain import (
    binding,
    campaign_manifest,
    explain_response_valid,
    manifest,
    validate_manifest,
)


def explain_operation(*, analyze=True, empty=True):
    return {
        "method": "POST",
        "path": "/v1/projects/p/databases/(default)/documents/c:runQuery",
        "body": {
            "structuredQuery": {"from": [{"collectionId": "items"}], "limit": 0 if empty else 1},
            "explainOptions": {"analyze": analyze},
        },
    }


def new_empty_analyze_body():
    return [
        {
            "readTime": "2026-09-14T11:58:21.463876Z",
            "explainMetrics": {
                "planSummary": {},
                "executionStats": {
                    "executionDuration": "0.011995s",
                    "readOperations": "1",
                    "debugStats": {
                        "documents_scanned": "0",
                        "index_entries_scanned": "0",
                        "billing_details": {
                            "documents_billable": "0",
                            "index_entries_billable": "0",
                            "small_ops": "0",
                            "min_query_cost": "0",
                        },
                    },
                },
            },
        }
    ]


def test_explain_validator_accepts_new_empty_analyze_protojson_shape():
    assert explain_response_valid(explain_operation(), 200, new_empty_analyze_body())


@pytest.mark.parametrize(
    "mutation",
    [
        "missing-plan",
        "missing-stats",
        "wrong-index-entry",
        "empty-index-entry",
        "unknown-index-field",
        "missing-read-operations",
        "wrong-duration",
        "negative-duration",
        "wrong-debug-stat",
        "huge-debug-stat",
        "wrong-billing-detail",
        "missing-billing-field",
        "empty-debug-stats",
        "negative-debug-stat",
        "negative-billing-detail",
        "huge-results",
        "omitted-default-nonempty",
        "invalid-media",
        "http-200-error-body",
        "http-auth-error-body",
        "http-quota-error-body",
        "http-temporary-error-body",
        "malformed-error-body",
        "wrong-error-status",
    ],
)
def test_explain_validator_rejects_invalid_metric_and_error_shapes(mutation):
    body = new_empty_analyze_body()
    status = 200
    operation = explain_operation()
    if mutation == "missing-plan":
        body[0]["explainMetrics"].pop("planSummary")
    elif mutation == "missing-stats":
        body[0]["explainMetrics"].pop("executionStats")
    elif mutation == "wrong-index-entry":
        body[0]["explainMetrics"]["planSummary"]["indexesUsed"] = [1]
    elif mutation == "empty-index-entry":
        body[0]["explainMetrics"]["planSummary"]["indexesUsed"] = [{}]
    elif mutation == "unknown-index-field":
        body[0]["explainMetrics"]["planSummary"]["indexesUsed"] = [
            {"properties": "x", "query_scope": "Collection", "extra": "x"}
        ]
    elif mutation == "missing-read-operations":
        body[0]["explainMetrics"]["executionStats"].pop("readOperations")
    elif mutation == "wrong-duration":
        body[0]["explainMetrics"]["executionStats"]["executionDuration"] = 1
    elif mutation == "negative-duration":
        body[0]["explainMetrics"]["executionStats"]["executionDuration"] = "-1s"
    elif mutation == "wrong-debug-stat":
        body[0]["explainMetrics"]["executionStats"]["debugStats"]["documents_scanned"] = 0
    elif mutation == "huge-debug-stat":
        body[0]["explainMetrics"]["executionStats"]["debugStats"][
            "documents_scanned"
        ] = str(2**63)
    elif mutation == "wrong-billing-detail":
        body[0]["explainMetrics"]["executionStats"]["debugStats"]["billing_details"] = []
    elif mutation == "missing-billing-field":
        body[0]["explainMetrics"]["executionStats"]["debugStats"][
            "billing_details"
        ].pop("small_ops")
    elif mutation == "empty-debug-stats":
        body[0]["explainMetrics"]["executionStats"]["debugStats"] = {}
    elif mutation == "negative-debug-stat":
        body[0]["explainMetrics"]["executionStats"]["debugStats"][
            "documents_scanned"
        ] = "-1"
    elif mutation == "negative-billing-detail":
        body[0]["explainMetrics"]["executionStats"]["debugStats"][
            "billing_details"
        ]["small_ops"] = "-1"
    elif mutation == "huge-results":
        body[0]["explainMetrics"]["executionStats"]["resultsReturned"] = str(2**63)
    elif mutation == "omitted-default-nonempty":
        operation = explain_operation(empty=False)
    elif mutation == "invalid-media":
        operation["contentType"] = "text/html"
    elif mutation == "http-200-error-body":
        status = 200
        body = [{"error": {"status": "FAILED_PRECONDITION"}}]
    elif mutation == "http-auth-error-body":
        status = 403
        body = [{"error": {"status": "PERMISSION_DENIED"}}]
    elif mutation == "http-quota-error-body":
        status = 429
        body = [{"error": {"status": "RESOURCE_EXHAUSTED"}}]
    elif mutation == "http-temporary-error-body":
        status = 503
        body = [{"error": {"status": "UNAVAILABLE"}}]
    elif mutation == "malformed-error-body":
        status = 400
        body = [{"error": {"status": "FAILED_PRECONDITION"}, "result": []}]
    else:
        status = 400
        body = [{"error": {"status": "bad status"}}]
    assert not explain_response_valid(operation, status, body)


@pytest.mark.parametrize(
    ("status", "error_status"),
    [
        (400, "INVALID_ARGUMENT"),
        (400, "FAILED_PRECONDITION"),
        (501, "UNIMPLEMENTED"),
    ],
)
def test_explain_validator_accepts_structured_comparable_api_errors(status, error_status):
    operation = explain_operation()
    body = [{"error": {"status": error_status, "message": "request rejected"}}]
    assert explain_response_valid(operation, status, body)


def test_manifest_is_exactly_six_owned_explain_cases():
    value = manifest()
    assert value["kind"] == "production-campaign-explain-01-v9"
    assert value["status"] == "prepared-offline"
    assert value["productionExecutable"] is True
    assert value["template"]["nonce"] == "{freshNonce}"
    assert value["template"]["wallSeconds"] <= 1200
    assert value["template"]["costMicrousd"] < 100_000
    assert len(value["cases"]) == 6
    assert {case["method"] for case in value["cases"]} == {
        "runQuery",
        "runAggregationQuery",
    }
    assert {case["mode"] for case in value["cases"]} == {
        "plan-only",
        "analyze",
        "empty-analyze",
    }


def test_manifest_rejects_nonce_or_case_drift():
    value = manifest()
    changed = copy.deepcopy(value)
    changed["template"]["jobs"]["query-explain"]["observation"][4]["method"] = "GET"
    with pytest.raises(ValueError, match="manifest drift"):
        validate_manifest(changed)

    with pytest.raises(ValueError, match="fresh hexadecimal namespace"):
        campaign_manifest("old-nonce")


def test_manifest_binds_metadata_and_recovery_budget():
    plan = campaign_manifest("a" * 32)
    assert len(plan["management"]["observation"]) == 6
    assert len(plan["management"]["recovery"]) == 6
    assert plan["observationRequests"] == 18
    assert plan["recoveryRequests"] == 12
    assert plan["totalRequests"] == 30
    assert plan["recoveryRequestIds"] == [
        "recovery:access-command",
        "recovery:tokeninfo",
        "recovery:project",
        "recovery:database",
        "recovery:auth",
        "recovery:key",
    ]


def test_checked_in_manifest_and_binding_are_stable():
    path = (
        __import__("pathlib").Path(__file__).parents[2]
        / "spec/compatibility/broad-runs/prod-campaign-explain-01-v9.json"
    )
    binding_path = path.with_name("prod-campaign-explain-01-v9-binding.json")
    assert json.loads(path.read_bytes()) == manifest()
    assert json.loads(binding_path.read_bytes()) == binding()
    assert binding()["manifestDigest"] == digest(manifest())


@pytest.mark.parametrize(
    "field",
    ["observerSha256", "configurationDigest", "databaseProjectionContractDigest"],
)
def test_environment_baseline_drift_fails_closed(field):
    value = manifest()
    value["environment"][field] = "drift"
    with pytest.raises(ValueError, match="environment baseline drift"):
        validate_manifest(value)


def test_comparator_contract_retains_mismatch_and_indeterminate():
    from shared_production_pair import compare_campaign_rows

    rows = manifest()["template"]["jobs"]["query-explain"]["stepIds"]
    base = {
        "recordingComplete": True,
        "collectionComplete": True,
        "cleanupComplete": True,
        "stateValidation": True,
        "principalEvidence": {
            "job": "query-explain",
            "nonce": "a" * 32,
            "localOrigins": {
                "auth": "http://127.0.0.1:18081",
                "firestore": "http://127.0.0.1:18082",
            },
            "planDigest": digest(
                {
                    **campaign_manifest("a" * 32),
                    "localOrigins": {
                        "auth": "http://127.0.0.1:18081",
                        "firestore": "http://127.0.0.1:18082",
                    },
                }
            ),
            "dispatch": {"observation": [], "recovery": []},
        },
        "rows": [{"id": row, "request": {}} for row in rows],
        "cleanup": [],
    }
    changed = copy.deepcopy(base)
    changed["rows"][0]["body"] = {"error": {"status": "FAILED_PRECONDITION"}}
    result = compare_campaign_rows(base, changed, rows)
    assert result["compatibility"] == "indeterminate"


def test_campaign_plan_uses_campaign_observer():
    from campaign_explain import campaign_observer_digest

    assert campaign_manifest("a" * 32)["observerSha256"] == campaign_observer_digest()


def test_minimal_local_evidence_is_rejected_before_approval(tmp_path, monkeypatch):
    import campaign_explain as campaign

    path = tmp_path / "local.json"
    path.write_text('{"cleanupComplete":true}')
    reached = []
    monkeypatch.setattr(campaign, "approve", lambda *args: reached.append("approval"))
    with pytest.raises(ValueError, match="local|envelope"):
        campaign.execute({}, "a" * 32, tmp_path / "production", "fake", path)
    assert reached == []


def test_configuration_binds_accepted_metadata_and_key():
    from campaign_explain import configuration

    value = configuration()
    assert value["databaseEvidence"]["contract"]["version"] == "database-settings-v2"
    assert value["databaseEvidence"]["projectionDigest"] == digest(
        value["databaseEvidence"]["projection"]
    )
    assert (
        value["authConfigDigest"]
        == "7878eb2600c66f48c82ef55fb8c2443ab15689ea7542a77fbda206da06f817c2"
    )
    assert (
        value["apiKeyOwnership"]["parent"] == "projects/592603257417/locations/global"
    )
    assert value["pricingLocation"] == "us-central1"
    assert value["pricingCheckedAt"].startswith("2026-09-14")
    assert value["permissionBaseline"]["ownerIdentity"] == "t-k"


def test_shadow_cli_imports_without_pythonpath(tmp_path):
    import os
    import subprocess
    import sys
    from pathlib import Path

    script = Path(__file__).with_name("campaign_explain_shadow.py").resolve()
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    result = subprocess.run(
        [sys.executable, str(script), "--help"],
        cwd=tmp_path,
        check=False,
        env=env,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert "FixtureWire" not in script.read_text()


def campaign_receipt(tmp_path, monkeypatch, *, backend=None, before_cleanup=None):
    import batch_adapter
    import campaign_explain as campaign
    from shared_cases import run_scenario
    from shared_gate import create
    from test_campaign_slice import FixtureBackend

    origins = {"auth": "http://127.0.0.1:18081", "firestore": "http://127.0.0.1:18082"}
    plan = {**campaign.campaign_manifest("b" * 32), "localOrigins": origins}
    create(tmp_path / "gate", plan)
    gate = campaign.Gate(tmp_path / "gate", "query-explain")
    gate.claim()
    adapter = batch_adapter.Adapter(
        batch_adapter.candidate(),
        plan["nonce"],
        tmp_path / "worker",
        local_origins=origins,
    )
    adapter.shared_gate = gate
    monkeypatch.setattr(batch_adapter, "wire", backend or FixtureBackend())
    monkeypatch.setattr("shared_gate.time.sleep", lambda _: None)
    result = run_scenario(adapter, plan, "query-explain", before_cleanup=before_cleanup)
    campaign.bind_receipt(result, gate.snapshot(), adapter)
    return result, gate.snapshot()


def test_campaign_specific_gate_dispatches_and_binds_receipt(tmp_path, monkeypatch):
    from shared_production_pair import _campaign_receipt_matches_manifest

    receipt, state = campaign_receipt(tmp_path, monkeypatch)
    assert receipt["recordingComplete"] is True
    assert receipt["lifecycleStateVerified"] is True
    assert receipt["cleanupComplete"] is True
    assert state["total"] == 18
    assert _campaign_receipt_matches_manifest(
        receipt, receipt["principalEvidence"], expected_plan=state["plan"]
    )


@pytest.mark.parametrize(
    "mutation",
    [
        "bool-index",
        "bool-status",
        "request-method",
        "request-path",
        "request-body",
        "dispatch",
        "plan",
        "nonce",
        "delete-status",
        "final404",
    ],
)
def test_campaign_receipt_rejects_rebound_wrong_operations(
    tmp_path, monkeypatch, mutation
):
    from shared_production_pair import _campaign_receipt_matches_manifest

    receipt, state = campaign_receipt(tmp_path, monkeypatch)
    changed = copy.deepcopy(receipt)
    evidence = changed["principalEvidence"]
    if mutation == "bool-index":
        changed["rows"][0]["index"] = False
        evidence["dispatch"]["observation"][0]["index"] = False
    elif mutation == "bool-status":
        changed["rows"][4]["status"] = True
        evidence["dispatch"]["observation"][4]["status"] = True
    elif mutation.startswith("request-"):
        key = mutation.split("-")[1]
        changed["rows"][4]["request"][key] = {
            "method": "GET",
            "path": "/v1/wrong",
            "body": {},
        }[key]
        evidence["dispatch"]["observation"][4]["requestDigest"] = digest(
            changed["rows"][4]["request"]
        )
    elif mutation == "dispatch":
        evidence["dispatch"]["observation"].pop()
    elif mutation == "plan":
        evidence["planDigest"] = "0" * 64
    elif mutation == "nonce":
        evidence["nonce"] = "c" * 32
    elif mutation == "delete-status":
        changed["cleanup"][1]["status"] = 412
        evidence["dispatch"]["recovery"][1]["status"] = 412
    else:
        changed["cleanup"][-1]["status"] = 200
        evidence["dispatch"]["recovery"][-1]["status"] = 200
    assert not _campaign_receipt_matches_manifest(
        changed, evidence, expected_plan=state["plan"]
    )


def test_malformed_envelopes_return_indeterminate_without_exception():
    from campaign_explain import compare_production_local

    for value in [None, [], True, {"cleanupComplete": True}]:
        assert (
            compare_production_local(value, value)["compatibility"] == "indeterminate"
        )


def skip_unless_checkout_is_frozen():
    """Report a dirty checkout once, by cause, instead of as dozens of fixture errors.

    A skip is right locally: the tree is a developer state, not a failed
    provenance claim, and the artifact run is refused before it starts. Under CI
    the tree is a fresh clone, so a dirty tree there is a real defect and fails.
    """
    import os

    from broad import DirtyCheckoutError, require_frozen_checkout

    try:
        require_frozen_checkout()
    except DirtyCheckoutError as error:
        if os.environ.get("CI"):
            pytest.fail(str(error))
        pytest.skip(str(error))


def test_frozen_checkout_lets_the_artifact_fixture_proceed(tmp_path, monkeypatch):
    import broad as runner
    from test_broad import temporary_checkout

    monkeypatch.setattr(runner, "ROOT", temporary_checkout(tmp_path / "clean"))
    assert skip_unless_checkout_is_frozen() is None


def test_dirty_checkout_skips_once_with_the_real_cause(tmp_path, monkeypatch):
    import broad as runner
    from test_broad import temporary_checkout

    checkout = temporary_checkout(tmp_path / "dirty")
    (checkout / "untracked.txt").write_text("new\n")
    monkeypatch.setattr(runner, "ROOT", checkout)
    monkeypatch.delenv("CI", raising=False)
    with pytest.raises(pytest.skip.Exception) as raised:
        skip_unless_checkout_is_frozen()
    assert "working tree is dirty" in str(raised.value)
    assert "untracked.txt" in str(raised.value)


def test_dirty_checkout_fails_instead_of_skipping_under_ci(tmp_path, monkeypatch):
    import broad as runner
    from test_broad import temporary_checkout

    checkout = temporary_checkout(tmp_path / "ci")
    (checkout / "untracked.txt").write_text("new\n")
    monkeypatch.setattr(runner, "ROOT", checkout)
    monkeypatch.setenv("CI", "true")
    with pytest.raises(pytest.fail.Exception) as raised:
        skip_unless_checkout_is_frozen()
    assert "working tree is dirty" in str(raised.value)


@pytest.fixture(scope="module")
def real_shadow(tmp_path_factory):
    """Execute the documented command with real artifact and process ownership."""
    import os
    import subprocess

    from broad_contract import ROOT

    skip_unless_checkout_is_frozen()
    output = tmp_path_factory.mktemp("campaign-cli") / "shadow"
    env = {key: value for key, value in os.environ.items() if key != "PYTHONPATH"}
    command = [
        "uv",
        "run",
        "--project",
        "tools/compat-inventory",
        "--locked",
        "--python",
        "3.12",
        "python",
        "tools/compat-broad/campaign_explain_shadow.py",
        "--output",
        str(output),
    ]
    completed = subprocess.run(
        command,
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        timeout=420,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    return json.loads((output / "result.json").read_bytes()), output


def test_documented_shadow_runs_real_server_and_closes_listeners(real_shadow):
    import campaign_explain as campaign
    from broad import socket_closed

    local, directory = real_shadow
    assert campaign.validate_envelope(local, local=True, directory=directory)
    assert local["runtime"]["ownedProcess"]["stopped"] is True
    for key in ("authOrigin", "firestoreOrigin", "controlOrigin"):
        assert socket_closed(local["instance"][key])
    assert len(local["receipt"]["rows"]) == 12
    assert len(local["receipt"]["cleanup"]) == 6
    partial = json.loads((directory / "cases.json").read_bytes())
    assert partial["recordingComplete"] is True
    assert partial["stateValidation"] is True
    assert partial["cleanupComplete"] is True


@pytest.mark.parametrize(
    "mutation",
    [
        "source",
        "build",
        "artifact",
        "runtime",
        "configuration",
        "process",
        "listener",
        "principal",
        "dispatch",
        "manifest",
        "comparison",
        "observer",
        "nonce",
        "plan",
        "state",
        "cleanup",
        "conditional-delete",
        "final404",
        "both-wrong-request",
    ],
)
def test_real_envelope_rejects_adversarial_bindings(real_shadow, mutation):
    import campaign_explain as campaign

    local, _ = real_shadow
    changed = copy.deepcopy(local)
    if mutation == "source":
        changed["executionCommit"] = "0" * 40
    elif mutation == "build":
        changed["runtime"]["build"]["exitCode"] = False
    elif mutation == "artifact":
        changed["instance"]["artifactSha256"] = "0" * 64
    elif mutation == "runtime":
        changed["runtime"]["runtimeInputs"] = {}
    elif mutation == "configuration":
        changed["configuration"]["pricingLocation"] = "elsewhere"
    elif mutation == "process":
        changed["runtime"]["ownedProcess"]["stopped"] = False
    elif mutation == "listener":
        changed["instance"]["firestoreOrigin"] = "https://firestore.googleapis.com"
    elif mutation == "principal":
        changed["receipt"]["principalEvidence"]["principal"] = "anonymous"
    elif mutation == "dispatch":
        changed["receipt"]["principalEvidence"]["dispatch"]["observation"].pop()
    elif mutation in ("manifest", "comparison", "observer"):
        changed[
            {
                "manifest": "manifestDigest",
                "comparison": "comparisonContractDigest",
                "observer": "observerSha256",
            }[mutation]
        ] = "0" * 64
    elif mutation == "nonce":
        changed["nonce"] = "0" * 32
    elif mutation == "plan":
        changed["gate"]["plan"]["costMicrousd"] = 100000
    elif mutation == "state":
        changed["receipt"]["rows"][-1]["body"]["fields"] = {}
    elif mutation == "cleanup":
        changed["receipt"]["cleanupComplete"] = False
    elif mutation == "conditional-delete":
        changed["receipt"]["cleanup"][1]["request"]["path"] = changed["receipt"][
            "cleanup"
        ][1]["request"]["path"].split("?")[0]
    elif mutation == "final404":
        changed["receipt"]["cleanup"][-1]["status"] = 200
    else:
        changed["receipt"]["rows"][4]["request"]["body"] = {}
        changed["receipt"]["principalEvidence"]["dispatch"]["observation"][4][
            "requestDigest"
        ] = digest({})
    # Re-sealing individual files must not turn inconsistent cross-bindings valid.
    changed["runtime"]["parentManifestSha256"] = digest(
        {
            key: value
            for key, value in changed["runtime"].items()
            if key != "parentManifestSha256"
        }
    )
    changed["fileDigests"] = {
        name: digest(changed[key])
        for name, key in [
            ("manifest.json", "runtime"),
            ("instance.json", "instance"),
            ("gate/state.json", "gate"),
            ("worker/result.json", "receipt"),
        ]
    }
    with pytest.raises(ValueError):
        campaign.validate_envelope(changed, local=True)
    assert (
        campaign.compare_production_local(changed, changed)["compatibility"]
        == "indeterminate"
    )


def production_fixture(local):
    """Synthetic production-side binding for offline comparator boundary tests."""
    import time

    import campaign_explain as campaign

    config = campaign.configuration()
    now = time.time()
    permission = {
        **config["permissionBaseline"],
        **{
            key: config[key]
            for key in (
                "project",
                "projectNumber",
                "quotaProject",
                "databaseProjectionContractDigest",
                "authConfigDigest",
                "apiKeyDigest",
                "apiKeyOwnership",
                "pricingLocation",
                "pricingCheckedAt",
                "pricingSource",
                "pricingQueryExplainSource",
                "tariffInputs",
            )
        },
        "kind": "production-campaign-explain-01-permission-v1",
        "configurationDigest": digest(config),
        "manifestSha256": digest(campaign.manifest()),
        "observerSha256": campaign.campaign_observer_digest(),
        "comparisonContractDigest": digest(campaign.binding()),
        "databaseProjection": config["databaseEvidence"]["projection"],
        "databaseProjectionDigest": config["databaseEvidence"]["projectionDigest"],
        "databaseResponseDigest": config["databaseEvidence"]["responseDigest"],
        "nonce": local["nonce"],
        "frozenCommit": local["executionCommit"],
        "localRecordSha256": digest(local),
        "issuedAt": now,
        "expiresAt": now + 1800,
    }
    campaign.approve(permission, permission["nonce"], digest(local), now)
    production = {
        key: copy.deepcopy(local[key])
        for key in (
            "executionCommit",
            "manifestDigest",
            "observerSha256",
            "comparisonContractDigest",
            "configuration",
            "configurationDigest",
            "configurationUnchanged",
            "nonce",
            "gate",
            "receipt",
        )
    }
    production.update(
        kind="production-campaign-explain-01-result-v2",
        productionExecuted=True,
        completed=True,
        cleanupComplete=True,
        recordingComplete=True,
        stateVerified=True,
        failure=None,
        permission=permission,
        permissionDigest=digest(permission),
        localRecordSha256=digest(local),
    )
    plan = {
        **campaign.campaign_manifest(local["nonce"]),
        "permissionDigest": digest(permission),
    }
    production["gate"]["plan"] = plan
    production["gate"]["planDigest"] = digest(plan)
    evidence = production["receipt"]["principalEvidence"]
    evidence.update(
        localOrigins={}, planDigest=digest(plan), permissionDigest=digest(permission)
    )
    for auth in evidence["authentication"]:
        auth.update(basis="tokeninfo", verifiedRemainingSeconds=1500)
    metadata = []
    for phase in ("observation", "recovery"):
        for name in ("project", "database", "auth", "key"):
            body = {
                "project": {
                    "projectId": config["project"],
                    "projectNumber": config["projectNumber"],
                },
                "database": config["databaseEvidence"],
                "auth": {},
                "key": config["apiKeyOwnership"],
            }[name]
            metadata.append(
                {
                    "id": phase + ":" + name,
                    "status": 200,
                    "value": copy.deepcopy(body),
                    "responseDigest": config["authConfigDigest"]
                    if name == "auth"
                    else config["databaseEvidence"]["responseDigest"]
                    if name == "database"
                    else digest(body),
                }
            )
    production["metadataEvidence"] = metadata
    production["databaseObservations"] = [
        {**copy.deepcopy(config["databaseEvidence"]), "phase": phase}
        for phase in ("observation", "recovery")
    ]
    production["databaseResponses"] = [
        {"phase": phase, "body": copy.deepcopy(config["databaseResponse"])}
        for phase in ("observation", "recovery")
    ]
    state = production["gate"]
    state["managementUsed"] = [
        "observation:" + key
        for key in ("access-command", "tokeninfo", "project", "database", "auth", "key")
    ] + ["recovery:" + key for key in ("project", "database", "auth", "key")]
    state["managementEvents"] = [
        {
            "id": key,
            "started": state["started"],
            "durationReserved": next(
                entry["duration"]
                for entry in plan["management"][key.split(":")[0]]
                if entry["id"] == key.split(":")[1]
            ),
        }
        for key in state["managementUsed"]
    ]
    state.update(
        total=28, observation=18, recovery=10, reservedRecovery=2, costMicrousd=3800
    )
    return production


def rebind_responses(value):
    for phase, rows in [
        ("observation", value["receipt"]["rows"]),
        ("recovery", value["receipt"]["cleanup"]),
    ]:
        events = value["receipt"]["principalEvidence"]["dispatch"][phase]
        gate_events = [
            event for event in value["gate"]["events"] if event["phase"] == phase
        ]
        for row, event, gate_event in zip(rows, events, gate_events, strict=True):
            for target in (event, gate_event):
                target.update(
                    requestDigest=digest(row["request"]),
                    responseDigest=digest(row["body"]),
                    status=row["status"],
                )
    if not value["productionExecuted"]:
        value["fileDigests"]["gate/state.json"] = digest(value["gate"])
        value["fileDigests"]["worker/result.json"] = digest(value["receipt"])


def test_fully_bound_mismatch_is_valid_collection(real_shadow):
    from campaign_explain import compare_production_local, validate_envelope

    local, _ = real_shadow
    production = production_fixture(local)
    assert validate_envelope(production, local=False)
    assert compare_production_local(production, local)["compatibility"] == "match"
    production["receipt"]["rows"][5]["body"][-1]["explainMetrics"][
        "executionStats"
    ]["resultsReturned"] = "1"
    assert production["receipt"]["stateValidation"] is True
    rebind_responses(production)
    assert validate_envelope(production, local=False)
    assert compare_production_local(production, local)["compatibility"] == "mismatch"


@pytest.mark.parametrize(
    ("status", "error_status"),
    [
        (400, "INVALID_ARGUMENT"),
        (400, "FAILED_PRECONDITION"),
        (400, "OUT_OF_RANGE"),
        (404, "NOT_FOUND"),
        (409, "ALREADY_EXISTS"),
        (501, "UNIMPLEMENTED"),
    ],
)
def test_fully_bound_success_vs_structured_api_rejection_is_mismatch(
    real_shadow, status, error_status
):
    from campaign_explain import compare_production_local

    original, _ = real_shadow
    local = copy.deepcopy(original)
    local["receipt"]["rows"][4]["status"] = status
    local["receipt"]["rows"][4]["body"] = [
        {"error": {"status": error_status, "message": "request rejected"}}
    ]
    rebind_responses(local)

    production = production_fixture(local)
    production["receipt"]["rows"][4] = copy.deepcopy(original["receipt"]["rows"][4])
    rebind_responses(production)

    assert compare_production_local(production, local)["compatibility"] == "mismatch"


def test_duration_only_difference_is_expected_nondeterminism(real_shadow):
    from campaign_explain import compare_production_local

    original, _ = real_shadow
    local = copy.deepcopy(original)
    production = production_fixture(local)
    durations = {
        "production": ["12.000001s", "0.000002s", "9.5s", "0.25s"],
        "local": ["0.000001s", "0.000003s", "0.75s", "0.01s"],
    }
    indexes = [5, 6, 8, 9]
    for index, duration in zip(indexes, durations["production"], strict=True):
        production["receipt"]["rows"][index]["body"][-1]["explainMetrics"][
            "executionStats"
        ]["executionDuration"] = duration
    rebind_responses(production)

    comparison = compare_production_local(production, local)
    assert comparison["compatibility"] == "match"
    assert all(row["verdict"] == "match" for row in comparison["rows"])


@pytest.mark.parametrize(
    ("status", "error_status"),
    [
        (401, "UNAUTHENTICATED"),
        (403, "PERMISSION_DENIED"),
        (429, "RESOURCE_EXHAUSTED"),
        (503, "UNAVAILABLE"),
    ],
)
def test_unreliable_api_errors_remain_indeterminate(real_shadow, status, error_status):
    from campaign_explain import compare_production_local

    original, _ = real_shadow
    local = copy.deepcopy(original)
    local["receipt"]["rows"][4]["status"] = status
    local["receipt"]["rows"][4]["body"] = [{"error": {"status": error_status}}]
    rebind_responses(local)
    production = production_fixture(local)
    production["receipt"]["rows"][4] = copy.deepcopy(original["receipt"]["rows"][4])
    rebind_responses(production)

    assert compare_production_local(production, local)["compatibility"] == "indeterminate"


def test_fully_bound_envelope_rejects_out_of_range_results_returned(real_shadow):
    from campaign_explain import validate_envelope

    local, _ = real_shadow
    production = production_fixture(local)
    production["receipt"]["rows"][5]["body"][-1]["explainMetrics"][
        "executionStats"
    ]["resultsReturned"] = str(2**63)
    rebind_responses(production)
    with pytest.raises(ValueError, match="typed Explain response incomplete"):
        validate_envelope(production, local=False)


def test_both_sides_same_rebound_wrong_request_is_indeterminate(real_shadow):
    from campaign_explain import compare_production_local

    original, _ = real_shadow
    local = copy.deepcopy(original)
    production = production_fixture(local)
    for value in (production, local):
        value["receipt"]["rows"][4]["request"]["body"] = {
            "structuredQuery": {"from": [{"collectionId": "wrong"}]}
        }
        rebind_responses(value)
    production["localRecordSha256"] = digest(local)
    production["permission"]["localRecordSha256"] = digest(local)
    assert (
        compare_production_local(production, local)["compatibility"] == "indeterminate"
    )


@pytest.mark.parametrize(
    "field",
    [
        "nonce",
        "observerSha256",
        "comparisonContractDigest",
        "frozenCommit",
        "apiKeyDigest",
        "authConfigDigest",
        "databaseProjectionDigest",
        "databaseResponseDigest",
        "pricingLocation",
        "pricingCheckedAt",
        "ownerIdentity",
        "issuedAt",
        "expiresAt",
    ],
)
def test_production_permission_drift_is_indeterminate(real_shadow, field):
    from campaign_explain import compare_production_local

    local, _ = real_shadow
    production = production_fixture(local)
    production["permission"][field] = "drift"
    production["permissionDigest"] = digest(production["permission"])
    production["gate"]["plan"]["permissionDigest"] = production["permissionDigest"]
    production["gate"]["planDigest"] = digest(production["gate"]["plan"])
    production["receipt"]["principalEvidence"]["planDigest"] = production["gate"][
        "planDigest"
    ]
    production["receipt"]["principalEvidence"]["permissionDigest"] = production[
        "permissionDigest"
    ]
    assert (
        compare_production_local(production, local)["compatibility"] == "indeterminate"
    )


@pytest.mark.parametrize(
    "mutation",
    [
        "missing-raw",
        "changed-raw",
        "missing-management",
        "management-count",
        "duplicate-management",
        "deleted-time",
    ],
)
def test_complete_production_rejects_rebound_metadata_and_time(real_shadow, mutation):
    from campaign_explain import validate_envelope

    local, _ = real_shadow
    production = production_fixture(local)
    if mutation == "missing-raw":
        production.pop("databaseResponses")
    elif mutation == "changed-raw":
        production["databaseResponses"][0]["body"]["etag"] = "changed"
    elif mutation == "missing-management":
        production["gate"]["managementEvents"] = []
    elif mutation == "management-count":
        production["gate"]["total"] = 18
        production["gate"]["costMicrousd"] = 2800
    elif mutation == "duplicate-management":
        production["gate"]["managementUsed"].append(
            production["gate"]["managementUsed"][0]
        )
    else:
        production["gate"]["events"][0].pop("ended")
    with pytest.raises(ValueError):
        validate_envelope(production, local=False)


def test_foreign_document_collision_is_never_deleted(tmp_path, monkeypatch):
    from test_campaign_slice import FixtureBackend

    class CollisionBackend(FixtureBackend):
        foreign = None

        def __call__(self, url, method, body, headers, **kwargs):
            if method == "PATCH" and self.foreign is None:
                path = url.split("/v1/", 1)[1].split("?", 1)[0]
                self.foreign = {
                    "name": path,
                    "fields": {"value": {"integerValue": "999"}},
                    "updateTime": "2026-09-14T00:00:01Z",
                }
                self.docs[path] = copy.deepcopy(self.foreign)
                return 409, {"error": {"status": "ALREADY_EXISTS"}}, "application/json"
            return super().__call__(url, method, body, headers, **kwargs)

    backend = CollisionBackend()
    receipt, _ = campaign_receipt(tmp_path, monkeypatch, backend=backend)
    assert backend.docs.get(backend.foreign["name"]) == backend.foreign
    assert receipt["cleanupComplete"] is False


def test_foreign_replacement_after_successful_create_is_never_deleted(
    tmp_path, monkeypatch
):
    from test_campaign_slice import FixtureBackend

    backend = FixtureBackend()
    foreign = {}

    def replace_before_cleanup():
        path = next(iter(backend.docs))
        foreign.update(
            name=path,
            fields={"value": {"integerValue": "999"}},
            updateTime="2026-09-14T00:00:01Z",
        )
        backend.docs[path] = copy.deepcopy(foreign)

    receipt, _ = campaign_receipt(
        tmp_path, monkeypatch, backend=backend, before_cleanup=replace_before_cleanup
    )
    assert backend.docs.get(foreign["name"]) == foreign
    assert receipt["cleanupComplete"] is False


@pytest.mark.parametrize(
    "failure", ["lost-response", "wrong-name", "missing-version", "wrong-fields"]
)
def test_uncertain_create_response_never_authorizes_delete(
    tmp_path, monkeypatch, failure
):
    from test_campaign_slice import FixtureBackend

    class UncertainBackend(FixtureBackend):
        def __init__(self):
            super().__init__()
            self.target = None
            self.deletes = []

        def __call__(self, url, method, body, headers, **kwargs):
            if method == "DELETE":
                self.deletes.append(url)
            result = super().__call__(url, method, body, headers, **kwargs)
            if method == "PATCH" and self.target is None:
                self.target = url.split("/v1/", 1)[1].split("?", 1)[0]
                if failure == "lost-response":
                    raise TimeoutError("fixture response lost after creation")
                status, response, media = result
                response = copy.deepcopy(response)
                if failure == "wrong-name":
                    response["name"] = "wrong"
                elif failure == "missing-version":
                    response.pop("updateTime")
                else:
                    response["fields"] = {}
                return status, response, media
            return result

    backend = UncertainBackend()
    receipt, _ = campaign_receipt(tmp_path, monkeypatch, backend=backend)
    assert backend.target in backend.docs
    assert not backend.deletes
    assert receipt["cleanupComplete"] is False


@pytest.mark.parametrize(
    "scope,field",
    [
        ("envelope", "completed"),
        ("envelope", "cleanupComplete"),
        ("envelope", "recordingComplete"),
        ("envelope", "stateVerified"),
        ("envelope", "failure"),
        ("receipt", "stateValidation"),
        ("receipt", "stateVerified"),
        ("receipt", "safety"),
        ("receipt", "failure"),
    ],
)
def test_rebound_lifecycle_flags_are_never_ignored(real_shadow, scope, field):
    from campaign_explain import validate_envelope

    local, _ = real_shadow
    changed = copy.deepcopy(local)
    target = changed if scope == "envelope" else changed["receipt"]
    target[field] = "failure" if field == "failure" else False
    rebind_responses(changed)
    with pytest.raises(ValueError):
        validate_envelope(changed, local=True)


def test_both_sides_empty_explain_is_indeterminate_even_with_rebound_true_flags(
    real_shadow,
):
    from campaign_explain import compare_production_local

    original, _ = real_shadow
    local = copy.deepcopy(original)
    production = production_fixture(local)
    for value in (local, production):
        value["receipt"]["rows"][4]["body"] = []
        value["receipt"].update(stateValidation=True, stateVerified=True, safety=True)
        rebind_responses(value)
    production["localRecordSha256"] = digest(local)
    permission = production["permission"]
    permission["localRecordSha256"] = digest(local)
    production["permissionDigest"] = digest(permission)
    production["gate"]["plan"]["permissionDigest"] = digest(permission)
    production["gate"]["planDigest"] = digest(production["gate"]["plan"])
    production["receipt"]["principalEvidence"].update(
        permissionDigest=digest(permission), planDigest=production["gate"]["planDigest"]
    )
    assert (
        compare_production_local(production, local)["compatibility"] == "indeterminate"
    )
