"""Prepared six-case Query Explain production campaign.

Planning and shadow execution are offline. Production execution remains a separate,
explicit command that requires an owner permission and current metadata baselines.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import subprocess
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import quote

from batch_contract import (
    DATABASE_PROJECTION,
    NUMBER,
    PROJECT,
    database_evidence,
    validate_owner_baseline,
)
from broad_contract import ROOT, digest, local_origin
from shared_cases import campaign_cases, run_scenario, save
from shared_cases import campaign_manifest as _campaign_manifest
from shared_gate import Gate as SharedGate
from shared_gate import create
from shared_production import (
    Coordinator as SharedCoordinator,
)
from shared_production import (
    DataAdapter as SharedDataAdapter,
)
from shared_production import (
    ProductionGate as SharedProductionGate,
)
from shared_production import management

CAMPAIGN_FILES = (
    "campaign_explain.py",
    "campaign_explain_shadow.py",
    "batch_adapter.py",
    "shared_cases.py",
    "shared_gate.py",
    "shared_production.py",
    "shared_production_pair.py",
)


def campaign_observer_digest() -> str:
    here = Path(__file__).parent
    from batch_adapter import observer_digest

    return digest(
        {
            "campaign": {
                name: hashlib.sha256((here / name).read_bytes()).hexdigest()
                for name in CAMPAIGN_FILES
            },
            "shared": observer_digest(),
            "runtimeHelpers": {
                name: hashlib.sha256(
                    (ROOT / "tools/compat-inventory" / name).read_bytes()
                ).hexdigest()
                for name in ("owned_runner.py", "evidence_common.py")
            },
            "baseline": hashlib.sha256(
                (here / "fixtures/database-settings-7be6cf08.json").read_bytes()
            ).hexdigest(),
        }
    )


def _schedule(nonce: str) -> dict:
    plan = _campaign_manifest(nonce)
    plan.update(
        transport="shared-explicit-production-v1",
        observerSha256=campaign_observer_digest(),
        configurationDigest=digest(configuration()),
        wallSeconds=1200,
        recoverySeconds=300,
        observationRequests=18,
        recoveryRequests=12,
        totalRequests=30,
        coordinatorRequests=0,
        costMicrousd=10_000,
        fixedCostMicrousd=1_000,
        management={"observation": management(), "recovery": management()},
        recoveryRequestIds=[
            "recovery:access-command",
            "recovery:tokeninfo",
            "recovery:project",
            "recovery:database",
            "recovery:auth",
            "recovery:key",
        ],
    )
    return plan


def campaign_manifest(nonce: str) -> dict:
    """Build the fixed executable plan for one fresh namespace."""
    return _schedule(fresh_nonce(nonce))


def manifest() -> dict:
    plan = _schedule("0" * 32)
    template = _replace_namespace(plan, "0" * 32, "{freshNonce}")
    return {
        "kind": "production-campaign-explain-01-v9",
        "status": "prepared-offline",
        "sourceCommit": "permission-bound-execution-HEAD",
        "preparation": {
            "authorizesProduction": False,
            "requiresFreshPermissionBinding": True,
            "productionExecuted": False,
        },
        "collector": "existing-batch-adapter-shared-v1",
        "admission": "existing-shared-gate-v2",
        "ownerAuthorization": {
            "owner": "t-k",
            "permissionReference": "conversation-2026-09-14-autonomous-production-under-usd10",
            "windowPolicy": "current-session-bounded-window",
            "noncePolicy": "fresh-generated-32-hex-only",
        },
        "environment": {
            "project": PROJECT,
            "projectNumber": NUMBER,
            "database": "(default)",
            "edition": "STANDARD",
            "databaseProjectionContractDigest": digest(DATABASE_PROJECTION),
            "observerSha256": campaign_observer_digest(),
            "configurationDigest": digest(configuration()),
        },
        "template": template,
        "cases": [
            {
                "id": case["id"],
                "method": (
                    "runAggregationQuery" if "aggregation" in case["id"] else "runQuery"
                ),
                "mode": case["id"].rsplit("/", 1)[1],
                "path": case["path"],
                "requestBudget": case["budget"],
                "recoveryBudget": case["recoveryBudget"],
            }
            for case in campaign_cases()
            if case["admission"] == "accepted"
        ],
        "budget": {
            "observationRequests": 18,
            "recoveryRequests": 12,
            "totalRequests": 30,
            "rateConcurrency": 1,
            "maxElapsedSeconds": 1200,
            "costCeilingMicrousd": 10_000,
            "costCeilingUsd": 0.01,
            "formula": "(30 requests * 100 micro-USD) + 1000 micro-USD fixed reserve = 4000 micro-USD; ceiling 10000 micro-USD",
            "pricingSnapshot": "https://firebase.google.com/docs/firestore/pricing",
            "pricingQueryExplain": "https://firebase.google.com/docs/firestore/query-data/query-explain",
        },
        "networkCalls": 0,
        "productionExecutable": True,
        "scope": "six Query Explain REST recipes over exactly two owned documents; no settings, indexes, rules or auth changes",
    }


def binding() -> dict:
    return {
        "kind": "production-campaign-explain-01-comparison-v3",
        "manifestDigest": digest(manifest()),
        "observerSha256": campaign_observer_digest(),
        "normalization": "shared-campaign-typed-json-v2",
        "durationProjection": {
            "scope": "successful analyze runQuery and runAggregationQuery responses",
            "path": "explainMetrics.executionStats.executionDuration",
            "marker": {
                "type": "google.protobuf.Duration",
                "nondeterministic": True,
            },
            "invalidValues": "rejected by the envelope validator",
        },
        "requireSameObserver": True,
        "retainMismatch": True,
        "indeterminateOnIncompleteLifecycle": True,
    }


def manifest_digest() -> str:
    return digest(manifest())


def validate_manifest(value: dict) -> bool:
    if value != manifest():
        baseline = manifest()["environment"]
        if any(
            value.get("environment", {}).get(key) != baseline.get(key)
            for key in baseline
        ):
            raise ValueError("environment baseline drift")
        raise ValueError("manifest drift")
    plan = value["template"]
    if plan["costMicrousd"] >= 100_000 or plan["wallSeconds"] > 1200:
        raise ValueError("budget ceiling drift")
    if len(value["cases"]) != 6 or plan["recoveryRequests"] != 12:
        raise ValueError("closed six-case scope drift")
    return True


def fresh_nonce(value: str) -> str:
    if not re.fullmatch(r"[a-f0-9]{32}", value or ""):
        raise ValueError("fresh hexadecimal namespace required")
    return value


def configuration() -> dict:
    """The reviewed baseline is fixed offline; live metadata can never replace it."""
    raw = json.loads(
        (
            ROOT / "tools/compat-broad/fixtures/database-settings-7be6cf08.json"
        ).read_bytes()
    )["observations"][0]["body"]
    return {
        "project": PROJECT,
        "projectNumber": NUMBER,
        "quotaProject": PROJECT,
        "database": "(default)",
        "edition": "STANDARD",
        "databaseProjectionContractDigest": digest(DATABASE_PROJECTION),
        "databaseResponse": raw,
        "databaseEvidence": database_evidence(raw),
        "authConfigDigest": "7878eb2600c66f48c82ef55fb8c2443ab15689ea7542a77fbda206da06f817c2",
        "apiKeyDigest": "122fca5d0ae44787ff78dd852f186fbeab71bfef183ea13e30d2d7c86b5aca96",
        "apiKeyOwnership": {
            "parent": "projects/592603257417/locations/global",
            "name": "projects/592603257417/locations/global/keys/6209b4d3-e86d-487b-860a-c5a54fdd8004",
        },
        "pricingSource": "https://firebase.google.com/docs/firestore/pricing",
        "pricingQueryExplainSource": "https://firebase.google.com/docs/firestore/query-data/query-explain",
        "pricingLocation": "us-central1",
        "pricingCheckedAt": "2026-09-14",
        "tariffInputs": {
            "requests": 30,
            "requestMicrousd": 100,
            "fixedMicrousd": 1000,
            "computedMicrousd": 4000,
            "ceilingMicrousd": 10000,
        },
        "permissionBaseline": {
            "ownerIdentity": "t-k",
            "permissionReference": "conversation-2026-09-14-autonomous-production-under-usd10",
            "recoveryOwner": "t-k",
            "tariffsConfirmedBelowPlanningCeilings": True,
            "costAssumptions": {
                "ownerConfirmed": True,
                "retentionHours": 24,
                "maximumUsd": 1,
            },
        },
    }


def accepted_configuration(permission: dict, api_key: str | None = None) -> dict:
    expected = configuration()
    required = {
        "configurationDigest": digest(expected),
        "databaseProjection": expected["databaseEvidence"]["projection"],
        "databaseProjectionDigest": expected["databaseEvidence"]["projectionDigest"],
        "databaseResponseDigest": expected["databaseEvidence"]["responseDigest"],
        **{
            key: expected[key]
            for key in (
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
        **expected["permissionBaseline"],
    }
    if not isinstance(permission, dict) or any(
        digest(permission.get(key)) != digest(value) for key, value in required.items()
    ):
        raise ValueError("accepted configuration/permission baseline differs")
    if api_key is not None and digest(api_key) != expected["apiKeyDigest"]:
        raise ValueError("accepted API key differs")
    return expected


def production_preflight_requirements(permission: dict) -> dict:
    return {
        "kind": "production-campaign-explain-01-permission-v1",
        "manifestSha256": digest(manifest()),
        "comparisonContractDigest": digest(binding()),
        "observerSha256": campaign_observer_digest(),
        "project": PROJECT,
        "projectNumber": NUMBER,
        "quotaProject": PROJECT,
        "databaseProjectionContractDigest": digest(DATABASE_PROJECTION),
        "permissionReference": permission.get("permissionReference"),
        "nonce": permission.get("nonce"),
    }


def approve(permission: dict, nonce: str, local_digest: str, now: float) -> None:
    """Validate the new conversation-scoped permission before any network call."""
    fresh_nonce(nonce)
    accepted_configuration(permission)
    required = {
        "kind": "production-campaign-explain-01-permission-v1",
        "manifestSha256": digest(manifest()),
        "comparisonContractDigest": digest(binding()),
        "observerSha256": campaign_observer_digest(),
        "localRecordSha256": local_digest,
        "nonce": nonce,
        "project": PROJECT,
        "projectNumber": NUMBER,
        "quotaProject": PROJECT,
        "tariffsConfirmedBelowPlanningCeilings": True,
        "databaseProjectionContractDigest": digest(DATABASE_PROJECTION),
        "configurationDigest": digest(configuration()),
    }
    validate_owner_baseline(permission, required, now)
    assumptions = permission.get("costAssumptions", {})
    if (
        assumptions.get("ownerConfirmed") is not True
        or assumptions.get("retentionHours") != 24
        or assumptions.get("maximumUsd") != 1
        or permission.get("ownerIdentity") != "t-k"
        or permission.get("permissionReference")
        != "conversation-2026-09-14-autonomous-production-under-usd10"
        or permission.get("recoveryOwner") != "t-k"
        or not re.fullmatch(r"[0-9a-f]{40}", permission.get("frozenCommit", ""))
        or not isinstance(permission.get("pricingLocation"), str)
        or not isinstance(permission.get("pricingCheckedAt"), str)
    ):
        raise ValueError("explicit bounded cost/retention/recovery acceptance required")


def shadow_hashes(output: Path) -> dict:
    """Return hashes for the private local artifact and lifecycle evidence."""
    names = {
        "artifactSha256": output / "artifact.json",
        "inputSha256": output / "gate" / "state.json",
        "processSha256": output / "process.json",
        "cleanupSha256": output / "batch" / "result.json",
    }
    return {key: artifact_hash(path) for key, path in names.items() if path.exists()}


def compare_production_local(production: dict, local: dict) -> dict:
    """Only complete, independently bound receipts reach semantic comparison."""
    result = {"compatibility": "indeterminate", "rows": [], "cleanupComplete": False}
    try:
        validate_envelope(local, local=True)
        validate_envelope(production, local=False)
        if production["localRecordSha256"] != digest(local):
            raise ValueError("local record binding differs")
        for before, after in zip(
            production["receipt"]["rows"], local["receipt"]["rows"], strict=True
        ):
            left = normalize_response(
                before["body"],
                production["nonce"],
                operation=before["request"],
                status=before["status"],
            )
            right = normalize_response(
                after["body"],
                local["nonce"],
                operation=after["request"],
                status=after["status"],
            )
            result["rows"].append(
                {
                    "id": before["id"],
                    "production": {"status": before["status"], "body": left},
                    "local": {"status": after["status"], "body": right},
                    "verdict": "match"
                    if digest([before["status"], left])
                    == digest([after["status"], right])
                    else "mismatch",
                }
            )
        result["cleanupComplete"] = True
        result["compatibility"] = (
            "match"
            if all(row["verdict"] == "match" for row in result["rows"])
            else "mismatch"
        )
    except (ValueError, TypeError, KeyError, AttributeError, OSError) as error:
        result["reason"] = str(error)
    return result


def normalize_response(value, nonce, *, operation=None, status=None):
    from batch_pair import normalize

    parent = f"projects/{PROJECT}/databases/(default)/documents/campaign/{nonce}"
    result = normalize(
        value, {"firestoreParents": {"campaign": parent}}, service="firestore"
    )
    if (
        type(status) is int
        and status == 200
        and isinstance(operation, dict)
        and operation.get("method") == "POST"
        and operation.get("path", "").endswith((":runQuery", ":runAggregationQuery"))
        and operation.get("body", {}).get("explainOptions") == {"analyze": True}
    ):
        _project_explain_duration(result)
    return result


def _project_explain_duration(value):
    """Replace only valid Explain analyze durations with a typed marker."""
    if not isinstance(value, list):
        raise ValueError("Explain analyze response must be a list")
    metrics_rows = [
        row for row in value if isinstance(row, dict) and "explainMetrics" in row
    ]
    if len(metrics_rows) != 1:
        raise ValueError("Explain analyze metrics row missing or repeated")
    metrics = metrics_rows[0]["explainMetrics"]
    if not isinstance(metrics, dict) or not isinstance(
        metrics.get("executionStats"), dict
    ):
        raise ValueError("Explain analyze executionStats missing")
    stats = metrics["executionStats"]
    duration = stats.get("executionDuration")
    if not isinstance(duration, str) or not _duration_valid(duration):
        raise ValueError("Explain analyze executionDuration invalid")
    stats["executionDuration"] = {
        "type": "google.protobuf.Duration",
        "nondeterministic": True,
    }


class Gate(SharedGate):
    """Campaign identity over the unchanged shared scheduler and journal."""

    def adapter_request(self, adapter, operation, send):
        plan = self.snapshot()["plan"]
        expected = {**campaign_manifest(adapter.nonce), "localOrigins": adapter.local}
        if not adapter.local or digest(plan) != digest(expected):
            raise ValueError("campaign adapter origin/nonce/observer binding mismatch")
        return _dispatch(self, adapter, operation, send)


class ProductionGate(SharedProductionGate):
    def adapter_request(self, adapter, operation, send):
        plan = self.snapshot()["plan"]
        expected = {
            **campaign_manifest(adapter.nonce),
            "permissionDigest": digest(adapter.permission),
        }
        if (
            not isinstance(adapter, DataAdapter)
            or adapter.local is not None
            or digest(plan) != digest(expected)
            or time.time() + 13 > adapter.permission["expiresAt"]
        ):
            raise ValueError("campaign production data binding refused")
        try:
            return _dispatch(self, adapter, operation, send)
        except Exception:
            if adapter.credential.failed:
                self.stop(environment=True)
            raise


def creation_proof(operation, status, body):
    name = operation["path"].split("?", 1)[0].removeprefix("/v1/")
    version = body.get("updateTime") if isinstance(body, dict) else None
    if (
        type(status) is not int
        or status != 200
        or not isinstance(body, dict)
        or operation["method"] != "PATCH"
        or not operation["path"].endswith("?currentDocument.exists=false")
        or body.get("name") != name
        or digest(body.get("fields")) != digest(operation["body"]["fields"])
        or not isinstance(version, str)
        or not re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z", version)
    ):
        raise ValueError("successful typed conditional creation required")
    datetime.fromisoformat(version)
    return {
        "kind": "campaign-created-document",
        "name": name,
        "updateTime": version,
        "requestDigest": digest(operation),
        "responseDigest": digest(body),
    }


def _dispatch(gate, adapter, operation, send):
    created = getattr(adapter, "_campaign_created", {})
    if operation["method"] == "DELETE":
        name = operation["path"].split("?", 1)[0].removeprefix("/v1/")
        proof = created.get(name)
        if proof is None or operation[
            "path"
        ] != "/v1/" + name + "?currentDocument.updateTime=" + quote(
            proof["updateTime"], safe=""
        ):
            raise ValueError(
                "cleanup requires this campaign's journaled creation version"
            )

    def admitted():
        adapter._shared_dispatch = True
        try:
            status, body = send()
            if operation["method"] == "PATCH":
                proof = creation_proof(operation, status, body)
                adapter.record(proof)
                adapter._campaign_created = {**created, proof["name"]: proof}
            return status, body
        finally:
            adapter._shared_dispatch = False

    return gate.dispatch(operation, adapter.budget.recovery, admitted)


class DataAdapter(SharedDataAdapter):
    def __init__(self, coordinator, key, output):
        super().__init__(coordinator, key, output)
        self.shared_gate = ProductionGate(coordinator.gate.path, key)


class Coordinator(SharedCoordinator):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.database_responses = []

    def request(
        self, service, path, body=None, *, method="POST", privileged=False, form=False
    ):
        status, response = super().request(
            service, path, body, method=method, privileged=privileged, form=form
        )
        if (
            service == "metadata"
            and path
            == f"firestore.googleapis.com/v1/projects/{PROJECT}/databases/(default)"
            and status == 200
        ):
            self.database_responses.append(
                {
                    "phase": "recovery" if self.budget.recovery else "observation",
                    "body": response,
                }
            )
        return status, response

    def preflight(self):
        accepted_configuration(self.permission, self.api_key)
        super().preflight()
        key = self.metadata_evidence[-1]
        if key["value"] != configuration()["apiKeyOwnership"]:
            self.ready = False
            raise ValueError("accepted API key ownership differs")


def bind_receipt(receipt, state, adapter):
    evidence = receipt["principalEvidence"]
    evidence.update(
        observerSha256=campaign_observer_digest(),
        manifestDigest=digest(manifest()),
        comparisonContractDigest=digest(binding()),
        configurationDigest=digest(configuration()),
        principal="administrator",
        quotaProject=PROJECT,
        authentication=adapter.auth_evidence,
        permissionDigest=None if adapter.local else digest(adapter.permission),
    )
    journal_bytes = adapter.journal.read_bytes() if adapter.journal.exists() else b""
    receipt["ownershipJournal"] = [
        json.loads(line) for line in journal_bytes.splitlines()
    ]
    receipt["ownershipJournalSha256"] = hashlib.sha256(journal_bytes).hexdigest()
    receipt["lifecycleStateVerified"] = state_readback_valid(receipt, state["plan"])
    # Shared recipe assertions are not production expectations. These campaign
    # flags describe owned state and cleanup; typed response validation is separate.
    receipt.update(
        stateVerified=receipt["lifecycleStateVerified"],
        stateValidation=receipt["lifecycleStateVerified"],
        safety=receipt["lifecycleStateVerified"] and receipt["cleanupComplete"] is True,
    )
    save(adapter.output / "result.json", receipt)


_COMPARABLE_EXPLAIN_ERRORS = {
    400: {"INVALID_ARGUMENT", "FAILED_PRECONDITION", "OUT_OF_RANGE"},
    404: {"NOT_FOUND"},
    409: {"ALREADY_EXISTS"},
    501: {"UNIMPLEMENTED"},
}


def _duration_valid(value):
    if not isinstance(value, str):
        return False
    match = re.fullmatch(r"(0|[1-9]\d*)(?:\.(\d{1,9}))?s", value)
    if match is None:
        return False
    seconds = int(match.group(1))
    fraction = match.group(2) or ""
    return seconds < 315_576_000_000 or (
        seconds == 315_576_000_000 and (not fraction or int(fraction) == 0)
    )


def explain_response_valid(operation, status, value):
    """Validate REST wire shape while retaining well-formed semantic differences."""

    def decimal_string(value):
        if not isinstance(value, str) or not re.fullmatch(r"\d+", value):
            return False
        try:
            return int(value) <= 2**63 - 1
        except ValueError:
            return False

    def int64_string(value):
        if not isinstance(value, str) or not re.fullmatch(r"\d+", value):
            return False
        try:
            return int(value) <= 2**63 - 1
        except ValueError:
            return False

    def signed_int64_string(value):
        if not isinstance(value, str) or not re.fullmatch(r"-?\d+", value):
            return False
        try:
            return -(2**63) <= int(value) <= 2**63 - 1
        except ValueError:
            return False

    if not isinstance(operation, dict) or not isinstance(operation.get("body"), dict):
        return False
    content_type = operation.get("contentType", "application/json")
    explain_options = operation["body"].get("explainOptions")
    if (
        not isinstance(explain_options, dict)
        or type(explain_options.get("analyze")) is not bool
        or operation.get("method") != "POST"
        or not isinstance(operation.get("path"), str)
        or not operation["path"].endswith((":runQuery", ":runAggregationQuery"))
        or operation.get("form", False) is not False
        or not isinstance(content_type, str)
        or content_type.split(";", 1)[0].strip().lower() != "application/json"
    ):
        return False
    analyze = explain_options["analyze"]
    query = operation["body"].get("structuredQuery")
    empty_analyze = (
        analyze
        and operation["path"].endswith(":runQuery")
        and isinstance(query, dict)
        and type(query.get("limit")) is int
        and query["limit"] == 0
    )

    def error_valid(row):
        error = row.get("error") if isinstance(row, dict) else None
        return (
            isinstance(error, dict)
            and isinstance(error.get("status"), str)
            and bool(re.fullmatch(r"[A-Z][A-Z_]+", error["status"]))
            and ("code" not in error or type(error["code"]) is int)
            and ("message" not in error or isinstance(error["message"], str))
        )

    if type(status) is not int or not 100 <= status <= 599:
        return False
    if (
        not isinstance(value, list)
        or not value
        or not all(isinstance(row, dict) for row in value)
    ):
        return False
    if any("error" in row for row in value):
        if (
            len(value) != 1
            or set(value[0]) != {"error"}
            or not error_valid(value[0])
        ):
            return False
        error = value[0]["error"]
        # A complete, structured API rejection is observable evidence. Auth,
        # quota, and transient transport/service failures remain incomplete so
        # they cannot be misclassified as a runtime semantic difference.
        return error["status"] in _COMPARABLE_EXPLAIN_ERRORS.get(status, set())
    if status != 200:
        return False
    metrics_rows = [row["explainMetrics"] for row in value if "explainMetrics" in row]
    if len(metrics_rows) != 1 or not isinstance(metrics_rows[0], dict):
        return False
    metrics = metrics_rows[0]
    plan = metrics.get("planSummary")
    if not isinstance(plan, dict):
        return False
    if "indexesUsed" not in plan and not empty_analyze:
        return False
    indexes_used = plan.get("indexesUsed", [])
    if not isinstance(indexes_used, list) or not all(
        isinstance(index, dict)
        and set(index) == {"properties", "query_scope"}
        and all(isinstance(item, str) for item in index.values())
        for index in indexes_used
    ):
        return False
    if analyze:
        stats = metrics.get("executionStats")
        if not isinstance(stats, dict):
            return False
        if "resultsReturned" not in stats and not empty_analyze:
            return False
        if "resultsReturned" not in stats:
            stats = {**stats, "resultsReturned": "0"}
        if not decimal_string(stats["resultsReturned"]):
            return False
        if not int64_string(stats.get("readOperations")):
            return False
        if not _duration_valid(stats.get("executionDuration")):
            return False
        debug_stats = stats.get("debugStats")
        if not isinstance(debug_stats, dict):
            return False
        if not {
            "documents_scanned",
            "index_entries_scanned",
            "billing_details",
        }.issubset(debug_stats):
            return False
        billing_details = debug_stats["billing_details"]
        if not isinstance(billing_details, dict) or set(billing_details) != {
            "documents_billable",
            "index_entries_billable",
            "min_query_cost",
            "small_ops",
        }:
            return False
        for key, item in debug_stats.items():
            if key == "billing_details":
                if not all(decimal_string(value) for value in item.values()):
                    return False
            elif not decimal_string(item):
                return False
    for row in value:
        if not any(key in row for key in ("document", "result", "explainMetrics")):
            return False
        if "readTime" in row:
            read_time = row["readTime"]
            if not isinstance(read_time, str) or not re.fullmatch(
                r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z", read_time
            ):
                return False
            try:
                datetime.fromisoformat(read_time)
            except ValueError:
                return False
        if "document" in row:
            doc = row["document"]
            if (
                not isinstance(doc, dict)
                or not isinstance(doc.get("name"), str)
                or not doc["name"]
                or not isinstance(doc.get("fields"), dict)
            ):
                return False
        if "result" in row:
            aggregate = row["result"]
            if not isinstance(aggregate, dict) or not isinstance(
                aggregate.get("aggregateFields"), dict
            ):
                return False
            for field in aggregate["aggregateFields"].values():
                if (
                    not isinstance(field, dict)
                    or set(field) != {"integerValue"}
                    or not signed_int64_string(field["integerValue"])
                ):
                    return False
    return True


def state_readback_valid(receipt, plan):
    rows = receipt.get("rows", [])
    if len(rows) != 12:
        return False
    for setup, readback, resource in zip(
        rows[2:4], rows[-2:], plan["jobs"]["query-explain"]["resources"], strict=True
    ):
        if setup.get("status") != 200 or readback.get("status") != 200:
            return False
        for row in (setup, readback):
            body = row.get("body")
            if (
                not isinstance(body, dict)
                or body.get("name") != resource
                or not isinstance(body.get("updateTime"), str)
                or not body["updateTime"]
            ):
                return False
        if digest(setup["body"]["fields"]) != digest(readback["body"].get("fields")):
            return False
    return all(row.get("status") == 404 for row in rows[:2])


def _require(condition, reason):
    if not condition:
        raise ValueError("campaign envelope: " + reason)


def validate_envelope(value, *, local, directory=None):
    """Single fail-closed validator for admission and both comparison operands."""
    try:
        _validate_envelope(value, local=local, directory=directory)
    except (KeyError, TypeError, AttributeError, IndexError, OSError) as error:
        raise ValueError("campaign envelope: malformed or missing evidence") from error
    return True


def _validate_envelope(value, *, local, directory):
    from shared_production_pair import _campaign_receipt_matches_manifest

    _require(isinstance(value, dict), "object required")
    _require(
        value.get("kind")
        == (
            "production-campaign-explain-01-local-v2"
            if local
            else "production-campaign-explain-01-result-v2"
        ),
        "local/result kind differs",
    )
    _require(value.get("productionExecuted") is (not local), "execution target differs")
    for key in ("completed", "cleanupComplete", "recordingComplete", "stateVerified"):
        _require(value.get(key) is True, "envelope " + key + " incomplete")
    _require(
        "failure" in value and value["failure"] is None,
        "envelope failure present or missing",
    )
    for key, expected in {
        "manifestDigest": digest(manifest()),
        "observerSha256": campaign_observer_digest(),
        "comparisonContractDigest": digest(binding()),
        "configurationDigest": digest(configuration()),
    }.items():
        _require(value.get(key) == expected, key + " differs")
    _require(
        digest(value.get("configuration")) == digest(configuration()),
        "accepted configuration differs",
    )
    _require(value.get("configurationUnchanged") is True, "configuration drift")
    nonce = fresh_nonce(value["nonce"])
    plan = campaign_manifest(nonce)
    if local:
        plan["localOrigins"] = value["receipt"]["principalEvidence"]["localOrigins"]
    else:
        _require(isinstance(value.get("permission"), dict), "permission missing")
        permission = value["permission"]
        accepted_configuration(permission)
        _require(
            all(
                type(permission.get(key)) in (int, float)
                and math.isfinite(permission[key])
                for key in ("issuedAt", "expiresAt")
            ),
            "permission time missing",
        )
        approve(permission, nonce, value["localRecordSha256"], permission["issuedAt"])
        _require(
            permission.get("nonce") == nonce
            and permission.get("frozenCommit") == value.get("executionCommit"),
            "permission nonce/source differs",
        )
        for key, expected in {
            "manifestSha256": digest(manifest()),
            "observerSha256": campaign_observer_digest(),
            "comparisonContractDigest": digest(binding()),
            "localRecordSha256": value.get("localRecordSha256"),
            "project": PROJECT,
            "projectNumber": NUMBER,
            "quotaProject": PROJECT,
            "databaseProjectionContractDigest": digest(DATABASE_PROJECTION),
        }.items():
            _require(permission.get(key) == expected, "permission " + key + " differs")
        _require(
            value.get("permissionDigest") == digest(permission),
            "permission digest differs",
        )
        plan["permissionDigest"] = digest(permission)
        validate_metadata(value)
    receipt = value["receipt"]
    evidence = receipt["principalEvidence"]
    _require(
        _campaign_receipt_matches_manifest(receipt, evidence, expected_plan=plan),
        "request/dispatch/cleanup binding differs",
    )
    for key in (
        "recordingComplete",
        "collectionComplete",
        "cleanupComplete",
        "lifecycleStateVerified",
        "stateVerified",
        "stateValidation",
        "safety",
    ):
        _require(receipt.get(key) is True, key + " incomplete")
    _require(
        "failure" in receipt and receipt["failure"] is None,
        "receipt failure present or missing",
    )
    _require(
        all(
            explain_response_valid(row["request"], row["status"], row["body"])
            for row in receipt["rows"][4:10]
        ),
        "typed Explain response incomplete",
    )
    _require(state_readback_valid(receipt, plan), "state readback differs")
    validate_creation_journal(receipt, plan)
    if local and directory is not None:
        _require(
            hashlib.sha256(
                (directory / "worker/ownership.jsonl").read_bytes()
            ).hexdigest()
            == receipt["ownershipJournalSha256"],
            "ownership journal file differs",
        )
    for key in (
        "manifestDigest",
        "comparisonContractDigest",
        "observerSha256",
        "configurationDigest",
        "nonce",
    ):
        _require(evidence.get(key) == value[key], "principal " + key + " differs")
    _require(
        evidence.get("principal") == "administrator"
        and evidence.get("quotaProject") == PROJECT,
        "principal differs",
    )
    _require(
        evidence.get("permissionDigest")
        == (None if local else digest(value["permission"])),
        "principal permission differs",
    )
    authentication = evidence["authentication"]
    rows = receipt["rows"] + receipt["cleanup"]
    _require(len(authentication) == len(rows), "authentication count differs")
    for index, (auth, row) in enumerate(zip(authentication, rows, strict=True)):
        _require(
            auth.get("operation") == row["request"]["path"].split("?", 1)[0]
            and auth.get("phase") == ("observation" if index < 12 else "recovery")
            and auth.get("basis") == ("local-owner" if local else "tokeninfo"),
            "authentication request differs",
        )
        remaining = auth.get("verifiedRemainingSeconds")
        _require(
            remaining is None
            if local
            else type(remaining) in (int, float) and 13 <= remaining < 86400,
            "credential lifetime missing",
        )
    state = value["gate"]
    _require(
        digest(state["plan"]) == digest(plan)
        and state.get("planDigest") == digest(plan),
        "gate plan differs",
    )
    job = state["jobs"]["query-explain"]
    _require(
        job.get("complete") is True
        and job.get("inflight") is False
        and state.get("coordinatorInflight") is False,
        "gate lifecycle incomplete",
    )
    _require(
        job.get("owned") == plan["jobs"]["query-explain"]["resources"]
        and job.get("absent") == job["owned"],
        "ownership or final absence differs",
    )
    for phase, count in (("observation", 12), ("recovery", 6)):
        _require(
            type(job.get(phase)) is int and job[phase] == count, "gate count differs"
        )
        events = [
            {
                key: event.get(key)
                for key in (
                    "index",
                    "requestDigest",
                    "status",
                    "responseDigest",
                    "completed",
                )
            }
            for event in state["events"]
            if event["job"] == "query-explain" and event["phase"] == phase
        ]
        _require(
            digest(events) == digest(evidence["dispatch"][phase]),
            "gate dispatch differs",
        )
    _require(len(state["events"]) == 18, "extra gate dispatch")
    _require(
        type(state.get("total")) is int
        and 18 <= state["total"] <= 30
        and state["costMicrousd"] == 1000 + state["total"] * 100
        and state["costMicrousd"] <= 10000,
        "gate budget differs",
    )
    validate_gate_accounting(state, local=local)
    if local:
        validate_local_runtime(value, directory)


def validate_creation_journal(receipt, plan):
    resources = plan["jobs"]["query-explain"]["resources"]
    expected = [
        {"kind": "document-attempt", "name": name, "preflightAbsent": True}
        for name in resources
    ]
    for row, read_index in zip(receipt["rows"][2:4], (0, 3), strict=True):
        proof = creation_proof(row["request"], row["status"], row["body"])
        expected.append(proof)
        cleanup_read = receipt["cleanup"][read_index]
        cleanup_delete = receipt["cleanup"][read_index + 1]
        _require(
            cleanup_read["body"].get("updateTime") == proof["updateTime"],
            "cleanup observed a replacement version",
        )
        _require(
            cleanup_delete["request"]["path"]
            == "/v1/"
            + proof["name"]
            + "?currentDocument.updateTime="
            + quote(proof["updateTime"], safe=""),
            "DELETE is not bound to the campaign creation version",
        )
    _require(
        digest(receipt["ownershipJournal"]) == digest(expected),
        "successful creation journal differs",
    )
    journal_bytes = b"".join(
        (json.dumps(event, allow_nan=False) + "\n").encode()
        for event in receipt["ownershipJournal"]
    )
    _require(
        hashlib.sha256(journal_bytes).hexdigest() == receipt["ownershipJournalSha256"],
        "ownership journal digest differs",
    )


def validate_gate_accounting(state, *, local):
    def number(value):
        return type(value) in (int, float) and math.isfinite(value)

    started = state.get("started")
    _require(number(started) and started >= 0, "gate start time invalid")
    for event in state["events"]:
        start, end = event.get("started"), event.get("ended")
        limit = 900 if event["phase"] == "observation" else 1200
        _require(
            number(start)
            and number(end)
            and started <= start <= end <= started + limit,
            "dispatch time missing or outside phase",
        )
    observation = [
        "observation:" + entry["id"]
        for entry in state["plan"]["management"]["observation"]
    ]
    recovery = [
        "recovery:" + entry["id"] for entry in state["plan"]["management"]["recovery"]
    ]
    used = state["managementUsed"]
    expected = (
        []
        if local
        else observation
        + (recovery if "recovery:access-command" in used else recovery[2:])
    )
    _require(
        used == expected
        and [event.get("id") for event in state["managementEvents"]] == expected,
        "management dispatch differs",
    )
    for event in state["managementEvents"]:
        phase, key = event["id"].split(":")
        declared = next(
            entry for entry in state["plan"]["management"][phase] if entry["id"] == key
        )
        _require(
            type(event.get("durationReserved")) is int
            and event["durationReserved"] == declared["duration"]
            and number(event.get("started"))
            and started
            <= event["started"]
            <= started + (900 if phase == "observation" else 1200),
            "management reservation differs",
        )
    observation_count = 12 + sum(key.startswith("observation:") for key in used)
    recovery_count = 6 + sum(key.startswith("recovery:") for key in used)
    for key, expected_count in {
        "total": observation_count + recovery_count,
        "observation": observation_count,
        "recovery": recovery_count,
        "reservedRecovery": 12 - recovery_count,
        "costMicrousd": 1000 + 100 * (observation_count + recovery_count),
    }.items():
        _require(
            type(state.get(key)) is int and state[key] == expected_count,
            "management/data accounting differs",
        )


def validate_metadata(value):
    accepted = configuration()
    metadata = value["metadataEvidence"]
    _require(
        [row.get("id") for row in metadata]
        == [
            phase + ":" + name
            for phase in ("observation", "recovery")
            for name in ("project", "database", "auth", "key")
        ],
        "metadata operations differ",
    )
    for row in metadata:
        _require(
            type(row.get("status")) is int and row["status"] == 200,
            "metadata response failed",
        )
        kind = row["id"].split(":")[1]
        body = row["value"]
        if kind == "project":
            _require(
                body == {"projectId": PROJECT, "projectNumber": NUMBER},
                "project differs",
            )
        elif kind == "database":
            _require(
                body.get("projectionDigest")
                == accepted["databaseEvidence"]["projectionDigest"]
                and digest(body.get("projection")) == body["projectionDigest"]
                and body.get("contractDigest") == digest(DATABASE_PROJECTION)
                and body.get("contract") == DATABASE_PROJECTION
                and body.get("responseDigest") == row.get("responseDigest"),
                "database metadata differs",
            )
        elif kind == "auth":
            _require(
                row.get("responseDigest") == accepted["authConfigDigest"],
                "Auth metadata differs",
            )
        else:
            _require(body == accepted["apiKeyOwnership"], "API key ownership differs")
    raw = value["databaseResponses"]
    _require(
        isinstance(raw, list)
        and [item.get("phase") for item in raw] == ["observation", "recovery"],
        "raw database phases missing",
    )
    for item in raw:
        expected = next(
            row["value"] for row in metadata if row["id"] == item["phase"] + ":database"
        )
        _require(
            digest(database_evidence(item["body"])) == digest(expected),
            "raw database response binding differs",
        )
    observations = value["databaseObservations"]
    _require(len(observations) == 2, "database phase observations missing")
    for phase, row in zip(("observation", "recovery"), observations, strict=True):
        expected = next(
            item["value"] for item in metadata if item["id"] == phase + ":database"
        )
        _require(row == {**expected, "phase": phase}, "database phase binding differs")


def validate_local_runtime(value, directory):
    from broad import CONFIG, FIRESTORE_CONFIG, source_inputs
    from evidence_common import runtime_inputs
    from owned_runner import validate_build

    report = value["runtime"]
    instance = value["instance"]
    _require(
        report.get("parentManifestSha256")
        == digest(
            {key: item for key, item in report.items() if key != "parentManifestSha256"}
        ),
        "parent seal differs",
    )
    _require(
        report.get("status") == "completed"
        and report.get("stopReason") == "child-completed"
        and type(report.get("exitCode")) is int
        and report["exitCode"] == 0
        and report.get("recordingComplete") is True,
        "runtime incomplete",
    )
    _require(
        report.get("executionInputs") == source_inputs()
        and report.get("runtimeInputs") == runtime_inputs(ROOT),
        "source/runtime inputs differ",
    )
    _require(
        value.get("executionCommit")
        == report.get("executionCommit")
        == subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip(),
        "execution source differs",
    )
    _require(
        type(report["build"].get("exitCode")) is int, "build exit code type differs"
    )
    validate_build(report["build"], report["artifactSha256"], report["runtimeInputs"])
    _require(
        instance.get("artifactSha256") == report["artifactSha256"],
        "executed artifact differs",
    )
    expected_config = {
        **CONFIG,
        "daemon": {"authProjectNumbers": {PROJECT: NUMBER}},
        "firestore": {**FIRESTORE_CONFIG, "indexFile": "<owned-private-index-file>"},
    }
    _require(
        report.get("configuration") == expected_config, "runtime configuration differs"
    )
    actual_config = instance["configuration"]
    normalized = {
        **actual_config,
        "firestore": {
            **actual_config["firestore"],
            "indexFile": "<owned-private-index-file>",
        },
    }
    _require(
        normalized == expected_config
        and digest(actual_config) == report.get("configurationDigest"),
        "executed configuration differs",
    )
    _require(
        instance.get("indexSha256") == report["indexConfiguration"]["sha256"],
        "executed index differs",
    )
    process = report["ownedProcess"]
    _require(
        process.get("stopped") is True
        and process.get("listenersClosed") is True
        and type(process.get("pid")) is int
        and process["pid"] > 1
        and instance.get("parentPid") == process["pid"],
        "process/listeners incomplete",
    )
    _require(
        type(instance.get("pid")) is int
        and instance["pid"] > 1
        and instance.get("nonce") == value["nonce"]
        and instance.get("wrongTokenStatus") == 403
        and instance.get("project") == PROJECT,
        "instance identity differs",
    )
    command = instance["parentArgv"]
    _require(
        isinstance(command, list)
        and command[0] == instance["artifactPath"]
        and command[1:3] == ["exec", "--config"]
        and command[3] == instance["configurationPath"]
        and command[command.index("--project") + 1] == PROJECT
        and command[-2:] == ["--nonce", value["nonce"]],
        "executed command differs",
    )
    origins = value["receipt"]["principalEvidence"]["localOrigins"]
    _require(
        origins
        == {"auth": instance["authOrigin"], "firestore": instance["firestoreOrigin"]},
        "listener origin binding differs",
    )
    for key in ("authOrigin", "firestoreOrigin", "controlOrigin"):
        local_origin(instance[key])
    _require(
        value["fileDigests"]
        == {
            "manifest.json": digest(report),
            "instance.json": digest(instance),
            "gate/state.json": digest(value["gate"]),
            "worker/result.json": digest(value["receipt"]),
        },
        "artifact file bindings differ",
    )
    if directory is not None:
        for name, expected in value["fileDigests"].items():
            _require(
                digest(json.loads((directory / name).read_bytes())) == expected,
                "artifact file changed: " + name,
            )


def execute(
    permission: dict, nonce: str, output: Path, api_key: str, local: Path
) -> dict:
    """Execute after all permission and current-environment gates pass."""
    local_evidence = json.loads(local.read_bytes())
    validate_envelope(local_evidence, local=True, directory=local.parent)
    local_digest = digest(local_evidence)
    approve(permission, nonce, local_digest, time.time())
    accepted_configuration(permission, api_key)
    head = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
    ).strip()
    if (
        head != permission.get("frozenCommit")
        or subprocess.check_output(
            ["git", "status", "--porcelain"], cwd=ROOT, text=True
        ).strip()
    ):
        raise ValueError("approved frozen checkout required")
    if not isinstance(api_key, str) or not api_key:
        raise ValueError("existing API key required")
    consumed = Path.home() / ".local/state/fireemu-broad/consumed"
    consumed.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(consumed / nonce, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w") as stream:
        stream.write(digest(permission))
        stream.flush()
        os.fsync(stream.fileno())
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    save(
        output / "execution-inputs.json",
        {
            "permission": permission,
            "localRecordSha256": local_digest,
            "manifest": manifest(),
        },
    )
    plan = campaign_manifest(nonce)
    plan["permissionDigest"] = digest(permission)
    create(output / "gate", plan)
    gate = ProductionGate(output / "gate", "query-explain")
    coordinator = Coordinator(permission, nonce, output / "coordinator", gate, api_key)
    jobs, failure = {}, None
    try:
        coordinator.acquire()
        coordinator.preflight()
        adapter = DataAdapter(coordinator, "query-explain", output / "query-explain")
        jobs["query-explain"] = run_scenario(
            adapter, plan, "query-explain", coordinator.recover_credentials
        )
    except Exception as error:  # noqa: BLE001 -- Always retain lifecycle failures and cleanup.
        failure = type(error).__name__ + ":" + str(error)
    finally:
        if coordinator.ready:
            try:
                coordinator.recover_credentials()
                coordinator.preflight()
                coordinator.configuration_unchanged = True
            except Exception as error:  # noqa: BLE001 -- Persist recovery failure.
                failure = failure or type(error).__name__
        state = gate.snapshot()
        job = jobs.get("query-explain", {})
        if job:
            bind_receipt(job, state, adapter)
        result = {
            "kind": "production-campaign-explain-01-result-v2",
            "executionCommit": head,
            "permission": permission,
            "configuration": configuration(),
            "receipt": job,
            "productionExecuted": True,
            "recordingComplete": job.get("recordingComplete") is True,
            "stateVerified": job.get("stateVerified") is True,
            "cleanupComplete": job.get("cleanupComplete") is True,
            "configurationUnchanged": coordinator.configuration_unchanged,
            "permissionDigest": digest(permission),
            "manifestDigest": digest(manifest()),
            "comparisonContractDigest": digest(binding()),
            "localRecordSha256": local_digest,
            "observerSha256": campaign_observer_digest(),
            "nonce": nonce,
            "configurationDigest": digest(configuration()),
            "metadataEvidence": coordinator.metadata_evidence,
            "databaseObservations": coordinator.database_observations,
            "databaseResponses": coordinator.database_responses,
            "jobs": jobs,
            "gate": state,
            "failure": failure,
            "completed": bool(job.get("recordingComplete"))
            and bool(job.get("stateVerified"))
            and bool(job.get("cleanupComplete"))
            and coordinator.configuration_unchanged
            and failure is None,
        }
        save(output / "result.json", result)
        comparison = compare_production_local(result, local_evidence)
        save(output / "comparison.json", comparison)
        result["compatibility"] = comparison["compatibility"]
        result["completed"] = comparison["compatibility"] in {"match", "mismatch"}
        save(output / "result.json", result)
    return result


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", action="store_true")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--permission", type=Path)
    parser.add_argument("--local", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--production", type=Path)
    parser.add_argument("--compare", action="store_true")
    args = parser.parse_args()
    if args.compare:
        if not args.production or not args.local or not args.output:
            parser.error("--compare requires --production, --local and --output")
        result = compare_production_local(
            json.loads(args.production.read_bytes()),
            json.loads(args.local.read_bytes()),
        )
        save(args.output, result)
        return 0 if result["compatibility"] in {"match", "mismatch"} else 2
    if args.manifest:
        print(json.dumps(manifest(), indent=2))
        return 0
    if not args.execute or not all((args.permission, args.local, args.output)):
        parser.error("--execute requires --permission, --local and --output")
    permission = json.loads(args.permission.read_bytes())
    result = execute(
        permission,
        permission.get("nonce"),
        args.output,
        os.environ.get("PRODUCTION_ORACLE_API_KEY"),
        args.local,
    )
    return 0 if result["completed"] else 2


def artifact_hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _replace_namespace(value, old: str, new: str):
    if isinstance(value, str):
        return value.replace(old, new)
    if isinstance(value, list):
        return [_replace_namespace(item, old, new) for item in value]
    if isinstance(value, dict):
        return {key: _replace_namespace(item, old, new) for key, item in value.items()}
    return value


if __name__ == "__main__":
    raise SystemExit(main())
