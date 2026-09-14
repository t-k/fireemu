"""Prepared six-case Query Explain production campaign.

Planning and shadow execution are offline. Production execution remains a separate,
explicit command that requires an owner permission and current metadata baselines.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import time
from pathlib import Path

from batch_contract import DATABASE_PROJECTION, NUMBER, PROJECT, validate_owner_baseline
from broad_contract import digest
from shared_cases import campaign_cases, campaign_manifest as _campaign_manifest
from shared_production import management
from shared_production import Coordinator, DataAdapter, ProductionGate
from shared_cases import run_scenario, save
from shared_gate import create
from batch_adapter import observer_digest


CAMPAIGN_FILES = ("campaign_explain.py", "campaign_explain_shadow.py", "batch_adapter.py", "shared_cases.py", "shared_gate.py", "shared_production.py", "shared_production_pair.py")


def campaign_observer_digest() -> str:
    here = Path(__file__).parent
    return digest({name: hashlib.sha256((here / name).read_bytes()).hexdigest() for name in CAMPAIGN_FILES})


def _schedule(nonce: str) -> dict:
    plan = _campaign_manifest(nonce)
    plan.update(
        transport="shared-explicit-production-v1",
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
        "kind": "production-campaign-explain-01-v1",
        "status": "prepared-offline",
        "sourceCommit": "be595c8b",
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
                    "runAggregationQuery"
                    if "aggregation" in case["id"]
                    else "runQuery"
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
        "kind": "production-campaign-explain-01-comparison-v1",
        "manifestDigest": digest(manifest()),
        "observerSha256": campaign_observer_digest(),
        "normalization": "shared-campaign-typed-json-v1",
        "requireSameObserver": True,
        "retainMismatch": True,
        "indeterminateOnIncompleteLifecycle": True,
    }


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
    return {
        "project": PROJECT,
        "projectNumber": NUMBER,
        "database": "(default)",
        "edition": "STANDARD",
        "databaseProjectionContractDigest": digest(DATABASE_PROJECTION),
        "pricingSource": "https://firebase.google.com/docs/firestore/pricing",
        "pricingQueryExplainSource": "https://firebase.google.com/docs/firestore/query-data/query-explain",
        "pricingLocationRequired": True,
    }


def production_preflight_requirements(permission: dict) -> dict:
    return {
        "kind": "production-campaign-explain-01-permission-v1",
        "manifestSha256": digest(manifest()),
        "comparisonContractDigest": digest(binding()),
        "observerSha256": observer_digest(),
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
        or permission.get("frozenCommit") != "be595c8b251b360d2b01c69ba8e3403f0e4f5f5f"
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
    """Compare campaign rows while preserving lifecycle incompleteness."""
    result = {"compatibility": "indeterminate", "rows": [], "cleanupComplete": False}
    if any(
        value.get("configurationUnchanged") is not True
        for value in (production, local)
    ):
        result["reason"] = "configuration drift"
        return result
    production_job = production.get("jobs", {}).get("query-explain", production)
    local_job = local.get("jobs", {}).get("query-explain", local)
    if not all(
        value.get("recordingComplete") is True
        and value.get("cleanupComplete") is True
        for value in (production_job, local_job)
    ):
        result["reason"] = "incomplete recording or cleanup"
        return result
    left, right = production_job.get("rows", []), local_job.get("rows", [])
    expected = campaign_manifest(production.get("nonce", "a" * 32))["jobs"]["query-explain"]["stepIds"]
    if [row.get("id") for row in left] != expected or [row.get("id") for row in right] != expected:
        result["reason"] = "campaign row identity drift"
        return result
    for before, after in zip(left, right, strict=True):
        result["rows"].append({"id": before["id"], "production": {"status": before.get("status"), "body": before.get("body")}, "local": {"status": after.get("status"), "body": after.get("body")}, "verdict": "match" if digest([before.get("status"), before.get("body")]) == digest([after.get("status"), after.get("body")]) else "mismatch"})
    result["cleanupComplete"] = True
    result["compatibility"] = "match" if all(row["verdict"] == "match" for row in result["rows"]) else "mismatch"
    return result


def execute(permission: dict, nonce: str, output: Path, api_key: str, local: Path) -> dict:
    """Execute after all permission and current-environment gates pass."""
    local_digest = hashlib.sha256(local.read_bytes()).hexdigest()
    approve(permission, nonce, local_digest, time.time())
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    if head != permission.get("frozenCommit") or subprocess.check_output(["git", "status", "--porcelain"], text=True).strip():
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
    save(output / "execution-inputs.json", {"permission": permission, "localRecordSha256": local_digest, "manifest": manifest()})
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
    except Exception as error:
        failure = type(error).__name__ + ":" + str(error)
    finally:
        if coordinator.ready:
            try:
                coordinator.recover_credentials()
                coordinator.preflight()
                coordinator.configuration_unchanged = True
            except Exception as error:
                failure = failure or type(error).__name__
        state = gate.snapshot()
        job = jobs.get("query-explain", {})
        result = {
            "kind": "production-campaign-explain-01-result-v1",
            "productionExecuted": True,
            "recordingComplete": job.get("recordingComplete") is True,
            "stateVerified": job.get("stateVerified") is True,
            "cleanupComplete": job.get("cleanupComplete") is True,
            "configurationUnchanged": coordinator.configuration_unchanged,
            "permissionDigest": digest(permission),
            "manifestDigest": digest(manifest()),
            "comparisonContractDigest": digest(binding()),
            "metadataEvidence": coordinator.metadata_evidence,
            "databaseObservations": coordinator.database_observations,
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
        result = compare_production_local(json.loads(args.production.read_bytes()), json.loads(args.local.read_bytes()))
        save(args.output, result)
        return 0 if result["compatibility"] in {"match", "mismatch"} else 2
    if args.manifest:
        print(json.dumps(manifest(), indent=2))
        return 0
    if not args.execute or not all((args.permission, args.local, args.output)):
        parser.error("--execute requires --permission, --local and --output")
    permission = json.loads(args.permission.read_bytes())
    result = execute(permission, permission.get("nonce"), args.output, os.environ.get("PRODUCTION_ORACLE_API_KEY"), args.local)
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
