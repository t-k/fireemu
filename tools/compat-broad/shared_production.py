"""Explicit production admission for two shared scenarios; no network during planning."""

from __future__ import annotations

# ruff: noqa: BLE001 -- Persist independent acquisition, observation and recovery failures.
import argparse
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import urlencode

from batch_adapter import Adapter, observer_digest
from batch_contract import DATABASE_PROJECTION, NUMBER, PROJECT, validate_owner_baseline
from broad_contract import ROOT, digest
from shared_cases import manifest as local_plan
from shared_cases import run_scenario, save
from shared_gate import Gate, _save, create


def management():
    return [
        {"id": "access-command", "duration": 86, "timeout": 60},
        {"id": "tokeninfo", "duration": 12, "timeout": 13},
    ] + [
        {"id": key, "duration": 12, "timeout": 13}
        for key in ("project", "database", "auth", "key")
    ]


def schedule(nonce):
    plan = local_plan(nonce)
    plan.update(
        transport="shared-explicit-production-v1",
        wallSeconds=1200,
        recoverySeconds=300,
        observationRequests=18,
        coordinatorRequests=0,
        costMicrousd=43600,
        management={"observation": management(), "recovery": management()},
    )
    return plan


def plan_limits(plan):
    """Validate and derive bounded phase limits from a closed Gate plan."""
    values = {
        key: plan.get(key)
        for key in (
            "wallSeconds",
            "recoverySeconds",
            "observationRequests",
            "requestCostMicrousd",
            "intervalSeconds",
        )
    }
    if (
        type(values["wallSeconds"]) is not int
        or not 1 <= values["wallSeconds"] <= 1200
        or type(values["recoverySeconds"]) is not int
        or not 1 <= values["recoverySeconds"] < values["wallSeconds"]
        or type(values["observationRequests"]) is not int
        or not 1 <= values["observationRequests"] <= 2400
        or type(values["requestCostMicrousd"]) is not int
        or not 1 <= values["requestCostMicrousd"] <= 1_000_000
        or type(values["intervalSeconds"]) not in (int, float)
        or not 0.25 <= values["intervalSeconds"] <= 60
    ):
        raise ValueError("invalid production phase budget")
    return {
        "observationDeadline": values["wallSeconds"] - values["recoverySeconds"],
        "recoveryDeadline": values["wallSeconds"],
        "observationRequests": values["observationRequests"],
        "requestCostMicrousd": values["requestCostMicrousd"],
        "intervalSeconds": values["intervalSeconds"],
        "observationCredentialSeconds": values["wallSeconds"],
        "recoveryCredentialSeconds": values["recoverySeconds"],
    }


def manifest():
    return {
        "kind": "shared-two-production-v1",
        "template": schedule("0" * 32),
        "nonceMapping": "closed builder substitutes one fresh hexadecimal nonce only",
        "totalRequests": 36,
        "observationRequests": 18,
        "recoveryRequests": 18,
        "maximumCostUsd": 1,
        "maximumRetentionHours": 24,
    }


def binding():
    return {
        "kind": "shared-two-production-local-v1",
        "manifestDigest": digest(manifest()),
        "normalization": "batch-response-v2 Firestore paths with exact resource mapping",
        "typedAdmission": "canonical-json-sha256",
        "requireSameObserver": True,
    }


def approve(permission, nonce, local_digest, now):
    if not re.fullmatch("[a-f0-9]{32}", nonce or ""):
        raise ValueError("new nonce required")
    required = {
        "kind": "shared-two-owner-permission-v1",
        "manifestSha256": digest(manifest()),
        "observerSha256": observer_digest(),
        "comparisonContractDigest": digest(binding()),
        "localRecordSha256": local_digest,
        "nonce": nonce,
        "project": PROJECT,
        "projectNumber": NUMBER,
        "quotaProject": PROJECT,
        "tariffsConfirmedBelowPlanningCeilings": True,
        "databaseProjectionContractDigest": digest(DATABASE_PROJECTION),
    }
    validate_owner_baseline(permission, required, now)
    costs = permission.get("costAssumptions", {})
    if (
        costs.get("ownerConfirmed") is not True
        or costs.get("retentionHours") != 24
        or type(costs.get("maximumUsd")) not in (float, int)
        or not 0.0436 <= costs["maximumUsd"] <= 1
        or costs.get("fixedStorageAndNetworkUpperUsd") != 0.04
        or any(
            not isinstance(permission.get(k), str) or not permission[k].strip()
            for k in ("ownerIdentity", "permissionReference", "recoveryOwner")
        )
    ):
        raise ValueError("explicit bounded cost/retention/recovery acceptance required")


class ProductionGate(Gate):
    def adapter_request(self, adapter, operation, send):
        plan = self.snapshot()["plan"]
        if (
            not isinstance(adapter, DataAdapter)
            or adapter.local is not None
            or adapter.nonce != plan["nonce"]
            or plan["transport"] != "shared-explicit-production-v1"
            or digest(adapter.permission) != plan["permissionDigest"]
            or observer_digest() != plan["observerSha256"]
            or time.time() + 13 > adapter.permission["expiresAt"]
        ):
            raise ValueError("production data binding refused")

        def admitted():
            adapter._shared_dispatch = True
            try:
                return send()
            finally:
                adapter._shared_dispatch = False

        try:
            return self.dispatch(operation, adapter.budget.recovery, admitted)
        except Exception:
            if adapter.credential.failed:
                self.stop(environment=True)
            raise

    def manage(self, coordinator, action, callback):
        with self.locked() as state:
            if (
                state.get("noDataAbort") is not None
                or state["coordinatorPid"] != os.getpid()
                or state["coordinatorInflight"]
                or any(j["inflight"] for j in state["jobs"].values())
                or (state["stopped"] and not coordinator.budget.recovery)
            ):
                raise ValueError("management stopped or uncertain")
            state["coordinatorInflight"] = True
            _save(self.path, state)
            coordinator.management_context = (state, action)
            try:
                return callback()
            except Exception:
                state["stopped"] = True
                raise
            finally:
                interruption = sys.exc_info()[0]
                state["coordinatorInflight"] = (
                    interruption is not None and not issubclass(interruption, Exception)
                )
                state["lastSent"] = time.monotonic()
                coordinator.management_context = None
                _save(self.path, state)


class Coordinator(Adapter):
    def __init__(self, permission, nonce, output, gate, api_key, *, routes=None):
        self.permission, self.nonce, self.gate = permission, nonce, gate
        self.local, self.ready, self.api_key = None, False, api_key
        self._routes = None if routes is None else dict(routes)
        self.key_digest = digest(api_key)
        self.initialize_state(output, nonce)
        self.management_context = None
        self.configuration_unchanged = False
        self.metadata_evidence = []

    def access(self):
        # Data and metadata callbacks can only use already verified credentials.
        if not self.credential.usable(time.monotonic(), 13):
            raise ValueError("coordinator credential unavailable; no implicit refresh")
        return self.credential.token

    def acquire(self, recovery=False):
        limits = plan_limits(self.gate.snapshot()["plan"])
        self.budget.recovery = recovery
        required = (
            limits["recoveryCredentialSeconds"]
            if recovery
            else limits["observationCredentialSeconds"]
        )
        if self.credential.usable(time.monotonic(), required):
            return
        self.credential.token = ""
        self.credential.expiry = 0
        self.gate.manage(self, "credentials", lambda: Adapter.access(self))
        if not self.credential.usable(time.monotonic(), required):
            self.credential.fail()
            raise ValueError("verified credential does not cover reserved phase")

    def reserve(self, service, duration=12):
        # Called by unchanged Adapter.access/request INSIDE manage's existing lock.
        # No lock reacquisition, no credential command outside this context.
        if service != "metadata" or self.management_context is None:
            raise ValueError("unmanaged coordinator request")
        state, action = self.management_context
        phase = "recovery" if self.budget.recovery else "observation"
        key = (
            ("access-command" if duration == 86 else "tokeninfo")
            if action == "credentials"
            else action
        )
        entries = state["plan"]["management"][phase]
        limits = plan_limits(state["plan"])
        entry = next((item for item in entries if item["id"] == key), None)
        identity = phase + ":" + key
        if (
            entry is None
            or duration != entry["duration"]
            or identity in state["managementUsed"]
            or (
                key == "tokeninfo"
                and phase + ":access-command" not in state["managementUsed"]
            )
        ):
            raise ValueError("closed management operation/attempt limit")
        delay = max(
            0, state["lastSent"] + limits["intervalSeconds"] - time.monotonic()
        )
        deadline = state["started"] + (
            limits["recoveryDeadline"]
            if self.budget.recovery
            else limits["observationDeadline"]
        )
        remaining = state["reservedRecovery"] - int(self.budget.recovery)
        if (
            time.monotonic() + delay + duration + 1 > deadline
            or time.time() + delay + duration + 1 > (self.permission or {})["expiresAt"]
            or (
                not self.budget.recovery
                and state["observation"] >= limits["observationRequests"]
            )
            or state["costMicrousd"]
            + (1 + remaining) * limits["requestCostMicrousd"]
            > state["plan"]["costMicrousd"]
        ):
            raise ValueError("shared management capacity/deadline")
        time.sleep(delay)
        if (
            time.monotonic() + duration + 1 > deadline
            or time.time() + duration + 1 > (self.permission or {})["expiresAt"]
        ):
            raise ValueError("management deadline after wait")
        state["managementUsed"].append(identity)
        state["total"] += 1
        state[phase] += 1
        state["reservedRecovery"] = remaining
        state["costMicrousd"] += limits["requestCostMicrousd"]
        state["lastSent"] = time.monotonic()
        state["managementEvents"].append(
            {"id": identity, "started": state["lastSent"], "durationReserved": duration}
        )
        _save(self.gate.path, state)
        Adapter.reserve(self, service, duration)

    def metadata_routes(self):
        """The closed management route table this campaign may call.

        A campaign that observes other configuration supplies its own table; the
        default is the four metadata routes the Commit and Limits lanes charge.
        """
        if self._routes is not None:
            return dict(self._routes)
        return {
            f"cloudresourcemanager.googleapis.com/v1/projects/{PROJECT}": "project",
            f"firestore.googleapis.com/v1/projects/{PROJECT}/databases/(default)": "database",
            f"identitytoolkit.googleapis.com/admin/v2/projects/{PROJECT}/config": "auth",
            "apikeys.googleapis.com/v2/keys:lookupKey?"
            + urlencode({"keyString": self.api_key}): "key",
        }

    def request(
        self, service, path, body=None, *, method="POST", privileged=False, form=False
    ):
        routes = self.metadata_routes()
        if (
            service != "metadata"
            or path not in routes
            or digest(self.api_key) != self.key_digest
            or digest([body, method, privileged, form])
            != digest([None, "GET", True, False])
        ):
            raise ValueError("closed metadata request")
        result = self.gate.manage(
            self,
            routes[path],
            lambda: Adapter.request(
                self,
                service,
                path,
                body,
                method=method,
                privileged=privileged,
                form=form,
            ),
        )
        status, response = result
        action = routes[path]
        value = {}
        if isinstance(response, dict):
            if action == "project":
                value = {k: response.get(k) for k in ("projectId", "projectNumber")}
            elif action == "database":
                from batch_contract import database_evidence

                value = database_evidence(response)
            elif action == "key":
                value = {k: response.get(k) for k in ("parent", "name")}
        self.metadata_evidence.append(
            {
                "id": ("recovery" if self.budget.recovery else "observation")
                + ":"
                + action,
                "status": status,
                "responseDigest": digest(response),
                "value": value,
            }
        )
        save(self.output / "metadata-evidence.json", self.metadata_evidence)
        return result

    def recover_credentials(self):
        self.acquire(recovery=True)


class DataAdapter(Adapter):
    def __init__(self, coordinator, key, output):
        self.coordinator = coordinator
        self.permission, self.nonce = coordinator.permission, coordinator.nonce
        self.local, self.ready, self.api_key = (
            None,
            coordinator.ready,
            coordinator.api_key,
        )
        self.initialize_state(output, self.nonce)
        self.credential = coordinator.credential
        self.shared_gate = ProductionGate(coordinator.gate.path, key)
        self.shared_gate.claim()

    def access(self):
        return self.coordinator.access()

    def reserve(self, service, duration=12):
        if time.time() + duration + 1 > (self.permission or {})["expiresAt"]:
            raise ValueError("permission deadline")
        Adapter.reserve(self, service, duration)


def execute(permission, nonce, output, api_key, local):
    """Admit once before any authentication or network operation."""
    from shared_production_pair import validate_record

    validate_record(local, local=True)
    approve(permission, nonce, digest(local), time.time())
    if (
        permission.get("frozenCommit")
        != subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip()
        or subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT).strip()
    ):
        raise ValueError("approved frozen checkout required")
    if not isinstance(api_key, str) or not api_key:
        raise ValueError("existing API key required")
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    consumed = Path.home() / ".local/state/fireemu-broad/consumed"
    consumed.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(consumed / nonce, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w") as stream:
        stream.write(digest(permission))
        stream.flush()
        os.fsync(stream.fileno())
    save(
        output / "execution-inputs.json",
        {
            "permission": permission,
            "localDigest": digest(local),
            "manifest": manifest(),
        },
    )
    plan = schedule(nonce)
    plan["permissionDigest"] = digest(permission)
    create(output / "gate", plan)
    gate = ProductionGate(output / "gate", "partial")
    coordinator = Coordinator(permission, nonce, output / "coordinator", gate, api_key)
    jobs, failure = {}, None
    try:
        coordinator.acquire()
        coordinator.preflight()
        for key in plan["jobs"]:
            if gate.snapshot()["stopped"]:
                break
            adapter = DataAdapter(coordinator, key, output / key)
            jobs[key] = run_scenario(
                adapter, plan, key, coordinator.recover_credentials
            )
            if not jobs[key]["cleanupComplete"] or not jobs[key]["stateVerified"]:
                gate.stop(environment=True)
    except Exception as error:
        failure = type(error).__name__
    finally:
        if coordinator.ready:
            try:
                coordinator.recover_credentials()
                coordinator.preflight()
                coordinator.configuration_unchanged = True
            except Exception as error:
                failure = failure or type(error).__name__
        state = gate.snapshot()
        recording = len(jobs) == 2 and all(
            j["recordingComplete"] for j in jobs.values()
        )
        # An empty ownership journal can mean the create acknowledgement was lost.
        # Only completed recovery or an untouched, unclaimed job is resolved.
        cleanup = all(
            not j["inflight"]
            and (
                j["complete"] is True
                or (
                    j["pid"] is None
                    and j["observation"] == 0
                    and j["recovery"] == 0
                )
            )
            for j in state["jobs"].values()
        )
        result = {
            "kind": "shared-two-production-result-v1",
            "acceptance": "candidate",
            "observerDigest": observer_digest(),
            "permissionDigest": digest(permission),
            "permission": permission,
            "metadataEvidence": coordinator.metadata_evidence,
            "localRecordSha256": digest(local),
            "manifestDigest": digest(manifest()),
            "comparisonContractDigest": digest(binding()),
            "productionExecuted": True,
            "recordingComplete": recording,
            "stateVerified": recording
            and all(j["stateVerified"] for j in jobs.values()),
            "cleanupComplete": cleanup,
            "configurationUnchanged": coordinator.configuration_unchanged,
            "compatibility": "not-compared",
            "jobs": jobs,
            "gate": state,
            "failure": failure,
            "databaseObservations": coordinator.database_observations,
            "completed": recording
            and all(j["stateVerified"] for j in jobs.values())
            and cleanup
            and coordinator.configuration_unchanged
            and failure is None,
        }
        save(output / "result.json", result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--permission", type=Path)
    parser.add_argument("--local", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if not args.execute:
        if args.manifest:
            save(args.manifest, manifest())
        else:
            print(json.dumps(manifest(), indent=2))
        return 0
    if not all((args.permission, args.local, args.output)):
        parser.error("--permission, --local and --output required")
    permission = json.loads(args.permission.read_bytes())
    nonce = permission.get("nonce")
    local = json.loads(args.local.read_bytes())
    key = os.environ.get("PRODUCTION_ORACLE_API_KEY")
    result = execute(permission, nonce, args.output, key, local)
    from shared_production_pair import compare

    comparison = compare(result, local)
    save(args.output / "comparison.json", comparison)
    return 0 if result["completed"] else 2


if __name__ == "__main__":
    sys.exit(main())
