"""Run the fixed campaign through the real local Adapter and shared Gate."""

from __future__ import annotations

import argparse
import copy
import json
import os
import subprocess
import sys
from pathlib import Path

import batch_adapter
from campaign_explain import campaign_manifest, shadow_hashes
from shared_cases import run_scenario, save
from shared_gate import Gate, create
from owned_runner import build_artifact


class FixtureWire:
    def __init__(self):
        self.docs = {}

    def __call__(self, url, method, body, headers, **_kwargs):
        path = url.split("/v1/", 1)[1].split("?", 1)[0]
        if method == "GET":
            value = copy.deepcopy(self.docs.get(path))
            return (200, value, "application/json") if value else (404, {"error": {}}, "application/json")
        if method == "PATCH":
            value = {"name": path, "fields": body["fields"], "updateTime": "2026-09-14T00:00:00Z"}
            self.docs[path] = value
            return 200, copy.deepcopy(value), "application/json"
        if method == "DELETE":
            self.docs.pop(path, None)
            return 200, {}, "application/json"
        explain = body.get("explainOptions", {}).get("analyze") is True
        aggregation = "structuredAggregationQuery" in body
        query = body.get("structuredQuery") or body["structuredAggregationQuery"]["structuredQuery"]
        empty = query.get("limit") == 0
        metrics = {"planSummary": {"indexesUsed": []}}
        if explain:
            metrics["executionStats"] = {"resultsReturned": "0" if empty else "2"}
        if not explain:
            return 200, [{"explainMetrics": metrics}], "application/json"
        if aggregation:
            return 200, [{"result": {"aggregateFields": {"count": {"integerValue": "0" if empty else "2"}}}, "readTime": "2026-09-14T00:00:00Z", "explainMetrics": metrics}], "application/json"
        if empty:
            return 200, [{"readTime": "2026-09-14T00:00:00Z", "explainMetrics": metrics}], "application/json"
        return 200, [{"document": {"name": path + "/items/item-a"}, "readTime": "2026-09-14T00:00:00Z"}, {"document": {"name": path + "/items/item-b"}, "readTime": "2026-09-14T00:00:00Z"}, {"readTime": "2026-09-14T00:00:00Z", "explainMetrics": metrics}], "application/json"


def run(output: Path, nonce: str = "a" * 32) -> dict:
    origins = {"auth": "http://127.0.0.1:18081", "firestore": "http://127.0.0.1:18082"}
    plan = campaign_manifest(nonce)
    plan["localOrigins"] = origins
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    create(output / "gate", plan)
    gate = Gate(output / "gate", "query-explain")
    gate.claim()
    binary, build = build_artifact()
    subprocess.run([str(binary), "--version"], check=True, stdout=subprocess.DEVNULL)
    adapter = batch_adapter.Adapter(batch_adapter.candidate(), nonce, output / "worker", local_origins=origins)
    adapter.shared_gate = gate
    wire = FixtureWire()
    original = batch_adapter.wire
    batch_adapter.wire = wire
    try:
        result = run_scenario(adapter, plan, "query-explain")
    finally:
        batch_adapter.wire = original
    result["manifestDigest"] = __import__("campaign_explain").manifest_digest()
    result["observerSha256"] = __import__("campaign_explain").campaign_observer_digest()
    result["configurationDigest"] = __import__("campaign_explain").digest(__import__("campaign_explain").configuration())
    result["configurationEvidence"] = {"source": "fixed-local-config", "configurationDigest": result["configurationDigest"]}
    result["configurationUnchanged"] = result["configurationDigest"] == __import__("campaign_explain").digest(__import__("campaign_explain").configuration())
    result["nonce"] = nonce
    save(output / "artifact.json", {"kind": "built-current-artifact", "path": str(binary), "artifactSha256": build["artifactSha256"], "collectorDigest": batch_adapter.observer_digest()})
    save(output / "process.json", {"pid": os.getpid(), "argv": sys.argv})
    (output / "batch").mkdir(mode=0o700, exist_ok=True)
    save(output / "batch/result.json", result)
    save(output / "shadow-input.json", {"planDigest": gate.snapshot()["planDigest"], "nonce": nonce, "origins": origins})
    save(output / "shadow-hashes.json", shadow_hashes(output))
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--nonce", default="a" * 32)
    args = parser.parse_args()
    print(json.dumps(run(args.output.resolve(), args.nonce), indent=2))
