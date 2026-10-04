"""Replay a native gRPC transaction program (P09 retry, P10 idle, P10b/c boundary) against a local fireemu and compare it with a production recording.

The framework programs (P01 to P13b) are replayed by fs_txn_compare_local.py. These three programs keep their own collector modules; each exports the same
pieces (`compile_plan`, `RequestBudget`, `Collector`, `projection`, `NodeWire`, `discover_runtime`), so one driver covers them. Run it as the child of
`fireemu exec` (it reads FIRESTORE_EMULATOR_HOST):

    SMOKE_FAMILY=txn_retry_grpc COMPARE_COMMIT=<full sha> COMPARE_PROFILE=strict COMPARE_BINARY_SHA256=<sha256> \\
      fireemu exec --config <config> --project demo-program --only firestore --firestore-port 0 ... -- \\
      python fs_txn_compare_local_grpc.py <production recording-N.json> <out.json>

`SMOKE_FAMILY` is one of txn_retry_grpc, txn_idle_grpc, txn_boundary_grpc. Both sides go through the family's own `projection`, which refuses an incomplete
graph, so a recording or a replay that is not complete cannot be compared. A row matches when every member of it equals: a case on RPC, code, diagnostic and
whether it issued a token; a read on code, state and diagnostic.
The project identifier inside a diagnostic is a declared volatile value and is replaced by a role on both sides. A wait is compared by the classification
of its measured idle interval against the threshold, not by its exact seconds."""

import hashlib
import importlib
import ipaddress
import json
import os
import re
import shutil
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, os.environ.get("SMOKE_TOOLS", str(HERE)))

FAMILIES = ("txn_retry_grpc", "txn_idle_grpc", "txn_boundary_grpc")
PROJECT_IN_NAME = re.compile(r"projects/[^/\s\"]+/databases")


def role_project(text):
    """The project identifier is declared volatile: replace it by a role."""
    return PROJECT_IN_NAME.sub("projects/<project>/databases", text or "")


def project_free(row):
    """A row with its diagnostic's project identifier replaced by a role."""
    return {key: role_project(value) if key == "details" else value for key, value in row.items()}


def compare(production, local):
    """Rows for cases, reads, skipped steps and idle candidates; each row carries `match`. A row matches when every member of it equals."""
    cases, reads, skipped, idle = [], [], [], []
    if [case["caseId"] for case in production["cases"]] != [case["caseId"] for case in local["cases"]]:
        raise ValueError("case inventory differs")
    for case, other in zip(production["cases"], local["cases"], strict=True):
        cases.append({"caseId": case["caseId"], "production": project_free(case), "local": project_free(other), "match": project_free(case) == project_free(other)})
    local_reads = {read["site"]: read for read in local["reads"]}
    if sorted(local_reads) != sorted(read["site"] for read in production["reads"]):
        raise ValueError("read inventory differs")
    for read in production["reads"]:
        other = local_reads[read["site"]]
        reads.append({"site": read["site"], "production": project_free(read), "local": project_free(other), "match": project_free(read) == project_free(other)})
    # the boundary program has no conditional steps, so its projection carries no `skipped` list
    skipped_local = {row["site"]: row for row in local.get("skipped", [])}
    if sorted(skipped_local) != sorted(row["site"] for row in production.get("skipped", [])):
        raise ValueError("skipped inventory differs")
    for row in production.get("skipped", []):
        skipped.append({"site": row["site"], "production": row, "local": skipped_local[row["site"]], "match": row == skipped_local[row["site"]]})
    local_idle = {row["site"]: row for row in local.get("idleCandidates", [])}
    for candidate in production.get("idleCandidates", []):
        other = local_idle.get(candidate["site"])
        idle.append({"site": candidate["site"], "production": candidate, "local": other, "match": other == candidate})
    if sorted(local_idle) != sorted(row["site"] for row in production.get("idleCandidates", [])):
        raise ValueError("idle candidate inventory differs")
    return cases, reads, skipped, idle


def main():
    family = os.environ["SMOKE_FAMILY"]
    if family not in FAMILIES:
        raise ValueError("unknown program family")
    program = importlib.import_module(f"{family}_program")
    collector = importlib.import_module(f"{family}_collector")
    wire_module = importlib.import_module(f"{family}_wire")
    host, port = os.environ["FIRESTORE_EMULATOR_HOST"].rsplit(":", 1)
    if not ipaddress.ip_address(host).is_loopback:
        raise ValueError("loopback local target required")
    source_path = Path(sys.argv[1])
    source = json.loads(source_path.read_text())
    production = collector.projection(source)
    runtime = wire_module.discover_runtime(Path(os.environ.get("NODE_BINARY") or shutil.which("node")))
    plan = program.compile_plan(os.urandom(16).hex(), os.urandom(16).hex())
    wire = wire_module.NodeWire(runtime, target={"kind": "local", "host": host, "port": int(port)})
    if os.environ.get("COMPARE_CLOCK") == "virtual":
        # the waits advance the emulator's virtual clock and keep the idle the production token had (see txn_replay_clock)
        from txn_replay_clock import VirtualClock, paced_grpc, production_idle_gaps

        clock = VirtualClock(os.environ["FIREEMU_CONTROL_URL"], os.environ["FIREEMU_CONTROL_TOKEN"])
        gaps = production_idle_gaps(source["steps"])
        receipt = paced_grpc(collector.Collector)(gaps, plan, program.RequestBudget(plan), wire, "owner", save=lambda _state: None, monotonic=clock.now, utc=clock.utc,
                                                  sleep=clock.sleep, timing_mode="control-clock").run()
    else:
        receipt = collector.Collector(plan, program.RequestBudget(plan), wire, "owner", save=lambda _state: None).run()
    out = Path(sys.argv[2])
    metadata = {key[8:].lower(): value for key, value in os.environ.items() if key.startswith("COMPARE_")}
    metadata.update({"clock": os.environ.get("COMPARE_CLOCK", "real"), "family": family, "program": plan["program"], "planCorpusDigest": plan["corpusDigest"], "productionCorpusDigest": production["corpusDigest"],
                     "productionFile": str(source_path), "productionFileSha256": hashlib.sha256(source_path.read_bytes()).hexdigest(),
                     "compareToolSha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()})
    result = {"metadata": metadata, "complete": receipt["complete"], "failure": receipt["failureType"], "cases": None, "reads": None, "skipped": None, "idleCandidates": None}
    if not receipt["complete"]:
        # what stopped the replay: the last native answer, so a failed replay is not read as a mismatch
        last = (receipt.get("steps") or [{}])[-1]
        result["failureDetail"] = {"site": last.get("site"), "result": {key: (last.get("result") or {}).get(key) for key in ("code", "details", "complete", "ipcComplete")}}
    if receipt["complete"]:
        local = collector.projection(receipt)
        result["cases"], result["reads"], result["skipped"], result["idleCandidates"] = compare(production, local)
        rows = result["cases"] + result["reads"] + result["skipped"] + result["idleCandidates"]
        result["mismatches"] = sum(not row["match"] for row in rows)
        if os.environ.get("COMPARE_CLOCK") == "virtual":
            # the idle each candidate reached beside the recorded one (the least the production token idled before the request)
            from txn_replay_clock import achieved_ages, production_idle_gaps

            sites = {row["site"] for row in production.get("idleCandidates", [])}
            result["achievedAges"] = achieved_ages(production_idle_gaps(source["steps"]), production_idle_gaps(receipt["steps"]), sites=sites)
        if not result["skipped"]:
            result["skipped"] = None
    out.write_text(json.dumps(result, indent=1))
    print("complete", receipt["complete"], receipt["failureType"], "mismatches", result.get("mismatches"))
    for row in (result["cases"] or []) + (result["reads"] or []) + (result["skipped"] or []) + (result["idleCandidates"] or []):
        if not row["match"]:
            print("DIVERGE", json.dumps(row)[:300])


if __name__ == "__main__":
    main()
