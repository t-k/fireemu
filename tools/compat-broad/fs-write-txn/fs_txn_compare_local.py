"""Replay a program table against a local fireemu and compare it with a production recording, row by row.

Run it as the child of `fireemu exec` (it reads FIRESTORE_EMULATOR_HOST):

    SMOKE_TABLE=fs_txn_table_p02 COMPARE_COMMIT=<full sha> COMPARE_PROFILE=strict COMPARE_BINARY_SHA256=<sha256> \\
      fireemu exec --config <config> --project demo-program --only firestore --firestore-port 0 ... -- \\
      python fs_txn_compare_local.py <production recording-N.json | freeze.json> <out.json>

It compares, for every declared case, the code and the first line of the diagnostic; for every read, the code, the
state and the batch documents; and, where the production file is a recording (it carries the responses), the commit
times: whether a successful Commit answered one, and for an empty commit of a token, whether it lies before the commit
time of the outside writer acknowledged just before it (production answers a read-only transaction's snapshot time). A
freeze file has no responses, so only cases and reads are compared. Every row carries a `match` flag; the summary line
counts the mismatches. COMPARE_* environment variables are copied into the output's metadata, together with the digest
of this file."""

import datetime
import hashlib
import importlib
import json
import os
import shutil
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, os.environ.get("SMOKE_TOOLS", str(HERE)))

from txn_program_collector import Collector, parse_time, projection  # noqa: E402
from txn_program_program import RequestBudget, compile_plan  # noqa: E402


DEFAULT_PROJECT = "fireemu-oracle-sbx"


def table_project(table):
    """The sandbox project a table was recorded in; a table that names none was recorded in the shared project."""
    return table.get("project", DEFAULT_PROJECT)


def normalize(text, project=DEFAULT_PROJECT):
    return text.replace("demo-program", project)


def commit_relations(steps):
    """Per successful Commit: whether it answered a commit time, and for an empty commit that carries a token, whether that
    time lies before the commit time of the nearest earlier outside writer (None when there is none)."""
    relations, writer_time = {}, None
    for step in steps:
        if step["rpc"] != "Commit" or step["result"]["code"] != 0:
            continue
        response = step["result"]["response"] or {}
        stamp = response.get("commitTime")
        moment = parse_time(stamp, step["transport"]) if stamp else None
        request = step.get("request") or {}
        empty_in_transaction = bool(request.get("transaction")) and not request.get("writes")
        relation = None
        if empty_in_transaction and moment is not None and writer_time is not None:
            relation = "before-writer" if moment < writer_time else "after-writer"
        relations[step["site"]] = {"commitTime": moment is not None, "relation": relation}
        if step.get("caseId") and step["caseId"].endswith("writer") and moment is not None:
            writer_time = moment
    return relations


def writer_orders(steps, plan):
    """Per outside writer sent beside a holder's release: whether it answered before the release was sent ("before-anchor": it was not held) or at or after it
    ("after-anchor": it was held until the release). Both clocks are the recording's own monotonic stamps. A pair with a row missing has no order."""
    rows = {step["site"]: step for step in steps}
    orders = {}
    for declared in plan["steps"]:
        anchor = declared.get("concurrentWith")
        if anchor is None or declared["id"] not in rows or anchor not in rows:
            continue
        orders[declared["id"]] = "before-anchor" if rows[declared["id"]]["timing"]["responseMonotonic"] < rows[anchor]["timing"]["dispatchMonotonic"] else "after-anchor"
    return orders


def compare_orders(production, local):
    return [{"site": site, "production": production.get(site), "local": local.get(site), "match": production.get(site) == local.get(site)} for site in sorted(set(production) | set(local))]


def compare(production, local, production_relations, local_relations, project=DEFAULT_PROJECT):
    cases, reads, times = [], [], []
    by_case = {case["caseId"]: case for case in local["cases"]}
    for case in production["cases"]:
        other = by_case.get(case["caseId"])
        same = other is not None and other["code"] == case["code"] and normalize(other["details"], project).split("\n")[0] == case["details"].split("\n")[0]
        cases.append({"caseId": case["caseId"], "production": {"code": case["code"], "details": case["details"][:100]},
                      "local": None if other is None else {"code": other["code"], "details": normalize(other["details"], project)[:100]}, "match": same})
    by_site = {read["site"]: read for read in local["reads"]}
    for read in production["reads"]:
        other = by_site.get(read["site"])
        row = lambda value: None if value is None else {"code": value["code"], "state": value.get("state"), "documents": value.get("documents")}  # noqa: E731
        reads.append({"site": read["site"], "production": row(read), "local": row(other), "match": row(read) == row(other)})
    for site, expected in (production_relations or {}).items():
        actual = local_relations.get(site)
        times.append({"site": site, "production": expected, "local": actual, "match": actual == expected})
    return cases, reads, times


def main():
    table = importlib.import_module(os.environ["SMOKE_TABLE"]).TABLE
    from txn_program_runner import wire_scope
    from txn_program_wire import NodeWire, discover_runtime

    host, port = os.environ["FIRESTORE_EMULATOR_HOST"].rsplit(":", 1)
    runtime = discover_runtime(Path(os.environ.get("NODE_BINARY") or shutil.which("node")))
    plan = compile_plan(table, os.urandom(16).hex(), os.urandom(16).hex())
    project = table_project(table)
    wire = NodeWire(runtime, wire_scope(table), target={"kind": "local", "host": host, "port": int(port)}, **({} if project == DEFAULT_PROJECT else {"project": project}))
    source = json.loads(Path(sys.argv[1]).read_text())
    recorded = "steps" in source
    if os.environ.get("COMPARE_CLOCK") == "frozen":
        # the emulator was started with `daemon.clockStart` (COMPARE_CLOCK_START): its clock moves only when advanced, so the waits advance it and nothing else does;
        # COMPARE_ADVANCE_SECONDS moves it once more, hidden, after the step COMPARE_ADVANCE_AFTER (a read an hour back needs a database older than that)
        from txn_replay_clock import VirtualClock, advancing

        start = datetime.datetime.fromisoformat(os.environ["COMPARE_CLOCK_START"].replace("Z", "+00:00"))
        clock = VirtualClock(os.environ["FIREEMU_CONTROL_URL"], os.environ["FIREEMU_CONTROL_TOKEN"], start)
        runner = advancing(Collector, clock, int(os.environ.get("COMPARE_ADVANCE_SECONDS", "0")), os.environ.get("COMPARE_ADVANCE_AFTER"))
        receipt = runner(plan, table, RequestBudget(plan, table), wire, "owner", save=lambda _state: None, monotonic=clock.now, utc=clock.utc, sleep=clock.sleep).run()
    elif os.environ.get("COMPARE_CLOCK") == "virtual":
        # the waits advance the emulator's virtual clock and reproduce the production token ages (see txn_replay_clock)
        from txn_replay_clock import PacedCollector, VirtualClock, production_age_steps

        clock = VirtualClock(os.environ["FIREEMU_CONTROL_URL"], os.environ["FIREEMU_CONTROL_TOKEN"])
        steps = production_age_steps(source["steps"]) if recorded else {}
        receipt = PacedCollector(plan, table, RequestBudget(plan, table), wire, "owner", save=lambda _state: None, production_steps=steps,
                                 monotonic=clock.now, utc=clock.utc, sleep=clock.sleep).run()
    else:
        receipt = Collector(plan, table, RequestBudget(plan, table), wire, "owner", save=lambda _state: None).run()
    production = projection(source, table) if recorded else source["projection"]
    out = Path(sys.argv[2])
    metadata = {key[8:].lower(): value for key, value in os.environ.items() if key.startswith("COMPARE_")}
    metadata.update({"clock": os.environ.get("COMPARE_CLOCK", "real"), "table": table["name"], "program": table["program"], "planCorpusDigest": plan["corpusDigest"],
                     "productionCorpusDigest": production["corpusDigest"], "productionFile": str(Path(sys.argv[1])),
                     "productionFileSha256": hashlib.sha256(Path(sys.argv[1]).read_bytes()).hexdigest(),
                     "productionFileKind": "recording" if recorded else "freeze",
                     "localProject": "demo-program", "compareToolSha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()})
    result = {"metadata": metadata, "complete": receipt["complete"], "failure": receipt["failureType"], "cases": None, "reads": None, "commitTimes": None}
    if receipt["complete"]:
        local = projection(receipt, table)
        production_relations = commit_relations(source["steps"]) if recorded else None
        local_relations = commit_relations(receipt["steps"])
        result["cases"], result["reads"], result["commitTimes"] = compare(production, local, production_relations, local_relations, project)
        result["orders"] = compare_orders(writer_orders(source["steps"], plan), writer_orders(receipt["steps"], plan)) if recorded else None
        rows = result["cases"] + result["reads"] + (result["commitTimes"] or []) + (result["orders"] or [])
        result["mismatches"] = sum(not row["match"] for row in rows)
    out.write_text(json.dumps(result, indent=1))
    print("complete", receipt["complete"], receipt["failureType"], "mismatches", result.get("mismatches"))
    for row in (result["cases"] or []) + (result["reads"] or []) + (result["commitTimes"] or []) + (result.get("orders") or []):
        if not row["match"]:
            print("DIVERGE", json.dumps(row)[:300])


if __name__ == "__main__":
    main()
