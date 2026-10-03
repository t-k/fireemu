"""Replay a program table against a local fireemu and compare it with a production recording, row by row.

Run it as the child of `fireemu exec` (it reads FIRESTORE_EMULATOR_HOST):

    SMOKE_TABLE=fs_txn_table_p02 COMPARE_COMMIT=<full sha> COMPARE_PROFILE=strict COMPARE_BINARY_SHA256=<sha256> \\
      fireemu exec --config <config> --project demo-program --only firestore --firestore-port 0 ... -- \\
      python fs_txn_compare_local.py <production recording-N.json | freeze.json> <out.json>

It compares, for every declared case, the code and full diagnostic; for every read, the code, the
state and the batch documents; and, where the production file is a recording (it carries the responses), the commit
times: whether a successful Commit answered one, and for an empty commit of a token, whether it lies before the commit
time of the outside writer acknowledged just before it (production answers a read-only transaction's snapshot time). A
freeze file has no responses, so only cases and reads are compared. Every row carries a `match` flag; the summary line
counts the mismatches. COMPARE_* environment variables are copied into the output's metadata, together with the digest
of this file."""

import hashlib
import importlib
import json
import os
import ipaddress
import shutil
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, os.environ.get("SMOKE_TOOLS", str(HERE)))

from txn_program_collector import Collector, parse_time, projection  # noqa: E402
from txn_program_program import RequestBudget, compile_plan  # noqa: E402


def validate_runtime_inputs(expected, actual):
    """An exact input map is required; subset equality cannot establish currency."""
    if not expected or expected != actual:
        raise ValueError("runtime inputs differ")


def recording_semantics(receipt, table, *, local_diagnostics=False):
    """Derive every declared response and cleanup from the existing closed-graph replay.

    Timestamp values are volatile. Their ordering, equality and wire precision remain visible.
    Marker identities and issued token values are replaced only by their declared roles.
    """
    projected = projection(receipt, table)
    pairs = diagnostic_resource_pairs(receipt, table)["steps"] if local_diagnostics else None
    rows = receipt["steps"] + receipt["cleanupSteps"]
    stamps = []

    def timestamps(value, transport, path=""):
        result = []
        if isinstance(value, dict):
            for key, item in value.items():
                name = f"{path}/{key}"
                if key in ("updateTime", "createTime", "commitTime", "readTime"):
                    moment = parse_time(item, transport)
                    layout = {"precision": len(item.partition(".")[2][:-1]) if "." in item else 0} if isinstance(item, str) else {"members": sorted(item)}
                    result.append((name, moment, layout))
                else:
                    result.extend(timestamps(item, transport, name))
        elif isinstance(value, list):
            for index, item in enumerate(value):
                result.extend(timestamps(item, transport, f"{path}/{index}"))
        return result

    for row in rows:
        stamps.extend(moment for _, moment, _ in timestamps(row["result"].get("response"), row["transport"]))
    ranks = {stamp: index for index, stamp in enumerate(sorted(set(stamps)))}
    reads = {row["site"]: row for row in projected["reads"]}

    def semantic(row):
        result = row["result"]
        if row["transport"] == "rest" and not (200 <= result["http"] < 300 or 400 <= result["http"] < 500):
            raise ValueError("HTTP outcome is indeterminate")
        details = normalize(result["details"], pairs[row["site"]]) if pairs is not None else result["details"]
        for role, token in receipt["tokens"].items():
            details = details.replace(token["value"], f"<token:{role}>")
        details = details.replace(receipt["nonce"], "<nonce>").replace(receipt["ownerId"], "<owner>")
        return {"transport": row["transport"], "rpc": row["rpc"], "caseId": row["caseId"],
                "code": result["code"], "http": result["http"], "details": details if pairs is not None else normalize(details),
                "read": reads.get(row["site"]),
                "versions": {name: {"rank": ranks[moment], "layout": layout} for name, moment, layout in timestamps(result.get("response"), row["transport"])} }

    return {"program": projected["program"], "corpusDigest": projected["corpusDigest"],
            "steps": {row["site"]: semantic(row) for row in receipt["steps"]},
            "cleanupSteps": {row["site"]: semantic(row) for row in receipt["cleanupSteps"]},
            "tokens": projected["tokens"], "cleanup": projected["cleanup"],
            "commitTimes": commit_relations(receipt["steps"])}


def diagnostic_resource_pairs(receipt, table):
    """Bind each closed request's declared document resources to its local wire resources."""
    projection(receipt, table)
    plan = compile_plan(table, receipt["nonce"], receipt["ownerId"])
    declared = set(plan["documents"].values())
    source_database = plan["database"]
    local_database = "projects/demo-program/databases/(default)"
    result = {"steps": {}, "cases": {}}
    for row in receipt["steps"] + receipt["cleanupSteps"]:
        request = row.get("request") or {}
        resources = [request.get("name"), *request.get("documents", []),
                     *(write.get("update", {}).get("name") for write in request.get("writes", []))]
        pairs = {source.replace(source_database + "/", local_database + "/", 1): source
                 for source in resources if source in declared}
        result["steps"][row["site"]] = pairs
        if row.get("caseId"):
            result["cases"][row["caseId"]] = {local.replace(receipt["nonce"], "<nonce>"): source.replace(receipt["nonce"], "<nonce>")
                                             for local, source in pairs.items()}
    return result


def normalize(text, resource_pairs=None):
    if resource_pairs is None:
        return text.replace("demo-program", "fireemu-oracle-sbx")
    for local, source in resource_pairs.items():
        text = text.replace('"' + local + '"', '"' + source + '"')
    return text


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


def compare(production, local, production_relations, local_relations, *, diagnostic_pairs=None):
    cases, reads, times = [], [], []
    for section, key in (("cases", "caseId"), ("reads", "site")):
        for value in (production, local):
            ids = [row[key] for row in value[section]]
            if len(ids) != len(set(ids)):
                raise ValueError("duplicate row identity")
        if set(row[key] for row in local[section]) - set(row[key] for row in production[section]):
            raise ValueError("unexpected row identity")
    by_case = {case["caseId"]: case for case in local["cases"]}
    for case in production["cases"]:
        other = by_case.get(case["caseId"])
        pairs = None if diagnostic_pairs is None else diagnostic_pairs.get(case["caseId"], {})
        details = None if other is None else normalize(other["details"], pairs)
        same = other is not None and other["code"] == case["code"] and details == case["details"] and all(other.get(key) == case.get(key) for key in ("transport", "rpc"))
        cases.append({"caseId": case["caseId"], "production": {"code": case["code"], "details": case["details"][:100] if diagnostic_pairs is None else case["details"]},
                      "local": None if other is None else {"code": other["code"], "details": details[:100] if diagnostic_pairs is None else details}, "match": same})
    by_site = {read["site"]: read for read in local["reads"]}
    for read in production["reads"]:
        other = by_site.get(read["site"])
        row = lambda value: None if value is None else {"code": value["code"], "state": value.get("state"), "documents": value.get("documents")}  # noqa: E731
        reads.append({"site": read["site"], "production": row(read), "local": row(other), "match": row(read) == row(other)})
    for site in sorted(set(production_relations or {}) | set(local_relations)):
        expected = (production_relations or {}).get(site)
        actual = local_relations.get(site)
        times.append({"site": site, "production": expected, "local": actual, "match": actual == expected})
    return cases, reads, times


def main():
    table = importlib.import_module(os.environ["SMOKE_TABLE"]).TABLE
    from txn_program_runner import wire_scope
    from txn_program_wire import NodeWire, discover_runtime

    host, port = os.environ["FIRESTORE_EMULATOR_HOST"].rsplit(":", 1)
    if not ipaddress.ip_address(host).is_loopback:
        raise ValueError("loopback local target required")
    source = json.loads(Path(sys.argv[1]).read_text())
    recorded = "steps" in source
    production = projection(source, table) if recorded else source["projection"]
    production_semantics = recording_semantics(source, table) if recorded else None
    runtime_proof = None
    if os.environ.get("COMPARE_RUNTIME_PROOF"):
        runtime_proof = json.loads(Path(os.environ["COMPARE_RUNTIME_PROOF"]).read_text())
        actual = {name: hashlib.sha256((Path(runtime_proof["root"]) / name).read_bytes()).hexdigest() for name in runtime_proof["inputs"]}
        validate_runtime_inputs(runtime_proof["inputs"], actual)
        if hashlib.sha256(Path(runtime_proof["binary"]).read_bytes()).hexdigest() != runtime_proof["binarySha256"] or runtime_proof["binarySha256"] != os.environ["COMPARE_BINARY_SHA256"] or runtime_proof["sourceCommit"] != os.environ["COMPARE_COMMIT"]:
            raise ValueError("runtime artifact binding differs")
    runtime = discover_runtime(Path(os.environ.get("NODE_BINARY") or shutil.which("node")))
    plan = compile_plan(table, os.urandom(16).hex(), os.urandom(16).hex())
    wire = NodeWire(runtime, wire_scope(table), target={"kind": "local", "host": host, "port": int(port)}, project=plan["project"])
    receipt = Collector(plan, table, RequestBudget(plan, table), wire, "owner", save=lambda _state: None).run()
    receipt["runtime"] = runtime
    out = Path(sys.argv[2])
    receipt_path = out.with_suffix(".receipt.json")
    receipt_path.write_text(json.dumps(receipt, indent=1))
    metadata = {key[8:].lower(): value for key, value in os.environ.items() if key.startswith("COMPARE_")}
    metadata.update({"table": table["name"], "program": table["program"], "planCorpusDigest": plan["corpusDigest"],
                     "productionCorpusDigest": production["corpusDigest"], "productionFile": str(Path(sys.argv[1])),
                     "productionFileSha256": hashlib.sha256(Path(sys.argv[1]).read_bytes()).hexdigest(),
                     "productionFileKind": "recording" if recorded else "freeze",
                     "localProject": "demo-program", "compareToolSha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                     "localReceiptSha256": hashlib.sha256(receipt_path.read_bytes()).hexdigest(),
                     "runtimeInputsValidated": runtime_proof is not None})
    result = {"metadata": metadata, "complete": receipt["complete"], "failure": receipt["failureType"], "cases": None, "reads": None, "commitTimes": None}
    if receipt["complete"]:
        local = projection(receipt, table)
        production_relations = commit_relations(source["steps"]) if recorded else None
        local_relations = commit_relations(receipt["steps"])
        result["cases"], result["reads"], result["commitTimes"] = compare(production, local, production_relations, local_relations, diagnostic_pairs=diagnostic_resource_pairs(receipt, table)["cases"])
        local_semantics = recording_semantics(receipt, table, local_diagnostics=True)
        result["allSteps"] = [{"site": site, "production": expected, "local": local_semantics["steps"].get(site), "match": expected == local_semantics["steps"].get(site)} for site, expected in (production_semantics or {}).get("steps", {}).items()]
        result["cleanupMatch"] = None if production_semantics is None else all(production_semantics[key] == local_semantics[key] for key in ("cleanupSteps", "tokens", "cleanup"))
        rows = result["cases"] + result["reads"] + (result["commitTimes"] or [])
        rows += result["allSteps"]
        result["mismatches"] = sum(not row["match"] for row in rows)
        if result["cleanupMatch"] is False:
            result["mismatches"] += 1
    if runtime_proof is not None:
        actual = {name: hashlib.sha256((Path(runtime_proof["root"]) / name).read_bytes()).hexdigest() for name in runtime_proof["inputs"]}
        validate_runtime_inputs(runtime_proof["inputs"], actual)
    out.write_text(json.dumps(result, indent=1))
    print("complete", receipt["complete"], receipt["failureType"], "mismatches", result.get("mismatches"))
    for row in (result["cases"] or []) + (result["reads"] or []) + (result["commitTimes"] or []):
        if not row["match"]:
            print("DIVERGE", json.dumps(row)[:300])


if __name__ == "__main__":
    main()
