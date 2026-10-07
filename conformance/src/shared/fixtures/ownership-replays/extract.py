#!/usr/bin/env python3
"""Derives the replay fixtures of ownership.test.mjs from real recorded production answers.

The sources live under docs.local/runs (private, untracked); every fixture records the source path
and its sha256, so a reader with the same files can re-run this script and get the same bytes.
Only what the ledger needs is kept: the action (create, delete or get), the transport, a name with
the project removed, the HTTP status (a gRPC code is mapped to its HTTP equivalent), whether a body
was read, and for a present get the name its body shows (`bodyName`). Nothing else of a response is
copied, and no project id or number. A request for a collection (a list) is not a get of a name and
is skipped, and counted in the fixture.

The output is byte-reproducible: running this script again on the same sources gives the same files,
and each fixture carries the sha256, the size and the line count of every source file. A capture
that is not complete (its last line is not the run-end note, or its request count is short) is
refused, as is a gRPC code the table below does not know.

Usage: extract.py <docs.local/runs directory> <output directory>

The decisions are plain functions (pubsub_ops, scheduler_ops, grpc_status, shows_name); test_extract.py
runs them on small synthetic captures. Importing this module reads nothing.
"""
import base64, hashlib, json, re, sys, urllib.parse
from pathlib import Path

RUNS = OUT = None  # set by main()
# The canonical gRPC code to HTTP status mapping (google.rpc.Code).
GRPC = {"OK": 200, "CANCELLED": 499, "UNKNOWN": 500, "INVALID_ARGUMENT": 400,
        "DEADLINE_EXCEEDED": 504, "NOT_FOUND": 404, "ALREADY_EXISTS": 409,
        "PERMISSION_DENIED": 403, "RESOURCE_EXHAUSTED": 429, "FAILED_PRECONDITION": 400,
        "ABORTED": 409, "OUT_OF_RANGE": 400, "UNIMPLEMENTED": 501, "INTERNAL": 500,
        "UNAVAILABLE": 503, "DATA_LOSS": 500, "UNAUTHENTICATED": 401}
COLLECTIONS = {"topics", "subscriptions", "snapshots"}
PROJECTS = ["fireemu-oracle-idp", "fireemu-oracle-sbx", "fireemu-oracle-events", "fireemu-oracle-query"]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def scrub(text):
    for project in PROJECTS:
        text = text.replace(project, "demo-project")
    return re.sub(r"\b\d{12}\b", "000000000000", text)


def short(name):
    return scrub(re.sub(r"^projects/[^/]+/", "", name))


def describe(path):
    data = (RUNS / path).read_bytes()
    return {"path": path, "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data),
            "lines": data.count(b"\n")}


def grpc_status(code):
    if code not in GRPC:
        sys.exit(f"extract.py: gRPC code {code!r} is not in the table; add it before extracting")
    return GRPC[code]


def write(name, source, ops, note, skipped=None):
    sources = source if isinstance(source, list) else [source]
    doc = {"sources": [describe(p) for p in sources], "note": note}
    if skipped:
        doc["skipped"] = skipped
    doc["ops"] = ops
    (OUT / name).write_text(json.dumps(doc, indent=1, sort_keys=False) + "\n")
    print(name, len(ops), "ops")


# ---- PUBSUB (run 148026092d56, production, REST and gRPC) ----
def pubsub_ops(rows, source="the capture"):
    """The ledger operations of a complete capture, and the number of list requests skipped."""
    last = rows[-1] if rows else {}
    requests = [r for r in rows if "n" in r]
    if last.get("note") != "run-end" or last.get("requests") != len(requests):
        sys.exit(f"extract.py: {source} is not a complete capture (no run-end note, or a short count)")
    ops, collections = [], 0
    for row in rows:
        op = row.get("op")
        if not op:
            continue
        m = re.match(r"(create|delete|get)(Topic|Subscription)$", op)
        if not m:
            continue
        request = row["request"]
        if row["transport"] == "rest":
            name = short(request["path"].removeprefix("/v1/"))
        else:
            body = request.get("body", {})
            name = short(body.get("name") or body.get("topic") or body.get("subscription") or "")
        if name in COLLECTIONS:
            collections += 1  # a list request, not a get of a name
            continue
        response = row["response"]
        if row["transport"] == "grpc":
            status = grpc_status(response["code"])
        else:
            status = response.get("status")
        entry = {"action": m.group(1), "transport": row["transport"], "name": name,
                 "status": status, "bodyReadable": not response.get("unknown", False),
                 "at": row["at"]}
        if response.get("unknown"):
            entry["transportError"] = response.get("error", "unknown")
        body = response.get("body")
        if m.group(1) == "get" and status is not None and 200 <= status < 300 \
                and isinstance(body, dict) and "name" in body:
            entry["bodyName"] = short(body["name"])
        ops.append(entry)
    return ops, collections


def pubsub():
    source = "pubsub-production-20261005-r1/capture-148026092d56.jsonl"
    rows = [json.loads(line) for line in (RUNS / source).read_text().splitlines()]
    ops, collections = pubsub_ops(rows, source)
    return write("pubsub-r1.json", source, ops,
                 "Pub/Sub lifecycle, name probes and cleanup, REST and gRPC, the complete run; one real create timed out (a transport error) and was still there 40 minutes later.",
                 {"collectionGets": collections})


# ---- calendar (Cloud Scheduler) and the scheduled shape run ----
def journal(path):
    return journal_rows(path.read_text().splitlines())


def journal_rows(lines):
    before, out = {}, []
    for line in lines:
        r = json.loads(line)
        if r["state"] == "before-send":
            before[r["id"]] = r
        elif r["state"] == "response-persisted":
            out.append((r["id"], before.get(r["id"], {}), r))
    return out


def shows_name(b, r):
    """True when the response body names the resource the request URL asks for."""
    try:
        body = json.loads(base64.b64decode(r["bodyBase64"]))
    except (KeyError, ValueError):
        return False
    asked = urllib.parse.urlparse(b.get("url", "")).path.rsplit("/", 1)[-1]
    return isinstance(body, dict) and isinstance(body.get("name"), str) and body["name"].rsplit("/", 1)[-1] == asked


def scheduler_ops(shape_entries, calendar_entries):
    """Operations of the scheduled shape run and of calendar v5, from their journal entries."""
    ops = []
    names = {"topic": "topics/shape", "subscription": "subscriptions/shape", "job": "jobs/shape"}
    for rid, b, r in shape_entries:
        m = re.match(r"(create|delete)-(topic|subscription|job)$", rid)
        if m:
            ops.append({"action": m.group(1), "transport": "rest", "name": names[m.group(2)],
                        "status": r["status"], "bodyReadable": True})
        m = re.match(r"(before|read-deleted)-(topic|subscription|job)$", rid)
        if m:
            op = {"action": "get", "transport": "rest", "name": names[m.group(2)],
                  "status": r["status"], "bodyReadable": True}
            if 200 <= r["status"] < 300 and shows_name(b, r):
                op["bodyName"] = op["name"]
            ops.append(op)
    for rid, b, r in calendar_entries:
        m = re.match(r"(?:(c\d\d)-)?(create|delete)(?:-(topic))?$", rid)
        if m:
            name = "topics/calendar" if m.group(3) else f"jobs/{m.group(1)}"
            ops.append({"action": m.group(2), "transport": "rest", "name": name,
                        "status": r["status"], "bodyReadable": True})
    return ops


def scheduler():
    shape = "codex-lane8/shape-96db1cb7ca5fcb35/requests.jsonl"
    cal = "codex-lane8/calendar-5a73ba99b7014cfd/requests.jsonl"
    ops = scheduler_ops(journal(RUNS / shape), journal(RUNS / cal))
    return write("scheduler.json", [shape, cal], ops,
                 "Scheduled shape run (delete of a paused job answered 409) and calendar v5 (two creates answered 400).")


# ---- FE v5 transport journal ----
def fe():
    source = "functions-events-formal-20261004T182904Z-a9621bfae74fe9bc/transport/journal.jsonl"
    before, ops = {}, []
    created_bucket = None
    for line in (RUNS / source).read_text().splitlines():
        r = json.loads(line)
        if "seq" not in r:
            continue
        if r["state"] == "before-send":
            before[r["seq"]] = r
            continue
        if r["state"] != "response-persisted":
            continue
        b = before[r["seq"]]
        url = b["url"]
        path = urllib.parse.urlparse(url)
        q = urllib.parse.parse_qs(path.query)
        name = None
        action = None
        if b["method"] == "PUT" and "/topics/" in path.path:
            action, name = "create", "topics/" + path.path.rsplit("/", 1)[-1]
        elif b["method"] == "POST" and path.path.startswith("/upload/storage/v1/b/") and "name" in q:
            action, name = "create", "objects/" + q["name"][0]
        elif b["method"] == "POST" and path.path == "/storage/v1/b":
            action, name = "create", "buckets/control"
        elif b["method"] == "DELETE" and "/storage/v1/b/" in path.path and "/o/" in path.path:
            action, name = "delete", "objects/" + urllib.parse.unquote(path.path.rsplit("/o/", 1)[-1])
        elif b["method"] == "DELETE" and path.path.endswith("-fe-events-control"):
            action, name = "delete", "buckets/control"
        elif b["method"] == "DELETE" and "/topics/" in path.path:
            action, name = "delete", "topics/" + path.path.rsplit("/", 1)[-1]
        if action is None:
            continue
        ops.append({"action": action, "transport": "rest", "name": scrub(name),
                    "status": r["status"], "bodyReadable": True})
    return write("fe-v5.json", source, ops,
                 "FE v5 storage objects, topics and the control bucket: creates 200, deletes 204 or 200, one delete of a missing object 404.")


def main(argv):
    global RUNS, OUT
    RUNS, OUT = Path(argv[1]), Path(argv[2])
    OUT.mkdir(parents=True, exist_ok=True)
    pubsub(); scheduler(); fe()


if __name__ == "__main__":
    main(sys.argv)
