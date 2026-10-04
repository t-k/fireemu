#!/usr/bin/env python3
"""Derives the replay fixtures of ownership.test.mjs from real recorded production answers.

The sources live under docs.local/runs (private, untracked); every fixture records the source path
and its sha256, so a reader with the same files can re-run this script and get the same bytes.
Only what the ledger needs is kept: the action (create, delete or get), the transport, a name with
the project removed, the HTTP status (a gRPC code is mapped to its HTTP equivalent) and whether a
body was read. Nothing else of a response is copied, and no project id or number.

Usage: extract.py <docs.local/runs directory> <output directory>
"""
import hashlib, json, re, sys, urllib.parse
from pathlib import Path

RUNS = Path(sys.argv[1])
OUT = Path(sys.argv[2])
GRPC = {"OK": 200, "ALREADY_EXISTS": 409, "INVALID_ARGUMENT": 400, "NOT_FOUND": 404,
        "FAILED_PRECONDITION": 400, "UNAVAILABLE": 503, "DEADLINE_EXCEEDED": 504}
PROJECTS = ["fireemu-oracle-idp", "fireemu-oracle-sbx", "fireemu-oracle-events", "fireemu-oracle-query"]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def scrub(text):
    for project in PROJECTS:
        text = text.replace(project, "demo-project")
    return re.sub(r"\b\d{12}\b", "000000000000", text)


def short(name):
    return scrub(re.sub(r"^projects/[^/]+/", "", name))


def write(name, source, ops, note):
    sources = source if isinstance(source, list) else [source]
    doc = {"sources": [{"path": p, "sha256": sha(RUNS / p)} for p in sources], "note": note, "ops": ops}
    (OUT / name).write_text(json.dumps(doc, indent=1, sort_keys=False) + "\n")
    print(name, len(ops), "ops")


# ---- PUBSUB (run 148026092d56, production, REST and gRPC) ----
def pubsub():
    source = "pubsub-production-20261005-r1/capture-148026092d56.jsonl"
    ops = []
    for line in (RUNS / source).read_text().splitlines():
        row = json.loads(line)
        op = row.get("op")
        if not op:
            continue
        m = re.match(r"(create|delete|get)(Topic|Subscription)$", op)
        if not m:
            continue
        request = row["request"]
        raw = request.get("path") or request["body"].get("name") if request.get("rpc") else request["path"]
        if row["transport"] == "rest":
            name = short(request["path"].removeprefix("/v1/"))
        else:
            body = request.get("body", {})
            name = short(body.get("name") or body.get("topic") or body.get("subscription") or "")
        response = row["response"]
        if row["transport"] == "grpc":
            status = GRPC[response["code"]]
        else:
            status = response.get("status")
        entry = {"action": m.group(1), "transport": row["transport"], "name": name,
                 "status": status, "bodyReadable": not response.get("unknown", False)}
        if response.get("unknown"):
            entry["transportError"] = response.get("error", "unknown")
        ops.append(entry)
    return write("pubsub-r1.json", source, ops,
                 "Pub/Sub lifecycle and name probes, REST and gRPC; one real create timed out (a transport error).")


# ---- calendar (Cloud Scheduler) and the scheduled shape run ----
def journal(path):
    before, out = {}, []
    for line in path.read_text().splitlines():
        r = json.loads(line)
        if r["state"] == "before-send":
            before[r["id"]] = r
        elif r["state"] == "response-persisted":
            out.append((r["id"], before.get(r["id"], {}), r))
    return out


def scheduler():
    ops = []
    shape = "codex-lane8/shape-96db1cb7ca5fcb35/requests.jsonl"
    names = {"topic": "topics/shape", "subscription": "subscriptions/shape", "job": "jobs/shape"}
    for rid, b, r in journal(RUNS / shape):
        m = re.match(r"(create|delete)-(topic|subscription|job)$", rid)
        if m:
            ops.append({"action": m.group(1), "transport": "rest", "name": names[m.group(2)],
                        "status": r["status"], "bodyReadable": True})
        m = re.match(r"(before|read-deleted)-(topic|subscription|job)$", rid)
        if m:
            ops.append({"action": "get", "transport": "rest", "name": names[m.group(2)],
                        "status": r["status"], "bodyReadable": True})
    cal = "codex-lane8/calendar-5a73ba99b7014cfd/requests.jsonl"
    for rid, b, r in journal(RUNS / cal):
        m = re.match(r"(?:(c\d\d)-)?(create|delete)(?:-(topic))?$", rid)
        if m:
            name = "topics/calendar" if m.group(3) else f"jobs/{m.group(1)}"
            ops.append({"action": m.group(2), "transport": "rest", "name": name,
                        "status": r["status"], "bodyReadable": True})
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


if __name__ == "__main__":
    OUT.mkdir(parents=True, exist_ok=True)
    pubsub(); scheduler(); fe()
